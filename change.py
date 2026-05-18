#!/usr/bin/env python3
from __future__ import annotations

import base64
import curses
import hashlib
import json
import os
import queue
import shutil
import sys
import tempfile
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

os.environ.setdefault("ESCDELAY", "25")

CODEX_DIR = Path.home() / ".codex"
AUTH = CODEX_DIR / "auth.json"
BAK = CODEX_DIR / "auth.json.bak"
PREFIX = "auth.json."

USAGE_URL = os.environ.get(
    "CODEX_USAGE_URL",
    "https://chatgpt.com/backend-api/wham/usage",
)
REFRESH_TOKEN_URL = os.environ.get(
    "CODEX_REFRESH_TOKEN_URL_OVERRIDE",
    "https://auth.openai.com/oauth/token",
)
CLIENT_ID = os.environ.get(
    "CODEX_OAUTH_CLIENT_ID",
    "app_EMoamEEZ73f0CkXaXp7hrann",
)

HTTP_TIMEOUT = float(os.environ.get("CODEX_USAGE_TIMEOUT", "3.0"))
MAX_USAGE_WORKERS = int(os.environ.get("CODEX_USAGE_WORKERS", "8"))

ACCESS_TOKEN_REFRESH_MARGIN_SECONDS = int(
    os.environ.get("CODEX_ACCESS_TOKEN_REFRESH_MARGIN_SECONDS", "60")
)

PROACTIVE_REFRESH_EXPIRED_ACCESS_TOKEN = (
    os.environ.get("CODEX_PROACTIVE_REFRESH_EXPIRED_ACCESS_TOKEN", "1") != "0"
)


@dataclass
class UsageInfo:
    text: str = "Checking usage..."
    done: bool = False
    ok: bool = False
    refreshed: bool = False


@dataclass
class Profile:
    name: str
    path: Path
    account: str = "unknown account"
    plan_hint: Optional[str] = None
    usage: UsageInfo = field(default_factory=UsageInfo)
    is_current: bool = False


@dataclass
class WindowUsage:
    used_percent: Optional[int]
    reset_at: Optional[int]
    window_seconds: Optional[int]


class HttpStatusError(Exception):
    def __init__(self, status: int, body: str) -> None:
        super().__init__(f"HTTP {status}")
        self.status = status
        self.body = body


class RefreshCoordinator:
    """
    同じ refresh_token を複数 profile が持つ場合、並列 refresh で token reuse 扱いになる可能性がある。
    token ごとに refresh を一度だけ実行し、他 worker はその結果を待って使う。
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entries: dict[str, dict[str, Any]] = {}

    def refresh(self, refresh_token: str) -> dict[str, Any]:
        owner = False

        with self._lock:
            entry = self._entries.get(refresh_token)
            if entry is None:
                entry = {
                    "event": threading.Event(),
                    "ok": False,
                    "result": None,
                }
                self._entries[refresh_token] = entry
                owner = True

        if owner:
            try:
                result = request_refresh_token(refresh_token)
                with self._lock:
                    entry["ok"] = True
                    entry["result"] = result
                    entry["event"].set()
            except Exception as e:
                with self._lock:
                    entry["ok"] = False
                    entry["result"] = e
                    entry["event"].set()
        else:
            entry["event"].wait()

        with self._lock:
            ok = bool(entry["ok"])
            result = entry["result"]

        if ok:
            if not isinstance(result, dict):
                raise RuntimeError("refresh result is not JSON object")
            return result

        if isinstance(result, Exception):
            raise result
        raise RuntimeError(str(result))


def fail(message: str, code: int = 1) -> None:
    print(f"change: {message}", file=sys.stderr)
    sys.exit(code)


def discover_profiles() -> list[Profile]:
    if not CODEX_DIR.exists():
        fail(f"{CODEX_DIR} が存在しません")

    profiles: list[Profile] = []
    for path in sorted(CODEX_DIR.glob(f"{PREFIX}*")):
        if not path.is_file():
            continue

        name = path.name[len(PREFIX):]
        if not name:
            continue

        account, plan_hint = read_profile_preview(path, name)
        profiles.append(Profile(name=name, path=path, account=account, plan_hint=plan_hint))

    mark_current_profile(profiles)
    return profiles


def read_profile_preview(path: Path, fallback: str) -> tuple[str, Optional[str]]:
    try:
        auth = read_json_file(path)
    except Exception:
        return fallback, None

    if auth.get("openai_api_key") and not auth.get("tokens"):
        return fallback, "API key"

    tokens = get_tokens(auth)
    if not tokens:
        if auth.get("agent_identity"):
            return fallback, "Agent"
        return fallback, None

    raw_id_token = extract_id_token_raw(tokens)
    id_payload = jwt_payload(raw_id_token)

    email = None
    if isinstance(id_payload.get("email"), str):
        email = id_payload["email"]

    profile_claim = id_payload.get("https://api.openai.com/profile")
    if not email and isinstance(profile_claim, dict) and isinstance(profile_claim.get("email"), str):
        email = profile_claim["email"]

    auth_claim = id_payload.get("https://api.openai.com/auth")
    plan = None
    account_id = None
    if isinstance(auth_claim, dict):
        raw_plan = auth_claim.get("chatgpt_plan_type")
        if isinstance(raw_plan, str):
            plan = pretty_plan(raw_plan)

        raw_account_id = auth_claim.get("chatgpt_account_id")
        if isinstance(raw_account_id, str):
            account_id = raw_account_id

    account = email or account_id or tokens.get("account_id") or fallback
    if not isinstance(account, str) or not account:
        account = fallback

    return account, plan


def mark_current_profile(profiles: list[Profile]) -> None:
    current_digest = file_digest(AUTH) if AUTH.exists() else None

    for profile in profiles:
        profile_digest = file_digest(profile.path)
        profile.is_current = (
            current_digest is not None
            and profile_digest is not None
            and profile_digest == current_digest
        )


def file_digest(path: Path) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def read_json_file(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        value = json.load(f)

    if not isinstance(value, dict):
        raise ValueError("top-level JSON is not an object")

    return value


def atomic_write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    data = json.dumps(value, ensure_ascii=False, indent=2, sort_keys=False)
    data += "\n"

    try:
        mode = path.stat().st_mode & 0o777
    except OSError:
        mode = 0o600

    with tempfile.NamedTemporaryFile(
        dir=str(path.parent),
        prefix=f".{path.name}.",
        delete=False,
        mode="w",
        encoding="utf-8",
    ) as tmp:
        tmp_path = Path(tmp.name)
        tmp.write(data)
        tmp.flush()
        os.fsync(tmp.fileno())

    try:
        os.chmod(tmp_path, mode)
        os.replace(tmp_path, path)
    except Exception:
        try:
            tmp_path.unlink(missing_ok=True)
        finally:
            raise


def atomic_copy(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.NamedTemporaryFile(
        dir=str(dst.parent),
        prefix=f".{dst.name}.",
        delete=False,
    ) as tmp:
        tmp_path = Path(tmp.name)

    try:
        shutil.copy2(src, tmp_path)
        os.replace(tmp_path, dst)
    except Exception:
        try:
            tmp_path.unlink(missing_ok=True)
        finally:
            raise


def jwt_payload(jwt: Optional[str]) -> dict[str, Any]:
    if not jwt or not isinstance(jwt, str):
        return {}

    parts = jwt.split(".")
    if len(parts) < 3:
        return {}

    payload = parts[1]
    payload += "=" * (-len(payload) % 4)

    try:
        decoded = base64.urlsafe_b64decode(payload.encode("ascii"))
        value = json.loads(decoded.decode("utf-8"))
        return value if isinstance(value, dict) else {}
    except Exception:
        return {}


def extract_id_token_raw(tokens: dict[str, Any]) -> Optional[str]:
    raw = tokens.get("id_token")

    if isinstance(raw, str):
        return raw

    if isinstance(raw, dict):
        embedded = raw.get("raw_jwt")
        if isinstance(embedded, str):
            return embedded

    return None


def auth_claims_from_tokens(tokens: dict[str, Any]) -> dict[str, Any]:
    raw_id_token = extract_id_token_raw(tokens)
    payload = jwt_payload(raw_id_token)
    claims = payload.get("https://api.openai.com/auth")
    return claims if isinstance(claims, dict) else {}


def get_tokens(auth: dict[str, Any]) -> Optional[dict[str, Any]]:
    tokens = auth.get("tokens")
    return tokens if isinstance(tokens, dict) else None


def access_token_expiration(auth: dict[str, Any]) -> Optional[int]:
    tokens = get_tokens(auth)
    if not tokens:
        return None

    access_token = tokens.get("access_token")
    if not isinstance(access_token, str) or not access_token:
        return None

    payload = jwt_payload(access_token)
    exp = payload.get("exp")

    try:
        return int(exp)
    except Exception:
        return None


def access_token_is_expired_or_near(auth: dict[str, Any]) -> bool:
    exp = access_token_expiration(auth)
    if exp is None:
        return False

    now = int(datetime.now(timezone.utc).timestamp())
    return exp <= now + ACCESS_TOKEN_REFRESH_MARGIN_SECONDS


def account_id_from_auth(auth: dict[str, Any]) -> Optional[str]:
    tokens = get_tokens(auth)
    if not tokens:
        return None

    account_id = tokens.get("account_id")
    if isinstance(account_id, str) and account_id:
        return account_id

    claims = auth_claims_from_tokens(tokens)
    claim_account_id = claims.get("chatgpt_account_id")
    if isinstance(claim_account_id, str) and claim_account_id:
        return claim_account_id

    return None


def is_fedramp_auth(auth: dict[str, Any]) -> bool:
    tokens = get_tokens(auth)
    if not tokens:
        return False

    claims = auth_claims_from_tokens(tokens)
    return claims.get("chatgpt_account_is_fedramp") is True


def auth_headers_for_usage(auth: dict[str, Any]) -> tuple[Optional[dict[str, str]], Optional[str]]:
    if auth.get("openai_api_key") and not auth.get("tokens"):
        return None, "API key · no ChatGPT usage"

    tokens = get_tokens(auth)
    if not tokens:
        if auth.get("agent_identity"):
            return None, "Agent · no refresh-token usage"
        return None, "No tokens"

    access_token = tokens.get("access_token")
    if not isinstance(access_token, str) or not access_token:
        return None, "No access token"

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json",
        "User-Agent": "codex-cli",
    }

    account_id = account_id_from_auth(auth)
    if account_id:
        headers["ChatGPT-Account-Id"] = account_id

    if is_fedramp_auth(auth):
        headers["X-OpenAI-Fedramp"] = "true"

    return headers, None


def http_json(
    url: str,
    *,
    headers: dict[str, str],
    method: str = "GET",
    body: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    data = None
    request_headers = dict(headers)

    if body is not None:
        data = json.dumps(body).encode("utf-8")
        request_headers["Content-Type"] = "application/json"

    req = urllib.request.Request(
        url,
        data=data,
        headers=request_headers,
        method=method,
    )

    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            raw = resp.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        raw_body = e.read().decode("utf-8", errors="replace")
        raise HttpStatusError(e.code, raw_body) from e

    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        raise ValueError("response JSON is not an object")

    return parsed


def request_refresh_token(refresh_token: str) -> dict[str, Any]:
    return http_json(
        REFRESH_TOKEN_URL,
        headers={
            "Accept": "application/json",
            "User-Agent": "codex-cli",
        },
        method="POST",
        body={
            "client_id": CLIENT_ID,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
        },
    )


def extract_refresh_error_code(body: str) -> Optional[str]:
    try:
        parsed = json.loads(body)
    except Exception:
        return None

    if not isinstance(parsed, dict):
        return None

    err = parsed.get("error")
    if isinstance(err, str):
        return err

    if isinstance(err, dict):
        code = err.get("code")
        if isinstance(code, str):
            return code

    code = parsed.get("code")
    if isinstance(code, str):
        return code

    return None


def refresh_error_message(status: int, body: str) -> str:
    code = extract_refresh_error_code(body)

    if status == 401:
        if code == "refresh_token_expired":
            return "Refresh failed · token expired"
        if code == "refresh_token_reused":
            return "Refresh failed · token already used"
        if code == "refresh_token_invalidated":
            return "Refresh failed · token revoked"
        return "Refresh failed · unauthorized"

    if code:
        return f"Refresh failed · HTTP {status} {code}"

    return f"Refresh failed · HTTP {status}"


def apply_refresh_response(auth: dict[str, Any], refresh_response: dict[str, Any]) -> dict[str, Any]:
    tokens = get_tokens(auth)
    if tokens is None:
        raise ValueError("token data is not available")

    id_token = refresh_response.get("id_token")
    access_token = refresh_response.get("access_token")
    refresh_token = refresh_response.get("refresh_token")

    if isinstance(id_token, str) and id_token:
        tokens["id_token"] = id_token

        claims = auth_claims_from_tokens(tokens)
        account_id = claims.get("chatgpt_account_id")
        if isinstance(account_id, str) and account_id and not tokens.get("account_id"):
            tokens["account_id"] = account_id

    if isinstance(access_token, str) and access_token:
        tokens["access_token"] = access_token

    if isinstance(refresh_token, str) and refresh_token:
        tokens["refresh_token"] = refresh_token

    auth["last_refresh"] = (
        datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )

    return auth


def refresh_profile_auth(
    auth: dict[str, Any],
    profile_path: Path,
    coordinator: RefreshCoordinator,
    active_digest_before: Optional[str],
) -> tuple[Optional[dict[str, Any]], Optional[str], bool]:
    tokens = get_tokens(auth)
    if tokens is None:
        return None, "Refresh skipped · no tokens", False

    refresh_token = tokens.get("refresh_token")
    if not isinstance(refresh_token, str) or not refresh_token:
        return None, "Refresh skipped · no refresh token", False

    try:
        refresh_response = coordinator.refresh(refresh_token)
    except HttpStatusError as e:
        return None, refresh_error_message(e.status, e.body), False
    except Exception as e:
        return None, f"Refresh failed · {e}", False

    try:
        updated = apply_refresh_response(auth, refresh_response)
        atomic_write_json(profile_path, updated)

        active_updated = False
        if active_digest_before and AUTH.exists() and file_digest(AUTH) == active_digest_before:
            atomic_write_json(AUTH, updated)
            active_updated = True

        return updated, None, active_updated
    except Exception as e:
        return None, f"Refresh save failed · {e}", False


def usage_payload_for_auth(auth: dict[str, Any]) -> dict[str, Any]:
    headers, reason = auth_headers_for_usage(auth)
    if reason:
        raise ValueError(reason)

    assert headers is not None
    return http_json(USAGE_URL, headers=headers)


def get_any(d: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in d:
            return d[key]
    return None


def parse_window(raw: Any) -> Optional[WindowUsage]:
    if not isinstance(raw, dict):
        return None

    used = get_any(raw, "used_percent", "usedPercent")
    reset_at = get_any(raw, "reset_at", "resetAt")
    window_seconds = get_any(raw, "limit_window_seconds", "limitWindowSeconds")

    try:
        used_percent = int(round(float(used))) if used is not None else None
    except Exception:
        used_percent = None

    try:
        reset_at_i = int(reset_at) if reset_at is not None else None
    except Exception:
        reset_at_i = None

    try:
        window_seconds_i = int(window_seconds) if window_seconds is not None else None
    except Exception:
        window_seconds_i = None

    return WindowUsage(
        used_percent=used_percent,
        reset_at=reset_at_i,
        window_seconds=window_seconds_i,
    )


def parse_usage_payload(payload: dict[str, Any]) -> tuple[Optional[str], Optional[WindowUsage], Optional[WindowUsage]]:
    raw_plan = get_any(payload, "plan_type", "planType")
    plan = pretty_plan(raw_plan) if isinstance(raw_plan, str) else None

    rate_limit = get_any(payload, "rate_limit", "rateLimit")
    if not isinstance(rate_limit, dict):
        return plan, None, None

    primary = parse_window(get_any(rate_limit, "primary_window", "primaryWindow"))
    secondary = parse_window(get_any(rate_limit, "secondary_window", "secondaryWindow"))
    return plan, primary, secondary


def pretty_plan(raw: str) -> str:
    normalized = raw.strip().replace("-", "_").lower()
    mapping = {
        "free": "Free",
        "go": "Go",
        "plus": "Plus",
        "pro": "Pro",
        "pro_lite": "Pro Lite",
        "team": "Team",
        "business": "Business",
        "enterprise": "Enterprise",
        "enterprise_cbp_usage_based": "Enterprise",
        "self_serve_business_usage_based": "Business",
        "edu": "Edu",
        "education": "Edu",
    }
    return mapping.get(normalized, raw.strip() or "Unknown")


def format_reset(epoch: Optional[int], *, compact_today: bool) -> str:
    if not epoch:
        return "--"

    dt = datetime.fromtimestamp(epoch).astimezone()
    now = datetime.now().astimezone()

    if compact_today and dt.date() == now.date():
        return dt.strftime("%H:%M")

    if dt.year == now.year:
        return dt.strftime("%b %-d %H:%M") if supports_dash_day() else dt.strftime("%b %d %H:%M")

    return dt.strftime("%Y-%m-%d %H:%M")


def supports_dash_day() -> bool:
    # macOS/Linux では大抵 %-d が通る。Windows などでは落ちる場合がある。
    try:
        datetime.now().strftime("%-d")
        return True
    except ValueError:
        return False


def remaining_percent(window: Optional[WindowUsage]) -> str:
    if window is None or window.used_percent is None:
        return "--"
    return f"{max(0, 100 - window.used_percent)}%"


def format_usage_text(
    plan: Optional[str],
    plan_hint: Optional[str],
    primary: Optional[WindowUsage],
    secondary: Optional[WindowUsage],
    *,
    refreshed: bool,
    active_updated: bool,
) -> str:
    plan_text = plan or plan_hint or "Unknown"
    reset_5h = format_reset(primary.reset_at if primary else None, compact_today=True)
    reset_1w = format_reset(secondary.reset_at if secondary else None, compact_today=False)

    text = (
        f"{plan_text} · Remaining  "
        f"5h {remaining_percent(primary)} · 1w {remaining_percent(secondary)}   "
        f"Reset {reset_5h} / {reset_1w}"
    )

    flags = []
    if refreshed:
        flags.append("refreshed")
    if active_updated:
        flags.append("active updated")

    if flags:
        text += f"   [{' / '.join(flags)}]"

    return text


def fetch_usage_for_profile(profile: Profile, coordinator: RefreshCoordinator) -> UsageInfo:
    try:
        auth = read_json_file(profile.path)
    except Exception as e:
        return UsageInfo(text=f"Auth read failed · {e}", done=True, ok=False)

    refreshed = False
    active_updated = False

    profile_digest_before = file_digest(profile.path)
    auth_digest_before = file_digest(AUTH) if AUTH.exists() else None
    active_digest_before = (
        auth_digest_before
        if profile_digest_before and auth_digest_before and profile_digest_before == auth_digest_before
        else None
    )

    headers, reason = auth_headers_for_usage(auth)
    if reason:
        return UsageInfo(text=reason, done=True, ok=False)

    if PROACTIVE_REFRESH_EXPIRED_ACCESS_TOKEN and access_token_is_expired_or_near(auth):
        updated, refresh_error, did_update_active = refresh_profile_auth(
            auth,
            profile.path,
            coordinator,
            active_digest_before,
        )
        if updated is not None:
            auth = updated
            refreshed = True
            active_updated = active_updated or did_update_active
        elif refresh_error:
            return UsageInfo(text=refresh_error, done=True, ok=False)

    try:
        payload = usage_payload_for_auth(auth)
    except HttpStatusError as e:
        if e.status != 401 or refreshed:
            return UsageInfo(text=f"Usage unavailable · HTTP {e.status}", done=True, ok=False)

        updated, refresh_error, did_update_active = refresh_profile_auth(
            auth,
            profile.path,
            coordinator,
            active_digest_before,
        )
        if updated is None:
            return UsageInfo(text=refresh_error or "Refresh failed", done=True, ok=False)

        refreshed = True
        active_updated = active_updated or did_update_active

        try:
            payload = usage_payload_for_auth(updated)
        except HttpStatusError as e2:
            return UsageInfo(text=f"Usage unavailable after refresh · HTTP {e2.status}", done=True, ok=False)
        except Exception as e2:
            return UsageInfo(text=f"Usage unavailable after refresh · {e2}", done=True, ok=False)
    except Exception as e:
        return UsageInfo(text=f"Usage unavailable · {e}", done=True, ok=False)

    plan, primary, secondary = parse_usage_payload(payload)
    if primary is None and secondary is None:
        return UsageInfo(text="Usage unavailable · no windows", done=True, ok=False)

    if plan:
        profile.plan_hint = plan

    return UsageInfo(
        text=format_usage_text(
            plan,
            profile.plan_hint,
            primary,
            secondary,
            refreshed=refreshed,
            active_updated=active_updated,
        ),
        done=True,
        ok=True,
        refreshed=refreshed,
    )


def usage_worker(
    profile_index: int,
    profile: Profile,
    sem: threading.BoundedSemaphore,
    coordinator: RefreshCoordinator,
    result_queue: queue.Queue,
) -> None:
    with sem:
        result = fetch_usage_for_profile(profile, coordinator)
        result_queue.put((profile_index, result, profile.plan_hint))


def start_usage_background(profiles: list[Profile], result_queue: queue.Queue) -> None:
    workers = max(1, min(MAX_USAGE_WORKERS, len(profiles)))
    sem = threading.BoundedSemaphore(workers)
    coordinator = RefreshCoordinator()

    for i, profile in enumerate(profiles):
        t = threading.Thread(
            target=usage_worker,
            args=(i, profile, sem, coordinator, result_queue),
            daemon=True,
        )
        t.start()


def drain_usage_results(profiles: list[Profile], result_queue: queue.Queue) -> bool:
    changed = False

    while True:
        try:
            i, usage, plan_hint = result_queue.get_nowait()
        except queue.Empty:
            break

        if 0 <= i < len(profiles):
            profiles[i].usage = usage
            if plan_hint:
                profiles[i].plan_hint = plan_hint
            changed = True

    if changed:
        mark_current_profile(profiles)

    return changed


def ellipsize(value: str, width: int) -> str:
    if width <= 0:
        return ""
    if len(value) <= width:
        return value
    if width <= 1:
        return "…"
    if width <= 8:
        return value[: width - 1] + "…"

    left = max(1, (width - 1) // 2)
    right = max(1, width - left - 1)
    return value[:left] + "…" + value[-right:]


def draw(
    stdscr: curses.window,
    profiles: list[Profile],
    idx: int,
    status_line: str,
) -> None:
    stdscr.erase()
    h, w = stdscr.getmaxyx()

    title = "Codex auth profile switcher"
    subtitle = f"source: {CODEX_DIR}/auth.json.<name>    backup: {BAK}"
    help_line = "↑/↓ or j/k: move    Enter: apply    q/Esc/Ctrl-C: cancel"

    lines = [title, subtitle, help_line, status_line, ""]
    account_width = 34

    for i, profile in enumerate(profiles):
        marker = ">" if i == idx else " "

        flags = [profile.name]
        if profile.name == "bak" or profile.path == BAK:
            flags.append("bak")
        if profile.is_current:
            flags.append("current")

        account = ellipsize(profile.account, account_width)
        line = f"{marker} {account:<{account_width}} · {profile.usage.text}   [{' '.join(flags)}]"
        lines.append(line)

    profile_start_y = 5

    for y, line in enumerate(lines[:h]):
        attr = curses.A_REVERSE if y >= profile_start_y and (y - profile_start_y) == idx else curses.A_NORMAL
        stdscr.addnstr(y, 0, line, max(0, w - 1), attr)

    stdscr.refresh()


def choose_profile(profiles: list[Profile]) -> Optional[int]:
    result_queue: queue.Queue = queue.Queue()

    def _main(stdscr: curses.window) -> Optional[int]:
        try:
            curses.set_escdelay(25)
        except Exception:
            pass

        try:
            curses.curs_set(0)
        except Exception:
            pass

        stdscr.keypad(True)
        stdscr.timeout(100)

        idx = 0
        pending_apply: Optional[int] = None
        status_line = "Profiles shown immediately; usage/refresh runs in background."

        draw(stdscr, profiles, idx, status_line)
        start_usage_background(profiles, result_queue)

        while True:
            if drain_usage_results(profiles, result_queue):
                if pending_apply is None:
                    status_line = "Usage updated."

            if pending_apply is not None and profiles[pending_apply].usage.done:
                return pending_apply

            draw(stdscr, profiles, idx, status_line)

            try:
                ch = stdscr.getch()
            except KeyboardInterrupt:
                try:
                    curses.flushinp()
                except Exception:
                    pass
                return None

            if ch == -1:
                continue

            if ch in (curses.KEY_UP, ord("k")):
                idx = (idx - 1) % len(profiles)
                pending_apply = None
                status_line = "Usage/refresh runs in background."
            elif ch in (curses.KEY_DOWN, ord("j")):
                idx = (idx + 1) % len(profiles)
                pending_apply = None
                status_line = "Usage/refresh runs in background."
            elif ch in (curses.KEY_ENTER, 10, 13):
                if profiles[idx].usage.done:
                    return idx

                pending_apply = idx
                status_line = f"Waiting for {profiles[idx].name} refresh before applying..."
            elif ch in (27, ord("q"), 3):
                try:
                    curses.flushinp()
                except Exception:
                    pass
                return None
            elif ch == curses.KEY_RESIZE:
                continue

    try:
        return curses.wrapper(_main)
    except KeyboardInterrupt:
        return None


def main() -> int:
    profiles = discover_profiles()
    if not profiles:
        fail(f"{CODEX_DIR}/{PREFIX}<name> が見つかりません")

    selected_idx = choose_profile(profiles)
    if selected_idx is None:
        print("cancelled")
        return 130

    selected_profile = profiles[selected_idx]
    selected = selected_profile.path

    if not selected.exists():
        fail(f"選択元が存在しません: {selected}")
    if not AUTH.exists():
        fail(f"現在の auth.json が存在しません: {AUTH}")

    with tempfile.NamedTemporaryFile(
        dir=str(CODEX_DIR),
        prefix=".change-selected.",
        delete=False,
    ) as tmp:
        tmp_selected = Path(tmp.name)

    try:
        shutil.copy2(selected, tmp_selected)
        atomic_copy(AUTH, BAK)
        atomic_copy(tmp_selected, AUTH)
    finally:
        tmp_selected.unlink(missing_ok=True)

    print(f"changed: auth.json <- {selected.name}")
    print("backup : auth.json.bak overwritten from previous auth.json")
    print(f"account: {selected_profile.account}")
    print(f"usage  : {selected_profile.usage.text}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
