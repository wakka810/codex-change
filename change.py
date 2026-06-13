#!/usr/bin/env python3
import argparse, base64, contextlib, curses, datetime as dt, fcntl, hashlib, json, os, queue, re, shutil, subprocess, sys, tempfile, threading, time, urllib.error, urllib.request
from pathlib import Path
from types import SimpleNamespace as NS

APP = "change"
CODEX_HOME = Path(os.getenv("CODEX_HOME", str(Path.home() / ".codex"))).expanduser()
AUTH, STATE, LOCK = CODEX_HOME / "auth.json", CODEX_HOME / "profile-state.json", CODEX_HOME / ".change.lock"
AUTH_DB = Path(os.getenv("CODEX_AUTH_JSONL", str(CODEX_HOME / "auth.jsonl"))).expanduser()
BACKUPS, LEGACY = CODEX_HOME / "backups", Path(os.getenv("CODEX_PROFILE_DIR", str(CODEX_HOME / "profiles"))).expanduser()
USAGE_URL = os.getenv("CODEX_USAGE_URL", "https://chatgpt.com/backend-api/wham/usage")
HTTP_TIMEOUT = float(os.getenv("CHANGE_HTTP_TIMEOUT", "2.5"))
MAX_USAGE_WORKERS = int(os.getenv("CHANGE_USAGE_WORKERS", "6"))
SAFE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
PLAN = {"free":"Free","go":"Go","plus":"Plus","pro":"Pro","pro_lite":"Pro Lite","team":"Team","business":"Business","enterprise":"Enterprise","enterprise_cbp_usage_based":"Enterprise","self_serve_business_usage_based":"Business","edu":"Edu","education":"Edu"}

class ChangeError(Exception): pass

def P(**kw):
    d = dict(account="unknown", email=None, account_id=None, plan=None, access_exp=None, refresh_hash=None, fedramp=False, auth_mode="unknown", has_tokens=False); d.update(kw); return NS(**d)
def W(used_percent=None, reset_at=None): return NS(used_percent=used_percent, reset_at=reset_at)
def U(text="--", primary=None, secondary=None, plan=None, error=None): return NS(text=text, primary=primary or W(), secondary=secondary or W(), plan=plan, error=error)
def R(name, auth, meta=None, updated_at="", preview=None, usage=None): return NS(name=name, auth=auth, meta=meta or {}, updated_at=updated_at, preview=preview or P(), usage=usage or U(), is_current=False, is_active=False)

def usage_score(u):
    vals = [max(0, 100 - w.used_percent) for w in (u.primary, u.secondary) if w.used_percent is not None]
    return min(vals) if vals else -1

@contextlib.contextmanager
def locked():
    CODEX_HOME.mkdir(parents=True, exist_ok=True)
    try: os.chmod(CODEX_HOME, 0o700)
    except Exception: pass
    with LOCK.open("a+") as f:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        try: yield
        finally: fcntl.flock(f.fileno(), fcntl.LOCK_UN)

def now_iso(): return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
def ts(): return dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
def D(x): return x if isinstance(x, dict) else {}
def get2(d, a, b): return d.get(a, d.get(b))

def validate_name(name):
    if not SAFE.fullmatch(name): raise ChangeError("profile name must be 1-64 chars: letters, digits, dot, underscore, hyphen")
    if name in {".", "..", "auth", "active", "current", "backups", "profiles"}: raise ChangeError(f"reserved profile name: {name}")
    return name

def atomic_write_text(path, text, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=str(path.parent), prefix=f".{path.name}.", delete=False) as f:
        tmp = Path(f.name); f.write(text); f.flush(); os.fsync(f.fileno())
    try: os.chmod(tmp, mode); os.replace(tmp, path)
    except Exception: tmp.unlink(missing_ok=True); raise

def atomic_write_json(path, obj, mode=0o600): atomic_write_text(path, json.dumps(obj, ensure_ascii=False, indent=2) + "\n", mode)

def atomic_copy(src, dst, mode=0o600):
    dst.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("wb", dir=str(dst.parent), prefix=f".{dst.name}.", delete=False) as f: tmp = Path(f.name)
    try: shutil.copy2(src, tmp); os.chmod(tmp, mode); os.replace(tmp, dst)
    except Exception: tmp.unlink(missing_ok=True); raise

def read_json(path):
    with path.open("r", encoding="utf-8") as f: v = json.load(f)
    if not isinstance(v, dict): raise ValueError("top-level JSON is not an object")
    return v

def read_json_maybe(path):
    try: return read_json(path)
    except Exception: return None

def digest_json(v): return hashlib.sha256(json.dumps(v, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
def active_digest():
    a = read_json_maybe(AUTH)
    return digest_json(a) if a else None

def jwt_payload(jwt):
    if not isinstance(jwt, str) or jwt.count(".") < 2: return {}
    p = jwt.split(".", 2)[1]; p += "=" * (-len(p) % 4)
    try:
        v = json.loads(base64.urlsafe_b64decode(p.encode()).decode())
        return v if isinstance(v, dict) else {}
    except Exception: return {}

def tokens(auth): return D(auth.get("tokens"))
def first_str(*xs): return next((x for x in xs if isinstance(x, str) and x), None)
def plan_name(x):
    if x is None: return None
    raw = x if isinstance(x, str) else str(x)
    return PLAN.get(raw.strip().replace("-", "_").lower(), raw.strip() or None)

def id_payload(t):
    raw = t.get("id_token")
    if isinstance(raw, str): return jwt_payload(raw)
    if isinstance(raw, dict): return jwt_payload(raw.get("raw_jwt")) or raw
    return {}

def preview(auth, fallback="unknown"):
    t, p = tokens(auth), None
    p = id_payload(t); claim, prof, ap = D(p.get("https://api.openai.com/auth")), D(p.get("https://api.openai.com/profile")), jwt_payload(t.get("access_token"))
    try: exp = int(ap["exp"]) if ap.get("exp") is not None else None
    except Exception: exp = None
    rt = t.get("refresh_token"); rh = hashlib.sha256(rt.encode()).hexdigest()[:16] if isinstance(rt, str) and rt else None
    email = first_str(p.get("email"), prof.get("email"), p.get("chatgpt_email"), t.get("email"))
    account_id = first_str(t.get("account_id"), claim.get("chatgpt_account_id"), p.get("chatgpt_account_id"))
    plan = plan_name(first_str(claim.get("chatgpt_plan_type"), p.get("chatgpt_plan_type"), t.get("plan_type")))
    mode = auth.get("auth_mode") or ("api_key" if auth.get("openai_api_key") else "unknown")
    return P(account=email or account_id or fallback, email=email, account_id=account_id, plan=plan, access_exp=exp, refresh_hash=rh, fedramp=claim.get("chatgpt_account_is_fedramp") is True, auth_mode=str(mode), has_tokens=bool(t))

def state(): return read_json_maybe(STATE) or {}
def save_state(name): atomic_write_json(STATE, {"current": name, "switched_at": now_iso(), "auth_digest": active_digest(), "auth_db": str(AUTH_DB)})

def read_db():
    out = {}
    if not AUTH_DB.exists(): return out
    for n, raw in enumerate(AUTH_DB.read_text(encoding="utf-8").splitlines(), 1):
        if not raw.strip(): continue
        try: obj = json.loads(raw)
        except Exception as e: raise ChangeError(f"invalid JSONL at {AUTH_DB}:{n}: {e}")
        if not isinstance(obj, dict): raise ChangeError(f"invalid JSONL at {AUTH_DB}:{n}: not an object")
        name, auth = obj.get("name"), obj.get("auth")
        if not isinstance(name, str): raise ChangeError(f"invalid JSONL at {AUTH_DB}:{n}: missing name")
        validate_name(name)
        if not isinstance(auth, dict): raise ChangeError(f"invalid JSONL at {AUTH_DB}:{n}: missing auth object")
        meta = obj.get("meta") if isinstance(obj.get("meta"), dict) else {}
        updated = obj.get("updated_at") if isinstance(obj.get("updated_at"), str) else ""
        out[name] = R(name, auth, meta, updated, preview(auth, name))
    mark(out); return out

def write_db(records):
    rows = [{"version":1,"name":n,"updated_at":r.updated_at or now_iso(),"auth":r.auth,"meta":r.meta or {}} for n, r in sorted(records.items())]
    atomic_write_text(AUTH_DB, "\n".join(json.dumps(x, ensure_ascii=False, separators=(",", ":")) for x in rows) + ("\n" if rows else ""), 0o600)

def backup(path, prefix, reason):
    if not path.exists(): return None
    BACKUPS.mkdir(parents=True, exist_ok=True)
    dst = BACKUPS / f"{prefix}.{ts()}.{reason}{path.suffix}"
    atomic_copy(path, dst); return dst

def backup_db(reason): return backup(AUTH_DB, "authdb", reason)
def backup_active(reason): return backup(AUTH, "auth", reason)

def mark(records):
    cur = state().get("current"); cur = cur if isinstance(cur, str) else None
    ad = active_digest()
    for r in records.values():
        r.preview = preview(r.auth, r.name); r.is_current = r.name == cur; r.is_active = bool(ad and digest_json(r.auth) == ad)

def update_meta(r, note=""):
    p = preview(r.auth, r.name); m = dict(r.meta or {})
    m.update(name=r.name, account=p.account, email=p.email, account_id=p.account_id, plan=p.plan, auth_mode=p.auth_mode, last_seen=now_iso())
    if note: m["note"] = note
    r.preview, r.meta, r.updated_at = p, m, now_iso()

def same_account(a, b): return not ((a.account_id and b.account_id and a.account_id != b.account_id) or (a.email and b.email and a.email.lower() != b.email.lower()))

def current_record(records):
    cur = state().get("current")
    if isinstance(cur, str) and cur in records: return cur
    ad = active_digest(); hits = [n for n, r in records.items() if ad and digest_json(r.auth) == ad]
    return hits[0] if len(hits) == 1 else None

def sync_active(records):
    if not AUTH.exists() or not records: return False
    active, cur = read_json_maybe(AUTH), current_record(records)
    if not cur or not active: backup_active("unknown-active"); return False
    r, ap = records[cur], preview(active, cur)
    if not same_account(r.preview, ap): backup_active("account-mismatch"); return False
    if digest_json(r.auth) == digest_json(active): return False
    r.auth = active; update_meta(r, "synced active auth.json back into auth.jsonl"); return True

def fmt_time(epoch, today=True):
    if not epoch: return "--"
    x, n = dt.datetime.fromtimestamp(epoch).astimezone(), dt.datetime.now().astimezone()
    return x.strftime("%H:%M") if today and x.date() == n.date() else x.strftime("%b %d %H:%M") if x.year == n.year else x.strftime("%Y-%m-%d %H:%M")

def to_int(x, rounded=False):
    try: return int(round(float(x))) if rounded and x is not None else int(x) if x is not None else None
    except Exception: return None

def usage_window(raw):
    raw = D(raw)
    return W(to_int(get2(raw, "used_percent", "usedPercent"), True), to_int(get2(raw, "reset_at", "resetAt")))

def rem(w): return "--" if w.used_percent is None else f"{max(0, 100 - w.used_percent)}%"

def usage_for(auth, fallback):
    t = tokens(auth)
    if auth.get("openai_api_key") and not t: return U("API key auth · no ChatGPT usage", error="api_key")
    access = t.get("access_token")
    if not isinstance(access, str) or not access: return U("no access token", error="no_access")
    p = preview(auth, fallback)
    if p.access_exp is not None and p.access_exp <= int(time.time()): return U(f"access expired {fmt_time(p.access_exp, False)} · not refreshed", error="access_expired")
    headers = {"Authorization": f"Bearer {access}", "Accept":"application/json", "User-Agent":"codex-cli"}
    if p.account_id: headers["ChatGPT-Account-Id"] = p.account_id
    if p.fedramp: headers["X-OpenAI-Fedramp"] = "true"
    try:
        with urllib.request.urlopen(urllib.request.Request(USAGE_URL, headers=headers, method="GET"), timeout=HTTP_TIMEOUT) as resp:
            payload = json.loads(resp.read().decode())
        plan = plan_name(get2(payload, "plan_type", "planType")) if isinstance(payload, dict) else None
        rl = get2(payload, "rate_limit", "rateLimit") if isinstance(payload, dict) else None
        if not isinstance(rl, dict): return U("usage: no windows", plan=plan, error="no_windows")
        pri, sec = usage_window(get2(rl, "primary_window", "primaryWindow")), usage_window(get2(rl, "secondary_window", "secondaryWindow"))
        return U(f"{plan or 'Unknown'} · Remaining 5h {rem(pri)} · 1w {rem(sec)} · Reset {fmt_time(pri.reset_at)} / {fmt_time(sec.reset_at, False)}", pri, sec, plan)
    except urllib.error.HTTPError as e:
        return U("usage 401 · stale token · not refreshed" if e.code == 401 else f"usage HTTP {e.code}", error="401" if e.code == 401 else f"http_{e.code}")
    except Exception as e: return U(f"usage unavailable · {e}", error="request_failed")

def start_usage(records, pending=False):
    q = queue.Queue()
    if not records: return q, []
    sem = threading.BoundedSemaphore(max(1, min(MAX_USAGE_WORKERS, len(records))))
    if pending:
        for r in records.values(): r.usage = U("Checking usage...")
    def worker(r):
        with sem: q.put((r.name, usage_for(r.auth, r.name)))
    threads = [threading.Thread(target=worker, args=(r,), daemon=True) for r in records.values()]
    for t in threads: t.start()
    return q, threads

def drain_usage(records, q):
    changed = False
    while True:
        try: n, u = q.get_nowait()
        except queue.Empty: return changed
        if n in records: records[n].usage = u; changed = True

def fetch_usage(records):
    q, ts_ = start_usage(records)
    for t in ts_: t.join(timeout=HTTP_TIMEOUT + .5)
    drain_usage(records, q)

def stale(r):
    if r.preview.auth_mode == "api_key": return None
    if not r.preview.has_tokens: return "no token data"
    if r.preview.access_exp is not None and r.preview.access_exp <= int(time.time()): return f"access expired {fmt_time(r.preview.access_exp, False)}"
    return r.usage.text if r.usage.error in {"access_expired", "401", "no_access"} else None

def line(r):
    flags = (["current"] if r.is_current else []) + (["active-copy"] if r.is_active and not r.is_current else []) + (["stale"] if stale(r) else [])
    acct = r.preview.account if len(r.preview.account) <= 34 else r.preview.account[:16] + "…" + r.preview.account[-17:]
    return f"{r.name:<16} {acct:<34} {(r.usage.plan or r.preview.plan or 'Unknown'):<10} {r.usage.text if r.usage.text != '--' else 'Checking usage...'}" + (f"  [{' '.join(flags)}]" if flags else "")

def print_records(records):
    if not records: print(f"No profiles in {AUTH_DB}. Run: change login <name> / change import <name> / change migrate"); return
    for n in sorted(records): print(line(records[n]))

def load_sync(with_usage=False):
    with locked():
        records = read_db(); changed = sync_active(records)
        if changed: write_db(records)
        mark(records)
    if with_usage: fetch_usage(records)
    return records

def write_active(auth): atomic_write_json(AUTH, auth, 0o600)

def switch_to(name):
    validate_name(name)
    with locked():
        records = read_db(); changed = sync_active(records)
        if name not in records: raise ChangeError(f"profile not found in {AUTH_DB}: {name}")
        if changed: write_db(records)
        backup_active("pre-switch"); write_active(records[name].auth); save_state(name)
        update_meta(records[name], "activated from auth.jsonl"); write_db(records)
    print(f"changed: auth.json <- auth.jsonl:{name}\naccount: {preview(records[name].auth, name).account}\nnote   : active auth.json was overwritten")

def import_active(name, overwrite=False):
    validate_name(name)
    with locked():
        active = read_json_maybe(AUTH)
        if not active: raise ChangeError(f"active auth not found: {AUTH}")
        records = read_db(); sync_active(records)
        if name in records and not overwrite: raise ChangeError(f"profile exists: {name} (use --overwrite)")
        backup_db("pre-import"); records[name] = R(name, active, updated_at=now_iso(), preview=preview(active, name)); update_meta(records[name], "imported from active auth.json")
        save_state(name); write_db(records)
    print(f"imported: {name} -> {AUTH_DB}")

def codex_login_temp(name, device_auth=False):
    CODEX_HOME.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=f".change-login-{name}.", dir=str(CODEX_HOME)) as td:
        home = Path(td); atomic_write_text(home / "config.toml", 'cli_auth_credentials_store = "file"\n')
        env = os.environ.copy(); env["CODEX_HOME"] = str(home)
        print(f"starting Codex login for profile: {name}\ntemporary CODEX_HOME={home}\nsign in with the intended account; generated auth.json will be stored in auth.jsonl")
        rc = subprocess.call(["codex", "login"] + (["--device-auth"] if device_auth else []), env=env)
        if rc: raise ChangeError(f"codex login failed with exit code {rc}")
        auth_file = home / "auth.json"
        if not auth_file.exists(): raise ChangeError("codex login did not create auth.json")
        auth = read_json(auth_file); p = preview(auth, name)
        if not p.has_tokens and p.auth_mode != "api_key": raise ChangeError("created auth.json does not look valid")
        return auth

def login(name, device_auth=False, overwrite=False):
    validate_name(name)
    with locked():
        records = read_db(); sync_active(records)
        if name in records and not overwrite: raise ChangeError(f"profile exists: {name} (use --overwrite or change relogin {name})")
        backup_db("pre-login"); auth = codex_login_temp(name, device_auth)
        records[name] = R(name, auth, updated_at=now_iso(), preview=preview(auth, name)); update_meta(records[name], "created by change login"); write_db(records)
    print(f"saved profile: {name} -> {AUTH_DB}\naccount      : {preview(auth, name).account}")

def relogin(name, device_auth=False, switch=False, allow_account_change=False):
    validate_name(name)
    with locked():
        records = read_db(); sync_active(records)
        if name not in records: raise ChangeError(f"profile not found: {name}")
        backup_db("pre-relogin"); old = records[name]; oldp = old.preview; was_current = current_record(records) == name or old.is_active
        print(f"re-login target profile : {name}\nexpected account        : {oldp.account}")
        auth = codex_login_temp(name, device_auth); newp = preview(auth, name)
        if not allow_account_change and not same_account(oldp, newp):
            BACKUPS.mkdir(parents=True, exist_ok=True); bad = BACKUPS / f"auth.{name}.{ts()}.mismatched.json"; atomic_write_json(bad, auth)
            raise ChangeError(f"logged-in account mismatch: old={oldp.account!r}, new={newp.account!r}; saved to {bad}; use --allow-account-change if intentional")
        old.auth = auth; update_meta(old, "refreshed by explicit re-login into auth.jsonl"); write_db(records)
        if was_current or switch: backup_active("pre-relogin-activate"); write_active(auth); save_state(name)
    print(f"updated profile         : {name} -> {AUTH_DB}")
    if was_current or switch: print(f"changed: auth.json <- auth.jsonl:{name}")

def next_profile(best=False):
    records = load_sync(best)
    if len(records) < 2: raise ChangeError("need at least two profiles")
    cur = current_record(records)
    if best: target = sorted((r for r in records.values() if r.name != cur), key=lambda r: (usage_score(r.usage), r.name), reverse=True)[0].name
    else:
        names = sorted(records); target = names[(names.index(cur) + 1) % len(names)] if cur in names else names[0]
    switch_to(target)

def remove(name, yes=False):
    validate_name(name)
    with locked():
        records = read_db()
        if name not in records: raise ChangeError(f"profile not found: {name}")
        if not yes and input(f"Remove {name!r} from auth.jsonl? Type 'yes': ") != "yes": print("cancelled"); return
        backup_db("pre-remove"); del records[name]
        if state().get("current") == name: save_state(None)
        write_db(records)
    print(f"removed: {name}")

def migrate(yes=False, overwrite=False):
    with locked():
        legacy = [(d.name, d / "auth.json") for d in sorted(LEGACY.iterdir()) if d.is_dir() and not d.name.startswith(".") and (d / "auth.json").exists()] if LEGACY.exists() else []
        for n, _ in legacy: validate_name(n)
        if not legacy: print(f"no legacy profiles found under {LEGACY}"); return
        if not yes:
            print(f"Import {len(legacy)} legacy profiles into {AUTH_DB}?")
            for n, p in legacy: print(f"  {n}: {p}")
            if input("Type 'yes': ") != "yes": print("cancelled"); return
        records = read_db(); sync_active(records); backup_db("pre-migrate"); imported = skipped = 0
        for n, p in legacy:
            if n in records and not overwrite: skipped += 1; continue
            auth = read_json(p); records[n] = R(n, auth, updated_at=now_iso(), preview=preview(auth, n)); update_meta(records[n], f"migrated from {p}"); imported += 1
        write_db(records)
    print(f"migrated: {imported} profiles -> {AUTH_DB}")
    if skipped: print(f"skipped : {skipped} existing profiles")

def doctor():
    records, problems = load_sync(True), 0
    print(f"CODEX_HOME : {CODEX_HOME}\nAUTH_DB    : {AUTH_DB}\nactive auth: {'yes' if AUTH.exists() else 'no'}\ncurrent    : {state().get('current', '-')}\n")
    print_records(records); print(); hashes = {}
    for n, r in records.items():
        if r.preview.refresh_hash: hashes.setdefault(r.preview.refresh_hash, []).append(f"auth.jsonl:{n}")
    ah = preview(read_json_maybe(AUTH) or {}, "active").refresh_hash if AUTH.exists() else None
    if ah: hashes.setdefault(ah, []).append("active/auth.json")
    cur = current_record(records)
    for h, names in hashes.items():
        allowed = len(names) == 2 and "active/auth.json" in names and cur and f"auth.jsonl:{cur}" in names
        if len(names) > 1 and not allowed: problems += 1; print(f"WARNING duplicate refresh token {h}: {', '.join(names)}")
    legacy = sorted(CODEX_HOME.glob("auth.json.*"))
    if legacy:
        problems += 1; print("WARNING legacy auth.json.* files exist:"); [print(f"  {p}") for p in legacy[:10]]
    if not problems: print("doctor: no structural problems found")
    return 1 if problems else 0

def interactive(device_auth=False, allow_account_change=False):
    records = load_sync(False)
    if not records: print(f"No profiles in {AUTH_DB}. Run: change login <name> or change migrate"); return
    usage_q, _ = start_usage(records, True); profiles = [records[n] for n in sorted(records)]
    def run(stdscr):
        try: curses.curs_set(0)
        except Exception: pass
        stdscr.keypad(True); stdscr.timeout(100); idx = 0
        while True:
            drain_usage(records, usage_q); profiles[:] = [records[n] for n in sorted(records)]
            stdscr.erase(); h, w = stdscr.getmaxyx()
            stdscr.addnstr(0, 0, "Codex auth.jsonl switcher (usage updates in background)", max(0, w - 1), curses.A_BOLD)
            stdscr.addnstr(1, 0, "↑/↓ or j/k: move   Enter: switch / re-login stale   q/Esc: cancel", max(0, w - 1))
            stdscr.addnstr(2, 0, f"AUTH_DB={AUTH_DB}", max(0, w - 1), curses.A_DIM)
            for row, r in enumerate(profiles[:max(0, h - 4)], 4):
                i = row - 4; stdscr.addnstr(row, 0, ("> " if i == idx else "  ") + line(r), max(0, w - 1), curses.A_REVERSE if i == idx else curses.A_NORMAL)
            ch = stdscr.getch()
            if ch == -1: continue
            if ch in (ord('q'), 27, 3): return None
            if ch in (curses.KEY_UP, ord('k')): idx = (idx - 1) % len(profiles)
            elif ch in (curses.KEY_DOWN, ord('j')): idx = (idx + 1) % len(profiles)
            elif ch in (curses.KEY_ENTER, 10, 13): return profiles[idx].name
    try: target = curses.wrapper(run)
    except KeyboardInterrupt: target = None
    drain_usage(records, usage_q)
    if not target: print("cancelled"); return
    why = stale(records[target])
    if why: print(f"profile {target!r} is stale: {why}"); relogin(target, device_auth, True, allow_account_change)
    else: switch_to(target)

def parser():
    p = argparse.ArgumentParser(prog="change", description="Codex auth profile switcher backed by ~/.codex/auth.jsonl")
    p.add_argument("--device-auth", action="store_true"); p.add_argument("--allow-account-change", action="store_true")
    sub = p.add_subparsers(dest="cmd")
    for name in ("list", "status", "doctor"): sub.add_parser(name)
    s = sub.add_parser("use"); s.add_argument("name")
    s = sub.add_parser("next"); s.add_argument("--best", action="store_true")
    s = sub.add_parser("import"); s.add_argument("name"); s.add_argument("--overwrite", action="store_true")
    s = sub.add_parser("login"); s.add_argument("name"); s.add_argument("--device-auth", action="store_true"); s.add_argument("--overwrite", action="store_true")
    s = sub.add_parser("relogin"); s.add_argument("name"); s.add_argument("--device-auth", action="store_true"); s.add_argument("--switch", action="store_true"); s.add_argument("--allow-account-change", action="store_true")
    s = sub.add_parser("remove"); s.add_argument("name"); s.add_argument("-y", "--yes", action="store_true")
    s = sub.add_parser("migrate"); s.add_argument("--yes", action="store_true"); s.add_argument("--overwrite", action="store_true")
    return p

def main(argv=None):
    a = parser().parse_args(argv)
    try:
        if a.cmd is None: interactive(a.device_auth, a.allow_account_change); return 0
        if a.cmd == "list": print_records(load_sync(True)); return 0
        if a.cmd == "status":
            rec = load_sync(True); print(f"current: {current_record(rec) or '-'}")
            if AUTH.exists(): print(f"active : {preview(read_json_maybe(AUTH) or {}, 'active').account}")
            print_records(rec); return 0
        if a.cmd == "use": switch_to(a.name); return 0
        if a.cmd == "next": next_profile(a.best); return 0
        if a.cmd == "import": import_active(a.name, a.overwrite); return 0
        if a.cmd == "login": login(a.name, a.device_auth, a.overwrite); return 0
        if a.cmd == "relogin": relogin(a.name, a.device_auth, a.switch, a.allow_account_change); return 0
        if a.cmd == "remove": remove(a.name, a.yes); return 0
        if a.cmd == "migrate": migrate(a.yes, a.overwrite); return 0
        if a.cmd == "doctor": return doctor()
        raise ChangeError(f"unknown command: {a.cmd}")
    except ChangeError as e: print(f"{APP}: {e}", file=sys.stderr); return 1
    except KeyboardInterrupt: print("cancelled", file=sys.stderr); return 130

if __name__ == "__main__": raise SystemExit(main())
