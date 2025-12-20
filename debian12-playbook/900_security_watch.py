#!/usr/bin/env python3
# Checkmk local security checks (stateful baseline/delta where useful)

import os
import re
import json
import time
import hashlib
import subprocess
from pathlib import Path

# ----------------------------- config -----------------------------

STATE_DIR = Path("/var/lib/check_mk_agent/security_watch")
STATE_FILE = STATE_DIR / "state.json"

SSH_WARN = int(os.getenv("CMK_SSH_FAIL_WARN", "10"))
SSH_CRIT = int(os.getenv("CMK_SSH_FAIL_CRIT", "20"))

SUSP_PROC_WARN = int(os.getenv("CMK_SUSP_PROC_WARN", "1"))
SUSP_PROC_CRIT = int(os.getenv("CMK_SUSP_PROC_CRIT", "3"))

FSTAB_PATH = Path("/etc/fstab")
CRON_PATHS = [
    Path("/etc/crontab"),
    Path("/etc/cron.d"),
    Path("/etc/cron.daily"),
    Path("/etc/cron.hourly"),
    Path("/etc/cron.weekly"),
    Path("/etc/cron.monthly"),
    Path("/var/spool/cron/crontabs"),
]

PASSWD_PATH = Path("/etc/passwd")
SHADOW_PATH = Path("/etc/shadow")
GROUP_PATH = Path("/etc/group")

IP_RE = re.compile(r"\bfrom\s+([0-9a-fA-F\.:]+)\b")
FAIL_RE = re.compile(r"(Failed password|Invalid user|authentication failure)", re.IGNORECASE)

# Process heuristics (cheap, intentionally conservative; expect allowlisting later)
SUSP_PATH_RE = re.compile(r"(^|\s)(/tmp/|/dev/shm/|/var/tmp/)", re.IGNORECASE)
SUSP_NAME_RE = re.compile(r"\b(kworkerd|kworker\d+|systemd--|dbusd--|sshd:)\b", re.IGNORECASE)
DELETED_RE = re.compile(r"\(deleted\)", re.IGNORECASE)

# ----------------------------- helpers -----------------------------

def load_state() -> dict:
    try:
        with STATE_FILE.open("r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}
    except Exception:
        return {}

def save_state(st: dict) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    tmp = STATE_FILE.with_suffix(".tmp")
    with tmp.open("w") as f:
        json.dump(st, f, indent=2, sort_keys=True)
    os.replace(tmp, STATE_FILE)

def local_line(code: int, svc: str, msg: str, perf: str = "") -> None:
    # Checkmk local format: "<state> <service> <perfdata> <text>" or "<state> <service> - <text>"
    if perf:
        print(f"{code} {svc} {perf} {msg}")
    else:
        print(f"{code} {svc} - {msg}")

def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def sha256_tree(paths) -> tuple[str, int]:
    # Deterministic hash over (path + content hash). Includes regular files in directories recursively.
    files = []
    for p in paths:
        if not p.exists():
            continue
        if p.is_file():
            files.append(p)
        elif p.is_dir():
            for fp in sorted(p.rglob("*")):
                try:
                    if fp.is_file():
                        files.append(fp)
                except OSError:
                    continue

    h = hashlib.sha256()
    for fp in sorted(set(files), key=lambda x: str(x)):
        try:
            h.update(str(fp).encode())
            h.update(b"\0")
            h.update(sha256_file(fp).encode())
            h.update(b"\n")
        except Exception:
            h.update(str(fp).encode() + b"\0<unreadable>\n")
    return h.hexdigest(), len(files)

def check_integrity(st: dict, key: str, svc: str, compute_fn) -> None:
    st.setdefault("integrity", {})
    baseline = st["integrity"].get(key)
    current = compute_fn()

    if baseline is None:
        st["integrity"][key] = current
        local_line(1, svc, "Baseline created (first run). Verify and re-run if expected.")
        return

    if baseline != current:
        local_line(2, svc, "Changed since baseline. Investigate; update baseline if legitimate.")
    else:
        local_line(0, svc, "OK")

def run_cmd(cmd: list[str]) -> tuple[int, str, str]:
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return p.returncode, p.stdout, p.stderr

# ============================= SERVICE BLOCKS =============================

# ----------------------------- SEC_SSH_AUTH -----------------------------
# SSH brute-force signal: count auth failures since last cursor using journald incremental cursor.

def run_journalctl_after_cursor(unit: str, cursor: str | None):
    cmd = ["journalctl", "--no-pager", "--output=json", "--show-cursor"]
    if unit:
        cmd += ["-u", unit]
    if cursor:
        cmd += ["--after-cursor", cursor]
    cmd += ["-n", "5000"]  # safety cap

    rc, out, err = run_cmd(cmd)
    if rc != 0:
        return None, None, f"journalctl error: {err.strip()[:200]}"

    new_cursor = None
    events = []
    for line in out.splitlines():
        if line.startswith("-- cursor: "):
            new_cursor = line.replace("-- cursor: ", "").strip()
            continue
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            msg = obj.get("MESSAGE", "")
            if msg:
                events.append(msg)
        except json.JSONDecodeError:
            continue
    return events, new_cursor, None

def check_ssh_auth(st: dict) -> None:
    st.setdefault("ssh", {})
    cursor = st["ssh"].get("cursor")
    events, new_cursor, err = run_journalctl_after_cursor("ssh", cursor)

    if err is not None:
        local_line(3, "SEC_SSH_AUTH", f"Cannot read journal: {err}")
        return

    failures = 0
    ips = {}
    for msg in events:
        if FAIL_RE.search(msg):
            failures += 1
            m = IP_RE.search(msg)
            if m:
                ip = m.group(1)
                ips[ip] = ips.get(ip, 0) + 1

    if new_cursor:
        st["ssh"]["cursor"] = new_cursor

    uniq_ips = len(ips)
    top_ip = max(ips.items(), key=lambda kv: kv[1])[0] if ips else "-"

    perf = f"failures={failures};{SSH_WARN};{SSH_CRIT}|uniq_ips={uniq_ips}"
    if failures >= SSH_CRIT:
        local_line(2, "SEC_SSH_AUTH", f"SSH auth failures: {failures}, uniq_ips={uniq_ips}, top={top_ip}", perf=perf)
    elif failures >= SSH_WARN:
        local_line(1, "SEC_SSH_AUTH", f"SSH auth failures: {failures}, uniq_ips={uniq_ips}, top={top_ip}", perf=perf)
    else:
        local_line(0, "SEC_SSH_AUTH", f"OK (failures={failures})", perf=perf)

# ----------------------------- SEC_PROC -----------------------------
# Runtime anomaly signal: flag processes with suspicious args patterns (temp dirs, deleted, typosquat-ish names).

def check_suspicious_processes():
    rc, out, err = run_cmd(["ps", "-eo", "pid=,user=,pcpu=,pmem=,args="])
    if rc != 0:
        return None, None, f"ps error: {err.strip()[:200]}"

    suspicious = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(None, 4)
        if len(parts) < 5:
            continue

        pid, user, pcpu, pmem, args = parts
        if SUSP_PATH_RE.search(args) or DELETED_RE.search(args) or SUSP_NAME_RE.search(args):
            suspicious.append((pid, user, pcpu, pmem, args[:160]))

    return suspicious, len(suspicious), None

def check_proc(st: dict) -> None:
    susp_list, susp_count, err = check_suspicious_processes()
    if err is not None:
        local_line(3, "SEC_PROC", f"Cannot list processes: {err}")
        return

    examples = "-"
    if susp_count:
        examples = "; ".join([f"{pid}:{user}:{args}" for pid, user, _, _, args in susp_list[:3]])

    perf = f"susp={susp_count};{SUSP_PROC_WARN};{SUSP_PROC_CRIT}"
    if susp_count >= SUSP_PROC_CRIT:
        local_line(2, "SEC_PROC", f"Suspicious processes: {susp_count} (examples: {examples})", perf=perf)
    elif susp_count >= SUSP_PROC_WARN:
        local_line(1, "SEC_PROC", f"Suspicious processes: {susp_count} (examples: {examples})", perf=perf)
    else:
        local_line(0, "SEC_PROC", f"OK (suspicious={susp_count})", perf=perf)

# ----------------------------- SEC_FSTAB -----------------------------
# Integrity baseline: hash /etc/fstab and alert on changes vs baseline.

def check_fstab(st: dict) -> None:
    def fstab_hash():
        if not FSTAB_PATH.exists():
            return "missing"
        return sha256_file(FSTAB_PATH)

    check_integrity(st, "fstab_sha256", "SEC_FSTAB", fstab_hash)

# ----------------------------- SEC_CRON -----------------------------
# Persistence baseline: deterministic hash of cron system paths and user crontabs directory tree.

def check_cron(st: dict) -> None:
    def cron_hash():
        digest, nfiles = sha256_tree(CRON_PATHS)
        return f"{digest}:{nfiles}"

    check_integrity(st, "cron_tree", "SEC_CRON", cron_hash)

# ----------------------------- SEC_SYSTEMD_PERSIST -----------------------------
# Persistence (strong): delta on enabled systemd service units; new enabled units are high-signal.

def check_systemd_persist(st: dict) -> None:
    rc, out, err = run_cmd(["systemctl", "list-unit-files", "--type=service", "--state=enabled", "--no-pager"])
    if rc != 0:
        local_line(3, "SEC_SYSTEMD_PERSIST", f"Cannot list enabled units: {err.strip()[:160]}")
        return

    units = []
    for line in out.splitlines():
        line = line.strip()
        if not line or line.startswith("UNIT FILE") or line.startswith("0 unit files"):
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "enabled":
            units.append(parts[0])

    units = sorted(set(units))
    prev = st.get("systemd_units_enabled")

    if prev is None:
        st["systemd_units_enabled"] = units
        local_line(1, "SEC_SYSTEMD_PERSIST", "Baseline created (enabled units)")
        return

    new_units = sorted(set(units) - set(prev))
    st["systemd_units_enabled"] = units

    if new_units:
        local_line(2, "SEC_SYSTEMD_PERSIST", f"New enabled units: {', '.join(new_units[:8])}")
    else:
        local_line(0, "SEC_SYSTEMD_PERSIST", "OK")

# ----------------------------- SEC_SSH_KEYS -----------------------------
# Account takeover (very strong): baseline+delta on authorized_keys for root and /home/* users.

def collect_authorized_keys() -> dict:
    paths = [Path("/root/.ssh/authorized_keys")]
    try:
        paths += list(Path("/home").glob("*/.ssh/authorized_keys"))
    except Exception:
        pass

    out = {}
    for p in paths:
        if p.exists():
            try:
                out[str(p)] = sha256_file(p)
            except Exception:
                out[str(p)] = "unreadable"
    return out

def check_ssh_keys(st: dict) -> None:
    current = collect_authorized_keys()
    prev = st.get("ssh_authorized_keys")

    if prev is None:
        st["ssh_authorized_keys"] = current
        local_line(1, "SEC_SSH_KEYS", "Baseline created (authorized_keys)")
        return

    changed = sorted([k for k in current if prev.get(k) != current[k]])
    removed = sorted([k for k in prev if k not in current])

    st["ssh_authorized_keys"] = current

    if changed or removed:
        msg = []
        if changed:
            msg.append(f"changed={len(changed)}")
        if removed:
            msg.append(f"removed={len(removed)}")
        examples = (changed + removed)[:6]
        local_line(2, "SEC_SSH_KEYS", f"authorized_keys delta ({', '.join(msg)}): {', '.join(examples)}")
    else:
        local_line(0, "SEC_SSH_KEYS", "OK")

# ----------------------------- SEC_SETUID -----------------------------
# Privilege escalation (strong): baseline+delta on setuid binaries (new entries are typically CRIT).

def collect_setuid_files() -> list[str]:
    rc, out, err = run_cmd(["find", "/", "-xdev", "-perm", "-4000", "-type", "f"])
    if rc != 0:
        return []
    files = [ln.strip() for ln in out.splitlines() if ln.strip()]
    return sorted(set(files))

def check_setuid(st: dict) -> None:
    current = collect_setuid_files()
    prev = st.get("setuid_files")

    if prev is None:
        st["setuid_files"] = current
        local_line(1, "SEC_SETUID", "Baseline created (setuid list)")
        return

    new = sorted(set(current) - set(prev))
    st["setuid_files"] = current

    if new:
        # High signal; treat as CRIT by default.
        local_line(2, "SEC_SETUID", f"New setuid binaries: {', '.join(new[:6])}")
    else:
        local_line(0, "SEC_SETUID", "OK")

# ----------------------------- SEC_LISTEN -----------------------------
# Backdoor/network signal: delta on TCP listening sockets; new listeners trigger WARN by default.

def collect_tcp_listeners() -> list[str]:
    rc, out, err = run_cmd(["ss", "-lntp"])
    if rc != 0:
        return []
    listeners = []
    for line in out.splitlines():
        line = line.strip()
        if not line or line.startswith("State"):
            continue
        if line.startswith("LISTEN"):
            listeners.append(line)
    return sorted(set(listeners))

def check_listen(st: dict) -> None:
    current = collect_tcp_listeners()
    prev = st.get("tcp_listeners")

    if prev is None:
        st["tcp_listeners"] = current
        local_line(1, "SEC_LISTEN", "Baseline created (TCP listeners)")
        return

    new = sorted(set(current) - set(prev))
    st["tcp_listeners"] = current

    if new:
        local_line(1, "SEC_LISTEN", f"New TCP listeners: {len(new)} (examples: {new[0][:140]})",
                   perf=f"new={len(new)};;;")
    else:
        local_line(0, "SEC_LISTEN", "OK", perf="new=0;;;")

# ----------------------------- SEC_USERS -----------------------------
# New users (strong): delta on /etc/passwd entries; flag newly added accounts (UID>=1000 by default).

def parse_passwd_users() -> dict:
    users = {}
    if not PASSWD_PATH.exists():
        return users
    try:
        for line in PASSWD_PATH.read_text(errors="ignore").splitlines():
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) < 7:
                continue
            name, _, uid, gid, gecos, home, shell = parts[:7]
            try:
                uid_i = int(uid)
                gid_i = int(gid)
            except ValueError:
                continue
            users[name] = {"uid": uid_i, "gid": gid_i, "home": home, "shell": shell}
    except Exception:
        return users
    return users

def check_new_users(st: dict) -> None:
    current = parse_passwd_users()
    prev = st.get("passwd_users")

    if prev is None:
        st["passwd_users"] = current
        local_line(1, "SEC_USERS", "Baseline created (/etc/passwd snapshot)")
        return

    new_names = sorted(set(current.keys()) - set(prev.keys()))
    # Filter to "human-ish" accounts by default; tune as needed.
    new_human = [u for u in new_names if current[u]["uid"] >= 1000 and u not in ("nobody",)]
    new_system = [u for u in new_names if u not in new_human]

    st["passwd_users"] = current

    if new_human:
        local_line(2, "SEC_USERS", f"New users (uid>=1000): {', '.join(new_human[:8])}",
                   perf=f"new={len(new_human)};;;")
    elif new_system:
        # System accounts can be created by package installs; warn softly.
        local_line(1, "SEC_USERS", f"New system users: {', '.join(new_system[:8])}",
                   perf=f"new={len(new_system)};;;")
    else:
        local_line(0, "SEC_USERS", "OK", perf="new=0;;;")

# ============================= MAIN =============================

def main():
    st = load_state()
    now = int(time.time())

    check_ssh_auth(st)
    check_proc(st)
    check_fstab(st)
    check_cron(st)
    check_systemd_persist(st)
    check_ssh_keys(st)
    check_setuid(st)
    check_listen(st)
    check_new_users(st)

    st["meta"] = {"last_run": now}
    save_state(st)

if __name__ == "__main__":
    main()
