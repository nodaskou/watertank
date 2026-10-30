"""Encrypted configuration backup and restore.

The file is always sealed. A passphrase export uses scrypt + Fernet (AES + HMAC).
An automatic copy on this machine is sealed with the installation secret instead,
so it is not plaintext and can be restored here without typing that passphrase.
"""
import base64
import hashlib
import json
import os
import time
from datetime import datetime, timezone

from cryptography.fernet import Fernet, InvalidToken

FORMAT = 1
MAGIC_PASS = b"WWNIM1"
MAGIC_LOCAL = b"WWNIM1K"
KEEP_LOCAL = 14
LOCAL_DIR = "config-backups"

# Runtime columns that are not part of the configuration identity.
HOST_SKIP_ON_COMPARE = {"id", "last_check", "last_ms", "last_seen", "consec_fail", "last_alert", "state", "down_since", "created_at"}


class BackupError(Exception):
    pass


def _kdf(secret, salt):
    return hashlib.scrypt(secret.encode("utf-8"), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)


def seal(payload, secret, local=False):
    """Encrypt payload. Refuses an empty secret so secrets are never written in the clear."""
    if not secret or len(secret) < 8:
        raise BackupError("A passphrase of at least 8 characters is required. Unencrypted export is not allowed.")
    salt = os.urandom(16)
    key = base64.urlsafe_b64encode(_kdf(secret, salt))
    token = Fernet(key).encrypt(payload)
    magic = MAGIC_LOCAL if local else MAGIC_PASS
    return magic + b"\n" + base64.b64encode(salt) + b"\n" + token


def unseal(blob, secret):
    if not secret:
        raise BackupError("Passphrase is required.")
    try:
        text = blob.strip()
        magic, salt_b64, token = text.split(b"\n", 2)
    except ValueError as e:
        raise BackupError("This is not a Wirewave config backup.") from e
    if magic not in (MAGIC_PASS, MAGIC_LOCAL):
        raise BackupError("Unrecognised backup header.")
    try:
        salt = base64.b64decode(salt_b64)
        key = base64.urlsafe_b64encode(_kdf(secret, salt))
        return Fernet(key).decrypt(token), magic == MAGIC_LOCAL
    except (InvalidToken, ValueError) as e:
        raise BackupError("Wrong passphrase, or the file is damaged.") from e


def _rows(c, sql, args=()):
    return [dict(r) for r in c.execute(sql, args)]


def _host_key(row):
    return (row.get("host") or "").strip().lower()


def build_document(c, data_dir, version, include_history=False):
    hosts = _rows(c, "SELECT * FROM hosts ORDER BY id")
    by_id = {h["id"]: h.get("host") for h in hosts}
    dash = []
    for row in _rows(c, "SELECT * FROM dash_ifaces"):
        addr = by_id.get(row["host_id"])
        if not addr:
            continue
        dash.append({"host": addr, "iface": row["iface"], "color_in": row["color_in"], "color_out": row["color_out"]})
    doc = {
        "format": FORMAT,
        "app": "Wirewave Network Infrastructure Monitor",
        "version": version,
        "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "includes_history": bool(include_history),
        "settings": {r["key"]: r["value"] for r in _rows(c, "SELECT key, value FROM settings")},
        "hosts": hosts,
        "dash_ifaces": dash,
        "sia_accounts": _rows(c, "SELECT * FROM sia_accounts"),
    }
    if include_history:
        files = []
        root = os.path.join(data_dir or "", "backups")
        doc["history"] = {
            "results": _rows(c, "SELECT * FROM results"),
            "events": _rows(c, "SELECT * FROM events"),
            "snmp_state": _rows(c, "SELECT * FROM snmp_state"),
            "snmp_samples": _rows(c, "SELECT * FROM snmp_samples"),
            "cam_state": _rows(c, "SELECT * FROM cam_state"),
            "wan_samples": _rows(c, "SELECT * FROM wan_samples"),
            "wan_status": _rows(c, "SELECT * FROM wan_status"),
            "backups": _rows(c, "SELECT * FROM backups"),
            "files": files,
        }
        for row in doc["history"]["backups"]:
            for col in ("path", "bin_path"):
                path = row.get(col) or ""
                if path and os.path.isfile(path) and os.path.realpath(path).startswith(os.path.realpath(root) + os.sep):
                    with open(path, "rb") as fh:
                        raw = fh.read()
                    if len(raw) <= 8_000_000:
                        files.append({"host_id": row["host_id"], "name": os.path.basename(path), "b64": base64.b64encode(raw).decode()})
    return doc


def preview(doc):
    if not isinstance(doc, dict) or doc.get("format") != FORMAT:
        raise BackupError("This backup format is not supported by this version of the app.")
    if "settings" not in doc or "hosts" not in doc:
        raise BackupError("The backup is missing settings or hosts.")
    hist = doc.get("history") or {}
    return {
        "version": doc.get("version") or "",
        "created": doc.get("created") or "",
        "hosts": len(doc.get("hosts") or []),
        "settings": len(doc.get("settings") or {}),
        "graphs": len(doc.get("dash_ifaces") or []),
        "alarms": len(doc.get("sia_accounts") or []),
        "history": bool(doc.get("includes_history")),
        "events": len(hist.get("events") or []),
        "samples": len(hist.get("results") or []),
        "router_backups": len(hist.get("backups") or []),
    }


def _insert(c, table, row, columns):
    cols = [k for k in row.keys() if k in columns and k != "id"]
    if not cols:
        return
    sql = f"INSERT INTO {table}({','.join(cols)}) VALUES({','.join('?' * len(cols))})"
    c.execute(sql, [row[k] for k in cols])


def apply_document(c, doc, data_dir, known_settings, mode="merge"):
    """Apply a document. mode is 'merge' or 'replace' for hosts. Settings are always taken from the file."""
    info = preview(doc)
    if mode not in ("merge", "replace"):
        raise BackupError("Choose merge or replace.")
    cols = {r[1] for r in c.execute("PRAGMA table_info(hosts)")}
    existing = { _host_key(dict(r)): dict(r) for r in c.execute("SELECT * FROM hosts") }
    id_map = {}
    seen = set()
    for src in doc["hosts"]:
        key = _host_key(src)
        if not key:
            continue
        seen.add(key)
        fields = {k: src[k] for k in src.keys() if k in cols and k != "id"}
        cur = existing.get(key)
        if cur:
            sets = ", ".join(f"{k}=?" for k in fields)
            c.execute(f"UPDATE hosts SET {sets} WHERE id=?", [*fields.values(), cur["id"]])
            id_map[src.get("id")] = cur["id"]
        else:
            names = [k for k in fields]
            c.execute(f"INSERT INTO hosts({','.join(names)}) VALUES({','.join('?' * len(names))})", [fields[k] for k in names])
            id_map[src.get("id")] = c.execute("SELECT last_insert_rowid()").fetchone()[0]
    if mode == "replace":
        for key, row in existing.items():
            if key not in seen:
                hid = row["id"]
                for table in ("results", "snmp_state", "snmp_samples", "cam_state", "backups", "dash_ifaces"):
                    c.execute(f"DELETE FROM {table} WHERE host_id=?", (hid,))
                c.execute("DELETE FROM events WHERE host_id=?", (hid,))
                c.execute("DELETE FROM hosts WHERE id=?", (hid,))
    for key, value in (doc.get("settings") or {}).items():
        if key in known_settings:
            c.execute("INSERT OR REPLACE INTO settings(key, value) VALUES(?, ?)", (key, str(value)))
    if mode == "replace":
        c.execute("DELETE FROM dash_ifaces")
    host_by_addr = {_host_key(dict(r)): r["id"] for r in c.execute("SELECT id, host FROM hosts")}
    for graph in doc.get("dash_ifaces") or []:
        hid = host_by_addr.get((graph.get("host") or "").strip().lower())
        if not hid:
            continue
        c.execute("""INSERT INTO dash_ifaces(host_id, iface, color_in, color_out) VALUES(?,?,?,?)
                     ON CONFLICT(host_id, iface) DO UPDATE SET color_in=excluded.color_in, color_out=excluded.color_out""",
                  (hid, graph.get("iface") or "", graph.get("color_in") or "#16a34a", graph.get("color_out") or "#1d5fbf"))
    for acc in doc.get("sia_accounts") or []:
        if not acc.get("account"):
            continue
        c.execute("""INSERT INTO sia_accounts(account, name, panel, key_enc, supervise_min, last_ts, last_text, state, rest_state, offline_alerted, ts_mode)
                     VALUES(?,?,?,?,?,?,?,?,?,?,?)
                     ON CONFLICT(account) DO UPDATE SET name=excluded.name, panel=excluded.panel, key_enc=excluded.key_enc,
                     supervise_min=excluded.supervise_min, ts_mode=excluded.ts_mode""",
                  (acc["account"], acc.get("name") or acc["account"], acc.get("panel") or "other", acc.get("key_enc") or "",
                   int(acc.get("supervise_min") or 10), acc.get("last_ts"), acc.get("last_text") or "",
                   acc.get("state") or "unknown", acc.get("rest_state") or "unknown", int(acc.get("offline_alerted") or 0),
                   acc.get("ts_mode") or ""))
    if doc.get("includes_history") and doc.get("history"):
        _apply_history(c, doc["history"], id_map, data_dir, replace=mode == "replace")
    return info


def _apply_history(c, hist, id_map, data_dir, replace):
    def hid(old):
        return id_map.get(old)

    if replace:
        c.execute("DELETE FROM results")
        c.execute("DELETE FROM events")
        c.execute("DELETE FROM snmp_state")
        c.execute("DELETE FROM snmp_samples")
        c.execute("DELETE FROM cam_state")
        c.execute("DELETE FROM wan_samples")
        c.execute("DELETE FROM wan_status")
        c.execute("DELETE FROM backups")
    for row in hist.get("results") or []:
        new = hid(row.get("host_id"))
        if not new:
            continue
        c.execute("INSERT INTO results(host_id, ts, ok, ms, n, nok, g) VALUES(?,?,?,?,?,?,?)",
                  (new, row.get("ts"), row.get("ok"), row.get("ms"), row.get("n") or 1,
                   row.get("nok") if row.get("nok") is not None else row.get("ok"), row.get("g") or 0))
    for row in hist.get("events") or []:
        new = hid(row.get("host_id")) if row.get("host_id") else None
        c.execute("""INSERT INTO events(ts, source, kind, severity, host_id, host_name, host_ip, title, message, details, attachments)
                     VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                  (row.get("ts"), row.get("source"), row.get("kind"), row.get("severity"), new, row.get("host_name"),
                   row.get("host_ip"), row.get("title"), row.get("message"), row.get("details"), row.get("attachments")))
    for row in hist.get("snmp_state") or []:
        new = hid(row.get("host_id"))
        if new:
            c.execute("INSERT OR REPLACE INTO snmp_state(host_id, ts, data) VALUES(?,?,?)", (new, row.get("ts"), row.get("data")))
    for row in hist.get("snmp_samples") or []:
        new = hid(row.get("host_id"))
        if new:
            c.execute("INSERT INTO snmp_samples(host_id, ts, cpu, mem, ifs, temp, extra, g) VALUES(?,?,?,?,?,?,?,?)",
                      (new, row.get("ts"), row.get("cpu"), row.get("mem"), row.get("ifs"), row.get("temp"), row.get("extra") or "", row.get("g") or 0))
    for row in hist.get("cam_state") or []:
        new = hid(row.get("host_id"))
        if new:
            c.execute("INSERT OR REPLACE INTO cam_state(host_id, ts, data) VALUES(?,?,?)", (new, row.get("ts"), row.get("data")))
    for row in hist.get("wan_samples") or []:
        c.execute("INSERT INTO wan_samples(ts, target, loss, avg_ms, jitter, g) VALUES(?,?,?,?,?,?)",
                  (row.get("ts"), row.get("target"), row.get("loss"), row.get("avg_ms"), row.get("jitter"), row.get("g") or 0))
    for row in hist.get("wan_status") or []:
        c.execute("INSERT OR REPLACE INTO wan_status(id, state, since_ts, alerted, detail) VALUES(1,?,?,?,?)",
                  (row.get("state"), row.get("since_ts"), row.get("alerted") or 0, row.get("detail")))
    files_by_host = {}
    for item in hist.get("files") or []:
        files_by_host.setdefault(item.get("host_id"), []).append(item)
    for row in hist.get("backups") or []:
        new = hid(row.get("host_id"))
        if not new:
            continue
        folder = os.path.join(data_dir, "backups", str(new))
        os.makedirs(folder, mode=0o750, exist_ok=True)
        path = bin_path = ""
        for item in files_by_host.get(row.get("host_id"), []):
            dest = os.path.join(folder, os.path.basename(item.get("name") or "backup.bin"))
            with open(dest, "wb") as fh:
                fh.write(base64.b64decode(item.get("b64") or ""))
            os.chmod(dest, 0o640)
            if dest.endswith(".backup"):
                bin_path = dest
            else:
                path = dest
        c.execute("""INSERT INTO backups(host_id, ts, ok, error, path, bin_path, sha, changed, diff, bytes)
                     VALUES(?,?,?,?,?,?,?,?,?,?)""",
                  (new, row.get("ts"), row.get("ok"), row.get("error"), path or row.get("path") or "",
                   bin_path or row.get("bin_path") or "", row.get("sha"), row.get("changed") or 0, row.get("diff"), row.get("bytes")))


def loads(blob, secret):
    raw, _local = unseal(blob, secret)
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise BackupError("The backup could not be read after decryption.") from e
    preview(doc)
    return doc


def dumps(doc, secret, local=False):
    return seal(json.dumps(doc).encode("utf-8"), secret, local=local)


def config_dir(data_dir):
    path = os.path.join(data_dir, LOCAL_DIR)
    os.makedirs(path, mode=0o750, exist_ok=True)
    return path


def write_local(c, data_dir, version, installation_key):
    """Daily encrypted copy. Uses the installation key, not a typed passphrase."""
    folder = config_dir(data_dir)
    doc = build_document(c, data_dir, version, include_history=False)
    stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    path = os.path.join(folder, f"config-{stamp}.wwnim")
    with open(path, "wb") as fh:
        fh.write(dumps(doc, installation_key, local=True))
    os.chmod(path, 0o640)
    files = sorted(f for f in os.listdir(folder) if f.startswith("config-") and f.endswith(".wwnim"))
    while len(files) > KEEP_LOCAL:
        os.remove(os.path.join(folder, files.pop(0)))
    return path


def list_local(data_dir):
    folder = config_dir(data_dir)
    out = []
    for name in sorted(os.listdir(folder)):
        if not (name.startswith("config-") and name.endswith(".wwnim")):
            continue
        path = os.path.join(folder, name)
        out.append({"name": name, "path": path, "size": os.path.getsize(path), "mtime": os.path.getmtime(path)})
    return out


def local_due(data_dir, now=None):
    files = list_local(data_dir)
    if not files:
        return True
    newest = max(f["mtime"] for f in files)
    return (now or time.time()) - newest >= 20 * 3600
