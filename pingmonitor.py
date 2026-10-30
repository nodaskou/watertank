#!/usr/bin/env python3
"""
Wirewave Network Infrastructure Monitor - network, camera and alarm monitor for client sites.

 * Pings hosts (MikroTik, UniFi, Hikvision, Dahua, TP-Link/Omada, ...) every N seconds
 * Read-only dashboard (green / amber / red, latency, uptime, 24h graphs, events)
 * Admin settings page: hosts, site name, intervals, Telegram, SMTP e-mail,
   webhook, built-in SMTP receiver for camera/NVR/controller alert e-mails, API token
 * Alerts: Telegram, e-mail, generic JSON webhook (for Grok Bot / automations)
 * Token-protected JSON API: /api/status and /api/events
 * Everything stored in one SQLite file. Admin password asked on first run.

Run:  python3 pingmonitor.py [--host 127.0.0.1] [--port 8080] [--db pingmonitor.db]
      python3 pingmonitor.py --set-password      (set / reset admin password)
"""
import argparse
import asyncio
import base64
import getpass
import jobs
import mtbackup
import reportpdf
import siarecv
import wirelogic
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import platform
import re
import secrets
import shutil
import smtplib
import sqlite3
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import getaddresses
from functools import wraps
from html import unescape

try:
    from zoneinfo import ZoneInfo, available_timezones
except ImportError:  # pragma: no cover
    ZoneInfo = None

from flask import (Flask, Response, abort, flash, jsonify, redirect, render_template_string,
                   request, send_file, send_from_directory, session, url_for)

VERSION = "2.2"
APP_NAME = "Wirewave Network Infrastructure Monitor"
log = logging.getLogger("pingmonitor")
MOCK_TELEGRAM = os.environ.get("PINGMON_MOCK_TELEGRAM") == "1"

DB_PATH = None
DATA_DIR = None
SNAP_DIR = None

# ----------------------------------------------------------------------------- device presets
DEVICE_TYPES = {
    "generic":   ("Generic device", "IP", "#64748b"),
    "hikvision": ("Hikvision camera / NVR", "HIK", "#c8102e"),
    "dahua":     ("Dahua camera / NVR", "DAH", "#e05a00"),
    "mikrotik":  ("MikroTik router / switch", "MT", "#2d3748"),
    "airmax":    ("Ubiquiti airMAX / UISP", "UBNT", "#0559c9"),
    "unifi":     ("UniFi (AP / switch / gateway)", "UniFi", "#006fff"),
    "tplink":    ("TP-Link (standalone)", "TP", "#0b9fb3"),
    "omada":     ("TP-Link Omada", "Omada", "#00897b"),
    "starlink":  ("Starlink", "SL", "#111827"),
    "fortinet":  ("Fortinet FortiGate", "FG", "#ee3124"),
    "pbx":       ("Phone system / PBX", "PBX", "#7c3aed"),
    "server":    ("PC / server / NVR software", "PC", "#475569"),
    "printer":   ("Printer", "PRN", "#a16207"),
    "ups":       ("UPS", "UPS", "#b45309"),
}

# ----------------------------------------------------------------------------- settings
DEFAULTS = {
    "site_name": "CLIENT-NAME",
    "timezone": "Europe/Athens",
    "public_url": "",
    "ping_interval": 60,
    "ping_timeout": 2,
    "fail_threshold": 3,
    "repeat_min": 30,
    "retention_days": 30,
    "ping_method": "auto",
    "dashboard_access": "login",          # login | public
    "viewer_hash": "",
    "admin_hash": "",
    "secret_key": "",
    "api_token": "",
    "telegram_enabled": 0, "telegram_token": "", "telegram_chat_id": "", "telegram_photos": 1,
    "email_enabled": 0, "smtp_host": "", "smtp_port": 587, "smtp_security": "starttls",
    "smtp_user": "", "smtp_password": "", "smtp_from": "", "smtp_to": "",
    "webhook_enabled": 0, "webhook_url": "", "webhook_header_name": "Authorization",
    "webhook_header_value": "",
    "rx_enabled": 0, "rx_host": "0.0.0.0", "rx_port": 2525, "rx_security": "none",  # none|starttls|ssl
    "rx_require_auth": 0, "rx_user": "alerts", "rx_password": "",
    "rx_allowed_nets": "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, 100.64.0.0/10",
    "rx_forward_min": "warning",          # info|warning|critical|none
    "rx_rate_limit": 300,
    # SNMP polling (per host config is stored with the host) + trap receiver
    "snmp_enabled": 1, "snmp_interval": 300, "snmp_timeout": 2, "snmp_cpu_threshold": 90,
    "snmp_alert_ifdown": 1, "snmp_alert_reboot": 1, "snmp_forward_min": "warning",
    "trap_enabled": 0, "trap_host": "0.0.0.0", "trap_port": 1162, "trap_community": "", "trap_forward_min": "warning",
    "quiet_start": "", "quiet_end": "", "quiet_critical": 1,
    "maintenance_until": 0,
    "cam_interval": 900,
    "snmp_temp_threshold": 75, "snmp_util_threshold": 80,
    "wan_enabled": 1, "wan_targets": "1.1.1.1, 8.8.8.8", "wan_loss_pct": 20, "wan_latency_ms": 200, "wan_count": 5,
    "mt_backup_day": 0, "mt_backup_time": "03:00", "mt_backup_keep": 52,
    "ups_runtime_min": 10, "ups_load_pct": 80,
    "event_keep": 100,
    "public_ip": "", "public_ip_isp": "", "public_ip_at": 0,
    "sia_enabled": 0, "sia_host": "0.0.0.0", "sia_port": 12128, "sia_tcp": 1, "sia_udp": 1,
}
INT_KEYS = {k for k, v in DEFAULTS.items() if isinstance(v, int)}
SECRET_KEYS = {"telegram_token", "smtp_password", "webhook_header_value", "rx_password"}
SEVERITY_RANK = {"info": 1, "warning": 2, "critical": 3, "none": 99}

_db_lock = threading.RLock()


class _Conn(sqlite3.Connection):
    """`with db() as c:` commits (or rolls back) and then closes the connection."""
    def __exit__(self, et, ev, tb):
        try:
            return super().__exit__(et, ev, tb)
        finally:
            self.close()


def db():
    conn = sqlite3.connect(DB_PATH, timeout=30, factory=_Conn)
    conn.row_factory = sqlite3.Row
    return conn


def _cols(c, table):
    return {r[1] for r in c.execute(f"PRAGMA table_info({table})")}


def _add_col(c, table, name, decl):
    if name not in _cols(c, table):
        c.execute(f"ALTER TABLE {table} ADD COLUMN {name} {decl}")


def _migrate(c):
    """Add columns and tables used by later versions. Existing rows keep working."""
    _add_col(c, "hosts", "fail_n", "INTEGER NOT NULL DEFAULT 0")
    _add_col(c, "hosts", "repeat_min", "INTEGER NOT NULL DEFAULT -1")
    _add_col(c, "hosts", "ping_every", "INTEGER NOT NULL DEFAULT 0")
    _add_col(c, "hosts", "last_alert", "REAL NOT NULL DEFAULT 0")
    _add_col(c, "hosts", "maint_until", "REAL NOT NULL DEFAULT 0")
    had_alert = "alerted_down" in _cols(c, "hosts")
    _add_col(c, "hosts", "alerted_down", "INTEGER NOT NULL DEFAULT 0")
    if not had_alert:
        c.execute("UPDATE hosts SET alerted_down=1 WHERE state='down'")
    _add_col(c, "hosts", "cam", "TEXT NOT NULL DEFAULT ''")
    _add_col(c, "hosts", "mtbak", "TEXT NOT NULL DEFAULT ''")
    _add_col(c, "results", "n", "INTEGER NOT NULL DEFAULT 1")
    if "nok" not in _cols(c, "results"):
        c.execute("ALTER TABLE results ADD COLUMN nok INTEGER")
        c.execute("UPDATE results SET nok=ok WHERE nok IS NULL")
    _add_col(c, "results", "g", "INTEGER NOT NULL DEFAULT 0")
    _add_col(c, "snmp_samples", "temp", "REAL")
    _add_col(c, "snmp_samples", "extra", "TEXT NOT NULL DEFAULT ''")
    _add_col(c, "snmp_samples", "g", "INTEGER NOT NULL DEFAULT 0")
    c.executescript("""
        CREATE TABLE IF NOT EXISTS cam_state(host_id INTEGER PRIMARY KEY, ts REAL, data TEXT);
        CREATE TABLE IF NOT EXISTS wan_samples(
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, target TEXT NOT NULL,
            loss REAL, avg_ms REAL, jitter REAL, g INTEGER NOT NULL DEFAULT 0);
        CREATE INDEX IF NOT EXISTS idx_wan_ts ON wan_samples(ts);
        CREATE TABLE IF NOT EXISTS wan_status(
            id INTEGER PRIMARY KEY CHECK(id=1), state TEXT, since_ts REAL,
            alerted INTEGER NOT NULL DEFAULT 0, detail TEXT);
        CREATE TABLE IF NOT EXISTS alert_queue(
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, severity TEXT, subject TEXT, body TEXT, payload TEXT);
        CREATE TABLE IF NOT EXISTS backups(
            id INTEGER PRIMARY KEY AUTOINCREMENT, host_id INTEGER NOT NULL, ts REAL NOT NULL,
            ok INTEGER NOT NULL, error TEXT, path TEXT, bin_path TEXT, sha TEXT,
            changed INTEGER NOT NULL DEFAULT 0, diff TEXT, bytes INTEGER);
        CREATE TABLE IF NOT EXISTS dash_ifaces(
            host_id INTEGER NOT NULL, iface TEXT NOT NULL,
            color_in TEXT NOT NULL DEFAULT '#16a34a', color_out TEXT NOT NULL DEFAULT '#1d5fbf',
            PRIMARY KEY(host_id, iface));
        CREATE TABLE IF NOT EXISTS sia_accounts(
            account TEXT PRIMARY KEY, name TEXT NOT NULL, panel TEXT NOT NULL DEFAULT 'ajax',
            key_enc TEXT NOT NULL DEFAULT '', supervise_min INTEGER NOT NULL DEFAULT 10,
            last_ts REAL, last_text TEXT NOT NULL DEFAULT '', state TEXT NOT NULL DEFAULT 'unknown',
            rest_state TEXT NOT NULL DEFAULT 'unknown', offline_alerted INTEGER NOT NULL DEFAULT 0);
    """)


def init_db():
    with _db_lock, db() as c:
        c.execute("PRAGMA journal_mode=WAL")
        c.executescript("""
        CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
        CREATE TABLE IF NOT EXISTS hosts(
            id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, host TEXT NOT NULL,
            grp TEXT NOT NULL DEFAULT '', device_type TEXT NOT NULL DEFAULT 'generic',
            enabled INTEGER NOT NULL DEFAULT 1, state TEXT NOT NULL DEFAULT 'pending',
            consec_fail INTEGER NOT NULL DEFAULT 0, last_ms REAL, last_check REAL,
            last_seen REAL, down_since REAL, created_at REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS results(host_id INTEGER NOT NULL, ts REAL NOT NULL,
            ok INTEGER NOT NULL, ms REAL);
        CREATE INDEX IF NOT EXISTS idx_results ON results(host_id, ts);
        CREATE TABLE IF NOT EXISTS events(
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, source TEXT NOT NULL,
            kind TEXT NOT NULL, severity TEXT NOT NULL, host_id INTEGER, host_name TEXT,
            host_ip TEXT, title TEXT, message TEXT, details TEXT, attachments TEXT);
        CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
        CREATE TABLE IF NOT EXISTS snmp_state(host_id INTEGER PRIMARY KEY, ts REAL, data TEXT);
        CREATE TABLE IF NOT EXISTS snmp_samples(host_id INTEGER NOT NULL, ts REAL NOT NULL, cpu REAL, mem REAL, ifs TEXT);
        CREATE INDEX IF NOT EXISTS idx_snmp_samples ON snmp_samples(host_id, ts);
        """)
        cols = {r[1] for r in c.execute("PRAGMA table_info(hosts)")}
        if "snmp" not in cols:   # upgrade from 2.0
            c.execute("ALTER TABLE hosts ADD COLUMN snmp TEXT NOT NULL DEFAULT ''")
        _migrate(c)
        for k, v in DEFAULTS.items():
            c.execute("INSERT OR IGNORE INTO settings(key, value) VALUES(?, ?)", (k, str(v)))
        for k in ("secret_key", "api_token"):
            if not c.execute("SELECT value FROM settings WHERE key=?", (k,)).fetchone()[0]:
                c.execute("UPDATE settings SET value=? WHERE key=?", (secrets.token_urlsafe(32), k))


def get_settings():
    with db() as c:
        raw = {r["key"]: r["value"] for r in c.execute("SELECT key, value FROM settings")}
    s = {}
    for k, d in DEFAULTS.items():
        v = raw.get(k, str(d))
        if k in INT_KEYS:
            try:
                v = int(v)
            except (TypeError, ValueError):
                v = d
        s[k] = v
    return s


def set_settings(**kv):
    with _db_lock, db() as c:
        for k, v in kv.items():
            if k not in DEFAULTS:
                raise KeyError(k)
            c.execute("INSERT OR REPLACE INTO settings(key, value) VALUES(?, ?)", (k, str(v)))


def _fernet():
    from cryptography.fernet import Fernet
    key = base64.urlsafe_b64encode(hashlib.sha256(get_settings()["secret_key"].encode()).digest())
    return Fernet(key)


def encrypt_secret(plain):
    if not plain:
        return ""
    return "enc:" + _fernet().encrypt(plain.encode()).decode()


def decrypt_secret(stored):
    if not stored:
        return ""
    if not str(stored).startswith("enc:"):
        return stored
    try:
        return _fernet().decrypt(str(stored)[4:].encode()).decode()
    except Exception:
        return ""


def minute_now(now=None):
    local = datetime.fromtimestamp(now or time.time(), tzinfo())
    return local.hour * 60 + local.minute


def global_maint(s, now=None):
    return int(s.get("maintenance_until") or 0) > (now or time.time())


def host_maint(h, s, now=None):
    now = now or time.time()
    if global_maint(s, now):
        return True
    return bool(h) and float(h.get("maint_until") or 0) > now


def is_quiet(s, now=None):
    return wirelogic.in_quiet(s.get("quiet_start"), s.get("quiet_end"), minute_now(now))


def fail_limit(h, s):
    n = int(h.get("fail_n") or 0)
    return n if n > 0 else max(1, int(s["fail_threshold"]))


def repeat_minutes(h, s):
    """Minutes between repeat DOWN alerts. Host -1 uses the global value. 0 means never."""
    raw = h.get("repeat_min")
    n = int(s.get("repeat_min") or 0) if raw is None or int(raw) < 0 else int(raw)
    return max(0, n)


def ping_seconds(h, s):
    """Seconds between pings. 0 on the host uses the global interval."""
    n = int(h.get("ping_every") or 0)
    return n if n >= 10 else max(10, int(s["ping_interval"]))


def consider_notify(s, host, severity, subject, text, payload):
    """Send, queue for quiet hours, or drop while maintenance is on."""
    now = time.time()
    if host_maint(host, s, now) or (host is None and global_maint(s, now)):
        return "suppressed"
    if is_quiet(s, now) and not (severity == "critical" and s.get("quiet_critical")):
        with _db_lock, db() as c:
            c.execute("INSERT INTO alert_queue(ts, severity, subject, body, payload) VALUES(?,?,?,?,?)",
                      (now, severity, subject, text, json.dumps(payload)))
        return "queued"
    notify(subject, text, payload)
    return "sent"


SPANS = {"12h": 12 * 3600, "24h": 86400, "7d": 7 * 86400, "30d": 30 * 86400}
SPAN_LABEL = {"12h": "12 hours", "24h": "24 hours", "7d": "7 days", "30d": "30 days"}


def current_span():
    span = request.args.get("span", "24h")
    if span not in SPANS:
        span = "24h"
    return span, SPANS[span]


def local_input_to_ts(text):
    text = (text or "").strip()
    if not text:
        return 0
    try:
        dt = datetime.strptime(text[:16], "%Y-%m-%dT%H:%M")
    except ValueError:
        raise ValueError("use the date and time picker")
    return dt.replace(tzinfo=tzinfo()).timestamp()


def ts_to_local_input(ts):
    if not ts:
        return ""
    return datetime.fromtimestamp(float(ts), tzinfo()).strftime("%Y-%m-%dT%H:%M")


# ----------------------------------------------------------------------------- passwords
def hash_password(pw):
    salt = os.urandom(16)
    n, r, p = 2 ** 14, 8, 1
    dk = hashlib.scrypt(pw.encode(), salt=salt, n=n, r=r, p=p, dklen=32)
    return f"scrypt${n}${r}${p}${salt.hex()}${dk.hex()}"


def verify_password(pw, stored):
    try:
        algo, n, r, p, salt, dk = stored.split("$")
        if algo != "scrypt":
            return False
        test = hashlib.scrypt(pw.encode(), salt=bytes.fromhex(salt), n=int(n), r=int(r),
                              p=int(p), dklen=len(dk) // 2)
        return hmac.compare_digest(test.hex(), dk)
    except Exception:
        return False


def prompt_new_password(from_stdin=False):
    if from_stdin:
        pw = sys.stdin.readline().rstrip("\r\n")
        if len(pw) < 8:
            sys.exit("Password must be at least 8 characters")
        return pw
    print(f"=== {APP_NAME} - set admin password ===")
    for _ in range(3):
        pw = getpass.getpass("New admin password (min 8 chars): ")
        if len(pw) < 8:
            print("Too short, try again.")
            continue
        if getpass.getpass("Repeat password: ") != pw:
            print("Passwords do not match, try again.")
            continue
        return pw
    sys.exit("Password not set.")


# ----------------------------------------------------------------------------- time helpers
def tzinfo():
    try:
        return ZoneInfo(get_settings()["timezone"])
    except Exception:
        return timezone.utc


def iso(ts, tz=None):
    if not ts:
        return None
    return datetime.fromtimestamp(ts, tz or tzinfo()).isoformat(timespec="seconds")


def fmt_ts(ts, tz=None):
    if not ts:
        return "never"
    return datetime.fromtimestamp(ts, tz or tzinfo()).strftime("%Y-%m-%d %H:%M:%S")


def fmt_dur(sec):
    sec = int(sec or 0)
    d, sec = divmod(sec, 86400)
    h, sec = divmod(sec, 3600)
    m, s = divmod(sec, 60)
    return (f"{d}d " if d else "") + (f"{h}h " if h or d else "") + f"{m}m {s}s"


def parse_since(v):
    """epoch seconds, ISO-8601 (2026-10-30T22:00:00+02:00) or relative: 30m, 2h, 1d."""
    if not v:
        return 0.0
    rel = re.fullmatch(r"\s*(\d+)\s*([smhd])\s*", v)
    if rel:
        return time.time() - int(rel.group(1)) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[rel.group(2)]
    try:
        return float(v)
    except ValueError:
        pass
    try:
        dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=tzinfo())
        return dt.timestamp()
    except ValueError:
        abort(400, "since must be epoch seconds, ISO-8601 or relative like 30m / 2h / 1d")


# ----------------------------------------------------------------------------- ping
HOST_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9.\-:]*[A-Za-z0-9])?$")
_ping_impl = {"key": None, "name": None, "fn": None}


def parse_ping_output(out, rc, system="linux"):
    """(ok, ms) from ping output; handles localized Windows output."""
    if system == "windows":
        for line in out.splitlines():
            if "TTL=" in line.upper():
                m = re.search(r"[=<]\s*(\d+(?:[.,]\d+)?)\s*ms", line, re.I)
                return True, float(m.group(1).replace(",", ".")) if m else 0.5
        return False, None
    if rc != 0:
        return False, None
    m = re.search(r"time[=<]\s*(\d+(?:\.\d+)?)\s*ms", out)
    return True, (float(m.group(1)) if m else None)


def _ping_system(host, timeout):
    system = platform.system().lower()
    flags = 0
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), host]
        flags = 0x08000000
    elif system == "darwin":
        cmd = ["ping", "-c", "1", "-W", str(int(timeout * 1000)), host]
    else:
        cmd = ["ping", "-n", "-c", "1", "-W", str(max(1, int(round(timeout)))), host]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 3, creationflags=flags)
    except (subprocess.TimeoutExpired, OSError):
        return False, None
    return parse_ping_output(p.stdout, p.returncode, system)


def _icmplib(privileged):
    from icmplib import ping as icmp_ping

    def _p(host, timeout):
        try:
            r = icmp_ping(host, count=1, timeout=timeout, privileged=privileged)
            return (True, round(r.avg_rtt, 2)) if r.is_alive else (False, None)
        except Exception as e:
            log.debug("icmplib %s: %s", host, e)
            return False, None
    return _p


def get_pinger(method):
    if _ping_impl["key"] == method and _ping_impl["fn"]:
        return _ping_impl
    cands = []
    if method in ("auto", "icmplib"):
        try:
            import icmplib  # noqa: F401
            cands += [("icmplib-unprivileged", _icmplib(False), False),
                      ("icmplib-privileged", _icmplib(True), True)]
        except ImportError:
            pass
    if method in ("auto", "system") and shutil.which("ping"):
        cands.append(("system-ping", _ping_system, None))
    for name, fn, priv in cands:
        if priv is not None:
            try:
                from icmplib import ping as icmp_ping
                icmp_ping("127.0.0.1", count=1, timeout=1, privileged=priv)
            except Exception as e:
                log.info("%s not usable: %s", name, e)
                continue
        log.info("Ping method: %s", name)
        _ping_impl.update(key=method, name=name, fn=fn)
        return _ping_impl
    raise RuntimeError("No usable ping method (install iputils-ping or grant CAP_NET_RAW)")


# ----------------------------------------------------------------------------- notifications
def _http_post(url, data, headers, timeout=15):
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, r.read(2000)


def send_telegram(s, text, photo_path=None):
    if MOCK_TELEGRAM:
        log.info("[MOCK TELEGRAM] chat=%s photo=%s text=%s", s["telegram_chat_id"],
                 os.path.basename(photo_path) if photo_path else None, text.replace("\n", " / "))
        return
    if not s["telegram_token"] or not s["telegram_chat_id"]:
        raise RuntimeError("Telegram bot token / chat id not set")
    base = f"https://api.telegram.org/bot{s['telegram_token']}"
    if photo_path and os.path.exists(photo_path):
        boundary = uuid.uuid4().hex
        with open(photo_path, "rb") as f:
            img = f.read()
        parts = []
        for k, v in (("chat_id", s["telegram_chat_id"]), ("caption", text[:1024])):
            parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode())
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="photo"; filename="snapshot.jpg"\r\n'
                     f'Content-Type: image/jpeg\r\n\r\n'.encode() + img + b"\r\n")
        parts.append(f"--{boundary}--\r\n".encode())
        _http_post(base + "/sendPhoto", b"".join(parts), {"Content-Type": f"multipart/form-data; boundary={boundary}"})
    else:
        data = urllib.parse.urlencode({"chat_id": s["telegram_chat_id"], "text": text[:4000]}).encode()
        _http_post(base + "/sendMessage", data, {"Content-Type": "application/x-www-form-urlencoded"})


def send_email(s, subject, text):
    to = [a.strip() for a in s["smtp_to"].replace(";", ",").split(",") if a.strip()]
    if not s["smtp_host"] or not to:
        raise RuntimeError("SMTP server / recipients not set")
    msg = EmailMessage()
    msg["Subject"] = subject
    addr = s["smtp_from"] or s["smtp_user"] or "monitor@localhost"
    msg["From"] = addr if "<" in addr else f"{APP_NAME} <{addr}>"
    msg["To"] = ", ".join(to)
    msg.set_content(text)
    ctx = ssl.create_default_context()
    port = int(s["smtp_port"])
    if s["smtp_security"] == "ssl":
        srv = smtplib.SMTP_SSL(s["smtp_host"], port, timeout=20, context=ctx)
    else:
        srv = smtplib.SMTP(s["smtp_host"], port, timeout=20)
    with srv:
        srv.ehlo()
        if s["smtp_security"] == "starttls":
            srv.starttls(context=ctx)
            srv.ehlo()
        if s["smtp_user"]:
            srv.login(s["smtp_user"], s["smtp_password"])
        srv.send_message(msg)


def send_webhook(s, payload):
    if not s["webhook_url"].startswith(("http://", "https://")):
        raise RuntimeError("Webhook URL must start with http:// or https://")
    headers = {"Content-Type": "application/json", "User-Agent": f"WirewaveNetworkInfrastructureMonitor/{VERSION}",
               "X-PingMonitor-Event": payload["event"]}
    if s["webhook_header_name"] and s["webhook_header_value"]:
        headers[s["webhook_header_name"]] = s["webhook_header_value"]
    status, _ = _http_post(s["webhook_url"], json.dumps(payload, ensure_ascii=False).encode(), headers)
    if status >= 300:
        raise RuntimeError(f"HTTP {status}")


def build_payload(s, event, ev_id=None, host=None, state=None, down_since=None, downtime=None,
                  fails=None, latency=None, severity="info", message="", alert=None, ts=None):
    ts = ts or time.time()
    tz = tzinfo()
    base = s["public_url"].rstrip("/")
    return {
        "event": event,                     # host_down | host_recovered | device_alert | test
        "event_id": ev_id,
        "site": s["site_name"],
        "timestamp": iso(ts, tz),
        "timezone": s["timezone"],
        "severity": severity,               # info | warning | critical
        "host": None if not host else {
            "id": host.get("id"), "name": host.get("name"), "ip": host.get("host"),
            "group": host.get("grp") or None, "device_type": host.get("device_type") or "generic"},
        "state": state,                     # down | up | null
        "down_since": iso(down_since, tz) if down_since else None,
        "downtime_seconds": int(downtime) if downtime is not None else None,
        "downtime": fmt_dur(downtime) if downtime is not None else None,
        "consecutive_failures": fails,
        "latency_ms": latency,
        "alert": alert,                     # only for device_alert (e-mail from a device)
        "message": message,
        "dashboard_url": (f"{base}/host/{host['id']}" if host and host.get("id") else base or None) if base else None,
    }


def notify(subject, text, payload, photo=None, sync=False):
    """Send to all enabled channels. Async with retries unless sync=True."""
    if APP_NAME not in subject:
        subject = f"{APP_NAME}: {subject}"
    if APP_NAME not in text[:120]:
        text = APP_NAME + "\n" + text
    s = get_settings()
    jobs = []
    if s["telegram_enabled"]:
        jobs.append(("telegram", lambda: send_telegram(s, text, photo if s["telegram_photos"] else None)))
    if s["email_enabled"]:
        jobs.append(("email", lambda: send_email(s, subject, text)))
    if s["webhook_enabled"]:
        jobs.append(("webhook", lambda: send_webhook(s, payload)))

    def run():
        for name, fn in jobs:
            for attempt in range(3):
                try:
                    fn()
                    log.info("%s alert sent: %s", name, subject)
                    break
                except Exception as e:
                    log.error("%s alert failed (try %d): %s", name, attempt + 1, e)
                    time.sleep(3 * (attempt + 1))
    if sync:
        run()
    else:
        threading.Thread(target=run, daemon=True).start()


def add_event(source, kind, severity, host=None, title="", message="", details=None, attachments=None, ts=None, conn=None):
    if conn is None:
        with _db_lock, db() as c:
            return add_event(source, kind, severity, host, title, message, details, attachments, ts, conn=c)
    cur = conn.execute(
        "INSERT INTO events(ts, source, kind, severity, host_id, host_name, host_ip, title, message, details, attachments)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        (ts or time.time(), source, kind, severity, host["id"] if host else None,
         host["name"] if host else None, host["host"] if host else None, title, message,
         json.dumps(details or {}, ensure_ascii=False), json.dumps(attachments or [])))
    try:
        jobs.trim_events(sys.modules[__name__], conn)
    except Exception:
        log.debug("event trim skipped", exc_info=True)
    return cur.lastrowid


# ----------------------------------------------------------------------------- monitor
def monitor_cycle(pool):
    s = get_settings()
    pinger = get_pinger(s["ping_method"])
    with db() as c:
        hosts = [dict(r) for r in c.execute("SELECT * FROM hosts WHERE enabled=1")]
    if not hosts:
        return
    timeout = float(s["ping_timeout"])
    now = time.time()
    due = []
    for h in hosts:
        last = h.get("last_check") or 0
        if not last or now - last >= ping_seconds(h, s) - 1:
            due.append(h)
    if not due:
        return
    results = list(pool.map(lambda h: (h, *pinger["fn"](h["host"], timeout)), due))
    site = s["site_name"]
    with _db_lock, db() as c:
        for h, ok, ms in results:
            fresh = c.execute("SELECT * FROM hosts WHERE id=? AND enabled=1", (h["id"],)).fetchone()
            if not fresh:
                continue
            h = dict(fresh)
            threshold = fail_limit(h, s)
            c.execute("INSERT INTO results(host_id, ts, ok, ms, n, nok, g) VALUES(?,?,?,?,1,?,0)",
                      (h["id"], now, int(ok), ms, 1 if ok else 0))
            label = f"{h['name']} ({h['host']})"
            if ok:
                if h["state"] == "down" and h.get("alerted_down"):
                    downtime = now - (h["down_since"] or now)
                    msg = f"{label} is back UP ({ms} ms) after {fmt_dur(downtime)} down."
                    eid = add_event("ping", "host_recovered", "info", h, "Recovered", msg, {"downtime_seconds": int(downtime)}, ts=now, conn=c)
                    text = f"✅ RECOVERED [{site}]\n{label} is back UP ({ms} ms)\nDowntime: {fmt_dur(downtime)}\n{fmt_ts(now)}"
                    consider_notify(s, h, "info", f"[{site}] RECOVERED: {h['name']}", text,
                                    build_payload(s, "host_recovered", eid, h, "up", h["down_since"], downtime, 0, ms, "info", msg, ts=now))
                c.execute("UPDATE hosts SET state='up', consec_fail=0, last_ms=?, last_check=?, last_seen=?, down_since=NULL, alerted_down=0, last_alert=0 WHERE id=?",
                          (ms, now, now, h["id"]))
            else:
                fails = h["consec_fail"] + 1
                state, down_since = h["state"], h["down_since"]
                alerted = h.get("alerted_down") or 0
                last_alert = h.get("last_alert") or 0
                if fails >= threshold and state != "down":
                    state, down_since = "down", now
                    msg = f"{label} is not responding ({fails} failed pings in a row). Last seen: {fmt_ts(h['last_seen'])}."
                    eid = add_event("ping", "host_down", "critical", h, "Down", msg, {"consecutive_failures": fails}, ts=now, conn=c)
                    text = (f"🔴 DOWN [{site}]\n{label} is not responding ({fails} failed pings in a row)\n"
                            f"Last seen: {fmt_ts(h['last_seen'])}\n{fmt_ts(now)}")
                    how = consider_notify(s, h, "critical", f"[{site}] DOWN: {h['name']}", text,
                                          build_payload(s, "host_down", eid, h, "down", now, 0, fails, None, "critical", msg, ts=now))
                    alerted = 1 if how in ("sent", "queued") else 0
                    last_alert = now if alerted else 0
                elif state == "down":
                    every = repeat_minutes(h, s)
                    if alerted and every > 0 and last_alert and now - last_alert >= every * 60:
                        msg = f"{label} is still DOWN ({fmt_dur(now - (down_since or now))})."
                        eid = add_event("ping", "host_down_repeat", "critical", h, "Still down", msg,
                                        {"consecutive_failures": fails}, ts=now, conn=c)
                        text = f"🔴 STILL DOWN [{site}]\n{msg}\n{fmt_ts(now)}"
                        consider_notify(s, h, "critical", f"[{site}] STILL DOWN: {h['name']}", text,
                                        build_payload(s, "host_down", eid, h, "down", down_since, now - (down_since or now),
                                                      fails, None, "critical", msg, ts=now))
                        last_alert = now
                elif state != "down":
                    state = "warn"
                c.execute("UPDATE hosts SET state=?, consec_fail=?, last_check=?, last_ms=NULL, down_since=?, alerted_down=?, last_alert=? WHERE id=?",
                          (state, fails, now, down_since, alerted, last_alert, h["id"]))


def refresh_public_ip():
    """Learn the WAN address every 10 minutes and note when the provider changes it."""
    s = get_settings()
    ip = ""
    for url in ("https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "curl/8.0"})
            ip = urllib.request.urlopen(req, timeout=6).read().decode("utf-8", "replace").strip().split()[0]
            if ip and len(ip) <= 64:
                break
            ip = ""
        except Exception:
            ip = ""
    isp = ""
    if ip:
        try:
            req = urllib.request.Request("https://ipinfo.io/" + ip + "/json",
                                         headers={"User-Agent": "curl/8.0", "Accept": "application/json"})
            info = json.loads(urllib.request.urlopen(req, timeout=6).read().decode("utf-8", "replace"))
            isp = str(info.get("org") or "")[:80]
        except Exception:
            isp = s.get("public_ip_isp") or ""
    prev = s.get("public_ip") or ""
    set_settings(public_ip=ip or prev, public_ip_isp=isp, public_ip_at=int(time.time()))
    if prev and ip and prev != ip:
        msg = f"Public IP changed from {prev} to {ip}" + (f" ({isp})" if isp else "") + "."
        add_event("wan", "public_ip_change", "info", None, "Public IP changed", msg, {"old": prev, "new": ip, "isp": isp})
        consider_notify(s, None, "info", f"[{s['site_name']}] Public IP changed", msg,
                        build_payload(s, "public_ip_change", None, None, severity="info", message=msg))


def _alarm_rows(tz):
    try:
        with db() as c:
            rows = c.execute("SELECT * FROM sia_accounts ORDER BY name").fetchall()
    except Exception:
        return []
    return [{"name": r["name"], "panel": r["panel"], "account": r["account"], "state": r["state"] or "unknown",
             "last_text": r["last_text"] or ""} for r in rows]


def _status_bar(hosts, wan, alarms):
    s = get_settings()
    latencies, losses = [], []
    if wan and wan.get("targets"):
        for target in wan["targets"]:
            if isinstance(target, dict) and target.get("avg_ms") is not None:
                latencies.append(target["avg_ms"])
            if isinstance(target, dict) and target.get("loss") is not None:
                losses.append(target["loss"])
    reasons, level = [], "ok"

    def worse(new):
        nonlocal level
        if {"ok": 0, "warn": 1, "bad": 2}[new] > {"ok": 0, "warn": 1, "bad": 2}[level]:
            level = new

    if wan and wan.get("state") == "down":
        reasons.append("Internet down")
        worse("bad")
    elif wan and wan.get("state") == "degraded":
        reasons.append("High latency or packet loss")
        worse("warn")
    down = [h for h in hosts if h["state"] == "down" and not h.get("maint")]
    if down:
        reasons.append(f"{len(down)} device" + ("s" if len(down) != 1 else "") + " down")
        worse("bad")
    if global_maint(s) or any(h.get("maint") for h in hosts):
        reasons.append("Maintenance")
        worse("warn")
    for h in hosts:
        ups = ((h.get("sn") or {}).get("ups") or {})
        if ups.get("on_battery"):
            reasons.append("UPS on battery")
            worse("bad")
            break
    for alarm in alarms or []:
        if alarm.get("state") == "alarm":
            reasons.append("Alarm: " + (alarm.get("last_text") or alarm.get("name") or "panel")[:48])
            worse("bad")
        elif alarm.get("state") == "offline":
            reasons.append("Panel offline: " + alarm.get("name", ""))
            worse("bad")
    return {
        "level": level,
        "reason": " · ".join(reasons) if reasons else "All clear",
        "latency": round(sum(latencies) / len(latencies), 1) if latencies else None,
        "loss": round(sum(losses) / len(losses), 1) if losses else None,
        "ip": s.get("public_ip") or "",
        "isp": s.get("public_ip_isp") or "",
        "checked": fmt_ts(s.get("public_ip_at"), tzinfo()) if s.get("public_ip_at") else "—",
    }


def prune():
    """Roll recent samples into 5-minute and hourly buckets, then cap the event log."""
    try:
        jobs.rollup(sys.modules[__name__])
    except Exception:
        log.exception("history rollup failed")
    with db() as c:
        c.execute("PRAGMA optimize")
    log.info("History rollup finished (raw 2 days, 5 min to 7 days, hourly after that)")


def monitor_loop(stop):
    last_prune = 0
    me = sys.modules[__name__]
    with ThreadPoolExecutor(max_workers=16) as pool:
        while not stop.is_set():
            start = time.time()
            try:
                monitor_cycle(pool)
                try:
                    jobs.wan_probe(me)
                    jobs.flush_quiet(me)
                    jobs.camera_poll(me)
                    jobs.backup_scheduled(me)
                except Exception:
                    log.exception("extra monitor jobs failed")
                if start - last_prune > 900:
                    prune()
                    last_prune = start
            except Exception:
                log.exception("monitor cycle failed")
            s = get_settings()
            interval = max(5, int(s["ping_interval"]))
            try:
                with db() as c:
                    for (n,) in c.execute("SELECT ping_every FROM hosts WHERE enabled=1 AND ping_every>=10"):
                        interval = min(interval, int(n))
                if start - int(s.get("public_ip_at") or 0) >= 600:
                    refresh_public_ip()
                sia_supervise()
            except Exception:
                log.exception("schedule lookup failed")
            stop.wait(max(1, interval - (time.time() - start)))


# ----------------------------------------------------------------------------- incoming e-mail (SMTP receiver)
# Classification rules, checked in order against "subject + body". (regex, type, severity, title)
MAIL_RULES = [
    (r"test\s*(mail|e-?mail|message)|this\s+is\s+a\s+test|smtp\s+test|email\s+test", "test", "info", "Test e-mail"),
    (r"(hdd|disk|storage|sd\s*card)\s*(is\s*)?full|disk\s*full|no\s+(free\s+)?space|storage\s+space\s+(is\s+)?(full|insufficient)",
     "disk_full", "critical", "Disk full"),
    (r"(hdd|hard\s*disk|disk|storage|sd\s*card)\s*(error|fail|failure|abnormal|exception|unformatted)|no\s+(hdd|disk)\b|hdd\s+not\s+found|disk\s+no\s+exist",
     "hdd_error", "critical", "Disk error"),
    (r"video\s*(signal\s*)?loss|video\s*lost|signal\s*loss|no\s+video", "video_loss", "critical", "Video loss"),
    (r"video\s*tamper|tamper(ing)?\s*(detect|alarm)?|video\s*blind|camera\s*mask|lens\s*(covered|blocked)|scene\s*change",
     "tamper", "warning", "Camera tampering"),
    (r"ip\s*(address\s*)?conflict", "ip_conflict", "critical", "IP address conflict"),
    (r"network\s*(is\s*)?(disconnect(ed)?|down|broken|abnormal|lost)|net(work)?\s*cable\s*(disconnect|unplug)|offline\s+alarm|network\s+exception",
     "network_disconnected", "critical", "Network disconnected"),
    (r"illegal\s*(login|access)|login\s*(fail(ed|ure)?|lock(ed)?)|invalid\s*(login|password|user)|brute\s*force|unauthori[sz]ed\s+(login|access)",
     "illegal_login", "warning", "Illegal login attempt"),
    (r"(was|is|has\s+been|got)\s+disconnected|disconnected\s+from|went\s+offline|is\s+(now\s+)?offline|lost\s+contact|is\s+unreachable|"
     r"(is|went)\s+down\b|heartbeat\s+(missed|lost)|offline\b", "device_offline", "critical", "Device offline"),
    (r"reconnected|is\s+back\s+online|back\s+up\b|came\s+(back\s+)?online|is\s+(now\s+)?online|(is|went)\s+up\b|(was|is)\s+connected|"
     r"recovered|restored|\bonline\b", "device_online", "info", "Device back online"),
    (r"line\s*crossing|intrusion|region\s*(entrance|exiting)|tripwire|perimeter|loitering", "intrusion", "warning", "Intrusion / line crossing"),
    (r"alarm\s*input|i/o\s*alarm|external\s*alarm|local\s*alarm", "alarm_input", "warning", "Alarm input"),
    (r"motion\s*detect(ion|ed)?|motion\s*alarm|\bmotion\b|\bvmd\b|human\s*detect|vehicle\s*detect|face\s*detect|smd\b",
     "motion", "info", "Motion detection"),
    (r"reboot(ed)?|restart(ed)?|power\s*(on|up|fail(ure)?|loss|lost)|cold\s*start|ups\s+", "device_restart", "warning", "Device restart / power"),
    (r"firmware|upgrade\s+available|update\s+available|new\s+version", "firmware", "info", "Firmware / update"),
]
MAIL_RULES = [(re.compile(r, re.I), t, sev, title) for r, t, sev, title in MAIL_RULES]

BRAND_HINTS = [
    ("hikvision", r"hikvision|hik-?connect|EVENT TYPE:|CAMERA NAME\(NUM\)|ivms"),
    ("dahua", r"dahua|dmss|Alarm Event\s*:|Alarm Input Channel|Alarm Device Name|imou"),
    ("unifi", r"unifi|ui\.com|ubiquiti\s+network"),
    ("airmax", r"uisp|airmax|airos|unms|ubnt"),
    ("omada", r"omada"),
    ("tplink", r"tp-?link"),
    ("mikrotik", r"mikrotik|routeros|netwatch"),
    ("fortinet", r"forti(gate|os|net)"),
]
BRAND_HINTS = [(b, re.compile(r, re.I)) for b, r in BRAND_HINTS]

FIELD_PATTERNS = {
    "camera": [r"CAMERA NAME\(NUM\)\s*:\s*(.+)", r"Camera\s*Name\s*:\s*(.+)", r"Alarm\s+(?:Input\s+)?Channel(?:\s*No\.)?\s*:\s*(.+)",
               r"Channel\s*(?:No\.|Name|Number)?\s*:\s*(.+)"],
    "device_name": [r"DEVICE NAME\s*:\s*(.+)", r"Alarm Device Name\s*:\s*(.+)", r"Device\s*Name\s*:\s*(.+)", r"NVR\s*NAME\s*:\s*(.+)"],
    "device_serial": [r"DEVICE SERIAL(?: No\.)?\s*:\s*(.+)", r"(?:NVR|DVR|DEVICE|IPC)\s*S/N\s*:\s*(.+)", r"Serial(?:\s*No\.?|\s*Number)?\s*:\s*(.+)"],
    "event_time": [r"EVENT TIME\s*:\s*(.+)", r"Alarm (?:Start )?Time(?:\s*\([^)]*\))?\s*:\s*(.+)", r"Time\s*:\s*(.+)"],
    "event_type": [r"EVENT TYPE\s*:\s*(.+)", r"Alarm Event\s*:\s*(.+)", r"Event\s*:\s*(.+)"],
}
FIELD_PATTERNS = {k: [re.compile(p, re.I) for p in v] for k, v in FIELD_PATTERNS.items()}


def html_to_text(html):
    html = re.sub(r"(?is)<(script|style|head).*?</\1>", " ", html)
    html = re.sub(r"(?i)<br\s*/?>|</(p|div|tr|li|h\d|table)>", "\n", html)
    html = re.sub(r"(?i)</t[dh]>", " ", html)
    text = unescape(re.sub(r"<[^>]+>", "", html))
    lines = [re.sub(r"[ \t\xa0]+", " ", l).strip() for l in text.splitlines()]
    return "\n".join(l for l in lines if l)


def _decode_part(part):
    data = part.get_payload(decode=True) or b""
    for cs in (part.get_content_charset(), "utf-8", "gb18030", "latin-1"):
        if not cs:
            continue
        try:
            return data.decode(cs)
        except (LookupError, UnicodeDecodeError):
            continue
    return data.decode("utf-8", "replace")


def parse_mail(raw):
    """Parse raw RFC822 bytes -> dict(subject, from, text, images=[(name, bytes)])"""
    msg = BytesParser(policy=policy.compat32).parsebytes(raw)
    from email.header import decode_header, make_header
    def hdr(name):
        v = msg.get(name, "")
        try:
            return str(make_header(decode_header(v))).strip()
        except Exception:
            return str(v).strip()
    text, html, images = "", "", []
    for part in msg.walk():
        if part.is_multipart():
            continue
        ctype = (part.get_content_type() or "").lower()
        fname = part.get_filename() or ""
        disp = (part.get("Content-Disposition") or "").lower()
        if ctype.startswith("image/") or fname.lower().endswith((".jpg", ".jpeg", ".png")) or \
                (ctype == "application/octet-stream" and fname.lower().endswith((".jpg", ".jpeg"))):
            data = part.get_payload(decode=True)
            if data:
                images.append((fname or "snapshot.jpg", data))
        elif ctype == "text/plain" and "attachment" not in disp:
            text += _decode_part(part) + "\n"
        elif ctype == "text/html" and "attachment" not in disp:
            html += _decode_part(part) + "\n"
    if not text.strip() and html:
        text = html_to_text(html)
    text = text.replace("\r\n", "\n").strip()
    return {"subject": hdr("Subject"), "from": hdr("From"), "text": text[:20000], "images": images}


def classify_mail(subject, text, host=None):
    blob = f"{subject}\n{text[:6000]}"
    kind, severity, title = "other", "warning", None
    # Prefer the subject; fall back to the body
    for scope in (subject, blob):
        for rx, t, sev, ttl in MAIL_RULES:
            if rx.search(scope):
                kind, severity, title = t, sev, ttl
                break
        if title:
            break
    brand = None
    for b, rx in BRAND_HINTS:
        if rx.search(blob):
            brand = b
            break
    if not brand and host and host.get("device_type") not in (None, "generic"):
        brand = host["device_type"]
    fields = {}
    for key, pats in FIELD_PATTERNS.items():
        for rx in pats:
            m = rx.search(text)
            if m:
                fields[key] = m.group(1).strip()[:120]
                break
    if kind in ("device_offline", "device_online"):
        # "[UniFi] AP Lobby-U6 was disconnected", "EAP245-Pool is disconnected", "Netwatch: 192.168.88.20 is DOWN"
        dm = re.search(r"(?:\b(?:AP|Switch|Gateway|Device|EAP|Router|Client)\s+)?\[?([\w.:\-]{2,64})\]?\s+(?:was|is|has been|went)\s+"
                       r"(?:disconnected|offline|down|lost|connected|online|up|reconnected|adopted)", subject or "", re.I) or \
            re.search(r"\[?([\w.:\-]{2,64}?)(?::[0-9A-F]{2}(?:-[0-9A-F]{2}){5})?\]?\s+(?:was|is)\s+(?:disconnected|offline)", text[:2000], re.I)
        if dm:
            fields["device"] = dm.group(1)
    if not title:
        title = subject or "E-mail from device"
    return {"type": kind, "severity": severity, "title": title, "brand": brand, "fields": fields}


_rx_rate = {}


def process_incoming_mail(raw, peer_ip, mail_from, rcpts, auth_user=None):
    s = get_settings()
    m = parse_mail(raw)
    with db() as c:
        row = c.execute("SELECT * FROM hosts WHERE host=? ORDER BY id LIMIT 1", (peer_ip,)).fetchone()
    host = dict(row) if row else None
    cl = classify_mail(m["subject"], m["text"], host)
    f = cl["fields"]
    source_label = host["name"] if host else (f.get("device_name") or peer_ip)
    if f.get("camera") and cl["type"] in ("motion", "video_loss", "tamper", "intrusion", "alarm_input", "other"):
        title = f"{cl['title']} - {f['camera']}"
    elif f.get("device"):
        title = f"{cl['title']} - {f['device']}"
    else:
        title = cl["title"]
    details = {"type": cl["type"], "brand": cl["brand"], "source_ip": peer_ip, "mail_from": mail_from,
               "from": m["from"], "to": rcpts, "subject": m["subject"], "fields": f,
               "body": m["text"][:3000], "auth_user": auth_user, "source_label": source_label}
    now = time.time()
    eid = add_event("mail", cl["type"], cl["severity"], host, title, m["text"][:500], details, [], ts=now)
    saved = []
    for i, (name, data) in enumerate(m["images"][:5]):
        if len(data) > 3 * 1024 * 1024:
            continue
        ext = ".png" if name.lower().endswith(".png") else ".jpg"
        fn = f"ev{eid}_{i}{ext}"
        with open(os.path.join(SNAP_DIR, fn), "wb") as fh:
            fh.write(data)
        saved.append(fn)
    if saved:
        with _db_lock, db() as c:
            c.execute("UPDATE events SET attachments=? WHERE id=?", (json.dumps(saved), eid))
    log.info("Mail from %s (%s): %s [%s/%s] %d image(s)", peer_ip, cl["brand"], m["subject"], cl["type"],
             cl["severity"], len(saved))
    # forward?
    if SEVERITY_RANK[cl["severity"]] < SEVERITY_RANK.get(s["rx_forward_min"], 2) and cl["type"] != "test":
        return eid
    # per sender + type + subject: one controller (UniFi/Omada) reports many APs from one IP
    key = (peer_ip, cl["type"], re.sub(r"\d{1,2}[:/.-]\d{1,2}([:/.-]\d{2,4})?", "", m["subject"] or "")[:120])
    if cl["type"] != "test" and now - _rx_rate.get(key, 0) < s["rx_rate_limit"]:
        log.info("Rate limited forward for %s", key)
        return eid
    _rx_rate[key] = now
    icon = {"critical": "🔴", "warning": "🟠", "info": "🔵"}[cl["severity"]]
    lines = [f"{icon} {title} [{s['site_name']}]", f"Sender: {source_label} ({peer_ip})"]
    if f.get("device_name") and f.get("device_name") != source_label:
        lines.append(f"Device: {f['device_name']}")
    if m["subject"] and m["subject"] != cl["title"]:
        lines.append(f"Subject: {m['subject']}")
    lines.append(fmt_ts(now))
    text = "\n".join(lines)
    alert = {"type": cl["type"], "title": title, "brand": cl["brand"], "source_ip": peer_ip,
             "from": m["from"], "subject": m["subject"], "fields": f, "attachments": len(saved)}
    payload = build_payload(s, "device_alert", eid, host, None, severity=cl["severity"], message=text, alert=alert, ts=now)
    notify(f"[{s['site_name']}] {title}", text, payload,
           photo=os.path.join(SNAP_DIR, saved[0]) if saved else None)
    return eid


class _MailHandler:
    async def handle_MAIL(self, server, session, envelope, address, mail_options):
        s = get_settings()
        if not ip_allowed(session.peer[0], s["rx_allowed_nets"]):
            log.warning("SMTP: rejected sender IP %s (not in allowed networks)", session.peer[0])
            return "550 5.7.1 Sender network not allowed"
        if s["rx_require_auth"] and not session.authenticated:
            return "530 5.7.0 Authentication required"
        envelope.mail_from = address
        envelope.mail_options.extend(mail_options)
        return "250 OK"

    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        envelope.rcpt_tos.append(address)
        return "250 OK"

    async def handle_DATA(self, server, session, envelope):
        peer = session.peer[0]
        if peer.startswith("::ffff:"):
            peer = peer[7:]
        user = None
        if session.auth_data is not None:
            user = getattr(session.auth_data, "login", None)
            user = user.decode(errors="replace") if isinstance(user, bytes) else user
        try:
            await asyncio.get_running_loop().run_in_executor(
                None, process_incoming_mail, envelope.original_content or envelope.content, peer,
                envelope.mail_from, list(envelope.rcpt_tos), user)
        except Exception:
            log.exception("Failed to process incoming mail")
        return "250 OK Message accepted"


def ip_allowed(ip, nets):
    try:
        addr = ipaddress.ip_address(ip.replace("::ffff:", ""))
    except ValueError:
        return False
    for n in [x.strip() for x in (nets or "").split(",") if x.strip()]:
        try:
            if addr in ipaddress.ip_network(n, strict=False):
                return True
        except ValueError:
            continue
    return False


def _tls_context():
    cert, key = os.path.join(DATA_DIR, "smtp_cert.pem"), os.path.join(DATA_DIR, "smtp_key.pem")
    if not (os.path.exists(cert) and os.path.exists(key)):
        if not shutil.which("openssl"):
            raise RuntimeError("openssl not found - cannot create self-signed certificate for STARTTLS/SSL")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "3650",
                        "-subj", "/CN=pingmonitor", "-keyout", key, "-out", cert],
                       check=True, capture_output=True)
        os.chmod(key, 0o600)
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.minimum_version = ssl.TLSVersion.TLSv1   # old cameras/NVRs only speak TLS 1.0
    try:
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    ctx.load_cert_chain(cert, key)
    return ctx


class SmtpReceiver:
    def __init__(self):
        self.ctrl = None
        self.error = None
        self.lock = threading.Lock()

    def status(self):
        if self.ctrl:
            s = get_settings()
            return f"running on {s['rx_host']}:{s['rx_port']} ({s['rx_security']})"
        return f"error: {self.error}" if self.error else "stopped"

    def restart(self):
        with self.lock:
            self.stop()
            s = get_settings()
            if not s["rx_enabled"]:
                return
            try:
                from aiosmtpd.controller import Controller
                from aiosmtpd.smtp import AuthResult

                def authenticator(server, session, envelope, mechanism, auth_data):
                    st = get_settings()
                    login = getattr(auth_data, "login", b"") or b""
                    pw = getattr(auth_data, "password", b"") or b""
                    login = login.decode(errors="replace") if isinstance(login, bytes) else str(login)
                    pw = pw.decode(errors="replace") if isinstance(pw, bytes) else str(pw)
                    if not st["rx_require_auth"]:
                        return AuthResult(success=True, handled=False)   # quirky devices that always AUTH: accept
                    ok = hmac.compare_digest(login, st["rx_user"]) and bool(st["rx_password"]) and \
                        hmac.compare_digest(pw, st["rx_password"])
                    if not ok:
                        log.warning("SMTP: bad login '%s' from %s", login, session.peer[0])
                    return AuthResult(success=ok, handled=False)   # handled=False -> server replies 235/535

                kw = dict(hostname=s["rx_host"], port=int(s["rx_port"]), authenticator=authenticator,
                          auth_required=False, auth_require_tls=False, data_size_limit=15 * 1024 * 1024,
                          decode_data=False, server_hostname="pingmonitor", ident=f"{APP_NAME} {VERSION}")
                if s["rx_security"] == "starttls":
                    kw.update(tls_context=_tls_context(), require_starttls=False)
                elif s["rx_security"] == "ssl":
                    kw.update(ssl_context=_tls_context())
                self.ctrl = Controller(_MailHandler(), **kw)
                self.ctrl.start()
                self.error = None
                log.info("SMTP receiver %s", self.status())
            except Exception as e:
                self.ctrl = None
                self.error = str(e)
                log.error("SMTP receiver failed to start: %s", e)

    def stop(self):
        if self.ctrl:
            try:
                self.ctrl.stop()
            except Exception:
                pass
            self.ctrl = None


RECEIVER = SmtpReceiver()


# ----------------------------------------------------------------------------- SNMP (polling + traps)
# Pure python: pysnmp (lextudio, 7.x, asyncio). Everything runs in one background asyncio thread.
O_SYS = {"sysDescr": "1.3.6.1.2.1.1.1.0", "sysObjectID": "1.3.6.1.2.1.1.2.0", "sysUpTime": "1.3.6.1.2.1.1.3.0",
         "sysName": "1.3.6.1.2.1.1.5.0", "sysLocation": "1.3.6.1.2.1.1.6.0"}
O_IF = {"descr": "1.3.6.1.2.1.2.2.1.2", "type": "1.3.6.1.2.1.2.2.1.3", "speed": "1.3.6.1.2.1.2.2.1.5",
        "admin": "1.3.6.1.2.1.2.2.1.7", "oper": "1.3.6.1.2.1.2.2.1.8", "in": "1.3.6.1.2.1.2.2.1.10",
        "inerr": "1.3.6.1.2.1.2.2.1.14", "out": "1.3.6.1.2.1.2.2.1.16", "outerr": "1.3.6.1.2.1.2.2.1.20",
        "name": "1.3.6.1.2.1.31.1.1.1.1", "hcin": "1.3.6.1.2.1.31.1.1.1.6", "hcout": "1.3.6.1.2.1.31.1.1.1.10",
        "highspeed": "1.3.6.1.2.1.31.1.1.1.15", "alias": "1.3.6.1.2.1.31.1.1.1.18"}
O_HR_CPU = "1.3.6.1.2.1.25.3.3.1.2"                    # hrProcessorLoad (per core, %)
O_HR_STORE = {"type": "1.3.6.1.2.1.25.2.3.1.2", "descr": "1.3.6.1.2.1.25.2.3.1.3", "units": "1.3.6.1.2.1.25.2.3.1.4",
              "size": "1.3.6.1.2.1.25.2.3.1.5", "used": "1.3.6.1.2.1.25.2.3.1.6"}
HR_RAM, HR_DISK = "1.3.6.1.2.1.25.2.1.2", "1.3.6.1.2.1.25.2.1.4"
O_UCD = {"memTotal": "1.3.6.1.4.1.2021.4.5.0", "memAvail": "1.3.6.1.4.1.2021.4.6.0", "memBuf": "1.3.6.1.4.1.2021.4.14.0",
         "memCached": "1.3.6.1.4.1.2021.4.15.0", "cpuIdle": "1.3.6.1.4.1.2021.11.11.0"}  # net-snmp (UniFi/airOS/EdgeOS/Linux)
O_MT = {"temp": "1.3.6.1.4.1.14988.1.1.3.10.0", "cpu_temp": "1.3.6.1.4.1.14988.1.1.3.11.0",
        "voltage": "1.3.6.1.4.1.14988.1.1.3.8.0"}                       # MIKROTIK-MIB (RouterOS 6, x10)
O_MT_GAUGE = {"name": "1.3.6.1.4.1.14988.1.1.3.100.1.2", "value": "1.3.6.1.4.1.14988.1.1.3.100.1.3",
              "unit": "1.3.6.1.4.1.14988.1.1.3.100.1.4"}                 # mtxrGaugeTable (RouterOS 7)
O_MT_WLCLIENTS = "1.3.6.1.4.1.14988.1.1.1.3.1.6"                         # mtxrWlApClientCount
O_MT_CAPS = "1.3.6.1.4.1.14988.1.1.1.6.0"                                # mtxrWlCMRegClientCount (CAPsMAN)
O_UBNT_VAP_STA = "1.3.6.1.4.1.41112.1.6.1.2.1.8"                         # UBNT-UniFi-MIB unifiVapNumStations
O_UBNT_AIRMAX_STA = "1.3.6.1.4.1.41112.1.4.5.1.15"                       # UBNT-AirMAX-MIB ubntWlStatStaCount
O_HIK_DISK = "1.3.6.1.4.1.39165.1.20"   # HIK-DEVICE-MIB area seen on some NVRs - read best-effort, firmware dependent
IFTYPE_PHYS = {6, 62, 69, 117, 71}       # ethernet, fastEther, gigabit..., ieee80211
TRAP_NAMES = {"1.3.6.1.6.3.1.1.5.1": "coldStart", "1.3.6.1.6.3.1.1.5.2": "warmStart", "1.3.6.1.6.3.1.1.5.3": "linkDown",
              "1.3.6.1.6.3.1.1.5.4": "linkUp", "1.3.6.1.6.3.1.1.5.5": "authenticationFailure",
              "1.3.6.1.6.3.1.1.5.6": "egpNeighborLoss",
              "1.3.6.1.2.1.33.2.1": "upsOnBattery", "1.3.6.1.2.1.33.2.3": "upsAlarm",
              "1.3.6.1.2.1.33.2.4": "upsAlarmCleared",
              "1.3.6.1.4.1.318.0.5": "upsOnBattery", "1.3.6.1.4.1.318.0.9": "powerRestored",
              "1.3.6.1.4.1.318.0.7": "lowBattery", "1.3.6.1.4.1.318.0.11": "returnFromLowBattery",
              "1.3.6.1.4.1.318.0.17": "batteryNeedsReplacement"}
V1_GENERIC = ["coldStart", "warmStart", "linkDown", "linkUp", "authenticationFailure", "egpNeighborLoss", "enterpriseSpecific"]
TRAP_INFO = {"coldStart": ("critical", "Device rebooted (coldStart trap)"), "warmStart": ("warning", "Device restarted (warmStart trap)"),
             "linkDown": ("critical", "Interface down (linkDown trap)"), "linkUp": ("info", "Interface up (linkUp trap)"),
             "authenticationFailure": ("warning", "SNMP authentication failure"), "egpNeighborLoss": ("warning", "EGP neighbor loss"),
             "upsOnBattery": ("critical", "UPS on battery (power cut)"), "powerRestored": ("info", "UPS mains restored"),
             "lowBattery": ("critical", "UPS battery low"), "returnFromLowBattery": ("info", "UPS battery recovered"),
             "batteryNeedsReplacement": ("warning", "UPS battery needs replacement"),
             "upsAlarm": ("warning", "UPS alarm"), "upsAlarmCleared": ("info", "UPS alarm cleared")}
O_SNMPTRAPOID, O_IFINDEX, O_IFDESCR_PFX, O_IFNAME_PFX = "1.3.6.1.6.3.1.1.4.1.0", "1.3.6.1.2.1.2.2.1.1.", "1.3.6.1.2.1.2.2.1.2.", "1.3.6.1.2.1.31.1.1.1.1."
SNMP_DEFAULT_CFG = {"enabled": 0, "version": "2c", "community": "", "port": 161, "user": "", "auth_proto": "SHA",
                    "auth_key": "", "priv_proto": "AES", "priv_key": "", "ifaces": None, "alert_ifaces": None}


def host_snmp_cfg(h):
    cfg = dict(SNMP_DEFAULT_CFG)
    try:
        cfg.update(json.loads(h.get("snmp") or "{}"))
    except (TypeError, ValueError):
        pass
    return cfg


def fmt_bps(v):
    if v is None:
        return "-"
    for unit, div in (("Gb/s", 1e9), ("Mb/s", 1e6), ("kb/s", 1e3)):
        if v >= div:
            return f"{v / div:.1f} {unit}"
    return f"{v:.0f} b/s"


def _snmp_err(ei):
    t = str(ei)
    if "digest" in t.lower() or "unknown user" in t.lower() or "StatusInformation" in t:
        return "SNMPv3 authentication failed (check user / auth key / protocols)"
    if "decrypt" in t.lower() or "ciphering" in t.lower():
        return "SNMPv3 privacy (encryption) failed - check priv key / protocol (needs the 'cryptography' package)"
    if "timeout" in t.lower():
        return "no SNMP response (timeout) - check IP, port, community / v3 user and that SNMP is enabled on the device"
    return t


def _snmp_val(v):
    """pysnmp value -> python (int / str / None for noSuchObject etc.)"""
    cls = v.__class__.__name__
    if cls in ("NoSuchObject", "NoSuchInstance", "EndOfMibView", "Null"):
        return None
    if cls in ("ObjectIdentifier", "ObjectName"):
        return str(v)
    if cls in ("OctetString", "DisplayString", "Opaque", "IpAddress"):
        if cls == "IpAddress":
            return ".".join(str(b) for b in bytes(v.asOctets()))
        b = bytes(v.asOctets())
        try:
            return b.decode("utf-8").rstrip("\x00")
        except UnicodeDecodeError:
            return b.hex(":")
    try:
        return int(v)
    except (TypeError, ValueError):
        return str(v)


class SnmpService:
    """Background asyncio loop: polls hosts with SNMP enabled and runs the trap listener."""

    def __init__(self):
        self.loop = None
        self.thread = None
        self.engine = None
        self.trap_transport = None
        self.trap_status = "disabled"
        self.counters = {}       # host_id -> {ifname: (ts, in, out, inerr, outerr, hc)}
        self.last_poll = {}      # host_id -> ts
        self.cpu_high = {}       # host_id -> consecutive high polls
        self.available = True
        try:
            import pysnmp  # noqa: F401
        except ImportError:
            self.available = False

    # --- lifecycle
    def start(self):
        if not self.available:
            log.warning("pysnmp not installed - SNMP disabled (pip install pysnmp)")
            return
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self._run, daemon=True, name="snmp")
        self.thread.start()

    def _run(self):
        asyncio.set_event_loop(self.loop)
        from pysnmp.hlapi.v3arch.asyncio import SnmpEngine
        self.engine = SnmpEngine()
        self.loop.create_task(self._scheduler())
        self.loop.run_until_complete(self._trap_restart())
        self.loop.run_forever()

    def call(self, coro, timeout=30):
        """Run a coroutine on the SNMP loop from another thread (web requests)."""
        if not self.loop:
            raise RuntimeError("SNMP not available (pysnmp missing)")
        return asyncio.run_coroutine_threadsafe(coro, self.loop).result(timeout)

    def restart_traps(self):
        if self.loop:
            self.call(self._trap_restart(), 10)

    # --- polling
    async def _scheduler(self):
        await asyncio.sleep(3)
        while True:
            try:
                s = get_settings()
                if s["snmp_enabled"]:
                    with db() as c:
                        hosts = [dict(r) for r in c.execute("SELECT * FROM hosts WHERE enabled=1 AND snmp LIKE '%\"enabled\": 1%'")]
                    now = time.time()
                    due = [h for h in hosts if now - self.last_poll.get(h["id"], 0) >= max(30, s["snmp_interval"]) - 2]
                    for h in due:
                        self.last_poll[h["id"]] = now
                    if due:
                        await asyncio.gather(*(self.poll_host(h, s) for h in due), return_exceptions=True)
            except Exception:
                log.exception("SNMP scheduler error")
            await asyncio.sleep(10)

    async def _auth(self, cfg):
        from pysnmp.hlapi.v3arch import asyncio as h
        if cfg["version"] == "3":
            ap = {"none": h.usmNoAuthProtocol, "MD5": h.usmHMACMD5AuthProtocol, "SHA": h.usmHMACSHAAuthProtocol,
                  "SHA256": h.usmHMAC192SHA256AuthProtocol}.get(cfg["auth_proto"], h.usmHMACSHAAuthProtocol)
            pp = {"none": h.usmNoPrivProtocol, "DES": h.usmDESPrivProtocol, "AES": h.usmAesCfb128Protocol,
                  "AES256": h.usmAesCfb256Protocol}.get(cfg["priv_proto"], h.usmAesCfb128Protocol)
            if cfg["auth_proto"] == "none" or not cfg["auth_key"]:
                return h.UsmUserData(cfg["user"])
            if cfg["priv_proto"] == "none" or not cfg["priv_key"]:
                return h.UsmUserData(cfg["user"], cfg["auth_key"], authProtocol=ap)
            return h.UsmUserData(cfg["user"], cfg["auth_key"], cfg["priv_key"], authProtocol=ap, privProtocol=pp)
        return h.CommunityData(cfg["community"] or "public", mpModel=0 if cfg["version"] == "1" else 1)

    async def _get(self, auth, target, oids):
        from pysnmp.hlapi.v3arch import asyncio as h
        ei, es, _, vbs = await h.get_cmd(self.engine, auth, target, h.ContextData(),
                                         *[h.ObjectType(h.ObjectIdentity(o)) for o in oids], lookupMib=False)
        if ei:
            raise RuntimeError(_snmp_err(ei))
        if es:
            # v1 agents fail the whole GET on one missing OID: fall back to one by one
            out = {}
            for o in oids:
                ei2, es2, _, vb2 = await h.get_cmd(self.engine, auth, target, h.ContextData(),
                                                   h.ObjectType(h.ObjectIdentity(o)), lookupMib=False)
                if not ei2 and not es2:
                    out[o] = _snmp_val(vb2[0][1])
            return out
        return {str(n): _snmp_val(v) for n, v in vbs}

    async def _walk(self, auth, target, base, limit=512):
        from pysnmp.hlapi.v3arch import asyncio as h
        out = {}
        async for ei, es, _, vbs in h.bulk_walk_cmd(self.engine, auth, target, h.ContextData(), 0, 25,
                                                   h.ObjectType(h.ObjectIdentity(base)), lexicographicMode=False,
                                                   lookupMib=False):
            if ei:
                raise RuntimeError(str(ei))
            if es:
                break
            for n, v in vbs:
                n = str(n)
                if not n.startswith(base + "."):
                    return out
                out[n[len(base) + 1:]] = _snmp_val(v)
            if len(out) >= limit:
                break
        return out

    async def query(self, h, cfg, s=None):
        """One full SNMP read of a device. Returns dict (raises on timeout/auth error)."""
        from pysnmp.hlapi.v3arch import asyncio as hl
        s = s or get_settings()
        auth = await self._auth(cfg)
        target = await hl.UdpTransportTarget.create((h["host"], int(cfg["port"] or 161)),
                                                    timeout=max(1, s["snmp_timeout"]), retries=1)
        sysv = await self._get(auth, target, list(O_SYS.values()))
        if all(v is None for v in sysv.values()):
            raise RuntimeError("no answer to system MIB")
        d = {k: sysv.get(o) for k, o in O_SYS.items()}
        d["ts"] = time.time()
        # interfaces
        cols = {}
        for k, o in O_IF.items():
            try:
                cols[k] = await self._walk(auth, target, o)
            except Exception:
                cols[k] = {}
        ifs = []
        for idx in sorted(cols["descr"] or cols["name"], key=lambda x: int(x) if x.isdigit() else 0):
            g = lambda k: cols.get(k, {}).get(idx)
            hc = g("hcin") is not None and g("hcout") is not None
            ifs.append({"index": int(idx) if idx.isdigit() else idx, "name": g("name") or g("descr") or f"if{idx}",
                        "descr": g("descr"), "alias": g("alias") or "", "type": g("type"),
                        "speed": (g("highspeed") * 1_000_000) if g("highspeed") else g("speed"),
                        "admin": {1: "up", 2: "down", 3: "testing"}.get(g("admin"), g("admin")),
                        "oper": {1: "up", 2: "down", 3: "testing", 5: "dormant", 6: "notPresent", 7: "lowerLayerDown"}.get(g("oper"), g("oper")),
                        "in": g("hcin") if hc else g("in"), "out": g("hcout") if hc else g("out"), "hc": hc,
                        "inerr": g("inerr") or 0, "outerr": g("outerr") or 0})
        d["ifaces"] = ifs
        # CPU / memory (HOST-RESOURCES, then UCD-SNMP)
        try:
            loads = [v for v in (await self._walk(auth, target, O_HR_CPU)).values() if isinstance(v, int)]
        except Exception:
            loads = []
        d["cpu"] = round(sum(loads) / len(loads), 1) if loads else None
        d["cpu_cores"] = len(loads) or None
        d["mem_pct"], d["storage"] = None, []
        try:
            st = {k: await self._walk(auth, target, o) for k, o in O_HR_STORE.items()}
            for i, typ in st["type"].items():
                size, used, units = st["size"].get(i), st["used"].get(i), st["units"].get(i) or 1
                if not size:
                    continue
                pct = round(100.0 * (used or 0) / size, 1)
                if typ == HR_RAM and d["mem_pct"] is None:
                    d["mem_pct"] = pct
                elif typ == HR_DISK:
                    d["storage"].append({"name": st["descr"].get(i), "pct": pct, "size_mb": round(size * units / 1048576)})
        except Exception:
            pass
        if d["cpu"] is None or d["mem_pct"] is None:
            try:
                u = await self._get(auth, target, list(O_UCD.values()))
                uv = {k: u.get(o) for k, o in O_UCD.items()}
                if d["cpu"] is None and isinstance(uv["cpuIdle"], int):
                    d["cpu"] = float(100 - uv["cpuIdle"])
                if d["mem_pct"] is None and uv["memTotal"]:
                    free = (uv["memAvail"] or 0) + (uv["memBuf"] or 0) + (uv["memCached"] or 0)
                    d["mem_pct"] = round(100.0 * (uv["memTotal"] - min(free, uv["memTotal"])) / uv["memTotal"], 1)
            except Exception:
                pass
        # brand extras
        oid = d.get("sysObjectID") or ""
        descr = (d.get("sysDescr") or "").lower()
        brand = h.get("device_type") or "generic"
        d["extra"] = {}
        try:
            if brand == "mikrotik" or oid.startswith("1.3.6.1.4.1.14988") or "routeros" in descr:
                mt = await self._get(auth, target, list(O_MT.values()))
                for k, o in O_MT.items():
                    if isinstance(mt.get(o), int) and mt[o] > 0:
                        d["extra"][k] = mt[o] / 10.0
                gn = await self._walk(auth, target, O_MT_GAUGE["name"], 64)
                if gn:
                    gv = await self._walk(auth, target, O_MT_GAUGE["value"], 64)
                    for i, name in gn.items():
                        v = gv.get(i)
                        if isinstance(v, int):
                            key = {"temperature": "temp", "cpu-temperature": "cpu_temp", "voltage": "voltage"}.get(str(name), str(name))
                            d["extra"][key] = v / 10.0 if key == "voltage" else v
                wl = await self._walk(auth, target, O_MT_WLCLIENTS, 64)
                caps = (await self._get(auth, target, [O_MT_CAPS])).get(O_MT_CAPS)
                n = sum(v for v in wl.values() if isinstance(v, int)) + (caps if isinstance(caps, int) else 0)
                if wl or isinstance(caps, int):
                    d["extra"]["wireless_clients"] = n
            elif brand in ("unifi", "airmax") or oid.startswith("1.3.6.1.4.1.41112") or "ubnt" in descr or "unifi" in descr:
                for base in (O_UBNT_VAP_STA, O_UBNT_AIRMAX_STA):
                    w = await self._walk(auth, target, base, 64)
                    if w:
                        d["extra"]["wireless_clients"] = sum(v for v in w.values() if isinstance(v, int))
                        break
            elif brand == "hikvision" or oid.startswith("1.3.6.1.4.1.39165"):
                w = await self._walk(auth, target, O_HIK_DISK, 64)
                if w:
                    d["extra"]["hik_vendor_values"] = len(w)   # vendor MIB answers; details vary by firmware
        except Exception as e:
            log.debug("SNMP extras for %s: %s", h["host"], e)
        temps = [v for v in (d["extra"].get("temp"), d["extra"].get("cpu_temp")) if isinstance(v, (int, float))]
        d["temp"] = max(temps) if temps else None
        if brand == "ups":
            try:
                d["ups"] = await self._read_ups(auth, target)
                if d["ups"].get("temperature") is not None:
                    d["temp"] = d["ups"]["temperature"]
            except Exception as e:
                log.debug("UPS %s: %s", h["host"], e)
                d["ups"] = {"error": str(e)[:160]}
        return d

    async def _read_ups(self, auth, target):
        std_raw = {}
        apc_raw = {}
        try:
            got = await self._get(auth, target, list(wirelogic.UPS_STD_OIDS.values()))
            std_raw = {name: got.get(oid) for name, oid in wirelogic.UPS_STD_OIDS.items()}
        except Exception:
            std_raw = {}
        try:
            got = await self._get(auth, target, list(wirelogic.UPS_APC_OIDS.values()))
            apc_raw = {name: got.get(oid) for name, oid in wirelogic.UPS_APC_OIDS.items()}
        except Exception:
            apc_raw = {}
        view = wirelogic.ups_view(std_raw, apc_raw)
        if not any(view.get(k) is not None for k in ("charge_pct", "load_pct", "input_voltage", "minutes_remaining")) and view.get("source") in (None, "unknown"):
            view["error"] = "no UPS-MIB answer"
        return view

    async def poll_host(self, h, s):
        cfg = host_snmp_cfg(h)
        with db() as c:
            row = c.execute("SELECT data FROM snmp_state WHERE host_id=?", (h["id"],)).fetchone()
        prev = json.loads(row["data"]) if row else {}
        try:
            d = await self.query(h, cfg, s)
        except Exception as e:
            prev.update(error=str(e)[:200], error_ts=time.time())
            with _db_lock, db() as c:
                c.execute("INSERT OR REPLACE INTO snmp_state(host_id, ts, data) VALUES(?,?,?)",
                          (h["id"], prev.get("ts") or 0, json.dumps(prev)))
            log.info("SNMP %s (%s): %s", h["name"], h["host"], e)
            return
        now = d["ts"]
        # rates
        cnt = self.counters.setdefault(h["id"], {})
        for i in d["ifaces"]:
            p = cnt.get(i["name"])
            i["in_bps"] = i["out_bps"] = None
            if p and isinstance(i["in"], int) and isinstance(i["out"], int) and now > p[0]:
                bits = 64 if i["hc"] else 32
                i["in_bps"] = wirelogic.octet_rate(p[1], i["in"], now - p[0], bits)
                i["out_bps"] = wirelogic.octet_rate(p[2], i["out"], now - p[0], bits)
                i["err_delta"] = max(0, i["inerr"] - p[3]) + max(0, i["outerr"] - p[4])
            cnt[i["name"]] = (now, i["in"], i["out"], i["inerr"], i["outerr"])
        # default selection: physical interfaces that are up (max 8)
        if cfg["ifaces"] is None:
            cfg["ifaces"] = [i["name"] for i in d["ifaces"] if i["type"] in IFTYPE_PHYS and i["oper"] == "up"][:8]
            cfg["alert_ifaces"] = list(cfg["ifaces"])
            with _db_lock, db() as c:
                c.execute("UPDATE hosts SET snmp=? WHERE id=?", (json.dumps(cfg), h["id"]))
        d.pop("error", None)
        self._alerts(h, s, cfg, prev, d)
        ups = d.get("ups") or {}
        extra = {"temp": d.get("temp"), "ups_charge": ups.get("charge_pct"), "ups_load": ups.get("load_pct"),
                 "ups_vin": ups.get("input_voltage")}
        with _db_lock, db() as c:
            c.execute("INSERT OR REPLACE INTO snmp_state(host_id, ts, data) VALUES(?,?,?)", (h["id"], now, json.dumps(d)))
            graphed = {i["name"]: [i["in_bps"], i["out_bps"]] for i in d["ifaces"] if i["name"] in (cfg["ifaces"] or [])}
            c.execute("INSERT INTO snmp_samples(host_id, ts, cpu, mem, ifs, temp, extra, g) VALUES(?,?,?,?,?,?,?,0)",
                      (h["id"], now, d["cpu"], d["mem_pct"], json.dumps(graphed), d.get("temp"), json.dumps(extra)))

    def _alerts(self, h, s, cfg, prev, d):
        if not prev.get("ts"):
            return
        found = []
        # reboot: sysUpTime went backwards (ignore the 497-day 32-bit wrap)
        pu, nu = prev.get("sysUpTime"), d.get("sysUpTime")
        if s["snmp_alert_reboot"] and isinstance(pu, int) and isinstance(nu, int) and nu + 100 < pu and pu < 4_200_000_000:
            found.append(("snmp_reboot", "warning", "Device rebooted",
                          f"uptime is now {fmt_dur(nu / 100)} (was {fmt_dur(pu / 100)})", {}))
        # interface oper status changes on watched interfaces
        watched = set(cfg.get("alert_ifaces") or [])
        try:
            with db() as c:
                watched |= {r["iface"] for r in c.execute("SELECT iface FROM dash_ifaces WHERE host_id=?", (h["id"],))}
        except Exception:
            pass
        if s["snmp_alert_ifdown"]:
            old = {i["name"]: i.get("oper") for i in prev.get("ifaces", [])}
            for i in d["ifaces"]:
                if i["name"] not in watched or i["name"] not in old:
                    continue
                label = i["name"] + (f" ({i['alias']})" if i["alias"] else "")
                if old[i["name"]] == "up" and i["oper"] != "up":
                    found.append(("snmp_if_down", "critical", f"Interface {i['name']} down", f"{label} is {i['oper']}",
                                  {"interface": i["name"], "ifIndex": i["index"], "oper": i["oper"]}))
                elif old[i["name"]] != "up" and i["oper"] == "up":
                    found.append(("snmp_if_up", "info", f"Interface {i['name']} up", f"{label} is up again",
                                  {"interface": i["name"], "ifIndex": i["index"], "oper": "up"}))
        # CPU high (2 polls in a row), recovered below threshold-10
        thr = s["snmp_cpu_threshold"]
        if thr and isinstance(d.get("cpu"), (int, float)):
            n = self.cpu_high.get(h["id"], 0)
            if d["cpu"] >= thr:
                n += 1
                if n == 2:
                    found.append(("snmp_cpu_high", "warning", f"High CPU {d['cpu']:.0f}%",
                                  f"CPU load {d['cpu']:.0f}% (threshold {thr}%)", {"cpu": d["cpu"], "threshold": thr}))
            elif d["cpu"] < thr - 10:
                if n >= 2:
                    found.append(("snmp_cpu_ok", "info", f"CPU back to {d['cpu']:.0f}%", "CPU load normal again", {"cpu": d["cpu"]}))
                n = 0
            self.cpu_high[h["id"]] = n
        thr_t = s.get("snmp_temp_threshold") or 0
        if thr_t and isinstance(d.get("temp"), (int, float)):
            hot = d["temp"] >= thr_t
            was = isinstance(prev.get("temp"), (int, float)) and prev["temp"] >= thr_t
            if hot and not was:
                found.append(("snmp_temp_high", "warning", f"Temperature {d['temp']:.0f}°C",
                              f"Temperature {d['temp']:.0f}°C (threshold {thr_t}°C)", {"temp": d["temp"]}))
        thr_u = s.get("snmp_util_threshold") or 0
        if thr_u:
            old_util = {}
            for i in prev.get("ifaces") or []:
                if i.get("speed") and i.get("in_bps") is not None:
                    old_util[i["name"]] = 100.0 * max(i["in_bps"], i.get("out_bps") or 0) / i["speed"]
            for i in d["ifaces"]:
                if i["name"] not in watched or not i.get("speed") or i.get("in_bps") is None:
                    continue
                util = 100.0 * max(i["in_bps"], i.get("out_bps") or 0) / i["speed"]
                if util >= thr_u and old_util.get(i["name"], 0) < thr_u:
                    found.append(("snmp_util_high", "warning", f"{i['name']} at {util:.0f}%",
                                  f"{i['name']} is using {util:.0f}% of {i['speed']} bps",
                                  {"interface": i["name"], "util": round(util, 1)}))
        if d.get("ups") and not d["ups"].get("error"):
            for kind, sev, title, msg in wirelogic.ups_alerts(prev.get("ups"), d["ups"], s.get("ups_runtime_min") or 0, s.get("ups_load_pct") or 0):
                eid = add_event("ups", kind, sev, h, title, msg, {"kind": kind})
                consider_notify(s, h, sev, f"[{s['site_name']}] {title}: {h['name']}", msg,
                                build_payload(s, "snmp_alert", eid, h, severity=sev, message=msg))
        for kind, sev, title, msg, extra in found:
            snmp_event(h, s, kind, sev, title, msg, extra, source_ip=h["host"])

    # --- traps
    async def _trap_restart(self):
        if self.trap_transport:
            self.trap_transport.close()
            self.trap_transport = None
        s = get_settings()
        if not s["trap_enabled"]:
            self.trap_status = "disabled"
            return
        svc = self

        class Proto(asyncio.DatagramProtocol):
            def datagram_received(self, data, addr):
                try:
                    svc.handle_trap(data, addr[0])
                except Exception:
                    log.exception("SNMP trap decode failed from %s", addr[0])

        try:
            self.trap_transport, _ = await self.loop.create_datagram_endpoint(
                Proto, local_addr=(s["trap_host"], int(s["trap_port"])))
            self.trap_status = f"listening on udp {s['trap_host']}:{s['trap_port']}"
            log.info("SNMP trap receiver %s", self.trap_status)
        except OSError as e:
            self.trap_status = f"error: {e}"
            log.error("SNMP trap receiver could not start: %s", e)

    def handle_trap(self, data, peer_ip):
        from pyasn1.codec.ber import decoder
        from pysnmp.proto import api
        s = get_settings()
        peer_ip = peer_ip.removeprefix("::ffff:")
        if not ip_allowed(peer_ip, s["rx_allowed_nets"]):
            log.warning("SNMP trap from %s ignored (not in allowed networks)", peer_ip)
            return
        ver = int(api.decodeMessageVersion(data))
        if ver not in api.PROTOCOL_MODULES:
            log.info("SNMP trap version %s from %s not supported (v1/v2c only)", ver, peer_ip)
            return
        pm = api.PROTOCOL_MODULES[ver]
        msg, _ = decoder.decode(data, asn1Spec=pm.Message())
        community = str(pm.apiMessage.get_community(msg))
        allowed = [x.strip() for x in s["trap_community"].split(",") if x.strip()]
        if allowed and community not in allowed:
            log.warning("SNMP trap from %s: wrong community", peer_ip)
            return
        pdu = pm.apiMessage.get_pdu(msg)
        vbs, trap = [], None
        if ver == api.SNMP_VERSION_1:
            if not pdu.isSameTypeWith(pm.TrapPDU()):
                return
            gen = int(pm.apiTrapPDU.get_generic_trap(pdu))
            ent = str(pm.apiTrapPDU.get_enterprise(pdu))
            trap = V1_GENERIC[gen] if 0 <= gen < 6 else f"{ent}.0.{int(pm.apiTrapPDU.get_specific_trap(pdu))}"
            vbs = [(str(o), _snmp_val(v)) for o, v in pm.apiTrapPDU.get_varbinds(pdu)]
        else:
            if not (pdu.isSameTypeWith(pm.SNMPv2TrapPDU()) or pdu.isSameTypeWith(pm.InformRequestPDU())):
                return
            vbs = [(str(o), _snmp_val(v)) for o, v in pm.apiPDU.get_varbinds(pdu)]
            toid = dict(vbs).get(O_SNMPTRAPOID) or "unknown"
            trap = TRAP_NAMES.get(toid, toid)
        process_trap(peer_ip, ver, community, trap, vbs, s)


def process_trap(peer_ip, ver, community, trap, vbs, s=None):
    s = s or get_settings()
    with db() as c:
        row = c.execute("SELECT * FROM hosts WHERE host=? ORDER BY id LIMIT 1", (peer_ip,)).fetchone()
    host = dict(row) if row else None
    sev, title = TRAP_INFO.get(trap, ("warning", f"SNMP trap {trap}"))
    iface = None
    for o, v in vbs:
        if o.startswith(O_IFNAME_PFX) or o.startswith(O_IFDESCR_PFX):
            iface = v
        elif o.startswith(O_IFINDEX) and iface is None:
            iface = f"ifIndex {v}"
    if iface and trap in ("linkDown", "linkUp"):
        title = f"Interface {iface} {'down' if trap == 'linkDown' else 'up'} (trap)"
    shown = [(o, v) for o, v in vbs if not o.startswith("1.3.6.1.2.1.1.3.0") and o != O_SNMPTRAPOID][:12]
    msg = f"{trap} from {peer_ip}" + ("; " + "; ".join(f"{o}={v}" for o, v in shown) if shown else "")
    extra = {"trap": trap, "snmp_version": "1" if ver == 0 else "2c", "interface": iface,
             "varbinds": [{"oid": o, "value": v} for o, v in vbs[:30]]}
    log.info("SNMP trap %s from %s", trap, peer_ip)
    ups_trap = trap in ("upsOnBattery", "powerRestored", "lowBattery", "returnFromLowBattery",
                        "batteryNeedsReplacement", "upsAlarm", "upsAlarmCleared")
    snmp_event(host or {"id": None, "name": None, "host": peer_ip}, s, "ups_trap" if ups_trap else "snmp_trap",
               sev, title, msg[:500], extra, source_ip=peer_ip, forward_min=s["trap_forward_min"],
               source="ups" if ups_trap else "snmp")


def snmp_event(h, s, kind, sev, title, msg, extra, source_ip=None, forward_min=None, source="snmp"):
    """Store + forward an SNMP poll alert or trap (event type snmp_* or ups)."""
    host = h if h.get("id") else None
    now = time.time()
    details = dict(extra, type=kind, source_ip=source_ip)
    eid = add_event(source, kind, sev, host, title, msg, details, ts=now)
    if host is None:
        with _db_lock, db() as c:
            c.execute("UPDATE events SET host_ip=? WHERE id=?", (source_ip, eid))
    fm = forward_min or s["snmp_forward_min"]
    if SEVERITY_RANK.get(sev, 1) < SEVERITY_RANK.get(fm, 2):
        return eid
    key = ("snmp", source_ip, kind, extra.get("interface"), extra.get("trap"))
    if now - _rx_rate.get(key, 0) < min(60, s["rx_rate_limit"]) and kind not in ("snmp_if_up", "snmp_cpu_ok"):
        return eid
    _rx_rate[key] = now
    icon = {"critical": "🔴", "warning": "🟠", "info": "🔵"}.get(sev, "🔵")
    label = f"{h['name']} ({source_ip})" if h.get("name") else source_ip
    text = f"{icon} {title} [{s['site_name']}]\nDevice: {label}\n{msg}\n{fmt_ts(now)}"
    alert = {"type": kind, "title": title, "brand": (host or {}).get("device_type"), "source_ip": source_ip,
             "from": None, "subject": None, "fields": {k: v for k, v in extra.items() if k != "varbinds"},
             "attachments": 0}
    if kind == "snmp_trap":
        alert["varbinds"] = extra.get("varbinds")
    payload = build_payload(s, "snmp_trap" if kind == "snmp_trap" else "snmp_alert", eid, host, None,
                            severity=sev, message=text, alert=alert, ts=now)
    consider_notify(s, host, sev, f"[{s['site_name']}] {title}" + (f": {h['name']}" if h.get("name") else ""), text, payload)
    return eid


SNMP = SnmpService()


# ----------------------------------------------------------------------------- web app
app = Flask(__name__)
app.json.sort_keys = False  # keep API fields in a readable order
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  SESSION_COOKIE_NAME="pingmon_session", PERMANENT_SESSION_LIFETIME=7 * 86400,
                  MAX_CONTENT_LENGTH=1024 * 1024)
_login_fail = {}


def client_ip():
    """Address used for the login lockout.

    The service listens on every interface. Two kinds of visitor reach it:

    * A PC on the LAN connects directly. ``remote_addr`` is that PC. A forged
      ``CF-Connecting-IP`` header is ignored, so the lockout follows the PC.
    * cloudflared on this machine connects to 127.0.0.1 (or ::1) and sets
      ``CF-Connecting-IP`` to the real visitor. Only then is that header used,
      and only when it is a single valid IP address.
    """
    peer = request.remote_addr or ""
    if peer in ("127.0.0.1", "::1"):
        hdr = (request.headers.get("CF-Connecting-IP") or "").strip()
        if hdr:
            try:
                ipaddress.ip_address(hdr)
            except ValueError:
                return peer
            return hdr
    return peer


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


@app.before_request
def _csrf_protect():
    if request.method == "POST":
        if not hmac.compare_digest(request.form.get("csrf", ""), session.get("csrf", "") or "x"):
            abort(400, "Bad or missing CSRF token - reload the page and try again")


def role():
    return session.get("role")


def viewer_required(f):
    @wraps(f)
    def w(*a, **kw):
        if role() in ("admin", "viewer") or get_settings()["dashboard_access"] == "public":
            return f(*a, **kw)
        return redirect(url_for("login", next=request.path))
    return w


def admin_required(f):
    @wraps(f)
    def w(*a, **kw):
        if role() != "admin":
            if role() == "viewer":
                flash("The settings page needs the admin password.")
            return redirect(url_for("login", next=request.path))
        return f(*a, **kw)
    return w


def api_auth(f):
    @wraps(f)
    def w(*a, **kw):
        tok = ""
        h = request.headers.get("Authorization", "")
        if h.lower().startswith("bearer "):
            tok = h[7:].strip()
        tok = tok or request.args.get("token", "")
        if not (tok and hmac.compare_digest(tok, get_settings()["api_token"])) and role() not in ("admin", "viewer"):
            return jsonify(error="unauthorized", hint="send Authorization: Bearer <API token> or ?token=<API token>"), 401
        return f(*a, **kw)
    return w


def mask(v):
    if not v:
        return ""
    return "•" * 8 + (v[-4:] if len(v) > 8 else "")


app.jinja_env.globals.update(csrf_token=csrf_token, DEVICE_TYPES=DEVICE_TYPES, mask=mask, role=role, fmt_bps=lambda v: fmt_bps(v))

CSS = """
*{box-sizing:border-box}body{margin:0;font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:#f1f4f9;color:#1c2b4a}
header{background:#0b2a55;color:#fff;padding:12px 24px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px}
header h1{font-size:19px;margin:0;display:flex;align-items:center;gap:10px}header small{opacity:.75;font-weight:400}header a{color:#cfe1ff;text-decoration:none;margin-left:16px}
header .logo{height:44px;width:44px;border-radius:50%;object-fit:cover;background:#fff;flex:none}
main{max-width:1240px;margin:0 auto;padding:20px}
.summary{display:flex;gap:10px;margin-bottom:16px;flex-wrap:wrap;align-items:center}
.pill{padding:9px 16px;border-radius:10px;color:#fff;font-weight:700;font-size:17px}
.g{background:#16a34a}.r{background:#dc2626}.a{background:#f59e0b}.p{background:#94a3b8}
.card{background:#fff;border-radius:12px;box-shadow:0 1px 3px rgba(0,0,0,.08);padding:16px;margin-bottom:16px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(350px,1fr));gap:16px}
.dev{display:flex;align-items:center;gap:12px}
.dot{width:52px;height:52px;border-radius:50%;flex:none;display:flex;align-items:center;justify-content:center;color:#fff;font-weight:800;font-size:12px}
.dev h3{margin:0;font-size:16px}.muted{color:#64748b;font-size:13px}
.badge{display:inline-block;padding:2px 7px;border-radius:6px;color:#fff;font-size:11px;font-weight:700;vertical-align:middle}
.sev-critical{background:#dc2626}.sev-warning{background:#f59e0b}.sev-info{background:#2563eb}
.stats{display:flex;gap:16px;margin:10px 0 6px;font-size:13px}.stats b{display:block;font-size:16px}
.chartbox{height:120px}h2{font-size:17px;margin:4px 0 12px}
.grp{font-size:14px;text-transform:uppercase;letter-spacing:.05em;color:#475569;margin:18px 0 8px}
table{width:100%;border-collapse:collapse;font-size:13px}td,th{padding:6px;border-bottom:1px solid #e2e8f0;text-align:left;vertical-align:middle}
input,select,button{font-size:14px;padding:7px 9px;border-radius:8px;border:1px solid #cbd5e1;font-family:inherit}
button{background:#1d5fbf;color:#fff;border:none;cursor:pointer}button.sec{background:#e2e8f0;color:#1c2b4a}button.del{background:#fff;color:#dc2626;border:1px solid #fca5a5}
.flash{background:#e0ecff;padding:10px;border-radius:8px;margin-bottom:12px}
.form-grid{display:grid;grid-template-columns:220px 1fr;gap:10px 14px;align-items:start;max-width:860px}
.form-grid>label{padding-top:7px}
.section-intro{margin:0 0 12px;font-size:13px;color:#475569;line-height:1.45}
.help-list{margin:0 0 12px;padding-left:18px;font-size:12px;color:#64748b;line-height:1.45}
.help-list li{margin:3px 0}
.form-grid .hint{display:block;margin:4px 0 0;line-height:1.4}
.form-grid input[type=text],.form-grid input[type=password],.form-grid input[type=number],.form-grid input[type=url],.form-grid select{width:100%}
.nav a{display:inline-block;margin:0 6px 8px 0;padding:6px 10px;background:#fff;border-radius:8px;text-decoration:none;color:#1d5fbf;font-size:13px;box-shadow:0 1px 2px rgba(0,0,0,.06)}
.thumb{height:44px;border-radius:4px}a{color:#1d5fbf}.hint{font-size:12px;color:#64748b}
.ranges a{display:inline-block;margin:0 6px 8px 0;padding:4px 8px;border-radius:8px;background:#fff;text-decoration:none}
.ranges a.on{background:#0b2a55;color:#fff}
.banner{padding:12px 16px;border-radius:10px;margin-bottom:14px;font-weight:700}
.banner.bad{background:#fee2e2;color:#991b1b}.banner.warn{background:#fef3c7;color:#92400e}
.statusbar{position:sticky;top:0;z-index:30;display:flex;flex-wrap:wrap;gap:8px 18px;align-items:center;padding:10px 16px;border-radius:10px;margin:0 0 14px;color:#fff}
.statusbar.ok{background:#15803d}.statusbar.warn{background:#b45309}.statusbar.bad{background:#b91c1c}
.statusbar .why{font-weight:700}
.snmpline{font-size:12.5px;color:#334155;margin:2px 0 8px}.lnk{display:inline-block;color:#fff;border-radius:6px;padding:1px 6px;margin:0 4px 3px 0;font-size:11.5px;font-weight:600}
.lnk small{font-weight:400;opacity:.9}.kv td:first-child{color:#64748b;width:160px}
code{background:#eef2f7;padding:1px 5px;border-radius:4px;font-size:12px}
"""

LAYOUT = """<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
{% if refresh %}<meta http-equiv="refresh" content="{{ refresh }}">{% endif %}
<link rel="icon" href="{{ url_for('brand_logo') }}" type="image/jpeg">
<title>{{ s.site_name }} - """ + APP_NAME + """</title><style>""" + CSS + """</style>
{% if charts %}<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>{% endif %}</head><body>
<header><h1><img class="logo" src="{{ url_for('brand_logo') }}" alt="Wirewave"><span>""" + APP_NAME + """ <small>· {{ s.site_name }}</small></span></h1><div>
<a href="{{ url_for('index') }}">Dashboard</a>
{% if role() %}<a href="{{ url_for('event_log') }}">Log</a>{% endif %}
{% if role() == 'admin' %}<a href="{{ url_for('report_page') }}">Report</a><a href="{{ url_for('settings') }}">Settings</a>{% endif %}
{% if role() %}<a href="{{ url_for('logout') }}">Logout ({{ role() }})</a>{% else %}<a href="{{ url_for('login') }}">Login</a>{% endif %}
</div></header><main>
{% with m = get_flashed_messages() %}{% for x in m %}<div class="flash">{{ x }}</div>{% endfor %}{% endwith %}
{{ body|safe }}</main></body></html>"""

CHART_JS = """<script>
const TZ = {{ s.timezone|tojson }};
const WIN = {{ win_ms|tojson }};
function hhmm(v){const opt=WIN>2*86400000?{timeZone:TZ,day:'2-digit',month:'2-digit',hour:'2-digit',minute:'2-digit'}:{timeZone:TZ,hour:'2-digit',minute:'2-digit'};
 return new Date(v).toLocaleString('en-GB',opt);}
function axisTicks(ax, from, now){const step=WIN>8*86400000?86400000:(WIN>2*86400000?6*3600e3:4*3600e3);const t=[],st=Math.ceil(from/step)*step;for(let v=st;v<=now;v+=step)t.push({value:v});ax.ticks=t;}
function drawChart(id, pts, big){
  const up=pts.filter(p=>p[1]).map(p=>({x:p[0]*1000,y:p[2]})), down=pts.filter(p=>!p[1]).map(p=>({x:p[0]*1000,y:0}));
  const now=Date.now(), from=now-WIN;
  new Chart(document.getElementById(id),{data:{datasets:[
    {type:'line',label:'Latency (ms)',data:up,borderColor:'#1d5fbf',backgroundColor:'rgba(29,95,191,.12)',fill:true,pointRadius:0,borderWidth:1.4,tension:.2},
    {type:'scatter',label:'Failed ping',data:down,pointBackgroundColor:'#dc2626',pointBorderColor:'#dc2626',pointRadius:3}]},
   options:{animation:false,responsive:true,maintainAspectRatio:false,
    plugins:{legend:{display:!!big},tooltip:{callbacks:{title:(i)=>new Date(i[0].parsed.x).toLocaleString('en-GB',{timeZone:TZ})}}},
    scales:{x:{type:'linear',min:from,max:now,afterBuildTicks:(ax)=>axisTicks(ax,from,now),
      ticks:{callback:(v)=>hhmm(v)}},y:{beginAtZero:true,title:{display:!!big,text:'ms'}}}}});
}
function fmtBps(v){if(v==null)return '';const u=[['G',1e9],['M',1e6],['k',1e3]];for(const [n,d] of u){if(v>=d)return (v/d).toFixed(1)+' '+n+'b/s';}return Math.round(v)+' b/s';}
function drawSeries(id, series, opts){
  const now=Date.now(), from=now-WIN;
  new Chart(document.getElementById(id),{type:'line',data:{datasets:series.map(x=>({label:x.label,data:x.data.map(p=>({x:p[0]*1000,y:p[1]})),
    borderColor:x.color,backgroundColor:x.fill||'transparent',fill:!!x.fill,pointRadius:0,borderWidth:1.4,tension:.2,spanGaps:false}))},
   options:{animation:false,responsive:true,maintainAspectRatio:false,
    plugins:{legend:{display:true,labels:{boxWidth:10}},tooltip:{callbacks:{title:(i)=>new Date(i[0].parsed.x).toLocaleString('en-GB',{timeZone:TZ}),
      label:(i)=>i.dataset.label+': '+(opts.bps?fmtBps(i.parsed.y):i.parsed.y+'%')}}},
    scales:{x:{type:'linear',min:from,max:now,afterBuildTicks:(ax)=>axisTicks(ax,from,now),
      ticks:{callback:(v)=>hhmm(v)}},y:{beginAtZero:true,max:(opts.bps||opts.plain)?undefined:100,ticks:{callback:(v)=>opts.bps?fmtBps(v):(opts.plain?v:v+'%')}}}}});
}</script>"""

STATE_CLS = {"up": "g", "down": "r", "warn": "a"}
STATE_TXT = {"up": "UP", "down": "DOWN", "warn": "?", "disabled": "OFF"}
app.jinja_env.globals.update(STATE_CLS=STATE_CLS, STATE_TXT=STATE_TXT)

LOGIN_BODY = """<div class="card" style="max-width:360px;margin:60px auto"><h2>Login</h2>
<form method="post"><input type="password" name="password" placeholder="Password" autofocus style="width:100%" required>
<input type="hidden" name="csrf" value="{{ csrf_token() }}"><br><br><button style="width:100%">Login</button></form>
<p class="hint">Admin password = dashboard + settings. Viewer password (if set) = dashboard only.</p></div>"""

EVENTS_TABLE = """<table><tr><th>Time</th><th>Source</th><th>Event</th><th>Details</th><th></th></tr>
{% for e in events %}<tr>
<td style="white-space:nowrap">{{ e.time }}</td>
<td>{% if e.host_name %}{{ e.host_name }} <span class="muted">{{ e.host_ip }}</span>{% else %}{{ e.d.get('source_label') or e.d.get('source_ip','') }}{% endif %}</td>
<td><span class="badge sev-{{ e.severity }}">{{ e.severity }}</span> {{ '📧' if e.source=='mail' else ('📡' if e.source=='snmp' else ('🔴' if e.kind=='host_down' else '✅')) }} {{ e.title }}</td>
<td class="muted">{{ e.message[:140] }}</td>
<td>{% for a in e.att %}<a href="{{ url_for('snapshot', name=a) }}" target="_blank"><img class="thumb" src="{{ url_for('snapshot', name=a) }}"></a>{% endfor %}</td></tr>
{% else %}<tr><td colspan="5" class="muted">No events yet.</td></tr>{% endfor %}</table>"""

INDEX_BODY = CHART_JS + """
<div class="statusbar {{ bar.level }}">
 <span class="why">{{ bar.reason }}</span>
 <span>Internet {% if bar.latency is not none %}{{ '%.0f'|format(bar.latency) }} ms{% else %}—{% endif %}
  · loss {% if bar.loss is not none %}{{ '%.0f'|format(bar.loss) }}%{% else %}—{% endif %}</span>
 <span>Public IP {{ bar.ip or '—' }}{% if bar.isp %} · {{ bar.isp }}{% endif %}</span>
 <span class="muted" style="color:rgba(255,255,255,.85)">checked {{ bar.checked }}</span>
</div>
{% if banner %}<div class="banner {{ banner.cls }}">{{ banner.text }}</div>{% endif %}
<p class="ranges">{% for key, label in spans %}<a href="?span={{ key }}" class="{{ 'on' if span==key else '' }}">{{ label }}</a>{% endfor %}</p>
<p class="hint">12 hours and 24 hours use each ping. A week keeps 5-minute averages after the last two days. A month keeps 1-hour averages after the first week.</p>
{% if wan and wan.state %}<div class="card"><h2>Internet {% if wan.state=='down' %}<span class="badge sev-critical">down</span>{% elif wan.state=='degraded' %}<span class="badge sev-warning">degraded</span>{% else %}<span class="badge sev-info">up</span>{% endif %}</h2>
<p class="muted">{% for t in wan.targets %}{{ t.target }}: loss {{ t.loss }}%{% if t.avg_ms is not none %} · {{ '%.0f'|format(t.avg_ms) }} ms{% endif %}{% if t.jitter is not none %} · jitter {{ t.jitter }} ms{% endif %}<br>{% endfor %}</p>
<div class="chartbox"><canvas id="wanlat"></canvas></div>
<script>drawSeries('wanlat',[{label:'Latency',color:'#1d5fbf',data:{{ wan.latency|tojson }}},{label:'Loss %',color:'#dc2626',data:{{ wan.loss|tojson }}}],{});</script>
</div>{% endif %}
{% if traffic %}<h2>Interface graphs</h2><div class="grid">{% for g in traffic %}<div class="card"><b>{{ g.host }} · {{ g.iface }}</b>
<div class="chartbox"><canvas id="dg{{ loop.index }}"></canvas></div>
<script>drawSeries('dg{{ loop.index }}',[{label:'In',color:{{ g.color_in|tojson }},fill:'rgba(22,163,74,.12)',data:{{ g.inn|tojson }}},{label:'Out',color:{{ g.color_out|tojson }},data:{{ g.out|tojson }}}],{bps:true});</script>
</div>{% endfor %}</div>{% endif %}
<div class="summary">
 <div class="pill g">UP {{ c.up }}</div><div class="pill r">DOWN {{ c.down }}</div>
 {% if c.warn %}<div class="pill a">UNSTABLE {{ c.warn }}</div>{% endif %}
 {% if c.pending %}<div class="pill p">PENDING {{ c.pending }}</div>{% endif %}
 <span class="muted">Ping every {{ s.ping_interval }}s · alert after {{ s.fail_threshold }} failed pings · refresh 60s · {{ now }} ({{ s.timezone }})</span>
</div>
{% for g, hs in groups %}<div class="grp">{{ g or 'Devices' }}</div><div class="grid">
{% for h in hs %}<div class="card"><div class="dev">
 <div class="dot {{ STATE_CLS.get(h.state,'p') }}">{{ STATE_TXT.get(h.state,'…') }}</div>
 <div style="flex:1"><a href="{{ url_for('host_page', hid=h.id) }}" style="color:inherit;text-decoration:none"><h3>{{ h.name }}</h3></a>
 <div class="muted"><span class="badge" style="background:{{ DEVICE_TYPES.get(h.device_type, DEVICE_TYPES['generic'])[2] }}">{{ DEVICE_TYPES.get(h.device_type, DEVICE_TYPES['generic'])[1] }}</span> {{ h.host }}
 {% if h.maint %}<span class="badge" style="background:#7c3aed">MAINT</span>{% endif %}{% if h.lan_down %} · LAN device down{% endif %}</div></div></div>
 <div class="stats"><div>Last ping<b>{{ '%.1f ms'|format(h.last_ms) if h.last_ms is not none else '—' }}</b></div>
 <div>Uptime 24h<b>{{ '%.1f%%'|format(h.uptime) if h.uptime is not none else '—' }}</b></div>
 <div>{% if h.state=='down' %}Down for<b style="color:#dc2626">{{ h.down_for }}</b>{% else %}Last seen<b style="font-size:13px">{{ h.last_seen_txt }}</b>{% endif %}</div></div>
 {% if h.sn %}<div class="snmpline">📡 {% if h.sn.error and h.sn.stale %}<span style="color:#dc2626">SNMP: {{ h.sn.error[:60] }}</span>{% else %}
 up <b>{{ h.sn.uptime_txt }}</b>{% if h.sn.cpu is not none %} · CPU <b>{{ '%.0f'|format(h.sn.cpu) }}%</b>{% endif %}{% if h.sn.mem_pct is not none %} · RAM <b>{{ '%.0f'|format(h.sn.mem_pct) }}%</b>{% endif %}
 {% if h.sn.extra.temp %} · <b>{{ h.sn.extra.temp }}°C</b>{% endif %}{% if h.sn.extra.voltage %} · <b>{{ h.sn.extra.voltage }} V</b>{% endif %}{% if h.sn.extra.wireless_clients is defined %} · <b>{{ h.sn.extra.wireless_clients }}</b> Wi-Fi clients{% endif %}
 <div style="margin-top:4px">{% for i in h.sn.watched %}<span class="lnk {{ 'g' if i.oper=='up' else 'r' }}" title="{{ i.alias }} {{ i.oper }}">{{ i.name }} {{ '▲' if i.oper=='up' else '▼' }}{% if i.in_bps is not none %} <small>{{ fmt_bps(i.in_bps) }}↓ {{ fmt_bps(i.out_bps) }}↑</small>{% endif %}</span>{% endfor %}</div>{% endif %}</div>{% endif %}
 <div class="chartbox"><canvas id="c{{ h.id }}"></canvas></div><script>drawChart('c{{ h.id }}', {{ h.points|tojson }});</script>
</div>{% endfor %}</div>{% else %}<div class="card">No hosts yet. {% if role()=='admin' %}<a href="{{ url_for('settings') }}#hosts">Add hosts in Settings</a>.{% endif %}</div>{% endfor %}
{% if alarms %}<div class="card"><h2>Alarms</h2>
<p class="hint">For information and technical monitoring only. This is not a certified alarm receiving centre (ARC/CMS). Keep the panel maker's own app (Ajax, Trikdis, Hikvision or Dahua) as the primary monitoring.</p>
<table><tr><th>Panel</th><th>Account</th><th>State</th><th>Last event</th></tr>
{% for a in alarms %}<tr><td>{{ a.name }} <span class="muted">{{ a.panel }}</span></td><td>{{ a.account }}</td>
<td><span class="badge {{ 'sev-critical' if a.state in ('alarm','offline') else ('sev-info' if a.state in ('armed','disarmed') else 'sev-warning') }}">{{ a.state }}</span></td>
<td class="muted">{{ a.last_text }}</td></tr>{% endfor %}</table></div>{% endif %}
<div class="card" style="margin-top:16px"><h2>Recent events (ping + device e-mails)</h2>""" + EVENTS_TABLE + """</div>"""

HOST_BODY = CHART_JS + """<p class="ranges">{% for key, label in spans %}<a href="?span={{ key }}" class="{{ 'on' if span==key else '' }}">{{ label }}</a>{% endfor %}</p>
<div class="card"><div class="dev">
<div class="dot {{ STATE_CLS.get(h.state,'p') }}">{{ STATE_TXT.get(h.state,'…') }}</div>
<div><h3>{{ h.name }}</h3><div class="muted">{{ DEVICE_TYPES.get(h.device_type, DEVICE_TYPES['generic'])[0] }} · {{ h.host }} · {{ h.grp }} ·
last seen {{ h.last_seen_txt }} · uptime 24h {{ '%.1f%%'|format(h.uptime) if h.uptime is not none else '—' }}</div></div></div>
<div style="height:320px;margin-top:16px"><canvas id="big"></canvas></div><script>drawChart('big', {{ h.points|tojson }}, true);</script></div>
{% if h.sn %}<div class="card"><h2>📡 SNMP {% if h.sn.error %}<span class="badge sev-{{ 'critical' if h.sn.stale else 'warning' }}">last poll failed: {{ h.sn.error }}</span>{% endif %}</h2>
<div class="grid" style="grid-template-columns:repeat(auto-fill,minmax(300px,1fr))"><div><table class="kv">
<tr><td>sysName</td><td>{{ h.sn.sysName or '—' }}</td></tr><tr><td>Description</td><td>{{ (h.sn.sysDescr or '—')[:160] }}</td></tr>
<tr><td>Location</td><td>{{ h.sn.sysLocation or '—' }}</td></tr><tr><td>Device uptime</td><td>{{ h.sn.uptime_txt }}</td></tr>
<tr><td>CPU</td><td>{{ '%.0f%%'|format(h.sn.cpu) if h.sn.cpu is not none else 'n/a' }}{% if h.sn.cpu_cores %} ({{ h.sn.cpu_cores }} cores){% endif %}</td></tr>
<tr><td>Memory used</td><td>{{ '%.0f%%'|format(h.sn.mem_pct) if h.sn.mem_pct is not none else 'n/a' }}</td></tr>
{% for d in h.sn.storage %}<tr><td>Disk {{ d.name }}</td><td>{{ d.pct }}% of {{ d.size_mb }} MB</td></tr>{% endfor %}
{% for k, v in h.sn.extra.items() %}<tr><td>{{ {'temp':'Temperature','cpu_temp':'CPU temperature','voltage':'Voltage','wireless_clients':'Wi-Fi clients'}.get(k, k) }}</td><td>{{ v }}{{ '°C' if 'temp' in k else (' V' if k=='voltage' else '') }}</td></tr>{% endfor %}
<tr><td>Last poll</td><td>{{ h.sn.last_txt }}</td></tr></table></div>
<div style="height:220px"><canvas id="res"></canvas></div></div>
<script>drawSeries('res',[{label:'CPU',color:'#1d5fbf',data:{{ h.sn.cpu_pts|tojson }}},{label:'RAM',color:'#a855f7',data:{{ h.sn.mem_pts|tojson }}}],{});</script>
<h2 style="margin-top:14px">Interfaces</h2><table><tr><th>Interface</th><th>Status</th><th>Speed</th><th>In</th><th>Out</th><th>Errors (total)</th><th>Graph</th><th>Alert</th></tr>
{% for i in h.sn.ifaces %}<tr><td><b>{{ i.name }}</b> <span class="muted">{{ i.alias }}</span></td>
<td><span class="lnk {{ 'g' if i.oper=='up' else ('p' if i.admin=='down' else 'r') }}">{{ i.oper }}</span>{% if i.admin=='down' %} <span class="muted">admin down</span>{% endif %}</td>
<td>{{ fmt_bps(i.speed) if i.speed else '—' }}</td><td>{{ fmt_bps(i.in_bps) }}</td><td>{{ fmt_bps(i.out_bps) }}</td><td>{{ i.inerr + i.outerr }}</td>
<td>{{ '✔' if i.name in h.sn.cfg.ifaces else '' }}</td><td>{{ '✔' if i.name in h.sn.cfg.alert_ifaces else '' }}</td></tr>{% endfor %}</table>
<div class="grid" style="margin-top:14px">{% for n, pts in h.sn.traffic %}<div class="card" style="box-shadow:none;border:1px solid #e2e8f0"><b>{{ n }}</b>
<div style="height:170px"><canvas id="t{{ loop.index }}"></canvas></div>
<script>drawSeries('t{{ loop.index }}',[{label:'In',color:'#16a34a',fill:'rgba(22,163,74,.12)',data:{{ pts[0]|tojson }}},{label:'Out',color:'#1d5fbf',data:{{ pts[1]|tojson }}}],{bps:true});</script></div>{% endfor %}</div>
</div>{% endif %}
{% if h.temp_pts %}<div class="card"><h2>Temperature</h2><div style="height:180px"><canvas id="temp"></canvas></div>
<script>drawSeries('temp',[{label:'°C',color:'#ea580c',data:{{ h.temp_pts|tojson }}}],{});</script></div>{% endif %}
{% if h.ups %}<div class="card"><h2>UPS {% if h.ups.on_battery %}<span class="badge sev-critical">on battery</span>{% elif h.ups.on_mains %}<span class="badge sev-info">on mains</span>{% endif %}</h2>
<table class="kv"><tr><td>Battery</td><td>{{ h.ups.charge_pct if h.ups.charge_pct is not none else '—' }}% · {{ h.ups.battery_status }}{% if h.ups.minutes_remaining is not none %} · {{ h.ups.minutes_remaining }} min left{% endif %}{% if h.ups.replace %} · replace battery{% endif %}</td></tr>
<tr><td>Load</td><td>{{ h.ups.load_pct if h.ups.load_pct is not none else '—' }}%</td></tr>
<tr><td>Input / output</td><td>{{ h.ups.input_voltage or '—' }} V / {{ h.ups.output_voltage or '—' }} V</td></tr>
<tr><td>Temperature</td><td>{{ h.ups.temperature if h.ups.temperature is not none else '—' }}°C</td></tr></table>
<div class="grid">{% if h.ups_charge %}<div style="height:160px"><canvas id="upc"></canvas></div><script>drawSeries('upc',[{label:'Battery %',color:'#16a34a',data:{{ h.ups_charge|tojson }}}],{});</script>{% endif %}
{% if h.ups_load %}<div style="height:160px"><canvas id="upl"></canvas></div><script>drawSeries('upl',[{label:'Load %',color:'#1d5fbf',data:{{ h.ups_load|tojson }}}],{});</script>{% endif %}
{% if h.ups_vin %}<div style="height:160px"><canvas id="upv"></canvas></div><script>drawSeries('upv',[{label:'Input V',color:'#a855f7',data:{{ h.ups_vin|tojson }}}],{plain:true});</script>{% endif %}</div></div>{% endif %}
{% if h.cam %}<div class="card"><h2>Recorder {% if not h.cam.ok %}<span class="badge sev-critical">{{ h.cam.error or 'no reply' }}</span>{% endif %}</h2>
<p class="muted">{{ h.cam.device.model or '' }} {{ h.cam.device.firmware or '' }} {{ h.cam.device.name or '' }}</p>
{% if h.cam.disks %}<table><tr><th>Disk</th><th>Status</th><th>Free</th></tr>{% for d in h.cam.disks %}<tr><td>{{ d.name }}</td><td>{{ d.status }}</td><td>{{ d.free_mb or '—' }} MB</td></tr>{% endfor %}</table>{% endif %}
{% if h.cam.channels %}<p class="hint">{% for ch in h.cam.channels %}Channel {{ ch.id }} {{ 'offline' if ch.online is sameas false else 'online' }} {{ ch.name or '' }} · {% endfor %}</p>{% endif %}
</div>{% endif %}
{% if h.backups %}<div class="card"><h2>Config backups</h2>
<table><tr><th>When</th><th>Result</th><th></th></tr>{% for b in h.backups %}<tr>
<td>{{ b.when }}</td><td>{% if b.ok %}weekly{% if b.changed %} · changed{% else %} · same{% endif %}{% else %}<span class="badge sev-critical">failed</span> {{ b.error }}{% endif %}</td>
<td>{% if b.ok %}<a href="{{ url_for('backup_download', bid=b.id) }}">export</a>{% if b.bin_path %} · <a href="{{ url_for('backup_download', bid=b.id, kind='bin') }}">binary</a>{% endif %}{% endif %}</td></tr>{% endfor %}</table>
{% if h.backup_diff %}<pre class="hint" style="white-space:pre-wrap">{{ h.backup_diff }}</pre>{% endif %}
</div>{% endif %}
<div class="card"><h2>Events</h2>""" + EVENTS_TABLE + """</div>"""


def snmp_view(h, tz, full=False, since=None):
    cfg = host_snmp_cfg(h)
    if not cfg["enabled"]:
        return None
    now = time.time()
    since = now - 86400 if since is None else since
    with db() as c:
        row = c.execute("SELECT data FROM snmp_state WHERE host_id=?", (h["id"],)).fetchone()
        d = json.loads(row["data"]) if row else {}
        if full:
            samples = c.execute(
                f"SELECT ts, cpu, mem, ifs, temp, extra FROM snmp_samples WHERE host_id=? AND {jobs.TIER} ORDER BY ts",
                (h["id"], *jobs.tier_args(since, now))).fetchall()
    s = get_settings()
    d.setdefault("ifaces", [])
    d.setdefault("extra", {})
    d.setdefault("storage", [])
    for k in ("cpu", "mem_pct", "cpu_cores", "sysName", "sysDescr", "sysLocation", "error"):
        d.setdefault(k, None)
    d["cfg"] = {"ifaces": cfg["ifaces"] or [], "alert_ifaces": cfg["alert_ifaces"] or []}
    d["uptime_txt"] = fmt_dur(d["sysUpTime"] / 100) if isinstance(d.get("sysUpTime"), int) else "—"
    d["last_txt"] = fmt_ts(d.get("ts"), tz) if d.get("ts") else "never"
    d["stale"] = not d.get("ts") or time.time() - d["ts"] > 3 * max(60, s["snmp_interval"])
    names = set(d["cfg"]["ifaces"]) | set(d["cfg"]["alert_ifaces"])
    d["watched"] = [i for i in d["ifaces"] if i["name"] in names][:8]
    if full:
        d["cpu_pts"] = [[r["ts"], r["cpu"]] for r in samples if r["cpu"] is not None]
        d["mem_pts"] = [[r["ts"], r["mem"]] for r in samples if r["mem"] is not None]
        d["temp_pts"] = [[r["ts"], r["temp"]] for r in samples if r["temp"] is not None]
        d["ups_charge"], d["ups_load"], d["ups_vin"] = [], [], []
        for r in samples:
            try:
                ex = json.loads(r["extra"] or "{}")
            except (TypeError, ValueError):
                ex = {}
            if ex.get("ups_charge") is not None:
                d["ups_charge"].append([r["ts"], ex["ups_charge"]])
            if ex.get("ups_load") is not None:
                d["ups_load"].append([r["ts"], ex["ups_load"]])
            if ex.get("ups_vin") is not None:
                d["ups_vin"].append([r["ts"], ex["ups_vin"]])
        d["ups"] = d.get("ups") or {}
        tr = {n: ([], []) for n in d["cfg"]["ifaces"]}
        for r in samples:
            for n, (bi, bo) in json.loads(r["ifs"] or "{}").items():
                if n in tr and bi is not None:
                    tr[n][0].append([r["ts"], bi])
                    tr[n][1].append([r["ts"], bo])
        d["traffic"] = list(tr.items())
    return d


def page(body_tpl, refresh=None, charts=False, **ctx):
    s = get_settings()
    body = render_template_string(body_tpl, s=s, **ctx)
    return render_template_string(LAYOUT, body=body, s=s, refresh=refresh, charts=charts)


def host_view(row, since, tz, full=False):
    h = dict(row)
    now = time.time()
    with db() as c:
        rows = c.execute(
            f"SELECT ts, ok, ms, n, nok FROM results WHERE host_id=? AND {jobs.TIER} ORDER BY ts",
            (h["id"], *jobs.tier_args(since, now))).fetchall()
    pts = []
    total_n = total_ok = 0
    for r in rows:
        n = r["n"] or 1
        nok = r["nok"] if r["nok"] is not None else r["ok"]
        total_n += n
        total_ok += nok
        pts.append((r["ts"], 0 if nok == 0 else 1, r["ms"]))
    h["points"] = pts
    h["uptime"] = (100.0 * total_ok / total_n) if total_n else None
    h["last_seen_txt"] = fmt_ts(h["last_seen"], tz)
    h["down_for"] = fmt_dur(time.time() - h["down_since"]) if h["down_since"] else ""
    h["maint"] = host_maint(h, get_settings())
    h["sn"] = snmp_view(h, tz, full, since)
    if not h["enabled"]:
        h["state"] = "disabled"
    return h


def event_rows(where="1=1", args=(), limit=30, tz=None):
    with db() as c:
        rows = c.execute(f"SELECT * FROM events WHERE {where} ORDER BY id DESC LIMIT ?", (*args, limit)).fetchall()
    out = []
    for r in rows:
        e = dict(r)
        e["time"] = fmt_ts(e["ts"], tz)
        e["d"] = json.loads(e["details"] or "{}")
        e["att"] = json.loads(e["attachments"] or "[]")
        e["message"] = e["message"] or ""
        out.append(e)
    return out


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        ip = client_ip()
        fails = [t for t in _login_fail.get(ip, []) if t > time.time() - 900]
        if len(fails) >= 10:
            abort(429, "Too many failed logins - try again in 15 minutes")
        pw = request.form.get("password", "")
        s = get_settings()
        r = "admin" if verify_password(pw, s["admin_hash"]) else \
            ("viewer" if s["viewer_hash"] and verify_password(pw, s["viewer_hash"]) else None)
        if r:
            session.clear()
            session.permanent = True
            session["role"] = r
            _login_fail.pop(ip, None)
            nxt = request.args.get("next", "/")
            return redirect(nxt if nxt.startswith("/") and not nxt.startswith("//") else "/")
        _login_fail[ip] = fails + [time.time()]
        log.warning("Failed login from %s", ip)
        time.sleep(1)
        flash("Wrong password")
    return page(LOGIN_BODY)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


def _private_host(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return addr.is_private or addr.is_loopback


def _wan_card(since):
    now = time.time()
    with db() as c:
        status = c.execute("SELECT state, detail FROM wan_status WHERE id=1").fetchone()
        rows = c.execute(
            f"SELECT ts, target, loss, avg_ms, jitter FROM wan_samples WHERE {jobs.TIER} ORDER BY ts",
            jobs.tier_args(since, now)).fetchall()
    if not status and not rows:
        return None
    latest = {}
    latency, loss = [], []
    for row in rows:
        latest[row["target"]] = {"target": row["target"], "loss": row["loss"], "avg_ms": row["avg_ms"], "jitter": row["jitter"]}
        if row["avg_ms"] is not None:
            latency.append([row["ts"], row["avg_ms"]])
        if row["loss"] is not None:
            loss.append([row["ts"], row["loss"]])
    try:
        targets = json.loads(status["detail"]) if status and status["detail"] else list(latest.values())
    except (TypeError, ValueError):
        targets = list(latest.values())
    return {"state": status["state"] if status else "unknown", "targets": targets, "latency": latency, "loss": loss}


def _traffic_cards(since):
    now = time.time()
    cards = []
    with db() as c:
        chosen = c.execute(
            "SELECT d.host_id, d.iface, d.color_in, d.color_out, h.name FROM dash_ifaces d JOIN hosts h ON h.id=d.host_id ORDER BY h.name, d.iface").fetchall()
        for row in chosen:
            samples = c.execute(
                f"SELECT ts, ifs FROM snmp_samples WHERE host_id=? AND {jobs.TIER} ORDER BY ts",
                (row["host_id"], *jobs.tier_args(since, now))).fetchall()
            inn, out = [], []
            for sample in samples:
                try:
                    pair = json.loads(sample["ifs"] or "{}").get(row["iface"])
                except (TypeError, ValueError):
                    pair = None
                if pair and pair[0] is not None:
                    inn.append([sample["ts"], pair[0]])
                    out.append([sample["ts"], pair[1]])
            cards.append({"host": row["name"], "iface": row["iface"], "color_in": row["color_in"],
                          "color_out": row["color_out"], "inn": inn, "out": out})
    return cards


@app.route("/")
@viewer_required
def index():
    tz = tzinfo()
    span, seconds = current_span()
    since = time.time() - seconds
    with db() as c:
        rows = c.execute("SELECT * FROM hosts ORDER BY grp, CASE state WHEN 'down' THEN 0 WHEN 'warn' THEN 1 ELSE 2 END, name").fetchall()
    hosts = [host_view(r, since, tz) for r in rows]
    wan = _wan_card(since)
    for h in hosts:
        h["lan_down"] = h["state"] == "down" and not h.get("maint") and wan and wan["state"] == "up" and _private_host(h["host"])
    groups, idx = [], {}
    for h in hosts:
        if h["grp"] not in idx:
            idx[h["grp"]] = len(groups)
            groups.append((h["grp"], []))
        groups[idx[h["grp"]]][1].append(h)
    counts = {k: sum(1 for h in hosts if h["state"] == k) for k in ("up", "down", "warn", "pending")}
    alarms = _alarm_rows(tzinfo())
    banner = None
    lan_up = any(h["state"] == "up" and _private_host(h["host"]) for h in hosts)
    if wan and wan["state"] == "down":
        banner = {"cls": "bad", "text": "Internet down (LAN OK)" if lan_up else "Internet down"}
    elif any(h.get("lan_down") for h in hosts):
        names = ", ".join(h["name"] for h in hosts if h.get("lan_down"))
        banner = {"cls": "warn", "text": "LAN device down: " + names}
    return page(INDEX_BODY, refresh=60, charts=True, groups=groups, c=counts, events=event_rows(limit=25, tz=tz),
                now=fmt_ts(time.time(), tz), span=span, spans=list(SPAN_LABEL.items()), win_ms=seconds * 1000,
                wan=wan, traffic=_traffic_cards(since), banner=banner, alarms=alarms, bar=_status_bar(hosts, wan, alarms))


@app.route("/host/<int:hid>")
@viewer_required
def host_page(hid):
    tz = tzinfo()
    span, seconds = current_span()
    with db() as c:
        row = c.execute("SELECT * FROM hosts WHERE id=?", (hid,)).fetchone()
    if not row:
        abort(404)
    h = host_view(row, time.time() - seconds, tz, full=True)
    sn = h.get("sn") or {}
    h["temp_pts"] = sn.get("temp_pts")
    h["ups"] = sn.get("ups") if sn.get("ups") and not sn["ups"].get("error") else None
    h["ups_charge"] = sn.get("ups_charge")
    h["ups_load"] = sn.get("ups_load")
    h["ups_vin"] = sn.get("ups_vin")
    with db() as c:
        cam = c.execute("SELECT data FROM cam_state WHERE host_id=?", (hid,)).fetchone()
        baks = c.execute("SELECT * FROM backups WHERE host_id=? ORDER BY ts DESC LIMIT 20", (hid,)).fetchall()
    h["cam"] = json.loads(cam["data"]) if cam and cam["data"] else None
    h["backups"] = [{"id": b["id"], "when": fmt_ts(b["ts"], tz), "ok": b["ok"], "changed": b["changed"],
                     "error": b["error"], "bin_path": b["bin_path"]} for b in baks]
    h["backup_diff"] = next((b["diff"] for b in baks if b["ok"] and b["changed"] and b["diff"]), "")
    return page(HOST_BODY, refresh=60, charts=True, h=h, events=event_rows("host_id=?", (hid,), 50, tz),
                span=span, spans=list(SPAN_LABEL.items()), win_ms=seconds * 1000)


@app.route("/snapshot/<name>")
@viewer_required
def snapshot(name):
    if not re.fullmatch(r"ev\d+_\d\.(jpg|png)", name):
        abort(404)
    return send_from_directory(SNAP_DIR, name, max_age=86400)


@app.route("/healthz")
def healthz():
    return "ok"


# Used only when assets/wirewave_logo.jpg is not next to this script.
LOGO_FALLBACK_B64 = "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"


def _logo_file():
    base = os.path.dirname(os.path.abspath(__file__))
    for rel in ("assets/wirewave_logo.jpg", "wirewave_logo.jpg"):
        path = os.path.join(base, rel)
        if os.path.isfile(path):
            return path
    return None


@app.route("/favicon.ico")
@app.route("/logo.jpg")
def brand_logo():
    """Logo next to the script, or the copy baked into this file if that is missing."""
    path = _logo_file()
    if path:
        return send_from_directory(os.path.dirname(path), os.path.basename(path),
                                   mimetype="image/jpeg", max_age=86400)
    return Response(base64.b64decode(LOGO_FALLBACK_B64), mimetype="image/jpeg",
                    headers={"Cache-Control": "public, max-age=86400"})


# ----------------------------------------------------------------------------- settings page
def _secret_input(name):
    return ('<input type="password" name="' + name + '" autocomplete="new-password" placeholder="'
            '{{ (\'saved \' + mask(s.' + name + ') + \' - leave empty to keep\') if s.' + name + ' else \'not set\' }}">')


SETTINGS_BODY = """
<div class="nav"><a href="#general">General</a><a href="#hosts">Hosts</a><a href="#alerts">Alerts</a><a href="#internet">Internet</a>
<a href="#graphs">Dashboard graphs</a><a href="#backups">Backups</a><a href="#telegram">Telegram</a><a href="#email">Outgoing e-mail</a>
<a href="#receiver">Incoming e-mail (devices)</a><a href="#snmp">SNMP + traps</a><a href="#webhook">Webhook</a><a href="#api">API</a><a href="{{ url_for('alarm_settings') }}">Alarms</a><a href="#password">Passwords</a></div>

<div class="card" id="hosts"><h2>Hosts</h2>
<p class="section-intro">Each row is one device this monitor pings. Add a camera, router, access point or server you want to watch. Save a row after you change it.</p>
<ul class="help-list">
<li><b>Name</b> — label on the dashboard and in alerts. Example: <code>Reception NVR</code>. Use a name you will recognise in a message.</li>
<li><b>IP / hostname</b> — address that is pinged. Example: <code>192.168.1.50</code> or <code>nvr.lan</code>. Use the address of the device on this LAN.</li>
<li><b>Group / location</b> — groups the cards on the dashboard. Example: <code>Cameras</code>, <code>Wi-Fi</code>, <code>Network</code>. Leave it blank on a very small site.</li>
<li><b>Device type</b> — badge colour, and a hint when an alarm e-mail is parsed. Example: Hikvision camera / NVR. Pick the closest brand.</li>
<li><b>On</b> — untick to stop pinging without deleting history. Use it while a device is powered off for maintenance.</li>
<li><b>SNMP</b> — opens that host's SNMP page (community or v3 user, which ports to graph). Use it when the device answers SNMP.</li>
<li><b>Fails</b> — missed pings before this host's alarm. Example: <code>3</code>. <code>0</code> uses the global “Failed pings before alert” (default 3).</li>
<li><b>Ping s</b> — seconds between pings for this host only. Example: <code>30</code>. Empty or <code>0</code> uses the global ping interval.</li>
<li><b>Repeat min</b> — resend the DOWN alarm while it stays down. Example: <code>15</code>. Empty uses the global repeat (default 30). <code>0</code> means never repeat for this host.</li>
<li><b>Maintenance until</b> — no alerts for this host until that time, and the card shows MAINT. Example: tonight 22:00 while you replace a switch. Clear the field to turn it off.</li>
<li><b>API</b> — Hikvision or Dahua username and password, checked on the recorder's own HTTP API.</li>
<li><b>Backup</b> — MikroTik export account. Use a user that can read the config, not the full admin if you can avoid it.</li>
</ul>
<table><tr><th>Name</th><th>IP / hostname</th><th>Group</th><th>Type</th><th>On</th><th>Fails</th><th>Ping s</th><th>Repeat</th><th>Maintenance until</th><th></th></tr>
{% for h in hosts %}<tr>
<td><input type="text" form="hf{{ h.id }}" name="name" value="{{ h.name }}" required maxlength="60" style="width:150px"></td>
<td><input type="text" form="hf{{ h.id }}" name="host" value="{{ h.host }}" required maxlength="253" style="width:140px"></td>
<td><input type="text" form="hf{{ h.id }}" name="grp" value="{{ h.grp }}" maxlength="60" style="width:120px"></td>
<td><select form="hf{{ h.id }}" name="device_type">{% for k, v in DEVICE_TYPES.items() %}<option value="{{ k }}" {{ 'selected' if k==h.device_type }}>{{ v[0] }}</option>{% endfor %}</select></td>
<td><input type="checkbox" form="hf{{ h.id }}" name="enabled" value="1" {{ 'checked' if h.enabled }}></td>
<td><input type="number" form="hf{{ h.id }}" name="fail_n" min="0" max="20" value="{{ h.fail_n or 0 }}" style="width:58px" title="0 = use the global fail count"></td>
<td><input type="number" form="hf{{ h.id }}" name="ping_every" min="0" max="3600" value="{{ h.ping_every or '' }}" style="width:64px" placeholder="global" title="0 or empty = global ping interval"></td>
<td><input type="number" form="hf{{ h.id }}" name="repeat_min" min="0" max="1440" value="{{ '' if h.repeat_min is not defined or h.repeat_min < 0 else h.repeat_min }}" style="width:64px" placeholder="global" title="empty = global, 0 = never"></td>
<td><input type="datetime-local" form="hf{{ h.id }}" name="maint_local" value="{{ h.maint_local }}"></td>
<td style="white-space:nowrap"><a href="{{ url_for('host_snmp', hid=h.id) }}">SNMP</a>
 · <a href="{{ url_for('host_camera', hid=h.id) }}">API</a>
 · <a href="{{ url_for('host_backup', hid=h.id) }}">Backup</a><br>
<form id="hf{{ h.id }}" method="post" action="{{ url_for('host_save', hid=h.id) }}" style="display:inline"><input type="hidden" name="csrf" value="{{ csrf_token() }}"><button>Save</button></form>
<form method="post" action="{{ url_for('host_delete', hid=h.id) }}" style="display:inline" onsubmit="return confirm('Delete {{ h.name }} and its history?')"><input type="hidden" name="csrf" value="{{ csrf_token() }}"><button class="del">Delete</button></form></td></tr>
{% endfor %}
<tr>
<td><input type="text" form="hadd" name="name" placeholder="e.g. Reception NVR" required maxlength="60" style="width:150px"></td>
<td><input type="text" form="hadd" name="host" placeholder="192.168.1.10" required maxlength="253" style="width:140px"></td>
<td><input type="text" form="hadd" name="grp" placeholder="e.g. Cameras" maxlength="60" style="width:120px"></td>
<td><select form="hadd" name="device_type">{% for k, v in DEVICE_TYPES.items() %}<option value="{{ k }}">{{ v[0] }}</option>{% endfor %}</select></td>
<td><input type="checkbox" form="hadd" name="enabled" value="1" checked></td><td></td><td></td><td></td><td></td>
<td><form id="hadd" method="post" action="{{ url_for('host_add') }}"><input type="hidden" name="csrf" value="{{ csrf_token() }}"><button>+ Add</button></form></td></tr></table></div>

<div class="card" id="general"><h2>General</h2>
<p class="section-intro">Name of this site, how often it pings, and who may open the dashboard. The address the web page itself listens on (the LAN and localhost together, or localhost only) is set by the installer, not here.</p>
<form method="post" action="{{ url_for('save_section', section='general') }}"><input type="hidden" name="csrf" value="{{ csrf_token() }}">
<div class="form-grid">
<label>Site / client name</label><div><input type="text" name="site_name" value="{{ s.site_name }}" required maxlength="80">
<p class="hint">Put at the start of every alert so you can tell sites apart. Example: <code>Hotel Nikiana</code>. Set one name per installation.</p></div>
<label>Timezone</label><div><input type="text" name="timezone" value="{{ s.timezone }}" list="tzs"><datalist id="tzs">{% for z in tzs %}<option>{{ z }}</option>{% endfor %}</datalist>
<p class="hint">Clock used for the dashboard, events and alert times. Example: <code>Europe/Athens</code>. Pick the zone where the devices are. The installer does not change this; set the PC clock with <code>timedatectl</code> as well.</p></div>
<label>Ping interval (seconds)</label><div><input type="number" name="ping_interval" min="10" max="3600" value="{{ s.ping_interval }}">
<p class="hint">How often each host is pinged. Example: <code>60</code>. Use 30 on a small site, or 120 if you watch a lot of devices.</p></div>
<label>Ping timeout (seconds)</label><div><input type="number" name="ping_timeout" min="1" max="10" value="{{ s.ping_timeout }}">
<p class="hint">How long one ping may take before it counts as a miss. Example: <code>2</code>. Raise it only on a slow or lossy link.</p></div>
<span id="alerts"></span>
<label>Failed pings before alert</label><div><input type="number" name="fail_threshold" min="1" max="20" value="{{ s.fail_threshold }}">
<p class="hint">Global default for how many missed pings in a row raise a DOWN alarm. Example: <code>3</code>. A host can override this with its own Fails column (0 on the host means “use this number”).</p></div>
<label>Alarm repeat (minutes)</label><div><input type="number" name="repeat_min" min="0" max="1440" value="{{ s.repeat_min }}">
<p class="hint">While a host stays down, send the alarm again every this many minutes. Example: <code>30</code>. Use <code>0</code> to never repeat. A host can override it; an empty Repeat field on the host uses this number.</p></div>
<label>Keep history (days)</label><div><input type="number" name="retention_days" min="1" max="365" value="{{ s.retention_days }}">
<p class="hint">How long ping and SNMP samples are kept. Example: <code>30</code>. Use fewer days on a small disk.</p></div>
<label>Ping method</label><div><select name="ping_method">{% for m in ['auto','icmplib','system'] %}<option {{ 'selected' if s.ping_method==m }}>{{ m }}</option>{% endfor %}</select>
<p class="hint"><code>auto</code> tries a raw ICMP library, then the system <code>ping</code> command. Use <code>system</code> on Windows, or if raw ICMP is blocked. Use <code>icmplib</code> when you want the library only.</p></div>
<label>Public URL (optional)</label><div><input type="url" name="public_url" value="{{ s.public_url }}" placeholder="https://hotel.monitor.example.com">
<p class="hint">Address written into alert links. Example: <code>https://hotel-monitor.example.com</code>. Set this to the Cloudflare Tunnel hostname. Leave it empty if you only open the page on the LAN.</p></div>
<label>Dashboard access</label><div><select name="dashboard_access"><option value="login" {{ 'selected' if s.dashboard_access=='login' }}>Login required (admin or viewer password)</option>
<option value="public" {{ 'selected' if s.dashboard_access=='public' }}>Public read-only (no login)</option></select>
<p class="hint"><b>Login required</b> is the right choice on a LAN. <b>Public read-only</b> shows the dashboard to anyone who can open the page; Settings still needs the admin password. Use public only for a wall display.</p></div>
<label>Viewer password (dashboard only)</label><div><input type="password" name="viewer_password" autocomplete="new-password" placeholder="{{ 'set - leave empty to keep' if s.viewer_hash else 'not set' }}" style="width:60%">
<label class="hint"><input type="checkbox" name="viewer_clear" value="1"> remove viewer password</label>
<p class="hint">Optional second password that can see the dashboard but not change settings. Example: a password for reception. At least 6 characters. Leave it empty to keep the current one. Tick remove to clear it.</p></div>
<span></span><div><button>Save general settings</button> <span class="hint">Ping method in use: {{ ping_name }}</span></div></div></form></div>

<div class="card" id="telegram"><h2>Telegram</h2>
<p class="section-intro">Sends a Telegram message when a host goes down or comes back, and for device or SNMP alerts that are set to be forwarded.</p>
<form method="post" action="{{ url_for('save_section', section='telegram') }}"><input type="hidden" name="csrf" value="{{ csrf_token() }}">
<div class="form-grid">
<label>Enabled</label><div><input type="checkbox" name="telegram_enabled" value="1" {{ 'checked' if s.telegram_enabled }}>
<p class="hint">Turn Telegram alerts on or off. Turn it on after the token and chat ID are saved and a test message arrives.</p></div>
<label>Bot token</label><div>""" + _secret_input("telegram_token") + """
<p class="hint">From @BotFather, command <code>/newbot</code>. Example: <code>123456789:AAH...</code>. Leave this blank when saving to keep the token already stored. Use it when you create the bot.</p></div>
<label>Chat ID</label><div><input type="text" name="telegram_chat_id" value="{{ s.telegram_chat_id }}" placeholder="123456789 or -100...">
<p class="hint">Where the messages go. Example: <code>123456789</code> for a person, or <code>-1001234567890</code> for a group. Open the bot, press Start, then read the id from getUpdates.</p></div>
<label>Send camera snapshots</label><div><input type="checkbox" name="telegram_photos" value="1" {{ 'checked' if s.telegram_photos }}>
<p class="hint">Attach the picture from a camera alarm e-mail. Leave it on for cameras. Turn it off if the chat should stay text only.</p></div>
<span></span><div><button>Save</button> <button formaction="{{ url_for('test_channel', ch='telegram') }}" class="sec">Save + send test</button></div></div></form></div>

<div class="card" id="email"><h2>Outgoing e-mail (alerts to you, via SMTP)</h2>
<p class="section-intro">Mail this monitor sends to you. It is not the mail cameras send in (that is the next section).</p>
<form method="post" action="{{ url_for('save_section', section='email') }}"><input type="hidden" name="csrf" value="{{ csrf_token() }}">
<div class="form-grid">
<label>Enabled</label><div><input type="checkbox" name="email_enabled" value="1" {{ 'checked' if s.email_enabled }}>
<p class="hint">Send alert e-mail. Turn it on after the server, the From address and the To address are filled in, then use the test button.</p></div>
<label>SMTP server</label><div><input type="text" name="smtp_host" value="{{ s.smtp_host }}" placeholder="smtp.gmail.com">
<p class="hint">Your provider's outgoing server. Example: <code>smtp.gmail.com</code> or <code>smtp.office365.com</code>. Use the server that hosts the From mailbox.</p></div>
<label>Port</label><div><input type="number" name="smtp_port" value="{{ s.smtp_port }}" min="1" max="65535">
<p class="hint">Match the security below. Example: <code>587</code> for STARTTLS, <code>465</code> for SSL, <code>25</code> for plain SMTP.</p></div>
<label>Security</label><div><select name="smtp_security">{% for k, v in [('none','None (plain, port 25)'),('starttls','STARTTLS (port 587)'),('ssl','SSL/TLS (port 465)')] %}<option value="{{ k }}" {{ 'selected' if s.smtp_security==k }}>{{ v }}</option>{% endfor %}</select>
<p class="hint">How the connection is encrypted. Use STARTTLS on port 587 for Gmail and Microsoft 365. Use SSL on port 465 if the provider asks for it.</p></div>
<label>Username</label><div><input type="text" name="smtp_user" value="{{ s.smtp_user }}" autocomplete="off" placeholder="empty = no login">
<p class="hint">Login for that server. Example: <code>monitor@yourdomain.gr</code>. Leave it empty only if the server does not ask you to log in.</p></div>
<label>Password</label><div>""" + _secret_input("smtp_password") + """
<p class="hint">Mailbox password, or an app password when the provider requires one. Leave it blank when saving to keep the password already stored.</p></div>
<label>From</label><div><input type="text" name="smtp_from" value="{{ s.smtp_from }}" placeholder="monitor@yourdomain">
<p class="hint">Address the alert is sent from. Example: <code>monitor@yourdomain.gr</code>. Often the same as the username.</p></div>
<label>To (comma separated)</label><div><input type="text" name="smtp_to" value="{{ s.smtp_to }}" placeholder="you@x.gr, tech@x.gr">
<p class="hint">Who receives the alerts. Example: <code>you@example.com, tech@example.com</code>. Separate several people with commas.</p></div>
<span></span><div><button>Save</button> <button formaction="{{ url_for('test_channel', ch='email') }}" class="sec">Save + send test e-mail</button></div></div></form></div>

<div class="card" id="receiver"><h2>Incoming e-mail receiver (alerts FROM cameras, NVRs, controllers)</h2>
<p class="section-intro">Cameras and recorders send their alarm mail to this machine. The monitor reads the message, shows it on the dashboard, and can forward it.</p>
<p class="hint">Point Hikvision / Dahua / UniFi / Omada / MikroTik e-mail settings at this box (its LAN IP) and this port.
Mails are parsed (motion, HDD error, video loss, device offline, ...), shown on the dashboard and forwarded to your channels.
Status: <b>{{ rx_status }}</b></p>
<form method="post" action="{{ url_for('save_section', section='receiver') }}"><input type="hidden" name="csrf" value="{{ csrf_token() }}">
<div class="form-grid">
<label>Enabled</label><div><input type="checkbox" name="rx_enabled" value="1" {{ 'checked' if s.rx_enabled }}>
<p class="hint">Accept alarm e-mail from devices. Turn it on when the cameras are set to use this machine as their SMTP server.</p></div>
<label>Listen address</label><div><input type="text" name="rx_host" value="{{ s.rx_host }}" placeholder="0.0.0.0 = all LAN interfaces">
<p class="hint">Interface that waits for device mail. Example: <code>0.0.0.0</code> so every LAN device can connect. Use <code>127.0.0.1</code> only for a test on this PC.</p></div>
<label>Port</label><div><input type="number" name="rx_port" value="{{ s.rx_port }}" min="1" max="65535">
<p class="hint">Port the devices must use. Example: <code>2525</code>. Put the same number in the camera's SMTP settings. Port 25 also works; the service may bind low ports.</p></div>
<label>Security</label><div><select name="rx_security">{% for k, v in [('none','None - plain SMTP (old devices)'),('starttls','STARTTLS offered (plain still allowed)'),('ssl','SSL/TLS (implicit, like port 465)')] %}<option value="{{ k }}" {{ 'selected' if s.rx_security==k }}>{{ v }}</option>{% endfor %}</select>
<p class="hint">Encryption the camera must speak. Example: <code>None</code> for most old Hikvision and Dahua cameras. Use STARTTLS or SSL only when the device supports it.</p></div>
<label>Require login (AUTH)</label><div><input type="checkbox" name="rx_require_auth" value="1" {{ 'checked' if s.rx_require_auth }}>
<p class="hint">Ask the device for the username and password below. Turn it on if this port is reachable from outside a trusted LAN. Leave it off for old cameras that cannot log in.</p></div>
<label>Username</label><div><input type="text" name="rx_user" value="{{ s.rx_user }}">
<p class="hint">SMTP user the camera must send. Example: <code>alerts</code>. It is used only when login is required. Type the same user into the camera.</p></div>
<label>Password</label><div>""" + _secret_input("rx_password") + """
<p class="hint">SMTP password the camera must send. Leave it blank when saving to keep the stored password. Set it when login is required.</p></div>
<label>Allowed sender networks</label><div><input type="text" name="rx_allowed_nets" value="{{ s.rx_allowed_nets }}">
<p class="hint">Mail from any other network is refused. Example: <code>192.168.0.0/16, 10.0.0.0/8</code>. Keep your LAN ranges. The same list is used for SNMP traps.</p></div>
<label>Forward to Telegram/e-mail/webhook</label><div><select name="rx_forward_min">{% for k, v in [('info','Everything (incl. motion)'),('warning','Warnings + critical (no motion)'),('critical','Critical only'),('none','Nothing (dashboard only)')] %}<option value="{{ k }}" {{ 'selected' if s.rx_forward_min==k }}>{{ v }}</option>{% endfor %}</select>
<p class="hint">Which device mails are also sent out. Example: Warnings + critical, so motion stays on the dashboard and disk or offline alarms are forwarded.</p></div>
<label>Max 1 forward per device+type every (s)</label><div><input type="number" name="rx_rate_limit" value="{{ s.rx_rate_limit }}" min="0" max="86400">
<p class="hint">Quiet period so one camera cannot flood you. Example: <code>300</code> (5 minutes) per device and event type. Use <code>0</code> to forward every message.</p></div>
<span></span><div><button>Save + restart receiver</button></div></div></form></div>

<div class="card" id="snmp"><h2>SNMP polling + trap receiver</h2>
<p class="section-intro">Polling asks each device for CPU, memory and interfaces. Traps are messages the device sends on its own, for example when a port goes down. Per-device community and v3 passwords are on each host's SNMP page (the gear icon in the hosts table).</p>
<p class="hint">Trap receiver status: <b>{{ trap_status }}</b>{% if not snmp_ok %} · <b style="color:#dc2626">pysnmp not installed</b>{% endif %}</p>
<form method="post" action="{{ url_for('save_section', section='snmp') }}"><input type="hidden" name="csrf" value="{{ csrf_token() }}">
<div class="form-grid">
<label>SNMP polling enabled</label><div><input type="checkbox" name="snmp_enabled" value="1" {{ 'checked' if s.snmp_enabled }}>
<p class="hint">Master switch for reading devices. Leave it on if any host has SNMP turned on. Turn it off to stop all polling.</p></div>
<label>Poll interval (seconds)</label><div><input type="number" name="snmp_interval" value="{{ s.snmp_interval }}" min="30" max="3600">
<p class="hint">How often each SNMP host is read. Example: <code>300</code> (5 minutes). Use 60–120 for a few devices, 300 for a large site.</p></div>
<label>Timeout (seconds)</label><div><input type="number" name="snmp_timeout" value="{{ s.snmp_timeout }}" min="1" max="10">
<p class="hint">How long to wait for one SNMP reply. Example: <code>2</code>. Raise it if a device is slow to answer.</p></div>
<label>High CPU alert at (%)</label><div><input type="number" name="snmp_cpu_threshold" value="{{ s.snmp_cpu_threshold }}" min="0" max="100">
<p class="hint">CPU percent that counts as high. Example: <code>90</code>. An alert is sent after two polls in a row above it. Use <code>0</code> to turn this alert off.</p></div>
<label>Alert on interface down</label><div><input type="checkbox" name="snmp_alert_ifdown" value="1" {{ 'checked' if s.snmp_alert_ifdown }}>
<p class="hint">Message when an interface you marked Alert goes from up to down. Turn it on for WAN and uplink ports. Choose those ports on the host's SNMP page.</p></div>
<label>Alert on device reboot</label><div><input type="checkbox" name="snmp_alert_reboot" value="1" {{ 'checked' if s.snmp_alert_reboot }}>
<p class="hint">Message when the device's uptime jumps backwards, which means it rebooted. Useful for routers and switches.</p></div>
<label>Forward SNMP poll alerts</label><div><select name="snmp_forward_min">{% for k, v in [('info','Everything (incl. link up / CPU ok)'),('warning','Warnings + critical'),('critical','Critical only'),('none','Nothing (dashboard only)')] %}<option value="{{ k }}" {{ 'selected' if s.snmp_forward_min==k }}>{{ v }}</option>{% endfor %}</select>
<p class="hint">Which poll alerts are also sent to Telegram, e-mail and the webhook. Example: Warnings + critical. Dashboard-only keeps them on this page.</p></div>
<label><b>Trap receiver enabled</b></label><div><input type="checkbox" name="trap_enabled" value="1" {{ 'checked' if s.trap_enabled }}>
<p class="hint">Listen for traps (link down, cold start, and similar). Turn it on after each device has this machine as its trap target.</p></div>
<label>Listen address</label><div><input type="text" name="trap_host" value="{{ s.trap_host }}" placeholder="0.0.0.0">
<p class="hint">Interface that receives traps. Example: <code>0.0.0.0</code> so every LAN device can send them.</p></div>
<label>UDP port</label><div><input type="number" name="trap_port" value="{{ s.trap_port }}" min="1" max="65535">
<p class="hint">Port devices send traps to. Example: <code>1162</code>, or <code>162</code> for the standard port. The device's trap target must use this same port. The service can bind port 162.</p></div>
<label>Accepted communities</label><div><input type="text" name="trap_community" value="{{ s.trap_community }}" placeholder="empty = any; e.g. public,wirewave">
<p class="hint">v1/v2c community strings to accept, separated by commas. Example: <code>wwmon</code>. Empty means any community. The sender must also be inside Allowed sender networks.</p></div>
<label>Forward traps</label><div><select name="trap_forward_min">{% for k, v in [('info','Everything (incl. linkUp)'),('warning','Warnings + critical'),('critical','Critical only (linkDown, coldStart)'),('none','Nothing (dashboard only)')] %}<option value="{{ k }}" {{ 'selected' if s.trap_forward_min==k }}>{{ v }}</option>{% endfor %}</select>
<p class="hint">Which traps are sent onward. Example: Critical only, so linkDown and coldStart are forwarded and linkUp stays on the dashboard.</p></div>
<span></span><div><button>Save + restart trap receiver</button></div></div></form></div>

<div class="card" id="webhook"><h2>Outgoing webhook (Grok Bot / automations)</h2>
<p class="section-intro">On each alert the monitor POSTs a JSON body to a URL you choose. Use it for Grok Bot or any other automation. The README lists the fields.</p>
<form method="post" action="{{ url_for('save_section', section='webhook') }}"><input type="hidden" name="csrf" value="{{ csrf_token() }}">
<div class="form-grid">
<label>Enabled</label><div><input type="checkbox" name="webhook_enabled" value="1" {{ 'checked' if s.webhook_enabled }}>
<p class="hint">Send the JSON. Turn it on after the URL answers a test.</p></div>
<label>URL</label><div><input type="url" name="webhook_url" value="{{ s.webhook_url }}" placeholder="https://...">
<p class="hint">Where the JSON is posted. Example: <code>https://bot.example.com/hook</code>. Use the address your automation gave you.</p></div>
<label>Secret header name</label><div><input type="text" name="webhook_header_name" value="{{ s.webhook_header_name }}" placeholder="Authorization or X-Webhook-Secret">
<p class="hint">HTTP header the receiver expects. Example: <code>Authorization</code> or <code>X-Webhook-Secret</code>. Match what the bot checks.</p></div>
<label>Secret header value</label><div>""" + _secret_input("webhook_header_value") + """
<p class="hint">The secret itself. Example: <code>Bearer</code> followed by a long random string. Leave it blank when saving to keep the stored value.</p></div>
<span></span><div><button>Save</button> <button formaction="{{ url_for('test_channel', ch='webhook') }}" class="sec">Save + send test</button></div></div></form></div>

<div class="card" id="api"><h2>JSON API token</h2>
<p class="section-intro">A password for scripts that read status. It is not the admin password, and it cannot change settings.</p>
<p class="hint">Send it as <code>Authorization: Bearer &lt;token&gt;</code> (best) or <code>?token=&lt;token&gt;</code> on <code>/api/status</code> and <code>/api/events</code>. Example: a Grok Bot poller. Show and Copy do not change it. Regenerate if it leaks; the old value stops working immediately.</p>
<input type="password" id="apitok" value="{{ s.api_token }}" readonly style="width:420px;font-family:monospace">
<button type="button" class="sec" onclick="const t=document.getElementById('apitok');t.type=t.type=='password'?'text':'password'">Show</button>
<button type="button" class="sec" onclick="navigator.clipboard.writeText(document.getElementById('apitok').value).then(()=>this.textContent='Copied')">Copy</button>
<form method="post" action="{{ url_for('regen_token') }}" style="display:inline" onsubmit="return confirm('Old token stops working. Continue?')"><input type="hidden" name="csrf" value="{{ csrf_token() }}"><button class="del">Regenerate</button></form></div>

<div class="card" id="password"><h2>Change admin password</h2>
<p class="section-intro">Replaces the password that opens Settings and the dashboard. It does not change the viewer password (that is under General).</p>
<form method="post" action="{{ url_for('change_password') }}"><input type="hidden" name="csrf" value="{{ csrf_token() }}">
<div class="form-grid"><label>Current password</label><div><input type="password" name="current" required>
<p class="hint">The admin password you use to log in now. It is checked before the new one is saved.</p></div>
<label>New password (min 8)</label><div><input type="password" name="new" required minlength="8">
<p class="hint">The replacement password. Example: a long phrase you do not use for e-mail. At least 8 characters.</p></div>
<label>Repeat new password</label><div><input type="password" name="new2" required minlength="8">
<p class="hint">Type the new password again. If the two do not match, nothing is changed.</p></div>
<span></span><div><button>Change password</button></div></div></form></div>
"""
BOOL_FIELDS = {"telegram_enabled", "telegram_photos", "email_enabled", "webhook_enabled", "rx_enabled", "rx_require_auth",
               "snmp_enabled", "snmp_alert_ifdown", "snmp_alert_reboot", "trap_enabled"}
SECTIONS = {
    "general": ["site_name", "timezone", "ping_interval", "ping_timeout", "fail_threshold", "repeat_min", "retention_days",
                "ping_method", "public_url", "dashboard_access"],
    "telegram": ["telegram_enabled", "telegram_token", "telegram_chat_id", "telegram_photos"],
    "email": ["email_enabled", "smtp_host", "smtp_port", "smtp_security", "smtp_user", "smtp_password", "smtp_from", "smtp_to"],
    "webhook": ["webhook_enabled", "webhook_url", "webhook_header_name", "webhook_header_value"],
    "receiver": ["rx_enabled", "rx_host", "rx_port", "rx_security", "rx_require_auth", "rx_user", "rx_password",
                 "rx_allowed_nets", "rx_forward_min", "rx_rate_limit"],
    "snmp": ["snmp_enabled", "snmp_interval", "snmp_timeout", "snmp_cpu_threshold", "snmp_alert_ifdown", "snmp_alert_reboot",
             "snmp_forward_min", "trap_enabled", "trap_host", "trap_port", "trap_community", "trap_forward_min"],
}
CHOICES = {"ping_method": {"auto", "icmplib", "system"}, "dashboard_access": {"login", "public"},
           "smtp_security": {"none", "starttls", "ssl"}, "rx_security": {"none", "starttls", "ssl"},
           "rx_forward_min": {"info", "warning", "critical", "none"}, "snmp_forward_min": {"info", "warning", "critical", "none"},
           "trap_forward_min": {"info", "warning", "critical", "none"}}
RANGES = {"ping_interval": (10, 3600), "ping_timeout": (1, 10), "fail_threshold": (1, 20), "repeat_min": (0, 1440), "retention_days": (1, 365),
          "smtp_port": (1, 65535), "rx_port": (1, 65535), "rx_rate_limit": (0, 86400),
          "snmp_interval": (30, 3600), "snmp_timeout": (1, 10), "snmp_cpu_threshold": (0, 100), "trap_port": (1, 65535)}


def _apply_section(section):
    upd = {}
    for k in SECTIONS[section]:
        if k in BOOL_FIELDS:
            upd[k] = 1 if request.form.get(k) else 0
            continue
        v = request.form.get(k, "").strip()
        if k in SECRET_KEYS and not v:
            continue  # keep saved secret
        if k in INT_KEYS:
            try:
                v = int(v)
            except ValueError:
                raise ValueError(f"{k} must be a number")
            lo, hi = RANGES.get(k, (0, 10 ** 9))
            if not lo <= v <= hi:
                raise ValueError(f"{k} must be between {lo} and {hi}")
        if k in CHOICES and v not in CHOICES[k]:
            raise ValueError(f"invalid {k}")
        if k == "timezone":
            ZoneInfo(v)
        if k in ("trap_host", "rx_host") and v:
            ipaddress.ip_address(v)
        if k == "rx_allowed_nets":
            for n in [x.strip() for x in v.split(",") if x.strip()]:
                ipaddress.ip_network(n, strict=False)
        upd[k] = v
    if section == "general":
        if request.form.get("viewer_clear"):
            upd["viewer_hash"] = ""
        elif request.form.get("viewer_password"):
            if len(request.form["viewer_password"]) < 6:
                raise ValueError("viewer password must be at least 6 characters")
            upd["viewer_hash"] = hash_password(request.form["viewer_password"])
    set_settings(**upd)


@app.route("/settings")
@admin_required
def settings():
    with db() as c:
        hosts = [dict(r) for r in c.execute("SELECT * FROM hosts ORDER BY grp, name")]
    for h in hosts:
        h["scfg"] = host_snmp_cfg(h)
        h["maint_local"] = ts_to_local_input(h.get("maint_until"))
    try:
        tzs = sorted(z for z in available_timezones() if z.startswith("Europe/"))
    except Exception:
        tzs = ["Europe/Athens"]
    return page(SETTINGS_BODY, hosts=hosts, tzs=tzs, rx_status=RECEIVER.status(), trap_status=SNMP.trap_status,
                snmp_ok=SNMP.available,
                ping_name=_ping_impl["name"] or "not started")


@app.route("/settings/<section>", methods=["POST"])
@admin_required
def save_section(section):
    if section not in SECTIONS:
        abort(404)
    try:
        _apply_section(section)
        flash(f"{section.capitalize()} settings saved.")
    except Exception as e:
        flash(f"Not saved: {e}")
        return redirect(url_for("settings") + "#" + section)
    if section == "receiver":
        RECEIVER.restart()
        flash(f"SMTP receiver: {RECEIVER.status()}")
    if section == "snmp":
        try:
            SNMP.restart_traps()
        except Exception as e:
            log.error("trap restart: %s", e)
        flash(f"SNMP trap receiver: {SNMP.trap_status}")
    if section == "general":
        app.secret_key = get_settings()["secret_key"]
    return redirect(url_for("settings") + "#" + section)


@app.route("/settings/test/<ch>", methods=["POST"])
@admin_required
def test_channel(ch):
    section = {"telegram": "telegram", "email": "email", "webhook": "webhook"}.get(ch)
    if not section:
        abort(404)
    try:
        _apply_section(section)
    except Exception as e:
        flash(f"Not saved: {e}")
        return redirect(url_for("settings") + "#" + section)
    s = get_settings()
    text = f"🔔 Test from {APP_NAME} [{s['site_name']}] - {fmt_ts(time.time())}"
    try:
        if ch == "telegram":
            send_telegram(s, text)
        elif ch == "email":
            send_email(s, f"[{APP_NAME}] [{s['site_name']}] test", text + "\n\nIf you can read this, e-mail alerts work.")
        else:
            send_webhook(s, build_payload(s, "test", None, None, None, severity="info", message=text))
        flash(f"✅ Test {ch} sent successfully.")
    except Exception as e:
        flash(f"❌ Test {ch} failed: {e}")
    return redirect(url_for("settings") + "#" + section)


def _host_form():
    name = request.form.get("name", "").strip()[:60]
    host = request.form.get("host", "").strip()
    grp = request.form.get("grp", "").strip()[:60]
    dt = request.form.get("device_type", "generic")
    if not name or not HOST_RE.match(host) or host.startswith("-"):
        raise ValueError("invalid name or IP/hostname")
    if dt not in DEVICE_TYPES:
        dt = "generic"
    raw_fail = request.form.get("fail_n", "").strip()
    try:
        fail_n = int(raw_fail) if raw_fail else 0
    except ValueError:
        raise ValueError("fails must be a number")
    if not 0 <= fail_n <= 20:
        raise ValueError("fails must be 0 (use the global number) or 1-20")
    maint = local_input_to_ts(request.form.get("maint_local", ""))
    raw_rep = request.form.get("repeat_min", "").strip()
    try:
        repeat_min = int(raw_rep) if raw_rep else -1
    except ValueError:
        raise ValueError("repeat must be a number of minutes")
    if not -1 <= repeat_min <= 1440:
        raise ValueError("repeat must be empty (use global), 0 (never) or 1-1440 minutes")
    raw_ping = request.form.get("ping_every", "").strip()
    try:
        ping_every = int(raw_ping) if raw_ping else 0
    except ValueError:
        raise ValueError("ping interval must be a number of seconds")
    if ping_every and not 10 <= ping_every <= 3600:
        raise ValueError("host ping interval must be 10-3600 seconds, or empty to use the global interval")
    return name, host, grp, dt, 1 if request.form.get("enabled") else 0, fail_n, maint, repeat_min, ping_every


@app.route("/settings/hosts/add", methods=["POST"])
@admin_required
def host_add():
    try:
        name, host, grp, dt, en, fail_n, maint, repeat_min, ping_every = _host_form()
    except ValueError as e:
        flash(f"Not added: {e}")
        return redirect(url_for("settings") + "#hosts")
    with _db_lock, db() as c:
        c.execute("INSERT INTO hosts(name, host, grp, device_type, enabled, created_at, state, fail_n, maint_until, repeat_min, ping_every) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                  (name, host, grp, dt, en, time.time(), "pending" if en else "disabled", fail_n, maint, repeat_min, ping_every))
    flash(f"Added {name} ({host}).")
    return redirect(url_for("settings") + "#hosts")


@app.route("/settings/hosts/<int:hid>/save", methods=["POST"])
@admin_required
def host_save(hid):
    try:
        name, host, grp, dt, en, fail_n, maint, repeat_min, ping_every = _host_form()
    except ValueError as e:
        flash(f"Not saved: {e}")
        return redirect(url_for("settings") + "#hosts")
    with _db_lock, db() as c:
        old = c.execute("SELECT * FROM hosts WHERE id=?", (hid,)).fetchone()
        if not old:
            abort(404)
        reset = old["host"] != host or old["enabled"] != en
        if old["host"] != host:
            c.execute("DELETE FROM snmp_state WHERE host_id=?", (hid,))
            SNMP.counters.pop(hid, None)
        c.execute("UPDATE hosts SET name=?, host=?, grp=?, device_type=?, enabled=?, fail_n=?, maint_until=?, repeat_min=?, ping_every=? WHERE id=?",
                  (name, host, grp, dt, en, fail_n, maint, repeat_min, ping_every, hid))
        if reset:  # new address or re-enabled: start fresh, no stale alerts
            c.execute("UPDATE hosts SET state=?, consec_fail=0, down_since=NULL, last_ms=NULL WHERE id=?",
                      ("pending" if en else "disabled", hid))
    flash(f"Saved {name}.")
    return redirect(url_for("settings") + "#hosts")


@app.route("/settings/hosts/<int:hid>/delete", methods=["POST"])
@admin_required
def host_delete(hid):
    with _db_lock, db() as c:
        c.execute("DELETE FROM results WHERE host_id=?", (hid,))
        c.execute("DELETE FROM snmp_state WHERE host_id=?", (hid,))
        c.execute("DELETE FROM snmp_samples WHERE host_id=?", (hid,))
        c.execute("DELETE FROM hosts WHERE id=?", (hid,))
    flash("Host deleted.")
    return redirect(url_for("settings") + "#hosts")


SNMP_HOST_BODY = """<p><a href="{{ url_for('settings') }}#hosts">← Settings / hosts</a></p>
<div class="card"><h2>SNMP for {{ h.name }} <span class="muted">{{ h.host }} · {{ DEVICE_TYPES.get(h.device_type, DEVICE_TYPES['generic'])[0] }}</span></h2>
<p class="section-intro">How this one device is polled. Save + test now checks the community or v3 password and fills in the interface list. Use a read-only community, or SNMPv3, and allow only this monitor's IP on the device.</p>
<form method="post" action="{{ url_for('host_snmp', hid=h.id) }}"><input type="hidden" name="csrf" value="{{ csrf_token() }}"><input type="hidden" name="has_ifaces" value="{{ 1 if ifaces else 0 }}">
<div class="form-grid">
<label>SNMP enabled</label><div><input type="checkbox" name="enabled" value="1" {{ 'checked' if c.enabled }}>
<p class="hint">Poll this host for uptime, CPU, memory and interfaces. Turn it on after the community or v3 user below is filled in.</p></div>
<label>Version</label><div><select name="version" onchange="document.querySelectorAll('.v3').forEach(e=>e.style.display=this.value=='3'?'':'none');document.querySelectorAll('.v2').forEach(e=>e.style.display=this.value=='3'?'none':'')">
{% for v in ['2c','1','3'] %}<option value="{{ v }}" {{ 'selected' if c.version==v }}>v{{ v }}</option>{% endfor %}</select>
<p class="hint"><b>v2c</b> is the usual choice and uses the community string. <b>v3</b> uses a user and passwords. <b>v1</b> is only for very old gear.</p></div>
<label>UDP port</label><div><input type="number" name="port" value="{{ c.port }}" min="1" max="65535">
<p class="hint">Device SNMP port. Example: <code>161</code>. Change it only when the device is not on the standard port.</p></div>
<label class="v2">Community</label><div class="v2"><input class="v2" type="password" name="community" autocomplete="new-password" placeholder="{{ ('saved ' + mask(c.community) + ' - leave empty to keep') if c.community else 'e.g. public (read-only)' }}">
<p class="hint">Read-only v1/v2c string configured on the device. Example: <code>wwmon</code>. Avoid <code>public</code> on a network you share. Leave it blank when saving to keep the stored value.</p></div>
<label class="v3">v3 user</label><div class="v3"><input class="v3" type="text" name="user" value="{{ c.user }}" autocomplete="off">
<p class="hint">SNMPv3 username on the device. Example: <code>monitor</code>. It must match exactly, including capitals.</p></div>
<label class="v3">Auth protocol</label><div class="v3"><select class="v3" name="auth_proto">{% for v in ['SHA','MD5','SHA256','none'] %}<option {{ 'selected' if c.auth_proto==v }}>{{ v }}</option>{% endfor %}</select>
<p class="hint">How the user is authenticated. Example: <code>SHA</code>. It must match the device. <code>none</code> means no authentication.</p></div>
<label class="v3">Auth password</label><div class="v3"><input class="v3" type="password" name="auth_key" autocomplete="new-password" placeholder="{{ ('saved ' + mask(c.auth_key) + ' - leave empty to keep') if c.auth_key else 'min 8 characters' }}">
<p class="hint">SNMPv3 authentication password. At least 8 characters, the same as on the device. Leave it blank when saving to keep the stored password.</p></div>
<label class="v3">Privacy protocol</label><div class="v3"><select class="v3" name="priv_proto">{% for v in ['AES','DES','AES256','none'] %}<option {{ 'selected' if c.priv_proto==v }}>{{ v }}</option>{% endfor %}</select>
<p class="hint">How the SNMP traffic is encrypted. Example: <code>AES</code>. <code>none</code> means the replies are not encrypted. Match the device.</p></div>
<label class="v3">Privacy password</label><div class="v3"><input class="v3" type="password" name="priv_key" autocomplete="new-password" placeholder="{{ ('saved ' + mask(c.priv_key) + ' - leave empty to keep') if c.priv_key else 'min 8 characters' }}">
<p class="hint">SNMPv3 encryption password, used when privacy is not <code>none</code>. At least 8 characters. Leave it blank when saving to keep the stored password.</p></div>
</div>
{% if ifaces %}<h2 style="margin-top:16px">Interfaces</h2><p class="hint">Graph draws a traffic chart on the host page. Alert sends a message when that interface goes from up to down, and again when it recovers. Tick the WAN and uplinks. Leave unused ports unticked.</p>
<table><tr><th>Interface</th><th>Status</th><th>Speed</th><th>Graph</th><th>Alert</th></tr>
{% for i in ifaces %}<tr><td><b>{{ i.name }}</b> <span class="muted">{{ i.alias }} {{ i.descr if i.descr != i.name else '' }}</span></td>
<td><span class="lnk {{ 'g' if i.oper=='up' else 'r' }}">{{ i.oper }}</span></td><td>{{ fmt_bps(i.speed) if i.speed else '—' }}</td>
<td><input type="checkbox" name="g_{{ i.name }}" value="1" {{ 'checked' if i.name in (c.ifaces or []) }}></td>
<td><input type="checkbox" name="a_{{ i.name }}" value="1" {{ 'checked' if i.name in (c.alert_ifaces or []) }}></td></tr>{% endfor %}</table>
{% else %}<p class="hint">Interfaces appear here after the first successful poll or a test. Physical interfaces that are up are selected automatically. Run Save + test now once SNMP answers.</p>{% endif %}
<p><button>Save</button> <button name="test" value="1" class="sec">Save + test now</button></p></form>
{% if test %}<div class="card" style="border:1px solid #e2e8f0;box-shadow:none">{% if test.error %}❌ <b>SNMP test failed:</b> {{ test.error }}{% else %}
✅ <b>{{ test.sysName }}</b> answered in {{ test.took }} s - {{ test.sysDescr[:150] if test.sysDescr }}<br>uptime {{ test.uptime_txt }} · CPU {{ test.cpu if test.cpu is not none else 'n/a' }} · RAM {{ test.mem_pct if test.mem_pct is not none else 'n/a' }}% · {{ test.ifaces|length }} interfaces{% for k, v in test.extra.items() %} · {{ k }} {{ v }}{% endfor %}{% endif %}</div>{% endif %}
</div><script>document.querySelector('select[name=version]').dispatchEvent(new Event('change'))</script>
"""


@app.route("/settings/hosts/<int:hid>/snmp", methods=["GET", "POST"])
@admin_required
def host_snmp(hid):
    with db() as c:
        row = c.execute("SELECT * FROM hosts WHERE id=?", (hid,)).fetchone()
        st = c.execute("SELECT data FROM snmp_state WHERE host_id=?", (hid,)).fetchone()
    if not row:
        abort(404)
    h = dict(row)
    cfg = host_snmp_cfg(h)
    ifaces = (json.loads(st["data"]).get("ifaces") if st else None) or []
    test = None
    if request.method == "POST":
        f = request.form
        try:
            cfg["enabled"] = 1 if f.get("enabled") else 0
            cfg["version"] = f.get("version") if f.get("version") in ("1", "2c", "3") else "2c"
            cfg["port"] = int(f.get("port") or 161)
            if not 1 <= cfg["port"] <= 65535:
                raise ValueError("port must be 1-65535")
            cfg["user"] = f.get("user", "").strip()[:64]
            cfg["auth_proto"] = f.get("auth_proto") if f.get("auth_proto") in ("SHA", "MD5", "SHA256", "none") else "SHA"
            cfg["priv_proto"] = f.get("priv_proto") if f.get("priv_proto") in ("AES", "DES", "AES256", "none") else "AES"
            for k in ("community", "auth_key", "priv_key"):
                if f.get(k):
                    cfg[k] = f[k].strip()[:128]
            if cfg["version"] == "3":
                if not cfg["user"]:
                    raise ValueError("SNMPv3 needs a user name")
                for k, p in (("auth_key", "auth_proto"), ("priv_key", "priv_proto")):
                    if cfg[p] != "none" and cfg[k] and len(cfg[k]) < 8:
                        raise ValueError("SNMPv3 passwords must be at least 8 characters")
            if f.get("has_ifaces") == "1":
                cfg["ifaces"] = [i["name"] for i in ifaces if f.get("g_" + i["name"])]
                cfg["alert_ifaces"] = [i["name"] for i in ifaces if f.get("a_" + i["name"])]
        except ValueError as e:
            flash(f"Not saved: {e}")
            return redirect(url_for("host_snmp", hid=hid))
        with _db_lock, db() as c:
            c.execute("UPDATE hosts SET snmp=? WHERE id=?", (json.dumps(cfg), hid))
        h["snmp"] = json.dumps(cfg)
        SNMP.last_poll.pop(hid, None)  # poll soon
        flash("SNMP settings saved.")
        if not f.get("test"):
            return redirect(url_for("host_snmp", hid=hid))
        t0 = time.time()
        try:
            test = SNMP.call(SNMP.query(h, cfg), 60)
            test["took"] = round(time.time() - t0, 2)
            test["uptime_txt"] = fmt_dur(test["sysUpTime"] / 100) if isinstance(test.get("sysUpTime"), int) else "?"
            ifaces = test["ifaces"]
            if cfg["ifaces"] is None:
                cfg["ifaces"] = [i["name"] for i in ifaces if i["type"] in IFTYPE_PHYS and i["oper"] == "up"][:8]
                cfg["alert_ifaces"] = list(cfg["ifaces"])
                with _db_lock, db() as c:
                    c.execute("UPDATE hosts SET snmp=? WHERE id=?", (json.dumps(cfg), hid))
        except Exception as e:
            test = {"error": _snmp_err(e) if not isinstance(e, RuntimeError) else str(e)}
    return page(SNMP_HOST_BODY, h=h, c=cfg, ifaces=ifaces, test=test)


@app.route("/settings/api/regenerate", methods=["POST"])
@admin_required
def regen_token():
    set_settings(api_token=secrets.token_urlsafe(32))
    flash("New API token generated - update it wherever you use it.")
    return redirect(url_for("settings") + "#api")


@app.route("/settings/password", methods=["POST"])
@admin_required
def change_password():
    s = get_settings()
    if not verify_password(request.form.get("current", ""), s["admin_hash"]):
        flash("Current password is wrong.")
    elif len(request.form.get("new", "")) < 8 or request.form.get("new") != request.form.get("new2"):
        flash("New passwords must match and be at least 8 characters.")
    else:
        set_settings(admin_hash=hash_password(request.form["new"]))
        flash("Admin password changed.")
    return redirect(url_for("settings") + "#password")


# ----------------------------------------------------------------------------- JSON API
def event_json(e, tz):
    d = json.loads(e["details"] or "{}")
    out = {"id": e["id"], "time": iso(e["ts"], tz), "source": e["source"], "type": e["kind"], "severity": e["severity"],
           "host": e["host_name"], "ip": e["host_ip"], "title": e["title"], "message": e["message"]}
    if e["source"] == "mail":
        out.update(brand=d.get("brand"), source_ip=d.get("source_ip"), subject=d.get("subject"),
                   fields=d.get("fields"), attachments=len(json.loads(e["attachments"] or "[]")))
        out["host"] = out["host"] or d.get("source_label")
    if e["source"] == "snmp":
        out.update(source_ip=d.get("source_ip"), trap=d.get("trap"), interface=d.get("interface"),
                   fields={k: v for k, v in d.items() if k not in ("type", "source_ip", "trap", "interface", "varbinds")} or None)
        if d.get("varbinds"):
            out["varbinds"] = d["varbinds"]
    return out


def snmp_json(h, tz):
    d = snmp_view(h, tz)
    if d is None:
        return None
    return {"last_poll": iso(d.get("ts"), tz) if d.get("ts") else None, "ok": not d["error"] and not d["stale"],
            "error": d["error"], "sys_name": d["sysName"], "sys_descr": d["sysDescr"],
            "uptime_seconds": int(d["sysUpTime"] / 100) if isinstance(d.get("sysUpTime"), int) else None,
            "cpu_pct": d["cpu"], "mem_pct": d["mem_pct"], "extra": d["extra"],
            "interfaces": [{"name": i["name"], "alias": i.get("alias") or None, "oper": i.get("oper"), "admin": i.get("admin"),
                            "speed_bps": i.get("speed"), "in_bps": i.get("in_bps"), "out_bps": i.get("out_bps"),
                            "errors": (i.get("inerr") or 0) + (i.get("outerr") or 0),
                            "graphed": i["name"] in d["cfg"]["ifaces"], "alerting": i["name"] in d["cfg"]["alert_ifaces"]}
                           for i in d["ifaces"] if i.get("type") != 24]}   # skip loopback


@app.route("/api/status")
@api_auth
def api_status():
    s = get_settings()
    tz = tzinfo()
    now = time.time()
    since = now - 86400
    hosts = []
    with db() as c:
        for r in c.execute("SELECT * FROM hosts ORDER BY grp, name").fetchall():
            st = c.execute("SELECT COUNT(*) n, SUM(ok) up FROM results WHERE host_id=? AND ts>=?", (r["id"], since)).fetchone()
            state = r["state"] if r["enabled"] else "disabled"
            hosts.append({
                "id": r["id"], "name": r["name"], "ip": r["host"], "group": r["grp"] or None,
                "device_type": r["device_type"], "enabled": bool(r["enabled"]), "state": state,
                "latency_ms": r["last_ms"],
                "uptime_24h": round(100.0 * (st["up"] or 0) / st["n"], 2) if st["n"] else None,
                "last_check": iso(r["last_check"], tz), "last_seen": iso(r["last_seen"], tz),
                "down_since": iso(r["down_since"], tz),
                "down_for_seconds": int(now - r["down_since"]) if r["down_since"] else None,
                "consecutive_failures": r["consec_fail"],
                "snmp": snmp_json(dict(r), tz)})
        evs = c.execute("SELECT * FROM events ORDER BY id DESC LIMIT 20").fetchall()
    summ = {k: sum(1 for h in hosts if h["state"] == k) for k in ("up", "down", "warn", "pending", "disabled")}
    summ["total"] = len(hosts)
    summ["all_ok"] = summ["down"] == 0 and summ["warn"] == 0
    summ["down_hosts"] = [h["name"] for h in hosts if h["state"] == "down"]
    summ["snmp_links_down"] = [f"{h['name']}:{i['name']}" for h in hosts if h["snmp"] for i in h["snmp"]["interfaces"]
                               if i["alerting"] and i["oper"] != "up"]
    return jsonify(site=s["site_name"], generated_at=iso(now, tz), timezone=s["timezone"], version=VERSION,
                   summary=summ, hosts=hosts, recent_events=[event_json(e, tz) for e in evs])


@app.route("/api/events")
@api_auth
def api_events():
    tz = tzinfo()
    since = parse_since(request.args.get("since"))
    since_id = int(request.args.get("since_id", 0) or 0)
    limit = max(1, min(500, int(request.args.get("limit", 100) or 100)))
    q, args = "ts > ? AND id > ?", [since, since_id]
    if request.args.get("source") in ("ping", "mail", "snmp"):
        q += " AND source=?"
        args.append(request.args["source"])
    if request.args.get("min_severity") in SEVERITY_RANK:
        allowed = [k for k, v in SEVERITY_RANK.items() if k != "none" and v >= SEVERITY_RANK[request.args["min_severity"]]]
        q += f" AND severity IN ({','.join('?' * len(allowed))})"
        args += allowed
    with db() as c:
        rows = c.execute(f"SELECT * FROM events WHERE {q} ORDER BY id ASC LIMIT ?", (*args, limit)).fetchall()
    evs = [event_json(e, tz) for e in rows]
    return jsonify(site=get_settings()["site_name"], count=len(evs), events=evs,
                   next_since_id=evs[-1]["id"] if evs else since_id)


@app.errorhandler(400)
@app.errorhandler(404)
def _api_errors(e):
    if request.path.startswith("/api/"):
        return jsonify(error=e.description if hasattr(e, "description") else str(e)), e.code
    return e


# ----------------------------------------------------------------------------- main
LOG_BODY = """<h2>Event log</h2>
<p class="hint">The newest {{ keep }} alerts. Ping and device e-mail events also stay in the dashboard section “Recent events (ping + device e-mails)”.</p>
<form method="get" class="ranges">
<select name="source"><option value="">All types</option>{% for src in sources %}<option value="{{ src }}" {{ 'selected' if src==filt }}>{{ src }}</option>{% endfor %}</select>
<button>Filter</button></form>
""" + EVENTS_TABLE


@app.route("/log")
@viewer_required
def event_log():
    keep = max(10, min(5000, int(get_settings().get("event_keep") or 100)))
    filt = request.args.get("source") or ""
    tz = tzinfo()
    if filt:
        events = event_rows("source=?", (filt,), keep, tz)
    else:
        events = event_rows(limit=keep, tz=tz)
    with db() as c:
        sources = [r[0] for r in c.execute("SELECT DISTINCT source FROM events ORDER BY source")]
    return page(LOG_BODY, events=events, sources=sources, filt=filt, keep=keep)


@app.route("/report", methods=["GET", "POST"])
@admin_required
def report_page():
    if request.method == "POST":
        lang = request.form.get("lang") if request.form.get("lang") in ("en", "el") else "en"
        days = int(request.form.get("days") or 7)
        end = time.time()
        start = end - max(1, min(days, 366)) * 86400
        data = jobs.report_context(sys.modules[__name__], start, end, lang, request.form.get("site") or "")
        logo = _logo_file()
        pdf = reportpdf.build_pdf(data, logo)
        return Response(pdf, mimetype="application/pdf",
                        headers={"Content-Disposition": f"attachment; filename=report-{lang}.pdf"})
    body = """<div class="card" style="max-width:640px"><h2>Report</h2>
<p class="section-intro">Download a PDF for a client. Greek and English are separate documents.</p>
<form method="post"><input type="hidden" name="csrf" value="{{ csrf_token() }}">
<div class="form-grid">
<label>Site name</label><div><input type="text" name="site" value="{{ s.site_name }}"></div>
<label>Range</label><div><select name="days"><option value="7">Last 7 days</option><option value="30">Last month</option></select></div>
<label>Language</label><div><select name="lang"><option value="en">English</option><option value="el">Greek</option></select></div>
<span></span><div><button>Download PDF</button></div></div></form></div>"""
    return page(body)


@app.route("/api/report.pdf")
@api_auth
def api_report():
    lang = request.args.get("lang") if request.args.get("lang") in ("en", "el") else "en"
    end = time.time()
    start = end - 7 * 86400
    if request.args.get("from"):
        try:
            start = datetime.fromisoformat(request.args["from"]).timestamp()
        except ValueError:
            pass
    if request.args.get("to"):
        try:
            end = datetime.fromisoformat(request.args["to"]).timestamp()
        except ValueError:
            pass
    data = jobs.report_context(sys.modules[__name__], start, end, lang, request.args.get("site") or "")
    pdf = reportpdf.build_pdf(data, _logo_file())
    return Response(pdf, mimetype="application/pdf")


@app.route("/settings/hosts/<int:hid>/camera", methods=["GET", "POST"])
@admin_required
def host_camera(hid):
    with db() as c:
        row = c.execute("SELECT * FROM hosts WHERE id=?", (hid,)).fetchone()
    if not row:
        abort(404)
    cfg = {}
    try:
        cfg = json.loads(row["cam"] or "{}")
    except (TypeError, ValueError):
        cfg = {}
    if request.method == "POST":
        cfg["enabled"] = 1 if request.form.get("enabled") else 0
        cfg["scheme"] = request.form.get("scheme") if request.form.get("scheme") in ("http", "https") else "http"
        try:
            cfg["port"] = int(request.form.get("port") or 80)
        except ValueError:
            cfg["port"] = 80
        cfg["user"] = request.form.get("user", "").strip()
        if request.form.get("password"):
            cfg["password"] = encrypt_secret(request.form.get("password"))
        with _db_lock, db() as c:
            c.execute("UPDATE hosts SET cam=? WHERE id=?", (json.dumps(cfg), hid))
        flash("Camera API settings saved.")
        return redirect(url_for("host_camera", hid=hid))
    body = """<p><a href="{{ url_for('settings') }}#hosts">← Hosts</a></p>
<div class="card"><h2>Camera API · {{ h.name }}</h2>
<p class="section-intro">Optional check of a Hikvision or Dahua recorder. The password is stored encrypted. NVR pictures that arrive by e-mail stay on the mail receiver; this page is the direct API.</p>
<form method="post"><input type="hidden" name="csrf" value="{{ csrf_token() }}">
<div class="form-grid">
<label>Enabled</label><div><input type="checkbox" name="enabled" value="1" {{ 'checked' if cfg.enabled }}></div>
<label>Scheme</label><div><select name="scheme"><option {{ 'selected' if cfg.scheme!='https' }}>http</option><option {{ 'selected' if cfg.scheme=='https' }}>https</option></select>
<p class="hint">Use https for a self-signed recorder. The certificate is accepted.</p></div>
<label>Port</label><div><input type="number" name="port" value="{{ cfg.port or 80 }}"></div>
<label>Username</label><div><input type="text" name="user" value="{{ cfg.user or '' }}"></div>
<label>Password</label><div><input type="password" name="password" placeholder="{{ 'saved — leave empty to keep' if cfg.password else 'not set' }}"></div>
<span></span><div><button>Save</button></div></div></form></div>"""
    return page(body, h=dict(row), cfg=cfg)


@app.route("/settings/hosts/<int:hid>/backup", methods=["GET", "POST"])
@admin_required
def host_backup(hid):
    with db() as c:
        row = c.execute("SELECT * FROM hosts WHERE id=?", (hid,)).fetchone()
    if not row:
        abort(404)
    try:
        cfg = json.loads(row["mtbak"] or "{}")
    except (TypeError, ValueError):
        cfg = {}
    if request.method == "POST":
        cfg["enabled"] = 1 if request.form.get("enabled") else 0
        cfg["user"] = request.form.get("user", "").strip()
        cfg["api_port"] = int(request.form.get("api_port") or 8728)
        cfg["ssh_port"] = int(request.form.get("ssh_port") or 22)
        cfg["use_ssl"] = 1 if request.form.get("use_ssl") else 0
        cfg["sensitive"] = 1 if request.form.get("sensitive") else 0
        cfg["binary"] = 1 if request.form.get("binary") else 0
        if request.form.get("password"):
            cfg["password"] = encrypt_secret(request.form.get("password"))
        with _db_lock, db() as c:
            c.execute("UPDATE hosts SET mtbak=? WHERE id=?", (json.dumps(cfg), hid))
        flash("Backup account saved. One export per week, keeping the last year (52) unless you change Backups to keep.")
        if request.form.get("now"):
            jobs.run_backup(sys.modules[__name__], dict(row) | {"mtbak": json.dumps(cfg)} if False else {**dict(row), "mtbak": json.dumps(cfg)}, "now")
        return redirect(url_for("host_backup", hid=hid))
    body = """<p><a href="{{ url_for('settings') }}#hosts">← Hosts</a></p>
<div class="card"><h2>MikroTik backup · {{ h.name }}</h2>
<p class="section-intro">Weekly text export. One per week, keeps the last year. Use a user with read and ssh (and api). Add sensitive only if you need passwords in the file. Binary backup also needs ftp and policy. Downloads require an admin login.</p>
<form method="post"><input type="hidden" name="csrf" value="{{ csrf_token() }}">
<div class="form-grid">
<label>Enabled</label><div><input type="checkbox" name="enabled" value="1" {{ 'checked' if cfg.enabled }}></div>
<label>Username</label><div><input type="text" name="user" value="{{ cfg.user or '' }}" placeholder="backup"></div>
<label>Password</label><div><input type="password" name="password" placeholder="{{ 'saved — leave empty to keep' if cfg.password else 'not set' }}"></div>
<label>API port</label><div><input type="number" name="api_port" value="{{ cfg.api_port or 8728 }}"><p class="hint">8728 plain, 8729 with API-SSL.</p></div>
<label>API SSL</label><div><input type="checkbox" name="use_ssl" value="1" {{ 'checked' if cfg.use_ssl }}></div>
<label>SSH port</label><div><input type="number" name="ssh_port" value="{{ cfg.ssh_port or 22 }}"></div>
<label>Include secrets</label><div><input type="checkbox" name="sensitive" value="1" {{ 'checked' if cfg.sensitive }}><p class="hint">Runs /export show-sensitive. Needs the sensitive policy.</p></div>
<label>Binary .backup</label><div><input type="checkbox" name="binary" value="1" {{ 'checked' if cfg.binary }}></div>
<span></span><div><button>Save</button> <button name="now" value="1" class="sec">Backup now</button></div></div></form></div>"""
    return page(body, h=dict(row), cfg=cfg)


@app.route("/backup/<int:bid>")
@admin_required
def backup_download(bid):
    with db() as c:
        row = c.execute("SELECT * FROM backups WHERE id=?", (bid,)).fetchone()
    if not row:
        abort(404)
    path = row["bin_path"] if request.args.get("kind") == "bin" else row["path"]
    root = os.path.join(DATA_DIR, "backups")
    if not path or not mtbackup.safe_under(root, path) or not os.path.isfile(path):
        abort(404)
    return send_file(path, as_attachment=True)


@app.route("/settings/dashboard-graphs", methods=["POST"])
@admin_required
def save_dash_graphs():
    hosts = request.form.getlist("dg_host")
    ifaces = request.form.getlist("dg_iface")
    with _db_lock, db() as c:
        c.execute("DELETE FROM dash_ifaces")
        for i, (host_id, iface) in enumerate(zip(hosts, ifaces)):
            if not request.form.get(f"dg_on_{i}"):
                continue
            color_in = request.form.get(f"dg_in_{i}") or "#16a34a"
            color_out = request.form.get(f"dg_out_{i}") or "#1d5fbf"
            if not re.fullmatch(r"#[0-9A-Fa-f]{6}", color_in):
                color_in = "#16a34a"
            if not re.fullmatch(r"#[0-9A-Fa-f]{6}", color_out):
                color_out = "#1d5fbf"
            c.execute("INSERT OR REPLACE INTO dash_ifaces(host_id, iface, color_in, color_out) VALUES(?,?,?,?)",
                      (int(host_id), iface[:64], color_in, color_out))
    flash("Dashboard graphs saved.")
    return redirect(url_for("settings") + "#graphs")


SIA = siarecv.SIAServer()


def _sia_map():
    """Account id -> pysiaalarm account. Keys are decrypted only in memory."""
    from pysiaalarm.account import SIAAccount
    out = {}
    with db() as c:
        rows = c.execute("SELECT * FROM sia_accounts").fetchall()
    for row in rows:
        key = decrypt_secret(row["key_enc"]) if row["key_enc"] else None
        try:
            out[row["account"].upper()] = SIAAccount(row["account"], key=key or None, allowed_timeband=(1200, 1200))
        except Exception as e:
            log.warning("SIA account %s skipped: %s", row["account"], e)
    return out


def on_sia_frame(line, peer):
    s = get_settings()
    if not ip_allowed(peer, s.get("rx_allowed_nets")):
        log.warning("SIA from %s ignored (not in allowed networks)", peer)
        return siarecv._response("NAK", "0000", "R0", "L0", "000")
    info = siarecv.parse_line(line, _sia_map())
    if not info.get("ok"):
        log.info("SIA reject from %s: %s", peer, info.get("error"))
        return info
    account = info.get("account") or ""
    now = time.time()
    with db() as c:
        row = c.execute("SELECT * FROM sia_accounts WHERE account=?", (account,)).fetchone()
    if not row:
        return info
    state = info.get("state") or (row["rest_state"] if info.get("heartbeat") and row["state"] == "offline" else row["state"])
    if info.get("heartbeat") and row["state"] == "offline":
        state = row["rest_state"] or "unknown"
    rest = state if state and state != "offline" else row["rest_state"]
    text = "" if info.get("heartbeat") else info.get("text") or ""
    with _db_lock, db() as c:
        c.execute("UPDATE sia_accounts SET last_ts=?, last_text=CASE WHEN ?='' THEN last_text ELSE ? END, state=?, rest_state=?, offline_alerted=0 WHERE account=?",
                  (now, text, text, state or row["state"], rest or "unknown", account))
    if not info.get("heartbeat"):
        host = {"id": None, "name": row["name"], "host": account, "device_type": row["panel"]}
        add_event("sia", "sia_" + (info.get("code") or "event"), info["severity"], None,
                  info["text"][:80], f"{row['name']} ({account}): {info['text']}",
                  {"account": account, "panel": row["panel"], "zone": info.get("zone"), "peer": peer})
        consider_notify(s, None, info["severity"], f"[{s['site_name']}] {row['name']}: {info['text'][:80]}",
                        f"{row['name']} account {account}\n{info['text']}\nfrom {peer}",
                        build_payload(s, "device_alert", None, host, severity=info["severity"], message=info["text"]))
    elif row["state"] == "offline":
        add_event("sia", "sia_online", "info", None, "Panel online", f"{row['name']} sent a heartbeat again.",
                  {"account": account})
    return info


def sia_supervise():
    s = get_settings()
    now = time.time()
    with db() as c:
        rows = [dict(r) for r in c.execute("SELECT * FROM sia_accounts")]
    for row in rows:
        limit = max(1, int(row["supervise_min"] or 10)) * 60
        if not row["last_ts"] or now - row["last_ts"] < limit or row["offline_alerted"]:
            continue
        with _db_lock, db() as c:
            c.execute("UPDATE sia_accounts SET state='offline', offline_alerted=1 WHERE account=?", (row["account"],))
        msg = f"{row['name']} ({row['account']}) sent no heartbeat for {row['supervise_min']} minutes."
        add_event("sia", "sia_offline", "critical", None, "Panel offline", msg, {"account": row["account"]})
        consider_notify(s, None, "critical", f"[{s['site_name']}] Panel offline: {row['name']}", msg,
                        build_payload(s, "device_alert", None, None, severity="critical", message=msg))


def restart_sia():
    s = get_settings()
    if not s.get("sia_enabled"):
        SIA.stop_server()
        return
    try:
        SIA.start(s.get("sia_host") or "0.0.0.0", int(s.get("sia_port") or 12128),
                  bool(s.get("sia_tcp")), bool(s.get("sia_udp")), on_sia_frame)
    except Exception as e:
        log.error("SIA receiver failed: %s", e)


@app.route("/settings/alarms", methods=["GET", "POST"])
@admin_required
def alarm_settings():
    if request.method == "POST":
        if request.form.get("delete"):
            with _db_lock, db() as c:
                c.execute("DELETE FROM sia_accounts WHERE account=?", (request.form.get("delete").upper(),))
            flash("Account removed.")
            return redirect(url_for("alarm_settings"))
        account = (request.form.get("account") or "").strip().upper()
        name = (request.form.get("name") or "").strip()[:60]
        panel = request.form.get("panel") if request.form.get("panel") in siarecv.PANELS else "other"
        try:
            supervise = int(request.form.get("supervise_min") or 10)
        except ValueError:
            supervise = 10
        key = (request.form.get("key") or "").strip()
        if not re.fullmatch(r"[A-F0-9]{3,16}", account):
            flash("Account must be 3-16 hex characters (an Ajax object number is fine).")
            return redirect(url_for("alarm_settings"))
        if key and (len(key) not in (16, 24, 32) or not re.fullmatch(r"[0-9A-Fa-f]+", key)):
            flash("Encryption key must be 16, 24 or 32 hex characters, or empty for no encryption.")
            return redirect(url_for("alarm_settings"))
        if not name:
            flash("Give the panel a name, for example Ajax office.")
            return redirect(url_for("alarm_settings"))
        with db() as c:
            old = c.execute("SELECT key_enc FROM sia_accounts WHERE account=?", (account,)).fetchone()
        key_enc = encrypt_secret(key) if key else (old["key_enc"] if old else "")
        with _db_lock, db() as c:
            c.execute("""INSERT INTO sia_accounts(account, name, panel, key_enc, supervise_min)
                         VALUES(?,?,?,?,?) ON CONFLICT(account) DO UPDATE SET
                         name=excluded.name, panel=excluded.panel, key_enc=excluded.key_enc,
                         supervise_min=excluded.supervise_min""",
                      (account, name, panel, key_enc, max(1, min(supervise, 1440))))
        set_settings(sia_enabled=1 if request.form.get("sia_enabled") else 0,
                     sia_port=int(request.form.get("sia_port") or 12128))
        restart_sia()
        flash("Alarm account saved. This monitor is not a certified receiving centre.")
        return redirect(url_for("alarm_settings"))
    with db() as c:
        rows = [dict(r) for r in c.execute("SELECT * FROM sia_accounts ORDER BY name")]
    body = """<div class="card"><h2>Alarm panels (SIA DC-09)</h2>
<p class="section-intro"><b>Information only.</b> This is not a certified alarm receiving centre (ARC/CMS). Keep Ajax, TrikdisConfig/Protegus, Hik-Connect and the Dahua app as the primary monitoring. TRK, the proprietary Trikdis protocol, is not supported — use SIA DC-09.</p>
<form method="post"><input type="hidden" name="csrf" value="{{ csrf_token() }}">
<div class="form-grid">
<label>Receiver enabled</label><div><input type="checkbox" name="sia_enabled" value="1" {{ 'checked' if s.sia_enabled }}>
<p class="hint">Listens on TCP and UDP port {{ s.sia_port }} on all interfaces. Only senders in the e-mail receiver's allowed networks are accepted. Example port: <code>12128</code>.</p></div>
<label>Port</label><div><input type="number" name="sia_port" min="1" max="65535" value="{{ s.sia_port }}"></div>
<label>Account</label><div><input type="text" name="account" placeholder="1234" maxlength="16">
<p class="hint">The object / account number in the panel, 3-16 hex digits. Example: <code>1234</code>.</p></div>
<label>Name</label><div><input type="text" name="name" placeholder="Office Ajax"></div>
<label>Panel</label><div><select name="panel">
<option value="ajax">Ajax hub</option><option value="trikdis">Trikdis communicator</option>
<option value="hik_ax">Hikvision AX PRO / AX Hybrid</option><option value="dahua_arc">Dahua AirShield / ARC</option>
<option value="other">Other SIA DC-09 panel</option></select></div>
<label>AES key</label><div><input type="password" name="key" autocomplete="new-password" placeholder="empty = no encryption">
<p class="hint">Optional. 16, 24 or 32 hex characters (AES-128/192/256). Stored encrypted. Leave empty when saving to keep the current key.</p></div>
<label>Heartbeat timeout (min)</label><div><input type="number" name="supervise_min" value="10" min="1" max="1440">
<p class="hint">Alarm “panel offline” if no NULL heartbeat arrives in this many minutes. Example: <code>10</code>. Match the panel's ping interval and add a couple of minutes.</p></div>
<span></span><div><button>Save account</button></div></div></form>
<h2>How to point the panel here</h2>
<ul class="help-list">
<li><b>Ajax</b> — PRO Desktop → Hub → Settings → Monitoring station. Protocol SIA DC-09 (SIA-DCS or ADM-CID). IP = this machine, port = the number above, account = object number. Encryption only if you set a key here.</li>
<li><b>Trikdis</b> (GT+, G16, E16, SP3 and similar, via TrikdisConfig) — monitoring channel SIA DC-09, DCS or ADM-CID. Fill account, receiver/line if asked (R0 L0 is fine), and the same hex key length. Heartbeats are NULL messages. The TRK protocol used toward Protegus is not accepted.</li>
<li><b>Hikvision AX PRO / AX Hybrid</b> — Hik-Connect or the panel web page → Communication → Alarm receiving centre. Protocol SIA-DCS or ADM-CID, this IP and port, account, optional encryption, and a heartbeat interval.</li>
<li><b>Dahua AirShield / ARC</b> — ARC settings → SIA DC-09 or Contact ID over IP. Account, this IP and port, heartbeat. Camera and NVR events stay on the camera API and the e-mail receiver, not here.</li>
</ul>
<table><tr><th>Name</th><th>Account</th><th>Panel</th><th>State</th><th></th></tr>
{% for a in rows %}<tr><td>{{ a.name }}</td><td>{{ a.account }}</td><td>{{ a.panel }}</td><td>{{ a.state }}</td>
<td><button form="del{{ a.account }}" class="del">Remove</button></td></tr>{% else %}<tr><td colspan="5" class="muted">No accounts yet.</td></tr>{% endfor %}</table>
{% for a in rows %}<form id="del{{ a.account }}" method="post"><input type="hidden" name="csrf" value="{{ csrf_token() }}"><input type="hidden" name="delete" value="{{ a.account }}"></form>{% endfor %}
</div>"""
    return page(body, rows=rows)


def main():
    global DB_PATH, DATA_DIR, SNAP_DIR
    ap = argparse.ArgumentParser(description=APP_NAME + " v" + VERSION)
    ap.add_argument("--host", default=os.environ.get("PINGMON_HOST", "127.0.0.1"), help="web bind address (default 127.0.0.1)")
    ap.add_argument("--port", type=int, default=int(os.environ.get("PINGMON_PORT", 8080)), help="web port (default 8080)")
    ap.add_argument("--db", default=os.environ.get("PINGMON_DB", os.path.join(os.path.dirname(os.path.abspath(__file__)), "pingmonitor.db")),
                    help="SQLite database file (snapshots are stored next to it)")
    ap.add_argument("--set-password", "--reset-password", dest="set_password", action="store_true",
                    help="set or reset the admin password, then exit")
    ap.add_argument("--password-stdin", action="store_true", help="with --set-password: read the password from stdin")
    ap.add_argument("--check-setup", action="store_true", help="exit 0 if an admin password is set, 3 if not")
    ap.add_argument("--show-token", action="store_true", help="print the API token and exit")
    ap.add_argument("--debug", action="store_true")
    a = ap.parse_args()
    logging.basicConfig(level=logging.DEBUG if a.debug else logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    logging.getLogger("mail.log").setLevel(logging.ERROR)  # aiosmtpd is chatty (deprecation notes)

    DB_PATH = os.path.abspath(a.db)
    DATA_DIR = os.path.dirname(DB_PATH)
    SNAP_DIR = os.path.join(DATA_DIR, "snapshots")
    os.makedirs(SNAP_DIR, exist_ok=True)
    init_db()
    s = get_settings()

    if a.check_setup:
        sys.exit(0 if s["admin_hash"] else 3)
    if a.show_token:
        print(s["api_token"])
        return
    if a.set_password or not s["admin_hash"]:
        if not a.set_password and not sys.stdin.isatty():
            log.error("No admin password set. Run once in a terminal:  %s %s --set-password --db %s",
                      sys.executable, os.path.abspath(__file__), DB_PATH)
            sys.exit(2)
        set_settings(admin_hash=hash_password(prompt_new_password(a.password_stdin)))
        print("Admin password saved.")
        if a.set_password:
            return

    app.secret_key = get_settings()["secret_key"]
    get_pinger(s["ping_method"])
    stop = threading.Event()
    threading.Thread(target=monitor_loop, args=(stop,), daemon=True, name="monitor").start()
    RECEIVER.restart()
    SNMP.start()
    restart_sia()
    log.info("%s %s - site '%s' - web UI http://%s:%d", APP_NAME, VERSION, s["site_name"], a.host, a.port)
    try:
        from waitress import serve
        serve(app, host=a.host, port=a.port, threads=4, ident="pingmonitor")
    except ImportError:
        app.run(host=a.host, port=a.port, threaded=True)
    finally:
        stop.set()
        RECEIVER.stop()


if __name__ == "__main__":
    main()
