"""Background work: history rollup, WAN probe, camera checks, MikroTik backups, PDF data.

Functions take the pingmonitor module as `pm` so this file does not import it.
"""
import json
import os
import time
from datetime import datetime

import camapi
import healthmon
import iotmon
import mtbackup
import reportpdf
import wirelogic

RAW_S = 2 * 86400
M5_S = 7 * 86400


def tier_args(since, now):
    """Bind values for: ts>=? AND (g=0 OR (g=300 AND ts<?) OR (g=3600 AND ts<?))."""
    return since, now - RAW_S, now - M5_S


TIER = "ts>=? AND (g=0 OR (g=300 AND ts<?) OR (g=3600 AND ts<?))"


def _bucket(rows, size, value_fn):
    acc = {}
    for row in rows:
        key = int(row["ts"] // size) * size
        acc.setdefault(key, []).append(row)
    out = []
    for key in sorted(acc):
        out.append((key, value_fn(acc[key])))
    return out


def _ping_fold(rows):
    n = nok = 0
    ms_sum = ms_n = 0
    for row in rows:
        count = row["n"] or 1
        good = row["nok"] if row["nok"] is not None else (count if row["ok"] else 0)
        n += count
        nok += good
        if row["ms"] is not None and good:
            ms_sum += row["ms"] * good
            ms_n += good
    ms = round(ms_sum / ms_n, 2) if ms_n else None
    return n, nok, ms


def _num_avg(rows, key):
    vals = [row[key] for row in rows if row[key] is not None]
    if not vals:
        return None
    return round(sum(vals) / len(vals), 2)


def _ifs_avg(rows):
    acc = {}
    for row in rows:
        try:
            data = json.loads(row["ifs"] or "{}")
        except (TypeError, ValueError):
            continue
        for name, pair in data.items():
            if not pair or pair[0] is None:
                continue
            slot = acc.setdefault(name, [0.0, 0.0, 0])
            slot[0] += pair[0]
            slot[1] += pair[1] or 0
            slot[2] += 1
    return {name: [round(v[0] / v[2]), round(v[1] / v[2])] for name, v in acc.items() if v[2]}


def _extra_avg(rows):
    acc = {}
    for row in rows:
        try:
            data = json.loads(row["extra"] or "{}")
        except (TypeError, ValueError):
            data = {}
        if row["temp"] is not None:
            data.setdefault("temp", row["temp"])
        for key, value in data.items():
            if isinstance(value, (int, float)):
                slot = acc.setdefault(key, [0.0, 0])
                slot[0] += value
                slot[1] += 1
    return {key: round(v[0] / v[1], 2) for key, v in acc.items() if v[1]}


def rollup(pm, now=None):
    """Raw samples for 2 days, 5-minute averages through 7 days, hourly until retention."""
    now = now or time.time()
    keep = max(1, int(pm.get_settings()["retention_days"])) * 86400
    with pm._db_lock, pm.db() as c:
        _roll_results(c, now)
        _roll_snmp(c, now)
        _roll_wan(c, now)
        c.execute("DELETE FROM results WHERE ts < ?", (now - keep,))
        c.execute("DELETE FROM snmp_samples WHERE ts < ?", (now - keep,))
        c.execute("DELETE FROM wan_samples WHERE ts < ?", (now - keep,))
        trim_events(pm, c)


def _roll_results(c, now):
    cut_raw, cut_5 = now - RAW_S, now - M5_S
    hosts = [r[0] for r in c.execute("SELECT DISTINCT host_id FROM results")]
    for hid in hosts:
        raw = c.execute(
            "SELECT ts, ok, ms, n, nok FROM results WHERE host_id=? AND g=0 AND ts<? ORDER BY ts",
            (hid, cut_raw)).fetchall()
        if raw:
            lo = int(raw[0]["ts"] // 300) * 300
            c.execute("DELETE FROM results WHERE host_id=? AND g=300 AND ts>=? AND ts<?", (hid, lo, cut_raw))
            for ts, folded in _bucket(raw, 300, _ping_fold):
                n, nok, ms = folded
                c.execute("INSERT INTO results(host_id, ts, ok, ms, n, nok, g) VALUES(?,?,?,?,?,?,300)",
                          (hid, ts, 1 if nok else 0, ms, n, nok))
            c.execute("DELETE FROM results WHERE host_id=? AND g=0 AND ts<?", (hid, cut_raw))
        mid = c.execute(
            "SELECT ts, ok, ms, n, nok FROM results WHERE host_id=? AND g=300 AND ts<? ORDER BY ts",
            (hid, cut_5)).fetchall()
        if mid:
            lo = int(mid[0]["ts"] // 3600) * 3600
            c.execute("DELETE FROM results WHERE host_id=? AND g=3600 AND ts>=? AND ts<?", (hid, lo, cut_5))
            for ts, folded in _bucket(mid, 3600, _ping_fold):
                n, nok, ms = folded
                c.execute("INSERT INTO results(host_id, ts, ok, ms, n, nok, g) VALUES(?,?,?,?,?,?,3600)",
                          (hid, ts, 1 if nok else 0, ms, n, nok))
            c.execute("DELETE FROM results WHERE host_id=? AND g=300 AND ts<?", (hid, cut_5))


def _roll_snmp(c, now):
    cut_raw, cut_5 = now - RAW_S, now - M5_S
    hosts = [r[0] for r in c.execute("SELECT DISTINCT host_id FROM snmp_samples")]
    for hid in hosts:
        raw = c.execute(
            "SELECT ts, cpu, mem, ifs, temp, extra FROM snmp_samples WHERE host_id=? AND g=0 AND ts<? ORDER BY ts",
            (hid, cut_raw)).fetchall()
        if raw:
            lo = int(raw[0]["ts"] // 300) * 300
            c.execute("DELETE FROM snmp_samples WHERE host_id=? AND g=300 AND ts>=? AND ts<?", (hid, lo, cut_raw))
            for ts, rows in _bucket(raw, 300, lambda rs: rs):
                extra = _extra_avg(rows)
                c.execute(
                    "INSERT INTO snmp_samples(host_id, ts, cpu, mem, ifs, temp, extra, g) VALUES(?,?,?,?,?,?,?,300)",
                    (hid, ts, _num_avg(rows, "cpu"), _num_avg(rows, "mem"), json.dumps(_ifs_avg(rows)),
                     extra.get("temp", _num_avg(rows, "temp")), json.dumps(extra)))
            c.execute("DELETE FROM snmp_samples WHERE host_id=? AND g=0 AND ts<?", (hid, cut_raw))
        mid = c.execute(
            "SELECT ts, cpu, mem, ifs, temp, extra FROM snmp_samples WHERE host_id=? AND g=300 AND ts<? ORDER BY ts",
            (hid, cut_5)).fetchall()
        if mid:
            lo = int(mid[0]["ts"] // 3600) * 3600
            c.execute("DELETE FROM snmp_samples WHERE host_id=? AND g=3600 AND ts>=? AND ts<?", (hid, lo, cut_5))
            for ts, rows in _bucket(mid, 3600, lambda rs: rs):
                extra = _extra_avg(rows)
                c.execute(
                    "INSERT INTO snmp_samples(host_id, ts, cpu, mem, ifs, temp, extra, g) VALUES(?,?,?,?,?,?,?,3600)",
                    (hid, ts, _num_avg(rows, "cpu"), _num_avg(rows, "mem"), json.dumps(_ifs_avg(rows)),
                     extra.get("temp", _num_avg(rows, "temp")), json.dumps(extra)))
            c.execute("DELETE FROM snmp_samples WHERE host_id=? AND g=300 AND ts<?", (hid, cut_5))


def _roll_wan(c, now):
    cut_raw, cut_5 = now - RAW_S, now - M5_S
    targets = [r[0] for r in c.execute("SELECT DISTINCT target FROM wan_samples")]
    for target in targets:
        raw = c.execute(
            "SELECT ts, loss, avg_ms, jitter FROM wan_samples WHERE target=? AND g=0 AND ts<? ORDER BY ts",
            (target, cut_raw)).fetchall()
        if raw:
            lo = int(raw[0]["ts"] // 300) * 300
            c.execute("DELETE FROM wan_samples WHERE target=? AND g=300 AND ts>=? AND ts<?", (target, lo, cut_raw))
            for ts, rows in _bucket(raw, 300, lambda rs: rs):
                c.execute("INSERT INTO wan_samples(ts, target, loss, avg_ms, jitter, g) VALUES(?,?,?,?,?,300)",
                          (ts, target, _num_avg(rows, "loss"), _num_avg(rows, "avg_ms"), _num_avg(rows, "jitter")))
            c.execute("DELETE FROM wan_samples WHERE target=? AND g=0 AND ts<?", (target, cut_raw))
        mid = c.execute(
            "SELECT ts, loss, avg_ms, jitter FROM wan_samples WHERE target=? AND g=300 AND ts<? ORDER BY ts",
            (target, cut_5)).fetchall()
        if mid:
            lo = int(mid[0]["ts"] // 3600) * 3600
            c.execute("DELETE FROM wan_samples WHERE target=? AND g=3600 AND ts>=? AND ts<?", (target, lo, cut_5))
            for ts, rows in _bucket(mid, 3600, lambda rs: rs):
                c.execute("INSERT INTO wan_samples(ts, target, loss, avg_ms, jitter, g) VALUES(?,?,?,?,?,3600)",
                          (ts, target, _num_avg(rows, "loss"), _num_avg(rows, "avg_ms"), _num_avg(rows, "jitter")))
            c.execute("DELETE FROM wan_samples WHERE target=? AND g=300 AND ts<?", (target, cut_5))


def trim_events(pm, conn=None):
    keep = max(10, min(5000, int(pm.get_settings().get("event_keep") or 100)))

    def run(c):
        old = c.execute(
            "SELECT id, attachments FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT ?)",
            (keep,)).fetchall()
        if not old:
            return
        c.execute("DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT ?)", (keep,))
        for row in old:
            if not pm.SNAP_DIR:
                break
            for name in json.loads(row["attachments"] or "[]"):
                try:
                    os.remove(os.path.join(pm.SNAP_DIR, name))
                except OSError:
                    pass

    if conn is not None:
        run(conn)
        return
    with pm._db_lock, pm.db() as c:
        run(c)


def wan_probe(pm):
    s = pm.get_settings()
    if not s.get("wan_enabled"):
        return
    targets = [t.strip() for t in (s.get("wan_targets") or "").split(",") if t.strip()]
    if not targets:
        return
    pinger = pm.get_pinger(s["ping_method"])["fn"]
    timeout = float(s["ping_timeout"])
    count = max(3, min(10, int(s.get("wan_count") or 5)))
    now = time.time()
    rows = []
    for target in targets:
        samples = []
        ok_n = 0
        for _ in range(count):
            ok, ms = pinger(target, timeout)
            if ok:
                ok_n += 1
                if ms is not None:
                    samples.append(ms)
        loss = round(100.0 * (count - ok_n) / count, 1)
        avg = round(sum(samples) / len(samples), 2) if samples else None
        rows.append({"target": target, "loss": loss, "avg_ms": avg, "jitter": wirelogic.jitter_ms(samples)})
    state = wirelogic.judge_wan(rows, s.get("wan_loss_pct") or 0, s.get("wan_latency_ms") or 0)
    with pm._db_lock, pm.db() as c:
        for row in rows:
            c.execute("INSERT INTO wan_samples(ts, target, loss, avg_ms, jitter, g) VALUES(?,?,?,?,?,0)",
                      (now, row["target"], row["loss"], row["avg_ms"], row["jitter"]))
        prev = c.execute("SELECT state, alerted, since_ts FROM wan_status WHERE id=1").fetchone()
        prev_state = prev["state"] if prev else None
        alerted = prev["alerted"] if prev else 0
        since_ts = now if state != prev_state or not prev else prev["since_ts"]
        if state != prev_state and prev_state is not None:
            if state == "down":
                how = pm.consider_notify(
                    s, None, "critical", f"[{s['site_name']}] Internet down",
                    f"Internet is down. Probes: " + ", ".join(f"{r['target']} loss {r['loss']}%" for r in rows),
                    pm.build_payload(s, "internet_down", None, None, "down", severity="critical",
                                     message="Internet down", ts=now))
                alerted = 1 if how in ("sent", "queued") else 0
                pm.add_event("wan", "internet_down", "critical", None, "Internet down",
                             "All probe targets failed.", {"targets": rows}, ts=now, conn=c)
            elif state == "degraded" and prev_state == "up":
                pm.add_event("wan", "internet_degraded", "warning", None, "Internet degraded",
                             "Loss or latency is above the threshold.", {"targets": rows}, ts=now, conn=c)
                pm.consider_notify(
                    s, None, "warning", f"[{s['site_name']}] Internet degraded",
                    "Packet loss or latency is above the threshold.",
                    pm.build_payload(s, "internet_degraded", None, None, severity="warning",
                                     message="Internet degraded", ts=now))
            elif state == "up" and prev_state == "down" and alerted:
                pm.add_event("wan", "internet_up", "info", None, "Internet restored",
                             "Probe targets answer again.", {"targets": rows}, ts=now, conn=c)
                pm.consider_notify(
                    s, None, "info", f"[{s['site_name']}] Internet restored",
                    "Internet probes succeed again.",
                    pm.build_payload(s, "internet_up", None, None, "up", severity="info",
                                     message="Internet restored", ts=now))
                alerted = 0
        elif prev_state is None:
            alerted = 0
        detail = json.dumps(rows)
        c.execute("INSERT OR REPLACE INTO wan_status(id, state, since_ts, alerted, detail) VALUES(1,?,?,?,?)",
                  (state, since_ts, alerted, detail))


def flush_quiet(pm):
    s = pm.get_settings()
    if pm.is_quiet(s) or pm.global_maint(s):
        return
    with pm._db_lock, pm.db() as c:
        rows = c.execute("SELECT subject FROM alert_queue ORDER BY id").fetchall()
        if not rows:
            return
        c.execute("DELETE FROM alert_queue")
    lines = "\n".join(f"- {r['subject']}" for r in rows[:40])
    text = f"Alerts held during quiet hours ({len(rows)}):\n{lines}"
    pm.notify(f"[{s['site_name']}] Queued alerts", text,
              pm.build_payload(s, "quiet_digest", None, None, severity="info", message=text))


def disk_repeat_seconds(s):
    """How often to remind about a disk that is still failed.

    A positive Disk reminder setting wins. Otherwise the global alarm repeat is used.
    If that is also 0 (never repeat ping alarms), a failed disk is still mentioned once a day.
    Ping fail-count is not used here.
    """
    try:
        chosen = int(s.get("disk_repeat_min") or 0)
    except (TypeError, ValueError):
        chosen = 0
    if chosen > 0:
        return chosen * 60
    try:
        global_rep = int(s.get("repeat_min") or 0)
    except (TypeError, ValueError):
        global_rep = 0
    if global_rep > 0:
        return global_rep * 60
    return 24 * 3600


def _recovery_copy(key):
    """Log line when a stored camera problem is gone. Disks name the slot."""
    text = str(key or "")
    for prefix in ("disk:", "disk-missing:"):
        if text.startswith(prefix):
            name = text[len(prefix):] or "disk"
            line = f"Disk {name} recovered"
            return line, line
    return "Camera check recovered", f"{text} is OK again."


def apply_camera_result(pm, host, result, notify, prev_row, now):
    """Store a camera check. `notify` is false for a manual Test so it cannot swallow later alerts.

    The notified map is separate from the problem list. A problem with no prior notice is
    alerted on the first scheduled check. Critical disk problems are repeated on the disk
    reminder interval. consider_notify sends critical alerts during quiet hours when that
    option is on (the default).
    """
    prev = {}
    if prev_row and prev_row["data"]:
        try:
            prev = json.loads(prev_row["data"])
        except (TypeError, ValueError):
            prev = {}
    problems = list(result.get("problems") or [])
    have = {p.get("key") for p in problems}
    for item in camapi.disks_gone(prev.get("disks") or [], result.get("disks") or []):
        if item["key"] not in have:
            problems.append(item)
            have.add(item["key"])
    problems = [p for p in problems if not str(p.get("key") or "").startswith("rec:")]
    expect = _record_expect(host)
    try:
        now_local = datetime.fromtimestamp(now, pm.tzinfo())
    except Exception:
        now_local = datetime.fromtimestamp(now)
    extra, note = camapi.recording_assessment(result.get("channels") or [], expect, now_local)
    problems.extend(extra)
    if note:
        result["recording_note"] = note
    have = {p.get("key") for p in problems}
    result["problems"] = problems
    notified = {k: float(v) for k, v in (prev.get("notified") or {}).items()}
    if not notify:
        result["notified"] = notified
        result["ts"] = now
        with pm._db_lock, pm.db() as c:
            c.execute("INSERT OR REPLACE INTO cam_state(host_id, ts, data) VALUES(?,?,?)",
                      (host["id"], now, json.dumps(result)))
        return result
    s = pm.get_settings()
    repeat = disk_repeat_seconds(s)
    for prob in problems:
        key = prob.get("key")
        last = notified.get(key)
        diskish = str(prob.get("kind") or "").startswith("cam_disk")
        remind = bool(last) and diskish and prob.get("severity") == "critical" and (now - last >= repeat)
        if last and not remind:
            continue
        title = prob["title"] + (" (still)" if remind else "")
        pm.add_event("cam", prob["kind"], prob["severity"], host, title, prob["message"], {"key": key})
        pm.consider_notify(s, host, prob["severity"], f"[{s['site_name']}] {title}: {host['name']}",
                           prob["message"],
                           pm.build_payload(s, "device_alert", None, host, severity=prob["severity"],
                                            message=prob["message"]))
        notified[key] = now
    for key in list(notified):
        if key not in have:
            if key.startswith("disk:"):
                slot = key.split(":", 1)[1]
                if f"disk-missing:{slot}" in have:
                    # The slot failed and then disappeared. The missing alert replaces it.
                    del notified[key]
                    continue
            title, message = _recovery_copy(key)
            pm.add_event("cam", "cam_recovered", "info", host, title, message, {"key": key})
            pm.consider_notify(s, host, "info", f"[{s['site_name']}] {title}: {host['name']}",
                               message,
                               pm.build_payload(s, "device_alert", None, host, severity="info",
                                                message=message))
            del notified[key]
    result["notified"] = notified
    result["ts"] = now
    with pm._db_lock, pm.db() as c:
        c.execute("INSERT OR REPLACE INTO cam_state(host_id, ts, data) VALUES(?,?,?)",
                  (host["id"], now, json.dumps(result)))
    return result


def _record_expect(host):
    try:
        cfg = json.loads((host or {}).get("cam") or "{}")
    except (TypeError, ValueError):
        cfg = {}
    if not isinstance(cfg, dict):
        cfg = {}
    raw = str(cfg.get("record_channels") or "").replace(";", ",")
    return {
        "channels": [part.strip() for part in raw.split(",") if part.strip()],
        "start": cfg.get("record_start") or "00:00",
        "end": cfg.get("record_end") or "23:59",
        "days": cfg.get("record_days") or "0123456",
    }


def camera_poll(pm, only_id=None):
    s = pm.get_settings()
    interval = max(60, int(s.get("cam_interval") or 900))
    now = time.time()
    with pm.db() as c:
        hosts = [dict(r) for r in c.execute("SELECT * FROM hosts WHERE enabled=1 AND cam != '' AND cam IS NOT NULL")]
    for host in hosts:
        if only_id and host["id"] != only_id:
            continue
        try:
            cfg = json.loads(host.get("cam") or "{}")
        except (TypeError, ValueError):
            continue
        if not cfg.get("enabled") and not only_id:
            continue
        brand = cfg.get("brand") if cfg.get("brand") in ("hikvision", "dahua") else host.get("device_type")
        if brand not in ("hikvision", "dahua"):
            continue
        with pm.db() as c:
            prev_row = c.execute("SELECT ts, data FROM cam_state WHERE host_id=?", (host["id"],)).fetchone()
        if not only_id and prev_row and now - (prev_row["ts"] or 0) < interval:
            continue
        password = pm.decrypt_secret(cfg.get("password") or "")
        scheme = cfg.get("scheme") or "http"
        port = int(cfg.get("port") or (443 if scheme == "https" else 80))
        base = f"{scheme}://{host['host']}:{port}"
        result = camapi.run_check(brand, base, cfg.get("user") or "", password, timeout=15)
        # A manual Test stores the reading but does not mark problems as already notified.
        saved = apply_camera_result(pm, host, result, notify=not only_id, prev_row=prev_row, now=now)
        if only_id:
            return saved
    return None


def _save_health(pm, key, status, alerted, detail, now):
    with pm._db_lock, pm.db() as c:
        c.execute("""INSERT INTO health_state(key, status, since_ts, alerted, detail) VALUES(?,?,?,?,?)
                     ON CONFLICT(key) DO UPDATE SET status=excluded.status, since_ts=excluded.since_ts,
                     alerted=excluded.alerted, detail=excluded.detail""",
                  (key, status, now, 1 if alerted else 0, detail[:400]))


def _health_step(pm, s, key, status, severity, title, message, now, host=None):
    """One warning or one recovery per key. unknown does not invent either."""
    if status == "unknown":
        return
    with pm.db() as c:
        row = c.execute("SELECT status, alerted FROM health_state WHERE key=?", (key,)).fetchone()
    prev = row["status"] if row else ""
    alerted = int(row["alerted"]) if row else 0
    bad = status in ("warning", "critical", "stale", "hung", "stopped")
    if status in ("ok", "off"):
        if bad is False and prev in ("warning", "critical", "stale", "hung", "stopped") and alerted and status == "ok":
            pm.add_event("health", "health_recovered", "info", host, title + " recovered", message)
            pm.consider_notify(s, host, "info", f"[{s['site_name']}] {title} recovered", message,
                               pm.build_payload(s, "device_alert", None, host, severity="info", message=message))
        _save_health(pm, key, status, 0, message, now)
        return
    if not bad:
        _save_health(pm, key, status, 0, message, now)
        return
    if prev == status and alerted:
        return
    pm.add_event("health", "health_" + status, severity, host, title, message)
    pm.consider_notify(s, host, severity, f"[{s['site_name']}] {title}", message,
                       pm.build_payload(s, "device_alert", None, host, severity=severity, message=message))
    # The log line is the dedup marker. A suppressed notify must not be rewritten every cycle.
    _save_health(pm, key, status, 1, message, now)


def health_poll(pm, now=None):
    """App-disk space and backup freshness. Recorder disks are a different check."""
    s = pm.get_settings()
    now = now or time.time()
    try:
        usage = os.statvfs(pm.DATA_DIR or ".")
        free = usage.f_bavail * usage.f_frsize
        total = usage.f_blocks * usage.f_frsize
    except OSError:
        free = total = None
    level = healthmon.disk_level(free, total, s.get("health_disk_warn_pct"), s.get("health_disk_crit_pct"))
    pct = ""
    if total and free is not None:
        pct = f" {100.0 * free / total:.0f}% free"
    _health_step(pm, s, "app_disk", level, "critical" if level == "critical" else "warning",
                 "App storage low", f"The monitor data disk is low.{pct}", now)
    grace = int(s.get("health_backup_grace_h") or 0) * 3600
    newest = None
    try:
        files = __import__("configbackup").list_local(pm.DATA_DIR)
        if files:
            newest = max(f["mtime"] for f in files)
    except Exception:
        newest = None
    cfg_status = healthmon.backup_status(newest, now, 24 * 3600, grace, enabled=bool(s.get("secret_key")))
    _health_step(pm, s, "config_backup", cfg_status, "warning", "App config backup stale",
                 "The daily encrypted config copy is older than a day plus the grace period.", now)
    with pm.db() as c:
        hosts = [dict(r) for r in c.execute("SELECT id, name, host, device_type, mtbak FROM hosts")]
    for host in hosts:
        try:
            cfg = json.loads(host.get("mtbak") or "{}")
        except (TypeError, ValueError):
            cfg = {}
        enabled = host.get("device_type") == "mikrotik" and bool(cfg.get("enabled"))
        last = None
        if enabled:
            with pm.db() as c:
                row = c.execute("SELECT MAX(ts) AS ts FROM backups WHERE host_id=? AND ok=1", (host["id"],)).fetchone()
            last = row["ts"] if row else None
        status = healthmon.backup_status(last, now, 7 * 86400, grace, enabled=enabled)
        _health_step(pm, s, f"mt:{host['id']}", status, "warning", f"MikroTik backup stale: {host['name']}",
                     f"{host['name']} has no successful export within a week plus the grace period.", now, host)


def _iot_cfg(host):
    try:
        cfg = json.loads(host.get("iot") or "{}")
    except (TypeError, ValueError):
        cfg = {}
    return cfg if isinstance(cfg, dict) else {}


def _iot_fetch(base, user, password):
    def fetch(path, body=None):
        url = base.rstrip("/") + path
        method = "POST" if body is not None else "GET"
        return iotmon.http_fetch(method, url, user, password, body)
    return fetch


def apply_iot_result(pm, host, result, prev, now, blocked):
    s = pm.get_settings()
    prev = prev or {}
    plan = iotmon.plan_iot(prev.get("reach"), prev.get("fails"), prev.get("alerted"), prev.get("last_alert"),
                           prev.get("held"), result.get("observation") or "unknown", now,
                           pm.fail_limit(host, s), pm.repeat_minutes(host, s), blocked)
    action = plan.get("action")
    label = f"{host['name']} ({host['host']})"
    if action in ("down", "release"):
        msg = f"{label} is not answering its status API ({result.get('detail') or plan.get('diag')})."
        pm.add_event("iot", "iot_offline", "critical", host, "Switch offline", msg, {"diag": plan.get("diag")})
        how = pm.consider_notify(s, host, "critical", f"[{s['site_name']}] Switch offline: {host['name']}", msg,
                                 pm.build_payload(s, "device_alert", None, host, severity="critical", message=msg))
        plan["alerted"] = 1 if how in ("sent", "queued") else 0
        plan["last_alert"] = now if plan["alerted"] else 0
    elif action == "repeat":
        msg = f"{label} is still not answering its status API."
        pm.add_event("iot", "iot_offline_repeat", "critical", host, "Switch still offline", msg)
        pm.consider_notify(s, host, "critical", f"[{s['site_name']}] Switch still offline: {host['name']}", msg,
                           pm.build_payload(s, "device_alert", None, host, severity="critical", message=msg))
    elif action == "held":
        msg = f"{label} is not answering. Alerts are held because an upstream device is down. The switch is still shown offline."
        pm.add_event("iot", "iot_held", "info", host, "Switch offline (alerts held)", msg)
    elif action == "recovered":
        msg = f"{label} is answering its status API again."
        pm.add_event("iot", "iot_online", "info", host, "Switch online", msg)
        pm.consider_notify(s, host, "info", f"[{s['site_name']}] Switch online: {host['name']}", msg,
                           pm.build_payload(s, "device_alert", None, host, severity="info", message=msg))
    notified = dict(prev.get("notified") or {})
    if result.get("observation") == "auth" and "auth" not in notified and not blocked:
        msg = f"{label} answered, but the username or password was rejected. The switch is not marked offline."
        pm.add_event("iot", "iot_auth", "warning", host, "Switch sign-in failed", msg)
        pm.consider_notify(s, host, "warning", f"[{s['site_name']}] Switch sign-in failed: {host['name']}", msg,
                           pm.build_payload(s, "device_alert", None, host, severity="warning", message=msg))
        notified["auth"] = now
    if result.get("observation") == "online":
        notified.pop("auth", None)
    if result.get("observation") == "online":
        for hit in iotmon.threshold_hits(result.get("parsed"), (prev.get("limits") or {}).get("temp_max"),
                                         (prev.get("limits") or {}).get("power_max")):
            if hit["key"] in notified:
                continue
            if blocked:
                continue
            pm.add_event("iot", "iot_" + hit["key"], hit["severity"], host, hit["title"], hit["message"])
            pm.consider_notify(s, host, hit["severity"], f"[{s['site_name']}] {hit['title']}: {host['name']}",
                               hit["message"], pm.build_payload(s, "device_alert", None, host,
                                                                severity=hit["severity"], message=hit["message"]))
            notified[hit["key"]] = now
        active = {h["key"] for h in iotmon.threshold_hits(result.get("parsed"), (prev.get("limits") or {}).get("temp_max"),
                                                          (prev.get("limits") or {}).get("power_max"))}
        for key in list(notified):
            if key in ("temp", "power") and key not in active:
                pm.add_event("iot", "iot_recovered", "info", host, "Switch reading normal", f"{key} is back within the limit.")
                del notified[key]
    stored = {
        "reach": plan["reach"], "fails": plan["fails"], "alerted": plan["alerted"],
        "last_alert": plan["last_alert"], "held": plan["held"], "diag": result.get("detail") or plan.get("diag"),
        "observation": result.get("observation"), "parsed": result.get("parsed"),
        "mode": result.get("mode"), "brand": result.get("brand"), "calls": result.get("calls") or [],
        "notified": notified, "limits": prev.get("limits") or {}, "ts": now,
        "last_seen": now if result.get("observation") == "online" else prev.get("last_seen"),
    }
    with pm._db_lock, pm.db() as c:
        c.execute("INSERT OR REPLACE INTO iot_state(host_id, ts, data) VALUES(?,?,?)",
                  (host["id"], now, json.dumps(stored)))
    return stored


def iot_poll(pm, only_id=None, now=None):
    s = pm.get_settings()
    interval = max(30, int(s.get("iot_interval") or 60))
    now = now or time.time()
    with pm.db() as c:
        hosts = [dict(r) for r in c.execute("SELECT * FROM hosts WHERE enabled=1")]
    by_state = {h["id"]: h.get("state") for h in hosts}
    parent_of = {h["id"]: h.get("parent_id") or None for h in hosts}
    down_ids = {i for i, st in by_state.items() if st == "down"}
    for host in hosts:
        if only_id and host["id"] != only_id:
            continue
        if host.get("device_type") not in ("shelly", "sonoff"):
            continue
        cfg = _iot_cfg(host)
        if not cfg.get("enabled") and not only_id:
            continue
        with pm.db() as c:
            prev_row = c.execute("SELECT data FROM iot_state WHERE host_id=?", (host["id"],)).fetchone()
        prev = {}
        if prev_row and prev_row["data"]:
            try:
                prev = json.loads(prev_row["data"])
            except (TypeError, ValueError):
                prev = {}
        if not only_id and prev.get("ts") and now - float(prev.get("ts") or 0) < interval:
            continue
        mode = cfg.get("mode") or ("auto" if host["device_type"] == "shelly" else "diy")
        user = cfg.get("user") or ""
        password = pm.decrypt_secret(cfg.get("password") or "")
        cfg["mqtt_password"] = pm.decrypt_secret(cfg.get("mqtt_password") or "")
        port = int(cfg.get("port") or (8081 if mode == "diy" else 80))
        base = f"http://{host['host']}:{port}"
        limits = {"temp_max": cfg.get("temp_max") or 0, "power_max": cfg.get("power_max") or 0}
        prev["limits"] = limits
        if mode == "mqtt":
            result = iotmon.mqtt_library_missing()
            try:
                import paho.mqtt.client as mqtt  # noqa: F401
            except ImportError:
                result = iotmon.mqtt_library_missing()
            else:
                result = _mqtt_read(cfg, host, now)
        elif host["device_type"] == "shelly":
            result = iotmon.check_shelly(_iot_fetch(base, user, password), cfg.get("generation") or "auto")
        elif mode == "tasmota":
            result = iotmon.check_tasmota(_iot_fetch(base, user, password))
        else:
            result = iotmon.check_sonoff_diy(
                lambda path, body=None: iotmon.http_fetch("POST", base.rstrip("/") + path, user, password, body),
                cfg.get("device_id") or "")
        ancestor = wirelogic.upstream_down(host["id"], parent_of, down_ids)
        blocked = bool(ancestor) or host.get("state") == "down"
        saved = apply_iot_result(pm, host, result, prev, now, blocked)
        if only_id:
            return saved
    return None


def _mqtt_read(cfg, host, now):
    import paho.mqtt.client as mqtt
    topic = (cfg.get("mqtt_topic") or "").strip().strip("/")
    if not topic or not cfg.get("mqtt_host"):
        return {"brand": "sonoff", "mode": "mqtt", "observation": "unknown", "parsed": None,
                "detail": "Set the broker address and the device topic. Connecting to a broker is not the same as the switch being online.",
                "calls": [], "ok": False}
    records = []

    def on_message(_c, _u, msg):
        records.append({"topic": msg.topic, "payload": msg.payload.decode("utf-8", "replace"), "ts": time.time()})

    client = mqtt.Client()
    if cfg.get("mqtt_user"):
        client.username_pw_set(cfg.get("mqtt_user"), cfg.get("mqtt_password") or "")
    try:
        client.connect(cfg.get("mqtt_host"), int(cfg.get("mqtt_port") or 1883), 10)
        client.on_message = on_message
        client.subscribe(f"tele/{topic}/#")
        client.subscribe(f"stat/{topic}/#")
        client.loop_start()
        time.sleep(2)
        client.loop_stop()
        client.disconnect()
    except Exception:
        return {"brand": "sonoff", "mode": "mqtt", "observation": "unknown", "parsed": None,
                "detail": "Could not read the broker. The switch is not marked offline just because the broker did not answer.",
                "calls": ["mqtt"], "ok": False}
    viewed = iotmon.evaluate_mqtt(records, now, cfg.get("stale_sec") or 180)
    return {"brand": "sonoff", "mode": "mqtt", "observation": viewed["reach"], "parsed": viewed.get("parsed"),
            "detail": viewed.get("diag") or "", "calls": ["mqtt"], "ok": viewed["reach"] == "online"}


def backup_due(s, last_ts, now=None):
    """True on the configured weekday once the clock has passed the configured time, if not already run."""
    now = now or time.time()
    try:
        hour, minute = (s.get("mt_backup_time") or "03:00").split(":")
        hour, minute = int(hour), int(minute)
        day = int(s.get("mt_backup_day") if s.get("mt_backup_day") is not None else 0)
    except (TypeError, ValueError):
        return False
    from zoneinfo import ZoneInfo
    try:
        tz = ZoneInfo(s.get("timezone") or "Europe/Athens")
    except Exception:
        tz = ZoneInfo("UTC")
    local = datetime.fromtimestamp(now, tz)
    if local.weekday() != day:
        return False
    slot = local.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if local < slot:
        return False
    if last_ts and datetime.fromtimestamp(last_ts, tz) >= slot:
        return False
    return True


def run_backup(pm, host, reason="schedule"):
    s = pm.get_settings()
    try:
        cfg = json.loads(host.get("mtbak") or "{}")
    except (TypeError, ValueError):
        cfg = {}
    if not cfg.get("enabled") and reason != "now":
        return None
    password = pm.decrypt_secret(cfg.get("password") or "")
    user = cfg.get("user") or ""
    if not user or not password:
        _backup_fail(pm, s, host, "Set the backup username and password first.")
        return None
    sensitive = bool(cfg.get("sensitive"))
    try:
        text, via = mtbackup.export_text(
            host["host"], user, password, api_port=int(cfg.get("api_port") or 8728),
            use_ssl=bool(cfg.get("use_ssl")), ssh_port=int(cfg.get("ssh_port") or 22), sensitive=sensitive)
    except Exception as e:
        _backup_fail(pm, s, host, str(e))
        return None
    binary = b""
    bin_err = ""
    if cfg.get("binary"):
        try:
            binary = mtbackup.fetch_binary(host["host"], user, password, int(cfg.get("ssh_port") or 22))
        except Exception as e:
            bin_err = str(e)
    now = time.time()
    stamp = datetime.fromtimestamp(now, pm.tzinfo()).strftime("%Y%m%d-%H%M%S")
    directory = os.path.join(pm.DATA_DIR, "backups", str(host["id"]))
    path, bin_path = mtbackup.save_pair(directory, stamp, text, binary or None)
    with pm.db() as c:
        prev = c.execute(
            "SELECT path FROM backups WHERE host_id=? AND ok=1 AND path!='' ORDER BY ts DESC LIMIT 1",
            (host["id"],)).fetchone()
    previous = ""
    if prev and prev["path"] and os.path.isfile(prev["path"]):
        try:
            with open(prev["path"], encoding="utf-8", errors="replace") as fh:
                previous = fh.read()
        except OSError:
            previous = ""
    changed, diff = mtbackup.compare_exports(previous, text)
    with pm._db_lock, pm.db() as c:
        c.execute(
            "INSERT INTO backups(host_id, ts, ok, error, path, bin_path, sha, changed, diff, bytes) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (host["id"], now, 1, bin_err, path, bin_path, mtbackup.sha256_text(text), 1 if changed else 0,
             diff, len(text.encode("utf-8"))))
        rows = [dict(r) for r in c.execute("SELECT id, ts, ok FROM backups WHERE host_id=?", (host["id"],))]
        drop = mtbackup.ids_to_prune(rows, int(s.get("mt_backup_keep") or 52))
        if drop:
            doomed = c.execute(
                f"SELECT path, bin_path FROM backups WHERE id IN ({','.join('?' * len(drop))})", tuple(drop)).fetchall()
            for row in doomed:
                for item in (row["path"], row["bin_path"]):
                    if item and mtbackup.safe_under(directory, item):
                        try:
                            os.remove(item)
                        except OSError:
                            pass
            c.execute(f"DELETE FROM backups WHERE id IN ({','.join('?' * len(drop))})", tuple(drop))
    if bin_err:
        pm.add_event("backup", "backup_binary_failed", "warning", host, "Binary backup failed", bin_err[:400])
        pm.consider_notify(s, host, "warning", f"[{s['site_name']}] Binary backup failed: {host['name']}", bin_err[:400],
                           pm.build_payload(s, "device_alert", None, host, severity="warning", message=bin_err[:400]))
    pm.add_event("backup", "backup_ok", "info", host, "Config backup saved",
                 f"Saved via {via}." + (" Config changed." if changed else " No config change."))
    return {"via": via, "changed": changed, "path": path}


def _backup_fail(pm, s, host, message):
    now = time.time()
    with pm._db_lock, pm.db() as c:
        c.execute(
            "INSERT INTO backups(host_id, ts, ok, error, path, bin_path, sha, changed, diff, bytes) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (host["id"], now, 0, message[:500], "", "", "", 0, "", 0))
    pm.add_event("backup", "backup_failed", "critical", host, "Backup failed", message[:400])
    pm.consider_notify(s, host, "critical", f"[{s['site_name']}] Backup failed: {host['name']}", message[:400],
                       pm.build_payload(s, "device_alert", None, host, severity="critical", message=message[:400]))


def backup_scheduled(pm):
    s = pm.get_settings()
    with pm.db() as c:
        hosts = [dict(r) for r in c.execute("SELECT * FROM hosts WHERE device_type='mikrotik' AND enabled=1")]
    for host in hosts:
        try:
            cfg = json.loads(host.get("mtbak") or "{}")
        except (TypeError, ValueError):
            continue
        if not cfg.get("enabled"):
            continue
        with pm.db() as c:
            last = c.execute("SELECT MAX(ts) AS ts FROM backups WHERE host_id=? AND ok=1", (host["id"],)).fetchone()
        if backup_due(s, last["ts"] if last else None):
            try:
                run_backup(pm, host, "schedule")
            except Exception as e:
                pm.log.exception("backup %s: %s", host.get("name"), e)


def report_context(pm, start, end, lang, site):
    s = pm.get_settings()
    tz = pm.tzinfo()

    def when(ts):
        return pm.fmt_ts(ts, tz) if ts else ""

    hosts = []
    outages = []
    with pm.db() as c:
        for host in c.execute("SELECT * FROM hosts ORDER BY grp, name"):
            rows = c.execute(
                f"SELECT ts, ok, ms, n, nok FROM results WHERE host_id=? AND {TIER} ORDER BY ts",
                (host["id"], *tier_args(start, end if False else time.time()))).fetchall()
            rows = [r for r in rows if start <= r["ts"] <= end]
            n = sum((r["n"] or 1) for r in rows)
            nok = sum((r["nok"] if r["nok"] is not None else r["ok"]) for r in rows)
            pct = f"{(100.0 * nok / n):.1f}%" if n else "—"
            hosts.append({"name": host["name"], "ip": host["host"], "group": host["grp"], "uptime": pct})
            down_at = None
            for row in rows:
                good = row["nok"] if row["nok"] is not None else row["ok"]
                is_down = good == 0
                if is_down and down_at is None:
                    down_at = row["ts"]
                elif not is_down and down_at is not None:
                    outages.append({"host": host["name"], "start": when(down_at), "end": when(row["ts"]),
                                    "duration": pm.fmt_dur(row["ts"] - down_at)})
                    down_at = None
            if down_at is not None:
                outages.append({"host": host["name"], "start": when(down_at), "end": "",
                                "duration": pm.fmt_dur(end - down_at)})
        wan_rows = list(c.execute(
            "SELECT ts, loss, avg_ms, jitter FROM wan_samples WHERE ts>=? AND ts<=?", (start, end)))
        cams = []
        for row in c.execute(
                "SELECT h.name, c.data FROM cam_state c JOIN hosts h ON h.id=c.host_id"):
            try:
                data = json.loads(row["data"] or "{}")
            except (TypeError, ValueError):
                data = {}
            bits = []
            if data.get("error"):
                bits.append(data["error"][:80])
            for disk in data.get("disks") or []:
                bits.append(f"{disk.get('name')}: {disk.get('status')}")
            off = [ch for ch in data.get("channels") or [] if ch.get("online") is False]
            if off:
                bits.append(f"{len(off)} camera(s) offline")
            cams.append({"host": row["name"], "status": "; ".join(bits) or "OK"})
        bands = []
        for host in c.execute("SELECT id, name FROM hosts"):
            samples = c.execute(
                "SELECT ifs FROM snmp_samples WHERE host_id=? AND ts>=? AND ts<=?",
                (host["id"], start, end)).fetchall()
            acc = {}
            for sample in samples:
                try:
                    data = json.loads(sample["ifs"] or "{}")
                except (TypeError, ValueError):
                    continue
                for name, pair in data.items():
                    if not pair or pair[0] is None:
                        continue
                    slot = acc.setdefault(name, [0.0, 0.0, 0])
                    slot[0] += pair[0]
                    slot[1] += pair[1] or 0
                    slot[2] += 1
            for name, (inn, out, n) in acc.items():
                bands.append({"host": host["name"], "iface": name,
                              "in": pm.fmt_bps(inn / n), "out": pm.fmt_bps(out / n)})
        power = []
        for host in c.execute("SELECT id, name FROM hosts WHERE device_type='ups'"):
            ev = c.execute(
                "SELECT COUNT(*) FROM events WHERE host_id=? AND source='ups' AND ts>=? AND ts<=?",
                (host["id"], start, end)).fetchone()[0]
            state = c.execute("SELECT data FROM snmp_state WHERE host_id=?", (host["id"],)).fetchone()
            status = ""
            if state:
                try:
                    ups = (json.loads(state["data"] or "{}")).get("ups") or {}
                    status = "on battery" if ups.get("on_battery") else ("on mains" if ups.get("on_mains") else "")
                    if ups.get("charge_pct") is not None:
                        status += f", battery {ups['charge_pct']}%"
                except (TypeError, ValueError):
                    status = ""
            power.append({"host": host["name"], "events": str(ev), "status": status or "—"})
        counts = {"critical": 0, "warning": 0, "info": 0}
        for row in c.execute(
                "SELECT severity, COUNT(*) AS n FROM events WHERE ts>=? AND ts<=? GROUP BY severity", (start, end)):
            if row["severity"] in counts:
                counts[row["severity"]] = row["n"]
    losses = [r["loss"] for r in wan_rows if r["loss"] is not None]
    lats = [r["avg_ms"] for r in wan_rows if r["avg_ms"] is not None]
    jits = [r["jitter"] for r in wan_rows if r["jitter"] is not None]
    internet = {}
    if wan_rows:
        internet = {
            "loss": f"{(sum(losses) / len(losses)):.1f}%" if losses else "—",
            "latency": f"{(sum(lats) / len(lats)):.0f} ms" if lats else "—",
            "jitter": f"{(sum(jits) / len(jits)):.0f} ms" if jits else "—",
            "down": sum(1 for r in wan_rows if (r["loss"] or 0) >= 99.9),
        }
    return {
        "lang": lang,
        "site": site or s["site_name"],
        "period": f"{when(start)} — {when(end)}",
        "generated": when(time.time()),
        "hosts": hosts,
        "outages": outages[:80],
        "internet": internet,
        "cameras": cams,
        "bandwidth": bands[:40],
        "power": power,
        "alerts": counts,
        "version": getattr(pm, "VERSION", ""),
    }
