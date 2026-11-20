"""Read-only parsers for the extra 3.2.0 checks, plus kiosk and on-call rules.

Network calls stay in the app. These functions only interpret data the tests can fake.
Power-cycle URLs are built only when that device has the option turned on.
"""
import hmac
import re
from datetime import datetime


def kiosk_matches(presented, stored):
    if not presented or not stored:
        return False
    try:
        return hmac.compare_digest(str(presented), str(stored))
    except Exception:
        return False


def config_change(previous, current):
    """Masked unified diff, or empty when there is nothing earlier to compare."""
    if not previous or not current:
        return ""
    old, new = previous.splitlines(), current.splitlines()
    if old == new:
        return ""
    import difflib
    diff = "\n".join(list(difflib.unified_diff(old, new, lineterm="", n=1))[:80])
    return mask_secrets(diff)


def sparkline(values):
    """Tiny SVG of dBm history. Empty input is an empty string, not a fake line."""
    nums = [float(v) for v in values or []]
    if len(nums) < 2:
        return ""
    lo, hi = min(nums), max(nums)
    span = hi - lo or 1
    pts = []
    for i, value in enumerate(nums):
        x = 4 + i * (112 / (len(nums) - 1))
        y = 36 - (value - lo) / span * 28
        pts.append(f"{x:.1f},{y:.1f}")
    return f'<svg viewBox="0 0 120 40" width="120" height="40"><polyline fill="none" stroke="#1d4ed8" stroke-width="2" points="{" ".join(pts)}"/></svg>'


def mask_secrets(text):
    """Hide password-like values in a config diff. The rest of the line stays."""
    def repl(match):
        return match.group(1) + match.group(2) + "***"
    return re.sub(r"(?i)(password|passwd|secret|community|psk|key)(\s*[:=]\s*)\S+", repl, text or "")


def parse_hik_tamper(body):
    """True/False only when a tamper flag is explicit. Otherwise unknown (None)."""
    if not body:
        return None
    low = body.lower()
    if "<tempered>" in low or "<tamperstatus>" in low or "tamper=" in low:
        if any(token in low for token in ("<tempered>true", "<tamperstatus>true", "tamper=1", "tamper=true")):
            return True
        if any(token in low for token in ("<tempered>false", "<tamperstatus>false", "tamper=0", "tamper=false")):
            return False
    return None


def parse_device_time(body):
    """ISO-like time from an NVR, or None when the body has no clock."""
    if not body:
        return None
    match = re.search(r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})", body)
    if not match:
        return None
    try:
        return datetime.strptime(match.group(1).replace("T", " "), "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


def clock_drift_seconds(device_time, server_time):
    if device_time is None or server_time is None:
        return None
    return int((device_time - server_time).total_seconds())


def recording_gap_minutes(ranges, start, end):
    """Minutes inside [start, end] that are not covered. None when ranges is None (unknown)."""
    if ranges is None:
        return None
    span = max(0, int(end - start))
    if span == 0:
        return 0
    covered = 0
    for begin, finish in ranges:
        lo, hi = max(start, begin), min(end, finish)
        if hi > lo:
            covered += hi - lo
    return max(0, int((span - covered) / 60))


def parse_routeros_resource(payload):
    if not isinstance(payload, dict):
        return None
    out = {}
    if "cpu-load" in payload:
        out["cpu"] = payload.get("cpu-load")
    if "free-memory" in payload and payload.get("total-memory"):
        out["mem_pct"] = round(100.0 * (1 - payload["free-memory"] / payload["total-memory"]), 1)
    if "board-temperature" in payload:
        out["temp"] = payload.get("board-temperature")
    if "voltage" in payload:
        out["voltage"] = payload.get("voltage")
    return out or None


def parse_default_gateway(routes):
    for row in routes or []:
        if not isinstance(row, dict):
            continue
        dst = str(row.get("dst-address") or "")
        if dst in ("0.0.0.0/0", "::/0") and row.get("active") in (True, "true", None) and row.get("gateway"):
            return str(row.get("gateway"))
    return None


def route_event(previous, current):
    """None, 'changed', or 'restored'. The first sample only remembers the gateway."""
    if not current:
        return None
    if not previous:
        return None
    if previous == current:
        return None
    return "changed"


def parse_sfp(rows):
    """Rows of {name, rx, tx} in dBm. Missing power stays absent."""
    out = []
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        item = {"name": row.get("name") or "sfp"}
        if row.get("sfp-rx-power") is not None:
            item["rx"] = float(row["sfp-rx-power"])
        if row.get("sfp-tx-power") is not None:
            item["tx"] = float(row["sfp-tx-power"])
        if "rx" in item or "tx" in item:
            out.append(item)
    return out


def sfp_level(dbm, warn, crit):
    """Lower (more negative) light is worse. None stays unknown."""
    if dbm is None:
        return "unknown"
    try:
        warn, crit = float(warn), float(crit)
        value = float(dbm)
    except (TypeError, ValueError):
        return "unknown"
    if value <= crit:
        return "critical"
    if value <= warn:
        return "warning"
    return "ok"


def parse_sip_peers(text):
    """AMI-like 'Name/user host status' lines. Unreadable text is unknown."""
    if not text:
        return None
    peers = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        status = parts[-1].lower()
        if status not in ("ok", "unmonitored", "unreachable", "unknown", "registered", "unregistered"):
            continue
        peers.append({"name": parts[0], "online": status in ("ok", "unmonitored", "registered")})
    return peers or None


def sip_code_online(code):
    """A SIP response code. No response is unknown, not offline."""
    if code is None:
        return None
    try:
        code = int(code)
    except (TypeError, ValueError):
        return None
    if code <= 0:
        return None
    return code < 400


def parse_pbx_api(payload):
    """FreePBX or Yeastar style JSON. Missing lists stay unknown."""
    if not isinstance(payload, dict):
        return None
    trunks = payload.get("trunks")
    exts = payload.get("extensions")
    if trunks is None and exts is None:
        return None
    def norm(rows):
        if rows is None:
            return None
        out = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            state = str(row.get("status") or row.get("state") or "").lower()
            out.append({"name": row.get("name") or row.get("ext") or "",
                        "online": state in ("registered", "ok", "online", "reachable")})
        return out
    return {"trunks": norm(trunks), "extensions": norm(exts)}


def power_url(kind, channel, turn_on):
    """Path only. Caller must already have checked that power control is enabled."""
    action = "on" if turn_on else "off"
    channel = int(channel or 0)
    if kind == "shelly-gen1":
        return f"/relay/{channel}?turn={action}"
    if kind == "shelly-gen2":
        return "/rpc/Switch.Set"
    if kind == "sonoff-diy":
        return "/zeroconf/switch"
    if kind == "tasmota":
        return "/cm?cmnd=Power%20" + ("ON" if turn_on else "OFF")
    raise ValueError("This device cannot be power-cycled from here.")


def on_duty(rows, when):
    """Weekly rota. when is a timezone-aware datetime. None when nobody is scheduled."""
    minute = when.hour * 60 + when.minute
    day = when.weekday()
    for row in rows or []:
        try:
            if int(row.get("day")) != day:
                continue
            start = _hm(row.get("start") or "00:00")
            end = _hm(row.get("end") or "24:00")
        except (TypeError, ValueError):
            continue
        if start == end:
            continue
        inside = start <= minute < end if start < end else minute >= start or minute < end
        if inside and row.get("chat_id"):
            return {"name": row.get("name") or "", "chat_id": str(row.get("chat_id"))}
    return None


def _hm(text):
    if text in ("24:00", "24:00:00"):
        return 24 * 60
    hour, minute = str(text).split(":")[:2]
    return int(hour) * 60 + int(minute)
