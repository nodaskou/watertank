"""Pure helpers for alerts, WAN quality, SNMP rates and UPS readings.

No Flask and no database, so the rules can be tested on their own.
"""


def octet_rate(prev, new, dt, bits=64):
    """Bits per second from a wrapping octet counter. None if the jump is not believable."""
    if not isinstance(prev, int) or not isinstance(new, int) or not dt or dt <= 0:
        return None
    wrap = 1 << int(bits)
    delta = (new - prev) % wrap
    if delta >= wrap // 4:
        return None
    return round(delta * 8 / dt)


def in_quiet(start, end, minute_of_day):
    """True when minute_of_day (0-1439) falls inside a same-day or overnight window.

    Empty times, or a start that equals the end, mean quiet hours are off.
    """
    if not start or not end:
        return False

    def parse(text):
        hour, minute = str(text).strip().split(":")
        hour, minute = int(hour), int(minute)
        if not (0 <= hour <= 23 and 0 <= minute <= 59):
            raise ValueError(text)
        return hour * 60 + minute

    try:
        begin, stop = parse(start), parse(end)
    except (TypeError, ValueError):
        return False
    if begin == stop:
        return False
    minute = int(minute_of_day)
    if begin < stop:
        return begin <= minute < stop
    return minute >= begin or minute < stop


def judge_wan(rows, loss_pct, latency_ms):
    """rows are {loss, avg_ms} for each target. down / degraded / up / unknown."""
    if not rows:
        return "unknown"
    if all((r.get("loss") or 0) >= 99.9 for r in rows):
        return "down"
    loss_thr = loss_pct or 0
    lat_thr = latency_ms or 0
    for row in rows:
        if loss_thr and (row.get("loss") or 0) >= loss_thr:
            return "degraded"
        avg = row.get("avg_ms")
        if lat_thr and avg is not None and avg >= lat_thr:
            return "degraded"
    return "up"


def jitter_ms(samples):
    """Mean absolute difference of successive successful latencies."""
    vals = [v for v in samples if isinstance(v, (int, float))]
    if len(vals) < 2:
        return None
    return round(sum(abs(b - a) for a, b in zip(vals, vals[1:])) / (len(vals) - 1), 1)


_SRC = {1: "other", 2: "none", 3: "mains", 4: "bypass", 5: "battery", 6: "booster", 7: "reducer"}
_BATT = {1: "unknown", 2: "normal", 3: "low", 4: "depleted"}
_APC_OUT = {1: "unknown", 2: "mains", 3: "battery", 4: "booster", 5: "sleep", 6: "bypass",
            7: "off", 8: "reboot", 9: "bypass", 10: "bypass", 11: "sleep", 12: "trim"}


def _num(value):
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    return None


def _volts(raw):
    """UPS-MIB input/output voltage is already RMS volts. Battery voltage is 0.1 V."""
    value = _num(raw)
    if value is None:
        return None
    return round(value, 1)


def _battery_volts(raw):
    value = _num(raw)
    if value is None:
        return None
    if value > 100:  # 0.1 VDC units, e.g. 136 = 13.6 V
        value = value / 10.0
    return round(value, 1)


def ups_view(std, apc=None):
    """Normalise UPS-MIB (and APC fallback) numbers into one reading.

    std/apc map the short names in UPS_STD_OIDS / UPS_APC_OIDS to values.
    Missing APC values do not hide a good standard reading.
    """
    std, apc = std or {}, apc or {}
    source = _SRC.get(int(std["output_source"])) if _num(std.get("output_source")) else None
    if source is None and _num(apc.get("output_status")):
        source = _APC_OUT.get(int(apc["output_status"]), "other")
    battery = _BATT.get(int(std["battery_status"]), "unknown") if _num(std.get("battery_status")) else "unknown"
    charge = _num(std.get("charge_pct"))
    if charge is None:
        charge = _num(apc.get("charge_pct"))
    minutes = _num(std.get("minutes_remaining"))
    if minutes is None:
        runtime = _num(apc.get("runtime"))
        if runtime is not None:
            minutes = runtime / 6000.0 if runtime > 10000 else runtime  # TimeTicks or minutes
    load = _num(std.get("load_pct"))
    if load is None:
        load = _num(apc.get("load_pct"))
    temp = _num(std.get("temperature"))
    if temp is None:
        temp = _num(apc.get("temperature"))
    vin = _volts(std.get("input_voltage"))
    if vin is None:
        vin = _volts(apc.get("input_voltage"))
    vout = _volts(std.get("output_voltage"))
    if vout is None:
        vout = _volts(apc.get("output_voltage"))
    replace = None
    if _num(apc.get("replace")) is not None:
        replace = int(apc["replace"]) == 2
    on_battery = source == "battery" or battery == "depleted"
    on_mains = source in ("mains", "booster", "reducer", "trim", "bypass") and not on_battery
    return {
        "source": source or "unknown",
        "on_battery": bool(on_battery),
        "on_mains": bool(on_mains),
        "battery_status": battery,
        "charge_pct": None if charge is None else round(charge, 1),
        "minutes_remaining": None if minutes is None else round(minutes, 1),
        "input_voltage": vin,
        "output_voltage": vout,
        "battery_voltage": _battery_volts(std.get("battery_voltage")),
        "load_pct": None if load is None else round(load, 1),
        "temperature": None if temp is None else round(temp, 1),
        "replace": replace,
    }


def ups_alerts(prev, cur, runtime_min=0, load_thr=0):
    """Edge-triggered UPS alerts. The first reading never alerts."""
    if not prev or not cur:
        return []
    found = []
    if cur.get("on_battery") and not prev.get("on_battery"):
        found.append(("ups_on_battery", "critical", "Power cut", "The UPS switched to battery."))
    if prev.get("on_battery") and not cur.get("on_battery") and cur.get("on_mains"):
        found.append(("ups_power_restored", "info", "Power restored", "The UPS is back on mains power."))
    for status, kind, title in (("low", "ups_low_battery", "Low battery"), ("depleted", "ups_battery_depleted", "Battery depleted")):
        if cur.get("battery_status") == status and prev.get("battery_status") != status:
            found.append((kind, "critical", title, f"Battery status is {status}."))
    if runtime_min:
        now_low = cur.get("minutes_remaining") is not None and cur["minutes_remaining"] < runtime_min
        was_low = prev.get("minutes_remaining") is not None and prev["minutes_remaining"] < runtime_min
        if now_low and not was_low:
            found.append(("ups_runtime_low", "warning", "Runtime low",
                          f"About {cur['minutes_remaining']} min left (threshold {runtime_min} min)."))
    if cur.get("replace") and not prev.get("replace"):
        found.append(("ups_replace", "warning", "Replace the battery", "The UPS says the battery needs replacement."))
    if load_thr:
        high = cur.get("load_pct") is not None and cur["load_pct"] >= load_thr
        was = prev.get("load_pct") is not None and prev["load_pct"] >= load_thr
        if high and not was:
            found.append(("ups_high_load", "warning", "UPS load high",
                          f"Load is {cur['load_pct']}% (threshold {load_thr}%)."))
    return found


# OID maps used by the poller. Tests can feed ups_view without SNMP.
UPS_STD_OIDS = {
    "battery_status": "1.3.6.1.2.1.33.1.2.1.0",
    "seconds_on_battery": "1.3.6.1.2.1.33.1.2.2.0",
    "minutes_remaining": "1.3.6.1.2.1.33.1.2.3.0",
    "charge_pct": "1.3.6.1.2.1.33.1.2.4.0",
    "battery_voltage": "1.3.6.1.2.1.33.1.2.5.0",
    "temperature": "1.3.6.1.2.1.33.1.2.7.0",
    "output_source": "1.3.6.1.2.1.33.1.4.1.0",
    "input_voltage": "1.3.6.1.2.1.33.1.3.3.1.3.1",
    "output_voltage": "1.3.6.1.2.1.33.1.4.4.1.2.1",
    "load_pct": "1.3.6.1.2.1.33.1.4.4.1.5.1",
}
UPS_APC_OIDS = {
    "replace": "1.3.6.1.4.1.318.1.1.1.2.2.4.0",
    "charge_pct": "1.3.6.1.4.1.318.1.1.1.2.2.1.0",
    "runtime": "1.3.6.1.4.1.318.1.1.1.2.2.3.0",
    "output_status": "1.3.6.1.4.1.318.1.1.1.4.1.1.0",
    "input_voltage": "1.3.6.1.4.1.318.1.1.1.3.2.1.0",
    "output_voltage": "1.3.6.1.4.1.318.1.1.1.4.2.1.0",
    "load_pct": "1.3.6.1.4.1.318.1.1.1.4.2.3.0",
    "temperature": "1.3.6.1.4.1.318.1.1.1.2.2.2.0",
}
