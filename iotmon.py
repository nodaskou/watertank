"""Read-only Shelly and Sonoff status.

No relay commands, no firmware upload, no cloud account. Optional measurements
that the payload does not contain are omitted. They are not treated as zero
and they do not make the device offline.

Sources:
- Shelly Gen1 HTTP: https://shelly-api-docs.shelly.cloud/gen1/
- Shelly Gen2+ RPC: https://shelly-api-docs.shelly.cloud/gen2/ComponentsAndServices/Switch
- Sonoff DIY: https://help.sonoff.tech/docs/DIY-MODE-API-PROTOCOL
- BASICR3/RFR3/MINI info: https://help.sonoff.tech/docs/BASICR3-RFR3-MINIR2-API
- Tasmota Status: https://tasmota.github.io/docs/JSON-Status-Responses/
"""
import json
import socket
import urllib.error
import urllib.request


# Stock eWeLink firmware is not a generic local HTTP API. DIY mode is a
# separate mode on the models listed in the Sonoff docs above.
SONOFF_DIY_MODELS = (
    "BASICR3", "RFR3", "MINI", "MINIR2", "MINIR3",
    "D1", "SPM-Main", "B02-BL-A60", "B05-BL-A19", "B05-BL-A60",
)


def judge_transport(kind):
    """Map a fetch outcome to online / offline / auth / api_error / unknown.

    offline is only a failed connection. HTTP 401 is auth: the device answered.
    A relay that is off is not represented here at all.
    """
    if kind == "offline":
        return "offline"
    if kind == "auth":
        return "auth"
    if kind == "api_error":
        return "api_error"
    if kind == "online":
        return "online"
    return "unknown"


def plan_iot(reach, fails, alerted, last_alert, held, observation, now, threshold, repeat_min, blocked):
    """One reachability step. observation is online, offline, auth, api_error, or unknown.

    Only `offline` counts toward the failure threshold. Auth, API errors and
    unknown stay off the offline alert. `blocked` is an upstream parent that is
    down, or this same host already down by ping: suppress the notification.
    """
    reach = reach or "unknown"
    fails = int(fails or 0)
    alerted = 1 if alerted else 0
    held = 1 if held else 0
    last_alert = float(last_alert or 0)
    threshold = max(1, int(threshold or 1))
    repeat_min = int(repeat_min or 0)
    base = {"diag": observation}
    if observation == "unknown":
        base.update(reach=reach or "unknown", fails=fails, alerted=alerted, last_alert=last_alert,
                    held=held, action=None)
        return base
    if observation in ("auth", "api_error"):
        action = "recovered" if reach == "offline" and alerted else None
        return {"reach": observation, "fails": 0, "alerted": 0, "last_alert": 0, "held": 0,
                "diag": observation, "action": action}
    if observation == "online":
        action = "recovered" if reach == "offline" and alerted else ("recovered_quiet" if reach == "offline" else None)
        return {"reach": "online", "fails": 0, "alerted": 0, "last_alert": 0, "held": 0,
                "diag": "online", "action": action}
    fails += 1
    down = fails >= threshold or reach == "offline"
    if not down:
        return {"reach": "unknown", "fails": fails, "alerted": 0, "last_alert": 0, "held": 0,
                "diag": "offline", "action": None}
    if blocked:
        action = "held" if reach != "offline" or not held else None
        return {"reach": "offline", "fails": fails, "alerted": alerted, "last_alert": last_alert,
                "held": 1, "diag": "offline", "action": action}
    if held and not alerted:
        return {"reach": "offline", "fails": fails, "alerted": 0, "last_alert": now,
                "held": 0, "diag": "offline", "action": "release"}
    if held and alerted:
        return {"reach": "offline", "fails": fails, "alerted": 1, "last_alert": now,
                "held": 0, "diag": "offline", "action": None}
    if reach != "offline":
        return {"reach": "offline", "fails": fails, "alerted": 0, "last_alert": 0,
                "held": 0, "diag": "offline", "action": "down"}
    if alerted and repeat_min > 0 and last_alert and now - last_alert >= repeat_min * 60:
        return {"reach": "offline", "fails": fails, "alerted": 1, "last_alert": now,
                "held": 0, "diag": "offline", "action": "repeat"}
    return {"reach": "offline", "fails": fails, "alerted": alerted, "last_alert": last_alert,
            "held": 0, "diag": "offline", "action": None}


def _num(value):
    if isinstance(value, bool) or value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _channel(index, kind, on, extra=None):
    item = {"index": index, "kind": kind, "on": bool(on) if on is not None else None}
    if extra:
        item.update(extra)
    return item


def parse_shelly_gen1(status):
    """Channels and readings present in a Gen1 /status object. Missing keys are omitted."""
    status = status or {}
    channels = []
    for i, rel in enumerate(status.get("relays") or []):
        if isinstance(rel, dict) and "ison" in rel:
            channels.append(_channel(i, "relay", rel.get("ison")))
    for i, light in enumerate(status.get("lights") or []):
        if isinstance(light, dict) and "ison" in light:
            extra = {}
            if "brightness" in light:
                extra["brightness"] = light.get("brightness")
            channels.append(_channel(i, "light", light.get("ison"), extra))
    inputs = []
    for i, inp in enumerate(status.get("inputs") or []):
        if isinstance(inp, dict) and "input" in inp:
            inputs.append({"index": i, "on": bool(inp.get("input"))})
    power, energy = [], []
    for i, meter in enumerate(status.get("meters") or []):
        if not isinstance(meter, dict):
            continue
        if "power" in meter:
            power.append({"index": i, "watts": _num(meter.get("power"))})
        if "total" in meter:
            energy.append({"index": i, "watt_hours": _num(meter.get("total"))})
    for i, meter in enumerate(status.get("emeters") or []):
        if not isinstance(meter, dict):
            continue
        if "power" in meter:
            power.append({"index": i, "watts": _num(meter.get("power"))})
        if "total" in meter:
            energy.append({"index": i, "watt_hours": _num(meter.get("total"))})
    temp = None
    tmp = status.get("tmp") if isinstance(status.get("tmp"), dict) else None
    if tmp is not None and tmp.get("is_valid") is False:
        temp = None
    elif tmp is not None and "tC" in tmp:
        temp = _num(tmp.get("tC"))
    elif "temperature" in status and not isinstance(status.get("temperature"), dict):
        temp = _num(status.get("temperature"))
    return {
        "channels": channels, "inputs": inputs, "power": power, "energy": energy,
        "temp_c": temp, "uptime": status.get("uptime") if isinstance(status.get("uptime"), int) else None,
        "model": None,
    }


def parse_shelly_gen2(status, info=None):
    """Gen2+ Shelly.GetStatus. Component names that are present become channels."""
    status = status or {}
    channels, inputs, power, energy = [], [], [], []
    temps = []
    for key, block in status.items():
        if not isinstance(block, dict) or ":" not in key:
            continue
        name, _, idx = key.partition(":")
        try:
            index = int(idx)
        except ValueError:
            continue
        if name in ("switch", "light") and "output" in block:
            extra = {}
            if isinstance(block.get("temperature"), dict) and "tC" in block["temperature"]:
                extra["temp_c"] = _num(block["temperature"].get("tC"))
                if extra["temp_c"] is not None:
                    temps.append(extra["temp_c"])
            if "apower" in block:
                power.append({"index": index, "watts": _num(block.get("apower"))})
            aenergy = block.get("aenergy") if isinstance(block.get("aenergy"), dict) else None
            if aenergy and "total" in aenergy:
                energy.append({"index": index, "watt_hours": _num(aenergy.get("total"))})
            channels.append(_channel(index, "relay" if name == "switch" else "light", block.get("output"), extra))
        elif name == "input" and "state" in block:
            inputs.append({"index": index, "on": bool(block.get("state"))})
        elif name == "temperature" and isinstance(block.get("tC"), (int, float)):
            temps.append(_num(block.get("tC")))
        elif name in ("pm1", "em") and ("apower" in block or "total_act_power" in block):
            watts = block.get("apower", block.get("total_act_power"))
            if watts is not None:
                power.append({"index": index, "watts": _num(watts)})
            aenergy = block.get("aenergy") if isinstance(block.get("aenergy"), dict) else None
            if aenergy and "total" in aenergy:
                energy.append({"index": index, "watt_hours": _num(aenergy.get("total"))})
    sysb = status.get("sys") if isinstance(status.get("sys"), dict) else {}
    model = None
    if isinstance(info, dict):
        model = info.get("model") or info.get("app")
    return {
        "channels": channels, "inputs": inputs, "power": power, "energy": energy,
        "temp_c": max(temps) if temps else None,
        "uptime": sysb.get("uptime") if isinstance(sysb.get("uptime"), int) else None,
        "model": model,
    }


def parse_sonoff_diy(payload):
    """DIY /zeroconf/info. switch on/off is a relay position, not reachability."""
    data = payload.get("data") if isinstance(payload, dict) and isinstance(payload.get("data"), dict) else payload
    if not isinstance(data, dict):
        return None
    channels = []
    if isinstance(data.get("switches"), list):
        for i, sw in enumerate(data["switches"]):
            if isinstance(sw, dict) and "switch" in sw:
                channels.append(_channel(int(sw.get("outlet", i)), "relay", str(sw.get("switch")).lower() == "on"))
    elif "switch" in data:
        channels.append(_channel(0, "relay", str(data.get("switch")).lower() == "on"))
    power, energy = [], []
    if "power" in data:
        power.append({"index": 0, "watts": _num(data.get("power"))})
    if "current" in data or "voltage" in data:
        pass
    readings = {}
    if "voltage" in data:
        readings["voltage"] = _num(data.get("voltage"))
    if "current" in data:
        readings["current"] = _num(data.get("current"))
    temp = _num(data.get("temperature")) if "temperature" in data else None
    return {
        "channels": channels, "inputs": [], "power": power, "energy": energy,
        "temp_c": temp, "uptime": None, "model": data.get("fwVersion") or data.get("deviceid"),
        "extra": readings, "firmware": data.get("fwVersion"),
    }


def parse_tasmota(status0, status8=None):
    """Tasmota Status 0 and optional Status 8. POWER OFF is a relay state."""
    root = status0 or {}
    sts = root.get("StatusSTS") if isinstance(root.get("StatusSTS"), dict) else root
    if not isinstance(sts, dict):
        return None
    channels = []
    if "POWER" in sts:
        channels.append(_channel(0, "relay", str(sts.get("POWER")).upper() == "ON"))
    for i in range(1, 9):
        key = f"POWER{i}"
        if key in sts:
            channels.append(_channel(i, "relay", str(sts.get(key)).upper() == "ON"))
    power, energy, temp = [], [], None
    sns = {}
    if isinstance(status8, dict):
        sns = status8.get("StatusSNS") if isinstance(status8.get("StatusSNS"), dict) else status8
    blob = {}
    if isinstance(sns, dict):
        blob.update(sns)
    energy_block = blob.get("ENERGY") if isinstance(blob.get("ENERGY"), dict) else None
    if energy_block:
        if "Power" in energy_block:
            power.append({"index": 0, "watts": _num(energy_block.get("Power"))})
        if "Total" in energy_block:
            energy.append({"index": 0, "watt_hours": (_num(energy_block.get("Total")) or 0) * 1000})
    for key, block in blob.items():
        if isinstance(block, dict) and "Temperature" in block:
            temp = _num(block.get("Temperature"))
            break
    uptime = sts.get("UptimeSec") if isinstance(sts.get("UptimeSec"), int) else None
    name = None
    status = root.get("Status") if isinstance(root.get("Status"), dict) else {}
    if isinstance(status.get("DeviceName"), str):
        name = status.get("DeviceName")
    return {"channels": channels, "inputs": [], "power": power, "energy": energy,
            "temp_c": temp, "uptime": uptime, "model": name or "Tasmota"}


def evaluate_mqtt(records, now, stale_sec):
    """Tasmota-style LWT plus staleness.

    Broker connectivity is not device online. No message yet is unknown.
    LWT Offline is offline. LWT Online with a fresh STATE/SENSOR is online.
    A stale STATE after Online is offline. Missing power does not change that.
    """
    try:
        stale = max(30, int(stale_sec or 180))
    except (TypeError, ValueError):
        stale = 180
    lwt = None
    lwt_ts = None
    state_ts = None
    payloads = []
    for row in records or []:
        topic = str(row.get("topic") or "")
        ts = float(row.get("ts") or 0)
        payload = row.get("payload")
        tail = topic.rsplit("/", 1)[-1].upper()
        if tail == "LWT":
            if lwt_ts is None or ts >= lwt_ts:
                lwt = str(payload or "").strip().lower()
                lwt_ts = ts
        elif tail in ("STATE", "SENSOR", "STATUS"):
            if state_ts is None or ts >= state_ts:
                state_ts = ts
                payloads.append(payload)
    if lwt is None and state_ts is None:
        return {"reach": "unknown", "diag": "no message yet", "parsed": None}
    fresh = state_ts is not None and (float(now) - state_ts) <= stale
    if lwt in ("offline", "0", "dead"):
        return {"reach": "offline", "diag": "last will offline", "parsed": None}
    if lwt in ("online", "1", "alive") and fresh:
        parsed = _mqtt_state(payloads[-1] if payloads else None)
        return {"reach": "online", "diag": "last will online", "parsed": parsed}
    if lwt in ("online", "1", "alive") and not fresh:
        return {"reach": "offline", "diag": "last will online but status is stale", "parsed": None}
    if fresh:
        parsed = _mqtt_state(payloads[-1] if payloads else None)
        return {"reach": "online", "diag": "status is fresh", "parsed": parsed}
    return {"reach": "offline", "diag": "status is stale", "parsed": None}


def _mqtt_state(payload):
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except (TypeError, ValueError):
            return None
    if not isinstance(payload, dict):
        return None
    fake = {"StatusSTS": payload, "Status": {"DeviceName": payload.get("Hostname") or "MQTT"}}
    if "POWER" not in payload and "POWER1" not in payload:
        return {"channels": [], "inputs": [], "power": [], "energy": [],
                "temp_c": None, "uptime": payload.get("UptimeSec") if isinstance(payload.get("UptimeSec"), int) else None,
                "model": "MQTT"}
    return parse_tasmota(fake)


def threshold_hits(parsed, temp_max, power_max):
    """Alerts only for readings that exist and are over a positive limit."""
    hits = []
    if not parsed:
        return hits
    try:
        tmax = float(temp_max or 0)
    except (TypeError, ValueError):
        tmax = 0
    try:
        pmax = float(power_max or 0)
    except (TypeError, ValueError):
        pmax = 0
    if tmax > 0 and parsed.get("temp_c") is not None and parsed["temp_c"] >= tmax:
        hits.append({"key": "temp", "severity": "warning", "title": "Switch temperature high",
                     "message": f"Temperature {parsed['temp_c']}°C is at or above {tmax:g}°C."})
    if pmax > 0:
        watts = [p.get("watts") for p in parsed.get("power") or [] if p.get("watts") is not None]
        if watts and max(watts) >= pmax:
            hits.append({"key": "power", "severity": "warning", "title": "Switch power high",
                         "message": f"Power {max(watts):g} W is at or above {pmax:g} W."})
    return hits


def _transport_from_error(exc):
    if isinstance(exc, (TimeoutError, socket.timeout)):
        return "offline"
    if isinstance(exc, ConnectionRefusedError):
        return "offline"
    if isinstance(exc, urllib.error.HTTPError):
        if exc.code in (401, 403):
            return "auth"
        return "api_error"
    if isinstance(exc, urllib.error.URLError):
        reason = exc.reason
        if isinstance(reason, (TimeoutError, socket.timeout, ConnectionRefusedError)):
            return "offline"
        text = str(reason).lower()
        if "timed out" in text or "refused" in text or "unreachable" in text or "no route" in text:
            return "offline"
        return "offline"
    return "api_error"


def http_fetch(method, url, user="", password="", body=None, timeout=8):
    """One HTTP call. Passwords are not put in the URL and are not logged."""
    data = None if body is None else (body if isinstance(body, bytes) else body.encode("utf-8"))
    req = urllib.request.Request(url, data=data, method=method)
    if body is not None:
        req.add_header("Content-Type", "application/json")
    handlers = []
    if user or password:
        password_mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
        password_mgr.add_password(None, url, user or "", password or "")
        handlers.append(urllib.request.HTTPBasicAuthHandler(password_mgr))
        handlers.append(urllib.request.HTTPDigestAuthHandler(password_mgr))
    opener = urllib.request.build_opener(*handlers)
    try:
        with opener.open(req, timeout=timeout) as resp:
            raw = resp.read(500_000)
            return resp.status, raw.decode("utf-8", "replace"), "online"
    except Exception as exc:
        return 0, "", _transport_from_error(exc)


def check_shelly(fetch, generation="auto"):
    """fetch(path) -> (status, body, transport). generation is auto, gen1, or gen2."""
    generation = generation if generation in ("auto", "gen1", "gen2") else "auto"
    order = ("gen1", "gen2") if generation == "auto" else (generation,)
    if generation == "gen2":
        order = ("gen2",)
    tried = []
    for gen in order:
        if gen == "gen1":
            status, body, transport = fetch("/shelly")
            tried.append("/shelly")
            if transport == "offline":
                return _checked("shelly", "gen1", transport, None, "no connection", tried)
            if transport == "auth":
                return _checked("shelly", "gen1", "auth", None, "sign-in failed", tried)
            st, raw, transport = fetch("/status")
            tried.append("/status")
            if transport in ("offline", "auth"):
                return _checked("shelly", "gen1", transport, None, "sign-in failed" if transport == "auth" else "no connection", tried)
            if transport != "online" or st != 200:
                if generation != "auto":
                    return _checked("shelly", "gen1", "api_error", None, f"HTTP {st or 0}", tried)
                continue
            try:
                parsed = parse_shelly_gen1(json.loads(raw or "{}"))
            except (TypeError, ValueError):
                return _checked("shelly", "gen1", "unknown", None, "status was not JSON", tried)
            info_model = None
            if status == 200 and body:
                try:
                    info = json.loads(body)
                    info_model = info.get("type")
                except (TypeError, ValueError):
                    info_model = None
            parsed["model"] = info_model
            return _checked("shelly", "gen1", "online", parsed, "", tried)
        status, body, transport = fetch("/rpc/Shelly.GetDeviceInfo")
        tried.append("/rpc/Shelly.GetDeviceInfo")
        if transport == "offline":
            return _checked("shelly", "gen2", "offline", None, "no connection", tried)
        if transport == "auth":
            return _checked("shelly", "gen2", "auth", None, "sign-in failed", tried)
        st, raw, transport = fetch("/rpc/Shelly.GetStatus")
        tried.append("/rpc/Shelly.GetStatus")
        if transport in ("offline", "auth"):
            return _checked("shelly", "gen2", transport, None, "sign-in failed" if transport == "auth" else "no connection", tried)
        if st != 200 or transport != "online":
            return _checked("shelly", "gen2", "api_error", None, f"HTTP {st or 0}", tried)
        try:
            info = json.loads(body) if body else {}
            parsed = parse_shelly_gen2(json.loads(raw or "{}"), info if isinstance(info, dict) else None)
        except (TypeError, ValueError):
            return _checked("shelly", "gen2", "unknown", None, "status was not JSON", tried)
        return _checked("shelly", "gen2", "online", parsed, "", tried)
    return _checked("shelly", generation, "unknown", None, "no supported Shelly status API answered", tried)


def check_sonoff_diy(fetch, device_id=""):
    """POST /zeroconf/info only. device_id is required by DIY firmware 3.7.6 and newer."""
    payload = json.dumps({"deviceid": device_id or "", "data": {}})
    status, body, transport = fetch("/zeroconf/info", payload)
    tried = ["/zeroconf/info"]
    if transport == "offline":
        return _checked("sonoff", "diy", "offline", None, "no connection", tried)
    if transport == "auth":
        return _checked("sonoff", "diy", "auth", None, "sign-in failed", tried)
    if status != 200 or transport != "online":
        return _checked("sonoff", "diy", "api_error", None, f"HTTP {status or 0}", tried)
    try:
        parsed = parse_sonoff_diy(json.loads(body or "{}"))
    except (TypeError, ValueError):
        return _checked("sonoff", "diy", "unknown", None, "info was not JSON", tried)
    if not parsed:
        return _checked("sonoff", "diy", "unknown", None, "info had no data object", tried)
    if parsed.get("channels") == [] and "switch" not in (body or "") and "switches" not in (body or ""):
        parsed["channels"] = []
    return _checked("sonoff", "diy", "online", parsed, "", tried)


def check_tasmota(fetch):
    """Status 0 and Status 8. Status 8 may be missing; that does not mean offline."""
    st, body, transport = fetch("/cm?cmnd=Status%200")
    tried = ["/cm?cmnd=Status%200"]
    if transport == "offline":
        return _checked("sonoff", "tasmota", "offline", None, "no connection", tried)
    if transport == "auth":
        return _checked("sonoff", "tasmota", "auth", None, "sign-in failed", tried)
    if st != 200 or transport != "online":
        return _checked("sonoff", "tasmota", "api_error", None, f"HTTP {st or 0}", tried)
    st8, body8, transport8 = fetch("/cm?cmnd=Status%208")
    tried.append("/cm?cmnd=Status%208")
    try:
        status0 = json.loads(body or "{}")
        status8 = json.loads(body8) if st8 == 200 and transport8 == "online" and body8 else None
        parsed = parse_tasmota(status0, status8)
    except (TypeError, ValueError):
        return _checked("sonoff", "tasmota", "unknown", None, "status was not JSON", tried)
    if not parsed:
        return _checked("sonoff", "tasmota", "unknown", None, "status had no StatusSTS", tried)
    note = "" if status8 else "Sensor status (Status 8) was not available. Power and temperature are omitted, the switch is still online."
    return _checked("sonoff", "tasmota", "online", parsed, note, tried)


def _checked(brand, mode, observation, parsed, detail, calls):
    return {
        "brand": brand, "mode": mode, "observation": judge_transport(observation if observation in ("online", "offline", "auth", "api_error") else ("online" if parsed else "unknown")),
        "parsed": parsed, "detail": detail, "calls": calls,
        "ok": observation == "online" and parsed is not None,
    }


def mqtt_library_missing():
    return {"brand": "sonoff", "mode": "mqtt", "observation": "unknown", "parsed": None,
            "detail": "The MQTT client library is not installed. This monitor does not install a broker. Install paho-mqtt in the server venv and point it at the broker you already run.",
            "calls": [], "ok": False}
