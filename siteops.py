"""Pure helpers for the 3.2.0 dashboard, map, controllers, certificates and commands.

No Flask. Network calls are injected so tests never touch a real device.
"""
import json
import socket
import ssl
import urllib.error
import urllib.request
from datetime import datetime, timezone


CATEGORIES = (
    ("routers", "Routers", "Δρομολογητές", "#1d4ed8"),
    ("switches", "Switches", "Μεταγωγείς", "#0f766e"),
    ("wifi", "Wi-Fi / AP", "Wi-Fi / Σημεία", "#0369a1"),
    ("voip", "VoIP phones", "Τηλέφωνα VoIP", "#7c3aed"),
    ("other", "Other devices", "Άλλες συσκευές", "#64748b"),
    ("cameras", "Cameras", "Κάμερες", "#c8102e"),
    ("nvr", "NVR / DVR", "Καταγραφικά", "#9f1239"),
    ("servers", "Servers / NAS", "Διακομιστές / NAS", "#334155"),
    ("printers", "Printers / POS", "Εκτυπωτές / POS", "#a16207"),
    ("ups", "UPS", "UPS", "#b45309"),
    ("iot", "Smart / IoT", "Έξυπνες συσκευές", "#ea580c"),
)
CATEGORY_IDS = {row[0] for row in CATEGORIES}

UI = {
    "en": {
        "dashboard": "Dashboard", "map": "Network map", "devices": "Devices",
        "users": "Users", "vendors": "Vendors", "settings": "Settings",
        "log": "Log", "report": "Report", "logout": "Logout", "login": "Login",
        "total": "Total devices", "online": "Online", "offline": "Offline",
        "availability": "Availability", "lang": "Ελληνικά",
        "users_body": "Admin can change settings. Viewer can open the dashboard only.",
        "vendors_title": "Vendors", "empty": "Nothing in this list.",
        "map_title": "Network map", "map_hint": "Drawn from each device's upstream link. Colour is the current status. Scroll or pinch to zoom, drag to pan.",
        "map_zoom_in": "Zoom in", "map_zoom_out": "Zoom out", "map_fit": "Fit",
        "map_site": "Site", "map_all": "All sites", "map_last": "Last seen", "map_status": "Status",
        "map_open": "Open device",
        "clear_alarms": "Clear all alarms",
        "confirm_clear_alarms": "Clear all current alarms? Anything still failing will raise one new alert on the next check.",
        "kiosk_offline": "Currently offline", "kiosk_none_down": "Everything online",
        "kiosk_events": "Recent events", "kiosk_theme_light": "Light", "kiosk_theme_dark": "Dark",
        "held": "Alerts held",
        "brand_title": "Client logo",
        "brand_name": "Client name",
        "brand_subtitle": "Subtitle",
        "brand_upload": "Upload logo",
        "brand_remove": "Remove logo",
        "brand_hint": "PNG, JPG, WebP, or SVG, up to 512 KB. The picture sits beside the Wirewave logo. The name is the Client name in General. The subtitle is optional.",
        "brand_save": "Save client branding",
        "kiosk": "Display screen",
        "kiosk_hint": "Read-only full-screen link. Regenerating the token turns the old link off.",
        "camera_health": "Camera health",
        "unknown": "unknown",
        "oncall": "On call",
        "power_cycle": "Power cycle",
        "confirm_power": "Cycle this switch off and on? This is logged.",
    },
    "el": {
        "dashboard": "Πίνακας", "map": "Χάρτης δικτύου", "devices": "Συσκευές",
        "users": "Χρήστες", "vendors": "Κατασκευαστές", "settings": "Ρυθμίσεις",
        "log": "Ημερολόγιο", "report": "Αναφορά", "logout": "Έξοδος", "login": "Είσοδος",
        "total": "Σύνολο συσκευών", "online": "Σε λειτουργία", "offline": "Εκτός",
        "availability": "Διαθεσιμότητα", "lang": "English",
        "users_body": "Ο διαχειριστής αλλάζει ρυθμίσεις. Ο θεατής βλέπει μόνο τον πίνακα.",
        "vendors_title": "Κατασκευαστές", "empty": "Κενή λίστα.",
        "map_title": "Χάρτης δικτύου", "map_hint": "Σχεδιάζεται από τη σύνδεση «upstream» κάθε συσκευής. Το χρώμα είναι η τρέχουσα κατάσταση. Κύλιση ή τσίμπημα για μεγέθυνση, σύρσιμο για μετακίνηση.",
        "map_zoom_in": "Μεγέθυνση", "map_zoom_out": "Σμίκρυνση", "map_fit": "Ταίριασμα",
        "map_site": "Χώρος", "map_all": "Όλοι οι χώροι", "map_last": "Τελευταία επαφή", "map_status": "Κατάσταση",
        "map_open": "Άνοιγμα συσκευής",
        "clear_alarms": "Εκκαθάριση όλων των συναγερμών",
        "confirm_clear_alarms": "Να καθαρίσουν όλοι οι τρέχοντες συναγερμοί; Ό,τι ακόμα αποτυγχάνει θα ειδοποιήσει μία φορά στον επόμενο έλεγχο.",
        "kiosk_offline": "Εκτός λειτουργίας τώρα", "kiosk_none_down": "Όλα σε λειτουργία",
        "kiosk_events": "Πρόσφατα γεγονότα", "kiosk_theme_light": "Φωτεινό", "kiosk_theme_dark": "Σκούρο",
        "held": "Οι ειδοποιήσεις κρατούνται",
        "brand_title": "Λογότυπο πελάτη",
        "brand_name": "Όνομα πελάτη",
        "brand_subtitle": "Υπότιτλος",
        "brand_upload": "Μεταφόρτωση λογότυπου",
        "brand_remove": "Αφαίρεση λογότυπου",
        "brand_hint": "PNG, JPG, WebP ή SVG, έως 512 KB. Η εικόνα μπαίνει δίπλα στο λογότυπο Wirewave. Το όνομα είναι το Όνομα πελάτη στις Γενικές. Ο υπότιτλος είναι προαιρετικός.",
        "brand_save": "Αποθήκευση",
        "kiosk": "Οθόνη υποδοχής",
        "kiosk_hint": "Σύνδεσμος μόνο για ανάγνωση σε πλήρη οθόνη. Νέο διακριτικό ακυρώνει τον παλιό σύνδεσμο.",
        "camera_health": "Υγεία καμερών",
        "unknown": "άγνωστο",
        "oncall": "Βάρδια",
        "power_cycle": "Επανεκκίνηση ρεύματος",
        "confirm_power": "Να κλείσει και να ανοίξει αυτός ο διακόπτης; Καταγράφεται.",
    },
}


def strings(lang):
    return UI["el"] if lang == "el" else UI["en"]


def category_label(code, lang):
    for cid, en, el, _color in CATEGORIES:
        if cid == code:
            return el if lang == "el" else en
    return code or ""


def category_color(code):
    for cid, _en, _el, color in CATEGORIES:
        if cid == code:
            return color
    return "#64748b"


def guess_category(device_type, name=""):
    """Best-effort category. The saved value can still be edited."""
    dt = (device_type or "generic").lower()
    text = (name or "").lower()
    if dt in ("shelly", "sonoff") or "tasmota" in text or "shelly" in text:
        return "iot"
    if dt == "ups" or "ups" in text:
        return "ups"
    if dt == "printer" or "printer" in text or "pos" in text:
        return "printers"
    if dt == "pbx" or "voip" in text or "phone" in text:
        return "voip"
    if dt in ("unifi", "airmax") or "wifi" in text or "access point" in text or text.startswith("ap"):
        return "wifi"
    if dt == "mikrotik":
        return "switches" if ("switch" in text or "crs" in text) else "routers"
    if dt in ("hikvision", "dahua"):
        return "nvr" if any(word in text for word in ("nvr", "dvr", "recorder", "καταγραφ")) else "cameras"
    if dt == "server" or "nas" in text or "server" in text:
        return "servers"
    if "switch" in text:
        return "switches"
    if dt in ("fortinet", "starlink") or "router" in text:
        return "routers"
    return "other"


def category_counts(hosts):
    """hosts are dicts with category and state. Online is up; offline is down."""
    out = []
    for cid, en, el, color in CATEGORIES:
        rows = [h for h in hosts if (h.get("category") or "other") == cid]
        total = len(rows)
        online = sum(1 for h in rows if h.get("state") == "up")
        offline = sum(1 for h in rows if h.get("state") == "down")
        out.append({"id": cid, "en": en, "el": el, "color": color, "total": total,
                    "online": online, "offline": offline,
                    "pct": (100.0 * online / total) if total else 0})
    return out


def summary_counts(hosts):
    total = len(hosts)
    online = sum(1 for h in hosts if h.get("state") == "up")
    offline = sum(1 for h in hosts if h.get("state") == "down")
    return {"total": total, "online": online, "offline": offline,
            "availability": round(100.0 * online / total, 1) if total else 0}


MAP_LABEL_PX = 14
MAP_NODE_R = 28


def _xml(text):
    return (str(text or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;"))


def map_layout(nodes):
    """Hierarchical tree from parent links. Spacing follows label width so text does not overlap.

    Returns width, height, placed nodes (x, y, label_px) and edges. No external assets.
    """
    by_id = {}
    children = {}
    for node in nodes:
        by_id[node["id"]] = node
    roots = []
    for node in nodes:
        parent = node.get("parent_id")
        if parent in by_id and parent != node["id"]:
            children.setdefault(parent, []).append(node["id"])
        else:
            roots.append(node["id"])
    for key in children:
        children[key].sort(key=lambda nid: (by_id[nid].get("name") or "", nid))
    roots.sort(key=lambda nid: (by_id[nid].get("name") or "", nid))
    gap = 40
    width_of = {}

    def measure(nid, seen):
        if nid in seen:
            width_of[nid] = 160
            return 160
        name = by_id[nid].get("name") or ""
        label_w = max(160, int(8.6 * min(len(name), 28)) + 28)
        kids = [kid for kid in children.get(nid, []) if kid not in seen]
        if not kids:
            width_of[nid] = label_w
            return label_w
        kids_w = sum(measure(kid, seen | {nid}) for kid in kids) + gap * (len(kids) - 1)
        width_of[nid] = max(label_w, kids_w)
        return width_of[nid]

    for root in roots:
        measure(root, set())
    pos = {}

    def place(nid, left, depth, seen):
        span = width_of.get(nid, 160)
        pos[nid] = (left + span / 2.0, depth)
        kids = [kid for kid in children.get(nid, []) if kid not in seen]
        if not kids:
            return
        used = sum(width_of.get(kid, 160) for kid in kids) + gap * (len(kids) - 1)
        cursor = left + max(0, (span - used) / 2.0)
        for kid in kids:
            place(kid, cursor, depth + 1, seen | {nid})
            cursor += width_of.get(kid, 160) + gap

    cursor = 0
    for root in roots:
        place(root, cursor, 0, set())
        cursor += width_of.get(root, 160) + gap
    missing = [node["id"] for node in nodes if node["id"] not in pos]
    for nid in missing:
        measure(nid, set(pos))
        place(nid, cursor, 0, set(pos))
        cursor += width_of.get(nid, 160) + gap
    row_h = 150
    pad = 56
    placed = []
    max_depth = 0
    for node in nodes:
        if node["id"] not in pos:
            continue
        unit_x, depth = pos[node["id"]]
        max_depth = max(max_depth, depth)
        item = dict(node)
        item["x"] = pad + unit_x
        item["y"] = pad + depth * row_h
        item["label_px"] = MAP_LABEL_PX
        placed.append(item)
    total = cursor if nodes else 640
    height = pad + (max_depth + 1) * row_h + 36 if nodes else 180
    edges = []
    ids = {node["id"] for node in placed}
    for node in placed:
        parent = node.get("parent_id")
        if parent in ids:
            edges.append((parent, node["id"]))
    return {"width": max(640, int(pad * 2 + total)), "height": int(height), "nodes": placed, "edges": edges}


def map_svg(nodes, lang="en"):
    """Readable SVG map. Status fills the node. The ring colour is the category."""
    layout = map_layout(nodes)
    colors = {"up": "#16a34a", "down": "#dc2626", "warn": "#d97706"}
    by_id = {node["id"]: node for node in layout["nodes"]}
    lines = []
    for parent, child in layout["edges"]:
        a, b = by_id[parent], by_id[child]
        lines.append(
            f'<line x1="{a["x"]:.0f}" y1="{a["y"]+MAP_NODE_R:.0f}" x2="{b["x"]:.0f}" y2="{b["y"]-MAP_NODE_R:.0f}" '
            f'stroke="#94a3b8" stroke-width="3"/>'
        )
    glyphs = []
    for node in layout["nodes"]:
        color = colors.get(node.get("state"), "#64748b")
        ring = category_color(node.get("category") or "other")
        label = _xml((node.get("name") or "")[:28])
        mark = _xml((node.get("category") or "other")[:1].upper())
        glyphs.append(
            f'<g class="node" data-name="{_xml(node.get("name"))}" data-ip="{_xml(node.get("host"))}" '
            f'data-state="{_xml(node.get("state"))}" data-seen="{_xml(node.get("last_seen"))}" '
            f'data-id="{int(node["id"])}">'
            f'<circle cx="{node["x"]:.0f}" cy="{node["y"]:.0f}" r="{MAP_NODE_R + 6}" fill="none" stroke="{ring}" stroke-width="4"/>'
            f'<circle cx="{node["x"]:.0f}" cy="{node["y"]:.0f}" r="{MAP_NODE_R}" fill="{color}"/>'
            f'<text x="{node["x"]:.0f}" y="{node["y"]+6:.0f}" text-anchor="middle" font-size="18" font-weight="700" fill="#fff">{mark}</text>'
            f'<text x="{node["x"]:.0f}" y="{node["y"]+MAP_NODE_R+22:.0f}" text-anchor="middle" font-size="{MAP_LABEL_PX}" fill="#0f172a">{label}</text>'
            f'</g>'
        )
    title = _xml(strings(lang)["map_title"])
    body = "\n".join(lines + glyphs) or f'<text x="24" y="48" font-size="{MAP_LABEL_PX}">{_xml(strings(lang)["empty"])}</text>'
    return (f'<svg id="netmap" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {layout["width"]} {layout["height"]}" '
            f'role="img" aria-label="{title}">'
            f'<g id="scene">{body}</g></svg>')


def parse_nut(text):
    """NUT LIST VAR / GET VAR text. ups.status OB means on battery. OL means on line."""
    values = {}
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("BEGIN") or line.startswith("END"):
            continue
        if line.startswith("VAR "):
            line = line[4:]
        if ":" not in line and '"' not in line:
            continue
        if '"' in line:
            key, _, rest = line.partition('"')
            key = key.strip().split()[-1]
            values[key] = rest.rsplit('"', 1)[0]
        else:
            key, _, value = line.partition(":")
            values[key.strip().split()[-1]] = value.strip().strip('"')
    status = (values.get("ups.status") or "").upper().split()
    charge = _float(values.get("battery.charge"))
    runtime = _float(values.get("battery.runtime"))
    minutes = runtime / 60.0 if runtime is not None else None
    load = _float(values.get("ups.load"))
    if not values:
        return None
    return {
        "charge_pct": charge,
        "minutes_remaining": minutes,
        "load_pct": load,
        "on_battery": "OB" in status or "LB" in status and "OL" not in status,
        "on_mains": "OL" in status,
        "battery_status": "low" if "LB" in status else ("normal" if charge is not None else "unknown"),
        "source": "nut",
    }


def _float(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def nut_query(host, port, name, timeout=5):
    """Read-only NUT LIST VAR. Returns (text, error). No password is sent."""
    try:
        with socket.create_connection((host, int(port or 3493)), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(f"LIST VAR {name}\n".encode())
            chunks = []
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                chunks.append(data.decode("utf-8", "replace"))
                if "END LIST" in chunks[-1] or "ERR" in chunks[-1]:
                    break
            sock.sendall(b"LOGOUT\n")
        return "".join(chunks), ""
    except (OSError, socket.timeout) as exc:
        return "", str(exc)


def parse_unifi_devices(payload):
    """UniFi stat/device list. Clients and radio only when the controller sent them."""
    data = payload.get("data") if isinstance(payload, dict) else payload
    out = []
    for row in data or []:
        if not isinstance(row, dict):
            continue
        radio = {}
        radios = row.get("radio_table_stats") or row.get("radio_table") or []
        if isinstance(radios, list) and radios and isinstance(radios[0], dict):
            if "channel" in radios[0]:
                radio["channel"] = radios[0].get("channel")
            if "cu_total" in radios[0] or "utilization" in radios[0]:
                radio["utilization"] = radios[0].get("cu_total", radios[0].get("utilization"))
        item = {
            "name": row.get("name") or row.get("mac") or "",
            "mac": row.get("mac") or "",
            "model": row.get("model") or "",
            "state": "up" if row.get("state") == 1 or row.get("adopted") else "down",
        }
        if "num_sta" in row:
            item["clients"] = row.get("num_sta")
        elif "user-num_sta" in row:
            item["clients"] = row.get("user-num_sta")
        item.update(radio)
        out.append(item)
    return out


def parse_omada_devices(payload):
    data = payload.get("result") if isinstance(payload, dict) else payload
    if isinstance(data, dict):
        data = data.get("data") or data.get("devices") or []
    out = []
    for row in data or []:
        if not isinstance(row, dict):
            continue
        item = {
            "name": row.get("name") or row.get("mac") or "",
            "mac": row.get("mac") or "",
            "model": row.get("model") or row.get("showModel") or "",
            "state": "up" if row.get("status") in (1, 14, "1", "connected") or row.get("statusCategory") == 1 else "down",
        }
        if "clientNum" in row:
            item["clients"] = row.get("clientNum")
        elif "clients" in row:
            item["clients"] = row.get("clients")
        if "channel" in row:
            item["channel"] = row.get("channel")
        if "utilization" in row or "txUtil" in row:
            item["utilization"] = row.get("utilization", row.get("txUtil"))
        out.append(item)
    return out


def parse_starlink(payload):
    """Dish status JSON. Missing fields stay absent. Not a guessed zero."""
    dish = payload.get("dishGetStatus") if isinstance(payload, dict) else None
    if not isinstance(dish, dict):
        dish = payload if isinstance(payload, dict) else None
    if not isinstance(dish, dict):
        return None
    known = {"state", "deviceState", "obstructionStats", "downlinkThroughputBps", "uplinkThroughputBps", "alerts"}
    if not known.intersection(dish):
        return None
    obs = dish.get("obstructionStats") if isinstance(dish.get("obstructionStats"), dict) else {}
    alerts = dish.get("alerts") if isinstance(dish.get("alerts"), dict) else {}
    out = {
        "state": dish.get("state") or dish.get("deviceState") or "",
        "online": (dish.get("state") or "").upper() in ("CONNECTED", "ONLINE"),
    }
    if "fractionObstructed" in obs:
        out["obstruction_pct"] = round(100.0 * float(obs["fractionObstructed"]), 2)
    if "downlinkThroughputBps" in dish:
        out["down_mbps"] = round(float(dish["downlinkThroughputBps"]) / 1e6, 2)
    if "uplinkThroughputBps" in dish:
        out["up_mbps"] = round(float(dish["uplinkThroughputBps"]) / 1e6, 2)
    active = [key for key, value in alerts.items() if value]
    if alerts:
        out["alerts"] = active
    pops = dish.get("popPingDropRate")
    if pops is not None:
        out["outage_drop"] = pops
    return out


def sustained_bad(samples, now, window_sec, latency_ms, loss_pct, min_samples=5):
    """samples are (ts, ok, ms). Returns a problem dict or None.

    A host that is simply down is not this alert. This is for a link that still answers.
    """
    window = [row for row in samples if now - row[0] <= window_sec]
    if len(window) < min_samples:
        return None
    if all(not row[1] for row in window):
        return None
    answered = [row[2] for row in window if row[1] and row[2] is not None]
    loss = 100.0 * sum(1 for row in window if not row[1]) / len(window)
    if loss_pct and loss >= loss_pct and any(row[1] for row in window):
        return {"kind": "loss", "value": round(loss, 1)}
    if latency_ms and answered:
        avg = sum(answered) / len(answered)
        if avg >= latency_ms:
            return {"kind": "latency", "value": round(avg, 1)}
    return None


def cert_not_after(host, port=443, timeout=8):
    """Days until the certificate ends, or an error string. No private key is used."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, int(port)), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
        text = cert.get("notAfter")
        if not text:
            return None, "no certificate date"
        ends = datetime.strptime(text, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days = (ends - datetime.now(timezone.utc)).total_seconds() / 86400.0
        return int(days), ""
    except Exception as exc:
        return None, str(exc)[:160]


def rdap_expiry(payload):
    """Days until a domain RDAP expiration event, or None if the document has none."""
    events = payload.get("events") if isinstance(payload, dict) else None
    if not events:
        return None
    for event in events:
        action = (event.get("eventAction") or "").lower()
        if action in ("expiration", "registrar expiration"):
            raw = event.get("eventDate") or ""
            try:
                ends = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            except ValueError:
                return None
            return int((ends - datetime.now(timezone.utc)).total_seconds() / 86400.0)
    return None


def next_threshold(days, thresholds, already):
    """Smallest configured threshold that days has reached and was not alerted yet.

    thresholds like (30, 14, 7, 0). already is the last alerted threshold or None.
    """
    if days is None:
        return None
    ordered = sorted({int(x) for x in thresholds}, reverse=True)
    hit = None
    for mark in ordered:
        if days <= mark:
            hit = mark
    if hit is None:
        return None
    if already is not None and int(already) <= hit:
        return None
    return hit


def parse_command(text):
    parts = (text or "").strip().split()
    if not parts or not parts[0].startswith("/"):
        return None, []
    name = parts[0].split("@", 1)[0].lower()
    return name, parts[1:]


def command_reply(text, chat_id, allowed, snapshot, lang="en"):
    """Reply text, or None when the chat is not authorized or the text is not a command."""
    name, args = parse_command(text)
    if not name:
        return None
    allowed = {str(item).strip() for item in allowed if str(item).strip()}
    if str(chat_id) not in allowed:
        return None
    el = lang == "el"
    if name == "/help":
        return ("Εντολές: /status /site <όνομα> /down /ups /help" if el else
                "Commands: /status /site <name> /down /ups /help")
    if name == "/status":
        s = snapshot or {}
        if el:
            return f"{s.get('site')}: {s.get('online', 0)} σε λειτουργία, {s.get('offline', 0)} εκτός, διαθεσιμότητα {s.get('availability', 0)}%."
        return f"{s.get('site')}: {s.get('online', 0)} online, {s.get('offline', 0)} offline, availability {s.get('availability', 0)}%."
    if name == "/down":
        names = snapshot.get("down_names") or []
        if not names:
            return "Καμία συσκευή εκτός." if el else "No devices are offline."
        title = "Εκτός: " if el else "Offline: "
        return title + ", ".join(names[:40])
    if name == "/site":
        want = " ".join(args).strip().lower()
        if not want:
            return "Γράψτε /site και το όνομα." if el else "Use /site and the site name."
        if want not in (snapshot.get("site") or "").lower():
            return "Δεν είναι αυτή η εγκατάσταση." if el else "That is not this site."
        return command_reply("/status", chat_id, allowed, snapshot, lang)
    if name == "/ups":
        ups = snapshot.get("ups") or []
        if not ups:
            return "Δεν υπάρχει μέτρηση UPS." if el else "No UPS reading."
        lines = []
        for row in ups[:10]:
            lines.append(f"{row.get('name')}: {row.get('charge', '—')}% · {row.get('source', '')}")
        return "\n".join(lines)
    return "Άγνωστη εντολή. /help" if el else "Unknown command. /help"


def _json_call(method, url, payload=None, timeout=8, headers=None):
    data = None if payload is None else json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read(1_000_000).decode("utf-8", "replace")), ""
    except Exception as exc:
        return None, str(exc)[:180]


def _opener_json(opener, method, url, payload=None, timeout=8, headers=None):
    data = None if payload is None else json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, method=method)
    if payload is not None:
        req.add_header("Content-Type", "application/json")
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return json.loads(resp.read(1_000_000).decode("utf-8", "replace")), ""
    except Exception as exc:
        return None, str(exc)[:180]


def fetch_unifi(base, user, password, site="default", timeout=8):
    """Local UniFi controller. The password is sent once and not logged."""
    base = (base or "").rstrip("/")
    if not base:
        return [], ""
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor())
    body, err = _opener_json(opener, "POST", base + "/api/login", {"username": user, "password": password}, timeout)
    if body is None:
        return [], err or "UniFi login failed"
    data, err = _opener_json(opener, "GET", f"{base}/api/s/{site or 'default'}/stat/device", timeout=timeout)
    if data is None:
        return [], err or "UniFi device list failed"
    return parse_unifi_devices(data), ""


def fetch_omada(base, user, password, site="", timeout=8):
    """Local Omada controller login. Password is not logged."""
    base = (base or "").rstrip("/")
    if not base:
        return [], ""
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor())
    token_body, err = _opener_json(opener, "POST", base + "/api/v2/login", {"username": user, "password": password}, timeout)
    if token_body is None:
        return [], err or "Omada login failed"
    token = ""
    result = token_body.get("result") if isinstance(token_body, dict) else None
    if isinstance(result, dict):
        token = result.get("token") or ""
    headers = {"Csrf-Token": token} if token else None
    path = f"{base}/api/v2/sites/{site}/devices" if site else base + "/api/v2/devices"
    data, err = _opener_json(opener, "GET", path, timeout=timeout, headers=headers)
    if data is None:
        return [], err or "Omada device list failed"
    return parse_omada_devices(data), ""


def fetch_starlink(host, timeout=5):
    """Local dish HTTP status. A failure is unavailable, not a fake offline dish."""
    host = (host or "").strip()
    if not host:
        return None, ""
    data, err = _json_call("GET", f"http://{host}/api/v1/status", timeout=timeout)
    if data is None:
        return None, err or "Starlink status unavailable"
    parsed = parse_starlink(data)
    if not parsed:
        return None, "Starlink reply had no dish status"
    return parsed, ""


def speedtest_args(binary):
    """None when the optional CLI is not installed. The installer does not require it."""
    if not binary:
        return None
    return [binary, "--format=json", "--accept-license", "--accept-gdpr"]
