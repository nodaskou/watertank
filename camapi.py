"""Hikvision ISAPI and Dahua HTTP API checks.

`check_device` talks to a recorder. Tests pass a fake `fetch(path) -> (status, body)`
so no camera is required. Passwords are not logged.
"""
import hashlib
import os
import re
import ssl
import urllib.error
import urllib.request
from xml.etree import ElementTree


def _local(tag):
    return tag.rsplit("}", 1)[-1] if tag else ""


def _xml_text(el, name):
    for child in el.iter():
        if _local(child.tag) == name and child.text and child.text.strip():
            return child.text.strip()
    return ""


def _children(root, name):
    return [el for el in root.iter() if _local(el.tag) == name]


def _num(text):
    try:
        return float(text)
    except (TypeError, ValueError):
        return None


def parse_hik_device(body):
    root = ElementTree.fromstring(body)
    return {
        "name": _xml_text(root, "deviceName"),
        "model": _xml_text(root, "model"),
        "serial": _xml_text(root, "serialNumber"),
        "firmware": _xml_text(root, "firmwareVersion"),
    }


_DISK_BAD = ("unformat", "error", "abnormal", "fail", "offline", "full", "smartfailed", "notexist")


def _disk_problem(status, capacity, free):
    st = (status or "").lower().replace(" ", "")
    if any(word in st for word in _DISK_BAD):
        return True
    if capacity and free is not None and capacity > 0 and free / capacity < 0.05:
        return True
    return False


def parse_hik_storage(body):
    root = ElementTree.fromstring(body)
    disks = []
    for el in _children(root, "hdd"):
        status = _xml_text(el, "status") or "unknown"
        cap = _num(_xml_text(el, "capacity"))
        free = _num(_xml_text(el, "freeSpace"))
        disks.append({
            "name": _xml_text(el, "hddName") or _xml_text(el, "id") or "disk",
            "status": status,
            "capacity_mb": cap,
            "free_mb": free,
            "problem": _disk_problem(status, cap, free),
        })
    return disks


def parse_hik_channels(body):
    root = ElementTree.fromstring(body)
    out = []
    for el in _children(root, "InputProxyChannelStatus"):
        online_txt = _xml_text(el, "online").lower()
        online = online_txt in ("true", "1", "yes")
        if online_txt in ("false", "0", "no"):
            online = False
        ip = ""
        for child in el.iter():
            if _local(child.tag) == "ipAddress" and child.text:
                ip = child.text.strip()
                break
        out.append({
            "id": _xml_text(el, "id") or str(len(out) + 1),
            "name": _xml_text(el, "channelName") or ip or "",
            "online": online if online_txt else None,
            "ip": ip,
        })
    return out


def parse_hik_recording(body):
    """Track list. Returns [] when the body has no tracks (caller treats 404 as unknown)."""
    root = ElementTree.fromstring(body)
    tracks = []
    for el in _children(root, "track"):
        enabled = (_xml_text(el, "enable") or _xml_text(el, "enabled")).lower()
        tracks.append({
            "id": _xml_text(el, "id") or _xml_text(el, "Channel") or str(len(tracks) + 1),
            "recording": enabled in ("true", "1", "yes") if enabled else None,
        })
    return tracks


def parse_dahua_kv(body):
    out = {}
    for line in (body or "").splitlines():
        line = line.strip()
        if "=" not in line or line.startswith("#"):
            continue
        key, value = line.split("=", 1)
        out[key.strip()] = value.strip()
    return out


def parse_dahua_storage(body):
    kv = parse_dahua_kv(body)
    indexes = set()
    for key in kv:
        m = re.match(r"list\.info\[(\d+)\]\.", key)
        if m:
            indexes.add(int(m.group(1)))
    disks = []
    for i in sorted(indexes):
        p = f"list.info[{i}]."
        status = kv.get(p + "State") or kv.get(p + "Status") or ""
        err = (kv.get(p + "IsError") or "").lower()
        cap = _num(kv.get(p + "TotalBytes"))
        used = _num(kv.get(p + "UsedBytes"))
        free = (cap - used) if cap is not None and used is not None else _num(kv.get(p + "FreeBytes"))
        cap_mb = cap / 1048576 if cap and cap > 100000 else cap
        free_mb = free / 1048576 if free and free > 100000 else free
        problem = err in ("true", "1", "yes") or _disk_problem(status, cap_mb, free_mb)
        if status and not problem and status.lower() in ("success", "ok", "normal", "running"):
            problem = False
        disks.append({
            "name": kv.get(p + "Name") or kv.get(p + "Path") or f"disk{i}",
            "status": status or ("error" if problem else "ok"),
            "capacity_mb": None if cap_mb is None else round(cap_mb, 1),
            "free_mb": None if free_mb is None else round(free_mb, 1),
            "problem": problem,
        })
    return disks


def parse_dahua_videoloss(body):
    """eventManager getEventIndexes: channels[0]=1 means channel 1 has video loss."""
    lost = []
    for key, value in parse_dahua_kv(body).items():
        if key.startswith("channels[") and str(value).strip().isdigit():
            lost.append(str(int(value)))
    return lost


def _hik_problems(disks, channels):
    found = []
    for disk in disks:
        if not disk.get("problem"):
            continue
        kind = "cam_disk_full" if "full" in (disk.get("status") or "").lower() or (
            disk.get("capacity_mb") and disk.get("free_mb") is not None and disk["capacity_mb"]
            and disk["free_mb"] / disk["capacity_mb"] < 0.05) else "cam_disk_error"
        found.append((f"disk:{disk['name']}", kind, "critical", f"Disk {disk['name']}",
                      f"{disk['name']} status {disk.get('status')}"))
    for ch in channels:
        if ch.get("online") is False:
            found.append((f"ch:{ch['id']}", "cam_camera_offline", "critical", f"Camera {ch['id']} offline",
                          f"Channel {ch['id']} {ch.get('name') or ''} is offline".strip()))
        if ch.get("recording") is False and ch.get("online") is not False:
            found.append((f"rec:{ch['id']}", "cam_not_recording", "warning", f"Camera {ch['id']} not recording",
                          f"Channel {ch['id']} is not recording"))
    return found


def check_hikvision(fetch):
    """fetch(path) -> (status:int, body:str). Missing optional paths return status 404."""
    info, disks, channels = {}, [], []
    ok_any = False
    errors = []
    for path, parser, target in (
        ("/ISAPI/System/deviceInfo", parse_hik_device, "info"),
        ("/ISAPI/ContentMgmt/Storage", parse_hik_storage, "disks"),
        ("/ISAPI/ContentMgmt/InputProxy/channels/status", parse_hik_channels, "channels"),
    ):
        status, body = fetch(path)
        if status == 200 and body:
            ok_any = True
            try:
                parsed = parser(body)
            except ElementTree.ParseError as e:
                errors.append(f"{path}: {e}")
                continue
            if target == "info":
                info = parsed
            elif target == "disks":
                disks = parsed
            else:
                channels = parsed
        elif status not in (404, 0):
            errors.append(f"{path}: HTTP {status}")
    status, body = fetch("/ISAPI/ContentMgmt/record/tracks")
    if status == 200 and body:
        ok_any = True
        try:
            rec = {t["id"]: t["recording"] for t in parse_hik_recording(body)}
            for ch in channels:
                if ch["id"] in rec:
                    ch["recording"] = rec[ch["id"]]
        except ElementTree.ParseError:
            pass
    return _result("hikvision", ok_any, info, disks, channels, errors)


def check_dahua(fetch):
    info, disks, channels = {}, [], []
    ok_any = False
    errors = []
    status, body = fetch("/cgi-bin/magicBox.cgi?action=getDeviceType")
    if status == 200 and body:
        ok_any = True
        kv = parse_dahua_kv(body)
        info["model"] = kv.get("type") or kv.get("deviceType") or body.strip().splitlines()[0][:80]
    elif status:
        errors.append(f"deviceType: HTTP {status}")
    status, body = fetch("/cgi-bin/magicBox.cgi?action=getSoftwareVersion")
    if status == 200 and body:
        ok_any = True
        kv = parse_dahua_kv(body)
        info["firmware"] = kv.get("version") or body.strip().splitlines()[0][:80]
    status, body = fetch("/cgi-bin/storageDevice.cgi?action=getDeviceAllInfo")
    if status == 200 and body:
        ok_any = True
        disks = parse_dahua_storage(body)
    elif status:
        errors.append(f"storage: HTTP {status}")
    status, body = fetch("/cgi-bin/eventManager.cgi?action=getEventIndexes&code=VideoLoss")
    if status == 200 and body is not None:
        ok_any = True
        lost = set(parse_dahua_videoloss(body))
        ids = lost or set()
        # Also list a channel when the body names it. Offline/loss channels are the alert.
        for cid in sorted(ids, key=lambda x: int(x) if x.isdigit() else 0):
            channels.append({"id": cid, "name": "", "online": False, "recording": None})
    return _result("dahua", ok_any, info, disks, channels, errors)


def _result(brand, ok, info, disks, channels, errors):
    problems = _hik_problems(disks, channels)
    if not ok:
        problems = [("unreachable", "cam_unreachable", "critical", "Recorder unreachable",
                     "; ".join(errors) or "no reply")] + problems
    return {
        "ok": ok, "brand": brand, "device": info, "disks": disks, "channels": channels,
        "error": "" if ok else ("; ".join(errors) or "no reply"),
        "problems": [{"key": k, "kind": kind, "severity": sev, "title": title, "message": msg}
                     for k, kind, sev, title, msg in problems],
    }


def check_device(brand, fetch):
    if brand == "hikvision":
        return check_hikvision(fetch)
    if brand == "dahua":
        return check_dahua(fetch)
    raise ValueError("camera API is only for Hikvision or Dahua")


def _digest_header(method, uri, user, password, challenge):
    def pick(name):
        m = re.search(name + r'\s*=\s*"([^"]*)"', challenge, re.I)
        if m:
            return m.group(1)
        m = re.search(name + r"\s*=\s*([^,\s]+)", challenge, re.I)
        return m.group(1) if m else ""

    realm, nonce, qop, opaque = pick("realm"), pick("nonce"), pick("qop"), pick("opaque")
    qop = qop.split(",")[0].strip() if qop else ""
    nc, cnonce = "00000001", os.urandom(8).hex()
    ha1 = hashlib.md5(f"{user}:{realm}:{password}".encode()).hexdigest()
    ha2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()
    if qop:
        resp = hashlib.md5(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}".encode()).hexdigest()
        extra = f', qop={qop}, nc={nc}, cnonce="{cnonce}"'
    else:
        resp = hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()
        extra = ""
    header = f'Digest username="{user}", realm="{realm}", nonce="{nonce}", uri="{uri}", response="{resp}"{extra}'
    if opaque:
        header += f', opaque="{opaque}"'
    return header


def http_get(url, user, password, timeout=12):
    """GET with digest (then basic) auth. Self-signed HTTPS is accepted. Returns (status, text)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def open_req(headers=None):
        req = urllib.request.Request(url, headers=headers or {}, method="GET")
        kwargs = {"timeout": timeout}
        if url.lower().startswith("https:"):
            kwargs["context"] = ctx
        try:
            with urllib.request.urlopen(req, **kwargs) as res:
                return res.status, res.read(2_000_000).decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, (e.read(200_000).decode("utf-8", "replace") if e.fp else ""), e.headers.get("WWW-Authenticate", "")

    status, body, www = _open(open_req)
    if status != 401:
        return status, body
    if www and "digest" in www.lower():
        uri = urllib.request.urlparse(url)
        path = uri.path or "/"
        if uri.query:
            path += "?" + uri.query
        header = _digest_header("GET", path, user or "", password or "", www)
        status, body, _ = _open(lambda h=None: open_req({"Authorization": header}))
        return status, body
    token = _basic(user, password)
    status, body, _ = _open(lambda h=None: open_req({"Authorization": "Basic " + token}))
    return status, body


def _basic(user, password):
    import base64
    return base64.b64encode(f"{user}:{password}".encode()).decode()


def _open(fn):
    try:
        result = fn()
    except urllib.error.URLError as e:
        return 0, "", ""
    except TimeoutError:
        return 0, "", ""
    except OSError:
        return 0, "", ""
    if len(result) == 2:
        return result[0], result[1], ""
    return result


def fetch_for(base, user, password, timeout=12):
    root = base.rstrip("/")

    def fetch(path):
        status, body = http_get(root + path, user, password, timeout=timeout)
        return status, body

    return fetch
