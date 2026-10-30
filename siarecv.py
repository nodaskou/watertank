"""SIA DC-09 receiver for Ajax, Trikdis, Hikvision AX and Dahua alarm hubs.

Parsing, CRC and AES use pysiaalarm (the same rules as a normal monitoring receiver).
TRK, the proprietary Trikdis protocol, is not handled.

This is a technical monitor, not a certified alarm receiving centre.
"""
import re
import socket
import threading

from pysiaalarm.account import SIAAccount
from pysiaalarm.errors import EventFormatError, NoAccountError
from pysiaalarm.event import SIAEvent
from pysiaalarm.utils import MessageTypes, ResponseType

PANELS = ("ajax", "trikdis", "hik_ax", "dahua_arc", "other")

# Codes that mean a person should be told immediately.
CRITICAL = {"BA", "FA", "PA", "HA", "MA", "QA", "GA", "KA", "WA", "TA", "SA"}
# Arm / disarm style events. The panel state follows these.
ARM = {"CL", "CA", "CG", "NL"}
DISARM = {"OP", "OA", "OG", "OR"}
WARNING = {"AT", "YT", "YC", "YX", "XT", "XQ", "YM"}


def crc16(msg):
    crc = 0
    for letter in msg.encode("ascii", "replace"):
        temp = letter
        for _ in range(8):
            temp ^= crc & 1
            crc >>= 1
            if temp & 1:
                crc ^= 0xA001
            temp >>= 1
    return f"{crc:04X}"


def build_frame(content):
    """Wrap a DC-09 body the way the panels do. CRC covers the body, not the length."""
    header = f"{len(content):04X}"
    return f"\n{crc16(content)}{header}{content}\r"


def _response(kind, sequence, receiver, line, account):
    receiver = receiver if receiver and receiver != "None" else "R0"
    line = line if line and line != "None" else "L0"
    sequence = sequence or "0000"
    account = account or "000"
    body = f'"{kind}"{sequence}{receiver}{line}#{account}[]'
    return build_frame(body).encode("ascii")


def normalize(line):
    """Accept the small differences the four brands send.

    Trikdis and some Hikvision builds omit the L (line) field. The CRC is checked
    on the bytes the panel actually sent, then L0 is inserted so the parser can
    read the account. A leading LF/CR and a trailing NUL are stripped. Proprietary
    TRK framing is left unchanged so it is rejected instead of guessed.
    """
    line = line.strip("\r\n\x00 ")
    if line.upper().startswith("TRK") or line.upper().startswith("\x02TRK"):
        return line
    match = re.match(r"([A-Fa-f0-9]{4})([A-Fa-f0-9]{4})(.*)", line, re.S)
    if not match:
        return line
    crc, length, body = match.group(1).upper(), match.group(2), match.group(3)
    if crc not in (crc16(body), crc16(length + body)):
        return line
    if re.search(r"L[0-9A-Fa-f]{1,6}", body):
        return line
    body = re.sub(r"(#)", r"L0\1", body, count=1)
    return crc16(body) + f"{len(body):04X}" + body


def _severity(code, message_type):
    if message_type == MessageTypes.NULL:
        return "info"
    if code in CRITICAL:
        return "critical"
    if code in WARNING:
        return "warning"
    return "info"


def _state_for(code, message_type):
    if message_type == MessageTypes.NULL:
        return None
    if code in CRITICAL:
        return "alarm"
    if code in ARM:
        return "armed"
    if code in DISARM:
        return "disarmed"
    return None


def _describe(event):
    if event.message_type == MessageTypes.NULL:
        return "Heartbeat (NULL)", ""
    desc = ""
    if event.sia_code is not None:
        desc = event.sia_code.description or event.sia_code.type or ""
    zone = event.ri or ""
    user = event.id or ""
    extra = []
    if zone:
        extra.append(f"zone {zone}")
    if user:
        extra.append(f"user {user}")
    if event.partition:
        extra.append(f"partition {event.partition}")
    text = desc or f"Event {event.code or '?'}"
    if extra:
        text = text + " (" + ", ".join(extra) + ")"
    return text, zone


def parse_line(line, accounts):
    """Parse one frame. Returns a dict the listener can log, plus the reply bytes.

    accounts maps an account id to a pysiaalarm SIAAccount (key set when encrypted).
    """
    raw = normalize(line)
    if raw.upper().startswith("TRK"):
        return {"ok": False, "error": "TRK protocol is not supported", "reply": _response("NAK", "0000", "R0", "L0", "000")}
    try:
        event = SIAEvent.from_line(raw, accounts)
    except EventFormatError:
        return {"ok": False, "error": "not a SIA DC-09 frame", "reply": _response("NAK", "0000", "R0", "L0", "000")}
    except NoAccountError:
        return {"ok": False, "error": "encrypted frame but this account has no key",
                "account": None, "reply": _response("NAK", "0000", "R0", "L0", "000")}
    if not event.valid_message:
        # A few communicators CRC the length field together with the body.
        alt = crc16((event.length or "") + (event.full_message or ""))
        if alt == (event.msg_crc or "").upper():
            event.calc_crc = event.msg_crc
        else:
            return {"ok": False, "error": "bad CRC", "account": event.account,
                    "reply": _response("NAK", event.sequence, event.receiver, event.line, event.account)}
    if event.account and event.sia_account is None:
        return {"ok": False, "error": "unknown account", "account": event.account,
                "reply": _response("NAK", event.sequence, event.receiver, event.line, event.account)}
    if not event.valid_timestamp:
        return {"ok": False, "error": "timestamp out of range", "account": event.account,
                "reply": _response("NAK", event.sequence, event.receiver, event.line, event.account)}
    text, zone = _describe(event)
    mtype = event.message_type.value if isinstance(event.message_type, MessageTypes) else str(event.message_type)
    return {
        "ok": True,
        "account": (event.account or "").upper(),
        "code": event.code,
        "message_type": mtype,
        "heartbeat": event.message_type == MessageTypes.NULL,
        "severity": _severity(event.code, event.message_type),
        "text": text,
        "zone": zone,
        "state": _state_for(event.code, event.message_type),
        "receiver": event.receiver,
        "line": event.line,
        "reply": _response("ACK", event.sequence, event.receiver, event.line, event.account),
    }


class SIAServer:
    """TCP and UDP listener. The handler is called with a parsed event dict."""

    def __init__(self):
        self.thread = None
        self.stop = threading.Event()
        self.tcp = None
        self.udp = None
        self.error = None
        self.status_text = "stopped"

    def status(self):
        return self.status_text

    def start(self, host, port, tcp, udp, on_event):
        self.stop_server()
        self.stop = threading.Event()
        self.error = None
        port = int(port)
        if tcp:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((host, port))
            sock.listen(16)
            sock.settimeout(1.0)
            self.tcp = sock
        if udp:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((host, port))
            sock.settimeout(1.0)
            self.udp = sock
        bits = []
        if tcp:
            bits.append("tcp")
        if udp:
            bits.append("udp")
        self.status_text = f"listening on {host}:{port} ({'+'.join(bits) or 'off'})"
        self.thread = threading.Thread(target=self._loop, args=(on_event,), daemon=True, name="sia")
        self.thread.start()

    def stop_server(self):
        self.stop.set()
        for sock in (self.tcp, self.udp):
            if sock:
                try:
                    sock.close()
                except OSError:
                    pass
        self.tcp = self.udp = None
        self.status_text = "stopped"

    def _loop(self, on_event):
        clients = []
        while not self.stop.is_set():
            if self.tcp:
                try:
                    conn, addr = self.tcp.accept()
                    conn.settimeout(1.0)
                    clients.append((conn, addr, b""))
                except socket.timeout:
                    pass
                except OSError:
                    break
            alive = []
            for conn, addr, buf in clients:
                try:
                    chunk = conn.recv(4096)
                except socket.timeout:
                    alive.append((conn, addr, buf))
                    continue
                except OSError:
                    continue
                if not chunk:
                    try:
                        conn.close()
                    except OSError:
                        pass
                    continue
                buf += chunk
                while b"\r" in buf:
                    frame, buf = buf.split(b"\r", 1)
                    reply = self._take(frame, addr[0], on_event)
                    if reply:
                        try:
                            conn.sendall(reply)
                        except OSError:
                            pass
                alive.append((conn, addr, buf))
            clients = alive
            if self.udp:
                try:
                    data, addr = self.udp.recvfrom(4096)
                except socket.timeout:
                    continue
                except OSError:
                    break
                reply = self._take(data.split(b"\r", 1)[0], addr[0], on_event)
                if reply:
                    try:
                        self.udp.sendto(reply, addr)
                    except OSError:
                        pass

    def _take(self, frame, peer, on_event):
        try:
            text = frame.decode("ascii", "replace")
        except Exception:
            return _response("NAK", "0000", "R0", "L0", "000")
        try:
            result = on_event(text, peer)
        except Exception:
            return _response("NAK", "0000", "R0", "L0", "000")
        if isinstance(result, dict) and result.get("reply"):
            return result["reply"]
        return result
