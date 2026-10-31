"""SIA DC-09 receiver for Ajax, Trikdis, Hikvision AX and Dahua alarm hubs.

Parsing, CRC and AES use pysiaalarm (the same rules as a normal monitoring receiver).
TRK, the proprietary Trikdis protocol, is not handled.

This is a technical monitor, not a certified alarm receiving centre.
"""
import re
import socket
import threading
import time
from datetime import datetime, timezone

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
# Second letter R is the restore of the matching alarm (BA → BR, FA → FR, TA → TR).
RESTORE = {code[0] + "R" for code in CRITICAL if len(code) == 2}
# Periodic test / supervision. Not an alarm: RP automatic test, RX manual test, TX test.
SUPERVISION = {"RP", "RX", "TX"}


def is_supervision(code, heartbeat=False):
    """NULL heartbeats and periodic test codes are supervision, not events to log."""
    if heartbeat:
        return True
    return (code or "").upper() in SUPERVISION


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


# DC-09's own limit is about ±20 s. Tolerant is the default window.
TS_MODES = ("strict", "tolerant", "local", "off")
STRICT_SECONDS = 20
# A frame this close to the site's UTC offset is a local-time clock, not a wrong UTC clock.
LOCAL_MATCH_SECONDS = 120


def format_delta(seconds):
    """Signed gap between the frame clock and server UTC, for the listen log."""
    if seconds is None:
        return ""
    sign = "+" if seconds >= 0 else "-"
    left = abs(int(seconds))
    hours, rem = divmod(left, 3600)
    minutes, secs = divmod(rem, 60)
    if hours:
        return f"{sign}{hours}h {minutes:02d}m {secs:02d}s"
    if minutes:
        return f"{sign}{minutes}m {secs:02d}s"
    return f"{sign}{secs}s"


def nak_frame(sequence, receiver, line, account, when=None):
    """NAK that carries the receiver's current UTC time so the panel can set its clock.

    DC-09 puts ``_HH:MM:SS,MM-DD-YYYY`` after the empty data block. The time is UTC,
    which is what a panel is supposed to store.
    """
    when = when or datetime.now(timezone.utc)
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    when = when.astimezone(timezone.utc)
    receiver = receiver if receiver and receiver != "None" else "R0"
    line = line if line and line != "None" else "L0"
    sequence = sequence or "0000"
    account = (account or "000").upper()
    stamp = when.strftime("_%H:%M:%S,%m-%d-%Y")
    body = f'"NAK"{sequence}{receiver}{line}#{account}[]{stamp}'
    return build_frame(body).encode("ascii")


def _site_offset(tz, now):
    """Seconds east of UTC for the site timezone at ``now`` (DST included)."""
    try:
        offset = now.astimezone(tz).utcoffset()
    except Exception:
        return 0
    if offset is None:
        return 0
    return int(offset.total_seconds())


def judge_timestamp(stamp, mode, window_s, tz, now=None):
    """Decide whether a panel clock is close enough to accept.

    ``stamp`` is the time the panel wrote, labeled UTC the way the parser reads the
    digits. It is compared with UTC now. pysiaalarm's own window is not consulted.

    ``mode`` is strict (±20 s), tolerant (``window_s``, default 10 minutes), local
    (treat the digits as the site's local time, then apply the tolerant window),
    or off. In strict and tolerant, a gap within two minutes of the site's UTC
    offset is accepted and flagged as local time.
    """
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    now = now.astimezone(timezone.utc)
    server_utc = now.strftime("%H:%M:%S %m-%d-%Y UTC")
    mode = mode if mode in TS_MODES else "tolerant"
    window = max(1, int(window_s or 600))
    if stamp is None:
        return {"accept": True, "reason": "", "flag": "", "delta_s": None,
                "frame_ts": "", "server_utc": server_utc}
    if not isinstance(stamp, datetime):
        return {"accept": True, "reason": "", "flag": "", "delta_s": None,
                "frame_ts": "", "server_utc": server_utc}
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    as_utc = stamp.astimezone(timezone.utc)
    frame_ts = as_utc.strftime("%H:%M:%S %m-%d-%Y")
    delta = int(round((as_utc - now).total_seconds()))
    offset = _site_offset(tz, now)

    def pack(accept, reason, flag=""):
        return {"accept": accept, "reason": reason, "flag": flag, "delta_s": delta,
                "frame_ts": frame_ts, "server_utc": server_utc}

    if mode == "off":
        return pack(True, "")
    if mode == "local":
        corrected = delta - offset
        if abs(corrected) <= window:
            return pack(True, "", "panel sends local time")
        return pack(False, _ts_reason("local", window, frame_ts, server_utc, corrected))
    limit = STRICT_SECONDS if mode == "strict" else window
    if abs(delta) <= limit:
        return pack(True, "")
    # UTC+0 has no separate local clock, so this does not widen a strict check there.
    if abs(offset) >= 60 and abs(delta - offset) <= LOCAL_MATCH_SECONDS:
        return pack(True, "", "panel sends local time")
    return pack(False, _ts_reason(mode, limit, frame_ts, server_utc, delta))


def _ts_reason(mode, limit, frame_ts, server_utc, delta):
    return (f"timestamp out of range ({mode} ±{format_delta(limit).lstrip('+')}, "
            f"frame {frame_ts} as UTC, server {server_utc}, {format_delta(delta)})")


def clock_warning(delta_s):
    """Owner-facing line when the panel clock is off by a minute or more."""
    if delta_s is None:
        return ""
    minutes = int(round(abs(int(delta_s)) / 60.0))
    if minutes < 1:
        return ""
    return f"panel clock is {minutes} min off — set NTP on the panel"


_PEEK_TS = re.compile(r"_(\d{2}:\d{2}:\d{2},\d{2}-\d{2}-\d{4})")
_PEEK_PROTO = re.compile(r'"(NULL|SIA-DCS|ADM-CID)"')
_PEEK_ACCT = re.compile(r"#([A-Fa-f0-9]{3,16})")


def peek_frame(line):
    """Pull protocol, account and clock digits out of a raw frame.

    Used when the library rejects the line before it hands back those fields,
    so the listen log can still show what arrived. The timestamp digits are
    labeled UTC, the same way the parser does, and are not shifted for timezone.
    """
    text = (line or "").strip("\r\n\x00 ")
    proto_m = _PEEK_PROTO.search(text)
    acct_m = _PEEK_ACCT.search(text)
    ts_m = _PEEK_TS.search(text)
    stamp = None
    if ts_m:
        try:
            stamp = datetime.strptime(ts_m.group(1), "%H:%M:%S,%m-%d-%Y").replace(tzinfo=timezone.utc)
        except ValueError:
            stamp = None
    return {
        "protocol": proto_m.group(1) if proto_m else "",
        "account": acct_m.group(1).upper() if acct_m else "",
        "stamp": stamp,
    }


# Consecutive frames within this many seconds share one learned skew.
SKEW_SLACK = 90
SKEW_NEED = 3


def next_skew(prev_s, prev_n, delta):
    """Track a stable panel skew. Returns (skew_seconds, count, learned)."""
    if delta is None:
        return prev_s, int(prev_n or 0), int(prev_n or 0) >= SKEW_NEED and prev_s is not None
    delta = int(delta)
    if prev_s is None or abs(delta - int(prev_s)) > SKEW_SLACK:
        return delta, 1, False
    count = int(prev_n or 0) + 1
    return delta, count, count >= SKEW_NEED


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
    if (code or "").upper() in SUPERVISION:
        return None
    if code in CRITICAL:
        return "alarm"
    if code in ARM:
        return "armed"
    if code in DISARM:
        return "disarmed"
    if code in RESTORE:
        return "restored"
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
    # The clock check lives in judge_timestamp. pysiaalarm's valid_timestamp uses the
    # account timezone for "now" and is not consulted.
    text, zone = _describe(event)
    mtype = event.message_type.value if isinstance(event.message_type, MessageTypes) else str(event.message_type)
    stamp = event.timestamp if isinstance(event.timestamp, datetime) else None
    return {
        "ok": True,
        "account": (event.account or "").upper(),
        "code": event.code,
        "message_type": mtype,
        "protocol": mtype,
        "heartbeat": event.message_type == MessageTypes.NULL,
        "supervision": is_supervision(event.code, event.message_type == MessageTypes.NULL),
        "severity": _severity(event.code, event.message_type),
        "text": text,
        "zone": zone,
        "state": _state_for(event.code, event.message_type),
        "sequence": event.sequence,
        "receiver": event.receiver,
        "line": event.line,
        "stamp": stamp,
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
        opened = []

        def bind_sock(kind):
            last = None
            for attempt in range(20):
                sock = socket.socket(socket.AF_INET, kind)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try:
                    sock.bind((host, port))
                    return sock
                except OSError as e:
                    last = e
                    sock.close()
                    if getattr(e, "errno", None) not in (98, 48) or attempt == 19:
                        raise
                    time.sleep(0.05)
            raise last

        try:
            if tcp:
                sock = bind_sock(socket.SOCK_STREAM)
                sock.listen(16)
                sock.settimeout(1.0)
                self.tcp = sock
                opened.append(sock)
            if udp:
                sock = bind_sock(socket.SOCK_DGRAM)
                sock.settimeout(1.0)
                self.udp = sock
                opened.append(sock)
        except OSError as e:
            for sock in opened:
                try:
                    sock.close()
                except OSError:
                    pass
            self.tcp = self.udp = None
            self.error = str(e)
            self.status_text = f"failed to listen on {host}:{port}: {e}"
            raise
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
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                try:
                    sock.close()
                except OSError:
                    pass
        self.tcp = self.udp = None
        thread = self.thread
        if thread and thread.is_alive() and thread is not threading.current_thread():
            thread.join(timeout=2)
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
