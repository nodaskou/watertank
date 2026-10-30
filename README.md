# Wirewave Network Infrastructure Monitor

## Quick install (Debian)

```bash
sudo apt update && sudo apt install -y git
git clone https://github.com/nodaskou/watertank.git pingmonitor && cd pingmonitor
sudo ./install.sh
systemctl status pingmonitor
sudo timedatectl set-timezone Europe/Athens
```

`sudo ./install.sh` must be run from this clone (it copies `pingmonitor.py`, `requirements.txt`, `pingmonitor.service` and `assets/wirewave_logo.jpg`). It installs `python3`, `python3-venv`, `iputils-ping`, `openssl` and `ca-certificates`, creates the `pingmon` user, and installs a venv under `/opt/pingmonitor`. On a terminal, when no admin password is stored yet, it **prompts for the admin password** (minimum 8 characters, typed twice).

The web page listens on **all interfaces** (`0.0.0.0:8080`) and **starts on boot**. There is no question to answer. At the end the installer prints both addresses, and it checks that `systemctl is-enabled pingmonitor` prints `enabled`:

* LAN: `http://<LAN-IP>:8080` (another PC on the same network)
* this machine: `http://127.0.0.1:8080`
* Cloudflare Tunnel: point the public hostname at `http://localhost:8080`

Both work at the same time. `cloudflared` on this machine connects to localhost. A PC on the LAN opens the LAN address. Login lockout uses the real visitor: through the tunnel that is Cloudflare's `CF-Connecting-IP` header (trusted only from localhost), and from the LAN it is that PC's own address. A fake `CF-Connecting-IP` header sent from the LAN is ignored.

To listen on this machine only, run `PINGMON_HOST=127.0.0.1 sudo ./install.sh`. The choice is saved in `/opt/pingmonitor/data/web-bind` and kept on the next update. Switch back to LAN + tunnel with `PINGMON_HOST=0.0.0.0 sudo ./install.sh`.

The installer sets the OS timezone to `Europe/Athens` (`timedatectl`, or a symlink to `/usr/share/zoneinfo` if that is not available). Override it with `PINGMON_TZ=Europe/Athens sudo ./install.sh`. The app's own timezone setting already defaults to `Europe/Athens`.

The dashboard, each host page and the log refresh themselves every 30 seconds (Settings → General → Dashboard refresh, 10–300). The page is not reloaded, so the graph range stays as you left it, and the refresh pauses while the browser tab is in the background. The corner shows the time of the last update. If the session has expired, the next update sends you to the login page.

The dashboard opens with a status bar: internet latency and packet loss, the site's public IP (and the provider name when a lookup works), and the time of the last check. The bar is green when the internet, every host, the UPS and the alarm panels are quiet. It is red for a down internet, down devices, a UPS on battery or an alarm, and amber for high latency, high loss or maintenance. A change of public IP is logged and sent as an info alert.

Alarms use a failed-ping count (global default 3, overridable per host) and a repeat interval (global default 30 minutes, `0` = do not repeat, also overridable per host). Each host can also use its own ping interval; empty means the global one.

Alarm panels (Ajax, Trikdis, Hikvision AX PRO / AX Hybrid, Dahua AirShield / ARC) can send SIA DC-09 to TCP/UDP port 12128. Open **Settings → Alarms** for the account, the optional AES key, and the click-path on each brand. Trikdis TRK toward Protegus is not accepted. This is technical monitoring, not a certified alarm receiving centre; keep the vendor app as the primary path. NVR and camera events stay on the camera API and the e-mail receiver.

## Update

```bash
cd pingmonitor && git pull && sudo ./install.sh
```

Run that from the parent of the clone (for example `cd ~/pingmonitor` when the clone is in the root home directory). The installer copies the new files over `/opt/pingmonitor`, refreshes the venv, reloads systemd and restarts the service. Settings, hosts and history are kept, and the password prompt is skipped when one is already set.

The first update from an older install, which always listened on `127.0.0.1`, switches the page to `0.0.0.0` so other PCs can open it. After that, a later update keeps the saved address. An update also enables the service for boot if it was not enabled yet.

---

A small, single-file network monitor for hotel and client sites. It runs on a Debian machine. People on the LAN open it directly, and you can also publish it with Cloudflare Tunnel.

* **Ping** every host on a fixed interval, with a latency graph and green/red state. It alerts after N failed pings and again on recovery.
* **Settings page** (admin only). The menu is General, Hosts, Alerts, Internet, Dashboard graphs, MikroTik backups, Telegram, Outgoing e-mail, Incoming e-mail (devices), SNMP + traps, Webhook, API, Alarms, App config backup/restore, Passwords, and Diagnostics. Each item opens its own section. Saving one section leaves the others as they were. MikroTik backups are the weekly router exports. App config backup/restore is the encrypted copy of this installation.
* **Read-only dashboard** (an info screen; nothing can be changed there).
* **Incoming e-mail receiver**: cameras, NVRs and controllers e-mail their alarms to the monitor. It parses them (Hikvision, Dahua, UniFi, UISP, Omada, MikroTik, ...), shows them as events and forwards them.
* **SNMP**: per-host polling of uptime, CPU, RAM, interface traffic and link state, plus brand extras. A **trap receiver** handles linkDown/linkUp/coldStart/warmStart.
* **Grok Bot integration**: a token-protected JSON API (`/api/status`, `/api/events`) and an outgoing **webhook** for every alert.
* Everything is in **one script**, `pingmonitor.py`, with SQLite storage. History is pruned after 30 days. Times use Europe/Athens.

```
├── pingmonitor.py          the whole app (web UI, monitor, mail receiver, SNMP, API)
├── requirements.txt
├── install.sh              Debian installer (venv + systemd, listens on the LAN)
├── pingmonitor.service     systemd unit (starts on boot)
├── assets/wirewave_logo.jpg
├── screenshots/
└── README.md
```

---

## 1. Install on Debian (thin client)

```bash
scp -r wirewave_ping_monitor_v2 user@thinclient:~
ssh user@thinclient
cd wirewave_ping_monitor_v2
sudo ./install.sh
```

The installer does the following:

1. Installs `python3`, `python3-venv` and `iputils-ping`.
2. Creates the system user `pingmon`.
3. Copies the files to `/opt/pingmonitor` and builds a virtualenv.
4. **Asks for the admin password**: it runs the script's own first-run prompt (min. 8 characters, typed twice).
5. Installs and starts the `pingmonitor` systemd service on **0.0.0.0:8080** (every interface) and enables it for the next boot (`systemctl enable --now`). `Restart=always` brings it back if it exits.

Run `install.sh` again to upgrade. Settings, hosts and history are kept. The listen address saved in `/opt/pingmonitor/data/web-bind` is kept too. The first upgrade from a build that was hard-coded to `127.0.0.1` moves the page onto the LAN.

| Task | Command |
|---|---|
| Status / logs | `systemctl status pingmonitor` · `journalctl -u pingmonitor -f` |
| Reset admin password | `sudo -u pingmon /opt/pingmonitor/venv/bin/python /opt/pingmonitor/pingmonitor.py --db /opt/pingmonitor/data/pingmonitor.db --set-password && sudo systemctl restart pingmonitor` |
| Show the API token | `... pingmonitor.py --db /opt/pingmonitor/data/pingmonitor.db --show-token` |
| Health check | `curl http://127.0.0.1:8080/healthz` -> `ok` |
| Open from another PC on the LAN | `http://<LAN-IP>:8080` (printed at the end of `install.sh`) |
| This machine only (no LAN) | `PINGMON_HOST=127.0.0.1 sudo ./install.sh` |
| LAN and Cloudflare Tunnel together | `PINGMON_HOST=0.0.0.0 sudo ./install.sh` (also the default) |
| Confirm it starts on boot | `systemctl is-enabled pingmonitor` -> `enabled` |

**Running it by hand** (any OS) goes through the same password flow:

```bash
python3 -m venv venv && . venv/bin/activate && pip install -r requirements.txt
python pingmonitor.py            # first run asks for the admin password, then http://127.0.0.1:8080
python pingmonitor.py --host 0.0.0.0   # same listen address as the Debian service: LAN and localhost
python pingmonitor.py --help     # --db, --host, --port, --set-password, --show-token ...
```

No secrets are written into the files. Every password and token lives in the SQLite DB (`data/pingmonitor.db`, mode 0750, owner `pingmon`). Passwords are stored as scrypt hashes; tokens are shown masked in the UI.

---

## 2. Settings page (log in as admin -> **Settings**)

| Section | What it does |
|---|---|
| **Hosts** | Name, IP/hostname, group (e.g. Cameras, Wi-Fi, Network), **device type** (sets the brand badge and helps parse e-mails), on/off. The **SNMP** column opens the per-host SNMP page. |
| **General** | Site/client name (it prefixes every alert), timezone, ping interval/timeout, failed pings before an alert, history days, public URL (used for links in alerts), dashboard access (login or public read-only), optional viewer password. |
| **Telegram** | Bot token, chat ID, camera snapshots on/off. Has a **Save + send test** button. |
| **Outgoing e-mail (SMTP)** | Server, port, security (STARTTLS 587 / SSL 465 / none 25), user, password, from, to (comma separated). Has a **Save + send test e-mail** button. |
| **Incoming e-mail receiver** | Lets devices send alarm e-mails to the monitor (see §4). |
| **SNMP polling + traps** | Global SNMP options and the trap receiver (see §5). |
| **Outgoing webhook** | URL plus a secret header for Grok Bot or other automations (see §6). |
| **JSON API token** | Show, copy or regenerate. |
| **Change admin password** | |

The web UI has CSRF protection on every form. Login is locked out after repeated wrong passwords, and the session cookie is HttpOnly.

### Telegram setup

1. In Telegram, open **@BotFather** -> `/newbot` -> copy the token.
2. Open your new bot and press **Start**. For a group, add the bot to the group and send a message there.
3. Open `https://api.telegram.org/bot<TOKEN>/getUpdates` and copy `"chat":{"id": ...}`. Group IDs are negative.
4. Paste both values into Settings -> Telegram, then click **Save + send test**.

### Outgoing e-mail examples

| Provider | Server | Port / security | Note |
|---|---|---|---|
| Gmail / Google Workspace | smtp.gmail.com | 587 STARTTLS | needs an **App password** (2-step verification on) |
| Microsoft 365 | smtp.office365.com | 587 STARTTLS | SMTP AUTH must be enabled for the mailbox |
| Your hosting (cPanel/Plesk) | mail.yourdomain.gr | 465 SSL or 587 | the full e-mail address is the username |

---

## 3. Dashboard (read only)

* Each host shows a green/red/orange card with its brand badge, last ping, 24 h uptime and down-for time, plus a 24 h latency graph with failed pings marked in red.
* When SNMP is on, the card also shows device uptime, CPU, RAM, temperature/voltage, Wi-Fi clients and link badges with live traffic.
* Click a host for its detail page: a large latency graph, the SNMP system table, a CPU/RAM chart, the interface table, traffic graphs per interface, and that host's events.
* **Recent events** lists ping DOWN/UP, device e-mails 📧 and SNMP alerts/traps 📡. Camera snapshot thumbnails appear when an e-mail had one.

---

## 4. Device e-mail receiver (cameras / NVRs / controllers)

Turn it on in **Settings -> Incoming e-mail receiver**.

* Default port is **2525**; security can be none, STARTTLS or SSL. You can require a login (username/password) and limit senders to allowed networks (LAN ranges by default).
* Each device's SMTP settings should be: **server = thin client LAN IP, port 2525**. Use the login if you enabled it. Any "to" address works (e.g. `alerts@monitor.local`).
* Mail is matched to a host by its **source IP**. Brand and fields (camera, device name, event type, time) are extracted.
* Events at or above the **Forward** level go to Telegram/e-mail/webhook, rate-limited per device and event type.
* Old cameras often only speak plain SMTP or TLS 1.0. If one fails with STARTTLS, try security **none** on a LAN-only port.

> Menu names change between firmware versions. The paths below are typical; look for the closest match.

| Brand | Where (typical) | Notes |
|---|---|---|
| **Hikvision** camera/NVR | *Configuration -> Network -> Advanced Settings -> Email* | SMTP server/port, "Authentication" only if enabled here; leave SSL/TLS **off** unless you set STARTTLS. Then tick **Notify Surveillance Center / Send Email** under *Event -> Basic/Smart Event -> Linkage Method*. "Attached image" sends a snapshot. |
| **Dahua** / Imou pro | *Setting -> Network -> Email* (web) or *Main Menu -> Network -> Email* (NVR GUI) | Enable, SMTP server + port, encryption **None** (or TLS if STARTTLS), "Attachment" for snapshots, then enable **Send Email** in *Event -> Alarm / Video Detection / Abnormality*. |
| **MikroTik** | `/tool e-mail set server=<thin-client-ip> port=2525 from=hex@site.local` | Use with Netwatch: `/tool netwatch add host=192.168.88.20 down-script="/tool e-mail send to=a@b subject=\"Netwatch: 192.168.88.20 is DOWN\""`. |
| **UniFi Network** | *Settings -> System -> (Advanced) -> SMTP / Email Services* (UniFi OS: custom SMTP server) | Then enable e-mail notifications for device offline/online under *Notifications*. Cloud-hosted controllers can't reach a LAN IP; use a self-hosted controller or a UDM on site. |
| **UISP / airMAX** | UISP: *Settings -> Notifications / SMTP*; airOS device: *Services -> SMTP Mail Server* | airOS can e-mail on events such as LAN cable unplugged. |
| **TP-Link Omada** | Controller: *Settings -> Services -> SMTP* (older: *Controller Settings -> Mail Server*) | Then *Settings -> Notifications* -> tick e-mail for "device disconnected" and similar. |
| **TP-Link** standalone | *System Tools -> Email / Mail Settings* (varies a lot) | Many cheap models have no SMTP. Use ping + SNMP instead. |

---

## 5. SNMP polling and traps

### 5.1 Polling

1. **Settings -> SNMP polling + traps**: keep "SNMP polling enabled" on and set the **poll interval** (default 300 s; 30–3600), timeout, **high-CPU threshold** (default 90 %), alert on interface down, alert on reboot, and the forward level.
2. **Settings -> Hosts -> SNMP** (per host):
   * Version **2c** with community, **or** **3** with user + auth (SHA/MD5/SHA-256) + priv (AES/DES/AES-256). Set the port (default 161).
   * Click **Save + test now**. It polls immediately and shows the result: system name, CPU, interfaces, or a clear error (timeout, wrong v3 password, ...).
   * Tick which interfaces to **Graph** and which to **Alert** on. The default is the physical interfaces that are up (max 8).

What is read (standard MIBs, works on almost anything):

| Data | MIB / OID |
|---|---|
| Name, description, location, uptime | SNMPv2-MIB `sysName/sysDescr/sysLocation/sysUpTime` |
| Interfaces: name, alias, oper/admin status, speed, in/out bps, errors | IF-MIB `ifTable` + `ifXTable` (64-bit HC counters when present, 32-bit wrap handled) |
| CPU % | HOST-RESOURCES `hrProcessorLoad` (average of all cores); fallback UCD `ssCpuIdle` |
| RAM % / disks | HOST-RESOURCES `hrStorageTable`; fallback UCD `memTotalReal/memAvailReal` |
| **MikroTik** extras | MIKROTIK-MIB board temperature, CPU temperature, voltage (RouterOS 6 OIDs + RouterOS 7 gauge table), wireless/CAPsMAN client count |
| **UniFi** AP extras | UBNT-UniFi-MIB `unifiVapNumStations` (sum = Wi-Fi clients) |
| **airMAX** extras | UBNT-AirMAX-MIB station count |
| **Hikvision / Dahua** | uptime + interfaces via the standard MIBs. Their vendor MIBs (HDD status) differ per model/firmware and are **not decoded**; use the e-mail receiver for HDD errors (it handles "HDD error / HDD full"). |
| **TP-Link / Omada** | standard MIBs only (sys, interfaces; CPU/RAM only if the model exposes HOST-RESOURCES) |

**Alerts** (shown as 📡 events and forwarded at or above the SNMP forward level):

| Type | When | Severity |
|---|---|---|
| `snmp_if_down` / `snmp_if_up` | an "Alert" interface changes oper status | critical / info |
| `snmp_reboot` | sysUpTime went backwards (device rebooted) | warning |
| `snmp_cpu_high` / `snmp_cpu_ok` | CPU ≥ threshold on 2 polls in a row / back below threshold−10 | warning / info |

Data is kept for the same number of days as ping history.

### 5.2 Trap receiver

* **Settings -> SNMP polling + traps -> Trap receiver enabled**. It accepts SNMP **v1 and v2c** traps.
* Default listen port is **udp 1162**. You can use the standard **162**: the systemd unit has `CAP_NET_BIND_SERVICE`. When running by hand, 162 needs root.
* **Accepted communities**: comma list; empty = any. Senders must be in the receiver's **allowed networks** list (shared with the e-mail receiver).
* A trap is mapped to a host by **source IP**. Unknown IPs still create an event, with no host.
* `linkDown`, `linkUp`, `coldStart`, `warmStart` and `authenticationFailure` are decoded, including interface name/index. Other traps are shown with their OID and varbinds.
* Webhook/API type: `snmp_trap`.
* Firewall: if the thin client runs one, allow it: `sudo ufw allow from 192.168.0.0/16 to any port 1162 proto udp`.

### 5.3 Enabling SNMP on the devices

> Use a **read-only** community that is not `public`, or SNMPv3. Allow only the thin client's IP. Menu paths are typical and vary by firmware.

**MikroTik RouterOS** (terminal):
```
/snmp community add name=wwmon addresses=192.168.88.10/32 read-access=yes write-access=no
/snmp set enabled=yes contact="Wirewave" location="Hotel X" trap-community=wwmon trap-version=2 trap-generators=interfaces,start-trap trap-target=192.168.88.10 trap-interfaces=all
# SNMPv3 (RouterOS 7):
/snmp community add name=monitor addresses=192.168.88.10/32 security=private authentication-protocol=SHA1 authentication-password=xxxxxxxx encryption-protocol=AES encryption-password=yyyyyyyy
```
(192.168.88.10 = thin client.) In Winbox the same settings are under *IP -> SNMP*. If you use port 1162, note that RouterOS sends traps to 162 by default. Either set the receiver to 162, or add a dst-nat/redirect on the thin client (`iptables -t nat -A PREROUTING -p udp --dport 162 -j REDIRECT --to-port 1162`).

**UniFi** (Network application): *Settings -> System -> Advanced* (older: *Settings -> Services -> SNMP*). Enable **SNMPv1/v2c** with a community, or SNMPv3 with username/password. It is pushed to adopted APs/switches; poll the device IPs, not the controller. UniFi gateways/UDM have separate SNMP settings in some versions. UniFi devices generally don't send traps, so rely on polling.

**Ubiquiti airMAX (airOS)**: *Services -> SNMP Agent* -> enable, community, contact, location. UISP-managed devices: set it in the device's UISP settings, otherwise UISP can overwrite local changes.

**Hikvision**: *Configuration -> Network -> Advanced Settings -> SNMP*. Enable SNMPv2c (read community) or SNMPv3. Set the **trap address** = thin client IP and trap port = 1162 or 162. Some NVR GUIs: *Menu -> Configuration -> Network -> SNMP*.

**Dahua**: *Setting -> Network -> SNMP* (web), sometimes *Network -> Advanced*. Enable v1/v2c (read community) or v3, and set **Trap address / port** to the thin client.

**TP-Link Omada**: Controller *Settings -> Services -> SNMP* (v2c community / v3), applied to managed switches/EAPs/gateways. Standalone JetStream switch: *Maintenance -> SNMP -> Global Config* (enable), then *SNMP v1/v2c -> Community* (read-only) and *Notification* (trap host = thin client).

**TP-Link** standalone/easy-smart: many models have **no SNMP** (Easy Smart TL-SG1xxE). Smart/JetStream models follow the Omada standalone path above.

Quick test from the thin client (optional): `sudo apt install snmp` then `snmpwalk -v2c -c wwmon 192.168.88.1 1.3.6.1.2.1.1`.

---

## 6. Grok Bot integration (reporting to you)

The dashboard is **info only**. Grok Bot (or any automation) gets data in two ways.

### 6.1 Pull: JSON API (token protected)

Send `Authorization: Bearer <API token>`, or `?token=<API token>` (header preferred). The token is under **Settings -> JSON API token**.

| Endpoint | Returns |
|---|---|
| `GET /api/status` | site, version, `summary` (up/down/warn counts, `all_ok`, `down_hosts`, `snmp_links_down`), every host (state, latency, uptime 24 h, down since, group, device type, `snmp` block) and the latest events |
| `GET /api/events?since_id=<id>&limit=100` | events in ascending id order. Use `next_since_id` from the answer as the cursor for the next call. Also `since=2h` / `since=2026-10-30T22:00:00+02:00`, `source=ping\|mail\|snmp`, `min_severity=info\|warning\|critical`. |
| `GET /healthz` | `ok` (no auth) |

```bash
curl -s -H "Authorization: Bearer $TOKEN" https://nikiana.monitor.wirewave.gr/api/status | jq .summary
```

```json
{"up": 11, "down": 1, "warn": 0, "pending": 0, "disabled": 0, "total": 12, "all_ok": false,
 "down_hosts": ["Hikvision NVR"], "snmp_links_down": ["Core router:ether2"]}
```

`hosts[].snmp` (null if SNMP is off for that host):

```json
{"last_poll": "2026-10-30T22:28:37+02:00", "ok": true, "error": null, "sys_name": "core-rb4011",
 "sys_descr": "RouterOS RB4011iGS+", "uptime_seconds": 259405, "cpu_pct": 12.5, "mem_pct": 39.3,
 "extra": {"temp": 41.5, "voltage": 24.3, "wireless_clients": 11},
 "interfaces": [{"name": "ether1", "alias": "WAN", "oper": "up", "admin": "up", "speed_bps": 1000000000,
                 "in_bps": 40029229, "out_bps": 8005726, "errors": 0, "graphed": true, "alerting": true}]}
```

**Cloudflare Access and the API.** Grok Bot can't do the e-mail PIN, so pick one of these:

* (a) **Service token** (recommended). In *Zero Trust -> Access -> Service Auth -> Service Tokens*, create one. In the application, add a policy with **Action: Service Auth** and **Include -> Service Token**. Grok Bot then sends both `CF-Access-Client-Id` and `CF-Access-Client-Secret` plus the app's `Authorization: Bearer` token.
* (b) A separate Access application for the path `/api/` with a **Bypass** policy. The app's API token still protects it. This is simpler but weaker.

### 6.2 Push: webhook

Configure it in **Settings -> Outgoing webhook**: URL, header name (default `Authorization`) and header value (e.g. `Bearer <secret>`). Each alert is POSTed as JSON with `Content-Type: application/json`, `User-Agent: WirewavePingMonitor/2.1` and `X-PingMonitor-Event: <event>`. Use **Save + send test** to send an `event: "test"`.

`event` is one of `host_down`, `host_recovered`, `device_alert` (e-mail from a device), `snmp_alert` (poll alert), `snmp_trap`, `test`. Every payload has the same keys:

```json
{
  "event": "host_down",
  "event_id": 20,
  "site": "Hotel Nikiana",
  "timestamp": "2026-10-30T22:15:20+02:00",
  "timezone": "Europe/Athens",
  "severity": "critical",
  "host": {"id": 6, "name": "Pool AP", "ip": "192.168.1.40", "group": "Wi-Fi", "device_type": "unifi"},
  "state": "down",
  "down_since": "2026-10-30T22:15:20+02:00",
  "downtime_seconds": 0,
  "downtime": "0m 0s",
  "consecutive_failures": 2,
  "latency_ms": null,
  "alert": null,
  "message": "Pool AP (192.168.1.40) is not responding (2 failed pings in a row). Last seen: 2026-10-30 22:15:00.",
  "dashboard_url": "https://nikiana.monitor.wirewave.gr/host/6"
}
```

For `device_alert`, `snmp_alert` and `snmp_trap`, the ping fields are `null` and `alert` is filled:

```json
"alert": {"type": "snmp_trap", "title": "Interface ether2 down (trap)", "brand": "mikrotik",
          "source_ip": "192.168.88.1", "from": null, "subject": null,
          "fields": {"trap": "linkDown", "snmp_version": "2c", "interface": "ether2"},
          "attachments": 0,
          "varbinds": [{"oid": "1.3.6.1.6.3.1.1.4.1.0", "value": "1.3.6.1.6.3.1.1.5.3"},
                       {"oid": "1.3.6.1.2.1.2.2.1.2.2", "value": "ether2"}]}
```

```json
"alert": {"type": "snmp_cpu_high", "title": "High CPU 98%", "brand": "mikrotik", "source_ip": "192.168.88.1",
          "from": null, "subject": null, "fields": {"cpu": 97.5, "threshold": 90}, "attachments": 0}
```

```json
"alert": {"type": "network_disconnected", "title": "Network disconnected - 1", "brand": "dahua",
          "source_ip": "192.168.1.60", "from": "nvr@hotel.local", "subject": "Network Disconnected",
          "fields": {"camera": "1", "device_name": "XVR5108HS", "event_time": "30/10/2026 22:13:00",
                     "event_type": "Network Disconnected"}, "attachments": 1}
```

The webhook is fire-and-forget: one try with a 15 s timeout, logged on failure. Telegram/e-mail are still sent independently. To catch anything missed, Grok Bot can also poll `/api/events?since_id=` as a catch-up.

---

## 7. Remote access with Cloudflare Tunnel

The app listens on every interface, so a PC on the LAN can open `http://<LAN-IP>:8080` directly. `cloudflared` on the same machine still publishes it: point the tunnel's public hostname at `http://localhost:8080`. That needs no port forwarding and works behind CGNAT or Starlink. Login lockout treats the two paths separately. A tunnel visitor is the address in `CF-Connecting-IP`, and that header is trusted only when the connection comes from localhost (where `cloudflared` runs). A PC on the LAN is limited by its own address, even if it sends a fake `CF-Connecting-IP` header.

```bash
# install (Cloudflare apt repo)
sudo mkdir -p --mode=0755 /usr/share/keyrings
curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg | sudo tee /usr/share/keyrings/cloudflare-main.gpg >/dev/null
echo 'deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main' | sudo tee /etc/apt/sources.list.d/cloudflared.list
sudo apt-get update && sudo apt-get install -y cloudflared
```

The easiest route is the dashboard. Go to **Zero Trust -> Networks -> Tunnels -> Create tunnel (Cloudflared)**, name it e.g. `nikiana-monitor`, run the `sudo cloudflared service install <token>` it shows, then add a **Public hostname**, e.g. `nikiana-monitor.wirewave.gr` -> `HTTP` -> `localhost:8080`.

For a CLI-managed tunnel instead: run `cloudflared tunnel login`, `cloudflared tunnel create nikiana-monitor`, `cloudflared tunnel route dns nikiana-monitor nikiana-monitor.wirewave.gr`, then write `/etc/cloudflared/config.yml` with `ingress: [{hostname: ..., service: http://localhost:8080}, {service: http_status:404}]` and run `sudo cloudflared service install`.

> Free Universal SSL covers one level (`*.wirewave.gr`). Prefer `client-monitor.wirewave.gr` over `client.monitor.wirewave.gr`, unless you have Advanced Certificate Manager.

**Cloudflare Access (e-mail one-time PIN), strongly recommended:**

1. In Zero Trust, go to *Settings -> Authentication* and enable **One-time PIN**.
2. Go to *Access -> Applications -> Add -> Self-hosted*. Set the domain to `nikiana-monitor.wirewave.gr` (or a wildcard for all clients) and a session of e.g. 24 h.
3. Add a policy: **Allow**, Include **Emails** = you and your technicians, or **Emails ending in** `@wirewave.gr`.
4. Add the **Service Auth** policy for Grok Bot (§6.1).

Set **Settings -> General -> Public URL** to the hostname so alerts contain clickable links.

---

## 8. Multiple clients

Use one thin client, one tunnel and one hostname per site, each with its own **Site/client name**. All of them can share the same Telegram bot/chat; every alert starts with the site name:

```
🔴 DOWN [Porto Galini - Nikiana]
NVR Cameras (192.168.1.50) is not responding (3 failed pings in a row). Last seen: 2026-10-30 21:14:02
```

| Client | Site name | Hostname |
|---|---|---|
| Porto Galini | Porto Galini - Nikiana | portogalini-monitor.wirewave.gr |
| Nirikos | Nirikos Hotel | nirikos-monitor.wirewave.gr |

For Grok Bot, use one webhook URL with the `site` field telling the clients apart, or give each site its own API token (each install generates its own).

---

## 9. Windows (brief)

1. Install Python 3.11+ and run `pip install -r requirements.txt`.
2. Run `python pingmonitor.py` (first run asks for the admin password).
3. Set **Settings -> General -> Ping method = system** (uses `ping.exe`, no admin needed).
4. To start it at boot, use NSSM (`nssm install PingMonitor C:\Python3\python.exe "C:\pingmonitor\pingmonitor.py --db C:\pingmonitor\pingmonitor.db"`) or Task Scheduler.
5. Allow the receiver ports (2525 TCP, 1162 UDP) in Windows Firewall if you use them.

---

## 10. Troubleshooting

| Problem | Fix |
|---|---|
| Service won't start, exit code 2 | No admin password yet: run the `--set-password` command from §1 |
| Every host DOWN | `journalctl -u pingmonitor` -> look for the ping method. Set Ping method = system |
| No Telegram | Press **Start** in the bot chat; check the chat ID (groups are negative); look for `telegram alert failed` in the log |
| Camera e-mails not arriving | Device IP in "allowed networks"? Security none vs STARTTLS? Port 2525 open in the thin client firewall? Log: `journalctl -u pingmonitor \| grep -i smtp` |
| SNMP "no SNMP response (timeout)" | SNMP enabled on the device? Right community/port? Is the device's SNMP allowed-address the thin client? `snmpwalk` test |
| SNMP "authentication failed / wrong digest" | SNMPv3 user / auth password / auth protocol mismatch |
| SNMP "privacy/decryption" error | v3 priv password or AES/DES mismatch; check `pip show cryptography` is installed |
| No traps | Trap target IP/port on the device; receiver enabled; community in the accepted list; source in allowed networks; firewall udp 1162/162 |
| CPU/RAM shows "-" | The device doesn't expose HOST-RESOURCES/UCD (common on cheap switches) |
| Page opens on the VM but not from another PC | `systemctl cat pingmonitor` should show `--host 0.0.0.0`. If it shows `127.0.0.1`, run `PINGMON_HOST=0.0.0.0 sudo ./install.sh`. If `ufw` is active: `sudo ufw allow 8080/tcp`. |
| Cloudflare 502 | `curl http://127.0.0.1:8080/healthz`; is the service running? The tunnel target must be `http://localhost:8080`. |
| API 401 behind Cloudflare | Add the Access service-token headers (§6.1) as well as the Bearer token |
| Wrong times | `sudo timedatectl set-timezone Europe/Athens` and check Settings -> General -> Timezone |
