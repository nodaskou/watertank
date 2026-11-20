# Changelog

## 3.2.0

- The dashboard opens with summary cards and coloured category tiles (routers, switches, Wi-Fi, VoIP, cameras, NVR, servers, printers, UPS, smart devices, other). Each tile shows total, online and offline, and opens a filtered list. A sidebar switches between English and Greek. Category is guessed from the device type and can be edited.
- The network map is drawn from the existing upstream links. Nodes are coloured by status. The drawing is local SVG, with no extra script.
- UPS readings from SNMP stay, and an optional NUT address (TCP 3493) can be added. Going to battery, low battery, and recovery each alert once.
- A local UniFi or Omada controller can be polled read-only for AP client counts and, when the controller sends them, channel and utilisation. Passwords are stored and not shown back.
- Ping latency and loss history stay on the graphs. A sustained high latency or loss alerts even when the host is not fully down. A speed test runs only if a speedtest command is already installed.
- An optional Starlink dish address reads the local status page. If that request fails, the dish is unavailable rather than marked healthy.
- A list of hostnames warns once at each configured day before a TLS certificate or an RDAP domain expiry.
- The monthly uptime PDF is one English file and one Greek file. It can be downloaded, and optionally sent on Telegram on a chosen day.
- Telegram commands /status, /site, /down, /ups and /help answer only the saved chat. They stay off until enabled, and they do not run while the bot has a webhook.
- An optional client logo (PNG, JPG, WebP, or a stripped SVG) and a name with a subtitle can sit beside the Wirewave logo. The same name is printed on the English and Greek monthly PDFs. Nothing extra is shown until it is set.
- A revocable read-only display link opens a full-screen board with no settings and no secrets. Regenerating the token disables the old link.
- Camera health lists video loss, tamper, clock drift and recording gaps only when the recorder sent that field.
- MikroTik read-only resource and default-route data can raise one WAN-failover alert and one recovery. A changed export sends one alert with a short diff and passwords masked. SFP RX/TX power uses warning and critical dBm thresholds.
- Optional SIP, AMI, FreePBX or Yeastar readings stay unknown until a reply actually contains trunk or extension status.
- Power-cycle of a Shelly, Sonoff DIY or Tasmota relay is off until enabled on that device, then an admin confirms it and the action is logged with the source address.
- A weekly on-call rota sends Telegram alerts to the technician on duty, and can copy the main chat after a configurable number of minutes.

## 3.1.0

- A host can name an upstream device. The choice cannot loop. When that upstream device is down, its outage is sent once under the usual quiet hours, maintenance and repeat rules, and the children’s outage notifications are held. The children still show down and keep ping history. The card says alerts are held. When the upstream device recovers, a child that is still down and was never notified gets one alert; repeats are not dumped in a burst.
- The monitor warns once when the disk that holds its own data is low (separate from a recorder disk), and once when the daily config copy or a weekly MikroTik export is late. A separate systemd timer notices a stopped or hung monitor process while this PC is still on. It uses the saved Telegram and e-mail settings. A powered-off host cannot report itself; set an external heartbeat URL you already run if you need that. This app does not create that service.
- Camera recording alarms apply only to channels you list, and only during the hours you set, and only when the recorder explicitly says recording is off while the channel is online. A missing recording API stays unknown. Offline, not recording, and disk failure stay separate.
- Shelly Gen1 and Gen2+ local status, Sonoff DIY mode on the documented models, and Tasmota HTTP or MQTT against a broker you already run, are read-only. Relay off is not offline. Sign-in and API errors are not offline. Missing power or temperature is omitted. Multi-channel relays and inputs are shown when the payload includes them.

## 3.0.2

- Settings → Telegram has Detect chat ID. It uses the token typed in the form, or the saved token, and asks Telegram for recent chats (private chats by first name and @username, groups and channels by title, including negative ids). Click a row to fill Chat ID. If a webhook is set, getUpdates is not used until you click Remove webhook. An unknown token shows a plain 401 message, and the token is not written to the log. Send test message saves the chat ID and sends one message. If no chat is found, the page says to send /start and click again, in English and Greek.

## 3.0.1

- A recorder disk whose status is ok, normal, idle or sleeping is not a failure, even when free space is reported as zero. That stops the false “Disk hdda (still)” reminder whose message was “hdda status ok”. A disk that was failed and is healthy again logs one info event, “Disk … recovered”, sends one recovery notice, and then the reminders stop. The next check after this update clears a reminder that was already stuck on a healthy disk. Error, abnormal, unformatted, uninitialized, SMART-failed, and a disk that used to be installed and is now missing, are still alerts. The ping fail-count still does not apply to disks.
- SIA periodic tests (RP, RX, TX) and NULL heartbeats update last seen and last test on the Alarms page and the dashboard tile. They are not written to the log, not alerted, and do not flash the tile, unless Settings → Alarms → Log periodic test reports is on (it defaults to off). If a panel sends nothing for its supervision timeout (default 10 minutes), one warning “panel communication lost” is logged and alerted. The next frame logs one “communication restored”. Quiet hours and maintenance apply as they do for other alerts.
- Alarm events name the panel in the Source column, for example ww (123456), or the panel IP. The siren is only for a real alarm. Info events do not use it.
- The dashboard section is titled Recent events.
- An admin can clear the log from the Log page or from Recent events on the dashboard. The button asks “Clear all log entries and events?” and then leaves one entry, “Log cleared”, with who did it, from which address, and when. Host down, a failed disk, and an active alarm are left as they are.

## 3.0.0

The settings pages, alarm panels, and recorder checks work as one monitor.

- Settings is a menu of separate sections. Saving one section leaves the others alone. MikroTik backups and app config backup/restore are different pages. The menu wraps on a narrow screen.
- SIA DC-09 clock check is ours, in UTC. Tolerant is the default (±10 minutes). A panel that sends local time, or a stable skewed clock, is accepted and labelled. NULL heartbeats are acknowledged whenever the CRC and account are valid.
- Each alarm account is a dashboard tile (brand, state, last event, clock skew). An active alarm flashes red in the tile, the status bar, the browser tab title, and the favicon until the panel restores it or an admin acknowledges it.
- Camera API has Save, Save + Test, and Test, with a brand choice and a 15 second limit. The last result (disks and channels) is kept for the host page and the dashboard. SNMP and MikroTik backup have a Test button.
- A disk that is already failed, unformatted, uninitialized, or missing on the first check raises an alert. A manual Test does not mark that problem as already sent. Critical disk problems repeat on the disk reminder (or the global alarm repeat, otherwise once a day). The ping fail-count does not apply. Critical alerts still go out during quiet hours when that option is on.
- The version is shown in the page footer, Diagnostics, the PDF report, and `pingmonitor.py --version`.

## 2.x

The ping monitor became a site monitor.

- Listens on the LAN and on localhost together, so a Cloudflare Tunnel and a PC on the same network both work. The logo and the product name are Wirewave Network Infrastructure Monitor.
- Hikvision and Dahua recorder checks, per-host alert rules, quiet hours, and maintenance.
- Internet probe, public IP, and the top status bar.
- SNMP health and interface graphs, dashboard interface colours, and history kept as raw samples, then 5-minute and hourly averages.
- PDF reports in English and Greek.
- Weekly MikroTik exports (last 52) and UPS readings.
- Encrypted configuration backup and restore, including a daily local copy and a command-line export.
- The dashboard, host page, and log refresh in place.

## 1.x

A single-process ping monitor for a client site.

- Ping each host, with a dashboard, latency graph, and up or down state.
- Telegram, outgoing e-mail, and an incoming e-mail receiver for camera and NVR alarms.
- SNMP polling and traps.
- A JSON API and an outgoing webhook.
- Admin and optional viewer passwords, SQLite storage, and a Debian installer.
