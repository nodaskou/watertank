# Changelog

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
