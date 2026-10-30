#!/usr/bin/env bash
# Wirewave Ping Monitor v2 - Debian installer (Debian 11/12/13, amd64 / arm64 / armhf)
# Usage:  sudo ./install.sh          (run again to upgrade - settings and history are kept)
set -euo pipefail

APP_DIR=/opt/pingmonitor
DATA_DIR=$APP_DIR/data
APP_USER=pingmon
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
PY="$APP_DIR/venv/bin/python"
DB="$DATA_DIR/pingmonitor.db"

[[ $EUID -eq 0 ]] || { echo "Run as root: sudo ./install.sh"; exit 1; }

echo "==> Installing system packages"
apt-get update -q
DEBIAN_FRONTEND=noninteractive apt-get install -y -q python3 python3-venv iputils-ping openssl ca-certificates

echo "==> Creating system user '$APP_USER'"
id -u "$APP_USER" >/dev/null 2>&1 || useradd --system --home-dir "$APP_DIR" --shell /usr/sbin/nologin "$APP_USER"

echo "==> Copying files to $APP_DIR"
mkdir -p "$DATA_DIR"
install -m 0644 "$SRC_DIR/pingmonitor.py" "$SRC_DIR/requirements.txt" "$APP_DIR/"

echo "==> Python virtualenv + packages"
[[ -x "$PY" ]] || python3 -m venv "$APP_DIR/venv"
"$APP_DIR/venv/bin/pip" install -q --upgrade pip
"$APP_DIR/venv/bin/pip" install -q -r "$APP_DIR/requirements.txt"

echo "==> Allowing unprivileged ICMP (icmplib)"
echo "net.ipv4.ping_group_range = 0 2147483647" > /etc/sysctl.d/60-pingmonitor.conf
sysctl -q -p /etc/sysctl.d/60-pingmonitor.conf || true

chown -R root:root "$APP_DIR"
chown -R "$APP_USER:$APP_USER" "$DATA_DIR"
chmod 0750 "$DATA_DIR"

echo "==> Admin password"
if runuser -u "$APP_USER" -- "$PY" "$APP_DIR/pingmonitor.py" --db "$DB" --check-setup; then
  echo "    already set (change it in Settings, or: sudo -u $APP_USER $PY $APP_DIR/pingmonitor.py --db $DB --reset-password)"
elif [[ -t 0 ]]; then
  runuser -u "$APP_USER" -- "$PY" "$APP_DIR/pingmonitor.py" --db "$DB" --set-password
else
  echo "!! No terminal - set the password later with:"
  echo "   sudo -u $APP_USER $PY $APP_DIR/pingmonitor.py --db $DB --set-password && sudo systemctl restart pingmonitor"
fi

echo "==> systemd service"
install -m 0644 "$SRC_DIR/pingmonitor.service" /etc/systemd/system/pingmonitor.service
systemctl daemon-reload
systemctl enable pingmonitor.service
systemctl restart pingmonitor.service

LAN_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
echo
echo "Done."
echo "  Status:     systemctl status pingmonitor"
echo "  Logs:       journalctl -u pingmonitor -f"
echo "  Web UI:     http://127.0.0.1:8080  (local only - publish it with Cloudflare Tunnel, see README)"
echo "  On the LAN: ssh -L 8080:127.0.0.1:8080 <user>@${LAN_IP:-thinclient}  then open http://127.0.0.1:8080"
echo "  Device e-mail receiver (when enabled in Settings): ${LAN_IP:-<thin-client-ip>}:2525"
echo "  SNMP traps (when enabled in Settings -> SNMP): udp ${LAN_IP:-<thin-client-ip>}:1162 (or 162 - the service has CAP_NET_BIND_SERVICE)"
echo "  API token:  sudo -u $APP_USER $PY $APP_DIR/pingmonitor.py --db $DB --show-token"
