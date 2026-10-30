#!/usr/bin/env bash
# Wirewave Network Infrastructure Monitor - Debian installer (Debian 11/12/13, amd64 / arm64 / armhf)
# Usage:  sudo ./install.sh
#         run again to upgrade - settings, history and the chosen listen address are kept
#         PINGMON_HOST=127.0.0.1 sudo ./install.sh   # this machine only (no LAN)
#         PINGMON_HOST=0.0.0.0   sudo ./install.sh   # LAN and localhost (the default)
set -euo pipefail

APP_DIR=/opt/pingmonitor
DATA_DIR=$APP_DIR/data
APP_USER=pingmon
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY="$APP_DIR/venv/bin/python"
DB="$DATA_DIR/pingmonitor.db"
BIND_FILE="$DATA_DIR/web-bind"
UNIT=/etc/systemd/system/pingmonitor.service

# IPv4 only. 0.0.0.0 = every interface (LAN PCs and localhost). 127.0.0.1 = this machine.
apply_timezone() {
  local tz="${1:-Europe/Athens}"
  if [[ ! "$tz" =~ ^[A-Za-z0-9_+-]+(/[A-Za-z0-9_+-]+)*$ ]]; then
    echo "Invalid PINGMON_TZ: $tz" >&2
    return 1
  fi
  if [[ ! -e "/usr/share/zoneinfo/$tz" ]]; then
    echo "Unknown timezone: $tz (install tzdata)" >&2
    return 1
  fi
  if command -v timedatectl >/dev/null 2>&1 && timedatectl set-timezone "$tz"; then
    echo "    $tz via timedatectl"
    return 0
  fi
  ln -sfn "/usr/share/zoneinfo/$tz" /etc/localtime
  printf '%s\n' "$tz" > /etc/timezone || true
  echo "    $tz via /etc/localtime"
}

valid_bind() {
  local h=$1 o
  [[ "$h" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
  for o in "${BASH_REMATCH[@]:1:4}"; do
    if ((10#$o > 255)); then
      return 1
    fi
  done
  return 0
}

# PINGMON_HOST wins. Otherwise keep the address this installer saved last time.
# An older unit that still says 127.0.0.1 is the previous hardcoded default, not a
# saved choice, so the first run of this version moves it to 0.0.0.0.
resolve_bind() {
  local saved=""
  if [[ -n "${PINGMON_HOST:-}" ]]; then
    if ! valid_bind "$PINGMON_HOST"; then
      echo "Invalid PINGMON_HOST: ${PINGMON_HOST}" >&2
      echo "Use 0.0.0.0 (LAN and localhost together) or 127.0.0.1 (this machine only)." >&2
      return 1
    fi
    printf '%s\n' "$PINGMON_HOST"
    return 0
  fi
  if [[ -f "$BIND_FILE" ]]; then
    saved=$(tr -d '[:space:]' < "$BIND_FILE")
    if valid_bind "$saved"; then
      printf '%s\n' "$saved"
      return 0
    fi
    echo "Ignoring invalid saved listen address in $BIND_FILE" >&2
  fi
  printf '%s\n' "0.0.0.0"
}

main() {
  [[ $EUID -eq 0 ]] || { echo "Run as root: sudo ./install.sh"; exit 1; }

  local BIND REASON LAN_IP EN
  mkdir -p "$DATA_DIR"
  if [[ -n "${PINGMON_HOST:-}" ]]; then
    REASON="from PINGMON_HOST"
  elif [[ -f "$BIND_FILE" ]] && valid_bind "$(tr -d '[:space:]' < "$BIND_FILE")"; then
    REASON="kept from the previous install"
  else
    REASON="default: all interfaces, so LAN browsers and a Cloudflare Tunnel both work"
  fi
  BIND="$(resolve_bind)"

  echo "==> Installing system packages"
  apt-get update -q
  DEBIAN_FRONTEND=noninteractive apt-get install -y -q python3 python3-venv iputils-ping openssl ca-certificates tzdata fonts-dejavu-core

  echo "==> Timezone (${PINGMON_TZ:-Europe/Athens})"
  apply_timezone "${PINGMON_TZ:-Europe/Athens}"

  echo "==> Creating system user '$APP_USER'"
  id -u "$APP_USER" >/dev/null 2>&1 || useradd --system --home-dir "$APP_DIR" --shell /usr/sbin/nologin "$APP_USER"

  echo "==> Copying files to $APP_DIR"
  mkdir -p "$DATA_DIR" "$APP_DIR/assets"
  install -m 0644 "$SRC_DIR/pingmonitor.py" "$SRC_DIR/wirelogic.py" "$SRC_DIR/camapi.py" \
    "$SRC_DIR/mtbackup.py" "$SRC_DIR/reportpdf.py" "$SRC_DIR/jobs.py" "$SRC_DIR/siarecv.py" \
    "$SRC_DIR/configbackup.py" \
    "$SRC_DIR/requirements.txt" "$APP_DIR/"
  if [[ -f "$SRC_DIR/assets/wirewave_logo.jpg" ]]; then
    install -m 0644 "$SRC_DIR/assets/wirewave_logo.jpg" "$APP_DIR/assets/wirewave_logo.jpg"
  else
    echo "    (no assets/wirewave_logo.jpg - the app will use its built-in logo)"
  fi

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
  printf '%s\n' "$BIND" > "$BIND_FILE"
  chown "$APP_USER:$APP_USER" "$BIND_FILE"
  chmod 0640 "$BIND_FILE"

  echo "==> Admin password"
  if runuser -u "$APP_USER" -- "$PY" "$APP_DIR/pingmonitor.py" --db "$DB" --check-setup; then
    echo "    already set (change it in Settings, or: sudo -u $APP_USER $PY $APP_DIR/pingmonitor.py --db $DB --reset-password)"
  elif [[ -t 0 ]]; then
    runuser -u "$APP_USER" -- "$PY" "$APP_DIR/pingmonitor.py" --db "$DB" --set-password
  else
    echo "!! No terminal - set the password later with:"
    echo "   sudo -u $APP_USER $PY $APP_DIR/pingmonitor.py --db $DB --set-password && sudo systemctl restart pingmonitor"
  fi

  echo "==> Web UI listen address: $BIND ($REASON)"
  if ! grep -q '__BIND_HOST__' "$SRC_DIR/pingmonitor.service"; then
    echo "pingmonitor.service is missing the __BIND_HOST__ marker" >&2
    exit 1
  fi
  sed "s/__BIND_HOST__/${BIND}/g" "$SRC_DIR/pingmonitor.service" > "$UNIT"
  chmod 0644 "$UNIT"
  if grep -q '__BIND_HOST__' "$UNIT"; then
    echo "Failed to write the listen address into $UNIT" >&2
    exit 1
  fi

  echo "==> systemd service (enable and start on boot)"
  systemctl daemon-reload
  systemctl enable --now pingmonitor.service
  systemctl restart pingmonitor.service

  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
    echo "==> ufw is active - opening monitor ports"
    if [[ "$BIND" != "127.0.0.1" ]]; then
      ufw --force allow 8080/tcp >/dev/null
    fi
    ufw --force allow 2525/tcp >/dev/null
    ufw --force allow 1162/udp >/dev/null
    ufw --force allow 12128/tcp >/dev/null
    ufw --force allow 12128/udp >/dev/null
    echo "    opened 8080/tcp (web, when listening on the LAN), 2525/tcp (device e-mail), 1162/udp (SNMP traps), 12128 tcp/udp (alarm panels)"
  else
    echo "==> Firewall"
    echo "    ufw is not active. If you turn it on later, run:"
    echo "    ufw allow 8080/tcp && ufw allow 2525/tcp && ufw allow 1162/udp && ufw allow 12128/tcp && ufw allow 12128/udp"
  fi

  LAN_IP="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
  EN="$(systemctl is-enabled pingmonitor.service 2>/dev/null || true)"
  echo
  echo "Done."
  if [[ "$BIND" == "127.0.0.1" ]]; then
    echo "  Web UI on this PC:  http://127.0.0.1:8080   (other PCs cannot open it)"
    echo "  Turn LAN access on: PINGMON_HOST=0.0.0.0 $0"
  else
    echo "  Web UI on the LAN:  http://${LAN_IP:-<this-machine-LAN-IP>}:8080"
    echo "  Web UI on this PC:  http://127.0.0.1:8080"
  fi
  echo "  Cloudflare Tunnel:  point the public hostname at http://localhost:8080"
  echo "                      (cloudflared on this machine uses localhost; LAN users use the LAN URL)"
  echo "  Auto-start:         systemctl is-enabled pingmonitor -> ${EN:-unknown}"
  if [[ "$EN" != "enabled" ]]; then
    echo "  !! expected 'enabled'. Run: systemctl enable --now pingmonitor" >&2
    exit 1
  fi
  echo "  Status:             systemctl status pingmonitor"
  echo "  Logs:               journalctl -u pingmonitor -f"
  echo "  This machine only:  PINGMON_HOST=127.0.0.1 $0"
  echo "  Device e-mail (when enabled in Settings): ${LAN_IP:-<thin-client-ip>}:2525"
  echo "  SNMP traps (when enabled in Settings -> SNMP): udp ${LAN_IP:-<thin-client-ip>}:1162 (or 162)"
  echo "  API token:          sudo -u $APP_USER $PY $APP_DIR/pingmonitor.py --db $DB --show-token"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
