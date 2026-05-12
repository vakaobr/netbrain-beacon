#!/bin/sh
# install.sh — tarball install script for netbrain-beacon
#
# Usage:  sudo ./install.sh [INSTALL_PREFIX]
# Default INSTALL_PREFIX is /usr/local
#
# Installs:
#   <prefix>/bin/netbrain-beacon         (the binary; expected next to this script)
#   /etc/systemd/system/netbrain-beacon.service
#   /var/lib/netbrain-beacon              (state dir, owned by the netbrain-beacon user)
#   /var/log/netbrain-beacon              (log dir)
#
# Does NOT enable or start the service — operator runs:
#     netbrain-beacon enroll --bundle <b64> --server-url https://platform:8443
#     systemctl enable --now netbrain-beacon

set -eu

PREFIX="${1:-/usr/local}"
SERVICE_USER="netbrain-beacon"

if [ "$(id -u)" -ne 0 ]; then
  echo "install.sh: must run as root (or via sudo)" >&2
  exit 1
fi

# 1) Create system user if missing.
if ! getent passwd "$SERVICE_USER" >/dev/null; then
  useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
  echo "created system user: $SERVICE_USER"
fi

# 2) Install binary.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
install -m 0755 "$SCRIPT_DIR/netbrain-beacon" "$PREFIX/bin/netbrain-beacon"

# 3) State + log dirs.
install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 0700 /var/lib/netbrain-beacon
install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 0750 /var/log/netbrain-beacon

# 4) systemd unit.
install -m 0644 "$SCRIPT_DIR/netbrain-beacon.service" /etc/systemd/system/netbrain-beacon.service
systemctl daemon-reload

cat <<NOTE

netbrain-beacon installed.

Next steps:
  1. Obtain an enrollment bundle from your NetBrain admin UI.
  2. Run as root:
       sudo -u $SERVICE_USER netbrain-beacon enroll \\
         --bundle '<base64-bundle>' \\
         --server-url 'https://platform.example.com:8443' \\
         --state-dir /var/lib/netbrain-beacon
  3. Enable + start the service:
       systemctl enable --now netbrain-beacon
  4. Check status:
       systemctl status netbrain-beacon
       sudo -u $SERVICE_USER netbrain-beacon status --state-dir /var/lib/netbrain-beacon
NOTE
