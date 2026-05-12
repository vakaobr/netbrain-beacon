#!/bin/sh
# Post-install: register the systemd unit and inform the operator how to
# enroll + start the daemon. Idempotent — works for both fresh install
# and upgrade-in-place.
set -e

# Reload systemd to pick up the unit file we just installed.
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
fi

# Owner the state dir explicitly (nfpm creates it during unpack, but a
# previous version might have left it root-owned).
if [ -d /var/lib/netbrain-beacon ]; then
    chown netbrain-beacon:netbrain-beacon /var/lib/netbrain-beacon
    chmod 0700 /var/lib/netbrain-beacon
fi

cat <<'EOF'

netbrain-beacon installed.

Next steps:
  1. Obtain an enrollment bundle from the NetBrain admin UI.
  2. Enroll the beacon:
       sudo -u netbrain-beacon \
         netbrain-beacon enroll --bundle-file /path/to/bundle.txt \
         --server-url https://platform.example.com:8443
  3. Start the daemon:
       sudo systemctl enable --now netbrain-beacon
  4. Verify:
       sudo systemctl status netbrain-beacon
       sudo -u netbrain-beacon netbrain-beacon status

Operator runbook: /usr/share/doc/netbrain-beacon/README.md
Source: https://github.com/vakaobr/netbrain-beacon

EOF
