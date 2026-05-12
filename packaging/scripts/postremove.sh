#!/bin/sh
# Post-remove: reload systemd. We deliberately do NOT delete:
#   - the state dir /var/lib/netbrain-beacon (contains enrollment + DEK + S&F buffer)
#   - the system user netbrain-beacon
# so that `apt remove` (without --purge) preserves enrollment for a reinstall.
#
# For full cleanup the operator runs `apt purge netbrain-beacon` (which
# triggers Debian's separate purge hook — not invoked here).
set -e

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
fi
