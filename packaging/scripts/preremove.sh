#!/bin/sh
# Pre-remove: stop the daemon cleanly before files are deleted.
# Idempotent — the unit might already be stopped.
set -e

if command -v systemctl >/dev/null 2>&1; then
    systemctl stop netbrain-beacon.service 2>/dev/null || true
    systemctl disable netbrain-beacon.service 2>/dev/null || true
fi
