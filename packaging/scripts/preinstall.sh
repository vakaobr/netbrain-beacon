#!/bin/sh
# Pre-install: create the netbrain-beacon system user + group if absent.
# Runs BEFORE files are unpacked, so /var/lib/netbrain-beacon (owned by this
# user per nfpm.yaml) can be created with the right ownership.
#
# Idempotent — re-runs (upgrades, reinstalls) are safe.
set -e

if ! getent group netbrain-beacon >/dev/null 2>&1; then
    groupadd --system netbrain-beacon
fi

if ! getent passwd netbrain-beacon >/dev/null 2>&1; then
    useradd \
        --system \
        --gid netbrain-beacon \
        --home-dir /var/lib/netbrain-beacon \
        --no-create-home \
        --shell /usr/sbin/nologin \
        --comment "NetBrain Beacon system user" \
        netbrain-beacon
fi
