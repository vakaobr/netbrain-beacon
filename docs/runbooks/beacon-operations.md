# beacon-operations runbook

Operator-facing reference for installing, enrolling, and running the
netbrain-beacon binary.

## Install

### Linux (tarball + systemd)

```bash
tar xzf netbrain-beacon-linux-amd64.tar.gz
sudo ./install.sh
```

Installs the binary to `/usr/local/bin/netbrain-beacon`, the systemd
unit to `/etc/systemd/system/`, the state dir at `/var/lib/netbrain-beacon`
(0700, owned by the `netbrain-beacon` system user), and the log dir at
`/var/log/netbrain-beacon`.

### Docker

```bash
docker run --rm -v /var/lib/netbrain-beacon:/var/lib/netbrain-beacon \
    netbrain-beacon:latest enroll --bundle '<b64>' --server-url https://platform:8443
docker run -d --restart=always \
    -v /var/lib/netbrain-beacon:/var/lib/netbrain-beacon \
    -p 514:514/udp -p 514:514/tcp \
    netbrain-beacon:latest daemon
```

### Windows (MSI — follow-up)

Pending `add-beacon-windows-installer`. Until then, build via
`make build-windows` and run `netbrain-beacon-windows-amd64.exe daemon`
under a Windows service wrapper (e.g., `nssm` or
`golang.org/x/sys/windows/svc` once Phase 10b lands).

## Enroll

1. The NetBrain platform admin generates an enrollment bundle for the
   tenant and shares the base64 string with the beacon operator
   (out-of-band; the bundle expires in 24 h).
2. The operator runs. **Use `--bundle-file` in production** — passing
   `--bundle <b64>` puts the bootstrap token in `ps`, shell history, and
   audit logs (S-1 / CWE-214). The token is short-lived but defense in
   depth says don't leak it:

   ```bash
   # Production form: read from a 0600 file, then delete the file.
   echo '<base64-bundle>' > /tmp/beacon-bundle.b64
   chmod 0600 /tmp/beacon-bundle.b64
   sudo -u netbrain-beacon netbrain-beacon enroll \
     --bundle-file /tmp/beacon-bundle.b64 \
     --server-url 'https://platform.example.com:8443' \
     --state-dir /var/lib/netbrain-beacon
   shred -u /tmp/beacon-bundle.b64    # or rm; the bundle is now consumed
   ```

   Dev / one-off form (NOT recommended for prod):

   ```bash
   sudo -u netbrain-beacon netbrain-beacon enroll \
     --bundle '<base64-bundle>' \
     --server-url 'https://platform.example.com:8443' \
     --state-dir /var/lib/netbrain-beacon
   ```

3. Success looks like:

   ```
   enrolled: beacon_id=abcdef00-1234-... dek_version=1 expires_at=2026-08-12T...
   state=/var/lib/netbrain-beacon
   ```

4. Verify the state dir:

   ```bash
   sudo ls -la /var/lib/netbrain-beacon
   # Expected:
   #   beacon.crt           0644
   #   beacon.key           0600
   #   dek.bin              0600
   #   platform-ca.pem      0644
   #   platform-pubkey.pem  0644
   #   enrollment-metadata.json
   ```

## Start the service

```bash
sudo systemctl enable --now netbrain-beacon
sudo systemctl status netbrain-beacon
```

## Check status

The `status` subcommand reads on-disk artifacts directly — works even
when the daemon is wedged:

```bash
sudo -u netbrain-beacon netbrain-beacon status --state-dir /var/lib/netbrain-beacon
```

Output shows whether the beacon is enrolled, the beacon UUID, server URL,
DEK version, cert expiry + lifecycle-remaining percentage, store-bucket
records/bytes, and any warnings.

For machine-readable output:

```bash
sudo -u netbrain-beacon netbrain-beacon status --state-dir /var/lib/netbrain-beacon --json | jq .
```

### Check server-side validity

Add `--check-server` to additionally hit `GET /cert-status` over mTLS
and verify the platform's view of this beacon:

```bash
sudo -u netbrain-beacon netbrain-beacon status \
    --state-dir /var/lib/netbrain-beacon --check-server
```

Output adds:

```
Server check (live mTLS round-trip):
  reachable:        yes (HTTP 200)
  expires_at:       2026-08-12T...
  recommended:      none | rotate | reenroll
  revocation:       (empty unless the platform revoked this beacon)
```

Use this when you need to confirm the platform still trusts this
beacon (e.g., after a suspected compromise, or before a maintenance
window). Doesn't require the daemon to be running.

## List collectors

```bash
sudo -u netbrain-beacon netbrain-beacon collectors
```

When the daemon is running, this returns the live registry state. When
the daemon is stopped, it lists the configured collector names with
`Running: false`.

## Tail logs

```bash
sudo netbrain-beacon logs --path /var/log/netbrain-beacon/beacon.log --follow --level ERROR
```

Filters:

- `--grep <substring>` — case-insensitive substring match.
- `--level INFO|WARN|ERROR` — filter on slog level prefix.
- `-n <N>` — only print the last N lines (before following, if --follow).

## Metrics

By default the daemon serves Prometheus metrics on
`http://127.0.0.1:9090/metrics`.

```bash
curl -s http://127.0.0.1:9090/metrics | grep beacon_dek_verify_failed
```

Key alerts (each maps to a platform-side Alertmanager rule):

- `beacon_dek_verify_failed_total` > 0 — **P1 security event** (M-11
  fail-closed). The platform delivered a DEK whose signature didn't
  verify against the pinned pubkey. Investigate MITM or operator-side
  pubkey corruption.
- `beacon_safedial_rejected_total` rising — a device IP in the config
  hit the M-9 allow-list reject path. Most likely a misconfigured
  device IP; in the worst case, an attacker-influenced config trying
  to exfiltrate via cloud-IMDS (169.254.169.254).
- `beacon_cert_expires_in_seconds` < 14 d — cert rotation isn't firing
  (or is failing). Check `beacon_cert_rotation_total{result=...}` for
  the failure mode.
- `beacon_collector_dropped_total` rate increasing — worker pool can't
  keep up; increase queue depth or scale the pool.

## Re-enroll

If the cert is revoked or the operator needs a fresh keypair:

```bash
sudo systemctl stop netbrain-beacon

# Optional: archive the old state dir.
sudo mv /var/lib/netbrain-beacon /var/lib/netbrain-beacon.old.$(date +%s)
sudo install -d -o netbrain-beacon -g netbrain-beacon -m 0700 /var/lib/netbrain-beacon

sudo -u netbrain-beacon netbrain-beacon enroll \
  --bundle '<new-bundle>' --server-url 'https://platform.example.com:8443' \
  --state-dir /var/lib/netbrain-beacon

sudo systemctl start netbrain-beacon
```

## Security model: host trust assumptions

The beacon's threat model assumes the host it runs on is operator-trusted.
Specifically:

- **Buffered telemetry is plaintext at rest in bbolt** (per ADR-002 /
  netbrain ADR-078). Records are only encrypted at SEND time (AES-GCM
  envelope). A local-root attacker on the beacon host can read
  buffered logs/flows/SNMP/configs between collection and egress
  (ST-1 — documented architectural choice, NOT a defect).

- **Private key + DEK live in /var/lib/netbrain-beacon at mode 0600**,
  but root on the host can read them. Cert rotation auto-rotates at
  80% lifetime to bound the impact of an exfiltrated key.

- **Bootstrap token survives in shell history / `ps` if you used
  `--bundle <b64>` instead of `--bundle-file`.** The token is one-time-use
  and 24h-expiry, but defense-in-depth says use `--bundle-file
  /path/to/bundle.b64` (mode 0600) in production.

### Hardening guidance for low-trust hosts

If the beacon runs on a host where you do NOT fully trust root (e.g.,
an MSP shared multi-tenant box, an air-gapped lab passed between teams),
add at least:

1. **Full-disk encryption** on the state-dir filesystem (LUKS, dm-crypt,
   BitLocker). Closes the offline-disk-extraction vector for the bbolt
   file + private key.
2. **Read-only root partition** with `/var/lib/netbrain-beacon` on a
   separate encrypted volume. The systemd unit already pins
   `ProtectSystem=strict` so the beacon process can't write outside
   its allowlist.
3. **SELinux / AppArmor profile** confining the `netbrain-beacon`
   binary to its state-dir + the platform's TCP endpoint. Distro
   packagers should ship a default profile; example skeleton in
   `packaging/selinux/netbrain_beacon.te`.
4. **Audit-log monitoring** for `execve` of `netbrain-beacon enroll`
   with `--bundle ` flag (catches operators bypassing the CLI hygiene
   guidance).

### Metrics endpoint security (M-1)

`--metrics-bind` defaults to `127.0.0.1:9090` (loopback-only).
Exposing `/metrics` and `/healthz` to a LAN requires a TLS+auth
terminator in front (nginx, traefik, oauth2-proxy) — they are
unauthenticated by design. The daemon emits
`metrics.non_loopback_bind` at WARN level when bound to a non-loopback
address. Production deployments that scrape from a Prometheus on a
different host should keep the bind loopback-only and run a TLS-front
sidecar.

## Recover from corrupt bbolt

If the daemon log shows `store was corrupt and renamed aside`:

```bash
ls /var/lib/netbrain-beacon/*.broken.*.bbolt
# Operator copies the broken file off-host for inspection if needed,
# then deletes it. The daemon already created a fresh empty store.
# The `configs` bucket loses its contents — the next config-poll cycle
# repopulates it from the platform side.
```

## Uninstall

### Graceful uninstall (preserve data)

If you might re-install later and want to keep the buffered telemetry
+ enrollment state:

```bash
# 1) Stop + disable the service.
sudo systemctl disable --now netbrain-beacon

# 2) Remove the systemd unit + binary.
sudo rm /etc/systemd/system/netbrain-beacon.service
sudo systemctl daemon-reload
sudo rm /usr/local/bin/netbrain-beacon
```

State stays at `/var/lib/netbrain-beacon` and logs at
`/var/log/netbrain-beacon`. A future `install.sh` + `netbrain-beacon
enroll` will reuse the directories.

### Full uninstall (delete state)

To completely remove the beacon including its enrollment, encrypted
buffer, and the dedicated system user:

```bash
# 1) Stop + disable.
sudo systemctl disable --now netbrain-beacon

# 2) Revoke the beacon on the platform side BEFORE deleting local
# state. The platform admin runs (from the netbrain admin UI or API):
#     POST /api/v1/admin/beacons/{beacon_id}/revoke
# This prevents the cert from being reusable if anyone recovers the
# state dir from disk forensics.
sudo -u netbrain-beacon netbrain-beacon status \
    --state-dir /var/lib/netbrain-beacon --json | jq -r .beacon_id
# Pass that UUID to the platform admin for revocation.

# 3) Remove the systemd unit + binary.
sudo rm /etc/systemd/system/netbrain-beacon.service
sudo systemctl daemon-reload
sudo rm /usr/local/bin/netbrain-beacon

# 4) Delete state + logs.
sudo rm -rf /var/lib/netbrain-beacon
sudo rm -rf /var/log/netbrain-beacon

# 5) Remove the service user.
sudo userdel netbrain-beacon
```

After step 5 the system is fully clean. If `userdel` complains the user
"is currently used by process N", check with `pgrep -u netbrain-beacon`
and ensure the daemon really stopped before retrying.

### Docker uninstall

```bash
docker stop netbrain-beacon
docker rm netbrain-beacon
docker rmi netbrain-beacon:<tag>
# State volume:
docker volume rm netbrain-beacon-state    # or rm -rf the bind-mounted dir
```

### Verify removal

```bash
# Service should be unknown to systemd:
systemctl status netbrain-beacon
#   Unit netbrain-beacon.service could not be found.

# Binary should be gone:
which netbrain-beacon
#   (empty)

# User should be gone:
getent passwd netbrain-beacon
#   (empty)
```

## Phase 7b pentest reference

After enabling `BEACON_MTLS_ENABLED=true` on the platform-side staging
deploy, the security team runs `/security/pentest add-multi-mode-ingestion`
**co-tested with this beacon**. Reference:

- `c:/Users/Anderson Leite/code/netbrain/.claude/planning/add-multi-mode-ingestion/09_DEPLOY_PLAN.md`
- `c:/Users/Anderson Leite/.claude/projects/c--Users-Anderson-Leite-code/memory/pending_beacon_pentest.md`

Specific test targets the beacon must survive without crashing or
data-leakage:

- **H-1 nginx header smuggling** — verify the beacon's `X-Client-Cert-*`
  headers can't be smuggled by an in-path attacker.
- **H-2 cross-beacon IDOR** — beacon-A's cert hitting `/data/{B_id}/...`
  must 403.
- **H-4 token replay** — a failed-enrollment bundle replayed from a
  different IP must 401-USED.
- **M-6 gzip bomb** — every `/data/*` endpoint must reject a 4 KiB
  compressed → 100 MiB plaintext payload.
- **M-9 SSRF probe** — beacon configured with a link-local device IP
  must increment `beacon_safedial_rejected_total` and NOT dial.
