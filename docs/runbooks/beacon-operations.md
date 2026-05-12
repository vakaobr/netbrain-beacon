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
2. The operator runs:

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

For machine-readable output:

```bash
sudo -u netbrain-beacon netbrain-beacon status --state-dir /var/lib/netbrain-beacon --json | jq .
```

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

## Recover from corrupt bbolt

If the daemon log shows `store was corrupt and renamed aside`:

```bash
ls /var/lib/netbrain-beacon/*.broken.*.bbolt
# Operator copies the broken file off-host for inspection if needed,
# then deletes it. The daemon already created a fresh empty store.
# The `configs` bucket loses its contents — the next config-poll cycle
# repopulates it from the platform side.
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
