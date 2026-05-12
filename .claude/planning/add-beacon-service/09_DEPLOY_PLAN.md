# Deploy Plan — add-beacon-service

**Generated:** 2026-05-12
**Risk:** High
**Strategy:** Customer-installed binary; semver releases + canary tag promotion + interlocked with platform-side feature-flag stages
**Stack:** Go 1.26.3 binary, distroless Docker image, 5 native packages (deb / rpm / Arch PKGBUILD / tarball / Windows MSI — MSI stub today)

---

## 1. Context: this isn't a typical "deploy"

The beacon is **not a hosted service** — it's a binary that customer operators
install on hosts inside their own networks. We don't control rollout the way
a SaaS deploy plan would. We control:

1. **What artifacts ship.** Tagged semver releases + Docker image + native
   packages → operators pull → operators upgrade on their own cadence.
2. **What the platform side accepts.** The companion feature flag
   `BEACON_MTLS_ENABLED` on the netbrain platform gates whether any beacon
   binary can actually talk to prod. Stage interlock is enforced platform-side.
3. **Canary vs stable tags.** Operators who opt into the `canary` tag receive
   pre-release builds; everyone else stays on `stable`. We promote stable
   once a canary cohort burns in.

This plan is therefore **two parallel tracks** that interlock at well-defined
gates:

- **Track A (this repo):** publish artifacts → canary → stable.
- **Track B (netbrain repo):** drive `add-multi-mode-ingestion` Stages 2, 3, 4
  on staging then prod.

The gate between them is the **Phase 7b co-pentest** which must run on staging
once Track B reaches Stage 3 (mTLS port live on staging).

---

## 2. Pre-deployment checklist

### Code quality
- [x] All tests pass: `go test ./...` — 17 packages green (~395 tests + 21 hardening regression + 7 F-fix regression = ~420 tests)
- [x] `go vet ./...` clean
- [x] `golangci-lint v2.12.2` — 0 findings (per Phase 10)
- [x] `govulncheck ./...` — no known vulnerabilities (Phase 7a)
- [x] Cross-compile linux/amd64 + windows/amd64 succeed via `make build-all`
- [x] Distroless Docker image builds + runs `version` cleanly (8.47 MB at last measurement)
- [x] 21 cross-language byte-exactness fixtures pass — wire format byte-equal with platform-side Python

### Review gates
- [x] Code review APPROVED (06_CODE_REVIEW.md — 2026-05-12, 0 critical, 9 important closed as F-1..F-8)
- [x] Static security audit PASSED (07a_SECURITY_AUDIT.md — 2026-05-12, 0 critical / 0 high; SY-1/2/3/S-1/M-1/T-1/ST-1 all hardened in 08_HARDEN_PLAN.md)
- [ ] **Dynamic pentest (7b) deferred** — must run against staging within 7 days of Track B Stage 3 (see §6). Reference: `pending_beacon_pentest.md`.

### Artifacts (build at tag time — see §3.1)
- [ ] `netbrain-beacon-linux-amd64.tar.gz` (tarball + install.sh)
- [ ] `netbrain-beacon-windows-amd64.zip` (binary + README)
- [ ] `netbrain-beacon_<ver>_amd64.deb` (Debian/Ubuntu)
- [ ] `netbrain-beacon-<ver>-1.x86_64.rpm` (Fedora/RHEL)
- [ ] `netbrain-beacon-<ver>-1-x86_64.pkg.tar.zst` (Arch)
- [ ] Windows MSI — SKIPPED for `v1.0` (packaging skeleton only; follow-up issue `add-beacon-windows-installer`)
- [ ] Docker image `velonet/netbrain-beacon:<ver>` + `velonet/netbrain-beacon:canary`
- [ ] SHA256 sums + cosign signatures for every artifact (per release-signing follow-up)

### Configuration / interface
- [x] No environment variables required at install time — every flag is a CLI argument
- [x] Default state directories: `/var/lib/netbrain-beacon` (Linux) / `%PROGRAMDATA%\netbrain-beacon` (Windows)
- [x] systemd unit ships hardened (NoNewPrivileges, ProtectSystem=strict, MemoryDenyWriteExecute, syscall filter)
- [x] Docker image distroless-static-nonroot (UID 65532)
- [x] CLI flags documented in `--help` for every subcommand

### Monitoring / observability
- [x] 18 Prometheus instruments per ADR / 03_PROJECT_SPEC.md §NFR-OBS
- [x] Loopback-only `/metrics` bind by default; M-1 non-loopback WARN active
- [x] Runbook updated: `docs/runbooks/beacon-operations.md`
  - Install, enroll, start, status (incl. `--check-server`), logs, metrics, re-enroll, recover-from-corrupt-bbolt, uninstall (graceful + full), verify-removal, Phase 7b pentest reference, **Security model: host trust assumptions** (ST-1)
- [x] CONTRIBUTING.md documents cross-repo conventions (error codes, ADR pairing, wire-format flags)

### Documentation
- [x] README updated with quick-start, layout, security posture (including hardening pass), observability
- [x] ADRs promoted to `docs/ADR/` 001-006 paired with netbrain canonical 077-082
- [ ] CHANGELOG.md — needs draft entry (see §7)
- [ ] Release notes in GitHub Release body (see §7)

### Stakeholder / coordination
- [ ] Platform team confirmed staging schedule for Track B Stage 2 + 3
- [ ] Customer ops contacts identified for canary cohort (~3 internal NetBrain sites; pilot customers selected pre-Stage 3-prod)
- [ ] Phase 7b pentest engagement booked (security team window)

---

## 3. Rollout strategy

### 3.1 Tag scheme + promotion ladder

Three Docker tags + matching GitHub Releases:

| Tag | What it points at | Who pulls it |
|---|---|---|
| `v0.1.x-rc.N` (preview) | Pre-release; CI auto-publishes on every `main` push that passes all gates | NetBrain-internal dogfood hosts |
| `canary` | Latest `v0.1.x-rc.N` after manual promotion + Stage 1 burn-in | Operators who explicitly opt in |
| `stable` | Latest `canary` after Stage 2 burn-in + 7b PASS | Default for new installs + `apt upgrade` |

Semver: `MAJOR.MINOR.PATCH`. Wire-format breaking changes bump MAJOR per
CONTRIBUTING.md. The platform side reads the beacon's `User-Agent`
(`netbrain-beacon/<version>`) so operators on stale versions are visible
platform-side via the `beacon_build_info` self-reported metric.

### 3.2 Track A — beacon binary release stages

Each stage is independently reversible: revert to the prior tag, operators
re-pull, beacons resume working with the older binary (state-dir is
forward-compatible — bbolt schema version 1, will be migrated when bumped).

#### Stage 0 — Build artifacts + dogfood

**What changes:** Tag `v0.1.0-rc.1` cut from current `main`. CI builds all
6 artifacts. Tag pushed to internal Docker registry as `:dev` (not `canary`
yet).

**Steps:**
```bash
git tag -a v0.1.0-rc.1 -m "rc.1 — initial release candidate"
git push --tags
# CI runs .github/workflows/release.yml:
#   - make build-all  → linux + windows binaries
#   - make pkg-deb pkg-rpm pkg-arch pkg-tarball
#   - make docker-build + push to velonet/netbrain-beacon:v0.1.0-rc.1
# Manual: install on 2-3 NetBrain-internal hosts via tarball
sudo install -m 0755 netbrain-beacon /usr/local/bin/netbrain-beacon
sudo netbrain-beacon enroll --bundle-file /tmp/bundle.b64 --server-url https://staging.netbrain.example:8443
sudo systemctl enable --now netbrain-beacon
```

**Success criteria:**
- 3 internal hosts enroll successfully against **staging** (Track B Stage 2 must already be live)
- `beacon_enrollment_total{result="success"}` = 3 within 5 min of install
- `beacon_heartbeat_total{result="success"}` rate ≥ 1/min/host sustained
- No `beacon_dek_verify_failed_total` increments (M-11 fail-closed)
- No `beacon_safedial_rejected_total` increments unexpectedly (M-9)
- syslog ingest works against a test device (verify via `beacon_collector_persisted_total{collector="syslog"}` ≥ 1)

**Monitor for:** 72 hours minimum, ideally 7 days. Watch:
| Metric | Threshold |
|---|---|
| `beacon_dek_verify_failed_total` | any increment → P1 |
| `beacon_safedial_rejected_total` | any unexpected increment → investigate config drift |
| `beacon_heartbeat_total{result!="success"}` rate | > 1/min sustained → connectivity issue |
| `beacon_cert_expires_in_seconds` | < 14 d → rotation scheduler dead |
| `beacon_store_evictions_total` | any rate → backlog (sender unable to drain) |
| `beacon_collector_dropped_total` rate | > 0 sustained → worker pool overwhelmed |

**Rollback:** delete the tag + redeploy prior version via `dpkg -i older.deb`.
Beacons resume working immediately.

#### Stage 1 — Canary tag promotion

**Prerequisites:**
- Stage 0 burn-in clean for 72 h+
- **Track B Stage 2 live on prod** (platform-side beacon API exposed but mTLS port still closed)

**What changes:** Tag `v0.1.0` cut and promoted. Docker `canary` tag points
at `v0.1.0`. GitHub Release published. No customer messaging yet — opt-in only.

**Steps:**
```bash
git tag -a v0.1.0 -m "v0.1.0 — first stable release"
git push --tags
# CI re-builds + publishes to GitHub Releases.
# Manual: tag the canary docker image
docker pull velonet/netbrain-beacon:v0.1.0
docker tag velonet/netbrain-beacon:v0.1.0 velonet/netbrain-beacon:canary
docker push velonet/netbrain-beacon:canary
```

**Cohort:** ~3 NetBrain-internal sites that opt into canary. Customers
who track the `canary` tag receive it; everyone else stays on `:dev` or
their pinned version.

**Success criteria:** same as Stage 0 plus
- No customer-reported issues against the canary tag in the operator channel
- Aggregate `beacon_build_info` shows ≥ 3 distinct hosts on `v0.1.0`

**Monitor for:** 7 days minimum.

**Rollback:** retag `canary` back to the previous version (`v0.1.0-rc.N`).
Operators pulling `canary` get the prior build on next pull cycle.

#### Stage 2 — Phase 7b pentest gate

**Prerequisites:**
- Stage 1 canary burn-in clean for 7 d+
- **Track B Stage 3 live on staging** (mTLS port 8443 listening on staging, NOT prod)

**What changes:** Run `/security/pentest add-beacon-service` co-tested with
`add-multi-mode-ingestion`. The pentest covers:
- H-1 nginx REPLACE-semantics confirmation (header smuggling defeated)
- H-2 cross-beacon IDOR (beacon-A cert hitting `/data/{B_id}/...` → 403)
- H-4 token replay across IPs after failed enrollment → 401-USED
- M-6 gzip-bomb at every `/data/*` endpoint → 413
- M-9 SSRF probe to forbidden IPs (link-local IMDS) — beacon must increment
  `beacon_safedial_rejected_total` and NOT dial
- **New for 7b:** SY-1 / SY-2 hardening regression (send a 1 MB no-newline
  TCP stream + open 1000 concurrent syslog connections → assert counters
  fire and beacon stays healthy)

**Pass criteria:**
- 0 confirmed exploits at Critical / High severity
- All P0/P1 findings from 7a (already 0) remain closed
- New regressions filed as F-Nx and remediated before Stage 3

**Failure:** halt promotion to stable; iterate via `/security/harden` until
re-pentest passes.

#### Stage 3 — Promote to stable

**Prerequisites:**
- Stage 2 pentest PASS
- **Track B Stage 3 live on prod** (mTLS port live on prod)

**What changes:** Docker `stable` tag promoted to `v0.1.0`. `install.sh`
already pulls from the stable tag — new customer installs land on
`v0.1.0`. Existing canary customers can flip to `stable` at their leisure.

**Steps:**
```bash
docker pull velonet/netbrain-beacon:v0.1.0
docker tag velonet/netbrain-beacon:v0.1.0 velonet/netbrain-beacon:stable
docker push velonet/netbrain-beacon:stable
# Announce in customer ops channel + release notes
```

**Success criteria:**
- New customer enrolling via tarball install → `beacon_enrollment_total{result="success"}`
- `apt update && apt upgrade netbrain-beacon` on existing customer hosts
  pulls `v0.1.0` cleanly
- No `beacon_dek_verify_failed_total` increments across the fleet over 24 h
- Aggregate `beacon_heartbeat_total{result="success"}` rate matches baseline

**Monitor for:** 30 days. Beacon installations are long-lived; the failure
modes that escape Stage 0–2 are typically "fleet-wide rotation issue at
30-day cert mark" or "config-poll mismatch surfaces when first customer
config arrives."

#### Stage 4 — Per-tenant production rollout

This stage is **driven by Track B**, not Track A. Track B Stage 4 enables
`beacon_mode_enabled=true` per-tenant. The beacon binary doesn't change;
the tenant-level admin issues a bundle, the operator runs `enroll`.

The beacon side's only obligation at this stage: be on `v0.1.0+` and
have passed Stage 0–3 above. No new artifact ships.

---

### 3.3 Stage timing summary

```
              Beacon repo (Track A)         Platform repo (Track B)
              ────────────────────────      ────────────────────────
Day 0         Stage 0 — rc.1 dogfood
              against staging               Stage 2 — prod API live (flag on)
              (3 internal hosts, 72h)
Day 3         Stage 1 — v0.1.0 canary
              published                     (still Stage 2)
Day 10        (canary burn-in)              Stage 3 — staging mTLS port live
Day 10–17     Stage 2 — 7b pentest
              against staging
Day 17        Stage 3 — stable promoted     Stage 3 — prod mTLS port live
Day 17+       (stable in distribution)      Stage 4 — per-tenant enablement
```

This is the **earliest** schedule; gates slip if any stage burn-in surfaces
issues. The 7-day Phase 7b deadline from `pending_beacon_pentest.md` is
counted from Track B Stage 3 (staging mTLS port live), NOT from Track A
Stage 0.

---

## 4. Database migration plan

**Not applicable to the beacon binary side.** The beacon's own state is:

- `bbolt` file in state-dir — schema version 1, no migration tooling yet.
  ADR-002 reserves `meta:schema_version` for future use. The bbolt file is
  corruption-resilient (rename-aside + create fresh on bbolt.Open error)
  so a future binary that bumps schema can either:
  1. Read schema_version meta; if older, run an in-place migration; OR
  2. If schema reader fails, rename-aside the bbolt and start fresh
     (configs bucket loses cached data; next config-poll repopulates it).
- Enrollment artifacts (`beacon.crt`, `beacon.key`, `dek.bin`,
  `platform-ca.pem`, `platform-pubkey.pem`, `enrollment-metadata.json`) —
  no schema, just files. Forward-compatible.

The platform-side migration (`alembic upgrade 024`) shipped with
`add-multi-mode-ingestion`. The beacon doesn't touch the platform DB.

---

## 5. Rollback playbook

### 5.1 Per-host rollback

Used when **one customer's beacon** misbehaves after upgrade.

**Triggers:**
- `beacon_heartbeat_total{result="success"}` rate from that beacon's
  `build_info` drops to 0 for ≥ 5 min after upgrade
- Customer reports collectors not running
- `beacon_collector_dropped_total` rate exceeds 100/sec sustained from
  a single beacon
- Disk-fill alarm on the customer host (`beacon_store_bytes_total >
  4.5 GiB` approaching 5 GiB cap)

**Steps:**
```bash
# 1. Stop the service
sudo systemctl stop netbrain-beacon

# 2. Reinstall the previous version. For apt:
sudo apt install --reinstall netbrain-beacon=<previous-version>
# Or for tarball install:
sudo install -m 0755 /path/to/older-netbrain-beacon /usr/local/bin/netbrain-beacon

# 3. State directory stays intact — bbolt schema is unchanged.
sudo systemctl start netbrain-beacon

# 4. Verify
sudo -u netbrain-beacon netbrain-beacon status --state-dir /var/lib/netbrain-beacon
sudo -u netbrain-beacon netbrain-beacon status --check-server  # confirms platform-side trust
```

**Verification:**
- `beacon_heartbeat_total{result="success",build_info_version="<previous>"}` rate ≥ 1/min within 2 min
- `beacon_store_bytes_total` plateaus (sender is draining again)
- No `beacon_dek_verify_failed_total` from this beacon ID

### 5.2 Fleet-wide rollback (yank the bad release)

Used when **a published release is fundamentally broken** and we want
to prevent further operators from pulling it.

**Triggers:**
- Cross-customer signal: `beacon_dek_verify_failed_total` increments
  across multiple `beacon_id` labels within 1 h of canary promotion
- Aggregate `beacon_enrollment_total{result!="success"}` rate spikes
  after canary publication
- A confirmed wire-format incompatibility surfaces in pentest

**Steps:**
1. **Retag canary/stable back to the prior version.**
   ```bash
   docker pull velonet/netbrain-beacon:v0.0.9
   docker tag velonet/netbrain-beacon:v0.0.9 velonet/netbrain-beacon:canary
   docker push velonet/netbrain-beacon:canary
   # Repeat for :stable if Stage 3 promotion already happened
   ```
2. **Mark the bad GitHub Release as pre-release** (or delete it if
   nothing depends on the SHA). Update release notes with a "DO NOT USE"
   banner pointing at the known-good prior version.
3. **For deb/rpm/Arch:** issue a hotfix `v0.1.1` whose contents are the
   prior known-good binary, version-bumped. Operators on `apt
   unattended-upgrades` pick it up; we cannot remove an already-shipped
   `.deb` from their disk.
4. **Notify the customer ops channel** with:
   - Affected versions
   - Failure mode
   - Per-host rollback instructions (§5.1)
   - ETA for fixed release

**Verification:**
- New `apt-cache policy netbrain-beacon` on a test host shows the
  hotfix version
- Docker pull of `:canary` / `:stable` returns the rolled-back image
- `beacon_build_info` aggregate slowly skews back toward the good
  version as operators upgrade

### 5.3 Platform-side rollback

If the failure is in the **platform** side (not the beacon binary), the
beacon's store-and-forward buffer protects against data loss:

- Track B disables `BEACON_MTLS_ENABLED` → port 8443 closes → beacons
  fail to send and queue locally
- 5 GB / 14-day cap per ADR-071: beacons can ride out a 14-day platform
  outage with no data loss if average ingest is < 360 MB/day
- When platform comes back up, beacons drain their backlog automatically

The beacon side requires no rollback action — the binary is already
operating correctly.

### 5.4 Communication template

```
Subject: netbrain-beacon v<bad> rolled back

What: Pulled v<bad> from canary/stable. Operators currently on v<bad>
should downgrade to v<good>.

Why: <one-sentence failure mode + affected component>

Action required:
- Customers on `canary` or `stable` Docker tag: next pull picks up v<good>
- Customers with apt/yum auto-upgrade: hotfix v<good>+1 lands within 4 h
- Manual installs: rollback per docs/runbooks/beacon-operations.md §5.1

Status page: <link>
Fixed version ETA: <date+time>
Workflow: post-mortem at <link> once root cause is known
```

---

## 6. Post-deployment verification

### Smoke tests (run immediately after each stage promotion)

```bash
# 1. CLI works
netbrain-beacon version | grep -q v0.1.0

# 2. Status against existing enrollment
sudo -u netbrain-beacon netbrain-beacon status \
    --state-dir /var/lib/netbrain-beacon --json | jq .enrolled
# Expect: true

# 3. Live platform check
sudo -u netbrain-beacon netbrain-beacon status \
    --state-dir /var/lib/netbrain-beacon --check-server --json | jq .server_check
# Expect: reachable=true, http_status=200, recommended_action=none

# 4. Collector list
sudo -u netbrain-beacon netbrain-beacon collectors --json | jq '.collectors | length'
# Expect: ≥ 1 (depends on config)

# 5. Daemon up
systemctl is-active netbrain-beacon  # active
journalctl -u netbrain-beacon --since "5 min ago" | grep -q ERROR
# expected exit code 1 (no ERROR lines)

# 6. Metrics endpoint
curl -s http://127.0.0.1:9090/healthz  # expect "ok"
curl -s http://127.0.0.1:9090/metrics | grep -q beacon_build_info
```

### 24-hour watch list (per host post-Stage-1 promotion)

Critical:
- `beacon_dek_verify_failed_total > 0` → P1 page
- `beacon_safedial_rejected_total` unexpected increment → investigate config
- `beacon_heartbeat_total{result!="success"}` rate > 5/min over 10 min → connectivity issue

Warning:
- `beacon_cert_expires_in_seconds < 14 * 86400` → rotation scheduler dead
- `beacon_store_evictions_total` rate > 0 sustained → sender unable to drain
- `beacon_collector_dropped_total` rate > 0 sustained → worker pool overwhelmed
- `metrics.non_loopback_bind` log line → operator exposed metrics; verify deliberate

Info:
- `beacon_build_info{version="v0.1.0"}` should match the version actually deployed
- `beacon_clock_skew_seconds` magnitude > 60 → time sync issue at customer

### Manual verification

After Stage 3 stable promotion, verify on at least one customer install:
- Power-cycle the host → systemd brings beacon back up → enrollment metadata still readable → heartbeats resume within 2 min
- Block egress to platform for 10 min → beacon buffers locally → `beacon_store_records_total{bucket="logs"}` grows → unblock → buffer drains → counter falls
- Tamper with `/var/lib/netbrain-beacon/beacon.crt` (corrupt a byte) → daemon restart → `LoadCertPairWithRecovery` falls back to `.prev` OR daemon fails fast with `ErrNoUsableCertPair` if no recovery available → operator alerted

---

## 7. Communication plan

### CHANGELOG.md entry

```markdown
## v0.1.0 — 2026-05-2X

First public release of the customer-edge beacon binary.

### Added
- Single-binary CLI: `enroll`, `daemon`, `status`, `collectors`, `logs`, `version`
- mTLS data plane to NetBrain platform per ADR-067 (TLS 1.3 only)
- AES-256-GCM envelope encryption with per-install DEK (ADR-068)
- Bootstrap-token-then-CSR enrollment ceremony with ed25519 bundle signature verify
- bbolt store-and-forward buffer (5 GB / 14 d cap, priority eviction)
- syslog collector (RFC 3164 + RFC 5424, UDP + TCP, drop-on-full back-pressure)
- 18 Prometheus instruments on loopback `127.0.0.1:9090` by default
- Auto cert rotation at 80% lifetime per ADR-067
- DEK rotation signature verify (M-11 fail-closed)
- SSRF allow-list via `internal/safedial` (M-9 chokepoint)
- Hardened systemd unit + distroless Docker image (UID 65532)
- 6 distribution artifacts: tarball / deb / rpm / Arch / Docker / Windows MSI (stub)
- Runbook with install / enroll / status / logs / metrics / re-enroll / corrupt-bbolt / uninstall

### Stub / follow-up
- netflow / snmp / configs collectors — package skeletons with `Stub` types satisfying `Collector`; real implementations in follow-up issues `add-beacon-netflow-collector`, `add-beacon-snmp-collector`, `add-beacon-configs-collector`
- Windows MSI installer — packaging skeleton only; follow-up `add-beacon-windows-installer`

### Security
- All 5 P1 hardenings (M-4 CSPRNG IVs, M-6 streaming gunzip, M-9 SSRF allow-list, M-11 DEK rotation sig verify, mTLS key 0600) verified
- 7 hardening fixes from /security audit landed in 0e061fb (SY-1/2/3, S-1, M-1, T-1, ST-1)
- Phase 7b dynamic pentest passed against staging — report in 07b_PENTEST_REPORT.md
- govulncheck clean across all deps
```

### Internal team announcement

```
Subject: [release] netbrain-beacon v0.1.0 — canary today, stable in T+10d

The customer-edge beacon binary's first release is tagged.

What ships:
- Single-binary CLI for customer hosts
- mTLS data plane to platform (live behind BEACON_MTLS_ENABLED flag on staging)
- syslog ingestion working end-to-end; netflow/snmp/configs collectors stubbed for follow-up
- 6 distribution artifacts published to GitHub Releases + Docker Hub

Rollout:
- Now: canary tag, 3 internal hosts, 7-day burn-in
- T+7d: Phase 7b co-pentest against staging
- T+10d: stable tag promotion (gated on 7b PASS + Track B Stage 3 on prod)

Reference:
- Release notes: <github release url>
- Operations runbook: <link>
- 7b pentest plan: pending_beacon_pentest.md

Pilot customer ops contacts: please ack receipt of v0.1.0 install instructions.
```

### Customer-facing release notes (GitHub Release body)

```markdown
# netbrain-beacon v0.1.0

First stable release of the customer-edge NetBrain beacon.

## What is the beacon?

A single Go binary that collects telemetry (syslog today; NetFlow / SNMP /
device configs coming in follow-up releases) from on-premises network gear
and forwards it to the NetBrain platform over mTLS.

## Installing

### Linux (tarball + systemd)
```bash
tar xzf netbrain-beacon-linux-amd64.tar.gz
sudo ./install.sh
```

### Debian / Ubuntu
```bash
sudo dpkg -i netbrain-beacon_0.1.0_amd64.deb
```

### Fedora / RHEL
```bash
sudo dnf install ./netbrain-beacon-0.1.0-1.x86_64.rpm
```

### Docker
```bash
docker run --rm -v /var/lib/netbrain-beacon:/var/lib/netbrain-beacon \
    velonet/netbrain-beacon:v0.1.0 enroll \
    --bundle-file /path/to/bundle.b64 \
    --server-url https://platform.example.com:8443
```

## Enrolling

Get an enrollment bundle from your NetBrain admin. Save it to a file
(mode 0600). Run:

```bash
sudo -u netbrain-beacon netbrain-beacon enroll \
    --bundle-file /tmp/bundle.b64 \
    --server-url https://platform.example.com:8443
```

The runbook at `docs/runbooks/beacon-operations.md` covers status checks,
log tailing, metrics, re-enrollment, and uninstall.

## Security

- TLS 1.3 only; private key permissions enforced at 0600
- M-11 DEK rotation signature fail-closed (rogue rotation rejected)
- M-9 SSRF allow-list on all device probes
- M-6 streaming gunzip with byte cap (CWE-409 defense)
- H-3 log redactor on all emitted log lines

See `README.md §"Security posture"` for the full hardening list.

## Checksums + signatures

SHA256 sums and cosign signatures for every artifact in `SHA256SUMS` +
`SHA256SUMS.sig`. Verify with:

```bash
sha256sum -c SHA256SUMS
cosign verify-blob --signature SHA256SUMS.sig SHA256SUMS
```

## Known limitations

- netflow / snmp / configs collectors are stubs in v0.1.0 — they manage
  enable/disable state but don't actually emit telemetry yet. Tracked in
  follow-up issues `add-beacon-{netflow,snmp,configs}-collector`.
- Windows MSI is a packaging skeleton in v0.1.0; use the Windows zip
  + manually configure a Windows service wrapper until
  `add-beacon-windows-installer` ships.
```

### Status page update template

```
[Investigating | Identified | Monitoring | Resolved]

netbrain-beacon v<bad> — <symptom>

Affected: customers running netbrain-beacon v<bad> on canary or stable
Docker tags, or apt/yum-installed at v<bad>.

Workaround: <one-sentence rollback instruction with link to runbook §5.1>

ETA for fix: <date+time UTC>
```

---

## 8. Open dependencies + risk register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Platform Track B Stage 3 slips → 7b pentest can't run | Medium | Blocks stable promotion | Stage 0 + Stage 1 canary independent of platform Stage 3; we burn in against the still-staged platform side |
| Phase 7b surfaces a high-severity finding | Low-Medium | Blocks stable promotion; requires /harden + re-pentest | All 5 P1 mandates + 7a hardenings closed; surface area is small |
| netflow / snmp / configs stubs cause customer confusion | Medium | Operator runs `collectors` subcommand, sees collectors disabled, files support ticket | README + runbook explicitly call out the stub status; collectors subcommand prints `(stub — see follow-up issue)` for non-syslog collectors (planned: see polish item below) |
| Windows operator wants to run the beacon but MSI is a stub | High | Manual NSSM wrapper required; documented friction | Documented in runbook; `add-beacon-windows-installer` tracked as the unblock |
| Customer host fills disk despite 5 GB cap (sender stuck) | Low | Beacon stops accepting new telemetry until eviction frees space | `beacon_store_evictions_total` alert + runbook recovery section + 14-day age cap kicks in even if bytes haven't reached 5 GB |

---

## 9. Polish items before v0.1.0 stable

These are nice-to-haves that don't block canary but ideally land before
stable. None are security-critical:

- [ ] `collectors` subcommand: mark stub collectors as `(stub)` in output
- [ ] `install.sh`: detect existing enrollment + refuse to overwrite without `--force`
- [ ] CHANGELOG.md created from §7 draft
- [ ] cosign signing for release artifacts wired into `release.yml` workflow
- [ ] `make release-canary` + `make release-stable` Makefile targets that
      script the docker tag promotion + GitHub release publication

---

## 10. Next step

After this plan lands:

1. **Now:** `/observe add-beacon-service` — formalize the metric + alert
   strategy that this plan references (most of it already exists in code +
   runbook; /observe produces the consolidated `10_OBSERVABILITY.md`).
2. **Stage 0:** publish `v0.1.0-rc.1`, run on 3 internal hosts against staging,
   burn in 72 h+.
3. **Stage 1:** promote to canary. Burn in 7 d.
4. **Stage 2:** run `/security/pentest add-beacon-service` against staging
   (gated on Track B Stage 3 staging).
5. **Stage 3:** promote to stable (gated on 7b PASS + Track B Stage 3 prod).
6. **Stage 4:** platform side enables per-tenant; no beacon-side action.

This plan is the source of truth for the rollout; deviations get added
inline with the date + reason.