# Changelog

All notable changes to netbrain-beacon are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Channels: `rc` for release candidates (`vX.Y.Z-rc.N`), `stable` + `latest` for
GA releases (`vX.Y.Z`). The release workflow tags the GHCR Docker image with
both the exact version and the appropriate channel pointer; the GitHub Release
attaches checksummed Linux/macOS/Windows binaries plus .deb / .rpm packages.

---

## [v0.1.0-rc.2] — 2026-05-12

**Distribution-only release.** The beacon binary is byte-equivalent to
v0.1.0-rc.1; this tag exists to validate the upgraded release pipeline
end-to-end (.deb / .rpm / arm64 / macOS / multi-arch Docker / structured
notes) and to make those artifacts available to dogfood hosts that need
them. Operators already running rc.1 do **not** need to upgrade.

### Distribution

- **NEW: `.deb` + `.rpm` packages** for linux/amd64 + linux/arm64, built
  via `nfpm v2.40`. Each package includes the systemd unit, a `netbrain-
  beacon` system user (created by the pre-install hook), and a non-
  destructive remove path (`apt remove` preserves `/var/lib/netbrain-
  beacon` so enrollment survives reinstalls; `apt purge` for full wipe).
- **NEW: linux/arm64 native binary + tarball + package**. Unlocks ARM
  customer hardware (AWS Graviton, RPi-class edge boxes, ARM-based
  on-prem appliances).
- **NEW: darwin/amd64 + darwin/arm64 tarballs**. macOS Intel + Apple
  Silicon, single static binary. Operator-installed via tarball; a `.pkg`
  installer can come in a future release if there's demand.
- **NEW: multi-arch Docker image** (`linux/amd64,linux/arm64`) at
  `ghcr.io/vakaobr/netbrain-beacon`. Same `:rc` / `:stable` / version
  channel pointers as before.
- **NEW: Windows .zip** wrapping `netbrain-beacon.exe` with README +
  CHANGELOG (was a bare .exe in rc.1).

### Internal

- Release workflow: 6 jobs (binaries × 5 platforms, tarballs × 4 unix,
  windows-zip, linux-packages × 2 archs, multi-arch docker, release).
- Release notes are now extracted from this CHANGELOG.md section plus
  the commit list since the prior tag — structured for operators
  evaluating the upgrade rather than a raw commit dump.

### Same as rc.1

All beacon-side functionality (binary, security mandates, observability,
collectors, store-and-forward, mTLS transport, cert rotation) is identical
to rc.1 — see the v0.1.0-rc.1 section below.

---

## [v0.1.0-rc.1] — 2026-05-12

First release candidate. **Pre-release** — Stage 0 dogfood per
[09_DEPLOY_PLAN.md](.claude/planning/add-beacon-service/09_DEPLOY_PLAN.md):
3 internal hosts, 72h burn-in against staging before promotion to canary.

### Highlights

- Full SDLC complete (Discovery → Retro across 10 phases) for the beacon
  binary's customer-edge half of the NetBrain platform.
- All 5 P1 security mandates enforced: M-4 (CSPRNG IVs), M-6 (streaming
  gunzip with byte cap), M-9 (SSRF allow-list at `internal/safedial`),
  M-11 (ed25519 DEK rotation signature verify), mTLS private key on disk
  at 0600 with auto-rotation at 80% cert lifetime.
- Phase 7a static security audit: **PASS** (0 critical, 0 high; 7 medium/
  low/info findings all closed in the hardening pass).
- 21 cross-language byte-exactness fixtures (UUIDv5 / AES-GCM / ed25519 /
  canonical-JSON) verify wire-format compatibility with the Python
  platform reference; startup self-test panics on regression.

### New features

- **Enrollment ceremony** (bootstrap-token + CSR) at `netbrain-beacon enroll`
  with `--bundle-file` to keep the token out of `ps`/shell-history (CWE-214).
- **Daemon orchestrator** (`netbrain-beacon daemon`) — config-poll every
  60s ± 10s with ETag short-circuit, heartbeat piggyback, M-11 DEK
  rotation verify, device-latency probes via `safedial`.
- **mTLS transport** — TLS 1.3 only, atomic-pointer cert hot-swap, 7-day
  `.prev` archive recovery for crash-mid-rotation.
- **Store-and-forward** — bbolt-backed, UUIDv7-keyed FIFO, 5 GB / 14 d cap
  with priority eviction (`flows → logs → snmp`; configs never evicted).
- **Syslog collector** — RFC 3164 + RFC 5424 via `leodido/go-syslog v4`;
  TCP + UDP listeners with SY-1 line cap (256 KiB) and SY-2 concurrent-
  connection cap (256) for CWE-770 protection.
- **NetFlow / SNMP / configs collectors** — stubbed; real implementations
  ship in follow-up issues `add-beacon-netflow-collector`,
  `add-beacon-snmp-collector`, `add-beacon-configs-collector`.
- **Operator CLI** — `status`, `collectors`, `logs` with structured JSON
  output for scripting.
- **Observability** — 18 Prometheus instruments on `127.0.0.1:9090`
  (`--no-metrics` to disable); structured slog with the H-3 redactor
  scrubbing bootstrap tokens, DEKs, and CSRs from every log line.

### Distribution

- **Native binaries** for linux/amd64, linux/arm64, windows/amd64,
  darwin/amd64, darwin/arm64 — single static binary, no CGo, no runtime
  dependencies.
- **Linux packages** — `.deb` and `.rpm` for both amd64 and arm64 with
  systemd unit + system-user pre/post-install scripts.
- **Tarballs** for every platform (sha256-checksummed).
- **Distroless Docker image** at `ghcr.io/vakaobr/netbrain-beacon`
  (multi-arch: linux/amd64 + linux/arm64) — channel pointer `:rc` for
  this release, `:stable` reserved for the canary→stable promotion.
- **Windows** — zip archive with the .exe; MSI installer scaffolding
  ships in `packaging/windows/` for a follow-up issue.

### Security

- M-4 / M-6 / M-9 / M-11 / mTLS-key-0600 (see Highlights).
- H-3 log redactor scrubs `bootstrap_token`, `dek`, `data_key_b64`,
  `csr_pem`, `Authorization`, and tokens matching `nbb_[A-Za-z0-9_-]{16,}`.
- forbidigo lint blocks `math/rand` in `internal/crypto/**`, `net.Dial*`
  outside `internal/safedial/**`, and `io.ReadAll(gzip.NewReader)`
  everywhere — the ADR is for humans, the lint stops contributor drift.

### Known limitations

- **Phase 7b co-pentest pending**. Cannot promote `rc → stable` until
  Shannon dynamic pentest runs against staging Stage 3 (per
  `09_DEPLOY_PLAN.md`).
- **NetFlow / SNMP / configs collectors are stubs.** Daemon registry
  manages enable/disable today but no data flows for those collectors.
- **deb / rpm signing not yet wired** — packages are unsigned. Operators
  can verify via the checksums on this release.

### Installation

**Debian / Ubuntu (amd64 or arm64):**
```bash
curl -fsSL -o netbrain-beacon.deb \
  https://github.com/vakaobr/netbrain-beacon/releases/download/v0.1.0-rc.1/netbrain-beacon_0.1.0-rc.1_amd64.deb
sudo dpkg -i netbrain-beacon.deb
# then: sudo -u netbrain-beacon netbrain-beacon enroll --bundle-file ...
# then: sudo systemctl enable --now netbrain-beacon
```

**RHEL / Fedora / CentOS (amd64 or arm64):**
```bash
curl -fsSL -o netbrain-beacon.rpm \
  https://github.com/vakaobr/netbrain-beacon/releases/download/v0.1.0-rc.1/netbrain-beacon-0.1.0-rc.1.x86_64.rpm
sudo rpm -i netbrain-beacon.rpm
```

**Docker (multi-arch):**
```bash
docker pull ghcr.io/vakaobr/netbrain-beacon:rc
# or pin: ghcr.io/vakaobr/netbrain-beacon:v0.1.0-rc.1
```

**macOS (amd64 or arm64) / generic Linux tarball:**
```bash
curl -fsSL -o netbrain-beacon.tar.gz \
  https://github.com/vakaobr/netbrain-beacon/releases/download/v0.1.0-rc.1/netbrain-beacon-v0.1.0-rc.1-darwin-arm64.tar.gz
tar -xzf netbrain-beacon.tar.gz
./netbrain-beacon version
```

**Windows (amd64):**
Download the `.zip` from the release page; extract; run `netbrain-beacon.exe`
from PowerShell as an Administrator.
