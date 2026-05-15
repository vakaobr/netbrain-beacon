# Changelog

All notable changes to netbrain-beacon are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Channels: `rc` for release candidates (`vX.Y.Z-rc.N`), `stable` + `latest` for
GA releases (`vX.Y.Z`). The release workflow tags the GHCR Docker image with
both the exact version and the appropriate channel pointer; the GitHub Release
attaches checksummed Linux/macOS/Windows binaries plus .deb / .rpm packages.

---

## [v0.2.0-rc.2] — 2026-05-15

**WARP CLI surface drift fix.** Cloudflare removed the
`warp-cli access set-default-account` and `warp-cli access add-account-key`
subcommands from current WARP CLI builds (2026.x). v0.2.0-rc.1 shipped
against the deprecated surface and could not complete headless
Service-Token enrollment on a freshly-installed WARP CLI. This release
replaces the argv-driven path with the supported MDM-file path on
**Linux only**; macOS / Windows return a typed `ErrMeshUnsupportedOS`
and operators fall back to interactive `warp-cli registration new` +
`--skip-mesh`.

### Breaking changes

- `mesh.Credentials` gained a `WARPTeamDomain` field. Callers
  constructing the struct directly (none in production today; only
  `cmd/netbrain-beacon/enroll_cmd.go` does so) must supply it.

### Changed

- **`internal/mesh` rewrite** — replaced the deprecated
  `warp-cli access` subprocess sequence with an MDM-file path:
  the beacon writes `/var/lib/cloudflare-warp/mdm.xml` (mode 0600,
  owner root, atomic temp+rename) carrying the team slug,
  `auth_client_id`, `auth_client_secret`, and the
  `service_mode=warp` / `auto_connect=1` / `onboarding=false` switches
  that Cloudflare's headless deployment surface expects, then triggers
  `warp-cli mdm refresh` (on `>= 2026.4.1350.0`) or falls back to
  `systemctl restart warp-svc`. The daemon connects itself —
  `warp-cli connect` is no longer invoked.
- **Linux-only headless mesh.** On macOS / Windows the new
  `mesh.ErrMeshUnsupportedOS` is returned and the operator runs
  interactive `warp-cli registration new <team-slug>` + the beacon
  with `--skip-mesh`. macOS / Windows headless MDM enrollment (plist /
  registry) is deferred to a future v0.3.0.
- `mesh.Client.Enroll` is now split across build tags
  (`internal/mesh/mdm_linux.go` vs `internal/mesh/mdm_other.go`); the
  `Client` interface contract is unchanged so the `enroll` command
  compiles without changes beyond the new `WARPTeamDomain` field.
- Minimum supported `warp-cli` raised to **`>= 2026.1.150.0`**. The
  `mdm refresh` fast-path requires `>= 2026.4.1350.0`; older CLIs
  still work via the systemctl-restart fallback.
- **On-disk secret posture.** The service-token client_secret now
  persists at `/var/lib/cloudflare-warp/mdm.xml` (mode 0600, root-only)
  instead of only living in memory during a subprocess argv. Documented
  in ADR-009 (paired with netbrain ADR-091). Hardening guidance in the
  runbook (full-disk encryption on low-trust hosts) gained an explicit
  pointer.

### Added

- **`mesh.ErrMeshUnsupportedOS`** — exported sentinel error so the
  `enroll` command can branch on it and print operator guidance.
- **Runbook updates** (`docs/runbooks/beacon-operations.md` §
  "Cloudflare WARP mesh prerequisite") — OS support matrix, MDM-file
  description, macOS / Windows manual operator path, troubleshooting
  rows for `ErrMeshUnsupportedOS` and "MDM file written but daemon
  doesn't connect".
- **ADR-008 erratum** noting the MDM-file pivot.
- **ADR-009** (`docs/ADR/ADR-009-mdm-file-headless-warp-enrollment.md`)
  documenting the headless-MDM-file approach + the on-disk-secret
  posture change (paired with netbrain ADR-091).

### Verified

- `make all` clean on Linux Docker:
  - golangci-lint v2.12.2 — 0 issues across `./...`
  - 340 tests pass (`go test -race -coverprofile`), `internal/mesh`
    coverage 73.9% (up from 70.4%; +17 tests in the package).
  - Cross-compile for `linux/amd64`, `linux/arm64`, `darwin/amd64`,
    `darwin/arm64`, `windows/amd64` all succeed.

### Removed

- The `warp-cli access set-default-account` / `add-account-key` /
  `connect` argv path. These subcommands were removed by Cloudflare
  and cannot be relied on by any current WARP CLI build.

### Notes

- The `redactArgs` helper is preserved for any future warp-cli
  subcommand that grows a secret-bearing argv. The MDM-file path
  itself carries no secrets via argv.
- Tag the release as `v0.2.0-rc.2` and let the GitHub Release
  workflow build the artifacts.

---

## [v0.2.0-rc.1] — 2026-05-14

**Bundle v2 + Cloudflare WARP mesh support.** Pairs with the platform-side
`add-cloudflare-mesh-onboarding` workflow (netbrain ADR-087..090,
netbrain-beacon ADR-007 + ADR-008). Enables beacons deployed by Velonet
consultants to customer infrastructure to route ingress through Cloudflare's
WARP-to-WARP mesh overlay, bypassing the need for inbound holes in the
customer's firewall.

### Breaking changes

- **Bundle v1 support removed.** The beacon now rejects any v1 bundle
  with `ErrBundleVersionUnsupported`. The platform side (netbrain
  `>= 8ee1cf3`) emits v2-only bundles, matching this cutover. Operators
  must re-request a fresh enrollment bundle from the NetBrain admin UI
  after upgrading both sides.

### Added

- **Bundle v2 parser** (`internal/enroll/bundle_v2.go`) with the wire
  layout `[ver(1B)=0x01 | salt(16B) | iv(12B) | ct(var) | tag(16B)]`
  base64-encoded. Argon2id KEK derivation at `t=2, m=64 MiB, p=1, len=32`
  (RFC 9106 / OWASP 2025 baseline) via `golang.org/x/crypto/argon2.IDKey`.
  AES-256-GCM decrypt with AAD binding `{beacon_token_prefix, expires_at}`.
  Ed25519 signature now covers the full v2 payload (including mesh fields)
  so dropping a `warp_*` field after signing trips the regression test.
- **WARP CLI sub-process wrapper** (`internal/mesh`) — `Client` interface
  with `cliClient` shelling out to `warp-cli access set-default-account`
  / `add-account-key` / `connect` and polling `warp-cli status` until
  connected. Bounded by `--warp-poll-seconds` (default 60). `redactArgs`
  scrubs the WARP service-token secret from any error message (CWE-214
  pattern).
- **`enroll` subcommand flags:**
  - `--skip-mesh` — bypass WARP enrollment even when the bundle carries
    credentials (useful for LAN-only deployments).
  - `--warp-cli <path>` — override the `warp-cli` binary path.
  - `--warp-poll-seconds <int>` — deadline for reaching the WARP
    "connected" state.
- **Cross-language byte-exactness fixtures** (`internal/crypto/fixtures_test.go`
  `TestCrossLangBundleV2`) — loads 5 bundle v2 envelope cases (happy /
  zero-length / multibyte / max-length 4096B / tampered-salt) from the
  platform-generated `cross_lang_fixtures.json` and asserts Python writer ↔
  Go reader byte-equivalence. `init()` panic-on-drift catches param
  divergence at process start, before any production code runs.
- **`docs/runbooks/beacon-operations.md` § Cloudflare WARP mesh
  prerequisite** — installation instructions for `warp-cli` per OS,
  flag reference, troubleshooting matrix for `ErrBundleVersionUnsupported`,
  `ErrWARPCLINotFound`, and mesh-side `/enroll` failures.
- **`docs/ADR/ADR-007-bundle-v2-warp-envelope.md`** (pairs with netbrain
  ADR-087) and **`docs/ADR/ADR-008-warp-cli-subprocess-wrapper.md`** (pairs
  with netbrain ADR-088).

### Changed

- `internal/enroll/bundle.go` becomes a thin discriminator —
  `Bundle = BundleV2` type alias + `ParseBundle` delegates to
  `ParseBundleV2`. Existing callers compile unchanged.
- Enrollment progress lines now emit during the 1-3 s Argon2id KDF so
  operators don't think the binary hung.
- `packaging/README.md` documents `warp-cli` as a runtime prerequisite
  for mesh-enabled bundles (NOT a package-install dependency — direct
  LAN/VPN deployments don't need it).

### Verified

- `make all` clean on both Windows host and Linux Docker: golangci-lint
  v2.12.2 zero issues, 17 packages green.
- `warp-cli status` polling regex (`\bconnected\b`) avoids the false-
  positive substring match on "Disconnected" — caught in Linux CI on
  the first run.

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
