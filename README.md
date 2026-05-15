# netbrain-beacon

Customer-edge collector for the NetBrain platform.

The beacon runs at customer sites that cannot ship telemetry directly to the NetBrain
SaaS (air-gapped, behind strict egress, internal-only device management). It collects
syslog, NetFlow, SNMP, and device-config data from on-premises network gear and ships
it back over mTLS to the NetBrain platform.

This binary is the client-side of the beacon protocol locked by
[`beacon-protocol-and-enrollment`](../netbrain/.claude/planning/beacon-protocol-and-enrollment/)
and consumed by the platform-side
[`add-multi-mode-ingestion`](../netbrain/.claude/planning/add-multi-mode-ingestion/).

## Status

Implementation Phase 10/10 complete. Operator-ready for syslog ingestion via mTLS
to the NetBrain platform. NetFlow / SNMP / device-configs collectors are stubs awaiting
follow-up issues — the daemon + sender + store framework is fully in place; new
collectors just implement the `Collector` interface.

See [`.claude/planning/add-beacon-service/00_STATUS.md`](.claude/planning/add-beacon-service/00_STATUS.md)
for per-phase detail.

## Quick start

```bash
# Build host-arch binary
make build

# Enroll (obtain bundle from the NetBrain admin UI)
./bin/netbrain-beacon enroll --bundle '<base64-bundle>' \
    --server-url https://platform.example.com:8443 \
    --state-dir ./state

# Inspect state
./bin/netbrain-beacon status --state-dir ./state

# Run the daemon
./bin/netbrain-beacon daemon --state-dir ./state
```

### Cloudflare WARP mesh (bundle v2)

Bundles emitted by the NetBrain platform are **always v2** (ADR-007 pairs with
netbrain ADR-087). v1 bundles are rejected with `ErrBundleVersionUnsupported`.

When the bundle carries WARP enrollment credentials (the platform's Cloudflare
mesh integration is configured), `enroll` will:

1. Argon2id-derive a per-bundle KEK from the bootstrap token + envelope salt
   (~1-3 s on commodity hardware).
2. AES-256-GCM-decrypt the WARP credential envelope.
3. Invoke `warp-cli access set-default-account ...`, `warp-cli access
   add-account-key ...`, `warp-cli connect` to attach the host to the
   platform's WARP team.
4. Poll `warp-cli status` until the daemon reaches the connected state
   (up to `--warp-poll-seconds`, default 60).
5. Continue with the HTTP `/enroll` round-trip over the mesh overlay.

Flags:

```
--skip-mesh                  bypass WARP enrollment even when the bundle carries
                             credentials (useful when the platform is reachable
                             without the mesh, e.g. LAN-only deployments)
--warp-cli <path>            override the warp-cli binary path
--warp-poll-seconds <int>    deadline for reaching the WARP "connected" state
```

The WARP CLI must be installed before running `enroll` on a customer machine —
the beacon binary does NOT bundle Cloudflare's distribution. Install via the
platform-appropriate package from <https://1.1.1.1> or follow Cloudflare's
WARP client docs. The beacon detects a missing `warp-cli` and exits with
`ErrWARPCLINotFound`; the runbook explains the install path.

**Dev / staging endpoint** (2026-05-13–): `https://netbrain-dev-beacon.andersonleite.me/` —
a Cloudflare tunnel forwards inbound traffic to the netbrain platform's nginx mTLS
terminator on host port 8443. Use this as the `--server-url` when testing against
the dev platform; the platform CA fingerprint is embedded in the enrollment bundle, so
no extra trust-store setup is needed on the beacon side. See `docs/runbooks/beacon-operations.md`
in the **netbrain** repo for tunnel-config caveats (mTLS pass-through, `noTLSVerify`).

Production install: see [`docs/runbooks/beacon-operations.md`](docs/runbooks/beacon-operations.md).

## Build

A working Go 1.26 toolchain is **not** required on the host — every build / test / lint
runs inside `golang:1.26-alpine` via Docker.

```bash
make build         # host-arch binary
make build-all     # cross-compile linux/amd64 + windows/amd64
make docker-build  # distroless Docker image
make test          # full test suite + coverage
make lint          # golangci-lint v2.12.2
make all           # lint + test + build (the CI-equivalent local check)
```

For developers who do install Go locally, all `make` targets fall back to `go ...`
if invoked directly.

## CLI

```
netbrain-beacon version
netbrain-beacon enroll --bundle <b64> --server-url <https://...> [--state-dir <path>]
netbrain-beacon daemon [--state-dir <path>] [--no-metrics] [--metrics-bind 127.0.0.1:9090]
netbrain-beacon status [--state-dir <path>] [--json]
netbrain-beacon collectors [--json]
netbrain-beacon logs --path <log-file> [--follow] [-n N] [--grep <s>] [--level INFO|WARN|ERROR]
```

## Layout

```
cmd/netbrain-beacon/    — entrypoint (CLI subcommand dispatch)
internal/api/           — generated OpenAPI client (oapi-codegen v2.5.0; Phase 4)
internal/crypto/        — AES-GCM envelope, UUIDv5 idempotency, ed25519 verify, streaming gunzip (Phase 2)
internal/safedial/      — M-9 SSRF chokepoint (Phase 3)
internal/transport/     — mTLS HTTP client + cert auto-rotation (Phases 4 + 6)
internal/enroll/        — bootstrap-token-then-CSR ceremony (Phase 5)
internal/store/         — bbolt store-and-forward buffer (Phase 7)
internal/probe/         — TCP-connect device-latency probe per ADR-072 (Phase 8)
internal/daemon/        — config-poll loop + heartbeat + M-11 DEK verify (Phase 8)
internal/collectors/    — sender + syslog (full); netflow/snmp/configs (stubs) (Phase 9)
internal/admin/cli/     — `status`, `collectors`, `logs` subcommands (Phase 10)
internal/log/           — H-3 redactor for slog (Phase 5)
internal/metrics/       — Prometheus registry + /metrics server (Phase 10)
packaging/              — tarball + systemd (ready); deb/rpm/arch/Windows MSI (skeletons)
docs/runbooks/          — operator-facing runbooks
tests/fixtures/         — cross-language byte-exactness fixtures (Phase 2; per ADR-080)
```

## Security posture

The beacon enforces 5 mandatory P1 hardenings carried forward from the parent issue:

- **M-4** AES-GCM IVs via `crypto/rand` only (forbidigo lint blocks `math/rand`)
- **M-6** streaming gunzip with per-call byte cap (no `io.ReadAll(gzip.NewReader)`)
- **M-9** SSRF allow-list reject in `internal/safedial` (forbidigo lint blocks `net.Dial*` outside the chokepoint)
- **M-11** ed25519 signature verify on every server-delivered DEK rotation; fail-closed (verify-error never advances `DEKVersion`)
- mTLS private key on disk at 0600; cert auto-rotates at 80% lifetime per ADR-067

Plus:
- **H-3 log redactor** scrubs `bootstrap_token`, `dek`, `csr_pem`, `Authorization`, and tokens matching `nbb_[A-Za-z0-9_-]{16,}` from every emitted log line.
- **Cross-language byte-exactness** fixtures (21 cases: 10 UUIDv5 + 5 AES-GCM + 3 ed25519 + 3 canonical-JSON) verify the wire format matches the Python reference implementation in the netbrain repo. CI fails on any drift.

Hardening pass (07a / /security/harden, 2026-05-12):
- **SY-1** syslog TCP `bufio.Scanner` with bounded buffer; lines past `MaxLineBytes` (default 256 KiB) are dropped + counted (CWE-770).
- **SY-2** syslog TCP listener semaphore caps concurrent connections at `MaxTCPConnections` (default 256); over-cap accepts are closed immediately (CWE-770).
- **SY-3** syslog worker per-message panic-recover (CWE-754).
- **S-1** `enroll --bundle-file <path>` alternative; runbook recommends this over `--bundle <b64>` to keep the bootstrap token out of `ps` / shell history / audit logs (CWE-214).
- **M-1** `/metrics` `non_loopback_bind` WARN at startup when `--metrics-bind` exposes the endpoint past 127.0.0.1 (CWE-200).
- **T-1** `transport.LoadCertPairWithRecovery` falls back through live → .new → .prev slots after a crash mid-rotation.
- **ST-1** plaintext-at-rest host-trust assumption documented in runbook §"Security model" and ADR-002.

See [docs/ADR/ADR-004](docs/ADR/ADR-004-cross-language-byte-exactness-fixtures.md)
and [docs/ADR/ADR-005](docs/ADR/ADR-005-ssrf-safe-dial-package.md), plus
[docs/runbooks/beacon-operations.md §"Security model"](docs/runbooks/beacon-operations.md).

## Observability

The daemon hosts a Prometheus `/metrics` endpoint on `127.0.0.1:9090` by default (D-8).
18 instruments cover enrollment, poll cycles, heartbeat, M-11 fail-closed events,
cert rotation, store size by bucket, eviction counters, sender throughput, collector
back-pressure, and SSRF rejections. See
[`internal/metrics/registry.go`](internal/metrics/registry.go) for the canonical list.

To disable metrics entirely: `--no-metrics` flag on the `daemon` subcommand.

## Phase 7b co-pentest

A dynamic pentest co-tested with the netbrain platform side (`add-multi-mode-ingestion`)
is mandatory before Stage 3 enables `BEACON_MTLS_ENABLED=true` in production. See
[`docs/runbooks/beacon-operations.md`](docs/runbooks/beacon-operations.md#phase-7b-pentest-reference)
for specific targets.

## Documentation

- [End-to-end data flow: devices → beacon → platform](docs/data-flow.md) — Mermaid diagram + component / encryption / transport tables for consultants installing beacons and operators troubleshooting ingestion.
- [Operator runbook](docs/runbooks/beacon-operations.md) — install, enroll, monitor, re-enroll, uninstall.
- [Architecture decision records](docs/ADR/README.md) — ADR-001..009 + netbrain pairing map.

## License

Proprietary — internal NetBrain product. License file pending legal review.
