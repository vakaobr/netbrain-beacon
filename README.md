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

Active development — Phase 1 (foundation/scaffolding) only. See
[`.claude/planning/add-beacon-service/00_STATUS.md`](.claude/planning/add-beacon-service/00_STATUS.md)
for current phase progress.

## Build

A working Go 1.26 toolchain is **not** required on the host — every build / test / lint
runs inside `golang:1.26-alpine` via Docker.

```bash
# host-arch test binary
make build

# cross-compile linux + windows binaries
make build-all

# distroless Docker image
make docker-build

# lint + test + build (the CI-equivalent local check)
make all
```

For developers who do install Go locally, all `make` targets fall back to `go ...`
if invoked directly.

## Layout

```
cmd/netbrain-beacon/    — entrypoint (CLI subcommand dispatch)
internal/api/           — generated OpenAPI client (oapi-codegen v2; Phase 4)
internal/crypto/        — AES-GCM envelope, UUIDv5 idempotency, ed25519 verify, streaming gunzip (Phase 2)
internal/safe_dial/     — M-9 SSRF chokepoint (Phase 3)
internal/transport/     — mTLS HTTP client + cert auto-rotation (Phase 4 + 6)
internal/enroll/        — bootstrap-token-then-CSR ceremony (Phase 5)
internal/store/         — bbolt store-and-forward buffer (Phase 7)
internal/daemon/        — config-poll loop + heartbeat + device probe (Phase 8)
internal/collectors/    — syslog + netflow + snmp + configs (Phase 9)
internal/admin/cli/     — `status`, `collectors`, `logs` subcommands (Phase 10)
internal/metrics/       — Prometheus registry (Phase 10)
packaging/              — deb / rpm / arch / tarball / systemd / Windows MSI (Phase 10)
tests/fixtures/         — cross-language byte-exactness fixtures (Phase 2; per ADR-080)
```

## Security posture

The beacon enforces 5 mandatory P1 hardenings carried forward from the parent issue:

- **M-4** AES-GCM IVs via `crypto/rand` only (forbidigo lint blocks `math/rand`)
- **M-6** streaming gunzip with per-call byte cap (no `io.ReadAll(gzip.NewReader)`)
- **M-9** SSRF allow-list reject in `internal/safe_dial` (forbidigo lint blocks `net.Dial*` outside the chokepoint)
- **M-11** ed25519 signature verify on every server-delivered DEK rotation
- mTLS private key on disk at 0600; cert auto-rotates at 80% lifetime

See [ADR-080](.claude/planning/add-beacon-service/03_ADR-080-cross-language-byte-exactness-fixtures.md)
and [ADR-081](.claude/planning/add-beacon-service/03_ADR-081-ssrf-safe-dial-package.md).

## License

Proprietary — internal NetBrain product. License file pending legal review.
