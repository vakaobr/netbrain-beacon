# Discovery: add-beacon-service

## Summary

Build `netbrain-beacon`, a Go-based customer-edge appliance that collects network telemetry (logs / netflows / SNMP / device configs) from devices on isolated customer networks and ships them to the NetBrain platform over mTLS. This is the **second half of the beacon ecosystem**, completing the work begun by `beacon-protocol-and-enrollment` (contract) and `add-multi-mode-ingestion` (platform side, WORKFLOW COMPLETE 2026-05-10, tag `beacon-server-v1.0`). The Go client must be generated from the canonical OpenAPI spec, must comply with the 9 P1 hardenings catalogued by the parent issue, and must ship a single static binary deployable as Docker container or bare-metal VM install (Linux + Windows amd64).

## Problem Statement

Corporate customers on isolated networks (air-gapped, behind strict egress controls, or with internal-only device management) cannot ship telemetry directly to the NetBrain SaaS. The platform-side beacon endpoints exist (17 OpenAPI operations, mTLS-authed, fully tested) but have no client. Without `netbrain-beacon`, the beacon ecosystem is half-built — customers cannot onboard, the deploy plan's Stage 3 cannot be exercised, and the deferred Phase 7b pentest cannot run.

**Affected:**
- **Customers** on isolated networks (the entire reason the protocol exists).
- **NetBrain operations** (cannot demo, cannot pentest, cannot graduate `add-multi-mode-ingestion` from Stage 1 flag-off to Stage 4 production).
- **`add-device-discovery-wizard`** (the third issue in the trio; depends on beacon-shipped telemetry to surface unknown devices).

## Success Criteria

- [ ] Beacon enrolls against the running netbrain platform via `netbrain-beacon enroll --server-url https://<host>:8443 --token nbb_<token>` and persists `beacon.crt` (0644), `beacon.key` (0600), `dek.bin` (0600), `beacon-state.bbolt` (0600).
- [ ] Beacon completes the full ceremony: bootstrap-token redemption → CSR signing → cert + DEK + signed bundle returned → bundle ed25519 signature verified against platform pubkey → all artifacts persisted atomically.
- [ ] Daemon mode polls `/config` every 60 s ± 10 s with `If-None-Match`, applies ETag short-circuit, and persists hot-reload config changes without restart.
- [ ] Heartbeat carries device-latency probes (SYN/SYN-ACK to ports 22 → 161 → 80, median-of-3) for multi-proxy dedup signaling per ADR-072.
- [ ] All 4 data plane endpoints (`/data/{logs,flows,snmp,configs}`) succeed end-to-end against the platform: encrypted with AES-256-GCM, AAD-bound to Idempotency-Key (UUIDv5 namespace `c4d2c5e0-1c9b-5b9e-8d0a-7f3a4e1c2b3d`), gzipped where applicable, retried with backoff on transient failure.
- [ ] Store-and-forward buffers data in bbolt with 5 GB OR 14 d cap (whichever first), priority eviction `flows → logs → snmp → never configs`, and replays at ≤ 2× normal rate after reconnect (ADR-071).
- [ ] All 5 mandatory P1 hardenings verified by regression tests: M-4 (`crypto/rand` only for IVs), M-6 (streaming `gzip.NewReader` with byte cap), M-9 (SSRF allow-list reject for link-local/loopback/unspecified), M-11 (ed25519 signature verify on rotated DEKs), mTLS key 0600 perms with cert auto-rotate at 80% lifetime.
- [ ] CI pipeline green: `go vet`, `staticcheck`, `golangci-lint`, `go test ./...` with race detector on linux/windows amd64 matrix.
- [ ] Static binary cross-compiles to ~15 MB stripped via `go build -ldflags="-s -w" -trimpath` for both `GOOS=linux GOARCH=amd64` and `GOOS=windows GOARCH=amd64`.
- [ ] Local admin surface (final form decided at /design-system) exposes status, collector enable/disable, enrollment, and log tail.
- [ ] Phase 7b co-pentest (this issue + `add-multi-mode-ingestion`) passes against staging — both halves of the beacon ecosystem exercised together.

## Scope

### In Scope

- Single Go binary `netbrain-beacon` with subcommands: `enroll`, `daemon`, `status`, `version`.
- OpenAPI client generated via `oapi-codegen v2` against `beacon-v1.yaml` (single source of truth).
- mTLS client with cert auto-rotate at 80% lifetime, key on disk with 0600 perms.
- AES-256-GCM payload encryption with stdlib `crypto/aes` and `crypto/cipher`; CSPRNG IVs via `crypto/rand`.
- bbolt-backed store-and-forward buffer (5 GB / 14 d cap, priority eviction).
- 4 collector implementations: syslog server (UDP/TCP 514), netflow collector (UDP 2055 + nfcapd), SNMP poller (gosnmp), device-config SSH puller.
- Device-latency probe (TCP-connect SYN/SYN-ACK, median-of-3) for multi-proxy dedup signaling.
- Local admin surface — exact form (web UI vs CLI status command vs systemd) decided at /design-system.
- Cross-compile for `linux/amd64` and `windows/amd64`; Docker image (Alpine or distroless base).
- GitHub Actions CI: lint, test (race detector), build matrix, security scan (govulncheck).
- M-9 SSRF defense against device IP allow-list (reject link-local 169.254.0.0/16, loopback 127.0.0.0/8, unspecified 0.0.0.0, multicast).
- Structured logging (stdlib `log/slog` JSON handler) with redaction of `bootstrap_token` and `dek` fields.
- Operational runbook covering enroll / re-enroll / cert-rotation / store-forward inspection / log-tail / collector restart.

### Out of Scope

- Beacon self-upgrade / auto-update mechanism (deferred to v2; manual binary swap for v1).
- Beacon-to-beacon hot failover (deferred to v2).
- gRPC transport (parent locked HTTPS+JSON; not revisited).
- Cross-customer multi-tenant beacon install (each beacon binds to exactly one tenant via cert).
- Code generation for languages other than Go.
- macOS or arm64 builds for v1 (linux/windows amd64 only).
- TLS 1.2 fallback (TLS 1.3 only, enforced server-side at nginx 8443).
- Custom in-tree crypto primitives (stdlib `crypto/*` only; no third-party crypto libraries).

## Stakeholders

- **Users:** customers running NetBrain on isolated networks; field operations engineers deploying the beacon.
- **Teams:**
  - NetBrain platform team (consumes the data this beacon ships; owns `add-multi-mode-ingestion`).
  - NetBrain security team (Phase 7b co-pentest target).
  - Customer success / field ops (runbook owners for deployment).
- **Systems:**
  - NetBrain platform `api-gateway` (port 8443 mTLS, port 8000 admin JWT — both contracted via OpenAPI).
  - Customer network devices (SSH/SNMP/syslog/NetFlow producers; no changes required on them).
  - NetBox (the platform side surfaces unknown devices via `add-device-discovery-wizard`; not directly consumed here).

## Risk Assessment

**Level:** High

**Justification:**
1. **Customer-edge appliance, long-lived, internet-exposed.** Compromise of one beacon could expose its tenant's data. Private-key handling is the single most critical surface.
2. **Cryptographic primitives in the data path.** AES-256-GCM, AAD binding, IV uniqueness — any mistake silently breaks tenant isolation guarantees. M-4 (CSPRNG) and M-11 (ed25519 DEK signature verify) are non-negotiable.
3. **SSRF surface (M-9).** The beacon polls device IPs configured via the platform. A compromised configuration could redirect probes to link-local metadata services (cloud IMDS), loopback (local services), or internal-network routing. Allow-list reject is mandatory at this layer because the platform cannot enforce it for arbitrary customer networks.
4. **Store-and-forward correctness.** Under prolonged disconnects, eviction must be deterministic and priority-aware. A bug here means lost data; a worse bug means lost data without telemetry signaling the loss.
5. **Cross-tenant data path.** The beacon's DEK + mTLS cert are tenant-bound. Any logic that mixes these (e.g., shared HTTP client state) could leak across tenants — though v1 ships single-tenant, the code structure should not assume that forever.
6. **Phase 7b pentest deferred from parent.** `add-multi-mode-ingestion` Phase 7a static audit passed but explicitly recommended dynamic confirmation of H-1/H-2/H-4/M-3/M-6 with a real Go client. This issue is the prerequisite for that pentest.

## Dependencies

### Locked contract inputs (do NOT re-litigate)

- `c:/Users/Anderson Leite/code/netbrain/services/api-gateway/openapi/beacon-v1.yaml` — 1161-line OpenAPI 3.1, 17 endpoints. Single source of truth.
- `c:/Users/Anderson Leite/code/netbrain/ADR/ADR-067-beacon-enrollment-ceremony.md` — bootstrap-token-then-CSR ceremony; 24 h one-time-use; 90-day cert; auto-rotate at 80%.
- `c:/Users/Anderson Leite/code/netbrain/ADR/ADR-068-beacon-data-encryption-model.md` — per-install AES-256-GCM DEK; AAD = `bytes([dek_v]) || idempotency_key_bytes`; 7-day rotation grace.
- `c:/Users/Anderson Leite/code/netbrain/ADR/ADR-069-beacon-wire-format.md` — HTTPS+JSON control / gzip-NDJSON logs / multipart binary netflow; Idempotency-Key UUIDv5 namespace `c4d2c5e0-1c9b-5b9e-8d0a-7f3a4e1c2b3d`.
- `c:/Users/Anderson Leite/code/netbrain/ADR/ADR-070-beacon-config-poll-protocol.md` — 60 s ± 10 s poll; ETag 304 short-circuit; heartbeat piggybacks.
- `c:/Users/Anderson Leite/code/netbrain/ADR/ADR-071-beacon-store-and-forward.md` — bbolt single-file; 5 GB / 14 d cap; eviction `flows → logs → snmp → never configs`; 2× replay pacing.
- `c:/Users/Anderson Leite/code/netbrain/ADR/ADR-072-multi-proxy-device-dedup.md` — TCP-connect probe every 5 min; ports 22 → 161 → 80 fallback; median-of-3.

### Cross-issue dependencies

- **Phase 7b pentest for `add-multi-mode-ingestion` is mandatory** within 7 days of enabling `BEACON_MTLS_ENABLED=true` on staging. The plan is to **co-test both halves in one pass** — this issue's beacon + the platform — against staging. Reference: `c:/Users/Anderson Leite/code/netbrain/.claude/planning/add-multi-mode-ingestion/09_DEPLOY_PLAN.md` §"Phase 7b pentest mandatory" and `c:/Users/Anderson Leite/.claude/projects/c--Users-Anderson-Leite-code/memory/pending_beacon_pentest.md`. Surface this in every downstream phase (review, security, deploy) — do NOT ship Stage 3+ on the platform side until both halves co-pentest.
- **Stage 2+ deploy of `add-multi-mode-ingestion`** is blocked on this issue producing a working beacon (operationally, not architecturally — you can enable the platform's API surface, but there is no client to exercise it).
- **`add-device-discovery-wizard`** starts after this issue ships data through the platform end-to-end (it consumes the beacon-derived "unknown device" signal).

## Estimated Complexity

**Size:** L (Large)

**Reasoning:**
- Symmetric design surface with `add-multi-mode-ingestion` (which took 10 phases).
- 9 distinct concerns: enrollment, mTLS lifecycle, crypto, OpenAPI client, config poll, 4 collectors, store-and-forward, device probe, local admin surface.
- 5 mandatory P1 hardenings to verify (M-4, M-6, M-9, M-11, mTLS key perms).
- Cross-compile + CI matrix + Docker packaging adds operational scope a server-only feature would not.
- 8-10 phases expected — final count locked at /plan.

## Detected Tech Stack

This is a **greenfield Go repo** — only an `initial commit` and a 16-byte README exist today. All tooling listed below is **planned**, not yet present. The /research phase must verify Go version, library choices, and CI/CD conventions; this discovery captures the intent.

### Languages & Frameworks

| Technology | Version | Expert Command |
|------------|---------|----------------|
| Go (planned) | 1.26.3 (latest stable as of 2026-05-10) | (native knowledge — Go is well-supported) |

### Infrastructure

| Technology | Expert Command |
|------------|----------------|
| Docker (planned — Alpine or distroless container image) | (note in stack) |
| GitHub Actions (planned — `go vet`, `staticcheck`, `golangci-lint`, `go test`, build matrix) | (native knowledge) |

### Quality Tooling

| Tool | Status |
|------|--------|
| Linter (`golangci-lint`) | ✗ Missing (greenfield) |
| Formatter (`gofumpt` / `gofmt`) | ✗ Missing (greenfield) |
| Test Runner (`go test`) | ✗ Missing (greenfield) |
| CI/CD (`.github/workflows/`) | ✗ Missing (greenfield) |
| Pre-commit Hooks | ✗ Missing (greenfield) |

### Missing Quality Tooling Recommendations

This is a greenfield repo, so ALL quality tooling is missing — expected. Set up in Phase 1 of implementation rather than running standalone commands:

- **Phase 1 setup task** should create: `go.mod`, `.golangci.yml`, `.github/workflows/ci.yml`, `Dockerfile`, `Makefile`, `.gitignore`, `.editorconfig`. Treat these as load-bearing scaffolding — write them once, never revisit.
- Reference: the **`add-multi-mode-ingestion` retrospective** documents the cost of skipping CI setup early; do not repeat.

### Fallback Expert Commands

- **Primary:** native Go knowledge (the model has strong Go expertise — no language expert command needed).
- **Cloud / Infrastructure fallback:** `/language/cloud-engineer-pro` if cross-platform packaging (Linux/Windows), systemd unit files, or Windows service registration questions arise.

## Repository Map

```
.
├── README.md       — 16-byte stub: "#netbrain-beacon"
└── .git/           — initial commit, single branch `main`, no remote configured
```

**Files:** 1 source (README only) | 0 test | 0 config
**Primary language:** None yet — Go intended
**Key entry points:** None yet — `cmd/netbrain-beacon/main.go` proposed at /design-system

> Generated automatically during discovery. Run `/repo-map` to refresh once code exists.

## Symbol Index

(empty — no source code in repo)

> Generated alongside repo map. Run `/repo-map` to refresh after Phase 1 scaffolding.
