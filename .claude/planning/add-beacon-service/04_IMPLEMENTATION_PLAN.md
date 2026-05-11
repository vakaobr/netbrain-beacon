# Implementation Plan: add-beacon-service

## Overview

- **Total Phases:** 10
- **Estimated Effort:** L (Large) — matches the netbrain-side scale (`add-multi-mode-ingestion` shipped 10 phases over 9 days)
- **Dependencies:**
  - `add-multi-mode-ingestion` WORKFLOW COMPLETE (2026-05-10) — platform side live in Stage 1 flag-off; required for Phase 5 end-to-end enrollment test
  - Sibling repo `c:/Users/Anderson Leite/code/netbrain/` provides OpenAPI spec, ADRs, and crypto reference impls
- **Feature flag:** none at binary level (server enforces `BEACON_PROTOCOL_ENABLED` / `BEACON_MTLS_ENABLED`); beacon reads env vars `NETBRAIN_BEACON_*`
- **Phase 7b co-pentest** scheduled after Phase 8 deploy plan completes — co-test both halves of the beacon ecosystem
- **Coverage target:** ≥85% on `internal/crypto/**`, `internal/safe_dial/`, `internal/enroll/`, `internal/transport/` (security-hot); ≥70% repo-wide

---

## Phase 1: Foundation & scaffolding

### Objective
Establish the Go module, repo layout, CI/lint/test infrastructure, and Docker build. Produce a binary that runs `netbrain-beacon version` and nothing else — proves the toolchain end to end.

### Tasks
- [ ] Task 1.1: `go.mod` with `module github.com/secra/netbrain-beacon`, `go 1.26.3`, minimum direct deps stubbed (`testify`, `slog` is stdlib, `prometheus/client_golang`) — `go.mod`, `go.sum`
- [ ] Task 1.2: Repo layout per ADR-077 — `cmd/netbrain-beacon/main.go` (stub printing version), `internal/` empty dirs with `.gitkeep` for the 14 sub-packages enumerated in 03_ARCHITECTURE.md §2
- [ ] Task 1.3: `.golangci.yml` v2 with `errcheck`, `gosec`, `bodyclose`, `forbidigo`, `staticcheck`, `gocritic`, `revive`; forbidigo rules per ADR-077 (math/rand in crypto/, net.Dial outside safe_dial/, TLS without MinVersion, gzip.decompress, fmt.Errorf with %s for errors)
- [ ] Task 1.4: `.github/workflows/ci.yml` — matrix `{linux,windows}/amd64`; jobs: lint (golangci-lint), test (`go test -race -coverprofile`), build (cross-compile), govulncheck, license scan
- [ ] Task 1.5: `Makefile` targets — `lint`, `test`, `build` (host arch), `build-linux`, `build-windows`, `docker-build`, `clean`, `generate` (oapi-codegen stub for Phase 4)
- [ ] Task 1.6: `Dockerfile` multi-stage — `golang:1.26-alpine` build stage with `CGO_ENABLED=0 -ldflags="-s -w -buildid=" -trimpath`; runtime stage `gcr.io/distroless/static-debian12:nonroot`
- [ ] Task 1.7: `.gitignore`, `.editorconfig`, `LICENSE` (Apache-2.0 or proprietary — confirm at task time), `README.md` upgrade with build instructions

### Tests
- [ ] Unit: `cmd/netbrain-beacon/main_test.go` — `go run . version` outputs a non-empty semver string
- [ ] Integration: `make test` exits 0; `make lint` exits 0 with zero findings; `make build-linux` and `make build-windows` produce binaries
- [ ] CI: workflow runs end-to-end on a throwaway branch push

### Acceptance Criteria
- `make all` (lint + test + build) green
- Docker image builds and runs `netbrain-beacon version` cleanly
- Cross-compiled linux/amd64 + windows/amd64 binaries each < 20 MB stripped
- CI matrix runs all 4 jobs on push and on PR

### Rollback
- `git revert` the foundation commit; no runtime state created

---

## Phase 2: Crypto primitives + cross-language byte-exactness fixtures

### Objective
Implement the four crypto primitives that must be byte-compatible with the Python netbrain side: AES-256-GCM envelope, UUIDv5 idempotency derivation, ed25519 signature verify, streaming gunzip with byte cap. Pull the cross-language fixture file from the netbrain repo and pin it under `tests/fixtures/cross_lang/`.

### Tasks
- [ ] Task 2.1: Generate fixture file in netbrain repo via a one-off Python script writing `cross_lang_fixtures.json` with 10 UUIDv5 inputs/outputs + 5 AES-GCM round-trips + 3 ed25519 signed bundles + 3 canonical-JSON cases (per ADR-080). Commit to `c:/Users/Anderson Leite/code/netbrain-beacon/tests/fixtures/cross_lang/cross_lang_fixtures.json`
- [ ] Task 2.2: `internal/crypto/idempotency.go` — `Derive(beaconID, plaintext) uuid.UUID` matching Python `uuid.uuid5(NAMESPACE, beacon_id + sha256(plaintext).hex())`. Mind the `hex()` vs `bytes` gotcha (R-1). Namespace constant `c4d2c5e0-1c9b-5b9e-8d0a-7f3a4e1c2b3d`
- [ ] Task 2.3: `internal/crypto/dek_envelope.go` — `Wrap(dek, dekVersion, plaintext, idempotencyKey)` returns `[ver(1)|dek_v(1)|iv(12)|ct|tag(16)]`; `Unwrap` inverse. AAD = `bytes([dek_v]) || idempotency_key.bytes` (17 bytes). IV via `crypto/rand.Read` (M-4)
- [ ] Task 2.4: `internal/crypto/platform_verify.go` — `Verify(pubKey, payload, signature) error` using stdlib `crypto/ed25519`. Payload is canonical-JSON of `{data_key_b64, data_key_version, beacon_id, issued_at}` (M-11)
- [ ] Task 2.5: `internal/crypto/streaming_gunzip.go` — `GunzipCapped(r io.Reader, maxBytes int64) ([]byte, error)` using `gzip.NewReader` + bounded `io.CopyN`; abort with `ErrDecompressionBomb` if cap exceeded (M-6). Forbidigo rule blocks `io.ReadAll(gzip.NewReader)` in repo
- [ ] Task 2.6: `internal/crypto/startup_selftest.go` — runs all fixture cases at binary startup; `panic` on any byte-mismatch. Disable in unit tests via build tag
- [ ] Task 2.7: Refresh procedure documented in `tests/fixtures/cross_lang/README.md` — how to regenerate when netbrain crypto evolves

### Tests
- [ ] Unit: `internal/crypto/*_test.go` — every primitive has table-driven tests; fixture cases loaded from JSON; property-based tests via `pgregory.net/rapid` for IV uniqueness over 10k iters and AES-GCM round-trip
- [ ] Unit: tamper tests — flipped tag, flipped AAD byte, flipped DEK version → `Unwrap` returns specific errors
- [ ] Unit: streaming_gunzip — 4 KB → 100 MB bomb aborts in < 100 ms (matches platform NFR-15)
- [ ] Unit: startup_selftest — panics on a deliberately corrupted fixture

### Acceptance Criteria
- All 21 fixture cases pass byte-for-byte
- IV uniqueness property holds (10k samples, zero collisions)
- Gzip-bomb test aborts within 100 ms wall clock
- Coverage on `internal/crypto/**` ≥ 90%

### Rollback
- Revert crypto package; no on-disk state yet

---

## Phase 3: SSRF defense — `internal/safe_dial`

### Objective
Build the M-9 chokepoint package that all device-IP dials must go through. Enforce DNS resolve-once-then-dial-literal to defeat DNS rebinding. Add forbidigo lint gate.

### Tasks
- [ ] Task 3.1: `internal/safe_dial/safe_dial.go` — `Dial(ctx context.Context, network, hostOrIP string, port int) (net.Conn, error)`; resolves DNS once via `net.DefaultResolver.LookupIP`, applies allow-list reject, then `net.Dial(network, resolvedIP.String() + ":" + strconv.Itoa(port))`
- [ ] Task 3.2: `internal/safe_dial/allowlist.go` — forbidden ranges from ADR-081: `127.0.0.0/8`, `169.254.0.0/16`, `224.0.0.0/4`, `0.0.0.0/32`, `fe80::/10`, `ff00::/8`, `::1/128`, IPv4-mapped IPv6 equivalents
- [ ] Task 3.3: forbidigo lint rule in `.golangci.yml` — `net.Dial`, `net.DialContext`, `(*net.Dialer).Dial`, `(*net.Dialer).DialContext` forbidden outside `internal/safe_dial/` and `internal/transport/` (transport calls public netbrain URL, not user-supplied; allowed but warned)
- [ ] Task 3.4: Wire to a `clock.Clock` interface for testability (in `internal/clock/`); used here for connect timeouts
- [ ] Task 3.5: Document in `internal/safe_dial/doc.go` why this exists, the DNS rebinding scenario, and the lint gate rationale

### Tests
- [ ] Unit: every forbidden CIDR returns `ErrForbiddenIP` (one test per CIDR, 8 cases)
- [ ] Unit: allowed RFC1918 IPs (10.x, 172.16-31.x, 192.168.x) succeed
- [ ] Unit: DNS resolves to forbidden IP → reject even if hostname looked safe
- [ ] Unit: hostname with multi-IP A record where one is forbidden → reject ALL (defense in depth, not partial-allow)
- [ ] Unit: forbidigo rule rejects `net.Dial` in a fixture test file

### Acceptance Criteria
- All 8 forbidden CIDRs reject with `ErrForbiddenIP`
- DNS rebinding test passes (resolve to allowed, dial-time hostname changes to forbidden — beacon still dials the originally-resolved IP)
- `golangci-lint run` fails when fixture file uses `net.Dial` outside safe_dial

### Rollback
- Revert package; no consumers yet (collectors land in Phase 9)

---

## Phase 4: OpenAPI codegen + mTLS transport

### Objective
Generate the OpenAPI client from `beacon-v1.yaml` via `oapi-codegen v2` (client + models, no server). Build the mTLS HTTP transport with TLS 1.3-only, atomic `*http.Client` swap pointer, and a `RequestEditorFn` middleware that adds the per-request bearer token (Idempotency-Key on data writes, JWT-equivalent if needed).

### Tasks
- [ ] Task 4.1: `Makefile generate` target — copies `beacon-v1.yaml` from netbrain repo to `internal/api/spec/beacon-v1.yaml`, applies the OpenAPI 3.1 → 3.0 Overlay shim (per research §3), runs `oapi-codegen --config api-config.yaml`
- [ ] Task 4.2: `internal/api/api-config.yaml` — `package: api`, `generate: {client: true, models: true}`, output `internal/api/zz_generated.go`. Pin generator version
- [ ] Task 4.3: `internal/transport/client.go` — builds `*tls.Config` with `MinVersion: tls.VersionTLS13`, `Certificates: [...]` from on-disk cert+key, `RootCAs: [from enrollment bundle platform-ca.pem]`. Wraps in `*http.Client` with `MaxIdleConnsPerHost=2`, `IdleConnTimeout=90s`
- [ ] Task 4.4: `internal/transport/client.go` — `*Client` struct with `current atomic.Pointer[http.Client]`; `Swap(newClient)` for cert rotation; `Current() *http.Client` for callers
- [ ] Task 4.5: `internal/transport/editor.go` — `RequestEditorFn` adding standard headers: `User-Agent: netbrain-beacon/<version>`, `Idempotency-Key` (computed by caller, attached here), `Content-Encoding: gzip` when applicable
- [ ] Task 4.6: `internal/transport/errors.go` — map server error codes (17 codes from 03_ARCHITECTURE.md §4) to beacon actions: drop / retry / fatal-reenroll
- [ ] Task 4.7: `internal/transport/doc.go` — usage pattern, how `*Client` is shared across goroutines safely

### Tests
- [ ] Unit: generated code compiles; manual smoke test against a fixture server
- [ ] Unit: `Swap` is safe under concurrent reads (rapid property test, 1000 swaps × 100 readers)
- [ ] Unit: TLS config rejects 1.2 client; accepts 1.3
- [ ] Unit: error-code → action map covers all 17 codes (no defaults to retry — must be enumerated)
- [ ] Integration: spin up a local httptest server with cert chain; full request round-trip succeeds

### Acceptance Criteria
- Generated client code compiles with zero warnings
- `Swap` benchmark < 1 µs at p99
- All 17 server error codes have explicit mapped actions
- TLS 1.2 client → handshake failure (verified with explicit fixture)

### Rollback
- Delete generated code; revert transport package

---

## Phase 5: Enrollment ceremony

### Objective
Implement `netbrain-beacon enroll --server-url URL --token TOKEN`. Generates ECDSA-P-256 key + CSR, sends to `/api/v1/beacons/enroll`, verifies ed25519 signature on returned bundle, persists `beacon.crt` (0644), `beacon.key` (0600), `dek.bin` (0600), `platform-pubkey.pem` (0644), `enrollment-metadata.json` atomically.

### Tasks
- [ ] Task 5.1: `internal/enroll/csr.go` — generate P-256 key via `ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`; build CSR with `CommonName: "pending-server-assigned"` (server overrides per H-3 of parent); encode PEM
- [ ] Task 5.2: `internal/enroll/enroll.go` — `Enroll(ctx, serverURL, token) (*EnrollmentResult, error)` calling generated `BeaconEnrollWithResponse` from `internal/api`; parse response, extract certificate + DEK + platform pubkey + signed bundle
- [ ] Task 5.3: `internal/enroll/persist.go` — atomic writes via `os.WriteFile(tmpPath, ...)` + `os.Rename(tmpPath, finalPath)` for each artifact; explicit `os.Chmod(path, 0600)` for `beacon.key` and `dek.bin` after rename
- [ ] Task 5.4: `internal/enroll/verify.go` — verifies bundle signature using `internal/crypto/platform_verify` before persisting (fail-closed; do NOT write artifacts if signature fails)
- [ ] Task 5.5: `cmd/netbrain-beacon/enroll.go` — CLI subcommand parser; `--server-url`, `--token`, `--state-dir` (default `/var/lib/netbrain-beacon` on Linux, `%PROGRAMDATA%\netbrain-beacon` on Windows); structured output (success: cert serial + DEK version + expires_at; failure: redacted error)
- [ ] Task 5.6: `internal/log/redactor.go` — `slog.Handler` middleware dropping fields named `bootstrap_token`, `dek`, `data_key_b64`, `csr_pem`, `enrollment_bundle.bootstrap_token`, plus regex sweep over `nbb_[A-Za-z0-9]+` patterns in formatted messages (H-3)
- [ ] Task 5.7: `internal/enroll/idempotency.go` — if `enrollment-metadata.json` already exists with matching server URL, refuse to re-enroll (operator must `--force`); avoids accidental double-enroll

### Tests
- [ ] Unit: CSR generation produces valid P-256 PEM, parseable by `crypto/x509`
- [ ] Unit: atomic persist + chmod sequence; race test ensuring half-written files are never observed (kill mid-write, verify nothing or all)
- [ ] Unit: tampered signature → `Verify` fails → NO artifacts written (chmod the dir to RO + assert empty)
- [ ] Integration: against an httptest fixture that mocks the netbrain `/enroll` endpoint with a valid bundle; full happy path
- [ ] Integration: real run against local netbrain Stage 1 deploy (BEACON_MTLS_ENABLED=true required — re-enable in test)

### Acceptance Criteria
- `netbrain-beacon enroll` against local netbrain produces a working cert + DEK on disk in < 5 s
- File perms: `beacon.key` = 0600, `dek.bin` = 0600, `beacon.crt` = 0644
- Tampered-bundle test never writes a single artifact file
- `slog` logs from a full enrollment session contain zero matches for `nbb_[A-Za-z0-9]{32,}` (H-3)

### Rollback
- `rm -rf $STATE_DIR` ; revert enrollment package; binary returns to pre-enroll state

---

## Phase 6: Cert auto-rotation

### Objective
Implement the ADR-079 atomic cert rotation strategy. When `cert-status` endpoint returns `recommended_action: "rotate"` or when local cert is within 20% of expiry, trigger a `POST /rotate-cert` and swap the active `*http.Client` atomically.

### Tasks
- [ ] Task 6.1: `internal/transport/cert_lifecycle.go` — `lifecycleRemaining(cert *x509.Certificate, now time.Time) float64` returns 0.0..1.0; trigger rotation at ≤ 0.20
- [ ] Task 6.2: `internal/transport/rotate.go` — `Rotate(ctx) error` — generate new CSR (reusing `internal/enroll/csr.go`), POST `/api/v1/beacons/{id}/rotate-cert`, parse response, persist new cert atomically (tmpfile + rename per ADR-079), build new `*tls.Config` + `*http.Client`, `atomic.Pointer.Swap` to publish
- [ ] Task 6.3: Rotation scheduler — a goroutine inside the daemon (started Phase 8) that polls cert lifecycle every 60 s; idempotent (concurrent rotate calls coalesce via `sync.Once`-equivalent)
- [ ] Task 6.4: Failure handling — if rotation fails, retry up to 3 times over 30 min; if all fail, log + alert via Prometheus counter `netbrain_beacon_cert_rotation_failed_total`; daemon continues on old cert until expiry then halts
- [ ] Task 6.5: Cleanup — after successful rotation, archive the old cert+key as `beacon.crt.prev` for 7 days (revocation window safety), then delete

### Tests
- [ ] Unit: `lifecycleRemaining` table-driven across edge cases (just-issued, exactly 80%, just-expired)
- [ ] Unit: concurrent `Rotate` calls produce exactly one server call (verified via httptest counter)
- [ ] Unit: tmpfile + rename atomicity — kill mid-rotation, restart, beacon still works on old cert
- [ ] Integration: against fixture netbrain that issues a 1-hour cert; beacon rotates within 12 minutes (20% of 1h)
- [ ] Integration: rotation failure → retry → eventually succeeds; counter increments

### Acceptance Criteria
- Rotation completes within 5 s end-to-end
- Zero in-flight request failures during atomic swap (1000-request load test)
- Failed rotation never destroys the working cert
- `beacon.crt.prev` archive cleaned up after 7 days

### Rollback
- Revert cert rotation package; daemon stays on initial cert until expiry (90 days for v1)

---

## Phase 7: Store-and-forward (bbolt)

### Objective
Implement ADR-078's bbolt schema — 4 data buckets (`flows`, `logs`, `snmp`, `configs`) keyed by UUIDv7 + 1 `meta` bucket for cursors and byte totals. Implement priority eviction at 5 GB / 14 d caps. Implement FIFO replay at ≤ 2× normal rate.

### Tasks
- [ ] Task 7.1: `internal/store/schema.go` — bucket names constants; UUIDv7 key generator; record envelope wrapping (timestamp + size + payload bytes)
- [ ] Task 7.2: `internal/store/store.go` — `Put(bucket, payload)`, `Iter(bucket, fn(key, val) error)`, `Delete(bucket, key)`, `Close()`. Single `*bbolt.DB` shared; no `Stats()` on hot path (per research)
- [ ] Task 7.3: `internal/store/meta.go` — `meta` bucket holds `bytes:<bucket>` totals, `cursor:<bucket>` replay position, `evict_last` timestamp; updates atomic with the data write in same `bbolt.Tx`
- [ ] Task 7.4: `internal/store/evict.go` — eviction strategy from ADR-071: when `bytes:total > 5 GB` OR oldest record > 14 d, evict oldest from `flows` first → `logs` → `snmp`; NEVER evict `configs`. Counter `netbrain_beacon_evictions_total{bucket=...}` per evicted record
- [ ] Task 7.5: `internal/store/replay.go` — `Replay(bucket, send func(payload) error)` reads from cursor, advances on success, halts on send error (sender retries handle backoff). Rate limit to 2× normal-rate pacing (token bucket)
- [ ] Task 7.6: `internal/store/recovery.go` — on startup, verify bbolt integrity; if corrupt, rename to `.broken.<timestamp>` and start fresh (log + alert; configs bucket is gone, will re-fetch on next config poll)
- [ ] Task 7.7: Doc — `internal/store/doc.go` covering bbolt single-writer-lock contention pattern, cursor advancement semantics

### Tests
- [ ] Unit: Put → Iter ordering matches insertion order (UUIDv7 monotonicity)
- [ ] Unit: eviction priority — fill to 5 GB with mixed buckets, verify configs untouched
- [ ] Unit: meta byte-total stays exact across Put/Delete cycles (1000 random ops)
- [ ] Unit: Replay survives mid-stream `send` error and resumes from correct cursor
- [ ] Unit: corrupt bbolt → recovery renames and rebuilds; configs bucket loss is logged
- [ ] Property: rapid 10k random Put/Delete/Iter sequences → invariants hold

### Acceptance Criteria
- Write throughput ≥ 5 MB/s sustained on commodity SSD
- Eviction priority enforced under cap pressure (never evicts configs)
- Recovery succeeds from `kill -9` during write (post-tx integrity)
- Coverage ≥ 85% on `internal/store/**`

### Rollback
- Revert store package + delete `beacon-state.bbolt`; daemon falls back to drop-on-disconnect (which is wrong but doesn't crash)

---

## Phase 8: Config poll + heartbeat + device probe

### Objective
Implement the 60 s ± 10 s config poll loop with ETag short-circuit (ADR-070), heartbeat piggyback, and TCP-connect device probe (ADR-072 — median-of-3, ports 22 → 161 → 80). All three loops live in `internal/daemon/`.

### Tasks
- [ ] Task 8.1: `internal/daemon/poll.go` — main loop with `time.Ticker` at 60 s; jitter `±10s` via `rand.Intn` (math/rand allowed here — non-crypto context, plus existing forbidigo carves out daemon/); calls `GetConfig` with `If-None-Match: <last-etag>`
- [ ] Task 8.2: `internal/daemon/apply.go` — on 200, parse new config, classify changes as hot-reload vs restart-required (per ADR-070 field classification); apply hot-reload immediately; surface restart-required to operator via CLI status output
- [ ] Task 8.3: `internal/daemon/heartbeat.go` — on every poll cycle, send `POST /heartbeat` with last_seen + last_config_hash + 5 most recent device probes (per ADR-072)
- [ ] Task 8.4: `internal/probe/probe.go` — `Probe(device DeviceID) (latencyMs int, port int, err error)` using `internal/safe_dial.Dial`; tries port 22 → 161 → 80 (first success wins); 3 probes per cycle, takes median
- [ ] Task 8.5: `internal/probe/scheduler.go` — runs every 5 min; iterates current device inventory from last config; results stashed in-memory buffer consumed by heartbeat
- [ ] Task 8.6: `internal/daemon/dek_rotation.go` — when poll response includes `data_key_rotated: true`, verify the `X-Beacon-DataKey-Signature` header against platform pubkey (using `internal/crypto/platform_verify`); on success, swap active DEK (keep prev DEK for 7-day grace); on failure, log + drop response + alert (M-11 fail-closed)
- [ ] Task 8.7: `internal/daemon/daemon.go` — orchestrator: starts poll loop, probe scheduler, cert-rotation scheduler; wires shutdown via `context.Context`

### Tests
- [ ] Unit: poll with `If-None-Match` → 304 → no apply path executed
- [ ] Unit: poll with new config → apply path runs; classify hot-reload vs restart-required
- [ ] Unit: DEK rotation — valid sig swaps DEK; tampered sig leaves DEK unchanged + counter increments
- [ ] Unit: probe falls through 22→161→80; median-of-3 logic on artificial latencies (5/50/500ms → returns 50)
- [ ] Unit: probe rejects forbidden device IPs via safe_dial (carries through M-9)
- [ ] Integration: full daemon loop against fixture netbrain — 3 cycles, ETag short-circuits 2 of them
- [ ] Integration: kill daemon mid-cycle → graceful shutdown via SIGTERM completes in < 10 s

### Acceptance Criteria
- Config poll p95 ≤ 100 ms against local netbrain
- ETag short-circuit rate ≥ 90% over a 10-min idle window
- DEK rotation with valid sig succeeds; tampered sig is rejected and counted
- Graceful shutdown completes in < 10 s

### Rollback
- Revert daemon package; binary still runs `enroll`/`version`/`status` standalone

---

## Phase 9: Collectors — syslog / netflow / snmp / configs

### Objective
Implement the 4 collector packages with the goroutine pool model from ADR-082. Each collector reads device telemetry and writes to its bbolt bucket via `internal/store`. Per-collector pool sizes: syslog=8w/1000q, netflow=4w/500q, snmp=16w/200q, configs=4w/100q.

### Tasks
- [ ] Task 9.1: `internal/collectors/syslog/server.go` — UDP 514 + TCP 514 listener using `github.com/leodido/go-syslog/v4` parser; pool of 8 workers reading from a buffered channel (1000 cap); each parsed message → bbolt `logs` bucket as gzip-NDJSON line
- [ ] Task 9.2: `internal/collectors/netflow/server.go` — UDP 2055 ingestion via `github.com/netsampler/goflow2/v2`; 4 workers; each batch of flows → pure-Go nfcapd writer (~300 LOC in `internal/collectors/netflow/nfcapd_writer.go`) → bbolt `flows` bucket as binary multipart-ready bytes
- [ ] Task 9.3: `internal/collectors/snmp/poller.go` — `gosnmp` client; 16 workers; polls each device's OID list at the config-specified interval (default 60 s); all dial calls go through `internal/safe_dial`; gathered MIB values → bbolt `snmp` bucket as gzip-NDJSON
- [ ] Task 9.4: `internal/collectors/configs/puller.go` — SSH config-pull via `golang.org/x/crypto/ssh`; 4 workers; `show running-config` (Cisco IOS/IOS-XR) or vendor-equivalent; all dials through `internal/safe_dial`; raw output → bbolt `configs` bucket (deduplication via sha256 cache to avoid storing unchanged configs)
- [ ] Task 9.5: `internal/collectors/sender.go` — single sender goroutine per data-type bucket; drains bbolt via `Replay`, encrypts with current DEK + computes Idempotency-Key, POSTs to `/data/{type}`; advances cursor on 2xx, persists for retry on 4xx/5xx (per error map from Phase 4)
- [ ] Task 9.6: Drop-on-full back-pressure — when worker queue is full, drop the incoming message + increment `netbrain_beacon_collector_drops_total{collector=...}`; do not block input listener
- [ ] Task 9.7: Collector enable/disable based on config — collectors started/stopped per current config's `collectors.{type}.enabled` field; transitions logged with audit detail
- [ ] Task 9.8: `internal/collectors/registry.go` — registry of running collectors for CLI `status` and `collectors list` subcommands

### Tests
- [ ] Unit: syslog parser handles RFC3164 + RFC5424 + malformed inputs (don't crash)
- [ ] Unit: nfcapd writer produces byte-correct file readable by `nfdump` (round-trip fixture)
- [ ] Unit: snmp poller handles v2c + v3 USM (test against `snmpsim` fixture if feasible; otherwise interface-mock)
- [ ] Unit: configs puller deduplicates unchanged configs (no bbolt write on identical sha256)
- [ ] Unit: sender drops on `BEACON_AAD_MISMATCH`; retries on `5xx`; back-pressure increments drops counter on full queue
- [ ] Integration: end-to-end with fake netbrain — beacon receives syslog, encrypts, sends, server verifies decrypted matches sent
- [ ] Integration: kill power mid-batch → on restart, batch resumes from cursor (zero data loss for accepted-by-bbolt records)

### Acceptance Criteria
- Each collector handles its target load (syslog 10k msgs/s, netflow 50k records/s, snmp 1k vars/s, configs 100 devices/min)
- Drop counters are zero under normal load; non-zero only under deliberate overload tests
- Sender p95 < 200 ms for 5 MB encrypted batches against local netbrain
- All 4 collectors disable cleanly via config change

### Rollback
- Revert collectors package; daemon loop continues but ingests no data (collectors are passive consumers)

---

## Phase 10: CLI + observability + packaging

### Objective
Complete the CLI surface (`status`, `collectors list`, `logs tail`); wire Prometheus metrics (full set from `internal/metrics/`); produce all 6 distribution artifacts from D-4 (deb, rpm, Arch PKGBUILD, tarball+systemd, Windows MSI, Docker image).

### Tasks
- [ ] Task 10.1: `internal/admin/cli/status.go` — prints daemon state (enrollment / cert expiry / DEK version / last poll / S&F bucket sizes / collector status per type)
- [ ] Task 10.2: `internal/admin/cli/collectors.go` — `list` (show all collectors + state) and the framework for future `enable`/`disable` (server-pushed config is canonical; CLI flags are informational in v1)
- [ ] Task 10.3: `internal/admin/cli/logs.go` — tail the local slog JSON log file with formatter; supports `--since`, `--level`, `--grep`
- [ ] Task 10.4: `internal/metrics/registry.go` — 18 Prometheus instruments matching 03_PROJECT_SPEC.md §NFR table: enrollment duration, config-poll duration + counter, heartbeat duration, data-push duration + counter, cert rotation success/fail, collector drops, bbolt size by bucket, eviction counters, replay rate, M-9 forbidden-ip-reject counter
- [ ] Task 10.5: `internal/metrics/server.go` — `/metrics` handler bound to `127.0.0.1:9090` (D-8); `--no-metrics` CLI flag disables
- [ ] Task 10.6: Packaging — `packaging/deb/`, `packaging/rpm/`, `packaging/arch/PKGBUILD`, `packaging/tarball/install.sh`, `packaging/systemd/netbrain-beacon.service`, `packaging/windows/installer.wxs` (WiX) producing MSI. CI matrix builds all 6 artifacts on tag push
- [ ] Task 10.7: `docs/runbooks/beacon-operations.md` — enroll / re-enroll / cert-rotation / store-forward inspection / log tail / collector restart / common error scenarios (per discovery deliverable)
- [ ] Task 10.8: README upgrade — install per-OS, first-run quickstart, troubleshooting, link to runbook

### Tests
- [ ] Unit: each CLI subcommand has a happy-path test against an in-memory daemon
- [ ] Unit: metrics registry registers all 18 instruments (compile-time assertion)
- [ ] Integration: `/metrics` endpoint returns valid Prometheus exposition; rejects non-loopback access
- [ ] Integration: each packaging artifact installs cleanly on a fresh VM and runs `netbrain-beacon version`
- [ ] Integration: systemd unit starts beacon; `journalctl -u netbrain-beacon` shows expected log lines

### Acceptance Criteria
- All 18 metrics emit non-zero values during a steady-state daemon run
- `/metrics` bound to 127.0.0.1 only (verified via netstat + remote curl rejected)
- 6 packaging artifacts produced by CI on a tagged release
- Runbook covers all known operator-facing scenarios

### Rollback
- Revert packaging configs; binary still works in `enroll` + `daemon` mode without admin CLI

---

## Test Strategy

### Unit Tests

- **Coverage target:** ≥ 85% on security-hot packages (`internal/crypto/`, `internal/safe_dial/`, `internal/enroll/`, `internal/transport/`); ≥ 70% repo-wide
- **Key areas:**
  - Crypto round-trips (with cross-language fixtures from ADR-080)
  - SSRF allow-list (every forbidden CIDR + DNS rebinding scenario)
  - Cert rotation atomicity (under concurrent reads, mid-rotation kill)
  - bbolt schema invariants (byte-total exactness, eviction priority)
  - Collector back-pressure (drop-counter accuracy)
- **Mocking strategy:** stdlib-first; mock external services (netbrain server) via `httptest`; mock filesystem only when testing atomic-write race conditions; never mock the crypto stdlib

### Integration Tests

- **API contract:** against generated `oapi-codegen` client + real netbrain `/api/v1/beacons/` running locally (Stage 1 deploy from `add-multi-mode-ingestion`)
- **bbolt integration:** full Put → evict → replay cycles
- **leodido/go-syslog:** real UDP listener + canned syslog messages from real network devices (Cisco IOS, Juniper Junos, Linux rsyslog)
- **goflow2 + nfcapd:** UDP NetFlow v5/v9/IPFIX → nfcapd output verified with stock `nfdump` tool

### E2E Tests

- **Critical flows** (each runs end-to-end against local netbrain):
  1. Enroll → daemon → data push → server confirms decrypted matches sent
  2. Kill daemon mid-batch → restart → resumes from bbolt cursor (zero data loss)
  3. Cert rotation under load (1000 RPS) — zero failed requests during swap
  4. Config push with new DEK → beacon verifies sig → swaps DEK → continues
  5. Disconnect for > 14 d simulated → eviction priority kicks in → configs preserved
- **Environment matrix:** linux/amd64 (primary), windows/amd64 (smoke), distroless Docker

### Performance Tests

- **Baseline:** captured at Phase 9 completion (steady-state syslog 10k msgs/s, netflow 50k flows/s)
- **Load scenarios:**
  - Sustained load: 10k syslog/s for 1 h on commodity SSD
  - Burst: 100k syslog/s for 30 s (verify drop-rate stays within configured back-pressure budget)
  - bbolt under disk-near-full: write throughput degrades gracefully (no panics)
- **Memory ceiling:** < 200 MB RSS at steady state; verify via `pprof` heap snapshot

### Cross-Language Byte-Exactness Tests

- **Fixture file:** `tests/fixtures/cross_lang/cross_lang_fixtures.json` — 21 cases (10 UUIDv5 + 5 AES-GCM + 3 ed25519 + 3 canonical-JSON)
- **Refresh procedure** documented in `tests/fixtures/cross_lang/README.md`
- **Startup self-test:** binary loads fixtures + runs all 21 cases at process start; panic on byte-mismatch (per ADR-080)
- **CI gate:** any fixture-case failure blocks PR