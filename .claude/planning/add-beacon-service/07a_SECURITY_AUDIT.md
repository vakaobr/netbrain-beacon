# 07a — Static Security Audit: add-beacon-service

**Date:** 2026-05-12
**Reviewer:** Claude (security skill, Phase 7a)
**Scope:** netbrain-beacon (Go customer-edge binary, ~30 packages). Platform-side
counterpart was audited under `add-multi-mode-ingestion` Phase 7a.
**Method:** OWASP / STRIDE static review of source (no dynamic testing — that
is Phase 7b). `govulncheck`, manual code-walk of every package marked
"security-hot" in 06_CODE_REVIEW.md, cross-reference against the mandatory
hardenings carried forward in 00_STATUS.md.
**Delegation decision:** Inline checklist rather than `security-orchestrator`.
The orchestrator agent description targets dynamic assessment against running
services; Phase 7a is static-source-only and the orchestrator's hunter skills
are not installed locally. Static checklist is the correct tool here.

---

## 1. Threat Model — STRIDE per component boundary

### 1.1 Enrollment ceremony (`internal/enroll/` + CLI)

| Threat | Description | Mitigation | Status |
|---|---|---|---|
| **S**poofing | Attacker forges a bundle to enrol against attacker-controlled platform | Bundle signature verified against embedded pubkey + bundle delivered out-of-band by NetBrain admin; 24 h bundle expiry; expiry check applied AFTER sig-verify so attacker cannot roll the clock back | ✓ |
| **S**poofing | Attacker substitutes the entire bundle (TOFU window) | Documented architectural assumption: operator trusts the out-of-band channel that delivers the bundle. After first enroll, pubkey + CA are pinned to disk and used to verify all subsequent platform responses. Bundle expiry (24h) limits the attack window. | ✓ (documented) |
| **T**ampering | Attacker modifies bundle in transit (e.g., MITM on email) | ed25519 signature over `{bootstrap_token, expires_at, platform_ca_cert}` — tampered bundle is rejected with `ErrBundleSignatureInvalid` BEFORE any state is persisted (`TestEnrollTamperedBundleNoPersist`) | ✓ |
| **R**epudiation | Operator denies running enrollment | Enrollment emits `beacon.enroll.success` / `.failed` slog records with beacon_id and timestamp; platform side logs the bootstrap-token consumption | ✓ |
| **I**nformation Disclosure | `--bundle <b64>` on command-line is captured in `ps`, shell history, audit logs | Token is short-lived (24h) and one-time-use (platform marks consumed). No `--bundle-file` alternative today. **Finding S-1 (Low).** | ⚠ |
| **I**nformation Disclosure | Bundle pubkey + CA + bootstrap_token logged accidentally | H-3 redactor scrubs 9 sensitive slog keys + regex sweeps `nbb_[A-Za-z0-9_-]{16,}` in messages and string attrs; group values recursed | ✓ |
| **D**enial of Service | Operator runs enroll repeatedly | Idempotency: `CheckNotEnrolled` reads existing metadata + refuses double-enroll unless `--force`. Zero-UUID + corrupt metadata treated as fresh so recovery works | ✓ |
| **E**levation of Privilege | Enrollment writes secret files world-readable | `Persist` chmod 0600 BEFORE rename for `beacon.key` + `dek.bin`; 0700 on state dir; chmod-before-rename closes the 0644 race window | ✓ |

### 1.2 mTLS transport + cert rotation (`internal/transport/`)

| Threat | Description | Mitigation | Status |
|---|---|---|---|
| **S**poofing | Server impersonation via untrusted CA | `RootCAs` set to pinned platform CA (NOT system trust store); refuses any cert not chained to it. `ErrNoCertsLoaded` rejects empty CA bundles | ✓ |
| **S**poofing | TLS downgrade to 1.2 with weak cipher | `MinVersion: tls.VersionTLS13` hard-coded. Test asserts handshake fails against TLS 1.2-only server (`TestNewClientRefusesTLS12`) | ✓ |
| **T**ampering | In-flight request body tampering | TLS 1.3 AEAD provides integrity; AAD binds DEK-version + idempotency-key for data payloads (M-2-AAD) | ✓ |
| **R**epudiation | Beacon denies sending a batch | Idempotency-Key (deterministic UUIDv5) included in every POST; platform-side dedupe makes "did beacon send X?" answerable from platform logs | ✓ |
| **I**nformation Disclosure | Private key 0644 after rotation | `atomicFileWrite` in `rotate.go` chmod-before-rename, 0600 for `beacon.key.new`. Same pattern as enroll | ✓ |
| **I**nformation Disclosure | `.prev` archived keys remain after grace window | `Rotator.CleanupPrev()` removes both .prev files after 7-day window. Daemon scheduler responsibility (Phase 8 wiring) | ✓ |
| **D**enial of Service | Concurrent goroutines hammering /rotate-cert | Coalescing gate via `atomic.Bool.CompareAndSwap`: 10 concurrent callers → 1 server hit (TestRotateConcurrencyCoalesces) | ✓ |
| **D**enial of Service | Server returns garbage cert; beacon left without a working pair | Fail-closed: `ParseCertPEM` validates BEFORE touching disk; 5xx on /rotate-cert leaves disk state unchanged. ZERO files touched on rotation failure. | ✓ |
| **E**levation of Privilege | Crash mid-rotation produces unusable state | Recovery via .prev fallback (planned Phase 8 helper). Today: crash between archive and promote leaves `.prev = live, .new = pending` — daemon restart re-reads from primary or .prev based on parse success. **Finding T-1 (Info).** | ⚠ (documented for follow-up) |

### 1.3 DEK rotation signature channel (`internal/daemon/dek_verify.go` + `poll.go`)

| Threat | Description | Mitigation | Status |
|---|---|---|---|
| **S**poofing | MITM (nginx TLS-terminator compromise) delivers rogue DEK | M-11: ed25519 signature over canonical-JSON of `{beacon_id, data_key_b64, data_key_version, issued_at}` — signed by platform signing key, verified against beacon-pinned pubkey BEFORE acting on rotation | ✓ |
| **T**ampering | Signature byte flip | `ed25519.Verify` rejects; `errors.Join(ErrDEKSignatureInvalid, inner)`. P1 security counter `beacon_dek_verify_failed_total` increments. New DEK is NOT swapped (fail-closed). | ✓ |
| **I**nformation Disclosure | Empty `data_key_b64=""` payload divergence beacon-vs-platform | F-4 verified: both sides intentionally sign empty string today (GET /config does not deliver rotated DEK material in body). Paired comments + `TestDEKVerifyEmptyDataKeyB64Contract` lock in the contract. | ✓ |
| **D**enial of Service | Garbage X-Beacon-DataKey-Signature header on every poll | Verify failure is logged + counted but the poll cycle CONTINUES (don't take daemon down for one bad header). The DEK version is preserved so the daemon keeps using the previous DEK. | ✓ |

### 1.4 Cryptographic envelope (`internal/crypto/`)

| Threat | Description | Mitigation | Status |
|---|---|---|---|
| **S**poofing | Attacker forges a batch that decrypts cleanly | AES-GCM AEAD authenticates ciphertext + AAD; tampered → `ErrEnvelopeAuthFailed`. AAD layout `[dek_version] ++ idempotency_key` binds the DEK version (closes M-11 downversion attack) | ✓ |
| **T**ampering | IV reuse leaks plaintext XOR | M-4: `iv := make([]byte, 12); rand.Read(iv)` for every Encrypt; `encryptWithIV` is unexported, only used by fixture tests + cross-language verifier. 1000-iteration uniqueness test asserts no collision. | ✓ |
| **I**nformation Disclosure | Decompression bomb (4 KB gzip → 100 MB plaintext) | M-6: streaming `gzip.NewReader` with per-call byte cap; `io.ReadAll(gzip.NewReader(...))` is forbidden via `forbidigo` lint. Regression test: 100 MB bomb aborts in 0.31s. | ✓ |
| **E**levation of Privilege | Cross-tenant batch slips through | Beacon does not handle tenant boundaries (single-tenant per install per ADR-067). Tenant cross-talk is a platform-side concern, covered in add-multi-mode-ingestion H-2 audit. | ✓ |

### 1.5 SSRF chokepoint (`internal/safedial/`)

| Threat | Description | Mitigation | Status |
|---|---|---|---|
| **S**poofing | DNS rebinding: hostname resolves to one IP at lookup, another at dial | Resolve-ONCE-then-dial-literal — the resolved IP is passed to `net.Dial` as a literal, never the hostname. Test asserts Resolver called exactly once. | ✓ |
| **T**ampering | Hostname containing forbidden IP (e.g., resolves to 169.254.169.254 cloud IMDS) | M-9: 9-CIDR allow-list `IsForbidden` applied to EVERY resolved IP; entire dial rejected if ANY resolved IP is forbidden (defence-in-depth — no "pick the good ones" split) | ✓ |
| **I**nformation Disclosure | IPv4-mapped IPv6 bypass (`::ffff:127.0.0.1`) | `netip.Addr.Unmap()` canonicalizes BEFORE prefix check. Loopback v6 wrap correctly rejected. | ✓ |
| **D**enial of Service | net.Dial outside safedial (bypass the chokepoint) | `forbidigo` lint rule: `net.Dial*` forbidden outside `internal/safedial/**`. ONE audited carve-out in `transport/` (platform server dial) — distinct allow-list (no RFC1918 block) because platform URL is operator-supplied | ✓ |
| **E**levation of Privilege | Beacon configured to probe public IPs at attacker's direction | Architectural choice: config arrives through mTLS + M-11-signed channel; an attacker needs to compromise the platform to inject configs. RFC1918 ranges NOT blocked by design (they ARE the device IPs). Documented in ADR-081. | ✓ (documented) |

### 1.6 Store-and-forward (`internal/store/`)

| Threat | Description | Mitigation | Status |
|---|---|---|---|
| **S**poofing | Attacker substitutes bbolt file with rogue data | bbolt file is plaintext-at-rest in 0700 state dir; OS file perms are the trust boundary. Documented in ADR-078 as known trust assumption. | ✓ (documented) |
| **T**ampering | Attacker mutates buffered records before send | Records are encrypted only at SEND time (sender wraps in AES-GCM envelope just before POST). Tampering with a buffered record => sender encrypts the tampered bytes, platform receives + decrypts cleanly. **Finding ST-1 (Info).** This matches the documented trust model — host trust covers it. | ⚠ (documented) |
| **R**epudiation | Replay-attack: same batch sent twice | Idempotency-Key in headers + platform-side dedupe. UUIDv5 derivation byte-compatible cross-language (21 fixture cases pass). | ✓ |
| **I**nformation Disclosure | bbolt file readable by other local users | State dir 0700, bbolt file 0600 (bbolt default). systemd unit pins `User=netbrain-beacon` + `ProtectSystem=strict` + `StateDirectoryMode=0700`. | ✓ |
| **D**enial of Service | Unbounded buffering fills disk | 5 GB cap + 14-day age cap per ADR-071; eviction `flows → logs → snmp` priority; configs bucket NEVER evicted. Tested under 1000-record-random-op shadow consistency check. | ✓ |
| **D**enial of Service | bbolt corrupt-on-disk halts the daemon | `Open` rename-aside + create fresh on bbolt.Open error. Returns `ErrCorrupt` informational; caller sees a working Store. | ✓ |
| **E**levation of Privilege | `b.Stats().KeyN` panic crashes daemon | F-5 closed: `Count()` rewritten to read `meta:records:<bucket>` counter (O(1), never calls bbolt.Stats). Counter exact across Put/Delete/Replay/Evict (TestCountTracksMetaRecordsCounter). | ✓ |

### 1.7 Collectors — syslog (`internal/collectors/syslog/`)

Syslog handles the most untrusted input surface in the beacon: arbitrary
bytes from arbitrary devices on the customer LAN.

| Threat | Description | Mitigation | Status |
|---|---|---|---|
| **S**poofing | Source-IP spoofing (UDP) → forged log entries | The beacon does NOT trust the sender beyond "received from the LAN"; the platform side is the source of truth for tenant-scoping. Not the beacon's threat to mitigate. | ✓ (out of scope) |
| **T**ampering | Malicious device floods workers | Drop-on-full back-pressure: bounded channel (1000), 8 workers, `droppedFull` counter increments per drop. Counter exposed via `Stats` and Prometheus. | ✓ |
| **R**epudiation | Logs missing during DoS | `droppedFull` + `parseFails` counters tell ops exactly how many were lost and why. | ✓ |
| **I**nformation Disclosure | Parsed message includes credentials from the device | The beacon forwards opaquely; redaction is the platform side's job (or DataAnonymizer for LLM-call paths). On the beacon side, raw bytes never appear in slog output (only summary stats). | ✓ |
| **D**enial of Service | TCP stream with no `\n` → unbounded buffer growth | `bufio.Reader.ReadBytes('\n')` does NOT enforce a buffer cap; the SetReadDeadline (30s) bounds idle time but a slow-drip attacker streaming data can extend it indefinitely. **Finding SY-1 (Medium).** | ✗ |
| **D**enial of Service | TCP accept loop spawns 1 goroutine per conn with no cap | 10000 concurrent connections = 10000 goroutines + 10000 64 KB buffers ~640 MB. **Finding SY-2 (Medium).** | ✗ |
| **D**enial of Service | UDP packets larger than 64 KB truncated | UDP max payload is 64 KB; truncation is expected. Logged via Warn but doesn't crash. | ✓ |
| **E**levation of Privilege | Parser bug crashes the worker | leodido v4 is a third-party parser; CVE check via govulncheck clean today. Worker `defer` ensures parser panic doesn't kill the whole pool — actually it would, since there's no recover. **Finding SY-3 (Low).** | ⚠ |

### 1.8 Daemon orchestrator + heartbeat (`internal/daemon/`)

| Threat | Description | Mitigation | Status |
|---|---|---|---|
| **S**poofing | Heartbeat carries beacon_id, not cert | Heartbeat goes over the mTLS transport; the platform identifies the beacon by cert-subject (H-2 cross-beacon-IDOR). Beacon-side ID in body is informational. | ✓ |
| **T**ampering | Server returns junk in /config | Body parse failure → poll cycle errors out (logged) + retry with backoff. Config hash mismatch surfaces as "modified" without breaking anything; the bad config eventually gets replaced. | ✓ |
| **R**epudiation | Clock skew lies | Server's Date header observed and `SetClockSkew` records the delta. Heartbeat carries clock_skew_seconds — anomalies visible platform-side. | ✓ |
| **I**nformation Disclosure | sanitizeBody truncates server errors | 2 KB truncation cap with `[truncated]` marker. Doesn't bleed multi-MB attacker-controlled bodies into local logs. | ✓ |
| **D**enial of Service | Server-side outage → tight retry loop | 1 s → 30 s exponential backoff; reset on successful poll. | ✓ |

### 1.9 Sender (`internal/collectors/sender/`)

| Threat | Description | Mitigation | Status |
|---|---|---|---|
| **T**ampering | Bbolt record tampered between Put and send | Sender encrypts at send time with current DEK + AAD; AAD binds dek_version + idempotency_key. Platform validates AAD → tampered record either decrypts to bad plaintext OR fails GCM-auth. | ✓ |
| **R**epudiation | Records delivered twice via retry | Idempotency-Key + platform dedupe; cursor advances atomically with delete in `commitDelivered` so a crash mid-batch resumes from the right place. | ✓ |
| **D**enial of Service | Sender stalls on transient errors | Send returns error → halts THIS replay; outer loop retries; meanwhile new records accumulate up to the 5 GB cap → eviction kicks in. No goroutine leak. | ✓ |

### 1.10 Admin CLI + metrics (`internal/admin/cli/` + `internal/metrics/`)

| Threat | Description | Mitigation | Status |
|---|---|---|---|
| **I**nformation Disclosure | `status --check-server` includes server's response body in error | `r.Error = fmt.Sprintf("HTTP %d: %s", resp.StatusCode, string(body))` with `io.LimitReader(resp.Body, 4096)` — bounded; only shown to local operator. | ✓ |
| **I**nformation Disclosure | `/metrics` exposes beacon ID + version + counts | Default bind `127.0.0.1:9090` (loopback only). Operator can override via `--metrics-bind` to expose to LAN — documented in runbook but no warning. **Finding M-1 (Low — defence-in-depth).** | ⚠ |
| **D**enial of Service | /metrics slowloris | Read/write/idle timeouts set: 10 s read, 10 s write, 30 s idle, 5 s read-header. | ✓ |
| **D**enial of Service | logs --follow hangs on a wedged file descriptor | F-8 closed: ctx-cancel returns nil promptly; rewrite uses bufio.Reader + Ticker + select. | ✓ |

---

## 2. OWASP Top 10 (2021) — checklist

| ID | Category | Beacon-relevant? | Status | Notes |
|---|---|---|---|---|
| A01 | Broken Access Control | Indirectly — beacon is a client | ✓ | Beacon doesn't enforce access control. Platform side covered by add-multi-mode-ingestion audit. Beacon refuses double-enroll w/o --force; --check-server endpoint is unauthenticated locally but only reads on-disk artifacts the operator already controls. |
| A02 | Cryptographic Failures | Yes — primary concern | ✓ | AES-GCM with CSPRNG IVs (M-4) + AAD binding + AEAD authentication; ed25519 signatures (bundle + M-11 DEK rotation); TLS 1.3 only; stdlib crypto only (no third-party AEAD); private keys 0600; no key material in logs (H-3 redactor + sweep regex). 21 cross-language byte-exactness fixtures verify Python↔Go agreement. |
| A03 | Injection | Limited surface | ✓ | No SQL/NoSQL. Path injection in CLI flags? Operator-controlled — file paths supplied via CLI are bounded to state-dir convention. JSON-encode of syslog parsed fields is via stdlib `json.Marshal` — no string concat. Log injection from syslog: messages stored as JSON values (not interpolated). |
| A04 | Insecure Design | Reviewed in 03_ADR-077..082 | ✓ | TOFU at enroll time, cert rotation atomicity, drop-on-full back-pressure, fail-closed signature verify. Documented architectural assumptions stated in ADRs. |
| A05 | Security Misconfiguration | Yes | ✓ | systemd unit: NoNewPrivileges, ProtectSystem=strict, RestrictAddressFamilies, MemoryDenyWriteExecute, syscall filter. Distroless `static-debian12:nonroot` (UID 65532, no shell, no package manager). State dir 0700, secret files 0600. `--metrics-bind` defaults loopback. ONE caveat: operator can override to expose metrics — see M-1 finding. |
| A06 | Vulnerable/Outdated Components | Audit clean | ✓ | `govulncheck ./...` → **No vulnerabilities found**. Direct deps: go-syslog v4, goflow2 v2.2.6, gosnmp v1.40, bbolt v1.4.1, oapi-codegen-runtime v1.21.0, prometheus/client_golang v1.20, testify v1.10, uuid v1.6.0, x/crypto/ssh, x/time/rate. Go toolchain 1.26.3. |
| A07 | Identification / Authentication Failures | Yes — enrollment + mTLS | ✓ | Bootstrap token: 24h expiry, one-time-use (platform marks consumed), CSRF-immune (single-step POST + Bearer header). mTLS cert: empty-subject CSR, platform-derived identity. Cert auto-rotation at 80% lifetime with atomic swap. Re-enrollment guard prevents accidental double-enroll. |
| A08 | Software / Data Integrity Failures | Yes | ✓ | ed25519 verify on enrollment bundle (rejects unsigned in prod); X-Beacon-DataKey-Signature verify on every /config response (M-11 fail-closed); cross-language byte-exactness fixtures (canonical-JSON + AEAD + signatures) panic on regression. `-trimpath` + `-buildid=` in build → reproducible binary. |
| A09 | Security Logging / Monitoring | Yes | ✓ | 18 Prometheus instruments (enroll/poll/heartbeat outcomes; DEK verify failures as P1 security counter; cert rotation; store bytes/records/evictions; sender delivered/failed; collector dropped; safedial rejected; build_info). H-3 redactor catches accidental token logging. Two-tier severity in slog levels (WARN for retryable, ERROR for fail-closed paths). |
| A10 | SSRF | Yes — primary concern (M-9) | ✓ | `internal/safedial` chokepoint with `forbidigo` lint enforcement; resolve-once-dial-literal closes DNS rebinding; 9 forbidden CIDRs cover loopback/link-local/IMDS/multicast/unspecified for both v4 and v6; IPv4-mapped v6 unmap. ONE audited carve-out in transport/ for platform-server dial. |

---

## 3. Dependency audit — `govulncheck`

```
$ go run golang.org/x/vuln/cmd/govulncheck@latest ./...
No vulnerabilities found.
```

Toolchain: Go 1.26.3 windows/amd64. govulncheck v1.3.0. Run against all
packages (cmd/* + internal/*). Clean across direct + transitive deps.

---

## 4. Code-level security review checklist

| Check | Status | Evidence |
|---|---|---|
| Input validation on all external data | ✓ | Bundle: required-field check + size; OpenAPI client validates response shapes via oapi-codegen; syslog: leodido parser rejects malformed input; safedial: port + CIDR validation; envelope: minimum-length + version-byte check |
| Output encoding | n/a | Beacon emits JSON (stdlib encoder, safe) and Prometheus text (promhttp safe). No HTML rendering. |
| Authentication required on protected endpoints | ✓ | mTLS on every platform RPC; /metrics + /healthz are loopback-only by default. Local CLI has no remote surface. |
| Authorization at resource level | n/a | Beacon is a client; platform enforces. H-2 cross-beacon-IDOR is platform-side concern. |
| Rate limiting on public/sensitive endpoints | ✓ | Cert rotation coalesces via atomic.Bool (1 concurrent rotation max); poll backoff 1→30 s; rotator backoff + retry; no public endpoint on the beacon side. |
| CORS | n/a | No browser-callable endpoints. |
| Secrets not hardcoded | ✓ | Bootstrap token from CLI flag (S-1 finding flags the CLI form); cert/key/DEK on disk after enrollment; no fixtures or test seeds in production code paths. |
| SQL parameterization | n/a | No SQL. |
| File uploads validated | n/a | No upload endpoints. |
| Error messages don't leak internals | ✓ | `sanitizeBody(body []byte) string` truncates to 2 KB with `[truncated]` marker before embedding in logs; certificate parse errors are wrapped without exposing PEM bytes. |

---

## 5. Data privacy

| Check | Status | Notes |
|---|---|---|
| PII identification + handling | ✓ | Beacon forwards device telemetry (IPs, hostnames, syslog text) opaquely. PII redaction is the platform side's job (DataAnonymizer for LLM paths; field-level redaction in routes). The beacon itself touches no end-user PII directly. |
| Retention | ✓ | 5 GB / 14-day cap on data buckets; configs bucket is never evicted (legitimate persistent state). |
| User consent / deletion | n/a | Beacon is infrastructure; the install itself is the consent grant. Operator can `rm -rf /var/lib/netbrain-beacon` per the uninstall runbook to delete all beacon-held data. |
| GDPR/CCPA | indirect | The beacon doesn't enrich data with new PII — it relays exactly what devices already emit. Compliance posture is governed by the platform's data-handling policy. |

---

## 6. Findings

### 6.1 Severity ranking

| ID | Severity | Title | CWE |
|---|---|---|---|
| **SY-1** | 🔵 Medium | Syslog TCP reader: `bufio.Reader.ReadBytes` without per-line cap → unbounded memory growth on slow-drip stream | CWE-770 |
| **SY-2** | 🔵 Medium | Syslog TCP listener: no per-source connection cap; 10k concurrent TCP conns → ~640 MB goroutine + buffer growth | CWE-770 |
| **SY-3** | ⚪ Low | Syslog worker has no panic-recover; a parser-bug panic in leodido v4 would terminate the daemon (govet-clean today but defence-in-depth) | CWE-754 |
| **S-1** | ⚪ Low | `--bundle <b64>` CLI flag captures bootstrap token in `ps`, shell history, audit logs. 24h-expiry + one-time-use limits blast radius. | CWE-214 |
| **M-1** | ⚪ Low | `--metrics-bind` allows operators to expose `/metrics` to LAN with no auth; runbook silent on the trade-off | CWE-200 |
| **T-1** | ⚪ Informational | No documented Recovery() helper for crash-during-rotation (.prev fallback). Planned but unwired. | n/a |
| **ST-1** | ⚪ Informational | bbolt records are plaintext at rest — tampering by a local-root attacker yields encrypted-on-send bytes that decrypt as the tampered content. Documented in ADR-078 as host-trust assumption. | n/a |

### 6.2 Specific remediations

**SY-1** — Replace `bufio.Reader.ReadBytes('\n')` with `bufio.Scanner` configured
with `SetBuffer(make([]byte, 64*1024), maxLineSize)` and a sane maxLineSize
(e.g., 256 KB — covers extreme RFC 5424 messages without unbounded growth).
On `bufio.ErrTooLong`, drop the line + increment `parseFails`. Test: send a
1 MB stream with no `\n`, assert the connection is closed + counter ticks.

**SY-2** — Add `MaxTCPConnections` (default 256) to `Config`; gate accept-loop
with a `chan struct{}` semaphore acquired before `go handleTCPConn` and
released in defer. On semaphore-full, accept + immediately close with a
`syslog.tcp_conn_dropped` counter increment.

**SY-3** — Wrap the worker body in `defer recover()` that logs + counts the
panic + continues the pool (don't re-panic). Same pattern in netflow/snmp
workers when they land.

**S-1** — Add `--bundle-file <path>` alternative that reads the base64 string
from a file (with mode-check warning if file is world-readable). Update
runbook to recommend the file form for production; document the CLI form
as dev-only.

**M-1** — Add a startup WARN log when `BindAddr != "127.0.0.1:9090"` and
the host is non-loopback. Document in runbook: exposing metrics requires
a TLS-front terminator or firewall ACL. Optional follow-up: add a
`--metrics-tls-cert / --metrics-tls-key` pair so operators have a built-in
TLS option.

**T-1** — File as separate follow-up `add-beacon-cert-rotation-recovery`;
the helper reads cert+key from primary or `.prev` based on parse success.

**ST-1** — No code change; ensure CLAUDE.md + runbook explicitly call
host-trust as an assumption.

---

## 7. Required-remediation triage

| Severity | Block ship? | Reason |
|---|---|---|
| 🔴 Critical | n/a | None. |
| 🟡 High | n/a | None. |
| 🔵 Medium (×2) | **Yes, fix in /harden** | SY-1 + SY-2 are easy fixes (~30 min each) with clear test coverage; shipping without them leaves a known DoS surface against the most-exposed beacon component. |
| ⚪ Low (×3) | Defer to follow-up issues | Defence-in-depth; not exploitable at the threat-model levels documented in ADRs. |
| ⚪ Informational (×2) | Defer to follow-up issues | Architectural assumptions, already documented. |

---

## 8. Summary

```
| Severity      | Count |
|---------------|-------|
| 🔴 Critical   | 0     |
| 🟡 High       | 0     |
| 🔵 Medium     | 2     |
| ⚪ Low        | 3     |
| ⚪ Info       | 2     |
```

### Verdict: ⚠ CONDITIONAL PASS

The beacon meets every mandatory P1 hardening (M-4 / M-6 / M-9 / M-11 +
mTLS key 0600) carried forward from `beacon-protocol-and-enrollment`.
Cryptography is correct (21 cross-language fixtures green); SSRF surface
is locked behind `internal/safedial` with `forbidigo` enforcement;
secrets are scrubbed from logs (H-3); systemd sandbox + distroless
runtime minimize the privileged blast radius. `govulncheck` clean
across all dependencies. No Critical or High findings.

The condition: **before Phase 7b dynamic pentest, fix SY-1 + SY-2** in
`/security/harden add-beacon-service`. They are DoS-class regressions in
the syslog TCP listener — the most exposed surface on the beacon — and
both are 30-minute fixes with clear test patterns. Shipping them in the
same release as the rest of `add-beacon-service` keeps the threat model
honest.

The Low + Info findings (S-1 CLI-bundle flag, M-1 metrics-bind LAN,
SY-3 worker panic-recover, T-1 rotation recovery helper, ST-1 plaintext
buffer at rest) are defense-in-depth items and can be filed as
follow-up issues without blocking ship.

### Required remediations (block ship)

1. **SY-1** — Cap per-line read size in syslog TCP reader (`bufio.Scanner`
   with `maxLineSize` ~256 KB; drop + count on overrun).
2. **SY-2** — Cap concurrent TCP connections in syslog listener
   (`MaxTCPConnections` default 256; semaphore-gated accept loop).

### Accepted risks (filed as follow-up)

1. **SY-3** — Worker panic-recover defence-in-depth.
2. **S-1** — `--bundle-file` alternative for CLI hygiene.
3. **M-1** — Metrics-bind LAN warning + optional TLS.
4. **T-1** — Cert-rotation crash-recovery helper.
5. **ST-1** — Plaintext-at-rest documented host-trust assumption.

### Out of scope for 7a (deferred to 7b / 7c)

- **Phase 7b co-pentest** — dynamic exploit validation against staging,
  co-tested with `add-multi-mode-ingestion`. Mandatory per
  `pending_beacon_pentest.md`. Carries the H-1 nginx REPLACE confirmation,
  H-2 cross-beacon IDOR, H-4 token replay, M-6 gzip-bomb-at-data, M-9
  SSRF-from-config tests.
- **Phase 7c AI threat model** — **NOT APPLICABLE.** The beacon has zero
  LLM call paths (Go binary, no embedded inference). 00_STATUS.md
  confirms this exclusion.