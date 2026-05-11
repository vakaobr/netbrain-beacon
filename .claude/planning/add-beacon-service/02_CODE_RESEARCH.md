# Code Research: add-beacon-service

**Phase:** 2 (Research) | **Date:** 2026-05-10 | **Risk:** High
**Repo posture:** greenfield Go (only `initial commit` + 16-byte README); contract is locked in sibling `netbrain` repo.

This document grounds every Phase 3+ decision in (a) the netbrain-side contract surface that the Go beacon must interoperate with byte-for-byte, (b) the Go ecosystem libraries the beacon will depend on, and (c) prior art for long-lived edge agents. All file references are absolute paths into `c:/Users/Anderson Leite/code/`.

---

## 1. Codebase Analysis

The Go repo is empty, so this section pivots to the **contract counterparty** — the netbrain platform side which has shipped `WORKFLOW COMPLETE 2026-05-10` (tag `beacon-server-v1.0`). Every wire-format detail below is verified against actual source.

### 1.1 Server-side endpoint inventory (17 operations, OpenAPI 3.1)

Source: `c:/Users/Anderson Leite/code/netbrain/services/api-gateway/openapi/beacon-v1.yaml` (1276 lines).

| # | Method | Path | Auth | Tag | Beacon-side relevance |
|---|--------|------|------|-----|----------------------|
| 1 | POST | `/api/v1/beacons/enrollment-tokens` | bearerJwt | beacon-enrollment | **Admin (server-only).** Beacon never calls. |
| 2 | GET | `/api/v1/beacons/enrollment-tokens` | bearerJwt | beacon-enrollment | **Admin (server-only).** |
| 3 | DELETE | `/api/v1/beacons/enrollment-tokens/{token_id}` | bearerJwt | beacon-enrollment | **Admin (server-only).** |
| 4 | POST | `/api/v1/beacons/enroll` | bootstrapToken | beacon-enrollment | **BEACON CALLS.** One-shot at install. |
| 5 | GET | `/api/v1/beacons` | bearerJwt | beacon-admin | **Admin (server-only).** |
| 6 | GET | `/api/v1/beacons/{beacon_id}` | bearerJwt | beacon-admin | **Admin (server-only).** |
| 7 | DELETE | `/api/v1/beacons/{beacon_id}` | bearerJwt | beacon-admin | **Admin (server-only).** |
| 8 | PATCH | `/api/v1/beacons/{beacon_id}/config` | bearerJwt | beacon-admin | **Admin (server-only).** |
| 9 | GET | `/api/v1/beacons/{beacon_id}/config` | mTls | beacon-control | **BEACON CALLS.** 60s ± 10s with `If-None-Match`. |
| 10 | POST | `/api/v1/beacons/{beacon_id}/rotate-key` | bearerJwt | beacon-admin | **Admin (server-only).** |
| 11 | POST | `/api/v1/beacons/{beacon_id}/heartbeat` | mTls | beacon-control | **BEACON CALLS.** Piggybacks with config poll. |
| 12 | GET | `/api/v1/beacons/{beacon_id}/cert-status` | mTls | beacon-control | **BEACON CALLS.** Per-heartbeat. |
| 13 | POST | `/api/v1/beacons/{beacon_id}/cert/rotate` | mTls | beacon-control | **BEACON CALLS.** At 80% lifetime. |
| 14 | POST | `/api/v1/beacons/{beacon_id}/data/logs` | mTls | beacon-data | **BEACON CALLS.** gzip-NDJSON encrypted. |
| 15 | POST | `/api/v1/beacons/{beacon_id}/data/flows` | mTls | beacon-data | **BEACON CALLS.** multipart binary nfcapd, encrypted per part. |
| 16 | POST | `/api/v1/beacons/{beacon_id}/data/configs` | mTls | beacon-data | **BEACON CALLS.** JSON encrypted. |
| 17 | POST | `/api/v1/beacons/{beacon_id}/data/snmp` | mTls | beacon-data | **BEACON CALLS.** JSON encrypted. |

**Beacon client surface = 9 of 17 operations.** Generate the full client (codegen ignores op groups), but only wire `enroll` + `mTls` operations into the daemon.

### 1.2 Wire format details (verified)

#### Envelope byte format

Verified in `c:/Users/Anderson Leite/code/netbrain/services/api-gateway/src/crypto/dek_envelope.py:30-39`:

```
[ ver(1B) | dek_v(1B) | iv(12B) | ciphertext | tag(16B) ]
```

- `ver` = `0x01` constant (line 32). Reject `parse()` if anything else (line 124-125 raises `EnvelopeFormatError`).
- `dek_v` = the active DEK version at encrypt time — used by the server during the 7-day rotation grace window to look up the right key.
- `iv` = 96-bit IV via Python `secrets.token_bytes(12)` (line 104). **Go must use `crypto/rand.Read(iv[:12])` — never `math/rand`.** This is the M-4 hardening.
- `ciphertext` length = plaintext length (GCM is a stream cipher).
- `tag` = 16-byte (128-bit) GCM auth tag, appended last.
- Minimum envelope length = `1 + 1 + 12 + 0 + 16 = 30 bytes` (`_MIN_ENVELOPE_LEN`, line 38).

Go construction:

```go
// Pseudocode for the encrypt path; see Section 5 risks for cross-language gotchas.
iv := make([]byte, 12)
if _, err := crand.Read(iv); err != nil { return nil, err }
aead, _ := cipher.NewGCM(aes.NewCipher(dek)) // 32-byte key → AES-256
ctAndTag := aead.Seal(nil, iv, plaintext, aad) // ct||tag (16-byte tag)
envelope := append([]byte{0x01, byte(dekV)}, iv...)
envelope = append(envelope, ctAndTag...) // ct||tag
```

#### AAD construction

Verified in `c:/Users/Anderson Leite/code/netbrain/services/api-gateway/src/crypto/dek_envelope.py:66-77` (`make_aad`):

```
AAD = bytes([dek_version]) || idempotency_key.bytes  // 1 + 16 = 17 bytes
```

- `idempotency_key.bytes` is the 16-byte raw form of the UUID (Python `UUID.bytes`, equivalent to Go `uuid.UUID.MarshalBinary()` or simply `uuid[:]`).
- The dek_v byte is in the AAD **separately** from being in the envelope header — this prevents a downgrade attack where an attacker swaps the envelope's dek_v byte to use an older, possibly weaker, key.

Go construction:

```go
aad := append([]byte{byte(dekVersion)}, idempotencyKey[:]...) // 17 bytes
```

#### Idempotency-Key UUIDv5 input

Verified in `c:/Users/Anderson Leite/code/netbrain/services/api-gateway/src/crypto/idempotency.py:34-49`:

```
NS_BEACON_BATCH = UUID("c4d2c5e0-1c9b-5b9e-8d0a-7f3a4e1c2b3d")
name = beacon_id.bytes + sha256(plaintext).digest()  // 16 + 32 = 48 bytes
key = uuid5(NS_BEACON_BATCH, name.hex())             // hex string passed
```

**Critical gotcha:** Python `uuid5(ns, name)` accepts a *string*. The code at line 49 passes `name.hex()` — a 96-char hex string — not the raw bytes. Go's `uuid.NewSHA1(ns, []byte(...))` accepts bytes. Therefore, the Go side MUST pass `[]byte(hex.EncodeToString(beaconID[:] + sha256.Sum256(plaintext)[:]))`, not the raw 48 bytes. This is the #1 cross-language byte-exactness pitfall — see Section 5 risks.

Namespace as 16 raw bytes (verified by `UUID.bytes` of the constant): `c4 d2 c5 e0 1c 9b 5b 9e 8d 0a 7f 3a 4e 1c 2b 3d`.

#### ed25519 signed bundle + DEK rotation header

Verified in `c:/Users/Anderson Leite/code/netbrain/services/api-gateway/src/crypto/platform_signer.py`:

- **Wire form:** `X-Beacon-DataKey-Signature: <base64(ed25519_signature)>` (lines 119-127, `sign()` returns base64).
- **Payload signed:** canonical JSON of `{data_key_b64, data_key_version, beacon_id, issued_at}` — built by `canonicalize_payload()` (lines 110-116) using `json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)`.
- **Public key wire format:** SPKI/PEM (lines 67-72, `serialize_public_key_pem`). Beacon pins this at enrollment in the bundle field `platform_pubkey_pem`. M-11 (DEK signature verify before accepting a rotated DEK) MUST verify against this pinned key.
- **Go verify:**
  ```go
  pub, _ := x509.ParsePKIXPublicKey(pem.Decode(pubkeyPem).Bytes) // returns ed25519.PublicKey
  sig, _ := base64.StdEncoding.DecodeString(headerValue)
  msg := canonicalJSON(payload) // sort keys, no whitespace, ASCII-only
  if !ed25519.Verify(pub.(ed25519.PublicKey), msg, sig) { reject }
  ```

#### Streaming gunzip with byte cap

Verified in `c:/Users/Anderson Leite/code/netbrain/services/api-gateway/src/ingestion/streaming_gunzip.py`:

- **Mechanism:** chunked `gz.read(64 * 1024)` loop; abort raises `PayloadTooLarge` as soon as `len(out) > max_bytes` (lines 75-83).
- **Per-endpoint caps from server:** logs 50 MB, snmp 20 MB, configs 20 MB. Beacon **inbound** gunzip path is the **rotated DEK delivery from `/config`** — small JSON, but defence-in-depth still requires a cap.
- **Beacon Go pattern** (M-6, mirror exactly):
  ```go
  func gunzipCapped(blob []byte, maxBytes int64) ([]byte, error) {
      gr, err := gzip.NewReader(bytes.NewReader(blob))
      if err != nil { return nil, GunzipCorrupt(err) }
      defer gr.Close()
      buf := bytes.NewBuffer(make([]byte, 0, 64*1024))
      _, err = io.CopyN(buf, gr, maxBytes+1) // read ONE more than cap
      if err == nil { return nil, PayloadTooLarge{Cap: maxBytes} } // copied >maxBytes → bomb
      if !errors.Is(err, io.EOF) { return nil, GunzipCorrupt(err) }
      if int64(buf.Len()) > maxBytes { return nil, PayloadTooLarge{Cap: maxBytes} }
      return buf.Bytes(), nil
  }
  ```
- **Forbidden:** `io.ReadAll(gzip.NewReader(...))` — loads the full plaintext before any cap check (CWE-409). CI lint must reject this pattern in `internal/ingestion/**` and `internal/config_poll/**`.

### 1.3 Error envelope and codes

Verified in `c:/Users/Anderson Leite/code/netbrain/services/api-gateway/src/routes/beacons.py:101-110`:

```json
{ "error": { "code": "...", "message": "...", "details": { ... } } }
```

`SimpleError` (used on 413 from data-plane endpoints with opaque encrypted body): `{"detail": "Payload too large"}` — note the lowercase `detail` field, not the structured envelope. The Go client must handle BOTH shapes when parsing `application/json` error responses.

**Full error code inventory** (extracted via `Grep` against `routes/beacons.py`):

| Code | HTTP | Semantics | Beacon action |
|------|------|-----------|---------------|
| `BEACON_PROTOCOL_NOT_ENABLED` | 503 | Platform-wide flag is off | Backoff 60s, retry |
| `BOOTSTRAP_TOKEN_INVALID` | 401 | Token unknown/used/expired | **Fatal at enroll;** prompt operator for fresh token |
| `BOOTSTRAP_TOKEN_RATE_LIMITED` | 429 | 10/hour per-prefix budget exhausted | **Fatal at enroll;** wait 1h or new token |
| `CSR_INVALID` | 400 | Subject not empty / wrong key type / extensions present | **Fatal at enroll/rotate;** beacon bug — log loudly, don't retry |
| `BEACON_ENVELOPE_INVALID` | 400 | Envelope structurally malformed | **Drop batch;** beacon bug, do not retry |
| `BEACON_DEK_EXPIRED` | 401 | dek_v in envelope older than rotation grace | Re-poll `/config` to receive new DEK; retry once |
| `BEACON_AAD_MISMATCH` | 400 | GCM tag fails — AAD or ciphertext tampered | **Drop batch;** likely beacon bug, log loudly |
| `BEACON_DECOMPRESSION_BOMB` | 413 | Plaintext exceeds per-endpoint cap | **Drop batch;** beacon bug — too much in one batch |
| `BEACON_GUNZIP_CORRUPT` | 400 | Source gzip stream malformed | **Drop batch;** transport bug — log |
| `BEACON_IDEMPOTENCY_KEY_MISMATCH` | 400 | Server-recomputed UUIDv5 ≠ header | **Drop batch;** beacon bug — UUIDv5 desync |
| `BEACON_URL_CERT_MISMATCH` | 403 | URL `{beacon_id}` ≠ cert-derived id | **Fatal;** beacon is presenting wrong cert for path |
| `NOT_FOUND_OR_CROSS_TENANT` | 404 | Resource absent OR in another tenant | **Fatal at enroll/rotate;** stale beacon record |
| `UNKNOWN_BEACON` | 401 | Cert fingerprint not registered | **Fatal;** re-enroll required |
| `BEACON_INVALID_FLOW_FILENAME` | 400 | nfcapd filename pattern violation | **Drop batch;** filename builder bug |
| `BEACON_PAYLOAD_TOO_LARGE` | 413 | Body exceeds size limit | **Drop batch + smaller batches** |
| `BEACON_EMPTY_PAYLOAD` | 400 | Empty flow file | **Drop;** caller bug |
| `BEACON_STORAGE_UNAVAILABLE` | 503 | netflow-mcp/Loki backend down | **Retain in store-and-forward;** retry with backoff |

The Go client should switch on `error.code` (not HTTP status) when deciding retry vs drop. ADR-071 §"ACK semantics" mandates: **on `4xx` other than 409 → drop the batch**; on `5xx` or network → retry with backoff. The above table refines that with code-specific actions.

### 1.4 Server-side conventions worth knowing

- **nginx 8443 terminator strips and replaces `X-Client-Cert-*` headers** (H-1 hardening). The Go beacon never sees these — it just presents its cert during the TLS handshake. **Beacon-side responsibility:** present `tls.Certificate{Certificate: [DER...], PrivateKey: ecdsaKey}` via `tls.Config.Certificates` or `GetClientCertificate`.
- **7-day DEK rotation grace** (ADR-068): the beacon may simultaneously hold `dek.bin` (current) and `dek.prev.bin` (previous-from-server) and use whichever the server's rotated DEK delivery indicates. The beacon side must persist BOTH atomically until the grace window closes, then delete the prev.
- **Server returns 304 with no body on `If-None-Match` match** — Go client must `resp.Body.Close()` even on 304 (no-op but linter-required).

### 1.5 Naming/error-handling conventions to mirror in Go

- **Error codes are SCREAMING_SNAKE_CASE.** Beacon Go constants live at `internal/api/errors.go`:
  ```go
  const (
      ErrBeaconProtocolNotEnabled    = "BEACON_PROTOCOL_NOT_ENABLED"
      ErrBootstrapTokenInvalid       = "BOOTSTRAP_TOKEN_INVALID"
      ErrBootstrapTokenRateLimited   = "BOOTSTRAP_TOKEN_RATE_LIMITED"
      // ... 15 more
  )
  ```
- **HTTP status maps consistently.** Beacon code switches on `error.code` strings, not status numbers, but uses status as a secondary signal: 5xx → retry, 4xx (except 409 Conflict) → drop, 401 → re-enroll path.
- **Idempotency-Key-MUST-be-UUIDv5** — server recomputes it. Any Go-side bug in the UUIDv5 derivation surfaces as `BEACON_IDEMPOTENCY_KEY_MISMATCH` 400s with no batches succeeding. **Cross-language test fixture is mandatory.**

---

## 2. Architecture Context

### 2.1 System placement

```
   Customer LAN (isolated)                       NetBrain SaaS
   ─────────────────────────                     ──────────────────────────
   Devices                                       nginx 8443 mTLS terminator
     │ syslog 514                                  │ (strips X-Client-Cert-*,
     │ netflow 2055                                │  re-adds via REPLACE H-1)
     │ snmp polls (out)                            ↓
     │ ssh config pulls (out)                    api-gateway
     ↓                                             ├─ /api/v1/beacons/...
   netbrain-beacon (Go binary)                     ├─ Loki (logs)
     ├─ collectors/{syslog,netflow,snmp,configs}    ├─ netflow-mcp
     ├─ store/ (bbolt store-and-forward)            └─ Postgres (audit, registrations)
     ├─ crypto/ (AES-256-GCM, ed25519)
     ├─ transport/ (mTLS HTTPS)
     ├─ config_poll/ (60s ETag)
     ├─ probe/ (TCP-connect + SSRF allowlist)
     ├─ admin/ (status CLI + Prom metrics)
     │
     ↓ mTLS HTTPS-only (one direction, beacon-initiated)
   Internet → nginx 8443
```

The beacon never receives unsolicited inbound HTTP from the platform. All control flow is **beacon → platform**, including config polling. The platform "sends" a rotated DEK by attaching it to the response of the beacon's next `GET /config`.

### 2.2 Data flow — three phases

#### Phase A: Bootstrap (one-shot)

1. Admin generates token in netbrain UI → `EnrollmentTokenResponse` returned (token + base64-signed bundle).
2. Operator copies token into beacon install command: `netbrain-beacon enroll --server-url https://... --token nbb_<60hex>` (or pastes the bundle file).
3. Beacon verifies bundle ed25519 signature against baked-in platform pubkey; pins `platform_pubkey_pem` from bundle for future M-11 verifications.
4. Beacon generates ECDSA P-256 keypair locally; builds CSR with empty Subject.
5. Beacon POSTs `/api/v1/beacons/enroll` with `bootstrap_token` + `csr_pem` + `beacon_metadata`.
6. Server returns `BeaconEnrollResponse` (cert + CA + DEK + endpoints).
7. Beacon persists atomically (via tmpfile + rename per file): `beacon.crt` (0644), `beacon.key` (**0600**, ECDSA P-256), `dek.bin` (**0600**, 32 bytes), `platform-pubkey.pem` (0644), `enrollment-bundle.json` (0600 — contains the consumed token, useful for debug-only re-enroll), `beacon-state.bbolt` (**0600**).

#### Phase B: Daemon (long-lived)

```
                ┌───────────────────────────┐
                │  goroutine: config_poll   │ every 60 ± 10 s
                │  GET /config + heartbeat  │ (ETag short-circuit)
                └─┬─────────────────────────┘
                  │ on apply: hot-reload
                  ↓
                ┌───────────────────────────┐
                │  goroutine: cert_lifecycle│ every heartbeat
                │  GET /cert-status         │ on rotate@80% → POST /cert/rotate
                └───────────────────────────┘

   collectors                   transport (one goroutine per data class)
   ──────────                   ────────────────────────────────────────
   syslog (UDP+TCP 514)──┐         ┌─────────────────────────────────┐
   netflow (UDP 2055)─────┼──→ in-memory bounded queues ──→ bbolt    │
   snmp poller            │       (drop-when-full per ADR-071)        │
   config ssh puller     ─┘                  │                        │
                                              ↓ goroutine: sender    │
                                     encrypt+sign → POST /data/{type}│
                                     ↓                                │
                                     204/409 → bbolt Delete records  │
                                     5xx/network → backoff retry     │
                                     4xx (≠409) → drop + metric inc  │
                                     └─────────────────────────────────┘
```

#### Phase C: Control-plane piggyback

Every 60 s ± 10 s jitter:

1. `GET /config` with `If-None-Match: <last_config_hash>`.
2. On 200: parse `BeaconConfigResponse`, hot-reload changed sub-trees; persist `config.json` (last applied) atomically.
3. On 200 with `X-Beacon-DataKey-Signature` header: verify signature (M-11), persist `dek.bin` atomically, retain old as `dek.prev.bin` for 7 days.
4. On 304: no-op.
5. Immediately after `/config`, POST `/heartbeat` with `BeaconHeartbeatRequest` (timestamp, uptime, queue depths, store size, evictions, replay lag, **last 5min device probes**, `pending_config_hash`).

### 2.3 API boundaries

- **Outbound only:** mTLS TCP 443 → platform `nginx 8443` (beacon never opens the route directly to api-gateway). The beacon resolves the server URL once at startup (and once at config-apply if the URL changed) and dials by IP if customer DNS is unstable.
- **No port 8000** on the beacon side — that's the admin-JWT plane and only platform admins use it.

### 2.4 No internal database

bbolt is the on-disk store-and-forward buffer; it is NOT a database in the relational sense. Otherwise the beacon is stateless. Persistent state files (Linux paths shown — Windows under `%PROGRAMDATA%\netbrain-beacon\`):

| File | Mode | Purpose |
|------|------|---------|
| `/etc/netbrain-beacon/config.yaml` | 0644 | Operator-visible boot config (server URL, log level) |
| `/var/lib/netbrain-beacon/beacon.crt` | 0644 | mTLS client cert (PEM) |
| `/var/lib/netbrain-beacon/beacon.key` | **0600** | mTLS private key (PEM, ECDSA P-256) — M-key-perms |
| `/var/lib/netbrain-beacon/dek.bin` | **0600** | Current 32-byte AES-256-GCM DEK |
| `/var/lib/netbrain-beacon/dek.prev.bin` | **0600** | Previous DEK (during 7-day rotation grace; deleted after) |
| `/var/lib/netbrain-beacon/platform-pubkey.pem` | 0644 | Platform ed25519 SPKI/PEM (pinned at enrollment) |
| `/var/lib/netbrain-beacon/beacon-state.bbolt` | 0600 | Store-and-forward buffer |
| `/var/lib/netbrain-beacon/applied-config.json` | 0644 | Last-applied config + `config_hash` |
| `/var/lib/netbrain-beacon/beacon-id.txt` | 0644 | UUID derived at enrollment (for cross-checks) |
| `/var/log/netbrain-beacon/beacon.log` | 0644 | JSON `slog` output (when not journald) |

---

## 3. Dependency Analysis

All versions verified late-2025 / early-2026 via web search and pkg.go.dev.

### 3.1 OpenAPI codegen

**`github.com/oapi-codegen/oapi-codegen/v2`** — pkg.go.dev. Latest stable v2.4.0 (next planned: v2.7.0 with Go 1.24 minimum). License: Apache-2.0. Active maintenance.

- **OpenAPI 3.1 caveat:** netbrain spec is `openapi: 3.1.0` (line 1 of beacon-v1.yaml). Upstream `kin-openapi` parser does not yet support 3.1 fully; oapi-codegen displays a warning and recommends downgrade. **Workaround pinned in the beacon repo:** use OpenAPI Overlay (added in v2.4.0) to translate 3.1-only constructs (`type: ['string', 'null']` → `nullable: true`, `examples` array → `example`) on the fly in `oapi-codegen.yaml`. Net effect: the netbrain repo retains 3.1 ergonomics; beacon reads via overlay shim. Document this in the implementation plan §"codegen build step".
- **Codegen targets:** generate `models` + `client` ONLY. Do NOT generate `server`/`std-http-server` — the beacon is a client. Use a `client.WithRequestEditorFn` chain to inject mTLS-derived auth (the cert is already on the underlying transport; editors handle `Idempotency-Key`, `X-Beacon-DEK-Version`, `If-None-Match`).
- **Known issue:** generated code uses `time.Time` for `format: date-time`; ETag header roundtrip is straightforward but the `If-None-Match` parameter isn't natively a `*string` in 3.1 mode under overlay — handle via custom `RequestEditorFn`.

### 3.2 HTTP client

**Standard library `net/http` + `crypto/tls`.** Wrapped via:

```go
tlsConfig := &tls.Config{
    Certificates: []tls.Certificate{cert},   // mTLS cert
    RootCAs:      caPool,                    // platform CA pinned
    MinVersion:   tls.VersionTLS13,          // ADR-067 explicit
    ServerName:   serverHostname,            // SNI
}
transport := &http.Transport{
    TLSClientConfig:       tlsConfig,
    MaxIdleConns:          4,
    MaxIdleConnsPerHost:   2,
    IdleConnTimeout:       90 * time.Second,
    TLSHandshakeTimeout:   10 * time.Second,
    ResponseHeaderTimeout: 30 * time.Second,
    ExpectContinueTimeout: 1 * time.Second,
    ForceAttemptHTTP2:     true,
}
client := &http.Client{
    Transport: transport,
    Timeout:   60 * time.Second, // hard cap per request; per-call override available
}
```

**No third-party HTTP client** (no `resty`, no `req`). Stdlib is sufficient and reduces dependency surface.

### 3.3 TLS / x509 / CSR

**Standard library `crypto/tls`, `crypto/x509`, `crypto/ecdsa`, `crypto/elliptic`.** CSR generation:

```go
priv, _ := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
template := &x509.CertificateRequest{
    Subject: pkix.Name{}, // empty per ADR-067 §"Phase 2"; server controls Subject
}
csrDER, _ := x509.CreateCertificateRequest(crand.Reader, template, priv)
csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
```

Server validates: ECDSA P-256, empty Subject, no extensions/SANs (ADR-067 §"Phase 2.5"). Beacon-side regression test: round-trip a CSR through `csr.is_signature_valid` equivalent via `x509.CertificateRequest.CheckSignature()` before POSTing.

### 3.4 Crypto primitives — stdlib only

- `crypto/aes` + `crypto/cipher` — AES-256-GCM via `cipher.NewGCM(aes.NewCipher(dek))`. 32-byte DEK → AES-256.
- `crypto/rand.Read` — sole source of IVs and ECDSA key generation. **CI lint must reject `math/rand` in `internal/crypto/**`.** Add the lint as a `forbidigo` rule in `.golangci.yml`.
- `crypto/ed25519.Verify(pub, msg, sig)` — boolean return; no error variants.
- `crypto/x509.ParsePKIXPublicKey` returns `any` — type-assert to `ed25519.PublicKey`.

**No third-party crypto.** No `golang.org/x/crypto` for AEAD (the `chacha20poly1305` route exists but is not the contract). The contract is AES-256-GCM, period.

### 3.5 UUIDv5 / UUIDv7

**`github.com/google/uuid`** — latest v1.6.0+ (de-facto stdlib companion; widely vendored). License: BSD-3-Clause. Maintained. Used for:

- `uuid.NewSHA1(NS_BEACON_BATCH, []byte(name.hex()))` — UUIDv5 for Idempotency-Key.
- `uuid.NewV7()` — for bbolt record keys (ADR-071 §"Records keyed by uuidv7"; time-ordered for FIFO replay).

**Cross-language byte-exactness gotcha** (see Section 5): Python passes the hex string into `uuid5()`; Go must pass `[]byte(hexEncodedName)` not the raw bytes. Test fixture in `internal/idempotency/fixtures_test.go` reads JSON output from `python -c "import uuid; print(uuid.uuid5(uuid.UUID('c4d2c5e0-1c9b-5b9e-8d0a-7f3a4e1c2b3d'), '<hex>'))"` and asserts Go matches.

### 3.6 bbolt

**`go.etcd.io/bbolt`** — latest v1.4.1 (verified via pkg.go.dev). License: MIT. Maintained by etcd-io org; production-tested in etcd, k3s, Vault, Consul.

- **Pure Go (no CGo)** — critical for cross-OS builds.
- **Single writer / multiple readers** — beacon's transport goroutine is the sole writer; collector goroutines push records via a channel to a shim writer. Reader goroutines (admin status, eviction janitor) operate concurrently.
- **MVCC via mmap** — no app-level eviction; the OS pages out cold pages. The 5 GB cap is enforced at the **app** level by the eviction janitor; bbolt itself doesn't shrink files (free pages reused but not returned to OS).
- **Known bug (open):** `Bucket.Stats()` panics on a corrupt branch page with zero elements (`x/vulndb` issue #4923). Beacon code MUST NOT call `Stats()` on the hot path; only at startup recovery and via the admin status command. Wrap in `recover()` for safety.
- **ext4 fast-commit corruption** (Linux kernel <5.10.94 / <5.15.17): not a CVE per se, but documented data-loss risk. Runbook MUST require kernel ≥5.15.17 on Linux beacon hosts.

### 3.7 SNMP

**`github.com/gosnmp/gosnmp`** — latest released 2026-01-12 (community-maintained after Sonia Hamilton transferred ownership). License: BSD-2-Clause. v2c + v3 USM (auth: SHA/SHA256/SHA512; priv: AES128/AES256).

- **CVE history:** CVE-2021-XXXXX class — malformed v1 trap packet → DoS. Fixed in v1.34.0 (2021-11-17). Beacon is a poller (not a trap receiver) so trap-parser path is not exercised, but pin **≥ v1.37.0** anyway.
- **Context name handling** is fragile: wrong v3 context returns zero results, no error. Beacon must validate at config-apply via a known-OID probe (`1.3.6.1.2.1.1.5.0` sysName) before declaring the SNMP collector "up".
- **Threading:** `gosnmp.GoSNMP` is NOT goroutine-safe. Beacon uses one `*GoSNMP` per goroutine, with a worker pool sized by `len(device_ips)` capped at 16.

### 3.8 Syslog server

**`gopkg.in/mcuadros/go-syslog.v2`** — v2.3.0 latest. License: MIT. **Maintenance status: STALE** (last release 2018-ish; PRs accumulating, no releases). Still works for RFC3164 + RFC5424 + RFC6587 over UDP/TCP/Unix.

**Recommendation:** ship with `mcuadros/go-syslog` for v1 (it's the de-facto Go syslog server) but vendor the source so we can patch quickly. Alternatives evaluated:
- `github.com/influxdata/go-syslog/v3` — used by Telegraf; parser-only (we'd write the listener ourselves).
- `github.com/leodido/go-syslog/v4` — successor of influxdata fork; parser-only.

**Decision (locked-in for /design-system):** mcuadros for v1; track a v2 migration to `leodido/go-syslog` if mcuadros remains unmaintained at 6-month review.

### 3.9 NetFlow collector

**`github.com/netsampler/goflow2`** — latest v2.2.6 (released 2025-12-27). License: BSD-3-Clause. Active maintenance.

- Supports v5 + v9 + IPFIX + sFlow.
- **nfcapd compatibility (U-4 unknown):** goflow2 ingests UDP flows directly; it does NOT parse nfcapd binary files. The contract requires `multipart/form-data` of nfcapd files. **Implication:** the beacon must EITHER (a) capture flows with goflow2 then re-encode to nfcapd via `nfdump --format=auto` (CGo dependency!), OR (b) use goflow2 in pass-through mode and ship its raw binary output, OR (c) use a separate listener that writes nfcapd-format directly.
- **Decision deferred to /design-system (D-9)**, but lean toward **(b): goflow2 pass-through + custom nfcapd writer in pure Go.** nfcapd binary format is documented (libnf, nfdump source); a pure-Go writer is ~300 lines.
- **CVE history:** none against `netsampler/goflow2`. (The Cloudflare goflow project — `github.com/cloudflare/goflow` — has a sFlow DoS GHSA-9rpw-2h95-666c, fixed in 3.4.4. We're not using that fork.)

### 3.10 SSH for config pulls

**`golang.org/x/crypto/ssh`** — Go-team maintained. Latest as of 2026: tracks `golang.org/x/crypto` semver (`v0.32.0+` typical). License: BSD-3-Clause.

- Vendor-specific quirks for Cisco IOS/IOS-XR (U-3): `show running-config` works; some platforms require `terminal length 0` first, others require a `more`-paginator workaround. ADR-046 (parent repo `scheduled-config-collection`) has prior art.
- **Host-key verification mandatory** — never `ssh.InsecureIgnoreHostKey()`. Beacon caches device host keys at first connect; mismatch → 401-equivalent collector-error metric, alert operator.

### 3.11 YAML config

**`gopkg.in/yaml.v3`** — latest v3.0.1+. License: Apache-2.0 + MIT (canonical Go YAML). The beacon's boot config is YAML; runtime config from `/config` is JSON (per OpenAPI). Two libraries acceptable here, but yaml.v3 also reads JSON (since JSON is YAML 1.2 subset), so we use yaml.v3 for both with `unmarshalStrict` for the on-disk YAML and stdlib `encoding/json` for the wire JSON.

### 3.12 Logging

**Standard library `log/slog`** (Go 1.21+). JSON handler built in. License: BSD (stdlib).

- Custom redactor `slog.Handler` middleware drops `bootstrap_token`, `dek`, `data_key_b64`, `csr_pem` (plaintext), `enrollment_bundle.bootstrap_token` from any structured log call. **CI grep gate** (per ADR-067 §"Logging hygiene") prevents new violations.
- No `zap`. No `zerolog`. The beacon doesn't log enough volume to justify either's perf advantage; stdlib slog is sufficient.

### 3.13 Testing

- **Standard library `testing`** + `github.com/stretchr/testify/require` (v1.8+). License: MIT. The de-facto Go assertion library.
- **Property-based testing:** `pgregory.net/rapid` for fuzz-like crypto round-trips (envelope encrypt/decrypt symmetry).
- **Test fixtures** for cross-language verification: shipped Python script generates known-answer envelopes/UUIDs into JSON; Go tests load the JSON and assert equality.
- **`testcontainers-go`** (v0.32+) for Phase 5 integration tests against a stub api-gateway container.

### 3.14 CLI

**Standard library `flag`** for v1. Subcommands `enroll`, `daemon`, `status`, `version` — only 4, no nested subcommands. `flag.NewFlagSet` per subcommand suffices. Resist `cobra` until the subcommand tree exceeds ~6 verbs.

### 3.15 Dependency health audit (CVE sweep, 2025-late through 2026-early)

| Library | Known CVE / Issue | Min pinned version | Status |
|---------|-------------------|--------------------|--------|
| `bbolt` | x/vulndb #4923 (`Stats()` panic on corrupt branch page) | v1.4.1 | Hot-path mitigation: don't call `Stats()` on hot path |
| `gosnmp` | Pre-v1.34.0 v1-trap DoS | v1.37.0+ | Beacon doesn't process traps; not exposed |
| `goflow2` | None against netsampler fork | v2.2.6 | Use this fork, NOT cloudflare/goflow |
| `mcuadros/go-syslog` | None CVE; **stale** (last release ~2018) | v2.3.0 | Vendor + monitor; migration plan to leodido |
| `golang.org/x/crypto` | GO-2025-3563 (ssh terrapin attack class) | track stdlib release pace; v0.32.0+ | Disable weak ciphers in our SSH client config |
| `google/uuid` | None | v1.6.0+ | OK |
| `oapi-codegen` | None | v2.4.0+ | OpenAPI 3.1 overlay workaround required |
| Go stdlib `net/http` | CVE-2025-22871 (request smuggling) + subsequent | Latest stable Go | Pin Go 1.26.3 (latest stable as of 2026-05-10) |

**Mandate:** add `govulncheck` to CI as a hard-fail step. Run weekly via dependabot-equivalent.

---

## 4. Integration Points

### 4.1 Inbound to beacon

- **syslog 514 UDP + 1514 TCP** (ADR config defaults `0.0.0.0:514` / `0.0.0.0:1514`). Hostname-restricted bind in production via config.
- **netflow 2055 UDP** — accept v5/v9/IPFIX per config.
- **No HTTP inbound** in v1. Admin surface is local-only.

### 4.2 Outbound from beacon

- **mTLS HTTPS to platform port 8443.** Single endpoint, derived from `data_endpoint` / `config_endpoint` returned at enrollment.
- **SSH outbound to devices** for config pull (port 22 typical, configurable per `BeaconConfigDevice.host`).
- **SNMP outbound to devices** for poll (UDP 161).
- **TCP-connect probes outbound to devices** (ports 22 → 161 → 80, ADR-072).

### 4.3 Local admin surface

**Decision deferred to /design-system (D-1).** Three options:

1. **CLI subcommands only:** `netbrain-beacon status`, `netbrain-beacon logs --tail`. Pros: no listening port = smaller attack surface. Cons: no remote inspection.
2. **Local web UI on 127.0.0.1:8080:** richer UX. Cons: another listening port; auth model required (likely token in env var or unix socket).
3. **systemd-style:** journald + `systemctl status netbrain-beacon`. Pros: zero new code. Cons: Linux-only; Windows would still need a fallback.

**Recommendation (locked at /research):** **Option 1 + Prometheus metrics endpoint on 127.0.0.1:9090** (D-1 → CLI + metrics). Smallest attack surface; metrics endpoint discoverable for `node_exporter`-style scrape. Web UI is a v2 feature.

### 4.4 OS integration

- **Linux:** systemd unit at `/etc/systemd/system/netbrain-beacon.service` with `User=netbrain`, `Group=netbrain`, `ProtectSystem=strict`, `ProtectHome=true`, `PrivateTmp=true`, `NoNewPrivileges=true`, `CapabilityBoundingSet=CAP_NET_BIND_SERVICE` (for syslog 514 < 1024). Ship as **tarball + systemd unit + install.sh** for v1. Defer deb/rpm to v2 (D-4 deferred).
- **Windows:** `golang.org/x/sys/windows/svc` for service registration. Event Log source registered by the installer (U-1 unknown; registry write requires admin at install time). Ship as `netbrain-beacon-windows-amd64.zip` with `install.ps1`.
- **Container:** `gcr.io/distroless/static-debian12:nonroot` (~2 MB base, UID 65532). Multi-stage: Go build in `golang:1.26-alpine`, copy binary into distroless. Image final ~17 MB.

### 4.5 File system layout

| Linux path | Windows path | Mode | Purpose |
|------------|--------------|------|---------|
| `/etc/netbrain-beacon/config.yaml` | `%PROGRAMDATA%\netbrain-beacon\config.yaml` | 0644 | boot config |
| `/var/lib/netbrain-beacon/` | `%PROGRAMDATA%\netbrain-beacon\state\` | 0700 | state dir |
| `/var/log/netbrain-beacon/` | EventLog | 0700 | logs (Linux only — Windows uses Event Log) |

### 4.6 Observability

- **Prometheus metrics** on `127.0.0.1:9090/metrics` (binds loopback only, no auth needed at the network layer).
- **Counters/gauges to expose:**
  - `netbrain_beacon_enroll_attempts_total{result}`
  - `netbrain_beacon_config_polls_total{status_code,etag_hit}`
  - `netbrain_beacon_data_pushes_total{type,status_code}`
  - `netbrain_beacon_sf_records_pending{type}` (gauge)
  - `netbrain_beacon_sf_evictions_total{type}` (per ADR-071)
  - `netbrain_beacon_sf_dead_letters_total{type}`
  - `netbrain_beacon_sf_corruption_recovery_total`
  - `netbrain_beacon_dek_signature_verify_failures_total` (M-11)
  - `netbrain_beacon_safe_dial_rejections_total{reason}` (M-9)
  - `netbrain_beacon_decompression_bomb_aborts_total`
  - `netbrain_beacon_ssh_pull_seconds{vendor}` (histogram)
  - `netbrain_beacon_uptime_seconds`
  - `netbrain_beacon_clock_skew_seconds` (gauge)
- **Library:** `github.com/prometheus/client_golang/prometheus` v1.20+; license Apache-2.0; canonical Go Prom client.

---

## 5. Risk Assessment

Specific risks with concrete mitigations.

### R-1: Python ↔ Go byte-exactness on UUIDv5 (HIGH)

**Risk:** Python `uuid.uuid5(NS, name_str)` and Go `uuid.NewSHA1(NS, []byte(...))` must produce identical UUIDs for identical inputs. The Python side passes `name.hex()` (a 96-char string) into `uuid5`. Go must therefore pass `[]byte(hex.EncodeToString(beaconID[:]) + hex.EncodeToString(sha256.Sum256(plaintext)[:]))` — the bytes of the hex string, NOT the raw 48 bytes.

**Concrete failure mode:** Every `/data/*` call returns 400 `BEACON_IDEMPOTENCY_KEY_MISMATCH`. Beacon retries forever (since 4xx-non-409 is "drop" but the bug means EVERY batch hits this).

**Mitigation:**
1. Cross-language test fixture in `internal/idempotency/fixtures_test.go` that loads `testdata/idempotency_fixtures.json` (generated by `scripts/gen_uuid_fixtures.py`) and asserts byte-exact match.
2. Unit test that cross-checks against `idempotency.py:derive_batch_idempotency_key` via Docker-exec at CI time.
3. Add a startup-time self-test that derives a known-answer UUIDv5 and panics if it doesn't match the embedded constant.

### R-2: AES-GCM byte-exactness Python ↔ Go (HIGH)

**Risk:** Python `cryptography.hazmat.primitives.ciphers.aead.AESGCM(key).encrypt(nonce, plaintext, aad)` and Go `aead.Seal(nil, nonce, plaintext, aad)` both produce `ciphertext || 16-byte-tag`. They are byte-compatible **when** key is 32 bytes, nonce is exactly 12 bytes, and tag size is 16 bytes — all true here. But edge cases differ:
- **Empty plaintext:** Python `AESGCM.encrypt(iv, b"", aad)` returns 16-byte tag-only result. Go `aead.Seal(nil, iv, []byte{}, aad)` likewise. OK in principle, but the envelope format mandates `_MIN_ENVELOPE_LEN = 30` (1+1+12+0+16 = 30 with empty ct). Both produce 30 bytes.
- **Empty AAD:** Python and Go both treat `nil`/`b""` AAD identically; OK.
- **Tag size override:** Python's `AESGCM` has a hardcoded 128-bit tag. Go's `cipher.NewGCM(...)` defaults to 128-bit; `cipher.NewGCMWithTagSize(...)` could override. **Beacon MUST use `NewGCM`, never `NewGCMWithTagSize`.**

**Mitigation:**
1. Cross-language test fixture in `internal/crypto/fixtures_test.go`: Python emits encrypted envelopes with known plaintexts and AADs; Go decrypts and asserts plaintext match; Go re-encrypts with the same iv (test-only path) and asserts byte-exact ciphertext+tag.
2. CI gate (`forbidigo`) prohibits `NewGCMWithTagSize` and `NewGCMWithNonceSize` in `internal/crypto/**`.

### R-3: bbolt single-writer lock holds during fsync (MEDIUM)

**Risk:** bbolt holds an exclusive write lock during `Tx.Commit()` which fsyncs. On a slow-disk customer host (HDD, noisy neighbor on shared VM), commits can take 100+ ms. Collector goroutines pushing 10k records/sec during a syslog burst will block at the channel send.

**Mitigation:**
1. **Bounded channel between collectors and writer**, default depth 1000 records (per ADR-071 §"Risks"). On full channel: drop with `beacon_sf_collector_drops_total{type}` increment. Documented loss path.
2. **Batch writes** — writer accumulates up to 64 KB or 100 records before opening a write transaction. Reduces lock-hold count by ~100×.
3. **Fsync mode tunable** — bbolt `db.NoSync = true` is FORBIDDEN in production (loses ACK semantics). Default `NoSync = false`; alert-loud on slow commits via `bbolt_commit_seconds` histogram.

### R-4: SNMP v3 USM context complexity (MEDIUM)

**Risk:** Wrong v3 context name silently returns zero rows, not errors. Beacon reports "all OIDs queried OK, 0 results" — operator sees a quiet mode failure.

**Mitigation:**
1. **Validation probe at config-apply:** before enabling the SNMP collector, GET `1.3.6.1.2.1.1.5.0` (sysName); if empty result OR error → reject config with structured collector-error metric.
2. **Surface in heartbeat:** `queue_depths.snmp` and a derived `last_successful_poll_seconds` are reported; `>5×poll_interval` = degraded.

### R-5: SSH key management for device pulls (HIGH for v1)

**Risk:** Per-device SSH credentials (private keys, passwords) on the beacon escalate blast radius. A compromised beacon yields **all** its tenant's devices' creds.

**Mitigation:**
1. **v1 reads SSH credentials from beacon config** (which only platform admin can push via `PATCH /config`). Stored encrypted at rest with the per-install DEK (per `BeaconConfigDevice.ssh_key_encrypted`).
2. **In-memory only after decrypt** — never write decrypted SSH keys to disk; `ssh.ParseRawPrivateKey` works on bytes, no temp files.
3. **v2: agent forwarding from netbrain UI.** Operator initiates a config pull from the platform; platform forwards an SSH agent challenge through the beacon to the device. No long-lived SSH creds on the beacon.

### R-6: Windows service stop timeout (MEDIUM)

**Risk:** Default Windows service-stop timeout is 30 s. If a store-and-forward flush takes longer (catching up on a multi-hour outage), the SCM kills the process and bbolt is left dirty.

**Mitigation:**
1. **Checkpoint markers**: writer commits a `meta:flush_pos = <bbolt-key>` after every batch ACK. On restart, replay starts from the marker.
2. **Accept dirty-on-restart:** bbolt's checksum detects corruption on open; recover-and-rotate (per ADR-071) is documented.
3. **Increase Windows service stop timeout** via registry: `HKLM\SYSTEM\CurrentControlSet\Control\ServicesPipeTimeout = 60000` (60 s). Documented in runbook; installer sets it.

### R-7: nginx `tls.Config.MinVersion = VersionTLS13` mismatch (HIGH)

**Risk:** Platform nginx 8443 enforces TLS 1.3 only (per platform deploy plan). If the Go beacon's `tls.Config` defaults to TLS 1.0+ and the negotiation lands at 1.2, handshake fails — but with a confusing error.

**Mitigation:**
1. **Explicit `MinVersion: tls.VersionTLS13`** in transport config. Forbidden default-via-omission.
2. **Lint:** `forbidigo` rule rejects `tls.Config{}` literal without `MinVersion` field.
3. **Test:** spin up a TLS 1.2-only stub in `transport_test.go`; assert the beacon refuses to dial.

### R-8: Cert auto-rotate race (MEDIUM)

**Risk:** During cert rotation at 80% lifetime, two valid certs exist simultaneously. An in-flight HTTP request uses the old cert while the new one is being written. If the write half-completes, the file is corrupt.

**Mitigation:**
1. **Atomic swap via `os.Rename`** after the new cert is verified (matching pubkey, valid chain). Rename is atomic on both POSIX and Windows NTFS (within the same volume).
2. **Reload TLS config under a `sync.RWMutex`** — `http.Client.Transport.TLSClientConfig` is shared; replace the whole `*http.Client` atomically rather than mutating in place. (See "anti-pattern: sharing http.Client with mutable Transport" in §6.)
3. **5-minute rotation window** — start rotation 18 days (90 × 0.20) before expiry; even a worst-case retry chain completes within 5 minutes.
4. **Runbook entry:** "How to manually trigger cert rotation" + "How to recover from a corrupted cert file" (move aside, re-enroll).

### R-9: M-9 SSRF bypass via DNS rebinding (HIGH)

**Risk:** A device IP that resolves to `10.0.0.5` at allow-list-check time but to `169.254.169.254` (cloud metadata) at dial time bypasses the check. This is the canonical DNS rebinding attack.

**Mitigation:**
1. **Resolve once at allow-list check, dial that resolved IP literal.** `internal/safe_dial/dial.go`:
   ```go
   func SafeDial(ctx context.Context, network, addr string) (net.Conn, error) {
       host, port, _ := net.SplitHostPort(addr)
       ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
       if err != nil { return nil, err }
       for _, ip := range ips {
           if isForbidden(ip) { return nil, ErrSSRFBlocked }
       }
       // Dial the IP LITERAL we just verified, never re-resolve.
       return net.Dial(network, net.JoinHostPort(ips[0].String(), port))
   }
   ```
2. **CI lint rule (`forbidigo`):** any `net.Dial(`, `net.DialContext(`, `gosnmp.Connect()`, `ssh.Dial(` to a device-supplied address must go through `internal/safe_dial`. Whitelist only the platform server URL (resolved once at startup).
3. **`isForbidden` bitmap:** link-local 169.254.0.0/16, loopback 127.0.0.0/8, unspecified 0.0.0.0, multicast 224.0.0.0/4 + ff00::/8, IPv6 link-local fe80::/10. **Mirror exactly to the parent issue's M-9 list.**

### R-10: Goroutine leak on shutdown (MEDIUM)

**Risk:** `daemon` subcommand spawns ~12 goroutines (per collector + transport + config_poll + admin + metrics + janitor). On `SIGTERM`, naive `os.Exit(0)` orphans pending bbolt writes and skips fsync.

**Mitigation:**
1. **Single `context.Context` cancelled on signal**, propagated to every goroutine.
2. **`sync.WaitGroup`** for the writer goroutine specifically — `wg.Wait()` with a 30 s deadline before exit.
3. **Defer `db.Close()`** at the top level in `daemon.Run()`, not inside any goroutine (see anti-pattern below).

---

## 6. Prior Art & Ecosystem Research

### 6.1 Datadog Agent (Go)

Architecture: `Collector` (runs checks) + `Forwarder` (sends to platform) + `Aggregator` (in-memory metrics buffer). Config providers signal whether to be polled and at what interval — exact pattern beacon's `config_poll` mirrors. Forwarder buffers in memory until size or send-request limit; spills to disk only via the `forwarder_storage_max_size_in_bytes` setting. **Takeaway for beacon:** Datadog leans memory-first; we lean disk-first (bbolt) because customer-edge appliances reboot more often. Beacon's decision is correct.

### 6.2 Vector (Rust, but architectural lessons)

Pipeline model: Sources → Transforms → Sinks. Each sink has its own retry strategy and **persistent buffer** (disk-backed via leveldb-equivalent). Vector supports a "disk_v2" buffer with similar 5 GB / age caps. **Takeaway:** Vector explicitly drops behind under pressure rather than blocking sources — beacon does the same with `beacon_sf_collector_drops_total`.

### 6.3 Telegraf (Go)

Plugin architecture: each input/output is a Go plugin compiled-in. Plugins are simple structs implementing `telegraf.Input` / `telegraf.Output`. **Takeaway:** Telegraf's plugin abstraction is **too heavy** for beacon v1 — we have 4 collectors, all in-process, no third-party plugins. Use straight Go interfaces (`Collector`, `Sender`) and skip the registry pattern. Revisit if v3 adds 10+ collector types.

### 6.4 Fluent Bit (C, but architectural lessons)

Input/output abstraction with a single in-memory chunk-based buffer. Pure C; tiny binary (~2 MB). **Takeaway:** Fluent Bit's chunk-streaming pattern (write a chunk to disk, ACK consumer, delete chunk) is *exactly* the bbolt pattern in ADR-071. Validates the design.

### 6.5 AWS SSM Agent (Go)

Long-lived mTLS-authenticated edge agent on customer hardware. Cert rotation: agent polls `Amazon SSM` for instance identity refresh, requests a new cert, atomic swap. **Takeaway for beacon:** SSM's atomic-swap-and-reload pattern is identical to ours; SSM's "lockfile + tmpfile + rename" sequence is the textbook approach. SSM also runs as a system service on Windows + Linux + macOS — same packaging considerations beacon faces.

### 6.6 HashiCorp Consul Agent (Go)

Uses bbolt internally for raft log + state. Cert rotation via `consul reload`. **Takeaway:** Consul's hot-reload pattern (write new config, send SIGHUP, reload sub-modules without process restart) is a known-good architecture. Beacon `config_poll`'s hot-reload mirrors this for the YAML-style sub-trees; non-hot-reloadable fields (syslog/netflow listen addresses) flag `pending_restart_required` in heartbeat per OpenAPI BeaconStatus.

### 6.7 oapi-codegen v2 — what's good, what's not, common pitfalls

- **Good:** Generated client is plain `net/http.Client`-based; `RequestEditorFn` chain is composable for auth/headers; types are POGO (plain old Go) structs with `omitempty`.
- **Pitfalls:**
  - **Custom date/time types:** `time.Time` for `format: date-time` works; but `time.Duration` or `format: date` need custom unmarshallers — use the OpenAPI extensions `x-go-type` and `x-go-type-import` to override.
  - **Optional vs nullable:** OpenAPI 3.1's `nullable: true` and `type: ['string', 'null']` are different on the wire (the latter generates `*string` always; the former needs the overlay shim).
  - **Examples in 3.1:** `examples` array is unused by codegen (only `example` singular); overlay can flatten.
  - **Polymorphic responses (`oneOf`/`anyOf`):** generated as `interface{}` with type switches — usable but ugly. The beacon spec doesn't use polymorphic data-plane responses; safe.
  - **`requestBody: required: true`** is enforced at compile time only when `WithRequestEditorFn` doesn't intervene. Test that enroll request can't be called with nil body.

### 6.8 Anti-patterns to call out specifically (DO NOT)

| Anti-pattern | Why it's bad | What to do instead |
|--------------|--------------|--------------------|
| Hand-rolled HTTP client wrapping the generated code | Defeats codegen's contract guarantee | Use generated client + `RequestEditorFn` chain for auth headers, `Idempotency-Key`, `If-None-Match` |
| Goroutine-per-request retries | Unbounded goroutine growth on outage | Single sender goroutine per collector; bounded queue; in-process exponential backoff |
| Spawning a goroutine inside a stdlib timer callback | `time.AfterFunc` runs on a shared goroutine; spawning adds an unowned goroutine | Use `time.Ticker` with a `select` loop in a dedicated goroutine |
| Defer-on-loop-iteration for cleanup | Defers stack until function returns; hot loop leaks resources | Extract loop body to a function with explicit `defer`, or call `Close()` explicitly |
| Sharing `http.Client` with mutable `Transport.TLSClientConfig` | Race during cert rotation; in-flight requests see partial state | Replace the whole `*http.Client` atomically via `atomic.Pointer[http.Client]` |
| `time.Now()` directly in business logic | Untestable; flaky tests | Inject a `Clock interface { Now() time.Time }`; use `clockwork` library or a custom test fake |
| `panic` for "shouldn't happen" branches | Crashes the daemon on a bad assumption | Return errors; log + metric + drop; only `panic` for genuinely impossible-given-types |
| `sync.Mutex` field by value (not pointer) when struct is copied | Lock not shared | Always `sync.Mutex` as a pointer field, or never copy the struct |
| `defer db.Close()` inside a goroutine that may outlive the daemon | bbolt closed while writer is mid-tx | Top-level `defer` in `daemon.Run()` only |
| `io.ReadAll(gzip.NewReader(blob))` | CWE-409 decompression bomb | `gunzipCapped(blob, maxBytes)` with `io.CopyN(buf, gr, maxBytes+1)` |
| `math/rand` for IVs / keypairs / nonces | CWE-338 cryptographic weakness | `crypto/rand.Read` exclusively; `forbidigo` lint gate |
| `tls.InsecureSkipVerify: true` even in dev | Disables MITM defense; gets shipped to prod | Never; use a dev CA pinned via `RootCAs` |
| `os.Chmod` after `os.Create` | Race window between create and chmod where file is mode-0644 | `os.OpenFile(path, os.O_WRONLY\|os.O_CREATE\|os.O_EXCL, 0600)` — atomic |
| `gosnmp.Default` (the package-global) shared across goroutines | Not goroutine-safe | One `*gosnmp.GoSNMP` per goroutine |
| `ssh.InsecureIgnoreHostKey()` | Trivial MITM on first connect | Pin host keys at first connect via `known_hosts`-style cache |
| Ignoring `resp.Body.Close()` even on 304 | Connection-pool leak | Always `defer resp.Body.Close()` (or `io.Copy(io.Discard, body)` then close) |
| `sync.Once` for resource that depends on dynamic config | Cannot reload | Lazy-init via mutex-guarded `*atomic.Pointer[T]` |

---

## 7. Recommendations

### 7.1 Suggested technical approach with alternatives

| Concern | Recommended | Alternative | Rationale |
|---------|-------------|-------------|-----------|
| CLI framework | stdlib `flag` | cobra | Only 4 subcommands; flat tree; revisit cobra at v2 |
| Config format on disk | YAML via `yaml.v3` | JSON-only | Operator-edit ergonomics; YAML is JSON-superset for parser |
| Logging | `log/slog` JSON handler + redactor middleware | zap, zerolog | Stdlib is sufficient at beacon's log volume; redactor mandatory for ADR-067 H-3 |
| Codegen target | `oapi-codegen v2` → `models` + `client` only | hand-roll types | Single source of truth; client regenerates with spec changes |
| Auth injection | `RequestEditorFn` for headers; mTLS via `Transport.TLSClientConfig` | wrapper struct | Composable; idiomatic for oapi-codegen |
| bbolt schema | bucket per data type + `meta` bucket; key = `uuidv7` | timestamp+counter | UUIDv7 is time-ordered; FIFO without separate index |
| Local admin surface | CLI subcommands + Prometheus on 127.0.0.1:9090 | web UI | Smallest attack surface; defer web UI to v2 |
| Cross-compile target | linux/amd64 + windows/amd64 only | linux/arm64 | Customer demand driven; ARM at v2 |
| Container base | `gcr.io/distroless/static-debian12:nonroot` | Alpine | No shell, no package manager → smaller attack surface; UID 65532 (`nonroot`) |
| Cert rotation | poll `/cert-status` per heartbeat; `POST /cert/rotate` at recommended_action=rotate | timer-based | Server-driven; simpler beacon code |
| Multi-tenancy posture | single-tenant per install (cert-bound); tenant_id-aware codepaths | global tenant | v1 single but no globals — keeps v2 multi-tenant open |
| Config validation | strict YAML decode + struct tags `yaml:"...,strictrequired"` | runtime check | Fail fast at boot |
| Build reproducibility | `CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -buildid="` | none | Reproducible across CI runs (Go 1.21+ supports it; we're on 1.26.3) |
| Lint | `golangci-lint` v2 with `errcheck`, `gosec`, `bodyclose`, `forbidigo`, `staticcheck`, `gocritic`, `revive` | v1 | v2 default rules are stricter; `forbidigo` for our custom mandates |
| CI matrix | linux/amd64 + windows/amd64 with `-race` | + macOS | Out of scope per discovery |
| Vulnerability scan | `govulncheck` weekly + on PR | snyk | Built-in; Go-team-maintained DB |

### 7.2 Key decisions to lock at /design-system

| ID | Decision | Default lean |
|----|----------|--------------|
| D-1 | Local admin surface form | CLI + Prometheus 127.0.0.1:9090 |
| D-2 | Config format on disk | YAML via `yaml.v3` |
| D-3 | Container base image | `gcr.io/distroless/static-debian12:nonroot` |
| D-4 | Linux service packaging | Tarball + systemd unit + install.sh (deb/rpm at v2) |
| D-5 | bbolt key schema | `uuidv7` per record (FIFO via sort order) |
| D-6 | Per-collector goroutine pool size + buffer queue depths | syslog=8 workers, queue 1000; netflow=4/500; snmp=16/200; configs=4/100 |
| D-7 | Cert rotation atomicity | `os.Rename(tmp, target)` after pubkey verify; `*atomic.Pointer[http.Client]` for client swap |
| D-8 | Prometheus metrics opt-in | Default ON, bound to 127.0.0.1:9090 only; opt-OUT via `--no-metrics` |
| D-9 | NetFlow → nfcapd conversion | goflow2 pass-through + pure-Go nfcapd writer (~300 LOC) |
| D-10 | Syslog server library | `mcuadros/go-syslog` v2.3.0 vendored; v2 migrate plan to leodido |

### 7.3 Locked decisions surfaced at /research

These are **not** deferred — they're settled and feed the implementation plan:

1. **Crypto: stdlib only.** No third-party AEAD/signature libs.
2. **Codegen: oapi-codegen v2, client + models only** (no server target).
3. **HTTP client: stdlib `net/http`** with explicit `MinVersion: tls.VersionTLS13`.
4. **bbolt: v1.4.1+** with no `Stats()` on hot path.
5. **UUID: `github.com/google/uuid` v1.6.0+** for both v5 (idempotency) and v7 (bbolt keys).
6. **Logging: `log/slog`** with redactor middleware that drops `bootstrap_token`, `dek`, `data_key_b64`, `csr_pem`, `enrollment_bundle.bootstrap_token`.
7. **No CGo:** every cross-compile is `CGO_ENABLED=0`. SQLite and goflow2-with-libpcap are out.
8. **Go version pin: 1.26.3** (latest stable as of 2026-05-10; includes CVE-2025-22871 fix and all subsequent security patches; oapi-codegen v2.7+ baseline satisfied).
9. **Test framework: stdlib `testing` + `stretchr/testify/require` + `pgregory.net/rapid`** for property-based crypto tests.
10. **CI lint: `golangci-lint` v2** with `errcheck`, `gosec`, `bodyclose`, `forbidigo`, `staticcheck`, `gocritic`, `revive`, `govulncheck` as a separate step.
11. **Cross-language test fixtures mandatory** for: UUIDv5 derivation, AES-GCM envelope round-trip, ed25519 signature verify, canonical-JSON byte string.
12. **Single-tenant per install** (cert-bound); no globals to preserve v2 multi-tenant option.

### 7.4 Unknowns to resolve before /design-system

| ID | Unknown | Path to resolve |
|----|---------|-----------------|
| U-1 | Does the Windows installer auto-register an Event Log source, or does the operator? | Test with WiX-generated MSI vs bare installer.ps1 in /design-system stage |
| U-2 | Does `gosnmp` v3 support customer's full SHA512+AES256 USM combinations? | Stand up a test SNMPv3 sim (`snmpsim`) and probe; addressed during implementation Phase 4 |
| U-3 | For Cisco IOS/IOS-XR config pull: `show running-config` sufficient? Vendor quirks? | Borrow patterns from netbrain repo's ADR-046; verify with one of each device class in lab |
| U-4 | Does `goflow2` parse nfcapd binary, or only UDP flows? | Confirmed: UDP only. Decision D-9 above: pure-Go nfcapd writer. |
| U-5 | TLS 1.3 cipher-suite list pinning — does Go honor `tls.Config.CipherSuites` for 1.3? | Spec says no (1.3 suites are fixed); document |
| U-6 | Does `oapi-codegen` v2 overlay handle our 3.1 spec without warnings? | Run codegen against `beacon-v1.yaml` with overlay in /design-system phase |

---

## Summary

- **Contract counterparty fully understood.** 17 server endpoints, 9 beacon-side; envelope format, AAD, UUIDv5 derivation, ed25519 signing, streaming gunzip, error codes — all verified against actual netbrain source.
- **Library set locked.** stdlib-heavy with `oapi-codegen v2`, `bbolt v1.4.1`, `gosnmp v1.37+`, `goflow2 v2.2.6`, `mcuadros/go-syslog v2.3.0` (vendored), `golang.org/x/crypto/ssh`, `google/uuid v1.6.0+`. No CGo anywhere.
- **10 specific risks catalogued** with concrete mitigations (#1 priority: UUIDv5 hex-vs-bytes byte-exactness; #2: AES-GCM cross-language verify; #9: SSRF via DNS rebinding).
- **12 locked decisions** at /research; **10 deferred** to /design-system; **6 unknowns** resolvable in implementation.
- All 5 P1 hardenings (M-4, M-6, M-9, M-11, mTLS key perms) traceable to specific code locations in the Go layout and lint rules.

Sources:
- [oapi-codegen GitHub releases](https://github.com/oapi-codegen/oapi-codegen/releases)
- [oapi-codegen OpenAPI 3.1 issue #373](https://github.com/oapi-codegen/oapi-codegen/issues/373)
- [Tricking oapi-codegen into working with OpenAPI 3.1](https://www.jvt.me/posts/2025/05/04/oapi-codegen-trick-openapi-3-1/)
- [bbolt pkg.go.dev](https://pkg.go.dev/go.etcd.io/bbolt)
- [bbolt GitHub](https://github.com/etcd-io/bbolt)
- [bbolt corruption issue golang/vulndb #4923](https://github.com/golang/vulndb/issues/4923)
- [gosnmp GitHub](https://github.com/gosnmp/gosnmp)
- [gosnmp DoS advisory v1.34.0](https://www.ampliasecurity.com/advisories/gosnmp-dos-vulnerability-ara111721.html)
- [netsampler/goflow2 releases](https://github.com/netsampler/goflow2/releases)
- [Cloudflare goflow GHSA-9rpw-2h95-666c](https://github.com/advisories/)
- [mcuadros/go-syslog](https://github.com/mcuadros/go-syslog)
- [Go reproducible builds blog](https://go.dev/blog/rebuild)
- [Statically compiling Go programs](https://www.arp242.net/static-go.html)
- [golangci-lint changelog](https://golangci-lint.run/docs/product/changelog/)
- [google/uuid pkg.go.dev](https://pkg.go.dev/github.com/google/uuid)
- [Datadog Agent architecture](https://docs.datadoghq.com/agent/architecture/)
- [Distroless GitHub](https://github.com/googlecontainertools/distroless)
- [Vector buffering model](https://vector.dev/docs/about/under-the-hood/architecture/buffering-model/)
- [CVE-2025-22871 Go net/http request smuggling](https://www.sentinelone.com/vulnerability-database/cve-2025-22871/)
- [Python AEAD docs](https://cryptography.io/en/latest/hazmat/primitives/aead/)
- [Go crypto/cipher pkg.go.dev](https://pkg.go.dev/crypto/cipher)
