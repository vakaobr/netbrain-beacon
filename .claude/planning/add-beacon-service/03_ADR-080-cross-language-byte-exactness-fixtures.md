# ADR-080: Cross-language byte-exactness test fixtures (Python ↔ Go)

**Status:** Accepted
**Date:** 2026-05-10
**Context issue:** add-beacon-service
**Companion:** parent ADR-068 (beacon data encryption model), ADR-069 (wire format)

## Context

The beacon is a Go binary; the platform is Python. They must agree byte-for-byte on:

1. **UUIDv5 derivation** for `Idempotency-Key` (research §1.2 — Python passes `name.hex()` *string*; Go must pass `[]byte(hexString)`, NOT raw bytes).
2. **AES-256-GCM envelope encryption** — `[ver(1B)|dek_v(1B)|iv(12B)|ct|tag(16B)]`. Both sides must produce decryptable output for the other.
3. **ed25519 signature verification** of the rotated-DEK bundle (M-11) — Python `ed25519.sign(payload, priv)` produces bytes that Go's `ed25519.Verify(pub, payload, sig)` accepts.
4. **Canonical JSON** byte string used as the signed payload — Python `json.dumps(payload, sort_keys=True, separators=(",",":"), ensure_ascii=True)` must match Go's serializer exactly.

Each of these has at least one byte-level pitfall:

- Python `uuid5(ns, name_str)` converts `name_str` to UTF-8 bytes internally and SHA-1s `ns_bytes || name_utf8`. Go `uuid.NewSHA1(ns, name_bytes)` SHA-1s `ns_bytes || name_bytes`. They match **only when** `name_bytes == name_str.encode('utf-8')`. The Python side passes a hex string; the Go side must pass the bytes of that hex string, not the underlying 48 raw bytes the hex represents. Wrong: every batch returns `BEACON_IDEMPOTENCY_KEY_MISMATCH` 400.
- AES-GCM is symmetric in spec but Python's `cryptography` library hard-codes 128-bit tags, while Go's `cipher.NewGCMWithTagSize` allows 96/104/...128 bit tags. The Go side must use `cipher.NewGCM` (default 128-bit) and never the variant.
- Canonical JSON: Python's `ensure_ascii=True` escapes non-ASCII codepoints to `\uXXXX`; Go's `encoding/json` defaults to UTF-8 inline encoding. Without `ensure_ascii=True` parity, signature verify fails on any non-ASCII payload.
- ed25519: stdlib on both sides; signature is 64 bytes; no surprises *if* the canonical JSON match holds.

R-1 and R-2 in research are HIGH risk because these regressions would manifest as 100% data-push failure, with cryptic 400 codes, in production.

## Decision

We adopt a **mandatory cross-language fixture file** committed to the `netbrain-beacon` repo. The Python side (the netbrain server) generates known-input → expected-output JSON; the Go side reads the file and asserts byte-for-byte equality.

### Fixture file layout

```
tests/fixtures/cross_lang/
├── README.md                    # how to regenerate; SLA on freshness
├── uuid_v5_fixtures.json        # 10 cases of UUIDv5 derivation
├── aes_gcm_fixtures.json        # 5 cases of AES-256-GCM envelope round-trip
├── ed25519_fixtures.json        # 3 cases of signature verify
├── canonical_json_fixtures.json # 3 cases of canonical JSON byte-string
├── _generated_at.txt            # ISO8601 timestamp of last regeneration
└── _generator.py                # the script (committed; run to refresh)
```

### Fixture content shapes

**`uuid_v5_fixtures.json`:**

```json
[
  {
    "name": "small_payload",
    "namespace": "c4d2c5e0-1c9b-5b9e-8d0a-7f3a4e1c2b3d",
    "beacon_id": "0123456789abcdef0123456789abcdef",
    "plaintext_b64": "aGVsbG8=",
    "expected_uuid": "5f3a-...-..."
  },
  ... 9 more cases covering: empty plaintext, 1 MB plaintext,
      Unicode plaintext, varied beacon IDs, NDJSON-shaped payload
]
```

**`aes_gcm_fixtures.json`:**

```json
[
  {
    "name": "round_trip_small",
    "dek_hex": "6c0a...32-bytes...",
    "dek_v": 1,
    "iv_hex": "0102030405060708090a0b0c",
    "plaintext_b64": "...",
    "idempotency_key": "5f3a-...",
    "expected_envelope_b64": "AQEBAg...",
    "expected_aad_hex": "01<idempotency_key_16_bytes_hex>"
  },
  ... 4 more cases: empty plaintext (30-byte envelope), 1 MB,
      Unicode, dek_v boundary
]
```

**`ed25519_fixtures.json`:**

```json
[
  {
    "name": "rotated_dek_bundle",
    "private_key_hex": "...",       // for fixture regeneration only
    "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...",
    "payload_canonical_json": "{\"beacon_id\":\"...\",\"data_key_b64\":\"...\",\"data_key_version\":2,\"issued_at\":\"...\"}",
    "expected_signature_b64": "..."
  },
  ... 2 more cases: ASCII edge cases, 64-byte payload boundary
]
```

**`canonical_json_fixtures.json`:**

```json
[
  {
    "name": "sorted_keys_ascii_compact",
    "input": {"b": 1, "a": "x", "c": "tëst"},
    "expected_bytes_hex": "7b 22 61 22 3a 22 78 22 ... 7d"
  },
  ... 2 more: nested objects, escaped Unicode, large array
]
```

### Generation: `_generator.py`

This script lives in the **netbrain-beacon** repo (committed alongside the fixtures), but imports the **netbrain platform's** crypto modules to ensure the fixtures are derived from the actual production code:

```python
# tests/fixtures/cross_lang/_generator.py
import sys, json, base64, secrets, datetime
sys.path.insert(0, "../netbrain/services/api-gateway/src")
from crypto.idempotency import derive_batch_idempotency_key
from crypto.dek_envelope import wrap, unwrap, make_aad
from crypto.platform_signer import sign, canonicalize_payload
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
# ... emits the four fixture JSONs deterministically
```

The script has no random component beyond pre-committed test private keys; running it twice produces byte-identical output (so `git diff --exit-code` works in CI).

### Go-side consumption

```go
// internal/crypto/idempotency_test.go
func TestUUIDv5_CrossLangFixtures(t *testing.T) {
    fixtures := loadFixtures(t, "tests/fixtures/cross_lang/uuid_v5_fixtures.json")
    for _, fx := range fixtures {
        plaintext, _ := base64.StdEncoding.DecodeString(fx.PlaintextB64)
        beaconID, _ := uuid.Parse(fx.BeaconID)
        got := DeriveBatchKey(beaconID, plaintext)
        require.Equal(t, fx.ExpectedUUID, got.String(),
            "case %s: Python says %s, Go got %s — UUIDv5 derivation regressed",
            fx.Name, fx.ExpectedUUID, got.String())
    }
}
```

Equivalent test files for envelope, ed25519, canonical JSON.

### Coverage targets

| Concern | Cases |
|---|---|
| UUIDv5 | 10 (mix of plaintext sizes, encodings, boundary conditions) |
| AES-256-GCM | 5 (small / 1MB / empty / Unicode / dek_v boundary) |
| ed25519 verify | 3 (typical / ASCII edge / 64-byte boundary) |
| Canonical JSON | 3 (sorted keys / nested / Unicode escape) |

Total: 21 fixture cases, all run on every CI build, < 1 s aggregate runtime.

### Refresh procedure

When the Python side changes any of the 4 modules:

1. Regenerate via `python _generator.py` in the netbrain-beacon repo.
2. Commit the updated fixture JSONs in the same PR as the Python change (or a follow-up PR with link back).
3. CI runs `go test ./internal/crypto/... -run TestCrossLang` and asserts pass.
4. If a wire-format break is intended (rare), the platform PR + the beacon PR ship together with the new fixtures; old fixtures retired.

### Startup self-test

In addition to CI, the beacon performs a startup-time self-test on a hardcoded fixture:

```go
// internal/crypto/selftest.go
const _selftestUUIDv5 = "5f3a-..." // a known-answer UUIDv5

func init() {
    // Deterministic input → known UUID. Panic on mismatch.
    plaintext := []byte("netbrain-beacon-selftest")
    beaconID, _ := uuid.Parse("00000000-0000-0000-0000-000000000001")
    got := DeriveBatchKey(beaconID, plaintext)
    if got.String() != _selftestUUIDv5 {
        panic("UUIDv5 self-test FAILED — cross-language byte-exactness regression. Cannot start.")
    }
}
```

This catches a release-time regression that somehow snuck past CI (e.g., dependency upgrade with subtle behavior change). Runtime cost: < 1 ms at startup.

## Alternatives considered

### Alt A: Dual-binary integration test

Stand up Python + Go containers in CI, send a batch through Python encrypt → Go decrypt → assert plaintext.

- Pros: tests the full live path.
- Cons: 30-60 s setup; harder to debug (which side failed?); CI flake surface; Docker dependency.
- **Rejected:** fixtures give the same coverage with < 1 s runtime and clearer failure messages.

### Alt B: No cross-language tests; trust unit tests on each side

- Pros: simpler.
- Cons: byte-exactness regressions are silent in production until hit (R-1, R-2). Catastrophic when they fire — 100% data push failure.
- **Rejected.**

### Alt C: Generate fixtures in Go, validate in Python

- Pros: symmetric.
- Cons: Python side is locked (already shipped, doesn't run beacon-repo tests). Adding Python CI to this Go repo is overkill.
- **Rejected:** one-way (Python generates, Go validates) is sufficient for the contract.

### Alt D: `testcontainers-go` to run Python CI step

- Pros: live Python at test time.
- Cons: testcontainers is for integration tests (Phase 5), not for byte-exactness. Adds 5+ s per test run.
- **Rejected:** static fixtures are correct here.

## Consequences

### Positive

- Wire-format regressions in **either** side fail CI immediately, with a clear error message naming the failed case.
- Refresh procedure is documented and committed (the generator is in-repo).
- Startup self-test catches release-time regressions that escape CI.
- < 1 s test runtime; no Docker dependency.

### Negative

- Fixture file maintenance burden when crypto changes (rare — once in 2 years).
- Tight coupling: requires the netbrain repo to be checked out alongside netbrain-beacon when the generator runs. CI must clone both repos for fixture regeneration jobs.
- Fixtures contain test-only ed25519 private keys (clearly labeled; not the production key). `secrets-in-code-hunter` lint must whitelist `tests/fixtures/cross_lang/`.

### Operational

- Runbook §"Crypto regression": instructions for diagnosing a `BEACON_IDEMPOTENCY_KEY_MISMATCH` storm in prod (run cross-lang fixtures locally; if they fail, regression in this beacon build).
- Phase 7b pentest mandates a fixture-regeneration test as part of the test plan (does the fixture refresh procedure actually work?).

## Acceptance criteria

- 21 fixture cases committed under `tests/fixtures/cross_lang/`.
- Each Go-side `*_test.go` consumes the fixtures via `loadFixtures()` helper and runs in CI.
- `_generator.py` is hermetic — running twice produces identical bytes.
- Startup self-test in `init()` panics on mismatch.
- README.md in `tests/fixtures/cross_lang/` documents the refresh procedure.
- CI step `go test ./internal/crypto/... -run TestCrossLang` is part of the gate.