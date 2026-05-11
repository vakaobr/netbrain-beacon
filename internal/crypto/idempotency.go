// Package crypto implements the cryptographic primitives the beacon shares
// with the NetBrain platform: UUIDv5 idempotency-key derivation (this file),
// AES-256-GCM data envelope wrap/unwrap, ed25519 signature verification, and
// streaming gunzip with byte cap.
//
// Every primitive in this package MUST be byte-compatible with the Python
// reference implementation under services/api-gateway/src/crypto/ in the
// netbrain repo. The cross-language fixture file at
// tests/fixtures/cross_lang/cross_lang_fixtures.json is the authoritative
// guardrail (ADR-080).
//
// Security mandates enforced here:
//   - M-4: CSPRNG-sourced IVs from crypto/rand (DEK envelope)
//   - M-6: streaming gunzip with byte cap (CWE-409)
//   - M-11: ed25519 signature verify before accepting rotated DEK
package crypto

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/google/uuid"
)

// NSBeaconBatch is the UUIDv5 namespace for beacon-batch Idempotency-Key
// derivation. Pinned at design time and MUST NEVER be regenerated — that
// would split the keyspace between old and new beacons and silently lose
// idempotency guarantees on rotation.
//
// Mirror of Python's NS_BEACON_BATCH in services/api-gateway/src/crypto/idempotency.py.
var NSBeaconBatch = uuid.MustParse("c4d2c5e0-1c9b-5b9e-8d0a-7f3a4e1c2b3d")

// DeriveBatchIdempotencyKey computes the UUIDv5 Idempotency-Key for a beacon
// data batch.
//
// Wire contract (ADR-069 §"Idempotency"):
//
//	name  = beacon_id.bytes ++ sha256(plaintext)        (48 bytes)
//	key   = uuid_v5(NS_BEACON_BATCH, name.hex())
//
// The .hex() is load-bearing — Python's reference implementation passes the
// 96-char hex string of `name` (not the raw 48 bytes) into uuid5. The Go side
// must mirror this by feeding `[]byte(hex.EncodeToString(name))` into
// uuid.NewSHA1. Skipping the hex step is the canonical R-1 byte-exactness
// failure flagged in ADR-080.
func DeriveBatchIdempotencyKey(beaconID uuid.UUID, plaintext []byte) uuid.UUID {
	digest := sha256.Sum256(plaintext)

	// name = beacon_id.bytes ++ sha256(plaintext)
	name := make([]byte, 0, 16+sha256.Size)
	name = append(name, beaconID[:]...)
	name = append(name, digest[:]...)

	// Python equivalent: uuid5(NS_BEACON_BATCH, name.hex())
	// The hex string is UTF-8 encoded by Python's uuid5 (ASCII-safe), so
	// []byte(hex string) yields identical bytes on both sides.
	hexName := hex.EncodeToString(name)
	return uuid.NewSHA1(NSBeaconBatch, []byte(hexName))
}

// VerifyIdempotencyKey is the server-side M-2-AAD check; included here for
// completeness even though the beacon (this binary) is on the client side.
//
// Returns true when the server-recomputed canonical key matches the
// client-supplied header. The beacon NEVER calls this — the server does.
// Defined here so beacon tests can assert their derivation matches the
// server's verification path.
func VerifyIdempotencyKey(expectedBeaconID uuid.UUID, plaintext []byte, clientSupplied uuid.UUID) bool {
	return DeriveBatchIdempotencyKey(expectedBeaconID, plaintext) == clientSupplied
}
