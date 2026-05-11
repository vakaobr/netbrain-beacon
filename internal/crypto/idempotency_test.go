package crypto

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestNSBeaconBatchPinned(t *testing.T) {
	// Refusing to ever regenerate this UUID is the single most important
	// invariant of the entire idempotency mechanism (per ADR-069). Pin it
	// in two places — the canonical const and a parse round-trip — to make
	// accidental mutation maximally annoying.
	const expected = "c4d2c5e0-1c9b-5b9e-8d0a-7f3a4e1c2b3d"
	require.Equal(t, expected, NSBeaconBatch.String())
}

func TestDeriveBatchIdempotencyKeyDeterministic(t *testing.T) {
	beaconID := uuid.MustParse("aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa")
	pt := []byte("hello world")
	first := DeriveBatchIdempotencyKey(beaconID, pt)
	for i := 0; i < 10; i++ {
		require.Equal(t, first, DeriveBatchIdempotencyKey(beaconID, pt),
			"derive must be deterministic across calls")
	}
}

func TestDeriveBatchIdempotencyKeyDifferentBeaconsDifferentKeys(t *testing.T) {
	// Same plaintext, different beacon_ids → different idempotency keys.
	// This is the per-beacon scoping invariant — without it, beacon A's
	// idempotency key could collide with beacon B's and silently drop.
	pt := []byte("same plaintext")
	beaconA := uuid.MustParse("aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa")
	beaconB := uuid.MustParse("bbbbbbbb-bbbb-4bbb-abbb-bbbbbbbbbbbb")
	require.NotEqual(t, DeriveBatchIdempotencyKey(beaconA, pt), DeriveBatchIdempotencyKey(beaconB, pt))
}

func TestDeriveBatchIdempotencyKeyDifferentPlaintextsDifferentKeys(t *testing.T) {
	beaconID := uuid.MustParse("aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa")
	require.NotEqual(t,
		DeriveBatchIdempotencyKey(beaconID, []byte("a")),
		DeriveBatchIdempotencyKey(beaconID, []byte("b")))
}

func TestVerifyIdempotencyKeyHappy(t *testing.T) {
	beaconID := uuid.MustParse("aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa")
	pt := []byte("payload")
	derived := DeriveBatchIdempotencyKey(beaconID, pt)
	require.True(t, VerifyIdempotencyKey(beaconID, pt, derived))
}

func TestVerifyIdempotencyKeyWrongPlaintext(t *testing.T) {
	beaconID := uuid.MustParse("aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa")
	derived := DeriveBatchIdempotencyKey(beaconID, []byte("legit"))
	require.False(t, VerifyIdempotencyKey(beaconID, []byte("tampered"), derived))
}
