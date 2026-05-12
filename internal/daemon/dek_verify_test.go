package daemon

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	bcrypto "github.com/velonet/netbrain-beacon/internal/crypto"
)

// TestDEKVerifyEmptyDataKeyB64Contract locks in the cross-repo invariant
// documented in poll.go (F-4): both the platform and the beacon currently
// sign / verify a payload where `data_key_b64` is the empty string. This
// test signs a payload with data_key_b64="" and verifies it with the
// same value — proving the beacon's verify path accepts the platform's
// current production envelope. The negative case at the bottom proves a
// drift (one side empty, the other non-empty) is caught.
//
// If you are reading this because the test failed, you almost certainly
// changed `DataKeyB64` in poll.go to a non-empty value. That's only
// correct if the netbrain platform PR landed in the same release. See
// CONTRIBUTING.md "Shipping a wire-format change".
func TestDEKVerifyEmptyDataKeyB64Contract(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	const (
		beaconID = "abcdef00-1234-4567-8901-abcdef012345"
		issuedAt = "2026-05-12T10:00:00Z"
		version  = 3
	)

	// Sign what the platform produces today: empty data_key_b64.
	platformPayload := map[string]any{
		"beacon_id":        beaconID,
		"data_key_b64":     "",
		"data_key_version": version,
		"issued_at":        issuedAt,
	}
	canonical, err := bcrypto.CanonicalizePayload(platformPayload)
	require.NoError(t, err)
	sig := ed25519.Sign(priv, canonical)

	hdr := http.Header{}
	hdr.Set("X-Beacon-DataKey-Signature", base64.StdEncoding.EncodeToString(sig))

	// Verify with the beacon's matching envelope (empty data_key_b64).
	err = verifyDEKRotationSignature(hdr, pub, dekRotationPayload{
		BeaconID:       beaconID,
		DataKeyB64:     "",
		DataKeyVersion: version,
		IssuedAt:       issuedAt,
	})
	require.NoError(t, err, "platform signs empty data_key_b64; beacon must verify with empty data_key_b64")

	// Drift detector: if the beacon ever passes a non-empty value while
	// the platform still signs empty, verify MUST fail. This catches the
	// most likely future-bug: someone reads parsed.DataKeyB64 into the
	// payload before the platform actually populates the response body.
	err = verifyDEKRotationSignature(hdr, pub, dekRotationPayload{
		BeaconID:       beaconID,
		DataKeyB64:     "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		DataKeyVersion: version,
		IssuedAt:       issuedAt,
	})
	require.ErrorIs(t, err, ErrDEKSignatureInvalid,
		"non-empty data_key_b64 must fail-closed against a signature over empty data_key_b64")
}

// TestDEKVerifyRotationContractNonEmpty exercises the future-state when
// the platform begins delivering real rotated DEKs. The byte-equivalence
// of the canonical payload is already covered by tests/fixtures/cross_lang/
// ed25519_signed_bundle; this test just confirms the daemon's
// verifyDEKRotationSignature accepts a non-empty data_key_b64 if the
// signature was generated over the same non-empty value.
func TestDEKVerifyRotationContractNonEmpty(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	const (
		beaconID    = "abcdef00-1234-4567-8901-abcdef012345"
		issuedAt    = "2026-05-12T10:00:00Z"
		version     = 4
		newDEKBytes = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=" // 32 bytes b64
	)

	payload := map[string]any{
		"beacon_id":        beaconID,
		"data_key_b64":     newDEKBytes,
		"data_key_version": version,
		"issued_at":        issuedAt,
	}
	canonical, err := bcrypto.CanonicalizePayload(payload)
	require.NoError(t, err)
	sig := ed25519.Sign(priv, canonical)

	hdr := http.Header{}
	hdr.Set("X-Beacon-DataKey-Signature", base64.StdEncoding.EncodeToString(sig))

	err = verifyDEKRotationSignature(hdr, pub, dekRotationPayload{
		BeaconID:       beaconID,
		DataKeyB64:     newDEKBytes,
		DataKeyVersion: version,
		IssuedAt:       issuedAt,
	})
	require.NoError(t, err, "matching non-empty data_key_b64 must verify (future rotation flow)")
}
