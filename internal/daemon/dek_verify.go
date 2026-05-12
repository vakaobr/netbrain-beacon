package daemon

import (
	"crypto/ed25519"
	"errors"
	"net/http"

	bcrypto "github.com/vakaobr/netbrain-beacon/internal/crypto"
)

// Errors surfaced by verifyDEKRotationSignature.
var (
	// ErrDEKSignatureMissing is returned when the caller asked for sig
	// verification but the header was empty. Distinguished from
	// ErrDEKSignatureInvalid so the daemon can log "no sig" vs "bad sig".
	ErrDEKSignatureMissing = errors.New("daemon: X-Beacon-DataKey-Signature header empty")

	// ErrDEKSignatureInvalid wraps the inner signature-verify failure.
	// Treated as a P1 security event by the daemon — logged + counted +
	// the new DEK is NOT swapped (M-11 fail-closed).
	ErrDEKSignatureInvalid = errors.New("daemon: X-Beacon-DataKey-Signature verify failed")
)

// dekRotationPayload is the canonical-JSON-encoded body the platform's
// ed25519 key signs. Matches Python's
// platform_signer._build_dek_signature_header() argument shape.
type dekRotationPayload struct {
	BeaconID       string `json:"beacon_id"`
	DataKeyB64     string `json:"data_key_b64"`
	DataKeyVersion int    `json:"data_key_version"`
	IssuedAt       string `json:"issued_at"`
}

// verifyDEKRotationSignature checks the X-Beacon-DataKey-Signature header
// against the platform pubkey. Used by the poll loop on every 200 OK that
// carries the header (per ADR-068 §"Rotation flow"). M-11 fail-closed.
//
// Returns ErrDEKSignatureMissing if the header is absent (caller treats
// as "no rotation this cycle" — not an error). Returns ErrDEKSignatureInvalid
// on tamper. Returns nil on success.
//
// payload is the {beacon_id, data_key_b64, data_key_version, issued_at}
// dict the caller assembled from the response body + response headers.
// The function NEVER reads the body itself — that's the poll loop's job.
func verifyDEKRotationSignature(headers http.Header, pubKey ed25519.PublicKey, payload dekRotationPayload) error {
	signatureB64 := headers.Get("X-Beacon-DataKey-Signature")
	if signatureB64 == "" {
		return ErrDEKSignatureMissing
	}
	payloadMap := map[string]any{
		"beacon_id":        payload.BeaconID,
		"data_key_b64":     payload.DataKeyB64,
		"data_key_version": payload.DataKeyVersion,
		"issued_at":        payload.IssuedAt,
	}
	if err := bcrypto.VerifyPayload(pubKey, payloadMap, signatureB64); err != nil {
		// Wrap so callers can errors.Is the sentinel + still surface the
		// inner cause for logging.
		return errors.Join(ErrDEKSignatureInvalid, err)
	}
	return nil
}
