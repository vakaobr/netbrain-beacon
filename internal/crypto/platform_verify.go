package crypto

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
)

// ed25519 platform-pubkey signature verification (M-11).
//
// The NetBrain platform owns one ed25519 keypair. The public half is
// distributed in each beacon's enrollment bundle (SPKI-PEM); the private
// half is Fernet-wrapped at the platform side and never leaves the server.
//
// When the platform delivers a rotated DEK in a config-poll response, it
// signs a canonical-JSON payload of
//
//	{data_key_b64, data_key_version, beacon_id, issued_at}
//
// with the platform priv key and emits the base64 signature in the
// X-Beacon-DataKey-Signature header. The beacon verifies the signature
// before overwriting its on-disk DEK. A failed verify means MITM at the
// TLS layer or a server-side regression — the beacon discards the new
// DEK and increments netbrain_beacon_dek_signature_verify_failed_total.
//
// Mirror of services/api-gateway/src/crypto/platform_signer.py.

// Errors surfaced by signature verification.
var (
	ErrPublicKeyEmpty   = errors.New("platform_verify: public key is empty")
	ErrPublicKeyFormat  = errors.New("platform_verify: public key format error")
	ErrSignatureFormat  = errors.New("platform_verify: signature is not valid base64")
	ErrSignatureInvalid = errors.New("platform_verify: signature does not authenticate payload")
	ErrCanonicalize     = errors.New("platform_verify: failed to canonicalize payload")
)

// LoadPublicKeyPEM parses an SPKI-PEM-encoded ed25519 public key.
//
// The PEM form is what the enrollment bundle delivers (per Python
// serialize_public_key_pem). The Go beacon stores this on disk at
// platform-pubkey.pem and loads it at daemon startup.
func LoadPublicKeyPEM(pemBytes []byte) (ed25519.PublicKey, error) {
	if len(pemBytes) == 0 {
		return nil, ErrPublicKeyEmpty
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("%w: no PEM block found", ErrPublicKeyFormat)
	}
	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("%w: unexpected PEM type %q", ErrPublicKeyFormat, block.Type)
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrPublicKeyFormat, err)
	}
	ed25519Pub, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: expected ed25519 public key, got %T", ErrPublicKeyFormat, pub)
	}
	return ed25519Pub, nil
}

// LoadPublicKeyRaw parses a raw 32-byte ed25519 public key. Used by the
// cross-language fixture loader (the fixture file ships pubkey_raw_b64,
// not PEM, to keep the JSON compact).
func LoadPublicKeyRaw(raw []byte) (ed25519.PublicKey, error) {
	if len(raw) == 0 {
		return nil, ErrPublicKeyEmpty
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: expected %d bytes, got %d", ErrPublicKeyFormat, ed25519.PublicKeySize, len(raw))
	}
	pub := make(ed25519.PublicKey, ed25519.PublicKeySize)
	copy(pub, raw)
	return pub, nil
}

// VerifyPayload returns nil if signatureB64 is a valid ed25519 signature
// over the canonical-JSON encoding of payload, signed by the private key
// counterpart of pub.
//
// Returns ErrSignatureInvalid on tamper. Returns ErrSignatureFormat or
// ErrCanonicalize for malformed inputs (caller can distinguish "tampered"
// from "garbage").
func VerifyPayload(pub ed25519.PublicKey, payload any, signatureB64 string) error {
	sig, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrSignatureFormat, err)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("%w: expected %d-byte signature, got %d", ErrSignatureFormat, ed25519.SignatureSize, len(sig))
	}

	canonical, err := CanonicalizePayload(payload)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrCanonicalize, err)
	}

	if !ed25519.Verify(pub, canonical, sig) {
		return ErrSignatureInvalid
	}
	return nil
}
