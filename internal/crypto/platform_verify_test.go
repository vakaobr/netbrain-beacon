package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/require"
)

// genKeypair returns a fresh ed25519 keypair for unit testing.
// The cross-language fixture file pins a separate keypair for byte-exact
// signature checks — those tests live in fixtures_test.go.
func genKeypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return pub, priv
}

func pemEncode(t *testing.T, pub ed25519.PublicKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func sign(t *testing.T, priv ed25519.PrivateKey, payload any) string {
	t.Helper()
	canonical, err := CanonicalizePayload(payload)
	require.NoError(t, err)
	sig := ed25519.Sign(priv, canonical)
	return base64.StdEncoding.EncodeToString(sig)
}

func TestLoadPublicKeyPEMHappy(t *testing.T) {
	pub, _ := genKeypair(t)
	pemBytes := pemEncode(t, pub)

	got, err := LoadPublicKeyPEM(pemBytes)
	require.NoError(t, err)
	require.Equal(t, pub, got)
}

func TestLoadPublicKeyPEMEmpty(t *testing.T) {
	_, err := LoadPublicKeyPEM(nil)
	require.ErrorIs(t, err, ErrPublicKeyEmpty)
}

func TestLoadPublicKeyPEMGarbage(t *testing.T) {
	_, err := LoadPublicKeyPEM([]byte("not a pem block at all"))
	require.ErrorIs(t, err, ErrPublicKeyFormat)
}

func TestLoadPublicKeyPEMWrongPEMType(t *testing.T) {
	pub, _ := genKeypair(t)
	der, _ := x509.MarshalPKIXPublicKey(pub)
	badPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})
	_, err := LoadPublicKeyPEM(badPEM)
	require.ErrorIs(t, err, ErrPublicKeyFormat)
}

func TestLoadPublicKeyRawHappy(t *testing.T) {
	pub, _ := genKeypair(t)
	got, err := LoadPublicKeyRaw(pub)
	require.NoError(t, err)
	require.Equal(t, pub, got)
}

func TestLoadPublicKeyRawWrongLength(t *testing.T) {
	_, err := LoadPublicKeyRaw(make([]byte, 16))
	require.ErrorIs(t, err, ErrPublicKeyFormat)
}

func TestVerifyPayloadHappy(t *testing.T) {
	pub, priv := genKeypair(t)
	payload := map[string]any{
		"beacon_id":        "abcdef00-1234-4567-8901-abcdef012345",
		"data_key_b64":     "AAAA",
		"data_key_version": 1,
		"issued_at":        "2026-05-11T00:00:00Z",
	}
	sig := sign(t, priv, payload)

	require.NoError(t, VerifyPayload(pub, payload, sig))
}

func TestVerifyPayloadTamperedSignature(t *testing.T) {
	pub, priv := genKeypair(t)
	payload := map[string]any{"x": 1}
	sig := sign(t, priv, payload)

	// Flip a byte in the base64-decoded signature.
	raw, err := base64.StdEncoding.DecodeString(sig)
	require.NoError(t, err)
	raw[0] ^= 0xff
	tampered := base64.StdEncoding.EncodeToString(raw)

	err = VerifyPayload(pub, payload, tampered)
	require.ErrorIs(t, err, ErrSignatureInvalid)
}

func TestVerifyPayloadTamperedPayload(t *testing.T) {
	pub, priv := genKeypair(t)
	original := map[string]any{"x": 1}
	tampered := map[string]any{"x": 2}
	sig := sign(t, priv, original)

	err := VerifyPayload(pub, tampered, sig)
	require.ErrorIs(t, err, ErrSignatureInvalid)
}

func TestVerifyPayloadWrongPublicKey(t *testing.T) {
	_, priv := genKeypair(t)
	otherPub, _ := genKeypair(t)
	payload := map[string]any{"x": 1}
	sig := sign(t, priv, payload)

	err := VerifyPayload(otherPub, payload, sig)
	require.ErrorIs(t, err, ErrSignatureInvalid)
}

func TestVerifyPayloadGarbageSignature(t *testing.T) {
	pub, _ := genKeypair(t)
	err := VerifyPayload(pub, map[string]any{}, "%%not_base64%%")
	require.ErrorIs(t, err, ErrSignatureFormat)
}

func TestVerifyPayloadShortSignature(t *testing.T) {
	pub, _ := genKeypair(t)
	short := base64.StdEncoding.EncodeToString([]byte("too short"))
	err := VerifyPayload(pub, map[string]any{}, short)
	require.ErrorIs(t, err, ErrSignatureFormat)
}
