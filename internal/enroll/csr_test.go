package enroll

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGenerateCSRReturnsValidPEM(t *testing.T) {
	km, err := GenerateCSR()
	require.NoError(t, err)
	require.NotNil(t, km.PrivateKey)

	// Key PEM round-trip.
	block, _ := pem.Decode(km.PrivateKeyPEM)
	require.NotNil(t, block)
	require.Equal(t, "PRIVATE KEY", block.Type)
	parsedKeyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	require.NoError(t, err)
	parsedKey, ok := parsedKeyAny.(*ecdsa.PrivateKey)
	require.True(t, ok, "expected ECDSA private key")
	require.Equal(t, elliptic.P256(), parsedKey.Curve, "must be P-256 per ADR-067")

	// CSR PEM round-trip.
	cBlock, _ := pem.Decode(km.CSRPEM)
	require.NotNil(t, cBlock)
	require.Equal(t, "CERTIFICATE REQUEST", cBlock.Type)
	csr, err := x509.ParseCertificateRequest(cBlock.Bytes)
	require.NoError(t, err)
	require.NoError(t, csr.CheckSignature(), "CSR must self-verify")

	// Subject MUST be empty per ADR-067 §H-3 — server rebuilds identity.
	require.Empty(t, csr.Subject.CommonName)
	require.Empty(t, csr.Subject.Organization)
	require.Empty(t, csr.Subject.Country)
}

func TestGenerateCSRUnique(t *testing.T) {
	// 5 fresh CSRs must produce 5 distinct public keys.
	seen := make(map[string]struct{})
	for i := 0; i < 5; i++ {
		km, err := GenerateCSR()
		require.NoError(t, err)
		marshalled, err := x509.MarshalPKIXPublicKey(&km.PrivateKey.PublicKey)
		require.NoError(t, err)
		key := string(marshalled)
		_, dup := seen[key]
		require.False(t, dup, "CSR keypair collision on iteration %d", i)
		seen[key] = struct{}{}
	}
}
