package enroll

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
)

// Errors surfaced by CSR generation.
var (
	// ErrCSRGeneration wraps any failure during keypair / CSR construction.
	ErrCSRGeneration = errors.New("enroll: csr generation failed")
)

// KeyMaterial bundles the freshly-generated keypair + CSR PEM that the
// beacon submits to /api/v1/beacons/enroll. The PrivateKeyPEM bytes MUST
// be persisted at 0600 immediately after a successful enrollment response;
// callers MUST NOT persist them before the response is verified.
type KeyMaterial struct {
	// PrivateKey holds the in-memory key; never serialise this directly,
	// use PrivateKeyPEM.
	PrivateKey *ecdsa.PrivateKey
	// PrivateKeyPEM is the PKCS#8-encoded PEM block of the private key.
	// Goes to disk at 0600 (`beacon.key`).
	PrivateKeyPEM []byte
	// CSRPEM is the PEM-encoded CSR sent to the server.
	CSRPEM []byte
}

// GenerateCSR creates an ECDSA-P-256 keypair and a CSR with an EMPTY
// Subject per ADR-067 §H-3.
//
// The server rebuilds the identity (CN = "beacon-{tenant}-{uuid}") to
// prevent a beacon from claiming a Subject of its choosing. The Subject
// the beacon sends here is ignored.
func GenerateCSR() (*KeyMaterial, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("%w: keygen: %w", ErrCSRGeneration, err)
	}

	tpl := &x509.CertificateRequest{
		// Subject is intentionally empty — server rebuilds it.
		Subject:            pkix.Name{},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tpl, priv)
	if err != nil {
		return nil, fmt.Errorf("%w: csr build: %w", ErrCSRGeneration, err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("%w: key marshal: %w", ErrCSRGeneration, err)
	}

	return &KeyMaterial{
		PrivateKey:    priv,
		PrivateKeyPEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		CSRPEM:        pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}),
	}, nil
}
