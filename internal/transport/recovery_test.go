package transport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// makeCertPair mints an ECDSA-P-256 cert+key pair signed by the same
// throwaway CA so tls.X509KeyPair accepts the pair. Used by the
// recovery-helper tests to populate one of the three on-disk slots
// with a parseable pair.
func makeCertPair(t *testing.T, cn string) (certPEM, keyPEM []byte) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "recov-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	clKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	clTpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clDER, err := x509.CreateCertificate(rand.Reader, clTpl, caCert, &clKey.PublicKey, caKey)
	require.NoError(t, err)
	clPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clDER})
	clKeyDER, err := x509.MarshalPKCS8PrivateKey(clKey)
	require.NoError(t, err)
	clKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: clKeyDER})
	return clPEM, clKeyPEM
}

// writePair drops a cert+key pair into a state dir with the given suffix
// (e.g., "" for live, ".new", ".prev").
func writePair(t *testing.T, dir, suffix string, cert, key []byte) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "beacon.crt"+suffix), cert, 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "beacon.key"+suffix), key, 0o600))
}

// --- T-1: live happy path ---

func TestLoadCertPairWithRecoveryLive(t *testing.T) {
	dir := t.TempDir()
	cert, key := makeCertPair(t, "live")
	writePair(t, dir, "", cert, key)

	gotCert, gotKey, slot, err := LoadCertPairWithRecovery(dir)
	require.NoError(t, err)
	require.Equal(t, CertSlotLive, slot)
	require.Equal(t, cert, gotCert)
	require.Equal(t, key, gotKey)

	// No promotion happened — .new + .prev still absent.
	_, err = os.Stat(filepath.Join(dir, "beacon.crt.new"))
	require.True(t, os.IsNotExist(err))
}

// --- T-1: .new fallback (crash between write and promote) ---

func TestLoadCertPairWithRecoveryFromNew(t *testing.T) {
	dir := t.TempDir()
	// Live is corrupt (cert exists but truncated → tls.X509KeyPair fails)
	// + .new is good. Simulates crash mid-promote-step-6 where .new is
	// fully written but live wasn't fully renamed.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "beacon.crt"), []byte("garbage"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "beacon.key"), []byte("garbage"), 0o600))
	cert, key := makeCertPair(t, "new")
	writePair(t, dir, ".new", cert, key)

	gotCert, gotKey, slot, err := LoadCertPairWithRecovery(dir)
	require.NoError(t, err)
	require.Equal(t, CertSlotNew, slot)
	require.Equal(t, cert, gotCert)
	require.Equal(t, key, gotKey)

	// .new must have been promoted to live; .new files gone.
	_, err = os.Stat(filepath.Join(dir, "beacon.crt.new"))
	require.True(t, os.IsNotExist(err), "beacon.crt.new must be promoted away")
	_, err = os.Stat(filepath.Join(dir, "beacon.key.new"))
	require.True(t, os.IsNotExist(err), "beacon.key.new must be promoted away")

	// Next call lands on live happy path.
	_, _, slot2, err := LoadCertPairWithRecovery(dir)
	require.NoError(t, err)
	require.Equal(t, CertSlotLive, slot2)
}

// --- T-1: .prev fallback (crash between archive and write-new) ---

func TestLoadCertPairWithRecoveryFromPrev(t *testing.T) {
	dir := t.TempDir()
	// Live entirely missing + .prev present. Simulates crash between
	// Rotator step 5 (rename old → .prev) and step 6 (write .new + promote).
	cert, key := makeCertPair(t, "prev")
	writePair(t, dir, ".prev", cert, key)

	gotCert, gotKey, slot, err := LoadCertPairWithRecovery(dir)
	require.NoError(t, err)
	require.Equal(t, CertSlotPrev, slot)
	require.Equal(t, cert, gotCert)
	require.Equal(t, key, gotKey)

	// .prev restored to live.
	_, err = os.Stat(filepath.Join(dir, "beacon.crt.prev"))
	require.True(t, os.IsNotExist(err))
}

// --- T-1: no-usable-pair surfaces ErrNoUsableCertPair ---

func TestLoadCertPairWithRecoveryNoUsablePair(t *testing.T) {
	dir := t.TempDir()
	// Nothing on disk.
	_, _, _, err := LoadCertPairWithRecovery(dir)
	require.ErrorIs(t, err, ErrNoUsableCertPair)
}

func TestLoadCertPairWithRecoveryAllCorrupt(t *testing.T) {
	dir := t.TempDir()
	// Files exist but parse fails in every slot.
	for _, suffix := range []string{"", ".new", ".prev"} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, "beacon.crt"+suffix), []byte("not a cert"), 0o644))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "beacon.key"+suffix), []byte("not a key"), 0o600))
	}
	_, _, _, err := LoadCertPairWithRecovery(dir)
	require.ErrorIs(t, err, ErrNoUsableCertPair)
}

// --- T-1: live wins over .new + .prev when all valid ---

func TestLoadCertPairWithRecoveryLiveWinsOverFallbacks(t *testing.T) {
	dir := t.TempDir()
	liveCert, liveKey := makeCertPair(t, "live")
	newCert, newKey := makeCertPair(t, "new")
	prevCert, prevKey := makeCertPair(t, "prev")
	writePair(t, dir, "", liveCert, liveKey)
	writePair(t, dir, ".new", newCert, newKey)
	writePair(t, dir, ".prev", prevCert, prevKey)

	gotCert, _, slot, err := LoadCertPairWithRecovery(dir)
	require.NoError(t, err)
	require.Equal(t, CertSlotLive, slot)
	require.Equal(t, liveCert, gotCert,
		"live must be preferred over .new/.prev when all parse")
}
