package transport

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func certWithLifetime(notBefore, notAfter time.Time) *x509.Certificate {
	return &x509.Certificate{
		NotBefore: notBefore,
		NotAfter:  notAfter,
	}
}

func TestLifecycleRemainingMidpoint(t *testing.T) {
	now := time.Date(2026, 5, 11, 12, 0, 0, 0, time.UTC)
	cert := certWithLifetime(now.Add(-30*24*time.Hour), now.Add(30*24*time.Hour))
	remaining := LifecycleRemaining(cert, now)
	require.InDelta(t, 0.5, remaining, 0.001, "midpoint of 60-day lifetime = 0.5")
}

func TestLifecycleRemainingFresh(t *testing.T) {
	now := time.Date(2026, 5, 11, 12, 0, 0, 0, time.UTC)
	cert := certWithLifetime(now, now.Add(90*24*time.Hour))
	require.InDelta(t, 1.0, LifecycleRemaining(cert, now), 0.001,
		"just-issued cert has ~1.0 remaining")
}

func TestLifecycleRemainingExpired(t *testing.T) {
	now := time.Date(2026, 5, 11, 12, 0, 0, 0, time.UTC)
	cert := certWithLifetime(now.Add(-100*24*time.Hour), now.Add(-1*time.Hour))
	require.Equal(t, 0.0, LifecycleRemaining(cert, now),
		"expired cert returns 0.0")
}

func TestLifecycleRemainingNotYetValid(t *testing.T) {
	now := time.Date(2026, 5, 11, 12, 0, 0, 0, time.UTC)
	// Clock skew: cert issued for "tomorrow"; today's check should NOT
	// trigger rotation.
	cert := certWithLifetime(now.Add(1*time.Hour), now.Add(90*24*time.Hour))
	require.Equal(t, 1.0, LifecycleRemaining(cert, now),
		"not-yet-valid cert returns 1.0 (don't rotate)")
}

func TestLifecycleRemainingDegenerate(t *testing.T) {
	now := time.Date(2026, 5, 11, 12, 0, 0, 0, time.UTC)
	cert := certWithLifetime(now, now) // zero-length validity
	require.Equal(t, 0.0, LifecycleRemaining(cert, now))
}

func TestLifecycleRemainingAtRotationBoundary(t *testing.T) {
	now := time.Date(2026, 5, 11, 12, 0, 0, 0, time.UTC)
	// 90-day cert with exactly 18 days remaining = 0.20 = on the boundary.
	cert := certWithLifetime(now.Add(-72*24*time.Hour), now.Add(18*24*time.Hour))
	require.InDelta(t, 0.2, LifecycleRemaining(cert, now), 0.001)
	require.True(t, ShouldRotate(cert, now), "exactly at threshold should trigger rotation")
}

func TestShouldRotateJustBeforeBoundary(t *testing.T) {
	now := time.Date(2026, 5, 11, 12, 0, 0, 0, time.UTC)
	// 90-day cert with 25% remaining → no rotation.
	cert := certWithLifetime(now.Add(-67*24*time.Hour-12*time.Hour), now.Add(22*24*time.Hour+12*time.Hour))
	require.False(t, ShouldRotate(cert, now))
}

func TestShouldRotateJustPastBoundary(t *testing.T) {
	now := time.Date(2026, 5, 11, 12, 0, 0, 0, time.UTC)
	// 90-day cert with 15% remaining → rotate.
	cert := certWithLifetime(now.Add(-76*24*time.Hour-12*time.Hour), now.Add(13*24*time.Hour+12*time.Hour))
	require.True(t, ShouldRotate(cert, now))
}

func TestParseCertPEMHappy(t *testing.T) {
	pki := newPKI(t)
	cert, err := ParseCertPEM(pki.clientPEM)
	require.NoError(t, err)
	require.NotNil(t, cert)
	require.Equal(t, "test-beacon", cert.Subject.CommonName)
}

func TestParseCertPEMNoPEM(t *testing.T) {
	_, err := ParseCertPEM([]byte("not a pem block"))
	require.ErrorIs(t, err, ErrCertParse)
}

func TestParseCertPEMWrongType(t *testing.T) {
	pemBytes := []byte("-----BEGIN PRIVATE KEY-----\nMIGTAgEAMBMGByqGSM49\n-----END PRIVATE KEY-----\n")
	_, err := ParseCertPEM(pemBytes)
	require.ErrorIs(t, err, ErrCertParse)
}
