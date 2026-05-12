package transport

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"
)

// RotationThreshold is the fraction of remaining cert lifecycle at which
// the beacon initiates a /rotate-cert request. ADR-067 mandates 80% — i.e.,
// start rotation when 20% of the cert's lifetime remains. The numeric
// constant lives here so tests can reference it without re-deriving.
const RotationThreshold = 0.20

// Errors surfaced by cert parsing.
var (
	// ErrCertParse wraps a failed PEM/DER parse — file corrupt or truncated.
	ErrCertParse = errors.New("transport: failed to parse certificate")
)

// ParseCertPEM decodes a single PEM-encoded X.509 certificate. Returns
// ErrCertParse on any decode failure so callers can distinguish "file
// missing" from "file unreadable" at higher layers.
func ParseCertPEM(pemBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("%w: no PEM block found", ErrCertParse)
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%w: unexpected PEM type %q", ErrCertParse, block.Type)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCertParse, err)
	}
	return cert, nil
}

// LifecycleRemaining returns the fraction of the cert's validity window
// that is still in the future at instant `now`. Values are clamped to
// [0.0, 1.0]:
//
//   - now < cert.NotBefore (cert not yet valid; clock skew or just-issued):
//     returns 1.0. We DON'T treat early-issue as "needs rotation".
//   - now >= cert.NotAfter (expired): returns 0.0.
//   - NotAfter <= NotBefore (degenerate cert): returns 0.0 to force rotation.
func LifecycleRemaining(cert *x509.Certificate, now time.Time) float64 {
	total := cert.NotAfter.Sub(cert.NotBefore)
	if total <= 0 {
		return 0
	}
	if now.Before(cert.NotBefore) {
		return 1.0
	}
	if !now.Before(cert.NotAfter) {
		return 0
	}
	remaining := cert.NotAfter.Sub(now)
	return float64(remaining) / float64(total)
}

// ShouldRotate reports whether `cert` is within the rotation window at
// instant `now`. Equivalent to LifecycleRemaining(cert, now) <= 0.20.
func ShouldRotate(cert *x509.Certificate, now time.Time) bool {
	return LifecycleRemaining(cert, now) <= RotationThreshold
}
