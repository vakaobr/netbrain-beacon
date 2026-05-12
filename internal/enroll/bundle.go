package enroll

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/vakaobr/netbrain-beacon/internal/crypto"
)

// Errors surfaced by bundle parsing.
var (
	// ErrBundleMalformed wraps base64 / JSON decode failures or missing
	// required fields.
	ErrBundleMalformed = errors.New("enrollment bundle malformed")

	// ErrBundleSignatureInvalid is returned when the embedded ed25519
	// signature fails to verify against the embedded pubkey. The beacon
	// MUST treat the entire bundle as untrusted and refuse to proceed.
	ErrBundleSignatureInvalid = errors.New("enrollment bundle signature invalid")

	// ErrBundleExpired is returned when the bundle's expires_at is in the
	// past. The operator must request a fresh bundle from the admin UI.
	ErrBundleExpired = errors.New("enrollment bundle expired")

	// ErrBundleUnsigned is returned when the bundle was emitted by a
	// platform with no signing key configured (dev only). Production
	// beacons MUST refuse unsigned bundles.
	ErrBundleUnsigned = errors.New("enrollment bundle is unsigned (dev-only — refuse in production)")
)

// Bundle is the verified contents of an enrollment bundle.
//
// Layout matches the Python _build_signed_enrollment_bundle() canonical-JSON
// envelope in services/api-gateway/src/routes/beacons.py.
type Bundle struct {
	BootstrapToken    string    `json:"bootstrap_token"`
	ExpiresAt         time.Time `json:"-"` // parsed from ExpiresAtRaw
	ExpiresAtRaw      string    `json:"expires_at"`
	PlatformCACert    string    `json:"platform_ca_cert"`
	PlatformPubKeyPEM string    `json:"platform_pubkey_pem"`
	Signature         string    `json:"signature"`
}

// payload is the subset of Bundle fields the signature covers. MUST match
// the Python side's `payload` dict in _build_signed_enrollment_bundle.
type bundlePayload struct {
	BootstrapToken string `json:"bootstrap_token"`
	ExpiresAt      string `json:"expires_at"`
	PlatformCACert string `json:"platform_ca_cert"`
}

// ParseBundle decodes a base64-encoded signed enrollment bundle and
// verifies its embedded signature against the embedded pubkey.
//
// On any error — base64 decode, JSON decode, missing field, signature
// mismatch, or expiry — the function returns an error and the caller MUST
// NOT trust any field of the partial result.
//
// allowUnsigned is the dev-only escape hatch; production callers pass false
// and the function rejects bundles with empty `signature` / `platform_pubkey_pem`.
func ParseBundle(b64 string, allowUnsigned bool) (*Bundle, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("%w: base64 decode: %w", ErrBundleMalformed, err)
	}

	var b Bundle
	if jerr := json.Unmarshal(raw, &b); jerr != nil {
		return nil, fmt.Errorf("%w: json decode: %w", ErrBundleMalformed, jerr)
	}

	// Required-field validation. Each field has a specific meaning — a
	// missing one indicates either an old platform version or a tampered
	// bundle.
	if b.BootstrapToken == "" {
		return nil, fmt.Errorf("%w: bootstrap_token is empty", ErrBundleMalformed)
	}
	if b.ExpiresAtRaw == "" {
		return nil, fmt.Errorf("%w: expires_at is empty", ErrBundleMalformed)
	}
	if b.PlatformCACert == "" {
		return nil, fmt.Errorf("%w: platform_ca_cert is empty", ErrBundleMalformed)
	}

	// Parse expiry. Python emits .isoformat() which Go's RFC3339 accepts
	// when timezones are present (Python's default for an aware datetime).
	exp, err := time.Parse(time.RFC3339, b.ExpiresAtRaw)
	if err != nil {
		// Try a fallback — Python's isoformat() sometimes omits the colon
		// in tz offset for older versions. Accept the best-effort parse.
		exp, err = time.Parse("2006-01-02T15:04:05-0700", b.ExpiresAtRaw)
		if err != nil {
			return nil, fmt.Errorf("%w: expires_at parse: %w", ErrBundleMalformed, err)
		}
	}
	b.ExpiresAt = exp

	// Unsigned-bundle check.
	if b.Signature == "" || b.PlatformPubKeyPEM == "" {
		if !allowUnsigned {
			return nil, ErrBundleUnsigned
		}
		// Dev path — return without sig verify but still apply expiry.
		if time.Now().After(b.ExpiresAt) {
			return nil, fmt.Errorf("%w: expired at %s", ErrBundleExpired, b.ExpiresAt)
		}
		return &b, nil
	}

	// Signature verify. Reconstruct the canonical-JSON payload the Python
	// side signed: {bootstrap_token, expires_at, platform_ca_cert}.
	payload := bundlePayload{
		BootstrapToken: b.BootstrapToken,
		ExpiresAt:      b.ExpiresAtRaw,
		PlatformCACert: b.PlatformCACert,
	}
	payloadMap := map[string]any{
		"bootstrap_token":  payload.BootstrapToken,
		"expires_at":       payload.ExpiresAt,
		"platform_ca_cert": payload.PlatformCACert,
	}

	pub, err := crypto.LoadPublicKeyPEM([]byte(b.PlatformPubKeyPEM))
	if err != nil {
		return nil, fmt.Errorf("%w: pubkey load: %w", ErrBundleMalformed, err)
	}
	if err := crypto.VerifyPayload(pub, payloadMap, b.Signature); err != nil {
		// Wrap as ErrBundleSignatureInvalid so callers can distinguish
		// "bundle tampered" from "bundle missing fields".
		return nil, fmt.Errorf("%w: %w", ErrBundleSignatureInvalid, err)
	}

	// Signature checked out — now apply expiry. Doing this AFTER the
	// signature verify ensures an attacker can't roll the clock back via
	// a forged bundle: only signed bundles get this far.
	if time.Now().After(b.ExpiresAt) {
		return nil, fmt.Errorf("%w: expired at %s", ErrBundleExpired, b.ExpiresAt)
	}

	return &b, nil
}
