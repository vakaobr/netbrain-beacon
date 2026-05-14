package enroll

import (
	"errors"
)

// Errors common to v1 and v2 parsing. The version gate
// (ErrBundleVersionUnsupported) lives in bundle_v2.go alongside the new
// parser; everything else stays here so callers can still ErrorIs against
// the existing sentinels.
var (
	// ErrBundleMalformed wraps base64 / JSON decode failures or missing
	// required fields.
	ErrBundleMalformed = errors.New("enrollment bundle malformed")

	// ErrBundleSignatureInvalid is returned when the embedded ed25519
	// signature fails to verify against the embedded pubkey. The beacon
	// MUST treat the entire bundle as untrusted and refuse to proceed.
	ErrBundleSignatureInvalid = errors.New("enrollment bundle signature invalid")

	// ErrBundleExpired is returned when the bundle's expires_at is in
	// the past. The operator must request a fresh bundle from the admin UI.
	ErrBundleExpired = errors.New("enrollment bundle expired")

	// ErrBundleUnsigned is returned when the bundle was emitted by a
	// platform with no signing key configured (dev only). Production
	// beacons MUST refuse unsigned bundles.
	ErrBundleUnsigned = errors.New("enrollment bundle is unsigned (dev-only — refuse in production)")
)

// Bundle is a backwards-compatible alias for BundleV2 so callers from the
// pre-cutover era keep compiling. New code should use BundleV2 directly.
//
// The v1 wire shape is gone — the platform emits v2 bundles unconditionally
// per ADR-087, and the discriminator inside ParseBundleV2 rejects anything
// else with ErrBundleVersionUnsupported.
type Bundle = BundleV2

// ParseBundle is the v1-era entry point. It now delegates to ParseBundleV2,
// which means: a v1 bundle (no `version` field, or `version != 2`) is
// rejected with ErrBundleVersionUnsupported; a v2 bundle is parsed and
// the returned *Bundle is a *BundleV2 with all v2 fields populated.
//
// Existing callers don't need to change. New code should call
// ParseBundleV2 directly so the v2 shape is visible at the call site.
func ParseBundle(b64 string, allowUnsigned bool) (*Bundle, error) {
	return ParseBundleV2(b64, allowUnsigned)
}
