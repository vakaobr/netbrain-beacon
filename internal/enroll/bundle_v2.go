package enroll

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/argon2"

	bcrypto "github.com/vakaobr/netbrain-beacon/internal/crypto"
)

// ADR-007 (this repo) // pairs with netbrain ADR-087.
//
// Bundle v2 wire shape (after base64-decoding the EnrollmentTokenResponse.
// enrollment_bundle field):
//
//	{
//	  "version": 2,
//	  "bootstrap_token": "nbb_<60hex>",
//	  "expires_at": "...",
//	  "platform_ca_cert": "-----BEGIN CERTIFICATE-----...",
//	  "platform_pubkey_pem": "-----BEGIN PUBLIC KEY-----...",
//	  "warp_team_domain": "...",
//	  "warp_platform_hostname": "...",
//	  "warp_enrollment_envelope_b64": "...",
//	  "signature": "base64-ed25519-over-canonical-JSON"
//	}
//
// The signature covers the canonical-JSON encoding of every field EXCEPT
// `signature` and `platform_pubkey_pem` (the pubkey is for verifying the
// signature itself; signing it would be circular).
//
// The three `warp_*` fields are empty strings (not omitted) when the
// platform's Cloudflare integration is not configured. The mesh-on /
// mesh-off branch happens at the consumer (the enroll command), not at
// the parser.
//
// Envelope wire layout (after base64-decoding warp_enrollment_envelope_b64):
//
//	[ ver(1B)=0x01 | salt(16B) | iv(12B) | ciphertext(var) | tag(16B) ]
//
// KEK = argon2id(
//
//	password = bootstrap_token bytes,
//	salt     = envelope.salt,
//	time_cost   = 2,
//	memory_cost = 65536 KiB (64 MiB),
//	parallelism = 1,
//	output_len  = 32,
//
// ) — RFC 9106, OWASP 2025 baseline. Cross-language byte-exactness with the
// Python writer is verified by TestCrossLangBundleV2 in this package.
//
// Plaintext is canonical-JSON of:
//
//	{
//	  "cf_service_token_id":         "<UUID>",
//	  "cf_service_token_client_id":  "<client_id from CF>",
//	  "cf_service_token_client_secret": "<client_secret from CF>",
//	  "cf_team_account_id":          "<32-char hex>"
//	}
//
// AAD is canonical-JSON of {beacon_token_prefix, expires_at}, binding the
// envelope to its parent bundle — a stolen envelope cannot be lifted into
// a different bundle and replayed.

// Locked Argon2id parameters — change in lockstep with Python's
// ARGON2ID_* constants and the cross-language fixtures. Mismatch → byte
// drift caught by TestCrossLangBundleV2.
const (
	argon2idTimeCost      = 2
	argon2idMemoryCostKiB = 64 * 1024 // 64 MiB
	argon2idParallelism   = 1
	argon2idOutputLen     = 32 // AES-256

	bundleV2VersionByte = 0x01 // envelope version, NOT bundle JSON `version`
	bundleV2SaltLen     = 16
	bundleV2IVLen       = 12
	bundleV2TagLen      = 16
	bundleV2HeaderLen   = 1 + bundleV2SaltLen + bundleV2IVLen // 29

	// bundleV2MinEnvelopeLen — header + 16-byte GCM tag (empty plaintext).
	bundleV2MinEnvelopeLen = bundleV2HeaderLen + bundleV2TagLen // 45

	// bundleJSONVersion is the value of the bundle JSON `version` field
	// for v2. ParseBundleV2 rejects anything else with
	// ErrBundleVersionUnsupported.
	bundleJSONVersion = 2
)

// Errors surfaced by bundle v2 parsing and envelope decrypt.
var (
	// ErrBundleVersionUnsupported is returned when the bundle's `version`
	// field is missing or not equal to 2. v1 callers see this; the operator
	// must regenerate the bundle from a v2-aware platform.
	ErrBundleVersionUnsupported = errors.New("enrollment bundle version unsupported (only v2 is accepted)")

	// ErrWARPEnvelopeMalformed wraps base64 / structural decode failures
	// of the warp_enrollment_envelope_b64 field.
	ErrWARPEnvelopeMalformed = errors.New("WARP envelope malformed")

	// ErrWARPEnvelopeAuthFailed is the catch-all for "wrong bootstrap token",
	// "tampered envelope bytes", or "AAD mismatch" — by design we don't
	// reveal which check failed (standard AEAD discipline).
	ErrWARPEnvelopeAuthFailed = errors.New("WARP envelope authentication failed (tampered envelope, wrong token, or AAD mismatch)")
)

// BundleV2 is the verified contents of a v2 enrollment bundle.
//
// All caller-relevant fields are populated by ParseBundleV2. The three
// `WARP*` fields are empty strings when the platform's Cloudflare
// integration is not configured (mesh-off deployments); callers
// distinguish "mesh disabled" from "mesh enabled" by checking
// `WARPEnrollmentEnvelopeB64 != ""`.
type BundleV2 struct {
	Version           int       `json:"version"`
	BootstrapToken    string    `json:"bootstrap_token"`
	ExpiresAt         time.Time `json:"-"` // parsed from ExpiresAtRaw
	ExpiresAtRaw      string    `json:"expires_at"`
	PlatformCACert    string    `json:"platform_ca_cert"`
	PlatformPubKeyPEM string    `json:"platform_pubkey_pem"`
	Signature         string    `json:"signature"`

	WARPTeamDomain            string `json:"warp_team_domain"`
	WARPPlatformHostname      string `json:"warp_platform_hostname"`
	WARPEnrollmentEnvelopeB64 string `json:"warp_enrollment_envelope_b64"`
}

// MeshEnabled reports whether the bundle carries WARP enrollment
// credentials. Returns true when the encrypted envelope is non-empty —
// the WARP team domain and platform hostname accompany it.
func (b *BundleV2) MeshEnabled() bool {
	return b.WARPEnrollmentEnvelopeB64 != ""
}

// WARPCredentials is the decrypted plaintext payload of a v2 bundle's
// `warp_enrollment_envelope_b64`. The fields mirror what
// `warp-cli access add-account-key <client_id> <client_secret>` and
// `warp-cli access set-default-account <account_id>` consume.
type WARPCredentials struct {
	ServiceTokenID     string `json:"cf_service_token_id"`
	ServiceTokenClient string `json:"cf_service_token_client_id"`
	ServiceTokenSecret string `json:"cf_service_token_client_secret"`
	TeamAccountID      string `json:"cf_team_account_id"`
}

// ParseBundleV2 decodes a base64-encoded enrollment bundle, verifies the
// embedded ed25519 signature against the embedded pubkey, and applies
// the version + expiry gates.
//
// Returns ErrBundleVersionUnsupported when `version != 2` (or missing).
// v1 bundles emitted by the pre-cutover platform fail this check.
//
// allowUnsigned is the dev-only escape hatch; production callers pass
// false and the function rejects bundles with empty signature /
// platform_pubkey_pem.
func ParseBundleV2(b64 string, allowUnsigned bool) (*BundleV2, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("%w: base64 decode: %w", ErrBundleMalformed, err)
	}

	var b BundleV2
	if jerr := json.Unmarshal(raw, &b); jerr != nil {
		return nil, fmt.Errorf("%w: json decode: %w", ErrBundleMalformed, jerr)
	}

	// Version gate — first, so the operator gets a clear "regenerate your
	// bundle on a v2-aware platform" error rather than a cryptic "missing
	// field" or "signature invalid".
	if b.Version != bundleJSONVersion {
		return nil, fmt.Errorf("%w: got version=%d, want %d", ErrBundleVersionUnsupported, b.Version, bundleJSONVersion)
	}

	if b.BootstrapToken == "" {
		return nil, fmt.Errorf("%w: bootstrap_token is empty", ErrBundleMalformed)
	}
	if b.ExpiresAtRaw == "" {
		return nil, fmt.Errorf("%w: expires_at is empty", ErrBundleMalformed)
	}
	if b.PlatformCACert == "" {
		return nil, fmt.Errorf("%w: platform_ca_cert is empty", ErrBundleMalformed)
	}

	exp, err := time.Parse(time.RFC3339, b.ExpiresAtRaw)
	if err != nil {
		// Fallback for Python isoformat() variants without the colon in tz.
		exp, err = time.Parse("2006-01-02T15:04:05-0700", b.ExpiresAtRaw)
		if err != nil {
			return nil, fmt.Errorf("%w: expires_at parse: %w", ErrBundleMalformed, err)
		}
	}
	b.ExpiresAt = exp

	// Unsigned-bundle check (dev path).
	if b.Signature == "" || b.PlatformPubKeyPEM == "" {
		if !allowUnsigned {
			return nil, ErrBundleUnsigned
		}
		if time.Now().After(b.ExpiresAt) {
			return nil, fmt.Errorf("%w: expired at %s", ErrBundleExpired, b.ExpiresAt)
		}
		return &b, nil
	}

	// Reconstruct the canonical-JSON payload the platform signs (every v2
	// field except `signature` and `platform_pubkey_pem`).
	payload := map[string]any{
		"version":                      b.Version,
		"bootstrap_token":              b.BootstrapToken,
		"expires_at":                   b.ExpiresAtRaw,
		"platform_ca_cert":             b.PlatformCACert,
		"warp_team_domain":             b.WARPTeamDomain,
		"warp_platform_hostname":       b.WARPPlatformHostname,
		"warp_enrollment_envelope_b64": b.WARPEnrollmentEnvelopeB64,
	}

	pub, err := bcrypto.LoadPublicKeyPEM([]byte(b.PlatformPubKeyPEM))
	if err != nil {
		return nil, fmt.Errorf("%w: pubkey load: %w", ErrBundleMalformed, err)
	}
	if err := bcrypto.VerifyPayload(pub, payload, b.Signature); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBundleSignatureInvalid, err)
	}

	// Apply expiry only after signature verification — an attacker holding
	// a forged bundle would otherwise be able to roll the clock back.
	if time.Now().After(b.ExpiresAt) {
		return nil, fmt.Errorf("%w: expired at %s", ErrBundleExpired, b.ExpiresAt)
	}

	return &b, nil
}

// DeriveKEK runs Argon2id at the locked parameters and returns the
// 32-byte KEK used to authenticate-decrypt the WARP envelope.
//
// On commodity x86_64 hardware (4 cores) this takes ~1-3 seconds — the
// intended cost. The operator install runbook calls out the brief delay.
//
// Cross-language equivalence with Python `cryptography`'s Argon2id is
// verified byte-for-byte in TestCrossLangBundleV2.
func DeriveKEK(bootstrapToken, salt []byte) ([]byte, error) {
	if len(salt) != bundleV2SaltLen {
		return nil, fmt.Errorf("%w: salt must be %d bytes, got %d", ErrWARPEnvelopeMalformed, bundleV2SaltLen, len(salt))
	}
	return argon2.IDKey(
		bootstrapToken,
		salt,
		argon2idTimeCost,
		argon2idMemoryCostKiB,
		argon2idParallelism,
		argon2idOutputLen,
	), nil
}

// ParsedWARPEnvelope is the decoded structural view of the wire-format
// envelope without decrypting. Used by tests that want to inspect the
// salt/iv before computing the KEK.
type ParsedWARPEnvelope struct {
	Version    byte
	Salt       []byte // 16 bytes
	IV         []byte // 12 bytes
	Ciphertext []byte
	Tag        []byte // 16 bytes
}

// ParseWARPEnvelope validates the wire-format layout and returns its
// components. Does NOT decrypt — call DecryptWARPEnvelope (or
// DecryptWARPEnvelopeRaw) once the KEK is in hand.
func ParseWARPEnvelope(envelope []byte) (ParsedWARPEnvelope, error) {
	if len(envelope) < bundleV2MinEnvelopeLen {
		return ParsedWARPEnvelope{}, fmt.Errorf(
			"%w: envelope must be >= %d bytes (got %d)",
			ErrWARPEnvelopeMalformed, bundleV2MinEnvelopeLen, len(envelope),
		)
	}
	if envelope[0] != bundleV2VersionByte {
		return ParsedWARPEnvelope{}, fmt.Errorf(
			"%w: unsupported envelope version 0x%02x", ErrWARPEnvelopeMalformed, envelope[0],
		)
	}
	salt := envelope[1 : 1+bundleV2SaltLen]
	iv := envelope[1+bundleV2SaltLen : bundleV2HeaderLen]
	tag := envelope[len(envelope)-bundleV2TagLen:]
	ciphertext := envelope[bundleV2HeaderLen : len(envelope)-bundleV2TagLen]
	return ParsedWARPEnvelope{
		Version:    envelope[0],
		Salt:       salt,
		IV:         iv,
		Ciphertext: ciphertext,
		Tag:        tag,
	}, nil
}

// DecryptWARPEnvelopeRaw runs the full envelope decrypt against
// raw bytes (no base64 wrapper). Returns the plaintext canonical-JSON
// bytes on success; the caller json.Unmarshal-s into WARPCredentials.
//
// Tampered envelope / wrong bootstrap_token / AAD mismatch all surface
// as ErrWARPEnvelopeAuthFailed — by design we don't distinguish which
// check failed.
func DecryptWARPEnvelopeRaw(envelope, bootstrapToken, aad []byte) ([]byte, error) {
	parsed, err := ParseWARPEnvelope(envelope)
	if err != nil {
		return nil, err
	}
	kek, err := DeriveKEK(bootstrapToken, parsed.Salt)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cipher.NewGCM: %w", err)
	}
	ctAndTag := make([]byte, 0, len(parsed.Ciphertext)+len(parsed.Tag))
	ctAndTag = append(ctAndTag, parsed.Ciphertext...)
	ctAndTag = append(ctAndTag, parsed.Tag...)
	pt, err := aead.Open(nil, parsed.IV, ctAndTag, aad)
	if err != nil {
		return nil, ErrWARPEnvelopeAuthFailed
	}
	return pt, nil
}

// DecryptWARPEnvelope is the convenience entry point used by the enroll
// command: it base64-decodes the envelope, recomputes the AAD from the
// bundle's token_prefix + expires_at, runs Argon2id + AES-GCM, and
// returns a typed WARPCredentials.
//
// AAD layout matches the Python side (see ADR-087):
//
//	canonical-JSON({beacon_token_prefix: <first 12 chars of token>,
//	                expires_at: <bundle.expires_at as ISO-8601>})
//
// The 12-char prefix matches Python's BeaconRepository._token_prefix.
func (b *BundleV2) DecryptWARPEnvelope() (*WARPCredentials, error) {
	if !b.MeshEnabled() {
		return nil, fmt.Errorf("%w: warp_enrollment_envelope_b64 is empty", ErrWARPEnvelopeMalformed)
	}
	env, err := base64.StdEncoding.DecodeString(b.WARPEnrollmentEnvelopeB64)
	if err != nil {
		return nil, fmt.Errorf("%w: base64 decode: %w", ErrWARPEnvelopeMalformed, err)
	}

	aad, err := warpEnvelopeAAD(b.BootstrapToken, b.ExpiresAtRaw)
	if err != nil {
		return nil, err
	}

	pt, err := DecryptWARPEnvelopeRaw(env, []byte(b.BootstrapToken), aad)
	if err != nil {
		return nil, err
	}

	var creds WARPCredentials
	if err := json.Unmarshal(pt, &creds); err != nil {
		return nil, fmt.Errorf("%w: plaintext json decode: %w", ErrWARPEnvelopeMalformed, err)
	}
	// Sanity-check required fields — a partial decrypt could mean a
	// platform-side bug emitted a malformed payload, NOT a tampered
	// envelope (which would have failed the GCM tag).
	if creds.ServiceTokenClient == "" || creds.ServiceTokenSecret == "" || creds.TeamAccountID == "" {
		return nil, fmt.Errorf("%w: WARP credentials missing required fields", ErrWARPEnvelopeMalformed)
	}
	return &creds, nil
}

// warpEnvelopeAAD computes the canonical-JSON AAD bound to a bundle.
// Exported via the bundle method; this helper exists so tests can build
// the same AAD bytes without going through a full BundleV2.
func warpEnvelopeAAD(bootstrapToken, expiresAtRaw string) ([]byte, error) {
	prefix := bundleTokenPrefix(bootstrapToken)
	aadPayload := map[string]any{
		"beacon_token_prefix": prefix,
		"expires_at":          expiresAtRaw,
	}
	aad, err := bcrypto.CanonicalizePayload(aadPayload)
	if err != nil {
		return nil, fmt.Errorf("%w: aad canonicalize: %w", ErrWARPEnvelopeMalformed, err)
	}
	return aad, nil
}

// bundleTokenPrefix returns the first 12 chars of a bootstrap token —
// the same prefix the platform persists on the enrollment-token row
// (Python `BeaconRepository._token_prefix`). When the token is shorter
// than 12 chars (test-only path) the whole string is returned.
func bundleTokenPrefix(token string) string {
	const n = 12
	if len(token) <= n {
		return token
	}
	return token[:n]
}
