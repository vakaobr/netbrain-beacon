package enroll

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	bcrypto "github.com/vakaobr/netbrain-beacon/internal/crypto"
)

// buildBundle is a test helper that mints a fresh ed25519 keypair, signs a
// bundle payload exactly like the Python netbrain side does, and returns
// the base64-encoded bundle ready for ParseBundle.
//
// Knobs let individual tests sabotage one field at a time:
//   - tamperSig: replace signature with garbage
//   - tamperPayload: mutate the canonical payload before signing (sig stays valid for old payload)
//   - expiresAt: override expiry
//   - omitField: zero out one field by name after signing
func buildBundle(t *testing.T, opts ...bundleOpt) string {
	t.Helper()
	cfg := bundleCfg{
		bootstrapToken: "nbb_test_token_abc123def456abcdef0123",
		expiresAt:      time.Now().Add(1 * time.Hour).UTC().Format(time.RFC3339),
		caCertPEM:      "-----BEGIN CERTIFICATE-----\nMIIBs\n-----END CERTIFICATE-----\n",
	}
	for _, o := range opts {
		o(&cfg)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))

	// Canonical-JSON-sign the same payload Python signs.
	payload := map[string]any{
		"bootstrap_token":  cfg.bootstrapToken,
		"expires_at":       cfg.expiresAt,
		"platform_ca_cert": cfg.caCertPEM,
	}
	canonical, err := bcrypto.CanonicalizePayload(payload)
	require.NoError(t, err)
	sig := ed25519.Sign(priv, canonical)
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	if cfg.tamperPayload {
		// Mutate AFTER signing so the bundle ships an invalid signature.
		payload["bootstrap_token"] = cfg.bootstrapToken + "-tampered"
	}

	if cfg.tamperSig {
		// Flip a byte in the signature.
		raw, decodeErr := base64.StdEncoding.DecodeString(sigB64)
		require.NoError(t, decodeErr)
		raw[0] ^= 0xff
		sigB64 = base64.StdEncoding.EncodeToString(raw)
	}

	bundle := map[string]any{
		"bootstrap_token":     payload["bootstrap_token"],
		"expires_at":          payload["expires_at"],
		"platform_ca_cert":    payload["platform_ca_cert"],
		"platform_pubkey_pem": pubPEM,
		"signature":           sigB64,
	}
	if cfg.omitPubkey {
		bundle["platform_pubkey_pem"] = ""
	}
	if cfg.omitSig {
		bundle["signature"] = ""
	}
	if cfg.omitToken {
		bundle["bootstrap_token"] = ""
	}
	if cfg.omitCA {
		bundle["platform_ca_cert"] = ""
	}

	raw, err := json.Marshal(bundle)
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(raw)
}

type bundleCfg struct {
	bootstrapToken string
	expiresAt      string
	caCertPEM      string
	tamperSig      bool
	tamperPayload  bool
	omitPubkey     bool
	omitSig        bool
	omitToken      bool
	omitCA         bool
}

type bundleOpt func(*bundleCfg)

func withExpiry(s string) bundleOpt    { return func(c *bundleCfg) { c.expiresAt = s } }
func withTamperedSignature() bundleOpt { return func(c *bundleCfg) { c.tamperSig = true } }
func withTamperedPayload() bundleOpt   { return func(c *bundleCfg) { c.tamperPayload = true } }
func withoutPubkey() bundleOpt         { return func(c *bundleCfg) { c.omitPubkey = true } }
func withoutSignature() bundleOpt      { return func(c *bundleCfg) { c.omitSig = true } }
func withoutToken() bundleOpt          { return func(c *bundleCfg) { c.omitToken = true } }
func withoutCA() bundleOpt             { return func(c *bundleCfg) { c.omitCA = true } }

// --- happy path ---

func TestParseBundleHappy(t *testing.T) {
	b := buildBundle(t)
	parsed, err := ParseBundle(b, false)
	require.NoError(t, err)
	require.NotEmpty(t, parsed.BootstrapToken)
	require.NotEmpty(t, parsed.PlatformCACert)
	require.NotEmpty(t, parsed.PlatformPubKeyPEM)
	require.True(t, parsed.ExpiresAt.After(time.Now()))
}

// --- error paths ---

func TestParseBundleBadBase64(t *testing.T) {
	_, err := ParseBundle("%%not-base64%%", false)
	require.ErrorIs(t, err, ErrBundleMalformed)
}

func TestParseBundleBadJSON(t *testing.T) {
	notJSON := base64.StdEncoding.EncodeToString([]byte("not json"))
	_, err := ParseBundle(notJSON, false)
	require.ErrorIs(t, err, ErrBundleMalformed)
}

func TestParseBundleMissingToken(t *testing.T) {
	b := buildBundle(t, withoutToken())
	_, err := ParseBundle(b, false)
	require.ErrorIs(t, err, ErrBundleMalformed)
}

func TestParseBundleMissingCA(t *testing.T) {
	b := buildBundle(t, withoutCA())
	_, err := ParseBundle(b, false)
	require.ErrorIs(t, err, ErrBundleMalformed)
}

func TestParseBundleTamperedSignature(t *testing.T) {
	// Critical security test: a tampered signature MUST be rejected.
	// The whole reason the bundle is signed is to defeat MITM.
	b := buildBundle(t, withTamperedSignature())
	_, err := ParseBundle(b, false)
	require.ErrorIs(t, err, ErrBundleSignatureInvalid)
}

func TestParseBundleTamperedPayload(t *testing.T) {
	// Mutate the bootstrap_token AFTER signing. The signature was over
	// the original token, so verify must fail.
	b := buildBundle(t, withTamperedPayload())
	_, err := ParseBundle(b, false)
	require.ErrorIs(t, err, ErrBundleSignatureInvalid)
}

func TestParseBundleUnsignedRejectedInProd(t *testing.T) {
	b := buildBundle(t, withoutSignature(), withoutPubkey())
	_, err := ParseBundle(b, false)
	require.ErrorIs(t, err, ErrBundleUnsigned)
}

func TestParseBundleUnsignedAcceptedInDev(t *testing.T) {
	b := buildBundle(t, withoutSignature(), withoutPubkey())
	parsed, err := ParseBundle(b, true)
	require.NoError(t, err)
	require.NotEmpty(t, parsed.BootstrapToken)
}

func TestParseBundleExpired(t *testing.T) {
	b := buildBundle(t, withExpiry(time.Now().Add(-1*time.Hour).UTC().Format(time.RFC3339)))
	_, err := ParseBundle(b, false)
	require.ErrorIs(t, err, ErrBundleExpired)
}
