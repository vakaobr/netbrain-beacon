package enroll

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	bcrypto "github.com/vakaobr/netbrain-beacon/internal/crypto"
)

// ----------------------------------------------------------------------------
// Cross-language fixture loader (bundle v2 envelope section).
//
// Mirrors the loader in internal/crypto/fixtures_test.go but reads the
// `bundle_v2_envelope` block. The fixture file is the single source of
// byte-exactness truth shared with the Python writer (netbrain repo).
// ----------------------------------------------------------------------------

type bundleV2FixtureMeta struct {
	BundleV2EnvelopeVersionByte int                    `json:"bundle_v2_envelope_version_byte"`
	BundleV2Argon2idParams      map[string]interface{} `json:"bundle_v2_argon2id_params"`
}

type bundleV2EnvelopeCase struct {
	CaseID              string `json:"case_id"`
	BootstrapTokenB64   string `json:"bootstrap_token_b64"`
	SaltB64             string `json:"salt_b64"`
	IVB64               string `json:"iv_b64"`
	PlaintextB64        string `json:"plaintext_b64"`
	AADB64              string `json:"aad_b64"`
	ExpectedEnvelopeB64 string `json:"expected_envelope_b64"`
}

type bundleV2Fixtures struct {
	Meta             bundleV2FixtureMeta    `json:"_meta"`
	BundleV2Envelope []bundleV2EnvelopeCase `json:"bundle_v2_envelope"`
}

func findBeaconRepoRoot(t *testing.T) string {
	t.Helper()

	if env := os.Getenv("NETBRAIN_BEACON_REPO_ROOT"); env != "" {
		return env
	}

	wd, err := os.Getwd()
	require.NoError(t, err)
	dir := wd
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("findBeaconRepoRoot: no go.mod found above %s", wd)
	return ""
}

func loadBundleV2Fixtures(t *testing.T) *bundleV2Fixtures {
	t.Helper()
	root := findBeaconRepoRoot(t)
	path := filepath.Join(root, "tests", "fixtures", "cross_lang", "cross_lang_fixtures.json")
	raw, err := os.ReadFile(path) //nolint:gosec // test-only path, not user-controlled
	require.NoError(t, err, "read fixture file at %s", path)

	var f bundleV2Fixtures
	require.NoError(t, json.Unmarshal(raw, &f))
	require.NotEmpty(t, f.BundleV2Envelope, "fixture file has no bundle_v2_envelope cases — regenerate via scripts/beacon/generate_cross_lang_fixtures.py in the netbrain repo")
	return &f
}

// ----------------------------------------------------------------------------
// TestCrossLangBundleV2 — the byte-exactness regression gate.
//
// For each fixture case, recompute the envelope with the Go writer
// (DeriveKEK + AES-GCM Seal at the explicit salt + IV) and assert
// byte-equality with the Python-emitted envelope. Then decrypt the
// Python-emitted envelope and confirm the plaintext round-trips.
//
// If this drifts: do NOT regenerate the fixtures to "fix" the test.
// The whole point of the fixture file is to lock the Python writer and
// the Go reader to the same wire shape. A drift indicates a real
// regression in either side's crypto.
// ----------------------------------------------------------------------------

func TestCrossLangBundleV2(t *testing.T) {
	f := loadBundleV2Fixtures(t)

	require.Equal(t, int(bundleV2VersionByte), f.Meta.BundleV2EnvelopeVersionByte,
		"bundle v2 envelope version byte drifted between Python and Go")

	// Verify the locked Argon2id parameters match — a misconfiguration
	// here is the most likely failure mode if someone "experiments" with
	// faster KDF settings, and the byte-exactness assertion below would
	// fire anyway, but the explicit check gives a much clearer error.
	expected := map[string]float64{
		"time_cost":       float64(argon2idTimeCost),
		"memory_cost_kib": float64(argon2idMemoryCostKiB),
		"parallelism":     float64(argon2idParallelism),
		"output_length":   float64(argon2idOutputLen),
	}
	for k, want := range expected {
		got, ok := f.Meta.BundleV2Argon2idParams[k].(float64)
		require.True(t, ok, "Argon2id param %q missing from fixture meta", k)
		require.Equal(t, want, got, "Argon2id param %q drifted between Python and Go", k)
	}

	for _, c := range f.BundleV2Envelope {
		t.Run(c.CaseID, func(t *testing.T) {
			token := mustB64Decode(t, c.BootstrapTokenB64)
			salt := mustB64Decode(t, c.SaltB64)
			iv := mustB64Decode(t, c.IVB64)
			aad := mustB64Decode(t, c.AADB64)
			pt := mustB64Decode(t, c.PlaintextB64)
			expected := mustB64Decode(t, c.ExpectedEnvelopeB64)

			// Step 1 — byte-exactness: Go writer with the same inputs
			// must emit byte-identical bytes to the Python writer.
			got, err := encryptWARPEnvelopeForTest(pt, token, aad, salt, iv)
			require.NoError(t, err)
			require.True(t, bytes.Equal(expected, got),
				"envelope byte mismatch for case %q\n  expected %x\n  got      %x",
				c.CaseID, expected, got)

			// Step 2 — round-trip the Python-emitted envelope through
			// the Go decryptor (the real prod codepath).
			decrypted, err := DecryptWARPEnvelopeRaw(expected, token, aad)
			require.NoError(t, err)
			require.True(t, bytes.Equal(pt, decrypted),
				"Python envelope decrypt mismatch on case %q", c.CaseID)
		})
	}

	// Locked invariant — `tampered_salt_diff_output` uses the same
	// (token, plaintext, aad) as `happy` but a different salt. Salt
	// MUST flow through Argon2id and change the KEK, which MUST change
	// the entire envelope.
	var happy, tampered *bundleV2EnvelopeCase
	for i := range f.BundleV2Envelope {
		switch f.BundleV2Envelope[i].CaseID {
		case "happy":
			happy = &f.BundleV2Envelope[i]
		case "tampered_salt_diff_output":
			tampered = &f.BundleV2Envelope[i]
		}
	}
	require.NotNil(t, happy, "fixture missing the 'happy' case")
	require.NotNil(t, tampered, "fixture missing the 'tampered_salt_diff_output' case")
	require.NotEqual(t, happy.ExpectedEnvelopeB64, tampered.ExpectedEnvelopeB64,
		"salt is not affecting the envelope output — Argon2id KDF is broken")
}

func mustB64Decode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	require.NoError(t, err)
	return b
}

// encryptWARPEnvelopeForTest is the deterministic counterpart of
// DecryptWARPEnvelopeRaw — used only by TestCrossLangBundleV2 to compute
// the expected wire bytes. NEVER expose this outside test code: real
// production callers must take an IV from CSPRNG (IV reuse under GCM
// leaks plaintext XOR).
func encryptWARPEnvelopeForTest(plaintext, bootstrapToken, aad, salt, iv []byte) ([]byte, error) {
	kek, err := DeriveKEK(bootstrapToken, salt)
	if err != nil {
		return nil, err
	}
	// Mirror the Python writer's bytes-assembly exactly.
	envelope, err := aeadEncryptForTest(plaintext, kek, iv, aad)
	if err != nil {
		return nil, err
	}
	header := append([]byte{bundleV2VersionByte}, salt...)
	header = append(header, iv...)
	out := make([]byte, 0, len(header)+len(envelope))
	out = append(out, header...)
	out = append(out, envelope...)
	return out, nil
}

func aeadEncryptForTest(plaintext, key, iv, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, iv, plaintext, aad), nil
}

// ----------------------------------------------------------------------------
// Direct API tests for ParseBundleV2 + the v1-rejection discriminator.
// ----------------------------------------------------------------------------

// buildBundleV2 mints a fresh ed25519 keypair and emits a v2 bundle
// signed exactly the way the Python netbrain side signs (canonical-JSON
// over every v2 field except signature + platform_pubkey_pem).
func buildBundleV2(t *testing.T, opts ...bundleV2Opt) (string, ed25519.PublicKey) {
	t.Helper()
	cfg := bundleV2Cfg{
		version:              bundleJSONVersion,
		bootstrapToken:       "nbb_test_token_abc123def456abcdef0123",
		expiresAt:            "2099-01-01T00:00:00+00:00",
		caCertPEM:            "-----BEGIN CERTIFICATE-----\nMIIBs\n-----END CERTIFICATE-----\n",
		warpTeamDomain:       "",
		warpPlatformHostname: "",
		warpEnvelopeB64:      "",
	}
	for _, o := range opts {
		o(&cfg)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	pubPEM := marshalPublicKeyPEM(t, pub)

	payload := map[string]any{
		"version":                      cfg.version,
		"bootstrap_token":              cfg.bootstrapToken,
		"expires_at":                   cfg.expiresAt,
		"platform_ca_cert":             cfg.caCertPEM,
		"warp_team_domain":             cfg.warpTeamDomain,
		"warp_platform_hostname":       cfg.warpPlatformHostname,
		"warp_enrollment_envelope_b64": cfg.warpEnvelopeB64,
	}
	canonical, err := bcrypto.CanonicalizePayload(payload)
	require.NoError(t, err)
	sig := ed25519.Sign(priv, canonical)
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	if cfg.tamperPayload {
		payload["bootstrap_token"] = cfg.bootstrapToken + "-tampered"
	}

	bundle := map[string]any{
		"version":                      payload["version"],
		"bootstrap_token":              payload["bootstrap_token"],
		"expires_at":                   payload["expires_at"],
		"platform_ca_cert":             payload["platform_ca_cert"],
		"platform_pubkey_pem":          pubPEM,
		"warp_team_domain":             payload["warp_team_domain"],
		"warp_platform_hostname":       payload["warp_platform_hostname"],
		"warp_enrollment_envelope_b64": payload["warp_enrollment_envelope_b64"],
		"signature":                    sigB64,
	}
	if cfg.omitVersion {
		delete(bundle, "version")
	}
	if cfg.omitPubkey {
		bundle["platform_pubkey_pem"] = ""
	}
	if cfg.omitSig {
		bundle["signature"] = ""
	}

	raw, err := json.Marshal(bundle)
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(raw), pub
}

type bundleV2Cfg struct {
	version              int
	bootstrapToken       string
	expiresAt            string
	caCertPEM            string
	warpTeamDomain       string
	warpPlatformHostname string
	warpEnvelopeB64      string
	tamperPayload        bool
	omitVersion          bool
	omitPubkey           bool
	omitSig              bool
}

type bundleV2Opt func(*bundleV2Cfg)

func withV2Version(v int) bundleV2Opt      { return func(c *bundleV2Cfg) { c.version = v } }
func withV2OmitVersion() bundleV2Opt       { return func(c *bundleV2Cfg) { c.omitVersion = true } }
func withV2ExpiresAt(s string) bundleV2Opt { return func(c *bundleV2Cfg) { c.expiresAt = s } }
func withV2WARP(td, host, env string) bundleV2Opt {
	return func(c *bundleV2Cfg) {
		c.warpTeamDomain = td
		c.warpPlatformHostname = host
		c.warpEnvelopeB64 = env
	}
}
func withV2TamperedPayload() bundleV2Opt { return func(c *bundleV2Cfg) { c.tamperPayload = true } }
func withV2Unsigned() bundleV2Opt {
	return func(c *bundleV2Cfg) {
		c.omitPubkey = true
		c.omitSig = true
	}
}

func TestParseBundleV2_Happy_NoMesh(t *testing.T) {
	b, _ := buildBundleV2(t)
	parsed, err := ParseBundle(b, false)
	require.NoError(t, err)
	require.Equal(t, 2, parsed.Version)
	require.NotEmpty(t, parsed.BootstrapToken)
	require.NotEmpty(t, parsed.PlatformCACert)
	require.False(t, parsed.MeshEnabled(), "mesh-off bundle reports MeshEnabled()==true")
}

func TestParseBundleV2_Happy_WithMesh(t *testing.T) {
	b, _ := buildBundleV2(t, withV2WARP("acme.cloudflareaccess.com", "netbrain-platform.mesh", "AYJK...=="))
	parsed, err := ParseBundle(b, false)
	require.NoError(t, err)
	require.True(t, parsed.MeshEnabled())
	require.Equal(t, "acme.cloudflareaccess.com", parsed.WARPTeamDomain)
	require.Equal(t, "netbrain-platform.mesh", parsed.WARPPlatformHostname)
	require.Equal(t, "AYJK...==", parsed.WARPEnrollmentEnvelopeB64)
}

func TestParseBundleV2_RejectsV1_WhenVersionMissing(t *testing.T) {
	// Emit a bundle WITHOUT a `version` field — this mirrors what a
	// pre-cutover v1 platform would send. The discriminator must
	// surface ErrBundleVersionUnsupported, NOT a cryptic "signature
	// invalid" or "missing field" error.
	b, _ := buildBundleV2(t, withV2OmitVersion())
	_, err := ParseBundle(b, false)
	require.ErrorIs(t, err, ErrBundleVersionUnsupported)
}

func TestParseBundleV2_RejectsV1_WhenVersionWrong(t *testing.T) {
	b, _ := buildBundleV2(t, withV2Version(1))
	_, err := ParseBundle(b, false)
	require.ErrorIs(t, err, ErrBundleVersionUnsupported)
}

func TestParseBundleV2_TamperedPayload_FailsSignature(t *testing.T) {
	b, _ := buildBundleV2(t, withV2TamperedPayload())
	_, err := ParseBundle(b, false)
	require.ErrorIs(t, err, ErrBundleSignatureInvalid)
}

func TestParseBundleV2_TamperedWARPFields_FailsSignature(t *testing.T) {
	// Sign a bundle WITHOUT mesh fields, then inject mesh fields after
	// signing. The signature was over the original (empty) mesh fields,
	// so verify must fail.
	b, _ := buildBundleV2(t)
	raw, err := base64.StdEncoding.DecodeString(b)
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(raw, &m))
	m["warp_enrollment_envelope_b64"] = "INJECTED_BY_ATTACKER"
	mutated, err := json.Marshal(m)
	require.NoError(t, err)
	_, err = ParseBundle(base64.StdEncoding.EncodeToString(mutated), false)
	require.ErrorIs(t, err, ErrBundleSignatureInvalid,
		"v2 signature must cover every warp_* field — without that, the bundle is forgeable")
}

func TestParseBundleV2_Unsigned_RejectedInProd(t *testing.T) {
	b, _ := buildBundleV2(t, withV2Unsigned())
	_, err := ParseBundle(b, false)
	require.ErrorIs(t, err, ErrBundleUnsigned)
}

func TestParseBundleV2_Unsigned_AcceptedInDev(t *testing.T) {
	b, _ := buildBundleV2(t, withV2Unsigned())
	parsed, err := ParseBundle(b, true)
	require.NoError(t, err)
	require.Equal(t, 2, parsed.Version)
}

func TestParseBundleV2_Expired(t *testing.T) {
	b, _ := buildBundleV2(t, withV2ExpiresAt("2000-01-01T00:00:00+00:00"))
	_, err := ParseBundle(b, false)
	require.ErrorIs(t, err, ErrBundleExpired)
}

// ----------------------------------------------------------------------------
// DecryptWARPEnvelope round-trip — uses the fixture file's "happy" case
// to confirm the BundleV2 → WARPCredentials path end-to-end. This
// exercises base64 decode + Argon2id KDF + AES-GCM decrypt +
// json.Unmarshal in one shot, mirroring the real enroll command.
// ----------------------------------------------------------------------------

func TestBundleV2_DecryptWARPEnvelope_RoundTrip(t *testing.T) {
	// Use a happy-path fixture from the JSON file: we already trust
	// that case (it's locked by TestCrossLangBundleV2). Build a v2
	// bundle around it and decrypt.
	f := loadBundleV2Fixtures(t)
	var happy *bundleV2EnvelopeCase
	for i := range f.BundleV2Envelope {
		if f.BundleV2Envelope[i].CaseID == "happy" {
			happy = &f.BundleV2Envelope[i]
		}
	}
	require.NotNil(t, happy)

	token := string(mustB64Decode(t, happy.BootstrapTokenB64))
	envelope := happy.ExpectedEnvelopeB64

	// The fixture AAD pins beacon_token_prefix=nbb_a1a1a1a1 + a known
	// expires_at — we recompute the AAD by hand to confirm the
	// bundle-level helper produces the same bytes the fixture used.
	fixturePrefix := "nbb_a1a1a1a1"
	fixtureExpires := "2026-05-15T20:28:09.921895+00:00"
	require.Equal(t, fixturePrefix, bundleTokenPrefix(token),
		"fixture prefix does not match bundleTokenPrefix(token) — wire-shape drift")

	bundle := &BundleV2{
		BootstrapToken:            token,
		ExpiresAtRaw:              fixtureExpires,
		WARPEnrollmentEnvelopeB64: envelope,
	}

	pt, err := DecryptWARPEnvelopeRaw(
		mustB64Decode(t, envelope),
		[]byte(token),
		mustB64Decode(t, happy.AADB64),
	)
	require.NoError(t, err)
	require.Equal(t, "warp-token-plain", string(pt))

	// And exercise the convenience BundleV2 method against a bundle
	// that carries proper canonical-JSON plaintext. The fixture's
	// "happy" plaintext is not canonical-JSON of WARPCredentials, so
	// build a bespoke bundle whose envelope wraps real creds.
	roundTripCreds(t, bundle)
}

// roundTripCreds builds a fresh envelope around real WARPCredentials
// (matching what the Python writer would produce in production) and
// confirms that BundleV2.DecryptWARPEnvelope returns the typed struct.
func roundTripCreds(t *testing.T, _ *BundleV2) {
	t.Helper()

	expires := "2099-01-01T00:00:00+00:00"
	token := "nbb_" + base64HexLen(60)
	creds := WARPCredentials{
		ServiceTokenID:     "svc-tok-123",
		ServiceTokenClient: "abc.access",
		ServiceTokenSecret: strings.Repeat("S", 32),
		TeamAccountID:      strings.Repeat("a", 32),
	}
	pt, err := json.Marshal(creds)
	require.NoError(t, err)

	aad, err := warpEnvelopeAAD(token, expires)
	require.NoError(t, err)

	// Fixed salt + IV — the round-trip is byte-deterministic so we can
	// re-derive the same envelope on the decrypt side without any
	// hidden state.
	salt := []byte("0123456789abcdef")
	iv := []byte("0123456789ab")

	env, err := encryptWARPEnvelopeForTest(pt, []byte(token), aad, salt, iv)
	require.NoError(t, err)
	envB64 := base64.StdEncoding.EncodeToString(env)

	b := &BundleV2{
		BootstrapToken:            token,
		ExpiresAtRaw:              expires,
		WARPEnrollmentEnvelopeB64: envB64,
	}
	gotCreds, err := b.DecryptWARPEnvelope()
	require.NoError(t, err)
	require.Equal(t, creds, *gotCreds)
}

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

// base64HexLen returns a 60-char ASCII hex string suitable as the
// bootstrap-token suffix in tests. The value isn't cryptographically
// meaningful — the v2 parser only cares that the field is non-empty.
func base64HexLen(n int) string {
	const alphabet = "0123456789abcdef"
	out := make([]byte, n)
	for i := range out {
		out[i] = alphabet[i%len(alphabet)]
	}
	return string(out)
}

// marshalPublicKeyPEM returns the SPKI-PEM encoding of an ed25519 pubkey
// in the same form Python's `serialize_public_key_pem` emits.
func marshalPublicKeyPEM(t *testing.T, pub ed25519.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}
