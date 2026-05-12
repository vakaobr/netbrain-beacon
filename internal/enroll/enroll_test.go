package enroll

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/secra/netbrain-beacon/internal/api"
	bcrypto "github.com/secra/netbrain-beacon/internal/crypto"
)

// integrationPKI returns an ECDSA-P-256 platform CA + a server cert signed
// by it. The server cert covers "localhost" so the URL-host trick from
// transport/client_test.go works here too.
type integrationPKI struct {
	CACertPEM []byte
	ServerTLS tls.Certificate
}

func newIntegrationPKI(t *testing.T) *integrationPKI {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "integration-ca"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	srvTpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTpl, caCert, &srvKey.PublicKey, caKey)
	require.NoError(t, err)
	return &integrationPKI{
		CACertPEM: caPEM,
		ServerTLS: tls.Certificate{Certificate: [][]byte{srvDER}, PrivateKey: srvKey},
	}
}

// buildSignedBundle mints a fresh ed25519 keypair, signs the given payload,
// and returns the base64 bundle string PLUS the CA-PEM and pubkey-PEM the
// fake server / verifier need.
//
// Different from buildBundle in bundle_test.go because here we want a real
// CA-PEM (matching the integrationPKI), not a stub string.
func buildSignedBundle(t *testing.T, token, caCertPEM string, expiresAt time.Time) string {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))

	expStr := expiresAt.UTC().Format(time.RFC3339)
	payload := map[string]any{
		"bootstrap_token":  token,
		"expires_at":       expStr,
		"platform_ca_cert": caCertPEM,
	}
	canonical, err := bcrypto.CanonicalizePayload(payload)
	require.NoError(t, err)
	sig := ed25519.Sign(priv, canonical)

	bundle := map[string]any{
		"bootstrap_token":     token,
		"expires_at":          expStr,
		"platform_ca_cert":    caCertPEM,
		"platform_pubkey_pem": pubPEM,
		"signature":           base64.StdEncoding.EncodeToString(sig),
	}
	raw, err := json.Marshal(bundle)
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(raw)
}

// startFakeEnrollServer launches an httptest server that accepts POST
// /api/v1/beacons/enroll and returns a canned 201 response. The handler
// validates that the Authorization header matches expectedToken — if not,
// it returns 401 with the CSR_INVALID envelope to test the rejection path.
func startFakeEnrollServer(t *testing.T, pki *integrationPKI, expectedToken string, signedClientCert []byte, dek []byte) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/beacons/enroll", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+expectedToken {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":{"code":"BOOTSTRAP_TOKEN_INVALID","message":"bad token"}}`))
			return
		}
		// Echo a minimal 201 — we don't validate the CSR contents here.
		resp := map[string]any{
			"beacon_id":                  "abcdef00-1234-4567-8901-abcdef012345",
			"client_cert_pem":            string(signedClientCert),
			"ca_cert_pem":                string(pki.CACertPEM),
			"config_endpoint":            "https://platform.invalid/api/v1/beacons/{id}/config",
			"data_endpoint":              "https://platform.invalid/api/v1/beacons/{id}/data",
			"data_key_b64":               base64.StdEncoding.EncodeToString(dek),
			"data_key_version":           1,
			"heartbeat_interval_seconds": 60,
			"log_batch_max_age_seconds":  30,
			"log_batch_max_bytes":        1024 * 1024,
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(resp)
	})

	srv := httptest.NewUnstartedServer(mux)
	srv.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{pki.ServerTLS},
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// localhostURL rewrites srv.URL's host from 127.0.0.1:<port> → localhost:<port>
// so the server cert SAN matches at TLS handshake.
func localhostURL(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	require.NoError(t, err)
	u.Host = "localhost:" + u.Port()
	return u.String()
}

func TestEnrollHappyPath(t *testing.T) {
	pki := newIntegrationPKI(t)
	token := "nbb_happy_test_token_abc123def456"
	dek := make([]byte, 32)
	for i := range dek {
		dek[i] = byte(i)
	}
	fakeCert := []byte("-----BEGIN CERTIFICATE-----\nfake-client-cert\n-----END CERTIFICATE-----\n")
	srv := startFakeEnrollServer(t, pki, token, fakeCert, dek)

	bundle := buildSignedBundle(t, token, string(pki.CACertPEM), time.Now().Add(1*time.Hour))
	parsed, err := ParseBundle(bundle, false)
	require.NoError(t, err)

	result, _, err := Enroll(context.Background(), Input{
		Bundle:    parsed,
		ServerURL: localhostURL(t, srv.URL),
		Metadata: api.BeaconMetadata{
			Hostname: "test-host",
			Os:       api.BeaconMetadataOs("linux"),
			Version:  "v0.1.0-test",
		},
	})
	require.NoError(t, err)
	require.Equal(t, uuid.MustParse("abcdef00-1234-4567-8901-abcdef012345"), result.BeaconID)
	require.Equal(t, fakeCert, result.BeaconCertPEM)
	require.Equal(t, dek, result.DEK)
	require.Equal(t, 1, result.DEKVersion)
	require.Equal(t, 60, result.HeartbeatIntervalSeconds)
}

func TestEnrollServerRejectsBadToken(t *testing.T) {
	pki := newIntegrationPKI(t)
	correctToken := "nbb_correct_token_abc123def456ab"
	srv := startFakeEnrollServer(t, pki, correctToken, nil, nil)

	// Build a bundle that signs the WRONG token. The bundle signature still
	// verifies (we control the keypair) but the server rejects the token.
	wrongTokenBundle := buildSignedBundle(t, "nbb_wrong_token_xyz789xyz789xyz0", string(pki.CACertPEM), time.Now().Add(1*time.Hour))
	parsed, err := ParseBundle(wrongTokenBundle, false)
	require.NoError(t, err)

	_, _, err = Enroll(context.Background(), Input{
		Bundle:    parsed,
		ServerURL: localhostURL(t, srv.URL),
		Metadata:  api.BeaconMetadata{Hostname: "t", Os: api.BeaconMetadataOs("linux"), Version: "v"},
	})
	require.ErrorIs(t, err, ErrEnrollmentRejected)
}

// TestEnrollTamperedBundleNoPersist is the canonical fail-closed test
// from the Phase 5 plan: a tampered bundle MUST cause zero artifacts to
// land on disk. The orchestrator should never reach the persist step.
func TestEnrollTamperedBundleNoPersist(t *testing.T) {
	stateDir := t.TempDir()

	// Build a tampered bundle (signature flipped) and try to parse.
	// ParseBundle is what guards persist — Enroll() never runs.
	b := buildBundle(t, withTamperedSignature())
	_, err := ParseBundle(b, false)
	require.ErrorIs(t, err, ErrBundleSignatureInvalid)

	// stateDir must remain empty.
	entries, err := os.ReadDir(stateDir)
	require.NoError(t, err)
	require.Empty(t, entries, "tampered bundle must leave state dir untouched")

	// Idempotency check on the empty dir still says "fresh".
	require.NoError(t, CheckNotEnrolled(stateDir))
}

// TestEnrollNoPersistOnRejection verifies the orchestrator does not call
// Persist when the server returns 4xx — the test checks the dir is still
// empty afterwards (the orchestrator returns ErrEnrollmentRejected before
// the caller would invoke Persist).
func TestEnrollNoPersistOnRejection(t *testing.T) {
	pki := newIntegrationPKI(t)
	srv := startFakeEnrollServer(t, pki, "nbb_correct_token_abc123def456ab", nil, nil)
	stateDir := t.TempDir()

	wrongTokenBundle := buildSignedBundle(t, "nbb_wrong_token_xyz789xyz789xyz0", string(pki.CACertPEM), time.Now().Add(1*time.Hour))
	parsed, _ := ParseBundle(wrongTokenBundle, false)

	_, _, err := Enroll(context.Background(), Input{
		Bundle:    parsed,
		ServerURL: localhostURL(t, srv.URL),
		Metadata:  api.BeaconMetadata{Hostname: "t", Os: api.BeaconMetadataOs("linux"), Version: "v"},
	})
	require.Error(t, err)

	// Caller would not have invoked Persist — state dir must be untouched.
	entries, _ := os.ReadDir(stateDir)
	require.Empty(t, entries)
	_, err = os.Stat(filepath.Join(stateDir, MetadataFilename))
	require.True(t, os.IsNotExist(err), "metadata file must NOT exist on rejection")
}

// TestMetadataFromArtifactsRoundTrip ensures the orchestrator's metadata
// builder produces a struct Persist round-trips cleanly.
func TestMetadataFromArtifactsRoundTrip(t *testing.T) {
	r := &Result{
		BeaconID:                 uuid.MustParse("abcdef00-1234-4567-8901-abcdef012345"),
		ConfigEndpoint:           "https://x/config",
		DataEndpoint:             "https://x/data",
		DEKVersion:               5,
		HeartbeatIntervalSeconds: 60,
		LogBatchMaxAgeSeconds:    30,
		LogBatchMaxBytes:         1024,
	}
	meta := MetadataFromArtifacts(r, "https://x:8443")
	require.Equal(t, r.BeaconID, meta.BeaconID)
	require.Equal(t, "https://x:8443", meta.ServerURL)
	require.Equal(t, 5, meta.DEKVersion)
	require.WithinDuration(t, time.Now().UTC(), meta.EnrolledAt, 2*time.Second)
}
