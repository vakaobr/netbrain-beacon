package cli

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
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

	"github.com/velonet/netbrain-beacon/internal/enroll"
)

// checkPKI bundles the artifacts a CheckServer test needs: a CA-signed
// client cert + key (for the beacon) and a server cert (for the fake
// platform). Both signed by the same CA so mTLS handshake succeeds.
type checkPKI struct {
	caCertPEM    []byte
	clientPEM    []byte
	clientKeyPEM []byte
	serverTLS    tls.Certificate
}

func newCheckPKI(t *testing.T) *checkPKI {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "check-ca"},
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
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	clKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	clTpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test-beacon"},
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

	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	srvTpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTpl, caCert, &srvKey.PublicKey, caKey)
	require.NoError(t, err)

	return &checkPKI{
		caCertPEM:    caPEM,
		clientPEM:    clPEM,
		clientKeyPEM: clKeyPEM,
		serverTLS:    tls.Certificate{Certificate: [][]byte{srvDER}, PrivateKey: srvKey},
	}
}

// startCheckServerFake spins an httptest TLS-1.3 server that responds to
// GET /api/v1/beacons/{id}/cert-status with the supplied response.
// handlerOverride may replace the default handler for error-path tests.
func startCheckServerFake(t *testing.T, pki *checkPKI, beaconID string, handlerOverride http.HandlerFunc) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/beacons/"+beaconID+"/cert-status", func(w http.ResponseWriter, r *http.Request) {
		if handlerOverride != nil {
			handlerOverride(w, r)
			return
		}
		expiresAt := time.Now().Add(60 * 24 * time.Hour).UTC()
		body := map[string]any{
			"days_until_expiry":  60,
			"expires_at":         expiresAt.Format(time.RFC3339),
			"recommended_action": "none",
			"revocation_reason":  nil,
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(body)
	})

	srv := httptest.NewUnstartedServer(mux)
	clientCAs := x509.NewCertPool()
	clientCAs.AppendCertsFromPEM(pki.caCertPEM)
	srv.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{pki.serverTLS},
		ClientCAs:    clientCAs,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// seedState writes the on-disk artifacts CheckServer needs.
func seedState(t *testing.T, pki *checkPKI, beaconID, serverURL string) string {
	t.Helper()
	dir := t.TempDir()
	art := &enroll.Artifacts{
		BeaconCertPEM:     pki.clientPEM,
		BeaconKeyPEM:      pki.clientKeyPEM,
		DEK:               make([]byte, 32),
		PlatformCAPEM:     pki.caCertPEM,
		PlatformPubKeyPEM: []byte("dummy"),
		Metadata: enroll.Metadata{
			BeaconID:   uuid.MustParse(beaconID),
			EnrolledAt: time.Now().UTC(),
			ServerURL:  serverURL,
			DEKVersion: 1,
		},
	}
	require.NoError(t, enroll.Persist(dir, art))
	return dir
}

func localhostFromHTTPTestURL(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	require.NoError(t, err)
	u.Host = "localhost:" + u.Port()
	return u.String()
}

// --- happy path ---

func TestCheckServerHappy(t *testing.T) {
	pki := newCheckPKI(t)
	beaconID := "abcdef00-1234-4567-8901-abcdef012345"
	srv := startCheckServerFake(t, pki, beaconID, nil)
	dir := seedState(t, pki, beaconID, localhostFromHTTPTestURL(t, srv.URL))

	r := CheckServer(context.Background(), dir)
	require.True(t, r.Reachable, "happy-path must succeed; got error: %s", r.Error)
	require.Equal(t, http.StatusOK, r.HTTPStatus)
	require.Equal(t, 60, r.DaysUntilExpiry)
	require.Equal(t, "none", r.RecommendedAction)
	require.Empty(t, r.RevocationReason)
}

// --- failure paths ---

func TestCheckServerNoMetadata(t *testing.T) {
	r := CheckServer(context.Background(), t.TempDir())
	require.False(t, r.Reachable)
	require.Contains(t, r.Error, "read metadata")
}

func TestCheckServerNoCert(t *testing.T) {
	pki := newCheckPKI(t)
	dir := seedState(t, pki, "abcdef00-1234-4567-8901-abcdef012345", "https://example.invalid")
	// Remove the cert file → CheckServer should surface the read error.
	require.NoError(t, os.Remove(filepath.Join(dir, enroll.BeaconCertFilename)))

	r := CheckServer(context.Background(), dir)
	require.False(t, r.Reachable)
	require.Contains(t, r.Error, "read cert")
}

func TestCheckServerServerError(t *testing.T) {
	pki := newCheckPKI(t)
	beaconID := "abcdef00-1234-4567-8901-abcdef012345"
	srv := startCheckServerFake(t, pki, beaconID, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"code":"UNAUTHORIZED","message":"go away"}}`))
	})
	dir := seedState(t, pki, beaconID, localhostFromHTTPTestURL(t, srv.URL))

	r := CheckServer(context.Background(), dir)
	require.True(t, r.Reachable, "request completed end-to-end; server-side rejection is a different state")
	require.Equal(t, http.StatusUnauthorized, r.HTTPStatus)
	require.Contains(t, r.Error, "401")
}

func TestCheckServerRevoked(t *testing.T) {
	pki := newCheckPKI(t)
	beaconID := "abcdef00-1234-4567-8901-abcdef012345"
	srv := startCheckServerFake(t, pki, beaconID, func(w http.ResponseWriter, _ *http.Request) {
		reason := "decommissioned"
		body := map[string]any{
			"days_until_expiry":  -10,
			"expires_at":         time.Now().Add(-10 * 24 * time.Hour).UTC().Format(time.RFC3339),
			"recommended_action": "reenroll",
			"revocation_reason":  reason,
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(body)
	})
	dir := seedState(t, pki, beaconID, localhostFromHTTPTestURL(t, srv.URL))

	r := CheckServer(context.Background(), dir)
	require.True(t, r.Reachable)
	require.Equal(t, "reenroll", r.RecommendedAction)
	require.Equal(t, "decommissioned", r.RevocationReason)
	require.Less(t, r.DaysUntilExpiry, 0)
}

func TestCheckServerNetworkFailure(t *testing.T) {
	pki := newCheckPKI(t)
	beaconID := "abcdef00-1234-4567-8901-abcdef012345"
	// Use a URL that won't resolve / connect.
	dir := seedState(t, pki, beaconID, "https://127.0.0.1:1") // port 1: no listener

	r := CheckServer(context.Background(), dir)
	require.False(t, r.Reachable, "network failure should surface as Reachable=false")
	require.NotEmpty(t, r.Error)
}
