package transport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// --- test cert helpers ---

type pkiBundle struct {
	caCertPEM  []byte
	caKey      *ecdsa.PrivateKey
	caCert     *x509.Certificate
	clientCert *x509.Certificate
	clientPEM  []byte
	clientKey  *ecdsa.PrivateKey
	clientKPEM []byte
	serverCert tls.Certificate // built from caCert; usable on httptest.Server
}

// newPKI builds an ECDSA-P-256 CA, a client cert signed by that CA, and a
// server cert (also signed by the CA) suitable for a local TLS server.
// All keys are throwaway — never persist these.
func newPKI(t *testing.T) *pkiBundle {
	t.Helper()

	// CA
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-platform-ca"},
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
	caCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	// Client cert
	clKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	clTpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test-beacon"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clDER, err := x509.CreateCertificate(rand.Reader, clTpl, caCert, &clKey.PublicKey, caKey)
	require.NoError(t, err)
	clCert, err := x509.ParseCertificate(clDER)
	require.NoError(t, err)
	clPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clDER})

	clKeyDER, err := x509.MarshalECPrivateKey(clKey)
	require.NoError(t, err)
	clKPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: clKeyDER})

	// Server cert (also CA-signed; allows localhost)
	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	srvTpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTpl, caCert, &srvKey.PublicKey, caKey)
	require.NoError(t, err)
	srvCert := tls.Certificate{
		Certificate: [][]byte{srvDER},
		PrivateKey:  srvKey,
	}

	return &pkiBundle{
		caCertPEM:  caCertPEM,
		caKey:      caKey,
		caCert:     caCert,
		clientCert: clCert,
		clientPEM:  clPEM,
		clientKey:  clKey,
		clientKPEM: clKPEM,
		serverCert: srvCert,
	}
}

// newTLS13Server starts an httptest.Server requiring TLS 1.3 and the supplied
// CA pool for client cert verification.
func newTLS13Server(t *testing.T, pki *pkiBundle, handler http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(handler)

	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(pki.caCert)
	srv.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{pki.serverCert},
		ClientCAs:    clientCAs,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// --- constructor tests ---

func TestNewClientHappy(t *testing.T) {
	pki := newPKI(t)
	c, err := NewClient(Config{
		CertPEM:       pki.clientPEM,
		KeyPEM:        pki.clientKPEM,
		PlatformCAPEM: pki.caCertPEM,
	})
	require.NoError(t, err)
	require.NotNil(t, c.Current())

	tr, ok := c.Current().Transport.(*http.Transport)
	require.True(t, ok)
	require.Equal(t, uint16(tls.VersionTLS13), tr.TLSClientConfig.MinVersion,
		"MinVersion must be TLS 1.3 (M-1)")
	require.Len(t, tr.TLSClientConfig.Certificates, 1)
	require.NotNil(t, tr.TLSClientConfig.RootCAs)
}

func TestNewClientBadCertKeyPair(t *testing.T) {
	pki := newPKI(t)
	_, err := NewClient(Config{
		CertPEM:       []byte("not a cert"),
		KeyPEM:        pki.clientKPEM,
		PlatformCAPEM: pki.caCertPEM,
	})
	require.ErrorIs(t, err, ErrInvalidCert)
}

func TestNewClientBadCA(t *testing.T) {
	pki := newPKI(t)
	_, err := NewClient(Config{
		CertPEM:       pki.clientPEM,
		KeyPEM:        pki.clientKPEM,
		PlatformCAPEM: []byte("not a ca bundle"),
	})
	require.ErrorIs(t, err, ErrInvalidCA)
}

// --- round-trip test ---

func TestRoundTripAgainstTLS13Server(t *testing.T) {
	pki := newPKI(t)
	srv := newTLS13Server(t, pki, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))

	c, err := NewClient(Config{
		CertPEM:       pki.clientPEM,
		KeyPEM:        pki.clientKPEM,
		PlatformCAPEM: pki.caCertPEM,
	})
	require.NoError(t, err)

	// httptest.Server runs on 127.0.0.1:<random>; the URL uses 127.0.0.1.
	// The server cert was issued for localhost — patch the URL host so
	// SNI matches the cert.
	u, err := url.Parse(srv.URL)
	require.NoError(t, err)
	u.Host = "localhost:" + u.Port()

	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	require.NoError(t, err)

	resp, err := c.Current().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.JSONEq(t, `{"ok":true}`, string(body))
}

// --- TLS 1.2 rejection ---

func TestTLS12ServerRejected(t *testing.T) {
	pki := newPKI(t)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12, // forbid 1.3 negotiation
		Certificates: []tls.Certificate{pki.serverCert},
	}
	srv.StartTLS()
	defer srv.Close()

	c, err := NewClient(Config{
		CertPEM:       pki.clientPEM,
		KeyPEM:        pki.clientKPEM,
		PlatformCAPEM: pki.caCertPEM,
	})
	require.NoError(t, err)

	u, err := url.Parse(srv.URL)
	require.NoError(t, err)
	u.Host = "localhost:" + u.Port()
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	require.NoError(t, err)

	_, err = c.Current().Do(req)
	require.Error(t, err, "TLS 1.3-only client must refuse a TLS 1.2-only server")
}

// --- atomic swap concurrency test ---

func TestSwapConcurrentReads(t *testing.T) {
	// Property: under 1000 swaps × 100 concurrent readers, Current()
	// always returns a non-nil *http.Client and Swap returns the previous
	// one without ever losing the chain.
	pki := newPKI(t)
	c, err := NewClient(Config{
		CertPEM:       pki.clientPEM,
		KeyPEM:        pki.clientKPEM,
		PlatformCAPEM: pki.caCertPEM,
	})
	require.NoError(t, err)

	const readers = 100
	const swaps = 1000

	var readCount atomic.Int64
	var wg sync.WaitGroup

	stop := make(chan struct{})
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					hc := c.Current()
					if hc == nil {
						t.Errorf("Current() returned nil")
						return
					}
					readCount.Add(1)
				}
			}
		}()
	}

	for i := 0; i < swaps; i++ {
		newClient := buildHTTPClient(pki.serverCert, x509.NewCertPool(), 30*time.Second)
		prev := c.Swap(newClient)
		require.NotNil(t, prev, "Swap must return the previous *http.Client")
	}
	close(stop)
	wg.Wait()

	require.Greater(t, readCount.Load(), int64(1000),
		"readers should have observed many Current() values during the swap storm")
}

// --- nil-swap defensive guard ---

func TestSwapNilNoOp(t *testing.T) {
	pki := newPKI(t)
	c, err := NewClient(Config{
		CertPEM:       pki.clientPEM,
		KeyPEM:        pki.clientKPEM,
		PlatformCAPEM: pki.caCertPEM,
	})
	require.NoError(t, err)
	original := c.Current()
	prev := c.Swap(nil)
	require.Same(t, original, prev, "Swap(nil) must return the current client unchanged")
	require.Same(t, original, c.Current(), "Swap(nil) must NOT replace the active client")
}

// --- timeout defaults applied ---

func TestNewClientAppliesTimeoutDefault(t *testing.T) {
	pki := newPKI(t)
	c, err := NewClient(Config{
		CertPEM:       pki.clientPEM,
		KeyPEM:        pki.clientKPEM,
		PlatformCAPEM: pki.caCertPEM,
	})
	require.NoError(t, err)
	require.Equal(t, defaultResponseTimeout, c.Current().Timeout)
}

func TestNewClientHonoursCustomTimeout(t *testing.T) {
	pki := newPKI(t)
	c, err := NewClient(Config{
		CertPEM:       pki.clientPEM,
		KeyPEM:        pki.clientKPEM,
		PlatformCAPEM: pki.caCertPEM,
		HTTPTimeout:   2 * time.Second,
	})
	require.NoError(t, err)
	require.Equal(t, 2*time.Second, c.Current().Timeout)
}

// Verify ErrInvalidCert is a stable sentinel (callers errors.Is on it).
func TestErrInvalidCertSentinel(t *testing.T) {
	_, err := NewClient(Config{CertPEM: []byte("bad"), KeyPEM: []byte("bad"), PlatformCAPEM: []byte("bad")})
	require.True(t, errors.Is(err, ErrInvalidCert))
}
