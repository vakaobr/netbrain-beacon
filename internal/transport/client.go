package transport

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"
)

// Errors surfaced by the transport constructor.
var (
	// ErrInvalidCert wraps a failed parse of the beacon's client cert/key
	// pair. Tells the caller the on-disk artifacts are unusable.
	ErrInvalidCert = errors.New("transport: failed to load beacon cert/key pair")

	// ErrInvalidCA wraps a failed parse of the platform CA bundle. Means
	// the enrollment bundle that landed at platform-ca.pem is malformed.
	ErrInvalidCA = errors.New("transport: failed to parse platform CA")

	// ErrNoCertsLoaded is returned when NewClient has zero certs in the
	// supplied bundle (would silently disable verification).
	ErrNoCertsLoaded = errors.New("transport: platform CA bundle contained no certificates")
)

// Defaults used by NewClient when not overridden. The values are tuned for a
// beacon's expected traffic shape: low concurrency (one daemon goroutine per
// collector type), long-running connections (config-poll cycle holds a
// pooled conn), no aggressive timeouts at the transport layer (callers bound
// per-request via context).
const (
	defaultMaxIdleConnsPerHost = 2
	defaultIdleConnTimeout     = 90 * time.Second
	defaultDialTimeout         = 10 * time.Second
	defaultTLSHandshakeTimeout = 10 * time.Second
	defaultResponseTimeout     = 30 * time.Second // overall request budget
)

// Config bundles the inputs to NewClient. Pulled out so tests can pass
// in-memory PEM blobs without ever touching disk.
type Config struct {
	// CertPEM is the beacon's client certificate in PEM form (issued by
	// the platform during enrollment).
	CertPEM []byte
	// KeyPEM is the matching private key (must be 0600 on disk; this
	// package reads bytes, not paths).
	KeyPEM []byte
	// PlatformCAPEM is the trust anchor — typically a single ECDSA P-256
	// CA cert delivered in the enrollment bundle. The beacon refuses
	// any server cert NOT chained to this CA.
	PlatformCAPEM []byte
	// HTTPTimeout is the per-request hard budget. Defaults to 30s. The
	// caller's context is the finer-grained timeout — this is the
	// outer ceiling.
	HTTPTimeout time.Duration
}

// Client wraps an atomically-swappable *http.Client and the constructor
// state needed to rebuild it on cert rotation.
type Client struct {
	current atomic.Pointer[http.Client]
}

// NewClient assembles a *Client from the supplied cert/key/CA bundle.
//
// Hard requirements (M-1, M-9-adjacent, M-11-adjacent):
//   - MinVersion: tls.VersionTLS13 — TLS 1.2 fallback is forbidden. The
//     platform side's nginx is configured for TLS 1.3 only; the beacon
//     should refuse to even attempt 1.2.
//   - ClientCAs from the platform CA bundle — pinned, not loaded from the
//     system trust store. Refuses any server cert NOT chained to the
//     supplied CA.
func NewClient(cfg Config) (*Client, error) {
	cert, err := tls.X509KeyPair(cfg.CertPEM, cfg.KeyPEM)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidCert, err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(cfg.PlatformCAPEM) {
		return nil, ErrInvalidCA
	}
	if numSubjects := len(caPool.Subjects()); numSubjects == 0 { //nolint:staticcheck // Subjects deprecated for system roots only; OK here for our pinned pool.
		return nil, ErrNoCertsLoaded
	}

	httpClient := buildHTTPClient(cert, caPool, cfg.HTTPTimeout)

	c := &Client{}
	c.current.Store(httpClient)
	return c, nil
}

// Current returns the active *http.Client. Safe under concurrent reads with
// in-flight Swap calls.
func (c *Client) Current() *http.Client {
	return c.current.Load()
}

// Swap replaces the active *http.Client with the new one and returns the
// previous client. The previous client is still usable — in-flight requests
// continue on its connection pool until they complete (or the caller
// closes the old transport).
//
// Cert rotation (ADR-079) builds the new client via NewClient using the
// freshly-rotated cert files, then calls Swap. The daemon scheduler keeps
// the returned old client around for a grace period before closing its
// idle connections (so any in-flight RPC drains cleanly).
func (c *Client) Swap(newClient *http.Client) *http.Client {
	if newClient == nil {
		// Defensive: refusing to swap to nil prevents nil-pointer dereferences
		// in any goroutine that called Current() after our atomic.Store.
		return c.current.Load()
	}
	return c.current.Swap(newClient)
}

// buildHTTPClient is the common assembly path for NewClient and any future
// helper that wants to construct an *http.Client from a parsed cert + CA pool.
func buildHTTPClient(cert tls.Certificate, caPool *x509.CertPool, timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = defaultResponseTimeout
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion:   tls.VersionTLS13,
				Certificates: []tls.Certificate{cert},
				RootCAs:      caPool,
			},
			MaxIdleConnsPerHost:   defaultMaxIdleConnsPerHost,
			IdleConnTimeout:       defaultIdleConnTimeout,
			TLSHandshakeTimeout:   defaultTLSHandshakeTimeout,
			ExpectContinueTimeout: 1 * time.Second,
			ForceAttemptHTTP2:     true,
		},
	}
}
