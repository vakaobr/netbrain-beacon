package transport

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/velonet/netbrain-beacon/internal/api"
)

// rotateFixture bundles everything a rotate test needs: a state dir
// pre-populated with the "current" cert + key, a fake-server URL, a
// transport.Client wrapping a mock *http.Client, and a Rotator ready to
// call Rotate.
type rotateFixture struct {
	StateDir  string
	BeaconID  uuid.UUID
	APIClient api.ClientInterface
	Client    *Client
	Rotator   *Rotator
	Server    *httptest.Server
	hits      *atomic.Int64
}

// newRotateFixture provisions all the moving parts. NEW_CERT is what the
// fake server returns on /rotate-cert.
func newRotateFixture(t *testing.T, newCertPEM []byte) *rotateFixture {
	t.Helper()
	stateDir := t.TempDir()

	// Seed the state dir with the "current" cert + key (the about-to-be-archived pair).
	curCertPEM, curKeyPEM := selfSignedCert(t, "current-beacon")
	require.NoError(t, os.WriteFile(filepath.Join(stateDir, "beacon.crt"), curCertPEM, 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(stateDir, "beacon.key"), curKeyPEM, 0o600))

	hits := &atomic.Int64{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path != "/api/v1/beacons/"+beaconUUIDPath+"/cert/rotate" {
			http.Error(w, "wrong path: "+r.URL.Path, http.StatusNotFound)
			return
		}
		resp := api.CertRotateResponse{
			ClientCertPem:    string(newCertPEM),
			CaCertPem:        "-----BEGIN CERTIFICATE-----\nfake-ca\n-----END CERTIFICATE-----\n",
			ValidFrom:        time.Now().UTC(),
			ValidUntil:       time.Now().UTC().Add(90 * 24 * time.Hour),
			GracePeriodHours: 168,
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)

	apiClient, err := api.NewClient(srv.URL)
	require.NoError(t, err)

	// Build a minimal transport.Client backed by an http.Client we control.
	// We seed it with a placeholder client so Swap has something to swap.
	initial := &http.Client{Transport: http.DefaultTransport}
	c := &Client{}
	c.current.Store(initial)

	// Capture every Swap target — the test asserts the rotator publishes.
	swapped := &atomic.Int64{}
	r := &Rotator{
		APIClient:     apiClient,
		Client:        c,
		BeaconID:      uuid.MustParse(beaconUUIDPath),
		StateDir:      stateDir,
		PlatformCAPEM: []byte("-----BEGIN CERTIFICATE-----\nfake-ca\n-----END CERTIFICATE-----\n"),
		// Inject a fake factory so we don't need a real PKI for the swap step.
		HTTPClientFactory: func(_, _, _ []byte) (*http.Client, error) {
			swapped.Add(1)
			return &http.Client{Transport: http.DefaultTransport}, nil
		},
	}

	return &rotateFixture{
		StateDir:  stateDir,
		BeaconID:  r.BeaconID,
		APIClient: apiClient,
		Client:    c,
		Rotator:   r,
		Server:    srv,
		hits:      hits,
	}
}

// Beacon UUID used in every rotate test. Hardcoded so URL matching is
// deterministic.
const beaconUUIDPath = "abcdef00-1234-4567-8901-abcdef012345"

// selfSignedCert mints an ECDSA-P-256 self-signed cert for use as the
// "current" or "new" cert in rotation tests. Returns cert PEM + key PEM.
func selfSignedCert(t *testing.T, cn string) ([]byte, []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	require.NoError(t, err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

// --- happy path ---

func TestRotateHappyPath(t *testing.T) {
	newCertPEM, _ := selfSignedCert(t, "new-beacon")
	f := newRotateFixture(t, newCertPEM)

	require.NoError(t, f.Rotator.Rotate(context.Background()))
	require.Equal(t, int64(1), f.hits.Load(), "exactly one /rotate-cert hit")

	// On-disk: live = new cert, .prev = old cert.
	liveCert, err := os.ReadFile(filepath.Join(f.StateDir, "beacon.crt"))
	require.NoError(t, err)
	require.Equal(t, newCertPEM, liveCert)

	prevCertBytes, err := os.ReadFile(filepath.Join(f.StateDir, "beacon.crt.prev"))
	require.NoError(t, err)
	prevCert, err := ParseCertPEM(prevCertBytes)
	require.NoError(t, err)
	require.Equal(t, "current-beacon", prevCert.Subject.CommonName, "old cert archived as .prev")

	// .new files cleaned up after promotion.
	_, err = os.Stat(filepath.Join(f.StateDir, "beacon.crt.new"))
	require.True(t, os.IsNotExist(err), "beacon.crt.new must be gone after promotion")
}

func TestRotateSecretFilePerms(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits aren't enforced on Windows")
	}
	newCertPEM, _ := selfSignedCert(t, "new-beacon")
	f := newRotateFixture(t, newCertPEM)
	require.NoError(t, f.Rotator.Rotate(context.Background()))

	keyInfo, err := os.Stat(filepath.Join(f.StateDir, "beacon.key"))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), keyInfo.Mode().Perm(),
		"rotated key must be 0600 (CWE-732)")
}

func TestRotateConcurrencyCoalesces(t *testing.T) {
	// Multiple goroutines call Rotate; the in-flight gate must ensure
	// exactly one /rotate-cert hit reaches the server.
	newCertPEM, _ := selfSignedCert(t, "new-beacon")
	f := newRotateFixture(t, newCertPEM)

	const N = 10
	var wg sync.WaitGroup
	inFlight := &atomic.Int64{}
	ok := &atomic.Int64{}
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			err := f.Rotator.Rotate(context.Background())
			if errors.Is(err, ErrRotationInFlight) {
				inFlight.Add(1)
				return
			}
			require.NoError(t, err)
			ok.Add(1)
		}()
	}
	wg.Wait()

	require.Equal(t, int64(1), ok.Load(), "exactly one Rotate must succeed")
	require.Equal(t, int64(N-1), inFlight.Load(), "all others must short-circuit with ErrRotationInFlight")
	require.Equal(t, int64(1), f.hits.Load(), "server saw exactly one /rotate-cert hit")
}

// --- error paths ---

func TestRotateServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, `{"error":{"code":"INTERNAL","message":"oops"}}`)
	}))
	t.Cleanup(srv.Close)

	apiClient, err := api.NewClient(srv.URL)
	require.NoError(t, err)
	c := &Client{}
	c.current.Store(&http.Client{})

	stateDir := t.TempDir()
	r := &Rotator{
		APIClient:     apiClient,
		Client:        c,
		BeaconID:      uuid.MustParse(beaconUUIDPath),
		StateDir:      stateDir,
		PlatformCAPEM: []byte{},
	}

	require.ErrorIs(t, r.Rotate(context.Background()), ErrRotationFailed)

	// State dir must be untouched on 5xx — no .new, no .prev files.
	entries, _ := os.ReadDir(stateDir)
	require.Empty(t, entries, "server error must leave state dir untouched")
}

func TestRotateMissingClientCertInResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Successful status but empty client_cert_pem — server-side regression.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(api.CertRotateResponse{
			ClientCertPem: "", // <-- missing
			CaCertPem:     "ca",
			ValidFrom:     time.Now(),
			ValidUntil:    time.Now().Add(time.Hour),
		})
	}))
	t.Cleanup(srv.Close)

	apiClient, err := api.NewClient(srv.URL)
	require.NoError(t, err)
	r := &Rotator{
		APIClient:     apiClient,
		Client:        &Client{},
		BeaconID:      uuid.MustParse(beaconUUIDPath),
		StateDir:      t.TempDir(),
		PlatformCAPEM: []byte{},
	}
	r.Client.current.Store(&http.Client{})

	require.ErrorIs(t, r.Rotate(context.Background()), ErrRotationFailed)
}

func TestRotateGarbageCertInResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Successful status, "cert" present but not a valid PEM.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(api.CertRotateResponse{
			ClientCertPem: "this is not a PEM",
			CaCertPem:     "ca",
			ValidFrom:     time.Now(),
			ValidUntil:    time.Now().Add(time.Hour),
		})
	}))
	t.Cleanup(srv.Close)

	apiClient, err := api.NewClient(srv.URL)
	require.NoError(t, err)
	stateDir := t.TempDir()
	r := &Rotator{
		APIClient:     apiClient,
		Client:        &Client{},
		BeaconID:      uuid.MustParse(beaconUUIDPath),
		StateDir:      stateDir,
		PlatformCAPEM: []byte{},
	}
	r.Client.current.Store(&http.Client{})

	require.ErrorIs(t, r.Rotate(context.Background()), ErrRotationFailed)

	// Garbage cert ⇒ ParseCertPEM rejected before ANY file is written.
	entries, _ := os.ReadDir(stateDir)
	require.Empty(t, entries)
}

// --- cleanup ---

func TestCleanupPrevRemovesArchive(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "beacon.crt.prev"), []byte("c"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "beacon.key.prev"), []byte("k"), 0o600))

	r := &Rotator{StateDir: dir}
	n, err := r.CleanupPrev()
	require.NoError(t, err)
	require.Equal(t, 2, n)

	for _, name := range []string{"beacon.crt.prev", "beacon.key.prev"} {
		_, err := os.Stat(filepath.Join(dir, name))
		require.True(t, os.IsNotExist(err), "%s must be removed", name)
	}
}

func TestCleanupPrevWhenNothingToClean(t *testing.T) {
	r := &Rotator{StateDir: t.TempDir()}
	n, err := r.CleanupPrev()
	require.NoError(t, err)
	require.Equal(t, 0, n)
}
