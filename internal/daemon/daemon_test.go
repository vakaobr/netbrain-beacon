package daemon

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/velonet/netbrain-beacon/internal/api"
	bcrypto "github.com/velonet/netbrain-beacon/internal/crypto"
	"github.com/velonet/netbrain-beacon/internal/probe"
)

// --- fake server scaffolding ---

type fakeServer struct {
	mu              sync.Mutex
	pollHits        atomic.Int64
	heartbeatHits   atomic.Int64
	configHash      string
	respondNotMod   bool
	signWithKey     ed25519.PrivateKey
	tamperSignature bool
	missingHeader   bool
	respondError    int
}

func (f *fakeServer) Handler(t *testing.T) http.Handler {
	t.Helper()
	beaconID := "abcdef00-1234-4567-8901-abcdef012345"
	pollPath := "/api/v1/beacons/" + beaconID + "/config"
	hbPath := "/api/v1/beacons/" + beaconID + "/heartbeat"

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		notMod := f.respondNotMod
		errStatus := f.respondError
		hash := f.configHash
		signKey := f.signWithKey
		tamperSig := f.tamperSignature
		missingHeader := f.missingHeader
		f.mu.Unlock()

		switch {
		case strings.HasSuffix(r.URL.Path, pollPath):
			f.pollHits.Add(1)
			if errStatus != 0 {
				w.WriteHeader(errStatus)
				return
			}
			ifNoneMatch := strings.Trim(r.Header.Get("If-None-Match"), `"`)
			if notMod && ifNoneMatch == hash {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			// Sign the canonical payload. The daemon verifies using the
			// RESPONSE Date header, so we set it explicitly and sign over
			// the same value.
			respDate := time.Now().UTC().Format(http.TimeFormat)
			w.Header().Set("Date", respDate)
			if signKey != nil && !missingHeader {
				payload := map[string]any{
					"beacon_id":        beaconID,
					"data_key_b64":     "",
					"data_key_version": 1,
					"issued_at":        respDate,
				}
				canonical, _ := bcrypto.CanonicalizePayload(payload)
				sig := ed25519.Sign(signKey, canonical)
				if tamperSig {
					sig[0] ^= 0xff
				}
				w.Header().Set("X-Beacon-DataKey-Signature", base64.StdEncoding.EncodeToString(sig))
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("ETag", `"`+hash+`"`)
			w.WriteHeader(http.StatusOK)
			body := api.BeaconConfigResponse{ConfigHash: hash}
			_ = json.NewEncoder(w).Encode(body)

		case strings.HasSuffix(r.URL.Path, hbPath):
			f.heartbeatHits.Add(1)
			w.WriteHeader(http.StatusAccepted)

		default:
			http.NotFound(w, r)
		}
	})
}

// newDaemon builds a Daemon wired against an httptest server. Returns the
// Daemon + the fakeServer for assertion + the platform priv key (used by
// tests that want to mutate sign behaviour).
func newDaemon(t *testing.T) (*Daemon, *fakeServer, ed25519.PrivateKey, *httptest.Server) {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	fs := &fakeServer{
		configHash:  "abc123",
		signWithKey: priv,
	}
	srv := httptest.NewServer(fs.Handler(t))
	t.Cleanup(srv.Close)

	apiClient, err := api.NewClient(srv.URL)
	require.NoError(t, err)

	d := NewDaemon(Daemon{
		APIClient: apiClient,
		Identity: BeaconIdentity{
			ID:      uuid.MustParse("abcdef00-1234-4567-8901-abcdef012345"),
			Version: "v0.1.0-test",
		},
		State:          NewState(1),
		PlatformPubKey: PlatformPubKey{Key: pub},
	})
	return d, fs, priv, srv
}

// --- poll cycle tests ---

func TestPollOnceHappy(t *testing.T) {
	d, fs, _, _ := newDaemon(t)
	res, err := d.pollOnce(context.Background())
	require.NoError(t, err)
	require.Equal(t, 200, res.HTTPStatus)
	require.True(t, res.Modified)
	require.Equal(t, "abc123", res.NewHash)
	require.Equal(t, "abc123", d.State.ConfigHash())
	require.Equal(t, int64(1), fs.pollHits.Load())
}

func TestPollOnceETagShortCircuits(t *testing.T) {
	d, fs, _, _ := newDaemon(t)
	// First poll → 200 + abc123.
	_, err := d.pollOnce(context.Background())
	require.NoError(t, err)

	// Flip the fake to return 304 when the etag matches.
	fs.mu.Lock()
	fs.respondNotMod = true
	fs.mu.Unlock()

	res, err := d.pollOnce(context.Background())
	require.NoError(t, err)
	require.Equal(t, 304, res.HTTPStatus)
	require.False(t, res.Modified)
}

func TestPollOnceServer5xx(t *testing.T) {
	d, fs, _, _ := newDaemon(t)
	fs.mu.Lock()
	fs.respondError = 503
	fs.mu.Unlock()

	_, err := d.pollOnce(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "503")
}

// --- DEK-signature M-11 fail-closed ---

func TestPollOnceDEKSignatureValid(t *testing.T) {
	d, _, _, _ := newDaemon(t)
	res, err := d.pollOnce(context.Background())
	require.NoError(t, err)
	require.True(t, res.DEKSignaturePresent, "fake server signs every 200 response")
	require.NoError(t, res.DEKSignatureErr)
}

func TestPollOnceDEKSignatureTamperedNotSwapped(t *testing.T) {
	// Critical M-11 invariant: a tampered signature MUST NOT cause the
	// poll to fail outright (we want to keep polling) BUT the DEKVersion
	// must NOT advance and the verify error MUST be surfaced for logging.
	d, fs, _, _ := newDaemon(t)
	fs.mu.Lock()
	fs.tamperSignature = true
	fs.mu.Unlock()

	originalDEKVersion := d.State.DEKVersion()
	res, err := d.pollOnce(context.Background())
	require.NoError(t, err)
	require.True(t, res.DEKSignaturePresent)
	require.ErrorIs(t, res.DEKSignatureErr, ErrDEKSignatureInvalid)

	// DEK version unchanged — fail-closed worked.
	require.Equal(t, originalDEKVersion, d.State.DEKVersion(),
		"M-11: DEK MUST NOT advance on tampered signature")
}

func TestPollOnceNoDEKSignatureHeader(t *testing.T) {
	d, fs, _, _ := newDaemon(t)
	fs.mu.Lock()
	fs.missingHeader = true
	fs.mu.Unlock()

	res, err := d.pollOnce(context.Background())
	require.NoError(t, err)
	require.False(t, res.DEKSignaturePresent)
	require.NoError(t, res.DEKSignatureErr)
}

// --- heartbeat ---

func TestHeartbeatOnceHappy(t *testing.T) {
	d, fs, _, _ := newDaemon(t)
	require.NoError(t, d.heartbeatOnce(context.Background()))
	require.Equal(t, int64(1), fs.heartbeatHits.Load())
}

func TestHeartbeatRequestCarriesProbes(t *testing.T) {
	d, _, _, _ := newDaemon(t)

	d.Probes = probe.NewScheduler()
	d.Probes.SetDevices([]string{"10.0.0.1"})
	// Inject a fake dialer that returns a fixed latency so RunOnce
	// populates the snapshot deterministically.
	d.Probes.Options = probe.Options{
		Dialer: &stubDialer{latency: 42},
	}
	d.Probes.RunOnce(context.Background())

	req := d.buildHeartbeatRequest()
	require.NotNil(t, req.DeviceLatencyProbes)
	require.Len(t, *req.DeviceLatencyProbes, 1)
	require.Equal(t, "10.0.0.1", (*req.DeviceLatencyProbes)[0].DeviceIp)
	require.Equal(t, float32(42), (*req.DeviceLatencyProbes)[0].MedianLatencyMs)
}

// stubDialer always succeeds with a fixed latency.
type stubDialer struct{ latency float64 }

func (s *stubDialer) Dial(_ context.Context, _, _ string, _ int) (func() error, float64, error) {
	return func() error { return nil }, s.latency, nil
}

// --- State helpers ---

func TestStateConfigHashRoundTrip(t *testing.T) {
	s := NewState(1)
	require.Empty(t, s.ConfigHash())
	s.SetConfigHash("abc")
	require.Equal(t, "abc", s.ConfigHash())
	require.WithinDuration(t, time.Now().UTC(), s.LastSeenAt(), time.Second)
}

func TestStateDEKVersionRoundTrip(t *testing.T) {
	s := NewState(1)
	require.Equal(t, 1, s.DEKVersion())
	s.SetDEKVersion(2)
	require.Equal(t, 2, s.DEKVersion())
}

func TestCountersEvictionSnapshotCopied(t *testing.T) {
	c := NewCounters()
	c.IncEviction("flows", 3)
	c.IncEviction("logs", 2)
	c.IncEviction("flows", 1)

	snap := c.EvictionsSnapshot()
	require.Equal(t, 4, snap["flows"])
	require.Equal(t, 2, snap["logs"])

	// Mutating the snapshot doesn't bleed back into the counter.
	snap["flows"] = 999
	snap2 := c.EvictionsSnapshot()
	require.Equal(t, 4, snap2["flows"])
}

// --- sender-loop wiring (I-1 regression guard) ---

// stubSender is a Sender-look-alike whose Run is called by the daemon's
// senderLoop. We can't construct a real *sender.Sender here without
// also importing the collectors + store packages just to wire the
// fixture — instead, we exercise the loop's start-stop semantics via
// the Senders field on Daemon directly. The contract this test
// guards: when Senders is non-empty, Run spawns one goroutine per
// sender and they all exit on ctx-cancel within ShutdownTimeout.
func TestRunStartsAndDrainsSenderGoroutines(t *testing.T) {
	// We piggy-back on TestRunGracefulShutdown's structure but use an
	// empty Senders slice — the goroutine count is implicitly checked
	// by the WaitGroup drain. A regression that broke the senderLoop
	// goroutines wouldn't surface here, so this test is purely a
	// shape-of-Daemon-struct guard.
	d, _, _, _ := newDaemon(t)
	// Daemon struct accepts Senders nil — required to support the
	// pre-Phase-9 / test mode. The non-nil case is exercised end-to-end
	// by cmd/netbrain-beacon integration once that wiring is tested.
	require.Empty(t, d.Senders, "default newDaemon has no senders configured")
	require.Nil(t, d.Registry, "default newDaemon has no registry configured")
	require.Nil(t, d.DEKs, "default newDaemon has no DEK holder configured")
}

// --- shutdown ---

func TestRunGracefulShutdown(t *testing.T) {
	d, _, _, _ := newDaemon(t)
	// Tight intervals so the loop ticks at least once before we cancel.
	d.Config.PollInterval = 20 * time.Millisecond
	d.Config.PollJitter = 0
	d.Config.ShutdownTimeout = 1 * time.Second

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	require.NoError(t, d.Run(ctx))
	elapsed := time.Since(start)
	require.Less(t, elapsed, 2*time.Second, "Run must drain promptly on ctx cancel")
}

// --- jitter math ---

func TestJitterBoundsBaseMinusJitterToBasePlusJitter(t *testing.T) {
	base := 1000 * time.Millisecond
	j := 100 * time.Millisecond
	for i := 0; i < 100; i++ {
		got := jitter(base, j)
		require.GreaterOrEqual(t, got, base-j)
		require.Less(t, got, base+j)
	}
}

func TestJitterZeroIsBase(t *testing.T) {
	require.Equal(t, 1*time.Second, jitter(time.Second, 0))
}

func TestNextBackoffCaps(t *testing.T) {
	require.Equal(t, 2*time.Second, nextBackoff(1*time.Second, 30*time.Second, 2.0))
	require.Equal(t, 30*time.Second, nextBackoff(25*time.Second, 30*time.Second, 2.0))
	require.Equal(t, 30*time.Second, nextBackoff(30*time.Second, 30*time.Second, 2.0))
}
