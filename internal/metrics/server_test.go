package metrics

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// fetchBody GETs url and returns the body string. Returns empty + the
// error on failure.
func fetchBody(t *testing.T, url string) string {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	require.NoError(t, err)
	c := http.Client{Timeout: 2 * time.Second}
	resp, err := c.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return string(body)
}

func TestServerStartCloseRoundTrip(t *testing.T) {
	s := NewServer("127.0.0.1:0") // ephemeral port
	require.NoError(t, s.Start(context.Background()))
	t.Cleanup(func() { _ = s.Close(context.Background()) })

	// Bump some metrics so the response body has lines.
	EnrollmentTotal.WithLabelValues("success").Inc()
	DEKVerifyFailedTotal.Inc()
	SetBuildInfo("v0.1.0-test", "deadbeef")

	body := fetchBody(t, "http://"+s.Addr()+"/metrics")
	require.Contains(t, body, "beacon_enrollment_total")
	require.Contains(t, body, "beacon_dek_verify_failed_total")
	require.Contains(t, body, `beacon_build_info{commit="deadbeef",version="v0.1.0-test"}`)
}

func TestHealthzEndpoint(t *testing.T) {
	s := NewServer("127.0.0.1:0")
	require.NoError(t, s.Start(context.Background()))
	t.Cleanup(func() { _ = s.Close(context.Background()) })

	body := fetchBody(t, "http://"+s.Addr()+"/healthz")
	require.Equal(t, "ok\n", body)
}

func TestCloseIdempotent(t *testing.T) {
	s := NewServer("127.0.0.1:0")
	// Close before Start is a no-op.
	require.NoError(t, s.Close(context.Background()))

	require.NoError(t, s.Start(context.Background()))
	require.NoError(t, s.Close(context.Background()))
	require.NoError(t, s.Close(context.Background()))
}

func TestServerDefaultsToLoopback(t *testing.T) {
	s := NewServer("")
	require.Equal(t, DefaultBindAddr, s.BindAddr)
}

func TestAllRegistered(t *testing.T) {
	// Each metric in All registers at init time. The slice has 18 entries
	// matching 03_PROJECT_SPEC.md §NFR-OBS.
	require.Len(t, All, 18, "exactly 18 metrics per spec §NFR-OBS")
}

func TestSetBuildInfoSetsLabels(t *testing.T) {
	SetBuildInfo("v1.0", "abc")
	// We don't inspect the registry directly; just make sure the call doesn't panic.
}

// --- M-1: non-loopback bind warning (CWE-200) ---

// TestIsLoopbackBindRecognizesLoopback exercises the cases that MUST
// be treated as loopback (no warning).
func TestIsLoopbackBindRecognizesLoopback(t *testing.T) {
	for _, addr := range []string{
		"127.0.0.1:9090",
		"127.0.0.1:0",
		"localhost:9090",
		"[::1]:9090",
	} {
		require.True(t, isLoopbackBind(addr), "loopback case: %s", addr)
	}
}

// TestIsLoopbackBindRecognizesNonLoopback exercises the cases that
// MUST trigger the warning.
func TestIsLoopbackBindRecognizesNonLoopback(t *testing.T) {
	for _, addr := range []string{
		"0.0.0.0:9090",
		"[::]:9090",
		"192.168.1.5:9090",
		"10.0.0.1:9090",
		":9090", // empty host → all interfaces
		"example.com:9090",
	} {
		require.False(t, isLoopbackBind(addr), "non-loopback case: %s", addr)
	}
}

// TestStartEmitsWarnOnNonLoopback verifies the structured warning fires
// at Start when bound to 0.0.0.0.
func TestStartEmitsWarnOnNonLoopback(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	s := NewServer("0.0.0.0:0")
	s.Logger = logger
	require.NoError(t, s.Start(context.Background()))
	t.Cleanup(func() { _ = s.Close(context.Background()) })

	out := buf.String()
	require.Contains(t, out, "metrics.non_loopback_bind",
		"non-loopback bind must emit the structured warning (M-1)")
	require.Contains(t, out, "unauthenticated_metrics_exposed")
}

// TestStartSilentOnLoopback verifies the warning does NOT fire on the
// happy default-bind path — no log noise for the 99% case.
func TestStartSilentOnLoopback(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	s := NewServer("127.0.0.1:0")
	s.Logger = logger
	require.NoError(t, s.Start(context.Background()))
	t.Cleanup(func() { _ = s.Close(context.Background()) })

	require.NotContains(t, buf.String(), "non_loopback_bind",
		"loopback bind must NOT emit the M-1 warning")
}
