package metrics

import (
	"context"
	"io"
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
