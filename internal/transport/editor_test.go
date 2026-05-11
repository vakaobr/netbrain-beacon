package transport

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func newReq(t *testing.T) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "https://example.invalid/", nil)
	return req
}

func TestWithUserAgent(t *testing.T) {
	req := newReq(t)
	require.NoError(t, WithUserAgent()(context.Background(), req))
	require.Equal(t, UserAgent, req.Header.Get("User-Agent"))
}

func TestWithIdempotencyKey(t *testing.T) {
	req := newReq(t)
	require.NoError(t, WithIdempotencyKey("4acceffe-1dfb-52de-8ff1-cc8629646925")(context.Background(), req))
	require.Equal(t, "4acceffe-1dfb-52de-8ff1-cc8629646925", req.Header.Get("Idempotency-Key"))
}

func TestWithGzipEncoding(t *testing.T) {
	req := newReq(t)
	require.NoError(t, WithGzipEncoding()(context.Background(), req))
	require.Equal(t, "gzip", req.Header.Get("Content-Encoding"))
}

func TestWithIfNoneMatch(t *testing.T) {
	req := newReq(t)
	require.NoError(t, WithIfNoneMatch(`"abc123"`)(context.Background(), req))
	require.Equal(t, `"abc123"`, req.Header.Get("If-None-Match"))
}

func TestWithIfNoneMatchEmptySkips(t *testing.T) {
	req := newReq(t)
	require.NoError(t, WithIfNoneMatch("")(context.Background(), req))
	require.Empty(t, req.Header.Get("If-None-Match"),
		"empty etag must NOT set the header (first-poll case)")
}
