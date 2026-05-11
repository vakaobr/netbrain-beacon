package transport

import (
	"context"
	"net/http"
)

// RequestEditorFn matches the generated client's RequestEditorFn signature.
// Each beacon RPC accepts one or more editors that mutate the outgoing
// *http.Request before send.
type RequestEditorFn func(ctx context.Context, req *http.Request) error

// UserAgent is the canonical User-Agent string. Replaced at build time
// via -ldflags "-X internal/transport.UserAgent=...". Tests use the
// default unless they override.
var UserAgent = "netbrain-beacon/dev"

// WithUserAgent returns an editor that sets the standard User-Agent header.
// Mandatory on every outbound request; the platform's nginx access log
// uses it for fleet diagnostics.
func WithUserAgent() RequestEditorFn {
	return func(_ context.Context, req *http.Request) error {
		req.Header.Set("User-Agent", UserAgent)
		return nil
	}
}

// WithIdempotencyKey attaches a caller-supplied UUIDv5 Idempotency-Key to
// the request. Required on every /data/* push so the platform can
// deduplicate retries (ADR-069).
//
// The key is computed by internal/crypto.DeriveBatchIdempotencyKey; the
// transport package never derives it itself.
func WithIdempotencyKey(keyStr string) RequestEditorFn {
	return func(_ context.Context, req *http.Request) error {
		req.Header.Set("Idempotency-Key", keyStr)
		return nil
	}
}

// WithGzipEncoding marks the request body as gzip-encoded. Use on /data/logs
// (NDJSON-gzipped wire format per ADR-069). Note: /data/flows uses multipart
// binary and does NOT set this header.
func WithGzipEncoding() RequestEditorFn {
	return func(_ context.Context, req *http.Request) error {
		req.Header.Set("Content-Encoding", "gzip")
		return nil
	}
}

// WithIfNoneMatch attaches an ETag for the config-poll short-circuit
// (ADR-070). Server returns 304 when the supplied tag matches.
func WithIfNoneMatch(etag string) RequestEditorFn {
	return func(_ context.Context, req *http.Request) error {
		if etag == "" {
			return nil
		}
		req.Header.Set("If-None-Match", etag)
		return nil
	}
}
