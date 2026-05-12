package log

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// newRedactedLogger returns a JSON-handler logger wrapped in the H-3 redactor,
// writing into the provided buffer for assertions.
func newRedactedLogger(buf *bytes.Buffer) *slog.Logger {
	inner := slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	return slog.New(NewHandler(inner))
}

func TestRedactorDropsBootstrapToken(t *testing.T) {
	var buf bytes.Buffer
	log := newRedactedLogger(&buf)

	log.Info("enroll start", "bootstrap_token", "nbb_secret_abc123def456abcdef0123")

	out := buf.String()
	require.NotContains(t, out, "nbb_secret_abc123", "plaintext token must NOT appear")
	require.Contains(t, out, "[REDACTED]", "redacted placeholder must appear in place")
}

func TestRedactorDropsDEK(t *testing.T) {
	var buf bytes.Buffer
	log := newRedactedLogger(&buf)
	log.Info("dek loaded", "dek", "raw-32-bytes-of-dek-here")
	require.NotContains(t, buf.String(), "raw-32-bytes-of-dek-here")
	require.Contains(t, buf.String(), "[REDACTED]")
}

func TestRedactorDropsCSRPEM(t *testing.T) {
	var buf bytes.Buffer
	log := newRedactedLogger(&buf)
	log.Info("csr built", "csr_pem", "-----BEGIN CERTIFICATE REQUEST-----\nbase64\n-----END CERTIFICATE REQUEST-----")
	require.NotContains(t, buf.String(), "base64")
}

func TestRedactorSweepsTokenInsideMessage(t *testing.T) {
	// Developer formatted the token into the message string by mistake.
	// The regex sweep over msg must catch it.
	var buf bytes.Buffer
	log := newRedactedLogger(&buf)
	log.Info("token nbb_leaked_abcdef0123456789abcdef accepted")
	require.NotContains(t, buf.String(), "nbb_leaked_abc")
	require.Contains(t, buf.String(), "[REDACTED]")
}

func TestRedactorSweepsTokenInsideAttrValue(t *testing.T) {
	var buf bytes.Buffer
	log := newRedactedLogger(&buf)
	log.Info("got error", "msg", "rejected nbb_abc123def456abcdef0123abc with reason X")
	require.NotContains(t, buf.String(), "nbb_abc123def456")
	require.Contains(t, buf.String(), "[REDACTED]")
}

func TestRedactorLeavesSafeFieldsAlone(t *testing.T) {
	var buf bytes.Buffer
	log := newRedactedLogger(&buf)
	log.Info("enrolled", "beacon_id", "abcdef00-1234-4567-8901-abcdef012345", "version", 2)
	out := buf.String()
	require.Contains(t, out, "abcdef00-1234-4567")
	require.Contains(t, out, `"version":2`)
}

func TestRedactorWithGroup(t *testing.T) {
	var buf bytes.Buffer
	log := newRedactedLogger(&buf)
	log = log.With(slog.Group("ctx", slog.String("bootstrap_token", "nbb_inside_group_abc123def456ab")))
	log.Info("hi")

	out := buf.String()
	require.NotContains(t, out, "nbb_inside_group")
}

func TestRedactorWithAttrs(t *testing.T) {
	// WithAttrs returns a new handler; must also scrub.
	var buf bytes.Buffer
	inner := slog.NewJSONHandler(&buf, nil)
	h := NewHandler(inner)
	h2 := h.WithAttrs([]slog.Attr{slog.String("bootstrap_token", "nbb_bound_abcdef0123456789abcd")})
	logger := slog.New(h2)
	logger.Info("hi")

	out := buf.String()
	require.NotContains(t, out, "nbb_bound_abc")
}

func TestRedactorEnabledDelegation(t *testing.T) {
	inner := slog.NewJSONHandler(&bytes.Buffer{}, &slog.HandlerOptions{Level: slog.LevelInfo})
	h := NewHandler(inner)
	require.False(t, h.Enabled(context.Background(), slog.LevelDebug))
	require.True(t, h.Enabled(context.Background(), slog.LevelInfo))
}

func TestContainsTokenPatternHelper(t *testing.T) {
	require.True(t, ContainsTokenPattern("nbb_abcdef0123456789abcdef0123"))
	require.False(t, ContainsTokenPattern("no token here"))
	require.False(t, ContainsTokenPattern("nbb_short"), "token-shaped but too short — must not match")
}

// TestRedactorNoLeakAcrossAllSensitiveKeys is the regression guard. Any
// new sensitive key added to sensitiveKeys must show up here too — keep
// this list synced.
func TestRedactorNoLeakAcrossAllSensitiveKeys(t *testing.T) {
	cases := []struct {
		key, val string
	}{
		{"bootstrap_token", "nbb_a-b_c-d-test-12345-67890-zzz"},
		{"dek", "raw-dek-bytes-secret"},
		{"data_key_b64", "base64dekgoeshereXYZ"},
		{"data_key", "raw-dek-equivalent"},
		{"csr_pem", "PEM-CSR-with-secret-pubkey"},
		{"beacon_key", "PEM-private-key-secret"},
		{"private_key", "rsa-private-secret"},
		{"Authorization", "Bearer nbb_secret_token_here_zzz"},
	}
	for _, c := range cases {
		var buf bytes.Buffer
		log := newRedactedLogger(&buf)
		log.Info("test", c.key, c.val)
		out := buf.String()
		require.NotContains(t, out, c.val, "leaked %s value", c.key)
		// The placeholder OR an empty value should appear instead.
		require.True(t, strings.Contains(out, "[REDACTED]"), "missing redaction marker for %s", c.key)
	}
}
