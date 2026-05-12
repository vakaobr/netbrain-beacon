// Package log wires the beacon's structured-logging setup (log/slog +
// JSON handler) and the H-3 redactor that scrubs bootstrap-token and
// DEK material from every emitted record.
package log

import (
	"context"
	"log/slog"
	"regexp"
	"strings"
)

// Sensitive keys that the redactor unconditionally drops from any slog
// record's attributes. Mirror of the netbrain platform's
// BootstrapTokenRedactor (services/api-gateway/src/log_filters/redactors.py).
var sensitiveKeys = map[string]struct{}{
	"bootstrap_token":                   {},
	"enrollment_bundle.bootstrap_token": {},
	"dek":                               {},
	"data_key_b64":                      {},
	"data_key":                          {},
	"csr_pem":                           {},
	"beacon_key":                        {},
	"private_key":                       {},
	"Authorization":                     {},
}

// tokenSweepRE catches plaintext bootstrap tokens that slipped into a
// formatted message (e.g., wrapped error strings). Token format:
//
//	nbb_[A-Za-z0-9_-]{32,}
//
// where nbb_ is the prefix the netbrain platform assigns and the body
// has 32+ url-safe-b64 characters.
var tokenSweepRE = regexp.MustCompile(`nbb_[A-Za-z0-9_\-]{16,}`)

// redactedPlaceholder is what every redacted field/value is replaced with.
// "[REDACTED]" is unmistakable in logs and search-engine-friendly for
// "did the redactor work?" forensics.
const redactedPlaceholder = "[REDACTED]"

// Handler wraps another slog.Handler and applies the H-3 redaction rules
// before delegating the record. Composition target — any handler can be
// the inner one (JSON, text, tint, etc.).
type Handler struct {
	inner slog.Handler
}

// NewHandler wraps inner with the H-3 redactor.
func NewHandler(inner slog.Handler) *Handler {
	return &Handler{inner: inner}
}

// Enabled delegates to the wrapped handler.
func (h *Handler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

// Handle scrubs sensitive attributes from r, sweeps the formatted message
// for token-shaped substrings, and passes the result to the wrapped handler.
func (h *Handler) Handle(ctx context.Context, r slog.Record) error {
	// Rewrite the message itself for the regex sweep — even a redactor
	// applied to extras can't help if the developer formatted the token
	// into the message string.
	newMsg := tokenSweepRE.ReplaceAllString(r.Message, redactedPlaceholder)
	newRec := slog.NewRecord(r.Time, r.Level, newMsg, r.PC)

	r.Attrs(func(a slog.Attr) bool {
		newRec.AddAttrs(redactAttr(a))
		return true
	})
	return h.inner.Handle(ctx, newRec)
}

// WithAttrs delegates to the wrapped handler after redacting the
// supplied attrs (so redactor.WithAttrs("bootstrap_token", "...") doesn't
// silently install a leaking handler).
func (h *Handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	red := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		red[i] = redactAttr(a)
	}
	return &Handler{inner: h.inner.WithAttrs(red)}
}

// WithGroup delegates unchanged; the group name itself isn't sensitive.
func (h *Handler) WithGroup(name string) slog.Handler {
	return &Handler{inner: h.inner.WithGroup(name)}
}

// redactAttr returns a copy of a with its value replaced by the
// redacted-placeholder if its key is in sensitiveKeys; otherwise descends
// into group/any values to redact nested sensitive keys; otherwise sweeps
// string values for nbb_-prefixed tokens.
func redactAttr(a slog.Attr) slog.Attr {
	if _, hit := sensitiveKeys[a.Key]; hit {
		return slog.String(a.Key, redactedPlaceholder)
	}
	switch a.Value.Kind() {
	case slog.KindGroup:
		inner := a.Value.Group()
		newInner := make([]slog.Attr, len(inner))
		for i, child := range inner {
			newInner[i] = redactAttr(child)
		}
		return slog.Group(a.Key, attrsToAny(newInner)...)
	case slog.KindString:
		s := a.Value.String()
		if tokenSweepRE.MatchString(s) {
			return slog.String(a.Key, tokenSweepRE.ReplaceAllString(s, redactedPlaceholder))
		}
		return a
	default:
		return a
	}
}

// attrsToAny converts []slog.Attr to the []any shape slog.Group expects.
func attrsToAny(attrs []slog.Attr) []any {
	out := make([]any, len(attrs))
	for i, a := range attrs {
		out[i] = a
	}
	return out
}

// ContainsTokenPattern reports whether s contains a substring shaped like
// a plaintext bootstrap token. Used by tests that assert "log output
// MUST NOT contain a token" without coupling to the exact format.
func ContainsTokenPattern(s string) bool {
	return strings.Contains(s, "nbb_") && tokenSweepRE.MatchString(s)
}
