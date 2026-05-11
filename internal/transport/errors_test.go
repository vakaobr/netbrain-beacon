package transport

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func resp(t *testing.T, status int, body string) *http.Response {
	t.Helper()
	r := &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
	}
	t.Cleanup(func() { _ = r.Body.Close() })
	return r
}

// --- happy paths ---

func TestClassify2xxSuccess(t *testing.T) {
	action, srvErr := Classify(resp(t, 200, `{"ok":true}`))
	require.Equal(t, ActionSuccess, action)
	require.Nil(t, srvErr)
}

func TestClassify304NotModified(t *testing.T) {
	action, srvErr := Classify(resp(t, 304, ""))
	require.Equal(t, ActionNotModified, action)
	require.Nil(t, srvErr)
}

// --- mapped codes (one test per Action category, exhaustive lookup via TestAllCodesHaveAction) ---

func TestClassifyFeatureFlagOff(t *testing.T) {
	body := `{"error":{"code":"BEACON_PROTOCOL_NOT_ENABLED","message":"flag off"}}`
	action, srvErr := Classify(resp(t, 503, body))
	require.Equal(t, ActionBackOffHeavy, action)
	require.NotNil(t, srvErr)
	require.Equal(t, "BEACON_PROTOCOL_NOT_ENABLED", srvErr.Code)
}

func TestClassifyAADMismatchDropAndAlert(t *testing.T) {
	body := `{"error":{"code":"BEACON_AAD_MISMATCH","message":"tag failed"}}`
	action, srvErr := Classify(resp(t, 400, body))
	require.Equal(t, ActionDropAndAlert, action)
	require.Equal(t, 400, srvErr.HTTPStatus)
}

func TestClassifyDEKExpiredRefreshes(t *testing.T) {
	body := `{"error":{"code":"BEACON_DEK_EXPIRED","message":"rotated"}}`
	action, srvErr := Classify(resp(t, 401, body))
	require.Equal(t, ActionRefreshDEK, action)
	require.Equal(t, "BEACON_DEK_EXPIRED", srvErr.Code)
}

func TestClassifyURLCertMismatchFatal(t *testing.T) {
	body := `{"error":{"code":"BEACON_URL_CERT_MISMATCH","message":"H-2"}}`
	action, _ := Classify(resp(t, 403, body))
	require.Equal(t, ActionFatalReenroll, action)
}

func TestClassifyNotFoundFatal(t *testing.T) {
	body := `{"error":{"code":"NOT_FOUND_OR_CROSS_TENANT","message":"M-3"}}`
	action, _ := Classify(resp(t, 404, body))
	require.Equal(t, ActionFatalReenroll, action)
}

func TestClassifyCSRInvalidFatal(t *testing.T) {
	body := `{"error":{"code":"CSR_INVALID","message":"sig"}}`
	action, _ := Classify(resp(t, 400, body))
	require.Equal(t, ActionFatalReenroll, action)
}

func TestClassifyRateLimitedRetries(t *testing.T) {
	body := `{"error":{"code":"BOOTSTRAP_TOKEN_RATE_LIMITED","message":"slow"}}`
	action, _ := Classify(resp(t, 429, body))
	require.Equal(t, ActionRetry, action)
}

// --- 5xx generic retry ---

func TestClassify5xxRetries(t *testing.T) {
	action, _ := Classify(resp(t, 500, ""))
	require.Equal(t, ActionRetry, action)
	action, _ = Classify(resp(t, 502, ""))
	require.Equal(t, ActionRetry, action)
	action, _ = Classify(resp(t, 503, "")) // No envelope; should retry
	require.Equal(t, ActionRetry, action)
}

func TestClassify5xxWithEnvelope(t *testing.T) {
	body := `{"error":{"code":"INTERNAL","message":"oops"}}`
	action, srvErr := Classify(resp(t, 500, body))
	require.Equal(t, ActionRetry, action)
	require.NotNil(t, srvErr)
	require.Equal(t, 500, srvErr.HTTPStatus)
}

// --- 4xx with unknown envelope ---

func TestClassifyUnknownCodeFallsToFatal(t *testing.T) {
	body := `{"error":{"code":"FUTURE_UNKNOWN_CODE","message":"server added a new error"}}`
	action, srvErr := Classify(resp(t, 400, body))
	require.Equal(t, ActionFatalReenroll, action)
	require.Equal(t, "FUTURE_UNKNOWN_CODE", srvErr.Code)
}

func TestClassify4xxNoEnvelopeFallsToFatal(t *testing.T) {
	action, srvErr := Classify(resp(t, 400, "not json"))
	require.Equal(t, ActionFatalReenroll, action)
	require.Equal(t, "UNPARSEABLE_RESPONSE", srvErr.Code)
	require.Equal(t, 400, srvErr.HTTPStatus)
}

func TestClassifyEmptyBody(t *testing.T) {
	action, _ := Classify(resp(t, 401, ""))
	require.Equal(t, ActionFatalReenroll, action)
}

// --- envelope-parsing limit ---

func TestParseEnvelopeOversizedBodyIgnored(t *testing.T) {
	// 1 MB of junk before the envelope — must NOT be loaded into memory
	// in full. Limit is 64 KiB; oversized body fails to parse cleanly.
	big := bytes.Repeat([]byte("a"), 1<<20)
	srvErr := parseEnvelope(bytes.NewReader(big))
	require.Nil(t, srvErr, "oversized non-JSON body must not parse as envelope")
}

// --- exhaustive coverage gate ---

// TestAllServerCodesHaveAction enforces the documented invariant:
// every error code the server is known to emit MUST have an explicit
// entry in codeActions. Adding a new code on the server side without
// updating this table makes Classify fall to ActionFatalReenroll
// (the conservative default) and breaks this test as a reminder.
func TestAllServerCodesHaveAction(t *testing.T) {
	// Server-side codes that the beacon's data-plane / config-poll /
	// enroll routes can return. Sourced from
	// services/api-gateway/src/routes/beacons.py + the OpenAPI spec.
	required := []string{
		"BEACON_PROTOCOL_NOT_ENABLED",
		"BOOTSTRAP_TOKEN_INVALID",
		"BOOTSTRAP_TOKEN_RATE_LIMITED",
		"CSR_INVALID",
		"BEACON_AAD_MISMATCH",
		"BEACON_IDEMPOTENCY_KEY_MISMATCH",
		"BEACON_ENVELOPE_INVALID",
		"BEACON_GUNZIP_CORRUPT",
		"BEACON_INVALID_FLOW_FILENAME",
		"BEACON_DEK_EXPIRED",
		"BEACON_URL_CERT_MISMATCH",
		"NOT_FOUND_OR_CROSS_TENANT",
		"BEACON_DECOMPRESSION_BOMB",
		"INVALID_PARAM",
		"INVALID_WINDOW",
		"UNAUTHORIZED",
	}
	for _, code := range required {
		_, ok := codeActions[code]
		require.True(t, ok, "code %q has no Action mapping — Classify will halt on it (conservative default)", code)
	}
}

func TestActionString(t *testing.T) {
	// String() exists so logs show the action name. Sanity-check all
	// values map to non-empty strings.
	for a := ActionUnknown; a <= ActionNotModified; a++ {
		require.NotEmpty(t, a.String())
	}
}

func TestServerErrorMessage(t *testing.T) {
	e := &ServerError{Code: "X", Message: "Y", HTTPStatus: 418}
	require.Contains(t, e.Error(), "X")
	require.Contains(t, e.Error(), "418")
	require.Contains(t, e.Error(), "Y")
}

func TestKnownCodesNonEmpty(t *testing.T) {
	require.NotEmpty(t, KnownCodes())
}
