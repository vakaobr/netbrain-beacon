package transport

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// Action enumerates the beacon's possible reactions to a server response.
// Every code path that handles an RPC result MUST switch on Action explicitly —
// the zero value (ActionUnknown) is treated as a fatal programming error.
type Action int

const (
	// ActionUnknown is the zero value — indicates a code path that received
	// a response shape it doesn't know how to interpret. Callers should log
	// + alert and treat as ActionFatalReenroll (most conservative choice).
	ActionUnknown Action = iota

	// ActionSuccess means 2xx response — payload is whatever the caller expected.
	ActionSuccess

	// ActionRetry means transient failure; retry with exponential backoff.
	// Covers 5xx, 429, and network-layer errors.
	ActionRetry

	// ActionDropAndAlert means the server rejected the batch with a code
	// that says "your payload is wrong" (AAD mismatch, decompression bomb,
	// malformed envelope). Retrying with the same payload will keep failing.
	// Drop the batch and emit an alert. Common signal: beacon-side bug or
	// attack.
	ActionDropAndAlert

	// ActionFatalReenroll means the beacon identity is broken or compromised
	// (cert/URL mismatch, cross-tenant access, NOT_FOUND). The beacon
	// cannot continue without operator intervention (re-enrollment).
	// Daemon should halt the affected collector + emit a P1 alert.
	ActionFatalReenroll

	// ActionBackOffHeavy means the server-side feature flag is off (503
	// BEACON_PROTOCOL_NOT_ENABLED). Don't hammer — wait 5 min and retry.
	ActionBackOffHeavy

	// ActionRefreshDEK means the server reported the current DEK is expired
	// or unknown. Beacon must poll /config to fetch a rotated DEK, verify
	// its signature, then retry the batch with the new key.
	ActionRefreshDEK

	// ActionNotModified means a 304 response from /config — apply nothing;
	// the beacon's cached config is still fresh.
	ActionNotModified
)

// String implements fmt.Stringer for debug output.
func (a Action) String() string {
	switch a {
	case ActionSuccess:
		return "success"
	case ActionRetry:
		return "retry"
	case ActionDropAndAlert:
		return "drop_and_alert"
	case ActionFatalReenroll:
		return "fatal_reenroll"
	case ActionBackOffHeavy:
		return "back_off_heavy"
	case ActionRefreshDEK:
		return "refresh_dek"
	case ActionNotModified:
		return "not_modified"
	default:
		return "unknown"
	}
}

// ServerError is the canonical { "error": { "code": "...", "message": "..."} }
// envelope returned by the platform on every 4xx and most 5xx responses.
type ServerError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	// HTTPStatus is set by Classify; not part of the wire envelope. Lets
	// callers correlate response shape with the original status line.
	HTTPStatus int `json:"-"`
}

// Error satisfies error so the type can be returned from RPC wrappers.
func (e *ServerError) Error() string {
	return fmt.Sprintf("beacon server error: %s (HTTP %d): %s", e.Code, e.HTTPStatus, e.Message)
}

// envelope is the wire shape of the error response.
type envelope struct {
	Error ServerError `json:"error"`
}

// codeActions maps the 17 server error codes catalogued in the netbrain
// OpenAPI spec (services/api-gateway/openapi/beacon-v1.yaml). The table is
// exhaustive — every code surfaces from at least one route. CI test
// TestAllServerCodesHaveAction asserts none are missing.
//
// The map is the SINGLE SOURCE OF TRUTH for what each code means to the
// beacon. Server-side code changes that introduce new codes MUST be added
// here in the same release, or Classify falls through to ActionUnknown
// and the beacon halts conservatively.
//
// === POLICY: ADDING A NEW SERVER-SIDE ERROR CODE ===========================
//
// The platform repo (netbrain/services/api-gateway/openapi/beacon-v1.yaml)
// is upstream of this table. Whenever a PR over there adds, renames, or
// removes a beacon error code, a coordinated PR in THIS repo MUST:
//
//   1. Update codeActions below — pick the Action that matches the code's
//      semantics (Retry for transient, DropAndAlert for "your payload is
//      bad", FatalReenroll for "your identity is broken", etc.). Adding a
//      new Action constant requires a separate PR and an ADR update.
//   2. Add a test case to errors_test.go demonstrating Classify dispatches
//      the new code to the chosen Action. The map-vs-KnownCodes consistency
//      test (TestAllServerCodesHaveAction) only catches the WRONG case —
//      a real round-trip test catches handler-wiring regressions.
//   3. Cite the platform PR + OpenAPI version in the PR description so the
//      audit trail crosses repos.
//
// If you ship a platform release with a new code but skip this PR, the
// beacon will halt the affected collector on first encounter (Classify's
// 4xx-fallback path returns ActionFatalReenroll). This is the intended
// fail-closed behaviour — better a halt than a silently-discarded batch —
// but it WILL page the operator on call, so don't.
var codeActions = map[string]Action{
	// 503 — platform feature flag is off.
	"BEACON_PROTOCOL_NOT_ENABLED": ActionBackOffHeavy,

	// 400 / 401 — enrollment ceremony failures. Operator action required.
	"BOOTSTRAP_TOKEN_INVALID":      ActionFatalReenroll,
	"BOOTSTRAP_TOKEN_RATE_LIMITED": ActionRetry, // rate limit recovers; back off
	"CSR_INVALID":                  ActionFatalReenroll,

	// 400 — data-plane authentication failures. Drop batch; alert.
	"BEACON_AAD_MISMATCH":             ActionDropAndAlert,
	"BEACON_IDEMPOTENCY_KEY_MISMATCH": ActionDropAndAlert,
	"BEACON_ENVELOPE_INVALID":         ActionDropAndAlert,
	"BEACON_GUNZIP_CORRUPT":           ActionDropAndAlert,
	"BEACON_INVALID_FLOW_FILENAME":    ActionDropAndAlert,

	// 401 — DEK expired or unknown version. Refresh and retry.
	"BEACON_DEK_EXPIRED": ActionRefreshDEK,

	// 403 — beacon presented cert for one beacon_id but URL was a
	// different beacon's. H-2 IDOR attempt. Halt.
	"BEACON_URL_CERT_MISMATCH": ActionFatalReenroll,

	// 404 — cross-tenant lookup. Halt; do not retry.
	"NOT_FOUND_OR_CROSS_TENANT": ActionFatalReenroll,

	// 413 — server-side bomb detector tripped. Beacon-side bug; drop + alert.
	"BEACON_DECOMPRESSION_BOMB": ActionDropAndAlert,

	// 400 — input validation failures the beacon shouldn't generate.
	"INVALID_PARAM":  ActionDropAndAlert,
	"INVALID_WINDOW": ActionDropAndAlert,

	// 401 - generic auth failure.
	"UNAUTHORIZED": ActionFatalReenroll,
}

// Classify inspects an HTTP response and returns the beacon's action plus
// any parsed ServerError envelope (nil on 2xx and on responses without a
// JSON envelope, e.g., infrastructure failures).
//
// The response body is read but not closed — the caller owns the response
// lifecycle.
//
// 2xx → ActionSuccess + nil error.
// 304 → ActionNotModified + nil error.
// 4xx with parseable envelope → mapped Action + populated ServerError.
// 4xx without envelope → ActionFatalReenroll (most conservative).
// 5xx → ActionRetry + envelope if present, nil otherwise.
func Classify(resp *http.Response) (Action, *ServerError) {
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return ActionSuccess, nil
	case resp.StatusCode == http.StatusNotModified:
		return ActionNotModified, nil
	}

	srvErr := parseEnvelope(resp.Body)
	if srvErr != nil {
		srvErr.HTTPStatus = resp.StatusCode
	}

	// Code-based dispatch runs FIRST (before any status-code heuristic) so
	// recognized codes return their canonical action even on 5xx. The
	// canonical example is BEACON_PROTOCOL_NOT_ENABLED → 503 + ActionBackOffHeavy,
	// which must NOT fall to the generic-5xx retry branch.
	if srvErr != nil {
		if action, ok := codeActions[srvErr.Code]; ok {
			return action, srvErr
		}
	}

	// 5xx with unrecognized (or absent) code — transient by default.
	if resp.StatusCode >= 500 {
		return ActionRetry, srvErr
	}

	// 4xx with known envelope shape but unknown code — halt conservatively
	// (server may have added a new code we don't recognize yet).
	if srvErr != nil {
		return ActionFatalReenroll, srvErr
	}

	// 4xx with no parseable envelope — also halt.
	return ActionFatalReenroll, &ServerError{
		Code:       "UNPARSEABLE_RESPONSE",
		Message:    fmt.Sprintf("HTTP %d with no parseable error envelope", resp.StatusCode),
		HTTPStatus: resp.StatusCode,
	}
}

// parseEnvelope reads the response body and parses it as a NetBrain error
// envelope. Returns nil on any read or decode failure — Classify falls back
// to the status-code-only heuristic.
func parseEnvelope(body io.Reader) *ServerError {
	if body == nil {
		return nil
	}
	// 64 KiB is generous for an error envelope; protects against a
	// misbehaving server returning a multi-MB body.
	raw, err := io.ReadAll(io.LimitReader(body, 64*1024)) //nolint:forbidigo // bounded reader; not user-input gunzip
	if err != nil || len(raw) == 0 {
		return nil
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil
	}
	if env.Error.Code == "" {
		return nil
	}
	return &env.Error
}

// KnownCodes returns the canonical list of error codes the beacon knows
// how to react to. Used by TestAllServerCodesHaveAction to enforce the
// "no missing codes" invariant at CI time.
func KnownCodes() []string {
	out := make([]string, 0, len(codeActions))
	for k := range codeActions {
		out = append(out, k)
	}
	return out
}
