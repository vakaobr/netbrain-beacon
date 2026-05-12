package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"

	"github.com/vakaobr/netbrain-beacon/internal/api"
	"github.com/vakaobr/netbrain-beacon/internal/enroll"
	"github.com/vakaobr/netbrain-beacon/internal/transport"
)

// ServerCheckReport is the server-side cert-status snapshot fetched via
// GET /api/v1/beacons/{id}/cert-status. Populated only when the operator
// passes --check-server on the `status` subcommand.
type ServerCheckReport struct {
	// Reachable indicates the request completed end-to-end (TLS + HTTP).
	// false means the request itself failed; check Error for details.
	Reachable bool `json:"reachable"`

	// HTTPStatus is the server's response code (200, 403, 503, etc.).
	HTTPStatus int `json:"http_status,omitempty"`

	// DaysUntilExpiry is the server's authoritative answer for how long
	// the cert remains valid. Negative values mean already-expired.
	DaysUntilExpiry int `json:"days_until_expiry,omitempty"`

	// ExpiresAt is the server-side cert expiry timestamp (RFC3339). Note
	// this may differ from the local-disk cert if the server has rotated
	// the cert chain.
	ExpiresAt string `json:"expires_at,omitempty"`

	// RecommendedAction is one of: "none" | "rotate" | "reenroll". When
	// the server says "rotate", the daemon's cert-rotation scheduler is
	// expected to act within minutes.
	RecommendedAction string `json:"recommended_action,omitempty"`

	// RevocationReason is non-empty if the server revoked this beacon's
	// cert (e.g., "decommissioned", "compromised").
	RevocationReason string `json:"revocation_reason,omitempty"`

	// Error captures any network / TLS / decode failure. Operators
	// looking at this field should compare with the on-disk cert via
	// the rest of StatusReport.
	Error string `json:"error,omitempty"`
}

// CheckServer fetches the server-side cert status over mTLS using the
// on-disk cert + key + CA bundle. Used by the `status --check-server`
// subcommand to answer "is my enrollment still valid according to the
// platform?" without requiring the daemon to be running.
//
// On any disk / TLS / HTTP failure, returns a ServerCheckReport with
// Reachable=false and the underlying error in Error. This function does
// NOT propagate errors — operators want the partial report ("we tried,
// here's what failed") rather than an opaque error string.
func CheckServer(ctx context.Context, stateDir string) *ServerCheckReport {
	r := &ServerCheckReport{}

	// 1) Load on-disk enrollment metadata to get serverURL + beaconID.
	metaPath := filepath.Join(stateDir, enroll.MetadataFilename)
	raw, err := os.ReadFile(metaPath) //nolint:gosec
	if err != nil {
		r.Error = "read metadata: " + err.Error()
		return r
	}
	var meta enroll.Metadata
	if jerr := json.Unmarshal(raw, &meta); jerr != nil {
		r.Error = "decode metadata: " + jerr.Error()
		return r
	}
	if meta.BeaconID == uuid.Nil {
		r.Error = "metadata has zero beacon_id (not enrolled)"
		return r
	}
	if meta.ServerURL == "" {
		r.Error = "metadata has empty server_url"
		return r
	}

	// 2) Load cert + key + CA bundle.
	certPEM, err := os.ReadFile(filepath.Join(stateDir, enroll.BeaconCertFilename)) //nolint:gosec
	if err != nil {
		r.Error = "read cert: " + err.Error()
		return r
	}
	keyPEM, err := os.ReadFile(filepath.Join(stateDir, enroll.BeaconKeyFilename)) //nolint:gosec
	if err != nil {
		r.Error = "read key: " + err.Error()
		return r
	}
	caPEM, err := os.ReadFile(filepath.Join(stateDir, enroll.PlatformCAFilename)) //nolint:gosec
	if err != nil {
		r.Error = "read ca: " + err.Error()
		return r
	}

	// 3) Build mTLS transport. Same TLS 1.3-only constraint the daemon uses.
	tc, err := transport.NewClient(transport.Config{
		CertPEM:       certPEM,
		KeyPEM:        keyPEM,
		PlatformCAPEM: caPEM,
		HTTPTimeout:   10 * time.Second,
	})
	if err != nil {
		r.Error = "tls config: " + err.Error()
		return r
	}

	// 4) Validate server URL + build api client.
	if _, perr := url.Parse(meta.ServerURL); perr != nil {
		r.Error = "bad server_url: " + perr.Error()
		return r
	}
	apiClient, err := api.NewClient(meta.ServerURL, api.WithHTTPClient(tc.Current()))
	if err != nil {
		r.Error = "api client: " + err.Error()
		return r
	}

	// 5) GET /cert-status — bounded by a 10s context so we don't hang
	// the operator's terminal on a black-hole network.
	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	resp, err := apiClient.GetCertStatus(reqCtx, meta.BeaconID)
	if err != nil {
		r.Error = "request: " + err.Error()
		return r
	}
	defer func() { _ = resp.Body.Close() }()

	r.Reachable = true
	r.HTTPStatus = resp.StatusCode

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096)) //nolint:forbidigo
		r.Error = fmt.Sprintf("HTTP %d: %s", resp.StatusCode, string(body))
		return r
	}

	parsed, err := api.ParseGetCertStatusResponse(resp)
	if err != nil {
		r.Error = "decode response: " + err.Error()
		return r
	}
	if parsed.JSON200 == nil {
		r.Error = "no JSON200 in response"
		return r
	}

	r.DaysUntilExpiry = parsed.JSON200.DaysUntilExpiry
	r.ExpiresAt = parsed.JSON200.ExpiresAt.UTC().Format(time.RFC3339)
	r.RecommendedAction = string(parsed.JSON200.RecommendedAction)
	if parsed.JSON200.RevocationReason != nil {
		r.RevocationReason = *parsed.JSON200.RevocationReason
	}
	return r
}

// silence unused-import grumbles when fields are commented out during dev
var _ = errors.New
