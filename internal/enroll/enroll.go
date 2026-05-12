package enroll

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/velonet/netbrain-beacon/internal/api"
)

// Errors surfaced by the enrollment orchestrator.
var (
	// ErrEnrollmentRejected wraps any 4xx/5xx response from the server. The
	// wrapped error carries the server's structured envelope (Code +
	// Message). Operator action depends on the code.
	ErrEnrollmentRejected = errors.New("enroll: server rejected enrollment")

	// ErrEnrollmentNetwork is returned for connect / TLS handshake / read
	// failures. Retryable by re-running the CLI.
	ErrEnrollmentNetwork = errors.New("enroll: network failure")

	// ErrEnrollmentResponseInvalid is returned when the server's 2xx body
	// is missing required fields (cert, DEK, endpoints). Indicates a
	// platform-side regression.
	ErrEnrollmentResponseInvalid = errors.New("enroll: server response invalid")
)

// Input is the orchestrator's input: a verified bundle, a target
// server URL, and the beacon's reported metadata. The bundle's
// PlatformCACert is what we trust at TLS handshake — NOT the system
// trust store.
type Input struct {
	Bundle    *Bundle
	ServerURL string
	Metadata  api.BeaconMetadata
	// HTTPTimeout for the enroll round-trip. Defaults to 30s.
	HTTPTimeout time.Duration
}

// Result is what the orchestrator hands back. Persist takes its
// fields directly.
type Result struct {
	BeaconID                 uuid.UUID
	BeaconCertPEM            []byte
	BeaconKeyPEM             []byte
	DEK                      []byte
	PlatformCAPEM            []byte
	PlatformPubKeyPEM        []byte
	ConfigEndpoint           string
	DataEndpoint             string
	DEKVersion               int
	HeartbeatIntervalSeconds int
	LogBatchMaxAgeSeconds    int
	LogBatchMaxBytes         int
}

// Enroll runs the bootstrap-token-then-CSR ceremony against the server URL.
//
// Sequence:
//  1. Generate ECDSA-P-256 key + CSR with empty Subject (ADR-067 §H-3).
//  2. POST /api/v1/beacons/enroll with Bearer <bootstrap_token>.
//  3. Parse response; fail-closed if any required field is missing.
//  4. Decode DEK base64.
//
// The CALLER must subsequently call Persist with the returned artifacts.
// Persist + Enroll are split so a test (or the CLI's --dry-run flag) can
// drive the round-trip without touching disk.
func Enroll(ctx context.Context, in Input) (*Result, *KeyMaterial, error) {
	// 1) keypair + CSR
	km, err := GenerateCSR()
	if err != nil {
		return nil, nil, err
	}

	// 2) HTTPS client pinned to the bundle's CA.
	httpClient, err := newEnrollHTTPClient(in.Bundle.PlatformCACert, in.HTTPTimeout)
	if err != nil {
		return nil, km, err
	}

	apiClient, err := api.NewClient(in.ServerURL, api.WithHTTPClient(httpClient))
	if err != nil {
		return nil, km, fmt.Errorf("%w: api client: %w", ErrEnrollmentNetwork, err)
	}

	req := api.BeaconEnrollRequest{
		BeaconMetadata: in.Metadata,
		BootstrapToken: in.Bundle.BootstrapToken,
		CsrPem:         string(km.CSRPEM),
	}

	// The OpenAPI spec requires Bearer auth even though the body carries the
	// token too — the platform's auth dep reads the header.
	resp, err := apiClient.EnrollBeacon(ctx, req, func(_ context.Context, r *http.Request) error {
		r.Header.Set("Authorization", "Bearer "+in.Bundle.BootstrapToken)
		r.Header.Set("User-Agent", "netbrain-beacon/dev")
		return nil
	})
	if err != nil {
		return nil, km, fmt.Errorf("%w: %w", ErrEnrollmentNetwork, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024)) //nolint:forbidigo // bounded; not user-input gunzip
	if err != nil {
		return nil, km, fmt.Errorf("%w: read body: %w", ErrEnrollmentNetwork, err)
	}

	if resp.StatusCode >= 400 {
		// The body should be the canonical { "error": {...} } envelope; if not,
		// the wrapped error still surfaces the status. We use a string here
		// because internal/transport's Classify needs the response value not
		// the body, and pulling that abstraction in for one call site adds
		// more coupling than it's worth.
		return nil, km, fmt.Errorf("%w: HTTP %d: %s", ErrEnrollmentRejected, resp.StatusCode, sanitizeBody(body))
	}

	parsed, err := api.ParseEnrollBeaconResponse(&http.Response{
		StatusCode: resp.StatusCode,
		Header:     resp.Header,
		Body:       io.NopCloser(strings.NewReader(string(body))),
	})
	if err != nil {
		return nil, km, fmt.Errorf("%w: parse: %w", ErrEnrollmentResponseInvalid, err)
	}
	if parsed.JSON201 == nil {
		return nil, km, fmt.Errorf("%w: expected 201 body, got status %d", ErrEnrollmentResponseInvalid, resp.StatusCode)
	}

	enrollResp := parsed.JSON201
	if enrollResp.ClientCertPem == "" || len(enrollResp.DataKeyB64) == 0 {
		return nil, km, fmt.Errorf("%w: missing client_cert_pem or data_key_b64", ErrEnrollmentResponseInvalid)
	}

	dek, err := decodeDEK(enrollResp.DataKeyB64)
	if err != nil {
		return nil, km, fmt.Errorf("%w: dek decode: %w", ErrEnrollmentResponseInvalid, err)
	}
	if len(dek) != 32 {
		return nil, km, fmt.Errorf("%w: dek must be 32 bytes, got %d", ErrEnrollmentResponseInvalid, len(dek))
	}

	return &Result{
		BeaconID:                 enrollResp.BeaconId,
		BeaconCertPEM:            []byte(enrollResp.ClientCertPem),
		BeaconKeyPEM:             km.PrivateKeyPEM,
		DEK:                      dek,
		PlatformCAPEM:            []byte(in.Bundle.PlatformCACert),
		PlatformPubKeyPEM:        []byte(in.Bundle.PlatformPubKeyPEM),
		ConfigEndpoint:           enrollResp.ConfigEndpoint,
		DataEndpoint:             enrollResp.DataEndpoint,
		DEKVersion:               enrollResp.DataKeyVersion,
		HeartbeatIntervalSeconds: enrollResp.HeartbeatIntervalSeconds,
		LogBatchMaxAgeSeconds:    enrollResp.LogBatchMaxAgeSeconds,
		LogBatchMaxBytes:         enrollResp.LogBatchMaxBytes,
	}, km, nil
}

// MetadataFromArtifacts builds a Metadata struct from an Result for
// the persist step. Kept here (not in persist.go) because it depends on the
// Result shape which is local to this file.
func MetadataFromArtifacts(r *Result, serverURL string) Metadata {
	return Metadata{
		BeaconID:                 r.BeaconID,
		EnrolledAt:               time.Now().UTC(),
		ServerURL:                serverURL,
		ConfigEndpoint:           r.ConfigEndpoint,
		DataEndpoint:             r.DataEndpoint,
		DEKVersion:               r.DEKVersion,
		HeartbeatIntervalSeconds: r.HeartbeatIntervalSeconds,
		LogBatchMaxAgeSeconds:    r.LogBatchMaxAgeSeconds,
		LogBatchMaxBytes:         r.LogBatchMaxBytes,
	}
}

// newEnrollHTTPClient builds the one-shot HTTPS client used for the
// enroll round-trip. NOT the same as internal/transport's mTLS client
// (the beacon has no cert yet — that's what enrollment delivers).
//
// Forbidigo carve-out: internal/transport is exempted from the net.Dial
// ban; internal/enroll is currently NOT. We rely on net/http's default
// transport here (which uses net.Dial under the hood). Since the URL is
// operator-supplied (the server URL passed at the CLI) and the IP is
// pinned by the platform CA chain, this is a controlled dial — but we
// add an `//nolint:forbidigo` annotation explicitly so reviewers see
// the carve-out at the site.
func newEnrollHTTPClient(caPEM string, timeout time.Duration) (*http.Client, error) {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM([]byte(caPEM)) {
		return nil, fmt.Errorf("%w: invalid platform CA in bundle", ErrEnrollmentNetwork)
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS13,
				RootCAs:    caPool,
			},
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			ForceAttemptHTTP2:     true,
		},
	}, nil
}

// decodeDEK handles both base64-encoded inputs (Python's typical wire
// shape) and already-raw inputs (the OpenAPI []byte field is auto-
// base64-decoded by oapi-codegen on the response side, so we may
// receive raw bytes here).
func decodeDEK(raw []byte) ([]byte, error) {
	if len(raw) == 32 {
		// Already raw.
		return raw, nil
	}
	// Try base64 — both standard and URL encoding.
	for _, dec := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if out, err := dec.DecodeString(string(raw)); err == nil && len(out) == 32 {
			return out, nil
		}
	}
	return nil, fmt.Errorf("dek not 32 bytes raw or base64; got %d bytes", len(raw))
}

// sanitizeBody trims response bodies to a length safe for log embedding.
// Server-side error envelopes are well under 1 KB; truncating defends
// against a misbehaving server returning multi-MB bodies that bloat logs.
func sanitizeBody(body []byte) string {
	const maxLen = 2048
	s := string(body)
	if len(s) > maxLen {
		return s[:maxLen] + "...[truncated]"
	}
	return s
}

// _ = runtime.GOOS keeps the import alive across platforms; some build tags
// drop it. (Indirectly used through persist.go's chmod logic.)
var _ = runtime.GOOS
