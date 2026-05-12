package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/vakaobr/netbrain-beacon/internal/api"
	"github.com/vakaobr/netbrain-beacon/internal/metrics"
)

// PollResult is the outcome of one poll cycle. Returned for tests +
// metrics; production code logs the struct via slog.
type PollResult struct {
	// HTTPStatus is the server's response status code (200, 304, or
	// an error code).
	HTTPStatus int

	// Modified is true when a new config landed (200 with a different
	// hash from State.ConfigHash). False for 304 / errors.
	Modified bool

	// NewHash is the freshly-applied config hash. Empty on 304 / errors.
	NewHash string

	// DEKSignaturePresent reports whether the response carried the
	// X-Beacon-DataKey-Signature header. The verifyDEKRotationSignature
	// result is captured separately in DEKSignatureErr.
	DEKSignaturePresent bool

	// DEKSignatureErr is the verify result. nil on success or "no header
	// present"; ErrDEKSignatureInvalid on tamper.
	DEKSignatureErr error
}

// pollOnce performs one config-poll round-trip:
//  1. Builds an If-None-Match header from the daemon's current config
//     hash (omitted on first poll where the hash is empty).
//  2. Calls PollBeaconConfig via the generated client.
//  3. Inspects the response:
//     - 304 → no-op; PollResult{HTTPStatus: 304}.
//     - 200 → parse body, update State.configHash, run DEK signature
//     verification if the header is present.
//     - everything else → wrap in an error.
//
// pollOnce does NOT block on backoff — the caller's outer loop handles
// retry pacing.
func (d *Daemon) pollOnce(ctx context.Context) (PollResult, error) {
	res := PollResult{}
	start := time.Now()

	params := &api.PollBeaconConfigParams{}
	if hash := d.State.ConfigHash(); hash != "" {
		etag := fmt.Sprintf(`"%s"`, hash)
		params.IfNoneMatch = &etag
	}

	resp, err := d.APIClient.PollBeaconConfig(ctx, d.Identity.ID, params, d.requestEditors()...)
	if err != nil {
		metrics.PollTotal.WithLabelValues("network_error").Inc()
		metrics.PollDurationSeconds.WithLabelValues("network_error").Observe(time.Since(start).Seconds())
		return res, fmt.Errorf("poll: http: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	res.HTTPStatus = resp.StatusCode

	// Measure clock skew opportunistically from the server's Date header.
	if dateStr := resp.Header.Get("Date"); dateStr != "" {
		if t, perr := http.ParseTime(dateStr); perr == nil {
			d.State.SetClockSkew(time.Since(t).Seconds())
		}
	}

	elapsed := time.Since(start).Seconds()

	switch resp.StatusCode {
	case http.StatusNotModified:
		// 304 → re-stamp lastSeenAt without changing the hash.
		d.State.SetConfigHash(d.State.ConfigHash())
		metrics.PollTotal.WithLabelValues("not_modified").Inc()
		metrics.PollDurationSeconds.WithLabelValues("not_modified").Observe(elapsed)
		return res, nil

	case http.StatusOK:
		// Parse body; surface DEK-signature errors but DON'T treat them
		// as a poll-cycle failure — the daemon should keep polling on its
		// existing config + DEK until the platform side fixes itself.
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) //nolint:forbidigo
		if err != nil {
			return res, fmt.Errorf("poll: read body: %w", err)
		}
		var parsed api.BeaconConfigResponse
		if err := json.Unmarshal(body, &parsed); err != nil {
			return res, fmt.Errorf("poll: decode config: %w", err)
		}

		// DEK rotation signature: if header is present, verify it. M-11
		// fail-closed.
		//
		// IMPORTANT — payload contract (F-4 verified 2026-05-12):
		//
		// The platform's `_build_dek_signature_header` in
		// netbrain/services/api-gateway/src/routes/beacons.py currently
		// signs `data_key_b64=""` (line 1242). This is intentional: the
		// GET /config endpoint does NOT deliver rotated DEK material in
		// its body today — the DEK is only transmitted ONCE during the
		// enrollment ceremony. The X-Beacon-DataKey-Signature header on
		// /config responses is therefore a "DEK version assertion" — the
		// platform vouches for the version, not for a new key value.
		//
		// When the platform wires a real rotation channel that returns
		// `data_key_b64` in the response body, BOTH sides must change
		// in the same PR:
		//   1. Platform: pass the real base64 string at beacons.py:1242.
		//   2. Beacon: parse `parsed.DataKeyB64` and pass it below
		//      instead of the empty string.
		// CONTRIBUTING.md "Shipping a wire-format change" mandates a
		// feature flag for this transition.
		if sig := resp.Header.Get("X-Beacon-DataKey-Signature"); sig != "" {
			res.DEKSignaturePresent = true
			verr := verifyDEKRotationSignature(resp.Header, d.PlatformPubKey.Key, dekRotationPayload{
				BeaconID:       d.Identity.ID.String(),
				DataKeyB64:     "", // see comment above; must match platform's _build_dek_signature_header(data_key_b64=...) exactly.
				DataKeyVersion: d.State.DEKVersion(),
				IssuedAt:       resp.Header.Get("Date"),
			})
			res.DEKSignatureErr = verr
			if verr != nil && !errors.Is(verr, ErrDEKSignatureMissing) {
				d.log("dek_signature_verify_failed", slog.LevelError,
					slog.String("beacon_id", d.Identity.ID.String()),
					slog.String("err", verr.Error()))
				// M-11 fail-closed: this is a P1 security signal.
				metrics.DEKVerifyFailedTotal.Inc()
				// Continue with the old DEK; DON'T swap.
			}
		}

		newHash := parsed.ConfigHash
		oldHash := d.State.ConfigHash()
		res.NewHash = newHash
		res.Modified = newHash != oldHash
		d.State.SetConfigHash(newHash)

		result := "modified"
		if !res.Modified {
			result = "unchanged"
		}
		metrics.PollTotal.WithLabelValues(result).Inc()
		metrics.PollDurationSeconds.WithLabelValues(result).Observe(elapsed)

		if res.Modified {
			d.log("config_applied", slog.LevelInfo,
				slog.String("config_hash", newHash))
		} else {
			d.log("config_unchanged_200", slog.LevelDebug,
				slog.String("config_hash", newHash))
		}
		return res, nil

	default:
		// 4xx/5xx — surface a sanitised body so the daemon can log the
		// server error code without dumping arbitrary content into the log.
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096)) //nolint:forbidigo
		metrics.PollTotal.WithLabelValues("server_error").Inc()
		metrics.PollDurationSeconds.WithLabelValues("server_error").Observe(elapsed)
		return res, fmt.Errorf("poll: HTTP %d: %s", resp.StatusCode, sanitizeBody(body))
	}
}

// requestEditors builds the standard editor chain every daemon RPC uses.
// User-Agent on every request; tests stub these to assert headers.
func (d *Daemon) requestEditors() []api.RequestEditorFn {
	return []api.RequestEditorFn{
		func(_ context.Context, req *http.Request) error {
			req.Header.Set("User-Agent", "netbrain-beacon/"+d.Identity.Version)
			return nil
		},
	}
}

// sanitizeBody trims response bodies to a length safe for log embedding.
// Bounded so a misbehaving server can't flood the logs.
func sanitizeBody(body []byte) string {
	const maxLen = 2048
	s := string(body)
	if len(s) > maxLen {
		return s[:maxLen] + "...[truncated]"
	}
	return s
}
