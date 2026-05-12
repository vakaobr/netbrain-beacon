package daemon

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"github.com/secra/netbrain-beacon/internal/api"
	"github.com/secra/netbrain-beacon/internal/metrics"
)

// heartbeatOnce builds a BeaconHeartbeatRequest from the current daemon
// state (config hash, probe results, evictions, clock skew) and POSTs it
// to /heartbeat. Called by the poll loop on every cycle per ADR-070
// "heartbeat piggybacks on poll".
//
// Errors from the heartbeat send are NOT fatal to the daemon — the next
// poll cycle will retry. We log + continue.
func (d *Daemon) heartbeatOnce(ctx context.Context) error {
	req := d.buildHeartbeatRequest()
	resp, err := d.APIClient.PostBeaconHeartbeat(ctx, d.Identity.ID, req, d.requestEditors()...)
	if err != nil {
		metrics.HeartbeatTotal.WithLabelValues("network_error").Inc()
		return fmt.Errorf("heartbeat: http: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096)) //nolint:forbidigo
		metrics.HeartbeatTotal.WithLabelValues("server_error").Inc()
		return fmt.Errorf("heartbeat: HTTP %d: %s", resp.StatusCode, sanitizeBody(body))
	}

	metrics.HeartbeatTotal.WithLabelValues("success").Inc()
	d.log("heartbeat_ok", slog.LevelDebug, slog.Int("status", resp.StatusCode))
	return nil
}

// buildHeartbeatRequest assembles the BeaconHeartbeatRequest payload.
// Pulled out so tests can assert its fields without the round-trip.
func (d *Daemon) buildHeartbeatRequest() api.BeaconHeartbeatRequest {
	clockSkew := float32(d.State.ClockSkew())
	configHash := d.State.ConfigHash()
	evictions := d.Counters.EvictionsSnapshot()

	// Convert probe.Result map → []DeviceLatencyProbe. The platform side
	// reads this and feeds it into the dedup-election job.
	var probes []api.DeviceLatencyProbe
	if d.Probes != nil {
		snap := d.Probes.Snapshot()
		probes = make([]api.DeviceLatencyProbe, 0, len(snap))
		for _, r := range snap {
			probes = append(probes, api.DeviceLatencyProbe{
				DeviceIp:        r.DeviceIP,
				MedianLatencyMs: r.MedianLatencyMs,
				ProbeCount:      r.ProbeCount,
			})
		}
	}

	// EvictionsTotal is required by the spec (map[string]int).
	// Treat as a snapshot of cumulative counters.
	if evictions == nil {
		evictions = map[string]int{}
	}

	body := api.BeaconHeartbeatRequest{
		BeaconVersion:    d.Identity.Version,
		ClockSkewSeconds: clockSkew,
		EvictionsTotal:   evictions,
	}
	if configHash != "" {
		body.PendingConfigHash = &configHash
	}
	if len(probes) > 0 {
		body.DeviceLatencyProbes = &probes
	}
	return body
}

// Ensure http.Header is referenced — keeps the import alive across edits.
var _ http.Header
