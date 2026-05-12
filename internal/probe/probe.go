package probe

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/secra/netbrain-beacon/internal/safedial"
)

// DefaultPorts is the probe order from ADR-072: SSH first (most common
// management interface), then SNMP, then HTTP. First successful connect
// wins.
var DefaultPorts = []int{22, 161, 80}

// DefaultSampleCount is the per-cycle median-of-N. ADR-072 mandates 3.
const DefaultSampleCount = 3

// DefaultPerProbeTimeout bounds each individual TCP connect attempt.
// A device that doesn't respond in 2s is treated as unreachable on that
// port and the probe falls through to the next port.
const DefaultPerProbeTimeout = 2 * time.Second

// Errors surfaced by Probe.
var (
	// ErrAllPortsFailed is returned when every port in DefaultPorts (or
	// the caller-supplied list) failed to connect within the per-probe
	// timeout. The wrapped error carries the last attempt's error.
	ErrAllPortsFailed = errors.New("probe: all ports failed to connect")

	// ErrNoSamples is returned when SampleCount is set but every sample
	// failed. Distinct from ErrAllPortsFailed (which is per-call); this
	// is per-cycle.
	ErrNoSamples = errors.New("probe: no successful samples")
)

// Dialer is the connect interface probe depends on. Defaults to
// safedial.DefaultDialer; tests substitute a mock to control timing.
type Dialer interface {
	Dial(ctx context.Context, network, host string, port int) (closeFn func() error, latencyMs float64, err error)
}

// safedialAdapter wraps internal/safedial.Dial in the local Dialer
// interface. Kept private so callers don't see safedial.Conn leaking
// through the probe API.
type safedialAdapter struct{}

// Dial implements Dialer by routing through safedial and timing the
// connect.
func (safedialAdapter) Dial(ctx context.Context, network, host string, port int) (func() error, float64, error) {
	start := time.Now()
	conn, err := safedial.Dial(ctx, network, host, port)
	if err != nil {
		return nil, 0, err
	}
	latency := float64(time.Since(start).Microseconds()) / 1000.0 // ms with µs precision
	return conn.Close, latency, nil
}

// DefaultDialer is the production dialer — routes through safedial.Dial.
var DefaultDialer Dialer = safedialAdapter{}

// Result is a single probe-cycle outcome for one device.
type Result struct {
	// DeviceIP is the input passed to MedianProbe.
	DeviceIP string
	// MedianLatencyMs is the median of all successful sample latencies.
	// 0 if no samples succeeded.
	MedianLatencyMs float32
	// ProbeCount is the number of successful samples (out of SampleCount
	// attempts).
	ProbeCount int
	// PortHit is the first port that responded. 0 if no samples succeeded.
	PortHit int
	// CapturedAt is the wall-clock time when the cycle finished. The
	// heartbeat upload uses this for freshness assertions.
	CapturedAt time.Time
}

// Options configures one MedianProbe call.
type Options struct {
	// Ports overrides the default port-fallback order. Empty → DefaultPorts.
	Ports []int
	// SampleCount overrides DefaultSampleCount. Zero → 3.
	SampleCount int
	// PerProbeTimeout overrides DefaultPerProbeTimeout. Zero → 2s.
	PerProbeTimeout time.Duration
	// Dialer overrides DefaultDialer (test injection). Nil → safedial.
	Dialer Dialer
}

// MedianProbe runs SampleCount connect attempts to deviceIP across the
// Ports list (first success per sample) and returns the median latency
// of the successful samples.
//
// Behaviour:
//   - For each sample, walks the Ports list in order. First port that
//     connects within PerProbeTimeout wins; the conn is closed immediately.
//   - If every port fails, the sample is recorded as a failure.
//   - At the end, the median of successful samples becomes the result.
//   - If zero samples succeeded, returns ErrNoSamples.
//
// Per-sample timeout: each sample's connect attempts share a single context
// derived from PerProbeTimeout. A device that responds on port 22 within
// 50 ms but is dead on 161/80 still uses port 22's latency for the sample
// (we don't measure ports beyond the first success).
func MedianProbe(ctx context.Context, deviceIP string, opts Options) (Result, error) {
	ports := opts.Ports
	if len(ports) == 0 {
		ports = DefaultPorts
	}
	samples := opts.SampleCount
	if samples == 0 {
		samples = DefaultSampleCount
	}
	timeout := opts.PerProbeTimeout
	if timeout == 0 {
		timeout = DefaultPerProbeTimeout
	}
	dialer := opts.Dialer
	if dialer == nil {
		dialer = DefaultDialer
	}

	latencies := make([]float64, 0, samples)
	portHit := 0
	var lastErr error

	for i := 0; i < samples; i++ {
		latency, port, err := singleSample(ctx, dialer, deviceIP, ports, timeout)
		if err != nil {
			lastErr = err
			continue
		}
		latencies = append(latencies, latency)
		if portHit == 0 {
			portHit = port
		}
	}

	if len(latencies) == 0 {
		return Result{
			DeviceIP:   deviceIP,
			CapturedAt: time.Now().UTC(),
		}, fmt.Errorf("%w: %w", ErrNoSamples, lastErr)
	}

	return Result{
		DeviceIP:        deviceIP,
		MedianLatencyMs: float32(median(latencies)),
		ProbeCount:      len(latencies),
		PortHit:         portHit,
		CapturedAt:      time.Now().UTC(),
	}, nil
}

// singleSample is one probe attempt: walk the port list, first success
// wins. Returns the latency in ms and which port hit, or an error if
// every port failed.
func singleSample(ctx context.Context, dialer Dialer, deviceIP string, ports []int, perPortTimeout time.Duration) (float64, int, error) {
	var lastErr error
	for _, port := range ports {
		portCtx, cancel := context.WithTimeout(ctx, perPortTimeout)
		closer, latency, err := dialer.Dial(portCtx, "tcp", deviceIP, port)
		cancel()
		if err != nil {
			lastErr = err
			continue
		}
		// We don't care about the conn body — just the SYN/SYN-ACK time.
		if closer != nil {
			_ = closer()
		}
		return latency, port, nil
	}
	return 0, 0, fmt.Errorf("%w: last=%w", ErrAllPortsFailed, lastErr)
}

// median computes the median of a slice. Mutates the input by sorting it
// — callers should pass a fresh slice. Empty input returns 0.
func median(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sort.Float64s(values)
	mid := len(values) / 2
	if len(values)%2 == 0 {
		return (values[mid-1] + values[mid]) / 2
	}
	return values[mid]
}
