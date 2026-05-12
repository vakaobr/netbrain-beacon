package probe

import (
	"context"
	"sync"
	"time"
)

// DefaultInterval is the scheduler's tick rate per ADR-072: 5 minutes
// between probe cycles for a given device. The platform-side election
// job runs at the same cadence, so latency staleness ≤ 1 cycle.
const DefaultInterval = 5 * time.Minute

// Scheduler runs MedianProbe for a configured device list on a fixed
// cadence and exposes the most recent results to the heartbeat goroutine.
// Safe for concurrent reads via Snapshot; writes serialise through the
// internal goroutine.
type Scheduler struct {
	// Interval is the per-device probe cadence. Defaults to DefaultInterval.
	Interval time.Duration

	// Options is the per-call MedianProbe configuration. Zero values
	// inherit the package defaults.
	Options Options

	// Devices is the list to probe. Updated atomically via SetDevices
	// (under mu); the scheduler reads a snapshot at each tick.
	mu      sync.RWMutex
	devices []string
	results map[string]Result
}

// NewScheduler returns a Scheduler ready to Run. Devices and Options are
// optional — set them via SetDevices / direct field assignment before
// the first tick.
func NewScheduler() *Scheduler {
	return &Scheduler{
		Interval: DefaultInterval,
		results:  map[string]Result{},
	}
}

// SetDevices replaces the probe target list atomically. Subsequent ticks
// use the new list. Devices removed from the list have their results
// preserved in the in-memory map (the heartbeat goroutine clears them
// when appropriate).
func (s *Scheduler) SetDevices(deviceIPs []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(deviceIPs))
	copy(out, deviceIPs)
	s.devices = out
}

// Devices returns the current probe target list. Copy returned — callers
// can mutate freely.
func (s *Scheduler) Devices() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, len(s.devices))
	copy(out, s.devices)
	return out
}

// Snapshot returns a copy of the current results map. Heartbeat
// invocations call this once per cycle.
func (s *Scheduler) Snapshot() map[string]Result {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]Result, len(s.results))
	for k, v := range s.results {
		out[k] = v
	}
	return out
}

// Run executes probe cycles on every Interval tick until ctx is done.
// Returns nil on graceful ctx-cancel; surfaces any unexpected error
// otherwise.
//
// The function is intentionally cheap to start: the first tick fires
// after Interval, not immediately. This avoids a thundering-herd at
// daemon startup where the cert-rotation, config-poll, and probe loops
// all hit the network simultaneously.
func (s *Scheduler) Run(ctx context.Context) error {
	if s.Interval == 0 {
		s.Interval = DefaultInterval
	}
	ticker := time.NewTicker(s.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			s.runOneCycle(ctx)
		}
	}
}

// RunOnce probes every current device once and updates results. Used by
// tests + the cold-start path that wants an immediate probe.
func (s *Scheduler) RunOnce(ctx context.Context) {
	s.runOneCycle(ctx)
}

// runOneCycle iterates the current device list and probes each. Failed
// probes are recorded with ProbeCount=0 so the heartbeat can report
// "we tried, it didn't respond" rather than silently omitting the device.
func (s *Scheduler) runOneCycle(ctx context.Context) {
	devices := s.Devices()
	for _, ip := range devices {
		if ctx.Err() != nil {
			return
		}
		result, _ := MedianProbe(ctx, ip, s.Options)
		// MedianProbe returns ErrNoSamples on total failure but populates
		// result.DeviceIP + CapturedAt; we keep the record so the heartbeat
		// can include zeros for devices that didn't respond.
		s.mu.Lock()
		s.results[ip] = result
		s.mu.Unlock()
	}
}
