// Package configs is the STUB for the device-config-pull collector.
//
// Full implementation deferred to `add-beacon-configs-collector`. Required:
//
//   - golang.org/x/crypto/ssh for SSH session.
//   - 4 worker pool (per ADR-082 D-6).
//   - "show running-config" command sequence (Cisco IOS/IOS-XR/Junos
//     vendor switches; the netbrain platform's ADR-046 has the canonical
//     vendor matrix).
//   - sha256 dedup cache: if the pulled config matches the last one,
//     don't write to the bucket — the platform side stores configs and
//     re-uploading identical bytes wastes both ends' bandwidth.
//   - Every Dial routed through internal/safedial (M-9).
//   - Records → bbolt `configs` bucket; eviction NEVER touches this
//     bucket per ADR-071, so a long offline period preserves the most
//     recent config snapshot.
//
// The Stub type satisfies the Collector interface so the registry can
// manage its enable/disable state.
package configs

import (
	"context"
	"sync/atomic"
)

// Stub is the placeholder configs collector. Replace in the follow-up.
type Stub struct {
	running atomic.Bool
}

// Start is a no-op. Full implementation will SSH-poll the device list
// on a configurable cadence.
func (s *Stub) Start(_ context.Context) error {
	s.running.Store(true)
	return nil
}

// Close marks the stub stopped.
func (s *Stub) Close() error {
	s.running.Store(false)
	return nil
}

// Running reports whether Start has been called without a matching Close.
func (s *Stub) Running() bool { return s.running.Load() }
