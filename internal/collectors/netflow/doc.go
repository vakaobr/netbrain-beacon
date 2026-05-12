// Package netflow is the STUB for the NetFlow collector.
//
// Full implementation deferred to a follow-up issue (`add-beacon-netflow-collector`).
// What's needed:
//
//   - UDP 2055 listener via github.com/netsampler/goflow2 (per ADR-082 D-9).
//   - Worker pool of 4 (D-6).
//   - Pure-Go nfcapd binary writer (~300 LOC; the netbrain platform
//     expects the multipart upload to contain bytes formatted as
//     `flows-<uuid>.nfcapd`).
//   - Records go to bbolt `flows` bucket; sender flushes via
//     internal/collectors/sender (already implemented).
//
// The Stub type implements the Collector interface from
// internal/collectors/registry.go so the daemon's enable/disable
// scaffolding works against it today — toggling `collectors.netflow.enabled`
// in BeaconConfig flips the stub's state but doesn't open any ports.
package netflow

import (
	"context"
	"sync/atomic"
)

// Stub is the placeholder NetFlow collector. Replace with the real
// implementation in the follow-up issue.
type Stub struct {
	running atomic.Bool
}

// Start records that the collector was started but takes no socket
// action. Always nil-returns; full implementation will open UDP 2055.
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
