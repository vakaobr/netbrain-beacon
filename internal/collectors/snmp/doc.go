// Package snmp is the STUB for the SNMP poller collector.
//
// Full implementation deferred to `add-beacon-snmp-collector`. Required:
//
//   - github.com/gosnmp/gosnmp v1.37+ for v2c + v3 USM polling.
//   - 16 worker pool (per ADR-082 D-6).
//   - Per-device OID list from the BeaconConfig.
//   - Every Dial routed through internal/safedial (M-9 — devices
//     accidentally configured with link-local / loopback IPs MUST be
//     refused at dial-time, not at the gosnmp library layer).
//   - Records → bbolt `snmp` bucket as gzip-NDJSON.
//
// The Stub type satisfies the same interface as the syslog Server so
// the registry can manage it during the daemon's lifecycle.
package snmp

import (
	"context"
	"sync/atomic"
)

// Stub is the placeholder SNMP collector. Replace in the follow-up.
type Stub struct {
	running atomic.Bool
}

// Start is a no-op. Full implementation will spawn the gosnmp poller
// goroutines + worker pool.
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
