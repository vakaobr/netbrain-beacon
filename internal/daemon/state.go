package daemon

import (
	"crypto/ed25519"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/velonet/netbrain-beacon/internal/metrics"
)

// State holds the runtime fields the daemon mutates across goroutines.
// All access goes through the mutex so the poll loop, heartbeat sender,
// and probe scheduler see a coherent snapshot.
//
// Fields are intentionally minimal — anything that doesn't change at
// runtime (BeaconID, PlatformPubKey) lives on the Daemon struct directly.
type State struct {
	mu sync.RWMutex

	// configHash is the SHA-256 of the last applied BeaconConfig. The
	// poll loop sends this as If-None-Match so the server can short-
	// circuit with 304 when nothing changed.
	configHash string

	// lastSeenAt is the timestamp of the last successful poll. The
	// heartbeat includes it so the platform's BeaconHeartbeatAbsent
	// alert (P2) has a freshness signal.
	lastSeenAt time.Time

	// clockSkewSeconds is the difference between the platform's
	// Date header and the local clock at the time of the last poll.
	// Reported in the heartbeat for operator diagnostics.
	clockSkewSeconds float64

	// dekVersion is the active DEK version. Bumped only when a DEK
	// rotation signature has been verified (M-11 fail-closed). NOT
	// mutated on signature failure.
	dekVersion int
}

// NewState returns a State with the given initial values from
// enrollment-metadata.json.
func NewState(initialDEKVersion int) *State {
	metrics.DEKVersion.Set(float64(initialDEKVersion))
	return &State{dekVersion: initialDEKVersion}
}

// ConfigHash returns the last-applied config hash. Empty string before
// the first poll succeeds.
func (s *State) ConfigHash() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.configHash
}

// SetConfigHash updates the config-hash baseline. Called by the poll
// loop after a successful 200 response.
func (s *State) SetConfigHash(h string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.configHash = h
	s.lastSeenAt = time.Now().UTC()
}

// LastSeenAt returns the timestamp of the last successful poll.
func (s *State) LastSeenAt() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastSeenAt
}

// SetClockSkew records the clock-skew measured at poll time.
func (s *State) SetClockSkew(seconds float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clockSkewSeconds = seconds
}

// ClockSkew returns the most recently measured skew.
func (s *State) ClockSkew() float64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.clockSkewSeconds
}

// DEKVersion returns the currently-trusted DEK version. Used by the
// data-plane senders (Phase 9) to label outbound batches with the right
// version.
func (s *State) DEKVersion() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.dekVersion
}

// SetDEKVersion updates the active DEK version. Called by the DEK
// rotation handler ONLY after a successful signature verification.
// Also updates the beacon_dek_version Prometheus gauge so operator
// dashboards reflect the rotation immediately.
func (s *State) SetDEKVersion(v int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dekVersion = v
	metrics.DEKVersion.Set(float64(v))
}

// Counters tracks operator-visible aggregate numbers the heartbeat
// surfaces. All increments go through Inc methods — bare field access
// would race with the heartbeat reader.
type Counters struct {
	mu              sync.Mutex
	evictionsByType map[string]int
}

// NewCounters returns a Counters with zero values.
func NewCounters() *Counters {
	return &Counters{evictionsByType: map[string]int{}}
}

// IncEviction records an eviction-by-type event. The heartbeat reads
// this snapshot and zeros nothing — totals are cumulative for the
// daemon's lifetime.
func (c *Counters) IncEviction(bucket string, n int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.evictionsByType[bucket] += n
}

// EvictionsSnapshot returns a copy of the current eviction counters.
func (c *Counters) EvictionsSnapshot() map[string]int {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string]int, len(c.evictionsByType))
	for k, v := range c.evictionsByType {
		out[k] = v
	}
	return out
}

// PlatformPubKey is the ed25519 trust anchor for X-Beacon-DataKey-Signature
// (M-11). Pinned at enrollment time and never mutated thereafter — held on
// the Daemon struct, NOT in State.
type PlatformPubKey struct {
	Key ed25519.PublicKey
}

// BeaconIdentity bundles immutable identity fields the daemon references.
type BeaconIdentity struct {
	ID         uuid.UUID
	HostName   string
	Version    string
	EnrolledAt time.Time
}
