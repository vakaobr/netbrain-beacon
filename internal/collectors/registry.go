package collectors

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

// Collector is the lifecycle interface every collector implements. The
// registry uses it to drive enable/disable based on the BeaconConfig
// from the platform.
//
// Start is expected to return quickly (open sockets / spawn goroutines).
// Long-running listeners run in the collector's own goroutines.
// Close MUST be idempotent — the registry may call it during shutdown
// even if Start was never invoked.
type Collector interface {
	Start(ctx context.Context) error
	Close() error
	Running() bool
}

// Errors surfaced by the registry.
var (
	// ErrUnknownCollector is returned when Enable / Disable references a
	// collector name not in the registry.
	ErrUnknownCollector = errors.New("collectors: unknown collector")
)

// Registry tracks the four configured collectors + their lifecycle
// state. The daemon's poll-loop apply phase (Phase 9 follow-up) calls
// Enable/Disable based on the platform-pushed config.
type Registry struct {
	mu         sync.RWMutex
	collectors map[string]Collector
}

// NewRegistry returns an empty Registry. Callers Add their collectors
// in any order at daemon-startup.
func NewRegistry() *Registry {
	return &Registry{collectors: map[string]Collector{}}
}

// Add registers a collector by name. Re-adding the same name replaces
// the existing entry (callers SHOULD Close the previous first).
func (r *Registry) Add(name string, c Collector) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.collectors[name] = c
}

// Get returns the collector with the given name + a found bool.
func (r *Registry) Get(name string) (Collector, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.collectors[name]
	return c, ok
}

// Names returns all registered collector names. Order is map-iteration
// (unspecified); callers should sort if presentation matters.
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.collectors))
	for k := range r.collectors {
		out = append(out, k)
	}
	return out
}

// Enable starts the named collector if it isn't already running. No-op
// if Running() is already true.
func (r *Registry) Enable(ctx context.Context, name string) error {
	r.mu.RLock()
	c, ok := r.collectors[name]
	r.mu.RUnlock()
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnknownCollector, name)
	}
	if c.Running() {
		return nil
	}
	return c.Start(ctx)
}

// Disable stops the named collector. No-op if not Running.
func (r *Registry) Disable(name string) error {
	r.mu.RLock()
	c, ok := r.collectors[name]
	r.mu.RUnlock()
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnknownCollector, name)
	}
	if !c.Running() {
		return nil
	}
	return c.Close()
}

// CloseAll stops every registered collector. Used during daemon
// shutdown. Returns the first error encountered; subsequent failures
// are logged at the caller's discretion (we don't aggregate to keep
// the interface simple).
func (r *Registry) CloseAll() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	var firstErr error
	for _, c := range r.collectors {
		if err := c.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// State is the operator-facing snapshot of which collectors are running.
type State struct {
	Name    string
	Running bool
}

// States returns one State per registered collector.
func (r *Registry) States() []State {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]State, 0, len(r.collectors))
	for name, c := range r.collectors {
		out = append(out, State{Name: name, Running: c.Running()})
	}
	return out
}
