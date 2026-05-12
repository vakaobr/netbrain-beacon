package daemon

import (
	"context"
	"errors"
	"log/slog"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/secra/netbrain-beacon/internal/api"
	"github.com/secra/netbrain-beacon/internal/probe"
)

// Defaults for the daemon's tunables. Production values can be overridden
// via Config; zero values inherit these.
const (
	DefaultPollInterval    = 60 * time.Second
	DefaultPollJitter      = 10 * time.Second
	DefaultShutdownTimeout = 10 * time.Second
	DefaultBackoffInitial  = 1 * time.Second
	DefaultBackoffMax      = 30 * time.Second
	DefaultBackoffFactor   = 2.0
)

// Config bundles the daemon's runtime knobs. Zero values are populated
// from the Default* constants by NewDaemon.
type Config struct {
	PollInterval    time.Duration
	PollJitter      time.Duration
	ShutdownTimeout time.Duration
	BackoffInitial  time.Duration
	BackoffMax      time.Duration
	BackoffFactor   float64
}

// Daemon is the long-running coordinator: poll → heartbeat → probe
// cycles. Constructed once at boot; Run blocks until ctx-cancel and then
// drains within ShutdownTimeout.
type Daemon struct {
	Config Config

	// APIClient is the generated client bound to the mTLS http.Client
	// (transport.NewClient output via transport.Client.Current()).
	APIClient api.ClientInterface

	// Identity is the immutable beacon identity (UUID, hostname, version).
	Identity BeaconIdentity

	// State is the mutable runtime state (config hash, dek version, etc.).
	State *State

	// Counters tracks eviction + send aggregates surfaced via heartbeat.
	Counters *Counters

	// Probes is the device-probe scheduler. nil means probes are disabled
	// (test mode, or pre-Phase-9 stub).
	Probes *probe.Scheduler

	// PlatformPubKey is the ed25519 trust anchor for DEK rotation
	// signatures. Loaded from platform-pubkey.pem at boot.
	PlatformPubKey PlatformPubKey

	// Logger is the structured logger used for daemon events. Wraps the
	// H-3 redactor in production; tests pass slog.Default() or a buffer.
	Logger *slog.Logger
}

// NewDaemon populates Config defaults + returns a Daemon ready to Run.
// Validation is minimal here — the caller is expected to wire everything
// from on-disk artifacts, and a missing field surfaces at Run time as a
// nil-pointer panic which is the right developer-facing failure mode.
func NewDaemon(d Daemon) *Daemon {
	if d.Config.PollInterval == 0 {
		d.Config.PollInterval = DefaultPollInterval
	}
	if d.Config.PollJitter == 0 {
		d.Config.PollJitter = DefaultPollJitter
	}
	if d.Config.ShutdownTimeout == 0 {
		d.Config.ShutdownTimeout = DefaultShutdownTimeout
	}
	if d.Config.BackoffInitial == 0 {
		d.Config.BackoffInitial = DefaultBackoffInitial
	}
	if d.Config.BackoffMax == 0 {
		d.Config.BackoffMax = DefaultBackoffMax
	}
	if d.Config.BackoffFactor == 0 {
		d.Config.BackoffFactor = DefaultBackoffFactor
	}
	if d.Logger == nil {
		d.Logger = slog.Default()
	}
	if d.Counters == nil {
		d.Counters = NewCounters()
	}
	return &d
}

// Run starts the poll loop + (if configured) the probe scheduler. Blocks
// until ctx is cancelled, then waits up to ShutdownTimeout for goroutines
// to drain.
//
// Returns nil on graceful ctx-cancel; never panics. Per-call errors
// (network failures, server 5xx) are logged at WARN and never surface
// to the caller — the daemon's job is to keep retrying.
func (d *Daemon) Run(ctx context.Context) error {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup

	// Poll loop.
	wg.Add(1)
	go func() {
		defer wg.Done()
		d.pollLoop(runCtx)
	}()

	// Probe scheduler (optional — nil in tests + pre-Phase-9 stubs).
	if d.Probes != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = d.Probes.Run(runCtx)
		}()
	}

	// Wait for ctx cancel.
	<-ctx.Done()
	cancel()

	// Drain — bounded by ShutdownTimeout.
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		d.log("shutdown_clean", slog.LevelInfo)
	case <-time.After(d.Config.ShutdownTimeout):
		d.log("shutdown_timeout", slog.LevelWarn,
			slog.Duration("timeout", d.Config.ShutdownTimeout))
	}
	return nil
}

// pollLoop is the main 60s ± 10s ticker. Each iteration runs pollOnce +
// heartbeatOnce; failures fall through to exponential backoff capped at
// BackoffMax.
//
// The loop fires the FIRST iteration after Config.PollInterval, not
// immediately — avoids the thundering-herd cold-start where every
// goroutine hits the network at boot.
func (d *Daemon) pollLoop(ctx context.Context) {
	delay := d.Config.PollInterval
	backoff := d.Config.BackoffInitial

	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(jitter(delay, d.Config.PollJitter)):
		}

		_, err := d.pollOnce(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return
			}
			d.log("poll_failed", slog.LevelWarn, slog.String("err", err.Error()))
			delay = backoff
			backoff = nextBackoff(backoff, d.Config.BackoffMax, d.Config.BackoffFactor)
			continue
		}

		// Successful poll → reset backoff, send heartbeat, return to normal cadence.
		backoff = d.Config.BackoffInitial
		delay = d.Config.PollInterval

		if err := d.heartbeatOnce(ctx); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return
			}
			d.log("heartbeat_failed", slog.LevelWarn, slog.String("err", err.Error()))
		}
	}
}

// jitter applies a ± jitter offset to base. Returns a positive duration.
// Uses math/rand/v2 (acceptable for non-crypto jitter — forbidigo allows
// it in non-crypto paths).
func jitter(base, j time.Duration) time.Duration {
	if j == 0 {
		return base
	}
	// uniformly distributed in [base-j, base+j].
	offset := time.Duration(rand.Int64N(int64(2*j))) - j //nolint:gosec // non-crypto jitter
	out := base + offset
	if out < time.Millisecond {
		out = time.Millisecond
	}
	return out
}

// nextBackoff computes the next backoff delay, capped at maxBackoff.
func nextBackoff(current, maxBackoff time.Duration, factor float64) time.Duration {
	next := time.Duration(float64(current) * factor)
	if next > maxBackoff {
		return maxBackoff
	}
	return next
}

// log is the structured-log shortcut. Wraps slog so call sites read
// "event verb-noun" without repeating slog.Default() everywhere.
func (d *Daemon) log(event string, level slog.Level, args ...any) {
	d.Logger.LogAttrs(context.Background(), level, "daemon."+event, toAttrs(args)...)
}

// toAttrs accepts a variadic that's either []slog.Attr already or a
// flat alternating key/value list. slog.LogAttrs is faster than Log
// because it avoids the runtime reflection that slog.Log uses on
// alternating-arg lists.
func toAttrs(args []any) []slog.Attr {
	out := make([]slog.Attr, 0, len(args))
	for _, a := range args {
		if attr, ok := a.(slog.Attr); ok {
			out = append(out, attr)
		}
	}
	return out
}
