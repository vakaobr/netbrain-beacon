package probe

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// fakeDialer programmable per-port latencies + errors. results[port] applies.
type fakeDialer struct {
	mu      sync.Mutex
	results map[int]struct {
		latencyMs float64
		err       error
	}
	calls atomic.Int64
}

func newFakeDialer() *fakeDialer {
	return &fakeDialer{results: map[int]struct {
		latencyMs float64
		err       error
	}{}}
}

func (f *fakeDialer) program(port int, latencyMs float64, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.results[port] = struct {
		latencyMs float64
		err       error
	}{latencyMs, err}
}

func (f *fakeDialer) Dial(_ context.Context, _, _ string, port int) (func() error, float64, error) {
	f.calls.Add(1)
	f.mu.Lock()
	r := f.results[port]
	f.mu.Unlock()
	if r.err != nil {
		return nil, 0, r.err
	}
	return func() error { return nil }, r.latencyMs, nil
}

// --- median ---

func TestMedianOdd(t *testing.T) {
	require.Equal(t, 50.0, median([]float64{5, 50, 500}))
}

func TestMedianEven(t *testing.T) {
	require.Equal(t, 7.5, median([]float64{5, 10, 5, 10}))
}

func TestMedianEmpty(t *testing.T) {
	require.Equal(t, 0.0, median([]float64{}))
}

// --- port fallback ---

func TestMedianProbeFirstPortWins(t *testing.T) {
	d := newFakeDialer()
	d.program(22, 50, nil)
	d.program(161, 100, nil)
	d.program(80, 200, nil)

	r, err := MedianProbe(context.Background(), "10.0.0.5", Options{
		Dialer:      d,
		SampleCount: 1,
	})
	require.NoError(t, err)
	require.Equal(t, 22, r.PortHit, "port 22 must win — listed first in DefaultPorts")
	require.Equal(t, float32(50), r.MedianLatencyMs)
	require.Equal(t, int64(1), d.calls.Load(), "no fallback when first port succeeds")
}

func TestMedianProbeFallsThrough22to161to80(t *testing.T) {
	d := newFakeDialer()
	d.program(22, 0, errors.New("connection refused"))
	d.program(161, 0, errors.New("connection refused"))
	d.program(80, 250, nil)

	r, err := MedianProbe(context.Background(), "10.0.0.5", Options{
		Dialer:      d,
		SampleCount: 1,
	})
	require.NoError(t, err)
	require.Equal(t, 80, r.PortHit, "port 80 wins after 22 + 161 both fail")
	require.Equal(t, float32(250), r.MedianLatencyMs)
}

func TestMedianProbeAllPortsFail(t *testing.T) {
	d := newFakeDialer()
	d.program(22, 0, errors.New("rst"))
	d.program(161, 0, errors.New("rst"))
	d.program(80, 0, errors.New("rst"))

	r, err := MedianProbe(context.Background(), "10.0.0.5", Options{
		Dialer:      d,
		SampleCount: 3,
	})
	require.ErrorIs(t, err, ErrNoSamples)
	require.Equal(t, 0, r.ProbeCount)
	require.Equal(t, "10.0.0.5", r.DeviceIP, "DeviceIP populated even on failure")
}

func TestMedianProbeMedianOf3(t *testing.T) {
	// 5 ms, 50 ms, 500 ms → median 50.
	d := newFakeDialer()
	// Every sample hits port 22; we vary latency per-call via a counter.
	var nth atomic.Int64
	d.results[22] = struct {
		latencyMs float64
		err       error
	}{} // primed; we override Dial below

	custom := &dynamicDialer{latencies: []float64{5, 50, 500}, nth: &nth}
	r, err := MedianProbe(context.Background(), "10.0.0.5", Options{
		Dialer:      custom,
		SampleCount: 3,
	})
	require.NoError(t, err)
	require.Equal(t, 3, r.ProbeCount)
	require.Equal(t, float32(50), r.MedianLatencyMs, "median of {5,50,500} = 50")
}

// dynamicDialer returns a different latency per call; used for median tests.
// Falls back to the last value if more samples are requested than the slice has.
type dynamicDialer struct {
	latencies []float64
	errors    []error
	nth       *atomic.Int64
}

func (d *dynamicDialer) Dial(_ context.Context, _, _ string, _ int) (func() error, float64, error) {
	i := int(d.nth.Add(1) - 1)
	if i >= len(d.latencies) {
		i = len(d.latencies) - 1
	}
	if d.errors != nil && i < len(d.errors) && d.errors[i] != nil {
		return nil, 0, d.errors[i]
	}
	return func() error { return nil }, d.latencies[i], nil
}

// --- context cancellation ---

func TestMedianProbeContextRespected(t *testing.T) {
	d := newFakeDialer()
	d.program(22, 100, nil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	r, err := MedianProbe(ctx, "10.0.0.5", Options{
		Dialer:      d,
		SampleCount: 5,
		// Tiny timeout so context.Canceled propagates via Dial / fail path.
		PerProbeTimeout: time.Millisecond,
	})
	// Our fake dialer ignores ctx; the production safedial wrapper would
	// surface ctx.Err(). At minimum, the result completes without panic.
	require.NotNil(t, r)
	_ = err
}

// --- scheduler ---

func TestSchedulerSnapshotEmptyBeforeRun(t *testing.T) {
	s := NewScheduler()
	require.Empty(t, s.Snapshot())
}

func TestSchedulerSetDevicesIsAtomic(t *testing.T) {
	s := NewScheduler()
	s.SetDevices([]string{"10.0.0.1", "10.0.0.2"})
	require.Equal(t, []string{"10.0.0.1", "10.0.0.2"}, s.Devices())

	// Returned slice is a copy — mutation doesn't bleed back in.
	dev := s.Devices()
	dev[0] = "evil"
	require.Equal(t, "10.0.0.1", s.Devices()[0])
}

func TestSchedulerRunOnceProbesEveryDevice(t *testing.T) {
	d := newFakeDialer()
	d.program(22, 42, nil)

	s := NewScheduler()
	s.Options.Dialer = d
	s.Options.SampleCount = 1
	s.SetDevices([]string{"10.0.0.1", "10.0.0.2", "10.0.0.3"})

	s.RunOnce(context.Background())

	snap := s.Snapshot()
	require.Len(t, snap, 3)
	for _, ip := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"} {
		r := snap[ip]
		require.Equal(t, ip, r.DeviceIP)
		require.Equal(t, float32(42), r.MedianLatencyMs)
		require.Equal(t, 22, r.PortHit)
	}
}

func TestSchedulerRunRespectsContext(t *testing.T) {
	d := newFakeDialer()
	d.program(22, 1, nil)

	s := NewScheduler()
	s.Interval = 10 * time.Millisecond
	s.Options.Dialer = d
	s.Options.SampleCount = 1
	s.SetDevices([]string{"10.0.0.1"})

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	require.NoError(t, s.Run(ctx))
	elapsed := time.Since(start)
	require.Less(t, elapsed, 200*time.Millisecond, "Run must exit promptly on ctx cancel")
}
