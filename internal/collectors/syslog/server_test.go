package syslog

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/velonet/netbrain-beacon/internal/store"
)

func newTestServer(t *testing.T, cfg Config) (*Server, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	s, err := store.Open(dir, store.Options{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	cfg.Store = s
	srv, err := NewServer(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Close() })
	return srv, s
}

func TestNewServerRequiresStore(t *testing.T) {
	_, err := NewServer(Config{})
	require.ErrorIs(t, err, ErrNoStore)
}

func TestSubmitRawPersistsRFC3164(t *testing.T) {
	srv, s := newTestServer(t, Config{Workers: 1, QueueDepth: 16})
	require.NoError(t, srv.Start(context.Background()))

	// Classic RFC 3164 BSD syslog line.
	msg := []byte("<13>Apr 11 22:14:15 myhost myapp: hello world")
	require.True(t, srv.SubmitRaw(msg))

	// Wait for the worker to drain.
	require.Eventually(t, func() bool {
		return srv.Stats().Persisted == 1
	}, 2*time.Second, 10*time.Millisecond)

	require.NoError(t, srv.Close())

	count, _ := s.Count(store.BucketLogs)
	require.Equal(t, 1, count)

	// Inspect the stored record — must be valid JSON.
	require.NoError(t, s.Iter(store.BucketLogs, func(_, val []byte) error {
		var m map[string]any
		require.NoError(t, json.Unmarshal(val, &m))
		require.Equal(t, "rfc3164", m["format"])
		require.Contains(t, m, "hostname")
		return nil
	}))
}

func TestSubmitRawPersistsRFC5424(t *testing.T) {
	srv, s := newTestServer(t, Config{Workers: 1, QueueDepth: 16})
	require.NoError(t, srv.Start(context.Background()))

	// RFC 5424 — VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID SP STRUCTURED-DATA SP MSG.
	msg := []byte(`<165>1 2026-05-12T22:14:15.003Z myhost myapp 1234 ID47 - hello structured`)
	require.True(t, srv.SubmitRaw(msg))
	require.Eventually(t, func() bool {
		return srv.Stats().Persisted == 1
	}, 2*time.Second, 10*time.Millisecond)
	require.NoError(t, srv.Close())

	count, _ := s.Count(store.BucketLogs)
	require.Equal(t, 1, count)
	require.NoError(t, s.Iter(store.BucketLogs, func(_, val []byte) error {
		var m map[string]any
		require.NoError(t, json.Unmarshal(val, &m))
		require.Equal(t, "rfc5424", m["format"])
		return nil
	}))
}

func TestSubmitRawHandlesGarbage(t *testing.T) {
	// Neither parser can make sense of pure garbage — parse-fail counter
	// goes up, but the worker doesn't crash.
	srv, s := newTestServer(t, Config{Workers: 1, QueueDepth: 16})
	require.NoError(t, srv.Start(context.Background()))
	require.True(t, srv.SubmitRaw([]byte("this is not syslog at all")))
	require.Eventually(t, func() bool {
		return srv.Stats().ParseFailed == 1
	}, 2*time.Second, 10*time.Millisecond)
	require.NoError(t, srv.Close())

	count, _ := s.Count(store.BucketLogs)
	require.Equal(t, 0, count, "parse-failed messages must NOT land in the bucket")
}

func TestUDPListenerReceivesDatagram(t *testing.T) {
	// Pick an ephemeral port to avoid colliding with the host's syslog.
	srv, s := newTestServer(t, Config{
		UDPListen:  "127.0.0.1:0",
		Workers:    1,
		QueueDepth: 4,
	})
	require.NoError(t, srv.Start(context.Background()))
	require.NotNil(t, srv.udpConn)

	// The listener bound on :0 picked some port — find it.
	addr := srv.udpConn.LocalAddr().(*net.UDPAddr)
	conn, err := net.DialUDP("udp", nil, addr)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	_, err = conn.Write([]byte("<13>May 12 22:14:15 hostA app: hi"))
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		return srv.Stats().Persisted >= 1
	}, 2*time.Second, 10*time.Millisecond, "datagram must be parsed + persisted")

	require.NoError(t, srv.Close())
	count, _ := s.Count(store.BucketLogs)
	require.GreaterOrEqual(t, count, 1)
}

func TestTCPListenerReceivesLine(t *testing.T) {
	srv, _ := newTestServer(t, Config{
		TCPListen:  "127.0.0.1:0",
		Workers:    1,
		QueueDepth: 4,
	})
	require.NoError(t, srv.Start(context.Background()))
	require.NotNil(t, srv.tcpLn)

	addr := srv.tcpLn.Addr().String()
	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	_, err = fmt.Fprintf(conn, "<13>May 12 22:14:15 hostA app: hi\n")
	require.NoError(t, err)
	_ = conn.Close()

	require.Eventually(t, func() bool {
		return srv.Stats().Persisted >= 1
	}, 2*time.Second, 10*time.Millisecond)
	require.NoError(t, srv.Close())
}

func TestStatsReflectCounters(t *testing.T) {
	srv, _ := newTestServer(t, Config{Workers: 1, QueueDepth: 4})
	require.NoError(t, srv.Start(context.Background()))
	srv.SubmitRaw([]byte("<13>May 12 22:14:15 h a: ok"))
	srv.SubmitRaw([]byte("garbage"))
	require.Eventually(t, func() bool {
		st := srv.Stats()
		return st.Received >= 2 && (st.Persisted+st.ParseFailed) >= 2
	}, 2*time.Second, 10*time.Millisecond)
	require.NoError(t, srv.Close())

	st := srv.Stats()
	require.GreaterOrEqual(t, st.Received, int64(2))
	require.Equal(t, 1, st.WorkerCount)
	require.Equal(t, 4, st.QueueCap)
}

func TestCloseIdempotent(t *testing.T) {
	srv, _ := newTestServer(t, Config{Workers: 1, QueueDepth: 4})
	require.NoError(t, srv.Start(context.Background()))
	require.NoError(t, srv.Close())
	require.NoError(t, srv.Close(), "second Close must be no-op")
}

// --- SY-1: TCP per-line cap (CWE-770) ---

// TestTCPLineCapDropsOversizedLine asserts that a TCP connection sending
// a line longer than MaxLineBytes is dropped (Stats().OversizedDropped
// ticks; Stats().Persisted does not). Without the fix, bufio.Reader's
// ReadBytes would have grown unbounded waiting for '\n'.
func TestTCPLineCapDropsOversizedLine(t *testing.T) {
	srv, _ := newTestServer(t, Config{
		Workers:      1,
		QueueDepth:   16,
		TCPListen:    "127.0.0.1:0",
		MaxLineBytes: 64,
	})
	require.NoError(t, srv.Start(context.Background()))

	addr := srv.tcpLn.Addr().String()
	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	// 200 bytes of 'A' — well past the 64-byte MaxLineBytes — followed
	// by a newline that the scanner would never reach if buffer growth
	// were unbounded. We send it as ONE write so the scanner sees the
	// overrun before any newline.
	payload := make([]byte, 200)
	for i := range payload {
		payload[i] = 'A'
	}
	payload = append(payload, '\n')
	_, err = conn.Write(payload)
	require.NoError(t, err)
	_ = conn.Close()

	require.Eventually(t, func() bool {
		return srv.Stats().OversizedDropped == 1
	}, 2*time.Second, 10*time.Millisecond,
		"line past MaxLineBytes must increment OversizedDropped (SY-1)")
	require.Equal(t, int64(0), srv.Stats().Persisted,
		"oversized line must NOT be persisted")
}

// TestTCPNormalLineStillWorks regression-guards SY-1: a normal-sized
// line still gets parsed + persisted.
func TestTCPNormalLineStillWorks(t *testing.T) {
	srv, _ := newTestServer(t, Config{
		Workers:    1,
		QueueDepth: 16,
		TCPListen:  "127.0.0.1:0",
	})
	require.NoError(t, srv.Start(context.Background()))

	conn, err := net.Dial("tcp", srv.tcpLn.Addr().String())
	require.NoError(t, err)
	_, err = conn.Write([]byte("<13>Apr 11 22:14:15 host app: ok\n"))
	require.NoError(t, err)
	_ = conn.Close()

	require.Eventually(t, func() bool {
		return srv.Stats().Persisted == 1
	}, 2*time.Second, 10*time.Millisecond)
}

// --- SY-2: TCP MaxTCPConnections cap (CWE-770) ---

// TestTCPConnectionsCappedAtMaxTCPConnections asserts that once
// MaxTCPConnections connections are open, the next accept is closed
// immediately and Stats().ConnsRejected increments.
func TestTCPConnectionsCappedAtMaxTCPConnections(t *testing.T) {
	srv, _ := newTestServer(t, Config{
		Workers:           1,
		QueueDepth:        16,
		TCPListen:         "127.0.0.1:0",
		MaxTCPConnections: 2,
	})
	require.NoError(t, srv.Start(context.Background()))
	addr := srv.tcpLn.Addr().String()

	// Open MaxTCPConnections = 2 concurrent connections + hold them.
	held := make([]net.Conn, 0, 2)
	for i := 0; i < 2; i++ {
		c, err := net.Dial("tcp", addr)
		require.NoError(t, err)
		held = append(held, c)
	}
	t.Cleanup(func() {
		for _, c := range held {
			_ = c.Close()
		}
	})
	// Tiny pause so the listener loop processes both accepts before we
	// try the third (semaphore acquisition is fast but not instantaneous).
	time.Sleep(50 * time.Millisecond)

	// 3rd connection: server accepts it then immediately closes
	// (semaphore full → default branch closes the new conn).
	c3, err := net.Dial("tcp", addr)
	require.NoError(t, err, "Dial succeeds — kernel TCP handshake completes before our app-level reject")
	_ = c3.Close()

	require.Eventually(t, func() bool {
		return srv.Stats().ConnsRejected >= 1
	}, 2*time.Second, 10*time.Millisecond,
		"3rd connection past MaxTCPConnections=2 must increment ConnsRejected (SY-2)")
}

// --- SY-3: worker panic-recover (CWE-754) ---

// TestWorkerSurvivesPanic asserts that a panic inside the worker (here
// triggered by injecting a parser stub that panics on a sentinel input)
// does not crash the pool. The worker counter ticks and the next
// message still gets processed.
//
// We test this via the panicOnSentinelStore wrapper which panics inside
// store.Put — the most realistic injection point for a worker-side
// panic (parser bugs surface deeper, but the recovery mechanism is the
// same).
func TestWorkerSurvivesPanic(t *testing.T) {
	srv, realStore := newTestServer(t, Config{
		Workers:    1,
		QueueDepth: 16,
	})
	// Inject a fake putter that panics on the first call, then delegates.
	pp := &panickyPutter{inner: realStore}
	srv.SetPutterForTest(pp)
	require.NoError(t, srv.Start(context.Background()))

	// First message panics inside processOne → recover ticks workerPanics.
	require.True(t, srv.SubmitRaw([]byte("<13>Apr 11 22:14:15 host app: trigger-panic")))

	require.Eventually(t, func() bool {
		return srv.Stats().WorkerPanics == 1
	}, 2*time.Second, 10*time.Millisecond,
		"panic inside processOne must be recovered (SY-3) and counted")

	// Second message: still processed normally — the worker survived.
	pp.disable()
	require.True(t, srv.SubmitRaw([]byte("<13>Apr 11 22:14:15 host app: ok")))
	require.Eventually(t, func() bool {
		return srv.Stats().Persisted == 1
	}, 2*time.Second, 10*time.Millisecond,
		"worker pool must keep processing after a recovered panic")
}

// panickyPutter satisfies the syslog package's internal putter interface
// (via SetPutterForTest). Panics on Put until disable() flips it back to
// delegating to the real Store.
type panickyPutter struct {
	inner    *store.Store
	disabled bool
}

func (p *panickyPutter) disable() { p.disabled = true }
func (p *panickyPutter) Put(bucket store.Bucket, payload []byte) ([]byte, error) {
	if !p.disabled {
		panic("simulated worker panic")
	}
	return p.inner.Put(bucket, payload)
}

// --- helpers ---

// Ensure imports stay live (used elsewhere; this is belt-and-braces).
var _ = filepath.Join
var _ = fmt.Sprintf
