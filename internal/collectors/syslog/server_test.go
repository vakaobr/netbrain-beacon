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

	"github.com/secra/netbrain-beacon/internal/store"
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

// --- helpers ---

// Ensure imports stay live (used elsewhere; this is belt-and-braces).
var _ = filepath.Join
