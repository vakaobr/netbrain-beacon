// Package syslog implements the beacon's syslog ingestion collector.
//
// Listens on both UDP and TCP 514 (configurable). Each accepted line is
// parsed via leodido/go-syslog v4 (auto-detects RFC3164 vs RFC5424), then
// handed to a worker pool that batches into NDJSON and writes to the
// bbolt `logs` bucket. The Phase 8 daemon's sender drains the bucket on
// its tick and ships batches to /api/v1/beacons/{id}/data/logs.
//
// # Drop-on-full back-pressure (D-6)
//
// The listener writes to a bounded channel (default 1000) drained by N
// workers (default 8). When the channel is full, the listener
// increments a `dropped` counter and discards the message rather than
// blocking. This preserves liveness at the customer edge.
package syslog

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	rfc3164 "github.com/leodido/go-syslog/v4/rfc3164"
	rfc5424 "github.com/leodido/go-syslog/v4/rfc5424"

	"github.com/vakaobr/netbrain-beacon/internal/store"
)

// Defaults match ADR-082's D-6 pool sizing for syslog.
const (
	DefaultWorkers      = 8
	DefaultQueueDepth   = 1000
	DefaultUDPListen    = ":514"
	DefaultTCPListen    = ":514"
	DefaultReadDeadline = 30 * time.Second

	// DefaultMaxLineBytes caps a single syslog line on a TCP connection.
	// 256 KiB comfortably covers extreme RFC 5424 messages while bounding
	// per-connection memory growth. Security: CWE-770 — prevents the
	// unbounded buffer-growth DoS in /security audit SY-1 (07a §1.7).
	DefaultMaxLineBytes = 256 * 1024

	// DefaultMaxTCPConnections caps concurrent TCP listener accepts.
	// 256 covers a realistic multi-device customer LAN; beyond that, an
	// attacker (or misconfigured device storm) would otherwise exhaust
	// goroutines + buffers. Security: CWE-770 — closes /security audit
	// SY-2 (07a §1.7).
	DefaultMaxTCPConnections = 256
)

// Config bundles the listener tunables. Zero values inherit the defaults.
type Config struct {
	// UDPListen is the address:port for the UDP listener. Empty disables
	// UDP ingest.
	UDPListen string
	// TCPListen is the address:port for the TCP listener. Empty disables
	// TCP ingest.
	TCPListen string
	// Workers is the size of the worker pool. Zero → DefaultWorkers.
	Workers int
	// QueueDepth bounds the listener → worker channel. Zero → DefaultQueueDepth.
	QueueDepth int
	// MaxLineBytes caps the per-line read size on each TCP connection.
	// Zero → DefaultMaxLineBytes. A connection sending a longer line is
	// dropped and Stats().OversizedDropped increments. SY-1 hardening.
	MaxLineBytes int
	// MaxTCPConnections caps concurrent TCP listener accepts. Zero →
	// DefaultMaxTCPConnections. Beyond this cap, a new accept is closed
	// immediately and Stats().ConnsRejected increments. SY-2 hardening.
	MaxTCPConnections int
	// Store is the bbolt store the workers write to. Required.
	Store *store.Store
	// Logger is the structured logger for collector events. Nil → slog.Default().
	Logger *slog.Logger
}

// putter is the minimal Store interface the worker needs. Lets tests
// inject a fake Put that returns an error or panics, without depending
// on the concrete *store.Store. *store.Store satisfies this interface
// naturally — no production change.
type putter interface {
	Put(bucket store.Bucket, payload []byte) ([]byte, error)
}

// Server is the running syslog collector. Build via NewServer; lifecycle
// methods are Start (idempotent) + Close (waits for in-flight messages
// to drain).
type Server struct {
	cfg Config
	log *slog.Logger

	// put is the Store handle the worker actually calls. Defaults to
	// cfg.Store at NewServer time; tests can swap it via SetPutterForTest.
	put putter

	queue chan []byte

	udpConn  *net.UDPConn
	tcpLn    net.Listener
	wg       sync.WaitGroup
	stopOnce sync.Once
	closed   atomic.Bool

	// Counters surfaced via Stats(); reset never (cumulative for the
	// daemon's lifetime).
	rxTotal       atomic.Int64
	parseFails    atomic.Int64
	droppedFull   atomic.Int64
	persisted     atomic.Int64
	persistFail   atomic.Int64
	oversizedDrop atomic.Int64 // SY-1: TCP lines past MaxLineBytes
	connsRejected atomic.Int64 // SY-2: TCP accepts past MaxTCPConnections
	workerPanics  atomic.Int64 // SY-3: panics recovered in worker
}

// Errors surfaced by NewServer / Start.
var (
	// ErrNoStore is returned when Config.Store is nil — the server has
	// nowhere to put parsed messages.
	ErrNoStore = errors.New("syslog: Config.Store is required")

	// ErrListenAlreadyStarted is returned when Start is called twice on
	// the same Server. Tests can use this to assert idempotence.
	ErrListenAlreadyStarted = errors.New("syslog: already started")
)

// Stats is the operator-facing snapshot of the server's lifetime counters.
type Stats struct {
	Received         int64
	Persisted        int64
	ParseFailed      int64
	PersistFailed    int64
	DroppedFull      int64
	OversizedDropped int64 // SY-1
	ConnsRejected    int64 // SY-2
	WorkerPanics     int64 // SY-3
	WorkerCount      int
	QueueCap         int
	QueueDepthNow    int
	MaxLineBytes     int
	MaxTCPConns      int
}

// NewServer constructs a Server with defaults applied. Doesn't start any
// listeners — call Start.
func NewServer(cfg Config) (*Server, error) {
	if cfg.Store == nil {
		return nil, ErrNoStore
	}
	if cfg.Workers == 0 {
		cfg.Workers = DefaultWorkers
	}
	if cfg.QueueDepth == 0 {
		cfg.QueueDepth = DefaultQueueDepth
	}
	if cfg.MaxLineBytes == 0 {
		cfg.MaxLineBytes = DefaultMaxLineBytes
	}
	if cfg.MaxTCPConnections == 0 {
		cfg.MaxTCPConnections = DefaultMaxTCPConnections
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Server{
		cfg:   cfg,
		log:   cfg.Logger,
		put:   cfg.Store,
		queue: make(chan []byte, cfg.QueueDepth),
	}, nil
}

// SetPutterForTest replaces the store handle the worker uses. Test-only;
// production callers leave the default (Config.Store).
func (s *Server) SetPutterForTest(p putter) { s.put = p }

// Start opens the configured listeners + spawns the worker pool. Returns
// without blocking; the listeners run in their own goroutines and exit
// when Close is called or ctx is cancelled.
func (s *Server) Start(ctx context.Context) error {
	if s.closed.Load() {
		return errors.New("syslog: server already closed")
	}

	// Spawn workers first so any messages buffered by the listeners' first
	// reads have somewhere to land.
	for i := 0; i < s.cfg.Workers; i++ {
		s.wg.Add(1)
		go s.worker(ctx)
	}

	if s.cfg.UDPListen != "" {
		addr, err := net.ResolveUDPAddr("udp", s.cfg.UDPListen)
		if err != nil {
			return fmt.Errorf("syslog: resolve udp: %w", err)
		}
		conn, err := net.ListenUDP("udp", addr)
		if err != nil {
			return fmt.Errorf("syslog: listen udp: %w", err)
		}
		s.udpConn = conn
		s.wg.Add(1)
		go s.udpLoop(ctx)
	}

	if s.cfg.TCPListen != "" {
		ln, err := net.Listen("tcp", s.cfg.TCPListen)
		if err != nil {
			return fmt.Errorf("syslog: listen tcp: %w", err)
		}
		s.tcpLn = ln
		s.wg.Add(1)
		go s.tcpLoop(ctx)
	}

	return nil
}

// Close shuts down the listeners + drains the queue. Idempotent.
func (s *Server) Close() error {
	s.stopOnce.Do(func() {
		s.closed.Store(true)
		if s.udpConn != nil {
			_ = s.udpConn.Close()
		}
		if s.tcpLn != nil {
			_ = s.tcpLn.Close()
		}
		close(s.queue)
	})
	// Wait for listeners + workers to drain.
	s.wg.Wait()
	return nil
}

// Stats returns a snapshot of the server's counters.
func (s *Server) Stats() Stats {
	return Stats{
		Received:         s.rxTotal.Load(),
		Persisted:        s.persisted.Load(),
		ParseFailed:      s.parseFails.Load(),
		PersistFailed:    s.persistFail.Load(),
		DroppedFull:      s.droppedFull.Load(),
		OversizedDropped: s.oversizedDrop.Load(),
		ConnsRejected:    s.connsRejected.Load(),
		WorkerPanics:     s.workerPanics.Load(),
		WorkerCount:      s.cfg.Workers,
		QueueCap:         s.cfg.QueueDepth,
		QueueDepthNow:    len(s.queue),
		MaxLineBytes:     s.cfg.MaxLineBytes,
		MaxTCPConns:      s.cfg.MaxTCPConnections,
	}
}

// SubmitRaw makes a raw message available to the worker pool. Exposed so
// the TCP loop can hand off per-line; also used by tests that exercise
// the parse + persist path without spinning up a real socket.
//
// Returns false if the queue was full and the message was dropped.
func (s *Server) SubmitRaw(raw []byte) bool {
	s.rxTotal.Add(1)
	// Defensive copy — caller's buffer may be reused.
	cp := make([]byte, len(raw))
	copy(cp, raw)
	select {
	case s.queue <- cp:
		return true
	default:
		s.droppedFull.Add(1)
		return false
	}
}

// udpLoop reads datagrams from the UDP socket and submits them. Each
// datagram is one syslog message (per RFC 3164 framing).
func (s *Server) udpLoop(ctx context.Context) {
	defer s.wg.Done()
	buf := make([]byte, 64*1024)
	for {
		if ctx.Err() != nil {
			return
		}
		_ = s.udpConn.SetReadDeadline(time.Now().Add(DefaultReadDeadline))
		n, _, err := s.udpConn.ReadFromUDP(buf)
		if err != nil {
			if isClosed(err) {
				return
			}
			if isTimeout(err) {
				continue
			}
			s.log.Warn("syslog.udp_read_err", slog.String("err", err.Error()))
			continue
		}
		s.SubmitRaw(buf[:n])
	}
}

// tcpLoop accepts TCP connections. Each connection is a stream of
// line-delimited (or octet-counted) syslog messages.
//
// Security: CWE-770 — accepts past MaxTCPConnections are closed
// immediately so the listener cannot be goroutine-exhausted by a flood
// of concurrent connections (SY-2 hardening, /security audit 07a §1.7).
func (s *Server) tcpLoop(ctx context.Context) {
	defer s.wg.Done()
	sem := make(chan struct{}, s.cfg.MaxTCPConnections)
	for {
		if ctx.Err() != nil {
			return
		}
		conn, err := s.tcpLn.Accept()
		if err != nil {
			if isClosed(err) {
				return
			}
			s.log.Warn("syslog.tcp_accept_err", slog.String("err", err.Error()))
			continue
		}
		select {
		case sem <- struct{}{}:
			s.wg.Add(1)
			go func(c net.Conn) {
				defer func() { <-sem }()
				s.handleTCPConn(ctx, c)
			}(conn)
		default:
			// At-cap: refuse the new connection rather than queue. The
			// goroutine + buffer growth past the cap is the threat, not
			// queue-depth latency.
			s.connsRejected.Add(1)
			_ = conn.Close()
		}
	}
}

// handleTCPConn reads lines from one TCP connection. Supports RFC 5425
// line-delimited framing (most common); octet-counting framing not
// supported in v1 (devices that use it are rare and the operator can
// configure a syslog relay).
//
// Security: CWE-770 — uses bufio.Scanner with a bounded buffer instead
// of bufio.Reader.ReadBytes, which would grow unbounded waiting for a
// '\n' that may never arrive. Lines past MaxLineBytes are dropped and
// counted (SY-1 hardening, /security audit 07a §1.7).
func (s *Server) handleTCPConn(ctx context.Context, conn net.Conn) {
	defer s.wg.Done()
	defer func() { _ = conn.Close() }()

	sc := bufio.NewScanner(conn)
	// Initial buffer: min(64 KiB, MaxLineBytes). Clamping to MaxLineBytes
	// is essential — Scanner only fires ErrTooLong when the buffer fills
	// AND its length is already >= maxTokenSize. If initial > max, the
	// scanner would find '\n' inside a slack buffer before any growth
	// check, bypassing the cap (caught by TestTCPLineCapDropsOversizedLine).
	initial := 64 * 1024
	if s.cfg.MaxLineBytes < initial {
		initial = s.cfg.MaxLineBytes
	}
	sc.Buffer(make([]byte, initial), s.cfg.MaxLineBytes)

	for {
		if ctx.Err() != nil {
			return
		}
		_ = conn.SetReadDeadline(time.Now().Add(DefaultReadDeadline))
		if !sc.Scan() {
			break
		}
		// sc.Bytes() points into the scanner's internal buffer — copy
		// inside SubmitRaw so the next Scan call doesn't clobber it.
		s.SubmitRaw(sc.Bytes())
	}
	if err := sc.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			s.oversizedDrop.Add(1)
			s.log.Warn("syslog.tcp_line_too_long",
				slog.Int("max_line_bytes", s.cfg.MaxLineBytes),
				slog.String("remote", conn.RemoteAddr().String()))
			return
		}
		if isTimeout(err) || isClosed(err) {
			return
		}
		// EOF is normal connection close (Scanner masks it as nil); any
		// remaining error is a transport error we don't need to log
		// (deadline-driven, peer reset, etc.).
	}
}

// worker pulls raw messages off the queue, parses + persists each.
//
// Security: CWE-754 — per-message panic-recover so a parser-bug panic
// (in leodido's RFC parsers or json.Marshal) cannot terminate the whole
// pool. Recovered panic is logged + counted and the worker continues
// (SY-3 hardening, /security audit 07a §1.7).
func (s *Server) worker(_ context.Context) {
	defer s.wg.Done()
	for raw := range s.queue {
		s.processOne(raw)
	}
}

// processOne is the per-message body extracted from worker so the panic
// recover scope is tight to ONE message — a panicking input doesn't
// taint other in-flight processing.
func (s *Server) processOne(raw []byte) {
	defer func() {
		if r := recover(); r != nil {
			s.workerPanics.Add(1)
			s.log.Error("syslog.worker_panic",
				slog.Any("recover", r),
				slog.Int("raw_len", len(raw)))
		}
	}()

	parsed := parseSyslog(raw)
	if parsed == nil {
		s.parseFails.Add(1)
		return
	}
	blob, err := json.Marshal(parsed)
	if err != nil {
		s.parseFails.Add(1)
		return
	}
	if _, err := s.put.Put(store.BucketLogs, blob); err != nil {
		s.persistFail.Add(1)
		s.log.Warn("syslog.persist_err", slog.String("err", err.Error()))
		return
	}
	s.persisted.Add(1)
}

// parseSyslog tries RFC 5424 first, falls back to RFC 3164. Returns nil
// if neither parser produces a message. Both leodido parsers are
// allocation-cheap; trying both in fallback order is the standard
// approach for mixed-vendor environments where some devices emit 3164
// (Cisco, Juniper older versions) and others emit 5424 (Linux rsyslog,
// Junos newer).
func parseSyslog(raw []byte) map[string]any {
	if msg := tryParse5424(raw); msg != nil {
		return msg
	}
	if msg := tryParse3164(raw); msg != nil {
		return msg
	}
	return nil
}

func tryParse5424(raw []byte) map[string]any {
	p := rfc5424.NewParser()
	m, err := p.Parse(raw)
	if err != nil || m == nil {
		return nil
	}
	// The leodido message types don't survive json.Marshal directly with
	// the right shape (some fields are interface types); convert to a
	// flat map.
	return flattenMessage(m, "rfc5424")
}

func tryParse3164(raw []byte) map[string]any {
	p := rfc3164.NewParser()
	m, err := p.Parse(raw)
	if err != nil || m == nil {
		return nil
	}
	return flattenMessage(m, "rfc3164")
}

// flattenMessage converts a leodido SyslogMessage into a flat JSON-safe
// map. Adds a `format` field so the platform-side parser knows which
// shape it received. Reads fields off the embedded *syslog.Base struct
// (Hostname, Appname, Message are *string fields, not interface methods).
func flattenMessage(m any, format string) map[string]any {
	out := map[string]any{"format": format}
	var base *baseFields
	switch msg := m.(type) {
	case *rfc3164.SyslogMessage:
		base = &baseFields{
			Hostname: msg.Hostname,
			Appname:  msg.Appname,
			Message:  msg.Message,
			Severity: msg.Severity,
			Facility: msg.Facility,
		}
	case *rfc5424.SyslogMessage:
		base = &baseFields{
			Hostname: msg.Hostname,
			Appname:  msg.Appname,
			Message:  msg.Message,
			Severity: msg.Severity,
			Facility: msg.Facility,
		}
	default:
		return out
	}
	if base.Hostname != nil {
		out["hostname"] = *base.Hostname
	}
	if base.Appname != nil {
		out["appname"] = *base.Appname
	}
	if base.Message != nil {
		out["msg"] = *base.Message
	}
	if base.Severity != nil {
		out["severity"] = int(*base.Severity)
	}
	if base.Facility != nil {
		out["facility"] = int(*base.Facility)
	}
	return out
}

// baseFields is the cross-format projection. Avoids reflecting twice on
// the concrete leodido types in flattenMessage's downstream property
// extraction.
type baseFields struct {
	Hostname *string
	Appname  *string
	Message  *string
	Severity *uint8
	Facility *uint8
}

func isClosed(err error) bool {
	return err != nil && errors.Is(err, net.ErrClosed)
}

func isTimeout(err error) bool {
	var ne net.Error
	if errors.As(err, &ne) {
		return ne.Timeout()
	}
	return false
}
