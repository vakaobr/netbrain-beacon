package metrics

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// DefaultBindAddr is the loopback-only listener per D-8.
const DefaultBindAddr = "127.0.0.1:9090"

// Server hosts the /metrics endpoint. Build via NewServer; lifecycle is
// Start (non-blocking) + Close (graceful shutdown via http.Server.Shutdown).
type Server struct {
	BindAddr string
	// Logger receives the M-1 non-loopback warning at Start time. Defaults
	// to slog.Default() when nil.
	Logger   *slog.Logger
	srv      *http.Server
	listener net.Listener
}

// NewServer returns a Server bound to addr (DefaultBindAddr if empty).
// The Server is not yet listening — call Start.
func NewServer(addr string) *Server {
	if addr == "" {
		addr = DefaultBindAddr
	}
	return &Server{BindAddr: addr}
}

// Start opens the listener and spawns a goroutine running the HTTP
// server. Returns the error from net.Listen if the bind fails;
// otherwise nil. Errors from Serve (post-listener-open) are logged via
// the caller's recovery path — Start doesn't block.
//
// Security: CWE-200 — emits a WARN log when the bind address is
// non-loopback. /metrics + /healthz are unauthenticated; exposing them
// to a LAN with no TLS+auth in front is an information-disclosure
// surface (beacon ID, version, internal counters). M-1 hardening,
// /security audit 07a §1.10.
func (s *Server) Start(_ context.Context) error {
	ln, err := net.Listen("tcp", s.BindAddr)
	if err != nil {
		return fmt.Errorf("metrics: bind %s: %w", s.BindAddr, err)
	}
	s.listener = ln

	if !isLoopbackBind(s.BindAddr) {
		log := s.Logger
		if log == nil {
			log = slog.Default()
		}
		log.Warn("metrics.non_loopback_bind",
			slog.String("addr", s.BindAddr),
			slog.String("risk", "unauthenticated_metrics_exposed"),
			slog.String("guidance",
				"front with TLS+auth (nginx, traefik) or restrict via firewall before exposing publicly"))
	}

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	s.srv = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	go func() {
		_ = s.srv.Serve(ln)
	}()
	return nil
}

// Addr returns the actual bound address (useful when BindAddr ends in
// `:0` and the kernel picks a port).
func (s *Server) Addr() string {
	if s.listener == nil {
		return s.BindAddr
	}
	return s.listener.Addr().String()
}

// isLoopbackBind reports whether addr binds to a loopback interface
// only (127.0.0.0/8 for v4, ::1 for v6). A bind to 0.0.0.0 / [::] / a
// public IP or hostname returns false. Used by Start to gate the M-1
// non-loopback warning.
//
// The host portion may be a literal IP, a hostname, an empty string
// (rare — defaults to 0.0.0.0), or an IPv6 literal in brackets. The
// helper handles all four.
func isLoopbackBind(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// Couldn't split — treat as non-loopback (fail-open warning).
		return false
	}
	switch host {
	case "":
		// Empty host with explicit port defaults to ALL interfaces.
		return false
	case "localhost":
		return true
	}
	// Strip an IPv6 zone identifier (e.g., "fe80::1%eth0") that
	// net.ParseIP would reject. The zone doesn't affect loopback-ness.
	if i := strings.IndexByte(host, '%'); i >= 0 {
		host = host[:i]
	}
	ip := net.ParseIP(host)
	if ip == nil {
		// Hostname (not "localhost") — treat as non-loopback. An
		// operator who points DNS at 127.0.0.1 still gets the warning,
		// which is the conservative behavior.
		return false
	}
	return ip.IsLoopback()
}

// Close stops the HTTP server gracefully. Returns nil if Server was
// never Started; otherwise propagates Shutdown's error.
func (s *Server) Close(ctx context.Context) error {
	if s.srv == nil {
		return nil
	}
	if err := s.srv.Shutdown(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
