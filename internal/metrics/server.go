package metrics

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// DefaultBindAddr is the loopback-only listener per D-8.
const DefaultBindAddr = "127.0.0.1:9090"

// Server hosts the /metrics endpoint. Build via NewServer; lifecycle is
// Start (non-blocking) + Close (graceful shutdown via http.Server.Shutdown).
type Server struct {
	BindAddr string
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
func (s *Server) Start(_ context.Context) error {
	ln, err := net.Listen("tcp", s.BindAddr)
	if err != nil {
		return fmt.Errorf("metrics: bind %s: %w", s.BindAddr, err)
	}
	s.listener = ln

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
