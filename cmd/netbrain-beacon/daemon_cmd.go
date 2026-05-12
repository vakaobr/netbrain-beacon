package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/velonet/netbrain-beacon/internal/admin/cli"
	"github.com/velonet/netbrain-beacon/internal/api"
	"github.com/velonet/netbrain-beacon/internal/collectors"
	"github.com/velonet/netbrain-beacon/internal/collectors/configs"
	"github.com/velonet/netbrain-beacon/internal/collectors/netflow"
	"github.com/velonet/netbrain-beacon/internal/collectors/sender"
	"github.com/velonet/netbrain-beacon/internal/collectors/snmp"
	bcrypto "github.com/velonet/netbrain-beacon/internal/crypto"
	"github.com/velonet/netbrain-beacon/internal/daemon"
	"github.com/velonet/netbrain-beacon/internal/enroll"
	beaconlog "github.com/velonet/netbrain-beacon/internal/log"
	"github.com/velonet/netbrain-beacon/internal/metrics"
	"github.com/velonet/netbrain-beacon/internal/store"
	"github.com/velonet/netbrain-beacon/internal/transport"
)

// runDaemon implements the `netbrain-beacon daemon` subcommand — the
// long-running mode the production install wires to its service manager
// (systemd / Windows service / Docker entrypoint).
//
// Flags:
//
//	--state-dir <path>        on-disk artifacts directory (default OS-aware)
//	--no-metrics              disable the Prometheus /metrics listener
//	--metrics-bind <addr>     override metrics bind (default 127.0.0.1:9090)
func runDaemon(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("daemon", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		stateDir    = fs.String("state-dir", defaultStateDir(), "directory containing enrollment artifacts")
		noMetrics   = fs.Bool("no-metrics", false, "disable the Prometheus /metrics listener")
		metricsBind = fs.String("metrics-bind", metrics.DefaultBindAddr, "metrics listener address (loopback only)")
	)
	if err := fs.Parse(args); err != nil {
		return 2
	}

	logger := slog.New(beaconlog.NewHandler(slog.NewJSONHandler(stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))
	slog.SetDefault(logger)

	metrics.SetBuildInfo(version, "dev")

	// 1) Load on-disk artifacts from the enrolled state dir.
	meta, err := loadMetadata(*stateDir)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "daemon: %v\n", err)
		_, _ = fmt.Fprintln(stderr, "Hint: run `netbrain-beacon enroll` first.")
		return 1
	}
	d, err := buildDaemon(*stateDir, meta, logger)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "daemon: build: %v\n", err)
		return 1
	}

	// 2) Optional Prometheus listener.
	var metricsSrv *metrics.Server
	if !*noMetrics {
		metricsSrv = metrics.NewServer(*metricsBind)
		// Wire the production slog handler so M-1 non-loopback warnings
		// land in the structured-log stream (not stderr) and trip the
		// platform's Alertmanager rule on `metrics.non_loopback_bind`.
		metricsSrv.Logger = logger
		if err := metricsSrv.Start(context.Background()); err != nil {
			_, _ = fmt.Fprintf(stderr, "daemon: metrics: %v\n", err)
			return 1
		}
		_, _ = fmt.Fprintf(stdout, "daemon: metrics on http://%s/metrics\n", metricsSrv.Addr())
	}

	// 3) Block on SIGINT / SIGTERM; cascade cancel to the daemon.
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	_, _ = fmt.Fprintf(stdout, "daemon: started for beacon_id=%s server=%s\n",
		meta.BeaconID, meta.ServerURL)
	if err := d.Run(ctx); err != nil {
		_, _ = fmt.Fprintf(stderr, "daemon: run: %v\n", err)
	}

	// Drain.
	if metricsSrv != nil {
		shutCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutCancel()
		_ = metricsSrv.Close(shutCtx)
	}
	_, _ = fmt.Fprintln(stdout, "daemon: shutdown complete")
	return 0
}

// loadMetadata reads enrollment-metadata.json and returns the parsed
// struct. Caller treats nil-error + zero BeaconID as "not enrolled".
func loadMetadata(stateDir string) (enroll.Metadata, error) {
	raw, err := os.ReadFile(filepath.Join(stateDir, enroll.MetadataFilename)) //nolint:gosec
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return enroll.Metadata{}, fmt.Errorf("not enrolled (no metadata at %s)", stateDir)
		}
		return enroll.Metadata{}, fmt.Errorf("read metadata: %w", err)
	}
	var m enroll.Metadata
	if err := json.Unmarshal(raw, &m); err != nil {
		return enroll.Metadata{}, fmt.Errorf("decode metadata: %w", err)
	}
	if m.BeaconID.String() == "00000000-0000-0000-0000-000000000000" {
		return m, fmt.Errorf("metadata has zero beacon_id (corrupt — re-enroll)")
	}
	return m, nil
}

// buildDaemon wires every Phase 4–9 component into a single Daemon
// ready to Run. Reads cert/key/DEK/pubkey off disk; constructs the
// mTLS transport client, the OpenAPI client, the bbolt store, the DEK
// holder, the collector registry, and the probe scheduler.
func buildDaemon(stateDir string, meta enroll.Metadata, logger *slog.Logger) (*daemon.Daemon, error) {
	// Cert + key + CA bundle for mTLS.
	certPEM, err := os.ReadFile(filepath.Join(stateDir, enroll.BeaconCertFilename)) //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("read cert: %w", err)
	}
	keyPEM, err := os.ReadFile(filepath.Join(stateDir, enroll.BeaconKeyFilename)) //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("read key: %w", err)
	}
	caPEM, err := os.ReadFile(filepath.Join(stateDir, enroll.PlatformCAFilename)) //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("read ca: %w", err)
	}
	pubPEM, err := os.ReadFile(filepath.Join(stateDir, enroll.PlatformPubKeyFilename)) //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("read pubkey: %w", err)
	}
	dek, err := os.ReadFile(filepath.Join(stateDir, enroll.DEKFilename)) //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("read dek: %w", err)
	}

	tc, err := transport.NewClient(transport.Config{
		CertPEM:       certPEM,
		KeyPEM:        keyPEM,
		PlatformCAPEM: caPEM,
	})
	if err != nil {
		return nil, fmt.Errorf("transport: %w", err)
	}

	// OpenAPI client bound to the mTLS http.Client.
	serverURL := meta.ServerURL
	if serverURL == "" {
		return nil, fmt.Errorf("metadata: server_url is empty")
	}
	if _, perr := url.Parse(serverURL); perr != nil {
		return nil, fmt.Errorf("metadata: bad server_url: %w", perr)
	}
	apiClient, err := api.NewClient(serverURL, api.WithHTTPClient(tc.Current()))
	if err != nil {
		return nil, fmt.Errorf("api client: %w", err)
	}

	// ed25519 platform pubkey.
	pub, err := bcrypto.LoadPublicKeyPEM(pubPEM)
	if err != nil {
		return nil, fmt.Errorf("load pubkey: %w", err)
	}

	// Open the on-disk store. The senders below drain its buckets.
	bboltStore, err := store.Open(stateDir, store.Options{})
	if err != nil {
		// store.ErrCorrupt is informational — Open returns a working
		// fresh-DB Store alongside the error. Anything else is fatal.
		if !errors.Is(err, store.ErrCorrupt) {
			return nil, fmt.Errorf("store open: %w", err)
		}
		logger.Warn("daemon.store_corrupt_recovered", slog.String("err", err.Error()))
	}

	// Register the 3 stub collectors so /collectors lists them and the
	// daemon config-apply loop can flip their enable/disable. syslog gets
	// wired by the future config-apply loop (it's a server.Server, not a
	// Stub).
	registry := collectors.NewRegistry()
	registry.Add("netflow", &netflow.Stub{})
	registry.Add("snmp", &snmp.Stub{})
	registry.Add("configs", &configs.Stub{})

	// DEK holder shared by the sender goroutines + the daemon's
	// DEK-rotation handler.
	deks := collectors.NewDEKHolder(&collectors.DEK{Key: dek, Version: byte(meta.DEKVersion)})

	// One sender per bucket. Each sender owns its bucket; sharing a
	// bucket across senders would race on cursor advance.
	senders := []*sender.Sender{
		{
			Store:     bboltStore,
			Bucket:    store.BucketLogs,
			BeaconID:  meta.BeaconID,
			DEKs:      deks,
			APIClient: apiClient,
		},
		{
			Store:     bboltStore,
			Bucket:    store.BucketFlows,
			BeaconID:  meta.BeaconID,
			DEKs:      deks,
			APIClient: apiClient,
		},
		{
			Store:     bboltStore,
			Bucket:    store.BucketSNMP,
			BeaconID:  meta.BeaconID,
			DEKs:      deks,
			APIClient: apiClient,
		},
		{
			Store:     bboltStore,
			Bucket:    store.BucketConfigs,
			BeaconID:  meta.BeaconID,
			DEKs:      deks,
			APIClient: apiClient,
		},
	}

	d := daemon.NewDaemon(daemon.Daemon{
		APIClient: apiClient,
		Identity: daemon.BeaconIdentity{
			ID:         meta.BeaconID,
			Version:    version,
			EnrolledAt: meta.EnrolledAt,
		},
		State:          daemon.NewState(meta.DEKVersion),
		PlatformPubKey: daemon.PlatformPubKey{Key: pub},
		Registry:       registry,
		DEKs:           deks,
		Senders:        senders,
		Logger:         logger,
	})
	return d, nil
}

// --- status / collectors / logs subcommand dispatchers ---

func runStatus(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	stateDir := fs.String("state-dir", defaultStateDir(), "directory containing enrollment artifacts")
	asJSON := fs.Bool("json", false, "emit machine-readable JSON instead of human-readable text")
	checkServer := fs.Bool("check-server", false, "additionally hit GET /cert-status over mTLS to report server-side cert validity")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	r, err := cli.CollectStatus(*stateDir)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "status: %v\n", err)
		return 1
	}
	if *checkServer {
		// Bound the round-trip; CheckServer returns a partial report on
		// any failure (Reachable=false + Error populated) — never panics.
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		r.ServerCheck = cli.CheckServer(ctx, *stateDir)
	}
	if *asJSON {
		if err := cli.FormatStatusJSON(stdout, r); err != nil {
			_, _ = fmt.Fprintf(stderr, "status: %v\n", err)
			return 1
		}
		return 0
	}
	cli.FormatStatusHuman(stdout, r)
	return 0
}

func runCollectors(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("collectors", flag.ContinueOnError)
	fs.SetOutput(stderr)
	asJSON := fs.Bool("json", false, "machine-readable JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	// Without a running daemon, we can't read the live registry — the
	// CLI subcommand here returns a friendly "daemon not running"
	// message + lists the 4 known collector names.
	rep := &cli.CollectorsReport{
		Collectors: []cli.CollectorEntry{
			{Name: "configs", Running: false},
			{Name: "netflow", Running: false},
			{Name: "snmp", Running: false},
			{Name: "syslog", Running: false},
		},
	}
	if *asJSON {
		_ = cli.FormatCollectorsJSON(stdout, rep)
		return 0
	}
	_, _ = fmt.Fprintln(stdout, "Note: live state requires running daemon; this command reports configured collector names.")
	cli.FormatCollectorsHuman(stdout, rep)
	return 0
}

func runLogs(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("logs", flag.ContinueOnError)
	fs.SetOutput(stderr)
	logPath := fs.String("path", "", "path to log file (default: stderr — pipe externally if needed)")
	follow := fs.Bool("follow", false, "tail the log as new lines arrive")
	maxLines := fs.Int("n", 0, "limit to last N lines (0 = unlimited)")
	grep := fs.String("grep", "", "substring filter (case-insensitive)")
	level := fs.String("level", "", "slog level filter (e.g. INFO, ERROR)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *logPath == "" {
		_, _ = fmt.Fprintln(stderr, "logs: --path is required (the daemon writes to stderr by default; configure file output in your service manager)")
		return 2
	}
	// Wire SIGINT/SIGTERM into Tail's ctx so --follow returns cleanly
	// when the operator hits Ctrl-C instead of slamming the process.
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := cli.Tail(ctx, stdout, cli.TailOptions{
		Path:     *logPath,
		Follow:   *follow,
		MaxLines: *maxLines,
		Grep:     *grep,
		Level:    *level,
	}); err != nil {
		_, _ = fmt.Fprintf(stderr, "logs: %v\n", err)
		return 1
	}
	return 0
}
