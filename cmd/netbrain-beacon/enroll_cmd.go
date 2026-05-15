package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/vakaobr/netbrain-beacon/internal/api"
	"github.com/vakaobr/netbrain-beacon/internal/enroll"
	"github.com/vakaobr/netbrain-beacon/internal/mesh"
)

// runEnroll implements the `netbrain-beacon enroll ...` subcommand.
//
// Flags:
//
//	--bundle <b64>       base64-encoded signed enrollment bundle (mutually
//	                     exclusive with --bundle-file; PREFER --bundle-file
//	                     in production — see Security note below)
//	--bundle-file <path> path to a file holding the base64 bundle. Reading
//	                     from disk avoids leaking the bootstrap token into
//	                     `ps`, shell history, audit logs (CWE-214, S-1).
//	--server-url <url>   (required) https://<platform-host>:8443
//	--state-dir <path>   override default state-dir (see defaultStateDir)
//	--force              overwrite an existing enrollment in state-dir
//	--allow-unsigned     accept an unsigned bundle (DEV ONLY)
//
// Security: CWE-214 — the bootstrap token is a short-lived secret
// (24h expiry, one-time-use). Passing it via --bundle puts the token
// in `ps auxw`, shell history, and audit logs. Use --bundle-file with
// a file mode of 0600 in production.
func runEnroll(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		bundleB64        = fs.String("bundle", "", "base64-encoded enrollment bundle (use --bundle-file in production to avoid leaking via ps)")
		bundleFile       = fs.String("bundle-file", "", "path to a file holding the base64-encoded bundle (recommended over --bundle)")
		serverURL        = fs.String("server-url", "", "platform URL, e.g. https://platform.example.com:8443 (required)")
		stateDir         = fs.String("state-dir", defaultStateDir(), "directory to persist enrollment artifacts")
		force            = fs.Bool("force", false, "overwrite existing enrollment in state-dir")
		allowUnsigned    = fs.Bool("allow-unsigned", false, "accept unsigned bundles (DEV ONLY)")
		hostnameOverride = fs.String("hostname", "", "override the hostname sent in beacon_metadata (default: os.Hostname)")
		skipMesh         = fs.Bool("skip-mesh", false, "skip Cloudflare WARP mesh enrollment even when the bundle carries credentials")
		warpCLIPath      = fs.String("warp-cli", "", "override the warp-cli binary path (default: looked up on PATH)")
		warpPollSeconds  = fs.Int("warp-poll-seconds", 60, "how long to wait for the WARP daemon to reach the connected state")
	)

	if err := fs.Parse(args); err != nil {
		// flag package already printed usage on its own writer.
		return 2
	}

	// Mutually-exclusive bundle source: exactly ONE of --bundle / --bundle-file
	// must be supplied. The CLI loads the bundle string into bundleStr.
	bundleStr, srcErr := readBundleArg(*bundleB64, *bundleFile, stderr)
	if srcErr != nil {
		_, _ = fmt.Fprintf(stderr, "enroll: %v\n", srcErr)
		fs.Usage()
		return 2
	}
	if *serverURL == "" {
		_, _ = fmt.Fprintln(stderr, "enroll: --server-url is required")
		fs.Usage()
		return 2
	}

	// 1) Parse + verify the bundle (v2 only — v1 bundles are rejected
	// with enroll.ErrBundleVersionUnsupported per ADR-007).
	bundle, err := enroll.ParseBundle(bundleStr, *allowUnsigned)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "enroll: bundle rejected: %v\n", err)
		return 1
	}

	// 1b) Cloudflare WARP mesh enrollment, when the bundle carries it.
	// This MUST land before the HTTP /enroll round-trip because the
	// platform's overlay-IP server cert is only reachable from inside
	// the WARP mesh in mesh-on deployments.
	if bundle.MeshEnabled() && !*skipMesh {
		if rc := runMeshEnroll(stdout, stderr, bundle, *warpCLIPath, *warpPollSeconds); rc != 0 {
			return rc
		}
	} else if bundle.MeshEnabled() && *skipMesh {
		_, _ = fmt.Fprintln(stdout, "enroll: --skip-mesh — skipping WARP enrollment; the HTTP /enroll round-trip MUST be reachable without the mesh")
	}

	// 2) Idempotency: refuse double-enroll unless --force.
	if !*force {
		if checkErr := enroll.CheckNotEnrolled(*stateDir); checkErr != nil {
			if errors.Is(checkErr, enroll.ErrAlreadyEnrolled) {
				_, _ = fmt.Fprintf(stderr, "enroll: %v\n", checkErr)
				_, _ = fmt.Fprintln(stderr, "       pass --force to overwrite")
				return 1
			}
			_, _ = fmt.Fprintf(stderr, "enroll: idempotency check failed: %v\n", checkErr)
			return 1
		}
	}

	// 3) Metadata: hostname + OS + version.
	hostname := *hostnameOverride
	if hostname == "" {
		if h, hostErr := os.Hostname(); hostErr == nil {
			hostname = h
		} else {
			hostname = "unknown-host"
		}
	}
	metadata := api.BeaconMetadata{
		Hostname: hostname,
		Os:       beaconOS(),
		Version:  version,
	}

	// 4) Round-trip /enroll.
	result, _, err := enroll.Enroll(context.Background(), enroll.Input{
		Bundle:    bundle,
		ServerURL: *serverURL,
		Metadata:  metadata,
	})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "enroll: %v\n", err)
		return 1
	}

	// 5) Persist atomically.
	art := &enroll.Artifacts{
		BeaconCertPEM:     result.BeaconCertPEM,
		BeaconKeyPEM:      result.BeaconKeyPEM,
		DEK:               result.DEK,
		PlatformCAPEM:     result.PlatformCAPEM,
		PlatformPubKeyPEM: result.PlatformPubKeyPEM,
		Metadata:          enroll.MetadataFromArtifacts(result, *serverURL),
	}
	if persistErr := enroll.Persist(*stateDir, art); persistErr != nil {
		_, _ = fmt.Fprintf(stderr, "enroll: persist failed: %v\n", persistErr)
		return 1
	}

	_, _ = fmt.Fprintf(stdout, "enrolled: beacon_id=%s dek_version=%d expires_at=%s\nstate=%s\n",
		result.BeaconID, result.DEKVersion, bundle.ExpiresAt.Format("2006-01-02T15:04:05Z"), *stateDir)
	return 0
}

// defaultStateDir returns the OS-appropriate state directory for the
// beacon's enrolled artifacts. The CLI flag --state-dir always wins; this
// is just the sensible default when the operator doesn't supply one.
func defaultStateDir() string {
	switch runtime.GOOS {
	case "windows":
		// On Windows the conventional location is %PROGRAMDATA%\netbrain-beacon
		if pd := os.Getenv("PROGRAMDATA"); pd != "" {
			return filepath.Join(pd, "netbrain-beacon")
		}
		return filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Local", "netbrain-beacon")
	default:
		return "/var/lib/netbrain-beacon"
	}
}

// readBundleArg resolves the bundle source flags. Exactly one of
// --bundle or --bundle-file must be set. When loading from a file, the
// helper emits a stderr warning if the file's mode allows other users
// to read it (mode & 0o077 != 0) — defense-in-depth so an operator who
// chmod 0644 their bundle file gets a visible heads-up.
//
// Security (S-1, CWE-214): the file path avoids leaking the bootstrap
// token to `ps`, shell history, and audit logs. We don't enforce mode
// 0600 hard (Windows ACLs make a unix-bit check unreliable there); we
// warn but proceed.
func readBundleArg(bundle, bundleFile string, stderr io.Writer) (string, error) {
	if bundle == "" && bundleFile == "" {
		return "", errors.New("--bundle or --bundle-file is required")
	}
	if bundle != "" && bundleFile != "" {
		return "", errors.New("--bundle and --bundle-file are mutually exclusive; use one or the other")
	}
	if bundle != "" {
		// Best-effort hint: if stderr looks like a terminal, surface the
		// guidance that --bundle leaks to ps. We don't gate on isatty
		// (no extra deps); the line is short and harmless in pipelines.
		_, _ = fmt.Fprintln(stderr,
			"enroll: WARNING — --bundle leaks the bootstrap token to `ps`/history/audit logs;",
			"prefer --bundle-file in production")
		return bundle, nil
	}

	// --bundle-file path. Check perms BEFORE reading so we can warn
	// even when the bytes turn out to be invalid base64 (which the
	// downstream ParseBundle catches).
	if runtime.GOOS != "windows" {
		if info, statErr := os.Stat(bundleFile); statErr == nil {
			if info.Mode().Perm()&0o077 != 0 {
				_, _ = fmt.Fprintf(stderr,
					"enroll: WARNING — bundle file %s is mode %#o (group/other readable);"+
						" set mode 0600 to protect the bootstrap token\n",
					bundleFile, info.Mode().Perm())
			}
		}
	}
	raw, err := os.ReadFile(bundleFile) //nolint:gosec // operator-supplied path
	if err != nil {
		return "", fmt.Errorf("read --bundle-file %s: %w", bundleFile, err)
	}
	// Trim surrounding whitespace so `echo "<b64>" > /tmp/bundle.txt`
	// produces a valid bundle (the newline is harmless to ParseBundle
	// today but the inconsistency would surprise operators).
	return strings.TrimSpace(string(raw)), nil
}

// runMeshEnroll decrypts the bundle's WARP envelope, drives warp-cli
// through the Service-Token attach + connect sequence, and polls until
// the daemon reaches the connected state. Returns 0 on success or a
// CLI exit code on failure.
//
// Argon2id KEK derivation runs the production OWASP-2025 parameters
// (t=2 / m=64 MiB / p=1 / len=32) which takes ~1-3 seconds on commodity
// hardware. The function prints a progress line so operators don't
// think the binary has hung.
func runMeshEnroll(stdout, stderr io.Writer, bundle *enroll.BundleV2, warpCLIPath string, pollSeconds int) int {
	_, _ = fmt.Fprintln(stdout, "enroll: decrypting WARP credentials (Argon2id KEK derivation — ~1-3 seconds)…")
	creds, err := bundle.DecryptWARPEnvelope()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "enroll: WARP envelope decrypt failed: %v\n", err)
		return 1
	}

	client := mesh.NewClient(warpCLIPath)
	_, _ = fmt.Fprintf(stdout, "enroll: attaching to Cloudflare team account %s via headless MDM enrollment…\n", redactID(creds.TeamAccountID))

	enrollCtx, cancel := context.WithTimeout(context.Background(), time.Duration(pollSeconds+30)*time.Second)
	defer cancel()

	if err := client.Enroll(enrollCtx, mesh.Credentials{
		WARPTeamDomain:     bundle.WARPTeamDomain,
		TeamAccountID:      creds.TeamAccountID,
		ServiceTokenClient: creds.ServiceTokenClient,
		ServiceTokenSecret: creds.ServiceTokenSecret,
	}); err != nil {
		switch {
		case errors.Is(err, mesh.ErrMeshUnsupportedOS):
			_, _ = fmt.Fprintln(stderr,
				"enroll: headless WARP mesh enrollment is only supported on Linux in this beacon release.")
			_, _ = fmt.Fprintln(stderr,
				"       On macOS / Windows, enroll the host into the team interactively first:")
			_, _ = fmt.Fprintln(stderr,
				"           warp-cli registration new <team-slug>")
			_, _ = fmt.Fprintln(stderr,
				"       then re-run `netbrain-beacon enroll ... --skip-mesh`.")
		case errors.Is(err, mesh.ErrWARPCLINotFound):
			_, _ = fmt.Fprintln(stderr, "enroll: warp-cli is not installed. Install Cloudflare WARP first, OR pass --skip-mesh if the platform is reachable without the mesh.")
		default:
			_, _ = fmt.Fprintf(stderr, "enroll: WARP enrollment failed: %v\n", err)
		}
		return 1
	}

	_, _ = fmt.Fprintf(stdout, "enroll: polling for WARP connected state (up to %d s)…\n", pollSeconds)
	pollCtx, pollCancel := context.WithTimeout(enrollCtx, time.Duration(pollSeconds)*time.Second)
	defer pollCancel()
	if err := client.PollEnrolled(pollCtx, 2*time.Second); err != nil {
		_, _ = fmt.Fprintf(stderr, "enroll: WARP did not reach connected state within %d s: %v\n", pollSeconds, err)
		return 1
	}
	_, _ = fmt.Fprintln(stdout, "enroll: WARP mesh ready — proceeding to HTTP /enroll")
	return 0
}

// redactID returns the first 8 chars of an account ID for logging — the
// CF account ID is not a secret per se but is operationally sensitive
// and there is no upside to printing it in full to operator logs.
func redactID(id string) string {
	if len(id) <= 8 {
		return id
	}
	return id[:8] + "…"
}

// beaconOS maps runtime.GOOS to the OpenAPI BeaconMetadataOs enum.
// Unknown OSes fall back to "linux" — the platform side rejects unknown
// values explicitly, surfacing the regression.
func beaconOS() api.BeaconMetadataOs {
	switch strings.ToLower(runtime.GOOS) {
	case "linux":
		return api.BeaconMetadataOs("linux")
	case "windows":
		return api.BeaconMetadataOs("windows")
	default:
		return api.BeaconMetadataOs("linux")
	}
}
