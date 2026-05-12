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

	"github.com/velonet/netbrain-beacon/internal/api"
	"github.com/velonet/netbrain-beacon/internal/enroll"
)

// runEnroll implements the `netbrain-beacon enroll ...` subcommand.
//
// Flags:
//
//	--bundle <b64>       (required) base64-encoded signed enrollment bundle
//	--server-url <url>   (required) https://<platform-host>:8443
//	--state-dir <path>   override default state-dir (see defaultStateDir)
//	--force              overwrite an existing enrollment in state-dir
//	--allow-unsigned     accept an unsigned bundle (DEV ONLY)
func runEnroll(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		bundleB64        = fs.String("bundle", "", "base64-encoded enrollment bundle (required)")
		serverURL        = fs.String("server-url", "", "platform URL, e.g. https://platform.example.com:8443 (required)")
		stateDir         = fs.String("state-dir", defaultStateDir(), "directory to persist enrollment artifacts")
		force            = fs.Bool("force", false, "overwrite existing enrollment in state-dir")
		allowUnsigned    = fs.Bool("allow-unsigned", false, "accept unsigned bundles (DEV ONLY)")
		hostnameOverride = fs.String("hostname", "", "override the hostname sent in beacon_metadata (default: os.Hostname)")
	)

	if err := fs.Parse(args); err != nil {
		// flag package already printed usage on its own writer.
		return 2
	}
	if *bundleB64 == "" || *serverURL == "" {
		_, _ = fmt.Fprintln(stderr, "enroll: --bundle and --server-url are required")
		fs.Usage()
		return 2
	}

	// 1) Parse + verify the bundle.
	bundle, err := enroll.ParseBundle(*bundleB64, *allowUnsigned)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "enroll: bundle rejected: %v\n", err)
		return 1
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
