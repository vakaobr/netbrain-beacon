// Package mesh wraps the Cloudflare WARP CLI as a sub-process so the
// beacon's enroll command can headlessly join the platform's WARP mesh
// without bundling Cloudflare's binaries.
//
// ADR-008 (this repo) // pairs with netbrain ADR-088.
// ADR-009 (this repo) supersedes the original `warp-cli access` argv path
// with an MDM-file approach after Cloudflare removed the `access` subcommand
// from current WARP CLI builds (v0.2.0-rc.2, 2026-05-15).
//
// The WARP CLI no longer exposes a headless Service-Token argv path. The
// supported headless enrollment surface is now an MDM-file dropped at a
// well-known path BEFORE the WARP daemon starts; the daemon reads it on
// service start (or via `warp-cli mdm refresh` on >= 2026.4.1350.0). On
// Linux that path is `/var/lib/cloudflare-warp/mdm.xml`; macOS uses a
// `/Library/Managed Preferences/...plist` and Windows uses registry
// values. Only Linux is implemented in this release — macOS / Windows
// return ErrMeshUnsupportedOS and the operator falls back to
// `--skip-mesh + interactive warp-cli registration new`.
//
// We continue to invoke warp-cli as a sub-process (for status polling and
// for the optional `warp-cli mdm refresh` fast-path) rather than linking
// any Cloudflare library:
//   - WARP is a system service (not a library) on Linux / macOS / Windows;
//     all interaction goes through the local socket the CLI already wraps.
//   - The sub-process boundary keeps WARP version drift outside our
//     module graph — operators upgrade WARP without recompiling the
//     beacon.
//   - It matches the documented operator path in Cloudflare's runbooks,
//     so what the beacon does on a given customer machine is identical to
//     what an operator would type at the shell.
package mesh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"
)

// warpConnectedRE matches the WARP CLI "Connected" state without
// false-positiving on "Disconnected". The CLI prints something like
// "Status update: Connected" / "Status update: Disconnected" /
// "Status update: Registration Missing"; we require the literal
// "Connected" token bounded by non-word characters (or string ends).
//
// (?i) case-insensitive — matches "Connected" / "CONNECTED" / etc.
// \b word boundary so "Disconnected" is NOT a match.
var warpConnectedRE = regexp.MustCompile(`(?i)\bconnected\b`)

// warpDisconnectedRE explicitly matches the negative case so we don't
// accidentally pass on a line that contains "Disconnected" as a
// substring of some richer status string the CLI grows in a future
// version.
var warpDisconnectedRE = regexp.MustCompile(`(?i)\bdisconnected\b`)

// Errors surfaced by the WARP wrapper.
var (
	// ErrWARPCLINotFound signals that the warp-cli binary is not on
	// PATH (and, on Windows, also not at the default install location).
	// Operators see this as "WARP must be installed before running
	// `netbrain-beacon enroll`" — the install runbook calls this out.
	ErrWARPCLINotFound = errors.New("warp-cli not found on PATH (install Cloudflare WARP and retry, or pass --skip-mesh)")

	// ErrWARPCLIFailed wraps any non-zero exit from warp-cli. The error
	// message embeds the stderr output, redacted for sensitive args.
	ErrWARPCLIFailed = errors.New("warp-cli sub-process failed")

	// ErrWARPNotEnrolled is returned by Client.IsEnrolled when the
	// status is not yet "Connected". Caller polls + retries until the
	// poll budget expires.
	ErrWARPNotEnrolled = errors.New("warp-cli reports not enrolled")

	// ErrMeshUnsupportedOS is returned by Enroll when the host OS is
	// not Linux. The Cloudflare-supplied headless enrollment surface
	// differs per OS (Linux XML, macOS plist, Windows registry) and
	// only Linux is implemented in this release. The error message
	// points the operator at the `--skip-mesh + interactive warp-cli
	// registration new` workaround.
	ErrMeshUnsupportedOS = errors.New(
		"headless WARP mesh enrollment is only implemented for Linux in this beacon release; " +
			"on macOS / Windows, run `warp-cli registration new <team-slug>` interactively first, " +
			"then re-run `netbrain-beacon enroll` with --skip-mesh",
	)

	// ErrMDMRefreshUnsupported is an internal sentinel signalling that
	// `warp-cli mdm refresh` failed (either the subcommand doesn't
	// exist on this WARP version, or the daemon rejected the call) and
	// the caller should fall back to `systemctl restart warp-svc`.
	// Not exported — internal control flow only.
	errMDMRefreshUnsupported = errors.New("warp-cli mdm refresh unsupported")
)

// Client is the contract the enroll command depends on. The default
// implementation invokes the warp-cli binary as a sub-process; tests
// inject a mock by passing a fake binary path via NewClient.
type Client interface {
	// Enroll attaches the WARP CLI to the Service-Token-backed account
	// described by `creds`, then waits for the daemon to reach the
	// connected state (Cloudflare confirms enrollment server-side).
	//
	// On Linux, the sequence is:
	//
	//   1. Write `/var/lib/cloudflare-warp/mdm.xml` (mode 0600) carrying
	//      the team slug + Service-Token client_id + client_secret.
	//   2. Try `warp-cli mdm refresh` (works on >= 2026.4.1350.0).
	//   3. If (2) fails, `systemctl restart warp-svc`.
	//   4. Poll `warp-cli status` until "Status update: Connected" or
	//      the ctx deadline.
	//
	// `auto_connect=1` in the MDM file causes the daemon to connect
	// itself — no explicit `warp-cli connect` call is needed.
	//
	// On macOS / Windows the call returns ErrMeshUnsupportedOS — the
	// operator must run interactive `warp-cli registration new` first
	// and re-invoke `netbrain-beacon enroll --skip-mesh`.
	//
	// Returns ErrWARPCLINotFound when warp-cli isn't on PATH;
	// ErrWARPCLIFailed (wrapping the sub-process exit + stderr) when
	// the CLI rejects the input. The caller's `enroll --skip-mesh` flag
	// bypasses this entirely.
	Enroll(ctx context.Context, creds Credentials) error

	// IsEnrolled returns nil when `warp-cli status` reports a connected
	// state, ErrWARPNotEnrolled while the daemon is still attaching,
	// and ErrWARPCLINotFound / ErrWARPCLIFailed for the obvious cases.
	IsEnrolled(ctx context.Context) error

	// PollEnrolled is the convenience entry point the enroll command
	// uses after Enroll: it calls IsEnrolled every interval until the
	// status flips to connected or the ctx deadline expires. Returns
	// nil on success or the last IsEnrolled error on timeout.
	PollEnrolled(ctx context.Context, interval time.Duration) error
}

// Credentials carries the Service-Token-backed inputs the WARP MDM file
// needs. Mirrors enroll.WARPCredentials (plus the `WARPTeamDomain`
// passed alongside from the bundle) so callers can hand the decrypted
// envelope contents directly without re-translating fields.
type Credentials struct {
	// WARPTeamDomain is the team's Cloudflare Access subdomain — for
	// example "netbrain-dev.cloudflareaccess.com". The MDM file's
	// `<organization>` value is derived by stripping the
	// `.cloudflareaccess.com` suffix.
	WARPTeamDomain string

	// TeamAccountID is the CF account UUID. Retained for logging /
	// future use; the MDM file does NOT carry it (Cloudflare's headless
	// MDM enrollment is per-team, not per-account).
	TeamAccountID string

	// ServiceTokenClient is the service-token client_id. Must end in
	// `.access`; the MDM writer appends the suffix if missing.
	ServiceTokenClient string

	// ServiceTokenSecret is the service-token client_secret. Written
	// to `/var/lib/cloudflare-warp/mdm.xml` at mode 0600 — see ADR-009
	// for the on-disk-secret posture decision.
	ServiceTokenSecret string
}

// NewClient returns the default cli-backed Client. The optional binPath
// arg is for tests — pass a path to a fake script that mimics warp-cli;
// otherwise the empty string resolves to the system "warp-cli".
//
// Platform dispatch: on Linux the returned client's Enroll method
// writes /var/lib/cloudflare-warp/mdm.xml and restarts warp-svc; on
// other OSes Enroll returns ErrMeshUnsupportedOS. The IsEnrolled /
// PollEnrolled methods are platform-agnostic (they just call
// `warp-cli status`).
func NewClient(binPath string) Client {
	if binPath == "" {
		binPath = "warp-cli"
	}
	return &cliClient{
		binPath:    binPath,
		goos:       runtime.GOOS,
		mdmPath:    defaultMDMPath,
		runRestart: defaultRunSystemctlRestart,
	}
}

// cliClient is the shared implementation backing all platforms. The
// platform-specific code paths live in mdm_linux.go and mdm_other.go,
// dispatched at runtime via the `goos` field (which exists so tests can
// override the platform predicate without juggling build tags).
type cliClient struct {
	binPath string
	goos    string // runtime.GOOS at construction time; overridable for tests

	// mdmPath returns the on-disk path the daemon expects the MDM
	// file at. Overridable in tests to point at a tempdir.
	mdmPath func() string

	// runRestart shells out to `systemctl restart warp-svc` as a
	// fallback when `warp-cli mdm refresh` fails. Overridable in
	// tests so we don't actually poke systemd.
	runRestart func(ctx context.Context) error
}

// IsEnrolled reports nil when warp-cli's status output contains the
// "Connected" word boundary (case-insensitive, excluding "Disconnected").
// Returns ErrWARPNotEnrolled while the daemon is still attaching, and
// ErrWARPCLINotFound / ErrWARPCLIFailed for the obvious cases.
func (c *cliClient) IsEnrolled(ctx context.Context) error {
	stdout, stderr, err := c.run(ctx, "status")
	if err != nil {
		if errors.Is(err, ErrWARPCLINotFound) {
			return err
		}
		return fmt.Errorf("%w: status: %s", ErrWARPCLIFailed, strings.TrimSpace(stderr))
	}
	// `warp-cli status` prints a line like "Status update: Connected"
	// (or "Disconnected", "Registration Missing", "Connecting"). Match
	// the word "Connected" with a regex word boundary so we don't
	// false-positive on "Disconnected". The negative case explicitly
	// short-circuits, so a "Disconnecting and reconnecting" type
	// status (hypothetical future CLI verbiage) doesn't slip through.
	if warpDisconnectedRE.MatchString(stdout) {
		return fmt.Errorf("%w: %s", ErrWARPNotEnrolled, strings.TrimSpace(stdout))
	}
	if warpConnectedRE.MatchString(stdout) {
		return nil
	}
	return fmt.Errorf("%w: %s", ErrWARPNotEnrolled, strings.TrimSpace(stdout))
}

// PollEnrolled calls IsEnrolled on a ticker until the status flips to
// connected or the ctx deadline expires. Returns nil on success or the
// last IsEnrolled error wrapped with ctx.Err() on timeout.
func (c *cliClient) PollEnrolled(ctx context.Context, interval time.Duration) error {
	if interval <= 0 {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	// One immediate probe before waiting — the WARP daemon is often
	// already connected by the time enroll-poll fires.
	lastErr := c.IsEnrolled(ctx)
	if lastErr == nil {
		return nil
	}
	for {
		select {
		case <-ctx.Done():
			if lastErr != nil {
				return fmt.Errorf("WARP enrollment poll: %w (last status: %s)", ctx.Err(), lastErr)
			}
			return ctx.Err()
		case <-ticker.C:
			if err := c.IsEnrolled(ctx); err != nil {
				lastErr = err
				continue
			}
			return nil
		}
	}
}

// run executes warp-cli with the given args, returning stdout, stderr,
// and any exec error. Sub-process exit code != 0 surfaces as an error;
// stderr is preserved for logging by the caller.
func (c *cliClient) run(ctx context.Context, args ...string) (stdout, stderr string, err error) {
	cmd := exec.CommandContext(ctx, c.binPath, args...) //nolint:gosec // c.binPath is configured at NewClient
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	if runErr := cmd.Run(); runErr != nil {
		// exec.ErrNotFound is wrapped by Go's exec package starting in
		// 1.20; surface as ErrWARPCLINotFound for the lookup path.
		if errors.Is(runErr, exec.ErrNotFound) {
			return outBuf.String(), errBuf.String(), fmt.Errorf("%w: %w", ErrWARPCLINotFound, runErr)
		}
		return outBuf.String(), errBuf.String(), runErr
	}
	return outBuf.String(), errBuf.String(), nil
}

// redactArgs returns a logging-safe form of a warp-cli argument list.
// As of ADR-009 (MDM-file pivot) the headless Service-Token surface no
// longer passes the secret as a CLI arg, so this function's primary
// caller is gone. It is preserved for any future warp-cli interactions
// that might carry sensitive argv (defense in depth).
func redactArgs(args []string) string {
	out := make([]string, len(args))
	copy(out, args)
	// Legacy: `access add-account-key <client_id> <client_secret>` is no
	// longer reachable but we keep the redaction in place in case the
	// CLI grows another secret-bearing subcommand we shell out to.
	if len(out) >= 4 && out[0] == "access" && out[1] == "add-account-key" {
		out[3] = "<redacted>"
	}
	return strings.Join(out, " ")
}

// defaultRunSystemctlRestart is the production fallback when
// `warp-cli mdm refresh` fails. It shells out to `systemctl restart
// warp-svc` with a small timeout. Overridable in tests via the
// cliClient.runRestart field.
func defaultRunSystemctlRestart(ctx context.Context) error {
	restartCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(restartCtx, "systemctl", "restart", "warp-svc") //nolint:gosec // fixed argv
	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("systemctl restart warp-svc: %w: %s", err, strings.TrimSpace(errBuf.String()))
	}
	return nil
}
