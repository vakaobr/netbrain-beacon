// Package mesh wraps the Cloudflare WARP CLI as a sub-process so the
// beacon's enroll command can headlessly join the platform's WARP mesh
// without bundling Cloudflare's binaries.
//
// ADR-008 (this repo) // pairs with netbrain ADR-088.
//
// The WARP CLI exposes a Service-Token authentication path
// (`warp-cli access add-account-key <client_id> <client_secret>`) that
// lets a beacon attach to the Velonet Zero Trust team without operator
// SSO. The bundle v2 envelope carries the Service Token credentials
// (decrypted at enroll time via enroll.BundleV2.DecryptWARPEnvelope);
// this package consumes them.
//
// We intentionally invoke warp-cli as a sub-process rather than linking
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
)

// Client is the contract the enroll command depends on. The default
// implementation invokes the warp-cli binary as a sub-process; tests
// inject a mock by passing a fake binary path via NewClient.
type Client interface {
	// Enroll attaches the WARP CLI to the Service-Token-backed account
	// described by `creds`, then waits for the daemon to reach the
	// connected state (Cloudflare confirms enrollment server-side).
	//
	// On Linux / macOS the sequence is:
	//
	//   warp-cli access set-default-account <team_account_id>
	//   warp-cli access add-account-key <client_id> <client_secret>
	//   warp-cli connect
	//
	// On Windows the call paths are the same but use a different
	// shell quoting strategy.
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

// Credentials carries the Service-Token-backed inputs warp-cli needs.
// Mirrors enroll.WARPCredentials so callers can hand the decrypted
// bundle payload directly without re-translating fields.
type Credentials struct {
	TeamAccountID      string // CF account ID — warp-cli access set-default-account <id>
	ServiceTokenClient string // client_id — warp-cli access add-account-key <id> ...
	ServiceTokenSecret string // client_secret — warp-cli access add-account-key ... <secret>
}

// NewClient returns the default cli-backed Client. The optional binPath
// arg is for tests — pass a path to a fake script that mimics warp-cli;
// otherwise the empty string resolves to the system "warp-cli".
func NewClient(binPath string) Client {
	if binPath == "" {
		binPath = "warp-cli"
	}
	return &cliClient{binPath: binPath}
}

type cliClient struct {
	binPath string
}

// Enroll runs the three-step service-token attach. Each sub-step is
// quoted explicitly so a malformed input doesn't get a chance to expand
// into separate arguments — exec.CommandContext takes argv as a slice,
// not a single string.
func (c *cliClient) Enroll(ctx context.Context, creds Credentials) error {
	if creds.TeamAccountID == "" || creds.ServiceTokenClient == "" || creds.ServiceTokenSecret == "" {
		return fmt.Errorf("%w: missing required field in Credentials", ErrWARPCLIFailed)
	}
	if err := c.assertBinaryAvailable(ctx); err != nil {
		return err
	}

	steps := [][]string{
		{"access", "set-default-account", creds.TeamAccountID},
		{"access", "add-account-key", creds.ServiceTokenClient, creds.ServiceTokenSecret},
		{"connect"},
	}

	for _, args := range steps {
		// Always run with a short timeout per step (the CLI returns
		// quickly on success; the slow path is the eventual `connect`
		// poll, which is handled by PollEnrolled, not here).
		stepCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		_, stderr, err := c.run(stepCtx, args...)
		cancel()
		if err != nil {
			return fmt.Errorf("%w: %s: %s", ErrWARPCLIFailed, redactArgs(args), strings.TrimSpace(stderr))
		}
	}
	return nil
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

// assertBinaryAvailable runs `warp-cli --version` and translates the
// "exec: not found" outcome to ErrWARPCLINotFound. Distinguishing
// "binary missing" from "binary returns error" gives operators a clear
// install-vs-troubleshoot signal.
func (c *cliClient) assertBinaryAvailable(ctx context.Context) error {
	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if _, err := exec.LookPath(c.binPath); err != nil {
		return fmt.Errorf("%w: looked up %q on PATH (GOOS=%s)", ErrWARPCLINotFound, c.binPath, runtime.GOOS)
	}
	_, stderr, err := c.run(probeCtx, "--version")
	if err != nil {
		return fmt.Errorf("%w: probe --version: %s", ErrWARPCLIFailed, strings.TrimSpace(stderr))
	}
	return nil
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

// redactArgs returns a logging-safe form of a warp-cli argument list:
// the Service-Token secret is replaced with "<redacted>" so failed-step
// error messages don't leak the secret into operator logs or audit logs.
func redactArgs(args []string) string {
	out := make([]string, len(args))
	copy(out, args)
	// add-account-key takes (<client_id>, <client_secret>); redact the
	// secret (position 3 in the full args list when the first two are
	// "access", "add-account-key").
	if len(out) >= 4 && out[0] == "access" && out[1] == "add-account-key" {
		out[3] = "<redacted>"
	}
	return strings.Join(out, " ")
}
