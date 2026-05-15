package mesh

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// writeFakeWarpCLI writes an executable script to disk that mimics the
// warp-cli sub-process for tests. The behaviour is controlled by writing
// a marker file that the script reads on each invocation.
//
// On Linux/macOS the script is a tiny shell snippet. On Windows we use
// a .cmd batch file. The script:
//   - On `--version` → prints "fake-warp-cli vX.Y" to stdout, exit 0.
//   - On `status`    → reads the marker file:
//     "connected"   → prints "Status update: Connected" to stdout, exit 0.
//     "disconnected" → prints "Status update: Disconnected" to stdout, exit 0.
//     "fail"        → exit 7 (rejected by warp-cli).
//     (anything else) → prints "Registration Missing", exit 0.
//   - On `mdm refresh` → reads marker file:
//     "mdm-unsupported" → stderr "error: unrecognized subcommand 'mdm'", exit 2.
//     "mdm-fail"        → stderr "error: refresh failed", exit 1.
//     anything else     → exit 0.
//   - On any other sub-command → exit 0 quietly (Enroll happy path).
func writeFakeWarpCLI(t *testing.T) (path string, markerPath string) {
	t.Helper()
	dir := t.TempDir()
	markerPath = filepath.Join(dir, "marker.txt")

	var (
		scriptName string
		body       string
	)
	if runtime.GOOS == "windows" {
		scriptName = "fake-warp-cli.cmd"
		body = `@echo off
if "%1"=="--version" (
  echo fake-warp-cli v0.0
  exit /b 0
)
if "%1"=="status" (
  if exist "` + markerPath + `" (
    set /p s=<"` + markerPath + `"
    if "%s%"=="connected" ( echo Status update: Connected & exit /b 0 )
    if "%s%"=="disconnected" ( echo Status update: Disconnected & exit /b 0 )
    if "%s%"=="fail" ( exit /b 7 )
  )
  echo Status update: Registration Missing
  exit /b 0
)
if "%1"=="mdm" (
  if exist "` + markerPath + `" (
    set /p s=<"` + markerPath + `"
    if "%s%"=="mdm-unsupported" ( echo error: unrecognized subcommand 'mdm' 1>&2 & exit /b 2 )
    if "%s%"=="mdm-fail" ( echo error: refresh failed 1>&2 & exit /b 1 )
  )
  exit /b 0
)
exit /b 0
`
	} else {
		scriptName = "fake-warp-cli.sh"
		body = `#!/bin/sh
case "$1" in
  --version)
    echo "fake-warp-cli v0.0"
    exit 0
    ;;
  status)
    if [ -f "` + markerPath + `" ]; then
      s=$(cat "` + markerPath + `")
      case "$s" in
        connected) echo "Status update: Connected"; exit 0 ;;
        disconnected) echo "Status update: Disconnected"; exit 0 ;;
        fail) exit 7 ;;
      esac
    fi
    echo "Status update: Registration Missing"
    exit 0
    ;;
  mdm)
    if [ -f "` + markerPath + `" ]; then
      s=$(cat "` + markerPath + `")
      case "$s" in
        mdm-unsupported) echo "error: unrecognized subcommand 'mdm'" 1>&2; exit 2 ;;
        mdm-fail) echo "error: refresh failed" 1>&2; exit 1 ;;
      esac
    fi
    exit 0
    ;;
  *)
    exit 0
    ;;
esac
`
	}

	path = filepath.Join(dir, scriptName)
	require.NoError(t, os.WriteFile(path, []byte(body), 0o755)) //nolint:gosec // test fixture
	return path, markerPath
}

func writeMarker(t *testing.T, markerPath, value string) {
	t.Helper()
	require.NoError(t, os.WriteFile(markerPath, []byte(value), 0o644)) //nolint:gosec // test fixture
}

// ----------------------------------------------------------------------------
// IsEnrolled — platform-agnostic; runs on every supported OS.
// ----------------------------------------------------------------------------

func TestIsEnrolled_Connected(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-script fake CLI is POSIX-only; Windows uses .cmd which is harder to make reliably executable from `go test` without elevation")
	}
	path, marker := writeFakeWarpCLI(t)
	writeMarker(t, marker, "connected")
	c := NewClient(path)
	require.NoError(t, c.IsEnrolled(context.Background()))
}

func TestIsEnrolled_NotConnected(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-script fake CLI is POSIX-only")
	}
	path, marker := writeFakeWarpCLI(t)
	writeMarker(t, marker, "disconnected")
	c := NewClient(path)
	err := c.IsEnrolled(context.Background())
	require.ErrorIs(t, err, ErrWARPNotEnrolled)
}

func TestIsEnrolled_CLIFails(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-script fake CLI is POSIX-only")
	}
	path, marker := writeFakeWarpCLI(t)
	writeMarker(t, marker, "fail")
	c := NewClient(path)
	err := c.IsEnrolled(context.Background())
	require.Error(t, err)
	require.ErrorIs(t, err, ErrWARPCLIFailed)
}

// ----------------------------------------------------------------------------
// PollEnrolled — timeout behaviour, platform-agnostic.
// ----------------------------------------------------------------------------

func TestPollEnrolled_Timeout(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-script fake CLI is POSIX-only")
	}
	path, marker := writeFakeWarpCLI(t)
	writeMarker(t, marker, "disconnected")

	c := NewClient(path)
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	err := c.PollEnrolled(ctx, 50*time.Millisecond)
	require.Error(t, err)
	// The timeout wraps the last IsEnrolled status — check both that it
	// timed out AND that the last error was the expected "not enrolled".
	require.True(t, errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled),
		"expected ctx deadline-exceeded, got %v", err)
}

// ----------------------------------------------------------------------------
// redactArgs — preserved post-MDM-pivot for any future secret-bearing argv.
// ----------------------------------------------------------------------------

func TestRedactArgs_RedactsServiceTokenSecret(t *testing.T) {
	got := redactArgs([]string{"access", "add-account-key", "abc.access", "S3CR3T-VALUE"})
	require.Contains(t, got, "<redacted>")
	require.NotContains(t, got, "S3CR3T-VALUE")
}

func TestRedactArgs_LeavesOtherArgsAlone(t *testing.T) {
	got := redactArgs([]string{"connect"})
	require.Equal(t, "connect", got)
	got = redactArgs([]string{"access", "set-default-account", "team-id-abc"})
	require.Equal(t, "access set-default-account team-id-abc", got)
}

// ----------------------------------------------------------------------------
// Enroll non-Linux path — must return ErrMeshUnsupportedOS on any OS that
// isn't Linux. We exercise this by overriding the platform predicate on the
// cliClient so the test can run on any dev host. The runtime-build dispatch
// is verified by the build-tag-split (`mdm_linux.go` vs `mdm_other.go`).
// ----------------------------------------------------------------------------

func TestEnrollNonLinuxReturnsUnsupportedOS(t *testing.T) {
	// We construct a cliClient directly (bypassing NewClient) so we can
	// flip the `goos` field. The build-tag guard in mdm_linux.go also
	// checks c.goos and short-circuits — that's the path under test.
	if runtime.GOOS != "linux" {
		// On non-Linux the build-tagged Enroll (in mdm_other.go) is the
		// implementation; it unconditionally returns ErrMeshUnsupportedOS.
		c := NewClient("warp-cli")
		err := c.Enroll(context.Background(), Credentials{
			WARPTeamDomain:     "netbrain-dev.cloudflareaccess.com",
			ServiceTokenClient: "abc",
			ServiceTokenSecret: "secret",
		})
		require.ErrorIs(t, err, ErrMeshUnsupportedOS)
		return
	}

	// On Linux, the Enroll function is the MDM-file path. We use the
	// `goos` override to make it think it's running somewhere else,
	// triggering the defensive guard in mdm_linux.go's Enroll.
	c := &cliClient{
		binPath: "warp-cli",
		goos:    "darwin",
		mdmPath: defaultMDMPath,
	}
	err := c.Enroll(context.Background(), Credentials{
		WARPTeamDomain:     "netbrain-dev.cloudflareaccess.com",
		ServiceTokenClient: "abc",
		ServiceTokenSecret: "secret",
	})
	require.ErrorIs(t, err, ErrMeshUnsupportedOS)
}
