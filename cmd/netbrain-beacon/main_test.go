package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRunVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"netbrain-beacon", "version"}, &stdout, &stderr)
	require.Equal(t, 0, code)
	require.NotEmpty(t, strings.TrimSpace(stdout.String()))
	require.Empty(t, stderr.String())
}

func TestRunNoArgs(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"netbrain-beacon"}, &stdout, &stderr)
	require.Equal(t, 2, code)
	require.Empty(t, stdout.String())
	require.Contains(t, stderr.String(), "usage:")
}

func TestRunUnknownSubcommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"netbrain-beacon", "bogus"}, &stdout, &stderr)
	require.Equal(t, 2, code)
	require.Contains(t, stderr.String(), "unknown subcommand")
}

func TestRunStartStopRestartRedirects(t *testing.T) {
	// Operators who reflex-type `start` / `stop` / `restart` get a hint
	// pointing at systemctl + docker + foreground modes.
	for _, cmd := range []string{"start", "stop", "restart"} {
		var stdout, stderr bytes.Buffer
		code := run([]string{"netbrain-beacon", cmd}, &stdout, &stderr)
		require.Equal(t, 2, code)
		require.Empty(t, stdout.String())
		out := stderr.String()
		require.Contains(t, out, "OS service manager")
		require.Contains(t, out, "systemctl "+cmd+" netbrain-beacon")
		require.Contains(t, out, "docker "+cmd)
	}
}

// --- S-1: enroll --bundle-file (CWE-214) ---

// TestReadBundleArgRequiresOneSource confirms that exactly one of
// --bundle / --bundle-file must be set.
func TestReadBundleArgRequiresOneSource(t *testing.T) {
	var stderr bytes.Buffer
	_, err := readBundleArg("", "", &stderr)
	require.Error(t, err)
	require.Contains(t, err.Error(), "required")
}

// TestReadBundleArgRejectsBoth confirms that supplying both flags is a
// hard error (prevents silent precedence rules).
func TestReadBundleArgRejectsBoth(t *testing.T) {
	var stderr bytes.Buffer
	_, err := readBundleArg("aaaa", "/some/path", &stderr)
	require.Error(t, err)
	require.Contains(t, err.Error(), "mutually exclusive")
}

// TestReadBundleArgFromInline returns the inline string + emits the
// ps-leak warning to stderr.
func TestReadBundleArgFromInline(t *testing.T) {
	var stderr bytes.Buffer
	out, err := readBundleArg("the-bundle-b64", "", &stderr)
	require.NoError(t, err)
	require.Equal(t, "the-bundle-b64", out)
	require.Contains(t, stderr.String(), "WARNING")
	require.Contains(t, stderr.String(), "ps")
}

// TestReadBundleArgFromFile trims whitespace + returns the file contents.
func TestReadBundleArgFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bundle.b64")
	require.NoError(t, os.WriteFile(path, []byte("the-bundle-b64\n"), 0o600))

	var stderr bytes.Buffer
	out, err := readBundleArg("", path, &stderr)
	require.NoError(t, err)
	require.Equal(t, "the-bundle-b64", out, "trailing newline must be trimmed")
}

// TestReadBundleArgWarnsOnLoosePerms emits a stderr warning when the
// bundle file's mode lets group/other read it.
func TestReadBundleArgWarnsOnLoosePerms(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("perm check is unix-only; Windows uses ACLs")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "bundle.b64")
	require.NoError(t, os.WriteFile(path, []byte("xxx"), 0o644))

	var stderr bytes.Buffer
	_, err := readBundleArg("", path, &stderr)
	require.NoError(t, err)
	require.Contains(t, stderr.String(), "WARNING")
	require.Contains(t, stderr.String(), "0644")
}
