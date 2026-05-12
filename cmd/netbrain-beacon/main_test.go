package main

import (
	"bytes"
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
