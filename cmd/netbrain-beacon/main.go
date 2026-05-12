// Command netbrain-beacon is the customer-edge collector binary for the
// NetBrain beacon protocol. It ships logs, NetFlow, SNMP data, and device
// configurations from isolated customer networks to the NetBrain platform
// over mTLS.
//
// Subcommands: version. Additional subcommands (enroll, daemon, status,
// collectors, logs) land in later phases per 04_IMPLEMENTATION_PLAN.md.
package main

import (
	"fmt"
	"io"
	"os"
)

// version is set via -ldflags "-X main.version=<value>" at build time.
// The default "dev" identifies developer builds.
var version = "dev"

func main() {
	os.Exit(run(os.Args, os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) < 2 {
		_, _ = fmt.Fprintln(stderr, "usage: netbrain-beacon <subcommand>")
		_, _ = fmt.Fprintln(stderr, "subcommands: version, enroll, daemon, status, collectors, logs")
		return 2
	}

	switch args[1] {
	case "version":
		_, _ = fmt.Fprintln(stdout, version)
		return 0
	case "enroll":
		return runEnroll(args[2:], stdout, stderr)
	case "daemon":
		return runDaemon(args[2:], stdout, stderr)
	case "status":
		return runStatus(args[2:], stdout, stderr)
	case "collectors":
		return runCollectors(args[2:], stdout, stderr)
	case "logs":
		return runLogs(args[2:], stdout, stderr)
	case "start", "stop", "restart":
		// Operators reach for these by reflex from other CLIs. Redirect
		// to the platform's service manager — we intentionally don't
		// implement daemonization in the binary (the OS does it better).
		_, _ = fmt.Fprintf(stderr, "netbrain-beacon: lifecycle is managed by the OS service manager, not the binary.\n")
		_, _ = fmt.Fprintf(stderr, "  Linux (systemd):  sudo systemctl %s netbrain-beacon\n", args[1])
		_, _ = fmt.Fprintf(stderr, "  Docker:           docker %s <container>\n", args[1])
		_, _ = fmt.Fprintf(stderr, "  Foreground (dev): ./netbrain-beacon daemon  (Ctrl-C to stop)\n")
		_, _ = fmt.Fprintf(stderr, "  See docs/runbooks/beacon-operations.md for full install + lifecycle steps.\n")
		return 2
	default:
		_, _ = fmt.Fprintf(stderr, "unknown subcommand: %s\n", args[1])
		return 2
	}
}
