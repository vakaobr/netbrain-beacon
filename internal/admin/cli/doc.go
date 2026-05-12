// Package cli implements the operator-facing subcommands the daemon
// embeds in the netbrain-beacon binary:
//
//	status     — print current enrollment + cert + DEK + store state
//	collectors — print collector enable/disable + counters
//	logs       — tail the structured log file
//
// Per ADR-082 D-1, the beacon ships with a CLI + Prometheus metrics
// surface for v1, not a web UI. The web UI is a deferred follow-up.
//
// CLI subcommands read on-disk state directly (enrollment-metadata.json,
// dek.bin, beacon.crt, beacon-state.bbolt) — they don't talk to a
// running daemon over RPC. This avoids needing an IPC channel and means
// `status` works even when the daemon is wedged.
package cli
