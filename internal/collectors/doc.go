// Package collectors hosts the four data-stream collector implementations
// per ADR-082 plus the shared `sender` infrastructure that flushes their
// bbolt-buffered records to the platform.
//
// # Layout
//
//	sender/    — Sender.Run drains one bbolt bucket; encrypts each record
//	             with the current DEK + derives the Idempotency-Key UUIDv5
//	             from beacon_id + sha256(plaintext) (byte-compatible with
//	             the platform's M-2-AAD recompute); POSTs to /data/{type}.
//	syslog/    — UDP + TCP 514 listener via leodido/go-syslog v4; worker
//	             pool of 8 (per ADR-082 D-6); drop-on-full back-pressure.
//	netflow/   — STUB (full implementation in follow-up): UDP 2055 +
//	             goflow2 + pure-Go nfcapd writer.
//	snmp/      — STUB: gosnmp poller; goes through safedial for SSRF
//	             (M-9).
//	configs/   — STUB: SSH config-pull via x/crypto/ssh + safedial.
//
// # DEK holder
//
// Senders need read access to the current DEK + DEK version. The
// collectors package owns the DEKHolder type — an atomic.Pointer wrapper
// the daemon updates after a successful DEK rotation (M-11 — Phase 8's
// dek_verify.go is the gating logic). Reads are lock-free; writes go
// through atomic.Pointer.Store.
//
// # Drop-on-full back-pressure
//
// Each collector has a bounded channel between the listener and the
// worker pool. When the channel is full, the listener increments a
// `dropped` counter and discards the message rather than blocking. This
// preserves the platform-side liveness invariant — a slow downstream
// must NEVER stall ingest at the customer edge, which would back up into
// the device's TCP buffer and trip noisy alarms.
//
// # Forbidigo carve-outs
//
// The collectors hit network listeners (UDP + TCP server sockets) and
// outbound device probes. UDP/TCP listeners use `net.ListenUDP` /
// `net.Listen("tcp", ...)` directly — these are NOT `net.Dial*` calls
// and are NOT subject to the SSRF chokepoint (we're accepting inbound
// connections, not dialing user-supplied targets). Outbound device dials
// (snmp + configs collectors) MUST go through internal/safedial.
package collectors
