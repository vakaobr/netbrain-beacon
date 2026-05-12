// Package daemon orchestrates the long-running beacon: config-poll loop,
// heartbeat with device-probe payload, and DEK-rotation signature
// verification.
//
// The Daemon struct holds references to the on-disk artifacts (cert,
// DEK, beacon ID), the transport-layer mTLS client, the bbolt store, the
// probe scheduler, and the generated OpenAPI client. Run(ctx) starts
// every goroutine and blocks until ctx is cancelled; goroutines drain
// within a bounded shutdown grace period (default 10s).
//
// # Poll loop (ADR-070)
//
// Every IntervalSeconds ± JitterSeconds, the daemon calls
// PollBeaconConfig with the last-known config_hash as If-None-Match.
//
//   - 304 Not Modified → no-op; emit `daemon.poll.not_modified` metric.
//   - 200 + new config_hash → persist config; emit `daemon.poll.applied`.
//   - 200 + X-Beacon-DataKey-Signature → call verifyDEKRotationSignature;
//     fail-closed on tamper (log + counter; do NOT swap the on-disk DEK).
//   - 5xx / network error → exponential backoff (1s → 30s cap).
//
// The poll loop ALSO triggers the heartbeat send on every successful
// cycle (ADR-070 §"Heartbeat piggybacks on poll").
//
// # M-11 fail-closed
//
// When the config response carries X-Beacon-DataKey-Signature, the
// signature MUST verify against the platform pubkey pinned at enrollment
// time. A failed verify is treated as a security event:
//   - increment `netbrain_beacon_dek_signature_verify_failed_total`
//   - emit slog.Error with structured `beacon_id` + `verify_error`
//   - DO NOT swap the on-disk DEK
//   - the next poll re-attempts (allows operator-side recovery)
package daemon
