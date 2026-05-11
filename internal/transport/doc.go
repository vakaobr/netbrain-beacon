// Package transport wraps the oapi-codegen-generated client (internal/api)
// with the mTLS-aware HTTP client used by the beacon's daemon loop, enroll
// command, and data-plane senders.
//
// # Responsibilities
//
//   - Build a *tls.Config bound to the beacon's per-install cert + key,
//     pinned to the platform CA, with MinVersion TLS 1.3 (no 1.2 fallback).
//   - Hold the active *http.Client in an atomic.Pointer for safe hot-swap
//     during cert rotation (ADR-079). Callers obtain the current client via
//     Current() and need not care about rotation timing.
//   - Provide RequestEditorFn middleware that adds the standard headers
//     every request needs (User-Agent, Idempotency-Key when caller-supplied,
//     Content-Encoding for gzipped bodies).
//   - Map the 17 OpenAPI error codes from the server to one of four
//     beacon-side actions (success / retry / drop_and_alert /
//     fatal_reenroll / back_off). Each call site checks the action and
//     reacts predictably.
//
// # Cert rotation pattern (ADR-079)
//
// The daemon's cert-rotation scheduler builds a NEW *http.Client (TLS config
// loaded from the freshly-rotated cert files) and calls Client.Swap(new).
// In-flight requests using the OLD client complete on the old TLS config;
// new requests use the new client. No lockfile, no draining — atomic
// pointer swap is the entire synchronisation primitive.
//
// # Forbidigo carve-out
//
// internal/transport is the only package besides internal/safedial allowed
// to call net.Dial* directly. The platform URL is server-controlled (set by
// the enrollment bundle), not device-supplied, so the SSRF allow-list
// doesn't apply.
package transport
