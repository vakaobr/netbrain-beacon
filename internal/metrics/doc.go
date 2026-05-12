// Package metrics is the Prometheus instrumentation surface for the
// beacon. Registers the 18 instruments documented in
// 03_PROJECT_SPEC.md §NFR-OBS and exposes them on /metrics via a
// loopback-only HTTP server.
//
// # Loopback-only binding (D-8)
//
// The /metrics endpoint binds to 127.0.0.1:9090 by default. Operators
// who need remote scraping configure an SSH tunnel or a host-level
// reverse proxy; the beacon never exposes its metrics surface to the
// internet directly.
//
// The CLI flag `--no-metrics` disables the endpoint entirely (for
// environments that don't run Prometheus locally).
//
// # Registration
//
// Every metric registers against the default prometheus.Registry at
// package-init time. Callers Inc/Observe via the exported metric
// variables — no constructor functions, no DI, just `metrics.PollTotal.WithLabelValues(...).Inc()`.
package metrics
