package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// The 18 instruments per 03_PROJECT_SPEC.md §NFR-OBS. Names follow the
// Prometheus naming convention (`<namespace>_<subsystem>_<metric>_<unit>`):
// namespace = `beacon`, subsystems group related metrics.
//
// Every instrument registers against the default prometheus registry at
// package-init time via prometheus.MustRegister.

// --- 1. Enrollment (Phase 5) ---

// EnrollmentTotal counts enroll attempts by outcome. Labels:
//
//	result ∈ {success, bundle_invalid, server_rejected, network, persist_failed}
var EnrollmentTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Namespace: "beacon",
	Subsystem: "enrollment",
	Name:      "total",
	Help:      "Beacon enrollment attempts by outcome.",
}, []string{"result"})

// --- 2-3. Config poll (Phase 8) ---

// PollDurationSeconds buckets poll-cycle latency. The Phase 8 daemon
// observes after every pollOnce; histogram buckets cover the typical
// 50ms-2s range with one outlier bucket at 10s.
var PollDurationSeconds = prometheus.NewHistogramVec(prometheus.HistogramOpts{
	Namespace: "beacon",
	Subsystem: "poll",
	Name:      "duration_seconds",
	Help:      "Config-poll round-trip latency.",
	Buckets:   []float64{0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0},
}, []string{"result"})

// PollTotal counts poll cycles by outcome. Labels:
//
//	result ∈ {modified, not_modified, server_error, network_error}
var PollTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Namespace: "beacon",
	Subsystem: "poll",
	Name:      "total",
	Help:      "Config-poll cycles by outcome.",
}, []string{"result"})

// --- 4. Heartbeat ---

// HeartbeatTotal counts heartbeat round-trips by outcome.
var HeartbeatTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Namespace: "beacon",
	Subsystem: "heartbeat",
	Name:      "total",
	Help:      "Heartbeat round-trips by outcome.",
}, []string{"result"})

// --- 5-6. DEK rotation (M-11) ---

// DEKVerifyFailedTotal is the M-11 fail-closed counter. Every increment
// is a P1 security signal — the platform delivered a DEK whose
// X-Beacon-DataKey-Signature didn't verify against the pinned pubkey.
var DEKVerifyFailedTotal = prometheus.NewCounter(prometheus.CounterOpts{
	Namespace: "beacon",
	Subsystem: "dek",
	Name:      "verify_failed_total",
	Help:      "X-Beacon-DataKey-Signature verification failures (M-11 fail-closed events). Each increment is a P1 security signal.",
})

// DEKVersion is the currently-trusted DEK version. Bumped only after
// a successful M-11 verify.
var DEKVersion = prometheus.NewGauge(prometheus.GaugeOpts{
	Namespace: "beacon",
	Subsystem: "dek",
	Name:      "version",
	Help:      "Currently-trusted DEK version (updates only after M-11 signature verify succeeds).",
})

// --- 7-8. Cert rotation (Phase 6) ---

// CertRotationTotal counts rotation attempts by outcome.
var CertRotationTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Namespace: "beacon",
	Subsystem: "cert",
	Name:      "rotation_total",
	Help:      "Beacon cert-rotation attempts by outcome.",
}, []string{"result"})

// CertExpiresInSeconds is the time-until-expiry of the active cert.
// Daemon's rotation scheduler updates this every cycle. Alertmanager-side
// rule fires when value drops below 20% of cert lifetime (RotationThreshold).
var CertExpiresInSeconds = prometheus.NewGauge(prometheus.GaugeOpts{
	Namespace: "beacon",
	Subsystem: "cert",
	Name:      "expires_in_seconds",
	Help:      "Seconds until the active beacon cert expires.",
})

// --- 9-11. Store (Phase 7) ---

// StoreBytesByBucket tracks the meta:bytes:<bucket> totals as a gauge.
// Updated by the store package's eviction job + Put/Delete paths.
var StoreBytesByBucket = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Namespace: "beacon",
	Subsystem: "store",
	Name:      "bytes",
	Help:      "Current byte total per bbolt bucket.",
}, []string{"bucket"})

// StoreRecordsByBucket counts records per bucket. Same source as
// store.Count.
var StoreRecordsByBucket = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Namespace: "beacon",
	Subsystem: "store",
	Name:      "records",
	Help:      "Current record count per bbolt bucket.",
}, []string{"bucket"})

// StoreEvictionsTotal counts records evicted by bucket.
var StoreEvictionsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Namespace: "beacon",
	Subsystem: "store",
	Name:      "evictions_total",
	Help:      "Records evicted by bucket (configs is NEVER incremented by design).",
}, []string{"bucket"})

// --- 12-13. Sender (Phase 9) ---

// SenderDeliveredTotal counts records the sender shipped to the platform.
var SenderDeliveredTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Namespace: "beacon",
	Subsystem: "sender",
	Name:      "delivered_total",
	Help:      "Records successfully delivered to /api/v1/beacons/{id}/data/{type}.",
}, []string{"bucket"})

// SenderFailedTotal counts non-2xx responses from the platform by reason.
var SenderFailedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Namespace: "beacon",
	Subsystem: "sender",
	Name:      "failed_total",
	Help:      "Records the sender failed to deliver by reason.",
}, []string{"bucket", "reason"})

// --- 14-16. Collectors (Phase 9) ---

// CollectorReceivedTotal counts inbound records per collector.
var CollectorReceivedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Namespace: "beacon",
	Subsystem: "collector",
	Name:      "received_total",
	Help:      "Raw inbound records per collector (pre-parse, pre-persist).",
}, []string{"collector"})

// CollectorDroppedTotal counts records dropped because the worker
// queue was full (drop-on-full back-pressure).
var CollectorDroppedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Namespace: "beacon",
	Subsystem: "collector",
	Name:      "dropped_total",
	Help:      "Records dropped due to worker-queue back-pressure (D-6).",
}, []string{"collector"})

// CollectorParseFailedTotal counts records that survived enqueue but
// failed to parse (e.g., malformed syslog from a misconfigured device).
var CollectorParseFailedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Namespace: "beacon",
	Subsystem: "collector",
	Name:      "parse_failed_total",
	Help:      "Records the collector workers couldn't parse.",
}, []string{"collector"})

// --- 17. SSRF (M-9) ---

// SafedialRejectedTotal is the M-9 SSRF chokepoint counter. Each
// increment means a device-dial target hit the allow-list reject path —
// a configuration or attack signal.
var SafedialRejectedTotal = prometheus.NewCounter(prometheus.CounterOpts{
	Namespace: "beacon",
	Subsystem: "safedial",
	Name:      "rejected_total",
	Help:      "Device-IP dials rejected by the M-9 SSRF allow-list. Each increment is a config/attack signal.",
})

// --- 18. Build info ---

// BuildInfo is a static 1-valued gauge with version + commit labels.
// Mimics the standard Prometheus build_info convention.
var BuildInfo = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Namespace: "beacon",
	Subsystem: "",
	Name:      "build_info",
	Help:      "Static build metadata (version, commit). Always 1; the labels carry the info.",
}, []string{"version", "commit"})

// All bundles every metric so tests can iterate them.
var All = []prometheus.Collector{
	EnrollmentTotal, PollDurationSeconds, PollTotal, HeartbeatTotal,
	DEKVerifyFailedTotal, DEKVersion, CertRotationTotal, CertExpiresInSeconds,
	StoreBytesByBucket, StoreRecordsByBucket, StoreEvictionsTotal,
	SenderDeliveredTotal, SenderFailedTotal,
	CollectorReceivedTotal, CollectorDroppedTotal, CollectorParseFailedTotal,
	SafedialRejectedTotal, BuildInfo,
}

func init() {
	for _, c := range All {
		prometheus.MustRegister(c)
	}
}

// SetBuildInfo publishes the build labels once at startup.
func SetBuildInfo(version, commit string) {
	BuildInfo.WithLabelValues(version, commit).Set(1)
}
