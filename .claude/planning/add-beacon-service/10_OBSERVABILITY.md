# Observability: add-beacon-service

**Generated:** 2026-05-12
**Phase:** 9 — Observe
**Status:** Complete

---

## 1. Overview

The beacon binary is a long-running, unattended daemon on customer-controlled infrastructure.
Operators have no SSH tunnel into the host in most deployments; the only observability
surface they can scrape is the Prometheus `/metrics` endpoint at `127.0.0.1:9090` (or a
forwarded port). All 18 instruments are already implemented in `internal/metrics/registry.go`.
This document defines alert thresholds, dashboard layout, SLI/SLO targets, and the structured
log event catalogue so that downstream Grafana/Alertmanager configuration can be generated
directly from this spec.

---

## 2. RED Metrics (Service-Oriented)

The beacon acts as a client toward the platform on five RPC paths. RED metrics are expressed
as label subsets of the instruments already in code.

### 2.1 Enrollment

| Metric | Instrument | Labels |
|--------|-----------|--------|
| Rate | `beacon_enrollment_total` | `result={success,bundle_invalid,server_rejected,network,persist_failed}` |
| Errors | `beacon_enrollment_total{result!="success"}` | — |
| Duration | *(one-shot operation; no histogram needed post-enroll)* | — |

**Targets:**
- Success rate: 100% (enrollment is a one-shot setup; any failure is operator-action)
- Alert: any `result=server_rejected` or `result=persist_failed` → P2 ticket

### 2.2 Config Poll

| Metric | Instrument | Labels |
|--------|-----------|--------|
| Rate (cycles/min) | `rate(beacon_poll_total[1m])` | — |
| Errors | `beacon_poll_total{result="server_error"} + beacon_poll_total{result="network_error"}` | — |
| Duration p50/p95/p99 | `histogram_quantile(0.99, beacon_poll_duration_seconds_bucket)` | — |

**Targets (NFR-2):**
- p95 < 100 ms
- p99 < 500 ms
- Error rate < 1%
- Poll cycle should fire every 60 s ± 10 s; expected rate ≈ 1/min

### 2.3 Heartbeat

| Metric | Instrument | Labels |
|--------|-----------|--------|
| Rate | `rate(beacon_heartbeat_total[1m])` | `result` |
| Errors | `beacon_heartbeat_total{result!="success"}` | — |
| Duration | *(piggybacked on poll cycle; shared `beacon_poll_duration_seconds` histogram)* | — |

**Targets (NFR-3):**
- p95 < 200 ms
- Error rate < 1%

### 2.4 Data Send (Sender)

| Metric | Instrument | Labels |
|--------|-----------|--------|
| Rate (records/s) | `rate(beacon_sender_delivered_total[1m])` | `bucket` |
| Errors | `beacon_sender_failed_total` | `bucket, reason` |
| Duration | *(per-request timing surfaced via `beacon_poll_duration_seconds` for now; a `beacon_sender_duration_seconds` histogram is a follow-up instrument)* | — |

**Targets (NFR-4):**
- p95 per-POST round-trip < 500 ms for 5 MB body
- Failure rate < 0.1% of delivered records

### 2.5 Cert Rotation

| Metric | Instrument | Labels |
|--------|-----------|--------|
| Rate | `rate(beacon_cert_rotation_total[1h])` | `result` |
| Errors | `beacon_cert_rotation_total{result="failed"}` | — |
| Time-to-expiry | `beacon_cert_expires_in_seconds` | — |

**Targets (NFR-17):**
- Rotation must trigger at ≤ 80% of cert lifetime (ADR-067)
- `cert_expires_in_seconds` should never fall below 18 days without a rotation in flight
- Any rotation failure → P1 alert (beacon will lose mTLS connectivity when cert expires)

---

## 3. USE Metrics (Resource-Oriented)

### 3.1 Store (bbolt)

| Resource | Utilization | Saturation | Errors |
|----------|------------|------------|--------|
| Disk space | `beacon_store_bytes{bucket}` sum vs 5 GB cap | `beacon_store_evictions_total` rate | `beacon_sf_corruption_recovery_total` (follow-up instrument) |
| Record count | `beacon_store_records{bucket}` | Eviction rate > 100/min sustained | — |
| Age | *(surfaced via eviction reason label `age_cap`)* | `beacon_store_evictions_total{reason="age_cap"}` | — |

**Targets (NFR-7):**
- Total store bytes < 5 GB
- Alert when bytes > 4 GB (80% of cap): operator investigation
- Alert when `beacon_store_evictions_total{reason="both"}` increments (store saturated on BOTH caps simultaneously)

### 3.2 CPU / Memory

| Resource | Utilization | Saturation | Errors |
|----------|------------|------------|--------|
| CPU | `rate(process_cpu_seconds_total[1m])` | > 25% of 1 core at heavy load (NFR-9) | — |
| Memory | `process_resident_memory_bytes` | > 200 MB (NFR-6) | OOM → daemon restart |
| Goroutines | `go_goroutines` | > 500 unexpected goroutine leak | — |

### 3.3 Syslog Ingest (Collector)

These surface via the `Stats()` struct in `internal/collectors/syslog/server.go`.
They are currently **not Prometheus-instrumented** — they are candidates for three
follow-up instruments (see §8 Follow-up Instruments).

| Resource | Current Surface | Alert Condition |
|----------|----------------|----------------|
| Oversized lines dropped | `server.Stats().OversizedDropped` | > 100/min → device misconfiguration |
| TCP connections rejected | `server.Stats().ConnsRejected` | > 10/5min → possible SYN flood |
| Worker panics | `server.Stats().WorkerPanics` | > 0 → P1 bug signal |

### 3.4 Syslog Back-pressure

| Resource | Instrument | Alert Condition |
|----------|-----------|----------------|
| Drop rate | `beacon_collector_dropped_total{collector="syslog"}` rate | > 1% of received rate → queue undersized |
| Parse failures | `beacon_collector_parse_failed_total{collector="syslog"}` rate | > 5% of received rate → malformed input |

### 3.5 Security Chokepoints (USE as Attack Surface)

| Resource | Instrument | Alert Condition |
|----------|-----------|----------------|
| SSRF rejects | `beacon_safedial_rejected_total` | Any increment → investigate device config or active SSRF probe |
| DEK verify failures | `beacon_dek_verify_failed_total` | Any increment → P1 (possible man-in-middle or key rotation bug) |

---

## 4. Business Metrics

| Metric | Instrument | Baseline | Alert Threshold |
|--------|-----------|----------|----------------|
| Platform connectivity (poll success rate) | `rate(beacon_poll_total{result="modified"}[5m]) + rate(beacon_poll_total{result="not_modified"}[5m])` | ~1/min | < 0.5/min for 10 min → P2 |
| Data pipeline throughput | `rate(beacon_sender_delivered_total[5m])` | Varies by site | < 50% of prior-7d avg for 30 min → P2 |
| Store accumulation (backpressure proxy) | `beacon_store_records{bucket="logs"}` | < 10k steady state | > 100k records any bucket for 30 min → P2 |
| DEK version currency | `beacon_dek_version` | Matches platform | Stuck at same value for > 7d → P3 (check rotation health) |

---

## 5. Structured Log Event Catalogue

All log events use `log/slog` structured JSON via the H-3 redactor middleware
(`internal/log/redactor.go`). Format: `logger.Info/Warn/Error(message, key, val, ...)`.

Redacted fields (never appear in output): `bootstrap_token`, `dek`, `data_key_b64`,
`csr_pem`, `beacon_key`, `private_key`, `Authorization`, `nbb_[A-Za-z0-9_-]{16,}`.

### 5.1 Enrollment Events

| Event Message | Level | Key Fields | When |
|---------------|-------|-----------|------|
| `enroll.bundle_parsed` | INFO | `beacon_id`, `expires_at`, `server_url` | Bundle decoded and signature verified |
| `enroll.csr_generated` | INFO | `key_algo`, `common_name` | ECDSA-P256 CSR created |
| `enroll.enrolled` | INFO | `beacon_id`, `cert_expiry` | Platform responded 201; files written |
| `enroll.already_enrolled` | WARN | `beacon_id`, `force` | Double-enroll guard; `--force` overrides |
| `enroll.bundle_invalid` | ERROR | `reason` | Signature bad / expired / parse failure |
| `enroll.server_rejected` | ERROR | `status_code`, `error_code` | Platform returned 4xx |
| `enroll.persist_failed` | ERROR | `file`, `error` | Atomic-write to state-dir failed |
| `enroll.bundle_file_perm_warn` | WARN | `path`, `mode` | Bundle file is world-readable (> 0600) |
| `enroll.bundle_flag_ps_leak` | WARN | — | `--bundle` used instead of `--bundle-file`; bootstrap token in ps |

### 5.2 Daemon / Config Poll Events

| Event Message | Level | Key Fields | When |
|---------------|-------|-----------|------|
| `daemon.started` | INFO | `version`, `commit`, `state_dir`, `beacon_id` | Daemon goroutines started |
| `daemon.poll_ok` | INFO | `modified`, `etag`, `duration_ms` | Successful poll (200 or 304) |
| `daemon.poll_error` | WARN | `error`, `backoff_seconds` | Network or server error; will retry |
| `daemon.config_applied` | INFO | `collectors_enabled`, `config_hash` | New config from platform applied |
| `daemon.dek_rotated` | INFO | `new_version` | DEK rotation accepted after M-11 verify |
| `daemon.dek_signature_verify_failed` | ERROR | `dek_version`, `reason` | M-11 fail-closed event; old DEK retained |
| `daemon.heartbeat_ok` | INFO | `duration_ms` | Heartbeat POST 2xx |
| `daemon.heartbeat_error` | WARN | `status_code`, `error` | Heartbeat failed |
| `daemon.shutting_down` | INFO | `reason` | SIGINT/SIGTERM received |
| `daemon.shutdown_complete` | INFO | `elapsed_ms` | Graceful drain done |

### 5.3 Cert Rotation Events

| Event Message | Level | Key Fields | When |
|---------------|-------|-----------|------|
| `cert.rotation_triggered` | INFO | `reason`, `lifetime_remaining_pct` | 80% threshold crossed or server recommends |
| `cert.rotation_ok` | INFO | `new_expiry`, `duration_ms` | Atomic rotation complete |
| `cert.rotation_failed` | ERROR | `reason`, `error` | Any rotation failure; old cert still active |
| `cert.rotation_in_flight` | INFO | — | Concurrent rotation attempt coalesced |
| `cert.recovery_used_slot` | WARN | `slot` | LoadCertPairWithRecovery fell back to `.new` or `.prev` |
| `cert.expires_soon` | WARN | `expires_in_hours` | < 18-day warning (NFR-17) |

### 5.4 Store Events

| Event Message | Level | Key Fields | When |
|---------------|-------|-----------|------|
| `store.opened` | INFO | `path`, `schema_version` | bbolt opened successfully |
| `store.corrupt_rotated` | ERROR | `old_path`, `new_path` | Corruption detected; fresh store created |
| `store.eviction_run` | INFO | `reason`, `bytes_freed`, `records_freed`, `duration_ms` | Janitor ran |
| `store.eviction_all_capped` | ERROR | `total_bytes`, `oldest_age_days` | Even after flows+logs+snmp eviction, cap not met |

### 5.5 Sender Events

| Event Message | Level | Key Fields | When |
|---------------|-------|-----------|------|
| `sender.batch_delivered` | INFO | `bucket`, `records`, `duration_ms` | Batch POST 2xx |
| `sender.record_failed` | WARN | `bucket`, `reason`, `action` | Non-2xx response; reason from `transport.Classify` |
| `sender.back_off` | WARN | `bucket`, `backoff_seconds` | ActionBackOff* received |
| `sender.reenroll_required` | ERROR | `bucket`, `error_code` | ActionFatalReenroll; operator must re-enroll |

### 5.6 Syslog Collector Events

| Event Message | Level | Key Fields | When |
|---------------|-------|-----------|------|
| `syslog.listener_started` | INFO | `udp_addr`, `tcp_addr` | Both listeners bound |
| `syslog.tcp_conn_accepted` | DEBUG | `remote_addr` | TCP connection accepted into semaphore |
| `syslog.tcp_conn_rejected` | WARN | `remote_addr` | Semaphore full; SY-2 protection |
| `syslog.line_oversized` | WARN | `remote_addr`, `max_bytes` | Line exceeded MaxLineBytes; SY-1 protection |
| `syslog.worker_panic` | ERROR | `recover_value` | Worker goroutine panicked; SY-3 recovery |
| `syslog.parse_failed` | WARN | `raw_prefix` | Syslog line not RFC3164 or RFC5424 |

### 5.7 Metrics Server Events

| Event Message | Level | Key Fields | When |
|---------------|-------|-----------|------|
| `metrics.started` | INFO | `addr` | `/metrics` listener bound |
| `metrics.non_loopback_bind` | WARN | `addr` | M-1: bind address is not 127.0.0.1 |
| `metrics.disabled` | INFO | — | `--no-metrics` flag set |

### 5.8 SSRF / Security Events

| Event Message | Level | Key Fields | When |
|---------------|-------|-----------|------|
| `safedial.rejected` | WARN | `host`, `resolved_ip`, `reason` | M-9 SSRF allow-list reject |

---

## 6. Alerting Rules

All rules reference the Prometheus beacon job. Runbook links use the canonical path
`docs/runbooks/beacon-operations.md#<anchor>`.

### 6.1 P1 Alerts (Page On-call)

| Alert Name | Condition | For | Severity | Action |
|-----------|-----------|-----|----------|--------|
| `BeaconDEKVerifyFailed` | `increase(beacon_dek_verify_failed_total[5m]) > 0` | immediate | P1 / critical | Possible MITM or platform key rotation bug. Check beacon and platform logs. See runbook §[dek-rotation-failures](docs/runbooks/beacon-operations.md#dek-rotation-failures). |
| `BeaconCertRotationFailed` | `increase(beacon_cert_rotation_total{result="failed"}[10m]) > 2` | 5m | P1 / critical | mTLS will break when cert expires. Escalate. See runbook §[cert-rotation-failure](docs/runbooks/beacon-operations.md#cert-rotation-failure). |
| `BeaconCertExpiresCritical` | `beacon_cert_expires_in_seconds < 86400 * 3` | 30m | P1 / critical | Cert expires within 3 days and rotation has not succeeded. See runbook §[cert-rotation-failure](docs/runbooks/beacon-operations.md#cert-rotation-failure). |
| `BeaconStoreCorruptionRecovered` | `increase(beacon_sf_corruption_recovery_total[1m]) > 0` *(follow-up instrument)* | immediate | P1 / critical | bbolt file was corrupt and rotated; data loss may have occurred. Preserve `.corrupt` file for forensics. See runbook §[corrupt-bbolt-recovery](docs/runbooks/beacon-operations.md#corrupt-bbolt-recovery). |
| `BeaconSenderReenrollRequired` | `beacon_sender_reenroll_required_total > 0` *(follow-up instrument)* | immediate | P1 / critical | Platform rejected beacon identity. Operator must re-enroll. See runbook §[re-enroll](docs/runbooks/beacon-operations.md#re-enroll). |

### 6.2 P2 Alerts (Notify Channel)

| Alert Name | Condition | For | Severity | Action |
|-----------|-----------|-----|----------|--------|
| `BeaconPollDown` | `rate(beacon_poll_total[5m]) < 0.5` | 10m | P2 / warning | Platform connectivity lost. Check network and platform health. See runbook §[daemon-connectivity](docs/runbooks/beacon-operations.md#troubleshoot-daemon). |
| `BeaconCertExpiresWarning` | `beacon_cert_expires_in_seconds < 86400 * 18` | 1h | P2 / warning | Cert within 18-day rotation window (NFR-17). Monitor rotation progress. |
| `BeaconStoreHighWatermark` | `sum(beacon_store_bytes) > 4 * 1024 * 1024 * 1024` | 30m | P2 / warning | Store above 4 GB (80% of 5 GB cap). Sender may be blocked. Check platform egress. See runbook §[sf-inspection](docs/runbooks/beacon-operations.md#sf-inspection). |
| `BeaconStoreEvictingBoth` | `rate(beacon_store_evictions_total{reason="both"}[10m]) > 0` | 5m | P2 / warning | Store hit both size AND age caps simultaneously. Operator investigation required. |
| `BeaconSenderHighFailureRate` | `rate(beacon_sender_failed_total[5m]) / rate(beacon_sender_delivered_total[5m]) > 0.05` | 10m | P2 / warning | > 5% of send attempts failing. Check platform availability and DEK health. |
| `BeaconCollectorHighDropRate` | `rate(beacon_collector_dropped_total[5m]) / rate(beacon_collector_received_total[5m]) > 0.01` | 10m | P2 / warning | > 1% of inbound records dropped due to back-pressure. Worker pool may be undersized. |
| `BeaconSSRFRejectSurge` | `rate(beacon_safedial_rejected_total[5m]) > 10` | 5m | P2 / warning | SSRF rejects above 10/5min. Possible device misconfiguration or active attack probe. |

### 6.3 P3 Alerts (Informational — Ticketing Only)

| Alert Name | Condition | For | Severity | Action |
|-----------|-----------|-----|----------|--------|
| `BeaconDEKVersionStale` | `time() - beacon_dek_rotation_last_timestamp > 7 * 86400` *(follow-up instrument)* | 1h | P3 / info | DEK has not rotated in 7 days. Verify platform rotation schedule. |
| `BeaconHighMemory` | `process_resident_memory_bytes > 200 * 1024 * 1024` | 30m | P3 / info | RSS > 200 MB (NFR-6). Investigate goroutine/bbolt mmap leak. |
| `BeaconCollectorParseFailed` | `rate(beacon_collector_parse_failed_total[10m]) > 5` | 10m | P3 / info | > 5 parse failures/min. Indicates device sending malformed syslog. |

---

## 7. Dashboard Specification

### Dashboard: NetBrain Beacon — `beacon-overview`

**Data Source:** Prometheus (beacon job, label `instance=<host>`)
**Refresh:** 30s
**Variables:** `instance` (multi-select, all beacon hosts)

---

#### Row 1: Health Overview

| Panel | Type | Query | Threshold Bands |
|-------|------|-------|----------------|
| Platform connectivity (poll/min) | Stat | `rate(beacon_poll_total[1m]) * 60` | Green ≥ 0.9, Yellow < 0.9, Red = 0 |
| Poll error rate (%) | Stat | `100 * rate(beacon_poll_total{result=~"server_error|network_error"}[5m]) / rate(beacon_poll_total[5m])` | Green < 1%, Yellow < 5%, Red ≥ 5% |
| Poll p99 latency | Stat | `histogram_quantile(0.99, rate(beacon_poll_duration_seconds_bucket[5m]))` | Green < 0.5s, Yellow < 2s, Red ≥ 2s |
| Last poll result | State Timeline | `beacon_poll_total` label `result` | Color by label |
| Sender delivered (records/s) | Time Series | `rate(beacon_sender_delivered_total[1m])` | — |
| Sender failure rate | Time Series | `rate(beacon_sender_failed_total[1m])` | Red fill on any value |

---

#### Row 2: Data Pipeline

| Panel | Type | Query | Notes |
|-------|------|-------|-------|
| Store bytes by bucket | Time Series (stacked) | `beacon_store_bytes{bucket=~"flows|logs|snmp|configs"}` | Dotted line at 5 GB cap |
| Store records by bucket | Time Series (stacked) | `beacon_store_records` | — |
| Evictions by bucket | Time Series | `rate(beacon_store_evictions_total[5m])` | — |
| Syslog received vs dropped | Time Series | `rate(beacon_collector_received_total{collector="syslog"}[1m])` + `rate(beacon_collector_dropped_total{collector="syslog"}[1m])` | Drop line red |
| Syslog parse failures | Stat | `rate(beacon_collector_parse_failed_total{collector="syslog"}[5m])` | — |
| Delivery backlog estimate | Stat | `beacon_store_records{bucket="logs"}` | Yellow > 50k, Red > 100k |

---

#### Row 3: Security Posture

| Panel | Type | Query | Notes |
|-------|------|-------|-------|
| DEK verify failures | Stat (last value) | `beacon_dek_verify_failed_total` | Red if > 0 ever |
| DEK version | Stat | `beacon_dek_version` | Informational |
| Cert expires in | Stat | `beacon_cert_expires_in_seconds / 86400` (days) | Red < 3d, Yellow < 18d |
| Cert rotation outcomes | Bar Chart | `increase(beacon_cert_rotation_total[24h])` label `result` | — |
| SSRF rejects | Time Series | `rate(beacon_safedial_rejected_total[5m])` | Red fill on any value |
| Build info | Table | `beacon_build_info` | Static: version + commit |

---

#### Row 4: Infrastructure

| Panel | Type | Query | Notes |
|-------|------|-------|-------|
| Memory RSS | Time Series | `process_resident_memory_bytes / 1024 / 1024` (MiB) | Dotted line at 200 MB |
| CPU rate | Time Series | `rate(process_cpu_seconds_total[1m])` | Dotted line at 25% (0.25) |
| Goroutines | Time Series | `go_goroutines` | Yellow > 300, Red > 500 |
| GC pause p99 | Time Series | `histogram_quantile(0.99, rate(go_gc_duration_seconds_bucket[5m]))` | — |

---

## 8. SLI / SLO Definitions

| SLI | SLO | Window | Measurement |
|-----|-----|--------|------------|
| Platform poll availability | ≥ 99.5% successful polls in any 24-hour window | rolling 24h | `rate(beacon_poll_total{result=~"modified|not_modified"}[24h]) / rate(beacon_poll_total[24h])` |
| Config poll latency | p99 < 500 ms | rolling 1h | `histogram_quantile(0.99, rate(beacon_poll_duration_seconds_bucket[1h]))` |
| Data delivery success rate | ≥ 99.9% of delivered records acknowledged | rolling 24h | `rate(beacon_sender_delivered_total[24h]) / (rate(beacon_sender_delivered_total[24h]) + rate(beacon_sender_failed_total[24h]))` |
| Cert rotation success | 100% of rotation attempts succeed (retries within 1h) | per-event | `beacon_cert_rotation_total{result="failed"}` stays 0 between scheduled rotations |
| M-11 DEK security | 0 unmitigated verify failures | all-time | `beacon_dek_verify_failed_total` increments trigger P1 human review |
| M-9 SSRF protection | 100% of forbidden-range dials rejected | all-time | `beacon_safedial_rejected_total` count vs forbidden-range probe results |
| Store within capacity | Total store < 5 GB at end of each 24h window | rolling 24h | `sum(beacon_store_bytes)` < 5e9 |
| Graceful shutdown | SIGTERM → clean exit ≤ 30 s | per-event | `daemon.shutdown_complete` elapsed_ms field |

**Error budget:** The 99.5% poll availability SLO gives a 43.8 min/day error budget (0.5% of 1440 min).
Alertmanager fires P2 when the instantaneous rate drops to 0.5/min for 10 min — that consumes ~8% of
the daily budget before the alert fires, leaving runway for investigation.

---

## 9. Follow-up Instruments (Not Yet Implemented)

These three syslog `Stats()` fields and two additional counters are strong candidates for
Prometheus promotion in a follow-up issue (`add-beacon-syslog-metrics`):

| Proposed Instrument | Type | Labels | Source |
|--------------------|------|--------|--------|
| `beacon_syslog_oversized_total` | Counter | — | `server.Stats().OversizedDropped` |
| `beacon_syslog_conns_rejected_total` | Counter | — | `server.Stats().ConnsRejected` |
| `beacon_syslog_worker_panics_total` | Counter | — | `server.Stats().WorkerPanics` |
| `beacon_sf_corruption_recovery_total` | Counter | — | `store.Open` rotate-and-resume path |
| `beacon_sender_reenroll_required_total` | Counter | — | `sender` on `ActionFatalReenroll` |
| `beacon_dek_rotation_last_timestamp` | Gauge (Unix seconds) | — | successful M-11 accept in daemon |

Until these are promoted, the relevant log events (`store.corrupt_rotated`,
`syslog.tcp_conn_rejected`, `syslog.worker_panic`) serve as the alert signal via
Loki log-count alerting rules.

---

## 10. Loki Log-Based Alerts (Complement to Prometheus)

For deployments where beacon hosts ship logs to the platform's Loki instance,
these LogQL rules cover the follow-up instruments that aren't yet Prometheus counters.

```logql
# P1: bbolt corruption
count_over_time({app="netbrain-beacon"} |= "store.corrupt_rotated"[5m]) > 0

# P1: Syslog worker panic
count_over_time({app="netbrain-beacon"} |= "syslog.worker_panic"[5m]) > 0

# P2: TCP connection rejections surge
count_over_time({app="netbrain-beacon"} |= "syslog.tcp_conn_rejected"[5m]) > 10

# P2: Oversized line drops
count_over_time({app="netbrain-beacon"} |= "syslog.line_oversized"[10m]) > 100
```

---

## 11. Scrape Configuration

Prometheus scrape config for the beacon `/metrics` endpoint.
The beacon binds to `127.0.0.1:9090` by default; operators who need remote scraping
must use a Prometheus push-gateway or a forwarding agent (see runbook §[metrics-endpoint-security](docs/runbooks/beacon-operations.md#metrics-endpoint-security)).

```yaml
# prometheus.yml snippet (operator side — runs at NetBrain SaaS)
scrape_configs:
  - job_name: 'netbrain-beacon'
    scrape_interval: 30s
    scrape_timeout: 10s
    static_configs:
      - targets: ['<beacon-host>:<forwarded-port>']
        labels:
          site: '<customer-site-id>'
          beacon_id: '<beacon-uuid>'
    # If forwarded over mTLS push-gateway:
    # tls_config:
    #   cert_file: /etc/prometheus/beacon-client.crt
    #   key_file: /etc/prometheus/beacon-client.key
    #   ca_file: /etc/prometheus/platform-ca.pem
```

---

## 12. Cross-Repo Dashboards

This document defines the **beacon-side** observability surface (`beacon_*` metrics on `127.0.0.1:9090`).

The **platform-side** complement lives in the netbrain repo at `monitoring/grafana/dashboards/`:

| Dashboard | UID | Purpose |
|-----------|-----|---------|
| `netbrain-beacon-protocol` | `beacon-protocol.json` | Platform-SRE view of the multi-mode ingestion path (`netbrain_beacon_*` from api-gateway). Pre-existing from `add-multi-mode-ingestion`. |
| `netbrain-beacon-fleet-status` | `beacon-fleet-status.json` | **NEW (added with this issue):** Tenant-facing fleet view. Velonet (main tenant) uses this to see at-a-glance how their registered beacons are doing — enrollment activity, per-tenant data push success, security signal counters, per-type latency. Includes a "follow-up" row reserving panels for the `add-beacon-fleet-exporter` issue (DB-backed `netbrain_beacon_fleet_*` gauges). |

The full observability story spans **three** scrape targets:

1. **api-gateway** (`netbrain_beacon_*`) — request-handler metrics from the platform's perspective.
2. **beacon binary** (`beacon_*`) — per-host metrics from each registered beacon's `/metrics`.
3. **fleet exporter** (`netbrain_beacon_fleet_*`) — DB-backed fleet-state gauges (follow-up).

---

*Next step: `/retro add-beacon-service`*