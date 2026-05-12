# ADR-006: Collector goroutine model

**Status:** Accepted
**Date:** 2026-05-10
**Context issue:** add-beacon-service
**Companion:** ADR-071 (parent — store-and-forward), ADR-002 (bbolt schema), D-6 (locked pool sizes)

## Context

The beacon hosts 4 collectors with very different load shapes:

| Collector | Burst pattern | Steady-state rate | Per-record cost |
|---|---|---|---|
| **syslog** | high-bursty (alert storms; firmware upgrades) | 1k-10k msg/s | parse + 200 bytes write |
| **netflow** | medium-steady (constant flow rate from edge devices) | 1k-10k flows/s | parse + 100 bytes write |
| **snmp** | scheduled (every 5 min, fan-out across devices) | 0 → N spike then idle | poll + ~5 KB response |
| **configs** | occasional (daily / on-demand) | < 1/s | SSH + 10-100 KB |

A single shared worker pool would let one slow collector starve the others — e.g., a 30-second SSH config pull blocks syslog drainage. Conversely, **unbounded** queues per collector would OOM the beacon under a syslog burst.

Three design questions:

1. **Per-collector pools or shared pool?** Per-collector (otherwise head-of-line blocking).
2. **Pool sizes and queue depths?** Locked at D-6 (research): syslog=8w/1000q, netflow=4w/500q, snmp=16w/200q, configs=4w/100q.
3. **Back-pressure response?** Drop-with-counter (Vector pattern) vs block-and-fail (Telegraf pattern). Beacon goes drop-with-counter to keep the listener responsive.

The bbolt write path is shared among all collectors and serializes naturally on the bbolt write lock (R-3). Collectors must NOT call bbolt directly — they push through a bounded channel to a single writer goroutine that batches commits.

## Decision

Each collector owns its own goroutine pool with a bounded channel, drop-on-full back-pressure, and a `Drain()` lifecycle method. All collectors write through a shared `internal/store` channel to a single writer goroutine.

### Pool sizing (D-6, locked)

| Collector | Workers | Queue depth | Rationale |
|---|---|---|---|
| **syslog** | 8 | 1000 | Bursts at 10k msg/s; 8 workers each parsing at ~5k msg/s = 40k/s ceiling; 1000-record queue absorbs ~100 ms burst. |
| **netflow** | 4 | 500 | Steady ~5k flows/s; 4 workers ample; 500-record queue covers nfcapd file-rotation interval. |
| **snmp** | 16 | 200 | High fan-out (one device = one connection, gosnmp not goroutine-safe — R-4); 16 workers serialize 1k-device fleet at ~3 min/device. |
| **configs** | 4 | 100 | Low rate; SSH cost dominates — 4 concurrent SSH sessions max to avoid hammering devices. |

These are **defaults**; a small subset is tunable per `BeaconConfig` field but exposed cautiously (operators who tune badly hurt themselves).

### Architecture

```
Per-collector layout (e.g., syslog):

  raw input (UDP 514 / TCP 1514)
        │
        ▼
   listener goroutine ──► record-channel (buffered, 1000 cap)
                                │
                                ▼
   worker pool (8 goroutines):  Parse → Validate → Build Record{...}
        │
        ▼
   shared collectors-out-channel (buffered, 100 cap)
        │
        ▼
   single writer goroutine ──► bbolt batch commit (≤64 KB or ≤100 records)
                                │
                                ▼
   single sender goroutine ◄── reads bbolt cursor → encrypt → mTLS POST
                                │
                                ▼
                              204 → bbolt Delete batch + cursor advance
```

### Collector interface

```go
package collectors

type Collector interface {
    Name() string
    Start(ctx context.Context, out chan<- Record) error
    Drain(ctx context.Context) error
    Status() Status   // for admin CLI + heartbeat
}

type Record struct {
    UUIDv7    [16]byte
    Type      string  // "logs" / "flows" / "snmp" / "configs"
    Plaintext []byte
    DeviceIP  string
}

type Status struct {
    State                string  // "running" / "degraded" / "stopped"
    QueueDepth           int
    LastSuccessAt        time.Time
    DroppedRecordsTotal  uint64
    InputErrorsTotal     uint64
}
```

### Worker pool implementation pattern

```go
// Common pattern — every collector has one of these:
type Pool struct {
    name      string
    workers   int
    queue     chan rawInput   // bounded
    out       chan<- Record
    metrics   *Metrics
    parse     func(rawInput) (Record, error)
}

func (p *Pool) Start(ctx context.Context) error {
    for i := 0; i < p.workers; i++ {
        go p.worker(ctx)
    }
    return nil
}

func (p *Pool) Submit(r rawInput) {
    select {
    case p.queue <- r:
        // accepted
    default:
        // full → drop with counter
        p.metrics.DroppedRecordsTotal.Inc()
    }
}

func (p *Pool) worker(ctx context.Context) {
    for {
        select {
        case <-ctx.Done():
            return
        case raw := <-p.queue:
            rec, err := p.parse(raw)
            if err != nil {
                p.metrics.InputErrorsTotal.Inc()
                continue
            }
            select {
            case p.out <- rec:
            case <-ctx.Done():
                return
            }
        }
    }
}

func (p *Pool) Drain(ctx context.Context) error {
    // Stop accepting (handled by listener); drain queue with deadline.
    deadline := time.NewTimer(10 * time.Second)
    defer deadline.Stop()
    for {
        select {
        case <-deadline.C:
            return errors.New("drain deadline exceeded")
        default:
            if len(p.queue) == 0 {
                return nil
            }
            time.Sleep(50 * time.Millisecond)
        }
    }
}
```

### Back-pressure semantics (drop, don't block)

When the queue is full:

1. **Listener** (UDP/TCP receive path) does a non-blocking send via `select { case ch <- x: default: drop }`.
2. **Drop counter** increments — `netbrain_beacon_sf_collector_drops_total{type=syslog}`.
3. **Listener stays responsive** — never blocks the OS receive buffer.

Rationale: syslog UDP packets are best-effort by protocol; dropping at the application layer when overwhelmed is more graceful than blocking the receive path (which fills the kernel buffer and triggers `recvfrom` ENOBUFS).

For netflow / SNMP / configs, the same pattern applies — the upstream is rate-limited by its own clock or by the device side, so application-layer drops are visible and recoverable.

### Shared writer goroutine

```go
// internal/store/writer.go (sketch)

func (s *Store) writerLoop(ctx context.Context, in <-chan Record) {
    batch := make([]Record, 0, 100)
    bytesAcc := 0
    flushTimer := time.NewTimer(5 * time.Second)
    flush := func() {
        if len(batch) == 0 { return }
        if err := s.commit(batch); err != nil {
            metrics.BboltCommitErrors.Inc()
            // retain batch — bbolt may recover (e.g., transient ENOSPC)
            return
        }
        batch = batch[:0]
        bytesAcc = 0
    }
    for {
        select {
        case <-ctx.Done():
            flush()
            return
        case rec := <-in:
            batch = append(batch, rec)
            bytesAcc += len(rec.Plaintext)
            if bytesAcc >= 64*1024 || len(batch) >= 100 {
                flush()
                flushTimer.Reset(5 * time.Second)
            }
        case <-flushTimer.C:
            flush()
            flushTimer.Reset(5 * time.Second)
        }
    }
}
```

Single writer keeps bbolt's exclusive write lock contention to one goroutine; batching amortizes fsync over up to 100 records.

### Graceful shutdown sequence

On `SIGTERM`:

```
1. Cancel root context.
2. Each collector's listener stops accepting (closes UDP/TCP listener).
3. Each collector's `Drain(ctx)` waits up to 10 s for queue to empty.
4. The shared writer goroutine flushes its current batch.
5. The sender goroutine finishes its in-flight HTTP request (60-s timeout).
6. bbolt `db.Close()` runs as a top-level defer in `daemon.Run()`.
7. Process exit 0 within 30 s wall clock.
```

If any step exceeds its deadline, log + force-exit with non-zero code; bbolt's MVCC+checksum recovery handles the dirty-write case on next start.

## Alternatives considered

### Alt A: Single shared worker pool

- Pros: simpler; fewer goroutines.
- Cons: head-of-line blocking — a slow SSH config pull blocks syslog drain.
- **Rejected.** Predictable per-collector behavior matters more than goroutine count.

### Alt B: Unbounded queues

- Pros: no drops.
- Cons: OOM on syslog burst; latency unbounded; no backpressure visibility.
- **Rejected.** Drops with counters are observable; OOM isn't.

### Alt C: Block on full queue (Telegraf pattern)

- Pros: no data loss at this layer.
- Cons: blocks the upstream listener (kernel buffer overflow → kernel-level drops we can't measure).
- **Rejected.** Application-layer drops are observable; kernel-layer drops are silent.

### Alt D: Sized pool driven by `runtime.NumCPU()`

- Pros: scales with hardware.
- Cons: D-6's per-collector reasoning is shaped by **load profile**, not CPU count. SNMP wants 16 workers because of fan-out + thread-unsafety, not CPU.
- **Rejected.** Load-shape-driven sizing is correct.

### Alt E: Queue per source IP (per-device fairness)

- Pros: no single device starves others.
- Cons: O(devices) queues; complicates eviction; rare in practice (devices are typically symmetric).
- **Rejected** for v1. Revisit if a customer reports per-device starvation.

## Consequences

### Positive

- Predictable memory ceiling: `Σ(workers × per-worker memory) + Σ(queue_depth × avg-record-size)` ≈ 100 MB worst case.
- Per-collector visibility via metrics.
- One slow collector cannot affect others.
- Graceful shutdown bounded at 30 s.

### Negative

- More goroutines (≈40 total: 8+4+16+4 collector workers + 4 listeners + 1 writer + 1 sender + 1 probe + 1 config-poll + 1 metrics + 1 admin + 1 janitor). 40 goroutines is small; Go runtime handles 100k easily.
- Drop-with-counter means under sustained overload, data is lost. Documented; surfaced via `sf_collector_drops_total` alert.
- D-6 numbers are defaults; tuning requires re-justifying in a runbook entry.

### Operational

- Alert: `rate(netbrain_beacon_sf_collector_drops_total[5m]) > 0` for > 10 min → warning ("collector overloaded").
- Heartbeat reports `queue_depths.{type}` so the platform side sees per-collector pressure.
- Runbook §"Tuning collector pools": when to bump workers / queue depths; warning that doing so without understanding R-3 (bbolt fsync) makes things worse.

## Acceptance criteria

- `internal/collectors/{syslog,netflow,snmp,configs}/pool.go` each implement the pattern above.
- Race detector test: 1k concurrent submits + 1 drain → no races, no panics.
- Load test: 50k syslog/s for 60 s — workers keep up, drops < 0.1%.
- Shutdown test: SIGTERM during heavy load → process exits within 30 s, queue counters reflect drops + drains accurately.
- D-6 numbers are encoded as named constants in `internal/collectors/defaults.go` with comments referencing this ADR.
