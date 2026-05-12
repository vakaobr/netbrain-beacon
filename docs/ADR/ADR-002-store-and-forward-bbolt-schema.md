# ADR-002: Store-and-forward bbolt schema

**Status:** Accepted
**Date:** 2026-05-10
**Context issue:** add-beacon-service
**Companion:** ADR-071 (parent contract — store-and-forward semantics), ADR-006 (collector goroutine model)
**Pairs with:** [netbrain/ADR/ADR-078-store-and-forward-bbolt-schema.md](https://github.com/velonet/netbrain/blob/main/ADR/ADR-078-store-and-forward-bbolt-schema.md) — same architectural decision, netbrain canonical numbering.

## Security: plaintext at rest

Records in the bbolt file are stored **plaintext** until the sender
encrypts them at egress time. A local-root attacker on the beacon host
can read buffered telemetry. This is a documented architectural choice
(see runbook §"Security model: host trust assumptions"); the threat
model assumes the operator trusts root on the beacon host. For low-trust
hosts, add full-disk encryption + SELinux/AppArmor confinement per the
runbook's "Hardening guidance for low-trust hosts" section. /security
audit 07a tracks this as ST-1.

## Context

ADR-071 (parent) mandates:

- 5 GB OR 14 d cap on the on-disk buffer, whichever first.
- Priority eviction: `flows → logs → snmp → never configs`.
- 2× normal pacing during replay.
- Records keyed by `uuidv7` for FIFO via natural sort order.
- Single-file embedded store; bbolt v1.4.1+ named.

The Go side (this issue) must define the concrete bbolt schema: bucket layout, key format, value format, metadata layout, eviction algorithm, recovery protocol.

The schema must:

1. Allow O(1) cursor advancement during replay (bbolt's `Cursor.Seek` + `Next` is ordered by key — UUIDv7 keys are time-ordered, so this works).
2. Allow O(buckets) eviction without rewriting unaffected buckets (bbolt's per-bucket isolation gives us this for free).
3. Track `bytes_total per bucket` cheaply so the eviction janitor doesn't need to walk every record to decide whether the cap is breached.
4. Survive process kill mid-write (bbolt's MVCC + checksums handle this; we add a recovery sentinel for catastrophic corruption).
5. Allow schema migration in the future (add `meta:schema_version` from day 1).

D-5 locked the key choice to UUIDv7 over (timestamp + counter):

- UUIDv7 sub-µs collision safe (random low bits) — important under bursts.
- Time-ordered (high 48 bits = ms since epoch) — gives FIFO for free.
- Single 16-byte key per record; uint64+counter would be 16 bytes also (8+8) and require us to maintain the counter atomic.

## Decision

The schema lives in `beacon-state.bbolt`, a single bbolt file with five top-level buckets:

```
beacon-state.bbolt
├── flows        — key: 16-byte UUIDv7, value: encoded Record (see §"Value format")
├── logs         — same shape
├── snmp         — same shape
├── configs      — same shape (NEVER evicted per ADR-071)
└── meta         — well-known keys (see §"Meta bucket")
```

### Value format

Each data-bucket value is a length-prefixed varint-encoded blob:

```
+--1B--+--1B--+--N--+
| ver  | dek_v| body|
+------+------+-----+
```

- `ver` = 0x01 (schema version of the record). Beacon rejects open if any record has `ver != 0x01`.
- `dek_v` = the DEK version that should be used to encrypt this record on egress. Recorded **at S&F-write time**, not encrypt time, so DEK rotation during replay uses the version captured at ingest.
- `body` = the raw plaintext payload (un-encrypted in S&F; mTLS protects in-flight, file ACL protects at-rest, full-disk encryption protects beyond that). Encryption happens at egress in `internal/transport/sender.go`. Storing plaintext avoids the cost of encrypting twice if the DEK rotates between write and send.

Rationale for plaintext-at-rest (vs encrypt-on-write): the S&F file is 0600, on a managed disk; encryption at this layer would (a) double-encrypt if the DEK is the same as egress, (b) require re-encryption on rotation, (c) hide the hot path from the OS page cache. AAD binding only happens at egress (idempotency key needs to match the body at send time). This trades on-disk plaintext exposure for simpler DEK rotation. Documented as a known trust assumption: customer host is trusted at-rest; if hostile, mTLS key is gone too.

### Key format

Keys are 16-byte UUIDv7 in **binary** (not hex string). bbolt sorts by `bytes.Compare`, which gives us:

- High 48 bits = ms since Unix epoch (big-endian).
- Bit 49-51 = version (0b111 for v7).
- Low 74 bits = randomness.

Sort order: time-ordered. Cursor walk = FIFO. Multiple records in the same ms get random tie-breakers.

### Meta bucket

Well-known keys, all values big-endian unless noted:

| Key | Type | Purpose |
|---|---|---|
| `cursor:flows` | 16 bytes | Last-acked UUIDv7; sender replays from `Seek(cursor) + Next()` |
| `cursor:logs` | 16 bytes | " |
| `cursor:snmp` | 16 bytes | " |
| `cursor:configs` | 16 bytes | " |
| `bytes:flows` | uint64 | Sum of value lengths in `flows` bucket |
| `bytes:logs` | uint64 | " |
| `bytes:snmp` | uint64 | " |
| `bytes:configs` | uint64 | " |
| `last_eviction_at` | RFC3339 string | Last time the eviction janitor ran |
| `last_eviction_reason` | string | "size_cap" / "age_cap" / "" |
| `schema_version` | uint32 | 1 (current) |

`bytes:*` are maintained incrementally by the writer goroutine: each `Put` adds `len(value)`, each `Delete` subtracts. Atomic within the same `bbolt.Tx`. The eviction janitor reads them in O(1) — no per-record walk.

`cursor:*` are advanced by the sender goroutine on successful ACK from the platform — `cursor:type = max-acked-key`. On startup, replay begins at `cursor:type` (exclusive) and walks forward.

### Eviction algorithm

Janitor goroutine wakes every 60 s (jittered ±10 s):

```
1. Read meta:bytes:* and sum → total.
2. Read oldest record's UUIDv7 high 48 bits → oldest_ms_since_epoch.
3. age_breach = (now - oldest_ms_since_epoch) > 14 days
4. size_breach = total > 5 GB
5. If !age_breach && !size_breach: return.
6. For each bucket in order [flows, logs, snmp]:
     - Cursor.First() → walk forward, deleting records, decrementing bytes:type
     - Stop when total drops below 4.5 GB (10% headroom) AND age drops below 13 d.
     - Increment netbrain_beacon_sf_evictions_total{type, reason} per evicted record.
7. NEVER touch `configs` bucket (ADR-071 mandate).
8. Update meta:last_eviction_at and meta:last_eviction_reason.
9. If even after evicting flows+logs+snmp the cap is still breached: alert critical
    (operator must investigate; likely SSL/network broken AND configs bucket bloated).
```

### Recovery protocol

bbolt handles single-write torn-page recovery via its own MVCC — no extra effort needed.

For catastrophic corruption (file truncated, page checksum mismatch on multiple pages, panic in `Bucket.Stats()` per x/vulndb #4923):

```
1. On daemon start, attempt bolt.Open(path).
2. If err contains "page X: invalid" or "freelist corrupt": rotate.
3. Rotate: rename to `beacon-state.bbolt.corrupt.<RFC3339>`, create fresh.
4. Increment netbrain_beacon_sf_corruption_recovery_total. Alert.
5. Data lost = whatever was in the corrupt file at rotation time.
6. Continue daemon. Operator forensic via the .corrupt file.
```

## Alternatives considered

### Alt A: timestamp + monotonic counter (uint64, BE) as key

- Pros: 8-byte keys; smaller index pages.
- Cons: counter requires atomic state in `meta`; concurrent collectors must serialize on the counter; complicates the writer-shim. Sub-µs collision unsafe.
- **Rejected:** D-5 locked UUIDv7. Sub-µs collision safety wins.

### Alt B: ascending uint64 (no time component)

- Pros: simplest possible key.
- Cons: no time ordering for free → eviction janitor must read every record's value to find age. O(n) age check.
- **Rejected:** would break the 60-s janitor cadence under load.

### Alt C: separate file per bucket (4 bbolt files)

- Pros: per-bucket eviction can shrink bbolt file (truncate after compact).
- Cons: 4× the file handles; 4× the recovery surface; harder to keep `cursor:*` consistent across files.
- **Rejected:** bbolt's per-bucket Delete is fast enough; file shrinking is an operational concern that runbook covers (manual `bbolt compact` on operator request).

### Alt D: encrypt-at-rest in S&F values

- Pros: defense-in-depth on a hostile host.
- Cons: re-encrypt on DEK rotation (or re-derive AAD); breaks the simple replay path; double-encrypt cost.
- **Rejected:** customer host is trusted (mTLS key + DEK both live there too — encrypting just the S&F doesn't help). File mode 0600 + ADR-067 §"on-host trust" cover at-rest model.

### Alt E: switch from bbolt to BadgerDB

- Pros: better write throughput; LSM-tree.
- Cons: more dependencies; Badger has its own CVE history; bbolt is battle-tested in etcd / Vault / Consul.
- **Rejected:** R-3 says current bbolt throughput target (50k records/s) is sufficient; benchmark in Phase 5 will confirm.

## Consequences

### Positive

- O(1) eviction decision via `meta:bytes:*`.
- O(log n) cursor advancement via bbolt's Cursor API.
- FIFO replay free with UUIDv7 sort.
- Per-bucket isolation matches per-type semantics naturally.
- Schema versioned from day 1; migration is `case schema_version { 1: ... }` in the open path.

### Negative

- 16-byte keys vs hypothetical 8-byte uint64 keys. bbolt page overhead (~25 bytes/record header + key) means the relative penalty is < 30%.
- Plaintext on disk: documented trust assumption.
- `bbolt_commit_seconds` p99 may spike on slow disks (R-3); mitigated by batching but visible to operator.

### Operational

- Operator can inspect S&F via `bbolt buckets beacon-state.bbolt` and `bbolt get flows <key>` (ADR-071 §"Inspection").
- Runbook §"S&F inspection" covers cursor/age queries.
- Backups: not in scope for v1; document that S&F is intentionally ephemeral.

## Acceptance criteria

- `internal/store/store.go` implements the schema above; structured tests cover put/get/cursor-advance/evict.
- `internal/store/eviction_test.go` simulates 5 GB-of-flows + 14-d-old records and asserts eviction order matches `flows → logs → snmp` and `configs` is untouched.
- Integration test loads 1M records, kills the process mid-write, restarts, asserts the bbolt file opens and replay resumes from the correct cursor.
- `meta:schema_version` is written at first bucket creation and verified on every open.
