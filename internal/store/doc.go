// Package store implements the beacon's bbolt-backed store-and-forward
// buffer per ADR-071.
//
// # Layout
//
// One bbolt file (default `beacon-state.bbolt` under the state dir) with
// five buckets:
//
//	flows    — per-batch NetFlow blobs (highest evict priority)
//	logs     — gzip-NDJSON log batches
//	snmp     — SNMP MIB snapshots
//	configs  — device config dumps (NEVER evicted — operator-visible data)
//	meta     — byte totals, replay cursors, last-eviction timestamp
//
// # Keys
//
// Data-bucket keys are UUIDv7 (16 bytes). UUIDv7's first 48 bits are a
// millisecond timestamp, so the natural sort order of the bucket is FIFO.
// Replay walks records in key order; eviction deletes from the smallest
// (oldest) key first. The remaining 80 bits are random, providing
// sub-millisecond uniqueness without an atomic counter.
//
// # Caps (ADR-071)
//
// Default: 5 GB OR 14 days, whichever fires first. When the cap trips,
// the eviction routine drops oldest records from `flows` first, then
// `logs`, then `snmp`. `configs` is NEVER evicted — it represents
// operator-visible state that must survive long disconnects.
//
// # Replay
//
// Replay(bucket, sendFn, opts) advances a per-bucket cursor through the
// records in FIFO order. Successful sends delete the record in the same
// transaction as the cursor advance, so a crash mid-batch resumes from
// the right place. A rate.Limiter caps replay throughput at 2× the
// collector's normal rate (ADR-071 §"Replay pacing").
//
// # Recovery
//
// Open() tries bbolt.Open and, on a corruption error, renames the file
// aside to `<name>.broken.<unix>.bbolt` and starts fresh. Logged as a
// data-loss event; configs bucket is lost, the daemon recovers it from
// the next config poll. Per-bucket cursor reset is implicit (empty
// buckets start with no cursor).
//
// # Hot path
//
// Per the research doc, bbolt's `Stats()` panics on a corrupt branch
// (golang/vulndb #4923). This package NEVER calls Stats on the hot path;
// byte-total tracking is maintained explicitly via the `meta` bucket.
package store
