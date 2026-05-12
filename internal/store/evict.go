package store

import (
	"fmt"
	"time"

	"go.etcd.io/bbolt"
)

// EvictionResult summarises one EvictIfNeeded run. Returned for telemetry
// + tests; production code logs the struct fields via slog.
type EvictionResult struct {
	// RecordsEvicted is the total count across all evictable buckets.
	RecordsEvicted int
	// BytesEvicted is the total payload bytes freed.
	BytesEvicted int64
	// ByBucket maps each evictable bucket to (records, bytes) it lost.
	ByBucket map[Bucket]EvictionPerBucket
	// Reason captures why eviction ran: "bytes_cap", "age_cap", "both",
	// or "" if no eviction was needed.
	Reason string
}

// EvictionPerBucket is the per-bucket counter in EvictionResult.
type EvictionPerBucket struct {
	Records int
	Bytes   int64
}

// EvictIfNeeded checks the byte total and the age of the oldest record;
// runs eviction if EITHER cap is exceeded. Drops oldest records from
// flows → logs → snmp until BOTH caps are within limits. NEVER touches
// the configs bucket.
//
// Returns the eviction stats. If no eviction was needed, returns a zero
// EvictionResult (ByBucket initialised but empty).
//
// Per ADR-071 the cap is "5 GB OR 14 days, whichever first" — this
// function trips when either is exceeded.
func (s *Store) EvictIfNeeded(now time.Time) (EvictionResult, error) {
	if s.closed.Load() {
		return EvictionResult{}, ErrClosed
	}

	result := EvictionResult{
		ByBucket: map[Bucket]EvictionPerBucket{},
	}

	err := s.db.Update(func(tx *bbolt.Tx) error {
		totalBytes := readTotalEvictableBytes(tx)
		oldestMS := readOldestEvictableTimestamp(tx)

		ageCutoff := now.Add(-s.opts.MaxAge).UnixMilli()
		bytesOver := totalBytes > s.opts.MaxBytes
		ageOver := oldestMS != 0 && oldestMS < ageCutoff

		if !bytesOver && !ageOver {
			return nil
		}
		switch {
		case bytesOver && ageOver:
			result.Reason = "both"
		case bytesOver:
			result.Reason = "bytes_cap"
		default:
			result.Reason = "age_cap"
		}

		// Drop records in priority order (flows → logs → snmp) until both
		// caps are under their limits. The inner loop walks bucket b's
		// records FIFO (UUIDv7 ordering) and deletes the oldest one at a
		// time, re-checking caps after each delete. This is more I/O than
		// "delete N at once" but keeps the meta-bucket totals exact even
		// if the caller crashes mid-eviction.
		for _, b := range evictableOrder {
			db := tx.Bucket([]byte(b))
			if db == nil {
				continue
			}
			c := db.Cursor()
			for k, v := c.First(); k != nil; k, v = c.First() {
				bytesNowOver := readTotalEvictableBytes(tx) > s.opts.MaxBytes
				ageNowOver := readOldestEvictableTimestamp(tx) != 0 &&
					readOldestEvictableTimestamp(tx) < ageCutoff
				if !bytesNowOver && !ageNowOver {
					return nil
				}
				size := int64(len(v))
				if err := db.Delete(k); err != nil {
					return fmt.Errorf("evict delete: %w", err)
				}
				if err := addBytes(tx, b, -size); err != nil {
					return err
				}
				if err := addRecords(tx, b, -1); err != nil {
					return err
				}
				stat := result.ByBucket[b]
				stat.Records++
				stat.Bytes += size
				result.ByBucket[b] = stat
				result.RecordsEvicted++
				result.BytesEvicted += size
			}
		}

		// Stamp the eviction timestamp regardless of which path tripped.
		mb := tx.Bucket([]byte(metaBucket))
		if mb != nil {
			_ = mb.Put(metaEvictLastKey, encodeUint64(uint64(now.UnixMilli()))) //nolint:gosec
		}
		return nil
	})
	if err != nil {
		return EvictionResult{}, err
	}
	return result, nil
}

// readTotalEvictableBytes returns the sum of bytes:flows + bytes:logs +
// bytes:snmp from meta. Called inside both read + write txs.
func readTotalEvictableBytes(tx *bbolt.Tx) int64 {
	mb := tx.Bucket([]byte(metaBucket))
	if mb == nil {
		return 0
	}
	var total int64
	for _, b := range evictableOrder {
		total += int64(decodeUint64(mb.Get(metaKey(metaPrefixBytes, b)))) //nolint:gosec
	}
	return total
}

// readOldestEvictableTimestamp returns the unix-ms timestamp of the
// oldest record across all evictable buckets, or 0 if all are empty.
// Reads the first key in each bucket (UUIDv7 sort = FIFO) and decodes
// its embedded timestamp.
func readOldestEvictableTimestamp(tx *bbolt.Tx) int64 {
	var oldest int64
	for _, b := range evictableOrder {
		db := tx.Bucket([]byte(b))
		if db == nil {
			continue
		}
		k, _ := db.Cursor().First()
		if k == nil {
			continue
		}
		ts := keyTimestamp(k)
		if oldest == 0 || ts < oldest {
			oldest = ts
		}
	}
	return oldest
}

// EvictLast returns the timestamp of the most recent EvictIfNeeded run
// (the time of the LAST eviction that actually deleted records or ran a
// cap check). Zero time if eviction has never been invoked.
func (s *Store) EvictLast() (time.Time, error) {
	if s.closed.Load() {
		return time.Time{}, ErrClosed
	}
	var t time.Time
	err := s.db.View(func(tx *bbolt.Tx) error {
		mb := tx.Bucket([]byte(metaBucket))
		if mb == nil {
			return nil
		}
		ms := decodeUint64(mb.Get(metaEvictLastKey))
		if ms == 0 {
			return nil
		}
		t = time.UnixMilli(int64(ms)) //nolint:gosec
		return nil
	})
	return t, err
}
