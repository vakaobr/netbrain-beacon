package store

import (
	"errors"
	"fmt"

	"go.etcd.io/bbolt"
)

// addBytes increments the bytes:<bucket> counter in meta by delta (which
// may be negative). Clamps the result to >= 0 — a corrupt meta counter
// can underflow if Put and Delete tx-counts drift; clamping recovers
// without surfacing a confusing wrap-around to callers.
//
// Called from inside an existing bbolt write transaction.
func addBytes(tx *bbolt.Tx, bucket Bucket, delta int64) error {
	mb := tx.Bucket([]byte(metaBucket))
	if mb == nil {
		return errors.New("addBytes: meta bucket missing")
	}
	key := metaKey(metaPrefixBytes, bucket)
	current := int64(decodeUint64(mb.Get(key))) //nolint:gosec
	next := current + delta
	if next < 0 {
		next = 0
	}
	return mb.Put(key, encodeUint64(uint64(next))) //nolint:gosec
}

// addRecords increments the records:<bucket> counter in meta by delta
// (which may be negative). Same clamp-to-zero behavior as addBytes —
// keeps Count() honest even if a tx-pair drifts.
//
// Tracked separately from byte totals because b.Stats().KeyN is O(N)
// in bbolt (full bucket scan) and the research doc (ADR-078 finding #4923)
// flags it as panic-prone on freelist-stressed databases.
//
// Called from inside an existing bbolt write transaction.
func addRecords(tx *bbolt.Tx, bucket Bucket, delta int64) error {
	mb := tx.Bucket([]byte(metaBucket))
	if mb == nil {
		return errors.New("addRecords: meta bucket missing")
	}
	key := metaKey(metaPrefixRecords, bucket)
	current := int64(decodeUint64(mb.Get(key))) //nolint:gosec
	next := current + delta
	if next < 0 {
		next = 0
	}
	return mb.Put(key, encodeUint64(uint64(next))) //nolint:gosec
}

// setCursor writes the cursor:<bucket> meta key to value. value is the
// most-recently-attempted record key — replay resumes from "value
// excluded", i.e. the next key after value in FIFO order.
//
// An empty value clears the cursor (replay starts from the beginning).
// Called from inside an existing bbolt write transaction.
func setCursor(tx *bbolt.Tx, bucket Bucket, value []byte) error {
	mb := tx.Bucket([]byte(metaBucket))
	if mb == nil {
		return errors.New("setCursor: meta bucket missing")
	}
	return mb.Put(metaKey(metaPrefixCursor, bucket), value)
}

// getCursor reads the current replay cursor for bucket. Returns nil if
// the cursor isn't set (replay starts from the beginning).
//
// Called from inside an existing bbolt read OR write transaction.
func getCursor(tx *bbolt.Tx, bucket Bucket) []byte {
	mb := tx.Bucket([]byte(metaBucket))
	if mb == nil {
		return nil
	}
	v := mb.Get(metaKey(metaPrefixCursor, bucket))
	if v == nil {
		return nil
	}
	// Return a copy — the slice from bbolt is only valid for the tx.
	out := make([]byte, len(v))
	copy(out, v)
	return out
}

// Cursor returns the current replay cursor for bucket (nil if unset).
// Public accessor for diagnostics + tests; production code uses Replay
// which manages the cursor internally.
func (s *Store) Cursor(bucket Bucket) ([]byte, error) {
	if s.closed.Load() {
		return nil, ErrClosed
	}
	if !bucket.IsValid() {
		return nil, ErrInvalidBucket
	}
	var cur []byte
	err := s.db.View(func(tx *bbolt.Tx) error {
		cur = getCursor(tx, bucket)
		return nil
	})
	return cur, err
}

// ResetCursor clears the replay cursor for bucket — the next Replay call
// starts from the oldest record again. Useful in tests + for manual
// operator intervention after a buffer-corruption event.
func (s *Store) ResetCursor(bucket Bucket) error {
	if s.closed.Load() {
		return ErrClosed
	}
	if !bucket.IsValid() {
		return ErrInvalidBucket
	}
	return s.db.Update(func(tx *bbolt.Tx) error {
		mb := tx.Bucket([]byte(metaBucket))
		if mb == nil {
			return fmt.Errorf("meta bucket missing")
		}
		return mb.Delete(metaKey(metaPrefixCursor, bucket))
	})
}
