package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"go.etcd.io/bbolt"
	"golang.org/x/time/rate"
)

// ReplayOptions configures one Replay invocation.
type ReplayOptions struct {
	// MaxRecords caps the records this call replays. Zero means "until
	// the bucket is empty or send returns an error". The daemon
	// scheduler typically passes a per-tick budget here so a backlog
	// flush doesn't starve other collectors.
	MaxRecords int

	// Limiter throttles the send rate (records per second). Nil means
	// unthrottled — used during cold-start drain. ADR-071 mandates 2×
	// normal-rate pacing; callers construct the limiter from their
	// collector's expected steady-state rate.
	Limiter *rate.Limiter
}

// SendFunc is the per-record callback Replay invokes. Return nil to mark
// the record successfully delivered (replay deletes it and advances the
// cursor); return non-nil to halt replay with the error (record stays
// in the bucket, cursor unchanged).
//
// The payload slice is valid only for the duration of the call; copy
// before returning if retention is needed.
type SendFunc func(ctx context.Context, key, payload []byte) error

// ReplayStats summarises one Replay invocation.
type ReplayStats struct {
	// Delivered is the count of records send() returned nil for and which
	// were therefore deleted + advanced past.
	Delivered int
	// BytesDelivered is the sum of payload sizes for delivered records.
	BytesDelivered int64
	// LastErr is the error from the last send call that halted replay,
	// or nil if Replay walked to MaxRecords / bucket end normally.
	LastErr error
}

// Replay walks records in bucket FIFO from the current cursor and invokes
// send for each. On success, the record is deleted and the cursor
// advances to the next key. On error, replay stops and the unsent record
// remains for the next Replay call.
//
// Concurrent Replay calls on the same bucket are safe (bbolt serialises
// writes) but pointless — the second caller will see the cursor advanced
// past the records the first caller drained. Callers should arrange to
// have one Replay goroutine per bucket.
//
// Cursor semantics: the cursor records the LAST DELIVERED key. Replay
// resumes by seeking to the cursor + advancing once. When the cursor is
// nil (fresh bucket), replay starts at the first key.
func (s *Store) Replay(ctx context.Context, bucket Bucket, send SendFunc, opts ReplayOptions) (ReplayStats, error) {
	if s.closed.Load() {
		return ReplayStats{}, ErrClosed
	}
	if !bucket.IsValid() {
		return ReplayStats{}, ErrInvalidBucket
	}
	if send == nil {
		return ReplayStats{}, errors.New("store.Replay: send is nil")
	}

	stats := ReplayStats{}

	for opts.MaxRecords == 0 || stats.Delivered < opts.MaxRecords {
		if err := ctx.Err(); err != nil {
			stats.LastErr = err
			return stats, err
		}
		if opts.Limiter != nil {
			if err := opts.Limiter.Wait(ctx); err != nil {
				stats.LastErr = err
				return stats, err
			}
		}

		key, payload, found, err := s.peekNext(bucket)
		if err != nil {
			return stats, err
		}
		if !found {
			break
		}

		if err := send(ctx, key, payload); err != nil {
			stats.LastErr = err
			return stats, nil // halt without error — caller decides retry
		}

		// Delete + advance cursor in one tx so a crash here can never
		// double-deliver: either both happen or neither.
		if err := s.commitDelivered(bucket, key, int64(len(payload))); err != nil {
			return stats, fmt.Errorf("store: commit replay: %w", err)
		}
		stats.Delivered++
		stats.BytesDelivered += int64(len(payload))
	}

	return stats, nil
}

// peekNext returns the next record after the current cursor (or the
// first record if no cursor). found=false means the bucket is empty
// beyond the cursor.
//
// The key/payload are copied out of the bbolt tx so they remain valid
// after the function returns.
func (s *Store) peekNext(bucket Bucket) (key, payload []byte, found bool, err error) {
	err = s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		if b == nil {
			return nil
		}
		cur := b.Cursor()
		cursor := getCursor(tx, bucket)

		var k, v []byte
		if cursor == nil {
			k, v = cur.First()
		} else {
			// Seek to cursor then step once. If cursor doesn't exist any
			// more (deleted in a parallel call), Seek returns the next
			// key after cursor, which is what we want — DON'T step in
			// that case.
			k, v = cur.Seek(cursor)
			if k != nil && bytes.Equal(k, cursor) {
				k, v = cur.Next()
			}
		}
		if k == nil {
			return nil
		}
		// Copy out of the tx.
		key = make([]byte, len(k))
		copy(key, k)
		payload = make([]byte, len(v))
		copy(payload, v)
		found = true
		return nil
	})
	return key, payload, found, err
}

// commitDelivered is the per-record write tx: delete the record, decrement
// the byte total, and advance the cursor.
func (s *Store) commitDelivered(bucket Bucket, key []byte, size int64) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		if b == nil {
			return ErrInvalidBucket
		}
		if err := b.Delete(key); err != nil {
			return fmt.Errorf("delete: %w", err)
		}
		if err := addBytes(tx, bucket, -size); err != nil {
			return err
		}
		if err := addRecords(tx, bucket, -1); err != nil {
			return err
		}
		return setCursor(tx, bucket, key)
	})
}
