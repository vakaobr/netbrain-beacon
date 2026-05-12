package store

import (
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"go.etcd.io/bbolt"
)

// DefaultFilename is the bbolt file name relative to the state dir.
const DefaultFilename = "beacon-state.bbolt"

// Options bundle the tunables for Open. Zero-value Options gives the
// production defaults documented in ADR-071.
type Options struct {
	// MaxBytes caps the total bytes across the three evictable data
	// buckets (flows + logs + snmp). Default: 5 GB.
	MaxBytes int64
	// MaxAge caps the age of the oldest evictable record. Default: 14 days.
	MaxAge time.Duration
	// OpenTimeout bounds the bbolt.Open file-lock wait. Default: 5 seconds.
	OpenTimeout time.Duration
}

// DefaultOptions returns the ADR-071 production defaults.
func DefaultOptions() Options {
	return Options{
		MaxBytes:    5 * 1024 * 1024 * 1024, // 5 GB
		MaxAge:      14 * 24 * time.Hour,    // 14 days
		OpenTimeout: 5 * time.Second,
	}
}

// Store wraps a bbolt.DB with the schema, meta-tracking, eviction, and
// replay helpers. Safe for concurrent use across goroutines — bbolt
// serialises writes at the engine layer; reads are concurrent.
type Store struct {
	db   *bbolt.DB
	opts Options
	// closed is set on Close so subsequent operations short-circuit with
	// ErrClosed instead of trying to operate on a closed bbolt handle.
	closed atomic.Bool
}

// Open opens (or creates) the bbolt file at filepath.Join(stateDir, DefaultFilename).
//
// If the file exists but bbolt rejects it (corrupt header, mismatched
// version, etc.), the corrupt file is renamed to
// `<name>.broken.<unix-ts>.bbolt` and a fresh empty Store is created. In
// this case the function returns (Store, ErrCorrupt) — the caller should
// log the data loss (configs bucket is gone; the next config poll
// rebuilds it) but continue.
//
// On any other error (permission denied, disk full, etc.) the function
// returns (nil, err) with the bbolt error wrapped.
func Open(stateDir string, opts Options) (*Store, error) {
	if opts.MaxBytes == 0 {
		opts.MaxBytes = DefaultOptions().MaxBytes
	}
	if opts.MaxAge == 0 {
		opts.MaxAge = DefaultOptions().MaxAge
	}
	if opts.OpenTimeout == 0 {
		opts.OpenTimeout = DefaultOptions().OpenTimeout
	}

	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, fmt.Errorf("store: mkdir state: %w", err)
	}

	path := filepath.Join(stateDir, DefaultFilename)

	db, openErr := openBolt(path, opts)
	var corruptFlag error
	if openErr != nil {
		// Best-effort distinguish "corrupt" from "transient": bbolt's
		// internal error types aren't part of its public API, so we treat
		// any open error as a candidate for recovery — rename + retry.
		// If the rename itself fails (permission denied on a read-only
		// volume), surface the original error.
		broken := fmt.Sprintf("%s.broken.%d.bbolt", path, time.Now().Unix())
		if renameErr := os.Rename(path, broken); renameErr != nil && !os.IsNotExist(renameErr) {
			return nil, fmt.Errorf("store: bbolt open failed and rename-aside failed: open=%w rename=%w", openErr, renameErr)
		}
		db, openErr = openBolt(path, opts)
		if openErr != nil {
			return nil, fmt.Errorf("store: bbolt open failed even after recovery: %w", openErr)
		}
		corruptFlag = ErrCorrupt
	}

	// Ensure every bucket exists. Idempotent on subsequent opens.
	if err := db.Update(func(tx *bbolt.Tx) error {
		for _, name := range allBuckets() {
			if _, err := tx.CreateBucketIfNotExists(name); err != nil {
				return fmt.Errorf("ensure bucket %s: %w", name, err)
			}
		}
		return nil
	}); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: schema init: %w", err)
	}

	return &Store{db: db, opts: opts}, corruptFlag
}

// openBolt wraps bbolt.Open with the Options-derived timeout. Extracted so
// the Open recovery path can call it twice (first attempt → rename-aside →
// second attempt) without duplicating the Options translation.
func openBolt(path string, opts Options) (*bbolt.DB, error) {
	return bbolt.Open(path, 0o600, &bbolt.Options{
		Timeout:      opts.OpenTimeout,
		FreelistType: bbolt.FreelistMapType,
	})
}

// Close flushes and closes the underlying bbolt file. Subsequent operations
// return ErrClosed.
func (s *Store) Close() error {
	if s.closed.Swap(true) {
		return nil
	}
	return s.db.Close()
}

// Path returns the absolute filesystem path of the bbolt file. Used by
// admin tools and recovery diagnostics.
func (s *Store) Path() string {
	return s.db.Path()
}

// Options returns the effective options (post-default-fill).
func (s *Store) Options() Options { return s.opts }

// Put writes payload into bucket. Returns the assigned UUIDv7 key + any
// error. Updates the bytes:<bucket> meta total in the same transaction.
//
// Empty bucket or unknown bucket returns ErrInvalidBucket. After Close,
// returns ErrClosed.
func (s *Store) Put(bucket Bucket, payload []byte) ([]byte, error) {
	if s.closed.Load() {
		return nil, ErrClosed
	}
	if !bucket.IsValid() {
		return nil, ErrInvalidBucket
	}

	key, err := newKey()
	if err != nil {
		return nil, err
	}

	if err := s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		if b == nil {
			return ErrInvalidBucket
		}
		// Copy payload — bbolt requires the value to remain valid for the
		// transaction lifetime and we want to defend against caller-side
		// reuse of the buffer after Put returns.
		value := make([]byte, len(payload))
		copy(value, payload)
		if err := b.Put(key, value); err != nil {
			return err
		}
		return addBytes(tx, bucket, int64(len(value)))
	}); err != nil {
		return nil, err
	}
	return key, nil
}

// Get returns the payload stored at (bucket, key) or nil if the record
// doesn't exist. The returned slice is a copy — safe to retain after
// the bbolt transaction ends.
func (s *Store) Get(bucket Bucket, key []byte) ([]byte, error) {
	if s.closed.Load() {
		return nil, ErrClosed
	}
	if !bucket.IsValid() {
		return nil, ErrInvalidBucket
	}
	var out []byte
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		if b == nil {
			return nil
		}
		v := b.Get(key)
		if v == nil {
			return nil
		}
		out = make([]byte, len(v))
		copy(out, v)
		return nil
	})
	return out, err
}

// Iter walks every key/value in bucket in FIFO order (UUIDv7 timestamp
// ascending) and invokes fn for each. Returning a non-nil error from fn
// stops iteration and propagates the error.
//
// The value slice is valid only for the duration of the fn call; copy if
// retention is needed.
func (s *Store) Iter(bucket Bucket, fn func(key, value []byte) error) error {
	if s.closed.Load() {
		return ErrClosed
	}
	if !bucket.IsValid() {
		return ErrInvalidBucket
	}
	return s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, v []byte) error {
			return fn(k, v)
		})
	})
}

// Delete removes a single record. Decrements the bytes:<bucket> meta
// total. Deleting a non-existent key is a no-op (no error).
func (s *Store) Delete(bucket Bucket, key []byte) error {
	if s.closed.Load() {
		return ErrClosed
	}
	if !bucket.IsValid() {
		return ErrInvalidBucket
	}
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		if b == nil {
			return ErrInvalidBucket
		}
		v := b.Get(key)
		if v == nil {
			return nil
		}
		size := int64(len(v))
		if err := b.Delete(key); err != nil {
			return err
		}
		return addBytes(tx, bucket, -size)
	})
}

// Count returns the number of records currently in bucket. O(1) — uses
// bbolt's internal counter, NOT a full scan.
func (s *Store) Count(bucket Bucket) (int, error) {
	if s.closed.Load() {
		return 0, ErrClosed
	}
	if !bucket.IsValid() {
		return 0, ErrInvalidBucket
	}
	var n int
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		if b == nil {
			return nil
		}
		n = b.Stats().KeyN
		return nil
	})
	return n, err
}

// Bytes returns the total byte size of payloads currently in bucket as
// tracked in the meta bucket. O(1) — does NOT call bbolt.Stats on the
// data bucket (which the research doc flags as panic-prone).
func (s *Store) Bytes(bucket Bucket) (int64, error) {
	if s.closed.Load() {
		return 0, ErrClosed
	}
	if !bucket.IsValid() {
		return 0, ErrInvalidBucket
	}
	var n int64
	err := s.db.View(func(tx *bbolt.Tx) error {
		mb := tx.Bucket([]byte(metaBucket))
		if mb == nil {
			return nil
		}
		raw := mb.Get(metaKey(metaPrefixBytes, bucket))
		n = int64(decodeUint64(raw)) //nolint:gosec // payload bytes <= MaxBytes (5 GiB) always fits in int64
		return nil
	})
	return n, err
}

// TotalEvictableBytes is the sum of Bytes(BucketFlows) + Bytes(BucketLogs)
// + Bytes(BucketSNMP). Used by the eviction policy to decide whether to
// trip. configs is NOT included — it has no cap.
func (s *Store) TotalEvictableBytes() (int64, error) {
	if s.closed.Load() {
		return 0, ErrClosed
	}
	var total int64
	err := s.db.View(func(tx *bbolt.Tx) error {
		mb := tx.Bucket([]byte(metaBucket))
		if mb == nil {
			return nil
		}
		for _, b := range evictableOrder {
			total += int64(decodeUint64(mb.Get(metaKey(metaPrefixBytes, b)))) //nolint:gosec
		}
		return nil
	})
	return total, err
}
