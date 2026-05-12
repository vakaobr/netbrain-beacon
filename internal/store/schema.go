package store

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

// Bucket identifies one of the four data streams the beacon buffers.
// Distinct strong type prevents callers from passing arbitrary bucket
// names; the bbolt file's bucket layout is fixed.
type Bucket string

// Data-bucket names. Ordering is the eviction priority — flows first,
// configs never.
const (
	BucketFlows   Bucket = "flows"
	BucketLogs    Bucket = "logs"
	BucketSNMP    Bucket = "snmp"
	BucketConfigs Bucket = "configs"
)

// metaBucket holds the byte-total + cursor + eviction-state tracking. Kept
// as an unexported constant — callers don't reach into meta directly.
const metaBucket = "meta"

// dataBuckets enumerates the four data buckets in eviction-priority order.
// The order matters: evict.go iterates this slice and stops once enough
// bytes are freed. configs is NEVER iterated for eviction.
var dataBuckets = []Bucket{BucketFlows, BucketLogs, BucketSNMP, BucketConfigs}

// evictableOrder is the eviction-priority subset of dataBuckets — configs
// is excluded.
var evictableOrder = []Bucket{BucketFlows, BucketLogs, BucketSNMP}

// allBuckets returns every bucket name (data + meta) as []byte for use in
// the Open() bucket-creation loop.
func allBuckets() [][]byte {
	out := make([][]byte, 0, len(dataBuckets)+1)
	for _, b := range dataBuckets {
		out = append(out, []byte(b))
	}
	out = append(out, []byte(metaBucket))
	return out
}

// IsValid reports whether b is one of the four data buckets.
func (b Bucket) IsValid() bool {
	switch b {
	case BucketFlows, BucketLogs, BucketSNMP, BucketConfigs:
		return true
	}
	return false
}

// String implements fmt.Stringer.
func (b Bucket) String() string { return string(b) }

// Errors surfaced by this package.
var (
	// ErrInvalidBucket is returned when a caller passes a Bucket name that
	// isn't one of the four documented data buckets.
	ErrInvalidBucket = errors.New("store: invalid bucket name")

	// ErrClosed is returned by Put/Iter/Delete/Replay after Close has
	// been called on the Store.
	ErrClosed = errors.New("store: closed")

	// ErrCorrupt is returned by Open when the bbolt file fails to open
	// and the recovery rename succeeded. Callers see a fresh empty
	// Store via the second return value; this error is informational.
	ErrCorrupt = errors.New("store: bbolt file was corrupt and renamed aside")
)

// newKey mints a fresh UUIDv7 and returns its 16-byte representation
// suitable for use as a bbolt key. UUIDv7's first 48 bits are a millisecond
// timestamp, making the natural sort order of the bucket equivalent to
// FIFO insertion order.
//
// Within a single millisecond, UUIDv7 uses the remaining 80 bits as a
// random counter, so two Put calls in the same ms produce distinct keys
// without explicit serialization.
func newKey() ([]byte, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return nil, fmt.Errorf("uuidv7: %w", err)
	}
	out := make([]byte, 16)
	copy(out, id[:])
	return out, nil
}

// keyTimestamp extracts the millisecond Unix timestamp embedded in a
// UUIDv7-shaped key. Used by eviction to find records older than the
// 14-day age cap.
//
// Returns 0 if the key doesn't have the expected length (defensive —
// the caller should already know the key is well-formed).
func keyTimestamp(key []byte) int64 {
	if len(key) < 6 {
		return 0
	}
	// UUIDv7 timestamp layout: 48 bits big-endian unix-ms in bytes [0..6).
	// Pad to 8 bytes for binary.BigEndian.Uint64.
	var buf [8]byte
	copy(buf[2:], key[:6])
	return int64(binary.BigEndian.Uint64(buf[:])) //nolint:gosec // 48-bit unix-ms always fits
}

// metaKey produces the meta-bucket key for a tracking field associated
// with bucket b. Format: "<prefix>:<bucket>", e.g. "bytes:flows".
func metaKey(prefix string, b Bucket) []byte {
	return []byte(prefix + ":" + string(b))
}

// Meta-key prefixes.
const (
	metaPrefixBytes   = "bytes"
	metaPrefixCursor  = "cursor"
	metaPrefixRecords = "records"
)

// metaEvictLastKey is the single timestamp-tracking key in meta.
var metaEvictLastKey = []byte("evict_last")

// encodeUint64 returns 8 big-endian bytes for v. Used for byte-total
// counters and timestamps stored in the meta bucket.
func encodeUint64(v uint64) []byte {
	out := make([]byte, 8)
	binary.BigEndian.PutUint64(out, v)
	return out
}

// decodeUint64 returns the big-endian uint64 in b, or 0 if b is not 8
// bytes (defensive — a corrupt meta entry is treated as zero, not as
// a panic).
func decodeUint64(b []byte) uint64 {
	if len(b) != 8 {
		return 0
	}
	return binary.BigEndian.Uint64(b)
}
