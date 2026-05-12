package store

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.etcd.io/bbolt"
)

func openStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	s, err := Open(dir, Options{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func openStoreWith(t *testing.T, opts Options) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	s, err := Open(dir, opts)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	return s, dir
}

// --- bucket validation ---

func TestBucketIsValid(t *testing.T) {
	require.True(t, BucketFlows.IsValid())
	require.True(t, BucketLogs.IsValid())
	require.True(t, BucketSNMP.IsValid())
	require.True(t, BucketConfigs.IsValid())
	require.False(t, Bucket("bogus").IsValid())
}

// --- Open + Close ---

func TestOpenCreatesBuckets(t *testing.T) {
	s := openStore(t)
	require.NotEmpty(t, s.Path())
}

func TestOpenIdempotent(t *testing.T) {
	dir := t.TempDir()
	s1, err := Open(dir, Options{})
	require.NoError(t, err)

	_, err = s1.Put(BucketLogs, []byte("seed"))
	require.NoError(t, err)
	require.NoError(t, s1.Close())

	// Re-open — data must persist.
	s2, err := Open(dir, Options{})
	require.NoError(t, err)
	defer func() { _ = s2.Close() }()
	count, err := s2.Count(BucketLogs)
	require.NoError(t, err)
	require.Equal(t, 1, count)
}

func TestOpenRecoversCorruptFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, DefaultFilename)
	// Write garbage to simulate corruption.
	require.NoError(t, os.WriteFile(path, []byte("not a bbolt file at all"), 0o600))

	s, err := Open(dir, Options{})
	require.ErrorIs(t, err, ErrCorrupt, "corrupt file must surface as ErrCorrupt + return a working Store")
	require.NotNil(t, s)
	defer func() { _ = s.Close() }()

	// The corrupt file got renamed aside.
	matches, mErr := filepath.Glob(filepath.Join(dir, "*.broken.*.bbolt"))
	require.NoError(t, mErr)
	require.Len(t, matches, 1)
}

func TestCloseIsIdempotent(t *testing.T) {
	s := openStore(t)
	require.NoError(t, s.Close())
	require.NoError(t, s.Close(), "second Close must be a no-op")
}

func TestPutAfterCloseReturnsErrClosed(t *testing.T) {
	s := openStore(t)
	require.NoError(t, s.Close())
	_, err := s.Put(BucketLogs, []byte("x"))
	require.ErrorIs(t, err, ErrClosed)
}

// --- Put / Get / Iter / Delete / Count / Bytes ---

func TestPutGetRoundTrip(t *testing.T) {
	s := openStore(t)
	key, err := s.Put(BucketLogs, []byte("hello"))
	require.NoError(t, err)
	require.Len(t, key, 16)

	got, err := s.Get(BucketLogs, key)
	require.NoError(t, err)
	require.Equal(t, []byte("hello"), got)
}

func TestPutInvalidBucket(t *testing.T) {
	s := openStore(t)
	_, err := s.Put(Bucket("nope"), []byte("x"))
	require.ErrorIs(t, err, ErrInvalidBucket)
}

func TestPutInsertionOrderEqualsFIFO(t *testing.T) {
	s := openStore(t)
	// 5 inserts spaced slightly to advance the UUIDv7 ms clock.
	wantOrder := []string{"a", "b", "c", "d", "e"}
	for _, v := range wantOrder {
		_, err := s.Put(BucketLogs, []byte(v))
		require.NoError(t, err)
		time.Sleep(2 * time.Millisecond)
	}

	var got []string
	require.NoError(t, s.Iter(BucketLogs, func(_, value []byte) error {
		got = append(got, string(value))
		return nil
	}))
	require.Equal(t, wantOrder, got, "Iter must walk in insertion (FIFO) order")
}

func TestBytesTrackedAcrossPutDelete(t *testing.T) {
	s := openStore(t)
	keys := [][]byte{}
	for i := 0; i < 100; i++ {
		k, err := s.Put(BucketLogs, []byte(strings.Repeat("x", 100)))
		require.NoError(t, err)
		keys = append(keys, k)
	}
	bytesNow, err := s.Bytes(BucketLogs)
	require.NoError(t, err)
	require.Equal(t, int64(100*100), bytesNow)

	// Delete every other.
	for i := 0; i < len(keys); i += 2 {
		require.NoError(t, s.Delete(BucketLogs, keys[i]))
	}
	bytesNow, err = s.Bytes(BucketLogs)
	require.NoError(t, err)
	require.Equal(t, int64(50*100), bytesNow)

	count, _ := s.Count(BucketLogs)
	require.Equal(t, 50, count)
}

func TestDeleteNonexistentIsNoop(t *testing.T) {
	s := openStore(t)
	require.NoError(t, s.Delete(BucketLogs, make([]byte, 16)))
}

func TestTotalEvictableBytesSums3Buckets(t *testing.T) {
	s := openStore(t)
	_, _ = s.Put(BucketFlows, []byte("1234567890"))           // 10
	_, _ = s.Put(BucketLogs, []byte("ABCDEFGHIJ"))            // 10
	_, _ = s.Put(BucketSNMP, []byte("klmnopqrst"))            // 10
	_, _ = s.Put(BucketConfigs, []byte("UVWXYZ-not-counted")) // configs NOT in total

	total, err := s.TotalEvictableBytes()
	require.NoError(t, err)
	require.Equal(t, int64(30), total, "configs is NEVER in the evictable total")
}

// --- Eviction ---

func TestEvictNoopWhenUnderCap(t *testing.T) {
	s, _ := openStoreWith(t, Options{MaxBytes: 1024, MaxAge: time.Hour})
	_, _ = s.Put(BucketLogs, []byte("small"))
	result, err := s.EvictIfNeeded(time.Now())
	require.NoError(t, err)
	require.Empty(t, result.Reason)
	require.Equal(t, 0, result.RecordsEvicted)
}

func TestEvictByByteCap(t *testing.T) {
	// 100-byte payloads × 10 = 1000 bytes; cap = 500 → evict at least 5.
	s, _ := openStoreWith(t, Options{MaxBytes: 500, MaxAge: 24 * time.Hour})
	for i := 0; i < 10; i++ {
		_, err := s.Put(BucketLogs, []byte(strings.Repeat("x", 100)))
		require.NoError(t, err)
	}
	result, err := s.EvictIfNeeded(time.Now())
	require.NoError(t, err)
	require.Equal(t, "bytes_cap", result.Reason)
	require.GreaterOrEqual(t, result.RecordsEvicted, 5)

	bytesNow, _ := s.Bytes(BucketLogs)
	require.LessOrEqual(t, bytesNow, int64(500))
}

func TestEvictPriorityFlowsFirst(t *testing.T) {
	s, _ := openStoreWith(t, Options{MaxBytes: 200, MaxAge: 24 * time.Hour})
	// Put 100 bytes into each evictable bucket = 300 total; cap 200 → must
	// evict at least 100 from flows first.
	_, _ = s.Put(BucketFlows, []byte(strings.Repeat("F", 100)))
	_, _ = s.Put(BucketLogs, []byte(strings.Repeat("L", 100)))
	_, _ = s.Put(BucketSNMP, []byte(strings.Repeat("S", 100)))
	_, _ = s.Put(BucketConfigs, []byte(strings.Repeat("C", 100))) // never evicted

	result, err := s.EvictIfNeeded(time.Now())
	require.NoError(t, err)
	require.Equal(t, 1, result.RecordsEvicted)
	require.Equal(t, 1, result.ByBucket[BucketFlows].Records,
		"flows must be evicted first (highest priority)")
	require.Equal(t, 0, result.ByBucket[BucketLogs].Records, "logs untouched")
	require.Equal(t, 0, result.ByBucket[BucketSNMP].Records, "snmp untouched")

	// configs untouched and still present.
	cCount, _ := s.Count(BucketConfigs)
	require.Equal(t, 1, cCount, "configs MUST be untouched by eviction")
}

func TestEvictNeverTouchesConfigs(t *testing.T) {
	// Even when flows + logs + snmp are empty but configs is large,
	// eviction must NOT delete configs.
	s, _ := openStoreWith(t, Options{MaxBytes: 50, MaxAge: 24 * time.Hour})
	for i := 0; i < 10; i++ {
		_, _ = s.Put(BucketConfigs, []byte(strings.Repeat("c", 100)))
	}
	result, err := s.EvictIfNeeded(time.Now())
	require.NoError(t, err)
	require.Empty(t, result.Reason, "configs alone never triggers eviction")
	require.Equal(t, 0, result.RecordsEvicted)
	configsCount, _ := s.Count(BucketConfigs)
	require.Equal(t, 10, configsCount)
}

func TestEvictByAgeCap(t *testing.T) {
	s, _ := openStoreWith(t, Options{MaxBytes: 100 * 1024 * 1024, MaxAge: 10 * time.Millisecond})
	_, _ = s.Put(BucketLogs, []byte("old"))
	time.Sleep(20 * time.Millisecond)
	_, _ = s.Put(BucketLogs, []byte("new"))

	result, err := s.EvictIfNeeded(time.Now())
	require.NoError(t, err)
	require.Equal(t, "age_cap", result.Reason)
	require.GreaterOrEqual(t, result.RecordsEvicted, 1)
}

func TestEvictLastTimestampWritten(t *testing.T) {
	s, _ := openStoreWith(t, Options{MaxBytes: 10, MaxAge: 24 * time.Hour})
	_, _ = s.Put(BucketLogs, []byte("triggers eviction"))
	before, _ := s.EvictLast()
	require.True(t, before.IsZero())

	now := time.Now()
	_, err := s.EvictIfNeeded(now)
	require.NoError(t, err)

	after, _ := s.EvictLast()
	require.False(t, after.IsZero())
	require.WithinDuration(t, now, after, 5*time.Second)
}

// --- Replay + cursor ---

func TestReplayDeliversInOrderAndDeletes(t *testing.T) {
	s := openStore(t)
	for _, v := range []string{"a", "b", "c"} {
		_, err := s.Put(BucketLogs, []byte(v))
		require.NoError(t, err)
		time.Sleep(2 * time.Millisecond)
	}

	var delivered []string
	stats, err := s.Replay(context.Background(), BucketLogs,
		func(_ context.Context, _, payload []byte) error {
			delivered = append(delivered, string(payload))
			return nil
		}, ReplayOptions{})
	require.NoError(t, err)
	require.Equal(t, []string{"a", "b", "c"}, delivered)
	require.Equal(t, 3, stats.Delivered)
	require.Equal(t, int64(3), stats.BytesDelivered)

	count, _ := s.Count(BucketLogs)
	require.Equal(t, 0, count, "Replay must delete delivered records")
}

func TestReplayHaltsOnSendError(t *testing.T) {
	s := openStore(t)
	for i := 0; i < 5; i++ {
		_, _ = s.Put(BucketLogs, []byte(fmt.Sprintf("v%d", i)))
		time.Sleep(2 * time.Millisecond)
	}

	sentinel := errors.New("transient send failure")
	calls := 0
	stats, err := s.Replay(context.Background(), BucketLogs,
		func(_ context.Context, _, _ []byte) error {
			calls++
			if calls == 3 {
				return sentinel
			}
			return nil
		}, ReplayOptions{})
	require.NoError(t, err, "Replay returns nil even when send halts — caller decides retry")
	require.ErrorIs(t, stats.LastErr, sentinel)
	require.Equal(t, 2, stats.Delivered, "exactly 2 records delivered before halt")

	// Remaining 3 records still in the bucket.
	count, _ := s.Count(BucketLogs)
	require.Equal(t, 3, count)
}

func TestReplayResumesFromCursor(t *testing.T) {
	s := openStore(t)
	for i := 0; i < 4; i++ {
		_, _ = s.Put(BucketLogs, []byte(fmt.Sprintf("v%d", i)))
		time.Sleep(2 * time.Millisecond)
	}

	// First call delivers 2 records then halts via MaxRecords.
	var seen []string
	stats, err := s.Replay(context.Background(), BucketLogs,
		func(_ context.Context, _, p []byte) error {
			seen = append(seen, string(p))
			return nil
		}, ReplayOptions{MaxRecords: 2})
	require.NoError(t, err)
	require.Equal(t, 2, stats.Delivered)
	require.Equal(t, []string{"v0", "v1"}, seen)

	// Second call resumes after the cursor.
	seen = nil
	stats, err = s.Replay(context.Background(), BucketLogs,
		func(_ context.Context, _, p []byte) error {
			seen = append(seen, string(p))
			return nil
		}, ReplayOptions{})
	require.NoError(t, err)
	require.Equal(t, 2, stats.Delivered)
	require.Equal(t, []string{"v2", "v3"}, seen)
}

func TestReplayMaxRecordsBudget(t *testing.T) {
	s := openStore(t)
	for i := 0; i < 100; i++ {
		_, _ = s.Put(BucketLogs, []byte("x"))
	}
	stats, err := s.Replay(context.Background(), BucketLogs,
		func(_ context.Context, _, _ []byte) error { return nil },
		ReplayOptions{MaxRecords: 10})
	require.NoError(t, err)
	require.Equal(t, 10, stats.Delivered, "MaxRecords budget honored")
	count, _ := s.Count(BucketLogs)
	require.Equal(t, 90, count)
}

func TestReplayContextCancellation(t *testing.T) {
	s := openStore(t)
	for i := 0; i < 100; i++ {
		_, _ = s.Put(BucketLogs, []byte("x"))
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancelled

	stats, err := s.Replay(ctx, BucketLogs,
		func(_ context.Context, _, _ []byte) error { return nil },
		ReplayOptions{})
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, 0, stats.Delivered)
}

func TestResetCursor(t *testing.T) {
	s := openStore(t)
	_, _ = s.Put(BucketLogs, []byte("a"))
	time.Sleep(2 * time.Millisecond)
	_, _ = s.Put(BucketLogs, []byte("b"))

	// Drain the bucket — cursor advances past the last record.
	_, err := s.Replay(context.Background(), BucketLogs,
		func(_ context.Context, _, _ []byte) error { return nil },
		ReplayOptions{})
	require.NoError(t, err)

	cursor, _ := s.Cursor(BucketLogs)
	require.NotNil(t, cursor)

	require.NoError(t, s.ResetCursor(BucketLogs))
	cursor, _ = s.Cursor(BucketLogs)
	require.Nil(t, cursor)
}

// --- Property: 1000 random ops → byte-total stays exact ---

func TestPropertyByteTotalExact(t *testing.T) {
	s := openStore(t)
	r := rand.New(rand.NewSource(42)) //nolint:gosec // deterministic test seed

	// Track a shadow total. Every Put adds payload size; every Delete
	// subtracts (only when we actually deleted a real key).
	var shadow int64
	keys := [][]byte{}

	for i := 0; i < 1000; i++ {
		switch r.Intn(3) {
		case 0, 1: // Put — 2/3 of the time
			size := r.Intn(200) + 1
			k, err := s.Put(BucketLogs, make([]byte, size))
			require.NoError(t, err)
			keys = append(keys, k)
			shadow += int64(size)
		case 2: // Delete — 1/3
			if len(keys) == 0 {
				continue
			}
			idx := r.Intn(len(keys))
			payload, _ := s.Get(BucketLogs, keys[idx])
			if payload != nil {
				shadow -= int64(len(payload))
			}
			require.NoError(t, s.Delete(BucketLogs, keys[idx]))
			keys = append(keys[:idx], keys[idx+1:]...)
		}
	}

	bytesNow, err := s.Bytes(BucketLogs)
	require.NoError(t, err)
	require.Equal(t, shadow, bytesNow,
		"meta:bytes:%s drifted from shadow total over 1000 random ops", BucketLogs)
}

// TestCountTracksMetaRecordsCounter verifies that Count() reads the
// records:<bucket> meta counter (not bbolt.Stats) and that the counter
// stays exact under Put + Delete + Replay + Evict — the four code paths
// that mutate bucket size.
func TestCountTracksMetaRecordsCounter(t *testing.T) {
	s := openStore(t)

	// Empty bucket — counter should be 0, not panic.
	n, err := s.Count(BucketFlows)
	require.NoError(t, err)
	require.Equal(t, 0, n)

	// Put 5, expect Count == 5.
	for i := 0; i < 5; i++ {
		_, perr := s.Put(BucketFlows, []byte{byte(i)})
		require.NoError(t, perr)
	}
	n, err = s.Count(BucketFlows)
	require.NoError(t, err)
	require.Equal(t, 5, n)

	// Delete the first record — Count == 4.
	var firstKey []byte
	require.NoError(t, s.Iter(BucketFlows, func(k, _ []byte) error {
		if firstKey == nil {
			firstKey = append([]byte(nil), k...)
		}
		return nil
	}))
	require.NotNil(t, firstKey)
	require.NoError(t, s.Delete(BucketFlows, firstKey))
	n, err = s.Count(BucketFlows)
	require.NoError(t, err)
	require.Equal(t, 4, n)

	// Replay-drain two records — Count == 2.
	delivered := 0
	_, err = s.Replay(context.Background(), BucketFlows, func(_ context.Context, _, _ []byte) error {
		delivered++
		if delivered >= 2 {
			return nil // deliver, but next iteration will check MaxRecords
		}
		return nil
	}, ReplayOptions{MaxRecords: 2})
	require.NoError(t, err)
	n, err = s.Count(BucketFlows)
	require.NoError(t, err)
	require.Equal(t, 2, n)

	// Delete remaining records via key-collection then per-key Delete.
	// (Doing s.Delete from inside the Iter callback would deadlock —
	// Iter holds a bbolt read tx; Delete needs a write tx.)
	var remaining [][]byte
	require.NoError(t, s.Iter(BucketFlows, func(k, _ []byte) error {
		remaining = append(remaining, append([]byte(nil), k...))
		return nil
	}))
	for _, k := range remaining {
		require.NoError(t, s.Delete(BucketFlows, k))
	}
	n, err = s.Count(BucketFlows)
	require.NoError(t, err)
	require.Equal(t, 0, n)

	// Confirm the underlying meta key actually exists and is zero (vs.
	// "absent and decode-to-zero by coincidence"). Use a write tx with
	// no-op delete to exercise that the key is in the meta bucket.
	require.NoError(t, s.db.View(func(tx *bbolt.Tx) error {
		mb := tx.Bucket([]byte(metaBucket))
		require.NotNil(t, mb, "meta bucket must exist after Open")
		raw := mb.Get(metaKey(metaPrefixRecords, BucketFlows))
		require.NotNil(t, raw, "records:flows meta key must exist after Put/Delete cycle")
		require.Equal(t, uint64(0), decodeUint64(raw))
		return nil
	}))
}

// TestCountAfterEviction confirms eviction's addRecords(-1) calls keep
// Count() honest after a cap-trip drains records.
func TestCountAfterEviction(t *testing.T) {
	// Tight cap: 4 records of 100 bytes each = 400, evict at 250.
	s, _ := openStoreWith(t, Options{MaxBytes: 250, MaxAge: 24 * time.Hour})

	for i := 0; i < 4; i++ {
		_, err := s.Put(BucketFlows, make([]byte, 100))
		require.NoError(t, err)
	}
	preCount, err := s.Count(BucketFlows)
	require.NoError(t, err)
	require.Equal(t, 4, preCount)

	res, err := s.EvictIfNeeded(time.Now())
	require.NoError(t, err)
	require.Greater(t, res.RecordsEvicted, 0, "eviction must trip with 400 bytes over 250-cap")

	postCount, err := s.Count(BucketFlows)
	require.NoError(t, err)
	require.Equal(t, 4-res.RecordsEvicted, postCount,
		"Count() must reflect records evicted; got %d, expected %d", postCount, 4-res.RecordsEvicted)
}
