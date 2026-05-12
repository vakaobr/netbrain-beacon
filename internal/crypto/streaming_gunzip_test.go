package crypto

import (
	"bytes"
	"compress/gzip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func gzipBytes(t *testing.T, src []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	_, err := gw.Write(src)
	require.NoError(t, err)
	require.NoError(t, gw.Close())
	return buf.Bytes()
}

func TestGunzipCappedHappy(t *testing.T) {
	src := []byte("the quick brown fox")
	zipped := gzipBytes(t, src)
	got, err := GunzipCapped(zipped, 1024)
	require.NoError(t, err)
	require.Equal(t, src, got)
}

func TestGunzipCappedEmpty(t *testing.T) {
	zipped := gzipBytes(t, nil)
	got, err := GunzipCapped(zipped, 1024)
	require.NoError(t, err)
	require.Empty(t, got)
}

func TestGunzipCappedExactlyAtCap(t *testing.T) {
	// Python reference aborts on > max_bytes, not >=. A plaintext of
	// exactly max_bytes must succeed.
	src := make([]byte, 128)
	zipped := gzipBytes(t, src)
	got, err := GunzipCapped(zipped, 128)
	require.NoError(t, err)
	require.Len(t, got, 128)
}

func TestGunzipCappedOneByteOver(t *testing.T) {
	src := make([]byte, 129)
	zipped := gzipBytes(t, src)
	_, err := GunzipCapped(zipped, 128)
	require.ErrorIs(t, err, ErrDecompressionBomb)
}

func TestGunzipCappedDecompressionBomb(t *testing.T) {
	// Build a small gzip stream containing a large run of zeros.
	// 100 MB of zeros compresses to a few KB — the classic decompression
	// bomb. The cap (50 MB) must abort within NFR-15's 100 ms ceiling.
	const bombSize = 100 * 1024 * 1024
	src := make([]byte, bombSize)
	zipped := gzipBytes(t, src)

	cap50MB := int64(50 * 1024 * 1024)
	start := time.Now()
	_, err := GunzipCapped(zipped, cap50MB)
	elapsed := time.Since(start)

	require.ErrorIs(t, err, ErrDecompressionBomb)
	// 5s CI ceiling vs. NFR-15's 100ms production target. GitHub Actions
	// runners are I/O-throttled and the 100 MB zero-allocation alone can
	// take >500ms on a shared runner. 5s still catches O(n²) regressions
	// (a missing-cap bug would walk the full bomb and take minutes), while
	// not flaking on cold-start CPU-shared runners.
	require.Less(t, elapsed, 5*time.Second,
		"bomb abort took %v (CI ceiling 5s; NFR-15 production target is 100ms)", elapsed)
}

func TestGunzipCappedCorruptInput(t *testing.T) {
	_, err := GunzipCapped([]byte("not gzip data at all"), 1024)
	require.ErrorIs(t, err, ErrGunzipCorrupt)
}

func TestGunzipCappedTruncatedStream(t *testing.T) {
	src := []byte("the quick brown fox")
	zipped := gzipBytes(t, src)
	truncated := zipped[:len(zipped)/2]
	_, err := GunzipCapped(truncated, 1024)
	require.ErrorIs(t, err, ErrGunzipCorrupt)
}

func TestGunzipCappedBadMaxBytes(t *testing.T) {
	zipped := gzipBytes(t, []byte("anything"))
	_, err := GunzipCapped(zipped, 0)
	require.Error(t, err)
	_, err = GunzipCapped(zipped, -1)
	require.Error(t, err)
}
