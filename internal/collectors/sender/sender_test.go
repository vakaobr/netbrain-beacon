package sender

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/vakaobr/netbrain-beacon/internal/api"
	"github.com/vakaobr/netbrain-beacon/internal/collectors"
	bcrypto "github.com/vakaobr/netbrain-beacon/internal/crypto"
	"github.com/vakaobr/netbrain-beacon/internal/store"
)

// fakePlatform records every /data/* hit and lets the test prescribe
// the response status code per call.
type fakePlatform struct {
	mu          sync.Mutex
	received    []fakeRecord
	statusCodes []int    // pop one per call; default 202 if exhausted
	errorCodes  []string // matching error envelope codes; default "X"
	hits        atomic.Int64
}

type fakeRecord struct {
	Path           string
	IdempotencyKey string
	DEKVersion     string
	Body           []byte
}

func (f *fakePlatform) handler(beaconID string) http.Handler {
	prefix := "/api/v1/beacons/" + beaconID + "/data/"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.hits.Add(1)
		body, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()
		path := strings.TrimPrefix(r.URL.Path, prefix)
		f.mu.Lock()
		f.received = append(f.received, fakeRecord{
			Path:           path,
			IdempotencyKey: r.Header.Get("Idempotency-Key"),
			DEKVersion:     r.Header.Get("X-Beacon-DEK-Version"),
			Body:           append([]byte(nil), body...),
		})
		status := http.StatusAccepted
		if len(f.statusCodes) > 0 {
			status = f.statusCodes[0]
			f.statusCodes = f.statusCodes[1:]
		}
		errCode := "X"
		if len(f.errorCodes) > 0 {
			errCode = f.errorCodes[0]
			f.errorCodes = f.errorCodes[1:]
		}
		f.mu.Unlock()
		if status >= 400 {
			w.Header().Set("Content-Type", "application/json")
		}
		w.WriteHeader(status)
		// For non-success status, include a JSON error envelope so the
		// caller can see we used the canonical platform error shape.
		if status >= 400 {
			_, _ = w.Write([]byte(`{"error":{"code":"` + errCode + `","message":"x"}}`))
		}
	})
}

func (f *fakePlatform) snapshot() []fakeRecord {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]fakeRecord, len(f.received))
	copy(out, f.received)
	return out
}

// senderFixture bundles every dep the sender needs.
type senderFixture struct {
	BeaconID uuid.UUID
	Store    *store.Store
	DEK      *collectors.DEK
	DEKs     *collectors.DEKHolder
	Server   *httptest.Server
	Plat     *fakePlatform
	Sender   *Sender
}

func newSenderFixture(t *testing.T, bucket store.Bucket) *senderFixture {
	t.Helper()

	beaconID := uuid.MustParse("abcdef00-1234-4567-8901-abcdef012345")
	plat := &fakePlatform{}
	srv := httptest.NewServer(plat.handler(beaconID.String()))
	t.Cleanup(srv.Close)

	apiClient, err := api.NewClient(srv.URL)
	require.NoError(t, err)

	dir := t.TempDir()
	s, err := store.Open(dir, store.Options{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	dek := &collectors.DEK{
		Key:     bytes32(0x42),
		Version: 1,
	}
	holder := collectors.NewDEKHolder(dek)

	return &senderFixture{
		BeaconID: beaconID,
		Store:    s,
		DEK:      dek,
		DEKs:     holder,
		Server:   srv,
		Plat:     plat,
		Sender: &Sender{
			Store:     s,
			Bucket:    bucket,
			BeaconID:  beaconID,
			DEKs:      holder,
			APIClient: apiClient,
		},
	}
}

func bytes32(b byte) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = b
	}
	return out
}

// --- happy paths ---

func TestSenderRunDeliversAllRecords(t *testing.T) {
	f := newSenderFixture(t, store.BucketLogs)

	for _, v := range [][]byte{[]byte("log-a"), []byte("log-b"), []byte("log-c")} {
		_, err := f.Store.Put(store.BucketLogs, v)
		require.NoError(t, err)
	}

	n, err := f.Sender.Run(context.Background())
	require.NoError(t, err)
	require.Equal(t, 3, n)

	// All 3 records delivered to the right path.
	recs := f.Plat.snapshot()
	require.Len(t, recs, 3)
	for _, r := range recs {
		require.Equal(t, "logs", r.Path)
		require.NotEmpty(t, r.IdempotencyKey, "Idempotency-Key must be set on every request")
		require.Equal(t, "1", r.DEKVersion, "X-Beacon-DEK-Version must match current DEK")
	}

	// Bucket drained.
	count, _ := f.Store.Count(store.BucketLogs)
	require.Equal(t, 0, count)
}

func TestSenderIdempotencyKeyMatchesCrypto(t *testing.T) {
	// The Idempotency-Key the sender emits MUST equal what
	// crypto.DeriveBatchIdempotencyKey returns for the same plaintext —
	// the platform recomputes it as its M-2-AAD check.
	f := newSenderFixture(t, store.BucketLogs)
	payload := []byte("payload to verify")
	_, err := f.Store.Put(store.BucketLogs, payload)
	require.NoError(t, err)

	_, err = f.Sender.Run(context.Background())
	require.NoError(t, err)

	expected := bcrypto.DeriveBatchIdempotencyKey(f.BeaconID, payload)
	recs := f.Plat.snapshot()
	require.Len(t, recs, 1)
	require.Equal(t, expected.String(), recs[0].IdempotencyKey)
}

func TestSenderBodyIsValidEnvelope(t *testing.T) {
	// The body sent to /data/logs must be a valid AES-256-GCM envelope
	// that decrypts cleanly with the same DEK + AAD.
	f := newSenderFixture(t, store.BucketLogs)
	payload := []byte("decrypt me")
	_, err := f.Store.Put(store.BucketLogs, payload)
	require.NoError(t, err)

	_, err = f.Sender.Run(context.Background())
	require.NoError(t, err)
	recs := f.Plat.snapshot()
	require.Len(t, recs, 1)

	// Reconstruct AAD + decrypt.
	idempotencyKey := uuid.MustParse(recs[0].IdempotencyKey)
	aad := bcrypto.MakeAAD(f.DEK.Version, idempotencyKey)
	got, decErr := bcrypto.Decrypt(recs[0].Body, f.DEK.Key, aad)
	require.NoError(t, decErr)
	require.Equal(t, payload, got)
}

// --- bucket routing ---

func TestSenderRoutesToCorrectPath(t *testing.T) {
	for _, tc := range []struct {
		bucket  store.Bucket
		urlPart string
	}{
		{store.BucketLogs, "logs"},
		{store.BucketFlows, "flows"},
		{store.BucketSNMP, "snmp"},
		{store.BucketConfigs, "configs"},
	} {
		tc := tc
		t.Run(string(tc.bucket), func(t *testing.T) {
			f := newSenderFixture(t, tc.bucket)
			_, err := f.Store.Put(tc.bucket, []byte("x"))
			require.NoError(t, err)
			_, err = f.Sender.Run(context.Background())
			require.NoError(t, err)
			recs := f.Plat.snapshot()
			require.Len(t, recs, 1)
			require.Equal(t, tc.urlPart, recs[0].Path)
		})
	}
}

func TestPathForBucketUnknownReturnsEmpty(t *testing.T) {
	require.Empty(t, PathForBucket(store.Bucket("nope")))
}

// --- error paths ---

func TestSenderHaltsOnPlatformError(t *testing.T) {
	f := newSenderFixture(t, store.BucketLogs)
	// First record succeeds, second fails with 500.
	f.Plat.statusCodes = []int{http.StatusAccepted, http.StatusInternalServerError}

	for _, v := range [][]byte{[]byte("a"), []byte("b"), []byte("c")} {
		_, err := f.Store.Put(store.BucketLogs, v)
		require.NoError(t, err)
	}

	_, err := f.Sender.Run(context.Background())
	require.ErrorIs(t, err, ErrSendFailed,
		"sender must surface ErrSendFailed when the platform rejects a batch")

	// 1 record delivered + deleted; 2 remain in the bucket.
	count, _ := f.Store.Count(store.BucketLogs)
	require.Equal(t, 2, count)
}

// --- I-6: Classify-dispatch action tests ---

func TestSenderDEKExpiredHaltsAndPreservesRecord(t *testing.T) {
	// BEACON_DEK_EXPIRED (401) → ActionRefreshDEK → ErrSendDEKExpired;
	// record stays in the bucket so the next cycle (after rotation) retries.
	f := newSenderFixture(t, store.BucketLogs)
	f.Plat.statusCodes = []int{http.StatusUnauthorized}
	f.Plat.errorCodes = []string{"BEACON_DEK_EXPIRED"}
	_, _ = f.Store.Put(store.BucketLogs, []byte("doomed"))

	_, err := f.Sender.Run(context.Background())
	require.ErrorIs(t, err, ErrSendDEKExpired)

	count, _ := f.Store.Count(store.BucketLogs)
	require.Equal(t, 1, count, "record preserved for next-cycle retry")
	require.Equal(t, int64(1), f.Sender.Stats().Refreshed)
}

func TestSenderProtocolDisabledTriggersBackoff(t *testing.T) {
	// 503 BEACON_PROTOCOL_NOT_ENABLED → ActionBackOffHeavy → ErrSendBackOff.
	f := newSenderFixture(t, store.BucketLogs)
	f.Plat.statusCodes = []int{http.StatusServiceUnavailable}
	f.Plat.errorCodes = []string{"BEACON_PROTOCOL_NOT_ENABLED"}
	_, _ = f.Store.Put(store.BucketLogs, []byte("queued"))

	_, err := f.Sender.Run(context.Background())
	require.ErrorIs(t, err, ErrSendBackOff)

	count, _ := f.Store.Count(store.BucketLogs)
	require.Equal(t, 1, count, "record preserved when platform feature flag is off")
	require.Equal(t, int64(1), f.Sender.Stats().BackedOff)
}

func TestSenderAADMismatchDropsRecord(t *testing.T) {
	// BEACON_AAD_MISMATCH (400) → ActionDropAndAlert → record DELETED;
	// retrying with the same payload would keep failing. Drop counter
	// increments so the alert path catches it.
	f := newSenderFixture(t, store.BucketLogs)
	f.Plat.statusCodes = []int{http.StatusBadRequest, http.StatusAccepted}
	f.Plat.errorCodes = []string{"BEACON_AAD_MISMATCH", ""}
	_, _ = f.Store.Put(store.BucketLogs, []byte("first"))
	_, _ = f.Store.Put(store.BucketLogs, []byte("second"))

	n, err := f.Sender.Run(context.Background())
	require.NoError(t, err, "drop is silent at the sender level; alert via counter")
	require.Equal(t, 2, n, "1 dropped + 1 delivered = 2 records processed off the bucket")

	count, _ := f.Store.Count(store.BucketLogs)
	require.Equal(t, 0, count, "AAD-mismatch record removed even though it failed")
	require.Equal(t, int64(1), f.Sender.Stats().DroppedAlert)
	require.Equal(t, int64(1), f.Sender.Stats().Delivered)
}

func TestSenderURLCertMismatchIsFatal(t *testing.T) {
	// BEACON_URL_CERT_MISMATCH (403) → ActionFatalReenroll → ErrSendFatal.
	// Indicates H-2 IDOR / mis-paired cert; operator must re-enroll.
	f := newSenderFixture(t, store.BucketLogs)
	f.Plat.statusCodes = []int{http.StatusForbidden}
	f.Plat.errorCodes = []string{"BEACON_URL_CERT_MISMATCH"}
	_, _ = f.Store.Put(store.BucketLogs, []byte("blocked"))

	_, err := f.Sender.Run(context.Background())
	require.ErrorIs(t, err, ErrSendFatal)
	require.Equal(t, int64(1), f.Sender.Stats().Fatal)

	count, _ := f.Store.Count(store.BucketLogs)
	require.Equal(t, 1, count, "fatal must preserve the record — re-enroll might succeed")
}

func TestSenderUnknownCodeIsFatal(t *testing.T) {
	// 4xx with a code Classify doesn't recognize → defaults to fatal
	// (the conservative choice for a server that added a code we
	// haven't mapped yet).
	f := newSenderFixture(t, store.BucketLogs)
	f.Plat.statusCodes = []int{http.StatusBadRequest}
	f.Plat.errorCodes = []string{"FUTURE_UNRECOGNIZED_CODE"}
	_, _ = f.Store.Put(store.BucketLogs, []byte("x"))

	_, err := f.Sender.Run(context.Background())
	require.ErrorIs(t, err, ErrSendFatal)
}

func TestSenderStatsRoundTrip(t *testing.T) {
	// One success + one drop + one DEK-expired across separate Run cycles.
	f := newSenderFixture(t, store.BucketLogs)

	// 1) success
	_, _ = f.Store.Put(store.BucketLogs, []byte("ok"))
	_, err := f.Sender.Run(context.Background())
	require.NoError(t, err)
	require.Equal(t, int64(1), f.Sender.Stats().Delivered)

	// 2) AAD mismatch (drop)
	f.Plat.statusCodes = []int{http.StatusBadRequest}
	f.Plat.errorCodes = []string{"BEACON_AAD_MISMATCH"}
	_, _ = f.Store.Put(store.BucketLogs, []byte("badaad"))
	_, _ = f.Sender.Run(context.Background())
	require.Equal(t, int64(1), f.Sender.Stats().DroppedAlert)
	require.Equal(t, int64(1), f.Sender.Stats().Delivered, "delivered count is cumulative across cycles")

	// 3) DEK expired (refreshed)
	f.Plat.statusCodes = []int{http.StatusUnauthorized}
	f.Plat.errorCodes = []string{"BEACON_DEK_EXPIRED"}
	_, _ = f.Store.Put(store.BucketLogs, []byte("preserved"))
	_, _ = f.Sender.Run(context.Background())
	require.Equal(t, int64(1), f.Sender.Stats().Refreshed)
}

func TestSenderNoDEK(t *testing.T) {
	f := newSenderFixture(t, store.BucketLogs)
	// Clear the DEK by swapping in a zero-key.
	f.DEKs.Set(&collectors.DEK{Key: nil, Version: 0})
	_, _ = f.Store.Put(store.BucketLogs, []byte("x"))

	_, err := f.Sender.Run(context.Background())
	require.ErrorIs(t, err, ErrNoDEK)

	// Record preserved.
	count, _ := f.Store.Count(store.BucketLogs)
	require.Equal(t, 1, count)
}

func TestSenderRespectsMaxRecordsPerCycle(t *testing.T) {
	f := newSenderFixture(t, store.BucketLogs)
	f.Sender.MaxRecordsPerCycle = 2
	for i := 0; i < 5; i++ {
		_, _ = f.Store.Put(store.BucketLogs, []byte("x"))
	}

	n, err := f.Sender.Run(context.Background())
	require.NoError(t, err)
	require.Equal(t, 2, n)
	count, _ := f.Store.Count(store.BucketLogs)
	require.Equal(t, 3, count)
}

// --- DEK holder ---

func TestDEKHolderRotationIsObserved(t *testing.T) {
	f := newSenderFixture(t, store.BucketLogs)

	_, _ = f.Store.Put(store.BucketLogs, []byte("payload-v1"))
	_, _ = f.Sender.Run(context.Background())

	// Rotate DEK to v2.
	newDEK := &collectors.DEK{Key: bytes32(0x99), Version: 2}
	prev := f.DEKs.Set(newDEK)
	require.Equal(t, byte(1), prev.Version)

	_, _ = f.Store.Put(store.BucketLogs, []byte("payload-v2"))
	_, _ = f.Sender.Run(context.Background())

	recs := f.Plat.snapshot()
	require.Len(t, recs, 2)
	require.Equal(t, "1", recs[0].DEKVersion)
	require.Equal(t, "2", recs[1].DEKVersion, "rotation must surface as new X-Beacon-DEK-Version")
}

func TestDEKHolderSetNilIsNoop(t *testing.T) {
	h := collectors.NewDEKHolder(&collectors.DEK{Key: bytes32(1), Version: 1})
	prev := h.Set(nil)
	require.Equal(t, byte(1), prev.Version)
	require.Equal(t, byte(1), h.Current().Version, "Set(nil) must NOT clear the active DEK")
}

// --- silence unused-import grumbles ---

var (
	_ = base64.StdEncoding.EncodeToString
	_ = json.NewEncoder
)
