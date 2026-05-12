// Package sender drains one bbolt bucket → encrypts each record with the
// current DEK + derives an Idempotency-Key UUIDv5 (byte-compatible with
// the platform's M-2-AAD recompute) + POSTs to /data/{type}.
//
// One Sender instance per bucket. Senders share the DEKHolder but never
// share their bucket — bbolt cursor advance is per-bucket so concurrent
// senders on the same bucket would race.
package sender

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"golang.org/x/time/rate"

	"github.com/secra/netbrain-beacon/internal/api"
	"github.com/secra/netbrain-beacon/internal/collectors"
	bcrypto "github.com/secra/netbrain-beacon/internal/crypto"
	"github.com/secra/netbrain-beacon/internal/store"
)

// Errors surfaced by Sender.
var (
	// ErrNoDEK is returned when the DEKHolder is empty at flush time —
	// typically only happens before the daemon's first DEK load. The
	// store retains the buffered records and the caller retries.
	ErrNoDEK = errors.New("sender: no DEK loaded")

	// ErrSendFailed wraps any non-2xx response from the platform. Carries
	// the HTTP status + body excerpt for the daemon's structured log.
	ErrSendFailed = errors.New("sender: platform rejected batch")
)

// PathForBucket maps a store.Bucket to the matching /data/{type} URL
// path suffix. Centralised here so any future bucket rename touches one
// place instead of every per-collector caller.
func PathForBucket(b store.Bucket) string {
	switch b {
	case store.BucketLogs:
		return "logs"
	case store.BucketFlows:
		return "flows"
	case store.BucketSNMP:
		return "snmp"
	case store.BucketConfigs:
		return "configs"
	default:
		return ""
	}
}

// Sender drains one bucket and ships its records to the platform.
type Sender struct {
	// Store is the bbolt-backed buffer the sender drains.
	Store *store.Store

	// Bucket is the data type this sender is responsible for.
	Bucket store.Bucket

	// BeaconID is the beacon's cert-derived UUID. Used in the
	// Idempotency-Key UUIDv5 derivation.
	BeaconID uuid.UUID

	// DEKs is the shared atomic-pointer DEK holder. The daemon updates
	// it on a verified rotation; the sender just reads.
	DEKs *collectors.DEKHolder

	// APIClient is the generated mTLS client.
	APIClient api.ClientInterface

	// Limiter caps outbound batch rate. Nil means unthrottled (used on
	// cold-start drain). ADR-071 §"Replay pacing": 2× normal collector
	// rate.
	Limiter *rate.Limiter

	// MaxRecordsPerCycle bounds how many records a single Run iteration
	// drains. The daemon's outer scheduler invokes Run on a tick; this
	// budget prevents one slow collector from starving the others.
	MaxRecordsPerCycle int
}

// Run drains the bucket once. Returns the number of records delivered +
// any error from the last send. Per ADR-071 + store.Replay semantics,
// a send error stops the cycle but leaves remaining records in the
// bucket for the next call.
func (s *Sender) Run(ctx context.Context) (int, error) {
	dek := s.DEKs.Current()
	if dek == nil || len(dek.Key) == 0 {
		return 0, ErrNoDEK
	}
	stats, err := s.Store.Replay(ctx, s.Bucket, s.makeSendFn(dek), store.ReplayOptions{
		MaxRecords: s.MaxRecordsPerCycle,
		Limiter:    s.Limiter,
	})
	if err != nil {
		return stats.Delivered, err
	}
	if stats.LastErr != nil {
		return stats.Delivered, stats.LastErr
	}
	return stats.Delivered, nil
}

// makeSendFn returns a store.SendFunc that closes over the active DEK.
// Captured once per Run so DEK rotation mid-cycle is OK — the cycle
// finishes on the old DEK, the next cycle picks up the new one.
func (s *Sender) makeSendFn(dek *collectors.DEK) store.SendFunc {
	return func(ctx context.Context, _, payload []byte) error {
		// 1. Idempotency-Key = UUIDv5(beacon_id, sha256(payload))
		idempotencyKey := bcrypto.DeriveBatchIdempotencyKey(s.BeaconID, payload)

		// 2. AAD = bytes([dek_v]) || idempotency_key.bytes
		aad := bcrypto.MakeAAD(dek.Version, idempotencyKey)

		// 3. Encrypt: envelope = [ver|dek_v|iv|ct|tag]
		envelope, err := bcrypto.Encrypt(payload, dek.Key, dek.Version, aad)
		if err != nil {
			return fmt.Errorf("sender: encrypt: %w", err)
		}

		// 4. POST /api/v1/beacons/{id}/data/{type}
		// We don't use the generated client's typed Push*WithBody helpers
		// because they require knowing each bucket's exact method name at
		// compile time. The reflection-free dispatch via PathForBucket
		// + manual http.Request keeps this generic across all 4 buckets.
		return s.postEnvelope(ctx, envelope, idempotencyKey, dek.Version)
	}
}

// postEnvelope dispatches the per-bucket POST. Uses the generated
// client's `Push*WithBody` methods by bucket name so we get the
// auto-generated URL templating + path params for free.
func (s *Sender) postEnvelope(ctx context.Context, envelope []byte, idempotencyKey uuid.UUID, dekVersion byte) error {
	body := bytes.NewReader(envelope)
	const contentType = "application/octet-stream"
	editor := func(_ context.Context, req *http.Request) error {
		req.Header.Set("Idempotency-Key", idempotencyKey.String())
		req.Header.Set("X-Beacon-DEK-Version", fmt.Sprintf("%d", dekVersion))
		return nil
	}

	var resp *http.Response
	var err error
	switch s.Bucket {
	case store.BucketLogs:
		resp, err = s.APIClient.PushBeaconLogsWithBody(ctx, s.BeaconID, nil, contentType, body, editor)
	case store.BucketSNMP:
		resp, err = s.APIClient.PushBeaconSnmpWithBody(ctx, s.BeaconID, nil, contentType, body, editor)
	case store.BucketConfigs:
		resp, err = s.APIClient.PushBeaconConfigsWithBody(ctx, s.BeaconID, nil, contentType, body, editor)
	case store.BucketFlows:
		// Flows endpoint takes multipart binary, not the envelope shape;
		// for v1 we POST the envelope as the file body. The platform
		// side will need to wrap multipart parsing — TBD by the Phase 9
		// netflow follow-up.
		resp, err = s.APIClient.PushBeaconFlowsWithBody(ctx, s.BeaconID, nil, contentType, body, editor)
	default:
		return fmt.Errorf("sender: invalid bucket %q", s.Bucket)
	}
	if err != nil {
		return fmt.Errorf("sender: http: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	return fmt.Errorf("%w: HTTP %d", ErrSendFailed, resp.StatusCode)
}
