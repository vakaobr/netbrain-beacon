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
	"sync/atomic"

	"github.com/google/uuid"
	"golang.org/x/time/rate"

	"github.com/secra/netbrain-beacon/internal/api"
	"github.com/secra/netbrain-beacon/internal/collectors"
	bcrypto "github.com/secra/netbrain-beacon/internal/crypto"
	"github.com/secra/netbrain-beacon/internal/store"
	"github.com/secra/netbrain-beacon/internal/transport"
)

// Errors surfaced by Sender.
var (
	// ErrNoDEK is returned when the DEKHolder is empty at flush time —
	// typically only happens before the daemon's first DEK load. The
	// store retains the buffered records and the caller retries.
	ErrNoDEK = errors.New("sender: no DEK loaded")

	// ErrSendFailed is the generic non-2xx wrapper — used when the
	// platform returns an error code that maps to ActionRetry. Caller
	// should retry on the next tick.
	ErrSendFailed = errors.New("sender: platform rejected batch (retry)")

	// ErrSendDEKExpired surfaces ActionRefreshDEK — the active DEK is
	// past the 7-day rotation grace. Daemon should poll /config
	// immediately to fetch the rotated DEK; the unsent record stays in
	// the bucket so the next cycle (after rotation) succeeds.
	ErrSendDEKExpired = errors.New("sender: DEK expired — needs rotation refresh")

	// ErrSendBackOff surfaces ActionBackOffHeavy — typically 503
	// BEACON_PROTOCOL_NOT_ENABLED. The daemon should slow down rather
	// than retry on its normal cadence.
	ErrSendBackOff = errors.New("sender: platform asked for heavy backoff")

	// ErrSendFatal surfaces ActionFatalReenroll — the platform sees this
	// beacon as cross-tenant / URL-mismatched / cert-revoked. The daemon
	// can't recover without operator action (re-enroll).
	ErrSendFatal = errors.New("sender: fatal — operator action required (re-enroll)")
)

// Counters exposes the sender's lifetime counters for metrics emission.
// Returned by Stats. Each field is the cumulative count over the
// daemon's lifetime; resets only on restart.
type Counters struct {
	Delivered    int64
	DroppedAlert int64 // ActionDropAndAlert: record deleted + alert flagged
	Retried      int64 // ActionRetry: record preserved, halt this cycle
	Refreshed    int64 // ActionRefreshDEK: record preserved, signal DEK refresh
	BackedOff    int64 // ActionBackOffHeavy
	Fatal        int64 // ActionFatalReenroll
	Unknown      int64 // ActionUnknown — server returned an unrecognized code
}

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

	// Lifetime counters surfaced via Stats(). Updated atomically by the
	// per-record makeSendFn callback so reads from the daemon's metric
	// emitter are lock-free.
	delivered    atomic.Int64
	droppedAlert atomic.Int64
	retried      atomic.Int64
	refreshed    atomic.Int64
	backedOff    atomic.Int64
	fatal        atomic.Int64
	unknown      atomic.Int64
}

// Stats returns the lifetime counter snapshot for metrics emission.
func (s *Sender) Stats() Counters {
	return Counters{
		Delivered:    s.delivered.Load(),
		DroppedAlert: s.droppedAlert.Load(),
		Retried:      s.retried.Load(),
		Refreshed:    s.refreshed.Load(),
		BackedOff:    s.backedOff.Load(),
		Fatal:        s.fatal.Load(),
		Unknown:      s.unknown.Load(),
	}
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

// postEnvelope dispatches the per-bucket POST and routes the response
// through transport.Classify so each of the 17 known platform error
// codes maps to the right action (drop / refresh-DEK / back-off /
// fatal / retry) instead of being lumped under "non-2xx = retry".
//
// Returns nil for actions where store.Replay should DELETE the record
// (Success, DropAndAlert) and a typed error for actions where the
// record must be preserved (Retry, RefreshDEK, BackOffHeavy, Fatal).
// Caller's store.Replay halts on non-nil error; the daemon's senderLoop
// inspects the error type via errors.Is to decide its next move.
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
		// Network-level failure (DNS, TLS handshake, connection refused).
		// Treat as retryable; the record stays in the bucket.
		s.retried.Add(1)
		return fmt.Errorf("%w: http: %w", ErrSendFailed, err)
	}
	defer func() { _ = resp.Body.Close() }()

	action, srvErr := transport.Classify(resp)
	switch action {
	case transport.ActionSuccess:
		s.delivered.Add(1)
		return nil

	case transport.ActionDropAndAlert:
		// AAD mismatch / decompression bomb / envelope invalid — these
		// mean the payload itself is unrecoverable; retrying won't help.
		// Returning nil lets store.Replay delete the record. The counter
		// + an upstream alert capture the security signal.
		s.droppedAlert.Add(1)
		return nil

	case transport.ActionRefreshDEK:
		// DEK expired — the daemon's next config-poll will fetch the
		// rotated key and verify its signature (M-11). Halt this cycle;
		// the record stays put.
		s.refreshed.Add(1)
		return fmt.Errorf("%w: %w", ErrSendDEKExpired, srvErrToError(srvErr))

	case transport.ActionBackOffHeavy:
		s.backedOff.Add(1)
		return fmt.Errorf("%w: %w", ErrSendBackOff, srvErrToError(srvErr))

	case transport.ActionFatalReenroll:
		// Cert/URL mismatch (H-2 IDOR attempt) or cross-tenant 404 —
		// operator action required.
		s.fatal.Add(1)
		return fmt.Errorf("%w: %w", ErrSendFatal, srvErrToError(srvErr))

	case transport.ActionRetry:
		s.retried.Add(1)
		return fmt.Errorf("%w: %w", ErrSendFailed, srvErrToError(srvErr))

	case transport.ActionNotModified:
		// 304 isn't valid for /data/* endpoints. Treat as a server-side
		// regression: halt + log.
		s.unknown.Add(1)
		return fmt.Errorf("%w: unexpected 304 on data-push", ErrSendFailed)

	default: // ActionUnknown
		// Server returned a code we don't recognize. Halt conservatively
		// — Classify already defaults to FatalReenroll for unknown 4xx,
		// so reaching here only happens on a future Action that we forgot
		// to handle.
		s.unknown.Add(1)
		return fmt.Errorf("%w: unmapped action", ErrSendFailed)
	}
}

// srvErrToError turns a parsed *transport.ServerError into a regular
// error (or a sentinel for nil). Used to enrich wrapped error chains
// without nil-deref panics.
func srvErrToError(e *transport.ServerError) error {
	if e == nil {
		return errors.New("no server envelope")
	}
	return e
}
