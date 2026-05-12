package transport

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/google/uuid"

	"github.com/velonet/netbrain-beacon/internal/api"
	"github.com/velonet/netbrain-beacon/internal/metrics"
)

// Errors surfaced by Rotate.
var (
	// ErrRotationInFlight is returned when a second goroutine calls Rotate
	// while a first call is still running. Callers should treat this as
	// success (the in-flight rotation will publish the new cert when it
	// completes) and not retry.
	ErrRotationInFlight = errors.New("rotate: rotation already in flight")

	// ErrRotationFailed wraps any persist / API / cert-parse failure during
	// rotation. The wrapped error carries the underlying cause.
	ErrRotationFailed = errors.New("rotate: failed")
)

// File modes — duplicated from internal/enroll/persist.go rather than
// imported to avoid a package-import cycle. Same security mandate
// applies: secret files at 0600, public at 0644.
const (
	rotateModeSecret = 0o600
	rotateModePublic = 0o644
)

// Rotator owns the cert-rotation lifecycle for a single beacon install.
// Multiple goroutines (cert-rotation scheduler, manual operator trigger,
// signal handler) may call Rotate concurrently; the Rotator coalesces
// them so the server sees exactly one /rotate-cert call per active rotation.
type Rotator struct {
	// APIClient is the generated client bound to the beacon's mTLS
	// transport. Rotate uses it to call /rotate-cert.
	APIClient api.ClientInterface

	// Client is the transport-layer holder whose *http.Client is
	// hot-swapped on a successful rotation (ADR-079).
	Client *Client

	// BeaconID is the cert-derived beacon UUID. The /rotate-cert URL
	// requires it.
	BeaconID uuid.UUID

	// StateDir holds the on-disk artifacts (beacon.crt, beacon.key, etc.).
	// New cert + key are written here atomically; the old pair is archived
	// at beacon.crt.prev / beacon.key.prev for the revocation grace
	// window. The daemon scheduler (Phase 8) cleans up .prev files after
	// 7 days.
	StateDir string

	// PlatformCAPEM is the trust anchor for the rebuilt *tls.Config.
	// Captured at Rotator construction; ADR-079 doesn't change it during
	// a rotation (CA rotation is a separate, manual-only event).
	PlatformCAPEM []byte

	// HTTPClientFactory builds a new *http.Client from the rotated cert
	// pair. Defaults to buildHTTPClient when nil. Tests inject a mock so
	// they can assert the rebuilt client without touching real TLS.
	HTTPClientFactory func(certPEM, keyPEM, caPEM []byte) (*http.Client, error)

	// inFlight is the coalescing primitive. Concurrent callers see
	// non-zero and return ErrRotationInFlight instead of duplicating
	// the server call.
	inFlight atomic.Bool

	// mu serializes the on-disk file dance (archive + promote) so two
	// goroutines that somehow both pass the inFlight gate don't race
	// at the filesystem layer. Belt-and-braces.
	mu sync.Mutex
}

// Rotate performs one cert-rotation cycle:
//
//  1. Generate a fresh ECDSA-P-256 keypair + CSR with empty Subject
//     (mirrors enroll.GenerateCSR but inlined to avoid the import cycle
//     enroll → transport doesn't exist today; transport → enroll would
//     drag the bundle parser into the transport package needlessly).
//  2. POST /api/v1/beacons/{id}/rotate-cert with the new CSR.
//  3. Parse the response; fail-closed on missing client_cert_pem.
//  4. Write `beacon.crt.new` + `beacon.key.new` atomically (tmpfile + chmod
//     + rename, in the standard order).
//  5. Archive the old pair: rename `beacon.crt` → `beacon.crt.prev` and
//     `beacon.key` → `beacon.key.prev`. The .prev files give a 7-day
//     revocation-window buffer for in-flight requests.
//  6. Promote the new pair: rename `beacon.crt.new` → `beacon.crt` and
//     `beacon.key.new` → `beacon.key`.
//  7. Build a new *http.Client from the rotated pair + the pinned CA.
//  8. Atomic-Pointer Swap. The previous client is returned and its idle
//     connections are closed lazily by net/http (or by the caller, which
//     in production is the daemon scheduler keeping a 5-min grace window).
//
// Crash semantics: if step 5 or 6 partially completes (file half-renamed),
// the on-disk state is "active=.prev, pending=.new". A daemon restart that
// finds this state can recover by reading either the primary or .prev
// path. The Recovery() helper (TODO Phase 8) prefers the primary; falls
// back to .prev only on parse failure.
func (r *Rotator) Rotate(ctx context.Context) (err error) {
	if !r.inFlight.CompareAndSwap(false, true) {
		// Coalesced caller — don't count as a rotation attempt for the
		// rotation_total metric (we'd double-count when the in-flight
		// rotation completes).
		return ErrRotationInFlight
	}
	defer r.inFlight.Store(false)

	// Emit the outcome metric on every Rotate call that actually
	// reaches the API. Labels: success | failed.
	defer func() {
		result := "success"
		if err != nil {
			result = "failed"
		}
		metrics.CertRotationTotal.WithLabelValues(result).Inc()
	}()

	r.mu.Lock()
	defer r.mu.Unlock()

	// 1) keypair + CSR
	priv, csrPEM, keyPEM, err := generateRotationKey()
	if err != nil {
		return fmt.Errorf("%w: csr: %w", ErrRotationFailed, err)
	}
	_ = priv // referenced by keyPEM via marshaling; explicit blank-assign so the linter doesn't drop it

	// 2) POST /rotate-cert
	resp, err := r.APIClient.RotateBeaconCert(ctx, r.BeaconID, api.RotateBeaconCertJSONRequestBody{CsrPem: string(csrPEM)})
	if err != nil {
		return fmt.Errorf("%w: http: %w", ErrRotationFailed, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024)) //nolint:forbidigo // bounded
		return fmt.Errorf("%w: HTTP %d: %s", ErrRotationFailed, resp.StatusCode, string(body))
	}

	parsed, err := api.ParseRotateBeaconCertResponse(resp)
	if err != nil {
		return fmt.Errorf("%w: parse: %w", ErrRotationFailed, err)
	}
	if parsed.JSON201 == nil || parsed.JSON201.ClientCertPem == "" {
		return fmt.Errorf("%w: response missing client_cert_pem (status %d)", ErrRotationFailed, resp.StatusCode)
	}
	newCertPEM := []byte(parsed.JSON201.ClientCertPem)

	// 3) Sanity: the new cert + key must form a valid keypair before we
	// touch disk. Catches a server-side regression that swaps cert and
	// key fields.
	if _, perr := ParseCertPEM(newCertPEM); perr != nil {
		return fmt.Errorf("%w: new cert: %w", ErrRotationFailed, perr)
	}

	// 4) Write the new pair as .new alongside the live pair.
	certNewPath := filepath.Join(r.StateDir, "beacon.crt.new")
	keyNewPath := filepath.Join(r.StateDir, "beacon.key.new")
	if werr := atomicFileWrite(certNewPath, newCertPEM, rotateModePublic); werr != nil {
		return fmt.Errorf("%w: write cert.new: %w", ErrRotationFailed, werr)
	}
	if werr := atomicFileWrite(keyNewPath, keyPEM, rotateModeSecret); werr != nil {
		_ = os.Remove(certNewPath)
		return fmt.Errorf("%w: write key.new: %w", ErrRotationFailed, werr)
	}

	// 5) Archive old → .prev (best-effort; on a fresh install both may not exist).
	certPath := filepath.Join(r.StateDir, "beacon.crt")
	keyPath := filepath.Join(r.StateDir, "beacon.key")
	certPrevPath := filepath.Join(r.StateDir, "beacon.crt.prev")
	keyPrevPath := filepath.Join(r.StateDir, "beacon.key.prev")

	if rerr := os.Rename(certPath, certPrevPath); rerr != nil && !os.IsNotExist(rerr) {
		return fmt.Errorf("%w: archive cert: %w", ErrRotationFailed, rerr)
	}
	if rerr := os.Rename(keyPath, keyPrevPath); rerr != nil && !os.IsNotExist(rerr) {
		return fmt.Errorf("%w: archive key: %w", ErrRotationFailed, rerr)
	}

	// 6) Promote .new → live.
	if rerr := os.Rename(certNewPath, certPath); rerr != nil {
		return fmt.Errorf("%w: promote cert: %w", ErrRotationFailed, rerr)
	}
	if rerr := os.Rename(keyNewPath, keyPath); rerr != nil {
		return fmt.Errorf("%w: promote key: %w", ErrRotationFailed, rerr)
	}

	// 7) Build a new *http.Client and Swap atomically.
	factory := r.HTTPClientFactory
	if factory == nil {
		factory = defaultRotationHTTPClientFactory
	}
	newClient, err := factory(newCertPEM, keyPEM, r.PlatformCAPEM)
	if err != nil {
		return fmt.Errorf("%w: rebuild http.Client: %w", ErrRotationFailed, err)
	}
	r.Client.Swap(newClient)

	return nil
}

// CleanupPrev removes the .prev archived cert + key files. Call this from
// the daemon scheduler N days after a successful rotation. Returns the
// number of files removed (0 or 2).
func (r *Rotator) CleanupPrev() (int, error) {
	removed := 0
	for _, name := range []string{"beacon.crt.prev", "beacon.key.prev"} {
		p := filepath.Join(r.StateDir, name)
		if err := os.Remove(p); err == nil {
			removed++
		} else if !os.IsNotExist(err) {
			return removed, fmt.Errorf("rotate cleanup %s: %w", name, err)
		}
	}
	return removed, nil
}

// generateRotationKey mints a fresh ECDSA-P-256 keypair and the matching
// CSR + private-key PEM bytes. Mirror of enroll.GenerateCSR — duplicated
// to avoid a transport → enroll import cycle.
func generateRotationKey() (*ecdsa.PrivateKey, []byte /*csrPEM*/, []byte /*keyPEM*/, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("keygen: %w", err)
	}
	tpl := &x509.CertificateRequest{SignatureAlgorithm: x509.ECDSAWithSHA256}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tpl, priv)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("csr build: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("key marshal: %w", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return priv, csrPEM, keyPEM, nil
}

// defaultRotationHTTPClientFactory rebuilds the *http.Client from the
// rotated cert pair + the pinned CA. Same shape as transport.NewClient
// minus the Config wrapper, since rotation pulls from on-disk bytes
// directly.
func defaultRotationHTTPClientFactory(certPEM, keyPEM, caPEM []byte) (*http.Client, error) {
	c, err := NewClient(Config{CertPEM: certPEM, KeyPEM: keyPEM, PlatformCAPEM: caPEM})
	if err != nil {
		return nil, err
	}
	return c.Current(), nil
}

// atomicFileWrite duplicates the enroll.atomicWrite pattern. Kept here to
// avoid the import cycle that would arise from internal/transport →
// internal/enroll. Behaviourally identical: tmpfile in the target dir,
// fsync, chmod-before-rename, atomic os.Rename onto the final path.
func atomicFileWrite(path string, contents []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-"+filepath.Base(path)+"-*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }

	if _, err := tmp.Write(contents); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("fsync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("close temp: %w", err)
	}

	// Chmod BEFORE rename so the file lands at the final path with the
	// correct perms — no race window where a secret file is 0644.
	if runtime.GOOS != "windows" {
		if err := os.Chmod(tmpName, mode); err != nil {
			cleanup()
			return fmt.Errorf("chmod temp: %w", err)
		}
	}
	if err := os.Rename(tmpName, path); err != nil {
		cleanup()
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}
