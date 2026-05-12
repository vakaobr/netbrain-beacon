package transport

import (
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ErrNoUsableCertPair is returned by LoadCertPairWithRecovery when none
// of the three on-disk slots (live, .new, .prev) yields a parseable
// cert+key pair. The daemon's only recovery from this state is operator
// intervention — re-enrollment.
var ErrNoUsableCertPair = errors.New("transport: no usable cert pair on disk")

// CertSlot names one of the three on-disk locations a cert+key pair can
// live in during a rotation cycle. Returned by LoadCertPairWithRecovery
// so callers can log which slot the recovered pair came from.
type CertSlot string

const (
	// CertSlotLive is the steady-state location: beacon.crt + beacon.key.
	CertSlotLive CertSlot = "live"

	// CertSlotNew is the just-written-but-not-yet-promoted pair. Seen
	// after a crash between Rotator step 4 (write .new) and step 6
	// (promote .new → live).
	CertSlotNew CertSlot = "new"

	// CertSlotPrev is the archived pre-rotation pair. Seen after a crash
	// between Rotator step 5 (archive old → .prev) and step 6 (promote
	// .new → live) — i.e., the old pair was renamed aside but the new
	// pair wasn't yet written.
	CertSlotPrev CertSlot = "prev"
)

// LoadCertPairWithRecovery loads a usable cert+key pair from stateDir
// and returns which slot it came from. T-1 hardening from
// /security audit 07a §1.2.
//
// Recovery sequence (try in order, return the first that parses):
//
//  1. Live: beacon.crt + beacon.key. Steady state.
//  2. New: beacon.crt.new + beacon.key.new. Crash between Rotator step
//     6a and 6b — new pair written, live partially renamed aside. On
//     success, promote .new → live atomically before returning so the
//     daemon's normal startup path can find the pair next time.
//  3. Prev: beacon.crt.prev + beacon.key.prev. Crash between Rotator
//     step 5 and step 6 — old pair archived, new pair not yet written.
//     On success, restore .prev → live atomically.
//
// Returns ErrNoUsableCertPair if every slot fails. Does NOT mutate disk
// on error.
//
// Security note: this is recovery-only. Steady-state callers should use
// the live filenames directly via os.ReadFile — falling back to .new or
// .prev silently would mask a rotation bug. Reserve this for daemon
// startup when the live pair fails to parse.
func LoadCertPairWithRecovery(stateDir string) (certPEM, keyPEM []byte, slot CertSlot, err error) {
	live := certPair{
		certPath: filepath.Join(stateDir, "beacon.crt"),
		keyPath:  filepath.Join(stateDir, "beacon.key"),
	}
	newSlot := certPair{
		certPath: filepath.Join(stateDir, "beacon.crt.new"),
		keyPath:  filepath.Join(stateDir, "beacon.key.new"),
	}
	prevSlot := certPair{
		certPath: filepath.Join(stateDir, "beacon.crt.prev"),
		keyPath:  filepath.Join(stateDir, "beacon.key.prev"),
	}

	// 1) Live — happy path; no rename on success.
	if c, k, ok := live.tryLoad(); ok {
		return c, k, CertSlotLive, nil
	}

	// 2) New — promote to live.
	if c, k, ok := newSlot.tryLoad(); ok {
		if mvErr := promote(newSlot, live); mvErr != nil {
			return nil, nil, "", fmt.Errorf("recover from .new slot: promote: %w", mvErr)
		}
		return c, k, CertSlotNew, nil
	}

	// 3) Prev — restore to live.
	if c, k, ok := prevSlot.tryLoad(); ok {
		if mvErr := promote(prevSlot, live); mvErr != nil {
			return nil, nil, "", fmt.Errorf("recover from .prev slot: restore: %w", mvErr)
		}
		return c, k, CertSlotPrev, nil
	}

	return nil, nil, "", ErrNoUsableCertPair
}

// certPair bundles the two paths for one rotation slot and the load
// helpers that read + validate them.
type certPair struct {
	certPath string
	keyPath  string
}

// tryLoad reads both files, parses them as a cert+key, and returns the
// bytes on success. Any read or parse failure returns (nil, nil, false)
// — caller falls through to the next slot.
func (p certPair) tryLoad() (certPEM, keyPEM []byte, ok bool) {
	certBytes, err := os.ReadFile(p.certPath) //nolint:gosec // operator-controlled state dir
	if err != nil {
		return nil, nil, false
	}
	keyBytes, err := os.ReadFile(p.keyPath) //nolint:gosec // operator-controlled state dir
	if err != nil {
		return nil, nil, false
	}
	// Validate the pair parses as TLS material — catches a cert that
	// reads cleanly but is corrupt / truncated / mismatched-key.
	if _, err := tls.X509KeyPair(certBytes, keyBytes); err != nil {
		return nil, nil, false
	}
	return certBytes, keyBytes, true
}

// promote renames the contents of src into dst atomically. Used by
// LoadCertPairWithRecovery to move .new → live or .prev → live after a
// successful fallback load. We delete the destination first if it
// happens to exist (e.g., a stale truncated file blocking the rename
// on Windows). Best-effort — a partial failure leaves disk consistent:
// the source files remain, callers can retry.
func promote(src, dst certPair) error {
	// Best-effort cleanup of any stale dst file. ENOENT is fine.
	_ = os.Remove(dst.certPath)
	_ = os.Remove(dst.keyPath)
	if err := os.Rename(src.certPath, dst.certPath); err != nil {
		return fmt.Errorf("rename %s → %s: %w", src.certPath, dst.certPath, err)
	}
	if err := os.Rename(src.keyPath, dst.keyPath); err != nil {
		return fmt.Errorf("rename %s → %s: %w", src.keyPath, dst.keyPath, err)
	}
	return nil
}
