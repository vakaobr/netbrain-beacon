package enroll

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/google/uuid"
)

// Errors surfaced by persistence.
var (
	// ErrPersistFailed wraps any write / chmod / rename failure during
	// artifact persistence. The caller MUST treat it as fatal — partial
	// writes are cleaned up by the function before return, but the on-disk
	// state may still be inconsistent if cleanup itself fails (logged).
	ErrPersistFailed = errors.New("enroll: persist failed")
)

// Filenames inside the state directory. Constants so the daemon (Phase 8)
// can reference them consistently when reading the artifacts back.
const (
	BeaconCertFilename     = "beacon.crt"
	BeaconKeyFilename      = "beacon.key"
	DEKFilename            = "dek.bin"
	PlatformCAFilename     = "platform-ca.pem"
	PlatformPubKeyFilename = "platform-pubkey.pem"
	MetadataFilename       = "enrollment-metadata.json"
)

// File modes. Mandated by ADR-081-adjacent (mTLS key perms):
//   - private key + DEK: 0600 (CWE-732 violation otherwise)
//   - certs + pubkey + metadata: 0644 (readable for ops; non-secret)
//   - state directory itself: 0700
const (
	modeStateDir = 0o700
	modeSecret   = 0o600
	modePublic   = 0o644
)

// Metadata is the human-readable summary written alongside the artifacts.
// Useful for the `status` subcommand (Phase 10) and ops debugging.
type Metadata struct {
	BeaconID                 uuid.UUID `json:"beacon_id"`
	EnrolledAt               time.Time `json:"enrolled_at"`
	ServerURL                string    `json:"server_url"`
	ConfigEndpoint           string    `json:"config_endpoint"`
	DataEndpoint             string    `json:"data_endpoint"`
	DEKVersion               int       `json:"dek_version"`
	HeartbeatIntervalSeconds int       `json:"heartbeat_interval_seconds"`
	LogBatchMaxAgeSeconds    int       `json:"log_batch_max_age_seconds"`
	LogBatchMaxBytes         int       `json:"log_batch_max_bytes"`
}

// Artifacts holds every byte the beacon needs to persist after a successful
// enrollment response. Callers MUST NOT persist them in any order other
// than what Persist enforces — partial state on a crash can mean a beacon
// that holds a cert but no DEK, which silently fails every data push.
type Artifacts struct {
	BeaconCertPEM     []byte
	BeaconKeyPEM      []byte
	DEK               []byte // raw 32 bytes; encoded base64 on the wire
	PlatformCAPEM     []byte
	PlatformPubKeyPEM []byte
	Metadata          Metadata
}

// Persist writes every artifact into stateDir using tmpfile + rename
// atomicity. On any error during the multi-file write, files that have
// already landed are removed before returning ErrPersistFailed; the caller
// can safely retry without manual cleanup.
//
// The order is chosen so that a crash mid-persist leaves the install
// either fully usable OR fully empty — never half-usable:
//
//  1. Public artifacts first (ca, pubkey, cert) — useless on their own.
//  2. Private key + DEK last — the bits that mean the beacon has been
//     successfully enrolled.
//  3. Metadata last of all — flags the install as "complete" for the
//     idempotency check.
//
// On Windows, os.Chmod's posix-bit handling is limited; we set 0600 anyway
// (Windows treats it as ReadOnly + a no-op for permission bits), and rely
// on the operator's filesystem ACL configuration for real protection.
// runtime.GOOS == "windows" callers MUST configure ACLs separately.
func Persist(stateDir string, art *Artifacts) (err error) {
	if err = os.MkdirAll(stateDir, modeStateDir); err != nil {
		return fmt.Errorf("%w: mkdir state dir: %w", ErrPersistFailed, err)
	}

	// On non-Windows, tighten the directory perms even if MkdirAll left
	// them looser (e.g., umask 022 → 0755).
	if runtime.GOOS != "windows" {
		if err = os.Chmod(stateDir, modeStateDir); err != nil {
			return fmt.Errorf("%w: chmod state dir: %w", ErrPersistFailed, err)
		}
	}

	// Track files we've successfully written so we can clean up on a
	// downstream failure. The deferred closure inspects the named return
	// `err` so it cleans up only on failure exit.
	written := []string{}
	defer func() {
		if err == nil {
			return
		}
		for _, p := range written {
			_ = os.Remove(p)
		}
	}()

	writes := []struct {
		name     string
		contents []byte
		mode     os.FileMode
	}{
		{PlatformCAFilename, art.PlatformCAPEM, modePublic},
		{PlatformPubKeyFilename, art.PlatformPubKeyPEM, modePublic},
		{BeaconCertFilename, art.BeaconCertPEM, modePublic},
		{BeaconKeyFilename, art.BeaconKeyPEM, modeSecret},
		{DEKFilename, art.DEK, modeSecret},
	}

	for _, w := range writes {
		path := filepath.Join(stateDir, w.name)
		if err = atomicWrite(path, w.contents, w.mode); err != nil {
			return fmt.Errorf("%w: %s: %w", ErrPersistFailed, w.name, err)
		}
		written = append(written, path)
	}

	// Metadata last — its presence marks the install as complete.
	metaPath := filepath.Join(stateDir, MetadataFilename)
	metaJSON, marshalErr := json.MarshalIndent(art.Metadata, "", "  ")
	if marshalErr != nil {
		err = fmt.Errorf("%w: metadata marshal: %w", ErrPersistFailed, marshalErr)
		return err
	}
	if err = atomicWrite(metaPath, metaJSON, modePublic); err != nil {
		return fmt.Errorf("%w: %s: %w", ErrPersistFailed, MetadataFilename, err)
	}
	return nil
}

// atomicWrite writes contents into a temp file, fsync's it, then renames
// over the destination. The rename is atomic on POSIX; on Windows it's
// effectively atomic for our use case (no other process is opening these
// files mid-rename — the daemon hasn't started yet at enroll time).
func atomicWrite(path string, contents []byte, mode os.FileMode) error {
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

	// Chmod BEFORE rename so the file lands with the right perms at the
	// final path — no race window with 0644 default.
	if err := os.Chmod(tmpName, mode); err != nil {
		cleanup()
		return fmt.Errorf("chmod temp: %w", err)
	}

	if err := os.Rename(tmpName, path); err != nil {
		cleanup()
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}
