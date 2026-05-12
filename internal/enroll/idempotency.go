package enroll

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// Errors surfaced by the idempotency check.
var (
	// ErrAlreadyEnrolled is returned when stateDir already contains a
	// complete enrollment-metadata.json. The operator must pass --force
	// to overwrite (typical use: re-enroll after platform CA rotation
	// or beacon decommission/restore).
	ErrAlreadyEnrolled = errors.New("enroll: beacon is already enrolled at this state dir")
)

// CheckNotEnrolled returns nil if stateDir does NOT contain a complete
// enrollment-metadata.json, and ErrAlreadyEnrolled otherwise.
//
// "Complete" here means: the metadata file exists, parses as JSON, and has
// a non-zero BeaconID. Partial state (cert without metadata, etc.) is
// treated as "not enrolled" — the user can re-run enroll safely.
//
// The check is intentionally cheap (single stat + json parse) so callers
// can run it before any expensive enrollment work.
func CheckNotEnrolled(stateDir string) error {
	path := filepath.Join(stateDir, MetadataFilename)
	raw, err := os.ReadFile(path) //nolint:gosec // stateDir is operator-supplied via CLI flag; not user-controllable web input
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		// Read error other than not-exist (permission denied etc.) — fail
		// closed: don't proceed with enrollment if we can't tell.
		return fmt.Errorf("enroll: stat metadata: %w", err)
	}

	var meta Metadata
	if err := json.Unmarshal(raw, &meta); err != nil {
		// Garbage metadata file → treat as not-enrolled (allow recovery).
		return nil
	}
	if meta.BeaconID.String() == "00000000-0000-0000-0000-000000000000" {
		// Zero UUID → also treat as not-enrolled.
		return nil
	}

	return fmt.Errorf("%w: beacon_id=%s enrolled_at=%s", ErrAlreadyEnrolled, meta.BeaconID, meta.EnrolledAt)
}
