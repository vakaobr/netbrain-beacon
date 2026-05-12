package enroll

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCheckNotEnrolledEmptyDir(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, CheckNotEnrolled(dir))
}

func TestCheckNotEnrolledMissingDir(t *testing.T) {
	require.NoError(t, CheckNotEnrolled(filepath.Join(t.TempDir(), "does-not-exist")))
}

func TestCheckNotEnrolledAfterPersist(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, Persist(dir, sampleArtifacts()))

	err := CheckNotEnrolled(dir)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrAlreadyEnrolled))
}

func TestCheckNotEnrolledZeroUUIDTreatedAsClean(t *testing.T) {
	dir := t.TempDir()
	// A metadata file with the zero UUID — treat as not enrolled (allow recovery).
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, MetadataFilename),
		[]byte(`{"beacon_id":"00000000-0000-0000-0000-000000000000"}`),
		0o644,
	))
	require.NoError(t, CheckNotEnrolled(dir))
}

func TestCheckNotEnrolledGarbageMetadataTreatedAsClean(t *testing.T) {
	dir := t.TempDir()
	// Corrupted metadata file — operator can recover by re-enrolling.
	require.NoError(t, os.WriteFile(filepath.Join(dir, MetadataFilename), []byte("garbage"), 0o644))
	require.NoError(t, CheckNotEnrolled(dir))
}
