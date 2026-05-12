package enroll

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func sampleArtifacts() *Artifacts {
	return &Artifacts{
		BeaconCertPEM:     []byte("-----BEGIN CERTIFICATE-----\nbeacon\n-----END CERTIFICATE-----\n"),
		BeaconKeyPEM:      []byte("-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n"),
		DEK:               []byte("0123456789abcdef0123456789abcdef"),
		PlatformCAPEM:     []byte("-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----\n"),
		PlatformPubKeyPEM: []byte("-----BEGIN PUBLIC KEY-----\npub\n-----END PUBLIC KEY-----\n"),
		Metadata: Metadata{
			BeaconID:                 uuid.MustParse("abcdef00-1234-4567-8901-abcdef012345"),
			EnrolledAt:               time.Date(2026, 5, 11, 0, 0, 0, 0, time.UTC),
			ServerURL:                "https://test.example.com:8443",
			ConfigEndpoint:           "https://test.example.com:8443/api/v1/beacons/{id}/config",
			DataEndpoint:             "https://test.example.com:8443/api/v1/beacons/{id}/data",
			DEKVersion:               1,
			HeartbeatIntervalSeconds: 60,
		},
	}
}

func TestPersistHappy(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, Persist(dir, sampleArtifacts()))

	// All six files landed.
	for _, name := range []string{
		BeaconCertFilename, BeaconKeyFilename, DEKFilename,
		PlatformCAFilename, PlatformPubKeyFilename, MetadataFilename,
	} {
		_, err := os.Stat(filepath.Join(dir, name))
		require.NoError(t, err, "missing %s", name)
	}
}

func TestPersistSecretFilesAre0600(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits aren't enforced on Windows; ACLs out of scope here")
	}
	dir := t.TempDir()
	require.NoError(t, Persist(dir, sampleArtifacts()))

	for _, name := range []string{BeaconKeyFilename, DEKFilename} {
		info, err := os.Stat(filepath.Join(dir, name))
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o600), info.Mode().Perm(),
			"%s must be 0600 (CWE-732)", name)
	}
}

func TestPersistPublicFilesAre0644(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits aren't enforced on Windows")
	}
	dir := t.TempDir()
	require.NoError(t, Persist(dir, sampleArtifacts()))

	for _, name := range []string{BeaconCertFilename, PlatformCAFilename, PlatformPubKeyFilename, MetadataFilename} {
		info, err := os.Stat(filepath.Join(dir, name))
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o644), info.Mode().Perm(), "%s must be 0644", name)
	}
}

func TestPersistMetadataRoundTrip(t *testing.T) {
	dir := t.TempDir()
	in := sampleArtifacts()
	require.NoError(t, Persist(dir, in))

	raw, err := os.ReadFile(filepath.Join(dir, MetadataFilename))
	require.NoError(t, err)
	var got Metadata
	require.NoError(t, json.Unmarshal(raw, &got))
	require.Equal(t, in.Metadata.BeaconID, got.BeaconID)
	require.Equal(t, in.Metadata.ServerURL, got.ServerURL)
	require.Equal(t, in.Metadata.DEKVersion, got.DEKVersion)
}

func TestPersistCreatesStateDir(t *testing.T) {
	parent := t.TempDir()
	newDir := filepath.Join(parent, "new-state")
	require.NoError(t, Persist(newDir, sampleArtifacts()))
	info, err := os.Stat(newDir)
	require.NoError(t, err)
	require.True(t, info.IsDir())
}

func TestPersistIsAtomicViaTmpfile(t *testing.T) {
	// After a successful Persist, no .tmp-* files should remain.
	dir := t.TempDir()
	require.NoError(t, Persist(dir, sampleArtifacts()))

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, e := range entries {
		require.NotContains(t, e.Name(), ".tmp-", "leftover tmpfile: %s", e.Name())
	}
}
