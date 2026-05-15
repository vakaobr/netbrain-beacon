//go:build linux

package mesh

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// ----------------------------------------------------------------------------
// renderMDMXML — snapshot-style: exact bytes.
// ----------------------------------------------------------------------------

func TestRenderMDMXML(t *testing.T) {
	got, err := renderMDMXML("netbrain-dev", "abc12345.access", "s3cr3t-value")
	require.NoError(t, err)

	want := `<?xml version="1.0" encoding="UTF-8"?>
<dict>
  <organization>netbrain-dev</organization>
  <auth_client_id>abc12345.access</auth_client_id>
  <auth_client_secret>s3cr3t-value</auth_client_secret>
  <service_mode>warp</service_mode>
  <auto_connect>1</auto_connect>
  <onboarding>false</onboarding>
</dict>
`
	require.Equal(t, want, got)
}

func TestRenderMDMXML_EmptyFieldsRejected(t *testing.T) {
	_, err := renderMDMXML("", "abc.access", "secret")
	require.Error(t, err)
	_, err = renderMDMXML("slug", "", "secret")
	require.Error(t, err)
	_, err = renderMDMXML("slug", "abc.access", "")
	require.Error(t, err)
}

func TestRenderMDMXML_EscapesSpecialChars(t *testing.T) {
	// Defense in depth: if the secret somehow contains XML metachars,
	// they're HTML-escaped so the daemon sees the literal bytes back
	// out (vs. a broken / truncated XML structure).
	got, err := renderMDMXML("slug", "abc.access", "s&cret<>")
	require.NoError(t, err)
	require.Contains(t, got, "s&amp;cret&lt;&gt;")
	require.NotContains(t, got, "s&cret<>")
}

// ----------------------------------------------------------------------------
// deriveTeamSlugFromDomain — happy paths + reject malformed.
// ----------------------------------------------------------------------------

func TestDeriveTeamSlugFromDomain_Happy(t *testing.T) {
	got, err := deriveTeamSlugFromDomain("netbrain-dev.cloudflareaccess.com")
	require.NoError(t, err)
	require.Equal(t, "netbrain-dev", got)
}

func TestDeriveTeamSlugFromDomain_BareSlugIdempotent(t *testing.T) {
	got, err := deriveTeamSlugFromDomain("netbrain-dev")
	require.NoError(t, err)
	require.Equal(t, "netbrain-dev", got)
}

func TestDeriveTeamSlugFromDomain_StripsScheme(t *testing.T) {
	got, err := deriveTeamSlugFromDomain("https://netbrain-dev.cloudflareaccess.com/")
	require.NoError(t, err)
	require.Equal(t, "netbrain-dev", got)
}

func TestDeriveTeamSlugFromDomain_RejectsEmpty(t *testing.T) {
	_, err := deriveTeamSlugFromDomain("")
	require.Error(t, err)
	_, err = deriveTeamSlugFromDomain("   ")
	require.Error(t, err)
}

func TestDeriveTeamSlugFromDomain_RejectsMultiLabel(t *testing.T) {
	// Stripping the suffix would leave "team.subdomain" which isn't a
	// single DNS label — reject.
	_, err := deriveTeamSlugFromDomain("team.subdomain.cloudflareaccess.com")
	require.Error(t, err)
}

func TestDeriveTeamSlugFromDomain_RejectsWhitespaceMid(t *testing.T) {
	_, err := deriveTeamSlugFromDomain("netbrain dev.cloudflareaccess.com")
	require.Error(t, err)
}

// ----------------------------------------------------------------------------
// ensureAccessSuffix — append-if-missing, idempotent.
// ----------------------------------------------------------------------------

func TestAuthClientIDSuffix_AppendsWhenMissing(t *testing.T) {
	require.Equal(t, "abc.access", ensureAccessSuffix("abc"))
}

func TestAuthClientIDSuffix_LeavesAloneWhenPresent(t *testing.T) {
	require.Equal(t, "abc.access", ensureAccessSuffix("abc.access"))
}

func TestAuthClientIDSuffix_TrimsWhitespace(t *testing.T) {
	require.Equal(t, "abc.access", ensureAccessSuffix("  abc  "))
}

func TestAuthClientIDSuffix_EmptyStaysEmpty(t *testing.T) {
	require.Equal(t, "", ensureAccessSuffix(""))
	require.Equal(t, "", ensureAccessSuffix("   "))
}

// ----------------------------------------------------------------------------
// writeFileAtomic0600 — verifies the file is written with mode 0600 and
// the temp file disappears on rename.
// ----------------------------------------------------------------------------

func TestMDMFileMode0600(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "mdm.xml")
	require.NoError(t, writeFileAtomic0600(target, "<dict/>\n"))

	info, err := os.Stat(target)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm(),
		"expected mode 0600, got %#o", info.Mode().Perm())

	// Confirm contents written intact.
	body, err := os.ReadFile(target) //nolint:gosec // test path
	require.NoError(t, err)
	require.Equal(t, "<dict/>\n", string(body))

	// Temp file should not survive (the .mdm-xml-* glob is empty).
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, e := range entries {
		require.False(t, strings.HasPrefix(e.Name(), ".mdm-xml-"),
			"orphan temp file: %s", e.Name())
	}
}

func TestWriteFileAtomic0600_Overwrite(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "mdm.xml")
	require.NoError(t, writeFileAtomic0600(target, "first"))
	require.NoError(t, writeFileAtomic0600(target, "second"))
	body, err := os.ReadFile(target) //nolint:gosec // test path
	require.NoError(t, err)
	require.Equal(t, "second", string(body))
}

// ----------------------------------------------------------------------------
// Enroll happy path: writes MDM file at the override path; mdm refresh
// succeeds (fake CLI returns exit 0); restart fallback NOT invoked.
// ----------------------------------------------------------------------------

func TestEnroll_Linux_WritesMDMFile_HappyPath(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "mdm.xml")

	path, _ := writeFakeWarpCLI(t)

	restartCalled := false
	c := &cliClient{
		binPath: path,
		goos:    "linux",
		mdmPath: func() string { return target },
		runRestart: func(_ context.Context) error {
			restartCalled = true
			return nil
		},
	}

	err := c.Enroll(context.Background(), Credentials{
		WARPTeamDomain:     "netbrain-dev.cloudflareaccess.com",
		TeamAccountID:      "acct-id",
		ServiceTokenClient: "abc",
		ServiceTokenSecret: "secret",
	})
	require.NoError(t, err)
	require.False(t, restartCalled, "systemctl restart should NOT have been called on mdm-refresh success")

	// Verify file exists, mode 0600, contains escaped fields.
	info, err := os.Stat(target)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	body, err := os.ReadFile(target) //nolint:gosec // test path
	require.NoError(t, err)
	require.Contains(t, string(body), "<organization>netbrain-dev</organization>")
	require.Contains(t, string(body), "<auth_client_id>abc.access</auth_client_id>")
	require.Contains(t, string(body), "<auth_client_secret>secret</auth_client_secret>")
}

// ----------------------------------------------------------------------------
// Enroll: warp-cli mdm refresh returns "unrecognized subcommand" → falls
// back to systemctl restart. Verifies the runRestart hook IS called.
// ----------------------------------------------------------------------------

func TestWarpSvcRestartFallback_OnUnsupportedMDMRefresh(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "mdm.xml")

	path, marker := writeFakeWarpCLI(t)
	writeMarker(t, marker, "mdm-unsupported")

	restartCalled := false
	c := &cliClient{
		binPath: path,
		goos:    "linux",
		mdmPath: func() string { return target },
		runRestart: func(_ context.Context) error {
			restartCalled = true
			return nil
		},
	}

	err := c.Enroll(context.Background(), Credentials{
		WARPTeamDomain:     "netbrain-dev.cloudflareaccess.com",
		ServiceTokenClient: "abc",
		ServiceTokenSecret: "secret",
	})
	require.NoError(t, err)
	require.True(t, restartCalled, "systemctl restart should have been called when mdm refresh is unsupported")
}

// ----------------------------------------------------------------------------
// Enroll: mdm refresh fails (non-unsupported) AND restart fails →
// ErrWARPCLIFailed surfaces the restart error.
// ----------------------------------------------------------------------------

func TestEnroll_RefreshAndRestartBothFail_ReturnsWARPCLIFailed(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "mdm.xml")

	path, marker := writeFakeWarpCLI(t)
	writeMarker(t, marker, "mdm-fail")

	c := &cliClient{
		binPath: path,
		goos:    "linux",
		mdmPath: func() string { return target },
		runRestart: func(_ context.Context) error {
			return errors.New("systemctl: unit warp-svc.service not found")
		},
	}

	err := c.Enroll(context.Background(), Credentials{
		WARPTeamDomain:     "netbrain-dev.cloudflareaccess.com",
		ServiceTokenClient: "abc",
		ServiceTokenSecret: "secret",
	})
	require.Error(t, err)
	require.ErrorIs(t, err, ErrWARPCLIFailed)
}

// ----------------------------------------------------------------------------
// Enroll: missing required credentials short-circuits with WARPCLIFailed
// BEFORE touching the disk.
// ----------------------------------------------------------------------------

func TestEnroll_MissingCredentials(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "mdm.xml")

	c := &cliClient{
		binPath: "/nonexistent",
		goos:    "linux",
		mdmPath: func() string { return target },
		runRestart: func(_ context.Context) error {
			return nil
		},
	}

	// Missing WARPTeamDomain.
	err := c.Enroll(context.Background(), Credentials{
		ServiceTokenClient: "abc",
		ServiceTokenSecret: "secret",
	})
	require.ErrorIs(t, err, ErrWARPCLIFailed)

	// Verify the file was NOT created (early return).
	_, statErr := os.Stat(target)
	require.True(t, os.IsNotExist(statErr), "mdm.xml must not exist when creds fail validation")
}
