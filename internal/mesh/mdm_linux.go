//go:build linux

package mesh

import (
	"context"
	"errors"
	"fmt"
	"html"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// defaultMDMPath is the canonical on-disk path Cloudflare's WARP daemon
// reads on Linux. The file MUST exist BEFORE `warp-svc` starts (or be
// followed by `warp-cli mdm refresh` on >= 2026.4.1350.0); we choose the
// `mdm refresh` fast-path first and fall back to a service restart.
//
// Reference:
//   - <https://developers.cloudflare.com/cloudflare-one/connections/connect-devices/warp/deployment/mdm-deployment/parameters/>
//   - <https://developers.cloudflare.com/cloudflare-one/tutorials/warp-on-headless-linux/>
const linuxMDMPath = "/var/lib/cloudflare-warp/mdm.xml"

// defaultMDMPath is the function the constructor wires into
// cliClient.mdmPath. Linux: the well-known path. Tests override the
// field directly.
var defaultMDMPath = func() string { return linuxMDMPath }

// Enroll on Linux performs the MDM-file-based headless enrollment:
//
//  1. Render the XML payload from creds + bundle's WARPTeamDomain.
//  2. Atomically write the file at /var/lib/cloudflare-warp/mdm.xml,
//     mode 0600 (the daemon runs as root and reads it; nothing else on
//     the host should be able to).
//  3. Try `warp-cli mdm refresh` (introduced in WARP CLI 2026.4.1350.0).
//  4. On failure, fall back to `systemctl restart warp-svc`.
//
// The MDM file carries `auto_connect=1` and `service_mode=warp` so the
// daemon connects itself once it picks up the file — no `warp-cli
// connect` call needed. Status polling is the caller's job (the enroll
// command runs PollEnrolled after this returns).
//
// Precondition: this MUST run as root (uid 0). The MDM file lives in a
// root-owned directory and the daemon refuses non-root mdm refresh
// invocations. The enroll runbook documents this.
//
// Security: the service-token client_secret is now persisted on disk at
// a well-known path. Mode 0600 + root ownership scopes read access to
// the daemon and root only. See ADR-009 for the on-disk-secret posture
// decision (paired with netbrain ADR-091).
func (c *cliClient) Enroll(ctx context.Context, creds Credentials) error {
	if creds.WARPTeamDomain == "" || creds.ServiceTokenClient == "" || creds.ServiceTokenSecret == "" {
		return fmt.Errorf("%w: missing required field in Credentials (need WARPTeamDomain + ServiceTokenClient + ServiceTokenSecret)", ErrWARPCLIFailed)
	}

	// Refuse to run on non-Linux even when the linux-tagged file is
	// somehow compiled in (defensive — build tags should prevent this).
	if c.goos != "" && c.goos != "linux" {
		return ErrMeshUnsupportedOS
	}

	slug, err := deriveTeamSlugFromDomain(creds.WARPTeamDomain)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrWARPCLIFailed, err)
	}
	clientID := ensureAccessSuffix(creds.ServiceTokenClient)

	xmlBody, err := renderMDMXML(slug, clientID, creds.ServiceTokenSecret)
	if err != nil {
		return fmt.Errorf("%w: render mdm xml: %w", ErrWARPCLIFailed, err)
	}

	target := c.mdmPath()
	if writeErr := writeFileAtomic0600(target, xmlBody); writeErr != nil {
		return fmt.Errorf("%w: write %s: %w", ErrWARPCLIFailed, target, writeErr)
	}

	// Best-effort: ask the daemon to re-read the MDM file. If the
	// subcommand doesn't exist (old WARP CLI) or the daemon rejects
	// it, fall back to a full service restart.
	if refreshErr := c.mdmRefresh(ctx); refreshErr != nil {
		if !errors.Is(refreshErr, errMDMRefreshUnsupported) {
			// Not the "unsupported" sentinel — real failure. Still try
			// the restart path; that's the more universal trigger.
			_ = refreshErr // surface in restart-failure error chain below
		}
		if restartErr := c.runRestart(ctx); restartErr != nil {
			return fmt.Errorf("%w: %w (mdm refresh: %v)", ErrWARPCLIFailed, restartErr, refreshErr)
		}
	}

	return nil
}

// mdmRefresh shells out to `warp-cli mdm refresh`. Returns
// errMDMRefreshUnsupported when the subcommand doesn't exist (old WARP
// CLI), and ErrWARPCLINotFound when the binary itself is missing. Any
// other failure is wrapped as ErrWARPCLIFailed.
func (c *cliClient) mdmRefresh(ctx context.Context) error {
	refreshCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if _, lookupErr := exec.LookPath(c.binPath); lookupErr != nil {
		return fmt.Errorf("%w: %w", ErrWARPCLINotFound, lookupErr)
	}
	_, stderr, err := c.run(refreshCtx, "mdm", "refresh")
	if err != nil {
		// Heuristic: if stderr names the subcommand as unrecognized,
		// flag as unsupported so the caller can fall back to systemctl.
		errLow := strings.ToLower(stderr)
		if strings.Contains(errLow, "unrecognized subcommand") ||
			strings.Contains(errLow, "unknown subcommand") ||
			strings.Contains(errLow, "error: unrecognized argument") {
			return errMDMRefreshUnsupported
		}
		return fmt.Errorf("%w: mdm refresh: %s", ErrWARPCLIFailed, strings.TrimSpace(stderr))
	}
	return nil
}

// deriveTeamSlugFromDomain extracts the team slug from a Cloudflare
// Access team domain. Accepts either the full
// "<slug>.cloudflareaccess.com" form or the bare slug (idempotent on the
// already-stripped form). Empty / malformed inputs return an error.
func deriveTeamSlugFromDomain(domain string) (string, error) {
	d := strings.TrimSpace(domain)
	if d == "" {
		return "", errors.New("WARPTeamDomain is empty")
	}
	// Tolerate operator pasting the full URL with scheme — strip it.
	d = strings.TrimPrefix(d, "https://")
	d = strings.TrimPrefix(d, "http://")
	d = strings.TrimSuffix(d, "/")

	d = strings.TrimSuffix(d, ".cloudflareaccess.com")
	if d == "" || strings.ContainsAny(d, " \t\r\n") {
		return "", fmt.Errorf("WARPTeamDomain %q does not resolve to a usable team slug", domain)
	}
	// A team slug is a single DNS label — no embedded dots, no slashes.
	if strings.ContainsAny(d, "./\\") {
		return "", fmt.Errorf("WARPTeamDomain %q does not resolve to a single-label team slug", domain)
	}
	return d, nil
}

// ensureAccessSuffix appends `.access` to a service-token client_id
// when missing. Cloudflare's MDM enrollment expects the suffixed form.
func ensureAccessSuffix(clientID string) string {
	c := strings.TrimSpace(clientID)
	if c == "" {
		return c
	}
	if strings.HasSuffix(c, ".access") {
		return c
	}
	return c + ".access"
}

// renderMDMXML produces the Linux MDM-file payload from the three
// inputs. The format mirrors Cloudflare's published example: an XML
// dict with element-per-key. Values are HTML-escaped to defend against
// stray `&` / `<` / `>` in either the slug or the secret (unlikely but
// the defense is cheap).
func renderMDMXML(orgSlug, authClientID, authClientSecret string) (string, error) {
	if orgSlug == "" || authClientID == "" || authClientSecret == "" {
		return "", errors.New("renderMDMXML: empty argument")
	}
	// We use a fixed key order so snapshot tests are stable.
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString("<dict>\n")
	b.WriteString("  <organization>" + html.EscapeString(orgSlug) + "</organization>\n")
	b.WriteString("  <auth_client_id>" + html.EscapeString(authClientID) + "</auth_client_id>\n")
	b.WriteString("  <auth_client_secret>" + html.EscapeString(authClientSecret) + "</auth_client_secret>\n")
	b.WriteString("  <service_mode>warp</service_mode>\n")
	b.WriteString("  <auto_connect>1</auto_connect>\n")
	b.WriteString("  <onboarding>false</onboarding>\n")
	b.WriteString("</dict>\n")
	return b.String(), nil
}

// writeFileAtomic0600 writes `body` to `target` via a same-directory
// temp file + rename, leaving the final file at mode 0600. The temp
// file is created with mode 0600 from the outset so the secret never
// transits a wider-permission state. If anything fails the temp file
// is removed.
func writeFileAtomic0600(target, body string) error {
	dir := filepath.Dir(target)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".mdm-xml-*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()
	// Tighten the mode immediately — CreateTemp opens at 0600 on most
	// platforms but we explicitly call Chmod for defense in depth.
	if chmodErr := os.Chmod(tmpName, 0o600); chmodErr != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("chmod 0600 %s: %w", tmpName, chmodErr)
	}
	if _, writeErr := tmp.WriteString(body); writeErr != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("write %s: %w", tmpName, writeErr)
	}
	if syncErr := tmp.Sync(); syncErr != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("sync %s: %w", tmpName, syncErr)
	}
	if closeErr := tmp.Close(); closeErr != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("close %s: %w", tmpName, closeErr)
	}
	if renameErr := os.Rename(tmpName, target); renameErr != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("rename %s -> %s: %w", tmpName, target, renameErr)
	}
	// Re-assert the final mode in case rename inherited something
	// looser from the destination filesystem's umask quirks.
	if chmodErr := os.Chmod(target, 0o600); chmodErr != nil {
		return fmt.Errorf("chmod 0600 %s: %w", target, chmodErr)
	}
	return nil
}
