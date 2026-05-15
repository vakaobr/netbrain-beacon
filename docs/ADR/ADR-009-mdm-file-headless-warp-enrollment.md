# ADR-009: MDM-file headless WARP enrollment (`internal/mesh` pivot)

**Status:** Accepted
**Date:** 2026-05-15
**Context issue:** fix-beacon-warp-cli-surface-drift (this repo) — v0.2.0-rc.2
**Pairs with:** netbrain ADR-091 (platform-side acknowledgement of the on-disk-secret posture; pending)
**Supersedes:** ADR-008 (only the specific argv contract; the sub-process boundary decision still applies)

## Context

ADR-008 captured the choice to drive Cloudflare WARP enrollment via the `warp-cli` sub-process — specifically the three-step argv sequence:

1. `warp-cli access set-default-account <team_account_id>`
2. `warp-cli access add-account-key <client_id> <client_secret>`
3. `warp-cli connect`

During the MacBook end-to-end test on 2026-05-14 (final integration step of `add-cloudflare-mesh-onboarding`), current WARP CLI builds — macOS 2026.x, Windows 2026.3.566.1, Linux package-installed `cloudflare-warp` — all rejected the `access` subcommand with:

```
error: unrecognized subcommand 'access'
  tip: a similar subcommand exists: 'certs'
```

Investigation (memory: `pending_beacon_warp_cli_surface_drift.md`) traced this to a Cloudflare-side removal of the `access` subcommand in early 2025. The headless Service-Token enrollment surface migrated to an MDM-file approach. The argv path that ADR-008 codified is gone permanently.

The beacon project shipped `v0.2.0-rc.1` (2026-05-14) carrying the deprecated argv and relied on `--skip-mesh` as a workaround. v0.2.0-rc.2 fixes the surface drift.

## Decision

Replace the deprecated argv sequence with an MDM-file path on Linux. The beacon writes the Cloudflare-prescribed XML dictionary to `/var/lib/cloudflare-warp/mdm.xml` BEFORE triggering the daemon to re-read its configuration. The daemon connects on its own via the file's `auto_connect=1` switch — no `warp-cli connect` is needed.

### File contents (Linux MDM dict)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<dict>
  <organization>netbrain-dev</organization>
  <auth_client_id>abc12345.access</auth_client_id>
  <auth_client_secret>...secret...</auth_client_secret>
  <service_mode>warp</service_mode>
  <auto_connect>1</auto_connect>
  <onboarding>false</onboarding>
</dict>
```

- `<organization>` is the team slug, derived from the bundle's `warp_team_domain` by stripping the `.cloudflareaccess.com` suffix.
- `<auth_client_id>` is the service-token client_id, with `.access` appended if missing (Cloudflare's MDM enrollment expects the suffixed form).
- `<auth_client_secret>` is the service-token secret from the decrypted bundle v2 envelope.

### Daemon refresh

After writing the file, the beacon attempts `warp-cli mdm refresh` (introduced in WARP CLI `>= 2026.4.1350.0`). If the subcommand is unrecognized (older WARP CLI) or returns an error, the beacon falls back to `systemctl restart warp-svc`. Either path causes the daemon to re-read the MDM file and connect.

### OS scope: Linux only in this release

Cloudflare publishes per-OS MDM enrollment surfaces:

| OS | Path | Format |
|---|---|---|
| Linux | `/var/lib/cloudflare-warp/mdm.xml` | XML |
| macOS | `/Library/Managed Preferences/com.cloudflare.warp.plist` | plist |
| Windows | `HKLM:\SOFTWARE\Cloudflare\CloudflareWARP\<key>=<value>` | registry |

This release implements **Linux only**. macOS and Windows return the exported `ErrMeshUnsupportedOS` and the operator follows a documented manual path: interactive `warp-cli registration new <team-slug>` (opens a browser callback) followed by `netbrain-beacon enroll ... --skip-mesh`. The Linux scope matches Velonet's customer-deployment shape (branch-site Linux boxes); macOS / Windows are Velonet-ops dogfooding boxes that tolerate the manual flow.

A future v0.3.0 may add plist + registry writers for the other two OSes if the dogfood load warrants it.

### File mode and atomicity

The file is written atomically — same-directory temp file at mode 0600 → rename → re-assert 0600 on the destination (defense in depth against destination-filesystem umask quirks). The directory itself is `mkdir -p` at mode 0700 if missing.

### Root precondition

The beacon process MUST run as root (uid 0) to land the file. `/var/lib/cloudflare-warp/` is a root-owned directory and the WARP daemon refuses non-root `mdm refresh` invocations. The runbook calls this out and the Linux packaging continues to install the beacon as a privileged-by-design system service. (Note: the prior `warp-cli access` argv path ALSO required root to talk to the warp-svc socket; the privilege requirement is unchanged in practice.)

## Security posture change: secret on disk

The architectural shift this ADR documents — beyond the argv-to-MDM pivot — is that the service-token client_secret now persists on disk at a well-known path. In ADR-008's argv sequence the secret only lived in memory during a 10-second subprocess call. In the MDM-file path it lives in `/var/lib/cloudflare-warp/mdm.xml` between runs, with the WARP daemon re-reading it on every `mdm refresh` / restart.

### Threat model delta

| Threat | argv path (ADR-008) | MDM path (this ADR) |
|---|---|---|
| Local-root attacker steals the secret | ✅ Yes (root sees argv via `/proc/.../cmdline` and ptrace) — already in the threat model | ✅ Yes (root reads the file directly) — **same outcome, different path** |
| Non-root local user steals the secret | ❌ No (argv is root-only in /proc) | ❌ No (file is mode 0600 root-only) |
| Offline-disk extraction | ❌ No (secret never persisted) | ✅ Yes — **NEW** |
| Process-list leak (`ps`, audit logs, shell history) | ✅ Yes — already the H-3 redactor pattern | ❌ No (no argv carries it) — **strictly better** |
| Defense in depth: `LimitNOFILE`, `ProtectSystem=strict` etc. | n/a | The systemd unit's existing pins cover the beacon process; the WARP daemon's own systemd hardening covers the mdm.xml read. |

The offline-disk vector is the only **new** exposure. Mitigations:

1. **Full-disk encryption on the state filesystem.** Already recommended for the bbolt store + private key (per ADR-002 + the existing § "Hardening guidance for low-trust hosts"). The MDM file lives in `/var/lib/cloudflare-warp` not `/var/lib/netbrain-beacon`, so operators must either put both directories on the same encrypted volume or add `/var/lib/cloudflare-warp` to the same FDE / LUKS / dm-crypt blanket.
2. **Service-token rotation policy.** The platform side (netbrain ADR-091 — pending) commits to rotating service tokens on the same cadence as bootstrap-token expiry windows (30-day baseline). A long-lived stale token at rest is a worse exposure than a daily-rotated one.
3. **Future enhancement (deferred):** zeroize the file on beacon `revoke` / `uninstall`. The naive `os.Remove` leaves the bytes in slack space; a follow-up issue tracks adding a zero-overwrite-then-remove path. Out of scope for v0.2.0-rc.2.

### Net assessment

The MDM-file posture is **strictly weaker than the argv path on the offline-disk vector** (the one new row) and **strictly stronger on the process-list-leak vector** (the prior row), with all other rows unchanged. Given that:

- The beacon's host trust model already assumes root on the host can read the private key, the DEK, and the bbolt store — adding the WARP secret to that root-readable set does not change the operator-trust requirement.
- The platform-side mitigation (rotate the service token) addresses the long-lived-stale exposure directly.
- The process-list-leak fix removes a real-in-the-wild leakage vector (operators DO have audit logs that capture argv).

The pivot is accepted. Documented for operators in the runbook's § "On-disk-secret invariant (Linux)" subsection.

## Alternatives considered

| Option | Pros | Cons | Decision |
|---|---|---|---|
| **A: Drop `internal/mesh` entirely** — document `--skip-mesh + interactive enroll` as canonical | Smallest code change | Customer-deployment shape needs headless; manual flow doesn't scale across thousands of branch sites | Rejected |
| **B: Linux-only MDM file (this ADR)** | Matches Velonet's customer profile; uses Cloudflare's supported surface | Two paths to maintain (Linux MDM vs macOS/Windows manual); on-disk secret posture change | **Accepted** |
| **C: Cross-OS MDM (Linux XML + macOS plist + Windows registry)** | Single headless code path everywhere | M-L effort; macOS plist + Windows registry writers each need their own atomicity + permissions story; insufficient dogfood volume to justify upfront | Deferred to v0.3.0 |
| **D: Reverse-engineer the WARP local socket protocol** | No file persistence; no argv leak | Protocol is undocumented and version-unstable; explicitly rejected by ADR-008's alternatives table | Rejected |
| **E: `warp-cli registration new <team-slug>` programmatic invocation** | Cloudflare-blessed interactive surface | Opens browser callback — not headless; doesn't accept a service token | Rejected |

## Consequences

### Positive

- Headless Service-Token enrollment works on Linux against current Cloudflare WARP CLI builds (the primary deployment target).
- Process-list-leak attack surface for the service-token secret is gone — argv no longer carries it.
- The `Client` interface is unchanged; only the field set of `Credentials` grew (`WARPTeamDomain` is new).
- Build-tag split (`mdm_linux.go` / `mdm_other.go`) keeps the platform-specific path testable without runtime branching in every code path.
- Test injection for the `systemctl restart` fallback is via a function-field override (`cliClient.runRestart`), staying consistent with the table-driven test patterns elsewhere in the repo.

### Negative

- Service-token secret persists on disk at a known path between runs (mode 0600). Mitigated as documented above.
- macOS / Windows operators take a manual-step penalty in this release.
- The minimum supported `warp-cli` version is now pinned to `>= 2026.1.150.0`. Operators on older WARP installs (an empty set today; Cloudflare auto-updates) would need to upgrade.

### Risks

- **Cloudflare changes the MDM file schema or path.** The XML field names and `/var/lib/cloudflare-warp/mdm.xml` location are documented Cloudflare contract surfaces; less version-volatile than CLI argv but not immune. **Mitigation:** Phase 7 integration test re-runs the enrollment ceremony against the live WARP package on every WARP release we onboard; `TestRenderMDMXML` is a snapshot test that fails loudly on any field-name typo introduced during a refactor.
- **`auto_connect=1` triggers connections at unwanted times.** When `mdm.xml` is dropped, the daemon connects unconditionally. **Acceptable:** the beacon's whole purpose is to be connected. Operator concerns about residual connection on uninstall are addressed in the runbook's "Full uninstall" section by clearing the MDM file before removing the beacon.

## References

- ADR-008 (this repo) — original WARP CLI sub-process wrapper decision; this ADR records the pivot but doesn't supersede the broader sub-process boundary choice.
- netbrain ADR-091 — platform-side on-disk-secret posture acknowledgement (pending).
- Cloudflare WARP MDM deployment parameters: <https://developers.cloudflare.com/cloudflare-one/connections/connect-devices/warp/deployment/mdm-deployment/parameters/>
- Cloudflare headless Linux tutorial: <https://developers.cloudflare.com/cloudflare-one/tutorials/warp-on-headless-linux/>
- Pending-memory note: `pending_beacon_warp_cli_surface_drift.md` (closed by this ADR).
