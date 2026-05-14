# ADR-008: WARP CLI sub-process wrapper (`internal/mesh`)

**Status:** Accepted
**Date:** 2026-05-14
**Context issue:** add-cloudflare-mesh-onboarding (cross-repo)
**Pairs with:** [netbrain/ADR/ADR-088-cloudflare-integration-module-and-fernet-wrapped-api-token.md](https://github.com/velonet/netbrain/blob/main/.claude/planning/add-cloudflare-mesh-onboarding/03_ADR-088-cloudflare-integration-module-and-fernet-wrapped-api-token.md) — the platform side mints the Service Token; this ADR records how the beacon consumes it via the WARP CLI.

## Context

The bundle v2 envelope (ADR-007) decrypts to a Cloudflare Service-Token credential set: `{cf_service_token_client_id, cf_service_token_client_secret, cf_team_account_id}`. To attach the host to the platform's WARP team headlessly, the beacon must drive the WARP CLI through:

1. `warp-cli access set-default-account <team_account_id>`
2. `warp-cli access add-account-key <client_id> <client_secret>`
3. `warp-cli connect`
4. Poll `warp-cli status` until "Connected".

Three architectural choices were on the table:

- Link a Cloudflare library directly.
- Talk to the WARP daemon's local socket.
- Shell out to `warp-cli` as a sub-process.

## Decision

Shell out to `warp-cli` via `os/exec.CommandContext`. The wrapper lives in `internal/mesh/warp.go` behind a small `Client` interface so tests can inject a fake binary path via `NewClient(binPath)`.

### Why sub-process

- **WARP is a system service, not a library.** Cloudflare distributes WARP as platform packages (deb / rpm / pkg / msi). Any interaction goes through the local socket the CLI already wraps. There is no first-party Go SDK.
- **Sub-process boundary insulates from WARP version drift.** Operators upgrade WARP without recompiling the beacon. The CLI's argv contract is far more stable than internal socket protocols.
- **Matches the documented operator path.** What the beacon does on a given customer machine is identical to what an operator would type at the shell. Diagnosis is straightforward: rerun the same `warp-cli` command and compare output.

### Status discrimination

The status check uses a regex word-boundary match (`\bconnected\b` case-insensitive, while also rejecting any output containing `\bdisconnected\b`) rather than a naive substring search. A substring search false-positives on "Disconnected" — we caught this in Linux CI on the first cross-platform test run.

### Test injection

`Client` is a small interface with three methods (`Enroll`, `IsEnrolled`, `PollEnrolled`). Tests pass a path to a tiny POSIX shell-script or Windows `.cmd` fake binary that reads a marker file to choose its response. Windows tests gate behind `runtime.GOOS != "windows"` because `.cmd` scripts have execution-policy nuances that aren't worth fighting in unit tests — the Windows code path is exercised in integration tests at Phase 7.

### Secret redaction

`redactArgs` strips the Service-Token secret from error messages (`access add-account-key <client_id> <redacted>`) so a failed-step error log doesn't leak the secret into operator log files or audit logs. This is the same pattern as `--bundle-file` vs `--bundle` from add-beacon-service (CWE-214).

## Alternatives Considered

| Option | Pros | Cons |
|---|---|---|
| **A: Link a Cloudflare Go SDK** | No sub-process overhead; type-safe | No first-party Go SDK exists; community alternatives are unmaintained |
| **B: Talk to the WARP local socket directly** | Faster than sub-process; programmatic status | Socket protocol is undocumented and version-unstable; brittle across WARP upgrades |
| **C: Shell out to warp-cli (this ADR)** | Stable argv contract; matches operator workflow; trivial to mock; secret redaction at one boundary | Sub-process overhead (~5 ms per call); requires WARP CLI installed |

Picked **C**. Sub-process overhead is irrelevant for a one-shot enroll command, and the version-stability win is decisive.

## Consequences

### Positive

- WARP version upgrades are zero-touch on the beacon side.
- Testable via fake binaries (no real WARP daemon needed in unit tests).
- Secret redaction is centralized at `redactArgs`.
- Clear `ErrWARPCLINotFound` vs `ErrWARPCLIFailed` vs `ErrWARPNotEnrolled` errors give operators an actionable diagnostic.

### Negative

- WARP CLI must be installed on the customer machine before running `enroll`. The beacon detects a missing binary and exits with `ErrWARPCLINotFound`; the runbook covers the install path.
- Status regex (`\bconnected\b`) is a fragile dependency on the CLI's output format. If Cloudflare reformats the status line, the regex needs an update. **Mitigation:** the negative-case word-boundary check (`\bdisconnected\b` ⇒ explicit not-enrolled) gives us a stable fallback signal.

### Risks

- **CLI output format change between WARP versions.** Cloudflare has reformatted the status line at least once in 2024. **Mitigation:** the regex pair is intentionally lenient on what comes around the keyword. Phase 7's two-machine integration test catches any breakage on a real CLI.
- **`--skip-mesh` operator escape hatch.** When the platform is reachable without the mesh (LAN-only deployments), operators can pass `--skip-mesh` to bypass the WARP enrollment entirely. The bundle's WARP credentials are then ignored. **Acceptable:** the deploy-plan documents when this is appropriate.

## References

- netbrain `ADR-088` — Cloudflare integration module (Python side, platform mint)
- Cloudflare Zero Trust → WARP CLI docs (community-link)
- ADR-007 — bundle v2 + WARP envelope (this repo's Go reader)
