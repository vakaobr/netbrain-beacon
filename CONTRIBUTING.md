# Contributing to netbrain-beacon

The beacon is the customer-edge half of the NetBrain platform. The
upstream half lives at github.com/velonet/netbrain. The two repos ship
on independent cadences but share a single OpenAPI contract, so most
contributions here happen in response to a paired PR over there.

## Paired-repo conventions

### Adding or changing a server-side error code

The OpenAPI spec at `netbrain/services/api-gateway/openapi/beacon-v1.yaml`
catalogues every error code the platform returns to a beacon. Every code
maps to a `transport.Action` constant in
[`internal/transport/errors.go`](internal/transport/errors.go) — that map
(`codeActions`) is the single source of truth for how the beacon reacts.

When the platform PR adds a new code, a coordinated PR here MUST:

1. Append the code to `codeActions` with the right `Action`. Pick from
   `ActionRetry` (transient), `ActionDropAndAlert` (your payload is
   broken), `ActionFatalReenroll` (your identity is broken),
   `ActionBackOffHeavy` (feature flag off), `ActionRefreshDEK` (key
   expired). Adding a new `Action` requires a separate PR + ADR.
2. Add a round-trip test in `internal/transport/errors_test.go` proving
   `Classify` dispatches the code to the chosen action.
3. Reference the platform PR + the OpenAPI version bump in the PR
   description, so the cross-repo audit trail is searchable.

Failing to do this is detected at runtime — `Classify`'s 4xx fallback
returns `ActionFatalReenroll`, which halts the affected collector on
the first encounter. This is intentional (fail-closed > silent drops)
but it WILL page on-call.

### Adding or changing an ADR

ADRs in this repo live under [`docs/ADR/`](docs/ADR/) and number from
001 upward. Each ADR has a `Pairs with` header line pointing to the
matching ADR in the netbrain repo (e.g., `Pairs with
netbrain/ADR/ADR-077-beacon-binary-layout.md`). The pairing is
informational — netbrain owns one canonical numbering for the joint
system, this repo owns its own sequence for ADRs whose blast radius is
beacon-only.

When updating an ADR's status (Proposed → Accepted → Superseded), copy
the change to the paired netbrain ADR in the same PR cycle.

### Shipping a wire-format change

Wire-format changes (envelope shape, AAD layout, DEK rotation header
format, OpenAPI request/response shapes) require:

- A platform-side PR landing FIRST behind a feature flag (e.g.,
  `BEACON_PROTOCOL_V2_ENABLED`). The flag MUST default off in prod.
- A beacon-side PR that detects the platform's flag state via the
  OpenAPI version negotiation header and falls back to the old format
  if it sees a v1-only server.
- A staged rollout: enable the flag on staging, run
  `/security/pentest add-multi-mode-ingestion` (or the equivalent for
  whatever feature added the new wire shape), THEN enable on prod.

Breaking the wire format without a flag breaks every deployed beacon
silently — the audit pipeline will not save you. The flag is mandatory.

## Local development

```bash
make build         # build the binary
make test          # run the test suite (race detector on)
make lint          # golangci-lint v2
make cross         # build all platform binaries (linux/darwin/windows)
```

CI runs `lint + test + build` on every PR; merges require all green.

## Filing a security finding

If you find a security issue in this repo, do NOT open a public issue.
Email `security@velonet.example` instead (placeholder — replace before
public release). The maintainers will respond within 48 h.

## Style

- Go 1.26 minimum. `gofmt` is enforced by CI.
- Test names: `Test<Subject><Behavior>`, e.g.,
  `TestClassifyReturnsRetryOn5xxWithoutKnownCode`.
- One assertion concept per test. Use `testify/require` for blocking
  asserts, `testify/assert` only when continuation makes sense.
- No `//nolint:gosec` without a one-line `// reason: ...` comment
  alongside.
