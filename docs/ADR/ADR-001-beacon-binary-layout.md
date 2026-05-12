# ADR-001: Beacon binary layout (`cmd/` + `internal/` structure)

**Status:** Accepted
**Date:** 2026-05-10
**Context issue:** add-beacon-service
**Supersedes / superseded by:** none
**Pairs with:** [netbrain/ADR/ADR-077-beacon-binary-layout.md](https://github.com/velonet/netbrain/blob/main/ADR/ADR-077-beacon-binary-layout.md) — same architectural decision, netbrain canonical numbering.
**Companion ADRs:** ADR-002, ADR-003, ADR-004, ADR-005, ADR-006

## Context

`netbrain-beacon` is a greenfield Go repository. Today it contains an `initial commit` and a 16-byte README. We need a directory layout that:

1. Hosts a single CLI entrypoint binary with subcommands (`enroll`, `daemon`, `status`, `collectors`, `logs`, `version`).
2. Discourages accidental external use of beacon internals (this is **not** a public library; nothing here is meant to be importable by other repos).
3. Demarcates code that is **generated** (the OpenAPI client) from code that is **hand-written** (everything else), so contributors don't accidentally edit generated files.
4. Keeps test fixtures co-located with the package they exercise, except for the cross-language fixtures that span Python ↔ Go (those go under `tests/fixtures/cross_lang/` per ADR-004).
5. Co-exists with packaging artifacts (deb, rpm, Arch PKGBUILD, tarball, systemd unit per D-4) without polluting the Go module tree.

Two community-standard layouts compete:

- **`cmd/` + `internal/`:** Go-team-blessed pattern; `internal/` enforces import boundary at compiler level (anything outside the module cannot import).
- **`pkg/`:** older convention for "code intended to be reused"; appropriate for libraries, not for an end-user binary.

The beacon is firmly in the binary camp — no other Go module ever should depend on it. Therefore `pkg/` is wrong for this codebase.

## Decision

We adopt the standard `cmd/` + `internal/` layout exclusively. There will be no `pkg/` directory in this repository. Generated code is segregated under `internal/api/` with a `DO NOT EDIT` header on every file, regenerated from the netbrain-side `beacon-v1.yaml` via `go generate ./internal/api/...`.

```
netbrain-beacon/
├── cmd/netbrain-beacon/main.go         # subcommand dispatch (≤200 LOC)
├── internal/
│   ├── api/                             # generated (DO NOT EDIT) — oapi-codegen v2
│   ├── enroll/                          # one-shot enrollment ceremony (ADR-067)
│   ├── crypto/
│   │   ├── dek_envelope.go              # AES-256-GCM wrap/unwrap
│   │   ├── idempotency.go               # UUIDv5 derivation
│   │   ├── platform_verify.go           # ed25519 verify (M-11)
│   │   └── streaming_gunzip.go          # byte-capped gunzip (M-6)
│   ├── transport/                       # mTLS HTTP client + cert rotate
│   ├── config_poll/                     # 60s±10s loop + heartbeat
│   ├── collectors/
│   │   ├── syslog/                      # leodido/go-syslog v4 listener
│   │   ├── netflow/                     # goflow2 + nfcapd writer
│   │   ├── snmp/                        # gosnmp poller
│   │   └── configs/                     # SSH config puller
│   ├── store/                           # bbolt S&F (ADR-002)
│   ├── probe/                           # TCP-connect device-latency
│   ├── safe_dial/                       # SSRF defense (ADR-005)
│   ├── admin/cli/                       # status / collectors / logs CLI
│   ├── metrics/                         # Prometheus registry
│   ├── clock/                           # injectable Clock interface
│   ├── log/                             # slog + redactor middleware
│   └── version/                         # build stamps via -ldflags -X
├── tests/fixtures/cross_lang/           # Python-generated, Go-consumed (ADR-004)
├── packaging/
│   ├── deb/                             # debian/ control, rules, etc.
│   ├── rpm/                             # netbrain-beacon.spec
│   ├── arch/                            # PKGBUILD
│   ├── tarball/                         # install.sh, layout
│   └── systemd/                         # netbrain-beacon.service
├── docs/
│   ├── runbooks/beacon-binary-operations.md
│   └── ARCHITECTURE.md → ../.claude/planning/add-beacon-service/03_ARCHITECTURE.md
├── Dockerfile                            # gcr.io/distroless/static-debian12:nonroot (D-3)
├── Makefile
├── .golangci.yml                         # v2 with errcheck, gosec, bodyclose, forbidigo, ...
├── .github/workflows/ci.yml
├── go.mod
├── go.sum
└── README.md
```

### Naming conventions

- Subpackage names match their directory; lowercased; no underscores (Go style). Exception: `safe_dial` keeps the underscore for legibility — `safedial` would obscure the meaning of the chokepoint, and the underscore is permitted by `golint` for short package names where readability wins.
- Each `internal/...` package exposes a `Run(ctx, opts) error` (or `Start` / `Open`, depending on lifecycle) and keeps its types unexported except for the small public API surface needed by callers.
- Generated files in `internal/api/` carry a `// Code generated by oapi-codegen DO NOT EDIT.` header per Go convention. CI step `go generate ./internal/api/... && git diff --exit-code` enforces "no manual edits".

### CI lint integration

`golangci-lint` v2 with `forbidigo` enforces visibility rules:

- `net.Dial`, `net.DialContext`, `(*net.Dialer).Dial*` are forbidden everywhere except `internal/safe_dial/**` (ADR-005).
- `math/rand` is forbidden in `internal/crypto/**`.
- `cipher.NewGCMWithTagSize`, `cipher.NewGCMWithNonceSize` forbidden everywhere.
- `io.ReadAll(gzip.NewReader(...))` forbidden in `internal/{config_poll,crypto}/**` (M-6).
- `tls.Config{}` literal without explicit `MinVersion` forbidden everywhere (R-7).

## Alternatives considered

### Alt A: Flat layout (everything at module root)

```
netbrain-beacon/
├── main.go
├── enroll.go
├── crypto.go
├── ...
```

**Rejected:** doesn't scale past ~10 files; no compiler-level boundary; no clean place for the generated client.

### Alt B: `pkg/` for "would-be-reusable" code

```
netbrain-beacon/
├── cmd/netbrain-beacon/
├── pkg/crypto/
├── pkg/api/
├── ...
```

**Rejected:** the beacon is single-purpose. There is no future external consumer for `pkg/crypto` (the rest of the netbrain ecosystem is Python). Putting code under `pkg/` falsely advertises stability; the Go community has [explicitly cooled on `pkg/`](https://go.dev/blog/package-names) for non-library projects since 2019.

### Alt C: `vendor/` everything (no module mode)

**Rejected:** Go modules are universal in 2026; `vendor/` is opt-in for build reproducibility but adds review noise. We use `go.mod` + `go.sum` checksum verification + `govulncheck` for the same property without the vendored-tree pollution.

### Alt D: Split CLI subcommands into separate binaries (`netbrain-beacon-enroll`, `netbrain-beacon-daemon`, ...)

**Rejected:** operator UX is much worse — one install action, one set of permissions, one log destination is the goal. Subcommands inside one binary share the version, config, and runtime — which is what we want. SSM Agent, Consul Agent, Prometheus Node Exporter all use this pattern; we follow it.

## Consequences

### Positive

- Compiler enforces import boundary — no other Go module can `import "github.com/netbrain/netbrain-beacon/internal/crypto"`. This is a load-bearing property: if we ever split the beacon (e.g., extract `crypto/` into a shared lib for a future sister project), the visibility move is deliberate, not accidental.
- Generated code is clearly demarcated; reviewers ignore it; CI catches manual edits.
- Single binary with subcommands matches operator expectation for edge agents (SSM, Consul, Telegraf all do this).
- Packaging artifacts live outside the Go module tree, so `go install` and `go build` ignore them naturally.

### Negative

- New contributors must learn the `internal/` rule the first time they try to import from outside (rare in this single-binary repo).
- Each new subcommand adds boilerplate in `main.go`'s dispatch. Mitigated by using a tiny dispatch helper that takes `map[string]func(ctx, args) int`.
- Cross-cutting concerns (logging, clock, metrics) need to be passed through every package's constructor — no global injection. This is intentional (testability) but adds plumbing.

### Operational

- `go install github.com/netbrain/netbrain-beacon/cmd/netbrain-beacon@latest` works for developer install.
- Build matrix: `GOOS=linux GOARCH=amd64` and `GOOS=windows GOARCH=amd64`, both with `CGO_ENABLED=0`. Static binary ~15 MB stripped via `-ldflags="-s -w" -trimpath`.
- Reproducible builds via `-trimpath -ldflags="-s -w -buildid="` (Go 1.21+).

### Forward-looking

- If a v2 of the beacon ever needs to support multi-tenant install with a shared crypto library, we move `internal/crypto/` to a sister `crypto-shared` Go module — a deliberate breaking change. The current `internal/` boundary makes this move visible in the diff rather than silent.
- `pkg/` is **forbidden** in this repo. If anyone proposes adding it, defer back to this ADR.

## Acceptance criteria

- Phase 1 of `04_IMPLEMENTATION_PLAN.md` scaffolds this layout exactly.
- `go vet ./...` passes from day 1 (empty packages count).
- `golangci-lint run` passes with the rule set above.
- `git ls-tree HEAD internal/ | head` shows the layout above.
- `go generate ./internal/api/... && git diff --exit-code` is green in CI.
