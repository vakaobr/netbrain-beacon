# Hardening Plan — add-beacon-service

**Generated:** 2026-05-12
**Source reports:** 07a_SECURITY_AUDIT.md (static). 07b/07c not yet run.
**Total findings:** 7 (Critical 0 | High 0 | Medium 2 | Low 3 | Info 2)

User intent (2026-05-12): fix ALL findings in this hardening pass, not
just the P2 ship-blockers. The default template triage (P3 = backlog
for Low/Info) is therefore overridden — every finding gets a code or
doc fix in this commit set.

## Fix summary

| Priority | Finding | CWE | Affected file | Effort |
|---|---|---|---|---|
| P2 | SY-1 syslog TCP per-line buffer growth | CWE-770 | internal/collectors/syslog/server.go | 30 m |
| P2 | SY-2 syslog TCP unbounded concurrent connections | CWE-770 | internal/collectors/syslog/server.go | 30 m |
| P3 | SY-3 syslog worker panic-recover | CWE-754 | internal/collectors/syslog/server.go | 15 m |
| P3 | S-1 enroll bundle on command line | CWE-214 | cmd/netbrain-beacon/enroll_cmd.go | 30 m |
| P3 | M-1 metrics-bind non-loopback silent | CWE-200 | cmd/netbrain-beacon/daemon_cmd.go + metrics/server.go | 20 m |
| P3 | T-1 cert rotation crash recovery helper | n/a | internal/transport/rotate.go | 45 m |
| P3 | ST-1 plaintext bbolt at rest — doc only | n/a | docs/runbooks/beacon-operations.md + ADR-002 | 15 m |

Total estimated effort: ~3 h. Single commit set; no GitHub issues
created (user is fixing inline).

## P2 fixes — block ship for Phase 7b

### Fix SY-1: syslog TCP per-line buffer growth (CWE-770)

**Finding.** `handleTCPConn` uses `bufio.NewReaderSize(conn, 64*1024)` +
`r.ReadBytes('\n')`. `bufio.Reader.ReadBytes` grows its internal buffer
unbounded until it finds the delimiter — an attacker streaming bytes
without `\n` causes unbounded memory growth per connection. The 30 s
`SetReadDeadline` is reset on every successful read, so slow-drip is not
bounded either.

**File:** `internal/collectors/syslog/server.go`.

**Root cause.** `ReadBytes` is the wrong primitive for untrusted input.
`bufio.Scanner` with `SetBuffer(initial, max)` is the correct one — it
returns `bufio.ErrTooLong` once the line exceeds `max` and lets the
caller decide what to do.

**Before** (vulnerable):

```go
r := bufio.NewReaderSize(conn, 64*1024)
for {
    _ = conn.SetReadDeadline(time.Now().Add(DefaultReadDeadline))
    line, err := r.ReadBytes('\n')
    if len(line) > 0 {
        s.SubmitRaw(trimNewline(line))
    }
    if err == io.EOF { return }
    if err != nil {
        if isTimeout(err) { continue }
        return
    }
}
```

**After** (hardened):

```go
sc := bufio.NewScanner(conn)
sc.Buffer(make([]byte, 64*1024), MaxLineBytes) // cap 256 KiB by default
for sc.Scan() {
    _ = conn.SetReadDeadline(time.Now().Add(DefaultReadDeadline))
    s.SubmitRaw(trimNewline(sc.Bytes()))
}
if err := sc.Err(); err != nil {
    if errors.Is(err, bufio.ErrTooLong) {
        s.oversizedDrop.Add(1)
        s.log.Warn("syslog.tcp_line_too_long", slog.Int("limit_bytes", MaxLineBytes))
    }
    // EOF + read-deadline-timeout are normal connection ends — silent.
}
```

**Regression test.** Open a TCP conn to a `Server` with a tiny
`MaxLineBytes` (e.g. 64) and send 200 bytes of `'A'` followed by `\n`.
Assert `Stats().OversizedDropped == 1` and `Stats().Persisted == 0`.

### Fix SY-2: syslog TCP unbounded concurrent connections (CWE-770)

**Finding.** `tcpLoop` calls `go s.handleTCPConn(...)` for every Accept
with no cap. 10 000 concurrent TCP conns ≈ 10 000 goroutines × 64 KiB
read buffer ≈ 640 MB resident + goroutine stack.

**File:** `internal/collectors/syslog/server.go`.

**Root cause.** Standard "accept loop spawns goroutine per conn" pattern
without backpressure. Need a semaphore-gated accept.

**Before** (vulnerable):

```go
for {
    conn, err := s.tcpLn.Accept()
    if err != nil { ... }
    s.wg.Add(1)
    go s.handleTCPConn(ctx, conn)
}
```

**After** (hardened):

```go
sem := make(chan struct{}, s.cfg.MaxTCPConnections) // default 256
for {
    conn, err := s.tcpLn.Accept()
    if err != nil { ... }
    select {
    case sem <- struct{}{}:
        s.wg.Add(1)
        go func(c net.Conn) {
            defer func() { <-sem }()
            s.handleTCPConn(ctx, c)
        }(conn)
    default:
        s.connRejected.Add(1)
        _ = conn.Close()
    }
}
```

**Regression test.** Open `MaxTCPConnections + 1` connections to a
`Server` configured with `MaxTCPConnections = 4`. Assert the 5th
Accept results in `Stats().ConnsRejected == 1`. Hold the first four
open until cleanup.

## P3 fixes — defense-in-depth (filed inline per user request)

### Fix SY-3: syslog worker panic-recover (CWE-754)

**Finding.** `worker()` has no `defer recover()`. A panic in
`json.Marshal`, `store.Put`, or the leodido parser terminates the
entire pool of N workers (and ultimately the daemon).

**File:** `internal/collectors/syslog/server.go`.

**Fix.** Wrap the per-message body in a panic-safe closure that logs +
counts + continues.

```go
func (s *Server) worker(_ context.Context) {
    defer s.wg.Done()
    for raw := range s.queue {
        s.processOne(raw)
    }
}

func (s *Server) processOne(raw []byte) {
    defer func() {
        if r := recover(); r != nil {
            s.workerPanics.Add(1)
            s.log.Error("syslog.worker_panic",
                slog.Any("recover", r),
                slog.String("raw_b64", base64.StdEncoding.EncodeToString(truncate(raw, 256))))
        }
    }()
    // ... existing parse + persist logic
}
```

**Regression test.** Inject a `Store` whose `Put` panics; submit a
message; assert the worker survives and counter ticks.

### Fix S-1: enroll `--bundle-file` (CWE-214)

**Finding.** `--bundle <b64>` puts the bootstrap token in `ps`, shell
history, audit logs. Token is short-lived (24 h) and one-use, but defense
in depth.

**File:** `cmd/netbrain-beacon/enroll_cmd.go` + runbook.

**Fix.** Add `--bundle-file <path>` mutually exclusive with `--bundle`.
Reject if both supplied or neither. Warn if `--bundle` is used and stderr
is a terminal ("--bundle leaks the token to ps; prefer --bundle-file").
Runbook recommends `--bundle-file` for production.

**Regression test.** CLI test:
1. `--bundle-file <path-to-base64>` parses cleanly.
2. `--bundle <b64> --bundle-file <path>` errors with "mutually exclusive".
3. Reading a file with mode 0644 emits a warning to stderr.

### Fix M-1: metrics-bind non-loopback warning (CWE-200)

**Finding.** `--metrics-bind 0.0.0.0:9090` exposes unauthenticated
Prometheus metrics to the LAN with no warning.

**Files:** `cmd/netbrain-beacon/daemon_cmd.go` + `internal/metrics/server.go`.

**Fix.** At Start, detect non-loopback bind and emit a structured WARN
log line with `beacon_metrics_bind_non_loopback{addr=...}` so operators
can detect via Prometheus self-monitoring. Update runbook section
"Metrics" to call out the auth gap + recommend nginx/iptables/wireguard
in front when LAN exposure is needed.

```go
func (s *Server) Start(_ context.Context) error {
    // ... existing Listen ...
    if !isLoopback(s.BindAddr) {
        s.log.Warn("metrics.non_loopback_bind",
            slog.String("addr", s.BindAddr),
            slog.String("guidance",
                "metrics is unauthenticated; front with TLS+auth before exposing publicly"))
    }
    // ...
}
```

**Regression test.** Verify the warn is emitted exactly when bind is
non-loopback (`0.0.0.0:0` and `[::]:0`), and NOT emitted for
`127.0.0.1:0` or `[::1]:0`.

### Fix T-1: cert rotation crash recovery helper

**Finding.** Today, a crash between Rotator step 5 (archive old →
`.prev`) and step 6 (promote `.new` → live) leaves disk in a state
where the live filenames don't exist but `.prev` + `.new` both do. The
daemon restart path reads only the live filenames and fails.

**File:** `internal/transport/rotate.go` (new helper) + daemon wiring.

**Fix.** Add `LoadCertPairWithRecovery(stateDir) (certPEM, keyPEM []byte, err error)`:

1. Try `beacon.crt` + `beacon.key`. If both parse → return.
2. Otherwise try `beacon.crt.new` + `beacon.key.new` (crash between
   step 6a and 6b — new pair written, not yet promoted). If both parse,
   atomically promote them via rename + return.
3. Otherwise try `beacon.crt.prev` + `beacon.key.prev` (crash between
   step 5 and step 6 — old archived, new not yet promoted). If both
   parse, atomically restore them to live via rename + return.
4. Otherwise → `ErrNoUsableCertPair`.

**Regression test.** Three scenarios:
- Setup state-dir with only live pair → returns live, no rename.
- Setup state-dir with live + `.new` corruption → restores `.new` to live.
- Setup state-dir with only `.prev` → restores `.prev` to live.

### Fix ST-1: document plaintext-at-rest host-trust assumption

**Finding.** bbolt records are plaintext at rest. A local-root attacker
on the beacon host can read buffered telemetry between collection and
egress. This is the documented architectural choice per ADR-078, but
the runbook + README don't surface it prominently to operators.

**Files:** `docs/runbooks/beacon-operations.md` + `README.md` +
`docs/ADR/ADR-002-store-and-forward-bbolt-schema.md`.

**Fix.** Add a "Security model: host trust" section to the runbook
listing the host-trust assumptions:
- bbolt records plaintext at rest in `/var/lib/netbrain-beacon`.
- Private key + DEK in the state dir (0600 perms but readable to root).
- Operator must restrict root access to the beacon host.
- For air-gapped or low-trust hosts, full-disk encryption (LUKS,
  BitLocker) is the recommended additional layer.

Cross-link from ADR-002's existing assumption note to the runbook
section.

## Verification checklist

After implementing all fixes:

- [ ] `go test ./...` — all green incl. new regression tests
- [ ] `go vet ./...` — clean
- [ ] `golangci-lint run` — 0 findings
- [ ] `govulncheck ./...` — clean
- [ ] Re-read 07a_SECURITY_AUDIT.md findings table — every one closed
- [ ] Update 00_STATUS.md: Phase 7a verdict upgraded to ✓ PASS
- [ ] CLAUDE.md learnings: bufio.Scanner > Reader.ReadBytes for untrusted
      streams; semaphore-gated accept loops for any public listener;
      `--flag-file` alternative for any short-lived-secret CLI flag

## Next step

After hardening lands:

1. `/security/pentest add-beacon-service` co-tested with
   `add-multi-mode-ingestion` on staging (mandatory per
   pending_beacon_pentest.md).
2. `/deploy-plan add-beacon-service` once 7b confirms no exploitable
   findings remain.