# ADR-079: Cert rotation atomicity (tmpfile + rename + atomic.Pointer[http.Client])

**Status:** Accepted
**Date:** 2026-05-10
**Context issue:** add-beacon-service
**Companion:** ADR-067 (parent — 90-day cert, auto-rotate at 80%)

## Context

ADR-067 (parent) mandates the beacon auto-rotates its mTLS cert at 80% lifetime — i.e., 18 days before the 90-day cert expires. The rotation flow:

1. Beacon detects 80% lifetime via `internal/transport.Manager.Tick()` OR receives `recommended_action=rotate` from `GET /cert-status`.
2. Beacon generates a new ECDSA P-256 keypair + CSR.
3. Beacon `POST /api/v1/beacons/{id}/cert/rotate` with the new CSR (using the *current* cert as auth).
4. Server returns the new signed cert.
5. Beacon must adopt the new cert without dropping in-flight HTTP requests.

The naive implementation has two race conditions:

- **File-system race:** if we `os.Create("beacon.crt")` and write directly, a process kill between create-and-fully-written leaves a partial cert; next start fails to parse → daemon dead.
- **In-memory race:** if we mutate `*http.Transport.TLSClientConfig` in place (the obvious thing to do), in-flight requests see partial state — some requests negotiate with the old cert, others with the new during the rebuild window. Worse, Go's `*http.Transport` does not specify thread-safety for `TLSClientConfig` mutation post-construction; the documentation says "modifications must not be made" once the transport is in use.

R-8 in research catalogs this; this ADR is the formal decision.

## Decision

We use **tmpfile + `os.Rename` + `atomic.Pointer[http.Client]` swap**. No lockfile, no SIGHUP, no in-place transport mutation.

### Step-by-step

```
1. PRE-ROTATE
   - Generate new ECDSA P-256 keypair in memory.
   - Build new CSR (empty Subject per ADR-067).
   - POST /cert/rotate with the new CSR using the *current* mTLS client.
   - Server returns the new signed cert.

2. WRITE-NEW (tmpfile + verify)
   - Create `beacon.crt.new` via `os.OpenFile(path, O_WRONLY|O_CREATE|O_EXCL, 0644)`.
   - Write the PEM-encoded cert. Sync. Close.
   - Create `beacon.key.new` via `os.OpenFile(path, O_WRONLY|O_CREATE|O_EXCL, 0600)`.
   - Write the PEM-encoded key. Sync. Close.
   - Re-read both files. Parse. Verify:
       - x509 cert public key matches the keypair we just generated (CSR-derived expectation).
       - Cert chain validates against pinned platform CA.
       - Cert NotBefore <= now < NotAfter.
       - Cert subject CN contains the expected beacon-id.

3. ATOMIC SWAP (file-system)
   - os.Rename("beacon.crt.new", "beacon.crt")  — atomic on POSIX and NTFS within the same volume.
   - os.Rename("beacon.key.new", "beacon.key") — atomic, mode preserved.
   - Both files are now in their final names. Process kill at this point leaves a consistent on-disk state.

4. BUILD-NEW (in-memory)
   - tlsConfig := &tls.Config{
         Certificates: []tls.Certificate{newCert},
         RootCAs:      pinnedCAPool,
         MinVersion:   tls.VersionTLS13,
         ServerName:   serverHostname,
     }
   - transport := &http.Transport{ ... TLSClientConfig: tlsConfig, ... }
   - newClient := &http.Client{ Transport: transport, Timeout: 60 * time.Second }

5. ATOMIC SWAP (in-memory)
   - oldClient := transportManager.client.Swap(newClient)  // atomic.Pointer[http.Client]

6. DRAIN-OLD
   - Old in-flight requests complete on the *old* http.Client (which still references the old TLS config).
   - oldClient.CloseIdleConnections() — best-effort to free old keepalive sockets after a grace period.
   - Old cert/key remain in memory (referenced by old TLS config) until last in-flight request completes; then GC'd.

7. METRICS + LOG
   - netbrain_beacon_cert_rotations_total{result=success}++
   - log "cert rotated" with new NotAfter timestamp (no key material logged).
```

### Failure paths

- **Step 1 (POST fail):** retry with exponential backoff up to 3 times; if persistent, log + alert + retain old cert; defer rotation to next tick.
- **Step 2 (write fail):** roll back via `os.Remove("beacon.crt.new")` + `os.Remove("beacon.key.new")`. Old cert untouched. Retry next tick.
- **Step 2 verification fail:** the new cert's pubkey doesn't match our generated keypair → alert (server-side bug or attack); roll back.
- **Step 3 (rename fail — extremely rare):** if `os.Rename("beacon.crt.new", "beacon.crt")` succeeds but `os.Rename("beacon.key.new", "beacon.key")` fails, we have a mismatched cert/key on disk. Detection: the next process start fails `x509.LoadX509KeyPair` ("private key does not match public key"). Recovery: runbook documents `cp beacon.crt.bak beacon.crt && cp beacon.key.bak beacon.key`. To minimize the window, we keep both `.bak` files updated atomically pre-step-3.
- **Step 5 (swap):** atomic; no failure mode.

### Why no lockfile

A lockfile would coordinate against another instance of `netbrain-beacon` running concurrently — but our systemd unit (and Windows SCM equivalent) prevents that at OS level. A lockfile inside our own process is meaningless — the swap is already serialized by the rotation goroutine being the only caller. So no lockfile.

### Why not SIGHUP-driven reload

SIGHUP works on Linux but is clumsy on Windows (no native equivalent; service control via SCM is heavier). Our approach is uniform across both OSes: the rotation is driven by an internal timer + `/cert-status` poll response, not by a signal.

### Why atomic.Pointer[T]

Go 1.19+ provides `atomic.Pointer[T]` for type-safe pointer swaps. The alternative is a `sync.RWMutex` guarding a `*http.Client` field — but `RLock/RUnlock` on every request adds two atomic ops per request and complicates testing. `atomic.Pointer.Load()` is a single-instruction load on amd64.

```go
type Manager struct {
    client atomic.Pointer[http.Client]
}

func (m *Manager) Client() *http.Client {
    return m.client.Load()
}

func (m *Manager) Rotate(newClient *http.Client) {
    old := m.client.Swap(newClient)
    go func() {
        time.Sleep(120 * time.Second)  // grace for in-flight requests
        old.CloseIdleConnections()
    }()
}
```

## Alternatives considered

### Alt A: Lockfile + SIGHUP

- Pros: matches Apache/nginx convention.
- Cons: clumsy on Windows; lockfile adds failure surface (stale lock on crash); no benefit over `atomic.Pointer` here.
- **Rejected.**

### Alt B: Mutate `Transport.TLSClientConfig` in place under `sync.RWMutex`

- Pros: fewer allocations; same `*http.Client` lives forever.
- Cons: Go docs say "must not modify" the TLSClientConfig once the transport is in use; in-flight requests racing the mutation can see torn state; race detector flags it.
- **Rejected.**

### Alt C: `http.Transport.GetClientCertificate` callback that re-reads cert from disk every call

- Pros: simplest possible implementation; cert is "always" fresh.
- Cons: 50-100 µs disk read per request; complicates testing; the rotation event itself isn't observable (no clear point at which "rotation completed"); multiple concurrent reads race during the rotation window.
- **Rejected.**

### Alt D: Single-threaded daemon (no concurrent requests during rotation)

- Pros: trivially correct.
- Cons: blocks all other traffic during the rotation; defeats the goroutine model in ADR-082.
- **Rejected.**

## Consequences

### Positive

- File-system state is always consistent — process kill at any point leaves a parseable cert/key pair.
- In-flight requests complete on their original TLS config; new requests use the new config. No torn state.
- Single atomic swap; no mutex on the request hot path.
- Cross-platform: works identically on Linux and Windows (rename is atomic on NTFS within the same volume).

### Negative

- Old keepalive connections survive briefly after rotation (until `CloseIdleConnections()` is called or `IdleConnTimeout` expires). Memory cost: ≤2 connections × ~16 KB each = negligible.
- During the ≤120 s grace window, in-flight requests use the old cert. If the old cert is `NotAfter`-expired *during* a request, the server may reject. Mitigated by rotating at 80% lifetime (18 days remaining) — far more than any possible request duration.

### Operational

- Runbook §"Cert rotation": documents the manual trigger (`netbrain-beacon rotate-cert`) and the recovery procedure for cert/key mismatch (see "Step 3 fail" above).
- Metric `netbrain_beacon_cert_lifetime_seconds_remaining` warns at < 18 d (rotation due) and alerts critical at < 5 d (rotation likely failing).
- Alerting rule: `rate(netbrain_beacon_cert_rotations_total{result="failure"}[1h]) > 0` → critical.

## Acceptance criteria

- `internal/transport/manager_test.go` covers the full rotation flow with a stub server returning a new cert.
- Race detector test (`go test -race`) confirms no data races during 100 concurrent requests + 1 rotation.
- Integration test kills the process mid-rotation between steps 2 and 3 (after .new files written), restarts, asserts old cert still loads.
- `forbidigo` lint forbids any `transport.TLSClientConfig.Certificates = ...` assignment (mutation of live transport).