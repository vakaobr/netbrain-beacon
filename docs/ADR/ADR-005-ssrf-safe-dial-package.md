# ADR-005: `internal/safe_dial` — single chokepoint for SSRF defense

**Status:** Accepted
**Date:** 2026-05-10
**Context issue:** add-beacon-service
**Companion:** parent issue M-9 hardening

## Context

The beacon dials customer-network device IPs supplied by platform-pushed config (see `BeaconConfigDevice.host` in `beacon-v1.yaml`). A compromised or misconfigured config could redirect probes/pulls to:

- **Cloud metadata services:** `169.254.169.254` (AWS / Azure / GCP) — escalation to host-credential theft.
- **Loopback:** `127.0.0.1`, `::1` — local services on the beacon host (Prometheus on 9090, admin socket).
- **Unspecified:** `0.0.0.0` — kernel-routes-to-loopback semantics.
- **Multicast:** `224.0.0.0/4`, `ff00::/8` — broadcast-domain disruption.
- **IPv6 link-local:** `fe80::/10` — accessible without explicit interface binding on some systems.

M-9 from the parent issue mandates allow-list **reject** of all of the above before any TCP connect or probe attempt.

A naive `if isForbidden(host) { reject }` check on the user-supplied hostname is **vulnerable to DNS rebinding** (R-9): the attacker controls a DNS record that resolves to `10.0.0.5` at allow-list-check time and to `169.254.169.254` 50 ms later when `net.Dial` resolves again. The defense is well-known: **resolve once, check, then dial the resolved IP literal — not the original hostname**.

The beacon has multiple dial paths today:

- `internal/probe/` — TCP-connect to 22/161/80.
- `internal/collectors/snmp/` — UDP 161 via `gosnmp`.
- `internal/collectors/configs/` — TCP 22 via `golang.org/x/crypto/ssh`.
- `internal/collectors/syslog/` — listener (no outbound).
- `internal/collectors/netflow/` — listener (no outbound).
- `internal/transport/` — TCP 443 to platform (whitelisted; not user-supplied).

Without architectural pressure, every one of those (except `transport`) is at risk of a contributor accidentally calling `net.Dial(host, port)` directly with a user-supplied host string.

## Decision

We create `internal/safe_dial/` as the **single chokepoint** for every dial of a customer-supplied address. The package exposes:

```go
package safe_dial

// Dial resolves addr's hostname ONCE, applies the M-9 allow-list to the
// resolved IP, then dials the IP literal (not the original hostname).
func Dial(ctx context.Context, network, addr string) (net.Conn, error)

// DialContext is an alias for Dial; matches the *net.Dialer signature for
// integration into HTTP/SSH/SNMP libraries that expect a DialContext callback.
func DialContext(ctx context.Context, network, addr string) (net.Conn, error)

// IsForbidden returns true iff ip is in any forbidden range. Public for tests.
func IsForbidden(ip net.IP) bool

// ErrSSRFBlocked wraps the rejection reason. Use errors.Is(err, ErrSSRFBlocked).
var ErrSSRFBlocked = errors.New("safe_dial: address rejected by SSRF allow-list")
```

### Implementation

```go
func Dial(ctx context.Context, network, addr string) (net.Conn, error) {
    host, port, err := net.SplitHostPort(addr)
    if err != nil { return nil, err }

    // Resolve ONCE, apply check to ALL resolved IPs, then dial the first
    // accepted IP literally. Never re-resolve.
    ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
    if err != nil { return nil, err }
    if len(ips) == 0 {
        return nil, fmt.Errorf("safe_dial: no addresses for %q", host)
    }
    for _, ip := range ips {
        reason, forbidden := classify(ip)
        if forbidden {
            metrics.SafeDialRejections.WithLabelValues(reason).Inc()
            return nil, fmt.Errorf("%w: %s (reason=%s)", ErrSSRFBlocked, ip, reason)
        }
    }

    // Dial the literal IP we just verified. Stdlib net.Dial here is permitted
    // by forbidigo because this file is in internal/safe_dial/.
    var d net.Dialer
    return d.DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
}

// classify returns ("link_local"|"loopback"|..., true) if ip is forbidden.
// Mirrors the M-9 list exactly; any change here requires updating the parent ADR.
func classify(ip net.IP) (string, bool) {
    if ip4 := ip.To4(); ip4 != nil {
        // 169.254.0.0/16 link-local
        if ip4[0] == 169 && ip4[1] == 254 { return "link_local", true }
        // 127.0.0.0/8 loopback
        if ip4[0] == 127 { return "loopback", true }
        // 0.0.0.0 unspecified
        if ip4[0] == 0 && ip4[1] == 0 && ip4[2] == 0 && ip4[3] == 0 { return "unspecified", true }
        // 224.0.0.0/4 multicast
        if ip4[0] >= 224 && ip4[0] <= 239 { return "multicast", true }
    } else {
        // IPv6 forms
        if ip.IsLoopback() { return "loopback", true }
        if ip.IsUnspecified() { return "unspecified", true }
        if ip.IsLinkLocalUnicast() { return "v6_link_local", true }       // fe80::/10
        if ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() {
            return "multicast", true                                       // ff00::/8 etc.
        }
        if ip.IsMulticast() { return "multicast", true }
    }
    return "", false
}
```

### Lint enforcement (the load-bearing half)

`.golangci.yml` `forbidigo` rules:

```yaml
- linters: [forbidigo]
  text: '`net\.Dial`|`net\.DialContext`|`(\*net\.Dialer)\.Dial(Context)?`'
  paths-except:
    - 'internal/safe_dial/.*'
    # transport/ has a single, audited net.Dial to the platform server URL;
    # explicitly allowed via inline `//nolint:forbidigo` with an audit comment.
    - 'internal/transport/manager\.go'
```

Any new `net.Dial` outside `safe_dial` (and the audited platform-bound dial in `transport`) fails CI. Reviewer checklist confirms no inline `nolint` was added without updating this ADR.

### Library integration

External libraries that do their own dialing must be configured to delegate to `safe_dial`:

- **`gosnmp`:** wrap with a custom dialer — `gosnmp.GoSNMP{Dialer: safe_dial.Dial, ...}`. (gosnmp v1.37+ supports a `Dialer` callback.)
- **`golang.org/x/crypto/ssh`:** dial first via `safe_dial.Dial`, then `ssh.NewClientConn(conn, ...)`. This is the standard ssh.Dial replacement pattern.
- **`net/http` (for transport/ to platform):** the platform URL is whitelisted at startup; we resolve it once and pin the IP. Not a `safe_dial` user.
- **`netsampler/goflow2`:** listener only; no outbound.

### Whitelist

The platform server URL is the only whitelisted dial. It's resolved once at startup in `internal/transport/manager.go` (the audited callsite); subsequent HTTP requests reuse the keepalive connection pool. If the resolved IP changes (e.g., DNS-load-balanced platform), we re-resolve at config-apply time only — never per-request.

## Alternatives considered

### Alt A: Hostname-only check (no resolve-once)

```go
if isForbiddenHostname(host) { reject }
return net.Dial(network, addr)  // resolves again here
```

- **Rejected.** Vulnerable to DNS rebinding (R-9). The whole point of this ADR is to defend against that.

### Alt B: Kernel-level egress firewall (iptables / Windows Firewall rules)

- Pros: defense at the OS layer; can't be bypassed by buggy code.
- Cons: requires root/Administrator at install (we run as `netbrain` non-root); customer policies may forbid modifying host firewall; doesn't work in container deployments without `--cap-add=NET_ADMIN`.
- **Rejected** for v1. The application-layer chokepoint is portable; we recommend customers ALSO deploy host firewall rules in the runbook (defense-in-depth).

### Alt C: A `Dialer` interface passed everywhere as a constructor argument

- Pros: idiomatic Go.
- Cons: every collector/probe/library integration must accept it; easy to accidentally bypass (just call `net.Dial` directly). The `forbidigo` lint gate is the load-bearing enforcement, regardless of constructor interface.
- **Rejected as the sole defense.** The ADR keeps the `safe_dial.Dial` package function as the public API; constructor injection is fine where libraries support it (gosnmp's `Dialer` field), but lint catches the gap.

### Alt D: Resolve at every dial via custom resolver

```go
type safeResolver struct { net.Resolver }
func (r *safeResolver) LookupIP(...) ([]net.IP, error) {
    // do the check here, drop forbidden IPs from the result
}
```

- Pros: works with any library that uses the default resolver.
- Cons: Go's `net.Dial` resolves *internally* and ignores custom resolvers unless plumbed via `net.Dialer.Resolver`; even then, the resolver returns the filtered list and `Dial` uses it — same effect as our approach but harder to reason about.
- **Rejected** for clarity. Explicit `safe_dial.Dial` makes the chokepoint visible at every callsite.

## Consequences

### Positive

- One chokepoint for every device dial; auditable.
- DNS rebinding defended by resolve-once-then-dial-literal.
- Lint gate prevents accidental bypass.
- Per-rejection reason metric (`safe_dial_rejections_total{reason}`) gives operators visibility into whether a config push is hitting forbidden IPs (likely misconfiguration or attack).

### Negative

- Adding a new outbound integration (e.g., a future Kafka collector) requires reading this ADR and routing through `safe_dial`. Mitigated by the lint gate forcing the conversation.
- DNS-load-balanced platform URL: if the platform's IP changes mid-day, we don't pick up the change until config-apply (rare, by design). Documented in runbook.

### Operational

- Pentest coverage (Phase 7b co-pentest): explicit test cases for each forbidden range — `169.254.169.254`, `127.0.0.1`, `0.0.0.0`, `224.0.0.1`, `ff02::1`, `fe80::1` — must each return `ErrSSRFBlocked`.
- Alerting: `rate(netbrain_beacon_safe_dial_rejections_total[10m]) > 0` warning, `> 5/min` critical (likely active attack or major config error).

## Acceptance criteria

- `internal/safe_dial/safe_dial_test.go` covers every forbidden range with both v4 and v6 cases (≥ 14 cases).
- Race detector test: 100 concurrent `Dial(ctx, "tcp", "10.0.0.5:22")` complete without races.
- Integration test: stub DNS resolver that returns a forbidden IP for a benign hostname → `Dial` returns `ErrSSRFBlocked`; metric increments.
- `forbidigo` lint rule active in `.golangci.yml` from Phase 1.
- Phase 7b pentest plan includes the SSRF cases above as required test items.
