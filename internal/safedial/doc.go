// Package safedial is the M-9 SSRF defence chokepoint for the beacon.
//
// Every TCP dial to a device-supplied address MUST flow through this package.
// The golangci-lint forbidigo rule (see .golangci.yml) blocks direct
// net.Dial, net.DialContext, and net.DialTimeout calls outside of
// internal/safedial and internal/transport (transport calls the platform
// URL, not user-supplied addresses, so it's exempt with a warning).
//
// # Threat model
//
// Devices and their IP allow-list arrive via the server-pushed beacon config
// (parent ADR-070 + ADR-072). A compromised or malicious config could
// instruct the beacon to:
//
//   - probe link-local 169.254.169.254 (cloud instance-metadata service —
//     IMDS credential theft path)
//   - probe loopback 127.0.0.1 (local services running on the beacon host
//     itself — admin Prometheus endpoint, sshd, etc.)
//   - probe broadcast / multicast / unspecified (resource exhaustion or
//     amplification reflection)
//   - smuggle a hostname that resolves to a public IP at allow-list check
//     time but flips to 169.254.169.254 at dial time (DNS rebinding)
//
// # Defence
//
// safedial.Dial:
//
//  1. Resolves the supplied hostname via the supplied (or default) Resolver
//     EXACTLY ONCE. The resolved IPs are pinned for the dial — even if a
//     subsequent re-resolve would yield different IPs, this Dial never
//     re-queries.
//  2. Checks every resolved IP against the forbidden CIDR list. If ANY
//     resolved IP falls inside a forbidden range, the entire dial is
//     rejected (defence in depth: we don't allow "skip the bad ones,
//     dial the good ones" because that opens DNS-rebinding splits where
//     the attacker arranges for one good and one bad IP).
//  3. Dials the first resolved IP as an IP literal: net.Dial(network,
//     resolvedIP.String() + ":" + port). The hostname is never used at
//     dial time — TLS SNI / certificate verification at higher layers
//     is the caller's concern.
//
// # Forbidden CIDRs (ADR-081)
//
// Reject before dial:
//
//	IPv4:
//	  127.0.0.0/8     loopback
//	  169.254.0.0/16  link-local (includes cloud IMDS at 169.254.169.254)
//	  0.0.0.0/32      unspecified
//	  224.0.0.0/4     multicast
//	  255.255.255.255 broadcast
//	IPv6:
//	  ::1/128         loopback
//	  fe80::/10       link-local
//	  ff00::/8        multicast
//	  ::/128          unspecified
//
// RFC1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) and ULA (fc00::/7)
// are NOT forbidden — most customer networks use private address space for
// the devices the beacon legitimately probes.
//
// # Usage
//
//	conn, err := safedial.Dial(ctx, "tcp", "10.0.0.5", 22)
//	if err != nil {
//	  if errors.Is(err, safedial.ErrForbiddenIP) { ... }
//	  if errors.Is(err, safedial.ErrDNSLookupFailed) { ... }
//	  return err
//	}
//	defer conn.Close()
//
// Hostnames are accepted; the package resolves them. Tests inject a custom
// Resolver to simulate DNS-rebinding scenarios.
package safedial
