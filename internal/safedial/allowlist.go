package safedial

import (
	"net"
	"net/netip"
)

// forbiddenPrefixes is the CIDR block-list applied before every dial.
// Mirrored in package doc; canonical source is here.
//
// Pre-parsed as netip.Prefix for hot-path checks. Order is informational —
// IsForbidden iterates the slice once per check.
var forbiddenPrefixes = []netip.Prefix{
	// IPv4 ----------------------------------------------------------------
	netip.MustParsePrefix("127.0.0.0/8"),        // loopback
	netip.MustParsePrefix("169.254.0.0/16"),     // link-local (includes IMDS 169.254.169.254)
	netip.MustParsePrefix("0.0.0.0/32"),         // unspecified
	netip.MustParsePrefix("224.0.0.0/4"),        // multicast
	netip.MustParsePrefix("255.255.255.255/32"), // broadcast (covered by 224.0.0.0/4? No — 255.255.255.255 is class E/limited broadcast, distinct)

	// IPv6 ----------------------------------------------------------------
	netip.MustParsePrefix("::1/128"),   // loopback
	netip.MustParsePrefix("fe80::/10"), // link-local
	netip.MustParsePrefix("ff00::/8"),  // multicast
	netip.MustParsePrefix("::/128"),    // unspecified
}

// IsForbidden reports whether ip falls inside any blocked CIDR.
//
// IPv4-mapped IPv6 addresses (e.g., ::ffff:127.0.0.1) are unmapped to their
// IPv4 form before the check — an attacker cannot bypass the loopback
// reject by wrapping it in v6.
func IsForbidden(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		// Unparseable — treat as forbidden (fail-closed).
		return true
	}
	// Canonicalize IPv4-in-IPv6 to IPv4 so v6-wrapped private addresses
	// hit the same CIDRs as their v4 form.
	addr = addr.Unmap()

	for _, p := range forbiddenPrefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}
