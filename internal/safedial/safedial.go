package safedial

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
)

// Errors surfaced by Dial.
var (
	// ErrForbiddenIP is returned when any resolved IP for the supplied
	// hostname falls inside a forbidden CIDR (per ADR-081 / IsForbidden).
	ErrForbiddenIP = errors.New("safedial: address resolves to a forbidden range")

	// ErrDNSLookupFailed wraps a DNS resolution failure for the supplied
	// hostname. Distinct from ErrForbiddenIP so callers can distinguish
	// "DNS server unreachable" from "DNS returned a blocked address".
	ErrDNSLookupFailed = errors.New("safedial: DNS lookup failed")

	// ErrEmptyResolve is returned when DNS returned zero addresses. This
	// is technically possible for some resolver edge cases; we treat it
	// as a fail-closed error rather than a silent no-op.
	ErrEmptyResolve = errors.New("safedial: DNS returned no addresses")

	// ErrBadPort is returned for ports outside the TCP/UDP valid range.
	ErrBadPort = errors.New("safedial: port must be in 1..65535")
)

// Resolver is the DNS lookup interface safedial depends on. The standard
// implementation wraps net.DefaultResolver; tests inject mocks to simulate
// DNS-rebinding scenarios where one A record returns a poisoned address.
type Resolver interface {
	LookupIP(ctx context.Context, network, host string) ([]net.IP, error)
}

// stdResolver wraps net.DefaultResolver to satisfy Resolver.
type stdResolver struct{}

// LookupIP delegates to net.DefaultResolver.LookupIP.
//
// Note: this is the ONE place in the package where we touch net.DefaultResolver.
// All other paths go through the injectable Resolver.
func (stdResolver) LookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	return net.DefaultResolver.LookupIP(ctx, network, host)
}

// DefaultResolver is the production Resolver — net.DefaultResolver behind
// the safedial.Resolver interface.
var DefaultResolver Resolver = stdResolver{}

// Dial connects to (hostOrIP, port) over network ("tcp", "tcp4", "tcp6") with
// SSRF allow-list enforcement.
//
// hostOrIP may be either an IP literal (no DNS lookup) or a hostname (one
// DNS lookup, then dial-literal — see package doc).
//
// The context bounds both the DNS lookup and the dial. To enforce a tight
// timeout on a probe, the caller passes a context.WithTimeout context.
//
// Returns ErrForbiddenIP, ErrDNSLookupFailed, ErrEmptyResolve, or ErrBadPort
// for the policy-rejection paths; standard net errors for dial-time failures.
func Dial(ctx context.Context, network, hostOrIP string, port int) (net.Conn, error) {
	return DefaultDialer.Dial(ctx, network, hostOrIP, port)
}

// Dialer is the configurable Dial entrypoint. Useful when tests need a
// non-default Resolver, or when transport code needs to attach pre-flight
// hooks. Production code uses DefaultDialer (which is what safedial.Dial
// delegates to).
type Dialer struct {
	Resolver Resolver
	// NetDialer is the underlying net.Dialer; tests can swap to a mock.
	// Production callers leave this nil and get the zero value (which is
	// a perfectly usable net.Dialer with no timeout — the context provides
	// the bound).
	NetDialer NetDialer
}

// NetDialer abstracts net.Dialer.DialContext so we can mock the actual
// connect step in tests.
//
//nolint:forbidigo // This package IS the chokepoint; net.Dialer is allowed here.
type NetDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// stdNetDialer is the zero-value net.Dialer wrapped to satisfy NetDialer.
type stdNetDialer struct {
	d net.Dialer
}

// DialContext satisfies NetDialer by delegating to the wrapped net.Dialer.
func (s stdNetDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return s.d.DialContext(ctx, network, address)
}

// DefaultDialer is the production Dialer used by package-level Dial.
var DefaultDialer = &Dialer{
	Resolver:  DefaultResolver,
	NetDialer: stdNetDialer{},
}

// Dial resolves hostOrIP, applies the allow-list to every resolved IP, and
// dials the first allowed IP as an IP literal.
//
// Defence-in-depth note: if hostOrIP resolves to a mix of allowed and
// forbidden IPs, the entire dial fails. We don't allow "pick the good
// ones" because that opens a DNS-rebinding split.
func (d *Dialer) Dial(ctx context.Context, network, hostOrIP string, port int) (net.Conn, error) {
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("%w: got %d", ErrBadPort, port)
	}

	// If the input is already an IP literal, skip DNS.
	ips, err := d.resolve(ctx, network, hostOrIP)
	if err != nil {
		return nil, err
	}

	// Allow-list ALL resolved IPs before picking one.
	for i, ip := range ips {
		if IsForbidden(ip) {
			return nil, fmt.Errorf("%w: %s resolves to %s (entry %d of %d)",
				ErrForbiddenIP, hostOrIP, ip, i+1, len(ips))
		}
	}

	// Dial the first resolved IP as an IP literal. This is the "resolve
	// once, dial literal" guarantee — even if a re-resolve would now
	// return different IPs, this dial uses the IP we already validated.
	addr := net.JoinHostPort(ips[0].String(), strconv.Itoa(port))
	return d.netDialer().DialContext(ctx, network, addr)
}

// resolve handles both IP-literal input (no lookup) and hostname input
// (one lookup via the injected Resolver).
func (d *Dialer) resolve(ctx context.Context, network, hostOrIP string) ([]net.IP, error) {
	// If the input is already an IP, parse it directly. No DNS, no
	// rebinding risk.
	if ip := net.ParseIP(hostOrIP); ip != nil {
		return []net.IP{ip}, nil
	}

	r := d.Resolver
	if r == nil {
		r = DefaultResolver
	}
	ips, err := r.LookupIP(ctx, lookupNetwork(network), hostOrIP)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrDNSLookupFailed, hostOrIP, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrEmptyResolve, hostOrIP)
	}
	return ips, nil
}

// netDialer returns the configured NetDialer or the zero-value default.
func (d *Dialer) netDialer() NetDialer {
	if d.NetDialer == nil {
		return stdNetDialer{}
	}
	return d.NetDialer
}

// lookupNetwork maps a dial network ("tcp", "tcp4", "tcp6") to the
// resolver's expected network argument ("ip", "ip4", "ip6").
func lookupNetwork(dialNetwork string) string {
	switch dialNetwork {
	case "tcp4", "udp4":
		return "ip4"
	case "tcp6", "udp6":
		return "ip6"
	default:
		return "ip"
	}
}
