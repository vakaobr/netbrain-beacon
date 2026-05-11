package safedial

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsForbiddenIPv4Loopback(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "127.0.0.5", "127.255.255.254"} {
		require.True(t, IsForbidden(net.ParseIP(ip)), "%s must be forbidden (loopback)", ip)
	}
}

func TestIsForbiddenIPv4LinkLocalIMDS(t *testing.T) {
	// 169.254.169.254 is the AWS / GCP / Azure instance-metadata endpoint —
	// the canonical SSRF exfiltration target.
	for _, ip := range []string{"169.254.0.1", "169.254.169.254", "169.254.254.254"} {
		require.True(t, IsForbidden(net.ParseIP(ip)), "%s must be forbidden (link-local / IMDS)", ip)
	}
}

func TestIsForbiddenIPv4Unspecified(t *testing.T) {
	require.True(t, IsForbidden(net.ParseIP("0.0.0.0")))
}

func TestIsForbiddenIPv4Multicast(t *testing.T) {
	for _, ip := range []string{"224.0.0.1", "239.255.255.255"} {
		require.True(t, IsForbidden(net.ParseIP(ip)), "%s must be forbidden (multicast)", ip)
	}
}

func TestIsForbiddenIPv4Broadcast(t *testing.T) {
	require.True(t, IsForbidden(net.ParseIP("255.255.255.255")))
}

func TestIsForbiddenIPv6Loopback(t *testing.T) {
	require.True(t, IsForbidden(net.ParseIP("::1")))
}

func TestIsForbiddenIPv6LinkLocal(t *testing.T) {
	for _, ip := range []string{"fe80::1", "fe80::abcd:1234"} {
		require.True(t, IsForbidden(net.ParseIP(ip)), "%s must be forbidden (IPv6 link-local)", ip)
	}
}

func TestIsForbiddenIPv6Multicast(t *testing.T) {
	for _, ip := range []string{"ff02::1", "ff05::1:3"} {
		require.True(t, IsForbidden(net.ParseIP(ip)), "%s must be forbidden (IPv6 multicast)", ip)
	}
}

func TestIsForbiddenIPv6Unspecified(t *testing.T) {
	require.True(t, IsForbidden(net.ParseIP("::")))
}

func TestIsAllowedRFC1918(t *testing.T) {
	// RFC 1918 private address space — customer networks legitimately use
	// these for the devices the beacon probes. NOT forbidden.
	for _, ip := range []string{"10.0.0.1", "10.255.255.254", "172.16.0.1", "172.31.255.254", "192.168.1.1"} {
		require.False(t, IsForbidden(net.ParseIP(ip)), "%s must NOT be forbidden (RFC 1918)", ip)
	}
}

func TestIsAllowedPublic(t *testing.T) {
	for _, ip := range []string{"8.8.8.8", "1.1.1.1", "203.0.113.5"} {
		require.False(t, IsForbidden(net.ParseIP(ip)), "%s must NOT be forbidden (public)", ip)
	}
}

func TestIPv4MappedIPv6CanonicalizedFirst(t *testing.T) {
	// An attacker might try to bypass the loopback reject by wrapping
	// 127.0.0.1 as ::ffff:127.0.0.1. IsForbidden must Unmap() first.
	mapped := net.ParseIP("::ffff:127.0.0.1")
	require.NotNil(t, mapped)
	require.True(t, IsForbidden(mapped), "IPv4-mapped IPv6 loopback must hit the IPv4 loopback CIDR")
}

func TestIsForbiddenNilOrInvalid(t *testing.T) {
	// Fail-closed — unparseable input is treated as forbidden.
	require.True(t, IsForbidden(nil))
	require.True(t, IsForbidden([]byte{0x01}))
}
