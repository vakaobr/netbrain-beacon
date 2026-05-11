package safedial

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// fakeResolver returns a fixed IP list (or error) regardless of the lookup
// arguments. Used to simulate DNS-rebinding scenarios deterministically.
type fakeResolver struct {
	ips []net.IP
	err error
}

func (f *fakeResolver) LookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.ips, nil
}

// recordingDialer captures the address it was asked to dial without actually
// opening a socket. Returns a closed connection placeholder via a pipe.
type recordingDialer struct {
	lastNetwork string
	lastAddress string
	dialErr     error
}

func (r *recordingDialer) DialContext(_ context.Context, network, address string) (net.Conn, error) {
	r.lastNetwork = network
	r.lastAddress = address
	if r.dialErr != nil {
		return nil, r.dialErr
	}
	// Return a closed pipe end so callers that immediately Close() don't panic.
	c1, c2 := net.Pipe()
	_ = c2.Close()
	return c1, nil
}

func newTestDialer(ips []net.IP, lookupErr error) (*Dialer, *recordingDialer) {
	rd := &recordingDialer{}
	return &Dialer{
		Resolver:  &fakeResolver{ips: ips, err: lookupErr},
		NetDialer: rd,
	}, rd
}

// --------------------------- IP literal inputs ---------------------------

func TestDialIPLiteralAllowed(t *testing.T) {
	d, rd := newTestDialer(nil, nil)
	conn, err := d.Dial(context.Background(), "tcp", "10.0.0.5", 22)
	require.NoError(t, err)
	require.NoError(t, conn.Close())
	require.Equal(t, "10.0.0.5:22", rd.lastAddress)
}

func TestDialIPLiteralLoopbackRejected(t *testing.T) {
	d, _ := newTestDialer(nil, nil)
	_, err := d.Dial(context.Background(), "tcp", "127.0.0.1", 80)
	require.ErrorIs(t, err, ErrForbiddenIP)
}

func TestDialIPLiteralIMDSRejected(t *testing.T) {
	d, _ := newTestDialer(nil, nil)
	_, err := d.Dial(context.Background(), "tcp", "169.254.169.254", 80)
	require.ErrorIs(t, err, ErrForbiddenIP)
}

// --------------------------- DNS hostname inputs ---------------------------

func TestDialHostnameResolvesToAllowed(t *testing.T) {
	d, rd := newTestDialer([]net.IP{net.ParseIP("10.0.0.5")}, nil)
	conn, err := d.Dial(context.Background(), "tcp", "device.example.com", 22)
	require.NoError(t, err)
	require.NoError(t, conn.Close())
	require.Equal(t, "10.0.0.5:22", rd.lastAddress, "must dial the resolved IP literal, not the hostname")
}

func TestDialHostnameResolvesToForbidden(t *testing.T) {
	d, rd := newTestDialer([]net.IP{net.ParseIP("169.254.169.254")}, nil)
	_, err := d.Dial(context.Background(), "tcp", "metadata.example.com", 80)
	require.ErrorIs(t, err, ErrForbiddenIP)
	require.Empty(t, rd.lastAddress, "must not dial after allow-list reject")
}

func TestDialDNSLookupFailure(t *testing.T) {
	d, _ := newTestDialer(nil, errors.New("no such host"))
	_, err := d.Dial(context.Background(), "tcp", "nonexistent.invalid", 80)
	require.ErrorIs(t, err, ErrDNSLookupFailed)
}

func TestDialEmptyResolve(t *testing.T) {
	d, _ := newTestDialer([]net.IP{}, nil)
	_, err := d.Dial(context.Background(), "tcp", "empty.example.com", 80)
	require.ErrorIs(t, err, ErrEmptyResolve)
}

// --------------------------- Multi-IP edge case ---------------------------

func TestDialMultipleIPsAllAllowed(t *testing.T) {
	d, rd := newTestDialer(
		[]net.IP{net.ParseIP("10.0.0.5"), net.ParseIP("10.0.0.6"), net.ParseIP("172.16.1.1")},
		nil,
	)
	conn, err := d.Dial(context.Background(), "tcp", "device.example.com", 22)
	require.NoError(t, err)
	require.NoError(t, conn.Close())
	require.Equal(t, "10.0.0.5:22", rd.lastAddress, "must dial the first resolved IP")
}

func TestDialMultipleIPsOneForbiddenRejectAll(t *testing.T) {
	// Defence in depth: a hostname that resolves to both 10.0.0.5 AND
	// 127.0.0.1 must be rejected ENTIRELY, not "skip the bad one, dial the
	// good one". This closes the DNS-rebinding split where the attacker
	// arranges for one allow-listed and one forbidden IP in the same A
	// record.
	d, rd := newTestDialer(
		[]net.IP{net.ParseIP("10.0.0.5"), net.ParseIP("127.0.0.1")},
		nil,
	)
	_, err := d.Dial(context.Background(), "tcp", "split.example.com", 22)
	require.ErrorIs(t, err, ErrForbiddenIP)
	require.Empty(t, rd.lastAddress, "must NOT dial when any resolved IP is forbidden")
}

// --------------------------- DNS rebinding ---------------------------

// rebindingResolver returns a SAFE IP on first call, a FORBIDDEN IP on
// every subsequent call. Simulates a TTL-0 attack where the attacker
// flips the response between the allow-list check and the actual dial.
type rebindingResolver struct {
	called int
}

func (r *rebindingResolver) LookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	r.called++
	if r.called == 1 {
		return []net.IP{net.ParseIP("10.0.0.5")}, nil
	}
	return []net.IP{net.ParseIP("127.0.0.1")}, nil
}

func TestDialResistantToDNSRebinding(t *testing.T) {
	// Even if a misuse of the API allows multiple resolves, safedial.Dial
	// must NEVER re-resolve after the allow-list check. The dial address
	// must contain the literal IP from the FIRST (and only) lookup.
	rr := &rebindingResolver{}
	rd := &recordingDialer{}
	d := &Dialer{Resolver: rr, NetDialer: rd}

	conn, err := d.Dial(context.Background(), "tcp", "rebind.example.com", 22)
	require.NoError(t, err)
	require.NoError(t, conn.Close())

	require.Equal(t, 1, rr.called, "Dial must resolve EXACTLY once")
	require.Equal(t, "10.0.0.5:22", rd.lastAddress, "must dial the first resolved IP literal")
	require.False(t, strings.Contains(rd.lastAddress, "rebind.example.com"),
		"the hostname must NEVER reach the net.Dialer — DNS rebinding bypass")
}

// --------------------------- Port validation ---------------------------

func TestDialBadPortZero(t *testing.T) {
	d, _ := newTestDialer(nil, nil)
	_, err := d.Dial(context.Background(), "tcp", "10.0.0.5", 0)
	require.ErrorIs(t, err, ErrBadPort)
}

func TestDialBadPortNegative(t *testing.T) {
	d, _ := newTestDialer(nil, nil)
	_, err := d.Dial(context.Background(), "tcp", "10.0.0.5", -1)
	require.ErrorIs(t, err, ErrBadPort)
}

func TestDialBadPortOver65535(t *testing.T) {
	d, _ := newTestDialer(nil, nil)
	_, err := d.Dial(context.Background(), "tcp", "10.0.0.5", 65536)
	require.ErrorIs(t, err, ErrBadPort)
}

// --------------------------- Context propagation ---------------------------

func TestDialContextCancelled(t *testing.T) {
	// Context cancellation during DNS lookup should surface as an error
	// (specific shape depends on the resolver; we just need ANY error).
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()

	// Use the default DialContext path (no mock) so the context actually
	// matters. Resolve a domain that won't be in the local cache.
	_, err := Dial(ctx, "tcp", "example.invalid", 80)
	require.Error(t, err)
}

// --------------------------- Package-level Dial ---------------------------

func TestPackageLevelDialUsesDefaultResolver(t *testing.T) {
	// Sanity check that the package-level safedial.Dial function
	// delegates to DefaultDialer (which uses DefaultResolver / stdResolver).
	// IP-literal allowed inputs short-circuit DNS, so we can test without
	// network access.
	conn, err := Dial(context.Background(), "tcp", "127.0.0.1", 22)
	require.ErrorIs(t, err, ErrForbiddenIP)
	require.Nil(t, conn)
}
