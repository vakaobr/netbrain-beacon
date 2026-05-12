// Package probe implements the multi-proxy device-dedup latency probe per
// ADR-072.
//
// The beacon periodically measures the round-trip time to each configured
// device by attempting a TCP connect on the device's management ports
// (22 → 161 → 80, first success wins). The result is a per-device
// median-of-N samples that the heartbeat piggybacks back to the platform.
// The platform-side election job (ADR-076) ranks beacons by this median
// to pick a canonical owner for each device when ≥2 beacons see it.
//
// # Probe vs. ping
//
// We use TCP connect rather than ICMP because:
//   - many customer networks block ICMP
//   - TCP SYN/SYN-ACK measures roughly the same path as SNMP/SSH traffic
//   - no raw socket / CAP_NET_RAW capability needed
//
// # SSRF safety
//
// Every dial flows through internal/safedial.Dial — the M-9 allow-list
// rejects link-local / loopback / multicast IPs before the connect, and
// DNS is resolved exactly once per call to prevent rebinding bypasses.
package probe
