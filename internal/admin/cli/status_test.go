package cli

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/velonet/netbrain-beacon/internal/collectors"
	"github.com/velonet/netbrain-beacon/internal/collectors/netflow"
	"github.com/velonet/netbrain-beacon/internal/collectors/snmp"
	"github.com/velonet/netbrain-beacon/internal/enroll"
	"github.com/velonet/netbrain-beacon/internal/store"
)

func TestCollectStatusEmptyDir(t *testing.T) {
	r, err := CollectStatus(t.TempDir())
	require.NoError(t, err)
	require.False(t, r.Enrolled)
	require.Empty(t, r.BeaconID)
}

func TestCollectStatusAfterEnroll(t *testing.T) {
	dir := t.TempDir()

	// Mint a self-signed cert for the status report's cert-expiry inspection.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	require.NoError(t, err)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	art := &enroll.Artifacts{
		BeaconCertPEM:     certPEM,
		BeaconKeyPEM:      []byte("key"),
		DEK:               make([]byte, 32),
		PlatformCAPEM:     []byte("ca"),
		PlatformPubKeyPEM: []byte("pub"),
		Metadata: enroll.Metadata{
			BeaconID:   uuid.MustParse("abcdef00-1234-4567-8901-abcdef012345"),
			EnrolledAt: time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC),
			ServerURL:  "https://platform.test:8443",
			DEKVersion: 2,
		},
	}
	require.NoError(t, enroll.Persist(dir, art))

	r, err := CollectStatus(dir)
	require.NoError(t, err)
	require.True(t, r.Enrolled)
	require.Equal(t, art.Metadata.BeaconID.String(), r.BeaconID)
	require.Equal(t, art.Metadata.ServerURL, r.ServerURL)
	require.Equal(t, 2, r.DEKVersion)
	require.NotEmpty(t, r.CertExpiresAt)
	require.Greater(t, r.CertLifeRemain, 0.9, "fresh 90-day cert should have ~1.0 lifecycle remaining")
}

func TestCollectStatusWithStore(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Open(dir, store.Options{})
	require.NoError(t, err)
	_, _ = s.Put(store.BucketLogs, []byte("seed"))
	require.NoError(t, s.Close())

	r, err := CollectStatus(dir)
	require.NoError(t, err)
	bs, ok := r.StoreBuckets["logs"]
	require.True(t, ok)
	require.Equal(t, 1, bs.Records)
	require.Equal(t, int64(4), bs.Bytes) // len("seed") = 4
}

func TestFormatStatusJSONRoundTrip(t *testing.T) {
	r := &StatusReport{
		Enrolled:   true,
		BeaconID:   "abc",
		EnrolledAt: "2026-05-12T00:00:00Z",
		ServerURL:  "https://test",
		DEKVersion: 1,
		StateDir:   "/var/lib/test",
	}
	var buf bytes.Buffer
	require.NoError(t, FormatStatusJSON(&buf, r))

	var back StatusReport
	require.NoError(t, json.NewDecoder(&buf).Decode(&back))
	require.Equal(t, r.BeaconID, back.BeaconID)
	require.Equal(t, r.DEKVersion, back.DEKVersion)
}

func TestFormatStatusHumanNotEnrolled(t *testing.T) {
	r := &StatusReport{Enrolled: false, StateDir: "/x"}
	var buf bytes.Buffer
	FormatStatusHuman(&buf, r)
	out := buf.String()
	require.Contains(t, out, "Enrolled:    no")
	require.Contains(t, out, "/x")
}

// --- collectors subcommand ---

func TestCollectStateFromRegistrySortedAndShape(t *testing.T) {
	r := collectors.NewRegistry()
	r.Add("snmp", &snmp.Stub{})
	r.Add("netflow", &netflow.Stub{})

	report := CollectStateFromRegistry(r)
	require.Len(t, report.Collectors, 2)
	require.Equal(t, "netflow", report.Collectors[0].Name, "sorted alphabetically")
	require.Equal(t, "snmp", report.Collectors[1].Name)
}

func TestFormatCollectorsHumanEmpty(t *testing.T) {
	var buf bytes.Buffer
	FormatCollectorsHuman(&buf, &CollectorsReport{})
	require.Contains(t, buf.String(), "No collectors registered.")
}

func TestFormatCollectorsHumanRows(t *testing.T) {
	rep := &CollectorsReport{Collectors: []CollectorEntry{
		{Name: "logs", Running: true},
		{Name: "snmp", Running: false},
	}}
	var buf bytes.Buffer
	FormatCollectorsHuman(&buf, rep)
	out := buf.String()
	require.Contains(t, out, "logs")
	require.Contains(t, out, "yes")
	require.Contains(t, out, "snmp")
	require.Contains(t, out, "no")
}

// --- logs tail ---

func TestTailFromFileBasic(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "beacon.log")
	lines := "line1\nline2\nline3\n"
	require.NoError(t, os.WriteFile(logPath, []byte(lines), 0o644))

	var buf bytes.Buffer
	require.NoError(t, Tail(context.Background(), &buf, TailOptions{Path: logPath, Follow: false}))
	require.Equal(t, lines, buf.String())
}

func TestTailMaxLinesBudget(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "beacon.log")
	require.NoError(t, os.WriteFile(logPath, []byte("a\nb\nc\nd\n"), 0o644))

	var buf bytes.Buffer
	require.NoError(t, Tail(context.Background(), &buf, TailOptions{Path: logPath, MaxLines: 2}))
	require.Equal(t, "a\nb\n", buf.String())
}

func TestTailGrepCaseInsensitive(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "beacon.log")
	require.NoError(t, os.WriteFile(logPath, []byte(`{"msg":"daemon.poll_failed"}
{"msg":"daemon.heartbeat_ok"}
{"msg":"daemon.DEK_signature_verify_failed"}
`), 0o644))

	var buf bytes.Buffer
	require.NoError(t, Tail(context.Background(), &buf, TailOptions{Path: logPath, Grep: "dek"}))
	require.Contains(t, buf.String(), "DEK_signature_verify_failed")
	require.NotContains(t, buf.String(), "poll_failed")
}

func TestTailLevelFilter(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "beacon.log")
	require.NoError(t, os.WriteFile(logPath, []byte(`{"level":"INFO","msg":"a"}
{"level":"ERROR","msg":"b"}
{"level":"INFO","msg":"c"}
`), 0o644))

	var buf bytes.Buffer
	require.NoError(t, Tail(context.Background(), &buf, TailOptions{Path: logPath, Level: "ERROR"}))
	require.Contains(t, buf.String(), `"msg":"b"`)
	require.NotContains(t, buf.String(), `"msg":"a"`)
}

func TestTailEmptyPath(t *testing.T) {
	require.Error(t, Tail(context.Background(), io.Discard, TailOptions{Path: ""}))
}

func TestTailMissingFile(t *testing.T) {
	require.Error(t, Tail(context.Background(), io.Discard, TailOptions{Path: "/nonexistent/log.json"}))
}

// TestTailFollowPicksUpAppendedLines verifies the follow-mode bug from
// I-8 / F-8: with the previous bufio.Scanner-reuse pattern, lines
// written after the initial drain were never observed because Scanner
// latches its done state on first EOF. This test writes lines AFTER
// starting Tail and asserts they are emitted.
func TestTailFollowPicksUpAppendedLines(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "beacon.log")
	require.NoError(t, os.WriteFile(logPath, []byte("initial-line\n"), 0o644))

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	type result struct {
		out string
		err error
	}
	done := make(chan result, 1)

	var buf safeBuffer
	go func() {
		err := Tail(ctx, &buf, TailOptions{
			Path:         logPath,
			Follow:       true,
			PollInterval: 20 * time.Millisecond,
		})
		done <- result{out: buf.String(), err: err}
	}()

	// Append lines to the file while Tail is following.
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0o644)
	require.NoError(t, err)
	// Stagger writes so they cross multiple poll ticks.
	time.Sleep(60 * time.Millisecond)
	_, _ = f.WriteString("append-1\n")
	time.Sleep(60 * time.Millisecond)
	_, _ = f.WriteString("append-2\n")
	time.Sleep(60 * time.Millisecond)
	_ = f.Close()

	// Give the poll loop one more tick to flush the second append,
	// then cancel and wait for Tail to return.
	time.Sleep(80 * time.Millisecond)
	cancel()

	r := <-done
	require.NoError(t, r.err, "Tail must return nil on ctx cancel; got: %v", r.err)
	require.Contains(t, r.out, "initial-line")
	require.Contains(t, r.out, "append-1", "follow-mode failed to pick up post-drain appended lines (F-8 regression)")
	require.Contains(t, r.out, "append-2", "follow-mode missed the second appended line")
}

// TestTailFollowReturnsOnCtxCancel verifies ctx-cancel makes Tail
// return promptly rather than blocking forever on the poll loop.
func TestTailFollowReturnsOnCtxCancel(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "beacon.log")
	require.NoError(t, os.WriteFile(logPath, []byte("x\n"), 0o644))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	var buf bytes.Buffer
	go func() {
		done <- Tail(ctx, &buf, TailOptions{Path: logPath, Follow: true, PollInterval: 10 * time.Millisecond})
	}()
	time.Sleep(50 * time.Millisecond) // let the goroutine enter the poll loop
	cancel()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(1 * time.Second):
		t.Fatal("Tail did not return within 1s of ctx cancel")
	}
}

// safeBuffer is a goroutine-safe wrapper around bytes.Buffer for tests
// that read the buffer concurrently with Tail's writes.
type safeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *safeBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *safeBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// ---

var _ = io.Discard
