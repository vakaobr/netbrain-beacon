package crypto

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
)

// Streaming gunzip with byte cap (M-6, CWE-409).
//
// ADR-069 forbids io.ReadAll(gzip.NewReader(...)) because the full plaintext
// is buffered before any size check. A 4 KB encrypted body containing 100 MB
// of zeros expands faster than the 413 response can fire if loaded eagerly.
//
// Mirror of services/api-gateway/src/ingestion/streaming_gunzip.py.
//
// Per-endpoint caps (parent issue):
//   - /data/logs:    50 MB plaintext
//   - /data/snmp:    20 MB
//   - /data/configs: 20 MB
//   - /data/flows:   multipart binary (not gzipped at envelope layer)

// chunkSize: 64 KiB read buffer. Small enough that the abort decision is
// fast on modern hardware; large enough to amortize gzip overhead.
const chunkSize = 64 * 1024

// Errors surfaced by streaming gunzip.
var (
	// ErrDecompressionBomb is returned when the running plaintext length
	// exceeds the caller-supplied cap during streaming read. Memory peak is
	// bounded by (maxBytes + chunkSize), not by the bomb's expanded payload.
	ErrDecompressionBomb = errors.New("plaintext exceeds max_bytes during gunzip (M-6)")

	// ErrGunzipCorrupt wraps a gzip-stream decoding failure.
	ErrGunzipCorrupt = errors.New("gzip stream corrupt")
)

// GunzipCapped decompresses src with a streaming read; aborts immediately
// with ErrDecompressionBomb if the plaintext exceeds maxBytes.
//
// Byte-compatibility note: the Python reference aborts when len(out) >
// max_bytes (strictly greater). This Go version mirrors that semantics —
// a plaintext of exactly max_bytes succeeds; max_bytes + 1 fails.
func GunzipCapped(src []byte, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		return nil, fmt.Errorf("max_bytes must be > 0, got %d", maxBytes)
	}

	gr, err := gzip.NewReader(bytes.NewReader(src))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrGunzipCorrupt, err)
	}
	defer func() {
		// Closing the reader after a streaming abort is best-effort; we
		// don't propagate close errors over the abort/corrupt error.
		_ = gr.Close()
	}()

	out := make([]byte, 0, chunkSize)
	buf := make([]byte, chunkSize)
	for {
		n, readErr := gr.Read(buf)
		if n > 0 {
			out = append(out, buf[:n]...)
			if int64(len(out)) > maxBytes {
				return nil, ErrDecompressionBomb
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, fmt.Errorf("%w: %w", ErrGunzipCorrupt, readErr)
		}
	}
	return out, nil
}
