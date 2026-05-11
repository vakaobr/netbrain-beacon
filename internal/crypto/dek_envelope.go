package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

// AES-256-GCM envelope per ADR-068.
//
// Wire format (parent issue §"Cipher"):
//
//	[ ver(1) | dek_v(1) | iv(12) | ct | tag(16) ]
//
// AAD layout (M-2-AAD): bytes([dek_v]) ++ idempotency_key.bytes (17 bytes).
//
// Byte-compatible with services/api-gateway/src/crypto/dek_envelope.py.

const (
	envelopeVersionByte = 0x01
	envelopeHeaderLen   = 1 + 1 + 12 // ver + dek_v + iv
	gcmTagLen           = 16
	gcmIVLen            = 12
	dekLen              = 32 // AES-256

	// MinEnvelopeLen is the byte count for an envelope holding an empty
	// plaintext: header + tag.
	MinEnvelopeLen = envelopeHeaderLen + gcmTagLen
)

// Errors surfaced by the envelope.
var (
	ErrEnvelopeTooShort   = errors.New("envelope: too short for header+tag")
	ErrEnvelopeBadVersion = errors.New("envelope: unsupported version byte")
	ErrEnvelopeBadDEKLen  = errors.New("envelope: DEK must be 32 bytes")
	ErrEnvelopeBadDEKVer  = errors.New("envelope: dek_version must fit in 1 byte")
	ErrEnvelopeAuthFailed = errors.New("envelope: GCM authentication failed (tampered ct/tag/aad)")
)

// Envelope is the parsed view of a wire-format envelope. The ciphertext and
// tag fields are slices into the original buffer — do not mutate.
type Envelope struct {
	Version    byte
	DEKVersion byte
	IV         []byte // 12 bytes
	Ciphertext []byte
	Tag        []byte // 16 bytes
}

// MakeAAD builds the AAD (additional authenticated data) for an encrypt/
// decrypt call. Layout: bytes([dek_version]) ++ idempotency_key.bytes
// (17 bytes total).
//
// Mirror of Python make_aad() — the dek_version byte in AAD prevents an
// attacker from down-versioning a batch (M-11 attack surface).
func MakeAAD(dekVersion byte, idempotencyKey uuid.UUID) []byte {
	out := make([]byte, 0, 1+16)
	out = append(out, dekVersion)
	out = append(out, idempotencyKey[:]...)
	return out
}

// Encrypt wraps plaintext into the wire-format envelope using AES-256-GCM
// with a CSPRNG-sourced IV (M-4).
//
// dekVersion must fit in one byte (0..255). aad is built by the caller via
// MakeAAD(dekVersion, idempotencyKey) — the function does not assume the AAD
// shape, mirroring the Python side.
func Encrypt(plaintext, dek []byte, dekVersion byte, aad []byte) ([]byte, error) {
	if len(dek) != dekLen {
		return nil, fmt.Errorf("%w: got %d", ErrEnvelopeBadDEKLen, len(dek))
	}

	iv := make([]byte, gcmIVLen)
	if _, err := rand.Read(iv); err != nil {
		// crypto/rand.Read on Linux/Windows is backed by getrandom/CryptGenRandom.
		// A failure here is exceptional (entropy pool exhausted under simulation,
		// or syscall failure) — surface, never substitute a non-crypto fallback.
		return nil, fmt.Errorf("crypto/rand: %w", err)
	}

	return encryptWithIV(plaintext, dek, dekVersion, iv, aad)
}

// encryptWithIV is the deterministic variant used by tests and by the
// cross-language fixture verifier. NEVER expose this externally — IV reuse
// under GCM leaks plaintext XOR.
func encryptWithIV(plaintext, dek []byte, dekVersion byte, iv, aad []byte) ([]byte, error) {
	if len(dek) != dekLen {
		return nil, fmt.Errorf("%w: got %d", ErrEnvelopeBadDEKLen, len(dek))
	}
	if len(iv) != gcmIVLen {
		return nil, fmt.Errorf("iv: must be %d bytes, got %d", gcmIVLen, len(iv))
	}

	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cipher.NewGCM: %w", err)
	}

	// aead.Seal appends ciphertext||tag to the first arg.
	// Total envelope = ver(1) + dek_v(1) + iv(12) + ciphertext + tag(16).
	out := make([]byte, 0, envelopeHeaderLen+len(plaintext)+gcmTagLen)
	out = append(out, envelopeVersionByte, dekVersion)
	out = append(out, iv...)
	out = aead.Seal(out, iv, plaintext, aad)
	return out, nil
}

// Parse decodes the envelope structure without decrypting. Useful for
// inspecting the dek_v byte (e.g., to look up the right DEK during the
// 7-day rotation grace) before invoking Decrypt.
func Parse(envelope []byte) (Envelope, error) {
	if len(envelope) < MinEnvelopeLen {
		return Envelope{}, fmt.Errorf("%w: got %d, need >= %d", ErrEnvelopeTooShort, len(envelope), MinEnvelopeLen)
	}
	if envelope[0] != envelopeVersionByte {
		return Envelope{}, fmt.Errorf("%w: got 0x%02x", ErrEnvelopeBadVersion, envelope[0])
	}
	return Envelope{
		Version:    envelope[0],
		DEKVersion: envelope[1],
		IV:         envelope[2:envelopeHeaderLen],
		Ciphertext: envelope[envelopeHeaderLen : len(envelope)-gcmTagLen],
		Tag:        envelope[len(envelope)-gcmTagLen:],
	}, nil
}

// Decrypt opens the envelope and returns the plaintext. Verifies the GCM tag
// against ciphertext AND aad — tampered AAD (e.g., wrong Idempotency-Key)
// surfaces as ErrEnvelopeAuthFailed.
func Decrypt(envelope, dek, aad []byte) ([]byte, error) {
	if len(dek) != dekLen {
		return nil, fmt.Errorf("%w: got %d", ErrEnvelopeBadDEKLen, len(dek))
	}

	parsed, err := Parse(envelope)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cipher.NewGCM: %w", err)
	}

	// AEAD expects ciphertext||tag joined. Concatenate (parsed slices point
	// into the source buffer; build a fresh slice to avoid aliasing concerns).
	ctAndTag := make([]byte, 0, len(parsed.Ciphertext)+len(parsed.Tag))
	ctAndTag = append(ctAndTag, parsed.Ciphertext...)
	ctAndTag = append(ctAndTag, parsed.Tag...)

	pt, err := aead.Open(nil, parsed.IV, ctAndTag, aad)
	if err != nil {
		return nil, ErrEnvelopeAuthFailed
	}
	return pt, nil
}
