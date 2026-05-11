package crypto

import (
	"crypto/rand"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func newDEK(t *testing.T) []byte {
	t.Helper()
	dek := make([]byte, dekLen)
	_, err := rand.Read(dek)
	require.NoError(t, err)
	return dek
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	dek := newDEK(t)
	dekVersion := byte(7)
	ik := uuid.New()
	aad := MakeAAD(dekVersion, ik)
	plaintext := []byte("the quick brown fox jumps over the lazy dog")

	envelope, err := Encrypt(plaintext, dek, dekVersion, aad)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(envelope), MinEnvelopeLen)

	got, err := Decrypt(envelope, dek, aad)
	require.NoError(t, err)
	require.Equal(t, plaintext, got)
}

func TestEncryptEmptyPlaintext(t *testing.T) {
	dek := newDEK(t)
	aad := MakeAAD(1, uuid.New())
	envelope, err := Encrypt(nil, dek, 1, aad)
	require.NoError(t, err)
	require.Equal(t, MinEnvelopeLen, len(envelope), "empty plaintext envelope = header + tag")

	got, err := Decrypt(envelope, dek, aad)
	require.NoError(t, err)
	require.Empty(t, got)
}

func TestEncryptIVUniqueness(t *testing.T) {
	// Property test: 1000 encryptions of the same plaintext with the same
	// key must produce 1000 distinct IVs. M-4 guarantees this via
	// crypto/rand. Failure here means the IV source is non-CSPRNG.
	dek := newDEK(t)
	aad := MakeAAD(1, uuid.New())
	pt := []byte("constant plaintext")

	const iters = 1000
	seen := make(map[[12]byte]struct{}, iters)
	for i := 0; i < iters; i++ {
		envelope, err := Encrypt(pt, dek, 1, aad)
		require.NoError(t, err)
		parsed, err := Parse(envelope)
		require.NoError(t, err)
		var iv [12]byte
		copy(iv[:], parsed.IV)
		_, dup := seen[iv]
		require.False(t, dup, "IV collision after %d iterations — CSPRNG regression", i)
		seen[iv] = struct{}{}
	}
}

func TestDecryptTamperedTag(t *testing.T) {
	dek := newDEK(t)
	aad := MakeAAD(1, uuid.New())
	envelope, err := Encrypt([]byte("payload"), dek, 1, aad)
	require.NoError(t, err)

	// Flip the last byte of the tag.
	tampered := make([]byte, len(envelope))
	copy(tampered, envelope)
	tampered[len(tampered)-1] ^= 0xff

	_, err = Decrypt(tampered, dek, aad)
	require.ErrorIs(t, err, ErrEnvelopeAuthFailed)
}

func TestDecryptTamperedCiphertext(t *testing.T) {
	dek := newDEK(t)
	aad := MakeAAD(1, uuid.New())
	envelope, err := Encrypt([]byte("payload"), dek, 1, aad)
	require.NoError(t, err)

	// Flip a byte in the ciphertext region (between header and tag).
	tampered := make([]byte, len(envelope))
	copy(tampered, envelope)
	tampered[envelopeHeaderLen] ^= 0xff

	_, err = Decrypt(tampered, dek, aad)
	require.ErrorIs(t, err, ErrEnvelopeAuthFailed)
}

func TestDecryptTamperedAAD(t *testing.T) {
	dek := newDEK(t)
	ik := uuid.New()
	aadGood := MakeAAD(1, ik)
	envelope, err := Encrypt([]byte("payload"), dek, 1, aadGood)
	require.NoError(t, err)

	// Mutate the AAD's idempotency-key portion → GCM tag must fail.
	aadBad := make([]byte, len(aadGood))
	copy(aadBad, aadGood)
	aadBad[5] ^= 0xff

	_, err = Decrypt(envelope, dek, aadBad)
	require.ErrorIs(t, err, ErrEnvelopeAuthFailed)
}

func TestDecryptDownversionAttackBoundByAAD(t *testing.T) {
	// M-11 attack surface: an attacker flips the envelope dek_v byte hoping
	// the server uses a different DEK to decrypt. The envelope header bytes
	// (ver, dek_v) are NOT included in GCM authentication — the BINDING is
	// in the AAD. So:
	//   - if the server re-constructs AAD from the (tampered) envelope dek_v,
	//     the AAD bytes diverge from the encryptor's AAD → tag fails → 400.
	//   - if the server uses an AAD with the ORIGINAL dek_v, tag passes but
	//     the server picked the wrong DEK to decrypt → decryption still fails.
	// Either way the attack is defeated; this test exercises the first path,
	// which is the canonical server behavior.
	dek := newDEK(t)
	ik := uuid.New()
	aadEncrypt := MakeAAD(1, ik)
	envelope, err := Encrypt([]byte("payload"), dek, 1, aadEncrypt)
	require.NoError(t, err)

	tampered := make([]byte, len(envelope))
	copy(tampered, envelope)
	tampered[1] = 2

	// Server re-derives AAD from tampered envelope's dek_v=2 → tag fails.
	aadServerSide := MakeAAD(2, ik)
	_, err = Decrypt(tampered, dek, aadServerSide)
	require.ErrorIs(t, err, ErrEnvelopeAuthFailed)
}

func TestDecryptWrongDEK(t *testing.T) {
	dekA := newDEK(t)
	dekB := newDEK(t)
	aad := MakeAAD(1, uuid.New())
	envelope, err := Encrypt([]byte("payload"), dekA, 1, aad)
	require.NoError(t, err)

	_, err = Decrypt(envelope, dekB, aad)
	require.ErrorIs(t, err, ErrEnvelopeAuthFailed)
}

func TestEncryptBadDEKLen(t *testing.T) {
	_, err := Encrypt([]byte("pt"), make([]byte, 16), 1, nil)
	require.ErrorIs(t, err, ErrEnvelopeBadDEKLen)
}

func TestParseTooShort(t *testing.T) {
	_, err := Parse([]byte{0x01})
	require.ErrorIs(t, err, ErrEnvelopeTooShort)
}

func TestParseBadVersion(t *testing.T) {
	short := make([]byte, MinEnvelopeLen)
	short[0] = 0x02
	_, err := Parse(short)
	require.ErrorIs(t, err, ErrEnvelopeBadVersion)
}

func TestParseRoundTrip(t *testing.T) {
	dek := newDEK(t)
	aad := MakeAAD(42, uuid.New())
	envelope, err := Encrypt([]byte("xyz"), dek, 42, aad)
	require.NoError(t, err)

	parsed, err := Parse(envelope)
	require.NoError(t, err)
	require.Equal(t, byte(0x01), parsed.Version)
	require.Equal(t, byte(42), parsed.DEKVersion)
	require.Len(t, parsed.IV, 12)
	require.Len(t, parsed.Tag, 16)
	require.Len(t, parsed.Ciphertext, len("xyz"))
}

func TestMakeAADShape(t *testing.T) {
	ik := uuid.MustParse("12345678-1234-1234-1234-1234567890ab")
	aad := MakeAAD(0x07, ik)
	require.Len(t, aad, 17)
	require.Equal(t, byte(0x07), aad[0])
	require.Equal(t, ik[:], aad[1:])
}

// ErrEnvelopeAuthFailed must be a stable sentinel (callers compare via
// errors.Is). Guard against accidental wrapping that breaks the contract.
func TestErrEnvelopeAuthFailedIsStable(t *testing.T) {
	dek := newDEK(t)
	aad := MakeAAD(1, uuid.New())
	envelope, _ := Encrypt([]byte("pt"), dek, 1, aad)
	envelope[len(envelope)-1] ^= 0xff
	_, err := Decrypt(envelope, dek, aad)
	require.True(t, errors.Is(err, ErrEnvelopeAuthFailed))
}
