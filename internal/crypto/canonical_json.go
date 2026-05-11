package crypto

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"unicode/utf16"
)

// Canonical JSON encoding for the ed25519 signed bundle.
//
// Mirror of Python:
//
//	json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
//
// Properties:
//   - Keys sorted lexicographically at every nesting level.
//   - No whitespace anywhere.
//   - Non-ASCII runes escaped as \uXXXX (surrogate pairs for runes > 0xFFFF).
//   - Control chars (< 0x20) escaped as \uXXXX or short forms (\n, \t, etc.).
//
// Go's encoding/json does NOT match Python on either non-ASCII escaping
// (Python escapes by default with ensure_ascii=True; Go passes UTF-8 bytes
// through) or on HTML escaping (Go escapes <, >, & by default; Python does
// not). This canonicalizer side-steps both issues by reformatting after
// decode.

// CanonicalizePayload returns the canonical JSON byte string of payload.
//
// Accepts an opaque any (typically map[string]any or json.Unmarshal output)
// and re-encodes deterministically. Used by VerifySignature to recompute
// the signed bytes the platform produced.
func CanonicalizePayload(payload any) ([]byte, error) {
	var buf bytes.Buffer
	if err := writeCanonical(&buf, payload); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// CanonicalizeRawJSON re-encodes already-marshalled JSON bytes canonically.
// Useful when the caller already has the JSON envelope (e.g., from an HTTP
// response body) and wants to verify a signature over its canonical form.
func CanonicalizeRawJSON(raw json.RawMessage) ([]byte, error) {
	var v any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("canonical_json: decode raw: %w", err)
	}
	return CanonicalizePayload(v)
}

func writeCanonical(buf *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if x {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		writeCanonicalString(buf, x)
	case json.Number:
		// Preserves the original lexical form (matches Python's repr of int
		// and the canonical form of float through json.dumps).
		buf.WriteString(string(x))
	case float64:
		// json.Marshal-style float — for our use case (issued_at strings,
		// integer versions) we'd prefer json.Number, but accept float64 as
		// a fallback. Use strconv to mirror json.Marshal output.
		s := strconv.FormatFloat(x, 'g', -1, 64)
		buf.WriteString(s)
	case int:
		buf.WriteString(strconv.Itoa(x))
	case int64:
		buf.WriteString(strconv.FormatInt(x, 10))
	case []any:
		buf.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeCanonicalString(buf, k)
			buf.WriteByte(':')
			if err := writeCanonical(buf, x[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("canonical_json: unsupported type %T", v)
	}
	return nil
}

// writeCanonicalString matches Python's json.dumps(ensure_ascii=True)
// for the string-escape rules. The function emits the surrounding quotes.
func writeCanonicalString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			switch {
			case r < 0x20:
				// Other control chars: \u00XX
				fmt.Fprintf(buf, `\u%04x`, r)
			case r < 0x7f:
				// Printable ASCII: pass through (note: Python ensure_ascii
				// passes printable ASCII through as-is; this matches).
				buf.WriteRune(r)
			case r <= 0xffff:
				// BMP non-ASCII: \uXXXX
				fmt.Fprintf(buf, `\u%04x`, r)
			default:
				// Supplementary plane: encode as UTF-16 surrogate pair to
				// match Python's json.dumps output (which uses surrogates).
				r1, r2 := utf16.EncodeRune(r)
				fmt.Fprintf(buf, `\u%04x\u%04x`, r1, r2)
			}
		}
	}
	buf.WriteByte('"')
}
