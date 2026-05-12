package collectors

import "sync/atomic"

// DEK is one immutable snapshot of the beacon's data-encryption-key
// state. The struct is value-copied across goroutines via DEKHolder's
// atomic.Pointer — never mutate fields after Set.
type DEK struct {
	// Key is the raw 32-byte AES-256 key. Zero-length means "no DEK
	// loaded yet" — the sender refuses to encrypt and returns an
	// ErrNoDEK to the caller.
	Key []byte
	// Version is the DEK version byte the envelope embeds. Mirrors the
	// server-side `beacon_registrations.data_key_version` column.
	Version byte
}

// DEKHolder is the runtime DEK state shared across collector senders.
// Lock-free reads via atomic.Pointer; the daemon's DEK-rotation handler
// (Phase 8 dek_verify.go path) calls Set to publish a rotated key.
//
// Zero value is ready to use; callers MUST call Set at least once before
// the first sender flush, otherwise senders surface ErrNoDEK.
type DEKHolder struct {
	current atomic.Pointer[DEK]
}

// NewDEKHolder returns a DEKHolder primed with the supplied DEK. Used
// at daemon startup right after reading dek.bin off disk.
func NewDEKHolder(initial *DEK) *DEKHolder {
	h := &DEKHolder{}
	if initial != nil {
		h.current.Store(initial)
	}
	return h
}

// Current returns the active DEK or nil if Set has never been called.
// Safe under concurrent reads + writes.
func (h *DEKHolder) Current() *DEK {
	return h.current.Load()
}

// Set publishes a new DEK as the active one. The previous DEK is
// returned for callers that want to retain it for the 7-day rotation
// grace window (Phase 8 doesn't yet wire grace lookup — that arrives
// when /data/* receives a 401 BEACON_DEK_EXPIRED and falls back to the
// previous DEK).
func (h *DEKHolder) Set(d *DEK) *DEK {
	if d == nil {
		// Defensive: refuse to clear the active DEK via Set(nil). A
		// concurrent reader would otherwise see Current()==nil and the
		// sender would start returning ErrNoDEK silently.
		return h.current.Load()
	}
	return h.current.Swap(d)
}
