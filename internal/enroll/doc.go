// Package enroll implements the beacon's bootstrap-token-then-CSR
// enrollment ceremony per ADR-067.
//
// # Flow
//
//  1. The operator obtains an enrollment bundle from the NetBrain admin UI
//     — a base64-encoded JSON blob signed with the platform's ed25519 key,
//     containing the bootstrap token, the platform CA cert (PEM), the
//     SPKI-PEM public key, and the bundle's expiry.
//  2. The beacon installer (`netbrain-beacon enroll --bundle <b64>`) parses
//     the bundle, verifies the signature against the embedded pubkey, and
//     refuses to proceed on any tamper.
//  3. The beacon generates a fresh ECDSA-P-256 keypair and a CSR with an
//     EMPTY Subject — the server rebuilds the identity per ADR-067 §H-3.
//  4. The beacon POSTs to /api/v1/beacons/enroll with
//     Authorization: Bearer <bootstrap_token>, sending {beacon_metadata,
//     bootstrap_token, csr_pem}. (The token is in both the header and
//     body for ergonomic reasons; the server checks the header.)
//  5. The server returns the signed client cert + DEK + endpoints +
//     intervals. The beacon persists everything atomically to disk:
//     beacon.crt (0644), beacon.key (0600), dek.bin (0600),
//     platform-ca.pem (0644), platform-pubkey.pem (0644),
//     enrollment-metadata.json (0644).
//  6. The persist step is atomic at the file-system level — temp files
//     are written then renamed into place. If any step (including the
//     bundle-signature verify) fails, NO artifacts are persisted.
//
// # Security mandates
//
//   - Bundle signature verify fail-closed (M-11 family): no artifacts on
//     verify error.
//   - Private key + DEK files set to 0600 (CWE-732).
//   - bootstrap_token NEVER logged in plaintext — the slog redactor in
//     internal/log strips it from every emitted record (H-3).
//   - Double-enroll refused unless --force; prevents accidental
//     re-issuance overwriting a working install.
//   - argon2 timing — server side; not handled here.
package enroll
