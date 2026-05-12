# netbrain-beacon — Engineering Learnings

Canonical store of lessons from beacon SDLC workflows. Mirror at `../netbrain/.claude/LEARNINGS.md` carries the full cross-repo history; this file is for beacon-repo-local entries.

---

### 2026-05-12 — add-beacon-service

- **`bufio.Scanner.Buffer(initial, max)` only enforces `max` once the buffer fills.** If `len(initial) > max`, the scanner can find a delimiter inside the slack and emit an oversize token without tripping `ErrTooLong`. Always clamp `initial = min(initial, max)` for hostile-input streams. CWE-770. (`internal/collectors/syslog/server.go handleTCPConn`)

- **`bufio.Reader.ReadBytes(delim)` grows unbounded on untrusted TCP.** `SetReadDeadline` does NOT bound memory under slow-drip. Use `bufio.Scanner` with bounded `Buffer`.

- **bbolt `Iter` callback cannot mutate the bucket.** Iter holds View tx; mutation opens Write tx → deadlock. Collect keys, mutate outside.

- **Never call `bbolt.Bucket.Stats()` on the hot path.** O(N) + panic risk (x/vulndb #4923). Maintain `meta:<counter>:<bucket>` keys updated in the same Tx. (`internal/store/meta.go addRecords`)

- **For test injection on concrete-struct deps, define a tiny `internal` interface in the consumer package.** Zero public-API change. (`internal/collectors/syslog/server.go putter`)

- **Cross-language byte-exactness via fixtures + startup `init()` self-test.** 21 cases (10 UUIDv5 / 5 AES-GCM / 3 ed25519 / 3 canonical JSON). Caught the UUIDv5 hex-string-vs-raw-bytes pitfall before it shipped. (ADR-004, `tests/fixtures/cross_lang/`)

- **forbidigo lint enforces security ADRs.** `math/rand` banned in `internal/crypto/**`; `net.Dial*` banned outside `internal/safedial/**`; `io.ReadAll(gzip.NewReader)` banned. (`.golangci.yml`)

- **`atomic.Pointer[*http.Client]` for cert hot-swap.** Old in-flight requests on old client; new on new client. No mutation, no lockfile, no SIGHUP. (ADR-003, `internal/transport/client.go`)

- **Cert recovery: walk live → .new → .prev, promote first that parses.** Only `LoadCertPairWithRecovery` may fall back. (`internal/transport/recovery.go`)

- **Empty-string crypto payloads as intentional contracts.** GET /config signs `data_key_b64=""` deliberately. Paired comments + regression test in BOTH repos. (`internal/daemon/poll.go`, `internal/daemon/dek_verify_test.go`)

- **`--bundle-file <path>` + ps-leak WARN for short-lived secrets.** Bootstrap tokens on CLI leak to ps/history/audit logs (CWE-214). Warn (don't error) on legacy inline flag. Perm check `> 0600` → WARN. (`cmd/netbrain-beacon/enroll_cmd.go readBundleArg`)

- **Two-track deploy for distributed binaries.** Track A artifact promotion (rc → canary → stable Docker tag + 6 distribution artifacts) interlocks with Track B platform feature-flag stages. Phase 7b pentest gates canary→stable. (`09_DEPLOY_PLAN.md`)

- **F-notes triage at review.** "Fix inline" (F-4/F-5/F-7/F-8 same-day) vs "follow-up issue" (F-1/F-2/F-3/F-6 stubs). (`06_CODE_REVIEW.md`)