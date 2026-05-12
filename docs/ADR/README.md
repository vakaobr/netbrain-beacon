# Architecture Decision Records — netbrain-beacon

This directory hosts ADRs whose scope is the beacon binary specifically.
Each ADR `Pairs with` a corresponding ADR in the netbrain repo
([github.com/velonet/netbrain/ADR](https://github.com/velonet/netbrain/tree/main/ADR))
which uses the joint cross-repo numbering (077, 078, …). The beacon's
own numbering starts fresh at 001 so additions here don't churn the
joint numbering, and vice versa.

## Current ADRs

| Beacon # | Title | Netbrain pair |
|---|---|---|
| [ADR-001](ADR-001-beacon-binary-layout.md) | Beacon binary layout (`cmd/` + `internal/`) | ADR-077 |
| [ADR-002](ADR-002-store-and-forward-bbolt-schema.md) | Store-and-forward bbolt schema | ADR-078 |
| [ADR-003](ADR-003-cert-rotation-strategy.md) | Cert rotation strategy | ADR-079 |
| [ADR-004](ADR-004-cross-language-byte-exactness-fixtures.md) | Cross-language byte-exactness fixtures | ADR-080 |
| [ADR-005](ADR-005-ssrf-safe-dial-package.md) | SSRF safe-dial package | ADR-081 |
| [ADR-006](ADR-006-collector-goroutine-model.md) | Collector goroutine model | ADR-082 |

## Writing a new ADR

1. Pick the next unused beacon number.
2. If the decision also affects netbrain (it usually does), open a
   coordinated PR there and pick the next netbrain number.
3. Add the `**Pairs with:**` header line pointing at the netbrain ADR.
4. Mark `Status: Proposed` while in review; flip to `Accepted` once
   merged. See CONTRIBUTING.md for the cross-repo pairing rules.
