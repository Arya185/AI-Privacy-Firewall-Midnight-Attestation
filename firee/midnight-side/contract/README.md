# commit.compact - contract notes

## What this is
Two circuits: `commit(newHash)` stores the latest audit hash-chain root hash
as public ledger state (`latestHash`) and increments `commitCount`;
`get_latest()` reads it back. No policy logic lives on-chain.

## Compile
From `firee/midnight-side/`, with Compact toolchain 0.31.1:
```
npm run compile        # = compact compile contract/commit.compact build/commit
```
Output: `build/commit/contract/` (JS + types), `build/commit/keys/`
(prover/verifier keys for both circuits), `build/commit/zkir/`.

## Verify without a network
```
npm run simulate
```
Runs the compiled contract with the Compact runtime: `commit(root hash)`,
then `get_latest()` must return it and `commitCount` must be 1.

## Deployment record
- Network: Midnight Preview (testnet)
- Status: **not deployed**; no deploy transaction has been submitted
- Contract address: —
- Deploy tx: —

Deployment steps are in `../README.md` ("Optional: live Midnight Preview").
If no live network is available, use `../docs/fallback_demo.md`.
