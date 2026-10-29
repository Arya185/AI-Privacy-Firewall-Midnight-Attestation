# midnight-side

Blockchain (Midnight) + cryptography module for the AI Privacy Firewall
project: notarize audit-log hashes with Compact contracts. The
firewall/policy/PII modules live in `../../privacy_firewall/`.

## Status

| Part | Status |
| --- | --- |
| `audit/` hash chain + Ed25519 sign/verify | Working offline; tampering detected |
| `contract/commit.compact` and `../../privacy_firewall/midnight/policy_attestation.compact` | Compile with Compact 0.31.1 |
| Contract logic | Verified by local simulation (`npm run simulate`), no network |
| TypeScript pipeline | `npm run typecheck` passes |
| Live Midnight Preview | **Not deployed. No transaction has been submitted.** A Preview wallet was generated, funded from the faucet (5,000 tNIGHT) and fully synced; the DUST-registration dry run builds a valid transaction (fee estimate: 1 Speck), but registration, deployment and commit were deliberately left for later |

Captured output of every check: [`../../docs/evidence/`](../../docs/evidence/).

## What's here

- `audit/` — Python: SHA-256 hash chain over an audit log, Ed25519
  signature over the root hash, verification.
- `contract/commit.compact` — stores the latest committed root hash
  (`commit`) and reads it back (`get_latest`).
- `scripts/`
  - `simulate_contract.ts` — runs both compiled contracts with the Compact
    runtime, offline.
  - `providers.ts` — wallet construction, sync with persisted state,
    Midnight.js providers.
  - `generate_wallet.ts`, `sync_wallet.ts`, `register_dust.ts`,
    `estimate_deploy_fee.ts`, `deploy_contract.ts`, `commit_to_chain.ts`,
    `run_pipeline.ts`.
- `docs/fallback_demo.md` — the offline demo path.

## Versions (Midnight support matrix)

Compact toolchain **0.31.1** (language 0.23.0) · compact-runtime **0.16.0** ·
compact-js 2.5.1 · Midnight.js 4.1.1 · proof server **8.1.3** · Node.js 22.

`compact-runtime` must be 0.16.0. Version 0.19.0 targets ledger 9 and is
listed by Midnight as incompatible with Midnight.js 4.1.1; it causes
`ContractConfigurationError: Failed to configure constructor context with
coin public key` at deploy time. Compilers 0.34+ also target ledger 9 and
produce contracts the Preview network cannot read.

## Offline setup and checks (no wallet, no network)

```bash
npm ci
curl --proto '=https' --tlsv1.2 -LsSf \
  https://github.com/midnightntwrk/compact/releases/latest/download/compact-installer.sh -o compact-installer.sh
less compact-installer.sh            # inspect, then:
sh compact-installer.sh
compact update 0.31.1

npm run compile                      # contract/commit.compact -> build/commit/
npm run compile:policy               # policy_attestation.compact -> build/policy_attestation/
npm run typecheck

python -m venv .venv && .venv/bin/pip install -r requirements.txt
(cd audit && ../.venv/bin/python fake_audit_generator.py && ../.venv/bin/python hash_chain.py)
(cd ../../privacy_firewall && PYTHONPATH=. python export_attestation_batch.py \
    ../firee/midnight-side/build/attestation_batch.json)
npm run simulate                     # 6/6 checks
```

## Optional: live Midnight Preview

Requires a running proof server, a funded wallet, and tDUST for fees.

Proof server (Podman shown; Docker works the same). Use the image's default
command — its `bash -c` entrypoint ignores extra arguments:

```bash
podman run -d --name midnight-proof-server -p 127.0.0.1:6300:6300 \
  --cap-drop=ALL --security-opt no-new-privileges docker.io/midnightntwrk/proof-server:8.1.3
curl http://127.0.0.1:6300/          # {"status":"ok",...}
```

Wallet and transactions:

```bash
npm run generate-wallet              # writes seed.txt (0600, never overwritten), prints the public address
# fund the address at https://midnight-tmnight-preview.nethermind.dev/
npm run sync-wallet                  # read-only; resumes from wallet-state.json; prints balances and fee estimate
npm run register-dust                # dry run: builds and signs locally, prints the exact fee, submits nothing
npm run register-dust -- --submit    # TRANSACTION: register tNIGHT for DUST generation
npm run estimate-deploy-fee          # read-only: deploy fee vs. available tDUST
npm run deploy                       # TRANSACTION: prints the contract address
MIDNIGHT_CONTRACT_ADDRESS=<addr> npm run commit   # TRANSACTION: commits audit/root_hash.txt
```

Notes:

- `generate-wallet` produces a raw 32-byte seed, not a recovery phrase, so
  it cannot be imported into Lace. DUST registration is done by
  `register_dust.ts`, signed by this wallet's own night key.
- A first sync from block 0 takes hours. Progress is saved every minute to
  `wallet-state.json` (0600, gitignored) and later runs resume from it;
  restored state is checked against the seed's keys and falls back to a
  full sync if it does not match. Only one process may use the state at a
  time (`wallet-state.json.lock`).
- `createProviders()` refuses to build transactions unless the wallet is
  fully synced and holds tDUST.

Environment variables (all optional):

- `MIDNIGHT_WALLET_SEED` or `MIDNIGHT_WALLET_SEED_FILE` (default `seed.txt`)
- `MIDNIGHT_INDEXER_URL` / `MIDNIGHT_INDEXER_WS_URL` (default: public Preview indexer)
- `MIDNIGHT_PROOF_SERVER_URL` (default `http://127.0.0.1:6300`)
- `MIDNIGHT_WALLET_STATE_FILE` (default `wallet-state.json`)
- `MIDNIGHT_SYNC_TIMEOUT_MS` (default 4 hours)
- `MIDNIGHT_CONTRACT_ADDRESS` (required for `npm run commit`)

Never commit `seed.txt`, `wallet-state.json*`, or `audit/*.pem`; all are gitignored.
