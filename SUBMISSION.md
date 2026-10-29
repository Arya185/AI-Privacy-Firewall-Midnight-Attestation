# AI Privacy Firewall – Midnight Attestation: Submission

A privacy boundary between an AI agent and sensitive data. It decides what
the model may receive (inbound), inspects what the model emits (outbound),
and reduces every decision to a 32-byte hash that a Midnight Compact
contract can attest, so an auditor can verify *that* a decision was made
without seeing *what data* it concerned.

## Submission checklist

| Item | Status | Evidence |
| --- | --- | --- |
| Source code: Python firewall | Complete | `privacy_firewall/` |
| Source code: Compact contracts | Complete; both compile | `privacy_firewall/midnight/policy_attestation.compact`, `firee/midnight-side/contract/commit.compact` |
| Unit / security tests | 234/234 pass | `docs/evidence/01_pytest.txt` |
| End-to-end demo | 5/5 scenarios pass | `docs/evidence/02_demo.txt` |
| Contract compilation (Compact 0.31.1) | Pass: 2 circuits each, prover/verifier keys | `docs/evidence/03_compile_contracts.txt` |
| TypeScript pipeline typecheck | Pass | `docs/evidence/04_typecheck.txt` |
| Firewall → contract integration (offline) | Pass: 4 real decision hashes recorded and attested; 6/6 checks | `docs/evidence/05_export_batch.txt`, `06_simulate_contracts.txt` |
| Tamper-evident audit + Ed25519 signature | Pass; tampered copy rejected | `docs/evidence/07_audit_sign_verify.txt` |
| Documentation | `README.md`, `DESIGN.md`, `firee/midnight-side/README.md`, this file | — |
| CI | GitHub Actions workflow (tests + demo on Python 3.10–3.12) | `.github/workflows/ci.yml` (not run as part of this verification) |
| Live Midnight Preview deployment | **Optional; not done** | See "Live network status" |

## Architecture

```
            structured request                       model output
 AI agent ───────────────────► ┌──────────────────────────────┐ ◄────────── FakeLLM
                               │ PrivacyFirewallMiddleware    │
                               │  PolicyEngine (YAML, fail-   │
                               │   closed, per-field RBAC)    │
                               │  DataMinimizer (raw /        │
                               │   {count,sum,avg} / drop,    │
                               │   k-anonymity floor)         │
                               │  OutputFirewall (canaries,   │
                               │   PII scan)                  │
                               └──────────────┬───────────────┘
                                              │ every decision
                                              ▼
                               AuditLog: SHA-256 hash chain (off-chain tamper evidence)
                                              │
                                              ▼
                               MidnightBridge: Bytes32 decision hash per decision
                               + private witness (agent, fields, reason stay local)
                               + HMAC-signed batch
                                              │ only hashes
                                              ▼
              ┌───────────────────────────────┴──────────────────────────────┐
              │ policy_attestation.compact          commit.compact           │
              │  attested: Map<Bytes<32>,Boolean>    latestHash: Bytes<32>   │
              │  recordAttestation / isAttested      commit / get_latest     │
              └──────────────────────────────────────────────────────────────┘
               compiled with Compact 0.31.1 · executed locally · not deployed
```

## Workflow

1. The agent sends a structured request; it never touches the database.
2. The policy engine resolves each field to `ALLOW`, `AGGREGATE_ONLY` or
   `DENY` (anything unlisted is denied).
3. The minimizer returns raw values, aggregates only, or nothing.
4. The output firewall blocks responses that contain canary tokens or
   unauthorized PII.
5. Each decision is appended to the hash-chained audit log.
6. The bridge turns each decision into a `Bytes32` hash and exports a
   signed batch; private details stay in the local witness.
7. `recordAttestation(hash)` stores the hash on the contract ledger;
   `isAttested(hash)` lets anyone check it. `commit.compact` notarizes the
   audit chain's root hash.

Steps 1–6 run in Python. Step 7 is verified by executing the compiled
contracts locally with real hashes from step 6.

## Reproduce

```bash
# Python firewall
cd privacy_firewall
python -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python -m pytest -q                         # 234 passed
.venv/bin/python demo.py --no-pause --no-color        # 5/5 PASS

# Contracts (Node.js 22 + Compact 0.31.1; see firee/midnight-side/README.md)
cd ../firee/midnight-side
npm ci && compact update 0.31.1
npm run compile && npm run compile:policy && npm run typecheck
python -m venv .venv && .venv/bin/pip install -r requirements.txt
(cd audit && ../.venv/bin/python fake_audit_generator.py && ../.venv/bin/python hash_chain.py)
(cd ../../privacy_firewall && PYTHONPATH=. .venv/bin/python export_attestation_batch.py \
    ../firee/midnight-side/build/attestation_batch.json)
npm run simulate                                      # 6/6 checks
```

## Verified results (2026-10-29, Fedora 44, Python 3.14.8, Node.js 22.23.4)

| Check | Result |
| --- | --- |
| `pytest` | 234 passed, 0 failed |
| `demo.py` | 5/5 scenarios PASS; `verify_chain()` PASSED |
| `npm run compile`, `npm run compile:policy` | Both contracts compiled (language 0.23.0, runtime 0.16.0) |
| `npm run typecheck` | No errors |
| `export_attestation_batch.py` | 4 decision hashes exported |
| `npm run simulate` | 6/6 checks pass |
| `audit/verify.py` | PASS on the original log; FAIL on a copy with one field changed |

The test suite was run on Python 3.14; CI targets 3.10–3.12.

## Live network status (Midnight Preview)

Verified facts only:

- A wallet was generated by `npm run generate-wallet`. Public address:
  `mn_addr_preview1ld03888rp4hu8622s7ncc4j3d9j02mvkth83kwwujfsjmvu824lsa6jnlc`.
- It was funded from the official Preview faucet (5,000,000,000 STAR in
  one UTXO). The faucet transaction is confirmed on the Preview indexer in
  block 1,503,471.
- The wallet fully synced, and the DUST-registration **dry run** built and
  signed a valid registration transaction locally (fee 1 Speck).
- **Not done:** DUST registration, contract deployment, audit-hash commit.
  No transaction from this wallet has been submitted. No contract address
  exists.

To finish later: `npm run register-dust -- --submit`, wait for tDUST to
accrue, `npm run estimate-deploy-fee`, `npm run deploy`, then
`npm run commit` (details in `firee/midnight-side/README.md`).

## Problems found and fixed during verification

| Problem | Fix |
| --- | --- |
| `policy_attestation.compact` did not compile (`unbound identifier Map`; `Opaque<"Bytes32">` unsupported) | Imported `CompactStandardLibrary`; used `Bytes<32>`. Parser and docstring in `midnight_bridge.py` and one demo label updated to match |
| `commit.compact` declared language 0.26.0 (ledger-9 toolchain) | Set to 0.23.0, the version supported by Preview |
| `compact-runtime` pinned to 0.19.0, incompatible with Midnight.js 4.1.1 (the "upstream compact-js bug" in the old README) | Pinned to 0.16.0 per Midnight's support matrix |
| Unshielded wallet started with no address; shielded/DUST wallets used raw-seed keys while signing with HD keys | Wallets now start from consistent HD-derived keys |
| Wallet never started syncing; whole wallet state, which can include key material, was logged | `facade.start()`, real sync wait with timeout, persisted state with verified restore, allowlisted logging |
| `generate-wallet` overwrote existing seeds and wrote them world-readable | Refuses to overwrite; file mode 0600; prints only the public address |
| `run_pipeline.ts` resolved paths from the working directory | Paths resolved from the script location |

## Limitations

- No live deployment; on-chain behaviour is shown by local execution of
  the compiled contracts, not by confirmed transactions.
- The off-chain batch is HMAC-SHA256 signed with a development key by
  default; it is not a zero-knowledge proof.
- `FakeLLM` stands in for a real model; behaviour of third-party models is
  not tested.
- PII detection is regex, Luhn and entropy based (deterministic, limited
  recall).
- Data source is an in-memory mock with five records; policies are flat,
  per-field.
- No image screenshots; evidence is captured terminal output.

## Future scope

- Complete the Preview deployment: DUST registration, deploy, and live
  `recordAttestation` / `commit` calls from the batch exporter, with a
  verifier UI.
- Replace the HMAC batch signature with a zero-knowledge proof.
- Optional high-recall PII backend (Presidio / transformer NER).
- Streaming outbound inspection.
- Nested fields, policy inheritance, purpose binding.
