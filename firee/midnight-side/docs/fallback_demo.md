# Fallback demo (no live testnet)

If deploy/commit fails at demo time, show the audit + crypto layer works
standalone, without needing a live chain:

1. `python audit/fake_audit_generator.py` — creates `audit_log.jsonl`.
2. `python audit/hash_chain.py` — prints the root hash, writes
   `audit_chain.jsonl` and `root_hash.txt`.
3. `python audit/sign.py generate` (once) — creates a signing keypair.
4. `python audit/sign.py sign <root_hash>` — produces a signature.
5. Show `contract/commit.compact` + the compiled `build/commit/` output as
   evidence the on-chain side is real code, without needing a live tx.
6. `python audit/verify.py audit_log.jsonl <root_hash> <signature_hex>` — PASS.
7. Edit one record in `audit_log.jsonl`, rerun step 6 — FAIL, demonstrating
   tamper detection.
