# Fallback demo (no live testnet)

Shows the audit, crypto, and contract layers working without a live chain.
Run from `firee/midnight-side/audit/` with the `cryptography` package
installed (`../.venv/bin/python` if you followed the README).

1. `python fake_audit_generator.py` — creates `audit_log.jsonl`.
2. `python hash_chain.py` — prints the root hash, writes
   `audit_chain.jsonl` and `root_hash.txt`.
3. `python sign.py generate` (once) — creates an Ed25519 keypair
   (`*.pem`, gitignored).
4. `python sign.py sign $(cat root_hash.txt)` — prints a signature.
5. `python verify.py audit_log.jsonl $(cat root_hash.txt) <signature_hex>` — PASS.
6. Copy the log, edit one record in the copy, and run step 5 on the copy —
   FAIL, demonstrating tamper detection.
7. From `firee/midnight-side/`: `npm run compile` and `npm run simulate` —
   compiles `contract/commit.compact` and executes it locally: the root hash
   from step 2 is committed and read back, with no network or transaction.

A captured run of steps 2–6 is in `../../../docs/evidence/07_audit_sign_verify.txt`,
and of step 7 in `06_simulate_contracts.txt` next to it.
