# Dashboard (local web UI)

A presentation dashboard for the AI Privacy Firewall. It calls the real project code; it does not
simulate results in the browser.

| Tab | What it runs |
| --- | --- |
| Overview | Live session counts, audit-chain state, contract compile state, recorded and live simulation, activity |
| Firewall | `PrivacyFirewallMiddleware.safe_handle_request` (policy + minimizer) and `OutputFirewall.inspect_response` |
| Audit | `AuditLog.verify_chain()`; sample log via `audit/hash_chain.py`, Ed25519 via `audit/sign.py` and `audit/verify.py`; tamper demo on a copy |
| Attestation | Contract sources and compile info from `build/`; `MidnightBridge` hash export; `npm run simulate` with this session's hashes |

Labels: **LIVE** = this server session, **SAMPLE** = synthetic log or example inputs,
**RECORDED** = `docs/evidence/`, **LOCAL ONLY** = nothing is sent to a blockchain.

## Run

```bash
cd privacy_firewall
source .venv/bin/activate          # the existing venv (PyYAML, pytest); no new packages
python -m web.server               # http://127.0.0.1:8765   (or: --port 9000)
```

Open http://127.0.0.1:8765 in a browser. Stop with Ctrl+C.

Requirements for the optional parts (already present if the project setup was followed):

- Ed25519 signature checks: `firee/midnight-side/.venv` (the `cryptography` package) and the existing
  signing key in `firee/midnight-side/audit/`. Without them the UI shows the signature check as N/A.
- Live contract simulation: Node.js 22 with `npm` on `PATH` (or in `~/.local/opt/node22`),
  `firee/midnight-side/node_modules`, and the compiled contracts (`npm run compile && npm run compile:policy`).
  Without them the button is disabled and the reason is shown.

There is no build step: the frontend is plain HTML, CSS and JavaScript in `static/`, with no CDN, so it
works offline.

## Safety

- Binds to `127.0.0.1` only; requests whose `Host`/`Origin` is not localhost are refused (403).
- Strict Content-Security-Policy; the page loads only its own files and renders server data as text.
- Request bodies are limited to 16 KB and validated (agent ID, operation, field names, query length).
- The live audit chain is in memory and starts empty on every server start; **Reset live session** clears it.
- The sample audit log is read, never rewritten. The tamper demo edits an in-memory copy (live chain)
  or a temporary file (sample log) and reports that the original is unchanged.
- Canary tokens are masked in output-firewall results; request IDs are truncated; exported hashes never
  include the private witness (agent, fields, reason).
- No wallet, DUST registration, deployment or commit actions exist in the UI or API.

## Test

```bash
cd privacy_firewall
python -m pytest web -q            # 27 dashboard tests (real HTTP server on a random port)
python -m pytest -q                # the core suite, unchanged (234 tests)
```

## Presenter walkthrough (about 5 minutes)

1. **Overview**: firewall healthy, contracts compiled, recorded simulation 6/6, deployment "not deployed".
   Counts start at zero because the live session is empty.
2. **Firewall → "Prompt injection: dump everything" → Send**: the query asks for everything; only
   `department` is released, the other six fields are denied, and each decision gets an audit hash.
3. **"Average salary (aggregate)" → Send**: salary leaves only as count, sum and average.
4. **Output inspection → "Model repeats a record note (canary)" → Inspect**: BLOCK; the canary is caught.
   Try "Model leaks personal data" too.
5. **Audit → Verify audit chains**: live chain PASS; sample log chain and Ed25519 signature PASS.
6. **Tamper with a copy** (sample log, index 0): TAMPER DETECTED, original file unchanged.
7. **Attestation → Export decision hashes → Run local contract simulation**: this session's hashes are
   recorded in the compiled contract and checked with `isAttested` (6/6). Point at the banner: local
   simulation, not deployment.
8. Back to **Overview**: the counts and activity now reflect what you just did.
