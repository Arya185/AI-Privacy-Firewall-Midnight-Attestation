#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "========================================================================"
echo "   AI PRIVACY FIREWALL & MIDNIGHT ATTESTATION: FULL PIPELINE RUNNER     "
echo "========================================================================"
echo "Working directory: $REPO_DIR"

# Stage 1: Pytest
echo -e "\n[1/8] Running Python Privacy Firewall Test Suite (pytest)..."
cd "$REPO_DIR/privacy_firewall"
.venv/bin/python -m pytest -q

# Stage 2: Demo
echo -e "\n[2/8] Running End-to-End Privacy Firewall Demo (5 scenarios)..."
.venv/bin/python demo.py --no-pause --no-color

# Stage 3: Compact compile
echo -e "\n[3/8] Compiling Midnight Compact Smart Contracts (0.31.1)..."
cd "$REPO_DIR/firee/midnight-side"
npm run compile
npm run compile:policy

# Stage 4: Typecheck
echo -e "\n[4/8] Running TypeScript Typecheck..."
npm run typecheck

# Stage 5: Fake audit & hash chain
echo -e "\n[5/8] Generating Audit Log & Building Hash Chain..."
cd "$REPO_DIR/firee/midnight-side/audit"
PYTHONWARNINGS="ignore" ../.venv/bin/python fake_audit_generator.py
PYTHONWARNINGS="ignore" ../.venv/bin/python hash_chain.py

# Stage 6: Batch export
echo -e "\n[6/8] Exporting Attestation Batch from Firewall to Midnight Side..."
cd "$REPO_DIR/privacy_firewall"
PYTHONPATH=. .venv/bin/python export_attestation_batch.py "$REPO_DIR/firee/midnight-side/build/attestation_batch.json"

# Stage 7: Simulate contracts
echo -e "\n[7/8] Simulating Smart Contracts Locally (Compact 0.31.1 runtime)..."
cd "$REPO_DIR/firee/midnight-side"
npm run simulate

# Stage 8: Audit sign and tamper verification
echo -e "\n[8/8] Cryptographic Audit Log Signing, Verification & Tamper Detection..."
cd "$REPO_DIR/firee/midnight-side/audit"
ROOT=$(cat root_hash.txt)
SIG=$(PYTHONWARNINGS="ignore" ../.venv/bin/python sign.py sign "$ROOT")
echo "  Root hash:         $ROOT"
echo "  Ed25519 signature: $SIG"
echo -e "\n  Verifying authentic audit log:"
PYTHONWARNINGS="ignore" ../.venv/bin/python verify.py audit_log.jsonl "$ROOT" "$SIG"

echo -e "\n  Testing tamper detection on modified copy (P-001 -> P-999):"
TAMPERED="/tmp/tampered_audit_$$.jsonl"
sed "0,/P-001/s/P-001/P-999/" audit_log.jsonl > "$TAMPERED"
set +e
PYTHONWARNINGS="ignore" ../.venv/bin/python verify.py "$TAMPERED" "$ROOT" "$SIG"
TAMPER_STATUS=$?
set -e
rm -f "$TAMPERED"

if [ $TAMPER_STATUS -ne 0 ]; then
    echo "  PASS: Tampering correctly detected and rejected (exit code: $TAMPER_STATUS)."
else
    echo "  FAIL: Tampered copy was unexpectedly accepted!"
    exit 1
fi

echo -e "\n========================================================================"
echo "   ALL 8 PIPELINE PHASES COMPLETED AND VERIFIED SUCCESSFULLY!           "
echo "========================================================================"
