"""Verifies an audit log's hash chain integrity and its signature over the root hash."""

import sys
from pathlib import Path
from hash_chain import load_records, build_chain
from sign import verify_signature, PUBLIC_KEY_PATH


def verify_log(log_path: str, expected_root_hash: str, signature_hex: str, verify_key_path: Path = PUBLIC_KEY_PATH) -> bool:
    records = load_records(Path(log_path))
    _, computed_root_hash = build_chain(records)

    chain_ok = computed_root_hash == expected_root_hash
    sig_ok = verify_signature(computed_root_hash, signature_hex, verify_key_path)

    print(f"Computed root hash: {computed_root_hash}")
    print(f"Expected root hash: {expected_root_hash}")
    print(f"Chain integrity:    {'PASS' if chain_ok else 'FAIL'}")
    print(f"Signature check:    {'PASS' if sig_ok else 'FAIL'}")

    return chain_ok and sig_ok


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python verify.py <log_file> <expected_root_hash> <signature_hex>")
        sys.exit(1)

    ok = verify_log(sys.argv[1], sys.argv[2], sys.argv[3])
    print("\nOVERALL: PASS" if ok else "\nOVERALL: FAIL - tamper detected or invalid signature")
    sys.exit(0 if ok else 1)
