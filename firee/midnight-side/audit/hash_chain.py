"""Builds a tamper-evident hash chain over an audit log (JSONL) and writes the root hash."""

import hashlib
import json
from pathlib import Path

LOG_FILE = Path(__file__).parent / "audit_log.jsonl"
CHAIN_FILE = Path(__file__).parent / "audit_chain.jsonl"
ROOT_HASH_FILE = Path(__file__).parent / "root_hash.txt"


def load_records(path: Path = LOG_FILE) -> list[dict]:
    records = []
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def hash_record(record: dict, prev_hash: str) -> str:
    payload = json.dumps(record, sort_keys=True) + prev_hash
    return hashlib.sha256(payload.encode()).hexdigest()


def build_chain(records: list[dict]) -> tuple[list[dict], str]:
    chain = []
    prev_hash = "0" * 64
    for record in records:
        current_hash = hash_record(record, prev_hash)
        chain.append({"record": record, "prev_hash": prev_hash, "hash": current_hash})
        prev_hash = current_hash
    return chain, prev_hash


if __name__ == "__main__":
    records = load_records()
    chain, root_hash = build_chain(records)

    with open(CHAIN_FILE, "w") as f:
        for entry in chain:
            f.write(json.dumps(entry) + "\n")

    with open(ROOT_HASH_FILE, "w") as f:
        f.write(root_hash)

    print(f"Chained {len(records)} records")
    print(f"Root hash (this is what gets committed on-chain): {root_hash}")
