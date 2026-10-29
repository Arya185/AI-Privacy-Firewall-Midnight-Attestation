/**
 * simulate_contract.ts
 *
 * Offline execution of the compiled Compact contracts with the Compact
 * runtime: no network, wallet, proofs, or transactions.
 *
 *  1. commit.compact: commit(audit/root_hash.txt), then get_latest() must
 *     return the same hash and commitCount must be 1.
 *  2. policy_attestation.compact (if compiled to build/policy_attestation):
 *     recordAttestation() for every decision hash in the attestation batch
 *     exported by privacy_firewall/export_attestation_batch.py, then
 *     isAttested() must be true for each and false for an unrecorded hash.
 *
 *     npm run simulate -- [path/to/attestation_batch.json]
 */

import { existsSync, readFileSync } from "fs";
import { fileURLToPath } from "url";
import * as rt from "@midnight-ntwrk/compact-runtime";
import { Contract, ledger } from "../build/commit/contract/index.js";

const COIN_PUBLIC_KEY = "00".repeat(32); // dummy key: local simulation only
const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
let failures = 0;
const check = (ok: boolean, label: string) => {
  console.log(`  ${ok ? "PASS" : "FAIL"}  ${label}`);
  if (!ok) failures++;
};

function deployLocally(contract: any) {
  const init = contract.initialState(rt.createConstructorContext(undefined, COIN_PUBLIC_KEY));
  return rt.createCircuitContext(rt.dummyContractAddress(), COIN_PUBLIC_KEY, init.currentContractState, undefined);
}

function simulateCommit() {
  console.log("commit.compact");
  const rootHashFile = new URL("../audit/root_hash.txt", import.meta.url);
  if (!existsSync(fileURLToPath(rootHashFile))) {
    check(false, "audit/root_hash.txt missing; run audit/fake_audit_generator.py and audit/hash_chain.py first");
    return;
  }
  const rootHash = readFileSync(rootHashFile, "utf-8").trim();
  const contract = new Contract({});
  let ctx = deployLocally(contract);
  check(ledger(ctx.currentQueryContext.state).commitCount === 0n, "fresh contract: commitCount = 0");

  ctx = contract.impureCircuits.commit(ctx, Buffer.from(rootHash, "hex")).context;
  const latest = hex(contract.impureCircuits.get_latest(ctx).result);
  check(latest === rootHash, `get_latest() == audit/root_hash.txt (${rootHash.slice(0, 16)}...)`);
  check(ledger(ctx.currentQueryContext.state).commitCount === 1n, "commitCount = 1 after commit");
}

async function simulatePolicyAttestation(batchPath: string) {
  console.log("policy_attestation.compact");
  const built = new URL("../build/policy_attestation/contract/index.js", import.meta.url);
  if (!existsSync(fileURLToPath(built))) {
    console.log("  SKIP  not compiled; run `npm run compile:policy` first");
    return;
  }
  if (!existsSync(batchPath)) {
    console.log(`  SKIP  no attestation batch at ${batchPath}; run privacy_firewall/export_attestation_batch.py`);
    return;
  }
  const policy: any = await import(built.href);
  const batch = JSON.parse(readFileSync(batchPath, "utf-8"));
  // Only the public decision hashes are read; the batch's private witness data is ignored.
  const hashes: string[] = batch.decisions.map((d: { decision_hash: string }) => d.decision_hash.replace(/^0x/, ""));

  const contract = new policy.Contract({});
  let ctx = deployLocally(contract);
  for (const h of hashes) {
    ctx = contract.impureCircuits.recordAttestation(ctx, Buffer.from(h, "hex")).context;
  }
  const attested = hashes.filter((h) => contract.impureCircuits.isAttested(ctx, Buffer.from(h, "hex")).result);
  check(attested.length === hashes.length, `isAttested() true for all ${hashes.length} firewall decision hashes`);
  check(policy.ledger(ctx.currentQueryContext.state).attested.size() === BigInt(hashes.length), "ledger holds exactly those hashes");
  const unrecorded = "ff".repeat(32);
  check(!contract.impureCircuits.isAttested(ctx, Buffer.from(unrecorded, "hex")).result, "isAttested() false for an unrecorded hash");
}

const batchPath = process.argv[2] ?? fileURLToPath(new URL("../build/attestation_batch.json", import.meta.url));
simulateCommit();
await simulatePolicyAttestation(batchPath);
console.log(failures === 0 ? "\nSimulation: all checks passed" : `\nSimulation: ${failures} check(s) FAILED`);
process.exit(failures === 0 ? 0 : 1);
