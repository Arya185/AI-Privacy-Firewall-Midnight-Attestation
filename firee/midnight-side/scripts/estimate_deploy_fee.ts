/**
 * estimate_deploy_fee.ts
 *
 * Read-only: builds the commit.compact deployment transaction locally (no
 * proving, no submission) and reports its fee next to the wallet's tDUST
 * balance. Prints only numbers: the unsubmitted tx data is privacy-sensitive.
 */

import path from "node:path";
import { setNetworkId } from "@midnight-ntwrk/midnight-js-network-id";
import { CompiledContract } from "@midnight-ntwrk/compact-js";
import { sampleSigningKey } from "@midnight-ntwrk/ledger-v8";
import { createUnprovenDeployTx } from "@midnight-ntwrk/midnight-js-contracts";
import { NodeZkConfigProvider } from "@midnight-ntwrk/midnight-js-node-zk-config-provider";
import type { WalletProvider } from "@midnight-ntwrk/midnight-js-types";
import { Contract } from "../build/commit/contract/index.js";
import { syncWallet, walletSummary } from "./providers.js";

setNetworkId("preview");

async function main() {
  const { facade, state, dustSecretKey } = await syncWallet();
  try {
    console.log(`Wallet: ${walletSummary(state)}`);

    // Only the public keys are used to build the tx; balancing never happens here.
    const walletProvider: WalletProvider = {
      getCoinPublicKey: () => state.shielded.coinPublicKey.toHexString(),
      getEncryptionPublicKey: () => state.shielded.encryptionPublicKey.toHexString(),
      balanceTx: () => Promise.reject(new Error("balanceTx is not used for fee estimation")),
    };
    const compiledContract = CompiledContract.make("CommitContract", Contract).pipe(
      CompiledContract.withVacantWitnesses,
      CompiledContract.withCompiledFileAssets("../build/commit"),
    );
    const deployTx = await createUnprovenDeployTx(
      {
        zkConfigProvider: new NodeZkConfigProvider<"commit" | "get_latest">(path.resolve("build/commit")),
        walletProvider,
      },
      // Throwaway authority key: this tx is never submitted, and the key does not affect the fee.
      { compiledContract, signingKey: sampleSigningKey() },
    );
    const unprovenTx = deployTx.private.unprovenTx;

    const txOnly = await facade.calculateTransactionFee(unprovenTx);
    console.log(`Deploy tx fee (tx only): ${txOnly} Specks`);
    try {
      const total = await facade.estimateTransactionFee(unprovenTx, dustSecretKey);
      console.log(`Deploy fee incl. balancing: ${total} Specks`);
    } catch (err) {
      console.log(`Total fee incl. balancing unavailable: ${(err as Error).message}`);
    }
    console.log(`tDUST available now: ${state.dust.balance(new Date())} Specks`);
  } finally {
    await facade.stop();
  }
}

main()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error("Deploy fee estimate failed:", (err as Error).message);
    process.exit(1);
  });
