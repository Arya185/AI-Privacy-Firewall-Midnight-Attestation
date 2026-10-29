/**
 * register_dust.ts
 *
 * Registers this wallet's unregistered tNIGHT UTXOs for DUST generation, with
 * this wallet's own DUST address as the receiver. The registration fee is paid
 * from the DUST the registered UTXO itself generates (SDK fee allowance).
 *
 * Default is a DRY RUN: syncs, estimates the fee, builds and signs the
 * transaction locally to report its exact fee, then releases the booked UTXOs.
 * Nothing is proved or submitted. Pass --submit to prove and submit.
 */

import { signatureVerifyingKey, signData } from "@midnight-ntwrk/ledger-v8";
import { MidnightBech32m } from "@midnight-ntwrk/wallet-sdk";
import { NetworkId } from "@midnight-ntwrk/wallet-sdk-abstractions";
import type { WalletFacade } from "@midnight-ntwrk/wallet-sdk-facade";
import { syncWallet, walletSummary } from "./providers.js";

const SUBMIT = process.argv.includes("--submit");
const CONFIRM_TIMEOUT_MS = 10 * 60 * 1000;

// Resolves once a registered tNIGHT UTXO is visible and no tx is pending.
function waitForRegistration(facade: WalletFacade): Promise<void> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      sub.unsubscribe();
      reject(new Error("Registration not confirmed within 10 min; check the wallet before retrying."));
    }, CONFIRM_TIMEOUT_MS);
    const sub = facade.state().subscribe({
      next: (s) => {
        const registered = s.unshielded.availableCoins.some((c) => c.meta.registeredForDustGeneration);
        if (registered && s.unshielded.pendingCoins.length === 0) {
          clearTimeout(timer);
          queueMicrotask(() => sub.unsubscribe());
          resolve();
        }
      },
      error: (err) => {
        clearTimeout(timer);
        reject(err);
      },
    });
  });
}

async function main() {
  const { facade, state, nightSigningKey } = await syncWallet();
  try {
    console.log(`Wallet: ${walletSummary(state)}`);

    const utxos = state.unshielded.availableCoins.filter((c) => !c.meta.registeredForDustGeneration);
    if (utxos.length === 0) {
      console.log("No unregistered tNIGHT UTXOs; nothing to register.");
      return;
    }
    const nightValue = utxos.reduce((sum, c) => sum + c.utxo.value, 0n);
    const dustAddress = MidnightBech32m.encode(NetworkId.NetworkId.Preview, state.dust.address).asString();
    console.log(`UTXOs to register: ${utxos.length} (total ${nightValue} STAR)`);
    console.log(`DUST receiver (this wallet): ${dustAddress}`);

    const estimate = await facade.estimateRegistration(utxos);
    console.log(`Estimated registration fee: ${estimate.fee} Specks`);
    estimate.dustGenerationEstimations.forEach((e, i) =>
      console.log(
        `  fee-paying UTXO #${i}: value=${e.utxo.value} generatedNow=${e.dust.generatedNow} Specks` +
          ` maxCap=${e.dust.maxCap} Specks rate=${e.dust.rate}`,
      ),
    );

    const recipe = await facade.registerNightUtxosForDustGeneration(
      utxos,
      signatureVerifyingKey(nightSigningKey),
      (payload) => signData(nightSigningKey, payload),
    );
    try {
      const fee = await facade.calculateTransactionFee(recipe.transaction);
      console.log(`Built and signed registration tx locally; its fee: ${fee} Specks`);

      if (!SUBMIT) {
        console.log("DRY RUN: not proved or submitted. Rerun with --submit to send it.");
        await facade.revert(recipe);
        return;
      }

      console.log("Proving via the proof server...");
      const finalized = await facade.finalizeRecipe(recipe);
      const txId = await facade.submitTransaction(finalized);
      console.log(`Submitted. Transaction identifier: ${txId}`);
      console.log("Waiting for on-chain confirmation...");
      await waitForRegistration(facade);
      console.log("Registration confirmed: tNIGHT UTXO is registered for DUST generation.");
    } catch (err) {
      await facade.revert(recipe).catch(() => {});
      throw err;
    }
  } finally {
    await facade.stop();
  }
}

main()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error("DUST registration failed:", (err as Error).message);
    process.exit(1);
  });
