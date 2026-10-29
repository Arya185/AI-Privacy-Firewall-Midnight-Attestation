/**
 * sync_wallet.ts
 *
 * Read-only: syncs the wallet (resuming from wallet-state.json when present),
 * prints public balances and DUST registration status, and estimates the fee
 * of registering the tNIGHT UTXOs for DUST generation. Never signs or submits
 * a transaction.
 */

import { syncWallet, walletSummary } from "./providers.js";

async function main() {
  const { facade, state } = await syncWallet();
  try {
    console.log(`Summary: ${walletSummary(state)}`);

    const coins = state.unshielded.availableCoins;
    console.log(`Unshielded UTXOs: ${coins.length}`);
    coins.forEach((c, i) =>
      console.log(
        `  #${i} value=${c.utxo.value} registeredForDustGeneration=${c.meta.registeredForDustGeneration}`,
      ),
    );

    const unregistered = coins.filter((c) => !c.meta.registeredForDustGeneration);
    if (unregistered.length > 0) {
      const est = await facade.estimateRegistration(unregistered);
      console.log(`DUST registration fee estimate (read-only): ${est.fee} Specks`);
      est.dustGenerationEstimations.forEach((e, i) =>
        console.log(
          `  estimate #${i}: nightValue=${e.utxo.value} generatedNow=${e.dust.generatedNow} Specks` +
            ` maxCap=${e.dust.maxCap} Specks maxCapReachedAt=${e.dust.maxCapReachedAt.toISOString()}` +
            ` rate=${e.dust.rate}`,
        ),
      );
    }
  } finally {
    await facade.stop();
  }
}

main()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error("Sync failed:", (err as Error).message);
    process.exit(1);
  });
