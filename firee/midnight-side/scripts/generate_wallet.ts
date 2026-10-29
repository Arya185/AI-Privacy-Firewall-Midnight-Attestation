import { writeFileSync } from "fs";
import { generateRandomSeed } from "@midnight-ntwrk/wallet-sdk-hd";
import { deriveUnshieldedAddress } from "./providers.js";

const seed = generateRandomSeed();
const seedHex = Buffer.from(seed).toString("hex");

const outFile = process.argv[2] ?? "seed.txt";
try {
  // "wx": never overwrite an existing seed; 0o600: owner-only.
  writeFileSync(outFile, seedHex, { flag: "wx", mode: 0o600 });
} catch (err) {
  if ((err as NodeJS.ErrnoException).code === "EEXIST") {
    console.error(`${outFile} already exists; refusing to overwrite it.`);
    process.exit(1);
  }
  throw err;
}
console.log(`Seed written to ${outFile} (owner-only permissions)`);
console.log("Unshielded Preview address (public, safe to share):");
console.log(deriveUnshieldedAddress(seed));
console.log("Fund this address via the Preview faucet:");
console.log("https://midnight-tmnight-preview.nethermind.dev/");
