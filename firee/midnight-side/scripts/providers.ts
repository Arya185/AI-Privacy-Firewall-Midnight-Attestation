import {
  chmodSync,
  copyFileSync,
  existsSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from "fs";
import path from "node:path";
import { setNetworkId } from "@midnight-ntwrk/midnight-js-network-id";
import { indexerPublicDataProvider } from "@midnight-ntwrk/midnight-js-indexer-public-data-provider";
import { httpClientProofProvider } from "@midnight-ntwrk/midnight-js-http-client-proof-provider";
import { levelPrivateStateProvider } from "@midnight-ntwrk/midnight-js-level-private-state-provider";
import { NodeZkConfigProvider } from "@midnight-ntwrk/midnight-js-node-zk-config-provider";
import type {
  MidnightProviders,
  WalletProvider,
  MidnightProvider,
} from "@midnight-ntwrk/midnight-js-types";
import { HDWallet, Roles } from "@midnight-ntwrk/wallet-sdk-hd";
import {
  WalletFacade,
  type BalancingRecipe,
  type FacadeState,
} from "@midnight-ntwrk/wallet-sdk-facade";
import { ShieldedWallet } from "@midnight-ntwrk/wallet-sdk-shielded";
import {
  UnshieldedWallet,
  createKeystore,
  PublicKey,
} from "@midnight-ntwrk/wallet-sdk-unshielded-wallet";
import { DustWallet } from "@midnight-ntwrk/wallet-sdk-dust-wallet";
import type { TotalCostParameters } from "@midnight-ntwrk/wallet-sdk-dust-wallet/v1";
import { NetworkId } from "@midnight-ntwrk/wallet-sdk-abstractions";
import {
  ZswapSecretKeys,
  DustSecretKey,
  LedgerParameters,
  signingKeyFromBip340,
  signData,
} from "@midnight-ntwrk/ledger-v8";

const INDEXER_HTTP_URL =
  process.env.MIDNIGHT_INDEXER_URL ??
  "https://indexer.preview.midnight.network/api/v4/graphql";

const INDEXER_WS_URL =
  process.env.MIDNIGHT_INDEXER_WS_URL ??
  "wss://indexer.preview.midnight.network/api/v4/graphql/ws";

const PROOF_SERVER_URL =
  process.env.MIDNIGHT_PROOF_SERVER_URL ?? "http://127.0.0.1:6300";

const ZK_CONFIG_DIR = path.resolve("build/commit");

// Serialized wallet snapshots hold private coin data: owner-only, gitignored,
// never logged. Lets later runs resume syncing instead of starting at block 0.
const WALLET_STATE_FILE = path.resolve(
  process.env.MIDNIGHT_WALLET_STATE_FILE ?? "wallet-state.json",
);
const WALLET_STATE_BACKUP = `${WALLET_STATE_FILE}.bak`;
const WALLET_STATE_LOCK = `${WALLET_STATE_FILE}.lock`;
const WALLET_STATE_VERSION = 1;

const SYNC_TIMEOUT_MS = Number(
  process.env.MIDNIGHT_SYNC_TIMEOUT_MS ?? 4 * 60 * 60 * 1000,
);
const PROGRESS_INTERVAL_MS = 30_000;
const STATE_SAVE_INTERVAL_MS = 60_000;

function loadSeed(): Uint8Array {
  const seedHex = process.env.MIDNIGHT_WALLET_SEED;

  if (seedHex) {
    return new Uint8Array(Buffer.from(seedHex, "hex"));
  }

  const seedFile =
    process.env.MIDNIGHT_WALLET_SEED_FILE ?? "seed.txt";

  return new Uint8Array(
    Buffer.from(readFileSync(seedFile, "utf-8").trim(), "hex"),
  );
}

function deriveKeys(seed: Uint8Array) {
  const seedResult = HDWallet.fromSeed(seed);

  if (seedResult.type === "seedError") {
    throw new Error(`Failed to derive HD wallet: ${seedResult.error}`);
  }

  const account = seedResult.hdWallet.selectAccount(0);
  const night = account.selectRole(Roles.NightExternal).deriveKeyAt(0);
  const zswap = account.selectRole(Roles.Zswap).deriveKeyAt(0);
  const dust = account.selectRole(Roles.Dust).deriveKeyAt(0);

  seedResult.hdWallet.clear();

  if (
    night.type !== "keyDerived" ||
    zswap.type !== "keyDerived" ||
    dust.type !== "keyDerived"
  ) {
    throw new Error("HD key derivation out of bounds");
  }

  return {
    zswapSecretKeys: ZswapSecretKeys.fromSeed(zswap.key),
    dustSecretKey: DustSecretKey.fromSeed(dust.key),
    nightSigningKey: signingKeyFromBip340(night.key),
    nightSecretKey: night.key,
  };
}

function unshieldedPublicKey(nightSecretKey: Uint8Array) {
  return PublicKey.fromKeyStore(
    createKeystore(nightSecretKey, NetworkId.NetworkId.Preview),
  );
}

// Public Bech32m address only (the one to fund via the faucet); derived
// exactly as the wallet below derives it.
export function deriveUnshieldedAddress(seed: Uint8Array): string {
  return unshieldedPublicKey(deriveKeys(seed).nightSecretKey).address;
}

type SavedWalletState = {
  version: number;
  networkId: string;
  unshieldedAddress: string;
  shielded: string;
  unshielded: string;
  dust: string;
};

// Returns the snapshot only if it is well-formed and belongs to this wallet
// on Preview; otherwise the reason it was rejected.
function readSavedState(
  file: string,
  expectedAddress: string,
): SavedWalletState | string {
  if (!existsSync(file)) return "not found";
  let s: SavedWalletState;
  try {
    s = JSON.parse(readFileSync(file, "utf-8"));
  } catch {
    return "unreadable";
  }
  if (s?.version !== WALLET_STATE_VERSION) return "unsupported format version";
  if (s.networkId !== NetworkId.NetworkId.Preview) return "different network";
  if (s.unshieldedAddress !== expectedAddress) return "belongs to a different wallet";
  if (![s.shielded, s.unshielded, s.dust].every((x) => typeof x === "string")) {
    return "incomplete";
  }
  return s;
}

function loadSavedState(expectedAddress: string): SavedWalletState | undefined {
  for (const file of [WALLET_STATE_FILE, WALLET_STATE_BACKUP]) {
    const s = readSavedState(file, expectedAddress);
    if (typeof s !== "string") {
      console.log(`Restoring wallet state from ${path.basename(file)}`);
      return s;
    }
    if (s !== "not found") {
      console.warn(`Ignoring ${path.basename(file)}: ${s}`);
    }
  }
  console.log("No usable saved wallet state; syncing from block 0.");
  return undefined;
}

let saveQueue: Promise<void> = Promise.resolve();

// Atomic write (temp file + rename). The previous snapshot is kept as .bak,
// but only if it is itself valid, so a good backup is never clobbered.
function saveWalletState(facade: WalletFacade, address: string): Promise<void> {
  saveQueue = saveQueue.then(async () => {
    const state: SavedWalletState = {
      version: WALLET_STATE_VERSION,
      networkId: NetworkId.NetworkId.Preview,
      unshieldedAddress: address,
      shielded: await facade.shielded.serializeState(),
      unshielded: await facade.unshielded.serializeState(),
      dust: await facade.dust.serializeState(),
    };
    const tmp = `${WALLET_STATE_FILE}.tmp`;
    writeFileSync(tmp, JSON.stringify(state), { mode: 0o600 });
    chmodSync(tmp, 0o600);
    if (typeof readSavedState(WALLET_STATE_FILE, address) !== "string") {
      copyFileSync(WALLET_STATE_FILE, WALLET_STATE_BACKUP);
      chmodSync(WALLET_STATE_BACKUP, 0o600);
    }
    renameSync(tmp, WALLET_STATE_FILE);
  });
  return saveQueue;
}

function isProcessAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === "EPERM";
  }
}

// One process per wallet state: concurrent syncs would race on the file.
function acquireWalletLock() {
  const pid = String(process.pid);
  try {
    writeFileSync(WALLET_STATE_LOCK, pid, { flag: "wx", mode: 0o600 });
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
    const owner = Number(readFileSync(WALLET_STATE_LOCK, "utf-8"));
    if (owner && isProcessAlive(owner)) {
      throw new Error(
        `Another process (pid ${owner}) is using this wallet state; not starting a second sync.`,
      );
    }
    writeFileSync(WALLET_STATE_LOCK, pid, { mode: 0o600 }); // stale lock
  }
  process.on("exit", () => {
    try {
      if (readFileSync(WALLET_STATE_LOCK, "utf-8") === pid) {
        unlinkSync(WALLET_STATE_LOCK);
      }
    } catch {
      // already gone
    }
  });
}

function currentState(facade: WalletFacade): Promise<FacadeState> {
  return new Promise((resolve, reject) => {
    const sub = facade.state().subscribe({
      next: (s) => {
        resolve(s);
        queueMicrotask(() => sub.unsubscribe());
      },
      error: reject,
    });
  });
}

// Allowlisted public fields only. Never serialize the state object itself:
// the per-wallet states carry internal core state.
export function walletSummary(s: FacadeState): string {
  const fmt = (balances: Record<string, bigint>) =>
    Object.entries(balances)
      .map(([token, amount]) => `${token}=${amount.toString()}`)
      .join(", ") || "none";
  const prog = (p: { appliedIndex?: bigint; highestRelevantWalletIndex?: bigint; isStrictlyComplete(): boolean }) =>
    p.isStrictlyComplete()
      ? "done"
      : `${p.appliedIndex ?? "?"}/${p.highestRelevantWalletIndex ?? "?"}`;
  return (
    `synced=${s.isSynced}` +
    ` progress[shielded=${prog(s.shielded.progress)} unshielded=${prog(s.unshielded.progress)} dust=${prog(s.dust.progress)}]` +
    ` unshielded=[${fmt(s.unshielded.balances)}]` +
    ` shielded=[${fmt(s.shielded.balances)}]` +
    ` dust=${s.dust.balance(new Date()).toString()}`
  );
}

// Resolves only once the SDK reports every sub-wallet strictly synced;
// rejects on timeout or a wallet stream error. Progress is saved either way.
async function waitForSync(
  facade: WalletFacade,
  address: string,
): Promise<FacadeState> {
  let latest: FacadeState | undefined;
  let streamFailed: (err: unknown) => void = () => {};
  const streamError = new Promise<never>((_, reject) => {
    streamFailed = reject;
  });
  const sub = facade.state().subscribe({
    next: (s) => {
      latest = s;
    },
    error: (err) => streamFailed(err),
  });
  const progress = setInterval(() => {
    if (latest) console.log(`SYNC: ${walletSummary(latest)}`);
  }, PROGRESS_INTERVAL_MS);
  const saveProgress = () =>
    saveWalletState(facade, address).catch((err) =>
      console.warn("Could not save wallet state:", (err as Error).message),
    );
  const saver = setInterval(saveProgress, STATE_SAVE_INTERVAL_MS);
  const onSignal = () => {
    console.log("Interrupted; saving sync progress before exit...");
    void saveProgress().finally(() => process.exit(130));
  };
  process.once("SIGINT", onSignal);
  process.once("SIGTERM", onSignal);
  let timer: NodeJS.Timeout | undefined;

  try {
    const synced = await Promise.race([
      facade.waitForSyncedState(),
      streamError,
      new Promise<never>((_, reject) => {
        timer = setTimeout(
          () =>
            reject(
              new Error(
                `Wallet not synced after ${Math.round(SYNC_TIMEOUT_MS / 60000)} min; progress saved, rerun to resume.`,
              ),
            ),
          SYNC_TIMEOUT_MS,
        );
      }),
    ]);
    if (!synced.isSynced) {
      throw new Error("Wallet reported synced state but isSynced is false.");
    }
    return synced;
  } finally {
    clearTimeout(timer);
    clearInterval(progress);
    clearInterval(saver);
    sub.unsubscribe();
    process.off("SIGINT", onSignal);
    process.off("SIGTERM", onSignal);
    await saveProgress();
  }
}

async function buildWalletFacade(seed: Uint8Array) {
  const { zswapSecretKeys, dustSecretKey, nightSigningKey, nightSecretKey } =
    deriveKeys(seed);
  const nightPublicKey = unshieldedPublicKey(nightSecretKey);

  const costParameters: TotalCostParameters = {
    feeBlocksMargin: 10,
  };

  console.log("INDEXER HTTP:", INDEXER_HTTP_URL);
  console.log("INDEXER WS:", INDEXER_WS_URL);
  console.log("NETWORK:", NetworkId.NetworkId.Preview);

  const sharedConfig = {
    networkId: NetworkId.NetworkId.Preview,
    indexerClientConnection: {
      indexerHttpUrl: INDEXER_HTTP_URL,
      indexerWsUrl: INDEXER_WS_URL,
    },
    costParameters,
    provingServerUrl: PROOF_SERVER_URL,
  };

  const dustParameters =
    LedgerParameters.initialParameters().dust;

  // Use the HD-derived keys for every sub-wallet: startWithSeed() would treat
  // the raw seed as the key seed, diverging from the keys passed to start().
  const initFacade = (saved?: SavedWalletState) =>
    WalletFacade.init({
      configuration: sharedConfig as any,
      shielded: (config) =>
        saved
          ? ShieldedWallet(config).restore(saved.shielded)
          : ShieldedWallet(config).startWithSecretKeys(zswapSecretKeys),
      unshielded: (config) =>
        saved
          ? UnshieldedWallet(config).restore(saved.unshielded)
          : UnshieldedWallet(config).startWithPublicKey(nightPublicKey),
      dust: (config) =>
        saved
          ? DustWallet(config).restore(saved.dust)
          : DustWallet(config).startWithSecretKey(dustSecretKey, dustParameters),
    });

  acquireWalletLock();

  let facade: WalletFacade | undefined;
  const saved = loadSavedState(nightPublicKey.address);
  if (saved) {
    try {
      facade = await initFacade(saved);
      await facade.start(zswapSecretKeys, dustSecretKey);
      const s = await currentState(facade);
      if (
        !s.shielded.coinPublicKey.equals(zswapSecretKeys.coinPublicKey) ||
        s.dust.publicKey !== dustSecretKey.publicKey
      ) {
        throw new Error("restored keys do not match this seed");
      }
    } catch (err) {
      console.warn(
        `Saved wallet state unusable (${(err as Error).message}); syncing from block 0.`,
      );
      await facade?.stop().catch(() => {});
      facade = undefined;
    }
  }
  if (!facade) {
    facade = await initFacade();
    await facade.start(zswapSecretKeys, dustSecretKey);
  }

  console.log("FACADE STARTED");
  console.log("UNSHIELDED ADDRESS:", nightPublicKey.address);

  let state: FacadeState;
  try {
    state = await waitForSync(facade, nightPublicKey.address);
  } catch (err) {
    await facade.stop().catch(() => {});
    throw err;
  }
  console.log(`WALLET SYNCED: ${walletSummary(state)}`);

  return {
    facade,
    state,
    zswapSecretKeys,
    dustSecretKey,
    nightSigningKey,
  };
}

// Read-only: starts the wallet, syncs (resuming from saved state), returns it.
export async function syncWallet() {
  return buildWalletFacade(loadSeed());
}

function makeWalletProvider(
  facade: WalletFacade,
  zswapSecretKeys: ZswapSecretKeys,
  dustSecretKey: DustSecretKey,
  nightSigningKey: string,
): WalletProvider {
  let latest = {
    coinPublicKey: "",
    encryptionPublicKey: "",
  };

  facade.state().subscribe((s) => {
    latest = {
      coinPublicKey: s.shielded.coinPublicKey.toHexString(),
      encryptionPublicKey:
        s.shielded.encryptionPublicKey.toHexString(),
    };
  });

  return {
    async balanceTx(tx, ttl) {
      const recipe: BalancingRecipe =
        await facade.balanceUnboundTransaction(
          tx as any,
          {
            shieldedSecretKeys: zswapSecretKeys,
            dustSecretKey,
          },
          {
            ttl:
              ttl ??
              new Date(Date.now() + 10 * 60 * 1000),
          },
        );

      const signed = await facade.signRecipe(
        recipe,
        (data) => signData(nightSigningKey, data),
      );

      return facade.finalizeRecipe(signed);
    },

    getCoinPublicKey() {
      return latest.coinPublicKey;
    },

    getEncryptionPublicKey() {
      return latest.encryptionPublicKey;
    },
  };
}

function makeMidnightProvider(
  facade: WalletFacade,
): MidnightProvider {
  return {
    async submitTx(tx) {
      return facade.submitTransaction(tx);
    },
  };
}

export async function createProviders(): Promise<
  MidnightProviders<"commit" | "get_latest">
> {
  setNetworkId("preview");

  const zkConfigProvider =
    new NodeZkConfigProvider<"commit" | "get_latest">(
      ZK_CONFIG_DIR,
    );

  const privateStateProvider =
    levelPrivateStateProvider<string>({
      privateStoragePasswordProvider: () =>
        process.env.MIDNIGHT_WALLET_PASSWORD ??
        "a-strong-local-dev-password-1",
      accountId:
        process.env.MIDNIGHT_WALLET_LABEL ??
        "firewall-audit-committer",
    });

  const publicDataProvider = indexerPublicDataProvider(
    INDEXER_HTTP_URL,
    INDEXER_WS_URL,
  );

  const proofProvider = httpClientProofProvider(
    PROOF_SERVER_URL,
    zkConfigProvider,
  );

  const seed = loadSeed();

  const {
    facade,
    state,
    zswapSecretKeys,
    dustSecretKey,
    nightSigningKey,
  } = await buildWalletFacade(seed);

  // Every transaction pays its fee in tDUST; fail before building one.
  if (state.dust.balance(new Date()) <= 0n) {
    await facade.stop().catch(() => {});
    throw new Error(
      "Wallet is synced but holds no tDUST. Register its tNIGHT for DUST generation and wait for DUST to accrue.",
    );
  }

  const walletProvider = makeWalletProvider(
    facade,
    zswapSecretKeys,
    dustSecretKey,
    nightSigningKey,
  );

  const midnightProvider = makeMidnightProvider(facade);

  return {
    privateStateProvider,
    publicDataProvider,
    zkConfigProvider,
    proofProvider,
    walletProvider,
    midnightProvider,
  };
}
