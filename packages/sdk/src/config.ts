/**
 * UTXOPIA SDK Configuration
 *
 * Centralized configuration for all network-specific addresses, endpoints, and settings.
 * This is the SINGLE SOURCE OF TRUTH for all on-chain addresses and configuration.
 *
 * When deploying to a new network or updating addresses:
 * 1. Update the relevant network config below
 * 2. Bump SDK version
 * 3. Publish to npm
 *
 * @module config
 */

import { address as _address, getAddressEncoder, getAddressDecoder, getProgramDerivedAddress, type Address } from "@solana/kit";

/**
 * Safe address wrapper — catches codec validation errors that occur during
 * Vercel's build phase when @solana/kit validates byte lengths at module load.
 * Returns the input string cast as Address on failure (safe for config objects
 * that are only used at runtime, not build time).
 */
export function address(input: string): Address {
  try {
    return _address(input);
  } catch {
    console.warn(`[utxopia-sdk] address() failed for "${input.slice(0, 12)}..." — returning raw string (build-time fallback)`);
    return input as Address;
  }
}

// =============================================================================
// Network Types
// =============================================================================

export type NetworkType = "devnet" | "mainnet" | "localnet";
export type AppNetworkId =
  | NetworkType
  | "devnet-regtest"
  | "devnet-testnet4";

export interface NetworkConfig {
  /** Network identifier */
  network: NetworkType;

  // -------------------------------------------------------------------------
  // Program IDs
  // -------------------------------------------------------------------------

  /** UTXOpia main program ID */
  utxopiaProgramId: Address;

  /** Minimal PER PolicyApproval coprocessor. Falls back to the asset program on older networks. */
  policyProgramId?: Address;

  /** BTC Light Client program ID (manages light client + block headers for SPV) */
  btcLightClientProgramId: Address;

  /** ChadBuffer program ID (for SPV verification) */
  chadbufferProgramId: Address;

  /** Token-2022 program ID */
  token2022ProgramId: Address;

  /** Associated Token Account program ID */
  ataProgramId: Address;

  // -------------------------------------------------------------------------
  // Deployed Accounts (PDAs and Mints)
  // -------------------------------------------------------------------------

  /** Pool State PDA address */
  poolStatePda: Address;

  /** Commitment Tree PDA address */
  commitmentTreePda: Address;

  /** zkBTC Mint address (Token-2022) */
  zkbtcMint: Address;

  /** Pool Vault (ATA for pool holding zkBTC) */
  poolVault: Address;

  // -------------------------------------------------------------------------
  // RPC Endpoints
  // -------------------------------------------------------------------------

  /** Solana RPC endpoint */
  solanaRpcUrl: string;

  /** Solana WebSocket endpoint */
  solanaWsUrl: string;

  // -------------------------------------------------------------------------
  // Bitcoin Network
  // -------------------------------------------------------------------------

  /** Bitcoin network */
  bitcoinNetwork: "mainnet" | "testnet" | "testnet4" | "signet" | "regtest";

  /** Esplora API endpoint */
  esploraUrl: string;

  // -------------------------------------------------------------------------
  // Circuit CDN
  // -------------------------------------------------------------------------

  /** Base URL for circuit artifacts */
  circuitCdnUrl: string;

  // -------------------------------------------------------------------------
  // Groth16 Verifier (Client-side ZK)
  // -------------------------------------------------------------------------

  /** Groth16 verifier program ID (browser proof generation via snarkjs) */
  groth16VerifierProgramId: Address;

  // -------------------------------------------------------------------------
  // VK Hashes (for CPI verification)
  // -------------------------------------------------------------------------

  /** VK hashes for each circuit type (32 bytes each, hex-encoded) */
  vkHashes: {
    claim: string;
    split: string;
    spendPartialPublic: string;
  };

  /** VK hashes for JoinSplit variants, keyed by "NxM" (e.g., "1x2" -> "abc...") */
  joinSplitVkHashes: Record<string, string>;

  // -------------------------------------------------------------------------
  // Pool Keys
  // -------------------------------------------------------------------------

  /** Ika dWallet x-only secp256k1 pubkey (hex, 64 chars = 32 bytes).
   *  The sole Taproot internal key for deposit-address derivation. Read from
   *  `pool_config.ika_dwallet_xonly_pubkey` (offset 68..100) on chain. All-zero
   *  indicates the pool's PoolConfig has not been initialized yet. */
  ikaDwalletXOnlyPubkey: string;

  /** BTC deposit custody mode.
   *  "sweep" keeps legacy per-deposit tweaked Taproot addresses.
   *  "direct" sends deposits directly to the Ika raw x-only vault address. */
  depositMode?: "sweep" | "direct" | "direct_vault" | "ika_direct";

  // -------------------------------------------------------------------------
  // SNS Subdomain Resolution (stealth address via .sol names)
  // -------------------------------------------------------------------------

  /** SPL Name Service program ID (stores name records / PDAs) */
  snsNameServiceProgramId: string;

  /** SNS Registrar program ID (for domain registration) */
  snsRegistrarProgramId: string;

  /** SNS Sub-Registrar program ID (for subdomain registration) */
  snsSubRegistrarProgramId: string;

  /** SNS root domain account (.sol TLD — differs per network) */
  snsRootDomain: string;

  /** Parent domain for stealth address subdomains (e.g., "utxopia" for *.utxopia.sol) */
  snsParentDomain: string;

  /** SNS reverse lookup class key (used for reverse name resolution) */
  snsReverseLookupClass: string;

  /** Stealth data version expected in SNS records */
  snsStealthDataVersion: number;
}

// =============================================================================
// Program IDs (Constants)
// =============================================================================

/** Legacy Token Program ID */
export const TOKEN_PROGRAM_ID: Address = address(
  "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
);

/** Token-2022 Program ID */
export const TOKEN_2022_PROGRAM_ID: Address = address(
  "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
);

/** Associated Token Account Program ID */
export const ATA_PROGRAM_ID: Address = address(
  "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"
);

/** ChadBuffer Program ID (deployed to devnet 2025-01-30) */
export const CHADBUFFER_PROGRAM_ID: Address = address(
  "C5RpjtTMFXKVZCtXSzKXD4CDNTaWBg3dVeMfYvjZYHDF"
);

/** ChadBuffer Program ID for localnet testing */
export const LOCALNET_CHADBUFFER_PROGRAM_ID: Address = address(
  "EgWyMVFZewHmjJ9GGvVBTyaC376Xp7qu7CAFjWYPYYDv"
);

// =============================================================================
// Network Configurations
// =============================================================================

/**
 * Greenfield devnet + Bitcoin testnet4 deployment (2026-08-26).
 *
 * The previous deployment's programs were closed on chain, so this is not a redeploy and none
 * of the old addresses resolve any more — anything still pinned to CvfSyACR… is talking to a
 * program that no longer exists.
 *
 * Two pools were deployed, each with its own Ika DKG and therefore its own dWallet. The default
 * below is the OPEN pool. Select the verified pool by overriding `zkbtcMint` and
 * `ikaDwalletXOnlyPubkey` — `getConfig` re-derives poolStatePda, commitmentTreePda and poolVault
 * from the mint, so those two values are all a caller needs:
 *
 *   verified  mint  G78CTddWGDaNaSKQayAt7m3pzcMyaUNxgR8y3R34YvEv
 *             state Eqn9SmFYtacrdfPE9Shbi8bDXLjCNNz3WhHfqtJnwbKY
 *             xonly 16c563baa11bfc8fe93acafe8fe169b954b3ead3ecda7754c615dec9e840b5a5
 *
 * Read off chain, not from the deploy notes: Eqn9SmFY… is the pool whose PoolState flags carry
 * the permissioned bit (0b10 at offset 2). The deployment also contains a THIRD pool —
 * 3chHiDqM… / 7wDtDd1u… — which the deploy notes name as the verified one but which is not
 * permissioned and whose mint has zero supply. Treat it as abandoned; do not wire it up.
 */
export const DEVNET_CONFIG: NetworkConfig = {
  network: "devnet",

  utxopiaProgramId: address("28z2AtKA6aFGrGCh4ns1rmp7vGpWuh6x3H7gXKBcfxur"),
  policyProgramId: address("9asWYKVriWGpExW5xM44ChHjZtispkLCiWKkM8SQi8Rs"),
  // testnet4 light client, deployed 2026-08-26. Must match the `devnet` arm of
  // BTC_LIGHT_CLIENT_PROGRAM_ID in programs/utxopia/src/constants.rs.
  btcLightClientProgramId: address("4LZbktiNsiVAe2bwPCTPNgqiWWgZNUj4T3bDx8GZmehv"),
  chadbufferProgramId: CHADBUFFER_PROGRAM_ID,
  token2022ProgramId: TOKEN_2022_PROGRAM_ID,
  ataProgramId: ATA_PROGRAM_ID,

  // Open pool. Derived and then confirmed on chain: pool_state and commitment_tree are owned by
  // the program (332 / 8816 bytes), the vault by Token-2022 (170 bytes).
  poolStatePda: address("FezM7ksBwftqrd4TtabMa9uXt51eCT5M946YnpSEQZHm"),
  commitmentTreePda: address("CHwJZqNAUag6ARDfmntvmbS4WeAsGX67f2vALxXbB6PP"),
  zkbtcMint: address("87zWstDnNgMig2vk8q8jTrK6YTcyugeRTanfT3LfyU3T"),
  poolVault: address("8VMfH4mDizU6nHybQumxeauyiEL2QTqrGQLXmAr9wpC3"),

  // RPC Endpoints
  solanaRpcUrl: "https://api.devnet.solana.com",
  solanaWsUrl: "wss://api.devnet.solana.com",

  // Bitcoin Network
  bitcoinNetwork: "testnet4",
  esploraUrl: "https://mempool.space/testnet4/api",

  // Circuit CDN (Groth16 artifacts: .wasm, .zkey files)
  circuitCdnUrl: "https://circuit.utxopia.com/circuits/v2/groth16",

  // Groth16 verification is inline in the UTXOpia program, so this is the same address.
  // It used to hold a stale third id, which `getConfig` silently overwrote with the program id
  // whenever a programId override was supplied — meaning the constant was only ever read on the
  // no-override path, where it was wrong.
  groth16VerifierProgramId: address("28z2AtKA6aFGrGCh4ns1rmp7vGpWuh6x3H7gXKBcfxur"),

  // VK Hashes (SHA256 of serialized VK bytes, generated from circom trusted setup)
  vkHashes: {
    claim: "7af0e702e7b595fbdb62fd268e6c529481003e07957e0f60e4fb23cd9fe6a77f",
    split: "00fb9e4c3fcc7b99fec5191370b516537f74831ad868a18c4ab2d519f332cc4f",
    spendPartialPublic: "732126aaec8355efdfb1b96aee1c9014506c99815a81057edbefd775b1b10663",
  },

  // JoinSplit VK hashes (populated after trusted setup for new circuits)
  joinSplitVkHashes: {
    "1x1": "745d536fb3a86424ee9560cb7b630bb0eb3d3c3af06c85bcda1eb7bcc5b1a07a",
    "1x2": "f782d4bc2f696417688cdec3cb4f822d6961892192e13e8842505bd8d119fa6d",
    "2x1": "3af6cdad3c1f4de9e088975a1ac5b20e0445d7f3fea0a5038f300102cf98fd98",
    "2x2": "6fffc4962028d0ac69f4d7877badc9f5adea4b83e6224ebb8db22657e847e7b8",
    "1x3": "ca396f36bbd1b07255b7a2f5585cedb4a51f925149747dd6ab4f695d19aa6ff8",
    "3x1": "4e0c5cbea0ccf80302d2589e41a2f22e19287f5acc5d0577451680fd909e1942",
    "2x3": "bf398583f064de96560cb9092b1357b0d742991a88f18a351e5b8793fed4b7a7",
    "3x2": "9da8d33d57896e76aadf3f5c66295774bd3273511af6e733ca7f9446ab58d42e",
    "1x4": "01728b82e810a8ba604cc66aa6a563444d18f4598c402d11767d0a7e5049a9be",
    "4x1": "0362b306b17dae916d836d9448a26c97e51b1b0a1a0ed052ebfbd4800e5000cf",
  },

  // Ika dWallet x-only pubkey for the OPEN pool, read from its PoolConfig PDA
  // (GQ5ZfD4tJmgcquHLAHSbmAm72Foi9hf3VduPrroysM1b, offset 68..100) on 2026-08-26.
  // All-zero here used to mean "deposit addresses cannot be derived until sync-env.sh runs";
  // the two pools have distinct dWallets, so a single synced value could only ever be right
  // for one of them. See the verified pool's key in the header comment above.
  ikaDwalletXOnlyPubkey:
    "3a6ab80ba14bc050f048ee3e0b77d8935adf4fc5e2f5947311f26cc2cb5bd194",

  // SNS Subdomain Resolution (devnet)
  snsNameServiceProgramId: "namesLPneVptA9Z5rqUDD9tMTWEJwofgaYwp8cawRkX",  // SPL Name Service (devnet)
  snsRegistrarProgramId: "snshBoEQ9jx4QoHBpZDQPYdNCtw7RMxJvYrKFEhwaPJ",    // SNS Registrar (devnet)
  snsSubRegistrarProgramId: "31tT5CmpphAtRL3mstu962zeYH7C6TEkJWLB5nYxciBB", // Sub-Registrar (devnet)
  snsRootDomain: "5eoDkP6vCQBXqDV9YN2NdUs3nmML3dMRNmEYpiyVNBm2",           // .sol TLD (devnet)
  snsParentDomain: "utxopia",
  snsReverseLookupClass: "7NbD1vprif6apthEZAqhRfYuhrqnuderB8qpnfXGCc8H",   // Reverse lookup class (devnet)
  snsStealthDataVersion: 1,
};

/**
 * Solana devnet + Bitcoin **regtest** deployment — the environment app.utxopia.com serves.
 *
 * This is a different deployment from DEVNET_CONFIG above, not a Bitcoin-side variation of it:
 * a different program (CvfSyACR…), a different pool, a different Ika dWallet. It used to share
 * DEVNET_CONFIG and differ only by bitcoinNetwork, which worked while one program hosted both.
 * It no longer does — after 2026-08-26 there are two programs — so `devnet-regtest` resolving
 * to DEVNET_CONFIG would silently point this environment at testnet4's program and pool.
 *
 * Pool addresses derived from the mint with the same seeds getConfig uses, then confirmed on
 * devnet: pool_state and commitment_tree owned by CvfSyACR… at 332 and 8816 bytes, the vault by
 * Token-2022 at 170.
 */
export const DEVNET_REGTEST_CONFIG: NetworkConfig = {
  ...DEVNET_CONFIG,

  utxopiaProgramId: address("CvfSyACR8xemPdeJsB3D8Xh15rKUQ3b5c1PvnmABCBJp"),
  groth16VerifierProgramId: address("CvfSyACR8xemPdeJsB3D8Xh15rKUQ3b5c1PvnmABCBJp"),
  btcLightClientProgramId: address("8hCSNKf8ByqZdet2D4SDiZHDrB1u9ohkhqKKzr9i7vfQ"),

  poolStatePda: address("CeEEmE9MvFPZtqcgv1rsXmzNmfvchbs8VEZJGFKZ2Cyj"),
  commitmentTreePda: address("45bCw97GssorJM9b1ZWZLMGy1NJUczcaNVaKASmCRohL"),
  zkbtcMint: address("BJ5SXA33qK8r8BxJD4nQPf72ae9bactiA2Zqo33EcvPu"),
  poolVault: address("JsZ1ipHZWiZYE8kRDXmEkKuiK6KKVxCVJKv1tGnCkM6"),

  ikaDwalletXOnlyPubkey:
    "243a6c47504f82d168754da9392a9dbcbab9b9f9c515a609227fac4642b2a26f",

  bitcoinNetwork: "regtest",
  esploraUrl: "http://localhost:2140",
};

/**
 * Mainnet Configuration (placeholder - not yet deployed)
 */
export const MAINNET_CONFIG: NetworkConfig = {
  network: "mainnet",

  // Program IDs (placeholder - update when deployed)
  utxopiaProgramId: address("11111111111111111111111111111111"),
  btcLightClientProgramId: address("11111111111111111111111111111111"),
  chadbufferProgramId: CHADBUFFER_PROGRAM_ID,
  token2022ProgramId: TOKEN_2022_PROGRAM_ID,
  ataProgramId: ATA_PROGRAM_ID,

  // Deployed Accounts (placeholder - update when deployed)
  poolStatePda: address("11111111111111111111111111111111"),
  commitmentTreePda: address("11111111111111111111111111111111"),
  zkbtcMint: address("11111111111111111111111111111111"),
  poolVault: address("11111111111111111111111111111111"),

  // RPC Endpoints
  solanaRpcUrl: "https://api.mainnet-beta.solana.com",
  solanaWsUrl: "wss://api.mainnet-beta.solana.com",

  // Bitcoin Network
  bitcoinNetwork: "mainnet",
  esploraUrl: "https://mempool.space/api",

  // Circuit CDN
  circuitCdnUrl: "https://circuit.utxopia.com",

  // Groth16 Verifier (placeholder)
  groth16VerifierProgramId: address("11111111111111111111111111111111"),

  // VK Hashes (placeholder - update when deployed)
  vkHashes: {
    claim: "0000000000000000000000000000000000000000000000000000000000000000",
    split: "0000000000000000000000000000000000000000000000000000000000000000",
    spendPartialPublic: "171daac7e5ff45e2d0e736ac0d28f5fe8e0cc8fc9961efa4dd9ee18e4413f755",
  },

  joinSplitVkHashes: {},

  ikaDwalletXOnlyPubkey:
    "0000000000000000000000000000000000000000000000000000000000000000",

  // SNS Subdomain Resolution (mainnet)
  snsNameServiceProgramId: "namesLPneVptA9Z5rqUDD9tMTWEJwofgaYwp8cawRkX",  // SPL Name Service (mainnet)
  snsRegistrarProgramId: "jCebN34bUfdeUYJT13J1yG16XWQpt5PDx6Mse9GUqhR",    // SNS Registrar (mainnet)
  snsSubRegistrarProgramId: "2KkyPzjaAYaz2ojQZ9P3xYakLd96B5UH6a2isLaZ4Cgs", // Sub-Registrar (mainnet)
  snsRootDomain: "58PwtjSDuFHuUkYjH9BYod9SZaELfsvdrNMryy9iYNvo",           // .sol TLD (mainnet)
  snsParentDomain: "utxopia",
  snsReverseLookupClass: "33m47vH6Eav6jr5Ry86XjhRft2jRBLDnDgPSHoquXi2Z",   // Reverse lookup class (mainnet)
  snsStealthDataVersion: 1,
};

/**
 * Localnet Configuration (for local development)
 * Synced with .localnet-config.json (2026-02-22)
 */
export const LOCALNET_CONFIG: NetworkConfig = {
  network: "localnet",

  // Program IDs
  utxopiaProgramId: address("2dBmKyfLibkqdxgyEWUhHos3g56oU2wXLVrucY2dCpGV"),
  btcLightClientProgramId: address("Ho6UTeF8yFnRdCK15tSZtcJozvkDABJZWYxkgGyWAfyq"),
  chadbufferProgramId: LOCALNET_CHADBUFFER_PROGRAM_ID,
  token2022ProgramId: TOKEN_2022_PROGRAM_ID,
  ataProgramId: ATA_PROGRAM_ID,

  // Deployed Accounts (synced with .localnet-config.json 2026-02-23)
  poolStatePda: address("E6DVestxC5dn5ixvLa3FcYodcVtwUAyanpVPbs4y3p16"),
  commitmentTreePda: address("JCiGqC1a1rjfqk2dqcybU2e3FQjAQ19x8ts9fQCtTFCq"),
  zkbtcMint: address("CHg1f85uxw4HrVkj3ianLezVAJTv29VcCWiBxjZ4YFdF"),
  poolVault: address("7vpuYKngG75Km1bbZ5TZJZzRn2BBtkh9BaqPS814tPLg"),

  // RPC Endpoints
  solanaRpcUrl: "http://127.0.0.1:8899",
  solanaWsUrl: "ws://127.0.0.1:8900",

  // Bitcoin Network (regtest for local dev)
  bitcoinNetwork: "regtest",
  esploraUrl: "http://localhost:2140",

  // Circuit CDN (use local files for development)
  circuitCdnUrl: "/circuits",

  // Groth16 Verifier: verification is inline in the UTXOpia program
  groth16VerifierProgramId: address("RoqAPQgZ5ztdhV3jHBKgTmeLBAfyYcaBsjKiXHNwXf3"),

  // VK Hashes (same as devnet - generated from same trusted setup)
  vkHashes: {
    claim: "7af0e702e7b595fbdb62fd268e6c529481003e07957e0f60e4fb23cd9fe6a77f",
    split: "00fb9e4c3fcc7b99fec5191370b516537f74831ad868a18c4ab2d519f332cc4f",
    spendPartialPublic: "732126aaec8355efdfb1b96aee1c9014506c99815a81057edbefd775b1b10663",
  },

  joinSplitVkHashes: {
    "1x1": "745d536fb3a86424ee9560cb7b630bb0eb3d3c3af06c85bcda1eb7bcc5b1a07a",
    "1x2": "f782d4bc2f696417688cdec3cb4f822d6961892192e13e8842505bd8d119fa6d",
    "2x1": "3af6cdad3c1f4de9e088975a1ac5b20e0445d7f3fea0a5038f300102cf98fd98",
    "2x2": "6fffc4962028d0ac69f4d7877badc9f5adea4b83e6224ebb8db22657e847e7b8",
  },

  // Ika dWallet x-only pubkey — populated by ./scripts/sync-env.sh from localnet-state.json.
  ikaDwalletXOnlyPubkey:
    "0000000000000000000000000000000000000000000000000000000000000000",

  // SNS Subdomain Resolution (not available on localnet)
  snsNameServiceProgramId: "",
  snsRegistrarProgramId: "",
  snsSubRegistrarProgramId: "",
  snsRootDomain: "",
  snsParentDomain: "",
  snsReverseLookupClass: "",
  snsStealthDataVersion: 1,
};

// =============================================================================
// Default Configuration
// =============================================================================

/** Current active configuration (defaults to devnet, overridden by env vars) */
let currentConfig: NetworkConfig = DEVNET_CONFIG;

// Eagerly apply env var overrides synchronously (program ID + mint only).
// PDA derivation happens async in initConfig(), but at least getConfig()
// returns the correct program ID immediately.
if (typeof process !== "undefined") {
  const _pid = process.env?.NEXT_PUBLIC_UTXOPIA_PROGRAM_ID || process.env?.UTXOPIA_PROGRAM_ID;
  const _mint = process.env?.NEXT_PUBLIC_ZKBTC_MINT || process.env?.UTXOPIA_ZKBTC_MINT;
  if (_pid) {
    currentConfig = { ...currentConfig, utxopiaProgramId: address(_pid), groth16VerifierProgramId: address(_pid) };
  }
  if (_mint) {
    currentConfig = { ...currentConfig, zkbtcMint: address(_mint) };
  }
}

/** Esplora URL for a given Bitcoin network */
function esploraUrlForNetwork(net: string): string {
  switch (net) {
    case "mainnet": return "https://mempool.space/api";
    case "testnet": return "https://mempool.space/testnet/api";
    case "testnet4": return "https://mempool.space/testnet4/api";
    case "signet": return "https://mempool.space/signet/api";
    case "regtest": return "http://localhost:2140";
    default: return `https://mempool.space/${net}/api`;
  }
}

/**
 * Base config for an app network id. Two devnet deployments now exist, so this cannot be
 * derived from NetworkType alone — that is what normalizeAppNetwork collapses away.
 */
function baseConfigForAppNetwork(network?: string): NetworkConfig {
  switch (network) {
    case "localnet":
      return LOCALNET_CONFIG;
    case "mainnet":
      return MAINNET_CONFIG;
    case "devnet-regtest":
      return DEVNET_REGTEST_CONFIG;
    case "devnet-testnet4":
    case "devnet":
    default:
      return DEVNET_CONFIG;
  }
}

function normalizeAppNetwork(network?: string): NetworkType {
  switch (network) {
    case "mainnet":
      return "mainnet";
    case "localnet":
      return "localnet";
    case "devnet":
    case "devnet-regtest":
    case "devnet-testnet4":
    default:
      return "devnet";
  }
}

function bitcoinNetworkForAppNetwork(network?: string): NetworkConfig["bitcoinNetwork"] | undefined {
  switch (network) {
    case "localnet":
    case "devnet-regtest":
      return "regtest";
    case "devnet":
    case "devnet-testnet4":
      return "testnet4";
    case "mainnet":
      return "mainnet";
    default:
      return undefined;
  }
}

/**
 * Get the current network configuration.
 * Respects NEXT_PUBLIC_BTC_NETWORK env var to override Bitcoin network
 * (e.g., "testnet" for testnet3, "testnet4" for testnet4).
 */
export function getConfig(): NetworkConfig {
  const btcNetOverride =
    typeof process !== "undefined" && process.env?.NEXT_PUBLIC_BTC_NETWORK;
  if (btcNetOverride && btcNetOverride !== currentConfig.bitcoinNetwork) {
    return {
      ...currentConfig,
      bitcoinNetwork: btcNetOverride as NetworkConfig["bitcoinNetwork"],
      esploraUrl: esploraUrlForNetwork(btcNetOverride),
    };
  }
  return currentConfig;
}

/**
 * Set the network configuration
 *
 * @param network - Network type or custom config
 * @throws Error if mainnet is selected (not yet deployed)
 */
export function setConfig(network: AppNetworkId | NetworkConfig): void {
  if (typeof network === "string") {
    const baseNetwork = normalizeAppNetwork(network);
    switch (baseNetwork) {
      case "devnet":
        currentConfig = baseConfigForAppNetwork(network);
        break;
      case "mainnet":
        throw new Error(
          "Mainnet is not yet deployed. " +
          "UTXOpia is currently available on devnet only. " +
          "Use setConfig('devnet') or wait for mainnet deployment announcement."
        );
      case "localnet":
        currentConfig = LOCALNET_CONFIG;
        break;
      default:
        throw new Error(`Unknown network: ${network}`);
    }
    const bitcoinNetwork = bitcoinNetworkForAppNetwork(network);
    if (bitcoinNetwork) {
      currentConfig = {
        ...currentConfig,
        bitcoinNetwork,
        esploraUrl: esploraUrlForNetwork(bitcoinNetwork),
      };
    }
  } else {
    // Check if custom config is using placeholder mainnet addresses
    if (network.network === "mainnet" && network.utxopiaProgramId === MAINNET_CONFIG.utxopiaProgramId) {
      throw new Error(
        "Cannot use placeholder mainnet configuration. " +
        "Mainnet is not yet deployed."
      );
    }
    currentConfig = network;
  }
}

/**
 * Create a custom configuration by overriding specific values
 *
 * @param base - Base configuration to extend
 * @param overrides - Values to override
 */
export function createConfig(
  base: NetworkConfig,
  overrides: Partial<NetworkConfig>
): NetworkConfig {
  return { ...base, ...overrides };
}

// =============================================================================
// Environment-based Initialization
// =============================================================================

/**
 * Initialize SDK configuration with optional overrides.
 *
 * Reads `utxopiaProgramId` and `zkbtcMint` from params, then env vars, then
 * falls back to DEVNET_CONFIG defaults. All PDAs are auto-derived from these
 * two values.
 *
 * Env vars checked (in order):
 * - NEXT_PUBLIC_UTXOPIA_PROGRAM_ID / UTXOPIA_PROGRAM_ID
 * - NEXT_PUBLIC_ZKBTC_MINT / UTXOPIA_ZKBTC_MINT
 *
 * @example
 * // Use env vars (set NEXT_PUBLIC_UTXOPIA_PROGRAM_ID + NEXT_PUBLIC_ZKBTC_MINT)
 * await initConfig();
 *
 * // Or pass explicitly
 * await initConfig({ utxopiaProgramId: "...", zkbtcMint: "..." });
 */
export type NetworkId = AppNetworkId;

export async function initConfig(overrides?: {
  network?: NetworkId;
  utxopiaProgramId?: string;
  policyProgramId?: string;
  zkbtcMint?: string;
  solanaRpcUrl?: string;
  ikaDwalletXOnlyPubkey?: string;
  depositMode?: "sweep" | "direct" | "direct_vault" | "ika_direct";
}): Promise<NetworkConfig> {
  // Pick base config from network: param > env > devnet
  const appNetworkId: NetworkId =
    overrides?.network ||
    (typeof process !== "undefined" && (process.env?.NEXT_PUBLIC_NETWORK || process.env?.UTXOPIA_NETWORK) as NetworkId) ||
    "devnet";
  const networkId = normalizeAppNetwork(appNetworkId);

  const baseConfig = baseConfigForAppNetwork(appNetworkId);

  const config = { ...baseConfig };
  const appBitcoinNetwork = bitcoinNetworkForAppNetwork(appNetworkId);
  const btcNetOverride =
    typeof process !== "undefined" && process.env?.NEXT_PUBLIC_BTC_NETWORK;
  const bitcoinNetwork = btcNetOverride || appBitcoinNetwork;
  if (bitcoinNetwork) {
    config.bitcoinNetwork = bitcoinNetwork as NetworkConfig["bitcoinNetwork"];
    config.esploraUrl = esploraUrlForNetwork(bitcoinNetwork);
  }

  // Resolve program ID: param > env > base config default
  const programId =
    overrides?.utxopiaProgramId ||
    (typeof process !== "undefined" && (process.env?.NEXT_PUBLIC_UTXOPIA_PROGRAM_ID || process.env?.UTXOPIA_PROGRAM_ID)) ||
    undefined;
  const policyProgramId =
    overrides?.policyProgramId ||
    (typeof process !== "undefined" &&
      (process.env?.NEXT_PUBLIC_UTXOPIA_POLICY_PROGRAM_ID ||
        process.env?.UTXOPIA_POLICY_PROGRAM_ID)) ||
    undefined;
  if (policyProgramId) {
    config.policyProgramId = address(policyProgramId);
  }

  // Resolve mint: param > env > default
  const mint =
    overrides?.zkbtcMint ||
    (typeof process !== "undefined" && (process.env?.NEXT_PUBLIC_ZKBTC_MINT || process.env?.UTXOPIA_ZKBTC_MINT)) ||
    config.zkbtcMint;

  // Resolve RPC URL for on-chain fetching
  const rpcUrl =
    overrides?.solanaRpcUrl ||
    (typeof process !== "undefined" && (process.env?.NEXT_PUBLIC_SOLANA_RPC_URL || process.env?.UTXOPIA_SOLANA_RPC)) ||
    undefined;

  if (programId) {
    config.utxopiaProgramId = address(programId);
    config.groth16VerifierProgramId = address(programId); // same program

    // Fresh multi-pool deployments use zkBTC mint as the pool namespace.
    const encoder = getAddressEncoder();
    config.zkbtcMint = address(mint);
    const [poolStatePda] = await getProgramDerivedAddress({
      programAddress: config.utxopiaProgramId,
      seeds: [
        new TextEncoder().encode("pool_state"),
        encoder.encode(config.zkbtcMint),
      ],
    });
    const treeIndex = new Uint8Array(4);
    const [commitmentTreePda] = await getProgramDerivedAddress({
      programAddress: config.utxopiaProgramId,
      seeds: [
        new TextEncoder().encode("commitment_tree"),
        encoder.encode(poolStatePda),
        treeIndex,
      ],
    });
    config.poolStatePda = poolStatePda;
    config.commitmentTreePda = commitmentTreePda;
  }

  if (mint) {
    config.zkbtcMint = address(mint);

    // Derive pool vault (ATA: seeds = [owner, TOKEN_2022, mint] under ATA program)
    const encoder = getAddressEncoder();
    const [poolVault] = await getProgramDerivedAddress({
      programAddress: config.ataProgramId,
      seeds: [
        encoder.encode(config.poolStatePda),
        encoder.encode(config.token2022ProgramId),
        encoder.encode(config.zkbtcMint),
      ],
    });
    config.poolVault = poolVault;
  }

  // Apply Ika dWallet x-only pubkey override (sole Taproot custody key)
  if (overrides?.ikaDwalletXOnlyPubkey) {
    config.ikaDwalletXOnlyPubkey = overrides.ikaDwalletXOnlyPubkey;
  }
  if (overrides?.depositMode) {
    config.depositMode = overrides.depositMode;
  }

  currentConfig = config;
  return config;
}

// =============================================================================
// Convenience Exports
// =============================================================================

/** Default UTXOpia program ID (from current config) */
export const UTXOPIA_PROGRAM_ID: Address = DEVNET_CONFIG.utxopiaProgramId;
export const UTXOPIA_POLICY_PROGRAM_ID: Address =
  DEVNET_CONFIG.policyProgramId ?? DEVNET_CONFIG.utxopiaProgramId;

/** BTC Light Client program ID (manages light client + block headers) */
export const BTC_LIGHT_CLIENT_PROGRAM_ID: Address = DEVNET_CONFIG.btcLightClientProgramId;

// =============================================================================
// Version Info
// =============================================================================

export const SDK_VERSION = "3.3.0";

/** JoinSplit Merkle tree depth */
export const JOINSPLIT_TREE_DEPTH = 16;

export const DEPLOYMENT_INFO = {
  version: SDK_VERSION,
  deployedAt: "2026-03-03",
  network: "devnet" as NetworkType,
  features: [
    "stealth-addresses",
    "groth16-browser-proving",
  ],
  notes: "Client-side Groth16 proof generation via snarkjs",
};
