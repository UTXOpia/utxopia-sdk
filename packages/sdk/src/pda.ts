/**
 * PDA (Program Derived Address) Derivation Utilities
 *
 * Centralized module for all UTXOpia PDA derivations.
 * Prevents code duplication across api.ts, pda.ts, etc.
 *
 * @module pda
 */

import {
  getAddressEncoder,
  getProgramDerivedAddress,
  type Address,
} from "@solana/kit";

import {
  UTXOPIA_PROGRAM_ID,
  UTXOPIA_POLICY_PROGRAM_ID,
  BTC_LIGHT_CLIENT_PROGRAM_ID,
} from "./config";

function seedBytes(value: Address | Uint8Array, label: string): Uint8Array {
  const bytes =
    typeof value === "string"
      ? new Uint8Array(getAddressEncoder().encode(value))
      : value;
  if (bytes.length !== 32) throw new Error(`${label} must be 32 bytes`);
  return bytes;
}

// =============================================================================
// PDA Seeds
// =============================================================================

export const PDA_SEEDS = {
  POOL_STATE: "pool_state",
  COMMITMENT_TREE: "commitment_tree",
  LIGHT_CLIENT: "btc_light_client",
  BLOCK_HEADER: "block",
  HEIGHT_INDEX: "height_index",
  VERIFIED_TX: "verified_tx",
  DEPOSIT: "deposit",
  NULLIFIER: "nullifier",
  POLICY_APPROVAL: "policy_approval",
  EXIT_DESTINATION: "exit_destination",
  VK_REGISTRY: "vk_registry",
  TOKEN_CONFIG: "token_config",
  POOL_CONFIG: "pool_config",
} as const;

// =============================================================================
// Seed builders — the single definition of every program-derived address
//
// These are the authority. Each mirrors the seed array the on-chain program
// derives with, and every derivation in this file is built on them, so there is
// one place to change when the program changes.
//
// They are exported and synchronous on purpose. `getProgramDerivedAddress` is
// async, but consumers on @solana/web3.js need `findProgramAddressSync` and
// `PublicKey`. Without a sync seam those consumers end up re-declaring the seeds
// themselves — which is exactly how the web app's copy drifted out of sync with
// the program twice (the nullifier and the redemption request both lost their
// pool scope, and both failed only on chain, after a proof had been paid for).
// Take the seeds from here and do your own address math with your own types.
// =============================================================================

const enc = (s: string): Uint8Array => new TextEncoder().encode(s);

const u32le = (n: number, label: string): Uint8Array => {
  if (!Number.isInteger(n) || n < 0 || n > 0xffffffff) {
    throw new Error(`${label} must be a u32, got ${n}`);
  }
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, true);
  return b;
};

const u64le = (n: bigint): Uint8Array => {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, n, true);
  return b;
};

/** `["pool_state", pool_id]` — pool_id is the pool's zkBTC mint. */
export function poolStateSeeds(poolId: Address | Uint8Array): Uint8Array[] {
  return [enc(PDA_SEEDS.POOL_STATE), seedBytes(poolId, "poolId")];
}

/** `["commitment_tree", pool_state, tree_index_le]`. */
export function commitmentTreeSeeds(
  poolState: Address | Uint8Array,
  treeIndex = 0,
): Uint8Array[] {
  return [
    enc(PDA_SEEDS.COMMITMENT_TREE),
    seedBytes(poolState, "poolState"),
    u32le(treeIndex, "treeIndex"),
  ];
}

/** `["token_config", pool_state, mint]`. */
export function tokenConfigSeeds(
  poolState: Address | Uint8Array,
  mint: Address | Uint8Array,
): Uint8Array[] {
  return [
    enc(PDA_SEEDS.TOKEN_CONFIG),
    seedBytes(poolState, "poolState"),
    seedBytes(mint, "mint"),
  ];
}

/** `["pool_config", pool_state]`. */
export function poolConfigSeeds(poolState: Address | Uint8Array): Uint8Array[] {
  return [enc(PDA_SEEDS.POOL_CONFIG), seedBytes(poolState, "poolState")];
}

/** `["nullifier", pool_state, nullifier]` on tree 0, and
 *  `["nullifier", pool_state, tree_index_le, nullifier]` after a rotation.
 *
 *  A nullifier is Poseidon(nullifyingKey, leafIndex), so it names a note only
 *  within one pool and one tree — leaf indices restart at 0 in each new tree.
 *  Drop either scope and two distinct notes collapse onto one PDA, where
 *  spending either strands the other. Tree 0 keeps the shorter seeds so records
 *  already on chain stay reachable (`joinsplit_common.rs`). */
export function nullifierRecordSeeds(
  nullifierHash: Uint8Array,
  poolState: Address | Uint8Array,
  treeIndex = 0,
): Uint8Array[] {
  const seeds: Uint8Array[] = [
    enc(PDA_SEEDS.NULLIFIER),
    seedBytes(poolState, "poolState"),
  ];
  if (treeIndex !== 0) seeds.push(u32le(treeIndex, "treeIndex"));
  seeds.push(nullifierHash);
  return seeds;
}

/** `["redemption", pool_state, user, nonce_le]` (`redeem.rs`). */
export function redemptionRequestSeeds(
  poolState: Address | Uint8Array,
  userPubkey: Address | Uint8Array,
  nonce: bigint,
): Uint8Array[] {
  return [
    enc("redemption"),
    seedBytes(poolState, "poolState"),
    seedBytes(userPubkey, "userPubkey"),
    u64le(nonce),
  ];
}

/** `["vk_registry", [n_inputs], [n_outputs]]`. */
export function vkRegistrySeeds(nInputs: number, nOutputs: number): Uint8Array[] {
  return [enc(PDA_SEEDS.VK_REGISTRY), Uint8Array.of(nInputs), Uint8Array.of(nOutputs)];
}

/** `["deposit_receipt", txid]`, or `[..., vout_le]` for the OP_RETURN-free
 *  `verify_deposit` flow. See deriveDepositReceiptPDA for which is which. */
export function depositReceiptSeeds(
  depositTxid: Uint8Array,
  depositVout?: number,
): Uint8Array[] {
  if (depositTxid.length !== 32) {
    throw new Error(`depositTxid must be 32 bytes, got ${depositTxid.length}`);
  }
  const seeds: Uint8Array[] = [enc("deposit_receipt"), depositTxid];
  if (depositVout !== undefined) seeds.push(u32le(depositVout, "depositVout"));
  return seeds;
}

/** `["policy_approval", pool_state, request_hash, nonce]`. */
export function policyApprovalSeeds(
  poolState: Address | Uint8Array,
  requestHash: Uint8Array,
  nonce: Uint8Array,
): Uint8Array[] {
  if (requestHash.length !== 32 || nonce.length !== 32) {
    throw new Error("requestHash and nonce must be 32 bytes");
  }
  return [
    enc(PDA_SEEDS.POLICY_APPROVAL),
    seedBytes(poolState, "poolState"),
    requestHash,
    nonce,
  ];
}

/** `["exit_destination", pool_state, [kind], key]`. */
export function exitDestinationSeeds(
  poolState: Address | Uint8Array,
  kind: number,
  key: Uint8Array,
): Uint8Array[] {
  if (key.length !== 32) throw new Error("exit destination key must be 32 bytes");
  if (kind !== EXIT_KIND_SOLANA_OWNER && kind !== EXIT_KIND_BTC_SCRIPT) {
    throw new Error("unknown exit destination kind");
  }
  return [
    enc(PDA_SEEDS.EXIT_DESTINATION),
    seedBytes(poolState, "poolState"),
    Uint8Array.of(kind),
    key,
  ];
}

/** `["btc_light_client"]`. */
export function lightClientSeeds(): Uint8Array[] {
  return [enc(PDA_SEEDS.LIGHT_CLIENT)];
}

/** `["block", block_hash]`. */
export function blockHeaderSeeds(blockHash: Uint8Array): Uint8Array[] {
  // A short hash still derives *an* address, just not the block's — the caller would then read
  // or write the wrong account with no error anywhere. Every other 32-byte seed here is checked.
  return [enc(PDA_SEEDS.BLOCK_HEADER), seedBytes(blockHash, "blockHash")];
}

/** `["height_index", height_le(8)]`. */
export function heightIndexSeeds(height: number | bigint): Uint8Array[] {
  return [enc(PDA_SEEDS.HEIGHT_INDEX), u64le(BigInt(height))];
}

/** `["verified_tx", block_hash, txid]`. */
export function verifiedTransactionSeeds(
  blockHash: Uint8Array,
  txid: Uint8Array,
): Uint8Array[] {
  return [enc(PDA_SEEDS.VERIFIED_TX), blockHash, txid];
}

// =============================================================================
// Core UTXOpia PDAs
// =============================================================================

/**
 * Derive Pool State PDA
 */
export async function derivePoolStatePDA(
  poolId: Address | Uint8Array,
  programId: Address = UTXOPIA_PROGRAM_ID
): Promise<[Address, number]> {
  const result = await getProgramDerivedAddress({
    programAddress: programId,
    seeds: poolStateSeeds(poolId),
  });
  return [result[0], result[1]];
}

/**
 * Derive Commitment Tree PDA
 *
 * @param treeIndex - Tree rotation index (default 0).
 */
export async function deriveCommitmentTreePDA(
  poolState: Address | Uint8Array,
  programId: Address = UTXOPIA_PROGRAM_ID,
  treeIndex?: number,
): Promise<[Address, number]> {
  const result = await getProgramDerivedAddress({
    programAddress: programId,
    seeds: commitmentTreeSeeds(poolState, treeIndex ?? 0),
  });
  return [result[0], result[1]];
}

/**
 * Derive TokenConfig PDA for a specific mint
 * Seeds: ["token_config", mint_pubkey_bytes]
 */
export async function deriveTokenConfigPDA(
  poolState: Address | Uint8Array,
  mintPubkey: Uint8Array,
  programId: Address = UTXOPIA_PROGRAM_ID
): Promise<[Address, number]> {
  const result = await getProgramDerivedAddress({
    programAddress: programId,
    seeds: tokenConfigSeeds(poolState, mintPubkey),
  });
  return [result[0], result[1]];
}

/** Derive ["pool_config", pool_state]. */
export async function derivePoolConfigPDA(
  poolState: Address | Uint8Array,
  programId: Address = UTXOPIA_PROGRAM_ID
): Promise<[Address, number]> {
  const result = await getProgramDerivedAddress({
    programAddress: programId,
    seeds: poolConfigSeeds(poolState),
  });
  return [result[0], result[1]];
}

/**
 * Derive Nullifier Record PDA.
 *
 * Seeds are `["nullifier", pool_state, nullifier]` on tree 0, and
 * `["nullifier", pool_state, tree_index_le, nullifier]` on any tree a rotation
 * created. Both scopes exist because a nullifier is Poseidon(nullifyingKey,
 * leafIndex) and so identifies a note only within one pool and one tree:
 *
 *  - Without the pool, the same seed spending into two vaults derives one PDA,
 *    and spending in either strands the twin note in the other.
 *  - Without the tree, the same happens across a rotation, because leaf indices
 *    restart at 0 in every new tree.
 *
 * Tree 0 keeps the shorter seeds so the records already on chain stay reachable
 * — re-deriving them would make every already-spent note spendable again.
 */
export async function deriveNullifierRecordPDA(
  nullifierHash: Uint8Array,
  poolState: Address | Uint8Array,
  treeIndex = 0,
  programId: Address = UTXOPIA_PROGRAM_ID
): Promise<[Address, number]> {
  const result = await getProgramDerivedAddress({
    programAddress: programId,
    seeds: nullifierRecordSeeds(nullifierHash, poolState, treeIndex),
  });
  return [result[0], result[1]];
}

/**
 * Derive one-time PolicyApproval PDA.
 * Seeds: ["policy_approval", pool_state, request_hash, nonce]
 */
export async function derivePolicyApprovalPDA(
  poolState: Address | Uint8Array,
  requestHash: Uint8Array,
  nonce: Uint8Array,
  programId: Address = UTXOPIA_POLICY_PROGRAM_ID
): Promise<[Address, number]> {
  const result = await getProgramDerivedAddress({
    programAddress: programId,
    seeds: policyApprovalSeeds(poolState, requestHash, nonce),
  });
  return [result[0], result[1]];
}

/** Destination kinds in the exit registry. Kind is a PDA seed, so a Solana
 *  owner and a BTC script hash sharing the same 32 bytes stay distinct. */
export const EXIT_KIND_SOLANA_OWNER = 0;
export const EXIT_KIND_BTC_SCRIPT = 1;

/**
 * Derive an ExitDestination PDA — the append-only registry of destinations a
 * permissioned pool's ragequit path may pay.
 *
 * Seeds: ["exit_destination", pool_state, [kind], key]
 *
 * `key` is the recipient token account's OWNER for `EXIT_KIND_SOLANA_OWNER`,
 * or `sha256(btcScript)` for `EXIT_KIND_BTC_SCRIPT`.
 */
export async function deriveExitDestinationPDA(
  poolState: Address | Uint8Array,
  kind: number,
  key: Uint8Array,
  programId: Address
): Promise<[Address, number]> {
  const result = await getProgramDerivedAddress({
    programAddress: programId,
    seeds: exitDestinationSeeds(poolState, kind, key),
  });
  return [result[0], result[1]];
}

// =============================================================================
// BTC Light Client PDAs
// =============================================================================

/**
 * Derive BTC Light Client PDA
 */
export async function deriveLightClientPDA(
  programId: Address = BTC_LIGHT_CLIENT_PROGRAM_ID
): Promise<[Address, number]> {
  const result = await getProgramDerivedAddress({
    programAddress: programId,
    seeds: lightClientSeeds(),
  });
  return [result[0], result[1]];
}

/**
 * Derive Block Header PDA (hash-based)
 * Seeds: ["block", blockHash(32)]
 */
export async function deriveBlockHeaderPDA(
  blockHash: Uint8Array,
  programId: Address = BTC_LIGHT_CLIENT_PROGRAM_ID
): Promise<[Address, number]> {
  const result = await getProgramDerivedAddress({
    programAddress: programId,
    seeds: blockHeaderSeeds(blockHash),
  });
  return [result[0], result[1]];
}

/**
 * Derive HeightIndex PDA
 * Seeds: ["height_index", height_le_bytes(8)]
 */
export async function deriveHeightIndexPDA(
  height: number | bigint,
  programId: Address = BTC_LIGHT_CLIENT_PROGRAM_ID
): Promise<[Address, number]> {
  const result = await getProgramDerivedAddress({
    programAddress: programId,
    seeds: heightIndexSeeds(height),
  });
  return [result[0], result[1]];
}

/**
 * Derive VerifiedTransaction PDA (btc-light-client)
 *
 * Seeds: ["verified_tx", blockHash(32), txid(32)]
 */
export async function deriveVerifiedTransactionPDA(
  blockHash: Uint8Array,
  txid: Uint8Array,
  programId: Address = BTC_LIGHT_CLIENT_PROGRAM_ID
): Promise<[Address, number]> {
  const result = await getProgramDerivedAddress({
    programAddress: programId,
    seeds: verifiedTransactionSeeds(blockHash, txid),
  });
  return [result[0], result[1]];
}

// =============================================================================
// Redemption Request PDAs
// =============================================================================

/**
 * Derive Redemption Request PDA
 *
 * Seeds: ["redemption", pool_state, user_pubkey(32), nonce_le(8)]
 */
export async function deriveRedemptionRequestPDA(
  poolState: Address | Uint8Array,
  userPubkey: Uint8Array,
  nonce: bigint,
  programId: Address = UTXOPIA_PROGRAM_ID
): Promise<[Address, number]> {
  const result = await getProgramDerivedAddress({
    programAddress: programId,
    seeds: redemptionRequestSeeds(poolState, userPubkey, nonce),
  });
  return [result[0], result[1]];
}

// =============================================================================
// VK Registry PDAs
// =============================================================================

/**
 * Derive VK Registry PDA for a JoinSplit variant
 *
 * Seeds: ["vk_registry", &[n_inputs], &[n_outputs]]
 */
export async function deriveVkRegistryPDA(
  nInputs: number,
  nOutputs: number,
  programId: Address = UTXOPIA_PROGRAM_ID
): Promise<[Address, number]> {
  const result = await getProgramDerivedAddress({
    programAddress: programId,
    seeds: vkRegistrySeeds(nInputs, nOutputs),
  });
  return [result[0], result[1]];
}

// =============================================================================
// Deposit Receipt PDAs
// =============================================================================

/**
 * Derive Deposit Receipt PDA.
 *
 * Two on-chain schemes exist:
 * - `complete_deposit` (disc 11, the active direct-vault flow): seeds ["deposit_receipt", txid] —
 *   call WITHOUT `depositVout`.
 * - `verify_deposit` (disc 25, OP_RETURN-free flow): seeds ["deposit_receipt", txid, vout(4 LE)] —
 *   pass `depositVout` so a funding tx with multiple independent deposit outputs gets one receipt
 *   per output (each creditable once) instead of the first output blocking the rest.
 */
export async function deriveDepositReceiptPDA(
  depositTxid: Uint8Array,
  depositVout?: number,
  programId: Address = UTXOPIA_PROGRAM_ID
): Promise<[Address, number]> {
  const result = await getProgramDerivedAddress({
    programAddress: programId,
    seeds: depositReceiptSeeds(depositTxid, depositVout),
  });
  return [result[0], result[1]];
}

// =============================================================================
// Utility Functions
// =============================================================================

/**
 * Convert bigint commitment to bytes for PDA derivation
 */
export function commitmentToBytes(commitment: bigint): Uint8Array {
  const hex = commitment.toString(16).padStart(64, "0");
  const bytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}
