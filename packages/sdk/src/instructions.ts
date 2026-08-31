/**
 * UTXOPIA Instruction Builders (JoinSplit Architecture)
 *
 * Low-level instruction building for UTXOPIA operations.
 * All Groth16 proofs are verified inline using BN254 pairing syscalls.
 *
 * @module instructions
 */

import {
  AccountRole,
  type Address,
} from "@solana/kit";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex as toHex } from "./crypto";

import { address, getConfig, TOKEN_2022_PROGRAM_ID } from "./config";
import { type AuditorCiphertextInput, resolveAuditorCiphertext } from "./auditor-ciphertext";
import {
  MAGICBLOCK_EPHEMERAL_VAULT_ID,
  MAGICBLOCK_DELEGATION_PROGRAM_ID,
  MAGICBLOCK_MAGIC_CONTEXT_ID,
  MAGICBLOCK_MAGIC_PROGRAM_ID,
  MAGICBLOCK_MAX_PER_MEMBERS,
  MAGICBLOCK_PERMISSION_PROGRAM_ID,
  MAGICBLOCK_PER_MEMBER_FLAGS,
} from "./magicblock";

/** System program address */
const SYSTEM_PROGRAM_ADDRESS = address("11111111111111111111111111111111");

// =============================================================================
// Types
// =============================================================================

/** Instruction type for v2 */
export interface Instruction {
  programAddress: Address;
  accounts: Array<{ address: Address; role: (typeof AccountRole)[keyof typeof AccountRole] }>;
  data: Uint8Array;
}

// =============================================================================
// Constants
// =============================================================================

/** Instruction discriminators — sequential 0-19 (must match contracts/programs/utxopia/src/lib.rs) */
const INSTRUCTION = {
  // Core (0-2)
  INITIALIZE: 0,
  SET_PAUSED: 1,
  SET_POOL_CONFIG: 2,
  // Pool updates (3-5)
  PROPOSE_POOL_UPDATE: 3,
  EXECUTE_POOL_UPDATE: 4,
  CANCEL_POOL_UPDATE: 5,
  // VK admin (6-7)
  INIT_VK_REGISTRY: 6,
  UPDATE_VK_REGISTRY: 7,
  // Multi-token (8-10)
  REGISTER_TOKEN: 8,
  UPDATE_TOKEN_CONFIG: 9,
  CLAIM_FEES: 10,
  // Deposit (11-12, 25)
  COMPLETE_DEPOSIT: 11,
  SHIELD: 12,
  /** OP_RETURN-free deposit: note keys ride in instruction data, proven by the
   *  deposit address's tapleaf. */
  VERIFY_DEPOSIT: 25,
  // JoinSplit (13-15) — all share n_in + n_out + n_pub + proof_source header
  TRANSACT: 13,
  UNSHIELD: 14,
  REDEEM: 15,
  // VK registry freeze (16) — NOT part of the redemption range below
  FREEZE_VK_REGISTRY: 16,
  // Redemption lifecycle (17-19)
  COMPLETE_REDEMPTION: 17,
  MARK_PROCESSING: 18,
  CANCEL_REDEMPTION: 19,
  // Tree management (20)
  ROTATE_TREE: 20,
  // 21-23 are permissioned-pool ops — see PERMISSIONED_DISC
  APPROVE_REDEMPTION_SIGNING: 27,
  // Auditor-only setters (28-29) — utxopia program, permissioned pools
  SET_AUDITOR_FROZEN: 28,
  SET_AUDITOR_VIEWING_PUBKEY: 29,
  // MagicBlock ER/PER lifecycle helpers (32-33)
  MAGICBLOCK_DELEGATE: 32,
  MAGICBLOCK_COMMIT: 33,
  MAGICBLOCK_PER_PERMISSION: 34,
  ROTATE_AUDITOR: 35,
  INITIALIZE_POLICY_APPROVAL: 36,
  POLICY_APPROVAL_DECISION: 37,
  POLICY_APPROVAL_COMMIT: 38,
} as const;

/**
 * Discriminants for permissioned-pool instructions (utxopia program only).
 * Values must match programs/utxopia/src/lib.rs exactly.
 */
const PERMISSIONED_DISC = {
  INITIALIZE_PERMISSIONED: 21,
  COMPLETE_DEPOSIT_PERMISSIONED: 22,
  /** Same binding as VERIFY_DEPOSIT, plus the permissioned pool's policy gate. */
  VERIFY_DEPOSIT_PERMISSIONED: 26,
  SHIELD_PERMISSIONED: 23,
  REGISTER_EXIT_DESTINATION: 39,
} as const;

/** Export instruction discriminators for consumers */
export const INSTRUCTION_DISCRIMINATORS = INSTRUCTION;

// =============================================================================
// Utilities
// =============================================================================

/**
 * Simple base58 decoding for addresses
 */
function bs58Decode(str: string): Uint8Array {
  const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  const ALPHABET_MAP = new Map<string, number>();
  for (let i = 0; i < ALPHABET.length; i++) {
    ALPHABET_MAP.set(ALPHABET[i], i);
  }

  let num = BigInt(0);
  for (const char of str) {
    const val = ALPHABET_MAP.get(char);
    if (val === undefined) {
      throw new Error(`Invalid base58 character: ${char}`);
    }
    num = num * BigInt(58) + BigInt(val);
  }

  // Count leading zeros
  let leadingZeros = 0;
  for (const char of str) {
    if (char === "1") {
      leadingZeros++;
    } else {
      break;
    }
  }

  // Convert to bytes
  const bytes: number[] = [];
  while (num > BigInt(0)) {
    bytes.unshift(Number(num % BigInt(256)));
    num = num / BigInt(256);
  }

  // Add leading zeros
  for (let i = 0; i < leadingZeros; i++) {
    bytes.unshift(0);
  }

  // Ensure 32 bytes for Solana addresses
  while (bytes.length < 32) {
    bytes.unshift(0);
  }

  return new Uint8Array(bytes);
}

/**
 * Convert Address to bytes
 */
function addressToBytes(addr: Address): Uint8Array {
  return bs58Decode(addr.toString());
}

const STEALTH_DATA_PER_OUTPUT = 72; // ephemeral_pub(32) + encrypted_amount(8) + encrypted_token_id(32)

function assertStealthDataRecordLengths(stealthData: Uint8Array[]): void {
  for (let i = 0; i < stealthData.length; i++) {
    if (stealthData[i].length !== STEALTH_DATA_PER_OUTPUT) {
      throw new Error(`Stealth data ${i} must be ${STEALTH_DATA_PER_OUTPUT} bytes, got ${stealthData[i].length}`);
    }
  }
}

// =============================================================================
// Shield Instruction Builder (disc=12)
// =============================================================================

/** Shield instruction options */
export interface ShieldInstructionOptions {
  /** Amount to shield (in token's smallest unit — lamports, micro-USDC, sats) */
  amount: bigint;
  /** NPK bytes (32) — recipient's note public key */
  npk: Uint8Array;
  /** Ephemeral public key (32) — for stealth address derivation */
  ephemeralPub: Uint8Array;
  /** Accounts required for the shield instruction */
  accounts: {
    user: Address;
    userTokenAccount: Address;
    poolState: Address;
    tokenConfig: Address;
    vault: Address;
    commitmentTree: Address;
    tokenProgram: Address;
  };
}

/**
 * Build shield instruction data (disc=12).
 *
 * Layout (after disc stripped by entrypoint):
 * - amount: u64 LE (8 bytes)
 * - npk: [u8; 32]
 * - ephemeral_pub: [u8; 32]
 */
export function buildShieldInstructionData(options: {
  amount: bigint;
  npk: Uint8Array;
  ephemeralPub: Uint8Array;
}): Uint8Array {
  const data = new Uint8Array(73);
  data[0] = INSTRUCTION.SHIELD;
  const view = new DataView(data.buffer);
  view.setBigUint64(1, options.amount, true);
  data.set(options.npk.slice(0, 32), 9);
  data.set(options.ephemeralPub.slice(0, 32), 41);
  return data;
}

/**
 * Build a complete shield instruction (disc=12).
 *
 * Shields SPL tokens into the privacy pool. Works with both
 * legacy Token program (wSOL) and Token-2022 (USDC, USDT, etc.).
 */
export function buildShieldInstruction(options: ShieldInstructionOptions): Instruction {
  const config = getConfig();
  const data = buildShieldInstructionData({
    amount: options.amount,
    npk: options.npk,
    ephemeralPub: options.ephemeralPub,
  });

  return {
    programAddress: config.utxopiaProgramId,
    accounts: [
      { address: options.accounts.user, role: AccountRole.WRITABLE_SIGNER },
      { address: options.accounts.userTokenAccount, role: AccountRole.WRITABLE },
      { address: options.accounts.poolState, role: AccountRole.WRITABLE },
      { address: options.accounts.tokenConfig, role: AccountRole.WRITABLE },
      { address: options.accounts.vault, role: AccountRole.WRITABLE },
      { address: options.accounts.commitmentTree, role: AccountRole.WRITABLE },
      { address: options.accounts.tokenProgram, role: AccountRole.READONLY },
    ],
    data,
  };
}

// =============================================================================
// Complete Redemption Instruction Builder
// =============================================================================

/** Complete redemption instruction options */
export interface CompleteRedemptionInstructionOptions {
  /** BTC transaction ID (internal byte order, 32 bytes) */
  btcTxid: Uint8Array;
  /** Raw tx size in ChadBuffer */
  txSize: number;
  /** Pool scriptPubKey for change UTXO tracking (empty = no tracking) */
  poolScript: Uint8Array;
  /** Number of consumed UTXO PDAs in remaining accounts */
  consumedUtxoCount: number;
  /** Account addresses */
  accounts: {
    poolState: Address;
    redemptionRequest: Address;
    authority: Address;
    rentRecipient: Address;
    verifiedTransaction: Address;
    lightClient: Address;
    txBuffer: Address;
    zkbtcMint: Address;
    poolVault: Address;
    completionReceipt: Address;
    poolConfig: Address;
    /** HeightIndex PDA for the VerifiedTransaction's block —
     *  `deriveHeightIndexPDA(blockHeight, config.btcLightClientProgramId)`.
     *
     *  REQUIRED. The program re-checks that the proof's block is still the canonical one at
     *  that height before it settles (audit_1 F-BTC-04): a VerifiedTransaction records a merkle
     *  proof that was valid once and is never invalidated, and the confirmation count is taken
     *  against a tip that only grows, so neither notices a reorg. Omitting this fails with
     *  InvalidSpvProof — the program locates the account by address, so its position in the
     *  list does not matter, but its absence is an error rather than a skipped check.
     */
    heightIndex: Address;
    /** Change UTXO PDA. Required when poolScript is non-empty. */
    changeUtxo?: Address;
    /** zkBTC TokenConfig PDA (credits protocol revenue) */
    tokenConfig: Address;
    /** Token program for zkBTC mint (TOKEN_2022_PROGRAM_ID or TOKEN_PROGRAM_ID). Defaults to Token-2022. */
    tokenProgram?: Address;
    /** Consumed UTXO PDAs to close */
    consumedUtxos?: Address[];
  };
}

export interface ApproveRedemptionSigningInstructionOptions {
  /** BIP-341 taproot key-spend sighash for the unsigned BTC transaction. */
  btcSighash: Uint8Array;
  /** Optional keccak256(Sign.message), where Sign.message is the TapSighash preimage. */
  ikaMessageDigest?: Uint8Array;
  /** Miner fee in satoshis, checked by the on-chain signing policy. */
  minerFeeSats: bigint | number;
  accounts: {
    poolState: Address;
    redemptionRequest: Address;
    authority: Address;
    poolConfig: Address;
    /** HeightIndex PDA for the VerifiedTransaction's block —
     *  `deriveHeightIndexPDA(blockHeight, config.btcLightClientProgramId)`.
     *
     *  REQUIRED. The program re-checks that the proof's block is still the canonical one at
     *  that height before it settles (audit_1 F-BTC-04): a VerifiedTransaction records a merkle
     *  proof that was valid once and is never invalidated, and the confirmation count is taken
     *  against a tip that only grows, so neither notices a reorg. Omitting this fails with
     *  InvalidSpvProof — the program locates the account by address, so its position in the
     *  list does not matter, but its absence is an error rather than a skipped check.
     */
    heightIndex: Address;
    ikaProgram: Address;
    ikaCoordinator: Address;
    ikaMessageApproval: Address;
    ikaDwallet: Address;
    callerProgram: Address;
    cpiAuthority: Address;
    ikaPayer: Address;
  };
}

export function buildApproveRedemptionSigningInstructionData(options: {
  btcSighash: Uint8Array;
  ikaMessageDigest?: Uint8Array;
  minerFeeSats: bigint | number;
}): Uint8Array {
  if (options.btcSighash.length !== 32) {
    throw new Error("btcSighash must be exactly 32 bytes");
  }
  if (options.ikaMessageDigest && options.ikaMessageDigest.length !== 32) {
    throw new Error("ikaMessageDigest must be exactly 32 bytes");
  }
  const data = new Uint8Array(1 + 32 + (options.ikaMessageDigest ? 32 : 0) + 8);
  const view = new DataView(data.buffer);
  let offset = 0;
  data[offset++] = INSTRUCTION.APPROVE_REDEMPTION_SIGNING;
  data.set(options.btcSighash, offset); offset += 32;
  if (options.ikaMessageDigest) {
    data.set(options.ikaMessageDigest, offset); offset += 32;
  }
  view.setBigUint64(offset, BigInt(options.minerFeeSats), true);
  return data;
}

export function buildApproveRedemptionSigningInstruction(
  options: ApproveRedemptionSigningInstructionOptions
): Instruction {
  const config = getConfig();
  return {
    programAddress: config.utxopiaProgramId,
    accounts: [
      { address: options.accounts.poolState, role: AccountRole.READONLY },
      { address: options.accounts.redemptionRequest, role: AccountRole.READONLY },
      { address: options.accounts.authority, role: AccountRole.READONLY_SIGNER },
      { address: options.accounts.poolConfig, role: AccountRole.READONLY },
      { address: options.accounts.ikaProgram, role: AccountRole.READONLY },
      { address: options.accounts.ikaCoordinator, role: AccountRole.READONLY },
      { address: options.accounts.ikaMessageApproval, role: AccountRole.WRITABLE },
      { address: options.accounts.ikaDwallet, role: AccountRole.READONLY },
      { address: options.accounts.callerProgram, role: AccountRole.READONLY },
      { address: options.accounts.cpiAuthority, role: AccountRole.READONLY },
      { address: options.accounts.ikaPayer, role: AccountRole.WRITABLE_SIGNER },
      { address: SYSTEM_PROGRAM_ADDRESS, role: AccountRole.READONLY },
    ],
    data: buildApproveRedemptionSigningInstructionData({
      btcSighash: options.btcSighash,
      ikaMessageDigest: options.ikaMessageDigest,
      minerFeeSats: options.minerFeeSats,
    }),
  };
}

/**
 * Build instruction data for COMPLETE_REDEMPTION (disc 17)
 *
 * Layout (after disc stripped):
 * - btc_txid: [u8; 32]
 * - tx_size: u32 LE
 * - pool_script_len: u8
 * - pool_script: [u8; 0-34]
 * - consumed_utxo_count: u8
 */
export function buildCompleteRedemptionInstructionData(options: {
  btcTxid: Uint8Array;
  txSize: number;
  poolScript: Uint8Array;
  consumedUtxoCount: number;
}): Uint8Array {
  const { btcTxid, txSize, poolScript, consumedUtxoCount } = options;

  const totalLen = 1 + 32 + 4 + 1 + poolScript.length + 1;
  const data = new Uint8Array(totalLen);
  const view = new DataView(data.buffer);

  let offset = 0;
  data[offset++] = INSTRUCTION.COMPLETE_REDEMPTION;

  data.set(btcTxid, offset); offset += 32;
  view.setUint32(offset, txSize, true); offset += 4;
  data[offset++] = poolScript.length;
  if (poolScript.length > 0) {
    data.set(poolScript, offset); offset += poolScript.length;
  }
  data[offset++] = consumedUtxoCount;

  return data;
}

/**
 * Build a complete redemption instruction
 *
 * Accounts (14 base + optional change + variable consumed UTXOs):
 * 0.  pool_state (writable)
 * 1.  redemption_request (writable)
 * 2.  authority (signer)
 * 3.  rent_recipient (readonly)
 * 4.  verified_transaction (readonly)
 * 5.  light_client (readonly)
 * 6.  tx_buffer (readonly)
 * 7.  zkbtc_mint (writable)
 * 8.  pool_vault (writable)
 * 9.  token_program (readonly)
 * 10. completion_receipt (writable)
 * 11. system_program (readonly)
 * 12. pool_config (readonly)
 * 13. change_utxo (writable, only when pool_script is non-empty)
 * 13/14..+N consumed_utxos (writable)
 * final. token_config (writable)
 */
export function buildCompleteRedemptionInstruction(
  options: CompleteRedemptionInstructionOptions
): Instruction {
  const config = getConfig();

  const data = buildCompleteRedemptionInstructionData({
    btcTxid: options.btcTxid,
    txSize: options.txSize,
    poolScript: options.poolScript,
    consumedUtxoCount: options.consumedUtxoCount,
  });

  const accounts: Instruction["accounts"] = [
    { address: options.accounts.poolState, role: AccountRole.WRITABLE },
    { address: options.accounts.redemptionRequest, role: AccountRole.WRITABLE },
    { address: options.accounts.authority, role: AccountRole.WRITABLE_SIGNER },
    { address: options.accounts.rentRecipient, role: AccountRole.READONLY },
    { address: options.accounts.verifiedTransaction, role: AccountRole.READONLY },
    { address: options.accounts.lightClient, role: AccountRole.READONLY },
    { address: options.accounts.txBuffer, role: AccountRole.READONLY },
    { address: options.accounts.zkbtcMint, role: AccountRole.WRITABLE },
    { address: options.accounts.poolVault, role: AccountRole.WRITABLE },
    { address: options.accounts.tokenProgram ?? TOKEN_2022_PROGRAM_ID, role: AccountRole.READONLY },
    { address: options.accounts.completionReceipt, role: AccountRole.WRITABLE },
    { address: SYSTEM_PROGRAM_ADDRESS, role: AccountRole.READONLY },
    { address: options.accounts.poolConfig, role: AccountRole.READONLY },
  ];

  if (options.poolScript.length > 0) {
    if (!options.accounts.changeUtxo) {
      throw new Error("changeUtxo is required when poolScript is non-empty");
    }
    accounts.push({ address: options.accounts.changeUtxo, role: AccountRole.WRITABLE });
  }

  // Append consumed UTXO PDAs
  if (options.accounts.consumedUtxos) {
    for (const utxo of options.accounts.consumedUtxos) {
      accounts.push({ address: utxo, role: AccountRole.WRITABLE });
    }
  }

  accounts.push({ address: options.accounts.tokenConfig, role: AccountRole.WRITABLE });
  // Located by address, so the trailing position is free — this instruction already has a
  // variable tail (change UTXO, consumed UTXOs) and the program scans rather than indexing.
  accounts.push({ address: options.accounts.heightIndex, role: AccountRole.READONLY });

  return {
    programAddress: config.utxopiaProgramId,
    accounts,
    data,
  };
}

// =============================================================================
// Cancel Redemption Instruction Builder
// =============================================================================

/** Cancel redemption instruction options */
export interface CancelRedemptionInstructionOptions {
  /** Note public key for the re-minted commitment (32 bytes) */
  npk: Uint8Array;
  accounts: {
    /** Original requester (signer; receives the closed request's rent) */
    user: Address;
    poolState: Address;
    redemptionRequest: Address;
    commitmentTree: Address;
    tokenConfig: Address;
    /**
     * Reserved UtxoRecord PDAs to release. Required when the request was in
     * Processing (mark_processing reserved these UTXOs); pass [] / omit for a
     * Pending cancel, which never reserved any. The program rejects a mismatch.
     */
    reservedUtxos?: Address[];
  };
}

/**
 * Build cancel redemption instruction data.
 *
 * Layout (after disc stripped by entrypoint):
 * - npk:        [u8; 32]
 * - utxo_count: u8  (number of reserved UtxoRecord accounts that follow; 0 for Pending)
 */
export function buildCancelRedemptionInstructionData(options: {
  npk: Uint8Array;
  reservedUtxoCount: number;
}): Uint8Array {
  const { npk, reservedUtxoCount } = options;
  if (npk.length !== 32) {
    throw new Error("npk must be 32 bytes");
  }
  // disc(1) + npk(32) + utxo_count(1)
  const data = new Uint8Array(1 + 32 + 1);
  let offset = 0;
  data[offset++] = INSTRUCTION.CANCEL_REDEMPTION;
  data.set(npk, offset);
  offset += 32;
  data[offset++] = reservedUtxoCount;
  return data;
}

/**
 * Build a cancel redemption instruction.
 *
 * Accounts (6 base + variable):
 * 0. user (writable signer)
 * 1. pool_state (writable)
 * 2. redemption_request (writable)
 * 3. commitment_tree (writable)
 * 4. system_program (readonly)
 * 5. token_config (writable)
 * 6..6+N reserved UtxoRecord PDAs (writable) — Processing cancels only
 */
export function buildCancelRedemptionInstruction(
  options: CancelRedemptionInstructionOptions
): Instruction {
  const config = getConfig();
  const reservedUtxos = options.accounts.reservedUtxos ?? [];

  const data = buildCancelRedemptionInstructionData({
    npk: options.npk,
    reservedUtxoCount: reservedUtxos.length,
  });

  const accounts: Instruction["accounts"] = [
    { address: options.accounts.user, role: AccountRole.WRITABLE_SIGNER },
    { address: options.accounts.poolState, role: AccountRole.WRITABLE },
    { address: options.accounts.redemptionRequest, role: AccountRole.WRITABLE },
    { address: options.accounts.commitmentTree, role: AccountRole.WRITABLE },
    { address: SYSTEM_PROGRAM_ADDRESS, role: AccountRole.READONLY },
    { address: options.accounts.tokenConfig, role: AccountRole.WRITABLE },
  ];

  for (const utxo of reservedUtxos) {
    accounts.push({ address: utxo, role: AccountRole.WRITABLE });
  }

  return {
    programAddress: config.utxopiaProgramId,
    accounts,
    data,
  };
}

// =============================================================================
// JoinSplit Transact Instruction Builder
// =============================================================================

/** JoinSplit transact instruction options */
export interface TransactInstructionOptions {
  /** Number of input notes being spent */
  nInputs: number;
  /** Number of output notes being created */
  nOutputs: number;
  /** Groth16 proof bytes (256 bytes) */
  proofBytes: Uint8Array;
  /** Merkle root */
  merkleRoot: Uint8Array;
  /** Bound parameters hash */
  boundParamsHash: Uint8Array;
  /** Nullifiers (32 bytes each) */
  nullifiers: Uint8Array[];
  /** Output commitments (32 bytes each) */
  commitmentsOut: Uint8Array[];
  /** Per-output stealth data: ephemeral_pub (32) + encrypted_amount (8) */
  stealthData: Uint8Array[];
  /** Reserved. Sender memos are rejected until they are proof-bound. */
  senderMemos?: Uint8Array[];
  /** Account addresses */
  accounts: {
    poolState: Address;
    commitmentTree: Address;
    vkRegistry: Address;
    user: Address;
    /** Nullifier record PDAs (one per input) */
    nullifierRecords: Address[];
    /** Required when poolState is permissioned. Appended before any proof buffer. */
    policyApproval?: Address;
  };
}

/**
 * Build transact instruction data (JoinSplit)
 *
 * Layout (after disc stripped by entrypoint):
 * - n_inputs: u8
 * - n_outputs: u8
 * - n_public_outputs: u8 (always 0 for transact)
 * - proof_source: u8 (0=inline, 1=buffer account)
 * - proof: [u8; 256] (only if proof_source=0)
 * - merkle_root: [u8; 32]
 * - bound_params_hash: [u8; 32]
 * - nullifiers: [[u8; 32]; n_inputs]
 * - commitments_out: [[u8; 32]; n_outputs]
 * - stealth_data: [ephemeral_pub(32) + encrypted_amount(8) + encrypted_token_id(32)] x n_outputs
 */
export function buildTransactInstructionData(options: {
  nInputs: number;
  nOutputs: number;
  /** Groth16 proof (256 bytes). Omit when using buffer mode. */
  proofBytes?: Uint8Array;
  merkleRoot: Uint8Array;
  boundParamsHash: Uint8Array;
  nullifiers: Uint8Array[];
  commitmentsOut: Uint8Array[];
  stealthData: Uint8Array[];
  /** 0=inline proof (default), 1=proof in separate ChadBuffer account */
  proofSource?: 0 | 1;
  /** Reserved. Sender memos are rejected until they are proof-bound. */
  senderMemos?: Uint8Array[];
}): Uint8Array {
  const { nInputs, nOutputs, proofBytes, merkleRoot, boundParamsHash, nullifiers, commitmentsOut, stealthData, senderMemos } = options;
  const proofSource = options.proofSource ?? 0;

  if (proofSource === 0 && (!proofBytes || proofBytes.length !== 256)) {
    throw new Error(`Inline mode requires 256-byte proof, got ${proofBytes?.length ?? 0}`);
  }
  if (nullifiers.length !== nInputs) {
    throw new Error(`Expected ${nInputs} nullifiers, got ${nullifiers.length}`);
  }
  if (commitmentsOut.length !== nOutputs) {
    throw new Error(`Expected ${nOutputs} commitments, got ${commitmentsOut.length}`);
  }
  if (stealthData.length !== nOutputs) {
    throw new Error(`Expected ${nOutputs} stealth data entries, got ${stealthData.length}`);
  }
  assertStealthDataRecordLengths(stealthData);

  if (senderMemos != null) {
    throw new Error("senderMemos are disabled until a proof-bound protocol version is available");
  }

  const proofSize = proofSource === 0 ? 256 : 0;
  const totalSize =
    1 + 4 + proofSize + 32 + 32 + nInputs * 32 + nOutputs * 32 + nOutputs * STEALTH_DATA_PER_OUTPUT;
  const data = new Uint8Array(totalSize);

  let offset = 0;

  // Discriminator
  data[offset++] = INSTRUCTION.TRANSACT;

  // Header (4 bytes)
  data[offset++] = nInputs;
  data[offset++] = nOutputs;
  data[offset++] = 0; // n_public_outputs = 0 for transact
  data[offset++] = proofSource;

  // Proof (256 bytes, only in inline mode)
  if (proofSource === 0 && proofBytes) {
    data.set(proofBytes, offset);
    offset += 256;
  }

  // Merkle root (32 bytes)
  data.set(merkleRoot, offset);
  offset += 32;

  // Bound params hash (32 bytes)
  data.set(boundParamsHash, offset);
  offset += 32;

  // Nullifiers
  for (const nullifier of nullifiers) {
    data.set(nullifier, offset);
    offset += 32;
  }

  // Output commitments
  for (const commitment of commitmentsOut) {
    data.set(commitment, offset);
    offset += 32;
  }

  // Stealth data (ephemeral_pub + encrypted_amount per output)
  for (const sd of stealthData) {
    data.set(sd, offset);
    offset += STEALTH_DATA_PER_OUTPUT;
  }

  return data;
}

/**
 * Build a complete JoinSplit transact instruction
 *
 * Accounts:
 * 0. pool_state (writable)
 * 1. commitment_tree (writable)
 * 2. vk_registry (read)
 * 3. user (signer)
 * 4. system_program (read)
 * 5..5+N nullifier_records (writable)
 */
export function buildTransactInstruction(options: TransactInstructionOptions): Instruction {
  const config = getConfig();

  const data = buildTransactInstructionData({
    nInputs: options.nInputs,
    nOutputs: options.nOutputs,
    proofBytes: options.proofBytes,
    merkleRoot: options.merkleRoot,
    boundParamsHash: options.boundParamsHash,
    nullifiers: options.nullifiers,
    commitmentsOut: options.commitmentsOut,
    stealthData: options.stealthData,
    senderMemos: options.senderMemos,
  });

  const accounts: Instruction["accounts"] = [
    { address: options.accounts.poolState, role: AccountRole.WRITABLE },
    { address: options.accounts.commitmentTree, role: AccountRole.WRITABLE },
    { address: options.accounts.vkRegistry, role: AccountRole.READONLY },
    { address: options.accounts.user, role: AccountRole.WRITABLE_SIGNER },
    { address: SYSTEM_PROGRAM_ADDRESS, role: AccountRole.READONLY },
  ];

  // Nullifier records (writable PDAs)
  for (const nr of options.accounts.nullifierRecords) {
    accounts.push({ address: nr, role: AccountRole.WRITABLE });
  }
  if (options.accounts.policyApproval) {
    accounts.push({ address: options.accounts.policyApproval, role: AccountRole.WRITABLE });
    accounts.push({
      address: config.policyProgramId ?? config.utxopiaProgramId,
      role: AccountRole.READONLY,
    });
  }

  return {
    programAddress: config.utxopiaProgramId,
    accounts,
    data,
  };
}

// =============================================================================
// JoinSplit + BTC Redeem Instruction Builder (disc=16)
// =============================================================================

/**
 * Build instruction data for REDEEM (disc=15) — atomic JoinSplit + BTC withdrawal (multi-output)
 *
 * Combines Groth16 proof verification with RedemptionRequest PDA creation.
 * Supports 1..3 public outputs, each creating a separate RedemptionRequest.
 *
 * Layout (4-byte common header):
 * - n_inputs: u8
 * - n_outputs: u8
 * - n_public_outputs: u8 (1..3)
 * - proof_source: u8 (0=inline, 1=buffer account)
 * - proof: [u8; 256] (only if proof_source=0)
 * - merkle_root: [u8; 32]
 * - bound_params_hash: [u8; 32]
 * - nullifiers: [[u8; 32]; n_inputs]
 * - commitments_out: [[u8; 32]; n_outputs]
 * - stealth_data: [ephemeral_pub(32) + encrypted_amount(8) + encrypted_token_id(32)] x n_tree_outputs
 * - For each public output: amount(8) + script_len(1) + script(var) + nonce(8)
 */
export function buildRedeemInstructionData(options: {
  nInputs: number;
  nOutputs: number;
  /** Number of public (redeem) outputs. Defaults to redeemAmounts.length. */
  nPublicOutputs?: number;
  /** Groth16 proof (256 bytes). Omit when using buffer mode. */
  proofBytes?: Uint8Array;
  merkleRoot: Uint8Array;
  boundParamsHash: Uint8Array;
  nullifiers: Uint8Array[];
  commitmentsOut: Uint8Array[];
  /** Stealth data for tree outputs only (n_tree_outputs entries, 72 bytes each) */
  stealthData: Uint8Array[];
  /** Amount(s) to redeem in satoshis — single or array */
  redeemAmounts: bigint[];
  /** Bitcoin scriptPubKey(s) (raw bytes, max 62 each) — single or array */
  btcScripts: Uint8Array[];
  /** Unique request nonce(s) — single or array */
  requestNonces: bigint[];
  /** 0=inline proof (default), 1=proof in separate ChadBuffer account */
  proofSource?: 0 | 1;
}): Uint8Array {
  const {
    nInputs, nOutputs, proofBytes, merkleRoot, boundParamsHash,
    nullifiers, commitmentsOut, stealthData, redeemAmounts, btcScripts, requestNonces,
  } = options;
  const nPublicOutputs = options.nPublicOutputs ?? redeemAmounts.length;
  const proofSource = options.proofSource ?? 0;

  if (proofSource === 0 && (!proofBytes || proofBytes.length !== 256)) {
    throw new Error(`Inline mode requires 256-byte proof, got ${proofBytes?.length ?? 0}`);
  }
  if (nPublicOutputs < 1 || nPublicOutputs > 3) {
    throw new Error(`nPublicOutputs must be 1-3, got ${nPublicOutputs}`);
  }
  const nTreeOutputs = nOutputs - nPublicOutputs;
  if (nTreeOutputs < 0) {
    throw new Error(`nOutputs (${nOutputs}) must be >= nPublicOutputs (${nPublicOutputs})`);
  }
  if (nullifiers.length !== nInputs) {
    throw new Error(`Expected ${nInputs} nullifiers, got ${nullifiers.length}`);
  }
  if (commitmentsOut.length !== nOutputs) {
    throw new Error(`Expected ${nOutputs} commitments, got ${commitmentsOut.length}`);
  }
  if (stealthData.length !== nTreeOutputs) {
    throw new Error(`Expected ${nTreeOutputs} stealth data entries, got ${stealthData.length}`);
  }
  assertStealthDataRecordLengths(stealthData);
  if (redeemAmounts.length !== nPublicOutputs) {
    throw new Error(`Expected ${nPublicOutputs} redeem amounts, got ${redeemAmounts.length}`);
  }
  if (btcScripts.length !== nPublicOutputs) {
    throw new Error(`Expected ${nPublicOutputs} BTC scripts, got ${btcScripts.length}`);
  }
  if (requestNonces.length !== nPublicOutputs) {
    throw new Error(`Expected ${nPublicOutputs} request nonces, got ${requestNonces.length}`);
  }
  for (let k = 0; k < nPublicOutputs; k++) {
    if (btcScripts[k].length === 0 || btcScripts[k].length > 62) {
      throw new Error(`BTC script[${k}] must be 1-62 bytes, got ${btcScripts[k].length}`);
    }
  }

  const proofSize = proofSource === 0 ? 256 : 0;
  let totalScriptLen = 0;
  for (const s of btcScripts) totalScriptLen += s.length;
  const totalSize = 1 + 4 + proofSize + 32 + 32
    + (nInputs * 32) + (nOutputs * 32) + (nTreeOutputs * STEALTH_DATA_PER_OUTPUT)
    + nPublicOutputs * (8 + 1 + 8) + totalScriptLen;

  const data = new Uint8Array(totalSize);
  const view = new DataView(data.buffer);
  let offset = 0;

  // Discriminator
  data[offset++] = INSTRUCTION.REDEEM;

  // Header (4 bytes)
  data[offset++] = nInputs;
  data[offset++] = nOutputs;
  data[offset++] = nPublicOutputs;
  data[offset++] = proofSource;

  // Proof (256 bytes, only in inline mode)
  if (proofSource === 0 && proofBytes) {
    data.set(proofBytes, offset);
    offset += 256;
  }

  // Merkle root (32 bytes)
  data.set(merkleRoot, offset);
  offset += 32;

  // Bound params hash (32 bytes)
  data.set(boundParamsHash, offset);
  offset += 32;

  // Nullifiers
  for (const nullifier of nullifiers) {
    data.set(nullifier, offset);
    offset += 32;
  }

  // Output commitments (all n_outputs, last n_public_outputs = redeem)
  for (const commitment of commitmentsOut) {
    data.set(commitment, offset);
    offset += 32;
  }

  // Stealth data for tree outputs only (72 bytes each)
  for (const sd of stealthData) {
    data.set(sd, offset);
    offset += STEALTH_DATA_PER_OUTPUT;
  }

  // Per-output redeem data: amount(8) + script_len(1) + script(var) + nonce(8)
  for (let k = 0; k < nPublicOutputs; k++) {
    view.setBigUint64(offset, redeemAmounts[k], true);
    offset += 8;
    data[offset++] = btcScripts[k].length;
    data.set(btcScripts[k], offset);
    offset += btcScripts[k].length;
    view.setBigUint64(offset, requestNonces[k], true);
    offset += 8;
  }

  return data;
}

// =============================================================================
// Public Unshield Instruction Builder
// =============================================================================

/** Unshield instruction options (multi-output) */
export interface UnshieldInstructionOptions {
  /** Number of input notes being spent */
  nInputs: number;
  /** Number of output notes (includes burn outputs at end) */
  nOutputs: number;
  /** Number of public (unshield) outputs. Defaults to 1. */
  nPublicOutputs?: number;
  /** Groth16 proof bytes (256 bytes) */
  proofBytes: Uint8Array;
  /** Merkle root */
  merkleRoot: Uint8Array;
  /** Bound parameters hash */
  boundParamsHash: Uint8Array;
  /** Nullifiers (32 bytes each) */
  nullifiers: Uint8Array[];
  /** Output commitments (32 bytes each, last nPublicOutputs = burn commitments) */
  commitmentsOut: Uint8Array[];
  /** Per-output stealth data for tree outputs only */
  stealthData: Uint8Array[];
  /** Amount(s) being unshielded */
  unshieldAmounts: bigint[];
  /** Account addresses */
  accounts: {
    poolState: Address;
    commitmentTree: Address;
    vkRegistry: Address;
    user: Address;
    tokenConfig: Address;
    vault: Address;
    /** Token program for the mint (TOKEN_2022_PROGRAM_ID or TOKEN_PROGRAM_ID). Defaults to Token-2022. */
    tokenProgram?: Address;
    /** Public destination accounts (SPL token accounts, or direct recipients for native SOL) */
    recipientTokenAccounts: Address[];
    /** Nullifier record PDAs (one per input) */
    nullifierRecords: Address[];
    /** Required when poolState is permissioned. Appended before any proof buffer. */
    policyApproval?: Address;
  };
}

/**
 * Build unshield instruction data (multi-output, disc=14).
 *
 * Layout (4-byte common header):
 * - disc(1) + n_inputs(1) + n_outputs(1) + n_public_outputs(1) + proof_source(1)
 * - proof(256) if inline
 * - merkle_root(32) + bound_params_hash(32)
 * - nullifiers(N*32) + commitments_out(M*32)
 * - stealth_data(n_tree_outputs * 72)
 * - amounts[P] (each u64 LE)
 *
 * Recipients come from the accounts array. Ordinary SPL outputs use token
 * accounts; native-SOL outputs use the recipient accounts directly.
 */
export function buildUnshieldInstructionData(options: {
  nInputs: number;
  nOutputs: number;
  /** Number of public (unshield) outputs. Defaults to 1. */
  nPublicOutputs?: number;
  /** Groth16 proof (256 bytes). Omit when using buffer mode. */
  proofBytes?: Uint8Array;
  merkleRoot: Uint8Array;
  boundParamsHash: Uint8Array;
  nullifiers: Uint8Array[];
  commitmentsOut: Uint8Array[];
  stealthData: Uint8Array[];
  /** Amount(s) being unshielded — single or array */
  unshieldAmounts: bigint[];
  /** 0=inline proof (default), 1=proof in separate ChadBuffer account */
  proofSource?: 0 | 1;
}): Uint8Array {
  const { nInputs, nOutputs, proofBytes, merkleRoot, boundParamsHash, nullifiers, commitmentsOut, stealthData, unshieldAmounts } = options;
  const nPublicOutputs = options.nPublicOutputs ?? unshieldAmounts.length;
  const proofSource = options.proofSource ?? 0;

  if (proofSource === 0 && (!proofBytes || proofBytes.length !== 256)) {
    throw new Error(`Inline mode requires 256-byte proof, got ${proofBytes?.length ?? 0}`);
  }
  if (nPublicOutputs < 1 || nPublicOutputs > 3) {
    throw new Error(`nPublicOutputs must be 1-3, got ${nPublicOutputs}`);
  }
  if (nullifiers.length !== nInputs) {
    throw new Error(`Expected ${nInputs} nullifiers, got ${nullifiers.length}`);
  }
  if (commitmentsOut.length !== nOutputs) {
    throw new Error(`Expected ${nOutputs} commitments, got ${commitmentsOut.length}`);
  }
  const nTreeOutputs = nOutputs - nPublicOutputs;
  if (nTreeOutputs < 0) {
    throw new Error(`nOutputs (${nOutputs}) must be >= nPublicOutputs (${nPublicOutputs})`);
  }
  if (stealthData.length !== nTreeOutputs) {
    throw new Error(`Expected ${nTreeOutputs} stealth data entries (tree outputs), got ${stealthData.length}`);
  }
  assertStealthDataRecordLengths(stealthData);
  if (unshieldAmounts.length !== nPublicOutputs) {
    throw new Error(`Expected ${nPublicOutputs} unshield amounts, got ${unshieldAmounts.length}`);
  }

  const proofSize = proofSource === 0 ? 256 : 0;
  const totalSize = 1 + 4 + proofSize + 32 + 32 + (nInputs * 32) + (nOutputs * 32) + (nTreeOutputs * STEALTH_DATA_PER_OUTPUT) + (nPublicOutputs * 8);
  const data = new Uint8Array(totalSize);
  const view = new DataView(data.buffer);

  let offset = 0;

  // Discriminator
  data[offset++] = INSTRUCTION.UNSHIELD;

  // Header (4 bytes)
  data[offset++] = nInputs;
  data[offset++] = nOutputs;
  data[offset++] = nPublicOutputs;
  data[offset++] = proofSource;

  // Proof (256 bytes, only in inline mode)
  if (proofSource === 0 && proofBytes) {
    data.set(proofBytes, offset);
    offset += 256;
  }

  // Merkle root (32 bytes)
  data.set(merkleRoot, offset);
  offset += 32;

  // Bound params hash (32 bytes)
  data.set(boundParamsHash, offset);
  offset += 32;

  // Nullifiers
  for (const nullifier of nullifiers) {
    data.set(nullifier, offset);
    offset += 32;
  }

  // Output commitments (all n_outputs, last nPublicOutputs = burn)
  for (const commitment of commitmentsOut) {
    data.set(commitment, offset);
    offset += 32;
  }

  // Stealth data for tree outputs only
  for (const sd of stealthData) {
    data.set(sd, offset);
    offset += STEALTH_DATA_PER_OUTPUT;
  }

  // Per-output unshield amounts (u64 LE each)
  for (const amount of unshieldAmounts) {
    view.setBigUint64(offset, amount, true);
    offset += 8;
  }

  return data;
}

/**
 * Build a complete unshield instruction (multi-output, disc=14)
 *
 * Accounts:
 * 0. pool_state (read)
 * 1. commitment_tree (writable)
 * 2. vk_registry (read)
 * 3. user (signer)
 * 4. system_program (read)
 * 5. token_config (writable)
 * 6. vault (writable)
 * 7. token_program (read)
 * 8..8+P public destinations (SPL token accounts or native-SOL recipients)
 * 8+P..8+P+N nullifier_records (writable)
 */
export function buildUnshieldInstruction(options: UnshieldInstructionOptions): Instruction {
  const config = getConfig();
  const nPublicOutputs = options.nPublicOutputs ?? options.unshieldAmounts.length;

  const data = buildUnshieldInstructionData({
    nInputs: options.nInputs,
    nOutputs: options.nOutputs,
    nPublicOutputs,
    proofBytes: options.proofBytes,
    merkleRoot: options.merkleRoot,
    boundParamsHash: options.boundParamsHash,
    nullifiers: options.nullifiers,
    commitmentsOut: options.commitmentsOut,
    stealthData: options.stealthData,
    unshieldAmounts: options.unshieldAmounts,
  });

  const accounts: Instruction["accounts"] = [
    { address: options.accounts.poolState, role: AccountRole.WRITABLE },
    { address: options.accounts.commitmentTree, role: AccountRole.WRITABLE },
    { address: options.accounts.vkRegistry, role: AccountRole.READONLY },
    { address: options.accounts.user, role: AccountRole.WRITABLE_SIGNER },
    { address: SYSTEM_PROGRAM_ADDRESS, role: AccountRole.READONLY },
    { address: options.accounts.tokenConfig, role: AccountRole.WRITABLE },
    { address: options.accounts.vault, role: AccountRole.WRITABLE },
    { address: options.accounts.tokenProgram ?? TOKEN_2022_PROGRAM_ID, role: AccountRole.READONLY },
  ];

  // Public destinations (one per public output)
  for (const rta of options.accounts.recipientTokenAccounts) {
    accounts.push({ address: rta, role: AccountRole.WRITABLE });
  }

  // Nullifier records (writable PDAs)
  for (const nr of options.accounts.nullifierRecords) {
    accounts.push({ address: nr, role: AccountRole.WRITABLE });
  }
  if (options.accounts.policyApproval) {
    accounts.push({ address: options.accounts.policyApproval, role: AccountRole.WRITABLE });
    accounts.push({
      address: config.policyProgramId ?? config.utxopiaProgramId,
      role: AccountRole.READONLY,
    });
  }

  return {
    programAddress: config.utxopiaProgramId,
    accounts,
    data,
  };
}

// Removed request_redemption/public_redeem instructions are reserved; use REDEEM for proof-checked BTC withdrawals.
// =============================================================================
// Timelocked Pool Update Instruction Builders
// =============================================================================

/** Propose pool update instruction options */
export interface ProposePoolUpdateOptions {
  /** New minimum deposit in satoshis */
  minDeposit: bigint;
  /** New maximum deposit in satoshis */
  maxDeposit: bigint;
  /** New service fee base in satoshis */
  serviceFee: bigint;
  /** Service fee in basis points (e.g. 30 = 0.3%). Applied immediately, no timelock. */
  serviceFeeBps?: number;
  /** Account addresses */
  accounts: {
    poolState: Address;
    authority: Address;
  };
}

/**
 * Build propose_pool_update instruction data
 *
 * Layout: discriminator(1) + min_deposit(8) + max_deposit(8) + service_fee(8) + [service_fee_bps(2)] = 25 or 27 bytes
 */
export function buildProposePoolUpdateInstructionData(
  minDeposit: bigint,
  maxDeposit: bigint,
  serviceFee: bigint,
  serviceFeeBps?: number,
): Uint8Array {
  const hasBps = serviceFeeBps !== undefined;
  const data = new Uint8Array(hasBps ? 27 : 25);
  const view = new DataView(data.buffer);

  data[0] = INSTRUCTION.PROPOSE_POOL_UPDATE;
  view.setBigUint64(1, minDeposit, true);
  view.setBigUint64(9, maxDeposit, true);
  view.setBigUint64(17, serviceFee, true);

  if (hasBps) {
    view.setUint16(25, serviceFeeBps, true);
  }

  return data;
}

/**
 * Build a complete propose_pool_update instruction
 *
 * Accounts:
 * 0. pool_state (writable)
 * 1. authority (signer)
 */
export function buildProposePoolUpdateInstruction(options: ProposePoolUpdateOptions): Instruction {
  const config = getConfig();

  const data = buildProposePoolUpdateInstructionData(
    options.minDeposit,
    options.maxDeposit,
    options.serviceFee,
    options.serviceFeeBps,
  );

  return {
    programAddress: config.utxopiaProgramId,
    accounts: [
      { address: options.accounts.poolState, role: AccountRole.WRITABLE },
      { address: options.accounts.authority, role: AccountRole.WRITABLE_SIGNER },
    ],
    data,
  };
}

/** Execute pool update instruction options */
export interface ExecutePoolUpdateOptions {
  accounts: {
    poolState: Address;
    /** Pool authority — must sign (execute is authority-only; audit f11). */
    authority: Address;
  };
}

/**
 * Build execute_pool_update instruction data
 *
 * Layout: discriminator(1) = 1 byte
 */
export function buildExecutePoolUpdateInstructionData(): Uint8Array {
  return new Uint8Array([INSTRUCTION.EXECUTE_POOL_UPDATE]);
}

/**
 * Build a complete execute_pool_update instruction (authority-only)
 *
 * Accounts:
 * 0. pool_state (writable)
 * 1. authority (signer)
 */
export function buildExecutePoolUpdateInstruction(options: ExecutePoolUpdateOptions): Instruction {
  const config = getConfig();

  return {
    programAddress: config.utxopiaProgramId,
    accounts: [
      { address: options.accounts.poolState, role: AccountRole.WRITABLE },
      { address: options.accounts.authority, role: AccountRole.READONLY_SIGNER },
    ],
    data: buildExecutePoolUpdateInstructionData(),
  };
}

/** Cancel pool update instruction options */
export interface CancelPoolUpdateOptions {
  accounts: {
    poolState: Address;
    authority: Address;
  };
}

/**
 * Build cancel_pool_update instruction data
 *
 * Layout: discriminator(1) = 1 byte
 */
export function buildCancelPoolUpdateInstructionData(): Uint8Array {
  return new Uint8Array([INSTRUCTION.CANCEL_POOL_UPDATE]);
}

/**
 * Build a complete cancel_pool_update instruction
 *
 * Accounts:
 * 0. pool_state (writable)
 * 1. authority (signer)
 */
export function buildCancelPoolUpdateInstruction(options: CancelPoolUpdateOptions): Instruction {
  const config = getConfig();

  return {
    programAddress: config.utxopiaProgramId,
    accounts: [
      { address: options.accounts.poolState, role: AccountRole.WRITABLE },
      { address: options.accounts.authority, role: AccountRole.WRITABLE_SIGNER },
    ],
    data: buildCancelPoolUpdateInstructionData(),
  };
}

// =============================================================================
// Rotate Tree Instruction Builder (disc=20)
// =============================================================================

/** Rotate tree instruction options */
export interface RotateTreeOptions {
  accounts: {
    poolState: Address;
    currentTree: Address;
    newTree: Address;
    authority: Address;
    systemProgram: Address;
  };
}

/**
 * Build rotate_tree instruction data (disc=20, no payload)
 */
export function buildRotateTreeInstructionData(): Uint8Array {
  return new Uint8Array([INSTRUCTION.ROTATE_TREE]);
}

/**
 * Build a complete rotate_tree instruction
 *
 * Accounts:
 * 0. pool_state    (writable)
 * 1. current_tree  (writable) — must be full
 * 2. new_tree      (writable) — to be created
 * 3. authority     (signer)
 * 4. system_program
 */
export function buildRotateTreeInstruction(options: RotateTreeOptions): Instruction {
  const config = getConfig();

  return {
    programAddress: config.utxopiaProgramId,
    accounts: [
      { address: options.accounts.poolState, role: AccountRole.WRITABLE },
      { address: options.accounts.currentTree, role: AccountRole.WRITABLE },
      { address: options.accounts.newTree, role: AccountRole.WRITABLE },
      { address: options.accounts.authority, role: AccountRole.WRITABLE_SIGNER },
      { address: options.accounts.systemProgram, role: AccountRole.READONLY },
    ],
    data: buildRotateTreeInstructionData(),
  };
}

/** Only policy decisions are delegated; asset-bearing pool/tree state stays on Solana. */
export type MagicBlockDelegateTarget = "policyApproval";

export interface MagicBlockDelegateInstructionOptions {
  accounts: {
    payer: Address;
    authority: Address;
    poolState: Address;
    delegatedAccount: Address;
    ownerProgram?: Address;
    buffer: Address;
    delegationRecord: Address;
    delegationMetadata: Address;
    systemProgram?: Address;
  };
  target: MagicBlockDelegateTarget;
  commitFrequencyMs: number;
  /** Required: the PER's TEE validator. An unpinned delegation is rejected on-chain. */
  validator: Address;
}

export interface MagicBlockCommitInstructionOptions {
  accounts: {
    payer: Address;
    /** Required for undelegation. Commit-only callers may omit it. */
    authority?: Address;
    magicContext?: Address;
    magicProgram?: Address;
    poolState: Address;
    commitmentTree: Address;
    nullifierAccounts: Address[];
  };
  nullifierHashes: Uint8Array[];
  allowUndelegation?: boolean;
}

export type MagicBlockPerPermissionOperation = "create" | "update" | "close";

export interface MagicBlockPerPermissionMember {
  address: Address;
  flags: number;
}

export interface MagicBlockPerPermissionInstructionOptions {
  operation: MagicBlockPerPermissionOperation;
  target: MagicBlockDelegateTarget;
  members?: MagicBlockPerPermissionMember[];
  accounts: {
    authority: Address;
    poolState: Address;
    permissionedAccount: Address;
    permission: Address;
    ephemeralVault?: Address;
    magicProgram?: Address;
    permissionProgram?: Address;
  };
}

function magicBlockDelegateTargetByte(target: MagicBlockDelegateTarget): number {
  if (target === "policyApproval") return 2;
  throw new Error(`Unsupported MagicBlock delegate target: ${target}`);
}

/**
 * Build magicblock_delegate instruction data (disc=32).
 */
export function buildMagicBlockDelegateInstructionData(options: {
  target: MagicBlockDelegateTarget;
  commitFrequencyMs: number;
  validator: Address;
}): Uint8Array {
  if (!Number.isInteger(options.commitFrequencyMs) || options.commitFrequencyMs < 0) {
    throw new Error("commitFrequencyMs must be a non-negative u32");
  }
  if (options.commitFrequencyMs > 0xffffffff) {
    throw new Error("commitFrequencyMs must fit in u32");
  }

  const data = new Uint8Array(38);
  const view = new DataView(data.buffer);
  data[0] = INSTRUCTION.MAGICBLOCK_DELEGATE;
  data[1] = magicBlockDelegateTargetByte(options.target);
  view.setUint32(2, options.commitFrequencyMs, true);
  data.set(addressToBytes(options.validator), 6);
  return data;
}

/**
 * Build a complete magicblock_delegate instruction.
 */
export function buildMagicBlockDelegateInstruction(
  options: MagicBlockDelegateInstructionOptions
): Instruction {
  const config = getConfig();

  return {
    programAddress: config.policyProgramId ?? config.utxopiaProgramId,
    accounts: [
      { address: options.accounts.payer, role: AccountRole.WRITABLE_SIGNER },
      { address: options.accounts.authority, role: AccountRole.READONLY_SIGNER },
      { address: options.accounts.poolState, role: AccountRole.READONLY },
      { address: options.accounts.delegatedAccount, role: AccountRole.WRITABLE },
      {
        address: options.accounts.ownerProgram ?? config.policyProgramId ?? config.utxopiaProgramId,
        role: AccountRole.READONLY,
      },
      { address: options.accounts.buffer, role: AccountRole.WRITABLE },
      { address: options.accounts.delegationRecord, role: AccountRole.WRITABLE },
      { address: options.accounts.delegationMetadata, role: AccountRole.WRITABLE },
      { address: options.accounts.systemProgram ?? SYSTEM_PROGRAM_ADDRESS, role: AccountRole.READONLY },
      { address: MAGICBLOCK_DELEGATION_PROGRAM_ID, role: AccountRole.READONLY },
    ],
    data: buildMagicBlockDelegateInstructionData({
      target: options.target,
      commitFrequencyMs: options.commitFrequencyMs,
      validator: options.validator,
    }),
  };
}

/**
 * Build magicblock_commit instruction data (disc=33).
 */
export function buildMagicBlockCommitInstructionData(options: {
  nullifierHashes: Uint8Array[];
  allowUndelegation?: boolean;
}): Uint8Array {
  if (
    options.nullifierHashes.length === 0 ||
    options.nullifierHashes.length > 10
  ) {
    throw new Error("MagicBlock commits require 1-10 nullifier hashes");
  }
  for (const hash of options.nullifierHashes) {
    if (hash.length !== 32) {
      throw new Error("Each MagicBlock commit nullifier hash must be 32 bytes");
    }
  }
  const data = new Uint8Array(4 + options.nullifierHashes.length * 32);
  data[0] = INSTRUCTION.MAGICBLOCK_COMMIT;
  data[1] = 1;
  data[2] = options.allowUndelegation ? 1 : 0;
  data[3] = options.nullifierHashes.length;
  options.nullifierHashes.forEach((hash, index) => data.set(hash, 4 + index * 32));
  return data;
}

/**
 * Build a complete magicblock_commit instruction.
 */
export function buildMagicBlockCommitInstruction(
  options: MagicBlockCommitInstructionOptions
): Instruction {
  const config = getConfig();
  if (
    options.accounts.nullifierAccounts.length !== options.nullifierHashes.length
  ) {
    throw new Error("Nullifier account and hash counts must match");
  }

  const accounts = [
    { address: options.accounts.payer, role: AccountRole.READONLY_SIGNER },
    {
      address: options.accounts.authority ?? options.accounts.payer,
      role: AccountRole.READONLY_SIGNER,
    },
    {
      address: options.accounts.magicContext ?? MAGICBLOCK_MAGIC_CONTEXT_ID,
      role: AccountRole.WRITABLE,
    },
    { address: options.accounts.magicProgram ?? MAGICBLOCK_MAGIC_PROGRAM_ID, role: AccountRole.READONLY },
    { address: options.accounts.poolState, role: AccountRole.WRITABLE },
    { address: options.accounts.commitmentTree, role: AccountRole.WRITABLE },
  ];

  for (const nullifier of options.accounts.nullifierAccounts) {
    accounts.push({ address: nullifier, role: AccountRole.WRITABLE });
  }

  return {
    programAddress: config.utxopiaProgramId,
    accounts,
    data: buildMagicBlockCommitInstructionData({
      nullifierHashes: options.nullifierHashes,
      allowUndelegation: options.allowUndelegation,
    }),
  };
}

function magicBlockPerOperationByte(operation: MagicBlockPerPermissionOperation): number {
  if (operation === "create") return 0;
  if (operation === "update") return 1;
  if (operation === "close") return 2;
  throw new Error(`Unsupported MagicBlock PER operation: ${operation}`);
}

export function buildMagicBlockPerPermissionInstructionData(options: {
  operation: MagicBlockPerPermissionOperation;
  target: MagicBlockDelegateTarget;
  members?: MagicBlockPerPermissionMember[];
}): Uint8Array {
  const members = options.members ?? [];
  if (options.operation === "close") {
    if (members.length !== 0) {
      throw new Error("Closing a MagicBlock PER permission does not accept members");
    }
  } else {
    if (members.length === 0 || members.length > MAGICBLOCK_MAX_PER_MEMBERS) {
      throw new Error(
        `MagicBlock PER permissions require 1-${MAGICBLOCK_MAX_PER_MEMBERS} members`
      );
    }
    if (!members.some((member) => (member.flags & MAGICBLOCK_PER_MEMBER_FLAGS.authority) !== 0)) {
      throw new Error("MagicBlock PER permissions must retain an authority member");
    }
  }

  const allowedFlags = Object.values(MAGICBLOCK_PER_MEMBER_FLAGS).reduce(
    (combined, flag) => combined | flag,
    0
  );
  const data = new Uint8Array(4 + members.length * 33);
  data[0] = INSTRUCTION.MAGICBLOCK_PER_PERMISSION;
  data[1] = magicBlockPerOperationByte(options.operation);
  data[2] = magicBlockDelegateTargetByte(options.target);
  data[3] = members.length;
  members.forEach((member, index) => {
    if (!Number.isInteger(member.flags) || member.flags < 0 || member.flags > 0xff) {
      throw new Error("MagicBlock PER member flags must fit in u8");
    }
    if ((member.flags & ~allowedFlags) !== 0) {
      throw new Error("MagicBlock PER member flags contain unsupported bits");
    }
    const offset = 4 + index * 33;
    data[offset] = member.flags;
    data.set(addressToBytes(member.address), offset + 1);
  });
  return data;
}

export function buildMagicBlockPerPermissionInstruction(
  options: MagicBlockPerPermissionInstructionOptions
): Instruction {
  const config = getConfig();
  return {
    programAddress: config.policyProgramId ?? config.utxopiaProgramId,
    accounts: [
      { address: options.accounts.authority, role: AccountRole.READONLY_SIGNER },
      { address: options.accounts.poolState, role: AccountRole.READONLY },
      { address: options.accounts.permissionedAccount, role: AccountRole.WRITABLE },
      { address: options.accounts.permission, role: AccountRole.WRITABLE },
      {
        address: options.accounts.ephemeralVault ?? MAGICBLOCK_EPHEMERAL_VAULT_ID,
        role: AccountRole.WRITABLE,
      },
      {
        address: options.accounts.magicProgram ?? MAGICBLOCK_MAGIC_PROGRAM_ID,
        role: AccountRole.READONLY,
      },
      {
        address: options.accounts.permissionProgram ?? MAGICBLOCK_PERMISSION_PROGRAM_ID,
        role: AccountRole.READONLY,
      },
    ],
    data: buildMagicBlockPerPermissionInstructionData(options),
  };
}

export type PolicyApprovalDecision = "approve" | "reject";

/** Must match `MAX_INTENT_PARTS` in the asset program. */
export const MAX_POLICY_INTENT_PARTS = 3;

/**
 * Build the intent parts a spend's policy approval commits to.
 *
 * The layout mirrors what the asset program hashes, and deliberately carries no
 * proof machinery: the merkle root, output commitments and stealth data all move
 * when a spend is re-proved, and a spend has to be re-proved whenever the root
 * advances — which is exactly while the authority is deciding. Binding them
 * would make every approval expire the moment someone else deposits.
 *
 * Amounts and BTC scripts are encoded exactly as the instruction encodes them,
 * because the program hashes the same trailing bytes it parses.
 */
export function buildPolicyIntentParts(
  options:
    | { action: 13; nullifiers: Uint8Array[] }
    | {
        action: 14;
        nullifiers: Uint8Array[];
        unshieldAmounts: bigint[];
        /** OWNER of each recipient token account — what the payout credits. */
        recipientOwners: Uint8Array[];
      }
    | {
        action: 15;
        nullifiers: Uint8Array[];
        redeemAmounts: bigint[];
        btcScripts: Uint8Array[];
        requestNonces: bigint[];
      },
): Uint8Array[] {
  const nullifiers = concatBytes(options.nullifiers);

  if (options.action === INSTRUCTION.TRANSACT) {
    // An internal transfer reveals no amount and no external destination, so the
    // only thing being decided is whether these notes may be spent at all.
    return [nullifiers];
  }

  if (options.action === INSTRUCTION.UNSHIELD) {
    const amounts = new Uint8Array(options.unshieldAmounts.length * 8);
    const view = new DataView(amounts.buffer);
    options.unshieldAmounts.forEach((amount, i) => view.setBigUint64(i * 8, amount, true));
    for (const owner of options.recipientOwners) {
      if (owner.length !== 32) throw new Error("recipient owner must be 32 bytes");
    }
    return [nullifiers, amounts, concatBytes(options.recipientOwners)];
  }

  // redeem: amount(8) + script_len(1) + script(var) + nonce(8), per output
  const { redeemAmounts, btcScripts, requestNonces } = options;
  if (redeemAmounts.length !== btcScripts.length || btcScripts.length !== requestNonces.length) {
    throw new Error("redeem amounts, scripts and nonces must be the same length");
  }
  const size = redeemAmounts.length * 17 + btcScripts.reduce((n, s) => n + s.length, 0);
  const outputs = new Uint8Array(size);
  const view = new DataView(outputs.buffer);
  let offset = 0;
  for (let k = 0; k < redeemAmounts.length; k++) {
    view.setBigUint64(offset, redeemAmounts[k], true);
    offset += 8;
    outputs[offset++] = btcScripts[k].length;
    outputs.set(btcScripts[k], offset);
    offset += btcScripts[k].length;
    view.setBigUint64(offset, requestNonces[k], true);
    offset += 8;
  }
  return [nullifiers, outputs];
}

function concatBytes(chunks: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(chunks.reduce((n, c) => n + c.length, 0));
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

/**
 * Mirror of `compute_policy_request_hash` in the asset program.
 *
 * The approval commits to what the authority decides — which notes are spent,
 * how much leaves, and where it goes — never to the whole instruction. Binding
 * the payload would tie an approval to one exact proof, and a spend has to be
 * re-proved whenever the merkle root moves on, which is precisely while the
 * authority is deciding.
 *
 * Parts, in the order the program hashes them:
 * - `transact`: [nullifiers]
 * - `unshield`: [nullifiers, amounts, recipientOwners]
 * - `redeem`:   [nullifiers, amountsScriptsAndNonces]
 * - value entry (`shield` / `completeDeposit`): [instructionDataWithoutDiscriminator]
 *
 * Each part is folded to a fixed 32 bytes before the parts are joined, so their
 * boundaries cannot be slid. Any drift from the on-chain version makes every
 * Verified spend fail with PolicyApprovalMismatch.
 */
export function buildPolicyRequestHash(options: {
  programId: Address;
  poolState: Address;
  actor: Address;
  /** Discriminator of the asset instruction this approval covers. */
  action: number;
  intentParts: Uint8Array[];
}): Uint8Array {
  if (
    options.intentParts.length < 1 ||
    options.intentParts.length > MAX_POLICY_INTENT_PARTS
  ) {
    throw new Error(
      `Policy intent must have 1-${MAX_POLICY_INTENT_PARTS} parts`,
    );
  }
  const domain = new TextEncoder().encode("UTXOPIA_POLICY_APPROVAL_V1");
  const chunks = [
    domain,
    addressToBytes(options.programId),
    addressToBytes(options.poolState),
    addressToBytes(options.actor),
    Uint8Array.of(options.action),
    Uint8Array.of(options.intentParts.length),
    ...options.intentParts.map((part) => sha256(part)),
  ];
  const length = chunks.reduce((total, chunk) => total + chunk.length, 0);
  const preimage = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    preimage.set(chunk, offset);
    offset += chunk.length;
  }
  return sha256(preimage);
}

export interface InitializePolicyApprovalOptions {
  action: number;
  expiresAtSlot: bigint;
  actor: Address;
  requestHash: Uint8Array;
  nonce: Uint8Array;
  accounts: {
    payer: Address;
    poolState: Address;
    policyApproval: Address;
    systemProgram?: Address;
  };
}

export function buildInitializePolicyApprovalInstructionData(
  options: Omit<InitializePolicyApprovalOptions, "accounts">
): Uint8Array {
  if (!Number.isInteger(options.action) || options.action < 0 || options.action > 0xff) {
    throw new Error("Policy approval action must fit in u8");
  }
  if (options.requestHash.length !== 32 || options.nonce.length !== 32) {
    throw new Error("Policy approval requestHash and nonce must be 32 bytes");
  }
  const data = new Uint8Array(106);
  const view = new DataView(data.buffer);
  data[0] = INSTRUCTION.INITIALIZE_POLICY_APPROVAL;
  data[1] = options.action;
  view.setBigUint64(2, options.expiresAtSlot, true);
  data.set(addressToBytes(options.actor), 10);
  data.set(options.requestHash, 42);
  data.set(options.nonce, 74);
  return data;
}

export function buildInitializePolicyApprovalInstruction(
  options: InitializePolicyApprovalOptions
): Instruction {
  const config = getConfig();
  return {
    programAddress: config.policyProgramId ?? config.utxopiaProgramId,
    accounts: [
      { address: options.accounts.payer, role: AccountRole.WRITABLE_SIGNER },
      { address: options.accounts.poolState, role: AccountRole.READONLY },
      { address: options.accounts.policyApproval, role: AccountRole.WRITABLE },
      {
        address: options.accounts.systemProgram ?? SYSTEM_PROGRAM_ADDRESS,
        role: AccountRole.READONLY,
      },
    ],
    data: buildInitializePolicyApprovalInstructionData(options),
  };
}

export function buildPolicyApprovalDecisionInstruction(options: {
  decision: PolicyApprovalDecision;
  accounts: { policyAuthority: Address; policyApproval: Address };
}): Instruction {
  const config = getConfig();
  return {
    programAddress: config.policyProgramId ?? config.utxopiaProgramId,
    accounts: [
      { address: options.accounts.policyAuthority, role: AccountRole.READONLY_SIGNER },
      { address: options.accounts.policyApproval, role: AccountRole.WRITABLE },
    ],
    data: new Uint8Array([
      INSTRUCTION.POLICY_APPROVAL_DECISION,
      options.decision === "approve" ? 1 : 2,
    ]),
  };
}

export function buildPolicyApprovalCommitInstruction(options: {
  accounts: {
    payer: Address;
    policyApproval: Address;
    magicContext?: Address;
    magicProgram?: Address;
  };
}): Instruction {
  const config = getConfig();
  return {
    programAddress: config.policyProgramId ?? config.utxopiaProgramId,
    accounts: [
      { address: options.accounts.payer, role: AccountRole.READONLY_SIGNER },
      {
        address: options.accounts.magicContext ?? MAGICBLOCK_MAGIC_CONTEXT_ID,
        role: AccountRole.WRITABLE,
      },
      {
        address: options.accounts.magicProgram ?? MAGICBLOCK_MAGIC_PROGRAM_ID,
        role: AccountRole.READONLY,
      },
      { address: options.accounts.policyApproval, role: AccountRole.WRITABLE },
    ],
    data: new Uint8Array([INSTRUCTION.POLICY_APPROVAL_COMMIT]),
  };
}

// =============================================================================
// Redemption Request PDA Derivation
// =============================================================================

// deriveRedemptionRequestPDA lived here too, over inlined copies of the same seeds pda.ts
// already builds — and it returned `address: userBytes`, the caller's own pubkey rather than the
// derived address, leaving a comment telling you to derive it yourself. Nothing used it. Use
// `deriveRedemptionRequestPDA` from pda.ts, which returns the real PDA.


// =============================================================================
// BTC Light Client Verify Transaction (disc=2)
// =============================================================================

/**
 * Build btc-light-client verify_transaction instruction data (disc=2)
 *
 * Layout (after disc byte):
 * txid(32) + block_hash(32) + tx_size(u32 LE) + merkle_proof(variable)
 *
 * Merkle proof sub-layout:
 * proof_txid(32) + path_bits(u32 LE) + path_len(u8) + tx_index(u32 LE) + siblings(32 * path_len)
 */
export function buildVerifyTransactionInstructionData(params: {
  txid: Uint8Array;        // 32 bytes, internal byte order
  blockHash: Uint8Array;   // 32 bytes
  txSize: number;          // raw tx size in ChadBuffer (after 32-byte authority)
  txIndex: number;
  merkleSiblings: Uint8Array[]; // each 32 bytes, internal byte order
  pathBits: number;        // bitmask of path direction
}): Uint8Array {
  const { txid, blockHash, txSize, txIndex, merkleSiblings, pathBits } = params;
  const pathLen = merkleSiblings.length;

  // disc(1) + txid(32) + blockHash(32) + txSize(4) + proofTxid(32) + pathBits(4) + pathLen(1) + txIndex(4) + siblings(32*N)
  const totalSize = 1 + 32 + 32 + 4 + 32 + 4 + 1 + 4 + 32 * pathLen;
  const data = new Uint8Array(totalSize);
  const view = new DataView(data.buffer);
  let offset = 0;

  data[offset++] = 2; // discriminator for verify_transaction
  data.set(txid, offset); offset += 32;
  data.set(blockHash, offset); offset += 32;
  view.setUint32(offset, txSize, true); offset += 4;

  // Merkle proof sub-layout
  data.set(txid, offset); offset += 32; // proof_txid = txid
  view.setUint32(offset, pathBits, true); offset += 4;
  data[offset++] = pathLen;
  view.setUint32(offset, txIndex, true); offset += 4;
  for (const sibling of merkleSiblings) {
    data.set(sibling, offset); offset += 32;
  }

  return data;
}

// =============================================================================
// UTXOpia Complete Deposit (disc=11)
// =============================================================================

/**
 * Build utxopia complete_deposit instruction data (disc=11)
 *
 * npk + ephemeral_pub are extracted ON-CHAIN from the deposit TX OP_RETURN.
 * Amount is extracted from the SPV-verified sweep TX.
 *
 * Layout: disc(1) + sweep_txid(32) + block_height(u64 LE)
 *         + sweep_tx_size(u32 LE) + deposit_tx_size(u32 LE) + deposit_txid(32) = 81 bytes
 */
export function buildCompleteDepositInstructionData(params: {
  sweepTxid: Uint8Array;      // 32 bytes, internal byte order
  blockHeight: number;
  sweepTxSize: number;
  depositTxSize: number;
  depositTxid: Uint8Array;    // 32 bytes, internal byte order
}): Uint8Array {
  const data = new Uint8Array(81);
  const view = new DataView(data.buffer);
  let offset = 0;

  data[offset++] = INSTRUCTION.COMPLETE_DEPOSIT;
  data.set(params.sweepTxid, offset); offset += 32;
  view.setBigUint64(offset, BigInt(params.blockHeight), true); offset += 8;
  view.setUint32(offset, params.sweepTxSize, true); offset += 4;
  view.setUint32(offset, params.depositTxSize, true); offset += 4;
  data.set(params.depositTxid, offset); offset += 32;

  return data;
}

// =============================================================================
// UTXOpia Verify Deposit (disc=25) — OP_RETURN-free
// =============================================================================

/**
 * Build utxopia verify_deposit instruction data (disc=25).
 *
 * The OP_RETURN-free deposit path. `notePublicKey` + `ephemeralPubkey` travel in
 * instruction data instead of in the Bitcoin transaction, and the program proves
 * them against the deposit output's tapleaf — a different key pair derives a
 * different leaf, and so a different address, which the funding transaction did
 * not pay. Nothing marks the deposit as a UTXOpia transaction on chain, so any
 * wallet or exchange that can send to a P2TR address can fund it.
 *
 * Derive the address with `deriveDepositAddress(depositTweakCommitment(npk, eph),
 * ikaXOnlyPubkey)`. Both keys are hashed into the leaf, so a caller cannot swap
 * in an ephemeral key that leaves the note undiscoverable.
 *
 * No sweep: the deposit output's tapleaf names the pool's own dWallet key, so it
 * is already under pool custody and is recorded as a pool UTXO directly. The
 * SPV-verified transaction must therefore BE the deposit — `depositTxSize` is 0
 * and `depositTxid` defaults to `sweepTxid`. The receipt PDA is seeded
 * `["deposit_receipt", txid, vout]`, so pass `depositVout` to
 * `deriveDepositReceiptPDA` for this flow.
 *
 * Layout: disc(1) + sweep_txid(32) + block_height(u64 LE) + sweep_tx_size(u32 LE)
 *         + deposit_tx_size(u32 LE) + deposit_txid(32) + ephemeral_pubkey(32)
 *         + note_public_key(32) + deposit_vout(u32 LE) = 149 bytes
 */
export function buildVerifyDepositInstructionData(params: {
  sweepTxid: Uint8Array;        // 32 bytes, internal byte order — the SPV-proven tx
  blockHeight: number;
  sweepTxSize: number;
  depositTxSize?: number;       // must be 0 or omitted: there is no second transaction
  depositTxid?: Uint8Array;     // defaults to sweepTxid, which it must equal
  ephemeralPubkey: Uint8Array;  // 32 bytes
  notePublicKey: Uint8Array;    // 32 bytes
  depositVout: number;
}): Uint8Array {
  const depositTxid = params.depositTxid ?? params.sweepTxid;
  for (const [name, value] of [
    ["sweepTxid", params.sweepTxid],
    ["depositTxid", depositTxid],
    ["ephemeralPubkey", params.ephemeralPubkey],
    ["notePublicKey", params.notePublicKey],
  ] as const) {
    if (value.length !== 32) {
      throw new Error(`${name} must be 32 bytes, got ${value.length}`);
    }
  }
  if (params.depositTxSize) {
    throw new Error("verify_deposit takes no second transaction: depositTxSize must be 0");
  }
  if (toHex(depositTxid) !== toHex(params.sweepTxid)) {
    throw new Error("verify_deposit proves the deposit itself: depositTxid must equal sweepTxid");
  }

  const data = new Uint8Array(149);
  const view = new DataView(data.buffer);
  let offset = 0;

  data[offset++] = INSTRUCTION.VERIFY_DEPOSIT;
  data.set(params.sweepTxid, offset); offset += 32;
  view.setBigUint64(offset, BigInt(params.blockHeight), true); offset += 8;
  view.setUint32(offset, params.sweepTxSize, true); offset += 4;
  view.setUint32(offset, 0, true); offset += 4; // no second transaction
  data.set(depositTxid, offset); offset += 32;
  data.set(params.ephemeralPubkey, offset); offset += 32;
  data.set(params.notePublicKey, offset); offset += 32;
  view.setUint32(offset, params.depositVout, true); offset += 4;

  return data;
}

/**
 * Build utxopia verify_deposit_permissioned instruction data (disc=26).
 *
 * `buildVerifyDepositInstructionData`'s payload with a different discriminator
 * and an auditor ciphertext appended. The tapleaf already tells the pools apart —
 * each carries its own Ika custody key — but that is not the same as clearing the
 * pool's policy, which is what a permissioned pool exists for.
 *
 * The one-time PolicyApproval is bound to the WHOLE payload, ciphertext included,
 * so these exact bytes must be the ones approved.
 */
export function buildVerifyDepositPermissionedInstructionData(
  params: Parameters<typeof buildVerifyDepositInstructionData>[0] & {
    auditorCiphertext?: Uint8Array;
  },
): Uint8Array {
  const base = buildVerifyDepositInstructionData(params);
  const ciphertext = params.auditorCiphertext ?? new Uint8Array(0);

  const data = new Uint8Array(base.length + ciphertext.length);
  data.set(base, 0);
  data.set(ciphertext, base.length);
  data[0] = PERMISSIONED_DISC.VERIFY_DEPOSIT_PERMISSIONED;
  return data;
}

// =============================================================================
// UTXOpia Set Pool Config (disc=2)
// =============================================================================

/** PoolConfig account discriminator (0x0a) */
export const POOL_CONFIG_DISCRIMINATOR = 0x0a;

/** Serialized PoolConfig account length (bytes) */
export const POOL_CONFIG_LEN = 129;

/** Max pool_script (P2TR scriptPubKey) length */
export const POOL_SCRIPT_MAX_LEN = 34;

/**
 * Build set_pool_config instruction data (disc=2).
 *
 * Strict payload — the program rejects any other shape:
 *   disc(1)
 *   + pool_script_len(1)
 *   + pool_script(N, 1..=34)
 *   + ika_dwallet(32)
 *   + ika_dwallet_xonly_pubkey(32)
 *   + cpi_authority_bump(1)
 *
 * `group_pub_key` is no longer part of PoolConfig and must not be sent.
 */
export function buildSetPoolConfigInstructionData(params: {
  poolScript: Uint8Array;
  ikaDwallet: Uint8Array;
  ikaDwalletXonlyPubkey: Uint8Array;
  cpiAuthorityBump: number;
}): Uint8Array {
  const { poolScript, ikaDwallet, ikaDwalletXonlyPubkey, cpiAuthorityBump } = params;
  if (poolScript.length < 1 || poolScript.length > POOL_SCRIPT_MAX_LEN) {
    throw new Error(`poolScript length must be 1..=${POOL_SCRIPT_MAX_LEN}, got ${poolScript.length}`);
  }
  if (ikaDwallet.length !== 32) {
    throw new Error(`ikaDwallet must be 32 bytes, got ${ikaDwallet.length}`);
  }
  if (ikaDwalletXonlyPubkey.length !== 32) {
    throw new Error(`ikaDwalletXonlyPubkey must be 32 bytes, got ${ikaDwalletXonlyPubkey.length}`);
  }

  const data = new Uint8Array(1 + 1 + poolScript.length + 32 + 32 + 1);
  let offset = 0;
  data[offset++] = INSTRUCTION.SET_POOL_CONFIG;
  data[offset++] = poolScript.length;
  data.set(poolScript, offset); offset += poolScript.length;
  data.set(ikaDwallet, offset); offset += 32;
  data.set(ikaDwalletXonlyPubkey, offset); offset += 32;
  data[offset++] = cpiAuthorityBump;
  return data;
}

/** Parsed PoolConfig account (Ika-only, 129 bytes) */
export interface ParsedPoolConfig {
  discriminator: number;
  poolScriptLen: number;
  poolScript: Uint8Array;
  ikaDwallet: Uint8Array;
  ikaDwalletXonlyPubkey: Uint8Array;
  cpiAuthorityBump: number;
}

/**
 * Parse a PoolConfig account.
 *
 * Layout (fixed offsets — pool_script is a 34-byte field regardless of len):
 *   disc(1) @0, pool_script_len(1) @1, pool_script(34) @2,
 *   ika_dwallet(32) @36, ika_dwallet_xonly_pubkey(32) @68,
 *   cpi_authority_bump(1) @100, reserved(28) @101
 */
export function parsePoolConfig(data: Uint8Array): ParsedPoolConfig {
  if (data.length < POOL_CONFIG_LEN) {
    throw new Error(`PoolConfig account too small: ${data.length} < ${POOL_CONFIG_LEN}`);
  }
  if (data[0] !== POOL_CONFIG_DISCRIMINATOR) {
    throw new Error(`Invalid PoolConfig discriminator: 0x${data[0].toString(16)}`);
  }
  const poolScriptLen = data[1];
  if (poolScriptLen > POOL_SCRIPT_MAX_LEN) {
    throw new Error(`Invalid pool script length: ${poolScriptLen}`);
  }
  return {
    discriminator: data[0],
    poolScriptLen,
    poolScript: data.subarray(2, 2 + poolScriptLen),
    ikaDwallet: data.subarray(36, 68),
    ikaDwalletXonlyPubkey: data.subarray(68, 100),
    cpiAuthorityBump: data[100],
  };
}

// =============================================================================
// Utility Exports
// =============================================================================

/**
 * Bigint to 32-byte Uint8Array (big-endian)
 */
export function bigintTo32Bytes(value: bigint): Uint8Array {
  const hex = value.toString(16).padStart(64, "0");
  const bytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/**
 * 32-byte Uint8Array to bigint (big-endian)
 */
export function bytes32ToBigint(bytes: Uint8Array): bigint {
  if (bytes.length !== 32) {
    throw new Error("Expected 32 bytes");
  }
  let hex = "0x";
  for (let i = 0; i < 32; i++) {
    hex += bytes[i].toString(16).padStart(2, "0");
  }
  return BigInt(hex);
}

// hexToBytes / bytesToHex live in ./crypto (single source); re-exported here
// to preserve this module's public surface.
export { hexToBytes, bytesToHex } from "./crypto";

// =============================================================================
// Permissioned Pool Builders
// =============================================================================

// ---------------------------------------------------------------------------
// completeDepositPermissioned (disc=22)
// ---------------------------------------------------------------------------

/** completeDepositPermissioned instruction options */
export interface CompleteDepositPermissionedOptions {
  /** SPV-proven sweep txid (32 bytes, internal byte order) */
  sweepTxid: Uint8Array;
  /** Block height containing the verified tx */
  blockHeight: number;
  /** Raw sweep tx size in ChadBuffer */
  sweepTxSize: number;
  /** Raw deposit tx size in ChadBuffer (0 = direct-to-pool) */
  depositTxSize: number;
  /** Deposit txid (32 bytes, internal byte order) */
  depositTxid: Uint8Array;
  /**
   * Auditor ciphertext: either a pre-computed 112-byte `Uint8Array` blob (advanced
   * / off-chain computed), OR the raw note fields from which the blob is derived
   * on the fly via {@link buildAuditorCiphertextForNote}.
   *
   * If a `Uint8Array` is supplied it is used verbatim (preferred for auditors who
   * hold the key off-chain).  Pass `{ auditorViewingPubKey, tokenId, amount, commitment }`
   * to have the builder encrypt and embed the ciphertext automatically.
   */
  auditorCiphertext: AuditorCiphertextInput;
  /** Account addresses — same 15 as complete_deposit PLUS auditor at index 15 */
  accounts: {
    /** 0. pool_state (writable) */
    poolState: Address;
    /** 1. verified_transaction PDA (readonly) */
    verifiedTransaction: Address;
    /** 2. light_client (readonly) */
    lightClient: Address;
    /** 3. commitment_tree (writable) */
    commitmentTree: Address;
    /** 4. tx_buffer / sweep ChadBuffer (readonly) */
    txBuffer: Address;
    /** 5. authority (writable signer) */
    authority: Address;
    /** 6. system_program (readonly) */
    systemProgram: Address;
    /** 7. zkbtc_mint (writable) */
    zkbtcMint: Address;
    /** 8. pool_vault (writable) */
    poolVault: Address;
    /** 9. token_program (readonly) */
    tokenProgram: Address;
    /** 10. deposit_tx_buffer (readonly) */
    depositTxBuffer: Address;
    /** 11. deposit_receipt PDA (writable) */
    depositReceipt: Address;
    /** 12. utxo_record PDA (writable) */
    utxoRecord: Address;
    /** 13. token_config PDA (writable) */
    tokenConfig: Address;
    /** 14. pool_config PDA (readonly) */
    poolConfig: Address;
    /** HeightIndex PDA for the VerifiedTransaction's block —
     *  `deriveHeightIndexPDA(blockHeight, config.btcLightClientProgramId)`.
     *
     *  REQUIRED. The program re-checks that the proof's block is still the canonical one at
     *  that height before it settles (audit_1 F-BTC-04): a VerifiedTransaction records a merkle
     *  proof that was valid once and is never invalidated, and the confirmation count is taken
     *  against a tip that only grows, so neither notices a reorg. Omitting this fails with
     *  InvalidSpvProof — the program locates the account by address, so its position in the
     *  list does not matter, but its absence is an error rather than a skipped check.
     */
    heightIndex: Address;
    /** 15. one-time PolicyApproval (writable) */
    policyApproval: Address;
  };
}

/**
 * Build completeDepositPermissioned instruction data (disc=22).
 *
 * Layout:
 *   disc(1) + CompleteDepositData fixed header (80 bytes) + auditorCiphertext (variable)
 *
 * The 80-byte header is identical to complete_deposit (disc=11).
 */
export function buildCompleteDepositPermissionedInstructionData(options: {
  sweepTxid: Uint8Array;
  blockHeight: number;
  sweepTxSize: number;
  depositTxSize: number;
  depositTxid: Uint8Array;
  auditorCiphertext: AuditorCiphertextInput;
}): Uint8Array {
  // disc(1) + sweep_txid(32) + block_height(8) + sweep_tx_size(4) + deposit_tx_size(4) + deposit_txid(32) + auditorCiphertext(variable)
  const auditorCiphertext = resolveAuditorCiphertext(options.auditorCiphertext);
  const headerSize = 1 + 32 + 8 + 4 + 4 + 32; // 81 bytes
  const data = new Uint8Array(headerSize + auditorCiphertext.length);
  const view = new DataView(data.buffer);
  let offset = 0;

  data[offset++] = PERMISSIONED_DISC.COMPLETE_DEPOSIT_PERMISSIONED; // disc = 22
  data.set(options.sweepTxid, offset); offset += 32;
  view.setBigUint64(offset, BigInt(options.blockHeight), true); offset += 8;
  view.setUint32(offset, options.sweepTxSize, true); offset += 4;
  view.setUint32(offset, options.depositTxSize, true); offset += 4;
  data.set(options.depositTxid, offset); offset += 32;
  if (auditorCiphertext.length > 0) {
    data.set(auditorCiphertext, offset);
  }

  return data;
}

/**
 * Build a complete completeDepositPermissioned instruction (disc=22).
 *
 * Same accounts as complete_deposit (disc=11), plus a one-time PolicyApproval
 * appended at account index 15.
 *
 * Accounts:
 * 0.  pool_state          (writable)
 * 1.  verified_transaction(readonly)
 * 2.  light_client        (readonly)
 * 3.  commitment_tree     (writable)
 * 4.  tx_buffer           (readonly)
 * 5.  authority           (writable signer)
 * 6.  system_program      (readonly)
 * 7.  zkbtc_mint          (writable)
 * 8.  pool_vault          (writable)
 * 9.  token_program       (readonly)
 * 10. deposit_tx_buffer   (readonly)
 * 11. deposit_receipt     (writable)
 * 12. utxo_record         (writable)
 * 13. token_config        (writable)
 * 14. pool_config         (readonly)
 * 15. policy_approval     (writable)
 * 16. policy_program      (readonly)
 * 17. height_index        (readonly) — canonicality re-check, located by address
 */
export function buildCompleteDepositPermissionedInstruction(
  options: CompleteDepositPermissionedOptions,
): Instruction {
  const config = getConfig();
  const data = buildCompleteDepositPermissionedInstructionData({
    sweepTxid: options.sweepTxid,
    blockHeight: options.blockHeight,
    sweepTxSize: options.sweepTxSize,
    depositTxSize: options.depositTxSize,
    depositTxid: options.depositTxid,
    auditorCiphertext: options.auditorCiphertext,
  });

  return {
    programAddress: config.utxopiaProgramId,
    accounts: [
      { address: options.accounts.poolState,          role: AccountRole.WRITABLE },
      { address: options.accounts.verifiedTransaction, role: AccountRole.READONLY },
      { address: options.accounts.lightClient,         role: AccountRole.READONLY },
      { address: options.accounts.commitmentTree,      role: AccountRole.WRITABLE },
      { address: options.accounts.txBuffer,            role: AccountRole.READONLY },
      { address: options.accounts.authority,           role: AccountRole.WRITABLE_SIGNER },
      { address: options.accounts.systemProgram,       role: AccountRole.READONLY },
      { address: options.accounts.zkbtcMint,           role: AccountRole.WRITABLE },
      { address: options.accounts.poolVault,           role: AccountRole.WRITABLE },
      { address: options.accounts.tokenProgram,        role: AccountRole.READONLY },
      { address: options.accounts.depositTxBuffer,     role: AccountRole.READONLY },
      { address: options.accounts.depositReceipt,      role: AccountRole.WRITABLE },
      { address: options.accounts.utxoRecord,          role: AccountRole.WRITABLE },
      { address: options.accounts.tokenConfig,         role: AccountRole.WRITABLE },
      { address: options.accounts.poolConfig,          role: AccountRole.READONLY },
      { address: options.accounts.policyApproval,      role: AccountRole.WRITABLE },
      { address: config.policyProgramId ?? config.utxopiaProgramId, role: AccountRole.READONLY },
      { address: options.accounts.heightIndex,         role: AccountRole.READONLY },
    ],
    data,
  };
}

// ---------------------------------------------------------------------------
// shieldPermissioned (disc=23)
// ---------------------------------------------------------------------------

/** shieldPermissioned instruction options */
export interface ShieldPermissionedInstructionOptions {
  /** Amount to shield (in token's smallest unit) */
  amount: bigint;
  /** NPK bytes (32) — recipient's note public key */
  npk: Uint8Array;
  /** Ephemeral public key (32) — for stealth address derivation */
  ephemeralPub: Uint8Array;
  /**
   * Auditor ciphertext: either a pre-computed 112-byte `Uint8Array` blob (advanced
   * / off-chain computed), OR the raw note fields from which the blob is derived
   * on the fly via {@link buildAuditorCiphertextForNote}.
   *
   * If a `Uint8Array` is supplied it is used verbatim (preferred for auditors who
   * hold the key off-chain).  Pass `{ auditorViewingPubKey, tokenId, amount, commitment }`
   * to have the builder encrypt and embed the ciphertext automatically.
   */
  auditorCiphertext: AuditorCiphertextInput;
  /** Account addresses — same 7 as shield (disc=12) plus PolicyApproval at index 7 */
  accounts: {
    /** 0. user (writable signer) */
    user: Address;
    /** 1. user_token_account (writable) */
    userTokenAccount: Address;
    /** 2. pool_state (readonly) */
    poolState: Address;
    /** 3. token_config (writable) */
    tokenConfig: Address;
    /** 4. vault (writable) */
    vault: Address;
    /** 5. commitment_tree (writable) */
    commitmentTree: Address;
    /** 6. token_program (readonly) */
    tokenProgram: Address;
    /** 7. one-time PolicyApproval (writable) */
    policyApproval: Address;
    /**
     * 9. ExitDestination PDA registered for `user`.
     *
     * Value cannot enter without a way back out: the program refuses a
     * depositor who has no registered exit, so they can always ragequit to
     * their own wallet without the auditor. Derive with
     * {@link deriveExitDestinationPDA} using `EXIT_KIND_SOLANA_OWNER` and the
     * depositor's address.
     */
    exitDestination: Address;
  };
}

/**
 * Build shieldPermissioned instruction data (disc=23).
 *
 * Layout:
 *   disc(1) + shield header (72 bytes) + auditorCiphertext (variable)
 *
 * The 72-byte header is identical to shield (disc=12):
 *   amount(8 LE) + npk(32) + ephemeral_pub(32)
 */
export function buildShieldPermissionedInstructionData(options: {
  amount: bigint;
  npk: Uint8Array;
  ephemeralPub: Uint8Array;
  auditorCiphertext: AuditorCiphertextInput;
}): Uint8Array {
  // disc(1) + amount(8) + npk(32) + ephemeral_pub(32) + auditorCiphertext(variable)
  const auditorCiphertext = resolveAuditorCiphertext(options.auditorCiphertext);
  const headerSize = 1 + 8 + 32 + 32; // 73 bytes
  const data = new Uint8Array(headerSize + auditorCiphertext.length);
  const view = new DataView(data.buffer);
  let offset = 0;

  data[offset++] = PERMISSIONED_DISC.SHIELD_PERMISSIONED; // disc = 23
  view.setBigUint64(offset, options.amount, true); offset += 8;
  data.set(options.npk.slice(0, 32), offset); offset += 32;
  data.set(options.ephemeralPub.slice(0, 32), offset); offset += 32;
  if (auditorCiphertext.length > 0) {
    data.set(auditorCiphertext, offset);
  }

  return data;
}

/**
 * Build a complete shieldPermissioned instruction (disc=23).
 *
 * Same accounts as shield (disc=12), plus three appended.
 *
 * Accounts:
 * 0. user              (writable signer)
 * 1. user_token_account(writable)
 * 2. pool_state        (writable)
 * 3. token_config      (writable)
 * 4. vault             (writable)
 * 5. commitment_tree   (writable)
 * 6. token_program     (readonly)
 * 7. policy_approval   (writable)
 * 8. policy_program    (readonly)
 * 9. exit_destination  (readonly) — the depositor's registered exit
 */
export function buildShieldPermissionedInstruction(
  options: ShieldPermissionedInstructionOptions,
): Instruction {
  const config = getConfig();
  const data = buildShieldPermissionedInstructionData({
    amount: options.amount,
    npk: options.npk,
    ephemeralPub: options.ephemeralPub,
    auditorCiphertext: options.auditorCiphertext,
  });

  return {
    programAddress: config.utxopiaProgramId,
    accounts: [
      { address: options.accounts.user,             role: AccountRole.WRITABLE_SIGNER },
      { address: options.accounts.userTokenAccount, role: AccountRole.WRITABLE },
      { address: options.accounts.poolState,        role: AccountRole.WRITABLE },
      { address: options.accounts.tokenConfig,      role: AccountRole.WRITABLE },
      { address: options.accounts.vault,            role: AccountRole.WRITABLE },
      { address: options.accounts.commitmentTree,   role: AccountRole.WRITABLE },
      { address: options.accounts.tokenProgram,     role: AccountRole.READONLY },
      { address: options.accounts.policyApproval,   role: AccountRole.WRITABLE },
      { address: config.policyProgramId ?? config.utxopiaProgramId, role: AccountRole.READONLY },
      { address: options.accounts.exitDestination,  role: AccountRole.READONLY },
    ],
    data,
  };
}

// ---------------------------------------------------------------------------
// registerExitDestination (disc=39)
// ---------------------------------------------------------------------------

/**
 * Build a registerExitDestination instruction (disc=39) — auditor-only.
 *
 * Adds one entry to a permissioned pool's append-only exit registry. Entries can
 * be added but never removed: a removable entry would hand the auditor back the
 * ability to prevent a withdrawal, which is the one power the design withholds.
 *
 * Register a depositor's address BEFORE their first `shieldPermissioned` — the
 * program refuses a depositor who has no exit.
 *
 * Data:     kind(1) + key(32)
 * Accounts: 0. auditor (writable signer, pays rent)
 *           1. pool_state (readonly)
 *           2. exit_destination PDA (writable, uninitialized)
 *           3. system_program (readonly)
 */
/**
 * Build registerExitDestination instruction data (disc=39).
 *
 * Layout: disc(1) + kind(1) + key(32)
 */
export function buildRegisterExitDestinationInstructionData(options: {
  kind: number;
  key: Uint8Array;
}): Uint8Array {
  if (options.key.length !== 32) {
    throw new Error("exit destination key must be 32 bytes");
  }
  const data = new Uint8Array(34);
  data[0] = PERMISSIONED_DISC.REGISTER_EXIT_DESTINATION;
  data[1] = options.kind;
  data.set(options.key, 2);
  return data;
}

export function buildRegisterExitDestinationInstruction(options: {
  /** `EXIT_KIND_SOLANA_OWNER` or `EXIT_KIND_BTC_SCRIPT`. */
  kind: number;
  /** Recipient token account owner, or sha256(btcScript). */
  key: Uint8Array;
  accounts: {
    auditor: Address;
    poolState: Address;
    exitDestination: Address;
  };
}): Instruction {
  const config = getConfig();
  const data = buildRegisterExitDestinationInstructionData(options);

  return {
    programAddress: config.utxopiaProgramId,
    accounts: [
      { address: options.accounts.auditor,         role: AccountRole.WRITABLE_SIGNER },
      { address: options.accounts.poolState,       role: AccountRole.READONLY },
      { address: options.accounts.exitDestination, role: AccountRole.WRITABLE },
      { address: SYSTEM_PROGRAM_ADDRESS,           role: AccountRole.READONLY },
    ],
    data,
  };
}

// ---------------------------------------------------------------------------
// rotateAuditor (disc=35)
// ---------------------------------------------------------------------------

export interface RotateAuditorOptions {
  auditor: Uint8Array;
  viewingPubkey: Uint8Array;
  accounts: {
    poolState: Address;
    authority: Address;
  };
}

export function buildRotateAuditorInstructionData(
  auditor: Uint8Array,
  viewingPubkey: Uint8Array,
): Uint8Array {
  if (auditor.length !== 32 || auditor.every((byte) => byte === 0)) {
    throw new Error("auditor must be a nonzero 32-byte public key");
  }
  if (viewingPubkey.length !== 32 || viewingPubkey.every((byte) => byte === 0)) {
    throw new Error("viewingPubkey must be a nonzero 32-byte public key");
  }
  const data = new Uint8Array(65);
  data[0] = INSTRUCTION.ROTATE_AUDITOR;
  data.set(auditor, 1);
  data.set(viewingPubkey, 33);
  return data;
}

export function buildRotateAuditorInstruction(options: RotateAuditorOptions): Instruction {
  const config = getConfig();
  return {
    programAddress: config.utxopiaProgramId,
    accounts: [
      { address: options.accounts.poolState, role: AccountRole.WRITABLE },
      { address: options.accounts.authority, role: AccountRole.READONLY_SIGNER },
    ],
    data: buildRotateAuditorInstructionData(options.auditor, options.viewingPubkey),
  };
}
