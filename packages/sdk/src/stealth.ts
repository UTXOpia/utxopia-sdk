/**
 * Stealth address utilities for UTXOPIA
 *
 * Dual-curve stealth flow (Railgun-style):
 *
 * Stealth Deposit Flow:
 * ```
 * Sender:
 *   1. ephemeral = random Ed25519 keypair
 *   2. sharedSecret = X25519(ephemeral.priv, recipientViewingPub)
 *   3. stealthScalar = SHA256(sharedSecret || domain) mod BJJ_ORDER
 *   4. stealthPub = spendingPub + stealthScalar × BASE8 (Baby Jubjub)
 *   5. commitment = Poseidon(stealthPub.x, amount)
 *   6. encryptedAmount = amount XOR sha256(sharedSecret)[0..8]
 *
 * Recipient (viewing key only - can detect and see amount):
 *   1. sharedSecret = X25519(viewingPriv, ephemeralPub)
 *   2. amount = encryptedAmount XOR sha256(sharedSecret)[0..8]
 *   3. stealthPub = spendingPub + stealthScalar × BASE8
 *   4. Verify: commitment == Poseidon(stealthPub.x, amount)
 *
 * Recipient (spending key - can claim):
 *   1. stealthPriv = spendingPriv + stealthScalar (mod BJJ_ORDER)
 *   2. nullifier = Poseidon(stealthPriv, leafIndex)
 * ```
 *
 * Format (90 bytes on-chain):
 * - ephemeral_pub (32 bytes) - Ed25519 public key
 * - encrypted_amount (8 bytes) - XOR encrypted with shared secret
 * - commitment (32 bytes) - Poseidon hash for Merkle tree
 * - leaf_index (8 bytes) - Position in Merkle tree
 * - created_at (8 bytes) - Timestamp
 */

// ========== Constants (defined before imports to ensure availability) ==========

/** Announcement type: deposit (plaintext amount) */
export const ANNOUNCEMENT_TYPE_DEPOSIT = 0;

/** Announcement type: transfer (XOR-encrypted amount) */
export const ANNOUNCEMENT_TYPE_TRANSFER = 1;

function isKnownAnnouncementType(value: number): boolean {
  return value === ANNOUNCEMENT_TYPE_DEPOSIT || value === ANNOUNCEMENT_TYPE_TRANSFER;
}

// ========== Imports ==========

import { sha256 } from "@noble/hashes/sha2.js";
import {
  bigintToBytes,
  bytesToBigint,
  bytesToHex,
  hexToBytes,
  BN254_FIELD_PRIME,
  babyJubMul,
  babyJubAdd,
  babyJubCompress,
  babyJubDecompress,
  BABYJUB_BASE8,
  BABYJUB_ORDER,
  scalarFromBytes,
  type BabyJubPoint,
} from "./crypto";
import {
  ed25519GenerateKeyPair,
  ed25519KeyPairFromMaterial,
  x25519Ecdh,
  encryptAmountEd25519,
  decryptAmountEd25519,
} from "./crypto-ed25519";
import type { StealthMetaAddress, UTXOpiaKeys, WalletSignerAdapter } from "./keys";
import { deriveKeysFromWallet, parseStealthMetaAddress, constantTimeCompare } from "./keys";
import {
  poseidonHashSync,
  computeNullifierSync as poseidonComputeNullifier,
  computeMPKSync,
  computeNPKSync,
  computeJoinSplitCommitmentSync,
  computeJoinSplitNullifierSync,
} from "./poseidon";
import { getConfig } from "./config";
import { deriveRawXOnlyP2TRAddress } from "./bitcoin/ika";
import type { DepositOpReturnContext } from "./taproot";

// ========== Amount Encryption Helpers ==========

/**
 * Encrypt amount using XOR with shared secret
 */
export function encryptAmount(amount: bigint, sharedSecret: Uint8Array): Uint8Array {
  return encryptAmountEd25519(amount, sharedSecret);
}

/**
 * Decrypt amount using XOR with shared secret
 */
export function decryptAmount(encryptedAmount: Uint8Array, sharedSecret: Uint8Array): bigint {
  return decryptAmountEd25519(encryptedAmount, sharedSecret);
}

// Re-export combined note data encryption
export { encryptNoteData, decryptNoteData } from "./crypto-ed25519";

// ========== Type Guard ==========

/**
 * Type guard to distinguish between WalletSignerAdapter and UTXOpiaKeys
 */
export function isWalletAdapter(source: unknown): source is WalletSignerAdapter {
  return (
    typeof source === "object" &&
    source !== null &&
    "signMessage" in source &&
    typeof (source as WalletSignerAdapter).signMessage === "function"
  );
}

// ========== Types ==========

/**
 * Stealth Deposit with single Ed25519 ephemeral key
 */
export interface StealthDeposit {
  /** Ed25519 ephemeral public key (32 bytes) */
  ephemeralPub: Uint8Array;

  /** Encrypted amount (8 bytes) */
  encryptedAmount: Uint8Array;

  /** Commitment for Merkle tree (32 bytes) - Poseidon(stealthPub.x, amount) */
  commitment: Uint8Array;

  /** Unix timestamp when created */
  createdAt: number;
}

/**
 * Scanned note from announcement (viewing key can detect)
 */
export interface ScannedNote {
  /** Amount in satoshis */
  amount: bigint;

  /** Ed25519 ephemeral public key (needed for shared secret) */
  ephemeralPub: Uint8Array;

  /** Computed stealth public key (Baby Jubjub) */
  stealthPub: BabyJubPoint;

  /** Leaf index in Merkle tree */
  leafIndex: number;

  /** Original announcement commitment */
  commitment: Uint8Array;

  /** Unix timestamp (seconds) from on-chain block_time, 0 if unavailable */
  blockTime?: number;
}

/**
 * Prepared claim inputs for JoinSplit ZK proof (requires spending key)
 */
export interface ClaimInputs {
  stealthPrivKey: bigint;
  nullifyingKey: bigint;
  amount: bigint;
  leafIndex: number;
  merklePath: bigint[];
  merkleIndices: number[];
  merkleRoot: bigint;
  nullifier: bigint;
  npk: bigint;
  random: bigint;
}

// ========== On-chain Announcement ==========

/**
 * Parsed stealth announcement from on-chain data
 */
export interface OnChainStealthAnnouncement {
  /** 0 = deposit (plaintext amount), 1 = transfer (encrypted amount) */
  announcementType: number;
  ephemeralPub: Uint8Array;
  /** Raw amount bytes: plaintext if type=0, encrypted if type=1 */
  encryptedAmount: Uint8Array;
  /** Commitment = Poseidon(npk, token, amount) stored on-chain */
  commitment: Uint8Array;
  leafIndex: number;
  /** Unix timestamp (seconds) from on-chain block_time, 0 if unavailable */
  blockTime?: number;
  /** Solana slot the announcement was emitted in. Needed for auditor slot-range scoping. */
  slot?: number;
  /** Token id hex from the backend indexer, when available. */
  tokenIdHex?: string;
}

// ========== Helper Functions ==========

/** Domain separator for stealth key derivation.
 *  "Utxopia-stealth-v1" is LOAD-BEARING — once real stealth addresses exist this
 *  exact byte sequence is FROZEN; sender and receiver must use the identical
 *  value or payments won't be detected. Bump the suffix only as a deliberate
 *  v2 break. */
const STEALTH_KEY_DOMAIN = new TextEncoder().encode("Utxopia-stealth-v1");

// tokenId removed — use computeTokenId(mintBytes) from poseidon.ts instead

/**
 * Derive stealth scalar from X25519 shared secret
 *
 * stealthScalar = SHA256(sharedSecret || domain) mod BJJ_ORDER
 */
function deriveStealthScalar(sharedSecret: Uint8Array): bigint {
  const hashInput = new Uint8Array(sharedSecret.length + STEALTH_KEY_DOMAIN.length);
  hashInput.set(sharedSecret, 0);
  hashInput.set(STEALTH_KEY_DOMAIN, sharedSecret.length);

  const hash = sha256(hashInput);
  return scalarFromBytes(hash);
}

/**
 * Derive stealth public key (Baby Jubjub)
 *
 * stealthPub = spendingPub + stealthScalar × BASE8
 */
function deriveStealthPubKey(
  spendingPub: BabyJubPoint,
  sharedSecret: Uint8Array
): BabyJubPoint {
  const scalar = deriveStealthScalar(sharedSecret);
  const scalarPoint = babyJubMul(scalar, BABYJUB_BASE8);
  return babyJubAdd(spendingPub, scalarPoint);
}

/**
 * Derive stealth private key (Baby Jubjub scalar addition)
 *
 * stealthPriv = spendingPriv + stealthScalar (mod BJJ_ORDER)
 */
function deriveStealthPrivKey(
  spendingPriv: bigint,
  sharedSecret: Uint8Array
): bigint {
  const scalar = deriveStealthScalar(sharedSecret);
  return (spendingPriv + scalar) % BABYJUB_ORDER;
}

// ========== Sender Functions ==========

/**
 * Create a stealth deposit (JoinSplit-compatible)
 *
 * 1. Generate Ed25519 ephemeral keypair
 * 2. sharedSecret = X25519(ephemeral.priv, viewingPub)
 * 3. stealthPub = spendingPub + hash(sharedSecret) × BASE8
 * 4. stealthMPK = Poseidon(stealthPub.x, stealthPub.y, nullifyingKey)
 *    (sender uses recipientMPK from meta-address for stealth deposits)
 * 5. npk = Poseidon(recipientMPK, random)
 * 6. commitment = Poseidon(npk, tokenId, amount)
 * 7. encryptedAmount = amount XOR sha256(sharedSecret)[0..8]
 */
export async function createStealthDeposit(
  recipientMeta: StealthMetaAddress,
  amountSats: bigint,
  tokenId: bigint,
  outgoing?: OutgoingRecoveryMaterial,
): Promise<StealthDeposit> {
  // Only viewingPubKey + mpk needed (spendingPubKey not used by sender)
  const viewingPubKey = new Uint8Array(recipientMeta.viewingPubKey);

  // Indexed off the sender's outgoing node when supplied, so they can recompute
  // this payment later; random otherwise, which works but leaves no trace the
  // sender can recover. Optional rather than required because the cost of
  // omitting it is a lost record, not lost funds — unlike a deposit address,
  // where the ephemeral key IS the only way to ever spend the coins.
  const ephemeral = outgoing
    ? outgoingEphemeralKeyPair(outgoing)
    : ed25519GenerateKeyPair();

  // X25519 ECDH: shared secret
  const sharedSecret = x25519Ecdh(ephemeral.privKey, viewingPubKey);

  // Derive stealth scalar as the random value for NPK
  const stealthScalar = deriveStealthScalar(sharedSecret);

  // Use recipient's MPK from meta-address to compute NPK
  const recipientMPK = bytesToBigint(recipientMeta.mpk);
  const npk = computeNPKSync(recipientMPK, stealthScalar);

  // Compute JoinSplit commitment = Poseidon(npk, token, amount)
  const commitmentBigint = computeJoinSplitCommitmentSync(npk, tokenId, amountSats);
  const commitment = bigintToBytes(commitmentBigint);

  // Encrypt amount
  const encryptedAmount = encryptAmount(amountSats, sharedSecret);

  return {
    ephemeralPub: new Uint8Array(ephemeral.pubKey),
    encryptedAmount,
    commitment,
    createdAt: Date.now(),
  };
}

/**
 * Extended stealth output data including the derived stealth pub key
 */
export interface StealthOutputWithKeys extends StealthOutputData {
  stealthPubKeyX: bigint;
  /** npk as 32-byte LE Uint8Array — ready for on-chain instruction data */
  npkBytes: Uint8Array;
}

/**
 * Create stealth deposit with npk for JoinSplit circuit input
 */
export async function createStealthDepositWithKeys(
  recipientMeta: StealthMetaAddress,
  amountSats: bigint,
  tokenId: bigint,
): Promise<StealthOutputWithKeys> {
  // Only viewingPubKey + mpk needed (spendingPubKey not used by sender)
  const viewingPubKey = new Uint8Array(recipientMeta.viewingPubKey);

  const ephemeral = ed25519GenerateKeyPair();
  const sharedSecret = x25519Ecdh(ephemeral.privKey, viewingPubKey);

  const stealthScalar = deriveStealthScalar(sharedSecret);
  const recipientMPK = bytesToBigint(recipientMeta.mpk);
  const npk = computeNPKSync(recipientMPK, stealthScalar);

  const commitmentBigint = computeJoinSplitCommitmentSync(npk, tokenId, amountSats);
  const commitment = bigintToBytes(commitmentBigint);
  const encryptedAmount = encryptAmount(amountSats, sharedSecret);

  return {
    ephemeralPub: new Uint8Array(ephemeral.pubKey),
    encryptedAmount,
    commitment,
    stealthPubKeyX: npk,
    npkBytes: bigintToBytes(npk),
  };
}

// ========== Non-Interactive Deposit (OP_RETURN) ==========

/**
 * Result of a non-interactive deposit preparation.
 * Contains everything needed to build a PSBT with an OP_RETURN output.
 *
 * npk-based flow: user can send any amount of BTC. The commitment is
 * computed on-chain from npk + actual amount.
 */
export interface NonInteractiveDepositResult {
  /** Taproot address to send BTC to */
  btcAddress: string;
  /** 32-byte x-only output key for the deposit P2TR output */
  depositOutputKey: Uint8Array;
  /** 73-byte OP_RETURN payload: header || poolTag || ephemeralPub || npk */
  opReturnPayload: Uint8Array;
  /** 32-byte note public key (for tracking) */
  npk: Uint8Array;
  /** 32-byte Ed25519 ephemeral public key */
  ephemeralPub: Uint8Array;
}

/**
 * Extended result when a user refund pubkey is provided.
 * Includes Taproot script-path data for the refund spending path.
 */
export interface NonInteractiveDepositWithRefundResult extends NonInteractiveDepositResult {
  /** 32-byte Merkle root (TapLeaf hash of the refund script) */
  merkleRoot: Uint8Array;
  /** 33-byte control block for script-path spend (leaf_version|parity + internal_key) */
  controlBlock: Uint8Array;
  /** 73-byte refund script */
  refundScript: Uint8Array;
}

/**
 * Create a non-interactive stealth deposit (npk-based).
 *
 * This is the client-side-only deposit flow: no backend API call needed.
 * The ephemeral key and npk are embedded in the BTC transaction's OP_RETURN
 * output so the backend can passively detect them.
 *
 * The user can send ANY amount of BTC — the commitment is computed on-chain
 * from the npk + actual BTC amount received.
 *
 * When `userRefundPubkey` is provided, the Taproot address includes a
 * script-path with a time-locked refund spending condition (144 blocks).
 *
 * @param recipientMeta - Recipient's stealth meta-address
 * @param custodyInternalKey - Pool custody x-only pubkey (32 bytes), used as the Taproot internal key
 * @param network - Bitcoin network for address encoding
 * @param userRefundPubkey - Optional 32-byte x-only pubkey for refund script path
 */
export async function createNonInteractiveDeposit(
  recipientMeta: StealthMetaAddress,
  custodyInternalKey: Uint8Array,
  network?: BitcoinNetwork,
  userRefundPubkey?: undefined,
  opReturnContext?: DepositOpReturnContext,
): Promise<NonInteractiveDepositResult>;
export async function createNonInteractiveDeposit(
  recipientMeta: StealthMetaAddress,
  custodyInternalKey: Uint8Array,
  network: BitcoinNetwork,
  userRefundPubkey: Uint8Array,
  opReturnContext: DepositOpReturnContext,
): Promise<NonInteractiveDepositWithRefundResult>;
export async function createNonInteractiveDeposit(
  recipientMeta: StealthMetaAddress,
  custodyInternalKey: Uint8Array,
  network: BitcoinNetwork = "testnet",
  userRefundPubkey?: Uint8Array,
  opReturnContext?: DepositOpReturnContext,
): Promise<NonInteractiveDepositResult | NonInteractiveDepositWithRefundResult> {
  if (!opReturnContext) {
    throw new Error("deposit OP_RETURN context is required");
  }
  // Only viewingPubKey + mpk needed (spendingPubKey not used by sender)
  const viewingPubKey = new Uint8Array(recipientMeta.viewingPubKey);

  // 1. Generate ephemeral Ed25519 keypair
  const ephemeral = ed25519GenerateKeyPair();

  // 2. X25519 ECDH shared secret
  const sharedSecret = x25519Ecdh(ephemeral.privKey, viewingPubKey);

  // 3. Derive stealth scalar → NPK (no commitment — computed on-chain)
  const stealthScalar = deriveStealthScalar(sharedSecret);
  const recipientMPK = bytesToBigint(recipientMeta.mpk);
  const npkBigint = computeNPKSync(recipientMPK, stealthScalar);
  const npk = bigintToBytes(npkBigint);

  const ephemeralPub = new Uint8Array(ephemeral.pubKey);

  if (userRefundPubkey) {
    // Refund path: Taproot with script tree containing refund script
    const { deriveTaprootAddressWithRefund, buildDepositOpReturn } = await import("./taproot");
    const {
      address: btcAddress,
      outputKey,
      merkleRoot,
      controlBlock,
      refundScript,
    } = deriveTaprootAddressWithRefund(npk, userRefundPubkey, custodyInternalKey, network);

    // Still build OP_RETURN so the backend can detect the deposit
    const opReturnPayload = buildDepositOpReturn(ephemeralPub, npk, opReturnContext);

    return {
      btcAddress,
      depositOutputKey: outputKey,
      opReturnPayload,
      npk,
      ephemeralPub,
      merkleRoot,
      controlBlock,
      refundScript,
    };
  }

  // Standard path: key-path-only Taproot address
  const { deriveTaprootAddress, buildDepositOpReturn } = await import("./taproot");
  const { address: btcAddress, outputKey } = deriveTaprootAddress(npk, network, custodyInternalKey);

  const opReturnPayload = buildDepositOpReturn(ephemeralPub, npk, opReturnContext);

  return {
    btcAddress,
    depositOutputKey: outputKey,
    opReturnPayload,
    npk,
    ephemeralPub,
  };
}

/**
 * Create a non-interactive deposit directly to an Ika-controlled vault.
 *
 * The BTC address is the raw Ika x-only Taproot witness program, so Ika can
 * later sign and spend the UTXO. Privacy/ownership metadata stays per-deposit
 * in OP_RETURN(header || poolTag || ephemeralPub || npk), and the destination chain
 * credits the note from that transaction.
 */
export async function createDirectVaultDeposit(
  recipientMeta: StealthMetaAddress,
  vaultXOnlyPubkey: Uint8Array,
  network: BitcoinNetwork = "testnet",
  opReturnContext?: DepositOpReturnContext,
): Promise<NonInteractiveDepositResult> {
  if (!opReturnContext) {
    throw new Error("deposit OP_RETURN context is required");
  }
  if (vaultXOnlyPubkey.length !== 32) {
    throw new Error("vaultXOnlyPubkey must be 32 bytes");
  }

  const viewingPubKey = new Uint8Array(recipientMeta.viewingPubKey);
  const ephemeral = ed25519GenerateKeyPair();
  const sharedSecret = x25519Ecdh(ephemeral.privKey, viewingPubKey);
  const stealthScalar = deriveStealthScalar(sharedSecret);
  const recipientMPK = bytesToBigint(recipientMeta.mpk);
  const npkBigint = computeNPKSync(recipientMPK, stealthScalar);
  const npk = bigintToBytes(npkBigint);
  const ephemeralPub = new Uint8Array(ephemeral.pubKey);

  const { buildDepositOpReturn } = await import("./taproot");
  const opReturnPayload = buildDepositOpReturn(ephemeralPub, npk, opReturnContext);

  return {
    btcAddress: deriveRawXOnlyP2TRAddress(vaultXOnlyPubkey, network),
    depositOutputKey: vaultXOnlyPubkey,
    opReturnPayload,
    npk,
    ephemeralPub,
  };
}

const DEPOSIT_VIEWING_NODE_DOMAIN = new TextEncoder().encode("utxopia:deposit-viewing-node:v1");
const DEPOSIT_EPHEMERAL_DOMAIN = new TextEncoder().encode("utxopia:deposit-ephemeral:v1");

/**
 * The delegable half of deposit recovery.
 *
 * Deposit addresses are derived from this node, so whoever holds it can rebuild
 * every address the owner was ever handed, and with it every tapleaf and control
 * block needed to spend those coins. It grants no spend authority over notes:
 * that needs the spending key and the nullifying key, neither of which is
 * derivable from here.
 *
 * Derived from the viewing key rather than the master seed on purpose. It means
 * an owner can hand a chosen party — another device, a custodian, the pool
 * operator — the ability to recover their BTC without handing over the ability
 * to spend their notes. Same split Fluidkey uses for its ephemeral key nodes.
 */
export function depositViewingNode(viewingPrivKey: Uint8Array): Uint8Array {
  if (viewingPrivKey.length === 0) {
    throw new Error("viewingPrivKey must not be empty");
  }
  const material = new Uint8Array(DEPOSIT_VIEWING_NODE_DOMAIN.length + viewingPrivKey.length);
  material.set(DEPOSIT_VIEWING_NODE_DOMAIN, 0);
  material.set(viewingPrivKey, DEPOSIT_VIEWING_NODE_DOMAIN.length);
  return sha256(material);
}

const OUTGOING_VIEWING_NODE_DOMAIN = new TextEncoder().encode(
  "utxopia:outgoing-viewing-node:v1",
);
const OUTGOING_EPHEMERAL_DOMAIN = new TextEncoder().encode("utxopia:outgoing-ephemeral:v1");

/**
 * The delegable half of *outgoing* history.
 *
 * An announcement is encrypted to the recipient's viewing key, and the sender
 * discards the ephemeral private key — so today a sender cannot rediscover what
 * they paid out. Their history exists only in local storage. Indexing the
 * ephemeral key off this node makes every outgoing payment recomputable from
 * keys alone. Zcash calls the equivalent an outgoing viewing key.
 *
 * Deliberately a different node from `depositViewingNode`. The two authorise
 * different things, and one should not smuggle in the other:
 *
 * - deposit node  → "you can recover my BTC"
 * - outgoing node → "you can see who I paid"
 */
export function outgoingViewingNode(viewingPrivKey: Uint8Array): Uint8Array {
  if (viewingPrivKey.length === 0) {
    throw new Error("viewingPrivKey must not be empty");
  }
  const material = new Uint8Array(OUTGOING_VIEWING_NODE_DOMAIN.length + viewingPrivKey.length);
  material.set(OUTGOING_VIEWING_NODE_DOMAIN, 0);
  material.set(viewingPrivKey, OUTGOING_VIEWING_NODE_DOMAIN.length);
  return sha256(material);
}

/** Which outgoing payment an ephemeral key belongs to. */
export interface OutgoingRecoveryMaterial {
  /** From `outgoingViewingNode(viewingPrivKey)`. */
  outgoingNode: Uint8Array;
  /** Monotonic per-sender counter. One payment per index. */
  sendIndex: number;
}

/** `sha256(domain || outgoingNode || sendIndex)` → Ed25519 ephemeral keypair. */
export function outgoingEphemeralKeyPair(outgoing: OutgoingRecoveryMaterial): {
  privKey: Uint8Array;
  pubKey: Uint8Array;
} {
  const { outgoingNode, sendIndex } = outgoing;
  if (outgoingNode.length === 0) {
    throw new Error("outgoingNode must not be empty");
  }
  if (!Number.isInteger(sendIndex) || sendIndex < 0) {
    throw new Error(`invalid sendIndex: ${sendIndex}`);
  }

  const material = new Uint8Array(OUTGOING_EPHEMERAL_DOMAIN.length + outgoingNode.length + 4);
  material.set(OUTGOING_EPHEMERAL_DOMAIN, 0);
  material.set(outgoingNode, OUTGOING_EPHEMERAL_DOMAIN.length);
  new DataView(material.buffer).setUint32(
    OUTGOING_EPHEMERAL_DOMAIN.length + outgoingNode.length,
    sendIndex,
    true,
  );
  return ed25519KeyPairFromMaterial(material);
}

/**
 * Recover the next unused send index by walking 0 upward against the ephemeral
 * pubkeys already on chain.
 *
 * An index is "used" when some announcement carries the ephemeral pubkey it
 * derives. Scanning stops after `gapLimit` consecutive misses, because a
 * derived-but-never-broadcast payment leaves a hole — an abandoned or failed
 * transaction — and stopping at the first hole would hand back an index that is
 * already spoken for.
 *
 * This is a FLOOR, not the live counter. A payment broadcast but not yet indexed
 * is invisible here, so a sender that keeps local state must take
 * `max(localCounter, findNextSendIndex(...))`. Reusing an index re-derives the
 * same ephemeral key, and to the same recipient that means the same note
 * commitment twice.
 */
export function findNextSendIndex(
  outgoingNode: Uint8Array,
  seenEphemeralPubs: Iterable<Uint8Array>,
  gapLimit = 20,
): number {
  const seen = new Set<string>();
  for (const pub of seenEphemeralPubs) seen.add(bytesToHex(pub));

  let highestUsed = -1;
  let misses = 0;
  for (let index = 0; misses <= gapLimit; index++) {
    if (seen.has(bytesToHex(outgoingEphemeralKeyPair({ outgoingNode, sendIndex: index }).pubKey))) {
      highestUsed = index;
      misses = 0;
    } else {
      misses++;
    }
  }
  return highestUsed + 1;
}

/**
 * What makes a deposit address reconstructable.
 *
 * The ephemeral key is NOT random. A deposit address commits to it via the
 * tapleaf, and the key path is a NUMS point, so an address whose ephemeral key
 * is lost is an address nobody — not the owner, not the pool — can ever spend.
 * Indexing it off the viewing node makes that node a complete backup: walk
 * `depositIndex` upward and every address comes back.
 */
export interface DepositRecoveryMaterial {
  /** From `depositViewingNode(viewingPrivKey)`. */
  viewingNode: Uint8Array;
  /** Monotonic per-owner counter. One address per index. */
  depositIndex: number;
}

/** `sha256(domain || viewingNode || depositIndex)` → Ed25519 ephemeral keypair. */
export function depositEphemeralKeyPair(recovery: DepositRecoveryMaterial): {
  privKey: Uint8Array;
  pubKey: Uint8Array;
} {
  const { viewingNode, depositIndex } = recovery;
  if (viewingNode.length === 0) {
    throw new Error("deposit viewingNode must not be empty");
  }
  if (!Number.isInteger(depositIndex) || depositIndex < 0) {
    throw new Error(`invalid depositIndex: ${depositIndex}`);
  }

  const material = new Uint8Array(DEPOSIT_EPHEMERAL_DOMAIN.length + viewingNode.length + 4);
  material.set(DEPOSIT_EPHEMERAL_DOMAIN, 0);
  material.set(viewingNode, DEPOSIT_EPHEMERAL_DOMAIN.length);
  new DataView(material.buffer).setUint32(
    DEPOSIT_EPHEMERAL_DOMAIN.length + viewingNode.length,
    depositIndex,
    true,
  );
  return ed25519KeyPairFromMaterial(material);
}

/** A deposit whose address alone binds the note keys — no OP_RETURN. */
export interface TweakDepositResult {
  /** Taproot address to send BTC to */
  btcAddress: string;
  /** 32-byte x-only output key for the deposit P2TR output */
  depositOutputKey: Uint8Array;
  /** 32-byte note public key */
  npk: Uint8Array;
  /** 32-byte Ed25519 ephemeral public key */
  ephemeralPub: Uint8Array;
  /** sha256(npk || ephemeralPub) — the commitment carried in the tapleaf */
  tweakCommitment: Uint8Array;
  /** The tapleaf: `<commitment> OP_DROP <ika_xonly> OP_CHECKSIG` */
  leafScript: Uint8Array;
  /** Its BIP-341 tapleaf hash, which is also the merkle root (single leaf) */
  leafHash: Uint8Array;
  /** Script-path witness is `[signature, leafScript, controlBlock]` */
  controlBlock: Uint8Array;
}

/**
 * Create a deposit for the OP_RETURN-free flow (`verify_deposit`, disc 25).
 *
 * The transaction carries nothing but a payment, so anything that can send to a
 * P2TR address can fund it — a hardware wallet, an exchange withdrawal, a faucet.
 * The note keys are recovered from instruction data at completion time and proven
 * against this address's tapleaf, so substituting either key derives a different
 * leaf, and so a different address that the funding transaction never paid.
 *
 * The address is spendable only by `vaultXOnlyPubkey` via the script path; its
 * key path is a NUMS point. That keeps the deposit under Ika custody from the
 * moment it confirms, and it is also the only shape Ika can sign for — its MPC
 * cannot produce a signature for a tweaked key.
 *
 * `recovery` is not optional on purpose. The address commits to the ephemeral
 * key and the key path is unspendable, so a random ephemeral key that is later
 * lost burns the coins outright. Indexing it off the viewing node means that
 * node is the backup — and it can be delegated without granting spend authority.
 *
 * Register the address with the tracker BEFORE any coins are sent — a deposit
 * with no OP_RETURN is invisible to block scanning, so an unregistered address
 * is one nobody is watching.
 */
export async function createTweakDeposit(
  recipientMeta: StealthMetaAddress,
  vaultXOnlyPubkey: Uint8Array,
  recovery: DepositRecoveryMaterial,
  network: BitcoinNetwork = "testnet",
): Promise<TweakDepositResult> {
  if (vaultXOnlyPubkey.length !== 32) {
    throw new Error("vaultXOnlyPubkey must be 32 bytes");
  }

  const viewingPubKey = new Uint8Array(recipientMeta.viewingPubKey);
  const ephemeral = depositEphemeralKeyPair(recovery);
  const sharedSecret = x25519Ecdh(ephemeral.privKey, viewingPubKey);
  const stealthScalar = deriveStealthScalar(sharedSecret);
  const recipientMPK = bytesToBigint(recipientMeta.mpk);
  const npk = bigintToBytes(computeNPKSync(recipientMPK, stealthScalar));
  const ephemeralPub = new Uint8Array(ephemeral.pubKey);

  const { depositTweakCommitment, deriveDepositAddress } = await import("./taproot");
  const tweakCommitment = depositTweakCommitment(npk, ephemeralPub);
  const { address, outputKey, leafScript, leafHash, controlBlock } = deriveDepositAddress(
    tweakCommitment,
    vaultXOnlyPubkey,
    network,
  );

  return {
    btcAddress: address,
    depositOutputKey: outputKey,
    npk,
    ephemeralPub,
    tweakCommitment,
    leafScript,
    leafHash,
    controlBlock,
  };
}

/**
 * Create a non-interactive deposit using the current SDK config.
 *
 * Direct-vault/Ika deposit helper.
 *
 * Deposits go to the raw Ika x-only P2TR vault address. Recipient binding
 * stays per-deposit in OP_RETURN(header || poolTag || ephemeralPub || npk), and the destination chain
 * credits the note by SPV-verifying that deposit transaction directly. Legacy sweep-mode
 * address derivation is intentionally not selected from config anymore.
 */
export async function createDepositFromConfig(
  recipientMeta: StealthMetaAddress,
  network: BitcoinNetwork = "testnet",
  opReturnContext?: DepositOpReturnContext,
): Promise<NonInteractiveDepositResult> {
  const config = getConfig();
  const ikaKey = pickIkaCustodyKey(config);
  if (!ikaKey) {
    throw new Error("Ika direct-vault deposits require ikaDwalletXOnlyPubkey in config");
  }
  if (config.depositMode && !isDirectVaultDepositMode(config.depositMode)) {
    throw new Error(`Unsupported depositMode "${config.depositMode}"; only Ika direct-vault deposits are supported`);
  }
  return createDirectVaultDeposit(recipientMeta, ikaKey, network, opReturnContext);
}

export function isDirectVaultDepositMode(mode?: string): boolean {
  return mode === "direct" || mode === "direct_vault" || mode === "ika_direct";
}

/**
 * Choose the Taproot internal key for deposit-address derivation.
 * The Ika dWallet x-only pubkey is the sole custody key; throws if unset.
 * Exported for unit tests; non-test callers should use `createDepositFromConfig`.
 */
export function pickCustodyInternalKey(config: {
  ikaDwalletXOnlyPubkey?: string;
}): Uint8Array {
  const ikaKey = pickIkaCustodyKey(config);
  if (!ikaKey) {
    throw new Error(
      "PoolConfig.ika_dwallet_xonly_pubkey is required; pool custody key is not configured",
    );
  }
  return ikaKey;
}

export function pickIkaCustodyKey(config: {
  ikaDwalletXOnlyPubkey?: string;
}): Uint8Array | null {
  const ikaHex = config.ikaDwalletXOnlyPubkey ?? "";
  if (ikaHex && /[1-9a-f]/i.test(ikaHex)) {
    return hexToBytes(ikaHex);
  }
  return null;
}

// ========== Recipient Scanning (Viewing Key Only) ==========

/**
 * Scan announcements using viewing key only
 */
export async function scanAnnouncements(
  source: WalletSignerAdapter | UTXOpiaKeys,
  announcements: {
    ephemeralPub: Uint8Array;
    encryptedAmount: Uint8Array;
    commitment: Uint8Array;
    leafIndex: number;
  }[],
  tokenId: bigint,
): Promise<ScannedNote[]> {
  const keys = isWalletAdapter(source) ? await deriveKeysFromWallet(source) : source;

  const found: ScannedNote[] = [];
  const MAX_SATS = 21_000_000n * 100_000_000n;

  // Compute MPK for this key set
  const mpk = computeMPKSync(keys.spendingPubKey.x, keys.spendingPubKey.y, keys.nullifyingKey);

  for (const ann of announcements) {
    try {
      // X25519 ECDH with viewing key
      const sharedSecret = x25519Ecdh(keys.viewingPrivKey, ann.ephemeralPub);

      // Decrypt amount
      const amount = decryptAmount(ann.encryptedAmount, sharedSecret);

      if (amount <= 0n || amount > MAX_SATS) {
        continue;
      }

      // Derive stealth public key (still needed for spending)
      const stealthPub = deriveStealthPubKey(keys.spendingPubKey, sharedSecret);

      // Derive stealth scalar as random for NPK
      const stealthScalar = deriveStealthScalar(sharedSecret);

      // Compute expected NPK and commitment (JoinSplit format)
      const npk = computeNPKSync(mpk, stealthScalar);
      const expectedCommitment = computeJoinSplitCommitmentSync(npk, tokenId, amount);
      const actualCommitment = bytesToBigint(ann.commitment);

      if (expectedCommitment !== actualCommitment) {
        continue;
      }

      found.push({
        amount,
        ephemeralPub: ann.ephemeralPub,
        stealthPub,
        leafIndex: ann.leafIndex,
        commitment: ann.commitment,
      });
    } catch (error) {
      // Re-throw programming errors; only skip data/crypto mismatches
      if (error instanceof TypeError || error instanceof RangeError) {
        throw error;
      }
      continue;
    }
  }

  return found;
}

// ========== View-Only Scanning ==========

/**
 * View-only keys for scanning without spending capability
 */
export interface ViewOnlyKeys {
  /** Ed25519 viewing private key (32 bytes) */
  viewingPrivKey: Uint8Array;
  /** Baby Jubjub spending public key */
  spendingPubKey: BabyJubPoint;
  /** Nullifying key (needed for MPK computation in JoinSplit scanning) */
  nullifyingKey: bigint;
}

/**
 * Scanned note from view-only scanning
 */
export interface ViewOnlyScannedNote {
  amount: bigint;
  leafIndex: number;
  commitment: Uint8Array;
  ephemeralPub: Uint8Array;
  /** Unix timestamp (seconds) from on-chain block_time, 0 if unavailable */
  blockTime?: number;
}

/**
 * Scan announcements with VIEW-ONLY keys against SEVERAL token ids in one pass.
 * Same one-ECDH-per-announcement economics as {@link scanUnifiedNotesMulti}.
 */
export async function scanAnnouncementsViewOnlyMulti(
  viewOnlyKeys: ViewOnlyKeys,
  announcements: {
    announcementType: number;
    ephemeralPub: Uint8Array;
    encryptedAmount: Uint8Array;
    commitment: Uint8Array;
    leafIndex: number;
    blockTime?: number;
  }[],
  tokenIds: bigint[],
): Promise<Array<ViewOnlyScannedNote & { tokenId: bigint }>> {
  return matchAnnouncements(viewOnlyKeys, announcements, tokenIds).map((match) => ({
    amount: match.amount,
    leafIndex: match.announcement.leafIndex,
    commitment: match.commitment,
    ephemeralPub: match.announcement.ephemeralPub,
    blockTime: match.announcement.blockTime ?? 0,
    tokenId: match.tokenId,
  }));
}

/**
 * Scan announcements with VIEW-ONLY keys.
 * Latest announcement rows must carry an explicit type.
 */
export async function scanAnnouncementsViewOnly(
  viewOnlyKeys: ViewOnlyKeys,
  announcements: {
    announcementType: number;
    ephemeralPub: Uint8Array;
    encryptedAmount: Uint8Array;
    commitment: Uint8Array;
    leafIndex: number;
    blockTime?: number;
  }[],
  tokenId: bigint,
): Promise<ViewOnlyScannedNote[]> {
  return scanAnnouncementsViewOnlyMulti(viewOnlyKeys, announcements, [tokenId]);
}

/**
 * Export view-only keys from full UTXOpiaKeys
 */
export function exportViewOnlyKeys(keys: UTXOpiaKeys): ViewOnlyKeys {
  return {
    viewingPrivKey: keys.viewingPrivKey,
    spendingPubKey: keys.spendingPubKey,
    nullifyingKey: keys.nullifyingKey,
  };
}

/**
 * Encode view-only keys as a hex string for sharing
 * Format: viewingPrivKey(32) + compressedSpendingPub(32) + nullifyingKey(32) = 96 bytes
 */
export function encodeViewOnlyKeys(keys: ViewOnlyKeys): string {
  const compressed = babyJubCompress(keys.spendingPubKey);
  const nullBytes = bigintToBytes(keys.nullifyingKey);
  const combined = new Uint8Array(96);
  combined.set(keys.viewingPrivKey, 0);
  combined.set(compressed, 32);
  combined.set(nullBytes, 64);
  return bytesToHex(combined);
}

/**
 * Decode view-only keys from a hex string
 */
export function decodeViewOnlyKeys(encoded: string): ViewOnlyKeys {
  const bytes = hexToBytes(encoded);
  if (bytes.length !== 96) {
    throw new Error("Invalid view-only key length (expected 96 bytes)");
  }
  const viewingPrivKey = bytes.slice(0, 32);
  const compressed = bytes.slice(32, 64);
  const spendingPubKey = babyJubDecompress(compressed);
  const nullifyingKey = bytesToBigint(bytes.slice(64, 96));
  return { viewingPrivKey, spendingPubKey, nullifyingKey };
}

// ========== Claim Preparation (Spending Key Required) ==========

/**
 * Prepare claim inputs for ZK proof generation
 */
export async function prepareClaimInputs(
  source: WalletSignerAdapter | UTXOpiaKeys,
  note: ScannedNote,
  merkleProof: {
    root: bigint;
    pathElements: bigint[];
    pathIndices: number[];
  }
): Promise<ClaimInputs> {
  const keys = isWalletAdapter(source) ? await deriveKeysFromWallet(source) : source;

  // X25519 ECDH to recover shared secret
  const sharedSecret = x25519Ecdh(keys.viewingPrivKey, note.ephemeralPub);

  // Derive stealth private key (Baby Jubjub scalar addition)
  const stealthPrivKey = deriveStealthPrivKey(keys.spendingPrivKey, sharedSecret);

  // Verify stealth public key matches
  const expectedStealthPub = babyJubMul(stealthPrivKey, BABYJUB_BASE8);
  if (expectedStealthPub.x !== note.stealthPub.x || expectedStealthPub.y !== note.stealthPub.y) {
    throw new Error(
      "Stealth key mismatch - this note may not belong to you or the announcement is invalid"
    );
  }

  // Derive the random value (stealth scalar) for NPK
  const stealthScalar = deriveStealthScalar(sharedSecret);

  // Compute MPK and NPK
  const mpk = computeMPKSync(keys.spendingPubKey.x, keys.spendingPubKey.y, keys.nullifyingKey);
  const npk = computeNPKSync(mpk, stealthScalar);

  // Compute JoinSplit nullifier
  const nullifier = computeJoinSplitNullifierSync(keys.nullifyingKey, BigInt(note.leafIndex));

  return {
    stealthPrivKey,
    nullifyingKey: keys.nullifyingKey,
    amount: note.amount,
    leafIndex: note.leafIndex,
    merklePath: merkleProof.pathElements,
    merkleIndices: merkleProof.pathIndices,
    merkleRoot: merkleProof.root,
    nullifier,
    npk,
    random: stealthScalar,
  };
}

// ========== Unified Note Scanning ==========

/** Announcement shape the scanners need. Wider than OnChainStealthAnnouncement
 *  so view-only callers can pass their own rows. */
interface ScannableAnnouncement {
  announcementType: number;
  ephemeralPub: Uint8Array;
  encryptedAmount: Uint8Array;
  commitment: Uint8Array;
  leafIndex: number;
  blockTime?: number;
}

/** What a scan recovers before it is shaped into a note. */
interface AnnouncementMatch {
  announcement: ScannableAnnouncement;
  amount: bigint;
  tokenId: bigint;
  commitment: Uint8Array;
  sharedSecret: Uint8Array;
}

const MAX_SATS = 21_000_000n * 100_000_000n;

/**
 * Trial-decrypt each announcement ONCE and test the result against every token
 * id, instead of redoing the whole derivation per token.
 *
 * Everything up to the commitment — the x25519 ECDH, the amount, the stealth
 * scalar, the NPK — is token-independent; only the closing
 * Poseidon(npk, tokenId, amount) comparison is not. Scanning T tokens the naive
 * way therefore paid T ECDHs per announcement to answer one question, and the
 * ECDH is the expensive half.
 *
 * A commitment binds exactly one token id, so the first match wins and the
 * remaining ids are skipped.
 */
function matchAnnouncements(
  viewKeys: ViewOnlyKeys,
  announcements: ScannableAnnouncement[],
  tokenIds: bigint[],
): AnnouncementMatch[] {
  if (tokenIds.length === 0) return [];

  const matches: AnnouncementMatch[] = [];
  const mpk = computeMPKSync(
    viewKeys.spendingPubKey.x,
    viewKeys.spendingPubKey.y,
    viewKeys.nullifyingKey,
  );

  for (const ann of announcements) {
    try {
      if (!isKnownAnnouncementType(ann.announcementType)) {
        continue;
      }

      // X25519 ECDH with viewing key — once per announcement, not per token
      const sharedSecret = x25519Ecdh(viewKeys.viewingPrivKey, ann.ephemeralPub);

      // Get amount based on type
      let amount: bigint;
      if (ann.announcementType === ANNOUNCEMENT_TYPE_DEPOSIT) {
        // Plaintext u64 LE
        const view = new DataView(ann.encryptedAmount.buffer, ann.encryptedAmount.byteOffset, 8);
        amount = view.getBigUint64(0, true);
      } else {
        // XOR-encrypted
        amount = decryptAmount(ann.encryptedAmount, sharedSecret);
      }

      if (amount <= 0n || amount > MAX_SATS) {
        continue;
      }

      // Derive stealth scalar and expected NPK (computed locally)
      const stealthScalar = deriveStealthScalar(sharedSecret);
      const npk = computeNPKSync(mpk, stealthScalar);
      const onChain = bytesToBigint(ann.commitment);

      for (const tokenId of tokenIds) {
        // Verify the recomputed commitment against the on-chain one for BOTH
        // deposits and transfers — a foreign transfer whose XOR-decrypted amount
        // lands in range would otherwise become a phantom note.
        const commitmentBigint = computeJoinSplitCommitmentSync(npk, tokenId, amount);
        if (commitmentBigint !== onChain) continue;

        matches.push({
          announcement: ann,
          amount,
          tokenId,
          // Use on-chain commitment bytes for transfers (preserves exact on-chain value)
          commitment: ann.announcementType === ANNOUNCEMENT_TYPE_DEPOSIT
            ? bigintToBytes(commitmentBigint)
            : new Uint8Array(ann.commitment),
          sharedSecret,
        });
        break;
      }
    } catch (error) {
      if (error instanceof TypeError || error instanceof RangeError) {
        throw error;
      }
      continue;
    }
  }

  return matches;
}

/** A note found by a multi-token scan, tagged with the token id it matched. */
export type MultiScannedNote = ScannedNote & { tokenId: bigint };

/**
 * Scan unified StealthAnnouncement notes (both deposits and transfers) against
 * SEVERAL token ids in one pass.
 *
 * Prefer this over calling {@link scanUnifiedNotes} once per token: the cost is
 * one ECDH per announcement either way, plus one Poseidon per token id tried.
 */
export async function scanUnifiedNotesMulti(
  source: WalletSignerAdapter | UTXOpiaKeys,
  announcements: OnChainStealthAnnouncement[],
  tokenIds: bigint[],
): Promise<MultiScannedNote[]> {
  const keys = isWalletAdapter(source) ? await deriveKeysFromWallet(source) : source;

  return matchAnnouncements(exportViewOnlyKeys(keys), announcements, tokenIds).map((match) => ({
    amount: match.amount,
    ephemeralPub: match.announcement.ephemeralPub,
    // Stealth public key, for spending
    stealthPub: deriveStealthPubKey(keys.spendingPubKey, match.sharedSecret),
    leafIndex: match.announcement.leafIndex,
    commitment: match.commitment,
    blockTime: match.announcement.blockTime ?? 0,
    tokenId: match.tokenId,
  }));
}

/**
 * Scan unified StealthAnnouncement notes (both deposits and transfers).
 *
 * For each announcement:
 * - type=0 (deposit): amount is plaintext u64 LE in amount_bytes
 * - type=1 (transfer): amount is XOR-encrypted in amount_bytes
 *
 * Commitment is computed locally: Poseidon(npk, tokenId, amount) and compared
 * against the on-chain one, which is what proves the note is ours.
 */
export async function scanUnifiedNotes(
  source: WalletSignerAdapter | UTXOpiaKeys,
  announcements: OnChainStealthAnnouncement[],
  tokenId: bigint,
): Promise<ScannedNote[]> {
  return scanUnifiedNotesMulti(source, announcements, [tokenId]);
}

// ========== Connection Adapter ==========

import type { Address } from "@solana/kit";
import type { BitcoinNetwork } from "./taproot";

export interface ConnectionAdapter {
  getAccountInfo: (
    pubkey: Address
  ) => Promise<{ data: Uint8Array } | null>;
}

// ========== Stealth Output Creation ==========

export interface StealthOutputData {
  /** Ed25519 ephemeral public key (32 bytes) */
  ephemeralPub: Uint8Array;
  /** XOR encrypted amount (8 bytes) */
  encryptedAmount: Uint8Array;
  /** Commitment = Poseidon(stealthPub.x, amount) */
  commitment: Uint8Array;
}

/**
 * Circuit-ready stealth output data
 */
export interface CircuitStealthOutput {
  /** Ephemeral pubkey (32 bytes as bigint) */
  ephemeralPubX: bigint;
  /** Packed: bits 0-63 = encrypted amount, bit 64 = reserved (0 for Ed25519) */
  encryptedAmountWithSign: bigint;
}

/**
 * Pack encrypted amount (no y_sign needed for Ed25519 — 32-byte keys, no prefix)
 *
 * Layout: bits 0-63 = encrypted amount (little-endian), bit 64 = 0 (reserved)
 */
export function packEncryptedAmountWithSign(encryptedAmount: Uint8Array, _ySign: boolean = false): bigint {
  if (encryptedAmount.length !== 8) {
    throw new Error("Encrypted amount must be 8 bytes");
  }

  let amount = 0n;
  for (let i = 7; i >= 0; i--) {
    amount = (amount << 8n) | BigInt(encryptedAmount[i]);
  }

  // For Ed25519, we don't have a y_sign prefix, but keep the bit for compatibility
  if (_ySign) {
    amount |= (1n << 64n);
  }

  return amount;
}

/**
 * Convert StealthOutputData to circuit-ready format
 */
export function packStealthOutputForCircuit(output: StealthOutputData): CircuitStealthOutput {
  // Ed25519 ephemeral pub is 32 bytes — interpret as big-endian bigint
  const ephemeralPubX = bytesToBigint(output.ephemeralPub);
  const encryptedAmountWithSign = packEncryptedAmountWithSign(output.encryptedAmount);

  return {
    ephemeralPubX,
    encryptedAmountWithSign,
  };
}

/**
 * Create stealth output data for a self-send (change output)
 */
export async function createStealthOutput(
  keys: UTXOpiaKeys,
  amountSats: bigint,
  tokenId: bigint,
): Promise<StealthOutputData> {
  const ephemeral = ed25519GenerateKeyPair();
  const sharedSecret = x25519Ecdh(ephemeral.privKey, keys.viewingPubKey);

  const stealthScalar = deriveStealthScalar(sharedSecret);
  const mpk = computeMPKSync(keys.spendingPubKey.x, keys.spendingPubKey.y, keys.nullifyingKey);
  const npk = computeNPKSync(mpk, stealthScalar);

  const commitmentBigint = computeJoinSplitCommitmentSync(npk, tokenId, amountSats);
  const commitment = bigintToBytes(commitmentBigint);
  const encryptedAmount = encryptAmount(amountSats, sharedSecret);

  return {
    ephemeralPub: new Uint8Array(ephemeral.pubKey),
    encryptedAmount,
    commitment,
  };
}

/**
 * Create stealth output with npk for JoinSplit circuit input
 */
export async function createStealthOutputWithKeys(
  keys: UTXOpiaKeys,
  amountSats: bigint,
  tokenId: bigint,
): Promise<StealthOutputWithKeys> {
  const ephemeral = ed25519GenerateKeyPair();
  const sharedSecret = x25519Ecdh(ephemeral.privKey, keys.viewingPubKey);

  const stealthScalar = deriveStealthScalar(sharedSecret);
  const mpk = computeMPKSync(keys.spendingPubKey.x, keys.spendingPubKey.y, keys.nullifyingKey);
  const npk = computeNPKSync(mpk, stealthScalar);

  const commitmentBigint = computeJoinSplitCommitmentSync(npk, tokenId, amountSats);
  const commitment = bigintToBytes(commitmentBigint);
  const encryptedAmount = encryptAmount(amountSats, sharedSecret);

  return {
    ephemeralPub: new Uint8Array(ephemeral.pubKey),
    encryptedAmount,
    commitment,
    stealthPubKeyX: npk,
    npkBytes: bigintToBytes(npk),
  };
}

/**
 * Create stealth output data with pre-computed commitment
 */
export async function createStealthOutputForCommitment(
  keys: UTXOpiaKeys,
  amountSats: bigint,
  existingCommitment: Uint8Array
): Promise<StealthOutputData> {
  const ephemeral = ed25519GenerateKeyPair();
  const sharedSecret = x25519Ecdh(ephemeral.privKey, keys.viewingPubKey);

  const encryptedAmount = encryptAmount(amountSats, sharedSecret);

  return {
    ephemeralPub: new Uint8Array(ephemeral.pubKey),
    encryptedAmount,
    commitment: existingCommitment,
  };
}

// ========== Nullifier Computation ==========

/**
 * Compute nullifier hash for a scanned note
 */
export function computeNullifierHashForNote(
  keys: UTXOpiaKeys,
  note: ScannedNote
): Uint8Array {
  // In JoinSplit model, nullifier = Poseidon(nullifyingKey, leafIndex)
  // No extra hash layer — the nullifier IS the public output
  const nullifier = computeJoinSplitNullifierSync(keys.nullifyingKey, BigInt(note.leafIndex));
  return bigintToBytes(nullifier);
}

/**
 * Compute nullifier hash for a note and return as raw bytes.
 * Convenience wrapper — avoids importing computeJoinSplitNullifierSync + bigintToBytes in consumers.
 */
export function computeNullifierBytes(nullifyingKey: bigint, leafIndex: number): Uint8Array {
  const nullifier = computeJoinSplitNullifierSync(nullifyingKey, BigInt(leafIndex));
  return bigintToBytes(nullifier);
}

// ========== Announcement Parsing ==========

/**
 * Parse backend announcement rows (hex strings) into the format scanUnifiedNotes expects.
 */
export function parseAnnouncementsFromHex(rows: Array<{
  announcement_type: number;
  ephemeral_pub: string;
  encrypted_amount: string;
  commitment: string;
  leaf_index: number;
  token_id?: string | null;
}>): Array<{
  announcementType: number;
  ephemeralPub: Uint8Array;
  encryptedAmount: Uint8Array;
  commitment: Uint8Array;
  leafIndex: number;
  tokenIdHex?: string;
}> {
  return rows.map((r) => ({
    announcementType: r.announcement_type,
    ephemeralPub: hexToBytes(r.ephemeral_pub),
    encryptedAmount: hexToBytes(r.encrypted_amount),
    commitment: hexToBytes(r.commitment),
    leafIndex: r.leaf_index,
    tokenIdHex: r.token_id ?? undefined,
  }));
}

// ========== Deposit Ownership Check ==========

/**
 * Check if a deposit (identified by its OP_RETURN ephemeralPub + npk) belongs
 * to the given viewing key holder.
 *
 * Performs X25519 ECDH between the viewer's private key and the deposit's
 * ephemeral public key, derives the expected NPK, and compares it with the
 * deposit's actual NPK.
 */
export function isDepositForViewer(
  viewingPrivKey: Uint8Array,
  spendingPubKey: { x: bigint; y: bigint },
  nullifyingKey: bigint,
  ephemeralPub: Uint8Array,
  depositNpk: bigint,
): boolean {
  try {
    const sharedSecret = x25519Ecdh(viewingPrivKey, ephemeralPub);
    const mpk = computeMPKSync(spendingPubKey.x, spendingPubKey.y, nullifyingKey);
    const stealthScalar = deriveStealthScalar(sharedSecret);
    const expectedNpk = computeNPKSync(mpk, stealthScalar);
    return expectedNpk === depositNpk;
  } catch {
    return false;
  }
}

/**
 * Check if a deposit belongs to this viewer — accepts hex string inputs.
 * Convenience wrapper around isDepositForViewer for frontend use.
 */
export function isDepositForViewerHex(
  keys: { viewingPrivKey: Uint8Array; spendingPubKey: { x: bigint; y: bigint }; nullifyingKey: bigint },
  ephemeralPubHex: string,
  npkHex: string,
): boolean {
  try {
    const ephPub = hexToBytes(ephemeralPubHex);
    const npk = bytesToBigint(hexToBytes(npkHex));
    return isDepositForViewer(keys.viewingPrivKey, keys.spendingPubKey, keys.nullifyingKey, ephPub, npk);
  } catch {
    return false;
  }
}
