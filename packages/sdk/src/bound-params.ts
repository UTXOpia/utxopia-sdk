/**
 * Bound Parameters Hash for JoinSplit transactions
 *
 * The boundParamsHash binds transaction metadata to the proof:
 * - treeNumber: Which commitment tree (for multi-tree support)
 * - unshieldAddress: Recipient for public unshield (null = private transfer)
 * - chainId: Prevents cross-chain replay
 * - stealthDataHash: SHA256 of concatenated stealth data (prevents relayer tampering)
 *
 * Hash: SHA256(serialize(params)) mod BN254_SCALAR_FIELD
 */

import { sha256 } from "@noble/hashes/sha2.js";
import { BN254_FIELD_PRIME, bytesToBigint } from "./crypto";

/** Bound params mode: transfer(0), unshield(1), redeem(2) */
export type BoundParamsMode = 'transfer' | 'unshield' | 'redeem';

export interface BoundParams {
  /** Tree number (0 for default) */
  treeNumber: number;
  /** Unshield recipient address (null = private transfer, 32 bytes = public unshield/redeem) */
  unshieldAddress: Uint8Array | null;
  /** Chain ID (prevents cross-chain replay) */
  chainId: bigint;
  /** Mode flag: 'transfer'(0), 'unshield'(1), 'redeem'(2). Defaults to inferred from unshieldAddress. */
  mode?: BoundParamsMode;
  /** SHA256 of concatenated stealth data (prevents relayer from corrupting change outputs) */
  stealthDataHash: Uint8Array;
  /**
   * Requester pubkey (32 bytes) — REQUIRED for redeem. Binds the proof to the signing account
   * that becomes RedemptionRequest.requester so a privileged orderflow actor cannot replay the
   * proof under their own key. Ignored for transfer/unshield.
   */
  requester?: Uint8Array;
}

/**
 * Compute SHA256 hash of concatenated stealth data arrays.
 * Returns 32-byte hash, or all zeros if no stealth data.
 */
export function computeStealthDataHash(stealthData: Uint8Array[]): Uint8Array {
  // Always SHA256 the concatenation — even for empty arrays.
  // On-chain: sha256(&data[stealth_start..stealth_end]) — empty slice → sha256("")
  const totalLen = stealthData.reduce((sum, sd) => sum + sd.length, 0);
  const concat = new Uint8Array(totalLen);
  let offset = 0;
  for (const sd of stealthData) {
    concat.set(sd, offset);
    offset += sd.length;
  }
  return sha256(concat);
}

/**
 * Compute the bound parameters hash
 *
 * Deterministic serialization:
 * - treeNumber: 4 bytes LE
 * - flag: 1 byte (0=transfer, 1=unshield, 2=redeem)
 * - unshieldAddress: 32 bytes (zeros if null)
 * - chainId: 8 bytes LE
 * - stealthDataHash: 32 bytes (SHA256 of concatenated stealth data)
 * - requester: 32 bytes (redeem only — appended, extending the buffer to 109 bytes)
 *
 * Total: 77 bytes (transfer/unshield) or 109 bytes (redeem) → SHA256 → mod BN254
 */
export function computeBoundParamsHash(params: BoundParams): bigint {
  const isRedeem = params.mode === 'redeem';
  // Redeem binds the requester pubkey, extending the preimage by 32 bytes (must match the
  // on-chain compute_bound_params_hash_redeem layout).
  const buf = new Uint8Array(isRedeem ? 109 : 77);
  const view = new DataView(buf.buffer);

  // treeNumber (4 bytes LE)
  view.setUint32(0, params.treeNumber, true);

  // flag byte: transfer=0, unshield=1, redeem=2
  if (isRedeem) {
    buf[4] = 2;
  } else if (params.mode === 'unshield' || params.unshieldAddress) {
    buf[4] = 1;
  } else {
    buf[4] = 0;
  }

  // unshieldAddress (32 bytes, zeros if null)
  if (params.unshieldAddress) {
    buf.set(params.unshieldAddress.slice(0, 32), 5);
  }

  // chainId (8 bytes LE)
  const chainIdBuf = new Uint8Array(8);
  let chainId = params.chainId;
  for (let i = 0; i < 8; i++) {
    chainIdBuf[i] = Number(chainId & 0xffn);
    chainId >>= 8n;
  }
  buf.set(chainIdBuf, 37);

  // stealthDataHash (32 bytes)
  buf.set(params.stealthDataHash.slice(0, 32), 45);

  // requester (32 bytes) — redeem only
  if (isRedeem) {
    if (!params.requester || params.requester.length !== 32) {
      throw new Error("redeem bound params require a 32-byte requester pubkey");
    }
    buf.set(params.requester.slice(0, 32), 77);
  }

  // SHA256 → mod BN254
  const hash = sha256(buf);
  return bytesToBigint(hash) % BN254_FIELD_PRIME;
}

/** Canonical chain ids folded into bound-params hashes (must match on-chain). */
export const SOLANA_BOUND_CHAIN_ID = 103n;
export const SUI_BOUND_CHAIN_ID = 784n;

/**
 * Default bound params for Solana devnet (private transfer)
 */
export function createTransferBoundParams(
  stealthDataHash: Uint8Array,
  chainId: bigint = 103n,
  treeNumber: number = 0,
): BoundParams {
  return {
    treeNumber,
    unshieldAddress: null,
    chainId,
    stealthDataHash,
  };
}

/** @deprecated Use createTransferBoundParams instead */
export const DEFAULT_BOUND_PARAMS: BoundParams = {
  treeNumber: 0,
  unshieldAddress: null,
  chainId: 103n,
  stealthDataHash: new Uint8Array(32),
};

/**
 * Create bound params for a redeem (JoinSplit → BTC withdrawal, multi-output)
 *
 * The BTC scriptPubKeys are concatenated and SHA-256 hashed into the address field
 * so the proof cryptographically binds ALL withdrawal destinations.
 *
 * For single output: SHA256(script_1) — no special case.
 * For multi-output: SHA256(script_1 || script_2 || ...)
 *
 * `requester` is the 32-byte pubkey of the signer that will submit the redeem (becomes
 * RedemptionRequest.requester); it is bound into the hash so the proof cannot be replayed
 * under a different signer.
 */
export function createRedeemBoundParams(
  btcScripts: Uint8Array | Uint8Array[],
  stealthDataHash: Uint8Array,
  requester: Uint8Array,
  chainId: bigint = 103n,
  treeNumber: number = 0,
): BoundParams {
  if (!requester || requester.length !== 32) {
    throw new Error("createRedeemBoundParams requires a 32-byte requester pubkey");
  }
  // Normalize to array
  const scripts = btcScripts instanceof Uint8Array ? [btcScripts] : btcScripts;
  // Length-prefixed scripts hash (audit #4): sha256(u32le(count) || per-script
  // [u32le(len) || bytes]). Binds the script boundaries so a redeem proof cannot be
  // replayed with the scripts re-partitioned to the same concatenation. Must match the
  // on-chain Solana `length_prefixed_hash` in compute_bound_params_hash_redeem.
  const lpParts: Uint8Array[] = [u32le(scripts.length)];
  for (const s of scripts) {
    lpParts.push(u32le(s.length), s);
  }
  const lpTotal = lpParts.reduce((sum, p) => sum + p.length, 0);
  const lp = new Uint8Array(lpTotal);
  let off = 0;
  for (const p of lpParts) {
    lp.set(p, off);
    off += p.length;
  }
  const scriptHash = sha256(lp);
  return {
    treeNumber,
    unshieldAddress: scriptHash,
    chainId,
    mode: 'redeem',
    stealthDataHash,
    requester,
  };
}

/**
 * Create bound params for a Sui generic-coin unshield.
 *
 * Mirrors `bound_params::unshield_hash`: the 32-byte (BCS) recipient addresses are
 * concatenated and SHA256'd into the unshieldAddress slot, with the Sui domain chain id.
 * `recipients` are raw 32-byte big-endian Sui addresses; `stealthHash` is the
 * already-computed SHA256 of the concatenated stealth data (see computeStealthDataHash).
 */
export function createSuiUnshieldBoundParams(
  recipients: Uint8Array | Uint8Array[],
  stealthHash: Uint8Array,
): BoundParams {
  return createUnshieldBoundParams(recipients, stealthHash, SUI_BOUND_CHAIN_ID);
}

// ---------------------------------------------------------------------------
// Sui length-prefixed bound-params (audit #4 / #51–54).
//
// The Sui Move program (`bound_params.move`) binds list inputs (BTC scripts, stealth-data
// entries, unshield recipients) with explicit boundaries so a proof can't be replayed with a
// different partitioning of the same concatenated bytes. These helpers reproduce that exact
// encoding and MUST stay byte-identical to the Move side (locked by tests in both languages).
//
// NOTE: this is Sui-only. The Solana program + the generic `computeBoundParamsHash` /
// `computeStealthDataHash` / `create*BoundParams` helpers keep the flat-concat encoding.
// ---------------------------------------------------------------------------

function u32le(n: number): Uint8Array {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n >>> 0, true);
  return b;
}

/** sha256( u32le(count) || for each item [ u32le(len) || item ] ) — matches Move `length_prefixed_hash`. */
export function suiLengthPrefixedHash(items: Uint8Array[]): Uint8Array {
  const parts: Uint8Array[] = [u32le(items.length)];
  for (const it of items) {
    parts.push(u32le(it.length));
    parts.push(it);
  }
  const total = parts.reduce((s, p) => s + p.length, 0);
  const buf = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    buf.set(p, off);
    off += p.length;
  }
  return sha256(buf);
}

/** SHA256 of the length-prefixed stealth-data list — matches Move `stealth_data_hash`. */
export function computeSuiStealthDataHash(stealthData: Uint8Array[]): Uint8Array {
  return suiLengthPrefixedHash(stealthData);
}

/**
 * Build the Sui bound-params hash (field element), matching Move `finalize`:
 *   payload = treeNumber(4=0) || flag(1) || addressSlot(32) || chainId_le(8) || stealthHash(32)
 *   result  = sha256(payload) mod BN254
 * flag: transfer=0, unshield=1, redeem=2.
 */
function computeSuiBoundParamsHash(flag: number, addressSlot: Uint8Array, stealthHash: Uint8Array): bigint {
  const buf = new Uint8Array(77);
  buf[4] = flag;
  buf.set(addressSlot.slice(0, 32), 5);
  let cid = SUI_BOUND_CHAIN_ID;
  for (let i = 0; i < 8; i++) {
    buf[37 + i] = Number(cid & 0xffn);
    cid >>= 8n;
  }
  buf.set(stealthHash.slice(0, 32), 45);
  return bytesToBigint(sha256(buf)) % BN254_FIELD_PRIME;
}

/** Sui private-transfer bound-params hash. `stealthData` are the raw per-output stealth blobs. */
export function computeSuiTransferBoundParamsHash(stealthData: Uint8Array[]): bigint {
  return computeSuiBoundParamsHash(0, new Uint8Array(32), suiLengthPrefixedHash(stealthData));
}

/** Sui unshield bound-params hash. `recipients` are raw 32-byte (BCS) Sui addresses. */
export function computeSuiUnshieldBoundParamsHash(recipients: Uint8Array[], stealthData: Uint8Array[]): bigint {
  return computeSuiBoundParamsHash(1, suiLengthPrefixedHash(recipients), suiLengthPrefixedHash(stealthData));
}

/** Sui redeem bound-params hash. `btcScripts` are the per-output scriptPubKeys (bound with boundaries). */
export function computeSuiRedeemBoundParamsHash(btcScripts: Uint8Array[], stealthData: Uint8Array[]): bigint {
  return computeSuiBoundParamsHash(2, suiLengthPrefixedHash(btcScripts), suiLengthPrefixedHash(stealthData));
}

/**
 * Create bound params for an unshield (public withdrawal, multi-output)
 *
 * For multi-output: destinations_hash = SHA256(owner_1 || owner_2 || ...)
 * For single output: SHA256(owner_1) — no special case.
 */
export function createUnshieldBoundParams(
  recipientAddresses: Uint8Array | Uint8Array[],
  stealthDataHash: Uint8Array,
  chainId: bigint = 103n,
  treeNumber: number = 0,
): BoundParams {
  // Normalize to array
  const addrs = recipientAddresses instanceof Uint8Array ? [recipientAddresses] : recipientAddresses;
  // Concatenate all addresses
  const totalLen = addrs.reduce((sum, a) => sum + a.length, 0);
  const concat = new Uint8Array(totalLen);
  let off = 0;
  for (const a of addrs) {
    concat.set(a, off);
    off += a.length;
  }
  const addressHash = sha256(concat);
  return {
    treeNumber,
    unshieldAddress: addressHash,
    chainId,
    stealthDataHash,
  };
}
