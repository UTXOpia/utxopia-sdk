/**
 * Bound Parameters Hash for JoinSplit transactions
 *
 * The operation hash binds transaction metadata to the proof:
 * - treeNumber: Which commitment tree (for multi-tree support)
 * - unshieldAddress: Recipient for public unshield (null = private transfer)
 * - chainId: Prevents cross-chain replay
 * - stealthDataHash: SHA256 of concatenated stealth data (prevents relayer tampering)
 *
 * Hash: SHA256(serialize(params)) mod BN254_SCALAR_FIELD
 *
 * Solana callers must wrap this operation hash with
 * `computeSolanaDomainBoundParamsHash()` before generating a proof.
 */

import { sha256 } from "@noble/hashes/sha2.js";
import { BN254_FIELD_PRIME, bytesToBigint } from "./crypto";
import { poseidonHashSync } from "./poseidon";

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

export type SolanaPrivacyDomainKind = "public" | "institution";

export interface SolanaPrivacyDomainContext {
  programId: Uint8Array;
  poolState: Uint8Array;
  kind: SolanaPrivacyDomainKind;
}

const SOLANA_DOMAIN_TAG = new TextEncoder().encode("UTXOPIA_DOMAIN_V1");

function assert32Bytes(value: Uint8Array, name: string): void {
  if (value.length !== 32) {
    throw new Error(`${name} must be 32 bytes`);
  }
}

function u64le(value: bigint): Uint8Array {
  if (value < 0n || value > 0xffffffffffffffffn) {
    throw new Error("chainId must fit in u64");
  }
  const bytes = new Uint8Array(8);
  let remaining = value;
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return bytes;
}

/**
 * Compute the canonical public/institution domain field for Solana.
 *
 * SHA256("UTXOPIA_DOMAIN_V1" || chainIdLE || programId || poolState || kind)
 * reduced modulo BN254 Fr. The on-chain verifier recomputes this from the
 * actual program, pool account, and PoolState.permissioned flag.
 */
export function computeSolanaDomainSeparator(
  context: SolanaPrivacyDomainContext,
  chainId: bigint = SOLANA_BOUND_CHAIN_ID,
): bigint {
  assert32Bytes(context.programId, "programId");
  assert32Bytes(context.poolState, "poolState");
  if (context.kind !== "public" && context.kind !== "institution") {
    throw new Error("kind must be public or institution");
  }
  const preimage = new Uint8Array(SOLANA_DOMAIN_TAG.length + 8 + 32 + 32 + 1);
  let offset = 0;
  preimage.set(SOLANA_DOMAIN_TAG, offset);
  offset += SOLANA_DOMAIN_TAG.length;
  preimage.set(u64le(chainId), offset);
  offset += 8;
  preimage.set(context.programId, offset);
  offset += 32;
  preimage.set(context.poolState, offset);
  offset += 32;
  preimage[offset] = context.kind === "institution" ? 1 : 0;
  return bytesToBigint(sha256(preimage)) % BN254_FIELD_PRIME;
}

/**
 * Bind an operation-specific hash to its exact Solana privacy domain.
 *
 * This occupies the existing boundParamsHash public input, so circuit/VK
 * dimensions remain unchanged while proofs become non-replayable across pools.
 */
export function computeSolanaDomainBoundParamsHash(
  params: BoundParams,
  context: SolanaPrivacyDomainContext,
): bigint {
  if (
    params.chainId !== SOLANA_DEVNET_BOUND_CHAIN_ID
    && params.chainId !== SOLANA_MAINNET_BOUND_CHAIN_ID
  ) {
    throw new Error("Solana domain binding requires a supported Solana chain ID");
  }
  return poseidonHashSync([
    computeSolanaDomainSeparator(context, params.chainId),
    computeBoundParamsHash(params),
  ]);
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
 * Compute the operation-specific bound parameters hash.
 *
 * Solana callers must wrap this with
 * `computeSolanaDomainBoundParamsHash()` to bind the program and pool.
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
export const SOLANA_MAINNET_BOUND_CHAIN_ID = 101n;
export const SOLANA_DEVNET_BOUND_CHAIN_ID = 103n;
/** Backward-compatible devnet alias. Prefer the network-specific constants. */
export const SOLANA_BOUND_CHAIN_ID = SOLANA_DEVNET_BOUND_CHAIN_ID;

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
function u32le(n: number): Uint8Array {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n >>> 0, true);
  return b;
}

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
