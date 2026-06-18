/**
 * Taproot address utilities for UTXOpia
 *
 * Generates commitment-bound Taproot addresses following BIP-340/341.
 * The deposit address is derived from the commitment, ensuring
 * cryptographic binding between the BTC deposit and the claim.
 */

import { sha256 } from "@noble/hashes/sha2.js";
import { taggedHash, hexToBytes, bytesToHex } from "./crypto";
import * as bech32 from "bech32";
import { secp256k1 } from "@noble/curves/secp256k1.js";

// UTXOpia internal key (x-only pubkey)
// In production, this should be the FROST threshold key
// Using a test key for demonstration
const INTERNAL_KEY_HEX =
  "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"; // secp256k1 generator x-coord

/**
 * Derive a Taproot address from a commitment
 *
 * Following BIP-341:
 * tweak = H_TapTweak(internal_key || commitment)
 * output_key = internal_key + tweak * G
 * address = bech32m encode(output_key)
 *
 * @param commitment - 32-byte commitment hash
 * @param network - 'mainnet' | 'testnet' | 'regtest'
 * @param internalKey - Optional custom internal key (x-only, 32 bytes)
 * @returns Taproot address (bc1p... or tb1p...)
 */
export function deriveTaprootAddress(
  commitment: Uint8Array,
  network: "mainnet" | "testnet" | "regtest" = "testnet",
  internalKey?: Uint8Array
): {
  address: string;
  outputKey: Uint8Array;
  tweak: Uint8Array;
} {
  const key = internalKey || hexToBytes(INTERNAL_KEY_HEX);
  if (key.length !== 32) {
    throw new Error("Internal key must be 32 bytes (x-only)");
  }
  // Refuse the secp256k1 generator x-coord (discrete log = 1): its key-path secret
  // 1+tweak is publicly computable, so any observer could sweep the output.
  if (bytesToHex(key) === INTERNAL_KEY_HEX) {
    throw new Error("Refusing to derive Taproot with the generator internal key; pass a real FROST/Ika key");
  }

  // Compute tweak = H_TapTweak(internal_key || commitment)
  const tweakInput = new Uint8Array(64);
  tweakInput.set(key, 0);
  tweakInput.set(commitment, 32);
  const tweak = taggedHash("TapTweak", tweakInput);

  // BIP-341: output_key = lift_x(internal_key) + tweak * G
  const tweakScalar = bytesToBigInt(tweak);
  const SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
  if (tweakScalar >= SECP256K1_ORDER) {
    throw new Error("Tweak scalar exceeds curve order");
  }

  // lift_x: recover full point from x-only key (even y per BIP-340)
  const keyHex = "02" + bytesToHex(key);
  const internalPoint = secp256k1.Point.fromHex(keyHex);
  // tweak * G
  const tweakPoint = secp256k1.Point.BASE.multiply(tweakScalar);
  // Q = P + t*G
  const outputPoint = internalPoint.add(tweakPoint);
  // x-only output key (BIP-340): drop prefix from compressed form
  const outputKeyHex = outputPoint.toHex(true); // 33-byte compressed hex
  const outputKey = hexToBytes(outputKeyHex.slice(2)); // drop "02"/"03" prefix

  // Encode as bech32m address
  const hrp = network === "mainnet" ? "bc" : network === "regtest" ? "bcrt" : "tb";
  const words = bech32.bech32m.toWords(outputKey);
  // Witness version 1 for taproot
  const address = bech32.bech32m.encode(hrp, [1, ...words]);

  return {
    address,
    outputKey,
    tweak,
  };
}

/**
 * Verify that a Taproot address is correctly derived from a commitment
 *
 * @param address - Taproot address to verify
 * @param commitment - Expected commitment
 * @param internalKey - Optional internal key
 * @returns true if address matches expected derivation
 */
export function verifyTaprootAddress(
  address: string,
  commitment: Uint8Array,
  internalKey?: Uint8Array
): boolean {
  try {
    const decoded = bech32.bech32m.decode(address);
    const witnessVersion = decoded.words[0];
    if (witnessVersion !== 1) {
      return false;
    }

    const actualOutputKey = new Uint8Array(
      bech32.bech32m.fromWords(decoded.words.slice(1))
    );

    const network = decoded.prefix === "bc" ? "mainnet" : "testnet";
    const expected = deriveTaprootAddress(commitment, network, internalKey);

    return arraysEqual(actualOutputKey, expected.outputKey);
  } catch {
    return false;
  }
}

/**
 * Generate a P2TR (Pay-to-Taproot) script pubkey
 *
 * @param outputKey - 32-byte output key (x-only)
 * @returns Script pubkey bytes (OP_1 <32-byte key>)
 */
export function createP2TRScriptPubkey(outputKey: Uint8Array): Uint8Array {
  if (outputKey.length !== 32) {
    throw new Error("Output key must be 32 bytes");
  }

  // OP_1 (0x51) + push 32 bytes (0x20) + key
  const script = new Uint8Array(34);
  script[0] = 0x51; // OP_1 (witness version 1)
  script[1] = 0x20; // Push 32 bytes
  script.set(outputKey, 2);

  return script;
}

/**
 * Parse P2TR script pubkey to extract output key
 *
 * @param scriptPubkey - Script pubkey bytes
 * @returns Output key or null if not P2TR
 */
export function parseP2TRScriptPubkey(
  scriptPubkey: Uint8Array
): Uint8Array | null {
  if (scriptPubkey.length !== 34) return null;
  if (scriptPubkey[0] !== 0x51) return null; // OP_1
  if (scriptPubkey[1] !== 0x20) return null; // Push 32

  return scriptPubkey.slice(2);
}

/**
 * Validate a Bitcoin address format
 */
export function isValidBitcoinAddress(address: string): {
  valid: boolean;
  type: "p2pkh" | "p2sh" | "p2wpkh" | "p2wsh" | "p2tr" | "unknown";
  network: "mainnet" | "testnet" | "unknown";
} {
  try {
    // Bech32m (Taproot)
    if (address.startsWith("bc1p") || address.startsWith("tb1p")) {
      const decoded = bech32.bech32m.decode(address);
      if (decoded.words[0] === 1 && decoded.words.length === 53) {
        return {
          valid: true,
          type: "p2tr",
          network: decoded.prefix === "bc" ? "mainnet" : "testnet",
        };
      }
    }

    // Bech32 (SegWit v0)
    if (
      address.startsWith("bc1q") ||
      address.startsWith("tb1q") ||
      address.startsWith("bcrt1q")
    ) {
      const decoded = bech32.bech32.decode(address);
      if (decoded.words[0] === 0) {
        const type = decoded.words.length === 33 ? "p2wpkh" : "p2wsh";
        return {
          valid: true,
          type,
          network:
            decoded.prefix === "bc"
              ? "mainnet"
              : decoded.prefix === "bcrt"
              ? "testnet"
              : "testnet",
        };
      }
    }

    // Legacy (base58check)
    const len = address.length;
    if (len >= 26 && len <= 35) {
      if (address.startsWith("1")) {
        return { valid: true, type: "p2pkh", network: "mainnet" };
      }
      if (address.startsWith("3")) {
        return { valid: true, type: "p2sh", network: "mainnet" };
      }
      if (address.startsWith("m") || address.startsWith("n")) {
        return { valid: true, type: "p2pkh", network: "testnet" };
      }
      if (address.startsWith("2")) {
        return { valid: true, type: "p2sh", network: "testnet" };
      }
    }

    return { valid: false, type: "unknown", network: "unknown" };
  } catch {
    return { valid: false, type: "unknown", network: "unknown" };
  }
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  let result = 0n;
  for (let i = 0; i < bytes.length; i++) {
    result = (result << 8n) | BigInt(bytes[i]);
  }
  return result;
}

function arraysEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

// ========== OP_RETURN Helpers ==========

/** Destination chain encoded in the compact deposit OP_RETURN header. */
export const DEPOSIT_DESTINATION_CHAIN = {
  SOLANA: 1,
  SUI: 2,
} as const;

export type DepositDestinationChain =
  (typeof DEPOSIT_DESTINATION_CHAIN)[keyof typeof DEPOSIT_DESTINATION_CHAIN];

/** Bitcoin network encoded in the compact deposit OP_RETURN header. */
export const DEPOSIT_BITCOIN_NETWORK = {
  MAINNET: 0,
  TESTNET4: 2,
  REGTEST: 3,
} as const;

export type DepositBitcoinNetwork =
  (typeof DEPOSIT_BITCOIN_NETWORK)[keyof typeof DEPOSIT_BITCOIN_NETWORK];

export const DEPOSIT_OP_RETURN_VERSION = 1;
export const DEPOSIT_POOL_TAG_SIZE = 8;
/** OP_RETURN payload size for deposit: header(1) + poolTag(8) + ephemeralPubkey(32) + notePublicKey(32). */
export const DEPOSIT_OP_RETURN_SIZE = 73;

export interface DepositOpReturnContext {
  destinationChain: DepositDestinationChain;
  bitcoinNetwork: DepositBitcoinNetwork;
  poolTag: Uint8Array;
}

export interface ParsedDepositOpReturn extends DepositOpReturnContext {
  version: number;
  ephemeralPubkey: Uint8Array;
  notePublicKey: Uint8Array;
}

/**
 * Build the compact deposit OP_RETURN payload for non-interactive stealth deposits.
 *
 * Layout:
 *   [0]      header           — version + destination chain + Bitcoin network
 *   [1..9)   poolTag          — destination deployment tag
 *   [9..41)  ephemeralPubkey  — Ed25519 public key
 *   [41..73) notePublicKey    — Note public key (Poseidon hash)
 *
 * Amount is no longer embedded — the on-chain program reads it from the BTC output.
 * The caller wraps this in an OP_RETURN script (0x6a + push opcode + payload).
 */
export function buildDepositOpReturn(
  ephemeralPubkey: Uint8Array,
  notePublicKey: Uint8Array,
  context: DepositOpReturnContext,
): Uint8Array {
  if (ephemeralPubkey.length !== 32) throw new Error("ephemeralPubkey must be 32 bytes");
  if (notePublicKey.length !== 32) throw new Error("notePublicKey must be 32 bytes");
  validateDepositOpReturnContext(context);

  const payload = new Uint8Array(DEPOSIT_OP_RETURN_SIZE);
  payload[0] = encodeDepositOpReturnHeader(context.destinationChain, context.bitcoinNetwork);
  payload.set(context.poolTag, 1);
  payload.set(ephemeralPubkey, 1 + DEPOSIT_POOL_TAG_SIZE);
  payload.set(notePublicKey, 1 + DEPOSIT_POOL_TAG_SIZE + 32);
  return payload;
}

/**
 * Parse the compact deposit OP_RETURN payload back into its constituent fields.
 *
 * @returns Parsed fields, or null if data is not exactly the expected size.
 */
export function parseDepositOpReturn(data: Uint8Array): ParsedDepositOpReturn | null {
  if (data.length !== DEPOSIT_OP_RETURN_SIZE) return null;
  const header = decodeDepositOpReturnHeader(data[0]);
  if (!header) return null;

  return {
    ...header,
    poolTag: data.slice(1, 1 + DEPOSIT_POOL_TAG_SIZE),
    ephemeralPubkey: data.slice(1 + DEPOSIT_POOL_TAG_SIZE, 1 + DEPOSIT_POOL_TAG_SIZE + 32),
    notePublicKey: data.slice(1 + DEPOSIT_POOL_TAG_SIZE + 32, DEPOSIT_OP_RETURN_SIZE),
  };
}

export function encodeDepositOpReturnHeader(
  destinationChain: DepositDestinationChain,
  bitcoinNetwork: DepositBitcoinNetwork,
): number {
  if (destinationChain !== DEPOSIT_DESTINATION_CHAIN.SOLANA && destinationChain !== DEPOSIT_DESTINATION_CHAIN.SUI) {
    throw new Error("invalid deposit destination chain");
  }
  if (
    bitcoinNetwork !== DEPOSIT_BITCOIN_NETWORK.MAINNET
    && bitcoinNetwork !== DEPOSIT_BITCOIN_NETWORK.TESTNET4
    && bitcoinNetwork !== DEPOSIT_BITCOIN_NETWORK.REGTEST
  ) {
    throw new Error("invalid deposit bitcoin network");
  }
  return (DEPOSIT_OP_RETURN_VERSION << 6) | (destinationChain << 4) | bitcoinNetwork;
}

export function decodeDepositOpReturnHeader(header: number): {
  version: number;
  destinationChain: DepositDestinationChain;
  bitcoinNetwork: DepositBitcoinNetwork;
} | null {
  const version = header >> 6;
  const destinationChain = (header >> 4) & 0x03;
  const bitcoinNetwork = header & 0x0f;
  if (version !== DEPOSIT_OP_RETURN_VERSION) return null;
  if (destinationChain !== DEPOSIT_DESTINATION_CHAIN.SOLANA && destinationChain !== DEPOSIT_DESTINATION_CHAIN.SUI) {
    return null;
  }
  if (
    bitcoinNetwork !== DEPOSIT_BITCOIN_NETWORK.MAINNET
    && bitcoinNetwork !== DEPOSIT_BITCOIN_NETWORK.TESTNET4
    && bitcoinNetwork !== DEPOSIT_BITCOIN_NETWORK.REGTEST
  ) {
    return null;
  }
  return {
    version,
    destinationChain: destinationChain as DepositDestinationChain,
    bitcoinNetwork: bitcoinNetwork as DepositBitcoinNetwork,
  };
}

export function validateDepositOpReturnContext(context: DepositOpReturnContext): void {
  encodeDepositOpReturnHeader(context.destinationChain, context.bitcoinNetwork);
  if (context.poolTag.length !== DEPOSIT_POOL_TAG_SIZE) {
    throw new Error(`poolTag must be ${DEPOSIT_POOL_TAG_SIZE} bytes`);
  }
}

export function computeDepositPoolTag(parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    bytes.set(part, offset);
    offset += part.length;
  }
  return sha256(bytes).slice(0, DEPOSIT_POOL_TAG_SIZE);
}

/**
 * Compute the Sui deposit OP_RETURN pool tag.
 *
 * MUST match the on-chain `btc_deposit::expected_pool_tag`, which is bound to the POOL ONLY
 * (no commitment-tree component) so deposits survive a tree rotation:
 *
 *   sha256("UTXOPIA_SUI" || bcs(pool_id))[0..8]
 *
 * A Sui address (and a shared object id) serializes under BCS as its raw 32 bytes, so
 * `poolObjectId` is the 0x-prefixed 32-byte object id of the shared `Pool`.
 */
export function computeSuiDepositPoolTag(poolObjectId: string): Uint8Array {
  const clean = poolObjectId.startsWith("0x") ? poolObjectId.slice(2) : poolObjectId;
  if (clean.length !== 64) {
    throw new Error(`Sui pool object id must be 32 bytes (64 hex chars), got ${clean.length}`);
  }
  const idBytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    idBytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return computeDepositPoolTag([new TextEncoder().encode("UTXOPIA_SUI"), idBytes]);
}

/**
 * Create an OP_RETURN script from an arbitrary payload (up to 80 bytes).
 *
 * Format: OP_RETURN (0x6a) + OP_PUSHDATA (length byte) + payload
 */
export function createOpReturnScriptFromPayload(payload: Uint8Array): Uint8Array {
  if (payload.length > 80) throw new Error("OP_RETURN payload exceeds 80 bytes");

  // For payloads <= 75 bytes, use a single-byte push opcode (OP_PUSH_N).
  // For 76..80 bytes, use OP_PUSHDATA1 (0x4c) + 1-byte length.
  if (payload.length <= 75) {
    const script = new Uint8Array(2 + payload.length);
    script[0] = 0x6a; // OP_RETURN
    script[1] = payload.length; // direct push opcode
    script.set(payload, 2);
    return script;
  } else {
    const script = new Uint8Array(3 + payload.length);
    script[0] = 0x6a; // OP_RETURN
    script[1] = 0x4c; // OP_PUSHDATA1
    script[2] = payload.length;
    script.set(payload, 3);
    return script;
  }
}

// ========== Refund Script Taproot Helpers ==========

/**
 * Encode an integer as Bitcoin Script compact size (CompactSize/varint).
 * - 0-252: single byte
 * - 253-65535: 0xfd + 2 bytes LE
 */
function compactSizeEncode(n: number): Uint8Array {
  if (n < 0) throw new Error("compactSize cannot be negative");
  if (n <= 252) {
    return new Uint8Array([n]);
  }
  if (n <= 0xffff) {
    const buf = new Uint8Array(3);
    buf[0] = 0xfd;
    buf[1] = n & 0xff;
    buf[2] = (n >> 8) & 0xff;
    return buf;
  }
  throw new Error("compactSize > 65535 not supported");
}

/**
 * Build a refund script for time-locked user recovery.
 *
 * Script:
 *   <npk_32> OP_DROP <144> OP_CHECKSEQUENCEVERIFY OP_DROP <user_x_only_pubkey_32> OP_CHECKSIG
 *
 * @param npk - 32-byte note public key (commitment binding)
 * @param userPubkey - 32-byte x-only public key for the refund path
 * @returns Script bytes (73 bytes)
 */
export function buildRefundScript(npk: Uint8Array, userPubkey: Uint8Array): Uint8Array {
  if (npk.length !== 32) throw new Error("npk must be 32 bytes");
  if (userPubkey.length !== 32) throw new Error("userPubkey must be 32 bytes (x-only)");

  // Total: 1+32+1+1+2+1+1+1+32+1 = 73 bytes
  const script = new Uint8Array(73);
  let offset = 0;

  // OP_PUSHBYTES_32 + npk
  script[offset++] = 0x20;
  script.set(npk, offset);
  offset += 32;

  // OP_DROP
  script[offset++] = 0x75;

  // Push 144 as minimal signed LE: 144 = 0x90, high bit set → needs 0x00 padding → [0x90, 0x00]
  // OP_PUSHBYTES_2
  script[offset++] = 0x02;
  script[offset++] = 0x90;
  script[offset++] = 0x00;

  // OP_CHECKSEQUENCEVERIFY
  script[offset++] = 0xb2;

  // OP_DROP
  script[offset++] = 0x75;

  // OP_PUSHBYTES_32 + user x-only pubkey
  script[offset++] = 0x20;
  script.set(userPubkey, offset);
  offset += 32;

  // OP_CHECKSIG
  script[offset++] = 0xac;

  return script;
}

/**
 * Compute a TapLeaf hash per BIP-341.
 *
 * TapLeaf = H_TapLeaf(leafVersion || compactSize(script.length) || script)
 *
 * @param script - The leaf script bytes
 * @param leafVersion - Leaf version byte (default 0xc0)
 * @returns 32-byte tagged hash
 */
export function computeTapLeafHash(script: Uint8Array, leafVersion: number = 0xc0): Uint8Array {
  const scriptLenBytes = compactSizeEncode(script.length);
  const data = new Uint8Array(1 + scriptLenBytes.length + script.length);
  data[0] = leafVersion;
  data.set(scriptLenBytes, 1);
  data.set(script, 1 + scriptLenBytes.length);
  return taggedHash("TapLeaf", data);
}

/**
 * Derive a Taproot address with a refund script path.
 *
 * The address commits to both the FROST group key (internal key) and a
 * time-locked refund script that allows the user to reclaim funds after
 * 144 blocks (~1 day) if the bridge fails to sweep.
 *
 * Taproot construction:
 * - Internal key = FROST group key (x-only)
 * - Single TapLeaf = refund script
 * - Merkle root = TapLeaf hash (single leaf, no branching)
 * - Tweak = H_TapTweak(internal_key || merkle_root)
 * - Output key = internal_key + tweak * G
 *
 * @param npk - 32-byte note public key (embedded in refund script for binding)
 * @param userRefundPubkey - 32-byte x-only pubkey for the refund spending path
 * @param internalKey - 32-byte x-only FROST group public key
 * @param network - Bitcoin network for address encoding
 */
export function deriveTaprootAddressWithRefund(
  npk: Uint8Array,
  userRefundPubkey: Uint8Array,
  internalKey: Uint8Array,
  network: "mainnet" | "testnet" | "regtest" = "testnet"
): {
  address: string;
  outputKey: Uint8Array;
  merkleRoot: Uint8Array;
  controlBlock: Uint8Array;
  refundScript: Uint8Array;
  tweak: Uint8Array;
} {
  if (internalKey.length !== 32) throw new Error("Internal key must be 32 bytes (x-only)");
  if (npk.length !== 32) throw new Error("npk must be 32 bytes");
  if (userRefundPubkey.length !== 32) throw new Error("userRefundPubkey must be 32 bytes (x-only)");

  // 1. Build the refund script
  const refundScript = buildRefundScript(npk, userRefundPubkey);

  // 2. Compute the TapLeaf hash (single leaf = merkle root)
  const merkleRoot = computeTapLeafHash(refundScript);

  // 3. Compute tweak = H_TapTweak(internal_key || merkle_root)
  const tweakInput = new Uint8Array(64);
  tweakInput.set(internalKey, 0);
  tweakInput.set(merkleRoot, 32);
  const tweak = taggedHash("TapTweak", tweakInput);

  // 4. Compute output key = lift_x(internal_key) + tweak * G
  const tweakScalar = bytesToBigInt(tweak);
  const SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
  if (tweakScalar >= SECP256K1_ORDER) {
    throw new Error("Tweak scalar exceeds curve order");
  }

  const keyHex = "02" + bytesToHex(internalKey);
  const internalPoint = secp256k1.Point.fromHex(keyHex);
  const tweakPoint = secp256k1.Point.BASE.multiply(tweakScalar);
  const outputPoint = internalPoint.add(tweakPoint);

  const outputKeyHex = outputPoint.toHex(true); // 33-byte compressed hex
  const outputKey = hexToBytes(outputKeyHex.slice(2)); // drop "02"/"03" prefix

  // 5. Determine parity bit for the control block
  const parityBit = outputKeyHex.startsWith("03") ? 1 : 0;

  // 6. Build the control block: <leaf_version | parity_bit> <internal_key>
  const controlBlock = new Uint8Array(33);
  controlBlock[0] = 0xc0 | parityBit;
  controlBlock.set(internalKey, 1);

  // 7. Encode as bech32m address
  const hrp = network === "mainnet" ? "bc" : network === "regtest" ? "bcrt" : "tb";
  const words = bech32.bech32m.toWords(outputKey);
  const address = bech32.bech32m.encode(hrp, [1, ...words]);

  return {
    address,
    outputKey,
    merkleRoot,
    controlBlock,
    refundScript,
    tweak,
  };
}

/**
 * Get the internal key used by UTXOpia
 * In production, this would be the FROST threshold public key
 */
export function getInternalKey(): Uint8Array {
  // The historical default is the secp256k1 generator (sweepable). Refuse it —
  // callers must supply a real FROST/Ika group key explicitly.
  throw new Error("getInternalKey() is disabled: configure a real FROST/Ika internal key");
}

/**
 * Set a custom internal key (for testing or custom deployments)
 */
export function createCustomInternalKey(key: Uint8Array): Uint8Array {
  if (key.length !== 32) {
    throw new Error("Internal key must be 32 bytes (x-only pubkey)");
  }
  return new Uint8Array(key);
}
