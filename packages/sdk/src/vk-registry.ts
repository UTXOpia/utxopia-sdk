/**
 * VK Registry helpers (JoinSplit Groth16 on-chain verification keys)
 *
 * JoinSplit verification keys are no longer embedded in the program binary.
 * Each `(nInputs, nOutputs)` shape is stored in its own `VkRegistry` PDA holding
 * the full verifier material: `vkHash`, `deltaG2`, and the ordered IC points.
 *
 * This module is chain-agnostic (Uint8Array in / Uint8Array out): it builds the
 * `init_vk_registry` / `update_vk_registry` instruction payloads, converts a
 * snarkjs `*.vkey.json` into on-chain VK material, and parses a fetched
 * `VkRegistry` account. PDA derivation lives in `./pda` (`deriveVkRegistryPDA`).
 *
 * @module vk-registry
 */

import { sha256 } from "@noble/hashes/sha2.js";

/** VkRegistry account discriminator (0x14). */
export const VK_REGISTRY_DISCRIMINATOR = 0x14;

/** Serialized VkRegistry account length (bytes). */
export const VK_REGISTRY_LEN = 1060;

/**
 * Maximum IC points the registry can hold: 1 base point + 2 fixed public inputs
 * (merkleRoot, boundParamsHash) + `MAX_SAFE_JOINSPLIT_SIZE` (10) note inputs.
 */
export const MAX_IC_POINTS = 13;

/** Largest `nInputs + nOutputs` the audited JoinSplit scope allows. */
export const MAX_SAFE_JOINSPLIT_SIZE = 10;

const VK_HASH_LEN = 32;
const DELTA_G2_LEN = 128;
const IC_POINT_LEN = 64;

/** init_vk_registry / update_vk_registry discriminators (see lib.rs). */
export const INIT_VK_REGISTRY_DISCRIMINATOR = 6;
export const UPDATE_VK_REGISTRY_DISCRIMINATOR = 7;

/** Full on-chain Groth16 VK material for a single JoinSplit shape. */
export type JoinSplitVkMaterial = {
  nInputs: number;
  nOutputs: number;
  /** sha256 over the canonical VK component serialization (32 bytes). */
  vkHash: Uint8Array;
  /** Groth16 delta G2 point, Ethereum-precompile byte order (128 bytes). */
  deltaG2: Uint8Array;
  /** IC points (one base + one per public input), 64 bytes each. */
  ic: Uint8Array[];
};

/** Public inputs for JoinSplit(N, M): merkleRoot + boundParamsHash + N + M. */
export function joinSplitNumPublicInputs(nInputs: number, nOutputs: number): number {
  return 2 + nInputs + nOutputs;
}

function assertDimensions(nInputs: number, nOutputs: number): void {
  if (nInputs < 1 || nOutputs < 1 || nInputs + nOutputs > MAX_SAFE_JOINSPLIT_SIZE) {
    throw new Error(
      `JoinSplit dimensions must satisfy nInputs>=1, nOutputs>=1, nInputs+nOutputs<=${MAX_SAFE_JOINSPLIT_SIZE}`,
    );
  }
}

// =============================================================================
// snarkjs vkey.json → on-chain VK material
// =============================================================================

/** Minimal shape of a snarkjs Groth16 `*.vkey.json`. */
export interface SnarkjsVkeyJson {
  nPublic: number;
  vk_alpha_1: [string, string, string];
  vk_beta_2: [[string, string], [string, string], [string, string]];
  vk_gamma_2: [[string, string], [string, string], [string, string]];
  vk_delta_2: [[string, string], [string, string], [string, string]];
  IC: Array<[string, string, string]>;
}

/** Decimal field-element string → 32-byte big-endian. */
function fieldTo32BE(decStr: string): Uint8Array {
  const hex = BigInt(decStr).toString(16).padStart(64, "0");
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/** Encode a G1 point as `[x_BE(32) | y_BE(32)]` (64 bytes). */
function encodeG1(point: readonly string[]): Uint8Array {
  const out = new Uint8Array(IC_POINT_LEN);
  out.set(fieldTo32BE(point[0]), 0);
  out.set(fieldTo32BE(point[1]), 32);
  return out;
}

/**
 * Encode a G2 point as `[x_imag | x_real | y_imag | y_real]` (128 bytes),
 * matching solana-bn254's Ethereum precompile order. snarkjs gives
 * `point = [[x_real, x_imag], [y_real, y_imag]]`.
 */
function encodeG2(point: readonly (readonly string[])[]): Uint8Array {
  const out = new Uint8Array(DELTA_G2_LEN);
  out.set(fieldTo32BE(point[0][1]), 0); // x_imag
  out.set(fieldTo32BE(point[0][0]), 32); // x_real
  out.set(fieldTo32BE(point[1][1]), 64); // y_imag
  out.set(fieldTo32BE(point[1][0]), 96); // y_real
  return out;
}

/**
 * Compute the canonical `vkHash`: sha256 over alpha, beta, gamma, delta and
 * every IC coordinate, each serialized as a 32-byte big-endian field element in
 * snarkjs order. Matches the on-chain ops registration hash.
 */
export function computeVkHash(vkey: SnarkjsVkeyJson): Uint8Array {
  const parts: string[] = [];
  parts.push(vkey.vk_alpha_1[0], vkey.vk_alpha_1[1]);
  parts.push(vkey.vk_beta_2[0][0], vkey.vk_beta_2[0][1], vkey.vk_beta_2[1][0], vkey.vk_beta_2[1][1]);
  parts.push(vkey.vk_gamma_2[0][0], vkey.vk_gamma_2[0][1], vkey.vk_gamma_2[1][0], vkey.vk_gamma_2[1][1]);
  parts.push(vkey.vk_delta_2[0][0], vkey.vk_delta_2[0][1], vkey.vk_delta_2[1][0], vkey.vk_delta_2[1][1]);
  for (const ic of vkey.IC) parts.push(ic[0], ic[1]);

  const serialized = new Uint8Array(parts.length * 32);
  parts.forEach((p, i) => serialized.set(fieldTo32BE(p), i * 32));
  return sha256(serialized);
}

/**
 * Convert a snarkjs `*.vkey.json` into on-chain `JoinSplitVkMaterial` for the
 * given shape. Validates that the IC count matches `3 + nInputs + nOutputs`
 * (1 base + 2 fixed + N + M public inputs).
 */
export function vkeyJsonToVkMaterial(
  vkey: SnarkjsVkeyJson,
  nInputs: number,
  nOutputs: number,
): JoinSplitVkMaterial {
  assertDimensions(nInputs, nOutputs);
  const expectedIcLen = joinSplitNumPublicInputs(nInputs, nOutputs) + 1;
  if (vkey.IC.length !== expectedIcLen) {
    throw new Error(
      `vkey IC length ${vkey.IC.length} does not match shape ${nInputs}x${nOutputs} (expected ${expectedIcLen})`,
    );
  }
  return {
    nInputs,
    nOutputs,
    vkHash: computeVkHash(vkey),
    deltaG2: encodeG2(vkey.vk_delta_2),
    ic: vkey.IC.map(encodeG1),
  };
}

// =============================================================================
// Instruction data builder (init_vk_registry = 6 / update_vk_registry = 7)
// =============================================================================

/**
 * Build the instruction data for `init_vk_registry` (disc 6) or
 * `update_vk_registry` (disc 7). Both share the layout:
 *
 *   disc(1) + n_inputs(1) + n_outputs(1) + vk_hash(32)
 *   + delta_g2(128) + ic_len(1) + ic_points(64 * ic_len)
 */
export function buildVkRegistryData(
  discriminator: typeof INIT_VK_REGISTRY_DISCRIMINATOR | typeof UPDATE_VK_REGISTRY_DISCRIMINATOR,
  vk: JoinSplitVkMaterial,
): Uint8Array {
  assertDimensions(vk.nInputs, vk.nOutputs);
  if (vk.vkHash.length !== VK_HASH_LEN) throw new Error("vkHash must be 32 bytes");
  if (vk.deltaG2.length !== DELTA_G2_LEN) throw new Error("deltaG2 must be 128 bytes");

  const expectedIcLen = joinSplitNumPublicInputs(vk.nInputs, vk.nOutputs) + 1;
  if (vk.ic.length !== expectedIcLen || vk.ic.length > MAX_IC_POINTS) {
    throw new Error(`expected ${expectedIcLen} IC points, got ${vk.ic.length}`);
  }
  vk.ic.forEach((p, i) => {
    if (p.length !== IC_POINT_LEN) throw new Error(`IC[${i}] must be 64 bytes`);
  });

  const data = new Uint8Array(1 + 2 + VK_HASH_LEN + DELTA_G2_LEN + 1 + vk.ic.length * IC_POINT_LEN);
  let offset = 0;
  data[offset++] = discriminator;
  data[offset++] = vk.nInputs;
  data[offset++] = vk.nOutputs;
  data.set(vk.vkHash, offset); offset += VK_HASH_LEN;
  data.set(vk.deltaG2, offset); offset += DELTA_G2_LEN;
  data[offset++] = vk.ic.length;
  for (const point of vk.ic) {
    data.set(point, offset); offset += IC_POINT_LEN;
  }
  return data;
}

// =============================================================================
// Account parser
// =============================================================================

/** Parsed `VkRegistry` account. */
export interface ParsedVkRegistry {
  discriminator: number;
  nInputs: number;
  nOutputs: number;
  /** 32-byte authority pubkey. */
  authority: Uint8Array;
  vkHash: Uint8Array;
  deltaG2: Uint8Array;
  icLen: number;
  ic: Uint8Array[];
}

/**
 * Parse a fetched `VkRegistry` account (1060-byte layout).
 *
 * Offsets: disc@0, n_inputs@2, n_outputs@3, authority@4, vk_hash@36,
 * delta_g2@68, ic_len@196, ic@228 (64 bytes each).
 */
export function parseVkRegistry(data: Uint8Array): ParsedVkRegistry {
  if (data.length < VK_REGISTRY_LEN) {
    throw new Error(`VkRegistry account too small: ${data.length} < ${VK_REGISTRY_LEN}`);
  }
  if (data[0] !== VK_REGISTRY_DISCRIMINATOR) {
    throw new Error(`Invalid VkRegistry discriminator: 0x${data[0].toString(16)}`);
  }

  const nInputs = data[2];
  const nOutputs = data[3];
  const icLen = data[196];
  const expectedIcLen = joinSplitNumPublicInputs(nInputs, nOutputs) + 1;
  if (icLen !== expectedIcLen || icLen > MAX_IC_POINTS) {
    throw new Error(`Invalid VkRegistry IC length: ${icLen} (expected ${expectedIcLen})`);
  }

  const ic: Uint8Array[] = [];
  for (let i = 0; i < icLen; i++) {
    const start = 228 + i * IC_POINT_LEN;
    ic.push(data.subarray(start, start + IC_POINT_LEN));
  }

  return {
    discriminator: data[0],
    nInputs,
    nOutputs,
    authority: data.subarray(4, 36),
    vkHash: data.subarray(36, 68),
    deltaG2: data.subarray(68, 196),
    icLen,
    ic,
  };
}

/**
 * Validate that a fetched account is an initialized `VkRegistry` for the exact
 * JoinSplit shape. Throws with an actionable message if not — call this before
 * submitting `transact`, `unshield`, or `redeem` so the failure happens
 * client-side instead of on-chain.
 *
 * @param data Raw account data (null/undefined if the account does not exist).
 */
export function assertVkRegistryForShape(
  data: Uint8Array | null | undefined,
  nInputs: number,
  nOutputs: number,
): ParsedVkRegistry {
  if (!data || data.length === 0) {
    throw new Error(
      `VK registry for JoinSplit ${nInputs}x${nOutputs} is not initialized. ` +
        `Run the ops VK registration before using this proof shape.`,
    );
  }
  const parsed = parseVkRegistry(data);
  if (parsed.nInputs !== nInputs || parsed.nOutputs !== nOutputs) {
    throw new Error(
      `VK registry shape mismatch: account is ${parsed.nInputs}x${parsed.nOutputs}, ` +
        `expected ${nInputs}x${nOutputs}`,
    );
  }
  return parsed;
}

/** True if `data` is an initialized `VkRegistry` for the given shape. */
export function isVkRegistryReady(
  data: Uint8Array | null | undefined,
  nInputs: number,
  nOutputs: number,
): boolean {
  try {
    assertVkRegistryForShape(data, nInputs, nOutputs);
    return true;
  } catch {
    return false;
  }
}
