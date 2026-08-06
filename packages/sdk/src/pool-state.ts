/**
 * PoolState account layout and fee arithmetic.
 *
 * Both mirror the program (`state/pool.rs`, `utils/fees.rs`), so both belong
 * here rather than in an app: a consumer that re-derives either gets it right
 * until the struct grows a field, and then reads the wrong bytes with no error.
 * TokenConfig and CommitmentTree are already decoded in this package; this
 * closes the gap for the third account.
 *
 * @module pool-state
 */

export const POOL_STATE_DISCRIMINATOR = 0x01;

/** `core::mem::size_of::<PoolState>()`. Fields are appended into `_reserved`,
 *  so the length is stable across the additions made so far. */
export const POOL_STATE_LEN = 332;

/** Byte offsets of every field, in declaration order (`#[repr(C)]`). */
export const POOL_STATE_OFFSETS = {
  discriminator: 0,
  bump: 1,
  flags: 2,
  authority: 4,
  zkbtcMint: 36,
  poolVault: 68,
  depositVault: 100,
  depositCount: 132,
  totalMinted: 140,
  totalBurned: 148,
  pendingRedemptions: 156,
  lastUpdate: 164,
  minDeposit: 172,
  maxDeposit: 180,
  totalShielded: 188,
  serviceFeeBase: 196,
  feePool: 204,
  pendingMinDeposit: 212,
  pendingMaxDeposit: 220,
  pendingServiceFee: 228,
  pendingExecuteAfter: 236,
  depositFeeBps: 244,
  withdrawalFeeBps: 246,
  totalBtcHeld: 248,
  utxoCount: 256,
  activeTreeIndex: 258,
  utxoCountHi: 262,
  auditor: 264,
  auditorViewingPubkey: 296,
  nullifierCount: 328,
} as const;

/** `flags` bits, from `state/pool.rs`. */
export const POOL_FLAG = {
  PAUSED: 1 << 0,
  PERMISSIONED: 1 << 1,
  AUDITOR_FROZEN: 1 << 2,
  VK_REGISTRY_FROZEN: 1 << 3,
} as const;

export interface PoolFees {
  depositFeeBps: number;
  withdrawalFeeBps: number;
}

export interface PoolState extends PoolFees {
  bump: number;
  paused: boolean;
  permissioned: boolean;
  auditorFrozen: boolean;
  vkRegistryFrozen: boolean;
  zkbtcMint: Uint8Array;
  poolVault: Uint8Array;
  depositCount: bigint;
  totalMinted: bigint;
  totalBurned: bigint;
  pendingRedemptions: bigint;
  minDeposit: bigint;
  maxDeposit: bigint;
  totalShielded: bigint;
  serviceFeeBase: bigint;
  feePool: bigint;
  totalBtcHeld: bigint;
  activeTreeIndex: number;
  auditor: Uint8Array;
  auditorViewingPubkey: Uint8Array;
  /** Counts only records created since the counter was added; older pools
   *  start from zero, so treat it as a floor rather than a total. */
  nullifierCount: number;
  /** `utxo_count` widened by `utxo_count_hi`, which was carved out later. */
  utxoCount: number;
}

const view = (data: Uint8Array): DataView =>
  new DataView(data.buffer, data.byteOffset, data.byteLength);

/** Fees only — the common case, and readable from a truncated account. */
export function parsePoolFees(data: Uint8Array): PoolFees | null {
  if (
    data.length < POOL_STATE_OFFSETS.withdrawalFeeBps + 2 ||
    data[0] !== POOL_STATE_DISCRIMINATOR
  ) {
    return null;
  }
  const v = view(data);
  return {
    depositFeeBps: v.getUint16(POOL_STATE_OFFSETS.depositFeeBps, true),
    withdrawalFeeBps: v.getUint16(POOL_STATE_OFFSETS.withdrawalFeeBps, true),
  };
}

/** Full decode. Returns null rather than throwing: callers poll this against
 *  whatever the RPC hands back, including a pool from an older deployment. */
export function parsePoolState(data: Uint8Array): PoolState | null {
  if (data.length < POOL_STATE_LEN || data[0] !== POOL_STATE_DISCRIMINATOR) {
    return null;
  }
  const v = view(data);
  const o = POOL_STATE_OFFSETS;
  const flags = data[o.flags];
  const bytes = (at: number, len = 32) => data.subarray(at, at + len);

  return {
    bump: data[o.bump],
    paused: (flags & POOL_FLAG.PAUSED) !== 0,
    permissioned: (flags & POOL_FLAG.PERMISSIONED) !== 0,
    auditorFrozen: (flags & POOL_FLAG.AUDITOR_FROZEN) !== 0,
    vkRegistryFrozen: (flags & POOL_FLAG.VK_REGISTRY_FROZEN) !== 0,
    zkbtcMint: bytes(o.zkbtcMint),
    poolVault: bytes(o.poolVault),
    depositCount: v.getBigUint64(o.depositCount, true),
    totalMinted: v.getBigUint64(o.totalMinted, true),
    totalBurned: v.getBigUint64(o.totalBurned, true),
    pendingRedemptions: v.getBigUint64(o.pendingRedemptions, true),
    minDeposit: v.getBigUint64(o.minDeposit, true),
    maxDeposit: v.getBigUint64(o.maxDeposit, true),
    totalShielded: v.getBigUint64(o.totalShielded, true),
    serviceFeeBase: v.getBigUint64(o.serviceFeeBase, true),
    feePool: v.getBigUint64(o.feePool, true),
    depositFeeBps: v.getUint16(o.depositFeeBps, true),
    withdrawalFeeBps: v.getUint16(o.withdrawalFeeBps, true),
    totalBtcHeld: v.getBigUint64(o.totalBtcHeld, true),
    activeTreeIndex: v.getUint32(o.activeTreeIndex, true),
    utxoCount: v.getUint16(o.utxoCount, true) + (v.getUint16(o.utxoCountHi, true) << 16),
    auditor: bytes(o.auditor),
    auditorViewingPubkey: bytes(o.auditorViewingPubkey),
    nullifierCount: v.getUint32(o.nullifierCount, true),
  };
}

// =============================================================================
// Fee arithmetic
// =============================================================================

export const BPS_DENOMINATOR = 10_000n;

/**
 * Compute an on-chain basis-point fee. Unshield withdrawals enforce a one-unit
 * minimum; deposits use plain floor division. Quoting a fee any other way shows
 * the user a number the program will not charge.
 */
export function computeBpsFee(
  amount: bigint,
  bps: number,
  minimumOne = true,
): bigint {
  if (amount <= 0n || bps <= 0) return 0n;
  const fee = (amount * BigInt(bps)) / BPS_DENOMINATOR;
  return fee > 0n || !minimumOne ? fee : 1n;
}

/** What share of `gross` a fee represents, in basis points. */
export function feeShareBps(fee: bigint, gross: bigint): number {
  if (fee <= 0n || gross <= 0n) return 0;
  return Number((fee * BPS_DENOMINATOR) / gross);
}
