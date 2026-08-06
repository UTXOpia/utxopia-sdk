/**
 * Pins the PoolState layout to `state/pool.rs`. Offsets are what a decoder gets
 * silently wrong: a field appended mid-struct shifts everything after it, and a
 * reader just returns a plausible number from the wrong bytes.
 */
import { describe, expect, test } from "bun:test";
import {
  POOL_STATE_DISCRIMINATOR,
  POOL_STATE_LEN,
  POOL_STATE_OFFSETS as O,
  computeBpsFee,
  feeShareBps,
  parsePoolFees,
  parsePoolState,
} from "../../src/pool-state";

function fixture(): Uint8Array {
  const d = new Uint8Array(POOL_STATE_LEN);
  const v = new DataView(d.buffer);
  d[0] = POOL_STATE_DISCRIMINATOR;
  d[O.bump] = 254;
  d[O.flags] = 0b0110; // permissioned + auditor frozen
  v.setBigUint64(O.depositCount, 7n, true);
  v.setBigUint64(O.totalShielded, 123_456n, true);
  v.setUint16(O.depositFeeBps, 20, true);
  v.setUint16(O.withdrawalFeeBps, 35, true);
  v.setUint32(O.activeTreeIndex, 2, true);
  v.setUint16(O.utxoCount, 5, true);
  v.setUint16(O.utxoCountHi, 1, true); // 5 + 65536
  v.setUint32(O.nullifierCount, 9, true);
  return d;
}

describe("PoolState layout", () => {
  test("size matches size_of::<PoolState>()", () => {
    expect(POOL_STATE_LEN).toBe(332);
  });

  test("fee offsets are where pool.rs puts them", () => {
    expect(O.depositFeeBps).toBe(244);
    expect(O.withdrawalFeeBps).toBe(246);
    // Carved out of _reserved after the fact; the backend reads it here too.
    expect(O.nullifierCount).toBe(328);
  });

  test("decodes every field", () => {
    const p = parsePoolState(fixture())!;
    expect(p).not.toBeNull();
    expect(p.bump).toBe(254);
    expect(p.paused).toBe(false);
    expect(p.permissioned).toBe(true);
    expect(p.auditorFrozen).toBe(true);
    expect(p.vkRegistryFrozen).toBe(false);
    expect(p.depositCount).toBe(7n);
    expect(p.totalShielded).toBe(123_456n);
    expect(p.depositFeeBps).toBe(20);
    expect(p.withdrawalFeeBps).toBe(35);
    expect(p.activeTreeIndex).toBe(2);
    expect(p.nullifierCount).toBe(9);
  });

  test("utxo_count is widened by utxo_count_hi", () => {
    expect(parsePoolState(fixture())!.utxoCount).toBe(5 + 65536);
  });

  test("rejects a foreign account instead of returning junk", () => {
    const wrong = fixture();
    wrong[0] = 0x0b; // TokenConfig
    expect(parsePoolState(wrong)).toBeNull();
    expect(parsePoolFees(wrong)).toBeNull();
  });

  test("parsePoolFees works on an account truncated after the fees", () => {
    const short = fixture().subarray(0, O.withdrawalFeeBps + 2);
    expect(parsePoolFees(short)).toEqual({ depositFeeBps: 20, withdrawalFeeBps: 35 });
    expect(parsePoolState(short)).toBeNull();
  });
});

describe("fee arithmetic matches the program", () => {
  test("floor division", () => {
    expect(computeBpsFee(10_000n, 20)).toBe(20n);
    expect(computeBpsFee(199n, 20, false)).toBe(0n);
  });

  test("withdrawals charge at least one unit", () => {
    expect(computeBpsFee(199n, 20)).toBe(1n);
  });

  test("no fee on zero amount or zero bps", () => {
    expect(computeBpsFee(0n, 20)).toBe(0n);
    expect(computeBpsFee(10_000n, 0)).toBe(0n);
  });

  test("feeShareBps inverts computeBpsFee", () => {
    expect(feeShareBps(20n, 10_000n)).toBe(20);
    expect(feeShareBps(0n, 10_000n)).toBe(0);
  });
});
