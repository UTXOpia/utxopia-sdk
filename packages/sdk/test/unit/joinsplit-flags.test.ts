import { describe, expect, test } from "bun:test";
import { JSFLAGS, joinSplitFlags, buildTransactInstructionData } from "../../src/instructions";

/**
 * The flags byte is the ABI contract with `jsflags` on-chain. A wrong bit does
 * not fail softly — the program reads a different account into a slot, or
 * rejects the transaction outright — so pin the encoding here.
 */
describe("joinSplitFlags", () => {
  test("a bare public spend declares nothing", () => {
    expect(joinSplitFlags({})).toBe(0);
    expect(joinSplitFlags({ proofSource: 0, policyTail: "none" })).toBe(0);
  });

  test("bit 0 keeps its old proof_source meaning", () => {
    expect(joinSplitFlags({ proofSource: 1 })).toBe(JSFLAGS.PROOF_IN_BUFFER);
    expect(JSFLAGS.PROOF_IN_BUFFER).toBe(1);
  });

  test("the two permissioned tails are mutually exclusive", () => {
    expect(joinSplitFlags({ policyTail: "verified" })).toBe(JSFLAGS.POLICY);
    expect(joinSplitFlags({ policyTail: "ragequit" })).toBe(JSFLAGS.RAGEQUIT);
    // Never both: the program refuses that combination.
    const verified = joinSplitFlags({ policyTail: "verified" });
    expect(verified & JSFLAGS.RAGEQUIT).toBe(0);
  });

  test("declarations combine without disturbing each other", () => {
    expect(
      joinSplitFlags({
        proofSource: 1,
        hasRelayer: true,
        hasFrozenSourceTree: true,
        policyTail: "verified",
      })
    ).toBe(
      JSFLAGS.PROOF_IN_BUFFER | JSFLAGS.RELAYER | JSFLAGS.FROZEN_SOURCE_TREE | JSFLAGS.POLICY
    );
  });
});

describe("transact data carries the flags in the header", () => {
  const base = {
    nInputs: 1,
    nOutputs: 1,
    proofBytes: new Uint8Array(256).fill(7),
    merkleRoot: new Uint8Array(32),
    boundParamsHash: new Uint8Array(32),
    nullifiers: [new Uint8Array(32).fill(1)],
    commitmentsOut: [new Uint8Array(32).fill(2)],
    stealthData: [new Uint8Array(72).fill(3)],
  };

  test("header byte 4 is the flags byte, not a bare proof source", () => {
    // data[0] is the discriminator, then n_in, n_out, n_pub, flags.
    expect(buildTransactInstructionData(base)[4]).toBe(0);
    expect(buildTransactInstructionData({ ...base, policyTail: "verified" })[4]).toBe(
      JSFLAGS.POLICY
    );
    expect(
      buildTransactInstructionData({ ...base, hasFrozenSourceTree: true })[4]
    ).toBe(JSFLAGS.FROZEN_SOURCE_TREE);
  });
});

describe("queued placement", () => {
  test("declaring queued leaves sets the flag", () => {
    expect(joinSplitFlags({ hasQueuedLeaves: true })).toBe(JSFLAGS.QUEUED_LEAVES);
  });

  /**
   * The leaf PDA is seeded on the commitment, so the same commitment cannot be
   * queued twice. That matters because the circuit derives
   * `nullifier = Poseidon(nullifyingKey, leafIndex)` — position, not content —
   * so one commitment at two leaf indices yields two spendable nullifiers.
   */
  test("a queued leaf PDA is unique per commitment", async () => {
    const { deriveQueuedLeafPDA } = await import("../../src/pda");
    const pool = new Uint8Array(32).fill(9);
    const [a] = await deriveQueuedLeafPDA(pool, new Uint8Array(32).fill(1));
    const [b] = await deriveQueuedLeafPDA(pool, new Uint8Array(32).fill(1));
    const [c] = await deriveQueuedLeafPDA(pool, new Uint8Array(32).fill(2));
    expect(a).toBe(b);
    expect(a).not.toBe(c);
  });
});

describe("buildMergeQueuedLeavesInstruction", () => {
  const addr = (n: number) =>
    ("1".repeat(31) + String.fromCharCode(65 + n)) as unknown as never;

  test("refuses a duplicated leaf before the program has to", async () => {
    const { buildMergeQueuedLeavesInstruction } = await import("../../src/instructions");
    const leaf = addr(1);
    expect(() =>
      buildMergeQueuedLeavesInstruction({
        accounts: { caller: addr(2), poolState: addr(3), commitmentTree: addr(4) },
        leaves: [
          { queuedLeaf: leaf, rentRecipient: addr(5) },
          { queuedLeaf: leaf, rentRecipient: addr(5) },
        ],
      })
    ).toThrow(/Duplicate queued leaf/);
  });

  test("refuses an empty batch", async () => {
    const { buildMergeQueuedLeavesInstruction } = await import("../../src/instructions");
    expect(() =>
      buildMergeQueuedLeavesInstruction({
        accounts: { caller: addr(2), poolState: addr(3), commitmentTree: addr(4) },
        leaves: [],
      })
    ).toThrow(/at least one leaf/);
  });
});
