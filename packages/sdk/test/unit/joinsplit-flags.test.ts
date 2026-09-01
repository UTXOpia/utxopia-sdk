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
