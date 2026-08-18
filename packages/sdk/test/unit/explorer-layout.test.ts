import { describe, expect, test } from "bun:test";
import {
  NULLIFIER_RECORD_SIZE,
  REDEMPTION_REQUEST_SIZE,
  NULLIFIER_RECORD_DISCRIMINATOR,
  REDEMPTION_REQUEST_DISCRIMINATOR,
} from "../../src/explorer";

// These mirror on-chain account layouts and are used as `dataSize` / discriminator filters, so
// drift does not throw — the query just stops matching and the caller sees an empty list. Both
// numbers are pinned on the program side too (state/redemption.rs, state/nullifier.rs); change
// them in the same commit or the explorer goes quiet.
describe("explorer account layout", () => {
  test("RedemptionRequest size matches the program", () => {
    // disc1 status1 scriptLen1 signingApproved1 slot4 id8 requester32 amount8 fee8 input8
    // script34 token32 reserved1 approved4 pad3 commitment32
    const fields = [1, 1, 1, 1, 4, 8, 32, 8, 8, 8, 34, 32, 1, 4, 3, 32];
    expect(fields.reduce((a, b) => a + b)).toBe(178);
    expect(REDEMPTION_REQUEST_SIZE).toBe(178);
  });

  test("NullifierRecord is the slim one-byte layout", () => {
    expect(NULLIFIER_RECORD_SIZE).toBe(1);
  });

  test("discriminators match the program", () => {
    expect(NULLIFIER_RECORD_DISCRIMINATOR).toBe(0x03);
    expect(REDEMPTION_REQUEST_DISCRIMINATOR).toBe(0x04);
  });
});
