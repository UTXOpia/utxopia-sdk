import { describe, expect, test } from "bun:test";
import {
  buildVerifyDepositInstructionData,
  buildVerifyDepositPermissionedInstructionData,
  depositTweakCommitment,
  bytesToHex,
} from "../../src/index";

const npk = new Uint8Array(32).fill(0x22);
const eph = new Uint8Array(32).fill(0x11);

/** sha256(npk || eph) for the fixtures above. Pinned in the program's
 *  `tweak_commitment` test too — if these two ever drift, every disc-25 deposit
 *  address the client derives stops verifying on chain. */
const PINNED_COMMITMENT =
  "adfafc05aac733fe9509f43bd1d158c882890351c7f343634c8ef9ea42cdb505";

const params = {
  sweepTxid: new Uint8Array(32).fill(0xaa),
  blockHeight: 900,
  sweepTxSize: 300,
  ephemeralPubkey: eph,
  notePublicKey: npk,
  depositVout: 3,
};

describe("buildVerifyDepositInstructionData", () => {
  test("lays every field out where the program reads it", () => {
    const data = buildVerifyDepositInstructionData(params);
    const view = new DataView(data.buffer);

    expect(data.length).toBe(149);
    expect(data[0]).toBe(25);
    expect(data.slice(1, 33)).toEqual(params.sweepTxid);
    expect(Number(view.getBigUint64(33, true))).toBe(900);
    expect(view.getUint32(41, true)).toBe(300);
    // No second transaction, and the proven txid IS the deposit txid.
    expect(view.getUint32(45, true)).toBe(0);
    expect(data.slice(49, 81)).toEqual(params.sweepTxid);
    expect(data.slice(81, 113)).toEqual(eph);
    expect(data.slice(113, 145)).toEqual(npk);
    expect(view.getUint32(145, true)).toBe(3);
  });

  test("refuses a second transaction — there is no sweep to describe", () => {
    expect(() =>
      buildVerifyDepositInstructionData({ ...params, depositTxSize: 250 }),
    ).toThrow(/no second transaction/);
  });

  test("refuses a deposit txid that is not the proven one", () => {
    // The credited output is read out of the SPV-proven transaction, so naming a
    // different deposit txid would credit an output nothing proved.
    expect(() =>
      buildVerifyDepositInstructionData({
        ...params,
        depositTxid: new Uint8Array(32).fill(0xbb),
      }),
    ).toThrow(/must equal sweepTxid/);
  });

  test("refuses a mis-sized key instead of silently padding it", () => {
    expect(() =>
      buildVerifyDepositInstructionData({ ...params, notePublicKey: new Uint8Array(31) }),
    ).toThrow(/32 bytes/);
  });
});

describe("depositTweakCommitment", () => {
  test("matches the program's tweak_commitment byte for byte", () => {
    expect(bytesToHex(depositTweakCommitment(npk, eph))).toBe(PINNED_COMMITMENT);
  });

  test("binds both keys, so neither can be swapped after the fact", () => {
    expect(depositTweakCommitment(npk, eph)).not.toEqual(npk);
    expect(depositTweakCommitment(npk, eph)).not.toEqual(depositTweakCommitment(eph, npk));

    const otherEph = new Uint8Array(eph);
    otherEph[0] ^= 1;
    expect(depositTweakCommitment(npk, eph)).not.toEqual(depositTweakCommitment(npk, otherEph));
  });
});

describe("buildVerifyDepositPermissionedInstructionData", () => {
  /// The policy approval is bound to the WHOLE payload, so the permissioned
  /// payload must be the public one byte for byte apart from the discriminator,
  /// with the ciphertext appended — not a re-serialisation that could drift.
  test("is the disc-25 payload with a new discriminator and a ciphertext tail", () => {
    const ciphertext = new Uint8Array(40).fill(0xc1);
    const permissioned = buildVerifyDepositPermissionedInstructionData({
      ...params,
      auditorCiphertext: ciphertext,
    });
    const base = buildVerifyDepositInstructionData(params);

    expect(permissioned[0]).toBe(26);
    expect(base[0]).toBe(25);
    expect(permissioned.slice(1, base.length)).toEqual(base.slice(1));
    expect(permissioned.slice(base.length)).toEqual(ciphertext);
  });

  test("an absent ciphertext is a valid payload, not a truncated one", () => {
    const permissioned = buildVerifyDepositPermissionedInstructionData(params);
    expect(permissioned.length).toBe(buildVerifyDepositInstructionData(params).length);
    expect(permissioned[0]).toBe(26);
  });

  test("inherits the no-sweep checks rather than restating them", () => {
    expect(() =>
      buildVerifyDepositPermissionedInstructionData({ ...params, depositTxSize: 250 }),
    ).toThrow(/no second transaction/);
  });
});

