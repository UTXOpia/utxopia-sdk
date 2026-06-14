import { describe, it, expect } from "bun:test";
import { pickCustodyInternalKey } from "../../src/stealth";
import { hexToBytes } from "../../src/crypto";

const ALL_ZEROS_HEX =
  "0000000000000000000000000000000000000000000000000000000000000000";
const IKA_HEX =
  "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

describe("pickCustodyInternalKey (Ika-only)", () => {
  it("returns the Ika pubkey when set", () => {
    const key = pickCustodyInternalKey({
      ikaDwalletXOnlyPubkey: IKA_HEX,
    });
    expect(Array.from(key)).toEqual(Array.from(hexToBytes(IKA_HEX)));
  });

  it("Ika pubkey of all-f's still counts as set (any non-zero hex digit)", () => {
    const allF =
      "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    const key = pickCustodyInternalKey({
      ikaDwalletXOnlyPubkey: allF,
    });
    expect(Array.from(key)).toEqual(Array.from(hexToBytes(allF)));
  });

  it("throws when Ika pubkey is all-zero (PoolConfig not initialized)", () => {
    expect(() =>
      pickCustodyInternalKey({ ikaDwalletXOnlyPubkey: ALL_ZEROS_HEX }),
    ).toThrow(/ika_dwallet_xonly_pubkey/);
  });

  it("throws when ikaDwalletXOnlyPubkey is undefined", () => {
    expect(() => pickCustodyInternalKey({})).toThrow(
      /ika_dwallet_xonly_pubkey/,
    );
  });

  it("throws when ikaDwalletXOnlyPubkey is empty string", () => {
    expect(() =>
      pickCustodyInternalKey({ ikaDwalletXOnlyPubkey: "" }),
    ).toThrow(/ika_dwallet_xonly_pubkey/);
  });
});
