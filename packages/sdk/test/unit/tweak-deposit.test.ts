import { describe, expect, test } from "bun:test";
import {
  createTweakDeposit,
  depositTweakCommitment,
  verifyTaprootAddress,
  bytesToHex,
} from "../../src/index";
import type { StealthMetaAddress } from "../../src/index";

// A real Ika x-only key comes from PoolConfig; any valid x-only point works for
// derivation, as long as it is not the generator (taproot.ts refuses that one).
const vaultKey = Uint8Array.from(
  Buffer.from("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0", "hex"),
);

const meta = {
  spendingPubKey: { x: 1n, y: 2n },
  viewingPubKey: new Uint8Array(32).fill(9),
  mpk: new Uint8Array(32).fill(5),
} as unknown as StealthMetaAddress;

describe("createTweakDeposit", () => {
  test("the address commits to both keys, so the program can re-derive it", async () => {
    const deposit = await createTweakDeposit(meta, vaultKey, "regtest");

    expect(deposit.btcAddress.startsWith("bcrt1p")).toBe(true);
    expect(deposit.npk.length).toBe(32);
    expect(deposit.ephemeralPub.length).toBe(32);
    expect(bytesToHex(deposit.tweakCommitment)).toBe(
      bytesToHex(depositTweakCommitment(deposit.npk, deposit.ephemeralPub)),
    );
    expect(verifyTaprootAddress(deposit.btcAddress, deposit.tweakCommitment, vaultKey)).toBe(true);
  });

  test("a fresh ephemeral key per call means a fresh address per deposit", async () => {
    const a = await createTweakDeposit(meta, vaultKey, "regtest");
    const b = await createTweakDeposit(meta, vaultKey, "regtest");

    expect(a.ephemeralPub).not.toEqual(b.ephemeralPub);
    expect(a.btcAddress).not.toBe(b.btcAddress);
  });

  test("swapping either key derives an address the funder never paid", async () => {
    const deposit = await createTweakDeposit(meta, vaultKey, "regtest");
    const forged = new Uint8Array(deposit.ephemeralPub);
    forged[0] ^= 1;

    expect(
      verifyTaprootAddress(
        deposit.btcAddress,
        depositTweakCommitment(deposit.npk, forged),
        vaultKey,
      ),
    ).toBe(false);
  });

  test("refuses a mis-sized vault key rather than deriving a dead address", async () => {
    await expect(createTweakDeposit(meta, new Uint8Array(31), "regtest")).rejects.toThrow(
      /32 bytes/,
    );
  });
});
