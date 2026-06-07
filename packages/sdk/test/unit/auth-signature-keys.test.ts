import { describe, expect, test } from "bun:test";
import {
  createStealthMetaAddress,
  deriveKeysFromAuthSignature,
  eddsaPoseidonSign,
  generateRandomAuthSignature,
  setupKeysFromAuthSignature,
} from "../../src/keys";
import { babyJubMul, BABYJUB_BASE8 } from "../../src/crypto-babyjub";

describe("auth signature key derivation", () => {
  test("accepts Fluidkey-style 65-byte signatures", async () => {
    const signature = new Uint8Array(65).fill(7);
    signature[64] = 27;
    const keys = await deriveKeysFromAuthSignature(signature, {
      account: "0xsui",
      chain: "sui",
      network: "testnet",
    });

    expect(keys.spendingPrivKey).toBeTypeOf("bigint");
    expect(keys.nullifyingKey).toBeTypeOf("bigint");
    expect(keys.viewingPrivKey.length).toBe(32);
    expect(keys.viewingPubKey.length).toBe(32);
    expect(keys.eddsaSeed.length).toBe(32);
    expect(createStealthMetaAddress(keys).mpk.length).toBe(32);
  });

  test("is deterministic for the same signature and context", async () => {
    const signature = new Uint8Array(65).fill(9);
    const a = await deriveKeysFromAuthSignature(signature, { account: "alice" });
    const b = await deriveKeysFromAuthSignature(signature, { account: "alice" });

    expect(a.spendingPrivKey).toBe(b.spendingPrivKey);
    expect(a.nullifyingKey).toBe(b.nullifyingKey);
    expect(a.viewingPubKey).toEqual(b.viewingPubKey);
  });

  test("domain context changes derived keys", async () => {
    const signature = new Uint8Array(65).fill(9);
    const a = await deriveKeysFromAuthSignature(signature, { account: "alice" });
    const b = await deriveKeysFromAuthSignature(signature, { account: "bob" });

    expect(a.spendingPrivKey).not.toBe(b.spendingPrivKey);
    expect(a.nullifyingKey).not.toBe(b.nullifyingKey);
    expect(a.viewingPubKey).not.toEqual(b.viewingPubKey);
  });

  test("sets up an encoded stealth address from a random test signature", async () => {
    const setup = await setupKeysFromAuthSignature(generateRandomAuthSignature(), {
      account: "agent-browser-test",
      chain: "sui",
      network: "sui-regtest",
    });

    expect(setup.root.length).toBe(32);
    expect(setup.encodedStealthAddress.startsWith("utxo:")).toBe(true);
    expect(setup.stealthMetaAddress.viewingPubKey.length).toBe(32);
  });

  // C-2 regression: the spending keypair MUST be self-consistent under the same
  // EdDSA derivation that signTransaction uses (eddsaPoseidonSign over eddsaSeed).
  // Previously the auth path derived spendingPubKey = babyJubMul(scalarFromBytes(seed))
  // (key A) while signing used the circomlibjs BLAKE-512 scalar (key B), so notes
  // were unspendable. These assertions fail on the old code and pass on the fix.
  test("spendingPubKey == spendingPrivKey * BASE8 (circuit-consistent)", async () => {
    const keys = await deriveKeysFromAuthSignature(new Uint8Array(65).fill(13), {
      account: "consistency",
      chain: "sui",
    });

    const derived = babyJubMul(keys.spendingPrivKey, BABYJUB_BASE8);
    expect(derived.x).toBe(keys.spendingPubKey.x);
    expect(derived.y).toBe(keys.spendingPubKey.y);
  });

  test("signature from eddsaSeed verifies against the derived spendingPubKey", async () => {
    const keys = await deriveKeysFromAuthSignature(new Uint8Array(65).fill(21), {
      account: "sign-verify",
      chain: "sui",
    });

    // Sign exactly the way signTransaction does, then verify R8/S against the
    // SAME public key the circuit binds — the heart of the C-2 break.
    const msgHash = 0x1234_5678_9abcn;
    const [R8x, R8y, S] = await eddsaPoseidonSign(keys.eddsaSeed, msgHash);

    const { buildEddsa } = await import("circomlibjs");
    const eddsa = await buildEddsa();
    const F = eddsa.babyJub.F;
    const ok = eddsa.verifyPoseidon(
      F.e(msgHash),
      { R8: [F.e(R8x), F.e(R8y)], S },
      [F.e(keys.spendingPubKey.x), F.e(keys.spendingPubKey.y)],
    );
    expect(ok).toBe(true);
  });
});
