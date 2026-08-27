import { describe, expect, test } from "bun:test";
import {
  createTweakDeposit,
  depositEphemeralKeyPair,
  depositViewingNode,
  depositTweakCommitment,
  deriveDepositAddress,
  depositLeafScript,
  DEPOSIT_NUMS_INTERNAL_KEY,
  verifyTaprootAddress,
  bytesToHex,
} from "../../src/index";
import type { StealthMetaAddress } from "../../src/index";

// Stand-in for the pool's Ika dWallet key, which really comes from PoolConfig.
// Same fixtures the program's verify_deposit_tests.rs uses.
const vaultKey = new Uint8Array(32).fill(0x33);
const npk = new Uint8Array(32).fill(0x22);
const eph = new Uint8Array(32).fill(0x11);

const viewingPrivKey = new Uint8Array(32).fill(0x77);
const recovery = { viewingNode: depositViewingNode(viewingPrivKey), depositIndex: 0 };

const meta = {
  spendingPubKey: { x: 1n, y: 2n },
  viewingPubKey: new Uint8Array(32).fill(9),
  mpk: new Uint8Array(32).fill(5),
} as unknown as StealthMetaAddress;

/** The program pins these same values in verify_deposit_tests.rs. If either side
 *  drifts, every address a client hands out stops verifying on chain — and the
 *  only symptom is deposits that never credit. */
const PINNED = {
  commitment: "adfafc05aac733fe9509f43bd1d158c882890351c7f343634c8ef9ea42cdb505",
  leafHash: "06b24c2fa653211557f4c8106c52ac04480606e06850fd967e87a995750a2933",
  outputKey: "fd6a4b0b28873788b11b45d8fdf81918d82c39b0503690647791e92215bf8b59",
  address: "bcrt1pl44ykzegsumc3vgmghv0m7qerrvzcwds2qmfqerhj85jy9dl3dvs084mpx",
};

describe("deriveDepositAddress", () => {
  test("derives byte for byte what the program verifies", () => {
    const commitment = depositTweakCommitment(npk, eph);
    expect(bytesToHex(commitment)).toBe(PINNED.commitment);

    const d = deriveDepositAddress(commitment, vaultKey, "regtest");
    expect(bytesToHex(d.leafHash)).toBe(PINNED.leafHash);
    expect(bytesToHex(d.outputKey)).toBe(PINNED.outputKey);
    expect(d.address).toBe(PINNED.address);
  });

  test("the key path is a NUMS point, because Ika cannot sign a tweaked key", () => {
    const d = deriveDepositAddress(depositTweakCommitment(npk, eph), vaultKey, "regtest");

    // Control block: <leaf_version | parity> || internal_key, single leaf so no path.
    expect(d.controlBlock.length).toBe(33);
    expect(d.controlBlock[0] & 0xfe).toBe(0xc0);
    expect(d.controlBlock.slice(1)).toEqual(DEPOSIT_NUMS_INTERNAL_KEY);
  });

  test("the leaf is the script Bitcoin will execute", () => {
    const commitment = depositTweakCommitment(npk, eph);
    const script = depositLeafScript(commitment, vaultKey);

    expect(script.length).toBe(68);
    expect(script[0]).toBe(0x20);
    expect(script.slice(1, 33)).toEqual(commitment);
    expect(script[33]).toBe(0x75); // OP_DROP
    expect(script[34]).toBe(0x20);
    expect(script.slice(35, 67)).toEqual(vaultKey);
    expect(script[67]).toBe(0xac); // OP_CHECKSIG
  });

  test("another pool's custody key derives a different address", () => {
    const commitment = depositTweakCommitment(npk, eph);
    const other = new Uint8Array(32).fill(0x34);

    expect(deriveDepositAddress(commitment, other, "regtest").address).not.toBe(PINNED.address);
  });
});

describe("createTweakDeposit", () => {
  test("the address commits to both keys, so the program can re-derive it", async () => {
    const deposit = await createTweakDeposit(meta, vaultKey, recovery, "regtest");

    expect(deposit.btcAddress.startsWith("bcrt1p")).toBe(true);
    expect(deposit.npk.length).toBe(32);
    expect(deposit.ephemeralPub.length).toBe(32);
    expect(bytesToHex(deposit.tweakCommitment)).toBe(
      bytesToHex(depositTweakCommitment(deposit.npk, deposit.ephemeralPub)),
    );
    // The address is a commitment to the leaf, tweaked from NUMS — not from the
    // custody key, which lives inside the leaf instead.
    expect(verifyTaprootAddress(deposit.btcAddress, deposit.leafHash, DEPOSIT_NUMS_INTERNAL_KEY))
      .toBe(true);
    expect(deposit.controlBlock.slice(1)).toEqual(DEPOSIT_NUMS_INTERNAL_KEY);
  });

  test("a new index means a new address", async () => {
    const a = await createTweakDeposit(meta, vaultKey, recovery, "regtest");
    const b = await createTweakDeposit(
      meta,
      vaultKey,
      { ...recovery, depositIndex: 1 },
      "regtest",
    );

    expect(a.ephemeralPub).not.toEqual(b.ephemeralPub);
    expect(a.btcAddress).not.toBe(b.btcAddress);
  });

  /// Losing the ephemeral key burns the coins: the address commits to it and the
  /// key path is a NUMS point, so nobody can ever spend it. The viewing node has
  /// to be a complete backup, which means the same node and index must always
  /// rebuild the same address.
  test("the same viewing node and index rebuild the same address", async () => {
    const a = await createTweakDeposit(meta, vaultKey, recovery, "regtest");
    const b = await createTweakDeposit(meta, vaultKey, { ...recovery }, "regtest");

    expect(b.btcAddress).toBe(a.btcAddress);
    expect(b.ephemeralPub).toEqual(a.ephemeralPub);
    expect(b.npk).toEqual(a.npk);
    expect(b.leafScript).toEqual(a.leafScript);
    expect(b.controlBlock).toEqual(a.controlBlock);
  });

  test("a different viewing key rebuilds nothing", async () => {
    const other = {
      viewingNode: depositViewingNode(new Uint8Array(32).fill(0x78)),
      depositIndex: 0,
    };
    const a = await createTweakDeposit(meta, vaultKey, recovery, "regtest");
    const b = await createTweakDeposit(meta, vaultKey, other, "regtest");

    expect(b.btcAddress).not.toBe(a.btcAddress);
  });

  test("swapping either key derives an address the funder never paid", async () => {
    const deposit = await createTweakDeposit(meta, vaultKey, recovery, "regtest");
    const forged = new Uint8Array(deposit.ephemeralPub);
    forged[0] ^= 1;

    const forgedLeaf = deriveDepositAddress(
      depositTweakCommitment(deposit.npk, forged),
      vaultKey,
      "regtest",
    ).leafHash;

    expect(verifyTaprootAddress(deposit.btcAddress, forgedLeaf, DEPOSIT_NUMS_INTERNAL_KEY))
      .toBe(false);
  });

  test("refuses a mis-sized vault key rather than deriving a dead address", async () => {
    await expect(createTweakDeposit(meta, new Uint8Array(31), recovery, "regtest")).rejects.toThrow(
      /32 bytes/,
    );
  });
});

describe("depositEphemeralKeyPair", () => {
  test("index 11 is not index 1 with a stray digit", () => {
    // The index is a fixed-width u32, not decimal text — otherwise seed "…1" at
    // index 1 and seed "…" at index 11 could collide into one address.
    const a = depositEphemeralKeyPair({ ...recovery, depositIndex: 1 });
    const b = depositEphemeralKeyPair({ ...recovery, depositIndex: 11 });
    expect(a.pubKey).not.toEqual(b.pubKey);
  });

  test("refuses material that would not be recoverable", () => {
    expect(() =>
      depositEphemeralKeyPair({ viewingNode: new Uint8Array(0), depositIndex: 0 }),
    ).toThrow(/must not be empty/);
    expect(() => depositViewingNode(new Uint8Array(0))).toThrow(/must not be empty/);
    for (const bad of [-1, 1.5, NaN]) {
      expect(() => depositEphemeralKeyPair({ ...recovery, depositIndex: bad })).toThrow(
        /invalid depositIndex/,
      );
    }
  });
});

describe("depositViewingNode", () => {
  /// The node is what makes recovery delegable: hand it over and the holder can
  /// rebuild every deposit address and spend the BTC behind them. It must NOT
  /// hand over anything more — spending a note needs the spending key and the
  /// nullifying key, and neither is reachable from here.
  test("is a one-way function of the viewing key", () => {
    const node = depositViewingNode(viewingPrivKey);

    expect(node.length).toBe(32);
    expect(node).not.toEqual(viewingPrivKey);
    expect(depositViewingNode(viewingPrivKey)).toEqual(node);

    const nudged = new Uint8Array(viewingPrivKey);
    nudged[0] ^= 1;
    expect(depositViewingNode(nudged)).not.toEqual(node);
  });
});

describe("UTXOpiaClient.prepareTweakDeposit", () => {
  async function loggedInClient() {
    const { UTXOpiaClient } = await import("../../src/index");
    const client = await UTXOpiaClient.init();
    await client.loginWithSeed(new Uint8Array(32).fill(0x42));
    return client;
  }

  /// The whole point of routing through the client: callers cannot supply a
  /// random ephemeral key by accident, because they never supply one at all.
  test("derives the same address for the same index, without the caller holding keys", async () => {
    const client = await loggedInClient();
    const a = await client.prepareTweakDeposit({ depositIndex: 2, ikaXOnlyPubkey: vaultKey, network: "regtest" });
    const b = await client.prepareTweakDeposit({ depositIndex: 2, ikaXOnlyPubkey: vaultKey, network: "regtest" });
    const next = await client.prepareTweakDeposit({ depositIndex: 3, ikaXOnlyPubkey: vaultKey, network: "regtest" });

    expect(b.btcAddress).toBe(a.btcAddress);
    expect(next.btcAddress).not.toBe(a.btcAddress);
  });

  /// Generating one of these for a third party would hand them a note they own
  /// and coins they can never recover — only the viewing key the ephemeral was
  /// derived from can rebuild the leaf.
  test("refuses to build a deposit address for someone else", async () => {
    const client = await loggedInClient();
    await expect(
      client.prepareTweakDeposit({
        depositIndex: 0,
        ikaXOnlyPubkey: vaultKey,
        recipient: meta,
        network: "regtest",
      }),
    ).rejects.toThrow(/self-deposit only/);
  });
});

