import { describe, expect, test } from "bun:test";
import {
  createStealthDeposit,
  depositViewingNode,
  findNextSendIndex,
  outgoingEphemeralKeyPair,
  outgoingViewingNode,
} from "../../src/index";
import type { StealthMetaAddress } from "../../src/index";

const viewingPrivKey = new Uint8Array(32).fill(0x77);
const node = outgoingViewingNode(viewingPrivKey);

const pubAt = (sendIndex: number) => outgoingEphemeralKeyPair({ outgoingNode: node, sendIndex }).pubKey;

const recipient = {
  spendingPubKey: { x: 1n, y: 2n },
  viewingPubKey: new Uint8Array(32).fill(9),
  mpk: new Uint8Array(32).fill(5),
} as unknown as StealthMetaAddress;

describe("outgoingViewingNode", () => {
  /// Handing someone the deposit node says "recover my BTC". Handing them the
  /// outgoing node says "see who I paid". Deriving both from the viewing key is
  /// fine; deriving them to the SAME value would make one grant the other.
  test("is a distinct authority from the deposit node", () => {
    expect(node).not.toEqual(depositViewingNode(viewingPrivKey));
    expect(node).not.toEqual(viewingPrivKey);
    expect(outgoingViewingNode(viewingPrivKey)).toEqual(node);
  });
});

describe("findNextSendIndex", () => {
  test("returns 0 when the sender has never paid anyone", () => {
    expect(findNextSendIndex(node, [])).toBe(0);
  });

  test("resumes past the highest index actually seen on chain", () => {
    expect(findNextSendIndex(node, [pubAt(0), pubAt(1), pubAt(2)])).toBe(3);
  });

  /// A derived-but-never-broadcast payment leaves a hole. Stopping at the first
  /// one hands back an index already spoken for — and reusing an index against
  /// the same recipient re-derives the same ephemeral key, hence the same note
  /// commitment twice.
  test("scans past holes left by abandoned payments", () => {
    expect(findNextSendIndex(node, [pubAt(0), pubAt(5)])).toBe(6);
    expect(findNextSendIndex(node, [pubAt(7)])).toBe(8);
  });

  test("stops after the gap limit rather than scanning forever", () => {
    // Beyond the gap, an index is unreachable — the caller's local counter is
    // the only thing that knows about it.
    expect(findNextSendIndex(node, [pubAt(0), pubAt(50)], 5)).toBe(1);
    expect(findNextSendIndex(node, [pubAt(0), pubAt(50)], 60)).toBe(51);
  });

  test("ignores ephemeral keys that are not this sender's", () => {
    const strangers = [
      outgoingEphemeralKeyPair({
        outgoingNode: outgoingViewingNode(new Uint8Array(32).fill(0x78)),
        sendIndex: 0,
      }).pubKey,
    ];
    expect(findNextSendIndex(node, strangers)).toBe(0);
  });
});

describe("createStealthDeposit", () => {
  test("an indexed payment is reproducible; an unindexed one is not", async () => {
    const outgoing = { outgoingNode: node, sendIndex: 3 };
    const a = await createStealthDeposit(recipient, 50_000n, 1n, outgoing);
    const b = await createStealthDeposit(recipient, 50_000n, 1n, outgoing);
    expect(b.ephemeralPub).toEqual(a.ephemeralPub);
    expect(b.commitment).toEqual(a.commitment);

    // Omitting it still works — the cost is a record the sender cannot recover,
    // not funds — so it must stay random rather than silently reusing an index.
    const r1 = await createStealthDeposit(recipient, 50_000n, 1n);
    const r2 = await createStealthDeposit(recipient, 50_000n, 1n);
    expect(r1.ephemeralPub).not.toEqual(r2.ephemeralPub);
  });

  test("the ephemeral pubkey it publishes is the one the scan looks for", async () => {
    const sent = await createStealthDeposit(recipient, 50_000n, 1n, {
      outgoingNode: node,
      sendIndex: 4,
    });
    expect(sent.ephemeralPub).toEqual(pubAt(4));
    expect(findNextSendIndex(node, [sent.ephemeralPub])).toBe(5);
  });
});
