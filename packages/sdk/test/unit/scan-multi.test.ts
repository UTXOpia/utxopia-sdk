/**
 * Multi-token scanning: one trial-decrypt per announcement, tested against N
 * token ids. Must agree note-for-note with scanning each token separately.
 */

import { describe, test, expect, beforeAll } from "bun:test";
import { initPoseidon } from "../../src/poseidon";
import { deriveKeysFromSeed, createStealthMetaAddress } from "../../src/keys";
import {
  createStealthDeposit,
  scanUnifiedNotes,
  scanUnifiedNotesMulti,
  scanAnnouncementsViewOnly,
  scanAnnouncementsViewOnlyMulti,
  exportViewOnlyKeys,
  ANNOUNCEMENT_TYPE_TRANSFER,
} from "../../src/stealth";

const SEED_MINE = new Uint8Array(32).fill(7);
const SEED_OTHER = new Uint8Array(32).fill(9);
const TOKEN_A = 0x7a627463n;
const TOKEN_B = 0x736f6c00n;
const TOKEN_UNUSED = 0x1234n;

describe("multi-token scanning", () => {
  beforeAll(async () => {
    await initPoseidon();
  });

  async function fixture() {
    const keys = deriveKeysFromSeed(SEED_MINE);
    const meta = createStealthMetaAddress(keys);
    const stranger = createStealthMetaAddress(deriveKeysFromSeed(SEED_OTHER));

    const announce = (
      deposit: { ephemeralPub: Uint8Array; encryptedAmount: Uint8Array; commitment: Uint8Array },
      leafIndex: number,
    ) => ({
      announcementType: ANNOUNCEMENT_TYPE_TRANSFER,
      ephemeralPub: deposit.ephemeralPub,
      encryptedAmount: deposit.encryptedAmount,
      commitment: deposit.commitment,
      leafIndex,
    });

    const announcements = [
      announce(await createStealthDeposit(meta, 42_000n, TOKEN_A), 0),
      announce(await createStealthDeposit(stranger, 11_000n, TOKEN_A), 1),
      announce(await createStealthDeposit(meta, 7_500n, TOKEN_B), 2),
    ];

    return { keys, announcements };
  }

  test("finds notes across token ids and tags each with the one it matched", async () => {
    const { keys, announcements } = await fixture();

    const found = await scanUnifiedNotesMulti(keys, announcements, [TOKEN_A, TOKEN_B]);

    expect(found.map((n) => [n.leafIndex, n.amount, n.tokenId])).toEqual([
      [0, 42_000n, TOKEN_A],
      [2, 7_500n, TOKEN_B],
    ]);
  });

  test("matches per-token scanning note for note", async () => {
    const { keys, announcements } = await fixture();

    const perToken = [
      ...(await scanUnifiedNotes(keys, announcements, TOKEN_A)),
      ...(await scanUnifiedNotes(keys, announcements, TOKEN_B)),
    ].sort((a, b) => a.leafIndex - b.leafIndex);
    const multi = await scanUnifiedNotesMulti(keys, announcements, [TOKEN_A, TOKEN_B]);

    expect(multi.length).toBe(perToken.length);
    for (let i = 0; i < multi.length; i++) {
      expect(multi[i].amount).toBe(perToken[i].amount);
      expect(multi[i].leafIndex).toBe(perToken[i].leafIndex);
      expect(multi[i].commitment).toEqual(perToken[i].commitment);
      expect(multi[i].stealthPub).toEqual(perToken[i].stealthPub);
    }
  });

  test("a token id nobody used finds nothing, and no ids finds nothing", async () => {
    const { keys, announcements } = await fixture();

    expect(await scanUnifiedNotesMulti(keys, announcements, [TOKEN_UNUSED])).toHaveLength(0);
    expect(await scanUnifiedNotesMulti(keys, announcements, [])).toHaveLength(0);
  });

  test("view-only multi agrees with view-only per token", async () => {
    const { keys, announcements } = await fixture();
    const viewOnly = exportViewOnlyKeys(keys);

    const multi = await scanAnnouncementsViewOnlyMulti(viewOnly, announcements, [TOKEN_A, TOKEN_B]);
    const single = await scanAnnouncementsViewOnly(viewOnly, announcements, TOKEN_A);

    expect(multi.map((n) => n.leafIndex)).toEqual([0, 2]);
    expect(multi[0].amount).toBe(single[0].amount);
    expect(multi[0].commitment).toEqual(single[0].commitment);
    // View-only notes stay spend-incapable.
    expect("stealthPub" in multi[0]).toBe(false);
  });
});
