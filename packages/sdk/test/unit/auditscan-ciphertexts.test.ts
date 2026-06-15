import { describe, it, expect } from "bun:test";
import { ed25519GenerateKeyPair } from "../../src/crypto-ed25519";
import { encryptAuditorCiphertext } from "../../src/auditor-ciphertext";
import { auditScanCiphertexts } from "../../src/auditor";

function makeCommitment(fill: number): Uint8Array {
  return new Uint8Array(32).fill(fill);
}

describe("auditScanCiphertexts", () => {
  it("decrypts 2 ciphertexts and returns 2 AUDITOR_VISIBLE records with correct amounts/tokenIds", async () => {
    const auditor = ed25519GenerateKeyPair();
    const tokenId1 = 0xdeadbeef_00000001n;
    const tokenId2 = 0xdeadbeef_00000002n;
    const commitment1 = makeCommitment(0x01);
    const commitment2 = makeCommitment(0x02);

    const blob1 = encryptAuditorCiphertext(auditor.pubKey, { tokenId: tokenId1, amount: 1_000_000n }, commitment1);
    const blob2 = encryptAuditorCiphertext(auditor.pubKey, { tokenId: tokenId2, amount: 2_500_000n }, commitment2);

    const summary = await auditScanCiphertexts(auditor.privKey, [
      { commitment: commitment1, blob: blob1, slot: 100, blockTime: 1700000000 },
      { commitment: commitment2, blob: blob2, slot: 200, blockTime: 1700001000 },
    ]);

    expect(summary.records).toHaveLength(2);
    expect(summary.outOfRangeSkipped).toBe(0);
    expect(summary.unscopedSkipped).toBe(0);
    expect(summary.notForViewerSkipped).toBe(0);

    const r1 = summary.records.find((r) => r.tokenId === tokenId1);
    const r2 = summary.records.find((r) => r.tokenId === tokenId2);
    expect(r1).toBeDefined();
    expect(r1!.direction).toBe("AUDITOR_VISIBLE");
    expect(r1!.amount).toBe(1_000_000n);
    expect(r1!.leafIndex).toBe(-1);
    expect(r1!.ephemeralPubHex).toBe("");
    expect(r1!.slot).toBe(100);

    expect(r2).toBeDefined();
    expect(r2!.amount).toBe(2_500_000n);
    expect(r2!.slot).toBe(200);
  });

  it("wrong key → 0 records", async () => {
    const auditor = ed25519GenerateKeyPair();
    const wrongKey = ed25519GenerateKeyPair();
    const commitment = makeCommitment(0xab);
    const blob = encryptAuditorCiphertext(auditor.pubKey, { tokenId: 1n, amount: 100n }, commitment);

    const summary = await auditScanCiphertexts(wrongKey.privKey, [
      { commitment, blob },
    ]);

    expect(summary.records).toHaveLength(0);
    expect(summary.notForViewerSkipped).toBe(1);
  });

  it("tokenIds filter: only returns records matching the requested tokenId", async () => {
    const auditor = ed25519GenerateKeyPair();
    const tokenId1 = 111n;
    const tokenId2 = 222n;
    const commitment1 = makeCommitment(0x11);
    const commitment2 = makeCommitment(0x22);

    const blob1 = encryptAuditorCiphertext(auditor.pubKey, { tokenId: tokenId1, amount: 500n }, commitment1);
    const blob2 = encryptAuditorCiphertext(auditor.pubKey, { tokenId: tokenId2, amount: 750n }, commitment2);

    const summary = await auditScanCiphertexts(
      auditor.privKey,
      [
        { commitment: commitment1, blob: blob1 },
        { commitment: commitment2, blob: blob2 },
      ],
      { tokenIds: [tokenId1] },
    );

    expect(summary.records).toHaveLength(1);
    expect(summary.records[0].tokenId).toBe(tokenId1);
    expect(summary.records[0].amount).toBe(500n);
    expect(summary.notForViewerSkipped).toBe(1);
  });

  it("slot range filter: skips entries outside fromSlot/toSlot", async () => {
    const auditor = ed25519GenerateKeyPair();
    const commitment1 = makeCommitment(0x31);
    const commitment2 = makeCommitment(0x32);
    const commitment3 = makeCommitment(0x33);

    const blob1 = encryptAuditorCiphertext(auditor.pubKey, { tokenId: 1n, amount: 100n }, commitment1);
    const blob2 = encryptAuditorCiphertext(auditor.pubKey, { tokenId: 1n, amount: 200n }, commitment2);
    const blob3 = encryptAuditorCiphertext(auditor.pubKey, { tokenId: 1n, amount: 300n }, commitment3);

    const summary = await auditScanCiphertexts(
      auditor.privKey,
      [
        { commitment: commitment1, blob: blob1, slot: 50 },
        { commitment: commitment2, blob: blob2, slot: 150 },
        { commitment: commitment3, blob: blob3, slot: 250 },
      ],
      { fromSlot: 100, toSlot: 200 },
    );

    expect(summary.records).toHaveLength(1);
    expect(summary.records[0].amount).toBe(200n);
    expect(summary.outOfRangeSkipped).toBe(2);
    expect(summary.effectiveFromSlot).toBe(100);
    expect(summary.effectiveToSlot).toBe(200);
  });

  it("entries missing slot are counted as unscopedSkipped when a slot range is set", async () => {
    const auditor = ed25519GenerateKeyPair();
    const commitment = makeCommitment(0x41);
    const blob = encryptAuditorCiphertext(auditor.pubKey, { tokenId: 1n, amount: 100n }, commitment);

    const summary = await auditScanCiphertexts(
      auditor.privKey,
      [{ commitment, blob }],
      { fromSlot: 100 },
    );

    expect(summary.records).toHaveLength(0);
    expect(summary.unscopedSkipped).toBe(1);
  });
});
