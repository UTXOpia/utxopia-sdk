import { describe, it, expect } from "bun:test";
import {
  generateAuditorViewingKeypair,
  deriveAuditorViewingKeypair,
} from "../../src/keys";
import {
  encryptAuditorCiphertext,
  decryptAuditorCiphertext,
  type AuditorNotePlain,
} from "../../src/auditor-ciphertext";

const COMMITMENT = new Uint8Array(32).fill(0xcd);

describe("generateAuditorViewingKeypair", () => {
  it("produces 32-byte privKey and 32-byte pubKey", () => {
    const kp = generateAuditorViewingKeypair();
    expect(kp.privKey).toBeInstanceOf(Uint8Array);
    expect(kp.pubKey).toBeInstanceOf(Uint8Array);
    expect(kp.privKey.length).toBe(32);
    expect(kp.pubKey.length).toBe(32);
  });

  it("two calls produce different keypairs", () => {
    const kp1 = generateAuditorViewingKeypair();
    const kp2 = generateAuditorViewingKeypair();
    expect(kp1.privKey).not.toEqual(kp2.privKey);
    expect(kp1.pubKey).not.toEqual(kp2.pubKey);
  });
});

describe("deriveAuditorViewingKeypair", () => {
  it("produces 32-byte privKey and 32-byte pubKey", () => {
    const seed = new Uint8Array(32).fill(0x42);
    const kp = deriveAuditorViewingKeypair(seed);
    expect(kp.privKey).toBeInstanceOf(Uint8Array);
    expect(kp.pubKey).toBeInstanceOf(Uint8Array);
    expect(kp.privKey.length).toBe(32);
    expect(kp.pubKey.length).toBe(32);
  });

  it("is deterministic — same seed yields same keypair", () => {
    const seed = new Uint8Array(32).fill(0x7f);
    const kp1 = deriveAuditorViewingKeypair(seed);
    const kp2 = deriveAuditorViewingKeypair(seed);
    expect(kp1.privKey).toEqual(kp2.privKey);
    expect(kp1.pubKey).toEqual(kp2.pubKey);
  });

  it("different seeds yield different keypairs", () => {
    const seed1 = new Uint8Array(32).fill(0x01);
    const seed2 = new Uint8Array(32).fill(0x02);
    const kp1 = deriveAuditorViewingKeypair(seed1);
    const kp2 = deriveAuditorViewingKeypair(seed2);
    expect(kp1.privKey).not.toEqual(kp2.privKey);
    expect(kp1.pubKey).not.toEqual(kp2.pubKey);
  });

  it("rejects seed that is not 32 bytes", () => {
    expect(() => deriveAuditorViewingKeypair(new Uint8Array(16))).toThrow("seed must be 32 bytes");
  });
});

describe("auditor keypair end-to-end round-trip", () => {
  it("generateAuditorViewingKeypair round-trips through encrypt/decrypt", () => {
    const auditor = generateAuditorViewingKeypair();
    const plain: AuditorNotePlain = {
      tokenId: 0xabcdef1234567890n,
      amount: 500_000n,
    };

    const blob = encryptAuditorCiphertext(auditor.pubKey, plain, COMMITMENT);
    expect(blob.length).toBe(112);

    const decoded = decryptAuditorCiphertext(auditor.privKey, blob, COMMITMENT);
    expect(decoded).not.toBeNull();
    expect(decoded!.tokenId).toBe(plain.tokenId);
    expect(decoded!.amount).toBe(plain.amount);
  });

  it("deriveAuditorViewingKeypair round-trips through encrypt/decrypt", () => {
    const seed = new Uint8Array(32).fill(0xde);
    const auditor = deriveAuditorViewingKeypair(seed);
    const plain: AuditorNotePlain = {
      tokenId: 0x1n,
      amount: 1_000_000_000n,
    };

    const blob = encryptAuditorCiphertext(auditor.pubKey, plain, COMMITMENT);
    const decoded = decryptAuditorCiphertext(auditor.privKey, blob, COMMITMENT);
    expect(decoded).not.toBeNull();
    expect(decoded!.tokenId).toBe(plain.tokenId);
    expect(decoded!.amount).toBe(plain.amount);
  });

  it("wrong key does not decrypt", () => {
    const auditor = generateAuditorViewingKeypair();
    const wrong = generateAuditorViewingKeypair();
    const plain: AuditorNotePlain = { tokenId: 1n, amount: 1n };

    const blob = encryptAuditorCiphertext(auditor.pubKey, plain, COMMITMENT);
    const decoded = decryptAuditorCiphertext(wrong.privKey, blob, COMMITMENT);
    expect(decoded).toBeNull();
  });
});
