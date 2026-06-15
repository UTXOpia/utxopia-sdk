import { describe, it, expect } from "bun:test";
import { ed25519GenerateKeyPair } from "../../src/crypto-ed25519";
import {
  encryptAuditorCiphertext,
  decryptAuditorCiphertext,
  buildAuditorCiphertextForNote,
  AUDITOR_CIPHERTEXT_BYTES,
  type AuditorNotePlain,
} from "../../src/auditor-ciphertext";

const COMMITMENT = new Uint8Array(32).fill(0xab);

describe("auditor-ciphertext", () => {
  it("round-trips tokenId+amount and blob is 112 bytes", () => {
    const auditor = ed25519GenerateKeyPair();
    const plain: AuditorNotePlain = {
      tokenId: 0xdeadbeefcafe1234n,
      amount: 1_000_000n,
    };

    const blob = encryptAuditorCiphertext(auditor.pubKey, plain, COMMITMENT);
    expect(blob.length).toBe(112);

    const decoded = decryptAuditorCiphertext(auditor.privKey, blob, COMMITMENT);
    expect(decoded).not.toBeNull();
    expect(decoded!.tokenId).toBe(plain.tokenId);
    expect(decoded!.amount).toBe(plain.amount);
  });

  it("wrong auditor private key → null", () => {
    const auditor = ed25519GenerateKeyPair();
    const wrong = ed25519GenerateKeyPair();
    const plain: AuditorNotePlain = { tokenId: 1n, amount: 1n };

    const blob = encryptAuditorCiphertext(auditor.pubKey, plain, COMMITMENT);
    const decoded = decryptAuditorCiphertext(wrong.privKey, blob, COMMITMENT);
    expect(decoded).toBeNull();
  });

  it("wrong commitment (AAD mismatch) → null", () => {
    const auditor = ed25519GenerateKeyPair();
    const plain: AuditorNotePlain = { tokenId: 42n, amount: 99n };
    const wrongCommitment = new Uint8Array(32).fill(0x00);

    const blob = encryptAuditorCiphertext(auditor.pubKey, plain, COMMITMENT);
    const decoded = decryptAuditorCiphertext(auditor.privKey, blob, wrongCommitment);
    expect(decoded).toBeNull();
  });
});

describe("buildAuditorCiphertextForNote", () => {
  it("produces a 112-byte blob that decrypts back to the same tokenId and amount", () => {
    const auditor = ed25519GenerateKeyPair();
    const tokenId = 0xc0ffee_deadbeefn;
    const amount = 5_000_000n;
    const commitment = new Uint8Array(32).fill(0x7e);

    const blob = buildAuditorCiphertextForNote({
      auditorViewingPubKey: auditor.pubKey,
      tokenId,
      amount,
      commitment,
    });

    expect(blob.length).toBe(AUDITOR_CIPHERTEXT_BYTES);

    const decoded = decryptAuditorCiphertext(auditor.privKey, blob, commitment);
    expect(decoded).not.toBeNull();
    expect(decoded!.tokenId).toBe(tokenId);
    expect(decoded!.amount).toBe(amount);
  });

  it("different auditor key cannot decrypt the blob", () => {
    const auditor = ed25519GenerateKeyPair();
    const wrong = ed25519GenerateKeyPair();
    const commitment = new Uint8Array(32).fill(0x11);

    const blob = buildAuditorCiphertextForNote({
      auditorViewingPubKey: auditor.pubKey,
      tokenId: 1n,
      amount: 100n,
      commitment,
    });

    expect(decryptAuditorCiphertext(wrong.privKey, blob, commitment)).toBeNull();
  });
});
