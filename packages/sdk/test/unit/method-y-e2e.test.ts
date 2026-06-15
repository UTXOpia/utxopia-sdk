import { describe, it, expect, beforeAll } from "bun:test";
import { initPoseidon } from "../../src/poseidon";
import { deriveKeysFromSeed, createDelegatedViewKey, ViewPermissions } from "../../src/keys";
import {
  generateAuditorViewingKeypair,
  buildAuditorCiphertextForNote,
  parseAuditorCiphertextEvent,
  auditorCiphertextFromSuiEventFields,
  EVENT_AUDITOR_CIPHERTEXT,
} from "../../src/index";
import { auditScan } from "../../src/auditor";

beforeAll(async () => {
  await initPoseidon();
});

const TOKEN_ID = 0x7a627463n; // zkBTC
const AMOUNT = 100_000n;
const COMMITMENT = new Uint8Array(32).fill(0xab);

// Stable delegated key for all tests that need one — auditScan requires
// spendingPubKeyCompressed + nullifyingKey (v2 key shape).
const senderKeys = deriveKeysFromSeed(new Uint8Array(32).fill(0x42));
const delegated = createDelegatedViewKey(senderKeys, ViewPermissions.FULL);

describe("Method-Y end-to-end round-trip", () => {
  it("step 1+2: generateAuditorViewingKeypair produces 32-byte keypair; buildAuditorCiphertextForNote produces 112-byte blob", () => {
    const auditor = generateAuditorViewingKeypair();
    expect(auditor.privKey).toBeInstanceOf(Uint8Array);
    expect(auditor.privKey.length).toBe(32);
    expect(auditor.pubKey).toBeInstanceOf(Uint8Array);
    expect(auditor.pubKey.length).toBe(32);

    const blob = buildAuditorCiphertextForNote({
      auditorViewingPubKey: auditor.pubKey,
      tokenId: TOKEN_ID,
      amount: AMOUNT,
      commitment: COMMITMENT,
    });
    expect(blob).toBeInstanceOf(Uint8Array);
    expect(blob.length).toBe(112);
  });

  it("step 3: parseAuditorCiphertextEvent round-trips through sol_log_data segments", () => {
    const auditor = generateAuditorViewingKeypair();
    const blob = buildAuditorCiphertextForNote({
      auditorViewingPubKey: auditor.pubKey,
      tokenId: TOKEN_ID,
      amount: AMOUNT,
      commitment: COMMITMENT,
    });

    // Simulate on-chain emit: sol_log_data segments [disc, commitment, blob]
    const segments = [
      new Uint8Array([EVENT_AUDITOR_CIPHERTEXT]),
      COMMITMENT,
      blob,
    ];

    const parsed = parseAuditorCiphertextEvent(segments);
    expect(parsed).not.toBeNull();
    expect(parsed!.type).toBe("auditor_ciphertext");
    expect(parsed!.commitment).toEqual(COMMITMENT);
    expect(parsed!.blob).toEqual(blob);
  });

  it("step 4: auditScan with correct auditor key produces one AUDITOR_VISIBLE record with correct tokenId + amount", async () => {
    const auditor = generateAuditorViewingKeypair();
    const blob = buildAuditorCiphertextForNote({
      auditorViewingPubKey: auditor.pubKey,
      tokenId: TOKEN_ID,
      amount: AMOUNT,
      commitment: COMMITMENT,
    });

    const result = await auditScan(delegated, [], {
      tokenIds: [TOKEN_ID],
      auditorCiphertexts: [{ commitment: COMMITMENT, blob }],
      auditorViewingPrivKey: auditor.privKey,
    });

    const visible = result.records.filter((r) => r.direction === "AUDITOR_VISIBLE");
    expect(visible).toHaveLength(1);
    expect(visible[0].tokenId).toBe(TOKEN_ID);
    expect(visible[0].amount).toBe(AMOUNT);
  });

  it("step 5 (negative): wrong auditor private key yields zero AUDITOR_VISIBLE records", async () => {
    const auditor = generateAuditorViewingKeypair();
    const wrongAuditor = generateAuditorViewingKeypair();

    const blob = buildAuditorCiphertextForNote({
      auditorViewingPubKey: auditor.pubKey,
      tokenId: TOKEN_ID,
      amount: AMOUNT,
      commitment: COMMITMENT,
    });

    const result = await auditScan(delegated, [], {
      tokenIds: [TOKEN_ID],
      auditorCiphertexts: [{ commitment: COMMITMENT, blob }],
      auditorViewingPrivKey: wrongAuditor.privKey,
    });

    expect(result.records.filter((r) => r.direction === "AUDITOR_VISIBLE")).toHaveLength(0);
  });

  it("step 6 (Sui path): auditorCiphertextFromSuiEventFields normalizes number[] and decrypts through auditScan", async () => {
    const auditor = generateAuditorViewingKeypair();
    const blob = buildAuditorCiphertextForNote({
      auditorViewingPubKey: auditor.pubKey,
      tokenId: TOKEN_ID,
      amount: AMOUNT,
      commitment: COMMITMENT,
    });

    // Sui vector<u8> fields arrive as number[]
    const suiEvent = auditorCiphertextFromSuiEventFields({
      commitment: Array.from(COMMITMENT),
      auditor_ciphertext: Array.from(blob),
    });

    expect(suiEvent).not.toBeNull();
    expect(suiEvent!.type).toBe("auditor_ciphertext");
    expect(suiEvent!.commitment).toEqual(COMMITMENT);
    expect(suiEvent!.blob).toEqual(blob);

    const result = await auditScan(delegated, [], {
      tokenIds: [TOKEN_ID],
      auditorCiphertexts: [{ commitment: suiEvent!.commitment, blob: suiEvent!.blob }],
      auditorViewingPrivKey: auditor.privKey,
    });

    const visible = result.records.filter((r) => r.direction === "AUDITOR_VISIBLE");
    expect(visible).toHaveLength(1);
    expect(visible[0].tokenId).toBe(TOKEN_ID);
    expect(visible[0].amount).toBe(AMOUNT);
  });
});
