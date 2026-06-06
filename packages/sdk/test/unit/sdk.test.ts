/**
 * UTXOpia SDK Tests (Consolidated) — JoinSplit Architecture
 *
 * Core tests for all SDK functionality:
 * - DEPOSIT: createNonInteractiveDeposit
 * - TRANSFER: encodeClaimLink / decodeClaimLink
 * - KEYS: deriveKeysFromSeed, createStealthMetaAddress
 */

import { expect, test, describe } from "bun:test";
import { address, createSolanaRpc, getProgramDerivedAddress, type Address } from "@solana/kit";

import { generateNote, formatBtc, parseBtc } from "../../src/note";
import { encodeClaimLink, decodeClaimLink } from "../../src/claim-link";
import { deriveKeysFromSeed, createStealthMetaAddress, encodeStealthMetaAddress, decodeStealthMetaAddress } from "../../src/keys";
import { createNonInteractiveDeposit, createStealthDeposit, scanAnnouncements } from "../../src/stealth";
import {
  DEPOSIT_BITCOIN_NETWORK,
  DEPOSIT_DESTINATION_CHAIN,
  DEPOSIT_OP_RETURN_SIZE,
  parseDepositOpReturn,
} from "../../src/taproot";

const ZKBTC_TOKEN_ID = 0x7a627463n;
const TEST_REGTEST_GROUP_PUBKEY = Uint8Array.from(
  Buffer.from("6c18d9968cc3612708aa5e2a6a10ee7ab57e0cfc6fa6cee7542546c84a00c9d2", "hex"),
);
const TEST_OP_RETURN_CONTEXT = {
  destinationChain: DEPOSIT_DESTINATION_CHAIN.SOLANA,
  bitcoinNetwork: DEPOSIT_BITCOIN_NETWORK.REGTEST,
  poolTag: new Uint8Array(8).fill(0x7a),
};
import { createEmptyMerkleProof, TREE_DEPTH } from "../../src/merkle";
import { poseidonHashSync, initPoseidon } from "../../src/poseidon";
import { generateBabyJubKeyPair, babyJubMul, BABYJUB_BASE8, isOnBabyJubCurve } from "../../src/crypto";
// Test constants
const TEST_SEED = new Uint8Array(32).fill(0x42);
// ============================================================================
// 1. DEPOSIT Functions (BTC → zkBTC)
// ============================================================================

describe("DEPOSIT", () => {
  test("createNonInteractiveDeposit() generates current BTC deposit metadata", async () => {
    const keys = deriveKeysFromSeed(TEST_SEED);
    const meta = createStealthMetaAddress(keys);
    const result = await createNonInteractiveDeposit(
      meta,
      TEST_REGTEST_GROUP_PUBKEY,
      "regtest",
      undefined,
      TEST_OP_RETURN_CONTEXT,
    );
    const parsed = parseDepositOpReturn(result.opReturnPayload);

    expect(result.btcAddress).toMatch(/^bcrt1p/);
    expect(result.opReturnPayload).toHaveLength(DEPOSIT_OP_RETURN_SIZE);
    expect(parsed).not.toBeNull();
    expect(parsed!.destinationChain).toBe(DEPOSIT_DESTINATION_CHAIN.SOLANA);
    expect(parsed!.bitcoinNetwork).toBe(DEPOSIT_BITCOIN_NETWORK.REGTEST);
    expect(parsed!.ephemeralPubkey).toEqual(result.ephemeralPub);
    expect(parsed!.notePublicKey).toEqual(result.npk);
  });

  test("different non-interactive deposits have unique addresses", async () => {
    const keys = deriveKeysFromSeed(TEST_SEED);
    const meta = createStealthMetaAddress(keys);
    const d1 = await createNonInteractiveDeposit(meta, TEST_REGTEST_GROUP_PUBKEY, "regtest", undefined, TEST_OP_RETURN_CONTEXT);
    const d2 = await createNonInteractiveDeposit(meta, TEST_REGTEST_GROUP_PUBKEY, "regtest", undefined, TEST_OP_RETURN_CONTEXT);
    expect(d1.btcAddress).not.toBe(d2.btcAddress);
  });
});

// ============================================================================
// 2. TRANSFER Functions (zkBTC → Someone)
// ============================================================================

describe("TRANSFER", () => {
  test("encodeClaimLink() creates decodeable link", () => {
    const seed = "test-seed-phrase-12345";
    const encoded = encodeClaimLink(seed);
    const decoded = decodeClaimLink(encoded);
    expect(decoded).toBe(seed);
  });

  test("claim link roundtrip with special chars", () => {
    const seed = "my secret phrase with spaces & symbols!";
    const encoded = encodeClaimLink(seed);
    const decoded = decodeClaimLink(encoded);
    expect(decoded).toBe(seed);
  });
});

// ============================================================================
// 3. KEY & STEALTH Functions
// ============================================================================

describe("KEY & STEALTH", () => {
  test("deriveKeysFromSeed() is deterministic", () => {
    const k1 = deriveKeysFromSeed(TEST_SEED);
    const k2 = deriveKeysFromSeed(TEST_SEED);
    expect(k1.spendingPrivKey).toBe(k2.spendingPrivKey);
    expect(k1.viewingPrivKey).toEqual(k2.viewingPrivKey);
  });

  test("different seeds produce different keys", () => {
    const k1 = deriveKeysFromSeed(new Uint8Array(32).fill(0x11));
    const k2 = deriveKeysFromSeed(new Uint8Array(32).fill(0x22));
    expect(k1.spendingPrivKey).not.toBe(k2.spendingPrivKey);
  });

  test("createStealthMetaAddress() creates 32-byte compressed keys", () => {
    const keys = deriveKeysFromSeed(TEST_SEED);
    const meta = createStealthMetaAddress(keys);

    expect(meta.spendingPubKey.length).toBe(32);
    expect(meta.viewingPubKey.length).toBe(32);
  });

  test("stealth meta-address encode/decode roundtrip", () => {
    const keys = deriveKeysFromSeed(TEST_SEED);
    const meta = createStealthMetaAddress(keys);
    const encoded = encodeStealthMetaAddress(meta);
    const decoded = decodeStealthMetaAddress(encoded);

    expect(decoded.spendingPubKey).toEqual(meta.spendingPubKey);
    expect(decoded.viewingPubKey).toEqual(meta.viewingPubKey);
  });

  test("createStealthDeposit() creates valid deposit", async () => {
    const keys = deriveKeysFromSeed(TEST_SEED);
    const meta = createStealthMetaAddress(keys);
    const deposit = await createStealthDeposit(meta, 100_000n, ZKBTC_TOKEN_ID);

    expect(deposit.commitment.length).toBe(32);
    expect(deposit.ephemeralPub.length).toBe(32);
  });

  test("scanAnnouncements() finds own deposits", async () => {
    const keys = deriveKeysFromSeed(TEST_SEED);
    const meta = createStealthMetaAddress(keys);
    const deposit = await createStealthDeposit(meta, 50_000n, ZKBTC_TOKEN_ID);

    const found = await scanAnnouncements(keys, [{
      ephemeralPub: deposit.ephemeralPub,
      encryptedAmount: deposit.encryptedAmount,
      commitment: deposit.commitment,
      leafIndex: 0,
      createdAt: deposit.createdAt,
    }], ZKBTC_TOKEN_ID);

    expect(found.length).toBe(1);
    expect(found[0].amount).toBe(50_000n);
  });

  test("wrong keys cannot find deposits", async () => {
    const realKeys = deriveKeysFromSeed(new Uint8Array(32).fill(0x11));
    const wrongKeys = deriveKeysFromSeed(new Uint8Array(32).fill(0x22));
    const meta = createStealthMetaAddress(realKeys);
    const deposit = await createStealthDeposit(meta, 50_000n, ZKBTC_TOKEN_ID);

    const found = await scanAnnouncements(wrongKeys, [{
      ephemeralPub: deposit.ephemeralPub,
      encryptedAmount: deposit.encryptedAmount,
      commitment: deposit.commitment,
      leafIndex: 0,
      createdAt: deposit.createdAt,
    }], ZKBTC_TOKEN_ID);

    expect(found.length).toBe(0);
  });
});

// ============================================================================
// 4. CRYPTOGRAPHY
// ============================================================================

describe("CRYPTOGRAPHY", () => {
  test("Poseidon hash is deterministic", async () => {
    await initPoseidon();
    const h1 = poseidonHashSync([123n, 456n]);
    const h2 = poseidonHashSync([123n, 456n]);
    expect(h1).toBe(h2);
  });

  test("Baby Jubjub keypair is valid", () => {
    const { privKey, pubKey } = generateBabyJubKeyPair();
    expect(privKey).toBeGreaterThan(0n);
    expect(isOnBabyJubCurve(pubKey)).toBe(true);
  });

  test("Baby Jubjub scalar multiplication", () => {
    const { privKey, pubKey } = generateBabyJubKeyPair();
    const computed = babyJubMul(privKey, BABYJUB_BASE8);
    expect(computed.x).toBe(pubKey.x);
    expect(computed.y).toBe(pubKey.y);
  });
});

// ============================================================================
// 8. UTILITIES
// ============================================================================

describe("UTILITIES", () => {
  test("BTC formatting", () => {
    expect(formatBtc(100_000_000n)).toBe("1.00000000 BTC");
    expect(formatBtc(50_000n)).toBe("0.00050000 BTC");
  });

  test("BTC parsing", () => {
    expect(parseBtc("1 BTC")).toBe(100_000_000n);
    expect(parseBtc("0.001 BTC")).toBe(100_000n);
  });

  test("Merkle proof structure", () => {
    const proof = createEmptyMerkleProof();
    expect(proof.pathElements.length).toBe(TREE_DEPTH);
    expect(proof.pathIndices.length).toBe(TREE_DEPTH);
    expect(proof.root.length).toBe(32);
  });
});
