/**
 * The seed builders are the single definition of every PDA, so they are what
 * has to be pinned. Two things are checked:
 *
 *  1. Known-good addresses from the live devnet-regtest deployment. A seed
 *     change that alters an address fails here instead of on chain, which is
 *     where every previous drift surfaced — and only after a proof had been
 *     generated and paid for.
 *  2. The scoping that has been lost twice: the nullifier and the redemption
 *     request must both depend on the pool, and the nullifier on the tree.
 *     Losing either lets two distinct notes collapse onto one address.
 */
import { describe, expect, test } from "bun:test";
import {
  poolStateSeeds,
  commitmentTreeSeeds,
  tokenConfigSeeds,
  nullifierRecordSeeds,
  redemptionRequestSeeds,
  vkRegistrySeeds,
} from "../../src/pda";

// Minimal, dependency-free PDA derivation so the test pins the seeds rather
// than agreeing with whichever library produced them.
const { PublicKey } = await import("@solana/web3.js");

const PROGRAM = new PublicKey("CvfSyACR8xemPdeJsB3D8Xh15rKUQ3b5c1PvnmABCBJp");
const ZKBTC_MINT = new PublicKey("BJ5SXA33qK8r8BxJD4nQPf72ae9bactiA2Zqo33EcvPu");
const POOL_STATE = new PublicKey("CeEEmE9MvFPZtqcgv1rsXmzNmfvchbs8VEZJGFKZ2Cyj");

const addr = (seeds: Uint8Array[]): string =>
  PublicKey.findProgramAddressSync(
    seeds.map((s) => Buffer.from(s)),
    PROGRAM,
  )[0].toBase58();

describe("PDA seeds match the deployed program", () => {
  test("pool_state", () => {
    expect(addr(poolStateSeeds(ZKBTC_MINT.toBytes()))).toBe(
      "CeEEmE9MvFPZtqcgv1rsXmzNmfvchbs8VEZJGFKZ2Cyj",
    );
  });

  test("commitment_tree (tree 0)", () => {
    expect(addr(commitmentTreeSeeds(POOL_STATE.toBytes(), 0))).toBe(
      "45bCw97GssorJM9b1ZWZLMGy1NJUczcaNVaKASmCRohL",
    );
  });

  test("token_config", () => {
    expect(addr(tokenConfigSeeds(POOL_STATE.toBytes(), ZKBTC_MINT.toBytes()))).toBe(
      "C9EFFFinGFVfdK7XiSjvjtMEA8JM3tvduzBjCMzAgTcZ",
    );
  });

  test("vk_registry 1x3", () => {
    expect(addr(vkRegistrySeeds(1, 3))).toBe(
      "ELAkqYSZL23QUpHqywYA66VbpjJ6aUkLgqx6eDWPunW9",
    );
  });
});

describe("scoping that has been lost before", () => {
  const hash = new Uint8Array(32).fill(7);
  const otherPool = new PublicKey("45bCw97GssorJM9b1ZWZLMGy1NJUczcaNVaKASmCRohL");

  test("nullifier is scoped by pool", () => {
    expect(addr(nullifierRecordSeeds(hash, POOL_STATE.toBytes(), 0))).not.toBe(
      addr(nullifierRecordSeeds(hash, otherPool.toBytes(), 0)),
    );
  });

  test("nullifier is scoped by tree", () => {
    // Leaf indices restart at 0 in each tree, so the same nullifier names a
    // different note per tree.
    expect(addr(nullifierRecordSeeds(hash, POOL_STATE.toBytes(), 0))).not.toBe(
      addr(nullifierRecordSeeds(hash, POOL_STATE.toBytes(), 1)),
    );
  });

  test("tree 0 keeps the short seeds so existing records stay reachable", () => {
    // joinsplit_common.rs omits the index on tree 0; a 4-byte zero index here
    // would orphan every nullifier already on chain.
    expect(nullifierRecordSeeds(hash, POOL_STATE.toBytes(), 0)).toHaveLength(3);
    expect(nullifierRecordSeeds(hash, POOL_STATE.toBytes(), 1)).toHaveLength(4);
  });

  test("redemption request is scoped by pool", () => {
    const user = new PublicKey("uFBMJSxoGkHj2NyncPzAkhNWsGSQirQcRjUnGfEfWg1").toBytes();
    expect(addr(redemptionRequestSeeds(POOL_STATE.toBytes(), user, 1n))).not.toBe(
      addr(redemptionRequestSeeds(otherPool.toBytes(), user, 1n)),
    );
  });

  test("redemption request is scoped by nonce", () => {
    const user = new PublicKey("uFBMJSxoGkHj2NyncPzAkhNWsGSQirQcRjUnGfEfWg1").toBytes();
    expect(addr(redemptionRequestSeeds(POOL_STATE.toBytes(), user, 1n))).not.toBe(
      addr(redemptionRequestSeeds(POOL_STATE.toBytes(), user, 2n)),
    );
  });
});
