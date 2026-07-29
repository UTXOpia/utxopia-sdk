import { describe, it, expect } from "bun:test";
import {
  isValidBitcoinAddress,
  buildDepositOpReturn,
  parseDepositOpReturn,
  DEPOSIT_BITCOIN_NETWORK,
  DEPOSIT_DESTINATION_CHAIN,
  DEPOSIT_OP_RETURN_SIZE,
} from "../../src/taproot";

describe("DEPOSIT_OP_RETURN_SIZE", () => {
  it("should equal compact deposit payload size", () => {
    expect(DEPOSIT_OP_RETURN_SIZE).toBe(73);
  });
});

describe("isValidBitcoinAddress", () => {
  it("recognizes mainnet P2TR (bc1p)", () => {
    // Valid bc1p address (62 chars after bc1p, bech32m)
    const addr =
      "bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297";
    const result = isValidBitcoinAddress(addr);
    expect(result.valid).toBe(true);
    expect(result.type).toBe("p2tr");
    expect(result.network).toBe("mainnet");
  });

  it("recognizes testnet P2TR (tb1p)", () => {
    const addr =
      "tb1pksj664hdqkzvw2tlfvqshnevxt2qdutk47p9z964dkcsxazmf0vsjas4n4";
    const result = isValidBitcoinAddress(addr);
    expect(result.valid).toBe(true);
    expect(result.type).toBe("p2tr");
    expect(result.network).toBe("testnet");
  });

  it("recognizes mainnet P2PKH (1...)", () => {
    const result = isValidBitcoinAddress("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
    expect(result.valid).toBe(true);
    expect(result.type).toBe("p2pkh");
    expect(result.network).toBe("mainnet");
  });

  it("recognizes mainnet P2SH (3...)", () => {
    const result = isValidBitcoinAddress("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy");
    expect(result.valid).toBe(true);
    expect(result.type).toBe("p2sh");
    expect(result.network).toBe("mainnet");
  });

  it("recognizes testnet P2PKH (m/n...)", () => {
    const result = isValidBitcoinAddress("mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn");
    expect(result.valid).toBe(true);
    expect(result.type).toBe("p2pkh");
    expect(result.network).toBe("testnet");
  });

  it("recognizes testnet P2SH (2...)", () => {
    const result = isValidBitcoinAddress("2MzQwSSnBHWHqSAqtTVQ6v47XtaisrJa1Vc");
    expect(result.valid).toBe(true);
    expect(result.type).toBe("p2sh");
    expect(result.network).toBe("testnet");
  });

  it("rejects empty string", () => {
    const result = isValidBitcoinAddress("");
    expect(result.valid).toBe(false);
    expect(result.type).toBe("unknown");
    expect(result.network).toBe("unknown");
  });

  it("rejects random garbage", () => {
    const result = isValidBitcoinAddress("not_an_address");
    expect(result.valid).toBe(false);
  });

  it("rejects truncated bech32m", () => {
    const result = isValidBitcoinAddress("bc1p");
    expect(result.valid).toBe(false);
  });
});

describe("buildDepositOpReturn / parseDepositOpReturn roundtrip", () => {
  const context = {
    destinationChain: DEPOSIT_DESTINATION_CHAIN.SOLANA,
    bitcoinNetwork: DEPOSIT_BITCOIN_NETWORK.REGTEST,
    poolTag: new Uint8Array(8).fill(0xcc),
  };

  it("builds and parses a compact deposit payload", () => {
    const ephemeralPubkey = new Uint8Array(32).fill(0x11);
    const notePublicKey = new Uint8Array(32).fill(0x22);

    const payload = buildDepositOpReturn(ephemeralPubkey, notePublicKey, context);

    expect(payload.length).toBe(DEPOSIT_OP_RETURN_SIZE);
    expect(payload[0]).toBe(0x53);
    expect(payload.slice(1, 9)).toEqual(context.poolTag);
    expect(payload.slice(9, 41)).toEqual(ephemeralPubkey);
    expect(payload.slice(41, 73)).toEqual(notePublicKey);

    const parsed = parseDepositOpReturn(payload);
    expect(parsed).not.toBeNull();
    expect(parsed!.version).toBe(1);
    expect(parsed!.destinationChain).toBe(DEPOSIT_DESTINATION_CHAIN.SOLANA);
    expect(parsed!.bitcoinNetwork).toBe(DEPOSIT_BITCOIN_NETWORK.REGTEST);
    expect(parsed!.poolTag).toEqual(context.poolTag);
    expect(parsed!.ephemeralPubkey).toEqual(ephemeralPubkey);
    expect(parsed!.notePublicKey).toEqual(notePublicKey);
  });

  it("rejects wrong-size ephemeralPubkey", () => {
    expect(() =>
      buildDepositOpReturn(new Uint8Array(16), new Uint8Array(32), context),
    ).toThrow("ephemeralPubkey must be 32 bytes");
  });

  it("rejects wrong-size notePublicKey", () => {
    expect(() =>
      buildDepositOpReturn(new Uint8Array(32), new Uint8Array(16), context),
    ).toThrow("notePublicKey must be 32 bytes");
  });

  it("parseDepositOpReturn returns null for wrong length", () => {
    expect(parseDepositOpReturn(new Uint8Array(DEPOSIT_OP_RETURN_SIZE - 1))).toBeNull();
    expect(parseDepositOpReturn(new Uint8Array(DEPOSIT_OP_RETURN_SIZE + 1))).toBeNull();
  });
});
