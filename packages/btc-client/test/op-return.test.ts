import { expect, test } from "bun:test";
import { extractUtxopiaDepositOpReturn, parseOpReturnPayload } from "../src/op-return";
import type { BitcoinTransaction } from "../src/types";

test("parses 73-byte UTXOpia OP_RETURN payload", () => {
  const payload = "53" + "aa".repeat(8) + "11".repeat(32) + "22".repeat(32);
  const parsed = parseOpReturnPayload(`6a49${payload}`);

  expect(parsed).toBeDefined();
  expect(parsed?.length).toBe(73);
});

test("extracts deposit OP_RETURN into canonical public key fields", () => {
  const payload = "53" + "aa".repeat(8) + "11".repeat(32) + "22".repeat(32);
  const tx: BitcoinTransaction = {
    txid: "tx",
    version: 2,
    locktime: 0,
    vin: [],
    size: 0,
    weight: 0,
    fee: 0,
    status: { confirmed: true, block_height: 1 },
    vout: [
      {
        scriptpubkey: `6a49${payload}`,
        scriptpubkey_asm: "",
        scriptpubkey_type: "op_return",
        value: 0,
      },
    ],
  };

  const opReturn = extractUtxopiaDepositOpReturn(tx);

  expect(opReturn?.version).toBe(1);
  expect(opReturn?.destinationChain).toBe(1);
  expect(opReturn?.bitcoinNetwork).toBe(3);
  expect(opReturn?.poolTag).toEqual(new Uint8Array(8).fill(0xaa));
  expect(opReturn?.ephemeralPubkey.length).toBe(32);
  expect(opReturn?.notePublicKey.length).toBe(32);
  expect(opReturn?.ephemeralPubkey[0]).toBe(0x11);
  expect(opReturn?.notePublicKey[0]).toBe(0x22);
});
