import { describe, it, expect } from "bun:test";
import * as btc from "@scure/btc-signer";
import { hex } from "@scure/base";
import { selectUtxos, estimateDepositFee, buildDepositPsbt } from "../../src/psbt";
import type { UtxoDescriptor } from "../../src/psbt";

function makeUtxo(value: number, label: string = "a"): UtxoDescriptor {
  return {
    txid: label.repeat(64).slice(0, 64),
    vout: 0,
    value,
    scriptPubkeyHex: "5120" + "bb".repeat(32), // P2TR
  };
}

function makeP2wpkhUtxo(value: number, label: string = "a"): UtxoDescriptor {
  return {
    txid: label.repeat(64).slice(0, 64),
    vout: 0,
    value,
    scriptPubkeyHex: "0014" + "bb".repeat(20),
  };
}

describe("estimateDepositFee", () => {
  it("computes fee for 1 P2TR input with change", () => {
    // TX_OVERHEAD(11) + 1*P2TR_INPUT(58) + P2TR_OUTPUT(43) + OP_RETURN_OUTPUT(84) + CHANGE_OUTPUT(43) = 239
    const fee = estimateDepositFee(1, 1, "p2tr", true);
    expect(fee).toBe(239);
  });

  it("computes fee for 1 P2TR input without change", () => {
    // TX_OVERHEAD(11) + 1*58 + 43 + 84 = 196
    const fee = estimateDepositFee(1, 1, "p2tr", false);
    expect(fee).toBe(196);
  });

  it("computes fee for 2 P2TR inputs with change", () => {
    // 11 + 2*58 + 43 + 84 + 43 = 297
    const fee = estimateDepositFee(2, 1, "p2tr", true);
    expect(fee).toBe(297);
  });

  it("computes fee for 1 P2WPKH input with change", () => {
    // 11 + 1*68 + 43 + 84 + 43 = 249
    const fee = estimateDepositFee(1, 1, "p2wpkh", true);
    expect(fee).toBe(249);
  });

  it("scales linearly with feeRate", () => {
    const fee1 = estimateDepositFee(1, 1, "p2tr", true);
    const fee5 = estimateDepositFee(1, 5, "p2tr", true);
    expect(fee5).toBe(Math.ceil(fee1 * 5));
  });

  it("defaults to p2tr with change", () => {
    const explicit = estimateDepositFee(1, 2, "p2tr", true);
    const defaulted = estimateDepositFee(1, 2);
    expect(defaulted).toBe(explicit);
  });

  it("rounds up with fractional feeRate", () => {
    const fee = estimateDepositFee(1, 1.5, "p2tr", true);
    // 239 * 1.5 = 358.5
    expect(fee).toBe(359);
  });
});

describe("selectUtxos", () => {
  it("selects a single UTXO that covers target + fee", () => {
    const utxos = [makeUtxo(100_000, "a")];
    const selected = selectUtxos(utxos, 10_000, 1);
    expect(selected).toHaveLength(1);
    expect(selected[0].value).toBe(100_000);
  });

  it("selects multiple UTXOs when one is not enough", () => {
    const utxos = [
      makeUtxo(5_000, "a"),
      makeUtxo(5_000, "b"),
      makeUtxo(5_000, "c"),
    ];
    // target=10000, fee for 1 input ~230, for 2 inputs ~288, for 3 inputs ~346
    // After sorting (all equal), accumulate:
    //   1 utxo: 5000 < 10000+230 => continue
    //   2 utxos: 10000 < 10000+288 => continue
    //   3 utxos: 15000 >= 10000+346 => done
    const selected = selectUtxos(utxos, 10_000, 1);
    expect(selected.length).toBeGreaterThanOrEqual(2);
  });

  it("sorts UTXOs descending by value (largest first)", () => {
    const utxos = [
      makeUtxo(1_000, "a"),
      makeUtxo(50_000, "b"),
      makeUtxo(10_000, "c"),
    ];
    const selected = selectUtxos(utxos, 5_000, 1);
    // Should pick the 50_000 UTXO first (largest), which covers everything
    expect(selected).toHaveLength(1);
    expect(selected[0].value).toBe(50_000);
  });

  it("throws on empty UTXO array", () => {
    expect(() => selectUtxos([], 10_000, 1)).toThrow("Insufficient funds");
  });

  it("throws when total funds are insufficient", () => {
    const utxos = [makeUtxo(100, "a")];
    expect(() => selectUtxos(utxos, 10_000, 1)).toThrow("Insufficient funds");
  });

  it("does not mutate the original array", () => {
    const utxos = [
      makeUtxo(1_000, "a"),
      makeUtxo(50_000, "b"),
      makeUtxo(10_000, "c"),
    ];
    const originalOrder = utxos.map((u) => u.value);
    selectUtxos(utxos, 5_000, 1);
    expect(utxos.map((u) => u.value)).toEqual(originalOrder);
  });

  it("handles exact match (target + fee = single UTXO value)", () => {
    // fee for 1 P2TR input with change = 230
    const fee = estimateDepositFee(1, 1);
    const target = 10_000;
    const utxos = [makeUtxo(target + fee, "a")];
    const selected = selectUtxos(utxos, target, 1);
    expect(selected).toHaveLength(1);
  });

  it("accounts for higher fee rates", () => {
    // At feeRate=1, 1 input fee = 230, so 10230 sats is enough for target 10000
    // At feeRate=10, 1 input fee = 2300, so 10230 is NOT enough
    const utxos = [makeUtxo(10_230, "a")];
    expect(() => selectUtxos(utxos, 10_000, 10)).toThrow("Insufficient funds");
  });
});

describe("buildDepositPsbt", () => {
  it("emits the compact deposit OP_RETURN as OP_PUSHBYTES_73", () => {
    const opReturnPayload = new Uint8Array(73).fill(0x33);

    const result = buildDepositPsbt({
      senderUtxos: [makeP2wpkhUtxo(100_000, "a")],
      depositAddress: "tb1pksj664hdqkzvw2tlfvqshnevxt2qdutk47p9z964dkcsxazmf0vsjas4n4",
      depositAmountSats: 10_000,
      opReturnPayload,
      changeAddress: "tb1pksj664hdqkzvw2tlfvqshnevxt2qdutk47p9z964dkcsxazmf0vsjas4n4",
      feeRate: 1,
      network: "testnet",
    });

    const tx = btc.Transaction.fromPSBT(hex.decode(result.psbtHex), { allowUnknownOutputs: true });
    const opReturnOutput = tx.getOutput(1);

    expect(opReturnOutput.script).toEqual(new Uint8Array([0x6a, 0x49, ...opReturnPayload]));
    expect(opReturnOutput.amount).toBe(0n);
  });
});
