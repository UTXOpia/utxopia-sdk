import { describe, expect, test } from "bun:test";
import {
  computeSolanaDomainBoundParamsHash,
  createRedeemBoundParams,
  createUnshieldBoundParams,
  formatSpendDoc,
  renderSpendDoc,
  SpendDocMismatch,
  type SolanaPrivacyDomainContext,
  type SpendDoc,
  type SpendSignals,
} from "../src/index";

const domain: SolanaPrivacyDomainContext = {
  programId: new Uint8Array(32).fill(7),
  poolState: new Uint8Array(32).fill(9),
  kind: "public",
};
const stealthDataHash = new Uint8Array(32).fill(3);
const chainId = 103n;
const owner = new Uint8Array(32).fill(0x42);

const unshieldDoc: SpendDoc = {
  mode: "unshield",
  network: "Solana Devnet",
  asset: "zkBTC",
  decimals: 8,
  recipient: "alice.utxopia.sol",
  recipientBytes: owner,
  amount: 3_500_000n,
  relayerFee: 1_000n,
  change: 500_000n,
};

const unshieldSignals = (): SpendSignals => ({
  outputValues: [500_000n, 3_500_000n, 1_000n],
  boundParamsHash: computeSolanaDomainBoundParamsHash(
    createUnshieldBoundParams(owner, stealthDataHash, chainId, 0),
    domain,
  ),
  stealthDataHash,
  chainId,
  domain,
});

describe("renderSpendDoc", () => {
  test("renders when the doc matches the signals", () => {
    const out = renderSpendDoc(unshieldDoc, unshieldSignals());
    expect(out).toContain("Unshield 0.035 zkBTC");
    expect(out).toContain("Relayer fee: 0.00001 zkBTC");
    expect(out).toContain("Change back to me: 0.005 zkBTC");
    expect(out).toContain("To: alice.utxopia.sol");
  });

  test("the previewed string is the verified string", () => {
    // The confirm modal shows formatSpendDoc(doc); the build verifies the same
    // doc. If these ever diverge the user reads one thing and approves another.
    expect(formatSpendDoc(unshieldDoc)).toBe(renderSpendDoc(unshieldDoc, unshieldSignals()));
  });

  test("a lying amount cannot be rendered", () => {
    expect(() => renderSpendDoc({ ...unshieldDoc, amount: 1n }, unshieldSignals()))
      .toThrow(SpendDocMismatch);
  });

  test("an extra hidden output cannot be rendered", () => {
    const s = unshieldSignals();
    s.outputValues = [...s.outputValues, 9_000_000n];
    expect(() => renderSpendDoc(unshieldDoc, s)).toThrow(SpendDocMismatch);
  });

  test("a swapped destination cannot be rendered", () => {
    const s = unshieldSignals();
    const evil = new Uint8Array(32).fill(0xee);
    expect(() => renderSpendDoc({ ...unshieldDoc, recipientBytes: evil }, s))
      .toThrow(SpendDocMismatch);
  });

  test("a redeem doc binds the btc script and the requester", () => {
    const script = Uint8Array.from([0x51, 0x20, ...new Uint8Array(32).fill(0xab)]);
    const requester = new Uint8Array(32).fill(0x11);
    const doc: SpendDoc = {
      ...unshieldDoc,
      mode: "redeem",
      recipient: "bc1p...",
      recipientBytes: script,
      relayerFee: 0n,
      change: 0n,
    };
    const signals: SpendSignals = {
      outputValues: [doc.amount],
      boundParamsHash: computeSolanaDomainBoundParamsHash(
        createRedeemBoundParams(script, stealthDataHash, requester, chainId, 0),
        domain,
      ),
      stealthDataHash,
      chainId,
      domain,
      requester,
    };
    expect(renderSpendDoc(doc, signals)).toContain("Withdraw 0.035 zkBTC to Bitcoin");
    expect(() => renderSpendDoc(doc, { ...signals, requester: new Uint8Array(32).fill(0x22) }))
      .toThrow(SpendDocMismatch);
  });
});
