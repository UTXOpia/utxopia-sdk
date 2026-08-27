/**
 * "What am I proving?" — a canonical sentence for a shielded spend.
 *
 * The text is not the point. The point is that `renderSpendDoc` recomputes the
 * proof's public signals from the numbers it is about to print and throws if
 * they disagree, so a UI cannot caption a proof with an amount or a destination
 * the proof does not actually contain.
 *
 * Nothing here changes the circuit. Every value below is already bound to the
 * user's spending key by the in-circuit EdDSA over
 * Poseidon(merkleRoot, boundParamsHash, nullifiers.., commitmentsOut..).
 */

import {
  computeSolanaDomainBoundParamsHash,
  createRedeemBoundParams,
  createTransferBoundParams,
  createUnshieldBoundParams,
  type SolanaPrivacyDomainContext,
} from "./bound-params";
import { bytesToHex as hex } from "./crypto";

export interface SpendDoc {
  mode: "transfer" | "unshield" | "redeem";
  /** Display label, e.g. "Solana Devnet". */
  network: string;
  /** Display label, e.g. "zkBTC". */
  asset: string;
  decimals: number;
  /** Destination as shown to the user (a .sol name, a BTC address, a pubkey). */
  recipient: string;
  /**
   * The destination bytes actually folded into boundParamsHash: 32-byte Solana
   * owner for `unshield`, raw scriptPubKey for `redeem`. Omitted for `transfer`,
   * where the destination is private and provably absent from the signals.
   */
  recipientBytes?: Uint8Array;
  /** Raw units the recipient receives. */
  amount: bigint;
  relayerFee: bigint;
  change: bigint;
}

/** The public signals of the proof about to be generated, plus what built them. */
export interface SpendSignals {
  /** `outputs.map(o => o.value)` from JoinSplitProofInputs. */
  outputValues: bigint[];
  /** The boundParamsHash going into the proof. */
  boundParamsHash: bigint;
  stealthDataHash: Uint8Array;
  chainId: bigint;
  domain: SolanaPrivacyDomainContext;
  /** Redeem only: the on-chain requester bound into the proof. */
  requester?: Uint8Array;
  treeNumber?: number;
}

export class SpendDocMismatch extends Error {}

function fmt(raw: bigint, decimals: number): string {
  const neg = raw < 0n;
  const s = (neg ? -raw : raw).toString().padStart(decimals + 1, "0");
  const whole = s.slice(0, s.length - decimals);
  const frac = decimals === 0 ? "" : s.slice(s.length - decimals).replace(/0+$/, "");
  return `${neg ? "-" : ""}${whole}${frac ? `.${frac}` : ""}`;
}

function sortedValues(v: bigint[]): string {
  return [...v].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0)).join(",");
}

function expectedBoundParamsHash(doc: SpendDoc, s: SpendSignals): bigint {
  const tree = s.treeNumber ?? 0;
  switch (doc.mode) {
    case "transfer":
      return computeSolanaDomainBoundParamsHash(
        createTransferBoundParams(s.stealthDataHash, s.chainId, tree),
        s.domain,
      );
    case "unshield":
      if (!doc.recipientBytes) throw new SpendDocMismatch("unshield doc has no recipientBytes");
      return computeSolanaDomainBoundParamsHash(
        createUnshieldBoundParams(doc.recipientBytes, s.stealthDataHash, s.chainId, tree),
        s.domain,
      );
    case "redeem":
      if (!doc.recipientBytes) throw new SpendDocMismatch("redeem doc has no recipientBytes");
      if (!s.requester) throw new SpendDocMismatch("redeem doc has no requester");
      return computeSolanaDomainBoundParamsHash(
        createRedeemBoundParams(doc.recipientBytes, s.stealthDataHash, s.requester, s.chainId, tree),
        s.domain,
      );
  }
}

/**
 * The statement itself. Show this before the user commits; pass the same `doc`
 * to `renderSpendDoc` when the proof is built so the string they read is the
 * string that gets checked.
 */
export function formatSpendDoc(doc: SpendDoc): string {
  const amt = (v: bigint) => `${fmt(v, doc.decimals)} ${doc.asset}`;
  const action =
    doc.mode === "redeem"
      ? `Withdraw ${amt(doc.amount)} to Bitcoin`
      : doc.mode === "unshield"
        ? `Unshield ${amt(doc.amount)}`
        : `Send ${amt(doc.amount)} privately`;

  const lines = [
    "UTXOpia Proof",
    "",
    "I AM PROVING",
    action,
    "",
    "DETAILS",
    `Network: ${doc.network}`,
    `Amount leaving the pool: ${amt(doc.amount)}`,
    `To: ${doc.recipient}`,
  ];
  if (doc.recipientBytes) lines.push(`Bound destination: ${hex(doc.recipientBytes)}`);
  if (doc.relayerFee > 0n) lines.push(`Relayer fee: ${amt(doc.relayerFee)}`);
  if (doc.change > 0n) lines.push(`Change back to me: ${amt(doc.change)}`);
  lines.push(
    "",
    "ENFORCED BY THE PROOF",
    "Amounts: these are every output this proof creates",
    doc.mode === "transfer"
      ? "Destination: private — not in the public signals. Confirm it with the recipient."
      : "Destination: bound into boundParamsHash and re-derived onchain",
  );
  if (doc.mode !== "transfer") {
    lines.push(
      "Protocol fee: deducted onchain from pool policy, not part of this statement",
    );
  }
  lines.push("", "Protocol: utxopia-spend-doc-v1");
  return lines.join("\n");
}

/**
 * Render the statement, or throw if it does not describe `signals`.
 *
 * Checked: every amount on screen is an output value of the proof and there are
 * no other outputs; the destination reproduces boundParamsHash.
 * Not checked: that `recipient` (a label) names `recipientBytes` — the doc
 * prints the bound bytes so that stays verifiable by eye.
 */
export function renderSpendDoc(doc: SpendDoc, signals: SpendSignals): string {
  const shown = [doc.amount, doc.relayerFee, doc.change].filter((v) => v > 0n);
  if (sortedValues(shown) !== sortedValues(signals.outputValues)) {
    throw new SpendDocMismatch(
      `amounts do not match the proof outputs: doc [${sortedValues(shown)}] vs proof [${sortedValues(signals.outputValues)}]`,
    );
  }
  const expected = expectedBoundParamsHash(doc, signals);
  if (expected !== signals.boundParamsHash) {
    throw new SpendDocMismatch("destination does not match the proof's boundParamsHash");
  }

  return formatSpendDoc(doc);
}
