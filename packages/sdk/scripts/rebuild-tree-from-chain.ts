#!/usr/bin/env bun
/**
 * Rebuild a pool's leaf set from Solana logs alone — no backend, no indexer.
 *
 * This is the load-bearing check under "a member can exit without the operator".
 * Every other step of an exit is authorised on chain and readable from public
 * state, but spending a note needs a Merkle proof, and a Merkle proof needs the
 * whole leaf set — which normally comes from the operator's indexer. If the
 * leaves were not recoverable from the chain itself, the exit guarantee would be
 * a promise rather than a property.
 *
 * They are: every insertion emits a StealthAnnouncement (0x03) or an
 * AnnouncementsBatch (0x0C) in the transaction logs, and the tree PDA's own
 * signature history bounds the search. Success is the rebuilt root matching the
 * one the program is verifying against.
 *
 * Usage:
 *   bun run scripts/rebuild-tree-from-chain.ts
 *   RPC=… TREE=… bun run scripts/rebuild-tree-from-chain.ts
 *
 * Defaults to the devnet pool in DEVNET_CONFIG. Nothing here is privileged —
 * a public RPC endpoint is the only input, which is the point.
 *
 * EPOCH_SIG is optional: set it to the tree's INITIALIZE signature to stop the
 * scan there. A closed-and-recreated PDA keeps its old signature history, so
 * without it the scan also replays a dead epoch — harmless (stale leaf indices
 * are overwritten by the live epoch's) but slower.
 */
import { Connection, PublicKey } from "@solana/web3.js";
import {
  CommitmentTreeIndex,
  DEVNET_CONFIG,
  bytesToBigint,
  initPoseidon,
  parseCommitmentTreeData,
} from "../src/index";

const RPC = process.env.RPC ?? DEVNET_CONFIG.solanaRpcUrl;
const TREE = new PublicKey(process.env.TREE ?? DEVNET_CONFIG.commitmentTreePda);
const EPOCH_SIG = process.env.EPOCH_SIG;

const EVENT_STEALTH_ANNOUNCEMENT = 0x03;
const EVENT_ANNOUNCEMENTS_BATCH = 0x0c;

/** "Program data: <b64> <b64> …" — one base64 blob per sol_log_data slice. */
function leavesFromLogs(logs: string[]): Array<[number, bigint]> {
  const out: Array<[number, bigint]> = [];
  for (const line of logs) {
    if (!line.startsWith("Program data: ")) continue;
    const segs = line.slice("Program data: ".length).split(" ")
      .map((s) => { try { return Buffer.from(s, "base64"); } catch { return null; } })
      .filter((b): b is Buffer => b !== null);
    if (segs.length === 0) continue;

    if (segs.length === 1 && segs[0].length > 1 && segs[0][0] === EVENT_ANNOUNCEMENTS_BATCH) {
      const d = segs[0];
      const count = d[1];
      let off = 2;
      for (let i = 0; i < count; i++) {
        // type(1) + ephemeral(32) + amount(8) + commitment(32) + leaf_index(4)
        const commitment = bytesToBigint(new Uint8Array(d.subarray(off + 41, off + 73)));
        out.push([d.readUInt32LE(off + 73), commitment]);
        off += 77;
      }
      continue;
    }
    if (segs[0].length === 1 && segs[0][0] === EVENT_STEALTH_ANNOUNCEMENT && segs.length >= 6) {
      out.push([segs[5].readUInt32LE(0), bytesToBigint(new Uint8Array(segs[4]))]);
    }
  }
  return out;
}

/** Public RPCs rate-limit hard, and this scan is exactly the shape they throttle. */
const PACE_MS = Number(process.env.PACE_MS ?? 120);
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function withRetry<T>(what: string, fn: () => Promise<T>): Promise<T> {
  for (let attempt = 0; ; attempt++) {
    try {
      return await fn();
    } catch (e) {
      const rateLimited = (e as { code?: number })?.code === 429
        || /429|Too many requests/i.test(String(e));
      if (!rateLimited || attempt >= 7) throw e;
      const wait = Math.min(30_000, 1000 * 2 ** attempt);
      console.log(`  rate limited on ${what}, retrying in ${wait / 1000}s`);
      await sleep(wait);
    }
  }
}

const conn = new Connection(RPC, "confirmed");
await initPoseidon();

console.log(`rpc   ${RPC}`);
console.log(`tree  ${TREE.toBase58()}`);

const treeInfo = await conn.getAccountInfo(TREE);
if (!treeInfo) throw new Error(`no account at ${TREE.toBase58()} — wrong TREE or wrong cluster?`);
const tree = parseCommitmentTreeData(new Uint8Array(treeInfo.data));
const expected = Number(tree.nextIndex);
const onChainRoot = bytesToBigint(tree.currentRoot);
console.log(`\non-chain: ${expected} leaves, root ${onChainRoot.toString(16).padStart(64, "0")}`);

// Walk this tree PDA's own signature history, oldest last.
const sigs: string[] = [];
let before: string | undefined;
outer: for (;;) {
  const page = await withRetry("getSignaturesForAddress", () =>
    conn.getSignaturesForAddress(TREE, { before, limit: 1000 }, "confirmed"));
  if (page.length === 0) break;
  for (const s of page) {
    if (s.signature === EPOCH_SIG) break outer;
    if (!s.err) sigs.push(s.signature);
  }
  before = page[page.length - 1].signature;
}
sigs.reverse();
console.log(`scanning ${sigs.length} transactions`);

const commitments = new Map<number, bigint>();
// One at a time, paced. Batched getTransactions is a single JSON-RPC batch call
// and public endpoints reject it outright — no amount of backoff gets it through.
for (let i = 0; i < sigs.length; i++) {
  const tx = await withRetry(`transaction ${i}`, () =>
    conn.getTransaction(sigs[i], { commitment: "confirmed", maxSupportedTransactionVersion: 0 }));
  for (const [leaf, commitment] of leavesFromLogs(tx?.meta?.logMessages ?? [])) {
    if (leaf < expected) commitments.set(leaf, commitment);
  }
  process.stdout.write(`\r  ${i + 1}/${sigs.length} scanned, ${commitments.size} leaves`);
  if (PACE_MS > 0) await sleep(PACE_MS);
}
process.stdout.write("\n");
console.log(`recovered ${commitments.size}/${expected} leaves from logs`);

const missing = Array.from({ length: expected }, (_, i) => i).filter((i) => !commitments.has(i));
if (missing.length > 0) {
  console.error(`\nMISSING leaves ${missing.slice(0, 20).join(", ")}${missing.length > 20 ? " …" : ""}`);
  console.error("The root cannot match with gaps. Set EPOCH_SIG if this PDA was recreated.");
  process.exit(1);
}

const rebuilt = new CommitmentTreeIndex();
for (let i = 0; i < expected; i++) rebuilt.addCommitment(commitments.get(i)!, 0n);
const rebuiltRoot = rebuilt.getRoot();

console.log(`rebuilt:  ${rebuilt.size()} leaves, root ${rebuiltRoot.toString(16).padStart(64, "0")}`);
if (rebuiltRoot !== onChainRoot) {
  console.error("\nMISMATCH — the tree could not be rebuilt without the indexer");
  process.exit(1);
}
console.log("\nMATCH — the leaf set is recoverable from chain alone");
