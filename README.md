# UTXOpia SDK

TypeScript client for [UTXOpia](https://utxopia.com) — a privacy-preserving Bitcoin-to-Solana
bridge. Deposits arrive as commitments in a Merkle tree, transfers move between commitments with
Groth16 JoinSplit proofs, and an amount only becomes public when someone withdraws.

> **Alpha.** `0.1.0-alpha.1`, not on npm, no stability guarantees. Interfaces move without notice
> and the protocol has not been deployed to mainnet. Do not point this at funds you cannot lose.

## Install

```bash
bun add @utxopia/sdk
```

Installing from git instead? Pin a commit, never a branch. A floating `#main` means two apps that
installed a week apart disagree about the note format, and the failure surfaces as a proof that
will not verify rather than as an install error:

```jsonc
// package.json
"@utxopia/sdk": "github:UTXOpia/utxopia-sdk#<full-commit-sha>"
```

`snarkjs` and `react` are optional peers — install `snarkjs` only if you generate proofs, `react`
only if you use the hooks.

## What the pieces are

| Concept | What it means here |
|---|---|
| **Note** | A commitment `Poseidon(npk, token, amount)` in the tree. Owning one means knowing the key behind `npk`. |
| **Nullifier** | `Poseidon(nullifyingKey, leafIndex)`. Published on spend so a note cannot be spent twice; it reveals nothing about which note it was. |
| **Stealth address** | A recipient publishes a meta-address; each sender derives a fresh one-time `npk` from it, so payments to the same person are unlinkable on-chain. |
| **JoinSplit(N,M)** | One proof spends N notes and creates M. Shapes with `N + M ≤ 10` are accepted on-chain, 45 in total. |
| **Viewing key** | Decrypts incoming announcements. Separate from the spending key, so scanning can be delegated. |

## Quick start

```typescript
import {
  deriveKeysFromWallet,
  resolveSnsName,
  createStealthDeposit,
  scanAnnouncements,
} from "@utxopia/sdk";

// Keys come from a wallet signature over a fixed message — nothing to store.
const keys = await deriveKeysFromWallet(walletAdapter);

// Recipients can be a .utxopia.sol name instead of a raw meta-address.
const recipient = await resolveSnsName(connection, "alice");

const deposit = await createStealthDeposit(recipient, 100_000n);

// Scanning is a local trial-decrypt of every announcement — there is no
// "my transactions" endpoint to ask, by design.
const notes = await scanAnnouncements(keys, announcements);
```

`docs/API-MAP.md` lists every export grouped by what you are building — config, keys, PDAs,
notes, stealth, Bitcoin, proving, instructions, chain reads, disclosure — and marks which ones
the reference apps actually use. `packages/sdk/README.md` covers each area in depth;
`packages/sdk/docs/SDK.md` has the full type reference.

## Entry points

```typescript
import { … } from "@utxopia/sdk";                 // everything below is re-exported here
import { … } from "@utxopia/sdk/prover/web";      // browser proving (snarkjs + WebAssembly)
import { … } from "@utxopia/sdk/prover/mobile";   // React Native proving
import { … } from "@utxopia/sdk/bitcoin";         // taproot, Ika custody
import { … } from "@utxopia/sdk/stealth";         // stealth addresses on their own
import { … } from "@utxopia/sdk/btc-client";      // Esplora client, OP_RETURN encoding
```

The root export is the whole surface. The subpaths exist so a bundle that only needs, say,
Esplora does not pull in the prover.

## Naming

The prefix tells you what a call costs, so you can read an import list without opening anything:

| prefix | meaning |
|---|---|
| `derive*PDA` | pure address math, synchronous |
| `fetch*` | hits the network — always async |
| `get*` | reads local or already-fetched state — synchronous |
| `parse*` | bytes in, typed object out; no IO |
| `build*InstructionData` / `build*Instruction` | encode instruction data / assemble the full instruction |
| `compute*Sync` | Poseidon and friends; the bare form is an async wrapper over the same thing |
| `encode`/`decode`, `pack`/`unpack`, `serialize`/`deserialize` | symmetric pairs, always both directions |

`PDA` is spelled in caps. Seven MagicBlock helpers used to say `Pda` and two RPC calls were named
`get*`; they were renamed before the first publish, while doing so was still free.

## Proving

Proof generation needs circuit artifacts — a `.wasm` witness generator and a `.zkey` — which are
too large to ship in the package. Point the prover at a host serving them:

```typescript
import { setCircuitPath, generateJoinSplitProof } from "@utxopia/sdk/prover/web";

setCircuitPath("https://circuit.utxopia.com/circuits/v2/groth16");
const proof = await generateJoinSplitProof(inputs);
```

**Pin the artifacts you are willing to prove with.** The `.wasm` is the witness generator: it
receives every private input a JoinSplit has — spending key, nullifying key, note randomness,
amounts, the full Merkle path — in the clear. It arrives over plain `fetch`, where subresource
integrity does not apply, and CDNs serve it `immutable, max-age=31536000`, so a substituted file
survives in browser and edge caches long after the origin is cleaned. Proofs built from a poisoned
generator still verify, so nothing fails and no user notices.

```typescript
import { setCircuitArtifactDigests } from "@utxopia/sdk/prover/web";
import digests from "./circuit-manifest.json"; // generated by your build, committed

setCircuitArtifactDigests(digests.artifacts);
```

Keys are paths under the circuit base (`joinsplit_1x1/joinsplit_1x1_js/joinsplit_1x1.wasm`), so one
manifest covers local dev and the CDN. Once set it fails closed: an artifact with no recorded
digest is refused rather than trusted, so the manifest has to cover every shape your origin serves.
The SDK cannot ship these — they change whenever circuits are rebuilt.

## Layout

```
packages/sdk/          the SDK — keys, notes, stealth, proving, Solana instructions
packages/btc-client/   standalone Esplora client and deposit OP_RETURN encoding
```

## Development

```bash
bun install
bun run test     # 782 tests
bun run build    # tsc
```

Tests are pure unit tests — no network, no validator, no proving. They run in about eight seconds,
so there is no reason to skip them.

## Security

Two things worth knowing before you build on this:

- **`createDelegatedViewKey` currently hands over the `nullifyingKey`.** Because
  `nullifier = Poseidon(nullifyingKey, leafIndex)` does not depend on note contents and leaf
  indices are small public integers, anyone holding it can compute every nullifier that key will
  ever produce and link the owner's entire spend history, retroactively and permanently. The
  `fromSlot`/`toSlot` and FULL/SCAN/INCOMING_ONLY fields on a delegated key are metadata, not
  enforcement. Treat a delegated viewing key as handing over the whole account, not a slice of it.
  `extractViewOnlyBundle` correctly omits the key and is the safer thing to reach for.
- Keys derive from a wallet signature, so **any party who can make that wallet sign the derivation
  message can reconstruct the shielded identity.** A hardware wallet does not change this.

Report anything else privately rather than in a public issue.

## License

MIT
