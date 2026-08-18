import { afterEach, describe, expect, test } from "bun:test";
import { setCircuitArtifactDigests, setCircuitPath } from "../../src/prover/web";
import { preloadJoinSplitCircuit } from "../../src/prover/web";

const BASE = "https://cdn.example/circuits/groth16";
const WASM_KEY = "joinsplit_1x1/joinsplit_1x1_js/joinsplit_1x1.wasm";
const ZKEY_KEY = "joinsplit_1x1/joinsplit_1x1.zkey";

const sha256Hex = async (bytes: Uint8Array) =>
  Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)), (b) =>
    b.toString(16).padStart(2, "0"),
  ).join("");

const originalFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = originalFetch;
  setCircuitArtifactDigests(null);
});

/** Serve fixed bytes for every artifact URL, and record which URLs were asked for. */
function serve(bytes: Uint8Array): string[] {
  const seen: string[] = [];
  globalThis.fetch = (async (url: string) => {
    seen.push(String(url));
    return { ok: true, status: 200, arrayBuffer: async () => bytes.buffer } as unknown as Response;
  }) as unknown as typeof fetch;
  return seen;
}

// preloadJoinSplitCircuit is the public entry that downloads without proving, so it exercises
// exactly the fetch path the digests guard.
const preload = () => preloadJoinSplitCircuit(1, 1);

describe("circuit artifact integrity", () => {
  test("refuses an artifact whose bytes do not match the recorded digest", async () => {
    setCircuitPath(BASE);
    serve(new TextEncoder().encode("not the real circuit"));
    setCircuitArtifactDigests({ [WASM_KEY]: "00".repeat(32), [ZKEY_KEY]: "00".repeat(32) });

    await expect(preload()).rejects.toThrow("failed its integrity check");
  });

  test("refuses an artifact that has no recorded digest at all", async () => {
    setCircuitPath(BASE);
    serve(new TextEncoder().encode("anything"));
    // Manifest covers a different shape only — this must fail closed, not fall through.
    setCircuitArtifactDigests({ "joinsplit_2x2/joinsplit_2x2.zkey": "00".repeat(32) });

    await expect(preload()).rejects.toThrow("No integrity digest recorded");
  });

  test("admits artifacts whose digests match", async () => {
    setCircuitPath(BASE);
    const bytes = new TextEncoder().encode("pretend circuit");
    serve(bytes);
    const digest = await sha256Hex(bytes);
    setCircuitArtifactDigests({ [WASM_KEY]: digest, [ZKEY_KEY]: digest });

    await expect(preload()).resolves.toBeUndefined();
  });

  test("verification is off until a manifest is supplied", async () => {
    setCircuitPath(BASE);
    serve(new TextEncoder().encode("unverified"));

    await expect(preload()).resolves.toBeUndefined();
  });
});
