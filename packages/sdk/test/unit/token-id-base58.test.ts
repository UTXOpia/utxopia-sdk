import { describe, expect, test } from "bun:test";
import { readFileSync } from "fs";
import { UTXOpiaClient } from "../../src/client";

// getTokenId used to decode base58 mints via require("@solana/web3.js"). That is not
// callable from an ESM browser bundle, so it threw for every real Solana mint and the
// hex fallback behind it threw again on the same input — leaving ChainInbox with zero
// scan targets in production while every Node test passed, because Node has require.
describe("getTokenId accepts base58 mints", async () => {
  const client = await UTXOpiaClient.init();
  const USDC_DEVNET = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU";
  const WSOL = "So11111111111111111111111111111111111111112";

  test("does not throw on a base58 mint", () => {
    expect(() => client.getTokenId(USDC_DEVNET)).not.toThrow();
  });

  test("distinct mints get distinct ids, and it is stable", () => {
    const a = client.getTokenId(USDC_DEVNET);
    const b = client.getTokenId(WSOL);
    expect(a).not.toBe(b);
    expect(client.getTokenId(USDC_DEVNET)).toBe(a);
  });

  // The behavioural tests above pass under the broken implementation too, because bun
  // has require. This is the one that actually fails on it.
  test("client.ts calls no require() — it has to run in a browser bundle", () => {
    const src = readFileSync(new URL("../../src/client.ts", import.meta.url), "utf8");
    const code = src
      .replace(/\/\*[\s\S]*?\*\//g, "")   // block comments
      .replace(/^\s*\/\/.*$/gm, "");        // line comments
    expect(code).not.toMatch(/\brequire\s*\(/);
  });
});
