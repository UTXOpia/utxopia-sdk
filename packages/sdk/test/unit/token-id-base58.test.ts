import { describe, expect, test } from "bun:test";
import { UTXOpiaClient } from "../../src/client";

// A base58 mint padded to 64 chars is not hex. The fallback used to be computed
// eagerly, so it threw before the base58 branch ran and getTokenId failed for
// every real Solana mint — leaving ChainInbox with zero scan targets.
describe("getTokenId accepts base58 mints", async () => {
  const client = await UTXOpiaClient.init();
  const USDC_DEVNET = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU";

  test("does not throw on a base58 mint", () => {
    expect(() => client.getTokenId(USDC_DEVNET)).not.toThrow();
  });

  test("distinct mints get distinct ids, and it is stable", () => {
    const a = client.getTokenId(USDC_DEVNET);
    const b = client.getTokenId("So11111111111111111111111111111111111111112");
    expect(a).not.toBe(b);
    expect(client.getTokenId(USDC_DEVNET)).toBe(a);
  });
});
