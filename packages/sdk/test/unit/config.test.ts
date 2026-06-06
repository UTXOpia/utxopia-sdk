import { afterEach, describe, expect, it } from "bun:test";
import { getConfig, initConfig, setConfig } from "../../src/config";

describe("SDK network config", () => {
  afterEach(() => {
    delete process.env.NEXT_PUBLIC_BTC_NETWORK;
    setConfig("devnet");
  });

  it("maps Solana hybrid app network to regtest Bitcoin", async () => {
    await initConfig({ network: "devnet-regtest" });

    const config = getConfig();
    expect(config.network).toBe("devnet");
    expect(config.bitcoinNetwork).toBe("regtest");
    expect(config.esploraUrl).toBe("http://localhost:2140");
  });

  it("maps Sui app networks to their Bitcoin side", async () => {
    await initConfig({ network: "sui-testnet" });
    expect(getConfig().network).toBe("devnet");
    expect(getConfig().bitcoinNetwork).toBe("testnet4");
    expect(getConfig().esploraUrl).toBe("https://mempool.space/testnet4/api");

    await initConfig({ network: "sui-regtest" });
    expect(getConfig().network).toBe("devnet");
    expect(getConfig().bitcoinNetwork).toBe("regtest");
    expect(getConfig().esploraUrl).toBe("http://localhost:2140");
  });

  it("lets explicit BTC network env override the app network Bitcoin side", async () => {
    process.env.NEXT_PUBLIC_BTC_NETWORK = "mainnet";
    await initConfig({ network: "sui-regtest" });

    expect(getConfig().bitcoinNetwork).toBe("mainnet");
    expect(getConfig().esploraUrl).toBe("https://mempool.space/api");
  });

  it("accepts app network names through setConfig", () => {
    setConfig("devnet-regtest");
    expect(getConfig().network).toBe("devnet");
    expect(getConfig().bitcoinNetwork).toBe("regtest");

    setConfig("sui-testnet");
    expect(getConfig().network).toBe("devnet");
    expect(getConfig().bitcoinNetwork).toBe("testnet4");
  });
});
