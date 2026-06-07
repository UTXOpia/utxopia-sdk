import { expect, test } from "bun:test";
import { UTXOpiaSuiAdapter } from "../src/sui-adapter";
import { deriveSuiTokenId } from "../src/sui-token-registry";
import { UTXOpiaSuiIkaAdapter, defaultIkaConfig } from "../src/ika";

const objectId = `0x${"1".padStart(64, "0")}`;

function adapter() {
  return new UTXOpiaSuiAdapter({
    rpcUrl: "http://127.0.0.1:9000",
    packageId: objectId,
    poolObjectId: objectId,
    poolInitialSharedVersion: 1,
    commitmentTreeObjectId: objectId,
    commitmentTreeInitialSharedVersion: 1,
    btcDepositRegistryObjectId: objectId,
    btcDepositRegistryInitialSharedVersion: 1,
    utxoSetObjectId: objectId,
    utxoSetInitialSharedVersion: 1,
    lightClientObjectId: objectId,
    lightClientInitialSharedVersion: 1,
    adminCapObjectId: objectId,
    adminCapVersion: "1",
    adminCapDigest: "11111111111111111111111111111111",
    verifyingKeyRegistryObjectId: objectId,
    verifyingKeyRegistryInitialSharedVersion: 1,
    nullifierRegistryObjectId: objectId,
    nullifierRegistryInitialSharedVersion: 1,
    redemptionQueueObjectId: objectId,
    redemptionQueueInitialSharedVersion: 1,
    redemptionCapObjectId: objectId,
    redemptionCapVersion: "1",
    redemptionCapDigest: "11111111111111111111111111111111",
    tokenRegistryObjectId: objectId,
    tokenRegistryInitialSharedVersion: 1,
  });
}

const SUI_COIN_TYPE = "0x2::sui::SUI";

test("rejects generic Sui shield PTBs offline", async () => {
  await expect(adapter().buildShieldTransaction({
    recipient: "recipient",
    tokenId: "zkbtc",
    amount: 1n,
    metadata: {
      commitment: "11".repeat(32),
    },
  })).rejects.toThrow("Sui generic shield PTBs are disabled");
});

test("builds register verifying key PTB transaction-kind bytes offline", async () => {
  const tx = await adapter().buildRegisterVerifyingKeyTransaction({
    nInputs: 2,
    nOutputs: 2,
    nPublic: 6,
    vkHash: new Uint8Array(32).fill(1),
    vkGammaAbcG1Bytes: new Uint8Array([1]),
    alphaG1BetaG2Bytes: new Uint8Array([2]),
    gammaG2NegPcBytes: new Uint8Array([3]),
    deltaG2NegPcBytes: new Uint8Array([4]),
  });

  expect(tx.kind).toBe("sui-programmable-transaction-block");
  expect(tx.bytes.length).toBeGreaterThan(0);
});

test("rejects Sui verifying keys for unsupported shared circuit shapes", async () => {
  await expect(adapter().buildRegisterVerifyingKeyTransaction({
    nInputs: 6,
    nOutputs: 1,
    nPublic: 9,
    vkHash: new Uint8Array(32).fill(1),
    vkGammaAbcG1Bytes: new Uint8Array([1]),
    alphaG1BetaG2Bytes: new Uint8Array([2]),
    gammaG2NegPcBytes: new Uint8Array([3]),
    deltaG2NegPcBytes: new Uint8Array([4]),
  })).rejects.toThrow("supports at most 8");
});

test("rejects Sui verifying keys with incorrect public input counts", async () => {
  await expect(adapter().buildRegisterVerifyingKeyTransaction({
    nInputs: 2,
    nOutputs: 2,
    nPublic: 7,
    vkHash: new Uint8Array(32).fill(1),
    vkGammaAbcG1Bytes: new Uint8Array([1]),
    alphaG1BetaG2Bytes: new Uint8Array([2]),
    gammaG2NegPcBytes: new Uint8Array([3]),
    deltaG2NegPcBytes: new Uint8Array([4]),
  })).rejects.toThrow("joinsplit_2x2 expects 6 public inputs");
});

test("builds SPV BTC deposit PTB transaction-kind bytes offline", async () => {
  const tx = await adapter().buildBtcDepositTransaction({
    blockHash: new Uint8Array(32).fill(1),
    sweepTxid: new Uint8Array(32).fill(2),
    txIndex: 0,
    merkleSiblings: [new Uint8Array(32).fill(3)],
    pathBits: 0,
    sweepRawTx: new Uint8Array([1, 2, 3]),
    directToPool: true,
  });

  expect(tx.kind).toBe("sui-programmable-transaction-block");
  expect(tx.bytes.length).toBeGreaterThan(0);
  expect(tx.objectIds).toContain(objectId);
});

test("builds transact PTB transaction-kind bytes offline", async () => {
  const tx = await adapter().buildTransactTransaction({
    inputNotes: [
      {
        commitment: "11".repeat(32),
        nullifier: "22".repeat(32),
        tokenId: "zkbtc",
        leafIndex: 0,
      },
    ],
    outputs: [
      {
        recipient: "recipient",
        tokenId: "zkbtc",
        amount: 1n,
      },
    ],
    proof: new Uint8Array(),
    boundParamsHash: "33".repeat(32),
    vkHash: new Uint8Array(32).fill(4),
    publicInputs: new Uint8Array(32 * 4).fill(5),
    proofPoints: new Uint8Array(128).fill(6),
    commitmentsOut: [new Uint8Array(32).fill(7)],
    stealthData: [new Uint8Array(72).fill(9)],
  });

  expect(tx.kind).toBe("sui-programmable-transaction-block");
  expect(tx.bytes.length).toBeGreaterThan(0);
});

test("builds transact PTB from explicit proof relay payload without placeholder notes", async () => {
  const tx = await adapter().buildTransactTransaction({
    nInputs: 1,
    nOutputs: 1,
    proof: new Uint8Array(),
    boundParamsHash: "33".repeat(32),
    vkHash: new Uint8Array(32).fill(4),
    publicInputs: new Uint8Array(32 * 4).fill(5),
    proofPoints: new Uint8Array(128).fill(6),
    nullifiers: [new Uint8Array(32).fill(8)],
    commitmentsOut: [new Uint8Array(32).fill(7)],
    stealthData: [new Uint8Array(72).fill(9)],
  });

  expect(tx.kind).toBe("sui-programmable-transaction-block");
  expect(tx.bytes.length).toBeGreaterThan(0);
});

test("rejects explicit transact payload with mismatched nullifier count", async () => {
  await expect(adapter().buildTransactTransaction({
    nInputs: 2,
    nOutputs: 1,
    proof: new Uint8Array(),
    boundParamsHash: "33".repeat(32),
    vkHash: new Uint8Array(32).fill(4),
    publicInputs: new Uint8Array(32 * 5).fill(5),
    proofPoints: new Uint8Array(128).fill(6),
    nullifiers: [new Uint8Array(32).fill(8)],
    commitmentsOut: [new Uint8Array(32).fill(7)],
  })).rejects.toThrow("nullifier count");
});

test("builds redemption PTB transaction-kind bytes offline", async () => {
  const tx = await adapter().buildRedemptionTransaction({
    inputNotes: [],
    btcAddress: `0014${"22".repeat(20)}`,
    amountSats: 1n,
    maxFeeSats: 1n,
    proof: new Uint8Array(),
    vkHash: new Uint8Array(32).fill(4),
    publicInputs: new Uint8Array(32 * 3).fill(5),
    proofPoints: new Uint8Array(128).fill(6),
    commitmentsOut: [new Uint8Array(32).fill(7)],
  });

  expect(tx.kind).toBe("sui-programmable-transaction-block");
  expect(tx.bytes.length).toBeGreaterThan(0);
});

test("builds redemption PTB from explicit proof relay payload without placeholder notes", async () => {
  const tx = await adapter().buildRedemptionTransaction({
    nInputs: 1,
    nOutputs: 1,
    nPublicOutputs: 1,
    proof: new Uint8Array(),
    vkHash: new Uint8Array(32).fill(4),
    publicInputs: new Uint8Array(32 * 4).fill(5),
    proofPoints: new Uint8Array(128).fill(6),
    nullifiers: [new Uint8Array(32).fill(8)],
    commitmentsOut: [new Uint8Array(32).fill(7)],
    btcScripts: [new Uint8Array([0x51, 0x20, ...Array(32).fill(0x22)])],
    amountsSats: [50_000n],
    maxFeesSats: [2_000n],
    stealthData: [],
  });

  expect(tx.kind).toBe("sui-programmable-transaction-block");
  expect(tx.bytes.length).toBeGreaterThan(0);
});

test("builds Ika approval PTB transaction-kind bytes offline", async () => {
  const tx = await adapter().buildIkaApprovalTransaction({
    redemptionId: 0,
    sighash: new Uint8Array(32).fill(9),
    dwalletCapId: objectId,
    estimatedMinerFeeSats: 800,
  });

  expect(tx.kind).toBe("sui-programmable-transaction-block");
  expect(tx.bytes.length).toBeGreaterThan(0);
});

test("builds Ika approval consume PTB transaction-kind bytes offline", async () => {
  const tx = await adapter().buildConsumeApprovalTransaction({
    approvalObjectId: objectId,
    approvalInitialSharedVersion: 1,
  });

  expect(tx.kind).toBe("sui-programmable-transaction-block");
  expect(tx.bytes.length).toBeGreaterThan(0);
  expect(tx.objectIds).toContain(objectId);
});

test("builds redemption UTXO selection PTB transaction-kind bytes offline", async () => {
  const tx = await adapter().buildMarkProcessingTransaction({
    redemptionId: 0,
    selectedUtxos: [{ txid: new Uint8Array(32).fill(11), vout: 7 }],
    estimatedMinerFeeSats: 800,
  });

  expect(tx.kind).toBe("sui-programmable-transaction-block");
  expect(tx.bytes.length).toBeGreaterThan(0);
  expect(tx.objectIds).toContain(objectId);
});

test("builds redemption completion PTB transaction-kind bytes offline", async () => {
  const tx = await adapter().buildCompleteRedemptionTransaction({
    redemptionId: 0,
    btcTxid: new Uint8Array(32).fill(10),
    blockHash: new Uint8Array(32).fill(12),
    txIndex: 0,
    merkleSiblings: [],
    pathBits: 0,
    rawTx: new Uint8Array([1, 2, 3]),
  });

  expect(tx.kind).toBe("sui-programmable-transaction-block");
  expect(tx.bytes.length).toBeGreaterThan(0);
});

test("rejects unsigned Sui transaction submission", async () => {
  await expect(adapter().submitTransaction({
    chain: "sui",
    kind: "sui-programmable-transaction-block",
    bytes: new Uint8Array([1, 2, 3]),
  } as any)).rejects.toThrow("signature is required");
});

test("builds register token PTB transaction-kind bytes offline", async () => {
  const tx = await adapter().buildRegisterTokenTransaction({
    coinType: SUI_COIN_TYPE,
    metadataObjectId: objectId,
    metadataInitialSharedVersion: 1,
    minDeposit: 100n,
    maxDeposit: 1_000_000n,
    depositCap: 10_000_000n,
    feeBps: 50,
  });

  expect(tx.kind).toBe("sui-programmable-transaction-block");
  expect(tx.bytes.length).toBeGreaterThan(0);
  expect(tx.objectIds).toContain(objectId);
});

test("builds single-PTB shield transaction-kind bytes offline", async () => {
  const tx = await adapter().buildShieldTokenTransaction({
    coinType: SUI_COIN_TYPE,
    fundingCoin: { objectId, version: "1", digest: "11111111111111111111111111111111" },
    amount: 50_000n,
    npk: new Uint8Array(32).fill(7),
    ephemeralPub: new Uint8Array(32).fill(8),
  });

  expect(tx.kind).toBe("sui-programmable-transaction-block");
  expect(tx.bytes.length).toBeGreaterThan(0);
});

test("builds sponsored-gas-compatible unshield PTB transaction-kind bytes offline", async () => {
  const tx = await adapter().buildUnshieldTransaction({
    coinType: SUI_COIN_TYPE,
    nInputs: 1,
    nOutputs: 1,
    nPublicOutputs: 1,
    vkHash: new Uint8Array(32).fill(4),
    publicInputs: new Uint8Array(32 * 4).fill(5),
    proofPoints: new Uint8Array(128).fill(6),
    nullifiers: [new Uint8Array(32).fill(8)],
    commitmentsOut: [new Uint8Array(32).fill(7)],
    stealthData: [],
    amounts: [50_000n],
    recipients: [objectId],
  });

  expect(tx.kind).toBe("sui-programmable-transaction-block");
  expect(tx.bytes.length).toBeGreaterThan(0);
});

test("rejects unshield payload with mismatched recipient count", async () => {
  await expect(adapter().buildUnshieldTransaction({
    coinType: SUI_COIN_TYPE,
    nInputs: 1,
    nOutputs: 1,
    nPublicOutputs: 1,
    vkHash: new Uint8Array(32).fill(4),
    publicInputs: new Uint8Array(32 * 4).fill(5),
    proofPoints: new Uint8Array(128).fill(6),
    nullifiers: [new Uint8Array(32).fill(8)],
    commitmentsOut: [new Uint8Array(32).fill(7)],
    stealthData: [],
    amounts: [50_000n],
    recipients: [objectId, objectId],
  })).rejects.toThrow("recipients must match");
});

test("deriveSuiTokenId matches Move token_registry_tests::sui_token_id vector", () => {
  // The fully-qualified on-chain type string `type_name::get<SUI>().into_string()`
  // (address without 0x) that produced the pinned Move vector.
  const typeName =
    "a5a0ff39f17b1eec14742c58a605257af9cbc677c5541cd63f103c6a09796cd8::token_registry_tests::SUI";
  const tokenId = deriveSuiTokenId(typeName);
  expect("0x" + tokenId.toString(16)).toBe(
    "0xe94827c457076803d7e193e2c2a5c9cc9efcedf973cb850ca8452527840ea5d",
  );
});

test("loads native Ika Sui testnet config", () => {
  const config = defaultIkaConfig("testnet");

  expect(config.packages.ikaPackage.startsWith("0x")).toBe(true);
  expect(config.objects.ikaSystemObject.objectID.startsWith("0x")).toBe(true);
  expect(config.objects.ikaDWalletCoordinator.objectID.startsWith("0x")).toBe(true);
});

test("validates native Ika Taproot approval inputs before PTB build", async () => {
  const ika = new UTXOpiaSuiIkaAdapter({
    rpcUrl: "https://fullnode.testnet.sui.io:443",
    network: "testnet",
    dWalletCapObjectId: objectId,
  });

  await expect(ika.buildApproveTaprootMessageTransaction({
    message: new Uint8Array(31).fill(9),
  })).rejects.toThrow("32 bytes");
});
