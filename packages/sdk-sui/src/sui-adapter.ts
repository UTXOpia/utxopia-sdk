import { Transaction } from "@mysten/sui/transactions";
import type {
  MerkleRoot,
  Note,
  NoteScanInput,
  PoolState,
  RedemptionInput,
  RegisterVerifyingKeyInput,
  ShieldInput,
  SignedTransaction,
  SuiUnsignedTransaction,
  TransactionResult,
  TransactInput,
  UTXOpiaChainAdapter,
} from "../../sdk-core/src/index";
import {
  assertSuiGroth16Compatible,
  joinSplitShape,
} from "../../sdk-core/src/index";

export interface UTXOpiaSuiAdapterConfig {
  rpcUrl: string;
  packageId: string;
  poolObjectId: string;
  poolInitialSharedVersion?: number | string;
  commitmentTreeObjectId?: string;
  commitmentTreeInitialSharedVersion?: number | string;
  btcDepositRegistryObjectId?: string;
  btcDepositRegistryInitialSharedVersion?: number | string;
  utxoSetObjectId?: string;
  utxoSetInitialSharedVersion?: number | string;
  lightClientObjectId?: string;
  lightClientInitialSharedVersion?: number | string;
  adminCapObjectId?: string;
  adminCapVersion?: string;
  adminCapDigest?: string;
  verifyingKeyRegistryObjectId?: string;
  verifyingKeyRegistryInitialSharedVersion?: number | string;
  nullifierRegistryObjectId?: string;
  nullifierRegistryInitialSharedVersion?: number | string;
  redemptionQueueObjectId?: string;
  redemptionQueueInitialSharedVersion?: number | string;
  redemptionCapObjectId?: string;
  redemptionCapVersion?: string;
  redemptionCapDigest?: string;
  indexerUrl?: string;
}

export class UTXOpiaSuiAdapter implements UTXOpiaChainAdapter {
  readonly chain = "sui" as const;

  constructor(private readonly config: UTXOpiaSuiAdapterConfig) {}

  async getPoolState(): Promise<PoolState> {
    return {
      chain: this.chain,
      poolId: this.config.poolObjectId,
      paused: false,
      latestMerkleRoot: "",
      treeDepth: 16,
    };
  }

  async getLatestMerkleRoot(): Promise<MerkleRoot> {
    return {
      root: "",
      index: 0,
      observedAt: new Date(0).toISOString(),
    };
  }

  async getNotes(_: NoteScanInput): Promise<Note[]> {
    if (!this.config.indexerUrl) {
      return [];
    }

    throw new Error("Sui note scanning requires the Sui indexer API implementation");
  }

  async buildShieldTransaction(input: ShieldInput): Promise<SuiUnsignedTransaction> {
    void input;
    throw new Error("Sui generic shield PTBs are disabled; use buildBtcDepositTransaction with a verified BTC deposit object");
  }

  /**
   * Trustless SPV deposit: composes `btc_light_client::verify_tx_inclusion` and
   * `btc_deposit::complete_deposit` in one PTB. The inclusion proof is verified
   * on-chain against the light client's canonical chain; the resulting
   * `VerifiedInclusion` hot potato is consumed by `complete_deposit`.
   */
  async buildBtcDepositTransaction(input: {
    /** Hash of the (canonical, sufficiently confirmed) block containing the sweep tx. */
    blockHash: Uint8Array;
    /** Internal-byte-order txid of the SPV-proven sweep transaction. */
    sweepTxid: Uint8Array;
    /** Index of the sweep tx within the block. */
    txIndex: number;
    /** Merkle branch from the sweep tx up to the block's merkle root. */
    merkleSiblings: Uint8Array[];
    /** Path bits for the merkle branch (bit i = side at level i). */
    pathBits: bigint | number;
    /** Raw bytes of the SPV-proven sweep transaction. */
    sweepRawTx: Uint8Array;
    /** Raw bytes of the original deposit tx carrying the OP_RETURN; omit when directToPool. */
    depositRawTx?: Uint8Array;
    /** True when the deposit paid the pool directly (sweep tx IS the deposit tx). */
    directToPool: boolean;
  }): Promise<SuiUnsignedTransaction> {
    if (!this.config.btcDepositRegistryObjectId) {
      throw new Error("Sui BTC deposit registry object ID is required to build BTC deposit PTBs");
    }
    if (!this.config.utxoSetObjectId) {
      throw new Error("Sui UTXO set object ID is required to build BTC deposit PTBs");
    }
    if (!this.config.lightClientObjectId) {
      throw new Error("Sui BTC light client object ID is required to build BTC deposit PTBs");
    }
    if (!this.config.commitmentTreeObjectId) {
      throw new Error("Sui commitment tree object ID is required to build BTC deposit PTBs");
    }

    const tx = new Transaction();
    const inclusion = tx.moveCall({
      target: `${this.config.packageId}::btc_light_client::verify_tx_inclusion`,
      arguments: [
        this.sharedObject(tx, this.config.lightClientObjectId, this.config.lightClientInitialSharedVersion, false),
        tx.pure.vector("u8", input.blockHash),
        tx.pure.vector("u8", input.sweepTxid),
        tx.pure.u32(input.txIndex),
        tx.pure("vector<vector<u8>>", input.merkleSiblings.map((bytes) => Array.from(bytes))),
        tx.pure.u64(input.pathBits.toString()),
      ],
    });

    tx.moveCall({
      target: `${this.config.packageId}::btc_deposit::complete_deposit`,
      arguments: [
        this.sharedObject(tx, this.config.poolObjectId, this.config.poolInitialSharedVersion, true),
        this.sharedObject(
          tx,
          this.config.btcDepositRegistryObjectId,
          this.config.btcDepositRegistryInitialSharedVersion,
          true,
        ),
        this.sharedObject(tx, this.config.utxoSetObjectId, this.config.utxoSetInitialSharedVersion, true),
        this.sharedObject(
          tx,
          this.config.commitmentTreeObjectId,
          this.config.commitmentTreeInitialSharedVersion,
          true,
        ),
        inclusion,
        tx.pure.vector("u8", input.sweepRawTx),
        tx.pure.vector("u8", input.depositRawTx ?? new Uint8Array()),
        tx.pure.bool(input.directToPool),
      ],
    });

    return this.buildPtb(tx, "Sui SPV BTC deposit PTB", [
      this.config.lightClientObjectId,
      this.config.poolObjectId,
      this.config.btcDepositRegistryObjectId,
      this.config.utxoSetObjectId,
      this.config.commitmentTreeObjectId,
    ]);
  }

  async buildTransactTransaction(input: TransactInput): Promise<SuiUnsignedTransaction> {
    if (!this.config.commitmentTreeObjectId) {
      throw new Error("Sui commitment tree object ID is required to build transact PTBs");
    }
    if (!this.config.nullifierRegistryObjectId) {
      throw new Error("Sui nullifier registry object ID is required to build transact PTBs");
    }
    if (!this.config.verifyingKeyRegistryObjectId) {
      throw new Error("Sui verifying-key registry object ID is required to build transact PTBs");
    }
    if (!input.vkHash || !input.publicInputs || !input.proofPoints || !input.commitmentsOut) {
      throw new Error("Sui transact PTBs require vkHash, publicInputs, proofPoints, and commitmentsOut");
    }

    const tx = new Transaction();
    const nullifiers = input.nullifiers ?? input.inputNotes
      .map((note) => note.nullifier)
      .filter((nullifier): nullifier is string => Boolean(nullifier))
      .map(bytesFromHexOrUtf8);
    const nullifierBytes = nullifiers.map((bytes) => Array.from(bytes));
    const commitmentBytes = input.commitmentsOut.map((bytes) => Array.from(bytes));

    tx.moveCall({
      target: `${this.config.packageId}::transact::transact`,
      arguments: [
        this.sharedObject(tx, this.config.poolObjectId, this.config.poolInitialSharedVersion, false),
        this.sharedObject(
          tx,
          this.config.commitmentTreeObjectId,
          this.config.commitmentTreeInitialSharedVersion,
          true,
        ),
        this.sharedObject(
          tx,
          this.config.nullifierRegistryObjectId,
          this.config.nullifierRegistryInitialSharedVersion,
          true,
        ),
        this.sharedObject(
          tx,
          this.config.verifyingKeyRegistryObjectId,
          this.config.verifyingKeyRegistryInitialSharedVersion,
          false,
        ),
        tx.pure.u8(input.inputNotes.length),
        tx.pure.u8(input.outputs.length),
        tx.pure.vector("u8", input.vkHash),
        tx.pure.vector("u8", input.publicInputs),
        tx.pure.vector("u8", input.proofPoints),
        tx.pure("vector<vector<u8>>", nullifierBytes),
        tx.pure("vector<vector<u8>>", commitmentBytes),
      ],
    });

    return this.buildPtb(tx, "Sui private transfer PTB", [
      this.config.poolObjectId,
      this.config.commitmentTreeObjectId,
      this.config.nullifierRegistryObjectId,
      this.config.verifyingKeyRegistryObjectId,
    ]);
  }

  async buildRedemptionTransaction(input: RedemptionInput): Promise<SuiUnsignedTransaction> {
    if (!this.config.redemptionQueueObjectId) {
      throw new Error("Sui redemption queue object ID is required to build redemption PTBs");
    }
    if (!this.config.commitmentTreeObjectId) {
      throw new Error("Sui commitment tree object ID is required to build redemption PTBs");
    }
    if (!this.config.nullifierRegistryObjectId) {
      throw new Error("Sui nullifier registry object ID is required to build redemption PTBs");
    }
    if (!this.config.verifyingKeyRegistryObjectId) {
      throw new Error("Sui verifying-key registry object ID is required to build redemption PTBs");
    }
    if (!input.vkHash || !input.publicInputs || !(input.proofPoints ?? input.proof) || !input.commitmentsOut) {
      throw new Error("Sui redemption PTBs require vkHash, publicInputs, proofPoints, and commitmentsOut");
    }

    const tx = new Transaction();
    const nullifiers = input.nullifiers ?? input.inputNotes
      .map((note) => note.nullifier)
      .filter((nullifier): nullifier is string => Boolean(nullifier))
      .map(bytesFromHexOrUtf8);
    const btcScripts = input.btcScripts ?? [bytesFromHexOrUtf8(input.btcAddress)];
    const amountsSats = input.amountsSats ?? [input.amountSats];
    const maxFeesSats = input.maxFeesSats ?? [input.maxFeeSats];
    const nPublicOutputs = input.nPublicOutputs ?? btcScripts.length;
    const nOutputs = input.commitmentsOut.length;

    if (nPublicOutputs !== btcScripts.length || nPublicOutputs !== amountsSats.length || nPublicOutputs !== maxFeesSats.length) {
      throw new Error("Sui redemption public output count must match btcScripts, amountsSats, and maxFeesSats");
    }

    tx.moveCall({
      target: `${this.config.packageId}::redemption::redeem`,
      arguments: [
        this.sharedObject(tx, this.config.poolObjectId, this.config.poolInitialSharedVersion, true),
        this.sharedObject(
          tx,
          this.config.commitmentTreeObjectId,
          this.config.commitmentTreeInitialSharedVersion,
          true,
        ),
        this.sharedObject(
          tx,
          this.config.nullifierRegistryObjectId,
          this.config.nullifierRegistryInitialSharedVersion,
          true,
        ),
        this.sharedObject(
          tx,
          this.config.verifyingKeyRegistryObjectId,
          this.config.verifyingKeyRegistryInitialSharedVersion,
          false,
        ),
        this.sharedObject(
          tx,
          this.config.redemptionQueueObjectId,
          this.config.redemptionQueueInitialSharedVersion,
          true,
        ),
        tx.pure.u8(input.inputNotes.length),
        tx.pure.u8(nOutputs),
        tx.pure.u8(nPublicOutputs),
        tx.pure.vector("u8", input.vkHash),
        tx.pure.vector("u8", input.publicInputs),
        tx.pure.vector("u8", input.proofPoints ?? input.proof),
        tx.pure("vector<vector<u8>>", nullifiers.map((bytes) => Array.from(bytes))),
        tx.pure("vector<vector<u8>>", input.commitmentsOut.map((bytes) => Array.from(bytes))),
        tx.pure("vector<vector<u8>>", btcScripts.map((bytes) => Array.from(bytes))),
        tx.pure("vector<u64>", amountsSats.map((amount) => amount.toString())),
        tx.pure("vector<u64>", maxFeesSats.map((fee) => fee.toString())),
      ],
    });

    return this.buildPtb(tx, "Sui proof-checked BTC redemption PTB", [
      this.config.poolObjectId,
      this.config.commitmentTreeObjectId,
      this.config.nullifierRegistryObjectId,
      this.config.verifyingKeyRegistryObjectId,
      this.config.redemptionQueueObjectId,
    ]);
  }

  /**
   * Policy-gated, single-use signing approval. Shares a `SigningApproval` object
   * bound to the redemption; the off-chain signer consumes it atomically with the
   * Ika `requestSign` PTB via {@link buildConsumeApprovalTransaction}.
   */
  async buildIkaApprovalTransaction(input: {
    redemptionId: bigint | number;
    sighash: Uint8Array;
    /** Ika dWallet cap object the approval is bound to. */
    dwalletCapId: string;
    /** Estimated BTC miner fee; must satisfy policy and the request's maxFeeSats. */
    estimatedMinerFeeSats: bigint | number;
  }): Promise<SuiUnsignedTransaction> {
    if (!this.config.redemptionQueueObjectId) {
      throw new Error("Sui redemption queue object ID is required to build Ika approval PTBs");
    }
    const redemptionCap = this.redemptionCapRef();

    const tx = new Transaction();
    tx.moveCall({
      target: `${this.config.packageId}::ika_policy::approve_signing`,
      arguments: [
        tx.objectRef(redemptionCap),
        this.sharedObject(tx, this.config.poolObjectId, this.config.poolInitialSharedVersion, false),
        this.sharedObject(
          tx,
          this.config.redemptionQueueObjectId,
          this.config.redemptionQueueInitialSharedVersion,
          false,
        ),
        tx.pure.address(input.dwalletCapId),
        tx.pure.u64(input.redemptionId.toString()),
        tx.pure.u64(input.estimatedMinerFeeSats.toString()),
        tx.pure.vector("u8", input.sighash),
      ],
    });

    return this.buildPtb(tx, "Sui Ika signing approval PTB", [
      redemptionCap.objectId,
      this.config.poolObjectId,
      this.config.redemptionQueueObjectId,
    ]);
  }

  /**
   * Burn a shared `SigningApproval` (single-use). Compose in the SAME PTB as the
   * Ika sign request so the approval is consumed atomically with signing.
   */
  async buildConsumeApprovalTransaction(input: {
    approvalObjectId: string;
    approvalInitialSharedVersion: number | string;
  }): Promise<SuiUnsignedTransaction> {
    if (!this.config.redemptionQueueObjectId) {
      throw new Error("Sui redemption queue object ID is required to build approval-consume PTBs");
    }
    const redemptionCap = this.redemptionCapRef();

    const tx = new Transaction();
    tx.moveCall({
      target: `${this.config.packageId}::ika_policy::consume_approval`,
      arguments: [
        tx.objectRef(redemptionCap),
        this.sharedObject(tx, this.config.poolObjectId, this.config.poolInitialSharedVersion, false),
        this.sharedObject(
          tx,
          this.config.redemptionQueueObjectId,
          this.config.redemptionQueueInitialSharedVersion,
          false,
        ),
        this.sharedObject(tx, input.approvalObjectId, input.approvalInitialSharedVersion, true),
      ],
    });

    return this.buildPtb(tx, "Sui Ika approval consume PTB", [
      redemptionCap.objectId,
      this.config.poolObjectId,
      this.config.redemptionQueueObjectId,
      input.approvalObjectId,
    ]);
  }

  async buildMarkProcessingTransaction(input: {
    redemptionId: bigint | number;
    selectedUtxos: Array<{ txid: Uint8Array; vout: number }>;
    estimatedMinerFeeSats: bigint | number;
  }): Promise<SuiUnsignedTransaction> {
    if (!this.config.redemptionQueueObjectId) {
      throw new Error("Sui redemption queue object ID is required to build mark-processing PTBs");
    }
    if (!this.config.utxoSetObjectId) {
      throw new Error("Sui UTXO set object ID is required to build mark-processing PTBs");
    }
    const redemptionCap = this.redemptionCapRef();

    const tx = new Transaction();
    tx.moveCall({
      target: `${this.config.packageId}::redemption::mark_processing`,
      arguments: [
        tx.objectRef(redemptionCap),
        this.sharedObject(tx, this.config.poolObjectId, this.config.poolInitialSharedVersion, false),
        this.sharedObject(tx, this.config.utxoSetObjectId, this.config.utxoSetInitialSharedVersion, true),
        this.sharedObject(
          tx,
          this.config.redemptionQueueObjectId,
          this.config.redemptionQueueInitialSharedVersion,
          true,
        ),
        tx.pure.u64(input.redemptionId.toString()),
        tx.pure("vector<vector<u8>>", input.selectedUtxos.map((utxo) => Array.from(utxo.txid))),
        tx.pure("vector<u32>", input.selectedUtxos.map((utxo) => utxo.vout)),
        tx.pure.u64(input.estimatedMinerFeeSats.toString()),
      ],
    });

    return this.buildPtb(tx, "Sui redemption UTXO selection PTB", [
      redemptionCap.objectId,
      this.config.poolObjectId,
      this.config.utxoSetObjectId,
      this.config.redemptionQueueObjectId,
    ]);
  }

  async buildCompleteRedemptionTransaction(input: {
    redemptionId: bigint | number;
    btcTxid: Uint8Array;
    blockHash?: Uint8Array;
    txIndex?: number;
    merkleSiblings?: Uint8Array[];
    pathBits?: bigint | number;
    rawTx?: Uint8Array;
  }): Promise<SuiUnsignedTransaction> {
    if (!this.config.redemptionQueueObjectId) {
      throw new Error("Sui redemption queue object ID is required to build completion PTBs");
    }
    if (!this.config.utxoSetObjectId) {
      throw new Error("Sui UTXO set object ID is required to build completion PTBs");
    }
    if (!this.config.lightClientObjectId) {
      throw new Error("Sui BTC light client object ID is required to build completion PTBs");
    }
    if (!input.blockHash || input.txIndex === undefined || !input.rawTx) {
      throw new Error("Sui redemption completion requires blockHash, txIndex, rawTx, and BTC SPV proof fields");
    }

    const tx = new Transaction();
    const redemptionCap = this.redemptionCapRef();
    const inclusion = tx.moveCall({
      target: `${this.config.packageId}::btc_light_client::verify_tx_inclusion`,
      arguments: [
        this.sharedObject(tx, this.config.lightClientObjectId, this.config.lightClientInitialSharedVersion, false),
        tx.pure.vector("u8", input.blockHash),
        tx.pure.vector("u8", input.btcTxid),
        tx.pure.u32(input.txIndex),
        tx.pure("vector<vector<u8>>", (input.merkleSiblings ?? []).map((bytes) => Array.from(bytes))),
        tx.pure.u64((input.pathBits ?? 0).toString()),
      ],
    });

    tx.moveCall({
      target: `${this.config.packageId}::redemption::complete_redemption`,
      arguments: [
        tx.objectRef(redemptionCap),
        this.sharedObject(tx, this.config.poolObjectId, this.config.poolInitialSharedVersion, false),
        this.sharedObject(tx, this.config.utxoSetObjectId, this.config.utxoSetInitialSharedVersion, true),
        this.sharedObject(
          tx,
          this.config.redemptionQueueObjectId,
          this.config.redemptionQueueInitialSharedVersion,
          true,
        ),
        tx.pure.u64(input.redemptionId.toString()),
        inclusion,
        tx.pure.vector("u8", input.rawTx),
      ],
    });

    return this.buildPtb(tx, "Sui BTC redemption completion PTB", [
      redemptionCap.objectId,
      this.config.lightClientObjectId,
      this.config.poolObjectId,
      this.config.utxoSetObjectId,
      this.config.redemptionQueueObjectId,
    ]);
  }

  async buildRegisterVerifyingKeyTransaction(
    input: RegisterVerifyingKeyInput,
  ): Promise<SuiUnsignedTransaction> {
    if (!this.config.adminCapObjectId || !this.config.adminCapVersion || !this.config.adminCapDigest) {
      throw new Error("Sui admin cap object ref is required to register verifying keys");
    }
    if (!this.config.verifyingKeyRegistryObjectId) {
      throw new Error("Sui verifying-key registry object ID is required to register verifying keys");
    }
    const shape = joinSplitShape(input.nInputs, input.nOutputs);
    if (input.nPublic !== shape.nPublic) {
      throw new Error(`${shape.name} expects ${shape.nPublic} public inputs, got ${input.nPublic}`);
    }
    assertSuiGroth16Compatible(shape);

    const tx = new Transaction();
    const adminCap = tx.objectRef({
      objectId: this.config.adminCapObjectId,
      version: this.config.adminCapVersion,
      digest: this.config.adminCapDigest,
    });
    const pool = this.sharedObject(
      tx,
      this.config.poolObjectId,
      this.config.poolInitialSharedVersion,
      false,
    );
    const registry = this.sharedObject(
      tx,
      this.config.verifyingKeyRegistryObjectId,
      this.config.verifyingKeyRegistryInitialSharedVersion,
      true,
    );

    if (input.rawVerifyingKey) {
      tx.moveCall({
        target: `${this.config.packageId}::verifier::register_raw_key`,
        arguments: [
          adminCap,
          pool,
          registry,
          tx.pure.u8(input.nInputs),
          tx.pure.u8(input.nOutputs),
          tx.pure.u8(input.nPublic),
          tx.pure.vector("u8", input.vkHash),
          tx.pure.vector("u8", input.rawVerifyingKey),
        ],
      });
    } else {
      tx.moveCall({
        target: `${this.config.packageId}::verifier::register_prepared_key`,
        arguments: [
          adminCap,
          pool,
          registry,
          tx.pure.u8(input.nInputs),
          tx.pure.u8(input.nOutputs),
          tx.pure.u8(input.nPublic),
          tx.pure.vector("u8", input.vkHash),
          tx.pure.vector("u8", input.vkGammaAbcG1Bytes),
          tx.pure.vector("u8", input.alphaG1BetaG2Bytes),
          tx.pure.vector("u8", input.gammaG2NegPcBytes),
          tx.pure.vector("u8", input.deltaG2NegPcBytes),
        ],
      });
    }

    return this.buildPtb(tx, "Sui register prepared verifying key PTB", [
      this.config.adminCapObjectId,
      this.config.poolObjectId,
      this.config.verifyingKeyRegistryObjectId,
    ]);
  }

  async submitTransaction(_: SignedTransaction): Promise<TransactionResult> {
    throw new Error("Sui transaction submission is not implemented yet");
  }

  private async buildPtb(
    tx: Transaction,
    description: string,
    objectIds: string[],
  ): Promise<SuiUnsignedTransaction> {
    return {
      chain: this.chain,
      kind: "sui-programmable-transaction-block",
      bytes: await tx.build({ onlyTransactionKind: true }),
      description,
      packageId: this.config.packageId,
      objectIds,
    };
  }

  private redemptionCapRef() {
    if (!this.config.redemptionCapObjectId || !this.config.redemptionCapVersion || !this.config.redemptionCapDigest) {
      throw new Error("Sui redemption cap object ref is required for policy-gated PTBs");
    }
    return {
      objectId: this.config.redemptionCapObjectId,
      version: this.config.redemptionCapVersion,
      digest: this.config.redemptionCapDigest,
    };
  }

  private sharedObject(
    tx: Transaction,
    objectId: string,
    initialSharedVersion: number | string | undefined,
    mutable: boolean,
  ) {
    if (initialSharedVersion === undefined) {
      throw new Error(`Initial shared version is required for Sui object ${objectId}`);
    }

    return tx.sharedObjectRef({
      objectId,
      initialSharedVersion,
      mutable,
    });
  }
}

function bytesFromHexOrUtf8(value: string): Uint8Array {
  const normalized = value.startsWith("0x") ? value.slice(2) : value;
  if (/^[0-9a-fA-F]+$/.test(normalized) && normalized.length % 2 === 0) {
    const bytes = new Uint8Array(normalized.length / 2);
    for (let i = 0; i < bytes.length; i += 1) {
      bytes[i] = Number.parseInt(normalized.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
  }

  return new TextEncoder().encode(value);
}
