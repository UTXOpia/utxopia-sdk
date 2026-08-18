/**
 * UTXOpia SDK v3.0 (JoinSplit Architecture)
 *
 * Complete client library for interacting with the UTXOpia protocol.
 * Private Bitcoin using ZK proofs.
 *
 * Networks: Solana deployments + Bitcoin testnet4/regtest/mainnet
 *
 * ## Quick Start
 * ```typescript
 * import { createNonInteractiveDeposit, generateJoinSplitProof, buildTransactInstruction } from '@utxopia/sdk';
 *
 * // 1. DEPOSIT: Generate BTC address + compact OP_RETURN payload.
 * const deposit = await createNonInteractiveDeposit(meta, custodyInternalKey, 'testnet', undefined, opReturnContext);
 * console.log('Send BTC to:', deposit.btcAddress);
 *
 * // 2. TRANSACT: JoinSplit proof for private transfer
 * const proof = await generateJoinSplitProof(inputs);
 *
 * // 3. BUILD: Create Solana instruction
 * const ix = buildTransactInstruction(options);
 * ```
 */

// ==========================================================================
// Cryptographic utilities
// ==========================================================================

export {
  // Byte conversion (encoding utilities)
  bigintToBytes,
  bytesToBigint,
  hexToBytes,
  bytesToHex,
  // Hashing
  sha256Hash,
  x25519Ecdh,
  ed25519GenerateKeyPair,
  ed25519PubToX25519,
  ed25519PrivToX25519,
  x25519PubFromPriv,
  x25519EcdhRaw,
  encryptAmountEd25519,
  decryptAmountEd25519,
  // Low-level crypto (needed by E2E test scripts + contract deploy scripts)
  randomFieldElement,
  BN254_FIELD_PRIME,
  babyJubMul,
  BABYJUB_BASE8,
} from "./crypto";

// ==========================================================================
// Key derivation (Solana wallet -> spending/viewing keys)
// ==========================================================================

export {
  // Key derivation (high-level)
  deriveKeysFromWallet,
  deriveKeysFromSeed,
  deriveKeysFromSeedCircuit,
  deriveKeysFromAuthSignature,
  setupKeysFromAuthSignature,
  generateRandomAuthSignature,
  // Key setup (combined derivation + stealth address)
  setupKeysFromWallet,
  setupKeysFromSeed,
  recreateStealthAddress,
  // EdDSA signing
  eddsaPoseidonSign,
  eddsaPoseidonSignWithScalar,
  eddsaGetPrivScalar,
  eddsaGetPubKey,
  // Stealth meta address
  createStealthMetaAddress,
  serializeStealthMetaAddress,
  deserializeStealthMetaAddress,
  encodeStealthMetaAddress,
  decodeStealthMetaAddress,
  // Key lifecycle
  clearUTXOpiaKeys,
  // Key serialization
  serializeKeysForStorage,
  deserializeKeysFromStorage,
  PASSKEY_CHAIN_SCOPE_DOMAIN,
  deriveChainScopedPasskeySeed,
  passkeyStorageOwner,
  // Types
  type UTXOpiaKeys,
  type KeySetupResult,
  type AuthSignatureKeyDerivationOptions,
  type AuthSignatureKeySetupResult,
  type ChainScopedPasskeyOptions,
  type PasskeyChainScope,
  type SerializedKeysForStorage,
  type StealthMetaAddress,
  type WalletSignerAdapter,
} from "./keys";

// Delegated viewing keys + auditor toolkit (Phase 1)
export {
  ViewPermissions,
  hasPermission,
  isDelegatedKeyValid,
  isSlotInDelegatedRange,
  createDelegatedViewKey,
  serializeDelegatedViewKey,
  deserializeDelegatedViewKey,
  makeDelegationRecord,
  fingerprintDelegatedKey,
  clearDelegatedViewKey,
  // The delegation-safe alternative: unlike createDelegatedViewKey this omits nullifyingKey,
  // which is what stops the holder from deriving every nullifier the account will ever publish.
  // It was reachable only by deep import while the footgun sat in the barrel.
  extractViewOnlyBundle,
  type DelegatedViewKey,
  type DelegationRecord,
} from "./keys";
export {
  auditScan,
  auditScanCiphertexts,
  auditRecordsToCsv,
  type AuditDirection,
  type AuditRecord,
  type AuditScanAnnouncement,
  type AuditScanOptions,
  type AuditScanSummary,
  type OnChainSenderMemo,
} from "./auditor";

// Auditor ciphertext (Method-Y permissioned pool)
export {
  encryptAuditorCiphertext,
  decryptAuditorCiphertext,
  buildAuditorCiphertextForNote,
  resolveAuditorCiphertext,
  AUDITOR_CIPHERTEXT_BYTES,
  type AuditorNotePlain,
  type AuditorCiphertextInput,
} from "./auditor-ciphertext";
export {
  generateAuditorViewingKeypair,
  deriveAuditorViewingKeypair,
} from "./keys";

// Sender memo channel (Phase 2)
export {
  encryptSenderMemo,
  decryptSenderMemo,
  deriveOutgoingViewingKey,
  packSenderMemo,
  unpackSenderMemo,
  packSenderMemoForInstruction,
  buildSenderMemosForTransact,
  generateSenderMemoNonce,
  SENDER_MEMO_AMOUNT_BYTES,
  SENDER_MEMO_CIPHERTEXT_BYTES,
  SENDER_MEMO_COMMITMENT_BYTES,
  SENDER_MEMO_NONCE_BYTES,
  SENDER_MEMO_PACKED_BYTES,
  SENDER_MEMO_TAG_BYTES,
  SENDER_MEMO_TOKEN_BYTES,
  type SenderMemoPlain,
  type SenderMemoCiphertext,
  type SenderMemoOutput,
} from "./sender-memo";

// Selective ZK disclosure proofs (Phase 4)
export {
  generateOwnershipProof,
  generateRangeSumProof,
  computeRangeSumAttestation,
  pickRangeSumVariant,
  RANGE_SUM_N,
  RANGE_SUM_VARIANTS,
  RANGE_SUM_SIZES,
  type OwnershipProofInputs,
  type OwnershipPublicInputs,
  type RangeSumAttestationStyle,
  type RangeSumProofInputs,
  type RangeSumPublicInputs,
} from "./selective-disclosure";

// ==========================================================================
// Deliberately not re-exported: isWalletAdapter, isDirectVaultDepositMode (guards the SDK
// branches on), updateNoteWithHashes, updateStealthNoteWithHashes (mutators for fields the
// SDK computes) and stealthNoteHasComputedHashes (a predicate over state no caller builds).
// Still exported from their own modules for internal use — they are just not public API.

// Poseidon hash utilities
// ==========================================================================

export {
  initPoseidon,
  isPoseidonReady,
  poseidonHashSync,
  computeUnifiedCommitmentSync,
  computeNullifierSync,
  hashNullifierSync,
  // JoinSplit primitives (used by E2E scripts + pay-flow)
  computeMPKSync,
  computeNPKSync,
  computeJoinSplitCommitmentSync,
  computeJoinSplitNullifierSync,
  // Multi-token
  computeTokenId,
  reduceToField,
} from "./poseidon";

// ==========================================================================
// Token Registry (multi-token support)
// ==========================================================================

export {
  fetchTokenConfig,
  getTokenId,
  fetchSupportedTokens,
  fetchEnabledTokens,
  parseTokenConfig,
  type TokenConfigData,
  type SupportedToken,
} from "./token-registry";

// ==========================================================================
// MagicBlock ER / PER execution domains
// ==========================================================================

export {
  MAGICBLOCK_DELEGATION_PROGRAM_ID,
  MAGICBLOCK_DEVNET_ROUTER_URL,
  MAGICBLOCK_DEVNET_ROUTER_WS_URL,
  MAGICBLOCK_EPHEMERAL_VAULT_ID,
  MAGICBLOCK_MAGIC_CONTEXT_ID,
  MAGICBLOCK_MAGIC_PROGRAM_ID,
  MAGICBLOCK_MAX_PER_MEMBERS,
  MAGICBLOCK_PERMISSION_PROGRAM_ID,
  MAGICBLOCK_PER_MEMBER_FLAGS,
  MAGICBLOCK_VALIDATOR_IDENTITIES,
  buildDefaultPrivacyDomain,
  buildMagicBlockPerMemberFlags,
  deriveMagicBlockCommitRecordPDA,
  deriveMagicBlockCommitStatePDA,
  deriveMagicBlockDelegateBufferPDA,
  deriveMagicBlockDelegationMetadataPDA,
  deriveMagicBlockDelegationRecordPDA,
  deriveMagicBlockPermissionPDA,
  deriveMagicBlockUndelegateBufferPDA,
  requiresMagicBlockEndpoint,
  getMagicBlockEndpoint,
  getMagicBlockValidatorIdentity,
  createMagicBlockRouterConnection,
  type BuildPrivacyDomainOptions,
  type MagicBlockEndpointConfig,
  type MagicBlockExecutionMode,
  type MagicBlockPolicyMode,
  type MagicBlockPerMemberFlagName,
  type MagicBlockValidatorRegion,
  type PrivacyDomainConfig,
  type PrivacyDomainKind,
} from "./magicblock";

// ==========================================================================
// Note (shielded commitment) utilities
// ==========================================================================

export {
  generateNote,
  createNoteFromSecrets,
  serializeNote,
  deserializeNote,
  noteHasComputedHashes,
  getNotePublicKeyX,
  computeNoteCommitment,
  computeNoteNullifier,
  formatBtc,
  parseBtc,
  deriveNote,
  deriveNotes,
  deriveMasterKey,
  deriveNoteFromMaster,
  estimateSeedStrength,
  createNote,
  prepareWithdrawal,
  createStealthNote,
  serializeStealthNote,
  deserializeStealthNote,
  type Note,
  type SerializedNote,
  type NoteData,
  type StealthNote,
  type SerializedStealthNote,
  // JoinSplit note types
  createJoinSplitNote,
  computeJoinSplitNoteNullifier,
  serializeJoinSplitNote,
  deserializeJoinSplitNote,
  type JoinSplitNote,
  type SerializedJoinSplitNote,
} from "./note";

// ==========================================================================
// Merkle tree utilities
// ==========================================================================

export {
  createMerkleProof,
  createMerkleProofFromBigints,
  proofToCircomFormat,
  proofToOnChainFormat,
  createEmptyMerkleProof,
  leafIndexToPathIndices,
  pathIndicesToLeafIndex,
  validateMerkleProofStructure,
  parseMerkleProofResponse,
  TREE_DEPTH,
  ROOT_HISTORY_SIZE,
  MAX_LEAVES,
  ZERO_VALUE,
  type MerkleProof,
} from "./merkle";

// ==========================================================================
// Taproot address utilities
// ==========================================================================

export {
  deriveTaprootAddress,
  deriveTaprootAddressWithRefund,
  buildRefundScript,
  computeTapLeafHash,
  verifyTaprootAddress,
  createP2TRScriptPubkey,
  parseP2TRScriptPubkey,
  isValidBitcoinAddress,
  getInternalKey,
  createCustomInternalKey,
  createOpReturnScriptFromPayload,
  buildDepositOpReturn,
  parseDepositOpReturn,
  encodeDepositOpReturnHeader,
  decodeDepositOpReturnHeader,
  validateDepositOpReturnContext,
  computeDepositPoolTag,
  DEPOSIT_DESTINATION_CHAIN,
  DEPOSIT_BITCOIN_NETWORK,
  DEPOSIT_OP_RETURN_VERSION,
  DEPOSIT_POOL_TAG_SIZE,
  DEPOSIT_OP_RETURN_SIZE,
  type DepositDestinationChain,
  type DepositBitcoinNetwork,
  type DepositOpReturnContext,
  type ParsedDepositOpReturn,
} from "./taproot";

// ==========================================================================
// Claim link utilities
// ==========================================================================

export {
  encodeClaimLink,
  decodeClaimLink,
  parseClaimUrl,
} from "./claim-link";

// ==========================================================================
// WASM Prover (Browser + Node.js) — JoinSplit only
// ==========================================================================

// Prover types only (no runtime dependency on snarkjs)
// For prover runtime functions (initProver, generateJoinSplitProof, etc.), import from:
// - @utxopia/sdk/prover/web    (browser/Node.js — uses snarkjs)
// - @utxopia/sdk/prover/mobile (React Native — uses mopro-ffi)
export type {
  ProofData,
  MerkleProofInput,
  CircuitType,
  JoinSplitProofInputs,
} from "./prover/web";

// ==========================================================================
// ChadBuffer utilities (for large proof uploads)
// ==========================================================================

export {
  uploadTransactionToBuffer,
  uploadProofToBuffer,
  closeBuffer,
  readBufferData,
  fetchRawTransaction,
  fetchMerkleProof,
  prepareVerifyDeposit,
  buildMerkleProof,
  needsBuffer as bufferNeedsBuffer,
  getProofSource,
  calculateUploadTransactions,
  CHADBUFFER_PROGRAM_ID,
  AUTHORITY_SIZE,
  MAX_DATA_PER_WRITE,
  SOLANA_TX_SIZE_LIMIT,
  type ProofUploadResult,
} from "./chadbuffer";

// ==========================================================================
// Bound Parameters (JoinSplit transaction binding)
// ==========================================================================

export {
  computeBoundParamsHash,
  computeSolanaDomainBoundParamsHash,
  computeSolanaDomainSeparator,
  computeStealthDataHash,
  createTransferBoundParams,
  createUnshieldBoundParams,
  createRedeemBoundParams,
  SOLANA_BOUND_CHAIN_ID,
  SOLANA_DEVNET_BOUND_CHAIN_ID,
  SOLANA_MAINNET_BOUND_CHAIN_ID,
  DEFAULT_BOUND_PARAMS,
  type BoundParams,
  type BoundParamsMode,
  type SolanaPrivacyDomainContext,
  type SolanaPrivacyDomainKind,
} from "./bound-params";

// ==========================================================================
// Configuration
// ==========================================================================

export {
  getConfig,
  setConfig,
  createConfig,
  initConfig,
  DEVNET_CONFIG,
  MAINNET_CONFIG,
  LOCALNET_CONFIG,
  TOKEN_PROGRAM_ID,
  TOKEN_2022_PROGRAM_ID,
  ATA_PROGRAM_ID,
  UTXOPIA_POLICY_PROGRAM_ID,
  SDK_VERSION,
  DEPLOYMENT_INFO,
  JOINSPLIT_TREE_DEPTH,
  type NetworkConfig,
  type NetworkType,
} from "./config";

// ==========================================================================
// PoolState account layout + fee arithmetic
// ==========================================================================

export {
  POOL_STATE_DISCRIMINATOR,
  POOL_STATE_LEN,
  POOL_STATE_OFFSETS,
  POOL_FLAG,
  parsePoolState,
  parsePoolFees,
  BPS_DENOMINATOR,
  computeBpsFee,
  feeShareBps,
} from "./pool-state";
export type { PoolState, PoolFees } from "./pool-state";

// ==========================================================================
// PDA Derivation
// ==========================================================================

export {
  PDA_SEEDS,
  // Seed builders — the single definition of every PDA. Consumers on
  // @solana/web3.js should derive from these with findProgramAddressSync rather
  // than restating the seeds, which is how copies drift from the program.
  poolStateSeeds,
  commitmentTreeSeeds,
  tokenConfigSeeds,
  poolConfigSeeds,
  nullifierRecordSeeds,
  redemptionRequestSeeds,
  vkRegistrySeeds,
  depositReceiptSeeds,
  policyApprovalSeeds,
  exitDestinationSeeds,
  lightClientSeeds,
  blockHeaderSeeds,
  heightIndexSeeds,
  verifiedTransactionSeeds,
  derivePoolStatePDA,
  deriveCommitmentTreePDA,
  deriveNullifierRecordPDA,
  derivePolicyApprovalPDA,
  deriveExitDestinationPDA,
  EXIT_KIND_SOLANA_OWNER,
  EXIT_KIND_BTC_SCRIPT,
  deriveLightClientPDA,
  deriveBlockHeaderPDA,
  deriveHeightIndexPDA,
  deriveVkRegistryPDA,
  deriveRedemptionRequestPDA,
  deriveTokenConfigPDA,
  derivePoolConfigPDA,
  deriveDepositReceiptPDA,
  commitmentToBytes,
} from "./pda";

// ==========================================================================
// Stealth address utilities
// ==========================================================================

export {
  createStealthDeposit,
  createStealthDepositWithKeys,
  createStealthOutput,
  createStealthOutputWithKeys,
  createStealthOutputForCommitment,
  packStealthOutputForCircuit,
  scanAnnouncements,
  scanAnnouncementsViewOnly,
  scanAnnouncementsViewOnlyMulti,
  exportViewOnlyKeys,
  encodeViewOnlyKeys,
  decodeViewOnlyKeys,
  prepareClaimInputs,
  scanUnifiedNotes,
  scanUnifiedNotesMulti,
  encryptAmount,
  decryptAmount,
  computeNullifierHashForNote,
  computeNullifierBytes,
  parseAnnouncementsFromHex,
  createDepositFromConfig,
  createDirectVaultDeposit,
  isDepositForViewer,
  isDepositForViewerHex,
  ANNOUNCEMENT_TYPE_DEPOSIT,
  ANNOUNCEMENT_TYPE_TRANSFER,
  type StealthDeposit,
  type StealthOutputData,
  type StealthOutputWithKeys,
  type CircuitStealthOutput,
  type ScannedNote,
  type ClaimInputs as StealthClaimInputs,
  type OnChainStealthAnnouncement,
  type ConnectionAdapter,
  type ViewOnlyKeys,
  type ViewOnlyScannedNote,
  createNonInteractiveDeposit,
  pickIkaCustodyKey,
  type NonInteractiveDepositResult,
  type NonInteractiveDepositWithRefundResult,
} from "./stealth";

// ==========================================================================
// PSBT builder for wallet-integrated deposits
// ==========================================================================

export {
  buildDepositPsbt,
  estimateDepositFee,
  fetchUtxos,
  selectUtxos,
  type BuildDepositPsbtParams,
  type BuildDepositPsbtResult,
  type UtxoDescriptor,
} from "./psbt";

// ==========================================================================
// Core utilities
// ==========================================================================

export {
  EsploraClient,
  esploraTestnet,
  esploraMainnet,
  type EsploraTransaction,
  type EsploraVin,
  type EsploraVout,
  type EsploraStatus,
  type EsploraAddressInfo,
  type EsploraUtxo,
  type EsploraMerkleProof,
  type EsploraNetwork,
} from "./core/esplora";

// Mempool.space client with SPV support
export {
  MempoolClient,
  mempoolTestnet,
  mempoolMainnet,
  reverseBytes,
  type BlockHeader,
  type TransactionInfo,
  type SPVProofData,
} from "./core/mempool";

// ==========================================================================
// Priority Fee Estimation
// ==========================================================================

export {
  estimatePriorityFee,
  buildPriorityFeeInstructionData,
  encodeSetComputeUnitLimit,
  encodeSetComputeUnitPrice,
  getHeliusRpcUrl,
  DEFAULT_COMPUTE_UNITS,
  DEFAULT_PRIORITY_FEE,
  COMPUTE_BUDGET_DISCRIMINATORS,
  type PriorityFeeConfig,
  type PriorityFeeEstimate,
  type PriorityFeeInstructions,
} from "./solana/priority-fee";

// ==========================================================================
// Debug Logging
// ==========================================================================

export { setDebug } from "./logger";

// ==========================================================================
// Connection Adapter Factory
// ==========================================================================

export {
  createFetchConnectionAdapter,
  createConnectionAdapterFromWeb3,
  createConnectionAdapterFromKit,
  getConnectionAdapter,
  clearConnectionAdapterCache,
  type RpcConfig,
  type Web3Connection,
  type KitRpc,
} from "./solana/connection";


// ==========================================================================
// SNS Subdomain Resolver (*.utxopia.sol stealth addresses)
// ==========================================================================

export {
  resolveSnsName,
  resolveStealthName,
  parseSnsStealthData,
  isSnsStealthAddress,
  isAuditorDisclosable,
  SnsComplianceFlags,
  SNS_COMPLIANCE_AUDITOR_OFFSET,
  SNS_COMPLIANCE_AUDITOR_BYTES,
  deriveParentDomainKey,
  SNS_STEALTH_DATA_SIZE,
  type SnsStealthAddress,
} from "./sns-resolver";

// ==========================================================================
// Commitment Tree
// ==========================================================================

export {
  COMMITMENT_TREE_DISCRIMINATOR,
  parseCommitmentTreeData,
  isValidRoot,
  fetchCommitmentTree,
  getCommitmentIndex,
  saveCommitmentIndex,
  CommitmentTreeIndex,
  // On-chain fetch functions (Helius-compatible)
  buildCommitmentTreeFromChain,
  fetchLeafIndexForCommitment,
  fetchMerkleProofForCommitment,
  getMerkleProofFromTree,
  type CommitmentTreeState,
  type RpcClient,
  type OnChainMerkleProof,
} from "./commitment-tree";

// ==========================================================================
// Low-level Instruction Builders (JoinSplit only)
// ==========================================================================

export {
  INSTRUCTION_DISCRIMINATORS,
  // Shield instruction
  buildShieldInstructionData,
  buildShieldInstruction,
  type ShieldInstructionOptions,
  buildApproveRedemptionSigningInstructionData,
  buildApproveRedemptionSigningInstruction,
  // Cancel redemption instruction
  buildCancelRedemptionInstructionData,
  buildCancelRedemptionInstruction,
  type CancelRedemptionInstructionOptions,
  bigintTo32Bytes,
  bytes32ToBigint,
  // JoinSplit transact instruction
  buildTransactInstructionData,
  buildTransactInstruction,
  // JoinSplit + BTC redeem instruction
  buildRedeemInstructionData,
  // Public unshield instruction
  buildUnshieldInstructionData,
  buildUnshieldInstruction,
  // Timelocked pool update instructions
  buildProposePoolUpdateInstructionData,
  buildProposePoolUpdateInstruction,
  buildExecutePoolUpdateInstructionData,
  buildExecutePoolUpdateInstruction,
  buildCancelPoolUpdateInstructionData,
  buildCancelPoolUpdateInstruction,
  // Rotate tree
  buildRotateTreeInstructionData,
  buildRotateTreeInstruction,
  type RotateTreeOptions,
  // MagicBlock lifecycle
  buildMagicBlockDelegateInstructionData,
  buildMagicBlockDelegateInstruction,
  buildMagicBlockCommitInstructionData,
  buildMagicBlockCommitInstruction,
  buildMagicBlockPerPermissionInstructionData,
  buildMagicBlockPerPermissionInstruction,
  buildPolicyRequestHash,
  buildPolicyIntentParts,
  buildRegisterExitDestinationInstruction,
  buildRegisterExitDestinationInstructionData,
  MAX_POLICY_INTENT_PARTS,
  buildInitializePolicyApprovalInstructionData,
  buildInitializePolicyApprovalInstruction,
  buildPolicyApprovalDecisionInstruction,
  buildPolicyApprovalCommitInstruction,
  buildCompleteDepositPermissionedInstructionData,
  buildCompleteDepositPermissionedInstruction,
  buildShieldPermissionedInstructionData,
  buildShieldPermissionedInstruction,
  buildRotateAuditorInstructionData,
  buildRotateAuditorInstruction,
  type MagicBlockDelegateTarget,
  type MagicBlockDelegateInstructionOptions,
  type MagicBlockCommitInstructionOptions,
  type MagicBlockPerPermissionOperation,
  type MagicBlockPerPermissionMember,
  type MagicBlockPerPermissionInstructionOptions,
  type PolicyApprovalDecision,
  type InitializePolicyApprovalOptions,
  type CompleteDepositPermissionedOptions,
  type ShieldPermissionedInstructionOptions,
  type RotateAuditorOptions,
  // Verify instruction data builders
  buildVerifyTransactionInstructionData,
  buildCompleteDepositInstructionData,
  // Pool config (disc 2) builder + parser
  buildSetPoolConfigInstructionData,
  parsePoolConfig,
  type ParsedPoolConfig,
  POOL_CONFIG_DISCRIMINATOR,
  POOL_CONFIG_LEN,
  POOL_SCRIPT_MAX_LEN,
  // Redemption PDA helper
  type Instruction,
  type ApproveRedemptionSigningInstructionOptions,
  type TransactInstructionOptions,
  type UnshieldInstructionOptions,
  type ProposePoolUpdateOptions,
  type ExecutePoolUpdateOptions,
  type CancelPoolUpdateOptions,
} from "./instructions";

// ==========================================================================
// VK Registry (JoinSplit Groth16 on-chain verification keys)
// ==========================================================================

export {
  VK_REGISTRY_DISCRIMINATOR,
  VK_REGISTRY_LEN,
  MAX_IC_POINTS,
  MAX_SAFE_JOINSPLIT_SIZE,
  INIT_VK_REGISTRY_DISCRIMINATOR,
  UPDATE_VK_REGISTRY_DISCRIMINATOR,
  joinSplitNumPublicInputs,
  computeVkHash,
  vkeyJsonToVkMaterial,
  buildVkRegistryData,
  parseVkRegistry,
  assertVkRegistryForShape,
  isVkRegistryReady,
  type JoinSplitVkMaterial,
  type SnarkjsVkeyJson,
  type ParsedVkRegistry,
} from "./vk-registry";

// ==========================================================================
// ChadBuffer Relay
// ==========================================================================

// relay.ts held a second implementation of the ChadBuffer lifecycle — create / upload / close —
// alongside chadbuffer.ts, which already does all three. Nothing imported it but this barrel, and
// the two disagreed on chunk size (1020 vs 1056 bytes for the same write instruction), so one of
// them was wrong. Removed; chadbuffer.ts is the single implementation.

// ==========================================================================
// Explorer (on-chain account fetchers & parsers)
// ==========================================================================

export {
  fetchExplorerDeposits,
  fetchExplorerTransfers,
  fetchExplorerRedemptions,
  parseNullifierRecord,
  parseRedemptionRequest,
  NULLIFIER_RECORD_SIZE,
  REDEMPTION_REQUEST_SIZE,
  NULLIFIER_RECORD_DISCRIMINATOR,
  REDEMPTION_REQUEST_DISCRIMINATOR,
  OPERATION_TYPE_LABELS,
  type ExplorerDeposit,
  type ExplorerTransferEvent,
  type ExplorerRedemption,
  type IndexerLeaf,
} from "./explorer";

// ==========================================================================
// Event Parsing (sol_log_data events from on-chain program)
// ==========================================================================

export {
  parseProgramEvents,
  parseNullifierSpentEvent,
  parseStealthAnnouncementEvent,
  parseSenderMemoEvent,
  parseBtcOriginAttestationEvent,
  parseAuditorCiphertextEvent,
  EVENT_NULLIFIER_SPENT,
  EVENT_STEALTH_ANNOUNCEMENT,
  EVENT_NULLIFIERS_BATCH,
  EVENT_ANNOUNCEMENTS_BATCH,
  EVENT_SENDER_MEMO,
  EVENT_BTC_ORIGIN_ATTESTATION,
  EVENT_AUDITOR_CIPHERTEXT,
  type NullifierSpentEvent,
  type StealthAnnouncementEvent,
  type SenderMemoEvent,
  type BtcOriginAttestationEvent,
  type AuditorCiphertextEvent,
  type ProgramEvent,
} from "./events";

// ==========================================================================
// Announcement Client (WS + REST + RPC fallback)
// ==========================================================================

export {
  AnnouncementClient,
  type AnnouncementClientConfig,
  type AnnouncementListener,
} from "./announcement-client";

// ==========================================================================
// Event Client (unified WS + REST for all event types)
// ==========================================================================

export {
  EventClient,
  type LeafInsertedEvent as EventLeafInserted,
  type NullifierSpentEvent as EventNullifierSpent,
  type AnnouncementEvent as EventAnnouncement,
  type ServerEvent as EventServerEvent,
  type EventListener,
  type TreeStatusResponse,
  type NullifierPdasResponse,
} from "./event-client";

// ==========================================================================
// High-Level Client (Phase 1: init + auth + balance)
// ==========================================================================

export {
  UTXOpiaClient,
  type UTXOpiaClientConfig,
  type TokenDefinition,
  type InboxNote as ClientInboxNote,
} from "./client";
