# API map

Every value the SDK exports, grouped in the order you meet them when building on the protocol.
Generated from source — regenerate rather than hand-edit.

| mark | meaning | safe to remove? |
|---|---|---|
| `•` | imported by `utxopia-web` or `ops` | no — a consumer breaks |
| `+` | used inside the SDK by another module | no — load-bearing, just not an entry point |
| `~` | only exercised by tests | probably keep; it is protocol surface nobody has needed yet |
| ` ` | no reference anywhere | candidate — judge whether the protocol needs it |

A blank mark is not automatically dead code: instruction builders for real on-chain operations
(`buildShieldInstruction`, `buildRotateTreeInstruction`) belong in a bridge SDK whether or not
the two reference apps happen to call them. It does mean nothing has ever exercised it, so
treat it as unverified.

```typescript
import { derivePoolStatePDA, buildUnshieldInstructionData } from "@utxopia/sdk";
```

## 1. Configuration & addresses

Point the SDK at a deployment before anything else.

**`config`** · 19 exports · 3 consumer, 7 internal, 6 unreferenced

```
  ATA_PROGRAM_ID                  + BTC_LIGHT_CLIENT_PROGRAM_ID     + CHADBUFFER_PROGRAM_ID
  DEPLOYMENT_INFO                 ~ DEVNET_CONFIG                     JOINSPLIT_TREE_DEPTH
  LOCALNET_CHADBUFFER_PROGRAM_ID  ~ LOCALNET_CONFIG                   MAINNET_CONFIG
  SDK_VERSION                     + TOKEN_2022_PROGRAM_ID           + TOKEN_PROGRAM_ID
+ UTXOPIA_POLICY_PROGRAM_ID       + UTXOPIA_PROGRAM_ID              + address
~ createConfig                    • getConfig                       • initConfig
• setConfig
```

**`token-registry`** · 5 exports · 0 consumer, 1 internal, 3 unreferenced

```
  fetchEnabledTokens      fetchSupportedTokens    getTokenConfig
+ getTokenId            ~ parseTokenConfig
```

**`pool-state`** · 9 exports · 0 consumer, 0 internal, 2 unreferenced

```
  BPS_DENOMINATOR             POOL_FLAG                 ~ POOL_STATE_DISCRIMINATOR
~ POOL_STATE_LEN            ~ POOL_STATE_OFFSETS        ~ computeBpsFee
~ feeShareBps               ~ parsePoolFees             ~ parsePoolState
```

## 2. Keys & identity

Derive the shielded identity; everything downstream is keyed off it.

**`keys`** · 41 exports · 17 consumer, 12 internal, 5 unreferenced

```
  PASSKEY_CHAIN_SCOPE_DOMAIN         SPENDING_KEY_DERIVATION_MESSAGE    clearDelegatedViewKey
~ clearKey                         + clearUTXOpiaKeys                 + constantTimeCompare
• createDelegatedViewKey           • createStealthMetaAddress         • decodeStealthMetaAddress
~ deriveAuditorViewingKeypair      • deriveChainScopedPasskeySeed     ~ deriveKeysFromAuthSignature
• deriveKeysFromSeed               • deriveKeysFromSeedCircuit          deriveKeysFromSignature
+ deriveKeysFromWallet             • deserializeDelegatedViewKey      • deserializeKeysFromStorage
~ deserializeStealthMetaAddress    • eddsaGetPrivScalar               • eddsaGetPubKey
• eddsaPoseidonSign                • eddsaPoseidonSignWithScalar      • encodeStealthMetaAddress
  extractViewOnlyBundle            • fingerprintDelegatedKey          ~ generateAuditorViewingKeypair
~ generateRandomAuthSignature      + hasPermission                    + isDelegatedKeyValid
+ isSlotInDelegatedRange           • makeDelegationRecord             + parseStealthMetaAddress
• passkeyStorageOwner              + recreateStealthAddress           • serializeDelegatedViewKey
+ serializeKeysForStorage          ~ serializeStealthMetaAddress      + setupKeysFromAuthSignature
+ setupKeysFromSeed                + setupKeysFromWallet
```

**`crypto-babyjub`** · 19 exports · 0 consumer, 18 internal, 1 unreferenced

```
+ BABYJUB_A                 + BABYJUB_BASE8               BABYJUB_COFACTOR
+ BABYJUB_D                 + BABYJUB_FIELD_PRIME       + BABYJUB_IDENTITY
+ BABYJUB_ORDER             + babyJubAdd                + babyJubCompress
+ babyJubDecompress         + babyJubDouble             + babyJubMul
+ babyJubNegate             + babyJubScalarFromBytes    + babyJubScalarToBytes
+ deriveBabyJubKeyFromSeed  + generateBabyJubKeyPair    + isIdentity
+ isOnBabyJubCurve
```

**`crypto-ed25519`** · 13 exports · 1 consumer, 12 internal, 0 unreferenced

```
+ decryptAmountEd25519      + decryptNoteData           + deriveAmountKey
+ ed25519DeriveKeyFromSeed  + ed25519GenerateKeyPair    + ed25519GetPublicKey
+ ed25519PrivToX25519       + ed25519PubToX25519        + encryptAmountEd25519
+ encryptNoteData           • x25519Ecdh                + x25519EcdhRaw
+ x25519PubFromPriv
```

**`crypto`** · 11 exports · 7 consumer, 2 internal, 2 unreferenced

```
• BN254_FIELD_PRIME   • bigintToBytes       • bytesToBigint
• bytesToHex            doubleSha256        • hexToBytes
• randomFieldElement  + scalarFromBytes       scalarToBytes
• sha256Hash          + taggedHash
```

**`poseidon`** · 21 exports · 7 consumer, 6 internal, 8 unreferenced

```
+ BN254_SCALAR_FIELD                computeJoinSplitCommitment      • computeJoinSplitCommitmentSync
  computeJoinSplitNullifier       • computeJoinSplitNullifierSync     computeMPK
• computeMPKSync                    computeNPK                      • computeNPKSync
+ computeNullifier                + computeNullifierSync            • computeTokenId
  computeTokenIdFromAddress         computeUnifiedCommitment        + computeUnifiedCommitmentSync
  hashNullifier                   + hashNullifierSync               • initPoseidon
  poseidonHash                    • poseidonHashSync                + reduceToField
```

## 3. PDA derivation

Every on-chain account address. Seed builders are the single source of truth — never restate seeds in app code.

**`pda`** · 32 exports · 15 consumer, 4 internal, 5 unreferenced

```
• EXIT_KIND_BTC_SCRIPT          • EXIT_KIND_SOLANA_OWNER          PDA_SEEDS
• blockHeaderSeeds              ~ commitmentToBytes             • commitmentTreeSeeds
• depositReceiptSeeds           ~ deriveBlockHeaderPDA          ~ deriveCommitmentTreePDA
~ deriveDepositReceiptPDA       + deriveExitDestinationPDA      ~ deriveHeightIndexPDA
  deriveLightClientPDA          ~ deriveNullifierRecordPDA      ~ derivePolicyApprovalPDA
  derivePoolConfigPDA           ~ derivePoolStatePDA            + deriveRedemptionRequestPDA
+ deriveTokenConfigPDA            deriveVerifiedTransactionPDA  + deriveVkRegistryPDA
• exitDestinationSeeds          • heightIndexSeeds              • lightClientSeeds
• nullifierRecordSeeds            policyApprovalSeeds           • poolConfigSeeds
• poolStateSeeds                • redemptionRequestSeeds        • tokenConfigSeeds
• verifiedTransactionSeeds      • vkRegistrySeeds
```

## 4. Notes & commitment tree

The shielded state itself: note construction, commitments, nullifiers, Merkle proofs.

**`note`** · 29 exports · 3 consumer, 0 internal, 14 unreferenced

```
  computeJoinSplitNoteNullifier  ~ computeNoteCommitment          ~ computeNoteNullifier
  createJoinSplitNote              createNote                     ~ createNoteFromSecrets
  createStealthNote              • deriveMasterKey                ~ deriveNote
~ deriveNoteFromMaster             deriveNotes                      deserializeJoinSplitNote
~ deserializeNote                  deserializeStealthNote         ~ estimateSeedStrength
• formatBtc                      ~ generateNote                   ~ getNotePublicKeyX
• initPoseidon                     isPoseidonReady                ~ noteHasComputedHashes
~ parseBtc                         prepareWithdrawal                serializeJoinSplitNote
~ serializeNote                    serializeStealthNote             stealthNoteHasComputedHashes
  updateNoteWithHashes             updateStealthNoteWithHashes
```

**`commitment-tree`** · 15 exports · 5 consumer, 2 internal, 5 unreferenced

```
  COMMITMENT_TREE_DISCRIMINATOR  • CommitmentTreeIndex            + MAX_LEAVES
+ ROOT_HISTORY_SIZE              • TREE_DEPTH                     ~ ZERO_HASHES
• buildCommitmentTreeFromChain     fetchCommitmentTree            ~ fetchMerkleProofForCommitment
  getCommitmentIndex             ~ getLeafIndexForCommitment      • getMerkleProofFromTree
  isValidRoot                    • parseCommitmentTreeData          saveCommitmentIndex
```

**`merkle`** · 13 exports · 2 consumer, 2 internal, 5 unreferenced

```
+ MAX_LEAVES                    + ROOT_HISTORY_SIZE             • TREE_DEPTH
  ZERO_VALUE                    ~ createEmptyMerkleProof          createMerkleProof
  createMerkleProofFromBigints  ~ leafIndexToPathIndices        • parseMerkleProofResponse
~ pathIndicesToLeafIndex          proofToCircomFormat             proofToOnChainFormat
~ validateMerkleProofStructure
```

## 5. Stealth addressing

Unlinkable recipients: meta-addresses, announcements, scanning, claiming.

**`stealth`** · 35 exports · 12 consumer, 6 internal, 9 unreferenced

```
+ ANNOUNCEMENT_TYPE_DEPOSIT         ~ ANNOUNCEMENT_TYPE_TRANSFER        + computeNullifierBytes
• computeNullifierHashForNote       + createDepositFromConfig           • createDirectVaultDeposit
• createNonInteractiveDeposit       • createNonInteractiveDeposit       • createNonInteractiveDeposit
~ createStealthDeposit              • createStealthDepositWithKeys        createStealthOutput
  createStealthOutputForCommitment  • createStealthOutputWithKeys       • decodeViewOnlyKeys
~ decryptAmount                     • encodeViewOnlyKeys                ~ encryptAmount
• exportViewOnlyKeys                  isDepositForViewer                + isDepositForViewerHex
  isDirectVaultDepositMode            isWalletAdapter                     packEncryptedAmountWithSign
  packStealthOutputForCircuit       • parseAnnouncementsFromHex         ~ pickCustodyInternalKey
  pickIkaCustodyKey                 • prepareClaimInputs                ~ scanAnnouncements
• scanAnnouncementsViewOnly         + scanAnnouncementsViewOnlyMulti    • scanUnifiedNotes
+ scanUnifiedNotesMulti               unpackEncryptedAmountWithSign
```

**`sns-resolver`** · 10 exports · 5 consumer, 0 internal, 2 unreferenced

```
~ SNS_COMPLIANCE_AUDITOR_BYTES   ~ SNS_COMPLIANCE_AUDITOR_OFFSET  ~ SNS_STEALTH_DATA_SIZE
• SnsComplianceFlags             • deriveParentDomainKey          • isAuditorDisclosable
  isSnsStealthAddress            • parseSnsStealthData            • resolveSnsName
  resolveStealthName
```

**`claim-link`** · 3 exports · 0 consumer, 0 internal, 0 unreferenced

```
~ decodeClaimLink  ~ encodeClaimLink  ~ parseClaimUrl
```

**`sender-memo`** · 16 exports · 4 consumer, 1 internal, 2 unreferenced

```
~ SENDER_MEMO_AMOUNT_BYTES      ~ SENDER_MEMO_CIPHERTEXT_BYTES  ~ SENDER_MEMO_COMMITMENT_BYTES
  SENDER_MEMO_LEAF_INDEX_BYTES  ~ SENDER_MEMO_NONCE_BYTES       ~ SENDER_MEMO_PACKED_BYTES
  SENDER_MEMO_TAG_BYTES         ~ SENDER_MEMO_TOKEN_BYTES       + buildSenderMemosForTransact
• decryptSenderMemo             • deriveOutgoingViewingKey      • encryptSenderMemo
~ generateSenderMemoNonce       ~ packSenderMemo                • packSenderMemoForInstruction
~ unpackSenderMemo
```

## 6. Bitcoin side

Deposit addresses, taproot custody, chain reads.

**`taproot`** · 22 exports · 8 consumer, 2 internal, 9 unreferenced

```
• DEPOSIT_BITCOIN_NETWORK          • DEPOSIT_DESTINATION_CHAIN        • DEPOSIT_OP_RETURN_SIZE
  DEPOSIT_OP_RETURN_VERSION          DEPOSIT_POOL_TAG_SIZE            • buildDepositOpReturn
  buildRefundScript                • computeDepositPoolTag              computeTapLeafHash
  createCustomInternalKey          + createOpReturnScriptFromPayload  ~ createP2TRScriptPubkey
  decodeDepositOpReturnHeader      • deriveTaprootAddress             + deriveTaprootAddressWithRefund
  encodeDepositOpReturnHeader        getInternalKey                   • isValidBitcoinAddress
• parseDepositOpReturn             ~ parseP2TRScriptPubkey              validateDepositOpReturnContext
~ verifyTaprootAddress
```

**`bitcoin/ika`** · 2 exports · 0 consumer, 2 internal, 0 unreferenced

```
+ deriveCustodyAddressFromIkaDWallet  + deriveRawXOnlyP2TRAddress
```

**`psbt`** · 4 exports · 1 consumer, 1 internal, 1 unreferenced

```
• buildDepositPsbt    ~ estimateDepositFee    fetchUtxos
+ selectUtxos
```

**`core/esplora`** · 3 exports · 0 consumer, 1 internal, 2 unreferenced

```
+ EsploraClient     esploraMainnet    esploraTestnet
```

**`core/mempool`** · 4 exports · 4 consumer, 0 internal, 0 unreferenced

```
• MempoolClient   • mempoolMainnet  • mempoolTestnet
• reverseBytes
```

## 7. Proving

Groth16 JoinSplit proofs, plus the verifying-key registry.

**`prover/web`**  — `@utxopia/sdk/prover/web` · 14 exports · 2 consumer, 7 internal, 3 unreferenced

```
  buildVerifyInstructionData   + circuitExists                + cleanup
+ generateGenericGroth16Proof  + generateJoinSplitProof         getCircuitPath
  getGroth16VerifierProgramId  + initProver                   + isProverAvailable
~ preloadJoinSplitCircuit      + proofToBytes                 ~ setCircuitArtifactDigests
• setCircuitPath               • verifyGroth16Proof
```

**`prover/mobile`**  — `@utxopia/sdk/prover/mobile` · 7 exports · 0 consumer, 6 internal, 1 unreferenced

```
+ circuitExists           + cleanup                 + generateJoinSplitProof
+ initProver              + isProverAvailable       + proofToBytes
  setCircuitResolver
```

**`bound-params`** · 11 exports · 6 consumer, 0 internal, 2 unreferenced

```
~ DEFAULT_BOUND_PARAMS                • SOLANA_BOUND_CHAIN_ID                 SOLANA_DEVNET_BOUND_CHAIN_ID
  SOLANA_MAINNET_BOUND_CHAIN_ID       • computeBoundParamsHash              ~ computeSolanaDomainBoundParamsHash
~ computeSolanaDomainSeparator        • computeStealthDataHash              • createRedeemBoundParams
• createTransferBoundParams           • createUnshieldBoundParams
```

**`vk-registry`** · 13 exports · 0 consumer, 1 internal, 1 unreferenced

```
~ INIT_VK_REGISTRY_DISCRIMINATOR      MAX_IC_POINTS                     + MAX_SAFE_JOINSPLIT_SIZE
~ UPDATE_VK_REGISTRY_DISCRIMINATOR  ~ VK_REGISTRY_DISCRIMINATOR         ~ VK_REGISTRY_LEN
~ assertVkRegistryForShape          ~ buildVkRegistryData               ~ computeVkHash
~ isVkRegistryReady                 ~ joinSplitNumPublicInputs          ~ parseVkRegistry
~ vkeyJsonToVkMaterial
```

## 8. Instruction building

Encode and assemble Solana instructions for every protocol operation.

**`instructions`** · 59 exports · 12 consumer, 2 internal, 28 unreferenced

```
• INSTRUCTION_DISCRIMINATORS                         MAX_POLICY_INTENT_PARTS                            POOL_CONFIG_DISCRIMINATOR
  POOL_CONFIG_LEN                                    POOL_SCRIPT_MAX_LEN                              • bigintTo32Bytes
  buildApproveRedemptionSigningInstruction           buildApproveRedemptionSigningInstructionData       buildCancelPoolUpdateInstruction
  buildCancelPoolUpdateInstructionData             ~ buildCancelRedemptionInstruction                 ~ buildCancelRedemptionInstructionData
• buildCompleteDepositInstructionData                buildCompleteDepositPermissionedInstruction        buildCompleteDepositPermissionedInstructionData
~ buildCompleteRedemptionInstruction               ~ buildCompleteRedemptionInstructionData             buildExecutePoolUpdateInstruction
• buildExecutePoolUpdateInstructionData              buildInitializePermissionedInstruction             buildInitializePermissionedInstructionData
~ buildInitializePolicyApprovalInstruction           buildInitializePolicyApprovalInstructionData     ~ buildMagicBlockCommitInstruction
~ buildMagicBlockCommitInstructionData             ~ buildMagicBlockDelegateInstruction               ~ buildMagicBlockDelegateInstructionData
~ buildMagicBlockPerPermissionInstruction          ~ buildMagicBlockPerPermissionInstructionData      ~ buildPolicyApprovalCommitInstruction
~ buildPolicyApprovalDecisionInstruction           • buildPolicyIntentParts                           ~ buildPolicyRequestHash
  buildProposePoolUpdateInstruction                • buildProposePoolUpdateInstructionData            • buildRedeemInstructionData
  buildRegisterExitDestinationInstruction            buildRegisterExitDestinationInstructionData        buildRotateAuditorInstruction
~ buildRotateAuditorInstructionData                  buildRotateTreeInstruction                         buildRotateTreeInstructionData
  buildSetAuditorFrozenInstruction                   buildSetAuditorFrozenInstructionData               buildSetAuditorViewingPubkeyInstruction
  buildSetAuditorViewingPubkeyInstructionData        buildSetPoolConfigInstructionData                  buildShieldInstruction
• buildShieldInstructionData                         buildShieldPermissionedInstruction               • buildShieldPermissionedInstructionData
~ buildTransactInstruction                         • buildTransactInstructionData                     ~ buildUnshieldInstruction
• buildUnshieldInstructionData                     • buildVerifyTransactionInstructionData            + bytes32ToBigint
+ deriveRedemptionRequestPDA                         parsePoolConfig
```

**`chadbuffer`** · 15 exports · 1 consumer, 3 internal, 7 unreferenced

```
• AUTHORITY_SIZE               + CHADBUFFER_PROGRAM_ID          MAX_DATA_PER_WRITE
+ SOLANA_TX_SIZE_LIMIT           buildMerkleProof               calculateUploadTransactions
~ closeBuffer                    fetchMerkleProof               fetchRawTransaction
  getProofSource               ~ needsBuffer                    prepareVerifyDeposit
~ readBufferData               + uploadProofToBuffer          ~ uploadTransactionToBuffer
```

**`relay`** · 3 exports · 0 consumer, 1 internal, 2 unreferenced

```
  closeChadBuffer        createChadBuffer     + uploadProofToBuffer
```

**`solana/connection`** · 5 exports · 2 consumer, 0 internal, 0 unreferenced

```
~ clearConnectionAdapterCache      ~ createConnectionAdapterFromKit   • createConnectionAdapterFromWeb3
• createFetchConnectionAdapter     ~ getConnectionAdapter
```

**`solana/priority-fee`** · 8 exports · 0 consumer, 0 internal, 0 unreferenced

```
~ COMPUTE_BUDGET_DISCRIMINATORS    ~ DEFAULT_COMPUTE_UNITS            ~ DEFAULT_PRIORITY_FEE
~ buildPriorityFeeInstructionData  ~ encodeSetComputeUnitLimit        ~ encodeSetComputeUnitPrice
~ estimatePriorityFee              ~ getHeliusRpcUrl
```

## 9. Reading chain state

Events, announcements, explorer-style queries.

**`events`** · 13 exports · 2 consumer, 0 internal, 1 unreferenced

```
~ EVENT_ANNOUNCEMENTS_BATCH       ~ EVENT_AUDITOR_CIPHERTEXT        ~ EVENT_BTC_ORIGIN_ATTESTATION
~ EVENT_NULLIFIERS_BATCH          ~ EVENT_NULLIFIER_SPENT             EVENT_SENDER_MEMO
~ EVENT_STEALTH_ANNOUNCEMENT      ~ parseAuditorCiphertextEvent     ~ parseBtcOriginAttestationEvent
~ parseNullifierSpentEvent        • parseProgramEvents              • parseSenderMemoEvent
~ parseStealthAnnouncementEvent
```

**`event-client`** · 1 exports · 1 consumer, 0 internal, 0 unreferenced

```
• EventClient
```

**`announcement-client`** · 1 exports · 1 consumer, 0 internal, 0 unreferenced

```
• AnnouncementClient
```

**`explorer`** · 10 exports · 1 consumer, 0 internal, 5 unreferenced

```
~ NULLIFIER_RECORD_DISCRIMINATOR    ~ NULLIFIER_RECORD_SIZE               OPERATION_TYPE_LABELS
~ REDEMPTION_REQUEST_DISCRIMINATOR  ~ REDEMPTION_REQUEST_SIZE             fetchExplorerDeposits
• fetchExplorerRedemptions            fetchExplorerTransfers              parseNullifierRecord
  parseRedemptionRequest
```

**`client`** · 1 exports · 1 consumer, 0 internal, 0 unreferenced

```
• UTXOpiaClient
```

## 10. Compliance & disclosure

Auditor ciphertexts and selective disclosure.

**`auditor`** · 3 exports · 2 consumer, 0 internal, 0 unreferenced

```
• auditRecordsToCsv     • auditScan             ~ auditScanCiphertexts
```

**`auditor-ciphertext`** · 5 exports · 1 consumer, 3 internal, 0 unreferenced

```
~ AUDITOR_CIPHERTEXT_BYTES       + buildAuditorCiphertextForNote  • decryptAuditorCiphertext
+ encryptAuditorCiphertext       + resolveAuditorCiphertext
```

**`selective-disclosure`** · 7 exports · 4 consumer, 0 internal, 3 unreferenced

```
  RANGE_SUM_N                 • RANGE_SUM_SIZES               RANGE_SUM_VARIANTS
• computeRangeSumAttestation  • generateOwnershipProof      • generateRangeSumProof
  pickRangeSumVariant
```

## 11. Ephemeral rollups

MagicBlock delegation and policy approval.

**`magicblock`** · 25 exports · 0 consumer, 7 internal, 4 unreferenced

```
+ MAGICBLOCK_DELEGATION_PROGRAM_ID       ~ MAGICBLOCK_DEVNET_ROUTER_URL           ~ MAGICBLOCK_DEVNET_ROUTER_WS_URL
+ MAGICBLOCK_EPHEMERAL_VAULT_ID          + MAGICBLOCK_MAGIC_CONTEXT_ID            + MAGICBLOCK_MAGIC_PROGRAM_ID
+ MAGICBLOCK_MAX_PER_MEMBERS             + MAGICBLOCK_PERMISSION_PROGRAM_ID       + MAGICBLOCK_PER_MEMBER_FLAGS
  MAGICBLOCK_VALIDATOR_IDENTITIES        ~ assertDomainExecutionPolicy            ~ assertMagicBlockRouteReady
~ buildDefaultPrivacyDomain              ~ buildMagicBlockPerMemberFlags          ~ createMagicBlockRouterConnection
  deriveMagicBlockCommitRecordPda          deriveMagicBlockCommitStatePda         ~ deriveMagicBlockDelegateBufferPda
~ deriveMagicBlockDelegationMetadataPda  ~ deriveMagicBlockDelegationRecordPda    ~ deriveMagicBlockPermissionPda
  deriveMagicBlockUndelegateBufferPda    ~ getMagicBlockEndpoint                  ~ getMagicBlockValidatorIdentity
~ requiresMagicBlockEndpoint
```

## 12. Utilities

**`utils/encoding`** · 2 exports · 0 consumer, 2 internal, 0 unreferenced

```
+ base64ToBinaryString  + fromBase64
```

**`logger`** · 3 exports · 0 consumer, 2 internal, 1 unreferenced

```
+ debug       setDebug  + warn
```
