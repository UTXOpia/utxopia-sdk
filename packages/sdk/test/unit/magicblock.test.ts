import { describe, expect, test } from "bun:test";
import { AccountRole } from "@solana/kit";
import {
  DEVNET_CONFIG,
  MAGICBLOCK_DELEGATION_PROGRAM_ID,
  MAGICBLOCK_DEVNET_ROUTER_URL,
  MAGICBLOCK_DEVNET_ROUTER_WS_URL,
  MAGICBLOCK_EPHEMERAL_VAULT_ID,
  MAGICBLOCK_MAGIC_CONTEXT_ID,
  MAGICBLOCK_MAGIC_PROGRAM_ID,
  MAGICBLOCK_PERMISSION_PROGRAM_ID,
  UTXOPIA_POLICY_PROGRAM_ID,
  buildMagicBlockPerMemberFlags,
  buildMagicBlockCommitInstruction,
  buildMagicBlockDelegateInstruction,
  buildMagicBlockPerPermissionInstruction,
  assertDomainExecutionPolicy,
  assertMagicBlockRouteReady,
  createMagicBlockRouterConnection,
  buildMagicBlockCommitInstructionData,
  buildMagicBlockDelegateInstructionData,
  buildMagicBlockPerPermissionInstructionData,
  buildPolicyRequestHash,
  buildInitializePolicyApprovalInstruction,
  buildPolicyApprovalDecisionInstruction,
  buildPolicyApprovalCommitInstruction,
  buildDefaultPrivacyDomain,
  deriveMagicBlockDelegateBufferPda,
  deriveMagicBlockDelegationMetadataPda,
  deriveMagicBlockDelegationRecordPda,
  deriveMagicBlockPermissionPda,
  derivePolicyApprovalPDA,
  getMagicBlockValidatorIdentity,
  getMagicBlockEndpoint,
  requiresMagicBlockEndpoint,
} from "../../src";

describe("MagicBlock execution domains", () => {
  test("builds a conservative public Solana domain by default", () => {
    const domain = buildDefaultPrivacyDomain(DEVNET_CONFIG);

    expect(domain.domainId).toBe("public");
    expect(domain.kind).toBe("public");
    expect(domain.executionMode).toBe("solana");
    expect(domain.policyMode).toBe("disabled");
    expect(domain.programId).toBe(DEVNET_CONFIG.utxopiaProgramId);
    expect(domain.poolStatePda).toBe(DEVNET_CONFIG.poolStatePda);
    expect(domain.commitmentTreePda).toBe(DEVNET_CONFIG.commitmentTreePda);
    expect(domain.magicblock?.routerUrl).toBe(MAGICBLOCK_DEVNET_ROUTER_URL);
    expect(domain.magicblock?.routerWsUrl).toBe(MAGICBLOCK_DEVNET_ROUTER_WS_URL);
    expect(domain.magicblock?.validatorRegion).toBe("asia");
  });

  test("exports MagicBlock program IDs and validator identities", () => {
    expect(MAGICBLOCK_DELEGATION_PROGRAM_ID.toString()).toBe(
      "DELeGGvXpWV2fqJUhqcF5ZSYMS4JTLjteaAMARRSaeSh"
    );
    expect(MAGICBLOCK_PERMISSION_PROGRAM_ID.toString()).toBe(
      "ACLseoPoyC3cBqoUtkbjZ4aDrkurZW86v19pXz2XQnp1"
    );
    expect(MAGICBLOCK_MAGIC_PROGRAM_ID.toString()).toBe(
      "Magic11111111111111111111111111111111111111"
    );
    expect(MAGICBLOCK_MAGIC_CONTEXT_ID.toString()).toBe(
      "MagicContext1111111111111111111111111111111"
    );
    expect(getMagicBlockValidatorIdentity("tee").toString()).toBe(
      "MTEWGuqxUpYZGFJQcp8tLN7x5v9BSeoFHYWQQ3n3xzo"
    );
  });

  test("combines PER member flags using bitmasks", () => {
    expect(buildMagicBlockPerMemberFlags(["authority", "txLogs"])).toBe(3);
    expect(buildMagicBlockPerMemberFlags(["txMessage", "accountSignatures"])).toBe(24);
  });

  test("builds MagicBlock delegate and commit instruction data", () => {
    const validator = getMagicBlockValidatorIdentity("asia");
    const delegate = buildMagicBlockDelegateInstructionData({
      target: "policyApproval",
      commitFrequencyMs: 500,
      validator,
    });
    expect(delegate.length).toBe(38);
    expect(delegate[0]).toBe(32);
    expect(delegate[1]).toBe(2);
    expect(new DataView(delegate.buffer).getUint32(2, true)).toBe(500);

    const anyValidator = buildMagicBlockDelegateInstructionData({
      target: "policyApproval",
      commitFrequencyMs: 1000,
    });
    expect(anyValidator.length).toBe(6);
    expect(anyValidator[0]).toBe(32);
    expect(anyValidator[1]).toBe(2);

    const commit = buildMagicBlockCommitInstructionData({
      nullifierHashes: [new Uint8Array(32).fill(7)],
      allowUndelegation: true,
    });
    expect(Array.from(commit.slice(0, 4))).toEqual([33, 1, 1, 1]);
    expect(commit.slice(4)).toEqual(new Uint8Array(32).fill(7));
  });

  test("builds the one-time PolicyApproval lifecycle", async () => {
    const payer = DEVNET_CONFIG.utxopiaProgramId;
    const pool = DEVNET_CONFIG.poolStatePda;
    const actionData = new Uint8Array([13, 1, 1, 0, 0]);
    const requestHash = buildPolicyRequestHash({
      programId: payer,
      poolState: pool,
      actor: payer,
      instructionData: actionData,
    });
    const nonce = new Uint8Array(32).fill(7);
    const [approval] = await derivePolicyApprovalPDA(pool, requestHash, nonce);
    const initialize = buildInitializePolicyApprovalInstruction({
      action: 13,
      expiresAtSlot: 1234n,
      actor: payer,
      requestHash,
      nonce,
      accounts: { payer, poolState: pool, policyApproval: approval },
    });
    expect(initialize.data[0]).toBe(36);
    expect(initialize.programAddress).toBe(UTXOPIA_POLICY_PROGRAM_ID);
    expect(initialize.data.length).toBe(106);
    expect(initialize.accounts?.at(2)?.role).toBe(AccountRole.WRITABLE);

    const decision = buildPolicyApprovalDecisionInstruction({
      decision: "approve",
      accounts: { policyAuthority: payer, policyApproval: approval },
    });
    expect(Array.from(decision.data)).toEqual([37, 1]);

    const commit = buildPolicyApprovalCommitInstruction({
      accounts: { payer, policyApproval: approval },
    });
    expect(Array.from(commit.data)).toEqual([38]);
    expect(commit.accounts?.map((account) => account.address)).toEqual([
      payer,
      MAGICBLOCK_MAGIC_CONTEXT_ID,
      MAGICBLOCK_MAGIC_PROGRAM_ID,
      approval,
    ]);

    const delegated = buildMagicBlockDelegateInstructionData({
      target: "policyApproval",
      commitFrequencyMs: 0,
      validator: getMagicBlockValidatorIdentity("tee"),
    });
    expect(delegated[1]).toBe(2);
  });

  test("derives MagicBlock delegate PDAs for a delegated UTXOpia account", async () => {
    const delegated = DEVNET_CONFIG.commitmentTreePda;
    const [buffer] = await deriveMagicBlockDelegateBufferPda(
      delegated,
      DEVNET_CONFIG.utxopiaProgramId
    );
    const [record] = await deriveMagicBlockDelegationRecordPda(delegated);
    const [metadata] = await deriveMagicBlockDelegationMetadataPda(delegated);
    const [permission] = await deriveMagicBlockPermissionPda(delegated);

    expect(buffer.toString()).not.toBe(record.toString());
    expect(record.toString()).not.toBe(metadata.toString());
    expect(metadata.toString()).not.toBe(buffer.toString());
    expect(permission.toString()).not.toBe(buffer.toString());
  });

  test("builds private PER ACL payloads and retains an authority", () => {
    const authority = DEVNET_CONFIG.utxopiaProgramId;
    const data = buildMagicBlockPerPermissionInstructionData({
      operation: "create",
      target: "policyApproval",
      members: [{
        address: authority,
        flags: buildMagicBlockPerMemberFlags(["authority", "txLogs"]),
      }],
    });
    expect(Array.from(data.slice(0, 4))).toEqual([34, 0, 2, 1]);
    expect(data.length).toBe(37);

    expect(() => buildMagicBlockPerPermissionInstructionData({
      operation: "update",
      target: "policyApproval",
      members: [{ address: authority, flags: buildMagicBlockPerMemberFlags(["txLogs"]) }],
    })).toThrow("retain an authority");
  });

  test("keeps delegate, commit, and PER account ABIs aligned with the program", () => {
    const payer = DEVNET_CONFIG.utxopiaProgramId;
    const pool = DEVNET_CONFIG.poolStatePda;
    const tree = DEVNET_CONFIG.commitmentTreePda;
    const delegate = buildMagicBlockDelegateInstruction({
      target: "policyApproval",
      commitFrequencyMs: 500,
      accounts: {
        payer,
        authority: payer,
        poolState: pool,
        delegatedAccount: tree,
        buffer: pool,
        delegationRecord: tree,
        delegationMetadata: pool,
      },
    });
    expect(delegate.programAddress).toBe(UTXOPIA_POLICY_PROGRAM_ID);
    expect(delegate.accounts?.map((account) => account.address)).toEqual([
      payer,
      payer,
      pool,
      tree,
      UTXOPIA_POLICY_PROGRAM_ID,
      pool,
      tree,
      pool,
      "11111111111111111111111111111111",
      MAGICBLOCK_DELEGATION_PROGRAM_ID,
    ]);
    expect(delegate.accounts?.map((account) => account.role)).toEqual([
      AccountRole.WRITABLE_SIGNER,
      AccountRole.READONLY_SIGNER,
      AccountRole.READONLY,
      AccountRole.WRITABLE,
      AccountRole.READONLY,
      AccountRole.WRITABLE,
      AccountRole.WRITABLE,
      AccountRole.WRITABLE,
      AccountRole.READONLY,
      AccountRole.READONLY,
    ]);

    const commit = buildMagicBlockCommitInstruction({
      nullifierHashes: [new Uint8Array(32).fill(9)],
      accounts: {
        payer,
        poolState: pool,
        commitmentTree: tree,
        nullifierAccounts: [payer],
      },
    });
    expect(commit.accounts?.map((account) => account.address)).toEqual([
      payer,
      payer,
      MAGICBLOCK_MAGIC_CONTEXT_ID,
      MAGICBLOCK_MAGIC_PROGRAM_ID,
      pool,
      tree,
      payer,
    ]);
    expect(commit.accounts?.map((account) => account.role)).toEqual([
      AccountRole.READONLY_SIGNER,
      AccountRole.READONLY_SIGNER,
      AccountRole.WRITABLE,
      AccountRole.READONLY,
      AccountRole.WRITABLE,
      AccountRole.WRITABLE,
      AccountRole.WRITABLE,
    ]);

    const permission = buildMagicBlockPerPermissionInstruction({
      operation: "create",
      target: "policyApproval",
      members: [{
        address: payer,
        flags: buildMagicBlockPerMemberFlags(["authority"]),
      }],
      accounts: {
        authority: payer,
        poolState: pool,
        permissionedAccount: tree,
        permission: pool,
      },
    });
    expect(permission.accounts?.map((account) => account.address)).toEqual([
      payer,
      pool,
      tree,
      pool,
      MAGICBLOCK_EPHEMERAL_VAULT_ID,
      MAGICBLOCK_MAGIC_PROGRAM_ID,
      MAGICBLOCK_PERMISSION_PROGRAM_ID,
    ]);
    expect(permission.accounts?.map((account) => account.role)).toEqual([
      AccountRole.READONLY_SIGNER,
      AccountRole.READONLY,
      AccountRole.WRITABLE,
      AccountRole.WRITABLE,
      AccountRole.WRITABLE,
      AccountRole.READONLY,
      AccountRole.READONLY,
    ]);
  });

  test("rejects incomplete commit clusters", () => {
    expect(() => buildMagicBlockCommitInstructionData({
      nullifierHashes: [],
    })).toThrow("1-10 nullifier");
    expect(() => buildMagicBlockCommitInstructionData({
      nullifierHashes: [new Uint8Array(31)],
    })).toThrow("32 bytes");
  });

  test("requires MagicBlock endpoints only for ER and PER", () => {
    expect(requiresMagicBlockEndpoint("solana")).toBe(false);
    expect(requiresMagicBlockEndpoint("er")).toBe(true);
    expect(requiresMagicBlockEndpoint("per")).toBe(true);
  });

  test("selects ER and PER endpoints independently", () => {
    const domain = buildDefaultPrivacyDomain(DEVNET_CONFIG, {
      executionMode: "er",
      magicblock: {
        erUrl: "https://er.example",
        perUrl: "https://per.example",
      },
    });

    expect(getMagicBlockEndpoint(domain, "er")).toBe("https://er.example");
    expect(getMagicBlockEndpoint(domain, "per")).toBe("https://per.example");
    expect(getMagicBlockEndpoint(domain, "solana")).toBeUndefined();
  });

  test("fails closed when an ER endpoint is missing", () => {
    const domain = buildDefaultPrivacyDomain(DEVNET_CONFIG, {
      executionMode: "er",
    });

    expect(() => assertMagicBlockRouteReady(domain)).toThrow("no MagicBlock ER endpoint");
  });

  test("fails closed when a PER endpoint is missing", () => {
    const domain = buildDefaultPrivacyDomain(DEVNET_CONFIG, {
      domainId: "institution",
      label: "Institution Pool",
      kind: "institution",
      policyMode: "per",
    });

    expect(() => assertDomainExecutionPolicy(domain)).toThrow("requires a PER policy endpoint");
  });

  test("rejects public domains requiring PER policy", () => {
    const domain = buildDefaultPrivacyDomain(DEVNET_CONFIG, {
      policyMode: "per",
      magicblock: { perUrl: "https://per.example" },
    });

    expect(() => assertDomainExecutionPolicy(domain)).toThrow(
      "Public permissionless domains must not require PER policy"
    );
  });

  test("rejects PER domains that do not use the TEE validator", () => {
    const domain = buildDefaultPrivacyDomain(DEVNET_CONFIG, {
      domainId: "institution",
      label: "Institution Pool",
      kind: "institution",
      policyMode: "per",
      magicblock: {
        perUrl: "https://per.example",
        validatorRegion: "asia",
      },
    });

    expect(() => assertDomainExecutionPolicy(domain)).toThrow(
      "PER policy domains must use the TEE validator region"
    );
  });

  test("keeps institution assets on Solana without requiring PER by default", () => {
    const domain = buildDefaultPrivacyDomain(DEVNET_CONFIG, {
      domainId: "institution",
      label: "Institution Pool",
      kind: "institution",
      executionMode: "solana",
    });

    expect(() => assertDomainExecutionPolicy(domain)).not.toThrow();
  });

  test("rejects ER/PER asset execution modes", () => {
    const domain = buildDefaultPrivacyDomain(DEVNET_CONFIG, {
      executionMode: "er",
      magicblock: { erUrl: "https://er.example" },
    });
    expect(() => assertDomainExecutionPolicy(domain)).toThrow(
      "asset execution must remain on Solana"
    );
  });

  test("does not create unauthenticated kit connections for PER", async () => {
    const domain = buildDefaultPrivacyDomain(DEVNET_CONFIG, {
      domainId: "institution",
      label: "Institution Pool",
      kind: "institution",
      policyMode: "per",
      magicblock: {
        perUrl: "https://per.example",
        validatorRegion: "tee",
      },
    });
    await expect(createMagicBlockRouterConnection(domain)).rejects.toThrow(
      "only for public ER"
    );
  });
});
