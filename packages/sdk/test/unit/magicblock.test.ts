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
  buildDefaultPrivacyDomain,
  deriveMagicBlockDelegateBufferPda,
  deriveMagicBlockDelegationMetadataPda,
  deriveMagicBlockDelegationRecordPda,
  deriveMagicBlockPermissionPda,
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
      target: "commitmentTree",
      commitFrequencyMs: 500,
      validator,
    });
    expect(delegate.length).toBe(38);
    expect(delegate[0]).toBe(32);
    expect(delegate[1]).toBe(1);
    expect(new DataView(delegate.buffer).getUint32(2, true)).toBe(500);

    const anyValidator = buildMagicBlockDelegateInstructionData({
      target: "poolState",
      commitFrequencyMs: 1000,
    });
    expect(anyValidator.length).toBe(6);
    expect(anyValidator[0]).toBe(32);
    expect(anyValidator[1]).toBe(0);

    const commit = buildMagicBlockCommitInstructionData({
      nullifierHashes: [new Uint8Array(32).fill(7)],
      allowUndelegation: true,
    });
    expect(Array.from(commit.slice(0, 4))).toEqual([33, 1, 1, 1]);
    expect(commit.slice(4)).toEqual(new Uint8Array(32).fill(7));
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
      target: "commitmentTree",
      members: [{
        address: authority,
        flags: buildMagicBlockPerMemberFlags(["authority", "txLogs"]),
      }],
    });
    expect(Array.from(data.slice(0, 4))).toEqual([34, 0, 1, 1]);
    expect(data.length).toBe(37);

    expect(() => buildMagicBlockPerPermissionInstructionData({
      operation: "update",
      target: "commitmentTree",
      members: [{ address: authority, flags: buildMagicBlockPerMemberFlags(["txLogs"]) }],
    })).toThrow("retain an authority");
  });

  test("keeps delegate, commit, and PER account ABIs aligned with the program", () => {
    const payer = DEVNET_CONFIG.utxopiaProgramId;
    const pool = DEVNET_CONFIG.poolStatePda;
    const tree = DEVNET_CONFIG.commitmentTreePda;
    const delegate = buildMagicBlockDelegateInstruction({
      target: "commitmentTree",
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
    expect(delegate.accounts?.map((account) => account.address)).toEqual([
      payer,
      payer,
      pool,
      tree,
      payer,
      pool,
      tree,
      pool,
      "11111111111111111111111111111111",
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
      target: "commitmentTree",
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
      executionMode: "per",
    });

    expect(() => assertMagicBlockRouteReady(domain)).toThrow("no MagicBlock PER endpoint");
  });

  test("rejects public domains defaulting to PER", () => {
    const domain = buildDefaultPrivacyDomain(DEVNET_CONFIG, {
      executionMode: "per",
      magicblock: { perUrl: "https://per.example" },
    });

    expect(() => assertDomainExecutionPolicy(domain)).toThrow(
      "Public permissionless domains must not default to PER"
    );
  });

  test("rejects PER domains that do not use the TEE validator", () => {
    const domain = buildDefaultPrivacyDomain(DEVNET_CONFIG, {
      domainId: "institution",
      label: "Institution Pool",
      kind: "institution",
      executionMode: "per",
      magicblock: {
        perUrl: "https://per.example",
        validatorRegion: "asia",
      },
    });

    expect(() => assertDomainExecutionPolicy(domain)).toThrow(
      "PER domains must use the TEE validator region"
    );
  });

  test("rejects institution domains that silently fall back to normal Solana", () => {
    const domain = buildDefaultPrivacyDomain(DEVNET_CONFIG, {
      domainId: "institution",
      label: "Institution Pool",
      kind: "institution",
      executionMode: "solana",
    });

    expect(() => assertDomainExecutionPolicy(domain)).toThrow(
      "Institution domains must use ER or PER explicitly"
    );
  });

  test("does not create unauthenticated kit connections for PER", async () => {
    const domain = buildDefaultPrivacyDomain(DEVNET_CONFIG, {
      domainId: "institution",
      label: "Institution Pool",
      kind: "institution",
      executionMode: "per",
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
