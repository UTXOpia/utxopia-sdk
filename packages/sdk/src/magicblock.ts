import { getAddressEncoder, getProgramDerivedAddress, type Address } from "@solana/kit";
import { Connection as MagicBlockConnection } from "@magicblock-labs/ephemeral-rollups-kit";
import { address, type NetworkConfig } from "./config";

export type MagicBlockExecutionMode = "solana" | "er" | "per";
export type MagicBlockPolicyMode = "disabled" | "per";
export type MagicBlockValidatorRegion = "asia" | "eu" | "us" | "tee" | "local";

export type PrivacyDomainKind = "public" | "institution";

export interface MagicBlockEndpointConfig {
  /** Magic Router HTTP endpoint used for delegated-account-aware routing. */
  routerUrl?: string;
  /** Magic Router WebSocket endpoint used for confirmations/subscriptions. */
  routerWsUrl?: string;
  /** MagicBlock ER endpoint used for low-latency public shielded transfers. */
  erUrl?: string;
  /** MagicBlock PER endpoint used for private institution policy execution. */
  perUrl?: string;
  /** Validator region selected for delegation. Use "tee" for PER. */
  validatorRegion?: MagicBlockValidatorRegion;
}

export interface PrivacyDomainConfig {
  /** Stable domain identifier. Bind this into future circuit bound params before multi-domain launch. */
  domainId: string;
  /** Human-readable label for UI and logs. */
  label: string;
  /** Product/compliance category for this privacy domain. */
  kind: PrivacyDomainKind;
  /** Execution lane selected for this domain. */
  executionMode: MagicBlockExecutionMode;
  /** Optional PER policy coprocessor. Asset execution remains Solana. */
  policyMode: MagicBlockPolicyMode;
  /** UTXOpia program instance for this domain. */
  programId: Address;
  /** Pool state PDA for this domain. */
  poolStatePda: Address;
  /** Active commitment tree PDA for this domain. */
  commitmentTreePda: Address;
  /** Optional auditor signer for permissioned domains. */
  auditor?: Address;
  /** Optional auditor viewing public key, encoded by the caller. */
  auditorViewingPubkey?: string;
  /** Optional MagicBlock endpoints for ER/PER routing. */
  magicblock?: MagicBlockEndpointConfig;
}

export interface BuildPrivacyDomainOptions {
  domainId?: string;
  label?: string;
  kind?: PrivacyDomainKind;
  executionMode?: MagicBlockExecutionMode;
  policyMode?: MagicBlockPolicyMode;
  auditor?: Address;
  auditorViewingPubkey?: string;
  magicblock?: MagicBlockEndpointConfig;
}

export const MAGICBLOCK_DELEGATION_PROGRAM_ID = address(
  "DELeGGvXpWV2fqJUhqcF5ZSYMS4JTLjteaAMARRSaeSh"
);

export const MAGICBLOCK_PERMISSION_PROGRAM_ID = address(
  "ACLseoPoyC3cBqoUtkbjZ4aDrkurZW86v19pXz2XQnp1"
);

export const MAGICBLOCK_MAGIC_PROGRAM_ID = address("Magic11111111111111111111111111111111111111");
export const MAGICBLOCK_MAGIC_CONTEXT_ID = address(
  "MagicContext1111111111111111111111111111111"
);
export const MAGICBLOCK_EPHEMERAL_VAULT_ID = address(
  "MagicVau1t999999999999999999999999999999999"
);

export const MAGICBLOCK_DEVNET_ROUTER_URL = "https://devnet-router.magicblock.app";
export const MAGICBLOCK_DEVNET_ROUTER_WS_URL = "wss://devnet-router.magicblock.app";

export const MAGICBLOCK_VALIDATOR_IDENTITIES: Record<MagicBlockValidatorRegion, Address> = {
  asia: address("MAS1Dt9qreoRMQ14YQuhg8UTZMMzDdKhmkZMECCzk57"),
  eu: address("MEUGGrYPxKk17hCr7wpT6s8dtNokZj5U2L57vjYMS8e"),
  us: address("MUS3hc9TCw4cGC12vHNoYcCGzJG1txjgQLZWVoeNHNd"),
  tee: address("MTEWGuqxUpYZGFJQcp8tLN7x5v9BSeoFHYWQQ3n3xzo"),
  local: address("mAGicPQYBMvcYveUZA5F5UNNwyHvfYh5xkLS2Fr1mev"),
};

export const MAGICBLOCK_PER_MEMBER_FLAGS = {
  authority: 1 << 0,
  txLogs: 1 << 1,
  txBalances: 1 << 2,
  txMessage: 1 << 3,
  accountSignatures: 1 << 4,
} as const;

export const MAGICBLOCK_MAX_PER_MEMBERS = 8;

export type MagicBlockPerMemberFlagName = keyof typeof MAGICBLOCK_PER_MEMBER_FLAGS;

export function buildMagicBlockPerMemberFlags(flags: MagicBlockPerMemberFlagName[]): number {
  return flags.reduce((acc, flag) => acc | MAGICBLOCK_PER_MEMBER_FLAGS[flag], 0);
}

export function getMagicBlockValidatorIdentity(region: MagicBlockValidatorRegion): Address {
  return MAGICBLOCK_VALIDATOR_IDENTITIES[region];
}

function magicBlockAddressBytes(value: Address): Uint8Array {
  return new Uint8Array(getAddressEncoder().encode(value));
}

export async function deriveMagicBlockDelegationRecordPda(
  delegatedAccount: Address
): Promise<[Address, number]> {
  const result = await getProgramDerivedAddress({
    programAddress: MAGICBLOCK_DELEGATION_PROGRAM_ID,
    seeds: [new TextEncoder().encode("delegation"), magicBlockAddressBytes(delegatedAccount)],
  });
  return [result[0], result[1]];
}

export async function deriveMagicBlockDelegationMetadataPda(
  delegatedAccount: Address
): Promise<[Address, number]> {
  const result = await getProgramDerivedAddress({
    programAddress: MAGICBLOCK_DELEGATION_PROGRAM_ID,
    seeds: [
      new TextEncoder().encode("delegation-metadata"),
      magicBlockAddressBytes(delegatedAccount),
    ],
  });
  return [result[0], result[1]];
}

export async function deriveMagicBlockDelegateBufferPda(
  delegatedAccount: Address,
  ownerProgram: Address
): Promise<[Address, number]> {
  const result = await getProgramDerivedAddress({
    programAddress: ownerProgram,
    seeds: [new TextEncoder().encode("buffer"), magicBlockAddressBytes(delegatedAccount)],
  });
  return [result[0], result[1]];
}

export async function deriveMagicBlockUndelegateBufferPda(
  delegatedAccount: Address
): Promise<[Address, number]> {
  const result = await getProgramDerivedAddress({
    programAddress: MAGICBLOCK_DELEGATION_PROGRAM_ID,
    seeds: [new TextEncoder().encode("undelegate-buffer"), magicBlockAddressBytes(delegatedAccount)],
  });
  return [result[0], result[1]];
}

export async function deriveMagicBlockCommitStatePda(
  delegatedAccount: Address
): Promise<[Address, number]> {
  const result = await getProgramDerivedAddress({
    programAddress: MAGICBLOCK_DELEGATION_PROGRAM_ID,
    seeds: [new TextEncoder().encode("state-diff"), magicBlockAddressBytes(delegatedAccount)],
  });
  return [result[0], result[1]];
}

export async function deriveMagicBlockCommitRecordPda(
  delegatedAccount: Address
): Promise<[Address, number]> {
  const result = await getProgramDerivedAddress({
    programAddress: MAGICBLOCK_DELEGATION_PROGRAM_ID,
    seeds: [
      new TextEncoder().encode("commit-state-record"),
      magicBlockAddressBytes(delegatedAccount),
    ],
  });
  return [result[0], result[1]];
}

export async function deriveMagicBlockPermissionPda(
  permissionedAccount: Address
): Promise<[Address, number]> {
  const result = await getProgramDerivedAddress({
    programAddress: MAGICBLOCK_PERMISSION_PROGRAM_ID,
    seeds: [
      new TextEncoder().encode("permission:"),
      magicBlockAddressBytes(permissionedAccount),
    ],
  });
  return [result[0], result[1]];
}

export function buildDefaultPrivacyDomain(
  config: NetworkConfig,
  options: BuildPrivacyDomainOptions = {}
): PrivacyDomainConfig {
  return {
    domainId: options.domainId ?? "public",
    label: options.label ?? "Public Pool",
    kind: options.kind ?? "public",
    executionMode: options.executionMode ?? "solana",
    policyMode: options.policyMode ?? "disabled",
    programId: config.utxopiaProgramId,
    poolStatePda: config.poolStatePda,
    commitmentTreePda: config.commitmentTreePda,
    auditor: options.auditor,
    auditorViewingPubkey: options.auditorViewingPubkey,
    magicblock: {
      routerUrl: MAGICBLOCK_DEVNET_ROUTER_URL,
      routerWsUrl: MAGICBLOCK_DEVNET_ROUTER_WS_URL,
      validatorRegion: options.policyMode === "per" ? "tee" : "asia",
      ...options.magicblock,
    },
  };
}

export function requiresMagicBlockEndpoint(mode: MagicBlockExecutionMode): boolean {
  return mode === "er" || mode === "per";
}

export function getMagicBlockEndpoint(
  domain: PrivacyDomainConfig,
  mode: MagicBlockExecutionMode = domain.executionMode
): string | undefined {
  if (mode === "er") {
    return domain.magicblock?.erUrl;
  }
  if (mode === "per") {
    return domain.magicblock?.perUrl;
  }
  return undefined;
}

export function assertMagicBlockRouteReady(domain: PrivacyDomainConfig): void {
  const mode = domain.executionMode;
  if (!requiresMagicBlockEndpoint(mode)) {
    return;
  }

  const endpoint = getMagicBlockEndpoint(domain, mode);
  if (!endpoint) {
    throw new Error(
      `Privacy domain "${domain.domainId}" uses ${mode.toUpperCase()} but no MagicBlock ${mode.toUpperCase()} endpoint is configured`
    );
  }
}

export function assertDomainExecutionPolicy(domain: PrivacyDomainConfig): void {
  if (domain.executionMode !== "solana") {
    throw new Error("UTXOpia asset execution must remain on Solana");
  }
  if (domain.kind === "public" && domain.policyMode === "per") {
    throw new Error("Public permissionless domains must not require PER policy");
  }
  if (domain.policyMode === "per" && domain.magicblock?.validatorRegion !== "tee") {
    throw new Error("PER policy domains must use the TEE validator region");
  }
  if (domain.policyMode === "per" && !domain.magicblock?.perUrl) {
    throw new Error(`Privacy domain "${domain.domainId}" requires a PER policy endpoint`);
  }
}

/**
 * Create the delegated-account-aware connection used for public ER traffic.
 * PER uses the authenticated server relay because the kit connection does not
 * expose request headers for the signed-challenge bearer token.
 */
export async function createMagicBlockRouterConnection(
  domain: PrivacyDomainConfig
): Promise<MagicBlockConnection> {
  assertDomainExecutionPolicy(domain);
  if (domain.executionMode !== "er") {
    throw new Error("MagicBlock kit router connections are supported only for public ER domains");
  }
  const routerUrl = domain.magicblock?.routerUrl;
  if (!routerUrl) {
    throw new Error("MagicBlock router URL is required for ER execution");
  }
  return MagicBlockConnection.create(routerUrl, domain.magicblock?.routerWsUrl);
}
