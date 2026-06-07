/**
 * Sui token-registry reader: enumerate the admin-curated `Coin<T>` allowlist and
 * derive circuit token ids. Mirrors the Solana token-registry reader for the
 * generic shielded pool on Sui.
 *
 * The on-chain `TokenRegistry` stores per-token `TokenCfg` in type-keyed dynamic
 * fields (`ConfigKey<T>`). This reader parses those into `SuiSupportedToken[]`.
 */

import { sha256 } from "@noble/hashes/sha2.js";
import { poseidonHashSync, reduceToField } from "../../sdk/src/poseidon";

/** Parsed on-chain `TokenCfg` for one registered `Coin<T>`. */
export interface SuiSupportedToken {
  /** Fully-qualified Move coin type, e.g. `0x2::sui::SUI`. */
  coinType: string;
  /** Poseidon(reduce_to_field(sha2_256(coinType)), 0) — circuit token id. */
  tokenId: bigint;
  /** Coin decimals (read from CoinMetadata at registration). */
  decimals: number;
  /** Whether shielding is enabled. */
  enabled: boolean;
  /** Minimum shield amount (native units). */
  minDeposit: bigint;
  /** Maximum shield amount (native units). */
  maxDeposit: bigint;
  /** Per-token total-shielded cap (native units). */
  depositCap: bigint;
  /** Current total shielded; equals the live vault `Balance<T>` value. */
  totalShielded: bigint;
  /** Fee in basis points, applied on shield and unshield. */
  feeBps: number;
}

/**
 * Derive the circuit token id for a Sui coin type, matching
 * `bound_params::sui_token_id<T>`: `poseidon(reduce_to_field(sha2_256(typeName)), 0)`.
 *
 * `coinType` MUST be the exact fully-qualified Move type string used on-chain
 * (`type_name::get<T>().into_string()` form — address without `0x`, e.g.
 * `0000…0002::sui::SUI`). The caller is responsible for passing the canonical form.
 */
export function deriveSuiTokenId(coinType: string): bigint {
  const digest = sha256(new TextEncoder().encode(coinType));
  return poseidonHashSync([reduceToField(digest), 0n]);
}

/** Minimal RPC surface needed to read the registry's dynamic fields. */
export interface SuiRegistryReaderClient {
  getDynamicFields(input: {
    parentId: string;
    cursor?: string | null;
  }): Promise<{
    data: Array<{ name: { type: string; value: unknown }; objectId: string }>;
    nextCursor?: string | null;
    hasNextPage: boolean;
  }>;
  getDynamicFieldObject(input: {
    parentId: string;
    name: { type: string; value: unknown };
  }): Promise<{ data?: { content?: unknown } | null }>;
}

// Dynamic-field key type tags: `<pkg>::token_registry::ConfigKey<T>`.
const CONFIG_KEY_RE = /::token_registry::ConfigKey<(.+)>$/;

/**
 * Extract the coin type `T` from a `ConfigKey<T>` dynamic-field name type string.
 * Returns null for non-ConfigKey fields (VaultKey/FeeKey).
 */
function configCoinType(nameType: string): string | null {
  const m = CONFIG_KEY_RE.exec(nameType);
  return m ? m[1] : null;
}

function toBigInt(value: unknown): bigint {
  return BigInt(value as string | number);
}

/** Parse a `TokenCfg` Move struct (move-call JSON `fields`) for a coin type. */
function parseTokenCfg(coinType: string, fields: Record<string, unknown>): SuiSupportedToken {
  return {
    coinType,
    tokenId: toBigInt(fields.token_id),
    decimals: Number(fields.decimals),
    enabled: Boolean(fields.enabled),
    minDeposit: toBigInt(fields.min_deposit),
    maxDeposit: toBigInt(fields.max_deposit),
    depositCap: toBigInt(fields.deposit_cap),
    totalShielded: toBigInt(fields.total_shielded),
    feeBps: Number(fields.fee_bps),
  };
}

/**
 * Read every registered token from the on-chain `TokenRegistry` dynamic fields.
 *
 * @param client - Sui RPC client (getDynamicFields + getDynamicFieldObject).
 * @param registryObjectId - the shared `TokenRegistry` object id.
 */
export async function fetchSuiSupportedTokens(
  client: SuiRegistryReaderClient,
  registryObjectId: string,
): Promise<SuiSupportedToken[]> {
  const tokens: SuiSupportedToken[] = [];
  let cursor: string | null | undefined;

  do {
    const page = await client.getDynamicFields({ parentId: registryObjectId, cursor });
    for (const field of page.data) {
      const coinType = configCoinType(field.name.type);
      if (!coinType) continue; // skip VaultKey/FeeKey entries

      const obj = await client.getDynamicFieldObject({
        parentId: registryObjectId,
        name: field.name,
      });
      const content = obj.data?.content as { fields?: { value?: { fields?: Record<string, unknown> } } } | undefined;
      // Dynamic-field value wraps the stored struct under `value.fields`.
      const cfgFields = content?.fields?.value?.fields;
      if (!cfgFields) continue;
      tokens.push(parseTokenCfg(coinType, cfgFields));
    }
    cursor = page.hasNextPage ? page.nextCursor : null;
  } while (cursor);

  return tokens;
}

/** Enabled-only convenience wrapper. */
export async function fetchSuiEnabledTokens(
  client: SuiRegistryReaderClient,
  registryObjectId: string,
): Promise<SuiSupportedToken[]> {
  const all = await fetchSuiSupportedTokens(client, registryObjectId);
  return all.filter((t) => t.enabled);
}
