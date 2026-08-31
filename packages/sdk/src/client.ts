/**
 * UTXOpiaClient — high-level SDK entry point.
 *
 * Initialize once, use simple methods everywhere. Encapsulates config,
 * keys, Poseidon init, token IDs, and note scanning so consumers don't
 * chain low-level SDK calls.
 *
 * ```typescript
 * const client = await UTXOpiaClient.init({ network: "devnet" });
 * await client.loginWithWallet(wallet);
 * const notes = await client.getNotes();
 * const balance = client.getBalance();
 * ```
 *
 * Phase 1: Init + auth + balance scanning
 * Phase 2: Deposit + shield (future)
 * Phase 3: Transfer + relay (future)
 */

import { initPoseidon, poseidonHashSync } from "./poseidon";
import { computeTokenId, reduceToField } from "./poseidon";
import { initConfig, getConfig, type NetworkConfig, type NetworkId } from "./config";
import { parseMerkleProofResponse } from "./merkle";
import { eddsaPoseidonSign } from "./keys";
import {
  setupKeysFromWallet,
  setupKeysFromSeed,
  setupKeysFromAuthSignature,
  recreateStealthAddress,
  serializeKeysForStorage,
  deserializeKeysFromStorage,
  clearUTXOpiaKeys,
  type AuthSignatureKeyDerivationOptions,
  type UTXOpiaKeys,
  type StealthMetaAddress,
  type WalletSignerAdapter,
  type KeySetupResult,
} from "./keys";
import {
  scanUnifiedNotesMulti,
  scanAnnouncementsViewOnlyMulti,
  computeNullifierHashForNote,
  computeNullifierBytes,
  isDepositForViewerHex,
  createDepositFromConfig,
  createTweakDeposit,
  depositViewingNode,
  createStealthOutputWithKeys,
  type ScannedNote,
  type ViewOnlyKeys,
  type ViewOnlyScannedNote,
  type StealthOutputWithKeys,
  type NonInteractiveDepositResult,
  type TweakDepositResult,
} from "./stealth";
import { selectUtxos, type UtxoDescriptor } from "./psbt";
import { hexToBytes, bytesToHex, bigintToBytes } from "./crypto";
import { getAddressEncoder, type Address } from "@solana/kit";
import { EventClient } from "./event-client";
import { type DepositOpReturnContext, type BitcoinNetwork } from "./taproot";

// ─── Types ──────────────────────────────────────────────────────────

export interface UTXOpiaClientConfig {
  network?: NetworkId;
  /** Override backend URL (default: from network config) */
  backendUrl?: string;
}

export interface TokenDefinition {
  symbol: string;
  shieldedSymbol: string;
  mint: string;
}

export interface InboxNote {
  id: string;
  commitmentHex: string;
  amount: bigint;
  leafIndex: number;
  tokenSymbol: string;
  isSpent: boolean;
  createdAt: number;
  ephemeralPub?: Uint8Array;
  stealthPub?: { x: bigint; y: bigint };
  commitment: Uint8Array;
}

// ─── Client ─────────────────────────────────────────────────────────

let _instance: UTXOpiaClient | null = null;

export class UTXOpiaClient {
  private _keys: UTXOpiaKeys | null = null;
  private _viewOnlyKeys: ViewOnlyKeys | null = null;
  private _isViewOnly = false;
  private _stealthAddress: StealthMetaAddress | null = null;
  private _stealthAddressEncoded: string | null = null;
  private _tokenIdCache = new Map<string, bigint>();
  private _eventClient: EventClient | null = null;
  private _backendUrl: string;
  private _appNetworkId: NetworkId;

  private constructor(backendUrl: string, appNetworkId: NetworkId) {
    this._backendUrl = backendUrl;
    this._appNetworkId = appNetworkId;
  }

  // ─── Lifecycle ──────────────────────────────────────────────────

  /**
   * Initialize the SDK. Call once at app startup.
   * Sets up config, initializes Poseidon hash, creates singleton.
   */
  static async init(opts: UTXOpiaClientConfig = {}): Promise<UTXOpiaClient> {
    // Init config (reads env vars, sets up network)
    if (opts.network) {
      await initConfig({ network: opts.network });
    }

    // Init Poseidon (required before any hashing)
    await initPoseidon();

    const backendUrl = opts.backendUrl || "";
    const appNetworkId = opts.network ||
      (typeof process !== "undefined" && (process.env?.NEXT_PUBLIC_NETWORK || process.env?.UTXOPIA_NETWORK) as NetworkId) ||
      "devnet";
    const client = new UTXOpiaClient(backendUrl, appNetworkId);

    _instance = client;
    return client;
  }

  /**
   * Get the initialized singleton. Throws if init() hasn't been called.
   */
  static instance(): UTXOpiaClient {
    if (!_instance) {
      throw new Error("UTXOpiaClient not initialized. Call UTXOpiaClient.init() first.");
    }
    return _instance;
  }

  /**
   * Check if the client has been initialized.
   */
  static get isInitialized(): boolean {
    return _instance !== null;
  }

  /**
   * Reset the singleton (for testing only).
   */
  static reset(): void {
    if (_instance) {
      _instance.logout();
      _instance._eventClient = null;
    }
    _instance = null;
  }

  // ─── Auth ───────────────────────────────────────────────────────

  /**
   * Derive keys from a Solana wallet signature.
   */
  async loginWithWallet(wallet: WalletSignerAdapter): Promise<KeySetupResult> {
    const result = await setupKeysFromWallet(wallet);
    this._keys = result.keys;
    this._stealthAddress = result.stealthAddress;
    this._stealthAddressEncoded = result.stealthAddressEncoded;
    this._isViewOnly = false;
    this._viewOnlyKeys = null;
    return result;
  }

  /**
   * Derive keys from a seed (passkey PRF output or secret phrase).
   */
  async loginWithSeed(seed: Uint8Array): Promise<KeySetupResult> {
    const result = await setupKeysFromSeed(seed);
    this._keys = result.keys;
    this._stealthAddress = result.stealthAddress;
    this._stealthAddressEncoded = result.stealthAddressEncoded;
    this._isViewOnly = false;
    this._viewOnlyKeys = null;
    return result;
  }

  /**
   * Derive keys from a chain-specific auth signature (wallet personal-message signing).
   */
  async loginWithAuthSignature(
    signature: Uint8Array,
    options: AuthSignatureKeyDerivationOptions = {},
  ): Promise<KeySetupResult> {
    const result = await setupKeysFromAuthSignature(signature, options);
    this._keys = result.keys;
    this._stealthAddress = result.stealthMetaAddress;
    this._stealthAddressEncoded = result.encodedStealthAddress;
    this._isViewOnly = false;
    this._viewOnlyKeys = null;
    return {
      keys: result.keys,
      stealthAddress: result.stealthMetaAddress,
      stealthAddressEncoded: result.encodedStealthAddress,
    };
  }

  /**
   * Restore keys from previously serialized storage (e.g., localStorage).
   * @param serialized — the object from serializeKeys()
   * @param solanaPublicKey — the wallet public key bytes (needed for key reconstruction)
   */
  restoreKeys(serialized: Record<string, unknown>, solanaPublicKey: Uint8Array): void {
    const keys = deserializeKeysFromStorage(serialized as any, solanaPublicKey);
    const { stealthAddress, stealthAddressEncoded } = recreateStealthAddress(keys);
    this._keys = keys;
    this._stealthAddress = stealthAddress;
    this._stealthAddressEncoded = stealthAddressEncoded;
    this._isViewOnly = false;
  }

  /**
   * Login with view-only keys (can scan but not spend).
   */
  loginViewOnly(viewOnlyKeys: ViewOnlyKeys): void {
    this._viewOnlyKeys = viewOnlyKeys;
    this._isViewOnly = true;
    this._keys = null;
  }

  /**
   * Clear all keys and reset auth state.
   */
  logout(): void {
    if (this._keys) {
      clearUTXOpiaKeys(this._keys);
    }
    this._keys = null;
    this._viewOnlyKeys = null;
    this._isViewOnly = false;
    this._stealthAddress = null;
    this._stealthAddressEncoded = null;
  }

  /**
   * Serialize current keys for encrypted storage.
   */
  serializeKeys(): Record<string, unknown> | null {
    if (!this._keys) return null;
    return { ...serializeKeysForStorage(this._keys) };
  }

  // ─── Getters ────────────────────────────────────────────────────

  get keys(): UTXOpiaKeys | null { return this._keys; }
  get stealthAddress(): StealthMetaAddress | null { return this._stealthAddress; }
  get stealthAddressEncoded(): string | null { return this._stealthAddressEncoded; }
  get isAuthenticated(): boolean { return this._keys !== null || this._viewOnlyKeys !== null; }
  get isViewOnly(): boolean { return this._isViewOnly; }
  get config(): NetworkConfig { return getConfig(); }

  // ─── Token IDs ──────────────────────────────────────────────────

  /**
   * Get token ID for a mint address. Cached after first computation.
   */
  getTokenId(mintAddress: string): bigint {
    const cached = this._tokenIdCache.get(mintAddress);
    if (cached !== undefined) return cached;

    // 64 hex chars is a raw token id; anything else is a base58 mint.
    //
    // Decoded with getAddressEncoder, the same path pda.ts uses, because
    // require("@solana/web3.js") is not callable from an ESM browser bundle —
    // it threw for every base58 mint, and the hex fallback behind it threw
    // again on the same input. There is no fallback now: both branches are
    // total for their input, and a malformed mint should raise, not be padded
    // into a different token's id.
    const bytes =
      mintAddress.length === 64 && /^[0-9a-fA-F]+$/.test(mintAddress)
        ? hexToBytes(mintAddress)
        : new Uint8Array(getAddressEncoder().encode(mintAddress as Address));

    const tokenId = computeTokenId(bytes);
    this._tokenIdCache.set(mintAddress, tokenId);
    return tokenId;
  }

  /**
   * Register multiple tokens for scanning. Caches their token IDs.
   */
  registerTokens(tokens: TokenDefinition[]): void {
    const config = getConfig();
    for (const token of tokens) {
      let mint = token.mint;
      if (!mint && (token.symbol === "BTC" || token.symbol === "zkBTC")) {
        mint = config.zkbtcMint;
      }
      if (!mint) continue;
      this.getTokenId(mint); // triggers computation + cache
    }
  }

  // ─── Note Scanning ─────────────────────────────────────────────

  /**
   * Scan for all notes belonging to the authenticated user.
   * Fetches announcements from backend, scans locally for privacy.
   */
  async getNotes(tokens: TokenDefinition[]): Promise<InboxNote[]> {
    if (!this._keys && !this._viewOnlyKeys) return [];

    // Fetch announcements via EventClient
    const client = this.getEventClient();
    const announcements = await client.fetchAll();

    // One trial-decrypt per announcement, tested against every token id — not
    // one full scan pass per token.
    const config = getConfig();
    type ScannedWithToken = (ScannedNote | ViewOnlyScannedNote) & { tokenSymbol: string };
    const symbolByTokenId = new Map<bigint, string>();

    for (const token of tokens) {
      let mint = token.mint;
      if (!mint && (token.symbol === "BTC" || token.symbol === "zkBTC")) {
        mint = config.zkbtcMint;
      }
      if (!mint) continue;
      const tokenId = this.getTokenId(mint);
      // First token wins the id, matching the old loop's dedup order.
      if (!symbolByTokenId.has(tokenId)) symbolByTokenId.set(tokenId, token.shieldedSymbol);
    }

    const tokenIds = [...symbolByTokenId.keys()];
    const matches = this._isViewOnly && this._viewOnlyKeys
      ? await scanAnnouncementsViewOnlyMulti(this._viewOnlyKeys, announcements, tokenIds)
      : await scanUnifiedNotesMulti(this._keys!, announcements, tokenIds);

    const scanned: ScannedWithToken[] = matches.map((note) => ({
      ...note,
      tokenSymbol: symbolByTokenId.get(note.tokenId)!,
    }) as ScannedWithToken);

    // Convert to InboxNote format
    return scanned.map((note, index) => {
      const rawHex = Buffer.from(note.commitment).toString("hex");
      const commitmentHex = rawHex.toLowerCase().padStart(64, "0");

      return {
        id: `${commitmentHex.slice(0, 16)}-${index}`,
        commitmentHex,
        amount: typeof note.amount === "bigint" ? note.amount : BigInt(note.amount),
        leafIndex: note.leafIndex,
        tokenSymbol: note.tokenSymbol,
        isSpent: false, // caller checks spent status separately
        createdAt: (note as any).blockTime ? (note as any).blockTime * 1000 : Date.now(),
        ephemeralPub: note.ephemeralPub,
        stealthPub: (note as ScannedNote).stealthPub,
        commitment: note.commitment,
      };
    });
  }

  /**
   * Get balance per token from unspent notes.
   */
  getBalance(notes: InboxNote[]): Map<string, bigint> {
    const balances = new Map<string, bigint>();
    for (const note of notes) {
      if (note.isSpent) continue;
      const current = balances.get(note.tokenSymbol) ?? 0n;
      balances.set(note.tokenSymbol, current + note.amount);
    }
    return balances;
  }

  /**
   * Check if a deposit announcement belongs to this user (hex string inputs).
   */
  isMyDeposit(ephemeralPubHex: string, npkHex: string): boolean {
    if (!this._keys) return false;
    return isDepositForViewerHex(this._keys, ephemeralPubHex, npkHex);
  }

  /**
   * Compute nullifier bytes for a note (for PDA existence checking).
   */
  computeNullifier(note: { leafIndex: number }): Uint8Array {
    if (this._isViewOnly && this._viewOnlyKeys) {
      return computeNullifierBytes(this._viewOnlyKeys.nullifyingKey, note.leafIndex);
    }
    if (this._keys) {
      return computeNullifierHashForNote(this._keys, note as ScannedNote);
    }
    throw new Error("Not authenticated");
  }

  // ─── Phase 2: Deposit + Shield ─────────────────────────────────

  /**
   * Prepare an OP_RETURN-free BTC deposit address (`verify_deposit`, disc 25).
   *
   * The ephemeral key is derived from this wallet's own viewing node and
   * `depositIndex`, never randomly. A deposit address commits to the ephemeral
   * key through its tapleaf and its key path is a NUMS point, so an address whose
   * ephemeral key is lost is one nobody can ever spend. Indexing it makes the
   * viewing key a complete backup: walk `depositIndex` upward and every address
   * comes back.
   *
   * Self-deposit only. The address is recovered by whoever holds the viewing key
   * it was derived from, so generating one *for someone else* would hand them a
   * note they own but coins they could never recover. Pay a third party with a
   * shielded transfer instead.
   *
   * `depositIndex` must be persisted and monotonic. Reusing one re-derives the
   * same address, which is safe on chain but links the two deposits.
   */
  async prepareTweakDeposit(opts: {
    depositIndex: number;
    ikaXOnlyPubkey: Uint8Array;
    recipient?: StealthMetaAddress;
    network?: BitcoinNetwork;
  }): Promise<TweakDepositResult> {
    if (!this._keys) {
      throw new Error("No keys (login first)");
    }
    const meta = opts.recipient ?? this._stealthAddress;
    if (!meta) throw new Error("No recipient stealth address (login first or provide recipient)");
    if (opts.recipient && this._stealthAddress && opts.recipient !== this._stealthAddress) {
      throw new Error(
        "prepareTweakDeposit is self-deposit only: the recipient must be able to derive the " +
          "ephemeral key to recover the coins, and only this wallet's viewing key can",
      );
    }

    const network = opts.network ?? sdkBitcoinNetworkToAddressNetwork(this.config.bitcoinNetwork);
    return createTweakDeposit(
      meta,
      opts.ikaXOnlyPubkey,
      {
        viewingNode: depositViewingNode(this._keys.viewingPrivKey),
        depositIndex: opts.depositIndex,
      },
      network,
    );
  }

  /**
   * Prepare a BTC deposit: generate stealth deposit address + OP_RETURN.
   * Returns the deposit result (btcAddress, opReturnPayload) ready for PSBT building.
   */
  async prepareDeposit(opts: {
    recipient?: StealthMetaAddress;
    network?: BitcoinNetwork;
    opReturnContext: DepositOpReturnContext;
  }): Promise<NonInteractiveDepositResult> {
    const meta = opts.recipient ?? this._stealthAddress;
    if (!meta) throw new Error("No recipient stealth address (login first or provide recipient)");
    const network = opts.network ?? sdkBitcoinNetworkToAddressNetwork(this.config.bitcoinNetwork);
    if (!opts.opReturnContext) {
      throw new Error("deposit OP_RETURN context is required");
    }
    return createDepositFromConfig(meta, network, opts.opReturnContext);
  }

  /**
   * Select UTXOs for a deposit amount. Returns the selected UTXO set.
   */
  selectUtxos(utxos: UtxoDescriptor[], targetSats: number, feeRate = 2): UtxoDescriptor[] {
    return selectUtxos(utxos, targetSats, feeRate);
  }

  /**
   * Prepare a stealth output for shielding (SPL token → shielded commitment).
   * Returns npkBytes, ephemeralPub, commitment, tokenId — everything needed
   * for the on-chain shield instruction.
   */
  async prepareShieldOutput(opts: {
    amount: bigint;
    mintAddress: string;
    recipient?: UTXOpiaKeys;
  }): Promise<StealthOutputWithKeys & { tokenId: bigint }> {
    const keys = opts.recipient ?? this._keys;
    if (!keys) throw new Error("No keys (login first or provide recipient)");
    const tokenId = this.getTokenId(opts.mintAddress);
    const output = await createStealthOutputWithKeys(keys, opts.amount, tokenId);
    return { ...output, tokenId };
  }

  // ─── Phase 3: Transfer + Relay ─────────────────────────────────

  /**
   * Fetch merkle proofs for multiple commitments.
   * Used before proof generation to get the on-chain tree state.
   *
   * @param commitmentHexes - Array of commitment hex strings
   * @param apiBaseUrl - Base URL for the merkle proof API (default: "" for same-origin)
   */
  async fetchMerkleProofs(
    commitmentHexes: string[],
    apiBaseUrl = "",
  ): Promise<
    Array<{
      commitmentHex: string;
      root: bigint;
      pathElements: bigint[];
      pathIndices: number[];
    }>
  > {
    const results = await Promise.all(
      commitmentHexes.map(async (hex) => {
        const resp = await fetch(
          `${apiBaseUrl}/api/merkle/proof?commitment=${hex}`,
        );
        const data = await resp.json();
        if (!data.success) {
          throw new Error(`Note ${hex.slice(0, 16)}... not found on-chain`);
        }
        const parsed = parseMerkleProofResponse(data);
        return { commitmentHex: hex, ...parsed };
      }),
    );

    // Validate all proofs share the same root
    const roots = results.map((r) => r.root);
    if (new Set(roots.map((r) => r.toString())).size > 1) {
      throw new Error(
        "Input notes have different Merkle roots — tree may have changed",
      );
    }

    return results;
  }

  /**
   * Hash transaction inputs and sign with EdDSA-Poseidon.
   *
   * @param msgHashInputs - Array of bigints to hash (merkleRoot, boundParamsHash, nullifiers, commitments)
   * @param eddsaSeed - The EdDSA seed bytes (from UTXOpiaKeys.eddsaSeed)
   */
  async signTransaction(
    msgHashInputs: bigint[],
    eddsaSeed: Uint8Array,
  ): Promise<{
    sigR8x: bigint;
    sigR8y: bigint;
    sigS: bigint;
    msgHash: bigint;
  }> {
    const msgHash = poseidonHashSync(msgHashInputs);
    const [sigR8x, sigR8y, sigS] = await eddsaPoseidonSign(
      eddsaSeed,
      msgHash,
    );
    return { sigR8x, sigR8y, sigS, msgHash };
  }

  /**
   * Submit a JoinSplit transaction to the relay backend.
   *
   * @param payload - Transaction data including proof, nullifiers, commitments, and mode-specific fields
   * @param relayUrl - URL for the relay endpoint (default is chain-aware from init network)
   */
  async submitToRelay(
    payload: {
      mode: "transfer" | "unshield" | "redeem";
      nInputs: number;
      nOutputs: number;
      proof: string;
      merkleRoot: string;
      boundParamsHash: string;
      nullifiers: string[];
      commitmentsOut: string[];
      stealthData: string[];
      // Transfer-specific
      relayerFeeOutputIndex?: number;
      /**
       * Optional Phase 2 sender memos — one 80-byte hex string per output
       * (nonce(24) || ciphertext_and_tag(56)). Compose with the SDK helper
       * `buildSenderMemosForTransact(viewingPrivKey, outputs)`. The relay
       * forwards them opaquely; viewing keys stay client-side.
       */
      senderMemos?: string[];
      // Unshield-specific
      unshieldAmounts?: string[];
      recipientAddresses?: string[];
      recipientTokenAccounts?: string[];
      // Redeem-specific
      redeemAmounts?: string[];
      btcScripts?: string[];
      requestNonces?: string[];
      /**
       * Optional frozen source-tree PDA (base58). Set only when a spent note was committed in a
       * commitment tree that has since been rotated out; the relay inserts it before the proof
       * buffer so the program can prove membership against that tree. Omit otherwise.
       */
      sourceTree?: string;
    },
    relayUrl = this.defaultRelayUrl(),
  ): Promise<{ success: boolean; signature?: string; error?: string }> {
    const resp = await fetch(relayUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    return resp.json();
  }

  // ─── Private helpers ────────────────────────────────────────────

  private getEventClient(): EventClient {
    if (!this._eventClient) {
      const config = getConfig();
      this._eventClient = new EventClient({
        backendUrl: this._backendUrl,
        solanaRpcUrl: config.solanaRpcUrl || "",
        programId: config.utxopiaProgramId,
      });
    }
    return this._eventClient;
  }

  private defaultRelayUrl(): string {
    return `/api/sol/relay?network=${encodeURIComponent(this._appNetworkId)}`;
  }
}

function sdkBitcoinNetworkToAddressNetwork(network: NetworkConfig["bitcoinNetwork"]): BitcoinNetwork {
  if (network === "mainnet") return "mainnet";
  if (network === "regtest") return "regtest";
  return "testnet";
}
