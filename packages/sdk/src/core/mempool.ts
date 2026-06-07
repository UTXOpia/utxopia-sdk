/**
 * Mempool.space API Client for SPV Verification
 *
 * Extended client for fetching Bitcoin SPV proof data.
 * Builds on EsploraClient with additional SPV-specific methods.
 */

import { EsploraClient, type EsploraNetwork, type EsploraMerkleProof } from "./esplora";

// =============================================================================
// Types
// =============================================================================

export interface BlockHeader {
  height: number;
  hash: string;
  version: number;
  previousBlockHash: string;
  merkleRoot: string;
  timestamp: number;
  bits: number;
  nonce: number;
  /** Raw 80-byte header in hex */
  rawHeader: string;
}

export interface TransactionInfo {
  txid: string;
  confirmed: boolean;
  blockHeight?: number;
  blockHash?: string;
  blockTime?: number;
}

export interface SPVProofData {
  txInfo: TransactionInfo;
  blockHeader: BlockHeader;
  merkleProof: EsploraMerkleProof & { blockHash: string };
  confirmations: number;
}

// =============================================================================
// MempoolClient (extends EsploraClient with SPV methods)
// =============================================================================

export class MempoolClient extends EsploraClient {
  constructor(network: EsploraNetwork = "testnet") {
    super(network);
  }

  /**
   * Get transaction info including block hash
   */
  async getTransactionInfo(txid: string): Promise<TransactionInfo> {
    const tx = await this.getTransaction(txid);
    return {
      txid: tx.txid,
      confirmed: tx.status.confirmed,
      blockHeight: tx.status.block_height,
      blockHash: tx.status.block_hash,
      blockTime: tx.status.block_time,
    };
  }

  /**
   * Get block header with raw 80-byte header
   */
  async getBlockHeaderFull(blockHash: string): Promise<BlockHeader> {
    const baseUrl = this.getBaseUrl();

    // Fetch block info
    const blockRes = await fetch(`${baseUrl}/block/${blockHash}`);
    if (!blockRes.ok) {
      throw new Error(`Failed to fetch block: ${blockRes.statusText}`);
    }
    const blockInfo = await blockRes.json();

    // Fetch raw header (80 bytes hex)
    const rawHeader = await this.getBlockHeader(blockHash);

    return {
      height: blockInfo.height,
      hash: blockHash,
      version: blockInfo.version,
      previousBlockHash: blockInfo.previousblockhash,
      merkleRoot: blockInfo.merkle_root,
      timestamp: blockInfo.timestamp,
      bits: blockInfo.bits,
      nonce: blockInfo.nonce,
      rawHeader,
    };
  }

  /**
   * Get block header by height
   */
  async getBlockHeaderByHeight(height: number): Promise<BlockHeader> {
    const blockHash = await this.getBlockHash(height);
    return this.getBlockHeaderFull(blockHash);
  }

  /**
   * Get all data needed for SPV verification
   */
  async getSPVProofData(txid: string): Promise<SPVProofData> {
    // Get transaction info
    const txInfo = await this.getTransactionInfo(txid);

    if (!txInfo.confirmed || !txInfo.blockHash) {
      throw new Error("Transaction not confirmed yet");
    }

    // Get block header
    const blockHeader = await this.getBlockHeaderFull(txInfo.blockHash);

    // Get merkle proof
    const merkleProof = await this.getTxMerkleProof(txid);

    // Get confirmations
    const tipHeight = await this.getBlockHeight();
    const confirmations = tipHeight - txInfo.blockHeight! + 1;

    return {
      txInfo,
      blockHeader,
      merkleProof: {
        ...merkleProof,
        blockHash: txInfo.blockHash,
      },
      confirmations,
    };
  }
}

// =============================================================================
// Utility Functions
// =============================================================================

/**
 * Reverse bytes (for Bitcoin internal byte order)
 */
export function reverseBytes(bytes: Uint8Array): Uint8Array {
  const reversed = new Uint8Array(bytes.length);
  for (let i = 0; i < bytes.length; i++) {
    reversed[i] = bytes[bytes.length - 1 - i];
  }
  return reversed;
}

// hexToBytes / bytesToHex live in ../crypto (single source); re-exported here
// to preserve this module's public surface.
export { hexToBytes, bytesToHex } from "../crypto";

// =============================================================================
// Default Instances
// =============================================================================

export const mempoolTestnet = new MempoolClient("testnet");
export const mempoolMainnet = new MempoolClient("mainnet");
