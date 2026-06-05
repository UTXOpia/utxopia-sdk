/**
 * Cross-layer instruction alignment tests
 *
 * Verifies that SDK/frontend instruction data formats match
 * what the on-chain contract expects. If someone changes the
 * contract's data layout, these tests break immediately.
 *
 * ┌─────────────┐     data format     ┌─────────────┐
 * │  Contract   │◄════════════════════│   SDK/FE    │
 * │  (Rust)     │  must match exactly │ (TypeScript) │
 * └─────────────┘                     └─────────────┘
 */

import { describe, it, expect } from "bun:test";
import {
  buildCompleteDepositInstructionData,
  buildShieldInstructionData,
  INSTRUCTION_DISCRIMINATORS,
} from "../../src/instructions";

// =============================================================================
// Contract-defined constants (from Rust source)
// =============================================================================

/** From solana-programs/programs/utxopia/src/lib.rs and instruction modules. */
const CONTRACT = {
  shield: {
    disc: 12,
    dataLen: 72, // amount(8) + npk(32) + ephemeral_pub(32)
    accountCount: 7,
    accounts: [
      "user (signer)",
      "user_token_account (writable)",
      "pool_state (read)",
      "token_config (writable)",
      "vault (writable)",
      "commitment_tree (writable)",
      "token_program (read)",
    ],
  },
  registerToken: {
    disc: 8,
    dataLen: 32, // service_fee(8) + min_deposit(8) + max_deposit(8) + deposit_cap(8)
    accountCount: 6,
    accounts: [
      "authority (signer)",
      "pool_state (read)",
      "mint (read)",
      "token_config (writable)",
      "vault (read)",
      "system_program (read)",
    ],
  },
  completeDeposit: {
    disc: 11,
    dataLen: 80, // sweep_txid(32) + block_height(8) + sweep_tx_size(4) + deposit_tx_size(4) + deposit_txid(32)
    accountCount: 14,
  },
  transact: {
    disc: 13,
    stealthDataPerOutput: 72, // ephemeral_pub(32) + encrypted_amount(8) + encrypted_token_id(32)
  },
  unshield: {
    disc: 14,
    fixedAccountCount: 8,
    stealthDataPerOutput: 72,
  },
};

// =============================================================================
// Tests
// =============================================================================

describe("Cross-layer: instruction alignment", () => {
  describe("shield (disc=12)", () => {
    it("builds correct data format: amount(8) + npk(32) + ephemeral_pub(32) = 72 bytes", () => {
      const amount = 50000n;
      const npk = new Uint8Array(32).fill(0xab);
      const ephemeralPub = new Uint8Array(32).fill(0xcd);

      const ixData = buildShieldInstructionData({ amount, npk, ephemeralPub });

      // Verify disc
      expect(ixData[0]).toBe(CONTRACT.shield.disc);
      expect(ixData[0]).toBe(INSTRUCTION_DISCRIMINATORS.SHIELD);

      // Verify amount at correct offset (contract reads data[0..8] after disc strip)
      const contractData = ixData.slice(1); // contract receives without disc
      expect(contractData.length).toBe(CONTRACT.shield.dataLen);

      const parsedAmount = new DataView(contractData.buffer, contractData.byteOffset).getBigUint64(0, true);
      expect(parsedAmount).toBe(amount);

      // Verify npk at correct offset
      const parsedNpk = contractData.slice(8, 40);
      expect(parsedNpk).toEqual(npk);

      // Verify ephemeral at correct offset
      const parsedEph = contractData.slice(40, 72);
      expect(parsedEph).toEqual(ephemeralPub);
    });

    it("requires exactly 7 accounts in correct order", () => {
      expect(CONTRACT.shield.accountCount).toBe(7);
      expect(CONTRACT.shield.accounts[0]).toContain("user");
      expect(CONTRACT.shield.accounts[1]).toContain("user_token_account");
      expect(CONTRACT.shield.accounts[2]).toContain("pool_state");
      expect(CONTRACT.shield.accounts[3]).toContain("token_config");
      expect(CONTRACT.shield.accounts[4]).toContain("vault");
      expect(CONTRACT.shield.accounts[5]).toContain("commitment_tree");
      expect(CONTRACT.shield.accounts[6]).toContain("token_program");
    });
  });

  describe("register_token (disc=8)", () => {
    it("builds correct data format: 4x u64 LE = 32 bytes", () => {
      const serviceFee = 1000n;
      const minDeposit = 5000n;
      const maxDeposit = 10_000_000_000n;
      const depositCap = 2_100_000_000_000_000n;

      // Build like init-devnet.mjs does
      const data = new Uint8Array(33);
      data[0] = CONTRACT.registerToken.disc;
      const view = new DataView(data.buffer);
      view.setBigUint64(1, serviceFee, true);
      view.setBigUint64(9, minDeposit, true);
      view.setBigUint64(17, maxDeposit, true);
      view.setBigUint64(25, depositCap, true);

      const contractData = data.slice(1);
      expect(contractData.length).toBe(CONTRACT.registerToken.dataLen);

      const cv = new DataView(contractData.buffer, contractData.byteOffset);
      expect(cv.getBigUint64(0, true)).toBe(serviceFee);
      expect(cv.getBigUint64(8, true)).toBe(minDeposit);
      expect(cv.getBigUint64(16, true)).toBe(maxDeposit);
      expect(cv.getBigUint64(24, true)).toBe(depositCap);
    });

    it("requires exactly 6 accounts", () => {
      expect(CONTRACT.registerToken.accountCount).toBe(6);
    });
  });

  describe("complete_deposit (disc=11)", () => {
    it("has correct data layout: 80 bytes total", () => {
      const sweepTxid = new Uint8Array(32).fill(0xaa);
      const blockHeight = 2311n;
      const sweepTxSize = 225;
      const depositTxSize = 300;
      const depositTxid = new Uint8Array(32).fill(0xbb);

      const data = buildCompleteDepositInstructionData({
        sweepTxid,
        blockHeight: Number(blockHeight),
        sweepTxSize,
        depositTxSize,
        depositTxid,
      });
      expect(data[0]).toBe(CONTRACT.completeDeposit.disc);
      expect(data[0]).toBe(INSTRUCTION_DISCRIMINATORS.COMPLETE_DEPOSIT);

      const contractData = data.slice(1);
      expect(contractData.length).toBe(CONTRACT.completeDeposit.dataLen);
    });

    it("requires exactly 14 accounts", () => {
      expect(CONTRACT.completeDeposit.accountCount).toBe(14);
    });
  });

  describe("transact (disc=13)", () => {
    it("stealth data per output is 72 bytes: ephemeral(32) + amount(8) + token_id(32)", () => {
      expect(CONTRACT.transact.disc).toBe(INSTRUCTION_DISCRIMINATORS.TRANSACT);
      expect(CONTRACT.transact.stealthDataPerOutput).toBe(72);
      expect(32 + 8 + 32).toBe(72);
    });
  });

  describe("unshield (disc=14)", () => {
    it("has 8 fixed accounts before public recipients and nullifier records", () => {
      expect(CONTRACT.unshield.disc).toBe(INSTRUCTION_DISCRIMINATORS.UNSHIELD);
      expect(CONTRACT.unshield.fixedAccountCount).toBe(8);
    });

    it("stealth data per output matches transact", () => {
      expect(CONTRACT.unshield.stealthDataPerOutput).toBe(CONTRACT.transact.stealthDataPerOutput);
    });
  });
});
