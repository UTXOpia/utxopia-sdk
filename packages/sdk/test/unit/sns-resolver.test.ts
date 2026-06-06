import { describe, it, expect } from "bun:test";
import {
  parseSnsStealthData,
  isAuditorDisclosable,
  SnsComplianceFlags,
  SNS_STEALTH_DATA_SIZE,
  SNS_COMPLIANCE_AUDITOR_OFFSET,
  SNS_COMPLIANCE_AUDITOR_BYTES,
  type SnsStealthAddress,
} from "../../src/sns-resolver";

const SNS_HEADER_SIZE = 96;

/** Build a synthetic SNS account: header + payload. Header bytes are
 *  irrelevant to the parser (it skips them), so they're zero-filled here. */
function buildAccount(payload: Uint8Array): Uint8Array {
  const out = new Uint8Array(SNS_HEADER_SIZE + payload.length);
  out.set(payload, SNS_HEADER_SIZE);
  return out;
}

/** Current stealth payload with optional trailing flag byte and
 *  optional 32-byte auditor pubkey after that. */
function currentPayload(opts: {
  viewingPubKey?: Uint8Array;
  mpk?: Uint8Array;
  trailingFlag?: number;
  auditorPubkey?: Uint8Array;
}): Uint8Array {
  const viewing = opts.viewingPubKey ?? new Uint8Array(32).fill(0x11);
  const mpk = opts.mpk ?? new Uint8Array(32).fill(0x22);
  const hasFlag = opts.trailingFlag !== undefined;
  const hasAuditor = opts.auditorPubkey !== undefined;
  const size =
    SNS_STEALTH_DATA_SIZE +
    (hasFlag ? 1 : 0) +
    (hasAuditor ? SNS_COMPLIANCE_AUDITOR_BYTES : 0);
  const buf = new Uint8Array(size);
  buf[0] = 2; // version
  buf.set(viewing, 1);
  buf.set(mpk, 33);
  if (hasFlag) {
    buf[SNS_STEALTH_DATA_SIZE] = opts.trailingFlag!;
  }
  if (hasAuditor) {
    buf.set(opts.auditorPubkey!, SNS_COMPLIANCE_AUDITOR_OFFSET);
  }
  return buf;
}

describe("parseSnsStealthData — compliance flags", () => {
  it("returns complianceFlags=0 for a base 65-byte payload with no extra byte", () => {
    const parsed = parseSnsStealthData(buildAccount(currentPayload({})));
    expect(parsed).not.toBeNull();
    expect(parsed!.complianceFlags).toBe(0);
    expect(parsed!.version).toBe(2);
  });

  it("reads complianceFlags from the optional 66-byte payload", () => {
    const parsed = parseSnsStealthData(
      buildAccount(currentPayload({ trailingFlag: SnsComplianceFlags.AUDITOR_DISCLOSABLE })),
    );
    expect(parsed).not.toBeNull();
    expect(parsed!.complianceFlags).toBe(SnsComplianceFlags.AUDITOR_DISCLOSABLE);
  });

  it("preserves unrelated bits (forward-compat for future flag bits)", () => {
    // 0b00000110 — bits 1 and 2 set; bit 0 (AUDITOR_DISCLOSABLE) clear.
    // The reader should still surface the raw byte; only `isAuditorDisclosable`
    // narrows to bit 0.
    const parsed = parseSnsStealthData(buildAccount(currentPayload({ trailingFlag: 0b110 })));
    expect(parsed!.complianceFlags).toBe(0b110);
  });

  it("rejects accounts that are too small to hold a stealth payload", () => {
    // Header + 64 bytes < required 65; null.
    const tiny = new Uint8Array(SNS_HEADER_SIZE + SNS_STEALTH_DATA_SIZE - 1);
    expect(parseSnsStealthData(tiny)).toBeNull();
  });
});

describe("parseSnsStealthData — auditor pubkey", () => {
  it("reads the auditor pubkey when the payload carries one", () => {
    const auditor = new Uint8Array(32).fill(0xaf);
    const parsed = parseSnsStealthData(
      buildAccount(currentPayload({
        trailingFlag: SnsComplianceFlags.AUDITOR_DISCLOSABLE,
        auditorPubkey: auditor,
      })),
    );
    expect(parsed).not.toBeNull();
    expect(parsed!.complianceFlags).toBe(SnsComplianceFlags.AUDITOR_DISCLOSABLE);
    expect(parsed!.auditorPubkey).toEqual(auditor);
  });

  it("treats an all-zero auditor pubkey as 'not set'", () => {
    // Recipient set the flag bit but provided no auditor — surface only
    // the flag, leave auditorPubkey undefined so callers don't render an
    // empty address.
    const parsed = parseSnsStealthData(
      buildAccount(currentPayload({
        trailingFlag: SnsComplianceFlags.AUDITOR_DISCLOSABLE,
        auditorPubkey: new Uint8Array(32), // all zeros
      })),
    );
    expect(parsed!.auditorPubkey).toBeUndefined();
    expect(parsed!.complianceFlags).toBe(SnsComplianceFlags.AUDITOR_DISCLOSABLE);
  });

  it("leaves auditorPubkey undefined on a flag-only payload", () => {
    const parsed = parseSnsStealthData(
      buildAccount(currentPayload({ trailingFlag: SnsComplianceFlags.AUDITOR_DISCLOSABLE })),
    );
    expect(parsed!.auditorPubkey).toBeUndefined();
    expect(parsed!.complianceFlags).toBe(SnsComplianceFlags.AUDITOR_DISCLOSABLE);
  });

  it("rejects version 1 records instead of parsing old layouts", () => {
    const payload = currentPayload({});
    payload[0] = 1;

    expect(parseSnsStealthData(buildAccount(payload))).toBeNull();
  });
});

describe("isAuditorDisclosable", () => {
  function fakeAddr(flags: number): SnsStealthAddress {
    return {
      name: "alice",
      fullDomain: "alice.utxopia.sol",
      viewingPubKey: new Uint8Array(32),
      mpk: new Uint8Array(32),
      version: 2,
      complianceFlags: flags,
    };
  }

  it("true only when bit 0 is set", () => {
    expect(isAuditorDisclosable(fakeAddr(0))).toBe(false);
    expect(isAuditorDisclosable(fakeAddr(SnsComplianceFlags.AUDITOR_DISCLOSABLE))).toBe(true);
    // Other bits don't trigger it
    expect(isAuditorDisclosable(fakeAddr(0b10))).toBe(false);
    // Bit 0 still wins even when other bits are set
    expect(isAuditorDisclosable(fakeAddr(0b11))).toBe(true);
  });
});
