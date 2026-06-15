/**
 * Tests for parseAuditorCiphertextEvent and auditorCiphertextFromSuiEventFields.
 *
 * Method-Y permissioned-pool auditor-ciphertext event parsing (Task 3).
 */

import { describe, test, expect } from "bun:test";
import { ed25519GenerateKeyPair } from "../../src/crypto-ed25519";
import { encryptAuditorCiphertext } from "../../src/auditor-ciphertext";
import {
  parseAuditorCiphertextEvent,
  auditorCiphertextFromSuiEventFields,
  EVENT_AUDITOR_CIPHERTEXT,
  type AuditorCiphertextEvent,
} from "../../src/events";

// =============================================================================
// Helpers
// =============================================================================

const COMMITMENT = new Uint8Array(32).fill(0xcc);

/** Build a real 112-byte blob via encryptAuditorCiphertext. */
function makeBlob(): Uint8Array {
  const { pubKey } = ed25519GenerateKeyPair();
  return encryptAuditorCiphertext(pubKey, { tokenId: 1n, amount: 100n }, COMMITMENT);
}

/** Build the 3-segment set expected by parseAuditorCiphertextEvent. */
function makeSegments(
  discByte: number = EVENT_AUDITOR_CIPHERTEXT,
  commitment: Uint8Array = COMMITMENT,
  blob: Uint8Array = makeBlob(),
): Uint8Array[] {
  return [new Uint8Array([discByte]), commitment, blob];
}

// =============================================================================
// parseAuditorCiphertextEvent — happy path
// =============================================================================

describe("parseAuditorCiphertextEvent", () => {
  test("returns correct commitment and blob for valid segments", () => {
    const blob = makeBlob();
    const segments = makeSegments(EVENT_AUDITOR_CIPHERTEXT, COMMITMENT, blob);

    const event = parseAuditorCiphertextEvent(segments);
    expect(event).not.toBeNull();
    expect(event!.type).toBe("auditor_ciphertext");
    expect(event!.commitment).toEqual(COMMITMENT);
    expect(event!.blob).toEqual(blob);
  });

  // =============================================================================
  // parseAuditorCiphertextEvent — wrong discriminant
  // =============================================================================

  test("returns null for wrong discriminant", () => {
    const segments = makeSegments(0x99);
    expect(parseAuditorCiphertextEvent(segments)).toBeNull();
  });

  test("returns null for discriminant 0x00", () => {
    const segments = makeSegments(0x00);
    expect(parseAuditorCiphertextEvent(segments)).toBeNull();
  });

  // =============================================================================
  // parseAuditorCiphertextEvent — wrong lengths
  // =============================================================================

  test("returns null when commitment is too short (31 bytes)", () => {
    const segments = makeSegments(
      EVENT_AUDITOR_CIPHERTEXT,
      new Uint8Array(31).fill(0xcc),
      makeBlob(),
    );
    expect(parseAuditorCiphertextEvent(segments)).toBeNull();
  });

  test("returns null when commitment is too long (33 bytes)", () => {
    const segments = makeSegments(
      EVENT_AUDITOR_CIPHERTEXT,
      new Uint8Array(33).fill(0xcc),
      makeBlob(),
    );
    expect(parseAuditorCiphertextEvent(segments)).toBeNull();
  });

  test("returns null when blob is too short (111 bytes)", () => {
    const segments = makeSegments(
      EVENT_AUDITOR_CIPHERTEXT,
      COMMITMENT,
      new Uint8Array(111).fill(0xaa),
    );
    expect(parseAuditorCiphertextEvent(segments)).toBeNull();
  });

  test("returns null when blob is too long (113 bytes)", () => {
    const segments = makeSegments(
      EVENT_AUDITOR_CIPHERTEXT,
      COMMITMENT,
      new Uint8Array(113).fill(0xaa),
    );
    expect(parseAuditorCiphertextEvent(segments)).toBeNull();
  });

  // =============================================================================
  // parseAuditorCiphertextEvent — too few segments
  // =============================================================================

  test("returns null when fewer than 3 segments supplied", () => {
    expect(parseAuditorCiphertextEvent([])).toBeNull();
    expect(
      parseAuditorCiphertextEvent([new Uint8Array([EVENT_AUDITOR_CIPHERTEXT])]),
    ).toBeNull();
    expect(
      parseAuditorCiphertextEvent([
        new Uint8Array([EVENT_AUDITOR_CIPHERTEXT]),
        COMMITMENT,
      ]),
    ).toBeNull();
  });

  // =============================================================================
  // parseAuditorCiphertextEvent — disc segment wrong length
  // =============================================================================

  test("returns null when disc segment has wrong length (2 bytes)", () => {
    const segments: Uint8Array[] = [
      new Uint8Array([EVENT_AUDITOR_CIPHERTEXT, 0x00]),
      COMMITMENT,
      makeBlob(),
    ];
    expect(parseAuditorCiphertextEvent(segments)).toBeNull();
  });
});

// =============================================================================
// auditorCiphertextFromSuiEventFields
// =============================================================================

describe("auditorCiphertextFromSuiEventFields", () => {
  test("normalizes number[] fields into Uint8Array and returns correct event", () => {
    const blob = makeBlob();
    const fields = {
      commitment: Array.from(COMMITMENT),
      auditor_ciphertext: Array.from(blob),
    };

    const event = auditorCiphertextFromSuiEventFields(fields);
    expect(event).not.toBeNull();
    expect(event!.type).toBe("auditor_ciphertext");
    expect(event!.commitment).toEqual(COMMITMENT);
    expect(event!.blob).toEqual(blob);
  });

  test("accepts Uint8Array fields directly", () => {
    const blob = makeBlob();
    const fields = {
      commitment: COMMITMENT,
      auditor_ciphertext: blob,
    };

    const event = auditorCiphertextFromSuiEventFields(fields);
    expect(event).not.toBeNull();
    expect(event!.commitment).toEqual(COMMITMENT);
    expect(event!.blob).toEqual(blob);
  });

  test("falls back to note field when commitment is absent", () => {
    const blob = makeBlob();
    const fields = {
      note: Array.from(COMMITMENT),
      auditor_ciphertext: Array.from(blob),
    };

    const event = auditorCiphertextFromSuiEventFields(fields);
    expect(event).not.toBeNull();
    expect(event!.commitment).toEqual(COMMITMENT);
  });

  test("returns null when auditor_ciphertext has wrong length (111 bytes)", () => {
    const fields = {
      commitment: Array.from(COMMITMENT),
      auditor_ciphertext: new Array(111).fill(0),
    };
    expect(auditorCiphertextFromSuiEventFields(fields)).toBeNull();
  });

  test("returns null when commitment has wrong length (31 bytes)", () => {
    const blob = makeBlob();
    const fields = {
      commitment: new Array(31).fill(0),
      auditor_ciphertext: Array.from(blob),
    };
    expect(auditorCiphertextFromSuiEventFields(fields)).toBeNull();
  });

  test("returns null when commitment is missing and note is absent", () => {
    const blob = makeBlob();
    const fields = {
      auditor_ciphertext: Array.from(blob),
    };
    expect(auditorCiphertextFromSuiEventFields(fields)).toBeNull();
  });
});
