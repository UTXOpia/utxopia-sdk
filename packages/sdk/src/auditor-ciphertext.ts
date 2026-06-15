/**
 * Auditor ciphertext — ECDH encrypt-to-auditor for Method-Y permissioned pools.
 *
 * Lets a depositor encrypt note viewing data (tokenId, amount) TO a permissioned-pool
 * auditor's Ed25519 viewing PUBLIC key. Only the auditor's private key can decrypt.
 *
 * Cipher: X25519 ECDH key-agreement + XChaCha20-Poly1305 AEAD.
 *
 * Wire format (112 bytes):
 *   eph_pub        :: 32 bytes  (ephemeral X25519 public key)
 *   nonce          :: 24 bytes  (random XChaCha20 nonce)
 *   ciphertext_tag :: 56 bytes  (encrypted tokenId(32 BE) || amount(8 LE) + Poly1305 tag(16))
 */

import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { x25519 } from "@noble/curves/ed25519.js";
import {
  ed25519PubToX25519,
  ed25519PrivToX25519,
  x25519PubFromPriv,
} from "./crypto-ed25519";

const DOMAIN = new TextEncoder().encode("utxopia.auditor-ciphertext.v1");

const EPH_PUB_BYTES = 32;
const NONCE_BYTES = 24;
const PLAINTEXT_BYTES = 40; // tokenId(32) + amount(8)
const TAG_BYTES = 16;
const CT_WITH_TAG_BYTES = PLAINTEXT_BYTES + TAG_BYTES; // 56
export const AUDITOR_CIPHERTEXT_BYTES = EPH_PUB_BYTES + NONCE_BYTES + CT_WITH_TAG_BYTES; // 112

export interface AuditorNotePlain {
  tokenId: bigint;
  amount: bigint;
}

function deriveKey(shared: Uint8Array): Uint8Array {
  const buf = new Uint8Array(shared.length + DOMAIN.length);
  buf.set(shared, 0);
  buf.set(DOMAIN, shared.length);
  return sha256(buf);
}

function packPlaintext(plain: AuditorNotePlain): Uint8Array {
  const out = new Uint8Array(PLAINTEXT_BYTES);
  // tokenId: 32 bytes big-endian
  let t = plain.tokenId;
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(t & 0xffn);
    t >>= 8n;
  }
  if (t !== 0n) throw new RangeError("tokenId exceeds 256 bits");
  // amount: 8 bytes little-endian
  let a = plain.amount;
  for (let i = 0; i < 8; i++) {
    out[32 + i] = Number(a & 0xffn);
    a >>= 8n;
  }
  if (a !== 0n) throw new RangeError("amount exceeds 64 bits");
  return out;
}

function unpackPlaintext(bytes: Uint8Array): AuditorNotePlain {
  let tokenId = 0n;
  for (let i = 0; i < 32; i++) tokenId = (tokenId << 8n) | BigInt(bytes[i]);
  let amount = 0n;
  for (let i = 7; i >= 0; i--) amount = (amount << 8n) | BigInt(bytes[32 + i]);
  return { tokenId, amount };
}

/**
 * Encrypt note viewing data to an auditor's Ed25519 viewing public key.
 *
 * @param auditorViewingPubKey - 32-byte Ed25519 public key of the auditor
 * @param plain                - tokenId + amount to encrypt
 * @param commitment           - 32-byte note commitment (AAD — binds blob to note)
 * @param ephemeralPriv        - optional 32-byte X25519 private key (random if omitted)
 * @returns 112-byte blob: eph_pub(32) || nonce(24) || ciphertextWithTag(56)
 */
export function encryptAuditorCiphertext(
  auditorViewingPubKey: Uint8Array,
  plain: AuditorNotePlain,
  commitment: Uint8Array,
  ephemeralPriv?: Uint8Array,
): Uint8Array {
  if (auditorViewingPubKey.length !== 32) throw new Error("auditorViewingPubKey must be 32 bytes");
  if (commitment.length !== 32) throw new Error("commitment must be 32 bytes");

  const ephPriv = ephemeralPriv ?? crypto.getRandomValues(new Uint8Array(32));
  const ephPub = x25519PubFromPriv(ephPriv);
  const auditorX = ed25519PubToX25519(auditorViewingPubKey);
  const shared = x25519.getSharedSecret(ephPriv, auditorX);
  const key = deriveKey(shared);

  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_BYTES));
  const aead = xchacha20poly1305(key, nonce, commitment);
  const ciphertextWithTag = aead.encrypt(packPlaintext(plain));

  const blob = new Uint8Array(AUDITOR_CIPHERTEXT_BYTES);
  blob.set(ephPub, 0);
  blob.set(nonce, EPH_PUB_BYTES);
  blob.set(ciphertextWithTag, EPH_PUB_BYTES + NONCE_BYTES);
  return blob;
}

/**
 * Decrypt an auditor ciphertext blob using the auditor's Ed25519 viewing private key.
 *
 * @param auditorViewingPrivKey - 32-byte Ed25519 private key of the auditor
 * @param blob                  - 112-byte blob from `encryptAuditorCiphertext`
 * @param commitment            - 32-byte note commitment (must match AAD used during encrypt)
 * @returns decrypted plain, or null on any failure (wrong key, wrong commitment, corrupt)
 */
export function decryptAuditorCiphertext(
  auditorViewingPrivKey: Uint8Array,
  blob: Uint8Array,
  commitment: Uint8Array,
): AuditorNotePlain | null {
  if (blob.length !== AUDITOR_CIPHERTEXT_BYTES) return null;
  if (commitment.length !== 32) return null;

  const ephPub = blob.slice(0, EPH_PUB_BYTES);
  const nonce = blob.slice(EPH_PUB_BYTES, EPH_PUB_BYTES + NONCE_BYTES);
  const ciphertextWithTag = blob.slice(EPH_PUB_BYTES + NONCE_BYTES);

  const auditorXPriv = ed25519PrivToX25519(auditorViewingPrivKey);
  const shared = x25519.getSharedSecret(auditorXPriv, ephPub);
  const key = deriveKey(shared);

  try {
    const aead = xchacha20poly1305(key, nonce, commitment);
    const plaintext = aead.decrypt(ciphertextWithTag);
    return unpackPlaintext(plaintext);
  } catch {
    return null;
  }
}
