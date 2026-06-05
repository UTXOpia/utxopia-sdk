/**
 * Claim link utilities for UTXOpia
 *
 * Claim links encode a seed phrase in a URL fragment (#note=...) so the
 * secret is never sent to the server (fragments are client-side only).
 *
 * SECURITY: Claim links are bearer instruments - anyone with the link can claim!
 */

/**
 * Encode a seed phrase for use in claim links.
 * URL-encodes the seed — much shorter than encoding nullifier+secret.
 *
 * @param seed - Seed phrase (user's secret note)
 * @returns URL-safe encoded string
 */
export function encodeClaimLink(seed: string): string {
  return encodeURIComponent(seed);
}

/**
 * Decode a claim link seed.
 *
 * @param encoded - URL-encoded seed string
 * @returns Decoded seed string, or null if invalid
 */
export function decodeClaimLink(encoded: string): string | null {
  try {
    const decoded = decodeURIComponent(encoded);
    if (/^[a-zA-Z0-9]/.test(decoded) && decoded.length >= 8) {
      return decoded;
    }
  } catch {
    // Not URL-encoded
  }

  return null;
}

/**
 * Parse claim URL — reads seed from URL fragment (#note=...).
 *
 * @param url - URL string
 * @returns Seed string or null if invalid
 */
export function parseClaimUrl(url: string): string | null {
  if (url.includes("#note=")) {
    const encoded = url.split("#note=")[1].split("&")[0];
    if (encoded) return decodeClaimLink(encoded);
  }

  return null;
}
