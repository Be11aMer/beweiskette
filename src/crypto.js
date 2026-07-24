/**
 * Cryptographic operations using the Web Crypto API.
 * All hashing happens client-side — files never leave the browser.
 */

import { bufferToHex } from './utils.js';

/**
 * Compute SHA-256 hash of a File object.
 * Returns the hex-encoded hash string.
 */
export async function hashFile(file) {
  const buffer = await file.arrayBuffer();
  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
  return bufferToHex(hashBuffer);
}

/**
 * Compute SHA-256 hash of a UTF-8 string.
 * Returns the hex-encoded hash string.
 */
export async function hashString(str) {
  const encoded = new TextEncoder().encode(str);
  const hashBuffer = await crypto.subtle.digest('SHA-256', encoded);
  return bufferToHex(hashBuffer);
}

/**
 * Constant-time string comparison.
 * Prevents timing side-channel attacks that could reveal hash values.
 * Always compares all bytes regardless of where strings differ.
 */
export function constantTimeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}
