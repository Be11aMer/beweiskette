/**
 * Cryptographic operations.
 * All hashing happens client-side — files never leave the browser.
 */

import { bufferToHex } from './utils.js';
import { Sha256 } from './sha256.js';

/**
 * Above this size a file is streamed rather than buffered.
 *
 * crypto.subtle.digest() requires the whole input in memory at once, so a
 * large evidence file — a disk image, a long recording — would exhaust the tab
 * before it could be hashed. Below the threshold Web Crypto is used because it
 * is native and much faster; above it, src/sha256.js consumes the file in
 * chunks so peak memory does not grow with file size. Both paths are verified
 * to produce identical digests (test/sha256.test.js).
 */
const STREAM_THRESHOLD = 64 * 1024 * 1024;

/** EXIF lives near the start of a JPEG; this much is enough to parse it. */
export const HEAD_BYTES = 131072;

/**
 * Hash a file and return its leading bytes in a single pass.
 *
 * The caller needs both the digest and the head of the file (for EXIF). Doing
 * that as two separate reads was not just wasteful — a File is a lazy handle
 * to a path, so if the underlying file changed between the reads, the recorded
 * file_hash and the recorded metadata would describe different bytes, and the
 * chain would attest to that inconsistent pair as a single fact.
 *
 * @param {File|Blob} file
 * @param {{onProgress?: (fraction: number) => void}} [options]
 * @returns {Promise<{hash: string, head: ArrayBuffer}>}
 */
export async function hashFileWithHead(file, { onProgress } = {}) {
  if (file.size <= STREAM_THRESHOLD || typeof file.stream !== 'function') {
    const buffer = await file.arrayBuffer();
    const digest = await crypto.subtle.digest('SHA-256', buffer);
    if (onProgress) onProgress(1);
    return { hash: bufferToHex(digest), head: buffer.slice(0, HEAD_BYTES) };
  }

  const hasher = new Sha256();
  const headChunks = [];
  let headLength = 0;
  let processed = 0;

  const reader = file.stream().getReader();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;

    hasher.update(value);

    if (headLength < HEAD_BYTES) {
      const take = Math.min(HEAD_BYTES - headLength, value.length);
      headChunks.push(value.slice(0, take));
      headLength += take;
    }

    processed += value.length;
    if (onProgress && file.size > 0) onProgress(processed / file.size);
  }

  const head = new Uint8Array(headLength);
  let offset = 0;
  for (const chunk of headChunks) {
    head.set(chunk, offset);
    offset += chunk.length;
  }

  return { hash: hasher.digest(), head: head.buffer };
}

/**
 * Compute the SHA-256 of a file. Returns the hex-encoded digest.
 */
export async function hashFile(file, options) {
  const { hash } = await hashFileWithHead(file, options);
  return hash;
}

/**
 * Compute SHA-256 of a UTF-8 string.
 * Returns the hex-encoded hash string.
 */
export async function hashString(str) {
  const encoded = new TextEncoder().encode(str);
  const hashBuffer = await crypto.subtle.digest('SHA-256', encoded);
  return bufferToHex(hashBuffer);
}

/**
 * Length-independent string comparison.
 *
 * Applied consistently to hash comparisons, but it should not be read as a
 * meaningful defence in this application: there is no secret. Both operands
 * are already public — in IndexedDB, in the exported JSON, and rendered into
 * the DOM — so a timing oracle would reveal nothing an attacker does not have.
 * JavaScript cannot guarantee constant-time execution in any case; string
 * representation changes indexing cost and the JIT is unconstrained. It is
 * hygiene, and it costs nothing. See docs/THREAT_MODEL.md.
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
