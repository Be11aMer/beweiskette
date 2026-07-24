/**
 * Hash chain logic for evidence entries.
 * Mirrors Zeitkette's pattern: SHA-256 of deterministic JSON, linked via prev_hash.
 */

import { hashString, constantTimeEqual } from './crypto.js';
import { sortedStringify, generateId, nowISO } from './utils.js';

const GENESIS = 'GENESIS';

/**
 * Create a new evidence entry and compute its hash.
 *
 * @param {Object} evidence - File evidence data (hash, name, size, type, lastModified)
 * @param {Object|null} metadata - EXIF metadata or null
 * @param {Object} custody - Custodian info (custodian, case_reference, notes)
 * @param {string} prevHash - Previous entry's hash, or 'GENESIS' for first entry
 * @returns {Object} Complete entry with entry_hash
 */
export async function createEntry(evidence, metadata, custody, prevHash) {
  const entry = {
    id: generateId(),
    timestamp_registered: nowISO(),
    evidence,
    metadata: metadata || null,
    custody,
    prev_hash: prevHash || GENESIS,
  };

  entry.entry_hash = await computeEntryHash(entry);
  return entry;
}

/**
 * Compute SHA-256 hash of an entry excluding the entry_hash field.
 * Uses deterministic serialization (sorted keys, no whitespace).
 */
export async function computeEntryHash(entry) {
  const hashable = {};
  for (const key of Object.keys(entry)) {
    if (key !== 'entry_hash') {
      hashable[key] = entry[key];
    }
  }
  const canonical = sortedStringify(hashable);
  return hashString(canonical);
}

/**
 * Verify the integrity of an entire chain of entries.
 *
 * @param {Array} entries - Ordered array of evidence entries
 * @returns {Object} { intact: boolean, entries: number, brokenAt?: number, brokenId?: string, details: string }
 */
export async function verifyChain(entries) {
  if (!entries || entries.length === 0) {
    return { intact: true, entries: 0, details: 'Chain is empty.' };
  }

  let expectedPrevHash = GENESIS;

  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i];

    if (entry.prev_hash !== expectedPrevHash) {
      return {
        intact: false,
        entries: entries.length,
        brokenAt: i + 1,
        brokenId: entry.id,
        details: `Chain broken at entry ${i + 1}: prev_hash mismatch.`,
      };
    }

    const computedHash = await computeEntryHash(entry);
    if (!constantTimeEqual(computedHash, entry.entry_hash)) {
      return {
        intact: false,
        entries: entries.length,
        brokenAt: i + 1,
        brokenId: entry.id,
        details: `Chain broken at entry ${i + 1}: entry content was modified.`,
      };
    }

    expectedPrevHash = entry.entry_hash;
  }

  return {
    intact: true,
    entries: entries.length,
    details: `Chain intact. ${entries.length} entries verified.`,
  };
}

export { GENESIS };
