/**
 * Hash chain logic for evidence entries.
 * SHA-256 over a deterministic JSON encoding, linked via prev_hash.
 *
 * Chain format v3. Fields covered by the digest, and why:
 *
 *   schema_version  so a change to the encoding is detectable in-band rather
 *                   than silently invalidating every existing chain
 *   seq             explicit height, so ordering is a property of the record
 *                   rather than of whatever order the storage layer returned
 *   chain_id        per-chain identity, so entries from two separate chains
 *                   cannot be spliced into one file that still verifies
 *   time_bound      a randomness-beacon pulse establishing "no earlier than"
 *                   (v3). Inside the digest because a bound attached after the
 *                   fact could be chosen once the desired answer was known.
 *
 * v2 entries remain verifiable: each entry is hashed under the field list for
 * its own schema_version. That is what the version field was added for.
 *
 * What this construction does and does not establish is documented in
 * docs/THREAT_MODEL.md. In short: it detects modification, reordering and
 * removal-from-the-middle of a chain you already hold. It says nothing about
 * wall-clock time, and it cannot distinguish a genuine chain from one
 * fabricated wholesale — for that the head must be anchored externally
 * (docs/ANCHORING.md).
 */

import { hashString, constantTimeEqual } from './crypto.js';
import { sortedStringify } from './canonical.js';
import { generateId, nowISO } from './utils.js';

const GENESIS = 'GENESIS';

/** The version stamped on newly created entries. */
export const SCHEMA_VERSION = 3;

/** Versions this build can verify. */
export const SUPPORTED_VERSIONS = [2, 3];

/**
 * Exactly the fields covered by entry_hash, in no particular order — the
 * canonical encoding sorts them.
 *
 * This is a whitelist rather than "every key except entry_hash" on purpose:
 * with a blacklist, any unexpected key an entry happens to carry silently
 * becomes part of the digest, so what a given entry_hash commits to depends on
 * the shape of the object rather than on the format.
 */
const V2_FIELDS = [
  'schema_version',
  'chain_id',
  'seq',
  'id',
  'timestamp_registered',
  'evidence',
  'metadata',
  'custody',
  'prev_hash',
];

/**
 * v3 adds `time_bound`, which carries the randomness-beacon pulse that
 * establishes "no earlier than". It has to be inside the digest: a bound
 * attached after the fact would prove nothing, since it could be chosen once
 * the desired answer was known.
 */
const V3_FIELDS = [...V2_FIELDS, 'time_bound'];

/**
 * The hashed field list, by schema version.
 *
 * Keeping both is the point of having stamped a version in the first place.
 * A second breaking migration would have been the easy option; making the
 * field earn its keep means chains written by the previous release stay
 * verifiable, and each entry is hashed under the rules it was created with.
 */
export const HASHED_FIELDS_BY_VERSION = {
  2: V2_FIELDS,
  3: V3_FIELDS,
};

/** Fields hashed for entries created by this build. */
export const HASHED_FIELDS = V3_FIELDS;

const HEX64 = /^[0-9a-f]{64}$/;

/** Start a new chain. The id is random and carried by every entry in it. */
export function createChainId() {
  return generateId();
}

/**
 * Create a new evidence entry and compute its hash.
 *
 * @param {Object} params
 * @param {Object} params.evidence  - file evidence data
 * @param {Object|null} params.metadata - EXIF metadata or null
 * @param {Object} params.custody   - custodian, case_reference, notes
 * @param {string} params.prevHash  - previous entry's hash, or 'GENESIS'
 * @param {number} params.seq       - 0-based height in the chain
 * @param {string} params.chainId   - identity of the chain being appended to
 * @returns {Promise<Object>} complete entry with entry_hash
 */
export async function createEntry({ evidence, metadata, custody, prevHash, seq, chainId, timeBound = null }) {
  const entry = {
    schema_version: SCHEMA_VERSION,
    chain_id: chainId,
    seq,
    id: generateId(),
    timestamp_registered: nowISO(),
    evidence,
    metadata: metadata || null,
    custody,
    prev_hash: prevHash || GENESIS,
    time_bound: timeBound || null,
  };

  entry.entry_hash = await computeEntryHash(entry);
  return entry;
}

/**
 * Compute SHA-256 of an entry's hashed fields.
 * Uses deterministic serialization (sorted keys, no whitespace).
 */
export async function computeEntryHash(entry) {
  const fields = HASHED_FIELDS_BY_VERSION[entry && entry.schema_version];
  if (!fields) {
    throw new Error(`cannot hash an entry with schema_version ${JSON.stringify(entry && entry.schema_version)}`);
  }
  const hashable = {};
  for (const key of fields) {
    hashable[key] = entry[key];
  }
  return hashString(sortedStringify(hashable));
}

function isPlainObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isNonEmptyString(value) {
  return typeof value === 'string' && value.length > 0;
}

/**
 * Structural validation of an entry.
 *
 * Without this, a hash check alone is not enough: an entry stripped of its
 * custody block still verifies, because the digest is recomputed over
 * whatever fields are actually present. Imported chains come from
 * counterparties, so shape has to be checked before meaning is assigned to
 * "CHAIN INTACT".
 *
 * @returns {string|null} a description of the first problem, or null if valid
 */
export function validateEntry(entry) {
  if (!isPlainObject(entry)) return 'entry is not an object';

  if (!SUPPORTED_VERSIONS.includes(entry.schema_version)) {
    return `unsupported schema_version ${JSON.stringify(entry.schema_version)} (supported: ${SUPPORTED_VERSIONS.join(', ')})`;
  }
  if (!isNonEmptyString(entry.chain_id)) return 'chain_id is missing or not a string';
  if (!Number.isInteger(entry.seq) || entry.seq < 0) return 'seq is not a non-negative integer';
  if (!isNonEmptyString(entry.id)) return 'id is missing or not a string';
  if (!isNonEmptyString(entry.timestamp_registered)) return 'timestamp_registered is missing or not a string';

  if (!isPlainObject(entry.evidence)) return 'evidence block is missing';
  const ev = entry.evidence;
  if (!HEX64.test(ev.file_hash || '')) return 'evidence.file_hash is not a SHA-256 hex digest';
  if (typeof ev.file_name !== 'string') return 'evidence.file_name is not a string';
  if (!Number.isInteger(ev.file_size) || ev.file_size < 0) return 'evidence.file_size is not a non-negative integer';
  if (typeof ev.file_type !== 'string') return 'evidence.file_type is not a string';
  if (typeof ev.file_last_modified !== 'string') return 'evidence.file_last_modified is not a string';

  if (entry.metadata !== null && !isPlainObject(entry.metadata)) return 'metadata is neither null nor an object';

  if (!isPlainObject(entry.custody)) return 'custody block is missing';
  for (const field of ['custodian', 'case_reference', 'notes']) {
    if (typeof entry.custody[field] !== 'string') return `custody.${field} is not a string`;
  }

  if (entry.prev_hash !== GENESIS && !HEX64.test(entry.prev_hash || '')) {
    return 'prev_hash is neither GENESIS nor a SHA-256 hex digest';
  }
  if (!HEX64.test(entry.entry_hash || '')) return 'entry_hash is not a SHA-256 hex digest';

  if (entry.schema_version >= 3) {
    const problem = validateTimeBound(entry.time_bound);
    if (problem) return problem;
  }

  return null;
}

/**
 * A v3 entry's `time_bound` is null, or a beacon pulse reference.
 *
 * Validated structurally here; whether the referenced pulse was actually
 * published is a separate question answered against the beacon archive
 * (src/beacon.js), not from the entry alone.
 */
function validateTimeBound(timeBound) {
  if (timeBound === null || timeBound === undefined) {
    return timeBound === undefined ? 'time_bound must be present (use null when absent)' : null;
  }
  if (!isPlainObject(timeBound)) return 'time_bound is neither null nor an object';

  const beacon = timeBound.beacon;
  if (beacon === undefined) return 'time_bound carries no beacon reference';
  if (!isPlainObject(beacon)) return 'time_bound.beacon is not an object';

  if (!isNonEmptyString(beacon.source)) return 'time_bound.beacon.source is missing';
  if (!Number.isInteger(beacon.pulse_index) || beacon.pulse_index < 0) {
    return 'time_bound.beacon.pulse_index is not a non-negative integer';
  }
  if (!Number.isInteger(beacon.chain_index) || beacon.chain_index < 0) {
    return 'time_bound.beacon.chain_index is not a non-negative integer';
  }
  if (!/^[0-9a-f]{128}$/.test(beacon.output_value || '')) {
    return 'time_bound.beacon.output_value is not a SHA-512 hex digest';
  }
  if (!isNonEmptyString(beacon.pulse_time)) return 'time_bound.beacon.pulse_time is missing';

  return null;
}

/**
 * What an entry must claim in order to extend `head`.
 * `head` is null for an empty chain.
 */
export function nextConstraints(head) {
  if (!head) return { seq: 0, prevHash: GENESIS, chainId: null };
  return { seq: head.seq + 1, prevHash: head.entry_hash, chainId: head.chain_id };
}

/**
 * Decide whether `entry` may be appended after `head`.
 *
 * Kept pure and separate from the storage layer so the fork-prevention rule
 * can be tested directly; store.js applies it inside the same readwrite
 * transaction that reads the head, so two tabs cannot both win the check.
 *
 * @returns {string|null} why the append must be refused, or null if it is valid
 */
export function checkAppend(head, entry) {
  const expected = nextConstraints(head);
  if (entry.seq !== expected.seq) {
    return `expected seq ${expected.seq}, entry claims ${entry.seq}`;
  }
  if (entry.prev_hash !== expected.prevHash) {
    return 'prev_hash does not match the current chain head';
  }
  if (expected.chainId !== null && entry.chain_id !== expected.chainId) {
    return 'entry belongs to a different chain';
  }
  return null;
}

function broken(entries, i, entry, details) {
  return {
    intact: false,
    entries: entries.length,
    brokenAt: i + 1,
    brokenId: entry && entry.id ? entry.id : null,
    details: `Chain broken at entry ${i + 1}: ${details}.`,
  };
}

/**
 * Verify the integrity of an entire chain of entries.
 *
 * @param {Array} entries - entries in chain order
 * @returns {Promise<Object>} { intact, entries, chainId?, headHash?, brokenAt?, brokenId?, details }
 */
export async function verifyChain(entries) {
  if (!Array.isArray(entries) || entries.length === 0) {
    return { intact: true, entries: 0, chainId: null, headHash: null, details: 'Chain is empty.' };
  }

  let expectedPrevHash = GENESIS;
  const chainId = isPlainObject(entries[0]) ? entries[0].chain_id : null;

  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i];

    const problem = validateEntry(entry);
    if (problem) return broken(entries, i, entry, problem);

    if (entry.seq !== i) {
      return broken(entries, i, entry, `expected seq ${i}, found ${entry.seq} (entries reordered or removed)`);
    }
    if (entry.chain_id !== chainId) {
      return broken(entries, i, entry, 'entry belongs to a different chain');
    }
    if (!constantTimeEqual(entry.prev_hash, expectedPrevHash)) {
      return broken(entries, i, entry, 'prev_hash does not match the preceding entry');
    }

    // validateEntry has already established that every hashed field is
    // present and well-typed, so this should not throw — but the input is
    // untrusted, so a canonicalization failure is reported as a broken chain
    // rather than escaping as an exception.
    let computedHash;
    try {
      computedHash = await computeEntryHash(entry);
    } catch (err) {
      return broken(entries, i, entry, `entry cannot be canonicalized (${err.message})`);
    }
    if (!constantTimeEqual(computedHash, entry.entry_hash)) {
      return broken(entries, i, entry, 'entry content was modified');
    }

    expectedPrevHash = entry.entry_hash;
  }

  return {
    intact: true,
    entries: entries.length,
    chainId,
    headHash: expectedPrevHash,
    details: `Chain intact. ${entries.length} entries verified.`,
  };
}

export { GENESIS };
