/**
 * Chain head receipts and anchor verification.
 *
 * A hash chain proves *sequence*: that the records it contains were built in
 * the order they claim and have not been altered since. It cannot prove
 * *time*, and it cannot prove *completeness*. Both gaps have the same cause —
 * nothing outside the file commits to it:
 *
 *   - Timestamps are read from the registering machine's own clock, which the
 *     person making the records controls.
 *   - Dropping entries from the end leaves a chain that still verifies
 *     perfectly, because nothing commits to how long it was supposed to be.
 *
 * A receipt closes both, without a server. It is a short text block naming the
 * chain, its height, and its head hash. Publish it somewhere you do not
 * control the timeline of — a git commit, a dated email, a public post, an
 * RFC-3161 timestamp authority — and it becomes evidence that the chain had
 * that exact content at that height no later than the moment of publication.
 * Later, checkAnchor() re-binds the chain to the receipt.
 *
 * This is the browser analogue of Zeitkette's git anchoring. See
 * docs/ANCHORING.md.
 */

import { hashString } from './crypto.js';
import { sortedStringify } from './canonical.js';
import { verifyChain, SCHEMA_VERSION } from './chain.js';

const HEADER = 'BEWEISKETTE ANCHOR RECEIPT';
const CHECK_LENGTH = 16;

/**
 * Build a receipt for a verified chain.
 * Throws if the chain does not verify — anchoring a broken chain is meaningless.
 */
export async function buildReceipt(entries, now = new Date().toISOString()) {
  const result = await verifyChain(entries);
  if (!result.intact) {
    throw new Error(`Cannot anchor a broken chain: ${result.details}`);
  }
  if (result.entries === 0) {
    throw new Error('Cannot anchor an empty chain.');
  }

  const receipt = {
    schema_version: SCHEMA_VERSION,
    chain_id: result.chainId,
    seq: entries[entries.length - 1].seq,
    entry_count: result.entries,
    head_hash: result.headHash,
    generated_at: now,
  };
  receipt.check = await receiptCheck(receipt);
  return receipt;
}

/**
 * Short integrity check over a receipt's fields.
 *
 * Not a security control — anyone can recompute it. It catches the ordinary
 * failure of a receipt being mangled in transit: line-wrapped by an email
 * client, truncated in a chat message, or transcribed by hand with a typo.
 * Without it a corrupted receipt reads as a tampered chain.
 */
async function receiptCheck(receipt) {
  const { check, ...fields } = receipt;
  const digest = await hashString(HEADER + '\n' + sortedStringify(fields));
  return digest.slice(0, CHECK_LENGTH);
}

/** Render a receipt as the text block a user publishes. */
export function formatReceipt(receipt) {
  return [
    HEADER,
    `schema:  ${receipt.schema_version}`,
    `chain:   ${receipt.chain_id}`,
    `seq:     ${receipt.seq}`,
    `entries: ${receipt.entry_count}`,
    `head:    ${receipt.head_hash}`,
    `time:    ${receipt.generated_at}`,
    `check:   ${receipt.check}`,
  ].join('\n');
}

const FIELD_MAP = {
  schema: ['schema_version', Number],
  chain: ['chain_id', String],
  seq: ['seq', Number],
  entries: ['entry_count', Number],
  head: ['head_hash', String],
  time: ['generated_at', String],
  check: ['check', String],
};

/**
 * Parse a receipt out of pasted text.
 *
 * Tolerates the ways a receipt actually arrives: surrounding prose, email
 * quote markers, list bullets, and Markdown code fences. Unknown lines are
 * ignored rather than rejected, so a receipt stays readable when it is pasted
 * into a commit message or a reply chain.
 *
 * @returns {Promise<Object>} the parsed receipt
 * @throws {Error} if required fields are missing or the check does not match
 */
export async function parseReceipt(text) {
  if (typeof text !== 'string' || text.trim() === '') {
    throw new Error('No receipt text provided.');
  }

  const parsed = {};
  for (const line of text.split(/\r?\n/)) {
    const cleaned = line.replace(/^[\s>*\-|]*/, '').trim();
    const match = /^([a-z_]+)\s*:\s*(.+?)\s*$/i.exec(cleaned);
    if (!match) continue;

    const mapping = FIELD_MAP[match[1].toLowerCase()];
    if (!mapping) continue;
    const [field, cast] = mapping;
    parsed[field] = cast(match[2]);
  }

  for (const field of ['schema_version', 'chain_id', 'seq', 'entry_count', 'head_hash', 'check']) {
    if (parsed[field] === undefined || parsed[field] === '') {
      throw new Error(`Receipt is missing the "${field}" field.`);
    }
  }
  if (!Number.isInteger(parsed.seq) || parsed.seq < 0) throw new Error('Receipt has an invalid seq.');
  if (!Number.isInteger(parsed.entry_count) || parsed.entry_count < 1) {
    throw new Error('Receipt has an invalid entry count.');
  }
  if (!/^[0-9a-f]{64}$/.test(parsed.head_hash)) throw new Error('Receipt has an invalid head hash.');
  if (parsed.generated_at === undefined) parsed.generated_at = '';

  const expected = await receiptCheck(parsed);
  if (expected !== parsed.check) {
    throw new Error('Receipt check digits do not match — the receipt text was altered or truncated in transit.');
  }
  return parsed;
}

/**
 * Check a chain against a previously published receipt.
 *
 * This is what makes tail truncation detectable: the receipt commits to a
 * height and the hash at that height, so a chain that no longer reaches it —
 * or reaches it with different content — is caught.
 *
 * @returns {Promise<{matches: boolean, reason: string, truncated?: boolean}>}
 */
export async function checkAnchor(entries, receipt) {
  const result = await verifyChain(entries);
  if (!result.intact) {
    return { matches: false, reason: `The chain itself does not verify: ${result.details}` };
  }
  if (receipt.chain_id !== result.chainId) {
    return { matches: false, reason: 'This receipt was issued for a different chain.' };
  }

  const anchored = entries.find((entry) => entry.seq === receipt.seq);
  if (!anchored) {
    return {
      matches: false,
      truncated: true,
      reason: `Entries are missing. The receipt commits to entry ${receipt.seq + 1}, but this chain ends at entry ${result.entries}.`,
    };
  }
  if (anchored.entry_hash !== receipt.head_hash) {
    return {
      matches: false,
      reason: `Entry ${receipt.seq + 1} does not match the receipt. The chain was rebuilt with different content after the receipt was published.`,
    };
  }

  const added = result.entries - receipt.entry_count;
  return {
    matches: true,
    reason: added > 0
      ? `Anchor confirmed at entry ${receipt.entry_count}, with ${added} ${added === 1 ? 'entry' : 'entries'} appended since.`
      : 'Anchor confirmed. The chain matches the published receipt exactly.',
  };
}

// ── Anchor records ─────────────────────────────────────────────────

/**
 * How an anchor was obtained, weakest to strongest.
 *
 * `published` covers a receipt the user posted somewhere themselves. It is not
 * inferior in principle — a receipt in a pushed git commit is excellent
 * evidence — but the app cannot confirm it happened, whereas it can check a
 * timestamp token without any help.
 */
export const ANCHOR_METHOD = {
  PUBLISHED: 'published',
  TSA: 'rfc3161',
};

/**
 * Build the record stored for an anchor, and carried in exports.
 *
 * The token is kept as base64 rather than parsed-and-summarised: the signature
 * is over the bytes, so a summary could not be re-verified by anyone later.
 */
export function createAnchorRecord({ receipt, method, token = null, genTime = null, status = null, obtainedAt = new Date().toISOString() }) {
  return {
    seq: receipt.seq,
    chain_id: receipt.chain_id,
    head_hash: receipt.head_hash,
    entry_count: receipt.entry_count,
    method,
    receipt: formatReceipt(receipt),
    token,
    gen_time: genTime,
    status,
    obtained_at: obtainedAt,
  };
}

/** Encode raw token bytes for storage and export. */
export function encodeToken(bytes) {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

/** Decode a stored token back to bytes. Returns null if unreadable. */
export function decodeToken(base64) {
  try {
    const binary = atob(String(base64));
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  } catch {
    return null;
  }
}

/**
 * Summarise how well anchored a chain is.
 *
 * The gap is the point: entries after the last anchor are the ones that could
 * be removed without any published evidence contradicting it. Keeping that
 * number visible is what keeps the window small.
 */
export function anchorCoverage(entries, anchors) {
  const height = entries.length ? entries[entries.length - 1].seq : -1;
  const usable = (anchors || []).filter((a) => a && Number.isInteger(a.seq) && a.seq <= height);

  if (usable.length === 0) {
    return {
      anchored: false,
      latestSeq: null,
      unanchored: entries.length,
      summary: entries.length
        ? `No anchors. All ${entries.length} entries could be removed without contradicting anything published.`
        : 'No entries yet.',
    };
  }

  const latest = usable.reduce((a, b) => (b.seq > a.seq ? b : a));
  const unanchored = height - latest.seq;
  return {
    anchored: true,
    latestSeq: latest.seq,
    latestMethod: latest.method,
    unanchored,
    summary: unanchored === 0
      ? `Anchored through the current head (entry ${latest.seq + 1}).`
      : `Anchored through entry ${latest.seq + 1}; ${unanchored} later ${unanchored === 1 ? 'entry is' : 'entries are'} not yet covered.`,
  };
}
