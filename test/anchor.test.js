/**
 * Head receipts and anchor verification.
 *
 * The property under test is the one the hash chain cannot provide on its own:
 * detecting that entries were removed from the end, and that the chain was not
 * rebuilt with different content after a receipt was published.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { buildReceipt, formatReceipt, parseReceipt, checkAnchor, anchorCoverage, createAnchorRecord, ANCHOR_METHOD } from '../src/anchor.js';
import { createEntry, createChainId, computeEntryHash, verifyChain, GENESIS } from '../src/chain.js';

async function buildChain(n, chainId = createChainId(), custodian = 'A. Muster') {
  const entries = [];
  let prev = GENESIS;
  for (let i = 0; i < n; i++) {
    const entry = await createEntry({
      evidence: {
        file_hash: String(i).padStart(64, '0'),
        file_name: `evidence-${i}.jpg`,
        file_size: 1000 + i,
        file_type: 'image/jpeg',
        file_last_modified: '2026-01-01T00:00:00.000Z',
      },
      metadata: null,
      custody: { custodian, case_reference: 'CASE-1', notes: '' },
      prevHash: prev,
      seq: i,
      chainId,
    });
    entries.push(entry);
    prev = entry.entry_hash;
  }
  return entries;
}

test('a receipt commits to the chain id, height and head hash', async () => {
  const entries = await buildChain(4);
  const receipt = await buildReceipt(entries);
  assert.equal(receipt.chain_id, entries[0].chain_id);
  assert.equal(receipt.seq, 3);
  assert.equal(receipt.entry_count, 4);
  assert.equal(receipt.head_hash, entries[3].entry_hash);
});

test('a receipt round-trips through its text form', async () => {
  const entries = await buildChain(3);
  const receipt = await buildReceipt(entries);
  const parsed = await parseReceipt(formatReceipt(receipt));
  assert.deepEqual(parsed, receipt);
});

test('a receipt survives being quoted, bulleted and fenced', async () => {
  const entries = await buildChain(2);
  const receipt = await buildReceipt(entries);
  const messy = [
    'Anchoring my chain today, see below:',
    '',
    '```',
    ...formatReceipt(receipt).split('\n').map((l) => `> ${l}`),
    '```',
    '',
    'Anyone can verify this.',
  ].join('\n');
  assert.deepEqual(await parseReceipt(messy), receipt);
});

test('a receipt mangled in transit is rejected rather than read as tampering', async () => {
  const entries = await buildChain(3);
  const receipt = await buildReceipt(entries);
  // Flip exactly one hex digit of the head hash.
  const flipped = (receipt.head_hash[0] === '0' ? '1' : '0') + receipt.head_hash.slice(1);
  const corrupted = formatReceipt(receipt).replace(receipt.head_hash, flipped);
  await assert.rejects(() => parseReceipt(corrupted), /altered or truncated/);
});

test('an incomplete receipt is rejected with the missing field named', async () => {
  const entries = await buildChain(2);
  const text = formatReceipt(await buildReceipt(entries));
  const withoutHead = text.split('\n').filter((l) => !l.startsWith('head:')).join('\n');
  await assert.rejects(() => parseReceipt(withoutHead), /head_hash/);
});

test('an unchanged chain matches its receipt', async () => {
  const entries = await buildChain(4);
  const receipt = await buildReceipt(entries);
  const result = await checkAnchor(entries, receipt);
  assert.equal(result.matches, true, result.reason);
});

test('tail truncation is detected — the property the chain alone cannot provide', async () => {
  const entries = await buildChain(6);
  const receipt = await buildReceipt(entries);

  // The truncated chain verifies perfectly on its own...
  const truncated = entries.slice(0, 3);
  const { verifyChain } = await import('../src/chain.js');
  assert.equal((await verifyChain(truncated)).intact, true);

  // ...but cannot satisfy the published receipt.
  const result = await checkAnchor(truncated, receipt);
  assert.equal(result.matches, false);
  assert.equal(result.truncated, true);
  assert.match(result.reason, /missing/i);
});

test('appending after a receipt still matches, and reports the growth', async () => {
  const chainId = createChainId();
  const entries = await buildChain(3, chainId);
  const receipt = await buildReceipt(entries);

  const extra = await createEntry({
    evidence: {
      file_hash: 'ff'.repeat(32),
      file_name: 'later.jpg',
      file_size: 10,
      file_type: 'image/jpeg',
      file_last_modified: '2026-02-01T00:00:00.000Z',
    },
    metadata: null,
    custody: { custodian: 'A. Muster', case_reference: 'CASE-1', notes: '' },
    prevHash: entries[2].entry_hash,
    seq: 3,
    chainId,
  });

  const result = await checkAnchor([...entries, extra], receipt);
  assert.equal(result.matches, true, result.reason);
  assert.match(result.reason, /1 entry appended/);
});

test('a chain rebuilt with different content fails its old receipt', async () => {
  // Every entry re-sealed, so the chain verifies — but it is not the chain
  // that was anchored. This is the forgery the receipt exists to expose.
  const chainId = createChainId();
  const original = await buildChain(3, chainId, 'A. Muster');
  const receipt = await buildReceipt(original);

  const rebuilt = await buildChain(3, chainId, 'Someone Else');
  const { verifyChain } = await import('../src/chain.js');
  assert.equal((await verifyChain(rebuilt)).intact, true);

  const result = await checkAnchor(rebuilt, receipt);
  assert.equal(result.matches, false);
  assert.match(result.reason, /does not match the receipt/);
});

test('a receipt from another chain is rejected', async () => {
  const receipt = await buildReceipt(await buildChain(3));
  const result = await checkAnchor(await buildChain(3), receipt);
  assert.equal(result.matches, false);
  assert.match(result.reason, /different chain/);
});

test('a broken chain fails the anchor check with the break reported', async () => {
  const entries = await buildChain(4);
  const receipt = await buildReceipt(entries);
  entries[1].custody.notes = 'tampered';
  entries[1].entry_hash = await computeEntryHash(entries[1]);

  const result = await checkAnchor(entries, receipt);
  assert.equal(result.matches, false);
  assert.match(result.reason, /does not verify/);
});

test('a broken or empty chain cannot be anchored', async () => {
  await assert.rejects(() => buildReceipt([]), /empty chain/);

  const entries = await buildChain(3);
  entries[1].evidence.file_name = 'tampered.jpg';
  await assert.rejects(() => buildReceipt(entries), /broken chain/);
});

// ── Export envelope and anchor records ─────────────────────────────

test('the envelope carries the chain and its anchors, and reads back', async () => {
  const { buildEnvelope, readEnvelope } = await import('../src/report.js');
  const entries = await buildChain(3);
  const receipt = await buildReceipt(entries);
  const anchor = createAnchorRecord({ receipt, method: ANCHOR_METHOD.PUBLISHED });

  const envelope = buildEnvelope(entries, [anchor]);
  assert.equal(envelope.format, 'beweiskette-chain');

  const read = readEnvelope(JSON.parse(JSON.stringify(envelope)));
  assert.equal(read.legacy, false);
  assert.deepEqual(read.chain, JSON.parse(JSON.stringify(entries)));
  assert.equal(read.anchors.length, 1);
});

test('a bare array still imports — old exports must not stop working', async () => {
  const { readEnvelope } = await import('../src/report.js');
  const entries = await buildChain(2);
  const read = readEnvelope(JSON.parse(JSON.stringify(entries)));
  assert.equal(read.legacy, true);
  assert.equal(read.chain.length, 2);
  assert.deepEqual(read.anchors, []);
});

test('junk is rejected rather than read as an empty chain', async () => {
  const { readEnvelope } = await import('../src/report.js');
  for (const bad of [null, 42, 'chain', {}, { chain: 'nope' }]) {
    assert.equal(readEnvelope(bad), null, `accepted ${JSON.stringify(bad)}`);
  }
});

test('an embedded anchor detects truncation with no receipt supplied', async () => {
  // The practical win: a recipient who has never seen a receipt still catches
  // a chain whose tail was removed, because the anchor travelled with it.
  const entries = await buildChain(6);
  const anchor = createAnchorRecord({
    receipt: await buildReceipt(entries),
    method: ANCHOR_METHOD.TSA,
  });

  const truncated = entries.slice(0, 3);
  assert.equal((await verifyChain(truncated)).intact, true, 'truncated chain should still verify on its own');

  const receipt = await parseReceipt(anchor.receipt);
  const result = await checkAnchor(truncated, receipt);
  assert.equal(result.matches, false);
  assert.equal(result.truncated, true);
});

test('anchor coverage reports the unanchored window', async () => {
  const entries = await buildChain(5);
  const early = createAnchorRecord({
    receipt: await buildReceipt(entries.slice(0, 2)),
    method: ANCHOR_METHOD.PUBLISHED,
  });

  const coverage = anchorCoverage(entries, [early]);
  assert.equal(coverage.anchored, true);
  assert.equal(coverage.latestSeq, 1);
  assert.equal(coverage.unanchored, 3);
  assert.match(coverage.summary, /3 later entries are not yet covered/);
});

test('coverage says so plainly when a chain has no anchors', async () => {
  const coverage = anchorCoverage(await buildChain(4), []);
  assert.equal(coverage.anchored, false);
  assert.match(coverage.summary, /All 4 entries could be removed/);
});

test('anchors claiming a height beyond the chain are ignored for coverage', async () => {
  // A stripped tail plus a leftover anchor must not read as fully covered.
  const entries = await buildChain(2);
  const coverage = anchorCoverage(entries, [{ seq: 99, method: ANCHOR_METHOD.TSA }]);
  assert.equal(coverage.anchored, false);
});

test('tokens survive the base64 round trip byte for byte', async () => {
  const { encodeToken, decodeToken } = await import('../src/anchor.js');
  const bytes = crypto.getRandomValues(new Uint8Array(2617));
  assert.deepEqual(decodeToken(encodeToken(bytes)), bytes);
  assert.equal(decodeToken('not base64!!'), null);
});

test('an anchor beyond the chain height is the truncation evidence, not noise', async () => {
  // Regression. anchorCoverage filters anchors above the chain height, which
  // is right for measuring coverage and wrong for detection: an anchor
  // committing to entry 3 against a chain ending at entry 1 is exactly the
  // signal that entries were removed. Filtering it discarded the one piece of
  // evidence the feature exists to surface, and the chain read as simply
  // "unanchored" instead of "truncated".
  const entries = await buildChain(3);
  const receipt = await buildReceipt(entries);
  const truncated = entries.slice(0, 1);

  assert.equal(anchorCoverage(truncated, [{ seq: receipt.seq }]).anchored, false);

  const result = await checkAnchor(truncated, receipt);
  assert.equal(result.truncated, true);
  assert.match(result.reason, /commits to entry 3, but this chain ends at entry 1/);
});
