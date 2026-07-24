/**
 * Hash chain construction and verification.
 *
 * These are the behavioural guarantees the whole tool rests on: an unmodified
 * chain verifies, and any modification to any past entry is detected at the
 * right position.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { createEntry, computeEntryHash, verifyChain, GENESIS } from '../src/chain.js';

/** Build a chain of n entries with deterministic-ish content. */
async function buildChain(n) {
  const entries = [];
  let prev = GENESIS;
  for (let i = 0; i < n; i++) {
    const entry = await createEntry(
      {
        file_hash: String(i).padStart(64, '0'),
        file_name: `evidence-${i}.jpg`,
        file_size: 1000 + i,
        file_type: 'image/jpeg',
        file_last_modified: '2026-01-01T00:00:00.000Z',
      },
      null,
      { custodian: `Custodian ${i}`, case_reference: 'CASE-2026-0042', notes: '' },
      prev,
    );
    entries.push(entry);
    prev = entry.entry_hash;
  }
  return entries;
}

test('an empty chain is intact', async () => {
  const result = await verifyChain([]);
  assert.equal(result.intact, true);
  assert.equal(result.entries, 0);
});

test('a freshly built chain verifies', async () => {
  const entries = await buildChain(5);
  const result = await verifyChain(entries);
  assert.equal(result.intact, true, result.details);
  assert.equal(result.entries, 5);
});

test('the first entry links to GENESIS', async () => {
  const [first] = await buildChain(1);
  assert.equal(first.prev_hash, GENESIS);
});

test('each entry links to its predecessor', async () => {
  const entries = await buildChain(4);
  for (let i = 1; i < entries.length; i++) {
    assert.equal(entries[i].prev_hash, entries[i - 1].entry_hash);
  }
});

test('verification recomputes rather than trusting the stored hash', async () => {
  const entries = await buildChain(3);
  // Change content AND fix up the stored hash to match, but leave the
  // successor's prev_hash pointing at the old value: still detected.
  entries[1].custody.notes = 'tampered';
  entries[1].entry_hash = await computeEntryHash(entries[1]);
  const result = await verifyChain(entries);
  assert.equal(result.intact, false);
  assert.equal(result.brokenAt, 3);
});

test('modifying any field of any entry breaks the chain at that entry', async () => {
  const mutations = [
    (e) => { e.custody.custodian = 'Someone Else'; },
    (e) => { e.custody.notes = 'added after the fact'; },
    (e) => { e.evidence.file_hash = 'ff'.repeat(32); },
    (e) => { e.evidence.file_name = 'renamed.jpg'; },
    (e) => { e.evidence.file_size = 999999; },
    (e) => { e.timestamp_registered = '2020-01-01T00:00:00.000Z'; },
    (e) => { e.id = 'different-id'; },
  ];

  for (const mutate of mutations) {
    const entries = await buildChain(4);
    mutate(entries[1]);
    const result = await verifyChain(entries);
    assert.equal(result.intact, false, `mutation went undetected: ${mutate}`);
    assert.equal(result.brokenAt, 2);
    assert.equal(result.brokenId, entries[1].id);
  }
});

test('a broken link is detected', async () => {
  const entries = await buildChain(4);
  entries[2].prev_hash = 'aa'.repeat(32);
  entries[2].entry_hash = await computeEntryHash(entries[2]);
  const result = await verifyChain(entries);
  assert.equal(result.intact, false);
  assert.equal(result.brokenAt, 3);
});

test('a missing or malformed entry_hash is treated as broken', async () => {
  for (const bad of [undefined, null, '', 123, {}]) {
    const entries = await buildChain(2);
    entries[1].entry_hash = bad;
    const result = await verifyChain(entries);
    assert.equal(result.intact, false, `entry_hash=${JSON.stringify(bad)} verified`);
  }
});

test('entry_hash itself is excluded from the digest it commits to', async () => {
  const [entry] = await buildChain(1);
  const recomputed = await computeEntryHash(entry);
  assert.equal(recomputed, entry.entry_hash);
  // Recomputing after clearing the field must give the same answer, proving
  // the field is genuinely not part of its own preimage.
  const withoutHash = { ...entry };
  delete withoutHash.entry_hash;
  assert.equal(await computeEntryHash(withoutHash), entry.entry_hash);
});

test('distinct entries get distinct hashes', async () => {
  const entries = await buildChain(20);
  const seen = new Set(entries.map((e) => e.entry_hash));
  assert.equal(seen.size, entries.length);
});
