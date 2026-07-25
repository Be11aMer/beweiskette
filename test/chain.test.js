/**
 * Hash chain construction and verification (chain format v2).
 *
 * These are the behavioural guarantees the whole tool rests on: an unmodified
 * chain verifies, and any modification, reordering or removal is detected at
 * the right position.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  createEntry,
  createChainId,
  computeEntryHash,
  verifyChain,
  validateEntry,
  GENESIS,
  SCHEMA_VERSION,
} from '../src/chain.js';

/** Build a chain of n entries. */
async function buildChain(n, chainId = createChainId()) {
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
      custody: { custodian: `Custodian ${i}`, case_reference: 'CASE-2026-0042', notes: '' },
      prevHash: prev,
      seq: i,
      chainId,
    });
    entries.push(entry);
    prev = entry.entry_hash;
  }
  return entries;
}

/** Re-seal an entry after mutating it, so only the intended defect is tested. */
async function reseal(entry) {
  entry.entry_hash = await computeEntryHash(entry);
  return entry;
}

test('an empty chain is intact', async () => {
  const result = await verifyChain([]);
  assert.equal(result.intact, true);
  assert.equal(result.entries, 0);
  assert.equal(result.headHash, null);
});

test('a freshly built chain verifies and reports its head', async () => {
  const entries = await buildChain(5);
  const result = await verifyChain(entries);
  assert.equal(result.intact, true, result.details);
  assert.equal(result.entries, 5);
  assert.equal(result.headHash, entries[4].entry_hash);
  assert.equal(result.chainId, entries[0].chain_id);
});

test('entries carry schema_version, seq and a shared chain_id', async () => {
  const entries = await buildChain(3);
  entries.forEach((e, i) => {
    assert.equal(e.schema_version, SCHEMA_VERSION);
    assert.equal(e.seq, i);
    assert.equal(e.chain_id, entries[0].chain_id);
  });
});

test('the first entry links to GENESIS and each entry to its predecessor', async () => {
  const entries = await buildChain(4);
  assert.equal(entries[0].prev_hash, GENESIS);
  for (let i = 1; i < entries.length; i++) {
    assert.equal(entries[i].prev_hash, entries[i - 1].entry_hash);
  }
});

test('verification recomputes rather than trusting the stored hash', async () => {
  const entries = await buildChain(3);
  entries[1].custody.notes = 'tampered';
  await reseal(entries[1]);
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

test('reordering entries is detected', async () => {
  // The defect seq exists to catch. Under v1 the chain was ordered by the
  // storage layer, so a reorder was indistinguishable from the real order.
  const entries = await buildChain(4);
  [entries[1], entries[2]] = [entries[2], entries[1]];
  const result = await verifyChain(entries);
  assert.equal(result.intact, false);
  assert.equal(result.brokenAt, 2);
  assert.match(result.details, /seq/);
});

test('removing an entry from the middle is detected', async () => {
  const entries = await buildChain(4);
  entries.splice(1, 1);
  const result = await verifyChain(entries);
  assert.equal(result.intact, false);
  assert.equal(result.brokenAt, 2);
});

test('removing the first entry is detected', async () => {
  const entries = await buildChain(3);
  entries.shift();
  const result = await verifyChain(entries);
  assert.equal(result.intact, false);
  assert.equal(result.brokenAt, 1);
});

test('splicing two chains together is detected', async () => {
  // Without chain_id, entries from separate chains are interchangeable and a
  // spliced file verifies as long as the links happen to line up.
  const a = await buildChain(2);
  const b = await buildChain(2);
  b[0].seq = 2;
  b[0].prev_hash = a[1].entry_hash;
  await reseal(b[0]);
  const result = await verifyChain([...a, b[0]]);
  assert.equal(result.intact, false);
  assert.equal(result.brokenAt, 3);
  assert.match(result.details, /different chain/);
});

test('a broken link is detected', async () => {
  const entries = await buildChain(4);
  entries[2].prev_hash = 'aa'.repeat(32);
  await reseal(entries[2]);
  const result = await verifyChain(entries);
  assert.equal(result.intact, false);
  assert.equal(result.brokenAt, 3);
});

test('truncating the tail still verifies — this is a known limitation', async () => {
  // Documented in docs/THREAT_MODEL.md: without an external anchor there is
  // nothing committing to the chain's length, so dropping trailing entries is
  // undetectable from the file alone. Asserted so the limitation is explicit
  // and a future anchoring change has a test to flip.
  const entries = await buildChain(5);
  const result = await verifyChain(entries.slice(0, 3));
  assert.equal(result.intact, true);
  assert.equal(result.entries, 3);
});

test('structurally malformed entries are rejected before hashing', async () => {
  for (const notAnObject of [null, undefined, 'string', 42, []]) {
    assert.match(validateEntry(notAnObject), /not an object/);
  }

  const cases = [
    ['schema_version', (e) => { e.schema_version = 1; }],
    ['chain_id', (e) => { delete e.chain_id; }],
    ['seq', (e) => { e.seq = -1; }],
    ['evidence block is missing', (e) => { delete e.evidence; }],
    ['file_hash', (e) => { e.evidence.file_hash = 'not-a-hash'; }],
    ['file_size', (e) => { e.evidence.file_size = -5; }],
    ['custody block is missing', (e) => { delete e.custody; }],
    ['custody.custodian', (e) => { delete e.custody.custodian; }],
    ['metadata', (e) => { e.metadata = 'nope'; }],
    ['prev_hash', (e) => { e.prev_hash = 'xyz'; }],
    ['entry_hash', (e) => { e.entry_hash = 'short'; }],
  ];

  for (const [expected, mutate] of cases) {
    const [entry] = await buildChain(1);
    mutate(entry);
    const problem = validateEntry(entry);
    assert.ok(problem, `expected a validation failure for ${expected}`);
    assert.ok(problem.includes(expected), `expected message about "${expected}", got "${problem}"`);
  }
});

test('an entry stripped of its custody block does not verify', async () => {
  // The attack schema validation exists to stop: with a blacklist digest and
  // no shape check, an entry missing a field is re-hashed over what remains
  // and reports INTACT.
  const entries = await buildChain(2);
  delete entries[1].custody;
  const result = await verifyChain(entries);
  assert.equal(result.intact, false);
  assert.match(result.details, /custody/);
});

test('an unexpected extra field is not silently covered by the digest', async () => {
  const [entry] = await buildChain(1);
  const before = entry.entry_hash;
  entry.injected = 'not part of the format';
  assert.equal(await computeEntryHash(entry), before);
});

test('validateEntry accepts a well-formed entry', async () => {
  const entries = await buildChain(2);
  for (const entry of entries) {
    assert.equal(validateEntry(entry), null);
  }
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
  assert.equal(await computeEntryHash(entry), entry.entry_hash);
  const withoutHash = { ...entry };
  delete withoutHash.entry_hash;
  assert.equal(await computeEntryHash(withoutHash), entry.entry_hash);
});

test('distinct entries get distinct hashes', async () => {
  const entries = await buildChain(20);
  assert.equal(new Set(entries.map((e) => e.entry_hash)).size, entries.length);
});

test('entries registered in the same millisecond still verify', async () => {
  // The regression that motivated seq: identical timestamps previously left
  // ordering to a random UUID primary key, producing a false CHAIN BROKEN.
  const chainId = createChainId();
  const entries = [];
  let prev = GENESIS;
  const results = await Promise.all([0, 1, 2].map((i) => createEntry({
    evidence: {
      file_hash: String(i).padStart(64, '0'),
      file_name: `same-ms-${i}.bin`,
      file_size: 1,
      file_type: 'application/octet-stream',
      file_last_modified: '2026-01-01T00:00:00.000Z',
    },
    metadata: null,
    custody: { custodian: 'X', case_reference: '', notes: '' },
    prevHash: GENESIS,
    seq: i,
    chainId,
  })));

  // Re-link them as the store would, then confirm identical timestamps are
  // irrelevant to verification.
  for (let i = 0; i < results.length; i++) {
    results[i].timestamp_registered = '2026-07-24T12:00:00.000Z';
    results[i].prev_hash = prev;
    await reseal(results[i]);
    prev = results[i].entry_hash;
    entries.push(results[i]);
  }

  const result = await verifyChain(entries);
  assert.equal(result.intact, true, result.details);
});
