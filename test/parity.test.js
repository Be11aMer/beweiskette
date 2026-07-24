/**
 * Parity between the app's verifier and the one embedded in exported reports.
 *
 * The report used to carry a hand-minified copy of sortedStringify, and that
 * copy had already drifted: it omitted the `undefined` case. Two copies of
 * consensus-critical code eventually mean two behaviours, and here that shows
 * up as the report calling a chain BROKEN that the app calls INTACT — on the
 * artifact handed to a third party.
 *
 * The report now inlines the single definition via Function.toString(). These
 * tests execute the generated report's own source and require it to agree,
 * digest for digest, so drift cannot reappear silently.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { generateHTMLReport } from '../src/report.js';
import { sortedStringify } from '../src/canonical.js';
import { computeEntryHash, createEntry, createChainId, GENESIS } from '../src/chain.js';

/** Pull the embedded verifier out of a generated report and evaluate it. */
function extractEmbedded(report) {
  const scripts = [...report.matchAll(/<script>([\s\S]*?)<\/script>/g)];
  assert.equal(scripts.length, 1, 'expected exactly one code block in the report');
  const source = scripts[0][1];

  const match = /const sortedStringify = ([\s\S]*?);\n\nasync function computeEntryHash/.exec(source);
  assert.ok(match, 'could not find the embedded canonicalizer');
  // eslint-disable-next-line no-new-func
  return { embeddedStringify: new Function(`return (${match[1]});`)(), source };
}

async function buildChain(n, custody = {}) {
  const chainId = createChainId();
  const entries = [];
  let prev = GENESIS;
  for (let i = 0; i < n; i++) {
    const entry = await createEntry({
      evidence: {
        file_hash: String(i).padStart(64, '0'),
        file_name: `evidence-${i}.jpg`,
        file_size: 100 + i,
        file_type: 'image/jpeg',
        file_last_modified: '2026-01-01T00:00:00.000Z',
      },
      metadata: i === 0 ? { camera_make: 'Canon', gps_lat: '52.520008', gps_lng: '13.404954' } : null,
      custody: { custodian: 'A. Muster', case_reference: 'CASE-1', notes: '', ...custody },
      prevHash: prev,
      seq: i,
      chainId,
    });
    entries.push(entry);
    prev = entry.entry_hash;
  }
  return entries;
}

test('the report embeds exactly one copy of the canonicalizer', () => {
  const report = generateHTMLReport([]);
  assert.equal((report.match(/const sortedStringify =/g) || []).length, 1);
  // The old hand-written duplicate is gone.
  assert.ok(!report.includes("if(typeof o==='undefined')"));
});

test('the embedded canonicalizer matches the app byte for byte', async () => {
  const entries = await buildChain(3, { custodian: 'Jörg Müller', notes: 'Übergabe: 09:15' });
  const { embeddedStringify } = extractEmbedded(generateHTMLReport(entries));

  for (const entry of entries) {
    assert.equal(embeddedStringify(entry), sortedStringify(entry));
  }
});

test('the embedded canonicalizer agrees on awkward values', async () => {
  const { embeddedStringify } = extractEmbedded(generateHTMLReport([]));
  const cases = [
    {},
    { a: 1, b: null, c: 'x' },
    { nested: { deep: { deeper: [1, 2, 3] } } },
    { 'ü': 1, 'a': 2, 'z': 3, 'Ä': 4 },
    { quote: 'he said "hi"', brace: '}{', comma: 'a,b' },
    { emoji: '🔗 chain', mixed: 'Müller-Straße' },
    [1, 'two', null, { three: 3 }],
    { newline: 'a\nb', tab: 'a\tb' },
  ];
  for (const value of cases) {
    assert.equal(embeddedStringify(value), sortedStringify(value), `disagreement on ${JSON.stringify(value)}`);
  }
});

test('the embedded verifier reproduces the app entry hashes', async () => {
  const entries = await buildChain(4);
  const { embeddedStringify, source } = extractEmbedded(generateHTMLReport(entries));

  const fields = JSON.parse(/const HASHED_FIELDS = (\[[^\]]*\]);/.exec(source)[1]);

  for (const entry of entries) {
    const hashable = {};
    for (const key of fields) hashable[key] = entry[key];
    const bytes = new TextEncoder().encode(embeddedStringify(hashable));
    const digest = await crypto.subtle.digest('SHA-256', bytes);
    const hex = Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('');

    assert.equal(hex, await computeEntryHash(entry));
    assert.equal(hex, entry.entry_hash);
  }
});

test('the report carries the same schema version and field list as the app', async () => {
  const { source } = extractEmbedded(generateHTMLReport(await buildChain(1)));
  const { SCHEMA_VERSION, HASHED_FIELDS } = await import('../src/chain.js');

  assert.equal(Number(/const SCHEMA_VERSION = (\d+);/.exec(source)[1]), SCHEMA_VERSION);
  assert.deepEqual(JSON.parse(/const HASHED_FIELDS = (\[[^\]]*\]);/.exec(source)[1]), HASHED_FIELDS);
});

test('the embedded verifier checks order and chain identity, not just hashes', async () => {
  const { source } = extractEmbedded(generateHTMLReport(await buildChain(1)));
  // Under v1 the report only checked prev_hash and the digest, so a reordered
  // or spliced chain read as intact there even when the app caught it.
  assert.match(source, /entry\.seq !== i/);
  assert.match(source, /entry\.chain_id !== chainId/);
  assert.match(source, /entry\.schema_version !== SCHEMA_VERSION/);
});
