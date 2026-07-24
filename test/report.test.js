/**
 * Export artifact tests.
 *
 * The HTML report is the artifact most likely to leave the operator's machine
 * — handed to a lawyer, a counterparty, or opposing counsel. Markup injected
 * into it via a filename or custody note travels with it.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { generateCSV, generateHTMLReport, embedJSON } from '../src/report.js';

function entry(overrides = {}) {
  return {
    id: '11111111-2222-4333-8444-555555555555',
    timestamp_registered: '2026-07-24T12:00:00.000Z',
    evidence: {
      file_hash: 'ab'.repeat(32),
      file_name: 'evidence.jpg',
      file_size: 2048,
      file_type: 'image/jpeg',
      file_last_modified: '2026-07-01T00:00:00.000Z',
      ...(overrides.evidence || {}),
    },
    metadata: null,
    custody: { custodian: 'A. Muster', case_reference: 'CASE-1', notes: '', ...(overrides.custody || {}) },
    prev_hash: 'GENESIS',
    entry_hash: 'cd'.repeat(32),
  };
}

test('a filename containing </script> cannot break out of the data block', () => {
  const evil = 'x</script><img src=x onerror=alert(1)>.jpg';
  const report = generateHTMLReport([entry({ evidence: { file_name: evil } })]);

  // Exactly two script elements: the JSON data block and the code block.
  // A successful breakout would raise both counts.
  assert.equal(report.match(/<script/g).length, 2);
  assert.equal(report.match(/<\/script>/g).length, 2);
  assert.ok(!report.includes('<img src=x'));
  // The payload survives inside the data block, but inert.
  assert.ok(report.includes('\\u003c/script>'));
});

test('markup in a filename is escaped in the report table', () => {
  const report = generateHTMLReport([entry({ evidence: { file_name: '<b>bold</b>' } })]);
  assert.ok(report.includes('&lt;b&gt;bold&lt;/b&gt;'));
  assert.ok(!report.includes('<b>bold</b>'));
});

test('markup in custody fields is escaped', () => {
  const report = generateHTMLReport([
    entry({ custody: { custodian: '<script>alert(1)</script>' } }),
  ]);
  assert.ok(!report.includes('<script>alert(1)'));
  assert.ok(report.includes('&lt;script&gt;alert(1)&lt;/script&gt;'));
});

test('embedJSON escapes < so no tag can be formed, and stays valid JSON', () => {
  const embedded = embedJSON({ n: '</script><svg onload=alert(1)>' });
  assert.ok(!embedded.includes('<'));
  assert.deepEqual(JSON.parse(embedded), { n: '</script><svg onload=alert(1)>' });
});

test('the embedded chain data round-trips unchanged', () => {
  // Escaping must not corrupt the evidence record: what the report verifies
  // has to be byte-identical to what was exported, or hashes will not match.
  const entries = [entry({ evidence: { file_name: 'a<b>c&"d\'e.jpg' } })];
  const report = generateHTMLReport(entries);
  const json = report.match(/<script type="application\/json" id="chain-data">([\s\S]*?)<\/script>/)[1];
  assert.deepEqual(JSON.parse(json), entries);
});

test('the report has no inline event handlers', () => {
  // Inline handlers make the report unhostable under any strict CSP.
  const report = generateHTMLReport([entry()]);
  assert.ok(!/\son\w+\s*=/.test(report));
});

test('the report guards against a missing Web Crypto API', () => {
  const report = generateHTMLReport([entry()]);
  assert.ok(report.includes('crypto.subtle'));
  assert.ok(report.includes('Cannot verify'));
});

test('CSV quotes every field and doubles embedded quotes', () => {
  const csv = generateCSV([entry({ custody: { notes: 'he said "hi", then left' } })]);
  const dataLine = csv.split('\r\n')[1];
  assert.ok(dataLine.includes('"he said ""hi"", then left"'));
  // A comma inside a field must not create a new column.
  assert.equal(dataLine.split('","').length, 11);
});

test('CSV neutralizes spreadsheet formula injection', () => {
  for (const payload of ['=1+1', '+1', '-1', '@SUM(A1)']) {
    const csv = generateCSV([entry({ custody: { custodian: payload } })]);
    assert.ok(csv.includes(`"'${payload}"`), `${payload} was not neutralized`);
  }
});

test('CSV starts with a UTF-8 BOM and uses CRLF', () => {
  const csv = generateCSV([entry({ custody: { custodian: 'Jörg Müller' } })]);
  assert.equal(csv.charCodeAt(0), 0xfeff);
  assert.ok(csv.includes('\r\n'));
  assert.ok(csv.includes('Jörg Müller'));
});
