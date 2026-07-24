/**
 * Cross-implementation canonicalization vectors.
 *
 * README claims Beweiskette and Zeitkette share a hash chain construction.
 * That claim was false: Python's json.dumps defaults to ensure_ascii=True and
 * escapes non-ASCII as \uXXXX where JavaScript emits raw UTF-8, so a custodian
 * named "Müller" hashed differently in the two tools. Key ordering diverged
 * too — Python sorts by code point, JavaScript's default sort by UTF-16 code
 * unit.
 *
 * test/vectors/canonical.json is the shared fixture that turns the claim into
 * something checkable. Zeitkette should run the same file against its own
 * canonicalizer; any implementation that reproduces every `canonical` and
 * `sha256` is compatible, and any that does not is not.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import { sortedStringify } from '../src/canonical.js';
import { hashString } from '../src/crypto.js';

const fixture = JSON.parse(
  readFileSync(new URL('./vectors/canonical.json', import.meta.url), 'utf8'),
);

test('the fixture covers the cases implementations actually diverge on', () => {
  const names = fixture.vectors.map((v) => v.name);
  for (const required of ['non-ascii latin', 'non-ascii keys', 'astral vs bmp key order', 'string escaping']) {
    assert.ok(names.includes(required), `missing vector: ${required}`);
  }
  assert.ok(fixture.python_equivalent.includes('ensure_ascii=False'));
});

test('every vector reproduces its canonical form and digest', async () => {
  for (const vector of fixture.vectors) {
    assert.equal(sortedStringify(vector.value), vector.canonical, `canonical form drifted for: ${vector.name}`);
    assert.equal(await hashString(vector.canonical), vector.sha256, `digest drifted for: ${vector.name}`);
  }
});

test('non-ASCII is emitted raw rather than escaped', () => {
  const vector = fixture.vectors.find((v) => v.name === 'non-ascii latin');
  assert.ok(vector.canonical.includes('Müller'), 'expected raw UTF-8');
  assert.ok(!vector.canonical.includes('\\u00fc'), 'expected no \\u escaping');
});

test('the fixture is JSON-round-trippable, so other languages can load it', () => {
  assert.deepEqual(JSON.parse(JSON.stringify(fixture)), fixture);
});
