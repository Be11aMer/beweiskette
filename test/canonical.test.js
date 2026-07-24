/**
 * Canonical serialization tests.
 *
 * sortedStringify is the load-bearing input to every entry hash. If two
 * structurally different entries can serialize to the same string, they get
 * the same entry_hash and the chain's tamper-evidence is void. If the same
 * entry serializes differently across implementations (this app vs. the
 * exported report vs. Zeitkette's Python), verification disagrees about a
 * chain that never changed.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { sortedStringify } from '../src/utils.js';

test('keys are sorted regardless of insertion order', () => {
  const a = sortedStringify({ zebra: 1, alpha: 2, mike: 3 });
  const b = sortedStringify({ mike: 3, zebra: 1, alpha: 2 });
  assert.equal(a, b);
  assert.equal(a, '{"alpha":2,"mike":3,"zebra":1}');
});

test('nested objects are sorted recursively', () => {
  const out = sortedStringify({ b: { z: 1, a: 2 }, a: { y: 3, b: 4 } });
  assert.equal(out, '{"a":{"b":4,"y":3},"b":{"a":2,"z":1}}');
});

test('output contains no insignificant whitespace', () => {
  const out = sortedStringify({ a: 1, b: [1, 2], c: { d: 'e' } });
  assert.equal(out, '{"a":1,"b":[1,2],"c":{"d":"e"}}');
});

test('array order is preserved (arrays are ordered, objects are not)', () => {
  assert.equal(sortedStringify([3, 1, 2]), '[3,1,2]');
  assert.notEqual(sortedStringify([1, 2]), sortedStringify([2, 1]));
});

test('scalars serialize as JSON', () => {
  assert.equal(sortedStringify(null), 'null');
  assert.equal(sortedStringify(true), 'true');
  assert.equal(sortedStringify(false), 'false');
  assert.equal(sortedStringify(0), '0');
  assert.equal(sortedStringify(-1.5), '-1.5');
  assert.equal(sortedStringify(''), '""');
});

test('strings with structural characters are escaped, not injected', () => {
  // A note containing a quote or brace must not be able to alter the shape
  // of the canonical form — that would be a collision primitive.
  assert.equal(sortedStringify({ n: 'a"b' }), '{"n":"a\\"b"}');
  assert.equal(sortedStringify({ n: '","x":"' }), '{"n":"\\",\\"x\\":\\""}');
  assert.equal(sortedStringify({ n: 'line\nbreak' }), '{"n":"line\\nbreak"}');
});

test('field boundaries are unambiguous', () => {
  // The classic concatenation collision: {a:"xy",b:"z"} vs {a:"x",b:"yz"}
  // must not produce the same canonical form.
  assert.notEqual(
    sortedStringify({ a: 'xy', b: 'z' }),
    sortedStringify({ a: 'x', b: 'yz' }),
  );
});

test('serialization is stable across repeated calls', () => {
  const entry = {
    custody: { custodian: 'A. Muster', case_reference: 'CASE-1', notes: '' },
    evidence: { file_hash: 'ab'.repeat(32), file_name: 'x.jpg', file_size: 12 },
    metadata: null,
    prev_hash: 'GENESIS',
  };
  const first = sortedStringify(entry);
  for (let i = 0; i < 100; i++) {
    assert.equal(sortedStringify(entry), first);
  }
});
