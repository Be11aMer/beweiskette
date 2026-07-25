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

import { sortedStringify } from '../src/canonical.js';

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
  assert.equal(sortedStringify(-42), '-42');
  assert.equal(sortedStringify(''), '""');
});

test('values with no unambiguous encoding are rejected, not guessed at', () => {
  // Each of these previously collapsed onto some other value's encoding,
  // which is a collision primitive: two structurally different entries
  // sharing one entry_hash.
  const cases = [
    // {a:1,b:undefined} and {a:1} both used to encode as {"a":1}.
    [{ a: 1, b: undefined }, /undefined is not representable/],
    [[undefined], /undefined is not representable/],
    // NaN and Infinity both used to encode as null.
    [{ n: NaN }, /NaN has no JSON representation/],
    [{ n: Infinity }, /Infinity has no JSON representation/],
    // 5n used to encode as 5.
    [{ n: 10n }, /BigInt is not representable/],
    // Every one of these used to encode as {}.
    [{ d: new Date(0) }, /Date is not a plain object/],
    [{ m: new Map() }, /Map is not a plain object/],
    [{ s: new Set() }, /Set is not a plain object/],
    [{ r: /x/ }, /RegExp is not a plain object/],
    [{ f: () => 1 }, /function is not representable/],
    [{ s: Symbol('x') }, /symbol is not representable/],
  ];

  for (const [value, pattern] of cases) {
    assert.throws(() => sortedStringify(value), pattern, `did not reject ${String(value)}`);
  }
});

test('non-integer and unsafe numbers are rejected', () => {
  // JS renders 52.0 as "52" and Python as "52.0", so a float would give the
  // same entry two different hashes across the twin tools.
  assert.throws(() => sortedStringify({ n: 1.5 }), /non-integer/);
  assert.throws(() => sortedStringify({ n: 52.0000001 }), /non-integer/);
  assert.throws(() => sortedStringify({ n: 2 ** 60 }), /exactly representable/);
  assert.equal(sortedStringify({ n: 52 }), '{"n":52}');
});

test('the error names the offending path', () => {
  assert.throws(
    () => sortedStringify({ custody: { notes: undefined } }),
    /\$\.custody\.notes/,
  );
  assert.throws(() => sortedStringify({ list: [1, NaN] }), /\$\.list\[1\]/);
});

test('keys are ordered by code point, matching Python', () => {
  // Default JS sort compares UTF-16 code units, which places astral
  // characters below U+E000-U+FFFF and disagrees with Python's ordering.
  // U+FB00 (64256) sorts before U+1F517 (128023) by code point. By UTF-16
  // code unit the astral character's leading surrogate D83D (55357) would
  // sort first instead — the divergence this comparator exists to remove.
  const astral = '\u{1f517}';
  const bmp = 'ﬀ';
  const out = sortedStringify({ [astral]: 1, [bmp]: 2 });
  assert.ok(out.indexOf(bmp) < out.indexOf(astral), `wrong key order: ${out}`);
  assert.equal(out, `{"${bmp}":2,"${astral}":1}`);
});

test('non-ASCII is emitted raw, as Python does with ensure_ascii=False', () => {
  // With Python's default ensure_ascii=True the same entry would hash
  // differently in Zeitkette than it does here.
  assert.equal(sortedStringify({ n: 'Müller' }), '{"n":"Müller"}');
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
