/**
 * SHA-256 known-answer tests and hash comparison behaviour.
 *
 * The digest values below are the published NIST/FIPS-180-4 test vectors.
 * They exist so that a refactor of the hashing path (e.g. moving to chunked
 * hashing) is provably digest-compatible with what came before — every entry
 * hash in every chain ever produced by this tool depends on it.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { hashFile, hashString, constantTimeEqual } from '../src/crypto.js';

const VECTORS = [
  ['', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'],
  ['abc', 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'],
  [
    'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq',
    '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1',
  ],
];

test('hashString matches the FIPS-180-4 vectors', async () => {
  for (const [input, expected] of VECTORS) {
    assert.equal(await hashString(input), expected);
  }
});

test('hashString hashes UTF-8 bytes, not UTF-16 code units', async () => {
  // "ü" is one UTF-16 code unit but two UTF-8 bytes. Hashing the wrong
  // encoding is the classic way two implementations silently disagree.
  const expected = await hashString('ü');
  const viaBytes = await hashFile(new Blob([new Uint8Array([0xc3, 0xbc])]));
  assert.equal(expected, viaBytes);
});

test('hashFile digests raw file bytes', async () => {
  const file = new File(['abc'], 'evidence.txt', { type: 'text/plain' });
  assert.equal(await hashFile(file), VECTORS[1][1]);
});

test('hashFile handles an empty file', async () => {
  const file = new File([], 'empty.bin');
  assert.equal(await hashFile(file), VECTORS[0][1]);
});

test('constantTimeEqual accepts identical strings and rejects differences', () => {
  const h = VECTORS[1][1];
  assert.equal(constantTimeEqual(h, h), true);
  assert.equal(constantTimeEqual(h, h.slice(0, -1) + '0'), false);
  // A difference in the very first character must be caught just as reliably
  // as one in the last — the loop must not short-circuit.
  assert.equal(constantTimeEqual(h, '0' + h.slice(1)), false);
});

test('constantTimeEqual rejects non-strings and length mismatches', () => {
  assert.equal(constantTimeEqual('abc', 'abcd'), false);
  assert.equal(constantTimeEqual(undefined, 'abc'), false);
  assert.equal(constantTimeEqual('abc', null), false);
  assert.equal(constantTimeEqual(null, null), false);
  // A missing entry_hash must never compare equal to a computed one.
  assert.equal(constantTimeEqual(VECTORS[0][1], undefined), false);
});
