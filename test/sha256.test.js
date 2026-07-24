/**
 * The hand-written incremental SHA-256 must agree with Web Crypto exactly.
 *
 * It is used only above the size threshold where crypto.subtle can no longer
 * buffer the file. That means the same chain can contain digests produced by
 * both implementations, so a single differing bit would split the chain at the
 * threshold. These tests check the published FIPS 180-4 vectors, then compare
 * directly against crypto.subtle over randomized inputs and every buffer
 * boundary the incremental path can land on.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { Sha256, sha256Hex } from '../src/sha256.js';

const encoder = new TextEncoder();

async function webCrypto(bytes) {
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('');
}

test('matches the FIPS 180-4 published vectors', () => {
  const vectors = [
    ['', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'],
    ['abc', 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'],
    ['abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq',
     '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1'],
    ['abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu',
     'cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1'],
  ];
  for (const [input, expected] of vectors) {
    assert.equal(sha256Hex(encoder.encode(input)), expected, `failed for ${JSON.stringify(input)}`);
  }
});

test('the million-a vector', () => {
  // FIPS 180-4: one million 'a' characters. Exercises many block iterations
  // and a byte count past a single block's length field.
  const hasher = new Sha256();
  const chunk = new Uint8Array(1000).fill(0x61);
  for (let i = 0; i < 1000; i++) hasher.update(chunk);
  assert.equal(hasher.digest(), 'cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0');
});

test('agrees with Web Crypto at every padding boundary', async () => {
  // Lengths around 55/56 (length field spills into an extra block) and around
  // 63/64/65 (block boundaries) are where padding bugs live.
  for (const length of [0, 1, 54, 55, 56, 57, 63, 64, 65, 111, 112, 113, 127, 128, 129, 1023, 1024]) {
    const bytes = new Uint8Array(length);
    for (let i = 0; i < length; i++) bytes[i] = (i * 31 + 7) & 0xff;
    assert.equal(sha256Hex(bytes), await webCrypto(bytes), `mismatch at length ${length}`);
  }
});

test('agrees with Web Crypto on random inputs', async () => {
  for (let i = 0; i < 100; i++) {
    const bytes = new Uint8Array(Math.floor(Math.random() * 5000));
    crypto.getRandomValues(bytes);
    assert.equal(sha256Hex(bytes), await webCrypto(bytes));
  }
});

test('the result depends only on the concatenation, not on the chunking', async () => {
  const total = new Uint8Array(4096);
  crypto.getRandomValues(total);
  const expected = await webCrypto(total);

  for (const chunkSize of [1, 7, 63, 64, 65, 100, 512, 4096]) {
    const hasher = new Sha256();
    for (let offset = 0; offset < total.length; offset += chunkSize) {
      hasher.update(total.subarray(offset, Math.min(offset + chunkSize, total.length)));
    }
    assert.equal(hasher.digest(), expected, `mismatch with chunk size ${chunkSize}`);
  }
});

test('handles randomly sized successive chunks', async () => {
  const total = new Uint8Array(10000);
  crypto.getRandomValues(total);
  const hasher = new Sha256();
  let offset = 0;
  while (offset < total.length) {
    const size = 1 + Math.floor(Math.random() * 200);
    hasher.update(total.subarray(offset, Math.min(offset + size, total.length)));
    offset += size;
  }
  assert.equal(hasher.digest(), await webCrypto(total));
});

test('empty updates are harmless', async () => {
  const hasher = new Sha256();
  hasher.update(new Uint8Array(0));
  hasher.update(encoder.encode('abc'));
  hasher.update(new Uint8Array(0));
  assert.equal(hasher.digest(), await webCrypto(encoder.encode('abc')));
});

test('high bytes are treated as unsigned', async () => {
  // A signed-byte slip shows up only once values exceed 0x7f.
  const bytes = new Uint8Array(256);
  for (let i = 0; i < 256; i++) bytes[i] = i;
  assert.equal(sha256Hex(bytes), await webCrypto(bytes));

  const allHigh = new Uint8Array(200).fill(0xff);
  assert.equal(sha256Hex(allHigh), await webCrypto(allHigh));
});

test('reuse after digest is refused rather than returning a wrong answer', () => {
  const hasher = new Sha256();
  hasher.update(encoder.encode('abc'));
  hasher.digest();
  assert.throws(() => hasher.digest(), /twice/);
  assert.throws(() => hasher.update(encoder.encode('x')), /after digest/);
});

test('instances do not share state', () => {
  const a = new Sha256().update(encoder.encode('abc'));
  const b = new Sha256().update(encoder.encode('different'));
  assert.equal(a.digest(), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  assert.notEqual(b.digest(), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
});
