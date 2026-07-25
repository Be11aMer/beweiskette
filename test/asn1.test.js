/**
 * Strict DER parser and encoder.
 *
 * This code parses untrusted input — timestamp tokens travel inside imported
 * chain files, not only over TLS from a TSA. Two properties matter:
 *
 *   1. It never accepts two encodings of the same value. Parser leniency
 *      around a signature check is how signature checks get bypassed.
 *   2. Malformed input produces a controlled Asn1Error, never a hang, a crash,
 *      or a partially recovered structure that reaches a verifier.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import {
  parse, parseOnly, readOID, readInteger, readBitString, readTime,
  encode, encodeSequence, encodeSet, encodeInteger, encodeIntegerFromBytes,
  encodeOctetString, encodeOID, encodeNull, encodeBoolean, toHex,
  Asn1Error, TAG, CLASS,
} from '../src/asn1.js';

const fixture = (name) => new Uint8Array(readFileSync(new URL(`./fixtures/tsa/${name}`, import.meta.url)));

test('parses a real RFC 3161 response produced by OpenSSL', () => {
  const root = parseOnly(fixture('response.tsr'));
  assert.equal(root.is(TAG.SEQUENCE), true);
  assert.equal(root.children.length, 2);

  assert.equal(readInteger(root.path(0, 0)), 0n); // PKIStatus: granted
  assert.equal(readOID(root.path(1, 0)), '1.2.840.113549.1.7.2'); // id-signedData
});

test('extracts the message imprint and time from the real token', () => {
  const root = parseOnly(fixture('response.tsr'));
  const signedData = root.path(1, 1, 0);
  const tstInfo = parseOnly(signedData.path(2, 1, 0).content);

  assert.equal(readOID(tstInfo.at(1)), '1.2.3.4.1');
  assert.equal(readOID(tstInfo.path(2, 0, 0)), '2.16.840.1.101.3.4.2.1'); // sha-256
  assert.equal(
    toHex(tstInfo.path(2, 1).content),
    'ec6b196bc741e76a51df8ad44075ccb23574e8eac47807c68636fe811d334058',
  );
  assert.match(readTime(tstInfo.at(4)), /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
});

test('every node reproduces its own byte range', () => {
  const bytes = fixture('response.tsr');
  const root = parseOnly(bytes);
  const walk = (node) => {
    assert.deepEqual(node.bytes, bytes.subarray(node.start, node.end));
    assert.deepEqual(node.content, bytes.subarray(node.contentStart, node.contentEnd));
    for (const child of node.children || []) walk(child);
  };
  walk(root);
});

// ── Strictness ─────────────────────────────────────────────────────

test('rejects indefinite-length encoding', () => {
  // Legal BER, forbidden in DER. SEQUENCE, indefinite, NULL, end-of-contents.
  const ber = Uint8Array.from([0x30, 0x80, 0x05, 0x00, 0x00, 0x00]);
  assert.throws(() => parseOnly(ber), Asn1Error);
  assert.throws(() => parseOnly(ber), /indefinite/);
});

test('rejects non-minimal length encodings', () => {
  // Length 1 expressed in long form, and a long form with a leading zero.
  assert.throws(() => parseOnly(Uint8Array.from([0x04, 0x81, 0x01, 0xaa])), /non-minimal/);
  assert.throws(() => parseOnly(Uint8Array.from([0x04, 0x82, 0x00, 0x80, ...new Array(128).fill(0)])), /non-minimal/);
});

test('rejects truncation at any point in a real token', () => {
  const bytes = fixture('response.tsr');
  for (let length = 1; length < bytes.length; length++) {
    assert.throws(
      () => parseOnly(bytes.subarray(0, length)),
      Asn1Error,
      `truncation to ${length} bytes was accepted`,
    );
  }
});

test('rejects trailing bytes after the top-level element', () => {
  const good = encodeSequence([encodeNull()]);
  const withTrailer = new Uint8Array(good.length + 1);
  withTrailer.set(good);
  assert.throws(() => parseOnly(withTrailer), /trailing/);
});

test('rejects content that runs past the buffer', () => {
  assert.throws(() => parseOnly(Uint8Array.from([0x04, 0x10, 0x01, 0x02])), /past end/);
});

test('rejects children that overrun their parent', () => {
  // SEQUENCE claiming 3 bytes, containing an OCTET STRING claiming 4.
  assert.throws(() => parseOnly(Uint8Array.from([0x30, 0x03, 0x04, 0x04, 0xaa, 0xbb])), Asn1Error);
});

test('rejects high-tag-number form and deep nesting', () => {
  assert.throws(() => parseOnly(Uint8Array.from([0x1f, 0x81, 0x00, 0x00])), /high-tag-number/);

  let deep = encodeNull();
  for (let i = 0; i < 60; i++) deep = encodeSequence([deep]);
  assert.throws(() => parseOnly(deep), /nesting too deep/);
});

test('rejects non-minimal INTEGER encodings', () => {
  assert.throws(() => readInteger(parseOnly(Uint8Array.from([0x02, 0x02, 0x00, 0x01]))), /non-minimal/);
  assert.throws(() => readInteger(parseOnly(Uint8Array.from([0x02, 0x02, 0xff, 0x80]))), /non-minimal/);
});

// ── Value decoding ─────────────────────────────────────────────────

test('decodes integers including negatives and large values', () => {
  const cases = [0n, 1n, 127n, 128n, 255n, 256n, -1n, -128n, -129n, 1n << 128n, -(1n << 100n)];
  for (const value of cases) {
    assert.equal(readInteger(parseOnly(encodeInteger(value))), value, `failed for ${value}`);
  }
});

test('decodes object identifiers', () => {
  const oids = [
    '1.2.840.113549.1.7.2',      // id-signedData
    '2.16.840.1.101.3.4.2.1',    // sha-256
    '1.2.840.113549.1.9.16.1.4', // id-ct-TSTInfo
    '1.3.6.1.5.5.7.3.8',         // id-kp-timeStamping
    '0.4.0.1733.2.1',            // multi-byte arcs
  ];
  for (const oid of oids) {
    assert.equal(readOID(parseOnly(encodeOID(oid))), oid);
  }
});

test('rejects non-minimal OID arc encodings', () => {
  // 0x80 as a leading continuation byte is a padded arc.
  assert.throws(() => readOID(parseOnly(Uint8Array.from([0x06, 0x03, 0x2a, 0x80, 0x01]))), /non-minimal/);
});

test('decodes UTCTime and GeneralizedTime as UTC', () => {
  const utc = encode(TAG.UTC_TIME, new TextEncoder().encode('260725054210Z'));
  assert.equal(readTime(parseOnly(utc)), '2026-07-25T05:42:10.000Z');

  const gen = encode(TAG.GENERALIZED_TIME, new TextEncoder().encode('20260725054210Z'));
  assert.equal(readTime(parseOnly(gen)), '2026-07-25T05:42:10.000Z');

  const frac = encode(TAG.GENERALIZED_TIME, new TextEncoder().encode('20260725054210.5Z'));
  assert.equal(readTime(parseOnly(frac)), '2026-07-25T05:42:10.500Z');
});

test('rejects times without an explicit UTC marker', () => {
  // Legal ASN.1, but the offset forms leave the meaning timezone-dependent.
  const local = encode(TAG.GENERALIZED_TIME, new TextEncoder().encode('20260725054210'));
  assert.throws(() => readTime(parseOnly(local)), /malformed/);
  const offset = encode(TAG.GENERALIZED_TIME, new TextEncoder().encode('20260725054210+0200'));
  assert.throws(() => readTime(parseOnly(offset)), /malformed/);
});

test('rejects a BIT STRING that is not byte-aligned', () => {
  assert.throws(() => readBitString(parseOnly(Uint8Array.from([0x03, 0x02, 0x03, 0xf8]))), /byte-aligned/);
  assert.deepEqual(readBitString(parseOnly(Uint8Array.from([0x03, 0x02, 0x00, 0xf8]))), Uint8Array.from([0xf8]));
});

test('readers reject the wrong tag rather than reinterpreting bytes', () => {
  const octet = parseOnly(encodeOctetString(Uint8Array.from([1, 2, 3])));
  assert.throws(() => readOID(octet), /expected an OBJECT IDENTIFIER/);
  assert.throws(() => readInteger(octet), /expected an INTEGER/);
  assert.throws(() => readBitString(octet), /expected a BIT STRING/);
  assert.throws(() => readTime(octet), /expected UTCTime/);
});

// ── Encoding ───────────────────────────────────────────────────────

test('encodes lengths in short and long form correctly', () => {
  for (const size of [0, 1, 127, 128, 255, 256, 65535, 65536]) {
    const node = parseOnly(encodeOctetString(new Uint8Array(size)));
    assert.equal(node.content.length, size, `wrong length for ${size}`);
  }
});

test('encoded structures round-trip through the parser', () => {
  const der = encodeSequence([
    encodeInteger(1),
    encodeSequence([encodeOID('2.16.840.1.101.3.4.2.1'), encodeNull()]),
    encodeOctetString(Uint8Array.from([0xde, 0xad, 0xbe, 0xef])),
    encodeBoolean(true),
    encodeSet([encodeInteger(-5)]),
  ]);
  const node = parseOnly(der);

  assert.equal(node.is(TAG.SEQUENCE), true);
  assert.equal(readInteger(node.at(0)), 1n);
  assert.equal(readOID(node.path(1, 0)), '2.16.840.1.101.3.4.2.1');
  assert.equal(toHex(node.at(2).content), 'deadbeef');
  assert.equal(node.at(3).content[0], 0xff);
  assert.equal(node.at(4).is(TAG.SET), true);
  assert.equal(readInteger(node.path(4, 0)), -5n);
});

test('encodeIntegerFromBytes keeps large magnitudes positive and minimal', () => {
  const highBit = Uint8Array.from([0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
  assert.ok(readInteger(parseOnly(encodeIntegerFromBytes(highBit))) > 0n);

  const padded = Uint8Array.from([0x00, 0x00, 0x2a]);
  assert.equal(readInteger(parseOnly(encodeIntegerFromBytes(padded))), 42n);

  assert.equal(readInteger(parseOnly(encodeIntegerFromBytes(Uint8Array.from([0x00])))), 0n);
});

test('context-specific tags are distinguished from universal ones', () => {
  const node = parseOnly(encode(0xa0, encodeInteger(7)));
  assert.equal(node.tagClass, CLASS.CONTEXT);
  assert.equal(node.isContext(0), true);
  assert.equal(node.is(TAG.SEQUENCE), false);
});

// ── Robustness ─────────────────────────────────────────────────────

test('random input never escapes as an unexpected error', () => {
  for (let trial = 0; trial < 3000; trial++) {
    const bytes = new Uint8Array(1 + Math.floor(Math.random() * 60));
    crypto.getRandomValues(bytes);
    try {
      parseOnly(bytes);
    } catch (err) {
      assert.ok(err instanceof Asn1Error, `unexpected ${err.name}: ${err.message}`);
    }
  }
});

test('corrupting a real token never escapes as an unexpected error', () => {
  const original = fixture('response.tsr');
  for (let trial = 0; trial < 1500; trial++) {
    const fuzzed = original.slice();
    const flips = 1 + Math.floor(Math.random() * 8);
    for (let i = 0; i < flips; i++) {
      fuzzed[Math.floor(Math.random() * fuzzed.length)] = Math.floor(Math.random() * 256);
    }
    try {
      const root = parseOnly(fuzzed);
      // If it parsed, the structure must still be internally consistent.
      const walk = (n) => {
        assert.ok(n.end <= fuzzed.length);
        for (const c of n.children || []) walk(c);
      };
      walk(root);
    } catch (err) {
      assert.ok(err instanceof Asn1Error, `unexpected ${err.name}: ${err.message}`);
    }
  }
});

test('parse rejects non-Uint8Array input', () => {
  for (const bad of [null, undefined, 'abc', 42, [1, 2, 3], new ArrayBuffer(4)]) {
    assert.throws(() => parseOnly(bad), Asn1Error);
  }
});
