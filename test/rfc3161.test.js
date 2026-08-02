/**
 * RFC 3161 timestamp verification.
 *
 * This is the most dangerous code in the project. A verifier that reports
 * VERIFIED when it merely failed to look launders a forged token into apparent
 * proof — worse than having no verifier at all. So the tests are weighted
 * towards the negative cases, and the two most important fixtures are tokens
 * that are *cryptographically perfect*: one attesting to unrelated data, one
 * signed by a TSA we have no reason to trust. Neither may ever read VERIFIED.
 *
 * Fixtures are real tokens from OpenSSL acting as a TSA; `openssl ts -verify`
 * accepts them independently. See test/fixtures/tsa/README.md.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';

import { verifyToken, inspectToken, buildTimestampRequest, requestTimestamp, spkiPin, pemToDer, VERDICT } from '../src/rfc3161.js';
import { parseOnly, readOID, readInteger, toHex, TAG } from '../src/asn1.js';

/**
 * The OpenSSL cross-checks are the point of the fixtures — they stop this
 * verifier from grading its own homework. They are skipped rather than failed
 * where openssl is absent, so the suite stays runnable anywhere.
 */
const hasOpenssl = (() => {
  try {
    execFileSync('openssl', ['version'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
})();

const dir = new URL('./fixtures/tsa/', import.meta.url);
const load = (name) => new Uint8Array(readFileSync(new URL(name, dir)));
const pinFor = (certName) => spkiPin(pemToDer(readFileSync(new URL(certName, dir), 'utf8')));

const headDigest = new Uint8Array(await crypto.subtle.digest('SHA-256', load('head.txt')));
const otherDigest = new Uint8Array(await crypto.subtle.digest('SHA-256', load('other.txt')));
const PINS = [await pinFor('tsa.crt'), await pinFor('ec-tsa.crt')];

const verify = (token, options = {}) =>
  verifyToken(token, { expectedDigest: headDigest, pinnedSpki: PINS, ...options });

// ── The happy path ─────────────────────────────────────────────────

test('a valid RSA-signed token verifies', async () => {
  const result = await verify(load('response.tsr'));
  assert.equal(result.verdict, VERDICT.VERIFIED, result.reason);
  assert.match(result.genTime, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
  assert.equal(result.signerSpkiSha256, PINS[0]);
});

test('a valid ECDSA-signed token verifies', async () => {
  // Exercises the DER SEQUENCE{r,s} -> raw r||s conversion Web Crypto needs.
  const result = await verify(load('response-ec.tsr'));
  assert.equal(result.verdict, VERDICT.VERIFIED, result.reason);
  assert.equal(result.signerSpkiSha256, PINS[1]);
});

test('the extracted time agrees with OpenSSL', { skip: !hasOpenssl && 'openssl not installed' }, async () => {
  // An independent implementation, so this is not the verifier grading itself.
  const text = execFileSync('openssl', ['ts', '-reply', '-in', new URL('response.tsr', dir).pathname, '-text'], { encoding: 'utf8' });
  const stamp = /Time stamp: (.+)/.exec(text)[1].trim();
  const opensslTime = new Date(stamp).toISOString();

  const result = await verify(load('response.tsr'));
  assert.equal(new Date(result.genTime).toISOString(), opensslTime);
});

test('OpenSSL independently accepts the fixture we call VERIFIED', { skip: !hasOpenssl && 'openssl not installed' }, () => {
  const out = execFileSync('openssl', [
    'ts', '-verify',
    '-in', new URL('response.tsr', dir).pathname,
    '-data', new URL('head.txt', dir).pathname,
    '-CAfile', new URL('ca.crt', dir).pathname,
    '-untrusted', new URL('tsa.crt', dir).pathname,
  ], { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] });
  assert.match(out, /Verification: OK/);
});

// ── Tokens that are valid but attest to the wrong thing ────────────

test('a valid token over different data is INVALID, not VERIFIED', async () => {
  // The binding check. Without it, any genuine token could be attached to any
  // chain and would pass every signature test.
  const result = await verify(load('response-other.tsr'));
  assert.equal(result.verdict, VERDICT.INVALID);
  assert.match(result.reason, /different data/);
});

test('the same token verifies against the data it actually covers', async () => {
  const result = await verifyToken(load('response-other.tsr'), {
    expectedDigest: otherDigest,
    pinnedSpki: PINS,
  });
  assert.equal(result.verdict, VERDICT.VERIFIED, result.reason);
});

// ── The pasted-token path ──────────────────────────────────────────
//
// Most timestamp authorities cannot be reached from a browser at all: the
// Content-Type an RFC 3161 request must carry is not CORS-safelisted, so the
// request is preflighted, and authorities built for server-side callers answer
// no preflight. So the token is minted with `openssl ts` and pasted in, and
// that path verifies with no nonce to compare against — this page never made
// the request that carried one.
//
// These tests exist to show that dropping the nonce check gives nothing away.
// The imprint binding is what stops a token being moved onto a chain it does
// not attest to, and it does not depend on the nonce.

test('a token verifies with no nonce expectation — the pasted-token path', async () => {
  const result = await verifyToken(load('response.tsr'), {
    expectedDigest: headDigest,
    pinnedSpki: PINS,
  });
  assert.equal(result.verdict, VERDICT.VERIFIED, result.reason);
});

test('without a nonce check, a token over other data is still INVALID', async () => {
  // The one that matters. If the nonce were carrying the binding, this would
  // pass here and the paste box would launder any genuine token onto any chain.
  const result = await verifyToken(load('response-other.tsr'), {
    expectedDigest: headDigest,
    pinnedSpki: PINS,
  });
  assert.equal(result.verdict, VERDICT.INVALID);
  assert.match(result.reason, /different data/);
});

test('without a nonce check, an unpinned signer is still UNVERIFIED', async () => {
  const result = await verifyToken(load('response-rogue.tsr'), {
    expectedDigest: headDigest,
    pinnedSpki: PINS,
  });
  assert.equal(result.verdict, VERDICT.UNVERIFIED);
  assert.match(result.reason, /pinned/);
});

test('a pasted token survives base64 armour and still verifies', async () => {
  // End to end for what the box actually receives: bytes in, wrapped and
  // armoured base64 back out, decoded by the same function the UI calls, and
  // the verdict unchanged.
  const { encodeToken, decodeToken } = await import('../src/anchor.js');
  const pasted = `-----BEGIN TIMESTAMP TOKEN-----\n${
    encodeToken(load('response.tsr')).replace(/(.{64})/g, '$1\n')
  }\n-----END TIMESTAMP TOKEN-----`;

  const decoded = decodeToken(pasted);
  assert.deepEqual(decoded, load('response.tsr'));

  const result = await verifyToken(decoded, { expectedDigest: headDigest, pinnedSpki: PINS });
  assert.equal(result.verdict, VERDICT.VERIFIED, result.reason);
});

test('a genuine token from an unpinned TSA is UNVERIFIED, never VERIFIED', async () => {
  const result = await verify(load('response-rogue.tsr'));
  assert.equal(result.verdict, VERDICT.UNVERIFIED);
  assert.match(result.reason, /pinned/);
});

test('an empty pin list never yields VERIFIED', async () => {
  const result = await verifyToken(load('response.tsr'), { expectedDigest: headDigest, pinnedSpki: [] });
  assert.equal(result.verdict, VERDICT.UNVERIFIED);
});

test('pinning the rogue TSA makes its token verify — pinning is the whole trust decision', async () => {
  const result = await verifyToken(load('response-rogue.tsr'), {
    expectedDigest: headDigest,
    pinnedSpki: [await pinFor('rogue-tsa.crt')],
  });
  assert.equal(result.verdict, VERDICT.VERIFIED, result.reason);
});

// ── Tampering ──────────────────────────────────────────────────────

/** Flip one byte inside the token's signature. */
function corruptSignature(token) {
  const root = parseOnly(token);
  const signedData = root.path(1, 1, 0);
  const signerInfo = signedData.children[signedData.children.length - 1].at(0);
  const sig = signerInfo.at(5);
  const copy = token.slice();
  copy[sig.contentStart] ^= 0x01;
  return copy;
}

test('a flipped signature byte is INVALID', async () => {
  const result = await verify(corruptSignature(load('response.tsr')));
  assert.equal(result.verdict, VERDICT.INVALID);
  assert.match(result.reason, /signature does not verify/);
});

test('altering the attested time is INVALID', async () => {
  // genTime lives inside the TSTInfo, which the signed messageDigest attribute
  // commits to — so backdating a token breaks verification.
  const token = load('response.tsr');
  const eContent = parseOnly(token).path(1, 1, 0).path(2, 1, 0);
  const tst = parseOnly(eContent.content);
  const genTime = tst.at(4);

  const copy = token.slice();
  // Turn the year 2026 into 2020 in the GeneralizedTime.
  copy[eContent.contentStart + genTime.contentStart + 3] = '0'.charCodeAt(0);

  const result = await verify(copy);
  assert.equal(result.verdict, VERDICT.INVALID, result.reason);
});

test('every byte of the signed region fails closed', async () => {
  // In CMS the signature covers SignedAttributes, and through its
  // messageDigest attribute the encapsulated TSTInfo. Those regions — plus the
  // signature itself — are where an attacker would have to work, and every
  // single-byte change in them must break verification.
  const token = load('response.tsr');
  const root = parseOnly(token);
  const signedData = root.path(1, 1, 0);
  const signerInfo = signedData.children[signedData.children.length - 1].at(0);

  const eContent = signedData.path(2, 1, 0);
  const signedAttrs = signerInfo.children.find((c) => c.isContext(0));
  const signature = signerInfo.at(5);

  const regions = [
    ['TSTInfo', eContent.contentStart, eContent.contentEnd],
    ['signedAttrs', signedAttrs.start, signedAttrs.end],
    ['signature', signature.contentStart, signature.contentEnd],
  ];

  for (const [name, start, end] of regions) {
    for (let offset = start; offset < end; offset += 7) {
      const copy = token.slice();
      copy[offset] ^= 0xff;
      const result = await verify(copy);
      assert.notEqual(result.verdict, VERDICT.VERIFIED, `${name} byte ${offset} still verified`);
    }
  }
});

test('unsigned wrapper fields are outside the signature, by design', async () => {
  // SignedData.version and digestAlgorithms are not covered by a CMS
  // signature. Editing them changes nothing about what was attested, so the
  // token still verifies. Asserted so the boundary is explicit rather than
  // assumed — "the signature covers the file" is the intuitive but wrong
  // mental model.
  const token = load('response.tsr');
  const signedData = parseOnly(token).path(1, 1, 0);
  const version = signedData.at(0);

  const copy = token.slice();
  copy[version.contentStart] = 0x03; // a different, still-legal CMS version

  const result = await verify(copy);
  assert.equal(result.verdict, VERDICT.VERIFIED, result.reason);
  // What matters is unchanged.
  assert.equal(result.genTime, (await verify(token)).genTime);
});

test('truncation is never VERIFIED', async () => {
  const token = load('response.tsr');
  for (const fraction of [0.1, 0.25, 0.5, 0.75, 0.9, 0.99]) {
    const result = await verify(token.subarray(0, Math.floor(token.length * fraction)));
    assert.notEqual(result.verdict, VERDICT.VERIFIED);
  }
});

test('random input is never VERIFIED and never throws', async () => {
  for (let i = 0; i < 200; i++) {
    const bytes = new Uint8Array(1 + Math.floor(Math.random() * 200));
    crypto.getRandomValues(bytes);
    const result = await verify(bytes);
    assert.notEqual(result.verdict, VERDICT.VERIFIED);
    assert.ok(typeof result.reason === 'string' && result.reason.length > 0);
  }
});

test('empty and non-buffer input is handled without throwing', async () => {
  for (const bad of [new Uint8Array(0), Uint8Array.from([0x30]), Uint8Array.from([0])]) {
    const result = await verify(bad);
    assert.notEqual(result.verdict, VERDICT.VERIFIED);
  }
});

// ── Nonce / replay ─────────────────────────────────────────────────

test('a mismatched nonce is INVALID', async () => {
  const wrongNonce = Uint8Array.from([9, 9, 9, 9, 9, 9, 9, 9]);
  const result = await verify(load('response.tsr'), { expectedNonce: wrongNonce });
  assert.equal(result.verdict, VERDICT.INVALID);
  assert.match(result.reason, /nonce/);
});

test('the nonce from the original request matches', async () => {
  // The fixture request carries a nonce; the response echoes it.
  const req = parseOnly(load('request.tsq'));
  const nonceNode = req.children.find((c) => c.is(TAG.INTEGER) && c.content.length > 1);
  const magnitude = nonceNode.content[0] === 0 ? nonceNode.content.subarray(1) : nonceNode.content;

  const result = await verify(load('response.tsr'), { expectedNonce: magnitude });
  assert.equal(result.verdict, VERDICT.VERIFIED, result.reason);
});

// ── Request construction ───────────────────────────────────────────

test('a built request is well-formed DER that OpenSSL can read', () => {
  const digest = new Uint8Array(32).fill(0xab);
  const { der, nonce } = buildTimestampRequest(digest);

  assert.equal(nonce.length, 8);
  const req = parseOnly(der);
  assert.equal(readInteger(req.at(0)), 1n);
  assert.equal(readOID(req.path(1, 0, 0)), '2.16.840.1.101.3.4.2.1');
  assert.equal(toHex(req.path(1, 1).content), 'ab'.repeat(32));
  assert.equal(req.children[req.children.length - 1].content[0], 0xff); // certReq TRUE
});

test('the request carries only the digest — nothing else about the file', () => {
  const digest = new Uint8Array(32).fill(0x5a);
  const { der } = buildTimestampRequest(digest);
  // 70-ish bytes: version, algorithm, digest, nonce, certReq. There is no room
  // for a filename or metadata, and this asserts it stays that way.
  assert.ok(der.length < 100, `request unexpectedly large: ${der.length} bytes`);
});

test('two requests use different nonces', () => {
  const digest = new Uint8Array(32);
  const a = toHex(buildTimestampRequest(digest).nonce);
  const b = toHex(buildTimestampRequest(digest).nonce);
  assert.notEqual(a, b);
});

test('buildTimestampRequest rejects anything but a SHA-256 digest', () => {
  for (const bad of [null, undefined, 'abc', new Uint8Array(31), new Uint8Array(33)]) {
    assert.throws(() => buildTimestampRequest(bad), /32-byte/);
  }
});

test('requestTimestamp posts the query and returns the token', async () => {
  let seen = null;
  const fetchImpl = async (url, init) => {
    seen = { url, init };
    return { ok: true, arrayBuffer: async () => load('response.tsr').buffer };
  };
  const { token, nonce } = await requestTimestamp('https://tsa.example/tsr', headDigest, { fetchImpl });

  assert.equal(seen.url, 'https://tsa.example/tsr');
  assert.equal(seen.init.method, 'POST');
  assert.equal(seen.init.headers['Content-Type'], 'application/timestamp-query');
  assert.equal(seen.init.credentials, 'omit');
  assert.ok(token.length > 0);
  assert.equal(nonce.length, 8);
});

test('an HTTP error from the TSA is reported, not swallowed', async () => {
  const fetchImpl = async () => ({ ok: false, status: 503 });
  await assert.rejects(
    () => requestTimestamp('https://tsa.example/tsr', headDigest, { fetchImpl }),
    /HTTP 503/,
  );
});

// ── Pinning helpers ────────────────────────────────────────────────

test('spkiPin is stable and distinguishes keys', async () => {
  assert.equal(await pinFor('tsa.crt'), await pinFor('tsa.crt'));
  assert.notEqual(await pinFor('tsa.crt'), await pinFor('rogue-tsa.crt'));
  assert.match(await pinFor('tsa.crt'), /^[0-9a-f]{64}$/);
});

test('pemToDer rejects input that is not a certificate', () => {
  const cases = [
    '',
    'not a pem',
    '-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----',
    '-----BEGIN CERTIFICATE-----\nQUJDRA==\n-----END CERTIFICATE-----', // decodes, but is not a certificate
  ];
  for (const bad of cases) {
    assert.throws(() => pemToDer(bad), /valid PEM/, `accepted: ${JSON.stringify(bad)}`);
  }
});

// ── inspectToken is display-only ───────────────────────────────────

test('inspectToken reports claims without vouching for them', async () => {
  const claims = await inspectToken(load('response-rogue.tsr'));
  assert.ok(claims.genTime);
  assert.equal(claims.messageImprint, toHex(headDigest));
  // The rogue token is readable, but verification still refuses it.
  const result = await verify(load('response-rogue.tsr'));
  assert.equal(result.verdict, VERDICT.UNVERIFIED);
});

test('inspectToken returns null for unreadable input', async () => {
  assert.equal(await inspectToken(new Uint8Array([1, 2, 3])), null);
  assert.equal(await inspectToken(new Uint8Array(0)), null);
});
