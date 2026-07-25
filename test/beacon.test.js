/**
 * Randomness-beacon lower bound.
 *
 * The property under test is "no earlier than": an entry containing pulse N
 * cannot predate pulse N's publication, because pulse values are
 * unpredictable. Authenticity is established by looking the pulse up in NIST's
 * public archive — comparePulse models that check — not by trusting this code.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { extractPulse, checkPulseSelfConsistency, comparePulse, archiveUrl, VERDICT } from '../src/beacon.js';

const toHex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

/**
 * Build a structurally valid pulse. outputValue is SHA-512(signatureValue),
 * which is the Beacon 2.0 invariant.
 */
async function makePulse({ pulseIndex = 4242, chainIndex = 1, timeStamp = '2026-07-25T05:42:00.000Z', signatureBytes } = {}) {
  const signature = signatureBytes || crypto.getRandomValues(new Uint8Array(256));
  const output = new Uint8Array(await crypto.subtle.digest('SHA-512', signature));
  return {
    pulse: {
      uri: `https://beacon.nist.gov/beacon/2.0/chain/${chainIndex}/pulse/${pulseIndex}`,
      version: 'Version 2.0',
      chainIndex,
      pulseIndex,
      timeStamp,
      signatureValue: toHex(signature).toUpperCase(),
      outputValue: toHex(output).toUpperCase(),
    },
  };
}

test('extracts the fields a third party needs to look the pulse up', async () => {
  const record = extractPulse(await makePulse());
  assert.equal(record.source, 'nist-beacon-2.0');
  assert.equal(record.pulse_index, 4242);
  assert.equal(record.chain_index, 1);
  assert.equal(record.pulse_time, '2026-07-25T05:42:00.000Z');
  assert.match(record.output_value, /^[0-9a-f]{128}$/);
});

test('hex is normalised to lowercase', async () => {
  // A server changing its hex casing must not change an entry's hash.
  const raw = await makePulse();
  const upper = extractPulse(raw);
  raw.pulse.outputValue = raw.pulse.outputValue.toLowerCase();
  assert.equal(extractPulse(raw).output_value, upper.output_value);
});

test('the recorded pulse survives canonicalization', async () => {
  // It goes into the hashed payload, so it must contain no floats or
  // undefined values.
  const { sortedStringify } = await import('../src/canonical.js');
  const record = extractPulse(await makePulse());
  assert.doesNotThrow(() => sortedStringify(record));
  assert.equal(Number.isInteger(record.pulse_index), true);
});

test('malformed pulses are rejected rather than partially accepted', async () => {
  const mutations = [
    ['missing outputValue', (p) => { delete p.pulse.outputValue; }],
    ['short outputValue', (p) => { p.pulse.outputValue = 'abcd'; }],
    ['non-hex signature', (p) => { p.pulse.signatureValue = 'not hex at all'; }],
    ['negative index', (p) => { p.pulse.pulseIndex = -1; }],
    ['non-numeric index', (p) => { p.pulse.pulseIndex = 'soon'; }],
    ['bad timestamp', (p) => { p.pulse.timeStamp = 'whenever'; }],
  ];
  for (const [name, mutate] of mutations) {
    const raw = await makePulse();
    mutate(raw);
    assert.throws(() => extractPulse(raw), Error, `accepted a pulse with ${name}`);
  }
  for (const bad of [null, undefined, 42, 'pulse', {}]) {
    assert.throws(() => extractPulse(bad), Error);
  }
});

test('a self-consistent pulse is reported as UNVERIFIED, never VERIFIED', async () => {
  // The structural check proves the pulse is not internally contradictory. It
  // does not prove NIST issued it, and must not be presented as if it did.
  const result = await checkPulseSelfConsistency(await makePulse());
  assert.equal(result.verdict, VERDICT.UNVERIFIED);
  assert.match(result.reason, /archive/);
});

test('a fabricated output value is INVALID', async () => {
  const raw = await makePulse();
  raw.pulse.outputValue = 'ab'.repeat(64);
  const result = await checkPulseSelfConsistency(raw);
  assert.equal(result.verdict, VERDICT.INVALID);
  assert.match(result.reason, /not self-consistent/);
});

test('altering the signature breaks self-consistency', async () => {
  const raw = await makePulse();
  const flipped = raw.pulse.signatureValue.split('');
  flipped[0] = flipped[0] === 'A' ? 'B' : 'A';
  raw.pulse.signatureValue = flipped.join('');
  assert.equal((await checkPulseSelfConsistency(raw)).verdict, VERDICT.INVALID);
});

test('a pulse matching the archive establishes the lower bound', async () => {
  const raw = await makePulse();
  const record = extractPulse(raw);
  const result = comparePulse(record, raw);
  assert.equal(result.verdict, VERDICT.VERIFIED);
  assert.match(result.reason, /no earlier than 2026-07-25/);
});

test('a pulse value that was never published is INVALID', async () => {
  // The forgery this defends against: claiming a pulse index while inventing
  // its value, to fake an earlier bound.
  const record = extractPulse(await makePulse({ pulseIndex: 900 }));
  const published = await makePulse({ pulseIndex: 900 });
  const result = comparePulse(record, published);
  assert.equal(result.verdict, VERDICT.INVALID);
  assert.match(result.reason, /never issued/);
});

test('comparing against the wrong pulse is UNVERIFIED, not a tampering claim', async () => {
  const record = extractPulse(await makePulse({ pulseIndex: 10 }));
  const other = await makePulse({ pulseIndex: 11 });
  const result = comparePulse(record, other);
  assert.equal(result.verdict, VERDICT.UNVERIFIED);
  assert.match(result.reason, /not the one referenced/);
});

test('an unreadable archive response does not read as tampering', async () => {
  const record = extractPulse(await makePulse());
  const result = comparePulse(record, { nonsense: true });
  assert.equal(result.verdict, VERDICT.UNVERIFIED);
});

test('archiveUrl points at the specific pulse', async () => {
  const record = extractPulse(await makePulse({ pulseIndex: 77, chainIndex: 2 }));
  assert.equal(archiveUrl(record), 'https://beacon.nist.gov/beacon/2.0/chain/2/pulse/77');
});
