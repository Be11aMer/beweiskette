/**
 * Randomness-beacon lower bound: proving an entry was made *no earlier than*
 * some moment.
 *
 * A timestamp token gives an upper bound — this chain existed no later than T.
 * A beacon pulse gives the other side. Pulse values are published on a fixed
 * cadence and cannot be predicted in advance, so a record containing pulse N
 * cannot have been created before pulse N was published. Combine the two and
 * the entry is bracketed rather than merely bounded.
 *
 * WHERE THE EVIDENTIARY VALUE ACTUALLY COMES FROM
 *
 * Not from this module verifying a signature. It comes from the pulse value
 * being unpredictable and independently republished: anyone can look up pulse
 * index N in NIST's public archive and compare it with what the entry claims.
 * That check needs neither this code nor any trust in it — it is the beacon
 * equivalent of `openssl ts -verify`, and it is the authoritative one.
 *
 * WHAT THIS MODULE CHECKS OFFLINE
 *
 * `outputValue == SHA-512(signatureValue)` is a structural invariant of the
 * Beacon 2.0 format. It costs nothing, needs no key, and catches a pulse whose
 * output value was simply made up. It is not a substitute for the archive
 * lookup and is not reported as one.
 *
 * WHAT THIS MODULE DELIBERATELY DOES NOT DO
 *
 * It does not verify the pulse's RSA signature. Doing that requires
 * reconstructing, byte for byte, the exact field concatenation NIST signs —
 * and that reconstruction cannot be validated here, because this build
 * environment has no route to beacon.nist.gov. An unvalidated layout fails in
 * a specifically harmful way: a mismatch is indistinguishable from a forged
 * pulse, so the app would accuse a genuine NIST pulse of being invalid. Being
 * wrong in that direction is worse than not checking, so signature status is
 * reported as UNVERIFIED with the reason stated, and the archive lookup is
 * surfaced instead. See docs/ANCHORING.md.
 */

import { VERDICT } from './rfc3161.js';

export { VERDICT };

const DEFAULT_BEACON_URL = 'https://beacon.nist.gov/beacon/2.0/pulse/last';
const HEX64 = /^[0-9A-Fa-f]{128}$/; // SHA-512 output, as NIST renders it

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

function toHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Reduce a raw Beacon 2.0 pulse to the fields recorded in an entry.
 *
 * Deliberately small: these are what a third party needs in order to look the
 * pulse up and compare it. Storing the whole pulse would bloat every entry
 * without adding anything checkable.
 *
 * @throws {Error} if the pulse is not structurally sound
 */
export function extractPulse(raw) {
  const pulse = raw && raw.pulse ? raw.pulse : raw;
  if (!pulse || typeof pulse !== 'object') throw new Error('not a Beacon 2.0 pulse');

  const index = Number(pulse.pulseIndex);
  const chainIndex = Number(pulse.chainIndex);
  if (!Number.isSafeInteger(index) || index < 0) throw new Error('pulse index is not a valid integer');
  if (!Number.isSafeInteger(chainIndex) || chainIndex < 0) throw new Error('chain index is not a valid integer');

  if (typeof pulse.outputValue !== 'string' || !HEX64.test(pulse.outputValue)) {
    throw new Error('pulse outputValue is not a SHA-512 hex string');
  }
  if (typeof pulse.signatureValue !== 'string' || !/^[0-9A-Fa-f]+$/.test(pulse.signatureValue)) {
    throw new Error('pulse signatureValue is not hex');
  }
  if (typeof pulse.timeStamp !== 'string' || Number.isNaN(Date.parse(pulse.timeStamp))) {
    throw new Error('pulse timeStamp is not a valid time');
  }

  return {
    source: 'nist-beacon-2.0',
    chain_index: chainIndex,
    pulse_index: index,
    // Lowercased so the canonical encoding of an entry cannot differ merely
    // because a server changed its hex casing.
    output_value: pulse.outputValue.toLowerCase(),
    pulse_time: new Date(pulse.timeStamp).toISOString(),
  };
}

/**
 * Check the offline structural invariant: outputValue == SHA-512(signatureValue).
 *
 * @returns {Promise<{verdict: string, reason: string}>}
 */
export async function checkPulseSelfConsistency(raw) {
  const pulse = raw && raw.pulse ? raw.pulse : raw;
  try {
    const signature = hexToBytes(pulse.signatureValue);
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-512', signature));
    if (toHex(digest) !== String(pulse.outputValue).toLowerCase()) {
      return {
        verdict: VERDICT.INVALID,
        reason: 'the pulse output value is not the SHA-512 of its signature — the pulse is not self-consistent',
      };
    }
    return {
      verdict: VERDICT.UNVERIFIED,
      reason: 'the pulse is internally self-consistent. Its authenticity is established by looking up '
        + `pulse ${Number(pulse.pulseIndex)} in NIST's public archive, not by this application.`,
    };
  } catch (err) {
    return { verdict: VERDICT.INVALID, reason: `the pulse could not be checked: ${err.message}` };
  }
}

/**
 * Fetch the latest pulse.
 *
 * One outbound request, made only when the user asks for it. Nothing about the
 * evidence is sent — this is a read.
 */
export async function fetchLatestPulse({ url = DEFAULT_BEACON_URL, fetchImpl = fetch, signal } = {}) {
  const response = await fetchImpl(url, {
    method: 'GET',
    headers: { Accept: 'application/json' },
    signal,
    credentials: 'omit',
    referrerPolicy: 'no-referrer',
    cache: 'no-store',
  });
  if (!response.ok) throw new Error(`Beacon returned HTTP ${response.status}`);

  const raw = await response.json();
  const record = extractPulse(raw);
  const check = await checkPulseSelfConsistency(raw);
  if (check.verdict === VERDICT.INVALID) throw new Error(check.reason);

  return { record, check };
}

/**
 * The URL at which a third party can independently confirm a recorded pulse.
 * This is the authoritative check, and it does not involve this application.
 */
export function archiveUrl(record) {
  return `https://beacon.nist.gov/beacon/2.0/chain/${record.chain_index}/pulse/${record.pulse_index}`;
}

/**
 * Compare a recorded pulse against one re-fetched from the archive.
 * Used when someone verifies a chain and chooses to check its lower bounds.
 */
export function comparePulse(recorded, fetchedRaw) {
  let fetched;
  try {
    fetched = extractPulse(fetchedRaw);
  } catch (err) {
    return { verdict: VERDICT.UNVERIFIED, reason: `could not read the archived pulse: ${err.message}` };
  }

  if (fetched.pulse_index !== recorded.pulse_index || fetched.chain_index !== recorded.chain_index) {
    return { verdict: VERDICT.UNVERIFIED, reason: 'the archived pulse is not the one referenced' };
  }
  if (fetched.output_value !== recorded.output_value) {
    return {
      verdict: VERDICT.INVALID,
      reason: 'the recorded pulse value does not match the published one — the entry references a pulse that was never issued',
    };
  }
  return {
    verdict: VERDICT.VERIFIED,
    reason: `Pulse ${recorded.pulse_index} matches the published archive; the entry was created no earlier than ${fetched.pulse_time}.`,
  };
}
