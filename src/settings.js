/**
 * Timestamp-authority configuration.
 *
 * Held in localStorage rather than IndexedDB: this is configuration, not
 * evidence. Losing it costs a re-entry of a URL and a pin; it must never be
 * confused with the chain itself.
 *
 * NO AUTHORITIES ARE PINNED BY DEFAULT, and that is deliberate. Shipping a pin
 * means asserting that a particular key belongs to a particular authority —
 * an assertion this project is in no position to make on a user's behalf, and
 * one they cannot check without doing the same work themselves. So the user
 * supplies the certificate, sees the computed pin, and decides. Until they do,
 * tokens verify as UNVERIFIED rather than silently trusting whatever answered
 * the request.
 */

const KEY = 'beweiskette.tsa';

/**
 * Suggested authorities. URLs only — the certificate, and therefore the trust
 * decision, is still the user's to supply.
 */
export const SUGGESTED_AUTHORITIES = [
  { label: 'FreeTSA', url: 'https://freetsa.org/tsr', certUrl: 'https://freetsa.org/files/tsa.crt' },
  { label: 'DigiCert', url: 'http://timestamp.digicert.com', certUrl: 'https://knowledge.digicert.com/tsa' },
  { label: 'Sectigo', url: 'http://timestamp.sectigo.com', certUrl: 'https://sectigo.com/resource-library' },
];

const EMPTY = { url: '', pins: [] };

function read() {
  try {
    const raw = globalThis.localStorage && localStorage.getItem(KEY);
    if (!raw) return { ...EMPTY };
    const parsed = JSON.parse(raw);
    return {
      url: typeof parsed.url === 'string' ? parsed.url : '',
      pins: Array.isArray(parsed.pins) ? parsed.pins.filter((p) => /^[0-9a-f]{64}$/.test(p)) : [],
    };
  } catch {
    return { ...EMPTY };
  }
}

function write(settings) {
  try {
    localStorage.setItem(KEY, JSON.stringify(settings));
  } catch {
    // A full or unavailable localStorage must not break registration.
  }
}

export function getTsaSettings() {
  return read();
}

/**
 * Set the authority URL. Only https is accepted, except on loopback for
 * development: a timestamp fetched over a channel someone can rewrite is not
 * worth having.
 */
export function setTsaUrl(url) {
  const trimmed = String(url || '').trim();
  if (trimmed !== '') {
    let parsed;
    try {
      parsed = new URL(trimmed);
    } catch {
      throw new Error('That is not a valid URL.');
    }
    const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(parsed.hostname);
    if (parsed.protocol !== 'https:' && !loopback) {
      throw new Error('Use an https:// timestamp authority — a plain http response can be rewritten in transit.');
    }
  }
  const settings = read();
  settings.url = trimmed;
  write(settings);
  return settings;
}

/** Trust a signer key. The pin is a SHA-256 of the certificate's SPKI. */
export function addPin(pin) {
  if (!/^[0-9a-f]{64}$/.test(pin)) throw new Error('A pin must be a 64-character hex SHA-256 digest.');
  const settings = read();
  if (!settings.pins.includes(pin)) settings.pins.push(pin);
  write(settings);
  return settings;
}

export function removePin(pin) {
  const settings = read();
  settings.pins = settings.pins.filter((p) => p !== pin);
  write(settings);
  return settings;
}
