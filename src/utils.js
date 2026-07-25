/**
 * Utility functions for Beweiskette.
 * Date formatting, hex conversion, UUID generation, HTML escaping.
 *
 * The canonical serializer that feeds the hash lives in canonical.js, kept
 * apart because it is consensus-critical and embedded verbatim in the
 * exported report.
 */

/**
 * Generate a UUID v4 using crypto.getRandomValues for cryptographic randomness.
 */
export function generateId() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    hex.slice(12, 16),
    hex.slice(16, 20),
    hex.slice(20),
  ].join('-');
}

/**
 * Convert an ArrayBuffer to a hex string.
 */
export function bufferToHex(buffer) {
  return Array.from(new Uint8Array(buffer), b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Format a file size in bytes to a human-readable string.
 */
export function formatFileSize(bytes) {
  if (bytes === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const value = bytes / Math.pow(1024, i);
  return (i === 0 ? value : value.toFixed(1)) + ' ' + units[i];
}

/**
 * Format an ISO datetime string to a human-readable local format.
 */
export function formatDate(isoString) {
  if (!isoString) return '—';
  try {
    const d = new Date(isoString);
    return d.toLocaleString('en-GB', {
      year: 'numeric',
      month: 'short',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    });
  } catch {
    return isoString;
  }
}

/**
 * Truncate a hash string for display: first 8 + last 8 chars.
 */
export function truncateHash(hash) {
  if (!hash || hash.length <= 20) return hash || '';
  return hash.slice(0, 8) + '...' + hash.slice(-8);
}

/**
 * Current time as an ISO 8601 timestamp in UTC ("...Z").
 *
 * Always UTC, never a local offset: the value is recorded verbatim in the
 * entry and hashed, so a fixed-width, timezone-independent form is the only
 * one that stays comparable across machines. It is a claim about when the
 * registering machine believed the entry was made — nothing more. See
 * docs/THREAT_MODEL.md.
 */
export function nowISO() {
  return new Date().toISOString();
}

/**
 * Escape a CSV field to prevent formula injection.
 * Prefixes with a single quote if field starts with =, +, -, @, \t, \r, \n
 */
export function escapeCSVField(value) {
  const str = String(value);
  if (/^[=+\-@\t\r\n]/.test(str)) {
    return "'" + str;
  }
  return str;
}

/**
 * Normalize a string for storage and display.
 *
 * Strips C0/C1 control characters, and the Unicode bidirectional override and
 * isolate formatting characters (U+202A-U+202E, U+2066-U+2069). Those are the
 * primitive behind "Trojan Source" style attacks: they let a custodian name or
 * note render in a different order than it is stored, so a human reviewer and
 * the hash disagree about what the record says. Legitimate right-to-left text
 * renders correctly through the Unicode bidi algorithm without them.
 *
 * This runs on input before an entry is hashed, so what is displayed and what
 * is committed to the chain are the same bytes. It is NOT an HTML escaping
 * function — use the `html` tagged template for that.
 */
export function sanitizeText(value) {
  if (typeof value !== 'string') return '';
  // Written as escape sequences on purpose: spelling these characters
  // literally would make this very file's source misleading to read.
  // eslint-disable-next-line no-control-regex
  return value.replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]/g, '');
}

/**
 * Markup that is already safe to insert. Produced by `html` and `raw`.
 */
class SafeHTML {
  constructor(value) {
    this.value = value;
  }

  toString() {
    return this.value;
  }
}

/**
 * Escape a value for interpolation into HTML.
 * Covers text content and both single- and double-quoted attribute contexts.
 */
export function escapeHTML(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Mark a string as trusted markup, exempting it from escaping.
 * Only ever call this on literals authored in this repository.
 */
export function raw(value) {
  return new SafeHTML(String(value));
}

function interpolate(value) {
  if (value instanceof SafeHTML) return value.value;
  if (value === null || value === undefined || value === false) return '';
  // Arrays are joined here rather than by the caller: calling .join('') on an
  // array of SafeHTML would collapse it to a plain string, which would then be
  // escaped a second time.
  if (Array.isArray(value)) return value.map(interpolate).join('');
  return escapeHTML(value);
}

/**
 * Tagged template that escapes every interpolated value by default.
 *
 *   element.innerHTML = html`<span>${untrustedName}</span>`;
 *
 * Nested html`` fragments and arrays of them compose without double-escaping.
 * Anything else — including a plain string containing markup — is escaped.
 * This inverts the previous default: markup safety no longer depends on the
 * author remembering to escape at each of ~40 interpolation sites.
 */
export function html(strings, ...values) {
  let out = strings[0];
  for (let i = 0; i < values.length; i++) {
    out += interpolate(values[i]) + strings[i + 1];
  }
  return new SafeHTML(out);
}
