/**
 * Utility functions for Beweiskette.
 * Date formatting, hex conversion, UUID generation, deterministic serialization.
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
 * Deterministic JSON serialization with recursively sorted keys and no whitespace.
 * Mirrors Python's json.dumps(obj, sort_keys=True, separators=(',', ':'))
 */
export function sortedStringify(obj) {
  if (obj === null) return 'null';
  if (typeof obj === 'undefined') return undefined;
  if (typeof obj === 'boolean') return obj ? 'true' : 'false';
  if (typeof obj === 'number') return JSON.stringify(obj);
  if (typeof obj === 'string') return JSON.stringify(obj);
  if (Array.isArray(obj)) {
    const items = obj.map(item => sortedStringify(item));
    return '[' + items.join(',') + ']';
  }
  if (typeof obj === 'object') {
    const keys = Object.keys(obj).sort();
    const pairs = keys
      .map(k => {
        const v = sortedStringify(obj[k]);
        return v !== undefined ? JSON.stringify(k) + ':' + v : undefined;
      })
      .filter(p => p !== undefined);
    return '{' + pairs.join(',') + '}';
  }
  return String(obj);
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
 * Get current timestamp in ISO 8601 with local timezone offset.
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
 * Sanitize a string for safe text display (strips control characters).
 */
export function sanitizeText(value) {
  if (typeof value !== 'string') return '';
  // eslint-disable-next-line no-control-regex
  return value.replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, '');
}
