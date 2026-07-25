/**
 * Canonical JSON serialization — the exact bytes that get hashed.
 *
 * Two properties matter here, and both are load-bearing:
 *
 * 1. INJECTIVITY. If two structurally different entries can serialize to the
 *    same string, they share an entry_hash and the chain's tamper-evidence is
 *    void. Rather than guessing at values it cannot represent, this encoder
 *    throws. A canonicalizer that silently coerces is a collision generator:
 *    the previous version turned `undefined` into a dropped key (so
 *    {a:1,b:undefined} and {a:1} hashed alike), every Date/Map/Set into `{}`,
 *    BigInt 5n into the same bytes as the number 5, and NaN into `null`.
 *
 * 2. CROSS-IMPLEMENTATION AGREEMENT. The same entry must produce the same
 *    bytes here, in the exported HTML report, and in Zeitkette's Python. Any
 *    divergence means one verifier calls a chain broken that another calls
 *    intact.
 *
 * Deliberately self-contained: it references no module-level binding, so
 * `sortedStringify.toString()` is complete, valid source. src/report.js embeds
 * exactly that into the offline verification report, which is why the report
 * cannot drift from this file (it previously carried a hand-maintained copy
 * that had already diverged).
 *
 * Python equivalent:
 *
 *     json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
 *
 * `ensure_ascii=False` is required and is NOT the Python default. With the
 * default, Python escapes non-ASCII as \uXXXX while JavaScript emits raw
 * UTF-8, so a custodian named "Müller" hashes differently in the two tools.
 * Key order also differs: Python sorts by code point, JavaScript's default
 * sort is by UTF-16 code unit — hence the explicit comparator below.
 */

/**
 * Serialize a value to its canonical form: keys sorted by Unicode code point,
 * no insignificant whitespace.
 *
 * @param {*} value
 * @returns {string}
 * @throws {TypeError} if the value has no unambiguous representation
 */
export function sortedStringify(value) {
  const compareCodePoints = (a, b) => {
    // Array.from splits on code points; a bare < comparison would order by
    // UTF-16 code unit, putting astral characters below U+E000-U+FFFF and
    // disagreeing with Python for any key outside the BMP.
    const ca = Array.from(a);
    const cb = Array.from(b);
    const shared = Math.min(ca.length, cb.length);
    for (let i = 0; i < shared; i++) {
      const delta = ca[i].codePointAt(0) - cb[i].codePointAt(0);
      if (delta !== 0) return delta;
    }
    return ca.length - cb.length;
  };

  const fail = (path, reason) => {
    throw new TypeError(`Cannot canonicalize ${path}: ${reason}`);
  };

  const encode = (v, path) => {
    if (v === null) return 'null';

    const type = typeof v;

    if (type === 'boolean') return v ? 'true' : 'false';

    if (type === 'number') {
      if (!Number.isFinite(v)) {
        fail(path, `${v} has no JSON representation`);
      }
      if (!Number.isInteger(v)) {
        fail(path, 'non-integer numbers format differently across languages; store it as a string');
      }
      if (!Number.isSafeInteger(v)) {
        fail(path, 'integer is outside the exactly representable range');
      }
      return String(v);
    }

    if (type === 'string') return JSON.stringify(v);

    if (type === 'undefined') {
      fail(path, 'undefined is not representable; omit the key or use null');
    }
    if (type === 'bigint') fail(path, 'BigInt is not representable');
    if (type === 'function') fail(path, 'a function is not representable');
    if (type === 'symbol') fail(path, 'a symbol is not representable');

    if (Array.isArray(v)) {
      return '[' + v.map((item, i) => encode(item, path + '[' + i + ']')).join(',') + ']';
    }

    if (type === 'object') {
      const proto = Object.getPrototypeOf(v);
      if (proto !== Object.prototype && proto !== null) {
        const name = v.constructor && v.constructor.name ? v.constructor.name : 'value';
        fail(path, name + ' is not a plain object; convert it to one first');
      }
      const keys = Object.keys(v).sort(compareCodePoints);
      const pairs = keys.map((k) => JSON.stringify(k) + ':' + encode(v[k], path + '.' + k));
      return '{' + pairs.join(',') + '}';
    }

    return fail(path, 'unsupported value');
  };

  return encode(value, '$');
}
