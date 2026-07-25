/**
 * Strict DER parsing and encoding.
 *
 * Needed to build RFC 3161 timestamp requests and to take apart the CMS
 * structures in the responses. Kept minimal and deliberately unforgiving.
 *
 * This parses untrusted input. Timestamp tokens do not only arrive from a TSA
 * over TLS — they travel inside imported chain files, which come from
 * counterparties. So:
 *
 *   - DER only. Indefinite-length encodings and non-minimal lengths are
 *     rejected rather than tolerated. Being liberal here would mean the same
 *     bytes could be read two ways, and "parser disagreement" is precisely how
 *     signature checks get bypassed.
 *   - Every read is bounds-checked, nesting is depth-capped, and any anomaly
 *     throws Asn1Error. Nothing is ever guessed at or partially recovered: a
 *     structure that does not parse cleanly must not reach a verifier.
 */

export class Asn1Error extends Error {
  constructor(message, offset) {
    super(offset === undefined ? message : `${message} (at byte ${offset})`);
    this.name = 'Asn1Error';
    this.offset = offset;
  }
}

export const CLASS = {
  UNIVERSAL: 0x00,
  APPLICATION: 0x40,
  CONTEXT: 0x80,
  PRIVATE: 0xc0,
};

export const TAG = {
  BOOLEAN: 0x01,
  INTEGER: 0x02,
  BIT_STRING: 0x03,
  OCTET_STRING: 0x04,
  NULL: 0x05,
  OID: 0x06,
  UTF8_STRING: 0x0c,
  SEQUENCE: 0x10,
  SET: 0x11,
  PRINTABLE_STRING: 0x13,
  IA5_STRING: 0x16,
  UTC_TIME: 0x17,
  GENERALIZED_TIME: 0x18,
};

const MAX_DEPTH = 40;

/**
 * A parsed TLV.
 *
 * `bytes` is the complete TLV including its header — needed when a structure
 * has to be re-digested or re-encoded exactly as it arrived. `content` is just
 * the value.
 */
class Node {
  constructor(fields) {
    Object.assign(this, fields);
  }

  /** Universal-class tag equality, the common case. */
  is(tag) {
    return this.tagClass === CLASS.UNIVERSAL && this.tag === tag;
  }

  /** Context-specific tag equality, e.g. [0]. */
  isContext(tag) {
    return this.tagClass === CLASS.CONTEXT && this.tag === tag;
  }

  /** Child at `index`, or throw. */
  at(index) {
    if (!this.children || index >= this.children.length) {
      throw new Asn1Error(`expected a child at index ${index}`, this.start);
    }
    return this.children[index];
  }

  /** Walk a chain of child indices. */
  path(...indices) {
    return indices.reduce((node, i) => node.at(i), this);
  }

  /** First child matching a predicate, or null. */
  find(predicate) {
    return (this.children || []).find(predicate) || null;
  }
}

function readTagAndLength(bytes, offset) {
  if (offset + 2 > bytes.length) throw new Asn1Error('truncated header', offset);

  const identifier = bytes[offset];
  const tagClass = identifier & 0xc0;
  const constructed = (identifier & 0x20) !== 0;
  let tag = identifier & 0x1f;
  let cursor = offset + 1;

  if (tag === 0x1f) {
    // High-tag-number form. Not needed by anything here, and supporting it
    // would widen the parser for no benefit.
    throw new Asn1Error('high-tag-number form is not supported', offset);
  }

  const first = bytes[cursor++];

  let length;
  if (first === 0x80) {
    // Legal in BER, forbidden in DER. Accepting it would allow two encodings
    // of the same value, which is exactly what must not happen around a
    // signature check.
    throw new Asn1Error('indefinite-length encoding is not valid DER', offset);
  } else if (first < 0x80) {
    length = first;
  } else {
    const count = first & 0x7f;
    if (count === 0x7f) throw new Asn1Error('reserved length form', offset);
    if (count > 4) throw new Asn1Error('length field too large', offset);
    if (cursor + count > bytes.length) throw new Asn1Error('truncated length', offset);

    length = 0;
    for (let i = 0; i < count; i++) length = length * 256 + bytes[cursor++];

    // DER requires the minimal encoding of the length.
    if (length < 0x80) throw new Asn1Error('non-minimal length encoding', offset);
    if (count > 1 && bytes[offset + 2] === 0x00) {
      throw new Asn1Error('non-minimal length encoding', offset);
    }
  }

  const contentStart = cursor;
  const contentEnd = contentStart + length;
  if (contentEnd > bytes.length) throw new Asn1Error('content runs past end of buffer', offset);

  return { tagClass, constructed, tag, contentStart, contentEnd };
}

/**
 * Parse one DER TLV starting at `offset`.
 * Constructed values are parsed recursively into `children`.
 */
export function parse(bytes, offset = 0, depth = 0) {
  if (!(bytes instanceof Uint8Array)) {
    throw new Asn1Error('expected a Uint8Array');
  }
  if (depth > MAX_DEPTH) throw new Asn1Error('nesting too deep', offset);

  const { tagClass, constructed, tag, contentStart, contentEnd } = readTagAndLength(bytes, offset);

  let children = null;
  if (constructed) {
    children = [];
    let cursor = contentStart;
    while (cursor < contentEnd) {
      const child = parse(bytes, cursor, depth + 1);
      if (child.end <= cursor) throw new Asn1Error('zero-length element', cursor);
      children.push(child);
      cursor = child.end;
    }
    if (cursor !== contentEnd) throw new Asn1Error('children overrun their parent', offset);
  }

  return new Node({
    tagClass,
    constructed,
    tag,
    start: offset,
    end: contentEnd,
    contentStart,
    contentEnd,
    children,
    bytes: bytes.subarray(offset, contentEnd),
    content: bytes.subarray(contentStart, contentEnd),
  });
}

/** Parse a buffer that must contain exactly one TLV and nothing else. */
export function parseOnly(bytes) {
  const node = parse(bytes, 0);
  if (node.end !== bytes.length) {
    throw new Asn1Error(`${bytes.length - node.end} trailing bytes after the top-level element`);
  }
  return node;
}

// ── Value readers ──────────────────────────────────────────────────

/** Decode an OBJECT IDENTIFIER to dotted-decimal form. */
export function readOID(node) {
  if (!node.is(TAG.OID)) throw new Asn1Error('expected an OBJECT IDENTIFIER', node.start);
  const b = node.content;
  if (b.length === 0) throw new Asn1Error('empty OBJECT IDENTIFIER', node.start);

  const arcs = [];
  // The first byte packs the first two arcs.
  arcs.push(Math.floor(b[0] / 40), b[0] % 40);

  let value = 0n;
  let started = false;
  for (let i = 1; i < b.length; i++) {
    if (!started && b[i] === 0x80) {
      throw new Asn1Error('non-minimal OID arc encoding', node.start);
    }
    started = true;
    value = (value << 7n) | BigInt(b[i] & 0x7f);
    if ((b[i] & 0x80) === 0) {
      arcs.push(value.toString());
      value = 0n;
      started = false;
    }
  }
  if (started) throw new Asn1Error('truncated OID arc', node.start);

  return arcs.join('.');
}

/** Decode an INTEGER as a BigInt (two's complement). */
export function readInteger(node) {
  if (!node.is(TAG.INTEGER)) throw new Asn1Error('expected an INTEGER', node.start);
  const b = node.content;
  if (b.length === 0) throw new Asn1Error('empty INTEGER', node.start);
  if (b.length > 1 && (b[0] === 0x00 || b[0] === 0xff)) {
    const second = b[1] & 0x80;
    if ((b[0] === 0x00 && !second) || (b[0] === 0xff && second)) {
      throw new Asn1Error('non-minimal INTEGER encoding', node.start);
    }
  }

  let value = 0n;
  for (const byte of b) value = (value << 8n) | BigInt(byte);
  if (b[0] & 0x80) value -= 1n << BigInt(8 * b.length);
  return value;
}

/** Decode a BIT STRING, requiring a whole number of bytes. */
export function readBitString(node) {
  if (!node.is(TAG.BIT_STRING)) throw new Asn1Error('expected a BIT STRING', node.start);
  if (node.content.length === 0) throw new Asn1Error('empty BIT STRING', node.start);
  const unused = node.content[0];
  if (unused !== 0) throw new Asn1Error('BIT STRING is not byte-aligned', node.start);
  return node.content.subarray(1);
}

/**
 * Decode UTCTime or GeneralizedTime to an ISO 8601 string in UTC.
 *
 * Only the Z-terminated forms are accepted. Local-time and offset forms are
 * legal ASN.1 but forbidden by RFC 5280 and RFC 3161 here, and accepting them
 * would make a timestamp's meaning depend on an unstated timezone.
 */
export function readTime(node) {
  const text = new TextDecoder('ascii').decode(node.content);

  if (node.is(TAG.UTC_TIME)) {
    const m = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(text);
    if (!m) throw new Asn1Error(`malformed UTCTime: ${text}`, node.start);
    const yy = Number(m[1]);
    // RFC 5280: 00-49 => 2000s, 50-99 => 1900s.
    const year = yy < 50 ? 2000 + yy : 1900 + yy;
    return `${year}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}.000Z`;
  }

  if (node.is(TAG.GENERALIZED_TIME)) {
    const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.(\d{1,6}))?Z$/.exec(text);
    if (!m) throw new Asn1Error(`malformed GeneralizedTime: ${text}`, node.start);
    const fraction = (m[7] || '').padEnd(3, '0').slice(0, 3);
    return `${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}.${fraction}Z`;
  }

  throw new Asn1Error('expected UTCTime or GeneralizedTime', node.start);
}

// ── Encoding ───────────────────────────────────────────────────────

function encodeLength(length) {
  if (length < 0x80) return [length];
  const bytes = [];
  let remaining = length;
  while (remaining > 0) {
    bytes.unshift(remaining & 0xff);
    remaining = Math.floor(remaining / 256);
  }
  return [0x80 | bytes.length, ...bytes];
}

/** Wrap content in a TLV with the given identifier octet. */
export function encode(identifier, content) {
  const body = content instanceof Uint8Array ? content : Uint8Array.from(content);
  const header = [identifier, ...encodeLength(body.length)];
  const out = new Uint8Array(header.length + body.length);
  out.set(header, 0);
  out.set(body, header.length);
  return out;
}

function concat(parts) {
  const total = parts.reduce((sum, p) => sum + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export function encodeSequence(parts) {
  return encode(0x30, concat(parts));
}

export function encodeSet(parts) {
  return encode(0x31, concat(parts));
}

export function encodeInteger(value) {
  let v = BigInt(value);
  const bytes = [];
  if (v === 0n) {
    bytes.push(0);
  } else if (v > 0n) {
    while (v > 0n) {
      bytes.unshift(Number(v & 0xffn));
      v >>= 8n;
    }
    if (bytes[0] & 0x80) bytes.unshift(0x00); // keep it positive
  } else {
    // Two's complement, minimal length.
    let width = 1;
    while (v < -(1n << BigInt(8 * width - 1))) width++;
    let u = v + (1n << BigInt(8 * width));
    for (let i = 0; i < width; i++) {
      bytes.unshift(Number(u & 0xffn));
      u >>= 8n;
    }
  }
  return encode(TAG.INTEGER, bytes);
}

/** Encode an INTEGER from raw big-endian magnitude bytes (for large nonces). */
export function encodeIntegerFromBytes(magnitude) {
  let start = 0;
  while (start < magnitude.length - 1 && magnitude[start] === 0x00) start++;
  const trimmed = Array.from(magnitude.subarray(start));
  if (trimmed[0] & 0x80) trimmed.unshift(0x00);
  return encode(TAG.INTEGER, trimmed);
}

export function encodeOctetString(bytes) {
  return encode(TAG.OCTET_STRING, bytes);
}

export function encodeNull() {
  return encode(TAG.NULL, []);
}

export function encodeBoolean(value) {
  return encode(TAG.BOOLEAN, [value ? 0xff : 0x00]);
}

export function encodeOID(dotted) {
  const arcs = dotted.split('.').map((a) => {
    if (!/^\d+$/.test(a)) throw new Asn1Error(`invalid OID arc: ${a}`);
    return BigInt(a);
  });
  if (arcs.length < 2) throw new Asn1Error(`OID needs at least two arcs: ${dotted}`);

  const body = [Number(arcs[0] * 40n + arcs[1])];
  for (const arc of arcs.slice(2)) {
    const septets = [];
    let v = arc;
    do {
      septets.unshift(Number(v & 0x7fn));
      v >>= 7n;
    } while (v > 0n);
    for (let i = 0; i < septets.length - 1; i++) septets[i] |= 0x80;
    body.push(...septets);
  }
  return encode(TAG.OID, body);
}

/** Hex helper for comparing digests and identifiers. */
export function toHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}
