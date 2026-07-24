/**
 * EXIF parser tests.
 *
 * EXIF is attacker-controlled binary in a pointer format, and whatever the
 * parser returns is written into the entry and covered by entry_hash. So the
 * bar is not just "does not crash" — it is that malformed input yields null
 * rather than plausible-looking values that would be committed to the evidence
 * record permanently.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { extractExif } from '../src/exif.js';

/** Minimal JPEG builder: SOI + APP1(Exif/TIFF) + EOI. */
function buildJpeg({ littleEndian = false, ifd0 = [], subIfds = {}, tiffMagic = 0x002a,
  byteOrderOverride = null, signature = 'Exif\0\0', declaredLength = null } = {}) {
  const le = littleEndian;
  const chunks = [];
  let tiff = [];

  const u16 = (v) => (le ? [v & 0xff, (v >> 8) & 0xff] : [(v >> 8) & 0xff, v & 0xff]);
  const u32 = (v) => (le
    ? [v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff, (v >>> 24) & 0xff]
    : [(v >>> 24) & 0xff, (v >> 16) & 0xff, (v >> 8) & 0xff, v & 0xff]);

  // TIFF header: byte order, magic, offset to IFD0.
  tiff.push(...(byteOrderOverride ?? (le ? [0x49, 0x49] : [0x4d, 0x4d])));
  tiff.push(...u16(tiffMagic));
  tiff.push(...u32(8));

  // Lay out IFD0 followed by any sub-IFDs, then the heap for oversized values.
  const ifdSize = (n) => 2 + n * 12 + 4;
  let heapStart = 8 + ifdSize(ifd0.length);
  const subOffsets = {};
  for (const [name, entries] of Object.entries(subIfds)) {
    subOffsets[name] = heapStart;
    heapStart += ifdSize(entries.length);
  }

  const heap = [];
  const emitEntry = (out, { tag, type, count, value, inline, inlineBytes }) => {
    out.push(...u16(tag), ...u16(type), ...u32(count));
    if (inlineBytes !== undefined) {
      // Raw, not byte-swapped: EXIF stores inline ASCII as bytes, so the
      // first byte is the character in either byte order.
      out.push(...inlineBytes, ...new Array(4 - inlineBytes.length).fill(0));
    } else if (inline !== undefined) {
      out.push(...u32(inline));
    } else {
      out.push(...u32(heapStart + heap.length));
      heap.push(...value);
    }
  };

  const ifdBytes = [];
  ifdBytes.push(...u16(ifd0.length));
  for (const e of ifd0) {
    emitEntry(ifdBytes, typeof e.inlineRef === 'string' ? { ...e, inline: subOffsets[e.inlineRef] } : e);
  }
  ifdBytes.push(...u32(0));

  const subBytes = [];
  for (const [, entries] of Object.entries(subIfds)) {
    subBytes.push(...u16(entries.length));
    for (const e of entries) emitEntry(subBytes, e);
    subBytes.push(...u32(0));
  }

  tiff = tiff.concat(ifdBytes, subBytes, heap);

  const sig = [...signature].map((c) => c.charCodeAt(0));
  const payload = [...sig, ...tiff];
  const length = declaredLength ?? payload.length + 2;

  chunks.push(0xff, 0xd8);                                   // SOI
  chunks.push(0xff, 0xe1, (length >> 8) & 0xff, length & 0xff); // APP1 + length
  chunks.push(...payload);
  chunks.push(0xff, 0xd9);                                   // EOI

  return new Uint8Array(chunks).buffer;
}

const ascii = (s) => [...s].map((c) => c.charCodeAt(0)).concat(0);

function rational(le, triples) {
  const out = [];
  for (const [n, d] of triples) {
    for (const v of [n, d]) {
      out.push(...(le
        ? [v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff, (v >>> 24) & 0xff]
        : [(v >>> 24) & 0xff, (v >> 16) & 0xff, (v >> 8) & 0xff, v & 0xff]));
    }
  }
  return out;
}

test('extracts camera make, model and datetime', () => {
  const jpeg = buildJpeg({
    ifd0: [
      { tag: 0x010f, type: 2, count: 6, value: ascii('Canon') },
      { tag: 0x0110, type: 2, count: 7, value: ascii('EOS 5D') },
      { tag: 0x0132, type: 2, count: 20, value: ascii('2026:07:24 09:15:00') },
    ],
  });
  assert.deepEqual(extractExif(jpeg), {
    camera_make: 'Canon',
    camera_model: 'EOS 5D',
    datetime: '2026:07:24 09:15:00',
  });
});

test('works in both byte orders', () => {
  for (const littleEndian of [true, false]) {
    const jpeg = buildJpeg({
      littleEndian,
      ifd0: [{ tag: 0x010f, type: 2, count: 6, value: ascii('Canon') }],
    });
    assert.equal(extractExif(jpeg).camera_make, 'Canon', `failed for le=${littleEndian}`);
  }
});

test('decodes UTF-8 camera names rather than mangling them', () => {
  // Previously decoded byte-by-byte as Latin-1, so a non-ASCII name became
  // mojibake — and that mojibake was hashed into the evidence record.
  const bytes = [...new TextEncoder().encode('Nikon Zwölf'), 0];
  const jpeg = buildJpeg({
    ifd0: [{ tag: 0x0110, type: 2, count: bytes.length, value: bytes }],
  });
  assert.equal(extractExif(jpeg).camera_model, 'Nikon Zwölf');
});

test('reads GPS coordinates as fixed-precision strings', () => {
  for (const littleEndian of [true, false]) {
    const jpeg = buildJpeg({
      littleEndian,
      ifd0: [{ tag: 0x8825, type: 4, count: 1, inlineRef: 'gps' }],
      subIfds: {
        gps: [
          { tag: 0x0001, type: 2, count: 2, inlineBytes: [0x4e] }, // 'N'
          { tag: 0x0002, type: 5, count: 3, value: rational(littleEndian, [[52, 1], [31, 1], [12, 1]]) },
          { tag: 0x0003, type: 2, count: 2, inlineBytes: [0x45] }, // 'E'
          { tag: 0x0004, type: 5, count: 3, value: rational(littleEndian, [[13, 1], [24, 1], [18, 1]]) },
        ],
      },
    });
    const exif = extractExif(jpeg);
    assert.equal(exif.gps_lat, '52.520000');
    assert.equal(exif.gps_lng, '13.405000');
    // Strings, not numbers: the canonical encoder rejects floats.
    assert.equal(typeof exif.gps_lat, 'string');
  }
});

test('southern and western hemispheres are negative', () => {
  const jpeg = buildJpeg({
    ifd0: [{ tag: 0x8825, type: 4, count: 1, inlineRef: 'gps' }],
    subIfds: {
      gps: [
        { tag: 0x0001, type: 2, count: 2, inlineBytes: [0x53] }, // 'S'
        { tag: 0x0002, type: 5, count: 3, value: rational(false, [[33, 1], [51, 1], [0, 1]]) },
        { tag: 0x0003, type: 2, count: 2, inlineBytes: [0x57] }, // 'W'
        { tag: 0x0004, type: 5, count: 3, value: rational(false, [[18, 1], [25, 1], [0, 1]]) },
      ],
    },
  });
  const exif = extractExif(jpeg);
  assert.ok(exif.gps_lat.startsWith('-33.'), exif.gps_lat);
  assert.ok(exif.gps_lng.startsWith('-18.'), exif.gps_lng);
});

test('an unrecognized hemisphere is rejected, not assumed north/east', () => {
  // A corrupt ref byte previously produced a confidently wrong location.
  const jpeg = buildJpeg({
    ifd0: [{ tag: 0x8825, type: 4, count: 1, inlineRef: 'gps' }],
    subIfds: {
      gps: [
        { tag: 0x0001, type: 2, count: 2, inlineBytes: [0x58] }, // 'X'
        { tag: 0x0002, type: 5, count: 3, value: rational(false, [[52, 1], [31, 1], [12, 1]]) },
        { tag: 0x0003, type: 2, count: 2, inlineBytes: [0x45] },
        { tag: 0x0004, type: 5, count: 3, value: rational(false, [[13, 1], [24, 1], [18, 1]]) },
      ],
    },
  });
  const exif = extractExif(jpeg);
  assert.ok(!exif || exif.gps_lat === undefined, 'a bogus hemisphere produced a coordinate');
});

test('a zero denominator does not yield Infinity or NaN', () => {
  const jpeg = buildJpeg({
    ifd0: [{ tag: 0x8825, type: 4, count: 1, inlineRef: 'gps' }],
    subIfds: {
      gps: [
        { tag: 0x0001, type: 2, count: 2, inlineBytes: [0x4e] },
        { tag: 0x0002, type: 5, count: 3, value: rational(false, [[52, 0], [31, 1], [12, 1]]) },
        { tag: 0x0003, type: 2, count: 2, inlineBytes: [0x45] },
        { tag: 0x0004, type: 5, count: 3, value: rational(false, [[13, 1], [24, 1], [18, 1]]) },
      ],
    },
  });
  const exif = extractExif(jpeg);
  assert.ok(!exif || exif.gps_lat === undefined);
});

test('out-of-range coordinates are rejected', () => {
  const jpeg = buildJpeg({
    ifd0: [{ tag: 0x8825, type: 4, count: 1, inlineRef: 'gps' }],
    subIfds: {
      gps: [
        { tag: 0x0001, type: 2, count: 2, inlineBytes: [0x4e] },
        { tag: 0x0002, type: 5, count: 3, value: rational(false, [[500, 1], [0, 1], [0, 1]]) },
        { tag: 0x0003, type: 2, count: 2, inlineBytes: [0x45] },
        { tag: 0x0004, type: 5, count: 3, value: rational(false, [[13, 1], [24, 1], [18, 1]]) },
      ],
    },
  });
  const exif = extractExif(jpeg);
  assert.ok(!exif || exif.gps_lat === undefined);
});

test('non-JPEG and empty input return null', () => {
  assert.equal(extractExif(new Uint8Array([]).buffer), null);
  assert.equal(extractExif(new Uint8Array([0x00]).buffer), null);
  assert.equal(extractExif(new Uint8Array([0x89, 0x50, 0x4e, 0x47]).buffer), null); // PNG
  assert.equal(extractExif(new TextEncoder().encode('plain text file').buffer), null);
});

test('a JPEG without EXIF returns null', () => {
  const jpeg = new Uint8Array([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x04, 0x00, 0x00, 0xff, 0xd9]);
  assert.equal(extractExif(jpeg.buffer), null);
});

test('malformed structures return null instead of misread values', () => {
  const cases = {
    'bad Exif signature': buildJpeg({ signature: 'Fake\0\0', ifd0: [{ tag: 0x010f, type: 2, count: 6, value: ascii('Canon') }] }),
    'bad TIFF magic': buildJpeg({ tiffMagic: 0x1234, ifd0: [{ tag: 0x010f, type: 2, count: 6, value: ascii('Canon') }] }),
    'bad byte order mark': buildJpeg({ byteOrderOverride: [0x41, 0x42], ifd0: [{ tag: 0x010f, type: 2, count: 6, value: ascii('Canon') }] }),
    'declared segment length far beyond the buffer': buildJpeg({ declaredLength: 60000, ifd0: [{ tag: 0x010f, type: 2, count: 6, value: ascii('Canon') }] }),
    'value offset past the segment': buildJpeg({ ifd0: [{ tag: 0x010f, type: 2, count: 200, inline: 0x7fffffff }] }),
    'absurd ascii count': buildJpeg({ ifd0: [{ tag: 0x0110, type: 2, count: 0xffffff, inline: 100 }] }),
  };

  for (const [name, jpeg] of Object.entries(cases)) {
    const result = extractExif(jpeg);
    assert.ok(result === null || Object.keys(result).length === 0, `${name}: got ${JSON.stringify(result)}`);
  }
});

test('truncation at any point never throws', () => {
  const full = new Uint8Array(buildJpeg({
    ifd0: [
      { tag: 0x010f, type: 2, count: 6, value: ascii('Canon') },
      { tag: 0x8825, type: 4, count: 1, inlineRef: 'gps' },
    ],
    subIfds: {
      gps: [
        { tag: 0x0001, type: 2, count: 2, inlineBytes: [0x4e] },
        { tag: 0x0002, type: 5, count: 3, value: rational(false, [[52, 1], [31, 1], [12, 1]]) },
      ],
    },
  }));

  for (let length = 0; length <= full.length; length++) {
    const truncated = full.slice(0, length).buffer;
    assert.doesNotThrow(() => extractExif(truncated), `threw at length ${length}`);
  }
});

test('random byte corruption never throws and never invents coordinates', () => {
  const template = new Uint8Array(buildJpeg({
    ifd0: [
      { tag: 0x010f, type: 2, count: 6, value: ascii('Canon') },
      { tag: 0x8825, type: 4, count: 1, inlineRef: 'gps' },
    ],
    subIfds: {
      gps: [
        { tag: 0x0001, type: 2, count: 2, inlineBytes: [0x4e] },
        { tag: 0x0002, type: 5, count: 3, value: rational(false, [[52, 1], [31, 1], [12, 1]]) },
        { tag: 0x0003, type: 2, count: 2, inlineBytes: [0x45] },
        { tag: 0x0004, type: 5, count: 3, value: rational(false, [[13, 1], [24, 1], [18, 1]]) },
      ],
    },
  }));

  for (let trial = 0; trial < 400; trial++) {
    const fuzzed = template.slice();
    const flips = 1 + Math.floor(Math.random() * 6);
    for (let i = 0; i < flips; i++) {
      fuzzed[Math.floor(Math.random() * fuzzed.length)] = Math.floor(Math.random() * 256);
    }

    let result;
    assert.doesNotThrow(() => { result = extractExif(fuzzed.buffer); }, 'parser threw on fuzzed input');

    if (result && result.gps_lat !== undefined) {
      assert.ok(Math.abs(Number(result.gps_lat)) <= 90, `latitude out of range: ${result.gps_lat}`);
      assert.ok(Math.abs(Number(result.gps_lng)) <= 180, `longitude out of range: ${result.gps_lng}`);
      assert.equal(typeof result.gps_lng, 'string');
    }
  }
});

test('extracted values survive canonicalization', async () => {
  // Whatever comes out of here goes into the hashed payload, so it must be
  // representable by the canonical encoder — no floats, no undefined.
  const { sortedStringify } = await import('../src/canonical.js');
  const jpeg = buildJpeg({
    ifd0: [
      { tag: 0x010f, type: 2, count: 6, value: ascii('Canon') },
      { tag: 0x8825, type: 4, count: 1, inlineRef: 'gps' },
    ],
    subIfds: {
      gps: [
        { tag: 0x0001, type: 2, count: 2, inlineBytes: [0x4e] },
        { tag: 0x0002, type: 5, count: 3, value: rational(false, [[52, 1], [0, 1], [0, 1]]) },
        { tag: 0x0003, type: 2, count: 2, inlineBytes: [0x45] },
        { tag: 0x0004, type: 5, count: 3, value: rational(false, [[13, 1], [0, 1], [0, 1]]) },
      ],
    },
  });
  const exif = extractExif(jpeg);
  assert.doesNotThrow(() => sortedStringify(exif));
  // A whole-degree coordinate is exactly the case a float would break:
  // JS renders 52.0 as "52", Python as "52.0".
  assert.equal(exif.gps_lat, '52.000000');
});
