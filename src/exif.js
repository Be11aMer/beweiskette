/**
 * Minimal EXIF parser for JPEG files.
 * Extracts only forensically relevant fields: DateTime, GPS, Camera Model.
 * Handles both big-endian (Motorola) and little-endian (Intel) byte orders.
 *
 * Two things shape the defensive posture here.
 *
 * First, the input is attacker-controlled. A JPEG's EXIF block is arbitrary
 * binary chosen by whoever produced the file, and TIFF is a pointer format —
 * IFD entries hold offsets that can point anywhere. Every read is therefore
 * bounded by the APP1 segment's own declared length rather than by the buffer,
 * and an out-of-range read aborts the parse instead of yielding whatever
 * happened to be nearby.
 *
 * Second, whatever comes out of here is written into the entry and covered by
 * entry_hash. Silently returning plausible-looking garbage would put that
 * garbage in the evidence record permanently, so anything that does not parse
 * cleanly yields null rather than a guess.
 *
 * Only the first 128KB of the file is read — EXIF sits near the start. The
 * values recovered are claims made by the file, faithfully recorded, not
 * independently verified facts. See docs/THREAT_MODEL.md.
 */

const TAG_MAKE = 0x010f;
const TAG_MODEL = 0x0110;
const TAG_DATETIME = 0x0132;
const TAG_EXIF_IFD = 0x8769;
const TAG_GPS_IFD = 0x8825;
const TAG_DATETIME_ORIGINAL = 0x9003;
const TAG_GPS_LAT_REF = 0x0001;
const TAG_GPS_LAT = 0x0002;
const TAG_GPS_LNG_REF = 0x0003;
const TAG_GPS_LNG = 0x0004;

const TYPE_ASCII = 2;
const TYPE_RATIONAL = 5;

const TYPE_SIZES = { 1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 9: 4, 10: 8, 12: 8 };

/** Guards against an IFD claiming an implausible number of entries. */
const MAX_IFD_ENTRIES = 512;

const SOI = 0xffd8;
const APP1 = 0xffe1;

/**
 * Extract EXIF metadata from a file's leading bytes.
 * Returns an object with available fields, or null if not a JPEG / no EXIF.
 *
 * @param {ArrayBuffer} arrayBuffer - the start of the file (see HEAD_BYTES)
 */
export function extractExif(arrayBuffer) {
  try {
    const view = new DataView(arrayBuffer);
    if (view.byteLength < 4 || view.getUint16(0) !== SOI) return null;

    let offset = 2;
    // Walk the marker segments looking for APP1.
    while (offset + 4 <= view.byteLength) {
      const marker = view.getUint16(offset);
      if ((marker & 0xff00) !== 0xff00) return null;

      const segmentLength = view.getUint16(offset + 2);
      // A segment length must at least cover its own length field.
      if (segmentLength < 2) return null;

      const segmentEnd = offset + 2 + segmentLength;
      if (segmentEnd > view.byteLength) return null;

      if (marker === APP1) return parseApp1(view, offset, segmentEnd);

      offset = segmentEnd;
    }

    return null;
  } catch {
    // Any out-of-range read lands here. A malformed file yields no metadata
    // rather than metadata derived from misread bytes.
    return null;
  }
}

function parseApp1(view, markerOffset, segmentEnd) {
  // "Exif\0\0" then the TIFF header.
  if (markerOffset + 10 > segmentEnd) return null;
  const signature = [0x45, 0x78, 0x69, 0x66, 0x00, 0x00];
  for (let i = 0; i < signature.length; i++) {
    if (view.getUint8(markerOffset + 4 + i) !== signature[i]) return null;
  }

  const tiffStart = markerOffset + 10;
  if (tiffStart + 8 > segmentEnd) return null;

  const byteOrder = view.getUint16(tiffStart);
  if (byteOrder !== 0x4949 && byteOrder !== 0x4d4d) return null;
  const le = byteOrder === 0x4949;

  if (view.getUint16(tiffStart + 2, le) !== 0x002a) return null;

  // All TIFF offsets are relative to tiffStart and must stay inside the
  // segment. `segmentEnd` — not the buffer length — is the boundary, so a
  // crafted APP1 cannot reach into unrelated parts of the file.
  const ctx = { view, tiffStart, end: segmentEnd, le };

  const ifd0 = readIFD(ctx, view.getUint32(tiffStart + 4, le));
  if (!ifd0) return null;

  const result = {};

  const make = readAscii(ctx, ifd0[TAG_MAKE]);
  if (make) result.camera_make = make;

  const model = readAscii(ctx, ifd0[TAG_MODEL]);
  if (model) result.camera_model = model;

  const datetime = readAscii(ctx, ifd0[TAG_DATETIME]);
  if (datetime) result.datetime = datetime;

  const exifOffset = readLongValue(ctx, ifd0[TAG_EXIF_IFD]);
  if (exifOffset !== null) {
    const exifIfd = readIFD(ctx, exifOffset);
    if (exifIfd) {
      const original = readAscii(ctx, exifIfd[TAG_DATETIME_ORIGINAL]);
      if (original) result.datetime_original = original;
    }
  }

  const gpsOffset = readLongValue(ctx, ifd0[TAG_GPS_IFD]);
  if (gpsOffset !== null) {
    const gpsIfd = readIFD(ctx, gpsOffset);
    if (gpsIfd) {
      const lat = readGPSCoord(ctx, gpsIfd, TAG_GPS_LAT, TAG_GPS_LAT_REF, 'N', 'S', 90);
      const lng = readGPSCoord(ctx, gpsIfd, TAG_GPS_LNG, TAG_GPS_LNG_REF, 'E', 'W', 180);
      // Half a coordinate is not a location; record both or neither.
      if (lat !== null && lng !== null) {
        result.gps_lat = lat;
        result.gps_lng = lng;
      }
    }
  }

  return Object.keys(result).length > 0 ? result : null;
}

/** True if [start, start+length) lies within the APP1 segment. */
function inBounds(ctx, start, length) {
  return start >= ctx.tiffStart && length >= 0 && start + length <= ctx.end;
}

function readIFD(ctx, ifdOffset) {
  const { view, tiffStart, le } = ctx;
  const base = tiffStart + ifdOffset;
  if (!inBounds(ctx, base, 2)) return null;

  const count = view.getUint16(base, le);
  if (count === 0 || count > MAX_IFD_ENTRIES) return null;
  if (!inBounds(ctx, base + 2, count * 12)) return null;

  const tags = {};
  for (let i = 0; i < count; i++) {
    const entryOffset = base + 2 + i * 12;
    tags[view.getUint16(entryOffset, le)] = {
      type: view.getUint16(entryOffset + 2, le),
      count: view.getUint32(entryOffset + 4, le),
      valueOffset: entryOffset + 8,
    };
  }
  return tags;
}

/**
 * Resolve where a tag's value lives.
 *
 * Values of four bytes or fewer are stored inline in the entry; anything
 * larger is stored elsewhere and the entry holds an offset.
 *
 * @returns {number|null} absolute offset of the data, or null if out of range
 */
function resolveValueOffset(ctx, tag) {
  const size = (TYPE_SIZES[tag.type] || 0) * tag.count;
  if (size === 0) return null;

  const offset = size <= 4
    ? tag.valueOffset
    : ctx.tiffStart + ctx.view.getUint32(tag.valueOffset, ctx.le);

  return inBounds(ctx, offset, size) ? offset : null;
}

/** Read a single LONG value (used for the sub-IFD pointers). */
function readLongValue(ctx, tag) {
  if (!tag || tag.count !== 1) return null;
  if (tag.type !== 4 && tag.type !== 3) return null;
  return ctx.view.getUint32(tag.valueOffset, ctx.le);
}

function readAscii(ctx, tag) {
  if (!tag || tag.type !== TYPE_ASCII || tag.count === 0) return null;

  const offset = resolveValueOffset(ctx, tag);
  if (offset === null) return null;

  const bytes = new Uint8Array(ctx.view.buffer, ctx.view.byteOffset + offset, tag.count);

  // Stop at the first NUL: EXIF ASCII strings are NUL-terminated and the
  // declared count includes the terminator.
  let length = bytes.indexOf(0);
  if (length === -1) length = bytes.length;
  if (length === 0) return null;

  // Decoded as UTF-8 rather than byte-by-byte via String.fromCharCode, which
  // treated the bytes as Latin-1 and turned any non-ASCII camera name into
  // mojibake — mojibake that then got hashed into the evidence record.
  // Malformed sequences become U+FFFD rather than throwing.
  const text = new TextDecoder('utf-8').decode(bytes.subarray(0, length)).trim();
  return text.length > 0 ? text : null;
}

/**
 * Read a GPS coordinate as degrees/minutes/seconds and convert to decimal.
 * Returned as a fixed 6-decimal string — see canonical.js on why the hashed
 * payload carries no floats.
 */
function readGPSCoord(ctx, gpsTags, coordTag, refTag, positiveRef, negativeRef, maxAbs) {
  const coord = gpsTags[coordTag];
  const ref = gpsTags[refTag];
  if (!coord || !ref) return null;

  if (coord.type !== TYPE_RATIONAL || coord.count !== 3) return null;
  if (ref.type !== TYPE_ASCII) return null;

  const refChar = String.fromCharCode(ctx.view.getUint8(ref.valueOffset)).toUpperCase();
  // Previously any unrecognized ref silently meant North/East, so a corrupt
  // hemisphere byte produced a confidently wrong location.
  if (refChar !== positiveRef && refChar !== negativeRef) return null;

  const offset = resolveValueOffset(ctx, coord);
  if (offset === null) return null;

  const parts = [];
  for (let i = 0; i < 3; i++) {
    const numerator = ctx.view.getUint32(offset + i * 8, ctx.le);
    const denominator = ctx.view.getUint32(offset + i * 8 + 4, ctx.le);
    if (denominator === 0) return null;
    parts.push(numerator / denominator);
  }

  const [degrees, minutes, seconds] = parts;
  if (minutes >= 60 || seconds >= 60) return null;

  let decimal = degrees + minutes / 60 + seconds / 3600;
  if (!Number.isFinite(decimal) || decimal > maxAbs) return null;
  if (refChar === negativeRef) decimal = -decimal;

  return decimal.toFixed(6);
}
