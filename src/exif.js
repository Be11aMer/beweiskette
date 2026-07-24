/**
 * Minimal EXIF parser for JPEG files.
 * Extracts only forensically relevant fields: DateTime, GPS, Camera Model.
 * Handles both big-endian (Motorola) and little-endian (Intel) byte orders.
 *
 * Only the first 128KB of the file is needed — EXIF data is always near the start.
 * Returns null gracefully for non-JPEG files or files without EXIF data.
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

const TYPE_SIZES = { 1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 9: 4, 10: 8, 12: 8 };

/**
 * Extract EXIF metadata from a file's ArrayBuffer.
 * Returns an object with available fields, or null if not a JPEG / no EXIF.
 */
export function extractExif(arrayBuffer) {
  try {
    const maxBytes = Math.min(arrayBuffer.byteLength, 131072);
    const view = new DataView(arrayBuffer, 0, maxBytes);

    if (view.getUint16(0) !== 0xffd8) return null;

    let offset = 2;
    while (offset < view.byteLength - 4) {
      const marker = view.getUint16(offset);

      if ((marker & 0xff00) !== 0xff00) break;

      if (marker === 0xffe1) {
        return parseApp1(view, offset);
      }

      const segmentLength = view.getUint16(offset + 2);
      offset += 2 + segmentLength;
    }

    return null;
  } catch {
    return null;
  }
}

function parseApp1(view, markerOffset) {
  const tiffStart = markerOffset + 10;

  if (
    view.getUint8(markerOffset + 4) !== 0x45 || // E
    view.getUint8(markerOffset + 5) !== 0x78 || // x
    view.getUint8(markerOffset + 6) !== 0x69 || // i
    view.getUint8(markerOffset + 7) !== 0x66    // f
  ) {
    return null;
  }

  const byteOrder = view.getUint16(tiffStart);
  const le = byteOrder === 0x4949;

  const magic = getU16(view, tiffStart + 2, le);
  if (magic !== 0x002a) return null;

  const ifd0Offset = getU32(view, tiffStart + 4, le);

  const result = {};
  const ifd0Tags = readIFD(view, tiffStart, ifd0Offset, le);

  if (ifd0Tags[TAG_MAKE]) {
    result.camera_make = readAscii(view, tiffStart, ifd0Tags[TAG_MAKE], le);
  }
  if (ifd0Tags[TAG_MODEL]) {
    result.camera_model = readAscii(view, tiffStart, ifd0Tags[TAG_MODEL], le);
  }
  if (ifd0Tags[TAG_DATETIME]) {
    result.datetime = readAscii(view, tiffStart, ifd0Tags[TAG_DATETIME], le);
  }

  if (ifd0Tags[TAG_EXIF_IFD]) {
    const exifOffset = readTagValue(view, tiffStart, ifd0Tags[TAG_EXIF_IFD], le);
    if (exifOffset) {
      const exifTags = readIFD(view, tiffStart, exifOffset, le);
      if (exifTags[TAG_DATETIME_ORIGINAL]) {
        result.datetime_original = readAscii(view, tiffStart, exifTags[TAG_DATETIME_ORIGINAL], le);
      }
    }
  }

  if (ifd0Tags[TAG_GPS_IFD]) {
    const gpsOffset = readTagValue(view, tiffStart, ifd0Tags[TAG_GPS_IFD], le);
    if (gpsOffset) {
      const gpsTags = readIFD(view, tiffStart, gpsOffset, le);
      const lat = readGPSCoord(view, tiffStart, gpsTags, TAG_GPS_LAT, TAG_GPS_LAT_REF, le);
      const lng = readGPSCoord(view, tiffStart, gpsTags, TAG_GPS_LNG, TAG_GPS_LNG_REF, le);
      if (lat !== null) result.gps_lat = lat;
      if (lng !== null) result.gps_lng = lng;
    }
  }

  return Object.keys(result).length > 0 ? result : null;
}

function readIFD(view, tiffStart, ifdOffset, le) {
  const tags = {};
  const abs = tiffStart + ifdOffset;

  if (abs + 2 > view.byteLength) return tags;

  const count = getU16(view, abs, le);

  for (let i = 0; i < count; i++) {
    const entryOffset = abs + 2 + i * 12;
    if (entryOffset + 12 > view.byteLength) break;

    const tagId = getU16(view, entryOffset, le);
    tags[tagId] = {
      type: getU16(view, entryOffset + 2, le),
      count: getU32(view, entryOffset + 4, le),
      valueOffset: entryOffset + 8,
    };
  }

  return tags;
}

function readTagValue(view, tiffStart, tagInfo, le) {
  if (!tagInfo) return null;
  const size = (TYPE_SIZES[tagInfo.type] || 1) * tagInfo.count;
  if (size <= 4) {
    return getU32(view, tagInfo.valueOffset, le);
  }
  return getU32(view, tagInfo.valueOffset, le);
}

function readAscii(view, tiffStart, tagInfo, le) {
  if (!tagInfo || tagInfo.type !== 2) return null;

  let dataOffset;
  if (tagInfo.count <= 4) {
    dataOffset = tagInfo.valueOffset;
  } else {
    dataOffset = tiffStart + getU32(view, tagInfo.valueOffset, le);
  }

  if (dataOffset + tagInfo.count > view.byteLength) return null;

  let str = '';
  for (let i = 0; i < tagInfo.count - 1; i++) {
    const c = view.getUint8(dataOffset + i);
    if (c === 0) break;
    str += String.fromCharCode(c);
  }
  return str || null;
}

function readGPSCoord(view, tiffStart, gpsTags, coordTag, refTag, le) {
  if (!gpsTags[coordTag] || !gpsTags[refTag]) return null;

  const refInfo = gpsTags[refTag];
  const ref = String.fromCharCode(view.getUint8(refInfo.valueOffset));

  const coordInfo = gpsTags[coordTag];
  if (coordInfo.type !== 5 || coordInfo.count !== 3) return null;

  const dataOffset = tiffStart + getU32(view, coordInfo.valueOffset, le);
  if (dataOffset + 24 > view.byteLength) return null;

  const degNum = getU32(view, dataOffset, le);
  const degDen = getU32(view, dataOffset + 4, le);
  const minNum = getU32(view, dataOffset + 8, le);
  const minDen = getU32(view, dataOffset + 12, le);
  const secNum = getU32(view, dataOffset + 16, le);
  const secDen = getU32(view, dataOffset + 20, le);

  if (degDen === 0 || minDen === 0 || secDen === 0) return null;

  let decimal = degNum / degDen + minNum / minDen / 60 + secNum / secDen / 3600;

  if (ref === 'S' || ref === 'W') decimal = -decimal;

  return Math.round(decimal * 1000000) / 1000000;
}

function getU16(view, offset, le) {
  if (offset + 2 > view.byteLength) return 0;
  return view.getUint16(offset, le);
}

function getU32(view, offset, le) {
  if (offset + 4 > view.byteLength) return 0;
  return view.getUint32(offset, le);
}
