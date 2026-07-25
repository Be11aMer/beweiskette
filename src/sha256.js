/**
 * Incremental SHA-256 (FIPS 180-4).
 *
 * The Web Crypto API has no streaming digest: crypto.subtle.digest() takes one
 * complete buffer, so hashing a file means holding all of it in memory at once.
 * For a forensics tool that is a real ceiling — a disk image or a long video
 * will exhaust the tab before it is ever hashed, and evidence files are exactly
 * the sort of thing that runs large.
 *
 * This implementation exists only to lift that ceiling. Files small enough to
 * buffer are still hashed by Web Crypto, which is native and far faster; this
 * takes over above the threshold in crypto.js, consuming the file as a stream
 * so peak memory stays at one chunk regardless of file size.
 *
 * Hand-rolled cryptography deserves suspicion, so note what this is and is not.
 * It is a hash function, not a secret-dependent operation: there is no key and
 * no secret input, so the usual side-channel hazards of hand-written crypto do
 * not apply. Correctness is the only requirement, and it is checked against the
 * published FIPS 180-4 vectors and directly against crypto.subtle over
 * randomized inputs and every buffer-boundary case (see test/sha256.test.js).
 * A digest that disagreed with Web Crypto by one bit would split every chain
 * hashed on either side of the threshold.
 */

const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

const INITIAL_STATE = new Uint32Array([
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]);

const BLOCK_SIZE = 64;

function rotr(x, n) {
  return (x >>> n) | (x << (32 - n));
}

export class Sha256 {
  constructor() {
    this.state = INITIAL_STATE.slice();
    this.block = new Uint8Array(BLOCK_SIZE);
    this.blockLength = 0;
    this.byteCount = 0;
    this.schedule = new Uint32Array(64);
    this.finished = false;
  }

  /**
   * Absorb more bytes. May be called any number of times with chunks of any
   * size; the result depends only on the concatenation, never on how it was
   * split.
   *
   * @param {Uint8Array} bytes
   * @returns {Sha256} this, for chaining
   */
  update(bytes) {
    if (this.finished) throw new Error('Sha256: update() called after digest()');
    this.byteCount += bytes.length;

    let offset = 0;

    // Top up a partially filled block from the previous call.
    if (this.blockLength > 0) {
      const take = Math.min(BLOCK_SIZE - this.blockLength, bytes.length);
      this.block.set(bytes.subarray(0, take), this.blockLength);
      this.blockLength += take;
      offset = take;
      if (this.blockLength === BLOCK_SIZE) {
        this.compress(this.block, 0);
        this.blockLength = 0;
      }
    }

    // Compress whole blocks straight out of the caller's buffer.
    while (offset + BLOCK_SIZE <= bytes.length) {
      this.compress(bytes, offset);
      offset += BLOCK_SIZE;
    }

    // Carry the remainder into the next call.
    if (offset < bytes.length) {
      this.block.set(bytes.subarray(offset), 0);
      this.blockLength = bytes.length - offset;
    }

    return this;
  }

  /**
   * Apply the FIPS 180-4 padding and return the digest as lowercase hex.
   * The instance cannot be updated afterwards.
   */
  digest() {
    if (this.finished) throw new Error('Sha256: digest() called twice');
    this.finished = true;

    // The length is appended as a 64-bit big-endian bit count. byteCount stays
    // an exact integer well past any file size a browser can read.
    const bits = this.byteCount * 8;

    this.block[this.blockLength++] = 0x80;

    // No room for the 8-byte length: flush this block first.
    if (this.blockLength > BLOCK_SIZE - 8) {
      this.block.fill(0, this.blockLength);
      this.compress(this.block, 0);
      this.blockLength = 0;
    }

    this.block.fill(0, this.blockLength, BLOCK_SIZE - 8);

    const view = new DataView(this.block.buffer, this.block.byteOffset, BLOCK_SIZE);
    view.setUint32(BLOCK_SIZE - 8, Math.floor(bits / 0x100000000), false);
    view.setUint32(BLOCK_SIZE - 4, bits % 0x100000000, false);
    this.compress(this.block, 0);

    let hex = '';
    for (let i = 0; i < 8; i++) {
      hex += (this.state[i] >>> 0).toString(16).padStart(8, '0');
    }
    return hex;
  }

  /** Process one 64-byte block starting at `offset`. */
  compress(bytes, offset) {
    const w = this.schedule;

    for (let i = 0; i < 16; i++) {
      const j = offset + i * 4;
      w[i] = (bytes[j] << 24) | (bytes[j + 1] << 16) | (bytes[j + 2] << 8) | bytes[j + 3];
    }
    for (let i = 16; i < 64; i++) {
      const a = w[i - 15];
      const b = w[i - 2];
      const s0 = rotr(a, 7) ^ rotr(a, 18) ^ (a >>> 3);
      const s1 = rotr(b, 17) ^ rotr(b, 19) ^ (b >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
    }

    let [a, b, c, d, e, f, g, h] = this.state;

    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const temp1 = (h + S1 + ch + K[i] + w[i]) | 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) | 0;

      h = g;
      g = f;
      f = e;
      e = (d + temp1) | 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) | 0;
    }

    this.state[0] = (this.state[0] + a) | 0;
    this.state[1] = (this.state[1] + b) | 0;
    this.state[2] = (this.state[2] + c) | 0;
    this.state[3] = (this.state[3] + d) | 0;
    this.state[4] = (this.state[4] + e) | 0;
    this.state[5] = (this.state[5] + f) | 0;
    this.state[6] = (this.state[6] + g) | 0;
    this.state[7] = (this.state[7] + h) | 0;
  }
}

/** One-shot convenience wrapper. */
export function sha256Hex(bytes) {
  return new Sha256().update(bytes).digest();
}
