/**
 * Hashes used as OSINT pivots.
 *
 * Two of the highest-yield pivots in the discipline are hash lookups, and both
 * need a hash we compute ourselves before anything else can use it:
 *
 *   - MurmurHash3 of a base64-encoded favicon is the key Shodan, Censys and
 *     FOFA index under `http.favicon.hash`. Two unrelated hostnames serving the
 *     same favicon share an operator far more often than not, and it is the
 *     standard way to find the origin server hiding behind a CDN.
 *   - Gravatar is keyed by the hash of a lower-cased email address. Computing
 *     it locally means the address is never sent to a third party — only its
 *     digest — while still resolving to a public profile.
 *
 * Runtime-agnostic: `crypto.subtle` and `TextEncoder` exist on both Workers and
 * Node 20+.
 */

/**
 * MurmurHash3 x86 32-bit, returned signed — the form Shodan indexes.
 *
 * Written out because the algorithm's whole point here is bit-exact agreement
 * with someone else's index: any deviation (unsigned output, a different seed,
 * `>>` instead of `>>>`) produces a number that is simply never found.
 *
 * @param {string} input  Latin-1/ASCII text. Callers pass base64, so this holds.
 * @param {number} seed
 * @returns {number} signed 32-bit hash
 */
export function murmur3(input, seed = 0) {
  const C1 = 0xcc9e2d51;
  const C2 = 0x1b873593;
  const remainder = input.length & 3;
  const blocks = input.length - remainder;

  let h1 = seed;
  let i = 0;

  const multiply = (a, b) =>
    // 32-bit multiply without losing the high bits to float precision.
    (((a & 0xffff) * b) + ((((a >>> 16) * b) & 0xffff) << 16)) & 0xffffffff;
  const rotate = (value, bits) => (value << bits) | (value >>> (32 - bits));

  while (i < blocks) {
    let k1 =
      (input.charCodeAt(i) & 0xff) |
      ((input.charCodeAt(i + 1) & 0xff) << 8) |
      ((input.charCodeAt(i + 2) & 0xff) << 16) |
      ((input.charCodeAt(i + 3) & 0xff) << 24);
    i += 4;

    k1 = multiply(k1, C1);
    k1 = rotate(k1, 15);
    k1 = multiply(k1, C2);

    h1 ^= k1;
    h1 = rotate(h1, 13);
    h1 = (multiply(h1, 5) + 0xe6546b64) & 0xffffffff;
  }

  let k1 = 0;
  switch (remainder) {
    case 3: k1 ^= (input.charCodeAt(i + 2) & 0xff) << 16; // falls through
    case 2: k1 ^= (input.charCodeAt(i + 1) & 0xff) << 8;  // falls through
    case 1:
      k1 ^= input.charCodeAt(i) & 0xff;
      k1 = multiply(k1, C1);
      k1 = rotate(k1, 15);
      k1 = multiply(k1, C2);
      h1 ^= k1;
      break;
    default:
      break;
  }

  h1 ^= input.length;
  h1 ^= h1 >>> 16;
  h1 = multiply(h1, 0x85ebca6b);
  h1 ^= h1 >>> 13;
  h1 = multiply(h1, 0xc2b2ae35);
  h1 ^= h1 >>> 16;

  return h1 | 0;
}

/**
 * Base64 in the layout Python's `base64.encodebytes` produces: 76-character
 * lines, each terminated by a newline.
 *
 * This detail is load-bearing. Shodan's crawler hashes the output of that exact
 * Python call, so hashing unwrapped base64 yields a valid MurmurHash of the
 * wrong string and every search built from it returns nothing.
 */
export function base64Lines(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);

  const encoded = base64(binary);
  const lines = [];
  for (let i = 0; i < encoded.length; i += 76) lines.push(encoded.slice(i, i + 76));
  return `${lines.join('\n')}\n`;
}

/** Base64 of a binary string, on either runtime. */
function base64(binary) {
  if (typeof btoa === 'function') return btoa(binary);
  return Buffer.from(binary, 'binary').toString('base64');
}

/** Shodan/Censys favicon hash for raw icon bytes. */
export function faviconHash(bytes) {
  return murmur3(base64Lines(bytes));
}

/** Lower-case hex digest. `algorithm` is any name `crypto.subtle` accepts. */
export async function digest(algorithm, text) {
  const bytes = new TextEncoder().encode(text);
  const buffer = await crypto.subtle.digest(algorithm, bytes);
  return [...new Uint8Array(buffer)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

export const sha256 = (text) => digest('SHA-256', text);

/**
 * MD5, implemented here because `crypto.subtle` deliberately does not offer it.
 *
 * Not used for anything security-bearing — Gravatar's original URL scheme is
 * keyed by the MD5 of the address, and older profile links still use it, so a
 * lookup that omits it silently misses accounts.
 */
export function md5(text) {
  const bytes = new TextEncoder().encode(text);
  const bitLength = bytes.length * 8;

  // Pad to 64-byte blocks: a 0x80 byte, zeroes, then the 64-bit length.
  const padded = new Uint8Array((((bytes.length + 8) >> 6) + 1) << 6);
  padded.set(bytes);
  padded[bytes.length] = 0x80;
  const view = new DataView(padded.buffer);
  view.setUint32(padded.length - 8, bitLength >>> 0, true);
  view.setUint32(padded.length - 4, Math.floor(bitLength / 0x100000000), true);

  const S = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
  ];
  const K = [...Array(64).keys()].map((i) => Math.floor(Math.abs(Math.sin(i + 1)) * 0x100000000));

  let [a0, b0, c0, d0] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];

  for (let offset = 0; offset < padded.length; offset += 64) {
    const M = [...Array(16).keys()].map((i) => view.getUint32(offset + i * 4, true));
    let [A, B, C, D] = [a0, b0, c0, d0];

    for (let i = 0; i < 64; i++) {
      let F;
      let g;
      if (i < 16) { F = (B & C) | (~B & D); g = i; }
      else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16; }
      else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) % 16; }
      else { F = C ^ (B | ~D); g = (7 * i) % 16; }

      F = (F + A + K[i] + M[g]) >>> 0;
      A = D;
      D = C;
      C = B;
      B = (B + ((F << S[i]) | (F >>> (32 - S[i])))) >>> 0;
    }

    a0 = (a0 + A) >>> 0;
    b0 = (b0 + B) >>> 0;
    c0 = (c0 + C) >>> 0;
    d0 = (d0 + D) >>> 0;
  }

  const hex = (value) =>
    [0, 8, 16, 24].map((shift) => ((value >>> shift) & 0xff).toString(16).padStart(2, '0')).join('');
  return hex(a0) + hex(b0) + hex(c0) + hex(d0);
}
