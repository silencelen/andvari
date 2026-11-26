// Byte and text helpers. No crypto here.

const B64URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const B64URL_INDEX = new Map([...B64URL].map((c, i) => [c, i]));

/** UTF-8 bytes of a JS string. */
export function utf8(s) {
  return new TextEncoder().encode(s);
}

/** Strict UTF-8 decode (RFC 3629): returns null for overlongs, surrogates, > U+10FFFF and truncations. */
export function utf8DecodeStrict(bytes) {
  try {
    return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    return null;
  }
}

/** Bytes to a one-char-per-byte string (for printing non-UTF-8 material and for byte-exact compares). */
export function latin1(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return s;
}

export function fromLatin1(s) {
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c > 0xff) throw new Error('fromLatin1: code unit above 0xff');
    out[i] = c;
  }
  return out;
}

export function concat(...parts) {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

export function bytesEqual(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

export function hex(bytes) {
  let s = '';
  for (const b of bytes) s += b.toString(16).padStart(2, '0');
  return s;
}

export function unhex(s) {
  if (typeof s !== 'string' || s.length % 2 !== 0 || !/^[0-9a-f]*$/.test(s)) throw new Error('unhex: not lowercase hex');
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(2 * i, 2 * i + 2), 16);
  return out;
}

/** Unpadded base64url (RFC 4648 §5). */
export function b64u(bytes) {
  let s = '';
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    s += B64URL[n >>> 18] + B64URL[(n >>> 12) & 63] + B64URL[(n >>> 6) & 63] + B64URL[n & 63];
  }
  if (i + 1 === bytes.length) {
    const n = bytes[i] << 16;
    s += B64URL[n >>> 18] + B64URL[(n >>> 12) & 63];
  } else if (i + 2 === bytes.length) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8);
    s += B64URL[n >>> 18] + B64URL[(n >>> 12) & 63] + B64URL[(n >>> 6) & 63];
  }
  return s;
}

/**
 * Canonical unpadded base64url decode: returns null unless the text uses only the url alphabet, has a
 * possible length, and re-encodes to itself (so no padding, no stray bits in the last character).
 */
export function unb64u(s) {
  if (typeof s !== 'string') return null;
  if (s.length % 4 === 1) return null;
  const out = new Uint8Array(Math.floor((s.length * 3) / 4));
  let acc = 0;
  let bits = 0;
  let o = 0;
  for (const c of s) {
    const v = B64URL_INDEX.get(c);
    if (v === undefined) return null;
    acc = ((acc << 6) | v) & 0xffffff;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (acc >>> bits) & 0xff;
    }
  }
  if (b64u(out) !== s) return null;
  return out;
}

/** Decode that must succeed (fixture construction). */
export function mustUnb64u(s) {
  const b = unb64u(s);
  if (!b) throw new Error('not canonical base64url: ' + s);
  return b;
}

export function u32be(bytes, offset = 0) {
  return ((bytes[offset] << 24) | (bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3]) >>> 0;
}

export function isPrintableAscii(bytes) {
  for (const b of bytes) if (b < 0x20 || b > 0x7e) return false;
  return true;
}

export function isAscii(str) {
  for (let i = 0; i < str.length; i++) if (str.charCodeAt(i) > 0x7f) return false;
  return true;
}
