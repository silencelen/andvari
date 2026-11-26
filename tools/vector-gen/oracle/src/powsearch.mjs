// Brute-force searches: proof-of-work nonces, and the code nonce that gives a link two equal
// comparison codes. Only a search: everything it returns is hashed again through prims.mjs (and so
// through WebCrypto) by the file that uses it, which also checks that the value does what it was
// searched for. Node's own SHA-256 is used here because it is the fastest one at hand, and results
// are remembered within a run.

import { createHash } from 'node:crypto';
import { leadingZeroBits } from './grammar.mjs';

const memo = new Map();

/**
 * The smallest i >= 0 for which the nonceB that cast.mjs's `fixed(label + i)` yields gives a link
 * the same six digits on both sides (§6.11 "Equal codes": about one link in a million). The other
 * four inputs of the two codes are given as their text. About one try in a million succeeds, and
 * a try is three hashes: the nonce, then the code of each side (§2.3).
 */
export function findEqualLinkCodes({ linkId, offerHash, answerHash, nonceAB64 }, label) {
  const key = ['equal-link-codes', linkId, offerHash, answerHash, nonceAB64, label].join('|');
  if (memo.has(key)) return memo.get(key);
  const head = '|' + linkId + '|' + offerHash + '|' + answerHash + '|' + nonceAB64 + '|';
  const digits = (side, tail) => createHash('sha256').update('andvari/v2|link|code|' + side + tail).digest().readUInt32BE(0) % 1000000;
  for (let i = 0; ; i++) {
    const nonceB = createHash('sha256').update('andvari-vector-oracle|' + label + i).digest();
    const tail = head + nonceB.toString('base64url');
    if (digits('creator', tail) === digits('answerer', tail)) {
      memo.set(key, i);
      return i;
    }
  }
}

/** The smallest nonce n >= 0 whose digest has at least `min` and fewer than `below` leading zero bits. */
export function findNonce(email, date, min, below = 257) {
  const key = [email, date, min, below].join('|');
  if (memo.has(key)) return memo.get(key);
  const prefix = 'andvari/v2|signup-pow|' + email + '|' + date + '|';
  for (let n = 0; ; n++) {
    const bits = leadingZeroBits(createHash('sha256').update(prefix + n).digest());
    if (bits >= min && bits < below) {
      memo.set(key, n);
      return n;
    }
  }
}
