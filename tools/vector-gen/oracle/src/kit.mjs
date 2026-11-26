// The recovery kit (design §10): the grouped secret, the typed secret, the three-group
// confirmation, and the kit QR text.

import { b64u, unb64u, utf8, utf8DecodeStrict } from './bytes.mjs';
import { isOrigin, isHex64, emailNorm } from './grammar.mjs';

export const KIT_MAX_LENGTH = 1024;

/** 43 base64url characters in 11 groups: ten of 4, one of 3, separated by single spaces. */
export function groupSecret(secret) {
  if (secret.length !== 32) throw new Error('groupSecret: 32 bytes');
  const text = b64u(secret);
  const groups = [];
  for (let i = 0; i < text.length; i += 4) groups.push(text.slice(i, i + 4));
  return { text, groups, display: groups.join(' ') };
}

/**
 * A typed kit secret: spaces, CR and LF are ignored, and nothing else is (not a tab, not a dash:
 * base64url uses `-`). What is left must be the canonical base64url of 32 bytes. Returns the secret
 * or null.
 */
export function parseTypedSecret(input) {
  if (typeof input !== 'string') return null;
  const text = input.replace(/[ \r\n]/g, '');
  if (text.length !== 43) return null;
  const secret = unb64u(text);
  return secret !== null && secret.length === 32 ? secret : null;
}

/** Three distinct group numbers, each 1..11. */
export function validGroupChoice(indices) {
  return Array.isArray(indices) && indices.length === 3 && new Set(indices).size === 3
    && indices.every((i) => Number.isInteger(i) && i >= 1 && i <= 11);
}

/**
 * The typed groups against the secret's groups at those numbers: compared exactly and
 * case-sensitively once space, CR and LF anywhere in each typed group are ignored (nothing else is:
 * not a tab).
 */
export function confirmGroups(secret, indices, typed) {
  if (!validGroupChoice(indices)) throw new Error('confirmGroups: not a valid choice of groups');
  const { groups } = groupSecret(secret);
  return typed.length === 3 && indices.every((n, k) => typeof typed[k] === 'string' && typed[k].replace(/[ \r\n]/g, '') === groups[n - 1]);
}

/** andvari-kit:2:<O>:<C>:<E>:<S> */
export function composeKit({ origin, card0Hash, email, secret }) {
  return `andvari-kit:2:${b64u(utf8(origin))}:${card0Hash}:${b64u(utf8(email))}:${b64u(secret)}`;
}

/**
 * Total, canonical parse of the kit QR text, "exactly as for links" (§6.1) except for the cap of
 * 1024 characters: ASCII white space (space, tab, CR, LF) is removed first; O is canonical base64url
 * of an origin of §2.2; C is 64 lowercase hex; E is canonical base64url of an address that is its own
 * emailNorm; S is canonical base64url of 32 bytes. Returns the four values, or null: a kit text
 * that does not parse is bad_kit (§2.4). White space is those four characters only: a form feed or
 * a vertical tab is not removed, so the text is malformed.
 */
export function parseKit(input) {
  if (typeof input !== 'string') return null;
  const text = input.replace(/[ \t\r\n]/g, '');
  if (text.length > KIT_MAX_LENGTH) return null;
  const parts = text.split(':');
  if (parts.length !== 6 || parts[0] !== 'andvari-kit' || parts[1] !== '2') return null;
  const originBytes = unb64u(parts[2]);
  const origin = originBytes === null ? null : utf8DecodeStrict(originBytes);
  if (origin === null || !isOrigin(origin)) return null;
  if (!isHex64(parts[3])) return null;
  const emailBytes = unb64u(parts[4]);
  const email = emailBytes === null ? null : utf8DecodeStrict(emailBytes);
  if (email === null || emailNorm(email) !== email) return null;
  const secret = unb64u(parts[5]);
  if (secret === null || secret.length !== 32) return null;
  return { origin, card0Hash: parts[3], email, secret };
}
