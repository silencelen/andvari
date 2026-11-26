// Sign-up (design §7.2, §7.3, §7.5): the code MAC, the proof of work, the uniform answers of
// verify, and the ticket's binding to an address. Server-side rules, as pure functions.

import { hex, b64u, bytesEqual } from './bytes.mjs';
import { sha256, hmacSha256 } from './prims.mjs';
import { emailNorm, leadingZeroBits } from './grammar.mjs';

class Undefined extends Error {}

/** HMAC-SHA-256(signupSecret, "andvari/v2|signup-code|" + emailNorm + "|" + code). */
export const codeMacInput = (email, code) => 'andvari/v2|signup-code|' + email + '|' + code;
export const codeMac = (secret, email, code) => hmacSha256(secret, codeMacInput(email, code));

/** emailHash = hex SHA-256(emailNorm). */
export const emailHash = (email) => hex(sha256(email));

export const powInput = (email, date, nonce) => 'andvari/v2|signup-pow|' + email + '|' + date + '|' + String(nonce);
const utcDate = (ms) => new Date(ms).toISOString().slice(0, 10);

/**
 * The proof of work of POST /signup/start: 'accepted', 'pow_required' or 'bad_pow'. The server is
 * stateless about it: it accepts today's or yesterday's UTC date and recomputes the hash.
 */
export function checkPow({ powBits, now, email, pow }) {
  if (powBits === 0) {
    if (pow !== null) throw new Undefined('a proof of work sent when none is required');
    return 'accepted';
  }
  if (pow === null) return 'pow_required';
  if (pow.date !== utcDate(now) && pow.date !== utcDate(now - 24 * 60 * 60 * 1000)) return 'bad_pow';
  const digest = sha256(powInput(email, pow.date, pow.nonce));
  return leadingZeroBits(digest) >= powBits ? 'accepted' : 'bad_pow';
}

/**
 * POST /signup/verify against the stored row for the address: 200, or the uniform 400 bad_code
 * whatever the cause (no code, a wrong code, an expired one, attempts used up). Each wrong code
 * increments `attempts`; at 5 the code is dead.
 */
export function verifyCode({ secret, stored, email, code, now }) {
  const bad = { status: 400, code: 'bad_code' };
  if (stored === null) return bad;
  // Expiry is exclusive: a code is valid while now < expiresAt and has expired at now = expiresAt.
  if (now >= stored.expiresAt || stored.attempts >= 5) return bad;
  if (!bytesEqual(codeMac(secret, email, code), stored.codeMac)) return { ...bad, attemptsAfter: stored.attempts + 1 };
  return { status: 200 };
}

/**
 * Register step 3 for a ticket: valid, unexpired, unused, and bound to SHA-256(emailNorm) of the
 * address being registered; anything else is the uniform 400 bad_ticket.
 */
export function checkTicket({ ticket, email, now }) {
  const norm = emailNorm(email);
  if (norm === null) throw new Undefined('register with an address that is not an email: step 1 refuses it');
  if (ticket === null) return 'bad_ticket';
  // Expiry is exclusive here too: a ticket has expired at now = expiresAt.
  if (ticket.used || now >= ticket.expiresAt || ticket.emailHash !== emailHash(norm)) return 'bad_ticket';
  return 'ok';
}

export { b64u };
