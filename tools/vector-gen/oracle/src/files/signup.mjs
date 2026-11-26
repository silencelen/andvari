// signup.json (server-only): the sign-up code MAC, proof-of-work acceptance, the uniform answers
// of verify, and the ticket's binding to an address (design §7.2, §7.3, §7.5, §2.3).

import { b64u, mustUnb64u, utf8, hex } from '../bytes.mjs';
import { sha256 } from '../prims.mjs';
import { emailNorm, leadingZeroBits } from '../grammar.mjs';
import { codeMac, codeMacInput, emailHash, powInput, checkPow, verifyCode, checkTicket } from '../signup.mjs';
import { findNonce } from '../powsearch.mjs';
import { fixed } from '../cast.mjs';

export const file = 'signup.json';

const SECRET = fixed('signup/secret');
const OTHER_SECRET = fixed('signup/other-secret');
const EMAIL = 'alice@example.com';
const NOW = Date.UTC(2026, 10, 15, 12, 0, 0); // 2026-11-15T12:00:00Z
const MINUTE = 60 * 1000;

export function build() {
  // ---- the code MAC ----
  const macRow = (why, secret, email, code) => ({
    why, signupSecretB64: b64u(secret), emailNorm: email, code, inputUtf8: codeMacInput(email, code),
    codeMacHex: hex(codeMac(secret, email, code)), codeMacB64: b64u(codeMac(secret, email, code)),
  });
  const codeMacRows = [
    macRow('the code MAC stored for an address', SECRET, EMAIL, '482915'),
    macRow('a code with leading zeros is six characters all the same', SECRET, EMAIL, '000042'),
    macRow('another code for the same address', SECRET, EMAIL, '482916'),
    macRow('the same code for another address', SECRET, 'bob@example.com', '482915'),
    macRow('the same address and code under another instance\'s secret', OTHER_SECRET, EMAIL, '482915'),
  ];
  const emailHashRows = ['Alice@Example.com ', EMAIL, 'bob@example.com'].map((input) => ({
    why: input === EMAIL ? 'an address that is already normal' : input.startsWith('A') ? 'the hash is taken over emailNorm, so case and outer white space do not matter' : 'another address',
    email: input, emailNorm: emailNorm(input), emailHash: emailHash(emailNorm(input)),
  }));

  // ---- proof of work ----
  const today = '2026-11-15';
  const yesterday = '2026-11-14';
  const older = '2026-11-13';
  const tomorrow = '2026-11-16';
  const pow = [];
  const powRow = (name, verdict, why, input) => {
    const full = { powBits: 8, now: NOW, email: EMAIL, pow: null, ...input };
    const norm = emailNorm(full.email);
    // spec 03 §14.1 checks the address (400 invalid_email) before the proof of work.
    const got = norm === null ? 'invalid_email' : checkPow({ powBits: full.powBits, now: full.now, email: norm, pow: full.pow });
    if (got !== verdict) throw new Error(`signup pow "${name}": the design says ${verdict}, the oracle says ${got}`);
    const row = { name, why, powBits: full.powBits, serverNow: full.now, serverNowUtc: new Date(full.now).toISOString(), email: full.email, emailNorm: norm, pow: full.pow };
    if (full.pow && norm !== null) {
      const digest = sha256(powInput(norm, full.pow.date, full.pow.nonce));
      row.inputUtf8 = powInput(norm, full.pow.date, full.pow.nonce);
      row.digestHex = hex(digest);
      row.leadingZeroBits = leadingZeroBits(digest);
    }
    row.expect = verdict === 'accepted' ? { verdict } : { verdict, wire: '400 ' + verdict };
    pow.push(row);
  };
  const n8 = (date, email = EMAIL) => findNonce(email, date, 8);
  powRow('off', 'accepted', 'powBits 0: proof of work is off and none is sent.', { powBits: 0 });
  powRow('required-and-missing', 'pow_required', 'powBits 8 and no pow in the body.', {});
  powRow('8-bits-today', 'accepted', '8 bits, hashed with today\'s UTC date.', { pow: { date: today, nonce: n8(today) } });
  powRow('8-bits-yesterday', 'accepted', '8 bits, hashed with yesterday\'s UTC date: accepted.', { pow: { date: yesterday, nonce: n8(yesterday) } });
  powRow('8-bits-older', 'bad_pow', 'A nonce that is right for the date two days ago: the date is neither today nor yesterday.', { pow: { date: older, nonce: n8(older) } });
  powRow('8-bits-tomorrow', 'bad_pow', 'A nonce that is right for tomorrow\'s date (a client clock ahead).', { pow: { date: tomorrow, nonce: n8(tomorrow) } });
  powRow('7-bits', 'bad_pow', 'The digest has 7 leading zero bits where 8 are needed.', { pow: { date: today, nonce: findNonce(EMAIL, today, 7, 8) } });
  powRow('more-bits-than-needed', 'accepted', 'A digest with more than 8 leading zero bits.', { pow: { date: today, nonce: findNonce(EMAIL, today, 12) } });
  powRow('nonce-for-another-address', 'bad_pow', 'A nonce found for another address.', { pow: { date: today, nonce: findNonce('bob@example.com', today, 8, 257) } });
  powRow('nonce-for-another-date', 'bad_pow', 'Yesterday\'s nonce sent with today\'s date.', { pow: { date: today, nonce: n8(yesterday) } });
  powRow('address-is-normalised-first', 'accepted', 'The body\'s address has capitals and a trailing space; the hash is over emailNorm.', { email: 'Alice@Example.com ', pow: { date: today, nonce: n8(today) } });
  powRow('just-after-midnight-yesterday', 'accepted', 'Thirty seconds after midnight UTC, yesterday\'s date is still accepted.', { now: Date.UTC(2026, 10, 15, 0, 0, 30), pow: { date: yesterday, nonce: n8(yesterday) } });
  powRow('just-after-midnight-two-days-ago', 'bad_pow', 'Thirty seconds after midnight UTC, the date before yesterday is refused.', { now: Date.UTC(2026, 10, 15, 0, 0, 30), pow: { date: older, nonce: n8(older) } });
  powRow('just-before-midnight-tomorrow', 'bad_pow', 'One second before midnight UTC, tomorrow\'s date is not yet today.', { now: Date.UTC(2026, 10, 14, 23, 59, 59), pow: { date: today, nonce: n8(today) } });
  const n20 = findNonce(EMAIL, today, 20);
  powRow('20-bits-today', 'accepted', '20 bits (about a second on a phone).', { powBits: 20, pow: { date: today, nonce: n20 } });
  powRow('20-bits-needed-8-found', 'bad_pow', 'powBits 20 with a nonce that reaches only 8 bits.', { powBits: 20, pow: { date: today, nonce: findNonce(EMAIL, today, 8, 20) } });
  if (leadingZeroBits(sha256(powInput(EMAIL, today, n20))) !== 20) throw new Error('signup: the 20-bit nonce should give exactly 20 bits');
  powRow('one-bit-short', 'bad_pow', 'powBits 21 with a digest of exactly 20 leading zero bits: one bit short.', { powBits: 21, pow: { date: today, nonce: n20 } });
  // Fourth batch (spec 01 §5.5): an address with no emailNorm is 400 invalid_email. This one passes
  // the strip, the case, the byte range and the one-@ test, so only the dot-atom rule refuses it.
  // powBits is 0 and no pow is sent, so no other refusal of this section can apply and the row
  // grades no order between refusals.
  powRow('address-in-a-display-name-form', 'invalid_email', 'powBits 0 and no pow, and the body\'s address is alice<alice@example.com>: lower case, one @, printable ASCII, but the local part is not a dot-atom, so the address has no emailNorm (spec 01 §5.5): 400 invalid_email. emailNorm is null.', { powBits: 0, email: 'alice<alice@example.com>' });

  // ---- verify: one uniform refusal ----
  const stored = (code, overrides = {}) => ({ codeMac: codeMac(SECRET, EMAIL, code), expiresAt: NOW + 15 * MINUTE, attempts: 0, ...overrides });
  const verify = [];
  const verifyRow = (name, why, state, code, now, want) => {
    const got = verifyCode({ secret: SECRET, stored: state, email: EMAIL, code, now });
    if (JSON.stringify(got) !== JSON.stringify(want)) throw new Error(`signup verify "${name}": the design says ${JSON.stringify(want)}, the oracle says ${JSON.stringify(got)}`);
    verify.push({
      name, why, signupSecretB64: b64u(SECRET), emailNorm: EMAIL,
      stored: state ? { codeMacB64: b64u(state.codeMac), expiresAt: state.expiresAt, attempts: state.attempts } : null,
      code, now, expect: want,
    });
  };
  const BAD = { status: 400, code: 'bad_code' };
  verifyRow('right-code', 'The stored code, in time, no attempts used: 200 with a ticket.', stored('482915'), '482915', NOW + MINUTE, { status: 200 });
  verifyRow('wrong-code', 'A wrong code: the uniform 400 bad_code, and attempts goes to 1.', stored('482915'), '482916', NOW + MINUTE, { ...BAD, attemptsAfter: 1 });
  verifyRow('right-code-after-four-wrong', 'Four wrong codes so far: the right one still verifies.', stored('482915', { attempts: 4 }), '482915', NOW + MINUTE, { status: 200 });
  verifyRow('fifth-wrong-code', 'The fifth wrong code: attempts reaches 5 and the code is dead.', stored('482915', { attempts: 4 }), '111111', NOW + MINUTE, { ...BAD, attemptsAfter: 5 });
  verifyRow('right-code-on-a-dead-code', 'Attempts used up (5): even the right code gets the same 400 bad_code.', stored('482915', { attempts: 5 }), '482915', NOW + MINUTE, BAD);
  verifyRow('right-code-expired', 'The right code one millisecond after its 15 minutes: the same 400 bad_code.', stored('482915'), '482915', NOW + 15 * MINUTE + 1, BAD);
  verifyRow('right-code-at-its-expiry', 'now equals expiresAt: expiry is exclusive, so the code has expired. The same 400 bad_code.', stored('482915'), '482915', NOW + 15 * MINUTE, BAD);
  verifyRow('right-code-one-millisecond-before-expiry', 'One millisecond before expiresAt the code still verifies.', stored('482915'), '482915', NOW + 15 * MINUTE - 1, { status: 200 });
  verifyRow('no-code-for-the-address', 'No code was ever sent to this address (or it has an account already): the same 400 bad_code.', null, '482915', NOW + MINUTE, BAD);
  verifyRow('code-of-another-address', 'The stored code belongs to another address: the MAC covers the address, so it does not verify.', { ...stored('482915'), codeMac: codeMac(SECRET, 'bob@example.com', '482915') }, '482915', NOW + MINUTE, { ...BAD, attemptsAfter: 1 });
  verifyRow('replaced-code', 'A new code replaced the first one for this address; the first code no longer verifies.', stored('730114'), '482915', NOW + MINUTE, { ...BAD, attemptsAfter: 1 });

  // ---- start: one uniform answer ----
  const start = [
    { why: 'the address has no account: a code is stored and the code email is sent', accountExists: false, expect: { status: 202, body: { status: 'sent' } }, email: 'signup_code' },
    { why: 'the address already has an account: the SAME answer; an "already registered" email goes out instead, at most once a day', accountExists: true, expect: { status: 202, body: { status: 'sent' } }, email: 'signup_existing' },
  ];

  // ---- the ticket ----
  const ticket = (overrides = {}) => ({ emailHash: emailHash(EMAIL), expiresAt: NOW + 30 * MINUTE, used: false, ...overrides });
  const tickets = [];
  const ticketRow = (name, why, t, email, now, verdict) => {
    const got = checkTicket({ ticket: t, email, now });
    if (got !== verdict) throw new Error(`signup ticket "${name}": the design says ${verdict}, the oracle says ${got}`);
    tickets.push({ name, why, ticket: t, registerEmail: email, now, expect: verdict === 'ok' ? { verdict } : { verdict, wire: '400 bad_ticket' } });
  };
  ticketRow('same-address', 'The ticket was issued for this address, is unused and in time.', ticket(), EMAIL, NOW + MINUTE, 'ok');
  ticketRow('same-address-other-spelling', 'The register body spells the address with capitals and a space: the binding is to SHA-256(emailNorm).', ticket(), ' Alice@EXAMPLE.com', NOW + MINUTE, 'ok');
  ticketRow('another-address', 'A ticket earned with one address used to register another.', ticket(), 'bob@example.com', NOW + MINUTE, 'bad_ticket');
  ticketRow('expired', 'One millisecond after its 30 minutes.', ticket(), EMAIL, NOW + 30 * MINUTE + 1, 'bad_ticket');
  ticketRow('at-its-expiry', 'now equals expiresAt: expiry is exclusive, so the ticket has expired.', ticket(), EMAIL, NOW + 30 * MINUTE, 'bad_ticket');
  ticketRow('one-millisecond-before-expiry', 'One millisecond before expiresAt the ticket is still good.', ticket(), EMAIL, NOW + 30 * MINUTE - 1, 'ok');
  ticketRow('used', 'A ticket is single use.', ticket({ used: true }), EMAIL, NOW + MINUTE, 'bad_ticket');
  ticketRow('unknown', 'No such ticket.', null, EMAIL, NOW + MINUTE, 'bad_ticket');

  return {
    _about: [
      'Sign-up of design 2026-11-15-onboarding-trust §7.2, §7.3 and §7.5, with the derivations of §2.3. Server-only: graded by the JVM server suite.',
      'Hand-authored from the independent oracle in tools/vector-gen/oracle (Node WebCrypto and @noble; no andvari code). Regenerate with `npm run generate` there; `npm run check` fails on any difference.',
      'codeMac: HMAC-SHA-256(signupSecret, "andvari/v2|signup-code|" + emailNorm + "|" + code), with the code as its six characters. The 32 bytes are given as hex and as unpadded base64url. emailHash: hex SHA-256 over emailNorm.',
      'pow: POST /signup/start with `powBits` in force and the server\'s clock at `serverNow`. The server normalises the address, accepts pow.date only if it is today\'s or yesterday\'s UTC date, and recomputes SHA-256("andvari/v2|signup-pow|" + emailNorm + "|" + pow.date + "|" + pow.nonce); the digest needs at least powBits leading zero bits, counted from the most significant bit of byte 0. expect.verdict: accepted, pow_required (no pow in the body) or bad_pow; and invalid_email (wire 400 invalid_email, emailNorm null) for the one row whose address has no emailNorm (spec 01 §5.5, added on 2026-11-15, fourth batch), which has powBits 0 and no pow so that no other refusal applies.',
      'verify: POST /signup/verify for an address whose stored row is `stored` (null when there is none). 200, or ONE uniform 400 bad_code whatever the cause: no code, a wrong code, an expired one, attempts used up. A wrong code increments attempts (expect.attemptsAfter); at 5 the code is dead. Expiry is exclusive: the code is valid while now < expiresAt.',
      'start: for an address that passes every refusal, the answer is always 202 {"status":"sent"}, whether or not the address has an account; only the email that goes out differs.',
      'ticket: register step 3. A ticket is bound to hex SHA-256(emailNorm) of the address it was earned with, lives 30 minutes (valid while now < expiresAt) and is single use; anything else is the uniform 400 bad_ticket.',
      'Not graded: the hash a ticket is stored under (over its 32 bytes or over its text; decided to be out of scope, no row), a proof of work sent while powBits is 0, and the order of the refusals of /signup/start.',
    ],
    serverNow: NOW,
    codeMac: codeMacRows,
    emailHash: emailHashRows,
    pow,
    verify,
    start,
    ticket: tickets,
  };
}

export function grade(doc) {
  const failures = [];
  let rows = 0;
  const expect = (cond, what) => {
    rows++;
    if (!cond) failures.push(what);
  };
  for (const row of doc.codeMac) {
    const mac = codeMac(mustUnb64u(row.signupSecretB64), row.emailNorm, row.code);
    expect(codeMacInput(row.emailNorm, row.code) === row.inputUtf8 && hex(mac) === row.codeMacHex && b64u(mac) === row.codeMacB64 && /^[0-9]{6}$/.test(row.code), 'codeMac: ' + row.why);
  }
  for (const row of doc.emailHash) expect(emailNorm(row.email) === row.emailNorm && emailHash(row.emailNorm) === row.emailHash, 'emailHash: ' + row.email);
  for (const row of doc.pow) {
    const norm = emailNorm(row.email);
    expect(norm === row.emailNorm && new Date(row.serverNow).toISOString() === row.serverNowUtc, `pow ${row.name}: inputs`);
    const verdict = norm === null ? 'invalid_email' : checkPow({ powBits: row.powBits, now: row.serverNow, email: norm, pow: row.pow });
    expect(verdict === row.expect.verdict && (norm !== null || (row.pow === null && row.powBits === 0)), `pow ${row.name}`);
    if (row.pow && norm !== null) {
      const digest = sha256(powInput(norm, row.pow.date, row.pow.nonce));
      expect(powInput(norm, row.pow.date, row.pow.nonce) === row.inputUtf8 && hex(digest) === row.digestHex && leadingZeroBits(digest) === row.leadingZeroBits, `pow ${row.name}: digest`);
    }
  }
  for (const row of doc.verify) {
    const stored = row.stored ? { codeMac: mustUnb64u(row.stored.codeMacB64), expiresAt: row.stored.expiresAt, attempts: row.stored.attempts } : null;
    const got = verifyCode({ secret: mustUnb64u(row.signupSecretB64), stored, email: row.emailNorm, code: row.code, now: row.now });
    expect(JSON.stringify(got) === JSON.stringify(row.expect), `verify ${row.name}: oracle says ${JSON.stringify(got)}`);
  }
  for (const row of doc.start) expect(row.expect.status === 202 && row.expect.body.status === 'sent', 'start: ' + row.why);
  for (const row of doc.ticket) expect(checkTicket({ ticket: row.ticket, email: row.registerEmail, now: row.now }) === row.expect.verdict, `ticket ${row.name}`);
  return { rows, failures };
}
