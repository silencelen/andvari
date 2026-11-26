// recoverykit.json: the grouped recovery secret, the typed secret, the three-group confirmation and
// the kit QR text (design §10).

import { b64u, mustUnb64u, utf8 } from '../bytes.mjs';
import { groupSecret, parseTypedSecret, validGroupChoice, confirmGroups, composeKit, parseKit, KIT_MAX_LENGTH } from '../kit.mjs';
import { fixed } from '../cast.mjs';

export const file = 'recoverykit.json';

const cp = (...codes) => String.fromCodePoint(...codes);
const X = 'https://vault.example.org';
const CARD0 = '5c' + 'a1'.repeat(31);
const EMAIL = 'alice@example.com';

/** A fixed secret whose base64url text holds both `-` and `_`, so the dash rows mean something. */
function secretWithDashes() {
  for (let i = 0; ; i++) {
    const secret = fixed('recoverykit/secret/' + i);
    const text = b64u(secret);
    if (text.includes('-') && text.includes('_') && /[a-z]/.test(text) && /[A-Z]/.test(text)) return secret;
  }
}

export function build() {
  const secret = secretWithDashes();
  const g = groupSecret(secret);
  const other = fixed('recoverykit/other-secret');

  // ---- grouping ----
  const grouping = [secret, other, new Uint8Array(32), new Uint8Array(32).fill(0xff)].map((s, i) => {
    const r = groupSecret(s);
    return {
      why: ['the kit secret used throughout this file; its text holds "-" and "_"', 'another secret', '32 zero bytes', '32 bytes of 0xff'][i],
      secretB64: r.text, groups: r.groups, display: r.display,
    };
  });

  // ---- the typed secret ----
  const typed = [];
  const ok = (why, input) => {
    const got = parseTypedSecret(input);
    if (got === null || b64u(got) !== g.text) throw new Error('recoverykit typed fixture should parse: ' + why);
    typed.push({ why, input, expect: { valid: true, secretB64: g.text } });
  };
  const no = (why, input) => {
    if (parseTypedSecret(input) !== null) throw new Error('recoverykit typed fixture should be refused: ' + why);
    typed.push({ why, input, expect: { valid: false } });
  };
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  const strayLast = g.text.slice(0, 42) + alphabet[alphabet.indexOf(g.text[42]) | 1];
  ok('as displayed: eleven groups separated by single spaces', g.display);
  ok('no separators at all', g.text);
  ok('one group per line (LF)', g.groups.join('\n'));
  ok('one group per line (CR LF)', g.groups.join('\r\n'));
  ok('several spaces between groups, and at both ends', '  ' + g.groups.join('   ') + '  ');
  ok('a space inside a group', g.text.slice(0, 2) + ' ' + g.text.slice(2));
  no('groups separated by tabs: a tab is not ignored', g.groups.join('\t'));
  no('groups separated by dashes: a dash is base64url and is not ignored', g.groups.join('-'));
  no('groups separated by NO-BREAK SPACE', g.groups.join(cp(0xa0)));
  no('a form feed between two groups', g.groups.slice(0, 5).join(' ') + cp(0x0c) + g.groups.slice(5).join(' '));
  no('the last character missing (42 characters)', g.text.slice(0, 42));
  no('one character too many (44 characters)', g.text + 'A');
  no('padded', g.text + '=');
  no('the standard alphabet: "+" for "-" and "/" for "_"', g.display.replaceAll('-', '+').replaceAll('_', '/'));
  no('43 characters whose last one carries stray bits', strayLast === g.text ? g.text.slice(0, 42) + 'B' : strayLast);
  no('empty', '');
  no('only spaces and line breaks', ' \n \r\n ');
  no('the whole kit QR text is not a typed secret', composeKit({ origin: X, card0Hash: CARD0, email: EMAIL, secret }));

  // ---- the three-group confirmation ----
  const confirm = [];
  const check = (why, indices, typedGroups, matches) => {
    if (confirmGroups(secret, indices, typedGroups) !== matches) throw new Error('recoverykit confirm fixture: ' + why);
    confirm.push({ why, secretB64: g.text, groups: indices, typed: typedGroups, expect: { matches } });
  };
  const pick = (indices) => indices.map((n) => g.groups[n - 1]);
  const swapCase = (s) => {
    const i = [...s].findIndex((c) => /[a-zA-Z]/.test(c));
    const c = s[i];
    return s.slice(0, i) + (c === c.toLowerCase() ? c.toUpperCase() : c.toLowerCase()) + s.slice(i + 1);
  };
  const withLetter = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10].find((n) => /[a-zA-Z]/.test(g.groups[n - 1]));
  check('"Type groups 2, 7 and 10": the three groups, exactly', [2, 7, 10], pick([2, 7, 10]), true);
  check('the first, the second and the last group; group 11 has three characters', [1, 2, 11], pick([1, 2, 11]), true);
  check('the groups are asked in the order drawn, not sorted', [10, 2, 7], pick([10, 2, 7]), true);
  check('one group wrong', [2, 7, 10], [g.groups[1], g.groups[6], g.groups[8]], false);
  check('the right groups in the wrong boxes', [2, 7, 10], pick([7, 2, 10]), false);
  check('case-sensitive: one letter in the other case', [withLetter, 7 === withLetter ? 8 : 7, 11], [swapCase(g.groups[withLetter - 1]), g.groups[(7 === withLetter ? 8 : 7) - 1], g.groups[10]], false);
  check('group 11 typed with a fourth character', [1, 2, 11], [g.groups[0], g.groups[1], g.groups[10] + 'A'], false);
  check('only two groups typed', [2, 7, 10], pick([2, 7]), false);
  const spaced = (s) => s.slice(0, 2) + ' ' + s.slice(2);
  check('a space inside a typed group: space, CR and LF anywhere in a typed group are ignored', [2, 7, 10], [spaced(g.groups[1]), g.groups[6], g.groups[9]], true);
  check('a space before and after a typed group', [2, 7, 10], [' ' + g.groups[1] + ' ', g.groups[6], g.groups[9]], true);
  check('a typed group that ends with CR LF', [2, 7, 10], [g.groups[1], g.groups[6] + '\r\n', g.groups[9]], true);
  check('a tab inside a typed group: a tab is not ignored', [2, 7, 10], [g.groups[1].slice(0, 2) + '\t' + g.groups[1].slice(2), g.groups[6], g.groups[9]], false);
  check('a space inside a typed group that is wrong anyway', [2, 7, 10], [spaced(g.groups[2]), g.groups[6], g.groups[9]], false);
  const choice = [
    { why: 'three distinct numbers in 1..11', groups: [2, 7, 10], valid: true },
    { why: 'the lowest and the highest', groups: [1, 6, 11], valid: true },
    { why: 'a number drawn twice', groups: [2, 2, 7], valid: false },
    { why: 'group 0 does not exist', groups: [0, 5, 6], valid: false },
    { why: 'group 12 does not exist', groups: [1, 11, 12], valid: false },
    { why: 'only two numbers', groups: [3, 4], valid: false },
    { why: 'four numbers', groups: [1, 2, 3, 4], valid: false },
  ];
  for (const row of choice) if (validGroupChoice(row.groups) !== row.valid) throw new Error('recoverykit choice fixture: ' + row.why);

  // ---- the kit QR text ----
  const good = composeKit({ origin: X, card0Hash: CARD0, email: EMAIL, secret });
  const longOrigin = 'https://' + ['a'.repeat(63), 'b'.repeat(63), 'c'.repeat(63), 'd'.repeat(61)].join('.') + ':65535';
  const longEmail = 'a'.repeat(64) + '@' + ('b'.repeat(61) + '.').repeat(3) + 'ccc';
  const longest = composeKit({ origin: longOrigin, card0Hash: CARD0, email: longEmail, secret });
  const compose = [
    { why: 'a kit for a self-hosted instance', origin: X, card0Hash: CARD0, email: EMAIL, secretB64: g.text, text: good },
    { why: 'a kit for the public instance', origin: 'https://vault.andvaripass.com', card0Hash: CARD0, email: EMAIL, secretB64: g.text, text: composeKit({ origin: 'https://vault.andvaripass.com', card0Hash: CARD0, email: EMAIL, secret }) },
    { why: `the longest kit the grammars allow: a 253-character host with port 65535 and a 254-octet address give ${longest.length} characters, under the cap of ${KIT_MAX_LENGTH}`, origin: longOrigin, card0Hash: CARD0, email: longEmail, secretB64: g.text, text: longest },
  ];

  const parse = [];
  const O = b64u(utf8(X));
  const E = b64u(utf8(EMAIL));
  const S = g.text;
  const kit = (o, c, e, s, head = 'andvari-kit:2') => `${head}:${o}:${c}:${e}:${s}`;
  const pOk = (why, input, origin = X, email = EMAIL) => {
    const got = parseKit(input);
    if (got === null || got.origin !== origin || got.card0Hash !== CARD0 || got.email !== email || b64u(got.secret) !== S) throw new Error('recoverykit parse fixture should parse: ' + why);
    parse.push({ why, input, expect: { valid: true, verdict: 'ok', origin, card0Hash: CARD0, email, secretB64: S } });
  };
  const pNo = (why, input) => {
    if (parseKit(input) !== null) throw new Error('recoverykit parse fixture should be refused: ' + why);
    parse.push({ why, input, expect: { valid: false, verdict: 'bad_kit' } });
  };
  pOk('the kit text as composed', good);
  pOk('the longest kit', longest, longOrigin, longEmail);
  pOk('spaces at both ends and a line feed inside: white space is removed first, as for links', ' ' + good.slice(0, 50) + '\n' + good.slice(50) + ' ');
  pOk('CR LF and a tab inside', good.slice(0, 30) + '\r\n' + good.slice(30, 70) + '\t' + good.slice(70));
  pNo('empty', '');
  pNo('the prefix in uppercase', kit(O, CARD0, E, S, 'ANDVARI-KIT:2'));
  pNo('another scheme word', kit(O, CARD0, E, S, 'andvari-key:2'));
  pNo('version 1', kit(O, CARD0, E, S, 'andvari-kit:1'));
  pNo('version 3', kit(O, CARD0, E, S, 'andvari-kit:3'));
  pNo('no version', `andvari-kit:${O}:${CARD0}:${E}:${S}`);
  pNo('five fields: no secret', `andvari-kit:2:${O}:${CARD0}:${E}`);
  pNo('seven fields', good + ':x');
  pNo('written as a URL', good.replace('andvari-kit:', 'andvari-kit://'));
  pNo('O is padded', kit(O + '=', CARD0, E, S));
  pNo('O carries stray bits', kit(O.slice(0, -1) + 'B', CARD0, E, S));
  pNo('O is the origin itself, not its base64url', kit(X, CARD0, E, S));
  pNo('O decodes to an origin with a path', kit(b64u(utf8(X + '/')), CARD0, E, S));
  pNo('O decodes to a plain-http LAN address', kit(b64u(utf8('http://192.168.1.10')), CARD0, E, S));
  pNo('card0Hash in uppercase hex', kit(O, CARD0.toUpperCase(), E, S));
  pNo('card0Hash of 63 hex characters', kit(O, CARD0.slice(1), E, S));
  pNo('card0Hash of 65 hex characters', kit(O, CARD0 + '0', E, S));
  pNo('card0Hash as base64url', kit(O, b64u(mustUnb64u(b64u(new Uint8Array(32).fill(0x5c)))), E, S));
  pNo('card0Hash is "none"', kit(O, 'none', E, S));
  pNo('E is padded', kit(O, CARD0, E + '=', S));
  pNo('E is the address itself, not its base64url', kit(O, CARD0, EMAIL, S));
  pNo('E decodes to an address with an uppercase letter: not an emailNorm', kit(O, CARD0, b64u(utf8('Alice@example.com')), S));
  pNo('E decodes to an address with a space after it', kit(O, CARD0, b64u(utf8('alice@example.com ')), S));
  pNo('E decodes to an address with no @', kit(O, CARD0, b64u(utf8('alice.example.com')), S));
  pNo('E decodes to a non-ASCII address', kit(O, CARD0, b64u(utf8(cp(0xe4) + 'lice@example.com')), S));
  pNo('E is empty', kit(O, CARD0, '', S));
  pNo('S is padded', kit(O, CARD0, E, S + '='));
  pNo('S is 31 bytes', kit(O, CARD0, E, b64u(secret.slice(0, 31))));
  pNo('S is 33 bytes', kit(O, CARD0, E, b64u(new Uint8Array(33).fill(7))));
  pNo('S carries stray bits', kit(O, CARD0, E, S.slice(0, 42) + (S[42] === 'B' ? 'C' : 'B')));
  pNo('S in the standard alphabet', kit(O, CARD0, E, S.replaceAll('-', '+').replaceAll('_', '/')));
  pNo('S as the grouped display, with dashes between the groups', kit(O, CARD0, E, g.groups.join('-')));
  pNo('an invite link is not a kit', `https://andvaripass.com/l#v2.${O}.${S}.-`);
  pNo('a form feed inside: it is not white space, so it is not removed and the text is malformed', good.slice(0, 50) + cp(0x0c) + good.slice(50));
  pNo('a vertical tab at the end', good + cp(0x0b));
  pNo('a NO-BREAK SPACE inside', good.slice(0, 50) + cp(0xa0) + good.slice(50));
  // Fourth batch (spec 01 §5.5): E must decode to an emailNorm, and an address of the right bytes,
  // case and @ count that is not a dot-atom at a host has none.
  pNo('E decodes to a display-name form, alice<alice@example.com>: lower case, one @, printable ASCII, but not a dot-atom local part, so not an emailNorm', kit(O, CARD0, b64u(utf8('alice<alice@example.com>')), S));

  return {
    _about: [
      'The recovery kit of design 2026-11-15-onboarding-trust §10.',
      'Hand-authored from the independent oracle in tools/vector-gen/oracle (no andvari code). Regenerate with `npm run generate` there; `npm run check` fails on any difference.',
      'grouping: the 32-byte secret as unpadded base64url, 43 characters, in 11 groups (ten of 4, one of 3); `display` joins them with single spaces.',
      'typedSecret: a secret typed by hand. Spaces, CR and LF are ignored and nothing else is: not a tab, and not a dash, because base64url uses "-" (FI-B10). What is left must be the canonical base64url of 32 bytes. expect.valid, with the secret when it parses.',
      'confirm: the type-back. `groups` are three group numbers (1..11) and `typed` what the person entered for them, in that order; expect.matches is an exact, case-sensitive comparison once space, CR and LF anywhere in each typed group are ignored (a tab is not ignored). groupChoice: a valid challenge is three DISTINCT numbers in 1..11.',
      'qr.compose: andvari-kit:2:<O>:<C>:<E>:<S>, O = unpadded base64url of the origin, C = card0Hash as 64 lowercase hex, E = unpadded base64url of emailNorm, S = unpadded base64url of the secret. It is deliberately not a URL.',
      'qr.parse: total and canonical, as for links (§6.1): white space (space, tab, CR and LF, and nothing else: a form feed or a vertical tab stays and makes the text malformed) is removed first; exactly six colon-separated fields; the literal prefix andvari-kit and version 2; O canonical base64url of an origin of §2.2; C 64 lowercase hex; E canonical base64url of an address that is its own emailNorm; S canonical base64url of 32 bytes; at most 1024 characters. expect.verdict is ok, with the four values, or bad_kit, the verdict §2.4 names for a kit text that does not parse; expect.valid says the same as a boolean.',
      'The cap of 1024 characters cannot be exercised on its own: the longest text the grammars allow is shorter, so anything longer already has a field that fails.',
      'The extension handles no kits and grades none of these rows (§17).',
      'Changed on 2026-11-15, fourth batch, with the dot-atom and domain rule of emailNorm (spec 01 §5.5): one qr.parse row is new, at the end: E decodes to alice<alice@example.com>, refused (bad_kit). Every address the file already carried is its own emailNorm, and no other row changed.',
    ],
    grouping,
    typedSecret: typed,
    confirm,
    groupChoice: choice,
    qr: { maxLength: KIT_MAX_LENGTH, compose, parse },
  };
}

export function grade(doc) {
  const failures = [];
  let rows = 0;
  const expect = (cond, what) => {
    rows++;
    if (!cond) failures.push(what);
  };
  for (const row of doc.grouping) {
    const r = groupSecret(mustUnb64u(row.secretB64));
    expect(r.text === row.secretB64 && JSON.stringify(r.groups) === JSON.stringify(row.groups) && r.display === row.display && row.groups.length === 11, 'grouping: ' + row.why);
  }
  for (const row of doc.typedSecret) {
    const got = parseTypedSecret(row.input);
    expect(row.expect.valid ? got !== null && b64u(got) === row.expect.secretB64 : got === null, 'typedSecret: ' + row.why);
  }
  for (const row of doc.confirm) expect(confirmGroups(mustUnb64u(row.secretB64), row.groups, row.typed) === row.expect.matches, 'confirm: ' + row.why);
  for (const row of doc.groupChoice) expect(validGroupChoice(row.groups) === row.valid, 'groupChoice: ' + row.why);
  for (const row of doc.qr.compose) expect(composeKit({ origin: row.origin, card0Hash: row.card0Hash, email: row.email, secret: mustUnb64u(row.secretB64) }) === row.text && row.text.length <= doc.qr.maxLength, 'qr compose: ' + row.why);
  for (const row of doc.qr.parse) {
    const got = parseKit(row.input);
    const ok = row.expect.valid
      ? got !== null && got.origin === row.expect.origin && got.card0Hash === row.expect.card0Hash && got.email === row.expect.email && b64u(got.secret) === row.expect.secretB64
      : got === null;
    expect(ok && row.expect.verdict === (got === null ? 'bad_kit' : 'ok'), 'qr parse: ' + row.why);
  }
  return { rows, failures };
}
