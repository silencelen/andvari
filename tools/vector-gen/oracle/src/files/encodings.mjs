// encodings.json: the §2.3 encoding rules that are grammars of their own (emailNorm, the platform
// enum, proof-of-work bit order) and the two §2.2 types every client must agree on outside a
// statement as well (name, origin).

import { b64u, utf8, hex, unhex, unb64u } from '../bytes.mjs';
import { sha256 } from '../prims.mjs';
import { findNonce } from '../powsearch.mjs';
import { emailNorm, isPlatform, PLATFORMS, leadingZeroBits, isName, isOrigin, isNameForbiddenCodePoint } from '../grammar.mjs';

const cp = (...codes) => String.fromCodePoint(...codes);
const BS = String.fromCharCode(92); // a backslash, spelled so that a fixture can hold one
const U = (code) => 'U+' + code.toString(16).toUpperCase().padStart(4, '0');

function emailRows() {
  const rows = [];
  const ok = (input, expected, why) => rows.push({ why, input, expect: { verdict: 'ok', emailNorm: expected } });
  const no = (input, why) => rows.push({ why, input, expect: { verdict: 'invalid_email' } });

  ok('alice@example.com', 'alice@example.com', 'already normal');
  ok('Alice@Example.COM', 'alice@example.com', 'ASCII A-Z are lowercased, in the local part too');
  ok('  alice@example.com  ', 'alice@example.com', 'spaces stripped from both ends');
  ok('\talice@example.com\r\n', 'alice@example.com', 'tab, CR and LF stripped from both ends');
  ok(' \t\r\nAlice@Example.com\n\r\t ', 'alice@example.com', 'a mix of the four white-space characters, then lowercasing');
  no('a@b', 'a one-label domain: 3 octets, one @, two non-empty parts, but the domain must be two or more labels under the origin host grammar (spec 01 §5.5; this row was ok before that rule)');
  ok('user+tag@example.com', 'user+tag@example.com', 'printable ASCII punctuation is left alone');
  ok('a!~b@example.com', 'a!~b@example.com', 'the lowest and the highest allowed bytes, 0x21 and 0x7E');
  const local64 = 'a'.repeat(64);
  const domain189 = ('b'.repeat(61) + '.').repeat(3) + 'ccc';
  ok(local64 + '@' + domain189, local64 + '@' + domain189, 'exactly 254 octets');
  ok('  ' + local64.toUpperCase() + '@' + domain189 + '\r\n', local64 + '@' + domain189,
    '254 octets once the white space at both ends is stripped: the length is taken after the strip');

  no(local64 + '@' + domain189 + 'c', '255 octets');
  no('', 'empty');
  no('   ', 'only white space');
  no('alice', 'no @');
  no('@', 'both parts empty');
  no('@example.com', 'empty local part');
  no('alice@', 'empty domain part');
  no('alice@@example.com', 'two @');
  no('a@b@c', 'two @');
  no('alice smith@example.com', 'a space inside the local part: after the strip every byte must be 0x21-0x7E (VR-6)');
  no('alice@exam ple.com', 'a space inside the domain part');
  no(cp(0xe4) + 'lice@example.com', 'non-ASCII in the local part (' + U(0xe4) + ')');
  no('alice@ex' + cp(0xe4) + 'mple.com', 'non-ASCII in the domain: no IDN conversion is applied');
  no('alice@' + cp(0x212a) + 'elvin.example', 'KELVIN SIGN ' + U(0x212a) + ': refused, never case-folded to k');
  no(cp(0x130) + 'stanbul@example.com', 'LATIN CAPITAL LETTER I WITH DOT ABOVE ' + U(0x130) + ': refused, no locale lowercasing');
  no('alice' + cp(0xff20) + 'example.com', 'FULLWIDTH COMMERCIAL AT ' + U(0xff20) + ' is not an @');
  no('ali' + cp(0x00) + 'ce@example.com', 'NUL inside');
  no('ali\tce@example.com', 'a tab inside is a control character (only the ends are stripped)');
  no('alice@exam\nple.com', 'a line feed inside');
  no('ali' + cp(0x1f) + 'ce@example.com', U(0x1f) + ' inside');
  no('ali' + cp(0x7f) + 'ce@example.com', 'DEL ' + U(0x7f) + ' is a control character');
  no(cp(0x0b) + 'alice@example.com', 'a leading vertical tab is not one of the four stripped characters, and is a control character');
  no('alice@example.com' + cp(0x0c), 'a trailing form feed is not stripped');
  no(cp(0xa0) + 'alice@example.com', 'a leading NO-BREAK SPACE is not ASCII white space');
  no('alice@example.com' + cp(0x3000), 'a trailing IDEOGRAPHIC SPACE is not ASCII white space');
  no(cp(0xfeff) + 'alice@example.com', 'a leading byte-order mark');

  // ---- Fourth batch (spec 01 §5.5): local@domain, with `local` a dot-atom of 1..64
  //      characters and `domain` two or more labels under the origin type's host grammar ----
  const D4 = 'dot-atom rule (spec 01 §5.5): ';
  // The accepted forms the server's fix listed.
  ok('user@example.com', 'user@example.com', D4 + 'a plain address');
  ok('  User@Example.COM \t', 'user@example.com', D4 + 'white space at both ends stripped, then A-Z lowercased in both parts');
  ok('first.last@example.com', 'first.last@example.com', D4 + 'one dot between two non-empty parts of the local part');
  ok('a+tag@sub.example.co.uk', 'a+tag@sub.example.co.uk', D4 + 'a plus tag, and a domain of four labels');
  ok('o\'brien@example.com', 'o\'brien@example.com', D4 + 'an apostrophe is in the dot-atom set');
  ok('x_y-z@ex-ample.com', 'x_y-z@ex-ample.com', D4 + 'underscore and hyphen in the local part; a hyphen inside a domain label');
  const PUNCT = '!#$%&\'*+/=?^_`{|}~-';
  ok(PUNCT + '@example.com', PUNCT + '@example.com', D4 + 'every punctuation character of the dot-atom set at once');
  // Boundaries.
  ok('a'.repeat(64) + '@example.com', 'a'.repeat(64) + '@example.com', D4 + 'a local part of 64 characters, the most allowed');
  for (const ch of PUNCT) ok(ch + '@example.com', ch + '@example.com', D4 + 'the punctuation character ' + ch + ' (' + U(ch.codePointAt(0)) + ') alone as the local part');
  ok('0123456789@example.com', '0123456789@example.com', D4 + 'a local part of digits only');
  ok('First.Last@Example.Com', 'first.last@example.com', D4 + 'upper case in a dotted local part and in the domain, lowercased first');
  ok('a@b.c', 'a@b.c', D4 + 'the shortest address now: 5 octets, a one-character local part at two one-character labels');
  ok('user@' + 'a'.repeat(63) + '.com', 'user@' + 'a'.repeat(63) + '.com', D4 + 'a domain label of 63 characters, the most the host grammar allows');
  ok('user@xn--bcher-kva.example', 'user@xn--bcher-kva.example', D4 + 'an xn-- label is an ordinary label: taken as it is, never decoded');
  ok('user@123.example.com', 'user@123.example.com', D4 + 'a label of digits is allowed anywhere but last');
  ok('user@example.c0m', 'user@example.c0m', D4 + 'a last label with a digit that is not all digits');
  ok('user@a-b.example', 'user@a-b.example', D4 + 'a hyphen inside a label');
  const host252 = ('b'.repeat(61) + '.').repeat(4) + 'cccc'; // 4 x 62 + 4
  const host253 = host252 + 'c';
  if (host252.length !== 252 || host253.length !== 253 || ('a@' + host252).length !== 254) throw new Error('encodings: long-domain fixtures');
  ok('a@' + host252, 'a@' + host252, D4 + 'a domain of 252 characters behind a one-character local part: 254 octets in all, accepted');
  no('a@' + host253, D4 + 'a domain of 253 characters (the most the origin host grammar allows) behind a one-character local part is 255 octets: the 254-octet limit refuses it, so no address can carry a 253-character domain');

  // The refused forms a mail library would rewrite to another mailbox.
  no('x<user@example.com>', D4 + 'a display name glued to an angle-bracketed address (no space, lower case, one @: only the dot-atom rule refuses it)');
  no('<user@example.com>', D4 + 'an address in angle brackets');
  no('user@example.com(x)', D4 + 'a comment after the domain');
  no('(x)user@example.com', D4 + 'a comment before the local part');
  no('user(x)@example.com', D4 + 'a comment inside the local part');
  no('"user"@example.com', D4 + 'a quoted local part');
  no('"a.b"@example.com', D4 + 'a quoted local part holding a dot-atom');
  no('a"b@example.com', D4 + 'a quote inside the local part');
  no('alice<alice@example.com>', D4 + 'a display-name form without a space');
  no('"alice"<alice@example.com>', D4 + 'a quoted display name');
  no('Alice <alice@example.com>', D4 + 'a display name with a space (refused by the byte range already)');
  no('team:user@example.com;', D4 + 'a group: a name, a colon, a member, a semicolon');
  no('team:;', D4 + 'an empty group (no @ at all)');
  no('user@example.com,other@example.com', D4 + 'two addresses joined by a comma');
  no('user@example.com;other@example.com', D4 + 'two addresses joined by a semicolon');
  no('user.@example.com', D4 + 'a trailing dot in the local part');
  no('us..er@example.com', D4 + 'two dots in a row in the local part');
  no('.user@example.com', D4 + 'a leading dot in the local part');
  no('.@example.com', D4 + 'a local part that is a dot alone');
  no('a'.repeat(65) + '@example.com', D4 + 'a local part of 65 characters, one over the limit');
  no('user@example', D4 + 'a one-label domain');
  no('user@localhost', D4 + 'localhost is one label: the origin type allows it only as plain http, never as an address domain');
  no('user@-example.com', D4 + 'a domain label that starts with a hyphen');
  no('user@example-.com', D4 + 'a domain label that ends with a hyphen');
  no('user@example.com-', D4 + 'a last label that ends with a hyphen');
  no('user@example..com', D4 + 'an empty label inside the domain');
  no('user@.example.com', D4 + 'an empty first label');
  no('user@example.com.', D4 + 'a trailing dot on the domain (the host grammar has no trailing dot)');
  no('user@' + 'a'.repeat(64) + '.com', D4 + 'a domain label of 64 characters, one over the host grammar\'s 63');
  no('user@ex_ample.com', D4 + 'an underscore in a domain label');
  no('user@example.com:443', D4 + 'a port after the domain');
  no('user@example.123', D4 + 'a last label of digits only (the host grammar reads it as an IPv4 address)');
  no('user@1.2.3.4', D4 + 'a dotted IPv4 address as the domain');
  no('user@127.0.0.1', D4 + 'the loopback address: the origin type allows it only as plain http, never as an address domain');
  no('user@example.0x1f', D4 + 'a last label of 0x and hex digits');
  no('user@example.0x', D4 + 'a last label that is exactly 0x');
  no('user@[192.168.0.1]', D4 + 'an IPv4 address literal in brackets');
  no('user@[ipv6:2001:db8::1]', D4 + 'an IPv6 address literal');
  no('a' + BS + 'b@example.com', D4 + 'a backslash in the local part');
  for (const ch of '(),:;<>[]') no('a' + ch + 'b@example.com', D4 + 'the special ' + ch + ' (' + U(ch.codePointAt(0)) + ') inside the local part: not in the dot-atom set');
  no('user@exam' + cp(0xe4) + 'ple.com', D4 + 'a non-ASCII letter in the domain');
  no('us' + cp(0xc4) + 'er@example.com', D4 + 'an upper-case non-ASCII letter (' + U(0xc4) + ') in the local part: refused, never lowercased');
  no('user@example.com' + cp(0xa0), D4 + 'a trailing NO-BREAK SPACE is not stripped');
  no('user@example.com\r\n' + cp(0xa0), D4 + 'CR LF then a NO-BREAK SPACE at the end: the strip stops at the no-break space, which stays');
  no('user@exa mple.com', D4 + 'a space inside the domain');
  no('user@example.com' + cp(0x0b), D4 + 'a trailing vertical tab: ASCII white space in some libraries, but not one of the four stripped');
  return rows;
}

function platformRows() {
  const rows = PLATFORMS.map((value) => ({ value, valid: true }));
  for (const value of ['Android', 'iOS', 'IOS', 'Windows', 'mac', 'osx', 'win', 'desktop', 'chrome', 'safari', 'ipados', '', 'web ', ' web', 'cli\n']) {
    rows.push({ value, valid: false });
  }
  return rows;
}

function powBitRows() {
  const rows = [];
  const row = (headHex, bits, why) => rows.push({ why, digestHex: headHex.padEnd(64, headHex.length ? 'f' : '0').slice(0, 64), leadingZeroBits: bits });
  const zero = (headHex, bits, why) => rows.push({ why, digestHex: headHex.padEnd(64, '0'), leadingZeroBits: bits });
  row('ff', 0, 'top bit of byte 0 set');
  row('80', 0, 'only the top bit of byte 0 set in that byte');
  row('7f', 1, 'one zero bit');
  row('40', 1, 'one zero bit');
  row('3f', 2, 'two zero bits');
  row('01', 7, 'seven zero bits, then the lowest bit of byte 0');
  row('0080', 8, 'byte 0 is zero, the top bit of byte 1 is set');
  row('00ff', 8, 'byte 0 is zero');
  row('007f', 9, 'nine');
  row('0001', 15, 'fifteen');
  row('000080', 16, 'two zero bytes');
  row('00000f', 20, 'two zero bytes and a zero high nibble');
  row('000010', 19, 'nineteen');
  row('000008', 20, 'twenty');
  row('000007', 21, 'twenty-one');
  zero('0100', 7, 'a least-significant-bit-first count of byte 0 would say 0; a little-endian word count would say more');
  zero('0000f0', 16, 'bits are counted from the most significant end of each byte: f0 has none, not four');
  zero('00000000000000000001', 79, 'nine zero bytes, then 0x01');
  zero('', 256, 'an all-zero digest');
  return rows;
}

function powInputRows() {
  // The nonces come from a plain search for the smallest one that reaches a target (powsearch.mjs).
  const find = (email, date, bits) => findNonce(email, date, bits);
  const rows = [];
  const add = (why, email, date, nonce) => {
    const input = 'andvari/v2|signup-pow|' + email + '|' + date + '|' + String(nonce);
    const digest = sha256(input);
    rows.push({ why, emailNorm: email, utcDate: date, nonce, inputUtf8: input, digestHex: hex(digest), leadingZeroBits: leadingZeroBits(digest) });
  };
  const email = 'alice@example.com';
  const date = '2026-11-15';
  add('nonce 0 is written as the single digit 0', email, date, 0);
  add('the smallest nonce reaching 8 bits', email, date, find(email, date, 8));
  add('the smallest nonce reaching 20 bits', email, date, find(email, date, 20));
  add('the largest nonce, 2^53 - 1, in plain decimal', email, date, 2 ** 53 - 1);
  add('the same nonce on another date gives another digest', email, '2026-11-14', find(email, date, 8));
  return rows;
}

export function nameRows() {
  const rows = [];
  const text = (s) => utf8(s);
  const fromBytes = (bytes, valid, why) => rows.push({ why, name: b64u(bytes), textHex: hex(bytes), valid });
  const ok = (s, why) => fromBytes(text(s), true, why);
  const no = (s, why) => fromBytes(text(s), false, why);
  const raw = (name, why) => rows.push({ why, name, valid: false });

  ok('Alice', 'plain ASCII');
  ok('A', 'one byte, the minimum');
  ok('a'.repeat(64), '64 bytes, the maximum');
  ok('Alice B', 'a space inside');
  ok('Zo' + cp(0xeb), 'a two-byte character');
  ok(cp(0x674e, 0x5c0f, 0x9f8d), 'three-byte characters');
  ok(cp(0x1f600), 'a four-byte character');
  ok(cp(0x1f600).repeat(16), 'sixteen four-byte characters: exactly 64 bytes');
  ok(cp(0xe9), 'e-acute precomposed (' + U(0xe9) + ')');
  ok('e' + cp(0x301), 'e + COMBINING ACUTE ACCENT: kept as written, no normalisation, so a different name from the row above');
  ok(cp(0xa0) + 'Alice', 'a leading NO-BREAK SPACE ' + U(0xa0) + ' is not U+0020 and is not on the list');
  ok('~', U(0x7e) + ', the last code point before the U+007F-U+009F range');
  for (const [code, note] of [
    [0xa0, 'the first code point after U+009F'],
    [0xac, 'the code point before U+00AD'],
    [0xae, 'the code point after U+00AD'],
    [0x61b, 'the code point before U+061C'],
    [0x61d, 'the code point after U+061C'],
    [0x180d, 'the code point before U+180E'],
    [0x180f, 'the code point after U+180E'],
    [0x200a, 'the code point before U+200B'],
    [0x2010, 'the code point after U+200F'],
    [0x2027, 'the code point before U+2028'],
    [0x202f, 'the code point after U+202E'],
    [0x205f, 'the code point before U+2060'],
    [0x2065, 'the gap between U+2064 and U+2066: not on the list'],
    [0x2070, 'the code point after U+206F'],
    [0xfefc, 'just below U+FEFF'],
    [0xff01, 'just above U+FEFF'],
    [0xfffc, 'the code point after U+FFFB'],
    [0xfffd, 'REPLACEMENT CHARACTER, genuinely present in the text: allowed'],
  ]) {
    ok('A' + cp(code) + 'B', U(code) + ' inside: ' + note);
  }

  for (const [code, note] of [
    [0x00, 'first of U+0000-U+001F'],
    [0x09, 'tab'],
    [0x0a, 'line feed'],
    [0x1f, 'last of U+0000-U+001F'],
    [0x7f, 'first of U+007F-U+009F'],
    [0x80, 'inside U+007F-U+009F'],
    [0x9f, 'last of U+007F-U+009F'],
    [0xad, 'SOFT HYPHEN'],
    [0x61c, 'ARABIC LETTER MARK'],
    [0x180e, 'MONGOLIAN VOWEL SEPARATOR'],
    [0x200b, 'first of U+200B-U+200F (ZERO WIDTH SPACE)'],
    [0x200d, 'inside U+200B-U+200F (ZERO WIDTH JOINER)'],
    [0x200f, 'last of U+200B-U+200F'],
    [0x2028, 'first of U+2028-U+202E (LINE SEPARATOR)'],
    [0x202a, 'inside U+2028-U+202E'],
    [0x202e, 'last of U+2028-U+202E (RIGHT-TO-LEFT OVERRIDE)'],
    [0x2060, 'first of U+2060-U+2064 (WORD JOINER)'],
    [0x2064, 'last of U+2060-U+2064'],
    [0x2066, 'first of U+2066-U+206F'],
    [0x2069, 'inside U+2066-U+206F'],
    [0x206f, 'last of U+2066-U+206F'],
    [0xfeff, 'ZERO WIDTH NO-BREAK SPACE (byte-order mark)'],
    [0xfff9, 'first of U+FFF9-U+FFFB'],
    [0xfffa, 'inside U+FFF9-U+FFFB'],
    [0xfffb, 'last of U+FFF9-U+FFFB'],
  ]) {
    if (!isNameForbiddenCodePoint(code)) throw new Error('fixture: ' + U(code) + ' is not forbidden');
    no('A' + cp(code) + 'B', U(code) + ' inside: ' + note);
  }
  no(cp(0x1f468, 0x200d, 0x1f469, 0x200d, 0x1f467), 'an emoji sequence joined with ZERO WIDTH JOINER: refused, U+200D is on the list');
  no(cp(0xfeff) + 'Alice', 'a leading byte-order mark is a listed code point, not something to strip');

  no(' Alice', 'a leading U+0020');
  no('Alice ', 'a trailing U+0020');
  no(' ', 'a single U+0020 is both leading and trailing');
  fromBytes(new Uint8Array(0), false, 'empty: decoded length 0');
  no('a'.repeat(65), '65 bytes');
  no(cp(0x1f600).repeat(16) + 'a', '65 bytes: sixteen four-byte characters and one more byte');

  fromBytes(unhex('c080'), false, 'not UTF-8: an overlong encoding of U+0000');
  fromBytes(unhex('e08080'), false, 'not UTF-8: a three-byte overlong');
  fromBytes(unhex('eda080'), false, 'not UTF-8: a surrogate (U+D800) encoded directly');
  fromBytes(unhex('f4908080'), false, 'not UTF-8: above U+10FFFF');
  fromBytes(unhex('80'), false, 'not UTF-8: a lone continuation byte');
  fromBytes(unhex('41c3'), false, 'not UTF-8: a truncated two-byte sequence');
  fromBytes(unhex('41ff42'), false, 'not UTF-8: the byte 0xff');

  raw('QWxpY2U=', 'padded base64url');
  raw('QQ==', 'padded base64url');
  raw('QR', 'non-canonical: the last character carries stray bits (it decodes to "A", which encodes as "QQ")');
  raw('fn5+', 'the standard alphabet: "+" where base64url has "-" ("~~~" is "fn5-")');
  raw('fn5/', 'the standard alphabet: "/"');
  raw('QWxp Y2U', 'a space inside the base64url text');
  raw('QWxpY', 'an impossible length (5 characters)');
  if (b64u(utf8('~~~')) !== 'fn5-' || !unb64u('fn5-')) throw new Error('fixture: fn5-');
  ok('~~~', 'the base64url text itself may contain "-" ("fn5-")');
  return rows;
}

export function originRows() {
  const rows = [];
  const ok = (origin, why) => rows.push({ why, origin, valid: true });
  const no = (origin, why) => rows.push({ why, origin, valid: false });

  ok('https://example.com', 'https with a two-label domain name');
  ok('https://vault.andvaripass.com', 'the public instance');
  ok('https://a.b', 'two one-character labels');
  ok('https://my-server.example.org', 'a hyphen inside a label');
  ok('https://1example.com', 'a label may start with a digit');
  ok('https://123.example.com', 'an all-digit label in a name that is not an IP literal');
  ok('https://sub.sub2.sub3.example.co.uk', 'many labels');
  ok('https://xn--bcher-kva.example', 'an internationalised name in A-label form');
  ok('https://example.com:8443', 'a port');
  ok('https://example.com:1', 'the lowest port');
  ok('https://example.com:65535', 'the highest port');
  ok('https://example.com:80', 'port 80 is not the default port of https');
  ok('https://example.com:4430', 'a port that starts with 443');
  ok('https://example.com:10443', 'a port that ends with 443');
  ok('https://' + 'a'.repeat(63) + '.example', 'a label of 63 characters, the longest allowed');
  ok('https://' + ['a'.repeat(63), 'b'.repeat(63), 'c'.repeat(63), 'd'.repeat(61)].join('.'), 'a host of 253 characters, the longest allowed');
  ok('https://xn--a.example', 'an xn-- label is an ordinary label: it is never decoded or checked as punycode');
  ok('https://xn--zzzzzzzzzz.example', 'another xn-- label no punycode decoder would accept');
  ok('https://ab--cd.example', 'hyphens in the third and fourth position of a label that is not xn--');
  ok('https://example.1a', 'a last label that starts with a digit but is not all digits');
  ok('https://example.0xzz', 'a last label that starts with 0x but is not hex digits after it');
  ok('http://localhost', 'development: plain http to localhost');
  ok('http://localhost:443', '443 is not the default port of http, so it is allowed there');
  ok('http://127.0.0.1:443', '443 after http://127.0.0.1');
  ok('http://localhost:8080', 'development: localhost with a port');
  ok('http://127.0.0.1', 'development: plain http to 127.0.0.1');
  ok('http://127.0.0.1:8080', 'development: 127.0.0.1 with a port');

  no('', 'empty');
  no('https://', 'no host');
  no('https://:8443', 'no host before the port');
  no('example.com', 'no scheme');
  no('//example.com', 'no scheme');
  no('https:/example.com', 'one slash');
  no('https:example.com', 'no slashes');
  no('ftp://example.com', 'another scheme');
  no('wss://example.com', 'another scheme');
  no('HTTPS://example.com', 'uppercase scheme');
  no('Https://example.com', 'uppercase in the scheme');
  no('https://Example.com', 'uppercase in the host');
  no('https://EXAMPLE.COM', 'uppercase host');
  no('https://localhost', 'a single-label host under https');
  no('https://intranet', 'a single-label host');
  no('https://example.com.', 'a trailing dot');
  no('https://example..com', 'an empty label');
  no('https://.example.com', 'a leading dot');
  no('https://-example.com', 'a label starting with a hyphen');
  no('https://example-.com', 'a label ending with a hyphen');
  no('https://exa_mple.com', 'an underscore');
  no('https://exa mple.com', 'a space inside');
  no('https://*.example.com', 'a wildcard');
  no('https://b' + cp(0xfc) + 'cher.example', 'an internationalised name in U-label form (' + U(0xfc) + ')');
  no('https://' + 'a'.repeat(64) + '.example', 'a label of 64 characters');
  no('https://' + ['a'.repeat(63), 'b'.repeat(63), 'c'.repeat(63), 'd'.repeat(62)].join('.'), 'a host of 254 characters, every label within 63');
  no('https://1.2.3', 'the last label is all digits: URL parsers read such a host as an IPv4 address');
  no('https://999.1.1.1', 'the last label is all digits, though no octet range fits');
  no('https://example.123', 'a name whose last label is all digits');
  no('https://example.0x1f', 'the last label is 0x followed only by hex digits');
  no('https://example.0x', 'the last label is exactly 0x, with no hex digit after it: URL parsers read it as 0');
  no('https://0x7f.0.0.1', 'a hexadecimal first part and an all-digit last label');
  no('https://192.168.1.10', 'an IPv4 literal');
  no('https://127.0.0.1', 'an IPv4 literal under https');
  no('https://10.0.0.1:8443', 'an IPv4 literal with a port');
  no('https://[::1]', 'an IPv6 literal');
  no('https://[2001:db8::1]:8443', 'an IPv6 literal with a port');
  no('https://example.com:443', 'port 443 is the default port of https and is never written');
  no('https://example.com:0', 'port 0');
  no('https://example.com:65536', 'a port above 65535');
  no('https://example.com:99999', 'a port above 65535');
  no('https://example.com:08443', 'a port with a leading zero');
  no('https://example.com:', 'an empty port');
  no('https://example.com:abc', 'a port that is not a number');
  no('https://example.com:+80', 'a signed port');
  no('https://example.com:8443:1', 'two ports');
  no('https://example.com/', 'a path (the bare slash)');
  no('https://example.com/vault', 'a path');
  no('https://example.com:8443/', 'a path after the port');
  no('https://example.com?x=1', 'a query');
  no('https://example.com#x', 'a fragment');
  no('https://example.com:8443#x', 'a fragment after the port');
  no('https://user@example.com', 'userinfo');
  no('https://user:pw@example.com', 'userinfo with a password');
  no(' https://example.com', 'a leading space');
  no('https://example.com ', 'a trailing space');
  no('https://example.com\n', 'a trailing line feed');
  no('http://example.com', 'plain http to a domain name');
  no('http://192.168.1.10', 'plain http to a LAN address');
  no('http://127.0.0.2', 'plain http to another loopback address');
  no('http://0.0.0.0', 'plain http to 0.0.0.0');
  no('http://[::1]', 'plain http to the IPv6 loopback');
  no('http://localhost.localdomain', 'plain http to another name');
  no('http://localhost.', 'localhost with a trailing dot');
  no('http://LOCALHOST', 'uppercase localhost');
  no('http://localhost/', 'localhost with a path');
  no('http://localhost:80', 'port 80 is the default port of http and is never written (VR-5)');
  no('http://127.0.0.1:80', 'port 80 after http://127.0.0.1');
  no('http://localhost:0', 'localhost with port 0');
  no('http://localhost:08080', 'localhost with a leading zero in the port');
  no('http://127.0.0.1:65536', '127.0.0.1 with a port above 65535');
  return rows;
}

export const file = 'encodings.json';

export function build() {
  return {
    _about: [
      'Encodings of design 2026-11-15-onboarding-trust §2.2 and §2.3 that every client and the server must apply the same way.',
      'Hand-authored from the independent oracle in tools/vector-gen/oracle (Node WebCrypto and @noble; no andvari code). Regenerate with `npm run generate` there; `npm run check` fails on any difference.',
      'emailNorm: `input` (the address as typed) -> expect.verdict ok with expect.emailNorm, or expect.verdict invalid_email with no emailNorm key (on the wire, 400 invalid_email). Steps in the order of spec 01 §5.5 and design §2.3: strip space, tab, CR and LF (and nothing else) from both ends; lowercase ASCII A-Z only; then refuse anything that, after the strip, is shorter than 3 or longer than 254 octets, holds a byte outside 0x21-0x7E, or is not one @ between two non-empty parts (VR-6); then the address must be local@domain, `local` 1 to 64 characters of a-z, 0-9 and !#$%&\'*+/=?^_`{|}~- with single dots between non-empty parts (a dot-atom), and `domain` a host under the origin type\'s host grammar (two or more labels of 1-63 characters [a-z0-9]([a-z0-9-]*[a-z0-9])?, no trailing dot, at most 253 characters, a last label neither all digits nor 0x plus hex digits). Every refusal is the one verdict invalid_email; no row depends on which check refuses first.',
      'platform: the closed enum of §2.3; `valid` says whether `value` is a member, compared exactly.',
      'powLeadingZeroBits: the count for a 32-byte digest, from the most significant bit of byte 0. powInput: the string that is hashed, SHA-256("andvari/v2|signup-pow|" + emailNorm + "|" + utcDate + "|" + nonce), with the nonce in decimal without leading zeros.',
      'name: `name` is the candidate value of the §2.2 `name` type (unpadded base64url text); `textHex` is the decoded bytes where the text decodes. `valid` is the whole verdict of the type: canonical base64url, 1..64 bytes, valid UTF-8, none of the listed code points, no U+0020 at either end, no normalisation.',
      'origin: `valid` says whether `origin` is in the §2.2 grammar: labels of 1-63 characters, a host of at most 253, a last label that is neither all digits nor 0x plus hex digits, never the scheme\'s default port (443 for https, 80 for http), xn-- labels taken as plain labels (VR-5). Inside a statement a refused origin is non_canonical. The same strings are refused by OriginCanon, the Trust Gate and `andvari setup`. The extension grades these rows too (§17).',
      'Changed on 2026-11-15, fourth batch, with the dot-atom and domain rule of spec 01 §5.5: emailNorm gained rows 36 onward (dot-atom local parts, domains under the origin host grammar, and the forms a mail library would rewrite to another mailbox: angle brackets, comments, quotes, display names, groups, two addresses). One existing expectation changed: row 5, input a@b, was ok and is now invalid_email (a one-label domain); its `why` says so. No other existing row changed. Core, the web twin, the CLI and the server grade every emailNorm row. Design §17 names only the origin rows of this file for the extension; an extension twin that computes emailNorm itself grades every emailNorm row too.',
    ],
    emailNorm: emailRows(),
    platform: platformRows(),
    powLeadingZeroBits: powBitRows(),
    powInput: powInputRows(),
    name: nameRows(),
    origin: originRows(),
  };
}

/** Grade the file the way a consumer would: from the parsed JSON alone. Returns a list of failures. */
export function grade(doc) {
  const failures = [];
  const expect = (cond, what) => {
    if (!cond) failures.push(what);
  };
  for (const row of doc.emailNorm) {
    const got = emailNorm(row.input);
    if (row.expect.verdict === 'invalid_email') expect(got === null && row.expect.emailNorm === undefined, 'emailNorm should refuse: ' + row.why);
    else expect(row.expect.verdict === 'ok' && got === row.expect.emailNorm, 'emailNorm: ' + row.why);
  }
  for (const row of doc.platform) expect(isPlatform(row.value) === row.valid, 'platform ' + JSON.stringify(row.value));
  for (const row of doc.powLeadingZeroBits) {
    expect(row.digestHex.length === 64 && leadingZeroBits(unhex(row.digestHex)) === row.leadingZeroBits, 'pow bits: ' + row.why);
  }
  for (const row of doc.powInput) {
    const input = 'andvari/v2|signup-pow|' + row.emailNorm + '|' + row.utcDate + '|' + String(row.nonce);
    const digest = sha256(input);
    expect(input === row.inputUtf8 && hex(digest) === row.digestHex && leadingZeroBits(digest) === row.leadingZeroBits, 'pow input: ' + row.why);
    expect(emailNorm(row.emailNorm) === row.emailNorm && /^\d{4}-\d{2}-\d{2}$/.test(row.utcDate) && Number.isSafeInteger(row.nonce), 'pow input shape: ' + row.why);
  }
  for (const row of doc.name) {
    expect(isName(row.name) === row.valid, 'name: ' + row.why);
    if (row.textHex !== undefined) expect(b64u(unhex(row.textHex)) === row.name, 'name textHex: ' + row.why);
  }
  for (const row of doc.origin) expect(isOrigin(row.origin) === row.valid, 'origin: ' + JSON.stringify(row.origin));
  return failures;
}
