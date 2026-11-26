// statement-v2.json: valid frames for purposes 0x03-0x0A, the value grammar of §2.2 inside real
// templates, the strict parse, the frame checks, and the two signer-binding forms of §2.1.

import { b64u, mustUnb64u, utf8, hex, concat } from '../bytes.mjs';
import { sha256, hkdfSha256, x25519Base } from '../prims.mjs';
import { parseStatement, describeTemplate, PURPOSE_CODES, PURPOSE_BY_CODE, LOG_KINDS, HOST_OFFER_PURPOSES, buildStatement } from '../statement.mjs';
import { parseFrame, splitFrame, signerMapsTo, signerEquals, signatureValid, frameHash, assembleFrame, DOMAIN, MIN_FRAME, MAX_FRAME } from '../frame.mjs';
import { verifyLog, vkCommit, ZERO_HASH, OFFER_MAX_MS } from '../vaultlog.mjs';
import {
  LogBuilder, signed, signedRaw, describeSigned, tokens, withToken, withoutKey, insertAfter, swapKeys, rawStatement, quote, nameOf,
} from '../build.mjs';
import { alice, bob, carol, operator, operator2, recoveryA, recoveryB, ids, fixed, T0, MINUTE, DAY, describe } from '../cast.mjs';
import { nameRows, originRows } from './encodings.mjs';

export const file = 'statement-v2.json';

const cp = (...codes) => String.fromCodePoint(...codes);
const at = (minutes) => T0 + minutes * MINUTE;

// ---- fixtures ----

function logChain() {
  const vk = fixed('statement-v2/vk');
  const id16 = (label) => b64u(fixed('statement-v2/' + label, 16));
  const log = new LogBuilder(ids.vault);
  log.append(alice, { kind: 'genesis', actor: alice.userId, at: at(0), ownerKey: alice.key, vkCommit: vkCommit(vk, ids.vault) });
  log.append(alice, { kind: 'add', actor: alice.userId, at: at(1), member: bob.userId, memberKey: bob.key, role: 'writer', grantId: id16('grant/bob') });
  log.append(alice, { kind: 'add', actor: alice.userId, at: at(2), member: carol.userId, memberKey: carol.key, role: 'reader', grantId: id16('grant/carol') });
  log.append(alice, { kind: 'role', actor: alice.userId, at: at(3), member: carol.userId, role: 'writer' });
  log.append(alice, { kind: 'offer', actor: alice.userId, at: at(4), to: bob.userId, toKey: bob.key, offerId: id16('offer/1'), expiresAt: at(4) + DAY });
  log.append(alice, { kind: 'cancel', actor: alice.userId, at: at(5), offerId: id16('offer/1') });
  log.append(alice, { kind: 'offer', actor: alice.userId, at: at(6), to: bob.userId, toKey: bob.key, offerId: id16('offer/2'), expiresAt: at(6) + OFFER_MAX_MS });
  log.append(bob, { kind: 'accept', actor: bob.userId, at: at(7), offerId: id16('offer/2') });
  log.append(bob, { kind: 'remove', actor: bob.userId, at: at(8), member: carol.userId });
  log.append(alice, { kind: 'leave', actor: alice.userId, at: at(9) });
  log.append(bob, { kind: 'delete', actor: bob.userId, at: at(10), deleteId: id16('delete/1') });
  log.append(bob, { kind: 'restore', actor: bob.userId, at: at(11), deleteId: id16('delete/1') });
  const result = verifyLog({ vaultId: ids.vault, frames: log.frames });
  if (result.verdict !== 'ok') throw new Error('statement-v2 fixture chain does not verify: ' + result.verdict);
  return log;
}

const CARD0 = {
  instanceId: ids.instance, seq: 0, prev: ZERO_HASH, origin: 'https://vault.example.org', name: nameOf('Example Vault'),
  kind: 'private', operator: operator.userId, operatorSignKey: b64u(operator.signPub), recoveryFp: 'none', issuedAt: at(0),
};

function fixtures() {
  const log = logChain();
  const card0 = signed('instance-card', operator, CARD0);
  const card1 = signed('instance-card', operator, {
    ...CARD0, seq: 1, prev: card0.hash, origin: 'https://vault.example.org:8443', recoveryFp: recoveryA.fp, issuedAt: at(60),
  });
  const cardPublic = signed('instance-card', operator, {
    instanceId: ids.otherInstance, seq: 0, prev: ZERO_HASH, origin: 'https://vault.andvaripass.com', name: nameOf('andvari'),
    kind: 'public', operator: operator.userId, operatorSignKey: b64u(operator.signPub), recoveryFp: 'none', issuedAt: at(0),
  });
  const genesis = signed('account-genesis', alice, {
    userId: alice.userId, identityKey: alice.key, instanceId: ids.instance, personalVaultId: ids.personalVault, createdAt: at(0),
  });

  // A link: every id and key below is derived from the secret as §2.3 says.
  const linkSecret = fixed('statement-v2/link-secret');
  const linkId = b64u(hkdfSha256(linkSecret, 'andvari/v2|link|id', 16));
  const nonceA = fixed('statement-v2/nonce-a');
  const commit = hex(sha256('andvari/v2|code-commit|' + b64u(nonceA)));
  const offerValues = {
    linkId, kind: 'connect', origin: CARD0.origin, instanceId: ids.instance, cardHash: card0.hash, from: alice.userId,
    fromKey: alice.key, name: nameOf('Alice'), commit, expiresAt: at(15), issuedAt: at(0),
  };
  const offerConnect = signed('link-offer', alice, offerValues);
  const offerRegister = signed('link-offer', alice, { ...offerValues, kind: 'register', expiresAt: at(0) + 3 * DAY });
  const answer = signed('link-answer', bob, {
    linkId, offerHash: offerConnect.hash, to: alice.userId, toKey: alice.key, from: bob.userId, fromKey: bob.key,
    name: nameOf('Bob'), nonce: b64u(fixed('statement-v2/nonce-b')), issuedAt: at(5),
  });

  const rotation = signed('recovery-rotation', recoveryA, {
    instanceId: ids.instance, fromFp: recoveryA.fp, toFp: recoveryB.fp, issuedAt: at(120),
  });
  const requestKey = x25519Base(fixed('statement-v2/request-secret'));
  const assisted = signed('assisted-recovery', recoveryA, {
    instanceId: ids.instance, userId: alice.userId, requestId: b64u(fixed('statement-v2/request-id', 16)),
    requestKey: b64u(requestKey), uvk: b64u(fixed('statement-v2/uvk')), issuedAt: at(200),
  });
  const veto = signed('recovery-veto', alice, {
    requestId: b64u(fixed('statement-v2/request-id', 16)), userId: alice.userId, issuedAt: at(150),
  });

  const setupOffer = buildStatement('setup-offer', {
    linkId, origin: CARD0.origin, instanceId: ids.instance, name: nameOf('Example Vault'), kind: 'private', recoveryFp: 'none', expiresAt: at(0) + DAY,
  });
  const enrolValues = {
    linkId, origin: CARD0.origin, instanceId: ids.instance, cardHash: card0.hash, email: b64u(utf8('alice@example.com')), expiresAt: at(0) + DAY,
  };

  return { log, card0, card1, cardPublic, genesis, offerConnect, offerRegister, answer, rotation, assisted, veto, setupOffer, enrolValues };
}

// ---- sections ----

function validRows(fx) {
  const rows = [];
  const x25519 = (key) => ({ form: 'x25519', keyB64: b64u(key) });
  const ed25519 = (key) => ({ form: 'ed25519', keyB64: b64u(key) });
  const add = (name, s, expectedKeys, why) => {
    const parsed = parseFrame(s.frame, s.purposeCode);
    if (parsed.verdict !== 'ok') throw new Error(`valid frame ${name} does not parse: ${parsed.verdict}`);
    for (const k of expectedKeys) {
      const binds = k.form === 'x25519' ? signerMapsTo(parsed.signerPub, mustUnb64u(k.keyB64)) : signerEquals(parsed.signerPub, mustUnb64u(k.keyB64));
      if (!binds || !signatureValid(parsed)) throw new Error(`valid frame ${name} does not verify under ${k.form}`);
    }
    rows.push({ name, why, ...describeSigned(s), signerPubB64: b64u(s.signerPub), expectedKeys });
  };

  for (const entry of fx.log.entries) {
    add('vault-log/' + entry.values.kind + (entry.values.kind === 'offer' && entry.values.seq === 6 ? '-max-lifetime' : entry.values.kind === 'add' && entry.values.seq === 2 ? '-reader' : ''),
      entry, [x25519(entry.signer.identityPub)],
      'purpose 0x03, kind ' + entry.values.kind + '; the twelve vault-log frames here form one valid chain');
  }
  add('instance-card/card-0', fx.card0, [ed25519(operator.signPub)], 'purpose 0x04: card 0 of a private instance with no operator recovery, signed by its own operatorSignKey');
  add('instance-card/card-1', fx.card1, [ed25519(operator.signPub)], 'purpose 0x04: card 1 moves the origin to a port and names a recovery key; signed by card 0\'s operatorSignKey');
  add('instance-card/public', fx.cardPublic, [ed25519(operator.signPub)], 'purpose 0x04: card 0 of a public instance');
  add('account-genesis', fx.genesis, [x25519(alice.identityPub), ed25519(alice.signPub)],
    'purpose 0x05: every client binds the signer to the Ed25519 key it derives from the identity seed, byte for byte; the server, which holds no seed, binds it to the X25519 identity key through the image (§2.4, the Signer binding row 0x05)');
  add('link-offer/connect', fx.offerConnect, [x25519(alice.identityPub)], 'purpose 0x06, kind connect');
  add('link-offer/register', fx.offerRegister, [x25519(alice.identityPub)], 'purpose 0x06, kind register');
  add('link-answer', fx.answer, [x25519(bob.identityPub)], 'purpose 0x07: offerHash is H(the connect offer frame above)');
  add('recovery-rotation', fx.rotation, [x25519(recoveryA.publicKey)], 'purpose 0x08: signed by the OUTGOING recovery seed\'s Ed25519 key; the expected key is the recovery public key that fromFp names');
  add('assisted-recovery', fx.assisted, [x25519(recoveryA.publicKey)], 'purpose 0x09: signed by the recovery-key signing key');
  add('recovery-veto', fx.veto, [x25519(alice.identityPub)], 'purpose 0x0A: signed by the account key');
  return rows;
}

/** One parse row: statement bytes checked against a template. Asserts the oracle returns `verdict`. */
function parseRow(rows, template, bytesOrText, verdict, extra) {
  const bytes = typeof bytesOrText === 'string' ? utf8(bytesOrText) : bytesOrText;
  const got = parseStatement(template, bytes).verdict;
  if (got !== verdict) throw new Error(`statement-v2 "${extra.why}": the design says ${verdict}, the oracle parser says ${got}`);
  rows.push({
    ...extra,
    template,
    purposeCode: Object.hasOwn(PURPOSE_CODES, template) ? PURPOSE_CODES[template] : null,
    statementB64: b64u(bytes),
    verdict,
  });
}

function grammarRows(fx) {
  const rows = [];
  const card = tokens('instance-card', CARD0);
  const addValues = fx.log.entries[1].values;
  const addTokens = tokens('vault-log', addValues);
  const offerTokens = tokens('link-offer', fx.offerConnect.values);
  const enrolTokens = tokens('enrol-offer', fx.enrolValues);

  const row = (type, template, base, field, token, valid, why) =>
    parseRow(rows, template, rawStatement(withToken(base, field, token)), valid ? 'ok' : 'non_canonical', { type, field, token, valid, why });

  // int (instance-card seq)
  for (const [token, valid, why] of [
    ['0', true, 'zero'],
    ['1', true, 'one'],
    ['7', true, 'a small integer'],
    ['9007199254740991', true, '2^53 - 1, the largest int'],
    ['9007199254740992', false, '2^53'],
    ['9007199254740993', false, '2^53 + 1, which a double rounds to 2^53'],
    ['18446744073709551616', false, '2^64'],
    ['01', false, 'a leading zero'],
    ['00', false, 'two zeros'],
    ['-1', false, 'negative'],
    ['-0', false, 'negative zero'],
    ['+1', false, 'a plus sign'],
    ['1.0', false, 'a fraction'],
    ['1e3', false, 'exponent form'],
    ['0x10', false, 'hexadecimal'],
    ['"1"', false, 'a string'],
    ['null', false, 'null'],
    ['true', false, 'a boolean'],
    ['', false, 'no value at all'],
  ]) row('int', 'instance-card', card, 'seq', token, valid, why);

  // ms (instance-card issuedAt): the inherited type, repeated on a template the extension parses
  for (const [token, valid, why] of [
    ['1', true, 'the smallest ms'],
    ['9007199254740991', true, '2^53 - 1, the largest ms'],
    ['0', false, 'zero is not an ms'],
    ['9007199254740992', false, '2^53'],
    ['01763164800000', false, 'a leading zero'],
    ['"1763164800000"', false, 'a string'],
    ['1763164800000.0', false, 'a fraction'],
    ['1.7631648e12', false, 'exponent form'],
    ['-1763164800000', false, 'negative'],
  ]) row('ms', 'instance-card', card, 'issuedAt', token, valid, why);

  // hex64n (instance-card recoveryFp)
  const fp = recoveryA.fp;
  for (const [token, valid, why] of [
    [quote('none'), true, 'the literal none'],
    [quote(fp), true, '64 lowercase hex'],
    [quote('None'), false, 'the literal is lowercase'],
    [quote('NONE'), false, 'uppercase'],
    [quote(''), false, 'empty'],
    [quote('null'), false, 'the word null'],
    ['null', false, 'JSON null'],
    [quote(fp.toUpperCase()), false, 'uppercase hex'],
    [quote(fp.slice(1)), false, '63 hex'],
    [quote(fp + '0'), false, '65 hex'],
    [quote('g' + fp.slice(1)), false, 'a character that is not hex'],
    [quote('0x' + fp.slice(2)), false, 'a 0x prefix'],
    [quote('none '), false, 'none with a trailing space'],
  ]) row('hex64n', 'instance-card', card, 'recoveryFp', token, valid, why);

  // hex64 (instance-card prev), inherited
  for (const [token, valid, why] of [
    [quote(fp), true, '64 lowercase hex'],
    [quote(fp.toUpperCase()), false, 'uppercase'],
    [quote(fp.slice(1)), false, '63 hex'],
    [quote(fp + '0'), false, '65 hex'],
    [quote('none'), false, 'none is allowed only where the type is hex64n'],
  ]) row('hex64', 'instance-card', card, 'prev', token, valid, why);

  // uuid (instance-card instanceId), inherited
  for (const [token, valid, why] of [
    [quote(ids.instance.toUpperCase()), false, 'uppercase'],
    [quote(ids.instance.replaceAll('-', '')), false, 'no dashes'],
    [quote(ids.instance.slice(0, 35)), false, 'one character short'],
    [quote('g' + ids.instance.slice(1)), false, 'a character that is not hex'],
    [quote('{' + ids.instance + '}'), false, 'braces'],
  ]) row('uuid', 'instance-card', card, 'instanceId', token, valid, why);

  // b64_32 (instance-card operatorSignKey), inherited
  const key = b64u(operator.signPub);
  const lastIndex = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'.indexOf(key[42]);
  const strayTail = key.slice(0, 42) + 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'[lastIndex | 1];
  for (const [token, valid, why] of [
    [quote(key.slice(0, 42)), false, '42 characters'],
    [quote(key + 'A'), false, '44 characters (33 bytes)'],
    [quote(key + '='), false, 'padded'],
    [quote(strayTail === key ? key.slice(0, 42) + 'B' : strayTail), false, 'stray bits in the last character'],
    [quote(b64u(new Uint8Array(32).fill(0xfb)).replaceAll('-', '+').replaceAll('_', '/')), false, 'the standard alphabet'],
    [quote(b64u(new Uint8Array(32).fill(0xfb))), true, 'a 32-byte value whose text uses "-" and "_" (grammar only: it is no curve point)'],
  ]) row('b64_32', 'instance-card', card, 'operatorSignKey', token, valid, why);

  // kind of an instance card
  for (const [token, valid, why] of [
    [quote('public'), true, 'public'],
    [quote('private'), true, 'private'],
    [quote('family'), false, 'not one of the two values'],
    [quote('Public'), false, 'case'],
    [quote(''), false, 'empty'],
  ]) row('instance-card kind', 'instance-card', card, 'kind', token, valid, why);

  // origin (instance-card origin): a subset of encodings.json's origin rows
  const originPick = new Set([
    'https://example.com', 'https://example.com:8443', 'https://xn--bcher-kva.example', 'http://localhost', 'http://localhost:8080',
    'http://127.0.0.1', 'http://127.0.0.1:8080', 'https://192.168.1.10', 'https://[::1]', 'https://localhost', 'https://Example.com',
    'HTTPS://example.com', 'https://example.com:443', 'https://example.com:08443', 'https://example.com/', 'https://example.com/vault',
    'https://example.com.', 'https://example.com?x=1', 'https://example.com#x', 'https://user@example.com', 'http://example.com',
    'http://127.0.0.2', 'http://192.168.1.10', 'https://b' + cp(0xfc) + 'cher.example', '',
    // the edges settled by VR-5
    'https://1.2.3', 'https://999.1.1.1', 'https://example.123', 'https://example.0x1f', 'https://example.0x', 'https://example.1a', 'https://example.0xzz',
    'https://' + 'a'.repeat(63) + '.example', 'https://' + 'a'.repeat(64) + '.example',
    'https://' + ['a'.repeat(63), 'b'.repeat(63), 'c'.repeat(63), 'd'.repeat(61)].join('.'),
    'https://' + ['a'.repeat(63), 'b'.repeat(63), 'c'.repeat(63), 'd'.repeat(62)].join('.'),
    'https://example.com:80', 'http://localhost:80', 'http://127.0.0.1:80', 'http://localhost:443', 'http://127.0.0.1:443',
    'https://xn--a.example', 'https://xn--zzzzzzzzzz.example', 'https://ab--cd.example',
  ]);
  const origins = originRows().filter((r) => originPick.has(r.origin));
  if (origins.length !== originPick.size) throw new Error('statement-v2: an origin pick is not in encodings.json');
  for (const r of origins) row('origin', 'instance-card', card, 'origin', quote(r.origin), r.valid, r.why);
  row('origin', 'instance-card', card, 'origin', '"https:\\/\\/vault.example.org"', false,
    'slashes written as \\/ : a JSON parser gives the right string, the re-encode compare refuses it');

  // name (instance-card name): every row of encodings.json's name table
  for (const r of nameRows()) row('name', 'instance-card', card, 'name', quote(r.name), r.valid, r.why);

  // role (vault-log add)
  for (const [token, valid, why] of [
    [quote('writer'), true, 'writer'],
    [quote('reader'), true, 'reader'],
    [quote('owner'), false, 'owner is a role in the state, never a value of the role type'],
    [quote('Writer'), false, 'case'],
    [quote('admin'), false, 'not a role'],
    [quote(''), false, 'empty'],
  ]) row('role', 'vault-log', addTokens, 'role', token, valid, why);

  // kind of a vault-log entry: an unknown kind has no template
  for (const [token, why] of [
    [quote('rename'), 'not one of the ten kinds'],
    [quote('Add'), 'case'],
    [quote(''), 'empty'],
  ]) row('vault-log kind', 'vault-log', addTokens, 'kind', token, false, why);

  // kind of a link offer
  for (const [token, valid, why] of [
    [quote('connect'), true, 'connect'],
    [quote('register'), true, 'register'],
    [quote('setup'), false, 'setup links are host-minted and never a signed offer'],
    [quote('enrol'), false, 'enrol links are host-minted and never a signed offer'],
  ]) row('link-offer kind', 'link-offer', offerTokens, 'kind', token, valid, why);

  // email_b64n (enrol-offer email; a host-minted offer has no frame and no purpose code)
  const email = (text) => quote(b64u(utf8(text)));
  const local64 = 'a'.repeat(64);
  const domain189 = ('b'.repeat(61) + '.').repeat(3) + 'ccc';
  for (const [token, valid, why] of [
    [quote('none'), true, 'the literal none: the link is not bound to an address'],
    [email('alice@example.com'), true, 'an emailNorm'],
    [email('a@b'), false, 'not an emailNorm: a one-label domain (3 bytes; the shortest emailNorm before spec 01 §5.5 required two or more labels)'],
    [email(local64 + '@' + domain189), true, 'the longest emailNorm, 254 bytes'],
    [email(local64 + '@' + domain189 + 'c'), false, '255 bytes'],
    [email('ab'), false, '2 bytes'],
    [email('Alice@example.com'), false, 'not an emailNorm: an uppercase letter'],
    [email(' alice@example.com'), false, 'not an emailNorm: a leading space'],
    [email('alice@example.com\n'), false, 'not an emailNorm: a trailing line feed'],
    [email('alice.example.com'), false, 'not an emailNorm: no @'],
    [email('a@b@c'), false, 'not an emailNorm: two @'],
    [email('ali' + cp(0) + 'ce@example.com'), false, 'not an emailNorm: a NUL'],
    [email('alice smith@example.com'), false, 'not an emailNorm: a space inside (VR-6)'],
    [email('ali' + cp(0x7f) + 'ce@example.com'), false, 'not an emailNorm: DEL'],
    [email(cp(0xe4) + 'lice@example.com'), false, 'not an emailNorm: non-ASCII'],
    [quote(b64u(utf8('alice@example.com')) + '='), false, 'padded base64url'],
    [quote('None'), false, 'the literal is lowercase'],
    [quote(''), false, 'empty'],
    [quote('alice@example.com'), false, 'the address itself, not its base64url'],
    // Fourth batch (spec 01 §5.5 dot-atom and domain rule): forms that pass the strip, the case, the
    // byte range and the one-@ test, and have no emailNorm only because of the local or domain grammar.
    [email('alice<alice@example.com>'), false, 'not an emailNorm: a display-name form with angle brackets (no space, all lower case: only the dot-atom rule refuses it)'],
    [email('"alice"@example.com'), false, 'not an emailNorm: a quoted local part'],
    [email('alice@example.com(x)'), false, 'not an emailNorm: a comment after the domain'],
    [email('alice.@example.com'), false, 'not an emailNorm: a trailing dot in the local part'],
    [email('alice@example.com.'), false, 'not an emailNorm: a trailing dot on the domain'],
    [email('a@b.c'), true, 'the shortest emailNorm, 5 bytes: one-character local part, two one-character labels'],
  ]) row('email_b64n', 'enrol-offer', enrolTokens, 'email', token, valid, why);

  return rows;
}

function strictnessRows(fx) {
  const rows = [];
  const cardText = fx.card0.statement;
  const card = tokens('instance-card', CARD0);
  const R = (template, bytesOrText, verdict, why) => parseRow(rows, template, bytesOrText, verdict, { why });

  // The whole battery on the instance card (0x04), which the extension parses too.
  R('instance-card', cardText, 'ok', 'card 0, untouched');
  R('instance-card', cardText.replace('"seq":', '"seq": '), 'non_canonical', 'white space after a colon');
  R('instance-card', cardText.replace(',"seq"', ', "seq"'), 'non_canonical', 'white space after a comma');
  R('instance-card', ' ' + cardText, 'non_canonical', 'leading white space');
  R('instance-card', cardText + ' ', 'non_canonical', 'trailing white space');
  R('instance-card', cardText + '\n', 'non_canonical', 'a trailing line feed');
  R('instance-card', cardText + '{}', 'non_canonical', 'trailing bytes after the object');
  R('instance-card', concat(utf8(cardText), Uint8Array.of(0)), 'non_canonical', 'a trailing NUL byte');
  R('instance-card', rawStatement(swapKeys(card, 'prev', 'origin')), 'non_canonical', 'key order: origin before prev');
  R('instance-card', rawStatement([card[card.length - 1], ...card.slice(0, -1)]), 'non_canonical', 'key order: the last key first');
  R('instance-card', rawStatement(swapKeys(card, 'v', 'purpose')), 'non_canonical', 'key order: purpose before v');
  R('instance-card', rawStatement(insertAfter(card, 'seq', ['seq', '1'])), 'non_canonical', 'a duplicate key with another value (a lax parser keeps the last)');
  R('instance-card', rawStatement(insertAfter(card, 'seq', ['seq', '0'])), 'non_canonical', 'a duplicate key with the same value');
  R('instance-card', rawStatement([...card, ['note', '"x"']]), 'non_canonical', 'an unknown key');
  R('instance-card', rawStatement(withoutKey(card, 'kind')), 'non_canonical', 'a missing key (no kind)');
  R('instance-card', rawStatement(withoutKey(card, 'recoveryFp')), 'non_canonical', 'a missing key (no recoveryFp): there are no optional keys');
  R('instance-card', rawStatement(withToken(card, 'operator', quote('\\u0039' + operator.userId.slice(1)))), 'non_canonical', 'an escaped character inside a string');
  R('instance-card', utf8(cardText.replace('vault.example.org', 'v' + cp(0xe4) + 'ult.example.org')), 'non_canonical', 'a non-ASCII character in the statement');
  R('instance-card', cardText.slice(1), 'non_canonical', 'not JSON');
  R('instance-card', cardText.slice(0, -1), 'non_canonical', 'the closing brace is missing');
  R('instance-card', '[' + cardText + ']', 'non_canonical', 'a JSON array, not an object');
  R('instance-card', '{}', 'non_canonical', 'an empty object');
  R('instance-card', rawStatement(withToken(card, 'name', '{"b64":' + quote(CARD0.name) + '}')), 'non_canonical', 'an object where a string belongs');
  R('instance-card', rawStatement(withToken(card, 'v', '2.0')), 'non_canonical', 'v as 2.0');
  R('instance-card', rawStatement(withToken(card, 'v', '"2"')), 'non_canonical', 'v as a string');
  R('instance-card', rawStatement(withToken(card, 'purpose', '"instance-card2"')), 'non_canonical', 'a purpose that is not a known literal');
  R('instance-card', rawStatement(withToken(card, 'purpose', '"Instance-Card"')), 'non_canonical', 'the purpose literal in another case');
  R('instance-card', rawStatement(withToken(card, 'v', '3')), 'bad_statement', 'canonical, but v is 3');
  R('instance-card', rawStatement(withToken(card, 'v', '1')), 'bad_statement', 'canonical, but v is 1');
  // v has the int type (VR-4): a value outside the type is non_canonical, an int other than 2 is bad_statement.
  R('instance-card', rawStatement(withToken(card, 'v', '0')), 'bad_statement', 'v is 0: an int, but not 2');
  R('instance-card', rawStatement(withToken(card, 'v', '22')), 'bad_statement', 'v is 22: an int, but not 2');
  R('instance-card', rawStatement(withToken(card, 'v', '9007199254740991')), 'bad_statement', 'v is 2^53 - 1: the largest int, but not 2');
  R('instance-card', rawStatement(withToken(card, 'v', '-1')), 'non_canonical', 'v is -1: not an int');
  R('instance-card', rawStatement(withToken(card, 'v', '02')), 'non_canonical', 'v is 02: a leading zero');
  R('instance-card', rawStatement(withToken(card, 'v', '2e0')), 'non_canonical', 'v is 2e0: exponent form');
  R('instance-card', rawStatement(withToken(card, 'v', '9007199254740992')), 'non_canonical', 'v is 2^53: outside the int type');
  R('instance-card', rawStatement(withToken(card, 'v', 'null')), 'non_canonical', 'v is null');
  R('instance-card', rawStatement(withToken(card, 'v', 'true')), 'non_canonical', 'v is true');
  R('instance-card', rawStatement(withToken(card, 'purpose', '"account-genesis"')), 'bad_statement', 'the card\'s key set with the literal of another purpose');
  R('instance-card', fx.genesis.statement, 'non_canonical', 'an account-genesis statement under the instance-card purpose');

  // account-genesis (0x05), which the extension parses too.
  const genesisTokens = tokens('account-genesis', fx.genesis.values);
  R('account-genesis', fx.genesis.statement, 'ok', 'the genesis, untouched');
  R('account-genesis', fx.genesis.statement.replace('"userId":', '"userId" :'), 'non_canonical', 'white space before a colon');
  R('account-genesis', rawStatement(swapKeys(genesisTokens, 'userId', 'identityKey')), 'non_canonical', 'key order: identityKey before userId');
  R('account-genesis', rawStatement(withoutKey(genesisTokens, 'personalVaultId')), 'non_canonical', 'a missing key');
  R('account-genesis', rawStatement([...genesisTokens, ['email', '"alice@example.com"']]), 'non_canonical', 'an unknown key');
  R('account-genesis', rawStatement(withToken(genesisTokens, 'instanceId', quote(ids.instance.toUpperCase()))), 'non_canonical', 'an uppercase uuid');
  R('account-genesis', rawStatement(withToken(genesisTokens, 'identityKey', quote(alice.key + '='))), 'non_canonical', 'a padded key');
  R('account-genesis', rawStatement(withToken(genesisTokens, 'createdAt', '0')), 'non_canonical', 'createdAt zero');
  R('account-genesis', rawStatement(withToken(genesisTokens, 'createdAt', quote(String(at(0))))), 'non_canonical', 'createdAt as a string');
  R('account-genesis', rawStatement(withToken(genesisTokens, 'v', '3')), 'bad_statement', 'canonical, but v is 3');
  R('account-genesis', rawStatement(withToken(genesisTokens, 'purpose', '"instance-card"')), 'bad_statement', 'the genesis key set with the literal of another purpose');
  R('account-genesis', fx.card0.statement, 'non_canonical', 'an instance-card statement under the account-genesis purpose');

  // vault-log (0x03): the key set hangs on the kind.
  const entries = Object.fromEntries(fx.log.entries.map((e) => [e.values.kind + '@' + e.values.seq, e]));
  const addT = tokens('vault-log', entries['add@1'].values);
  const leaveT = tokens('vault-log', entries['leave@9'].values);
  const removeT = tokens('vault-log', entries['remove@8'].values);
  const cancelT = tokens('vault-log', entries['cancel@5'].values);
  const genesisT = tokens('vault-log', entries['genesis@0'].values);
  R('vault-log', rawStatement(withoutKey(addT, 'grantId')), 'non_canonical', 'an add with no grantId');
  R('vault-log', rawStatement(withoutKey(addT, 'memberKey')), 'non_canonical', 'an add with no memberKey');
  R('vault-log', rawStatement([...leaveT, ['member', quote(carol.userId)]]), 'non_canonical', 'a leave with a member field: leave has no extra fields');
  R('vault-log', rawStatement([...removeT, ['role', '"reader"']]), 'non_canonical', 'a remove carrying a role');
  R('vault-log', rawStatement(cancelT.map(([k, v]) => (k === 'offerId' ? ['deleteId', v] : [k, v]))), 'non_canonical', 'a cancel with deleteId where offerId belongs');
  R('vault-log', rawStatement(withToken(genesisT, 'kind', '"add"')), 'non_canonical', 'kind add with the fields of a genesis');
  R('vault-log', rawStatement(swapKeys(addT, 'actor', 'at')), 'non_canonical', 'key order inside the head: at before actor');
  R('vault-log', rawStatement(swapKeys(addT, 'member', 'memberKey')), 'non_canonical', 'key order inside the kind\'s fields');
  R('vault-log', rawStatement(withToken(addT, 'v', '3')), 'bad_statement', 'canonical, but v is 3');
  R('vault-log', rawStatement(withToken(addT, 'purpose', '"vault-grant"')), 'bad_statement', 'an add\'s key set with the literal of another purpose');
  // §3.2's template rules (VR-1): a genesis has seq 0 and a zero prev; every other kind has seq >= 1.
  R('vault-log', rawStatement(genesisT), 'ok', 'a genesis with seq 0 and a zero prev');
  R('vault-log', rawStatement(withToken(genesisT, 'seq', '1')), 'bad_statement', 'a genesis with seq 1: a template rule, so it fails at the parse whatever its place in a chain');
  R('vault-log', rawStatement(withToken(genesisT, 'prev', quote(fx.log.entries[0].hash))), 'bad_statement', 'a genesis whose prev is not 64 zeros');
  R('vault-log', rawStatement(withToken(addT, 'seq', '0')), 'bad_statement', 'an add with seq 0: every kind but genesis has seq >= 1');
  R('vault-log', rawStatement(withToken(leaveT, 'seq', '0')), 'bad_statement', 'a leave with seq 0');
  R('vault-log', rawStatement(withToken(addT, 'prev', quote('0'.repeat(64)))), 'ok', 'an add with a zero prev: no template rule covers prev outside the genesis (in a chain it is bad_prev)');
  R('vault-log', rawStatement(withToken(genesisT, 'seq', '1')).replace('"seq":', '"seq": '), 'non_canonical', 'a genesis with seq 1 and a space after a colon: non_canonical comes before the template rules');

  // The other new purposes: one bad_statement and one non_canonical each.
  for (const s of [fx.offerConnect, fx.answer, fx.rotation, fx.assisted, fx.veto]) {
    const t = tokens(s.purpose, s.values);
    R(s.purpose, s.statement, 'ok', s.purpose + ', untouched');
    R(s.purpose, rawStatement(withToken(t, 'v', '3')), 'bad_statement', s.purpose + ': canonical, but v is 3');
    R(s.purpose, rawStatement(withToken(t, 'purpose', '"vault-log"')), 'bad_statement', s.purpose + ': the literal of another purpose');
    R(s.purpose, rawStatement(withoutKey(t, 'issuedAt')), 'non_canonical', s.purpose + ': no issuedAt');
  }
  const assistedT = tokens('assisted-recovery', fx.assisted.values);
  R('assisted-recovery', rawStatement(withToken(assistedT, 'requestId', quote(fx.assisted.values.requestKey))), 'non_canonical', 'assisted-recovery: requestId must be b64_16 (FI-B13), not 32 bytes');
  R('assisted-recovery', rawStatement(withToken(assistedT, 'uvk', quote(fx.assisted.values.requestId))), 'non_canonical', 'assisted-recovery: uvk must be b64_32 (FI-B13), not 16 bytes');
  R('assisted-recovery', rawStatement(withToken(assistedT, 'requestKey', quote(fx.assisted.values.requestId))), 'non_canonical', 'assisted-recovery: requestKey must be b64_32 (FI-B13), not 16 bytes');
  const rotationT = tokens('recovery-rotation', fx.rotation.values);
  R('recovery-rotation', rawStatement(withToken(rotationT, 'toFp', '"none"')), 'non_canonical', 'recovery-rotation: toFp is hex64, so none is not allowed');
  R('recovery-rotation', rawStatement(withToken(rotationT, 'fromFp', '"none"')), 'non_canonical', 'recovery-rotation: fromFp is hex64, so none is not allowed');

  // Host-minted offers (§6.4): canonical JSON with no frame.
  const setupT = tokens('setup-offer', parseStatement('setup-offer', utf8(fx.setupOffer)).values);
  const enrolT = tokens('enrol-offer', fx.enrolValues);
  R('setup-offer', fx.setupOffer, 'ok', 'a setup offer');
  R('setup-offer', rawStatement(withToken(setupT, 'recoveryFp', quote(recoveryA.fp))), 'ok', 'a setup offer for an instance with operator recovery');
  R('setup-offer', rawStatement(withToken(setupT, 'kind', '"public"')), 'ok', 'a setup offer for a public instance');
  R('setup-offer', rawStatement(withoutKey(setupT, 'recoveryFp')), 'non_canonical', 'a setup offer with no recoveryFp');
  R('setup-offer', rawStatement(withToken(setupT, 'origin', '"http://192.168.1.10"')), 'non_canonical', 'a setup offer for a plain-http LAN address (R4)');
  R('setup-offer', fx.setupOffer.replace('"origin":', '"origin": '), 'non_canonical', 'white space in a setup offer');
  R('enrol-offer', rawStatement(enrolT), 'ok', 'an enrol offer bound to an address');
  R('enrol-offer', rawStatement(withToken(enrolT, 'email', '"none"')), 'ok', 'an enrol offer bound to no address');
  R('enrol-offer', rawStatement(withoutKey(enrolT, 'email')), 'non_canonical', 'an enrol offer with no email key: none is spelled out, never omitted');
  R('enrol-offer', rawStatement(swapKeys(enrolT, 'cardHash', 'email')), 'non_canonical', 'key order in an enrol offer');

  // No nesting (§2.2): a statement is one flat object. A `[` anywhere, or a second `{`, is
  // non_canonical, refused on the bytes before any general JSON parser sees the text.
  const brackets = '['.repeat(1024);
  R('instance-card', brackets, 'non_canonical', 'no nesting: 1,024 [ and nothing else, the longest statement a frame can carry. It is refused on the bytes, before any general JSON parser sees it: a parser that recurses once per level can be made to overflow its stack by this text, and that is a crash, not a verdict');
  R('vault-log', brackets, 'non_canonical', 'no nesting: the same 1,024 [ under the vault-log template, whose key set hangs on its kind: no look-ahead for the kind may hand this text to a general parser either');
  R('instance-card', rawStatement(withToken(card, 'name', '[' + quote(CARD0.name) + ']')), 'non_canonical', 'no nesting: card 0 with its name inside an array');
  R('instance-card', rawStatement(withToken(card, 'seq', '{"n":0}')), 'non_canonical', 'no nesting: card 0 with an object where the number seq belongs (a second {)');
  R('instance-card', rawStatement(withToken(card, 'issuedAt', '[' + String(CARD0.issuedAt) + ']')), 'non_canonical', 'no nesting: card 0 with its last value, issuedAt, inside an array, so that the nesting closes just before the final brace');
  R('instance-card', rawStatement(withToken(card, 'issuedAt', '{"ms":' + String(CARD0.issuedAt) + '}')), 'non_canonical', 'no nesting: card 0 with an object as its last value, so that the statement ends in two closing braces');
  return rows;
}

function frameRows(fx) {
  const rows = [];
  const add = (why, frame, expectedPurposeCode, verdict) => {
    const got = parseFrame(frame, expectedPurposeCode).verdict;
    if (got !== verdict) throw new Error(`statement-v2 frame "${why}": the design says ${verdict}, the oracle says ${got}`);
    rows.push({ why, frameB64: b64u(frame), expectedPurposeCode, verdict });
  };
  const card = fx.card0.frame;
  const C = PURPOSE_CODES['instance-card'];
  const L = PURPOSE_CODES['vault-log'];
  const patch = (frame, index, value) => {
    const out = frame.slice();
    out[index] = value;
    return out;
  };
  const sizedStatement = (n) => '{' + 'x'.repeat(n - 2) + '}';

  add('empty', new Uint8Array(0), C, 'bad_frame');
  add('shorter than the magic', card.slice(0, 3), C, 'bad_frame');
  add('the magic alone', card.slice(0, 4), C, 'bad_frame');
  add('header only', card.slice(0, 5), C, 'bad_frame');
  add('truncated inside the signature', card.slice(0, 70), C, 'bad_frame');
  add('a statement of 1 byte (102 bytes in all)', assembleFrame(C, fx.card0.signerPub, fx.card0.signature, utf8('{')), C, 'bad_frame');
  add('a statement of 2 bytes (103 bytes in all): the frame is long enough, the statement {} is not canonical', signedRaw(C, operator, '{}').frame, C, 'non_canonical');
  add('a statement of 1024 bytes (1125 in all): the frame is allowed, the statement is not canonical', signedRaw(C, operator, sizedStatement(1024)).frame, C, 'non_canonical');
  add('a statement of 1025 bytes (1126 in all)', signedRaw(C, operator, sizedStatement(1025)).frame, C, 'bad_frame');
  add('bad magic', patch(card, 2, 0x7a), C, 'unknown_format');
  add('format version 0x03', patch(card, 3, 0x03), C, 'unknown_format');
  add('format version 0x01', patch(card, 3, 0x01), C, 'unknown_format');
  add('a bare JSON statement (first byte {)', utf8(fx.card0.statement), C, 'unknown_format');
  add('format version 0x03 on a frame that is also too short (50 bytes): the magic is read first, as spec 01 §5.1 step 1 lists the checks', patch(card, 3, 0x03).slice(0, 50), C, 'unknown_format');
  for (const code of [0x00, 0x0b, 0x0c, 0x10, 0x7f, 0x80, 0xff]) {
    add('reserved purpose code 0x' + code.toString(16).padStart(2, '0'), patch(card, 4, code), C, 'bad_frame');
  }
  add('a valid vault-log frame where an instance card is expected', fx.log.entries[1].frame, C, 'bad_frame');
  add('a valid instance-card frame where a vault-log entry is expected', card, L, 'bad_frame');
  add('a valid account-genesis frame where an instance card is expected', fx.genesis.frame, C, 'bad_frame');
  add('a valid instance-card frame where an account genesis is expected', card, PURPOSE_CODES['account-genesis'], 'bad_frame');
  add('a valid link-answer frame where a link offer is expected', fx.answer.frame, PURPOSE_CODES['link-offer'], 'bad_frame');
  add('a valid recovery-rotation frame where an assisted-recovery payload is expected', fx.rotation.frame, PURPOSE_CODES['assisted-recovery'], 'bad_frame');
  add('a valid recovery-veto frame where a recovery rotation is expected', fx.veto.frame, PURPOSE_CODES['recovery-rotation'], 'bad_frame');
  add('the card\'s statement, signed, under purpose code 0x05: the key set is not the genesis key set', signedRaw(PURPOSE_CODES['account-genesis'], operator, fx.card0.statement).frame, PURPOSE_CODES['account-genesis'], 'non_canonical');
  add('signed, but with white space after a colon', signedRaw(C, operator, fx.card0.statement.replace('"seq":', '"seq": ')).frame, C, 'non_canonical');
  add('signed, but with bytes after the object', signedRaw(C, operator, fx.card0.statement + '{}').frame, C, 'non_canonical');
  add('one byte appended after signing', concat(card, utf8(' ')), C, 'non_canonical');
  add('signed, canonical, but v is 3', signedRaw(C, operator, fx.card0.statement.replace('"v":2', '"v":3')).frame, C, 'bad_statement');
  add('signed, canonical, but the literal names another purpose', signedRaw(C, operator, fx.card0.statement.replace('"instance-card"', '"account-genesis"')).frame, C, 'bad_statement');
  add('a vault-log genesis the creator signed with seq 1 (VR-1)', signedRaw(L, alice, fx.log.entries[0].statement.replace('"seq":0', '"seq":1')).frame, L, 'bad_statement');
  add('a vault-log add the owner signed with seq 0 (VR-1)', signedRaw(L, alice, fx.log.entries[1].statement.replace('"seq":1', '"seq":0')).frame, L, 'bad_statement');
  for (const s of [fx.card0, fx.card1, fx.genesis, fx.log.entries[0], fx.offerConnect, fx.answer, fx.rotation, fx.assisted, fx.veto]) {
    add(`the valid ${s.purpose} frame parses`, s.frame, s.purposeCode, 'ok');
  }
  // No nesting (§2.2), as a whole frame: 1,024 `[` is the longest statement, so the frame is the longest legal one.
  const bracketFrame = signedRaw(C, operator, '['.repeat(1024)).frame;
  if (bracketFrame.length !== MAX_FRAME) throw new Error('statement-v2: the bracket frame must be the longest legal frame');
  add('a statement of 1,024 [ in a signed frame of 1125 bytes, the longest allowed: the frame checks pass, and the statement is non_canonical (no nesting), refused before any general JSON parser sees it', bracketFrame, C, 'non_canonical');
  return rows;
}

function bindingRows(fx) {
  const rows = [];
  const add = (why, frame, form, expectedKey, binds, signatureOk) => {
    const parts = splitFrame(frame);
    if (parts.verdict !== 'ok') throw new Error('binding fixture does not split: ' + why);
    const gotBinds = form === 'x25519' ? signerMapsTo(parts.signerPub, expectedKey) : signerEquals(parts.signerPub, expectedKey);
    const gotSig = signatureValid(parts);
    if (gotBinds !== binds || gotSig !== signatureOk) throw new Error(`statement-v2 binding "${why}": expected ${binds}/${signatureOk}, the oracle says ${gotBinds}/${gotSig}`);
    rows.push({ why, frameB64: b64u(frame), purposeCode: parts.purposeCode, form, expectedKeyB64: b64u(expectedKey), signerBinds: binds, signatureValid: signatureOk });
  };
  const entry = fx.log.entries[1]; // add bob, signed by alice
  const reassemble = (s, signerPub, signature = s.signature) => assembleFrame(s.purposeCode, signerPub, signature, utf8(s.statement));
  const negate = (pub) => {
    const out = pub.slice();
    out[31] ^= 0x80;
    return out;
  };
  const flipped = (s) => {
    const sig = s.signature.slice();
    sig[10] ^= 0x01;
    return reassemble(s, s.signerPub, sig);
  };
  const identity = new Uint8Array(32);
  identity[0] = 1;

  add('X25519 form: the signer maps to the expected identity key', entry.frame, 'x25519', alice.identityPub, true, true);
  add('X25519 form: another account\'s key is expected', entry.frame, 'x25519', bob.identityPub, false, true);
  add('X25519 form: the Ed25519 key itself is handed in where the X25519 key belongs', entry.frame, 'x25519', alice.signPub, false, true);
  add('X25519 form: an expected key of 31 bytes', entry.frame, 'x25519', alice.identityPub.slice(0, 31), false, true);
  add('X25519 form: signerPub swapped for bob\'s key, alice\'s signature kept', reassemble(entry, bob.signPub), 'x25519', alice.identityPub, false, false);
  add('X25519 form: signerPub is -A, under the signature alice made as A. -A has the same X25519 image, so it BINDS. The signature fails here only because nobody signed again: whoever holds the key can sign validly under -A too, so the X25519 form does not tell A from -A, and where the two must be told apart the Ed25519 bytes are compared (§4.1)', reassemble(entry, negate(entry.signerPub)), 'x25519', alice.identityPub, true, false);
  add('X25519 form: signerPub is the Edwards identity point, which has no X25519 image', reassemble(entry, identity), 'x25519', alice.identityPub, false, false);
  add('X25519 form: signerPub is 32 zero bytes', reassemble(entry, new Uint8Array(32)), 'x25519', alice.identityPub, false, false);
  add('X25519 form: one signature bit flipped', flipped(entry), 'x25519', alice.identityPub, true, false);
  add('X25519 form: the statement changed after signing (still canonical)',
    assembleFrame(entry.purposeCode, entry.signerPub, entry.signature, utf8(entry.statement.replace('"role":"writer"', '"role":"reader"'))), 'x25519', alice.identityPub, true, false);
  add('X25519 form: the purpose code changed after signing (0x03 to 0x04); the code is inside M',
    assembleFrame(PURPOSE_CODES['instance-card'], entry.signerPub, entry.signature, utf8(entry.statement)), 'x25519', alice.identityPub, true, false);

  add('Ed25519 form: signerPub equals the expected operatorSignKey byte for byte', fx.card0.frame, 'ed25519', operator.signPub, true, true);
  add('Ed25519 form: another operator key is expected', fx.card0.frame, 'ed25519', operator2.signPub, false, true);
  add('Ed25519 form: the X25519 identity key is handed in where the Ed25519 key belongs', fx.card0.frame, 'ed25519', operator.identityPub, false, true);
  add('Ed25519 form: signerPub is -A. Byte comparison refuses it here, where the X25519 form would not', reassemble(fx.card0, negate(fx.card0.signerPub)), 'ed25519', operator.signPub, false, false);
  add('Ed25519 form: one signature bit flipped', flipped(fx.card0), 'ed25519', operator.signPub, true, false);

  add('account genesis, X25519 form (the server, which holds no seed)', fx.genesis.frame, 'x25519', alice.identityPub, true, true);
  add('account genesis, Ed25519 form (every client: the full clients and the extension)', fx.genesis.frame, 'ed25519', alice.signPub, true, true);
  add('recovery rotation: the expected key is the recovery public key (X25519) of the outgoing seed', fx.rotation.frame, 'x25519', recoveryA.publicKey, true, true);
  add('recovery rotation: the incoming key is not the signer', fx.rotation.frame, 'x25519', recoveryB.publicKey, false, true);
  add('assisted recovery: signed by the recovery-key signing key', fx.assisted.frame, 'x25519', recoveryA.publicKey, true, true);
  add('assisted recovery: an account identity key is not the signer', fx.assisted.frame, 'x25519', alice.identityPub, false, true);
  return rows;
}

function templates() {
  const out = {};
  for (const kind of LOG_KINDS) out['vault-log/' + kind] = describeTemplate('vault-log', kind);
  for (const purpose of ['instance-card', 'account-genesis', 'link-offer', 'link-answer', 'recovery-rotation', 'assisted-recovery', 'recovery-veto', ...HOST_OFFER_PURPOSES]) {
    out[purpose] = describeTemplate(purpose);
  }
  return out;
}

export function build() {
  const fx = fixtures();
  return {
    _about: [
      'Signed statements of design 2026-11-15-onboarding-trust §2: the frame (§2.1, layout unchanged from spec 01 §5.1), the purpose codes 0x03-0x0A, and the canonical statement grammar (§2.2).',
      'Hand-authored from the independent oracle in tools/vector-gen/oracle (Node WebCrypto and @noble; no andvari code). Regenerate with `npm run generate` there; `npm run check` fails on any difference.',
      'frame = magic 61767302 || purposeCode || signerPub(32) || signature(64) || statement. M = "andvari/v2|signed-statement" || 0x00 || frame[0..5) || signerPub || statement. H(frame) = lowercase hex SHA-256 of the whole frame. Signatures are RFC 8032 Ed25519, which is deterministic, so signatureB64 and frameB64 reproduce byte for byte.',
      'valid: one frame per template. `fields` are the statement values in template order, `signer` names the cast account or recovery key whose seed signed, and each of `expectedKeys` is a key the frame must verify under: form x25519 means ed25519_pk_to_curve25519(signerPub) == key, form ed25519 means signerPub == key.',
      'grammar and parse: `statementB64` is checked against `template` (the strict parse of spec 01 §5.1 steps 2-6: printable ASCII, no nesting, the exact key set in order, every value in its type, the re-encode byte compare, then v, the purpose literal and the template rules). verdict is ok, non_canonical or bad_statement. No nesting (§2.2): a statement is one flat object, so a `[` anywhere, or a second `{`, is non_canonical, and an implementation refuses it on the bytes BEFORE handing the text to any general JSON parser (a parser that recurses once per level can be made to overflow its stack by 1,024 brackets, and that is a crash, not a verdict); the last six rows of `parse` and the last row of `frames` are these, added on 2026-11-15. A value that fails its type is non_canonical, and that includes `v` (an int, VR-4) and a template\'s listed literals (VR-3). A well-formed statement with v != 2, the literal of another purpose, or a broken template rule is bad_statement; the template rules are a grant\'s from != to and, for the vault log, "a genesis has seq 0 and a zero prev, every other kind has seq >= 1" (VR-1). `token` is the raw JSON token spliced into `field`. Rows with purposeCode null are the host-minted offers of §6.4, which have no frame.',
      'frames: the whole §2 parse of `frameB64` by the helper for `expectedPurposeCode`, in §2.4\'s order: bad_frame if shorter than 4 bytes; unknown_format for a wrong magic or version byte; bad_frame for a length outside 103..1125, a reserved purpose code or a purpose other than the expected one; then the statement verdicts. No signature is checked in this section.',
      'binding: the two predicates of §2.1 for a frame and an expected key. `signerBinds` is the signer-binding requirement in the given form; `signatureValid` is crypto_sign_verify_detached over M with the frame\'s own signerPub. The verdict for a failed binding is named per flow in §2.4: not_authorized for the vault log, the card and grants, signer_not_pinned_key for every other helper; a failed signature is bad_signature everywhere. Those names are graded in each flow\'s own file.',
      'The extension grades the rows whose purposeCode is 4 or 5 (§17).',
      'Changed on 2026-11-15, third batch, with the rule that every device checks the genesis signer as an Ed25519 key (design §2.4, the Signer binding row 0x05; spec 01 §5.1): the `why` of the valid row account-genesis and of the two binding rows that begin "account genesis" now say that every client compares signerPub with the Ed25519 key it derives from the seed, and that the X25519 form is the server\'s, which holds no seed. No expectation and no other byte changed: the genesis frame still verifies under both forms, and both predicates are still graded.',
      'Changed on 2026-11-15, fourth batch, with the dot-atom and domain rule of emailNorm (spec 01 §5.5), which email_b64n requires ("emailNorm of them must equal them exactly"): an address with no emailNorm at all is non_canonical. One expectation changed: the email_b64n grammar row whose token decodes to a@b was ok ("the shortest emailNorm, 3 bytes") and is now non_canonical (a one-label domain); its `why` says so. Six email_b64n rows are new, at the end of grammar: a display-name form, a quoted local part, a comment, a trailing dot in the local part and on the domain (all non_canonical), and a@b.c, the shortest emailNorm now (ok). No other row changed.',
    ],
    domainAscii: DOMAIN,
    magicHex: '61767302',
    purposeCodes: PURPOSE_CODES,
    statementBytes: { min: 2, max: 1024 },
    frameBytes: { min: MIN_FRAME, max: MAX_FRAME },
    keys: {
      alice: describe(alice), bob: describe(bob), carol: describe(carol), operator: describe(operator), operator2: describe(operator2),
      recoveryA: { seedB64: b64u(recoveryA.seed), publicKeyB64: b64u(recoveryA.publicKey), signPubB64: b64u(recoveryA.signPub), fingerprint: recoveryA.fp },
      recoveryB: { seedB64: b64u(recoveryB.seed), publicKeyB64: b64u(recoveryB.publicKey), signPubB64: b64u(recoveryB.signPub), fingerprint: recoveryB.fp },
    },
    templates: templates(),
    valid: validRows(fx),
    grammar: grammarRows(fx),
    parse: strictnessRows(fx),
    frames: frameRows(fx),
    binding: bindingRows(fx),
  };
}

export function grade(doc) {
  const failures = [];
  let rows = 0;
  const expect = (cond, what) => {
    rows++;
    if (!cond) failures.push(what);
  };

  for (const row of doc.valid) {
    const frame = mustUnb64u(row.frameB64);
    const parsed = parseFrame(frame, row.purposeCode);
    expect(parsed.verdict === 'ok', `valid ${row.name}: parse ${parsed.verdict}`);
    if (parsed.verdict !== 'ok') continue;
    expect(JSON.stringify(parsed.values) === JSON.stringify(row.fields), `valid ${row.name}: fields`);
    expect(new TextDecoder().decode(parsed.statementBytes) === row.statementUtf8, `valid ${row.name}: statementUtf8`);
    expect(buildStatement(row.purpose, row.fields) === row.statementUtf8, `valid ${row.name}: fields rebuild the statement`);
    expect(PURPOSE_BY_CODE[row.purposeCode] === row.purpose, `valid ${row.name}: purpose`);
    expect(b64u(parsed.signerPub) === row.signerPubB64 && b64u(parsed.signature) === row.signatureB64, `valid ${row.name}: signer and signature fields`);
    const message = concat(utf8(doc.domainAscii), Uint8Array.of(0), frame.slice(0, 5), parsed.signerPub, parsed.statementBytes);
    expect(hex(message) === row.messageHex, `valid ${row.name}: M`);
    expect(frameHash(frame) === row.frameHash, `valid ${row.name}: frame hash`);
    expect(signatureValid(parsed), `valid ${row.name}: signature`);
    const signerKeys = doc.keys[row.signer];
    expect(signerKeys && signerKeys.signPubB64 === row.signerPubB64, `valid ${row.name}: signer key`);
    for (const k of row.expectedKeys) {
      const key = mustUnb64u(k.keyB64);
      expect(k.form === 'x25519' ? signerMapsTo(parsed.signerPub, key) : signerEquals(parsed.signerPub, key), `valid ${row.name}: binding ${k.form}`);
    }
  }

  for (const section of ['grammar', 'parse']) {
    for (const row of doc[section]) {
      const got = parseStatement(row.template, mustUnb64u(row.statementB64)).verdict;
      expect(got === row.verdict, `${section} "${row.why}": oracle says ${got}, row says ${row.verdict}`);
      if (section === 'grammar') expect((row.verdict === 'ok') === row.valid, `grammar "${row.why}": valid flag`);
      expect(row.purposeCode === (Object.hasOwn(PURPOSE_CODES, row.template) ? PURPOSE_CODES[row.template] : null), `${section} "${row.why}": purposeCode`);
    }
  }

  for (const row of doc.frames) {
    const got = parseFrame(mustUnb64u(row.frameB64), row.expectedPurposeCode).verdict;
    expect(got === row.verdict, `frames "${row.why}": oracle says ${got}, row says ${row.verdict}`);
  }

  for (const row of doc.binding) {
    const parts = splitFrame(mustUnb64u(row.frameB64));
    expect(parts.verdict === 'ok' && parts.purposeCode === row.purposeCode, `binding "${row.why}": frame`);
    if (parts.verdict !== 'ok') continue;
    const key = mustUnb64u(row.expectedKeyB64);
    const binds = row.form === 'x25519' ? signerMapsTo(parts.signerPub, key) : signerEquals(parts.signerPub, key);
    expect(binds === row.signerBinds, `binding "${row.why}": signerBinds`);
    expect(signatureValid(parts) === row.signatureValid, `binding "${row.why}": signatureValid`);
  }
  return { rows, failures };
}
