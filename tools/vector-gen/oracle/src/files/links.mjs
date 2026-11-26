// links.json: the link URL, the §2.3 derivations, the committed comparison codes (one per side),
// offers and answers in their envelopes, and both verification orders of §6.8 with §2.4's verdicts.

import { b64u, mustUnb64u, utf8, hex } from '../bytes.mjs';
import { envelopeSeal, envelopeOpen } from '../prims.mjs';
import {
  deriveLink, creatorFingerprint, codeCommit, linkCodes, acceptsTypedCode, LINK_CODE_SIDES, composeLink, parseLink, openLink, processAnswer, checkReveal,
  LINK_MAX_LENGTH, HOST_JSON_MAX_DEPTH, LINK_ENVELOPE_MAX_CHARS,
} from '../links.mjs';
import { buildStatement, PURPOSE_CODES } from '../statement.mjs';
import { verifyCardChain } from '../card.mjs';
import { assembleFrame } from '../frame.mjs';
import { ZERO_HASH } from '../vaultlog.mjs';
import { findEqualLinkCodes } from '../powsearch.mjs';
import { nearZeroKey } from '../keyfloor.mjs';
import { signed, signedRaw, tokens, withToken, rawStatement, nameOf } from '../build.mjs';
import { alice, bob, carol, eve, operator, operator2, ids, fixed, T0, MINUTE, DAY, describe } from '../cast.mjs';

export const file = 'links.json';

const X = 'https://vault.example.org';
/** The public instance's origin (§0.3): the one a store build bakes. */
const P = 'https://vault.andvaripass.com';
const OFFER = PURPOSE_CODES['link-offer'];
const ANSWER = PURPOSE_CODES['link-answer'];
const at = (minutes) => T0 + minutes * MINUTE;
const nonce24 = (label) => fixed('links/envelope-nonce/' + label, 24);
/** The nonceB of the equal-codes row is fixed(EQUAL_CODES_LABEL + i) for the first i that gives two equal codes. */
const EQUAL_CODES_LABEL = 'links/nonce-b/equal/';
/**
 * The cap on a link's offer (and answer) envelope, in characters of its unpadded base64url text
 * (§6.6, spec 03 §15.1), and the same cap in bytes of envelope (§6.3: 2,732 characters are 2,049
 * bytes). An envelope is its plaintext and 42 bytes more (spec 02 §2: two header bytes, a 24-byte
 * nonce, a 16-byte tag).
 */
const OFFER_MAX_CHARS = LINK_ENVELOPE_MAX_CHARS;
const OFFER_MAX_BYTES = 2049;
const ENVELOPE_OVERHEAD = 42;
if (Math.ceil((OFFER_MAX_BYTES * 4) / 3) !== OFFER_MAX_CHARS || Math.ceil(((OFFER_MAX_BYTES + 1) * 4) / 3) <= OFFER_MAX_CHARS) throw new Error('links: 2,049 bytes are the most that fit in 2,732 characters');

function cardChain(owner, nameText) {
  const card0 = signed('instance-card', owner, {
    instanceId: ids.instance, seq: 0, prev: ZERO_HASH, origin: X, name: nameOf(nameText), kind: 'private',
    operator: owner.userId, operatorSignKey: b64u(owner.signPub), recoveryFp: 'none', issuedAt: at(-600),
  });
  const card1 = signed('instance-card', owner, { ...card0.values, seq: 1, prev: card0.hash, name: nameOf(nameText + ' 2'), issuedAt: at(-300) });
  return [card0, card1];
}

function fixtures() {
  const cards = cardChain(operator, 'Example Vault');
  const otherCards = cardChain(operator2, 'Another Chain');
  // The same chain after a move: card 2 names another origin.
  const movedCards = [...cards, signed('instance-card', operator, { ...cards[1].values, seq: 2, prev: cards[1].hash, origin: 'https://vault2.example.org', issuedAt: at(-100) })];
  const secret = fixed('links/secret/connect');
  const d = deriveLink(secret);
  const nonceA = fixed('links/nonce-a');
  const nonceB = fixed('links/nonce-b');
  const offerValues = {
    linkId: d.linkId, kind: 'connect', origin: X, instanceId: ids.instance, cardHash: cards[1].hash, from: alice.userId,
    fromKey: alice.key, name: nameOf('Alice'), commit: codeCommit(nonceA), expiresAt: at(15), issuedAt: at(0),
  };
  const offer = signed('link-offer', alice, offerValues);
  const answerValues = {
    linkId: d.linkId, offerHash: offer.hash, to: alice.userId, toKey: alice.key, from: bob.userId, fromKey: bob.key,
    name: nameOf('Bob'), nonce: b64u(nonceB), issuedAt: at(2),
  };
  const answer = signed('link-answer', bob, answerValues);

  // The public instance as a store build bakes it (§0.3, §4.4): its own chain, and what else its
  // address could serve.
  const pub0 = signed('instance-card', operator, {
    instanceId: ids.otherInstance, seq: 0, prev: ZERO_HASH, origin: P, name: nameOf('andvari'), kind: 'public',
    operator: operator.userId, operatorSignKey: b64u(operator.signPub), recoveryFp: 'none', issuedAt: at(-900),
  });
  const pub1 = signed('instance-card', operator, { ...pub0.values, seq: 1, prev: pub0.hash, issuedAt: at(-450) });
  const publicCards = [pub0, pub1];
  const baked = { origin: P, instanceId: pub0.values.instanceId, card0Hash: pub0.hash, kind: 'public' };
  const byOperator2 = { operator: operator2.userId, operatorSignKey: b64u(operator2.signPub) };
  // Another card 0 under the baked instanceId and origin: a new chain after an operator reset (§4.6),
  // or another server answering for the address.
  const publicOtherCard0 = [signed('instance-card', operator2, { ...pub0.values, ...byOperator2, issuedAt: at(-200) })];
  // Another instance that names the baked origin as its own.
  const publicImpostor = [signed('instance-card', operator2, { ...pub0.values, ...byOperator2, instanceId: ids.instance, issuedAt: at(-150) })];
  // The public instance's own chain once its newest card names another origin.
  const publicMoved = [...publicCards, signed('instance-card', operator, { ...pub1.values, seq: 2, prev: pub1.hash, origin: 'https://vault.andvari.example', issuedAt: at(-50) })];

  /** Every chain a recipient row can be served, by the name the row carries in `cards`. */
  const chains = {
    'both-cards': cards,
    'card-0-only': cards.slice(0, 1),
    'no-card': [],
    moved: movedCards,
    'public-both-cards': publicCards,
    'public-card-0-only': publicCards.slice(0, 1),
    'public-other-card-0': publicOtherCard0,
    'public-impostor': publicImpostor,
    'public-moved': publicMoved,
  };
  return {
    cards, otherCards, movedCards, publicCards, baked, chains, secret, d, nonceA, nonceB, offerValues, offer, answerValues, answer,
    f: creatorFingerprint(alice.identityPub),
  };
}

// ---- derivations ----

function deriveRows(fx) {
  const row = (why, secret) => {
    const d = deriveLink(secret);
    return {
      why, secretB64: b64u(secret), linkId: d.linkId, offerKeyB64: b64u(d.offerKey), offerAdUtf8: d.offerAd,
      answerKeyB64: b64u(d.answerKey), answerAdUtf8: d.answerAd, registerToken: d.registerToken, tokenHash: d.tokenHash,
    };
  };
  return [
    row('the secret of the connect link used throughout this file', fx.secret),
    row('another secret', fixed('links/secret/other')),
    // Not 32 zero bytes: spec 01 "Keys in memory and the lock" rule 4 refuses an all-zero key, so the lowest
    // input a client derives from is 31 zero bytes and one 0x01. The zero secret is in keyfloor.json, to be refused.
    row('31 zero bytes and one 0x01 byte (the lowest secret the key floor accepts; all zeros is refused as a wiped key)', nearZeroKey()),
    row('32 bytes of 0xff', new Uint8Array(32).fill(0xff)),
  ];
}

function fingerprintRows() {
  return [alice, bob, eve].map((a) => ({ why: `the creator fingerprint of ${a.name}'s identity key`, identityPubB64: b64u(a.identityPub), f: creatorFingerprint(a.identityPub) }));
}

// ---- the committed codes: one per side ----

/** The inputs of the two codes of this file's link: its id, its two frame hashes and its two nonces. */
const codeInputs = (fx) => ({ linkId: fx.d.linkId, offerHash: fx.offer.hash, answerHash: fx.answer.hash, nonceA: fx.nonceA, nonceB: fx.nonceB });
const describeCodeInputs = (inputs) => ({
  linkId: inputs.linkId, offerHash: inputs.offerHash, answerHash: inputs.answerHash, nonceAB64: b64u(inputs.nonceA), nonceBB64: b64u(inputs.nonceB),
});

function codeRows(fx) {
  const base = codeInputs(fx);
  const rows = [];
  /** `why` may be a function of the two codes, so that a row can name its own digits. */
  const add = (why, inputs, { equalCodes = false } = {}) => {
    const codes = linkCodes(inputs);
    // Every row has two different codes, and says so. They coincide for one link in a million; a
    // fixture that hits that by accident is replaced, not written down. The one row that was
    // searched for (`equalCodes`) must coincide instead.
    if ((codes.creator.shows === codes.answerer.shows) !== equalCodes) {
      throw new Error(equalCodes ? 'links: the equal-codes row does not have two equal codes' : 'links: the two codes of a row coincide; pick another fixture');
    }
    rows.push({ why: typeof why === 'function' ? why(codes) : why, ...describeCodeInputs(inputs), creator: codes.creator, answerer: codes.answerer });
    return codes;
  };
  const baseCodes = add((c) => 'the two codes of the link of this file (the offer and answer frames of `link`, nonceA committed in the offer and nonceB sent in the answer). '
    + `alice made the link: her screen shows ${c.creator.shows}, the creator code, and her app accepts only ${c.creator.accepts} as typed input. `
    + `bob answered it: his screen shows ${c.answerer.shows}, the answerer code, and his app accepts only ${c.answerer.accepts}. The two codes differ, and neither app displays the code it accepts`, base);
  const variants = [
    ['another linkId', { linkId: deriveLink(fixed('links/secret/other')).linkId }],
    ['another offerHash (the answerer saw another offer)', { offerHash: fx.answer.hash }],
    ['another answerHash', { answerHash: fx.offer.hash }],
    ['another nonceA', { nonceA: fixed('links/nonce-a/other') }],
    ['another nonceB', { nonceB: fixed('links/nonce-b/other') }],
    ['the two nonces swapped', { nonceA: fx.nonceB, nonceB: fx.nonceA }],
  ];
  for (const [why, change] of variants) {
    const codes = add('changing one input changes both codes: ' + why, { ...base, ...change });
    if (LINK_CODE_SIDES.some((side) => codes[side].shows === baseCodes[side].shows)) throw new Error('links: a code variant collides with a base code; pick another fixture');
  }
  // Both codes below 100000, to pin the zero padding of each: the first nonceB label that gives it.
  for (let i = 0; ; i++) {
    const nonceB = fixed('links/nonce-b/padded/' + i);
    const codes = linkCodes({ ...base, nonceB });
    if (LINK_CODE_SIDES.every((side) => codes[side].shows.startsWith('0'))) {
      add('codes below 100000 keep their leading zeros: six digits always, on both sides', { ...base, nonceB });
      break;
    }
  }
  // Equal codes (§6.11): about one link in a million has the same six digits on both sides. The
  // first nonceB label that gives it, found by a search (about one try in a million succeeds) and
  // derived again here; `add` refuses the row unless its two codes are equal.
  const equalAt = findEqualLinkCodes(describeCodeInputs(base), EQUAL_CODES_LABEL);
  add((c) => `equal codes: with this nonceB (found by search) the two codes of the link are the same six digits, ${c.creator.shows}, as they are for about one link in a million. `
    + `Each side shows ${c.creator.shows} and each side accepts ${c.creator.shows}. Nothing special happens: each app still accepts exactly the other side's code, which is here also the one on its own screen, and must not refuse a typed code for being equal to its own`,
  { ...base, nonceB: fixed(EQUAL_CODES_LABEL + equalAt) }, { equalCodes: true });
  return rows;
}

/**
 * Which typed text each side's app accepts (§6.11). Every row carries the five inputs of one of the
 * `code` rows: the first eight those of code[0], the later ones as their `why` says.
 */
function typedCodeRows(fx, code) {
  const inputs = codeInputs(fx);
  const codes = linkCodes(inputs);
  if (codes.creator.shows === codes.answerer.shows) throw new Error('links: the typedCode rows need two different codes');
  const who = { creator: { name: 'alice', screen: 'her' }, answerer: { name: 'bob', screen: 'his' } };
  const otherOf = (side) => (side === 'creator' ? 'answerer' : 'creator');
  const inputsOfRow = (row) => ({ linkId: row.linkId, offerHash: row.offerHash, answerHash: row.answerHash, nonceA: mustUnb64u(row.nonceAB64), nonceB: mustUnb64u(row.nonceBB64) });
  const rows = [];
  /** `accepted` is what §6.11 says; the builder checks the oracle agrees before writing the row. */
  const add = (rowInputs, typedInto, typed, accepted, why) => {
    const got = acceptsTypedCode(typedInto, rowInputs, typed);
    if (got !== accepted) throw new Error(`links typedCode "${why}": the design says ${accepted}, the oracle says ${got}`);
    rows.push({ why, typedInto, ...describeCodeInputs(rowInputs), typed, expect: { accepted } });
  };

  // ---- an app accepts only the other side's code (the inputs of code[0]) ----
  for (const side of LINK_CODE_SIDES) {
    const other = otherOf(side);
    const { name, screen } = who[side];
    const own = codes[side].shows;
    const theirs = codes[side].accepts;
    add(inputs, side, theirs, true, `${name} (the ${side}) types ${theirs}, the six digits ${who[other].name} reads from ${who[other].screen} screen: the ${other} code is the one the ${side}'s app accepts, and this entry alone sets compared = true on ${screen} device. The two codes of these inputs differ (${screen} own screen shows ${own}).`);
    add(inputs, side, own, false, `${name} (the ${side}) types ${own}, the code on ${screen} own screen: not accepted. The ${side}'s app compares typed digits with the ${other} code only (${theirs} here), and the two codes of these inputs differ, so the digits on ${screen} screen are not the digits ${screen} app accepts.`);
    const offByOne = theirs.slice(0, 5) + String((Number(theirs[5]) + 1) % 10);
    add(inputs, side, offByOne, false, `${name} (the ${side}) types ${offByOne}, the ${other} code with its last digit one off: not accepted. A failed comparison changes nothing.`);
    const fiveDigits = theirs.slice(0, 5);
    // The row must hold whether an engine compares text or numbers: five digits are not the code either way.
    if (fiveDigits.padStart(6, '0') === theirs || Number(fiveDigits) === Number(theirs)) throw new Error('links: the five-digit typedCode row needs another fixture');
    add(inputs, side, fiveDigits, false, `${name} (the ${side}) types ${fiveDigits}, only the first five digits of the ${other} code: not accepted.`);
  }

  // ---- the text rule (§6.11 "Typed input"): every ASCII space is removed, and what is left must be
  //      exactly six ASCII digits, equal to the other side's code. Nothing else is normalised. ----
  const shown = (digits) => digits.slice(0, 3) + ' ' + digits.slice(3); // as a screen shows a code: 481 207
  for (const side of LINK_CODE_SIDES) {
    const other = otherOf(side);
    const { name } = who[side];
    const theirs = codes[side].accepts;
    add(inputs, side, shown(theirs), true, `The text rule: ${name} (the ${side}) types ${shown(theirs)}, the ${other} code as ${who[other].name}'s screen shows it, with one space in the middle: accepted. A typed code is compared as text once every ASCII space (U+0020) is removed, and what is left here is exactly the six digits of the ${other} code.`);
    add(inputs, side, ' ' + theirs + ' ', true, `The text rule: ${name} (the ${side}) types the ${other} code ${theirs} with one space in front of it and one after it: accepted. Spaces are removed wherever they stand.`);
  }
  const everyOther = codes.creator.accepts.split('').join(' ');
  add(inputs, 'creator', everyOther, true, `The text rule: alice (the creator) types ${everyOther}, the answerer code with a space after every digit but the last: accepted. EVERY ASCII space is removed, however many there are, not only the one a code is shown with.`);

  // A dropped leading zero, on the inputs of code[7], whose two codes start with one 0.
  const zeroInputs = inputsOfRow(code[7]);
  const zeroCodes = linkCodes(zeroInputs);
  // Each code must start with exactly one 0, so that "without its leading zero" is five digits and the same number.
  if (!LINK_CODE_SIDES.every((side) => /^0[1-9]/.test(zeroCodes[side].shows))) throw new Error('links: the leading-zero typedCode rows need codes that start with exactly one 0 (code[7])');
  const dropped = (digits) => digits.slice(1);
  const forCreator = zeroCodes.creator.accepts;
  const forAnswerer = zeroCodes.answerer.accepts;
  if (Number(dropped(forCreator)) !== Number(forCreator) || dropped(forCreator).length !== 5) throw new Error('links: the dropped-zero fixture');
  add(zeroInputs, 'creator', forCreator, true, `The inputs of code[7], whose two codes start with 0. alice (the creator) types ${forCreator}, the answerer code in full, its leading zero included: accepted.`);
  add(zeroInputs, 'creator', dropped(forCreator), false, `The inputs of code[7]. alice (the creator) types ${dropped(forCreator)}, the answerer code ${forCreator} without its leading zero: not accepted. The comparison is on text, not on numbers: five digits are not the six digits of the code, although ${dropped(forCreator)} is the same number as ${forCreator}.`);
  add(zeroInputs, 'answerer', shown(forAnswerer), true, `The inputs of code[7]. bob (the answerer) types ${shown(forAnswerer)}, the creator code as alice's screen shows it, its leading zero and its space included: accepted.`);
  add(zeroInputs, 'answerer', dropped(forAnswerer), false, `The inputs of code[7]. bob (the answerer) types ${dropped(forAnswerer)}, the creator code ${forAnswerer} without its leading zero: not accepted. A dropped leading zero is a mismatch.`);

  // Any other character is a mismatch (the inputs of code[0] again). The characters are spelled by
  // code point, so that this source holds none of them.
  const cp = (...points) => String.fromCodePoint(...points);
  const inScript = (digits, zero) => digits.split('').map((d) => cp(zero + Number(d))).join('');
  const split = (digits, between) => digits.slice(0, 3) + between + digits.slice(3);
  const a = codes.creator.accepts; // what alice must type: the answerer code
  const b = codes.answerer.accepts; // what bob must type: the creator code
  add(inputs, 'creator', split(a, cp(0x09)), false, `The text rule: alice (the creator) types the answerer code ${a} with a tab (U+0009) between its third and fourth digits: not accepted. Only the ASCII space (U+0020) is removed; a tab is another character, and nothing else is normalised.`);
  add(inputs, 'answerer', split(b, '-'), false, `The text rule: bob (the answerer) types ${split(b, '-')}, the creator code with a dash in the middle: not accepted. A dash is not removed.`);
  add(inputs, 'creator', a + '0', false, `The text rule: alice (the creator) types ${a}0, the six digits of the answerer code and then a seventh: not accepted. What is left once the spaces are removed must be exactly six digits; the first six are not taken on their own.`);
  add(inputs, 'answerer', inScript(b, 0xff10), false, `The text rule: bob (the answerer) types the creator code ${b} in FULLWIDTH digits (U+FF10 to U+FF19): not accepted. The six characters must be the ASCII digits U+0030 to U+0039; a digit of another script is not mapped to them.`);
  add(inputs, 'creator', inScript(a, 0x0660), false, `The text rule: alice (the creator) types the answerer code ${a} in ARABIC-INDIC digits (U+0660 to U+0669): not accepted, for the same reason.`);
  add(inputs, 'answerer', split(b, cp(0xa0)), false, `The text rule: bob (the answerer) types the creator code ${b} with a NO-BREAK SPACE (U+00A0) in the middle: not accepted. Only U+0020 is removed.`);
  add(inputs, 'creator', '', false, 'The text rule: nothing is typed into the app of alice (the creator), the empty string: not accepted.');
  add(inputs, 'answerer', ' '.repeat(6), false, 'The text rule: bob (the answerer) types six spaces and no digit: not accepted. Once the spaces are removed nothing is left.');

  // ---- equal codes (§6.11 "Equal codes"), on the inputs of the last code row ----
  const equalIndex = code.length - 1;
  const equalInputs = inputsOfRow(code[equalIndex]);
  const equalCodes = linkCodes(equalInputs);
  const sharedCode = equalCodes.creator.shows;
  if (sharedCode !== equalCodes.answerer.shows) throw new Error('links: the equal-codes typedCode rows need the code row with two equal codes');
  for (const side of LINK_CODE_SIDES) {
    const { name, screen } = who[side];
    add(equalInputs, side, sharedCode, true, `The inputs of code[${equalIndex}], whose two codes are the same six digits, ${sharedCode} (about one link in a million has that). ${name} (the ${side}) types ${sharedCode}, the ${otherOf(side)} code, which is here also the code on ${screen} own screen: accepted. There is no special case: the ${side}'s app accepts exactly the other side's code, and must not refuse a typed code for being equal to its own.`);
  }
  const sharedOff = sharedCode.slice(0, 5) + String((Number(sharedCode[5]) + 1) % 10);
  add(equalInputs, 'answerer', sharedOff, false, `The inputs of code[${equalIndex}]. bob (the answerer) types ${sharedOff}, the shared code with its last digit one off: not accepted. Equal codes are no special case the other way either: a wrong entry is still wrong.`);
  return rows;
}

function commitRows(fx) {
  const commit = codeCommit(fx.nonceA);
  const other = fixed('links/nonce-a/other');
  const reveal = [
    { why: 'the creator reveals the nonce it committed to in the offer', commit, revealB64: b64u(fx.nonceA), expect: { verdict: checkReveal(commit, fx.nonceA) } },
    { why: 'another nonce is revealed: the answerer refuses it, the link is marked failed and no code is shown', commit, revealB64: b64u(other), expect: { verdict: checkReveal(commit, other) } },
    { why: 'the answerer\'s own nonceB is replayed as the reveal', commit, revealB64: b64u(fx.nonceB), expect: { verdict: checkReveal(commit, fx.nonceB) } },
  ];
  if (reveal[0].expect.verdict !== 'ok' || reveal[1].expect.verdict !== 'bad_reveal' || reveal[2].expect.verdict !== 'bad_reveal') throw new Error('links: reveal fixtures');
  return {
    commit: [fx.nonceA, other, new Uint8Array(32)].map((n) => ({ nonceB64: b64u(n), inputUtf8: 'andvari/v2|code-commit|' + b64u(n), commit: codeCommit(n) })),
    reveal,
  };
}

// ---- the URL ----

function urlRows(fx) {
  const good = composeLink({ origin: X, secret: fx.secret, f: fx.f });
  const O = b64u(utf8(X));
  const S = b64u(fx.secret);
  const longOrigin = 'https://' + ['a'.repeat(63), 'b'.repeat(63), 'c'.repeat(63), 'd'.repeat(61)].join('.') + ':65535';
  const compose = [
    { why: 'a connect or register link: F is the creator fingerprint', origin: X, secretB64: S, f: fx.f, url: good },
    { why: 'a host-minted setup or enrol link: F is "-"', origin: X, secretB64: S, f: '-', url: composeLink({ origin: X, secret: fx.secret, f: '-' }) },
    { why: 'the public instance', origin: 'https://vault.andvaripass.com', secretB64: S, f: fx.f, url: composeLink({ origin: 'https://vault.andvaripass.com', secret: fx.secret, f: fx.f }) },
    { why: 'the longest origin the grammar allows (a 253-character host and port 65535): the link is 452 characters, under the cap of 512', origin: longOrigin, secretB64: S, f: fx.f, url: composeLink({ origin: longOrigin, secret: fx.secret, f: fx.f }) },
  ];

  const parse = [];
  const ok = (why, input, origin = X, f = fx.f) => {
    const got = parseLink(input);
    if (got === null || got.origin !== origin || b64u(got.secret) !== S || got.f !== f) throw new Error('links parse fixture should parse: ' + why);
    parse.push({ why, input, expect: { verdict: 'ok', origin, secretB64: S, f } });
  };
  const no = (why, input) => {
    if (parseLink(input) !== null) throw new Error('links parse fixture should be refused: ' + why);
    parse.push({ why, input, expect: { verdict: 'bad_link' } });
  };
  const frag = (o, s, f, v = 'v2') => `https://andvaripass.com/l#${v}.${o}.${s}.${f}`;
  const pad = (prefixLength) => 'https://andvaripass.com/' + 'p'.repeat(prefixLength - 'https://andvaripass.com/'.length - 1) + '#';
  const fragment = good.slice(good.indexOf('#') + 1);

  ok('the whole URL', good);
  ok('only the fragment', fragment);
  ok('a host-minted link, F is "-"', composeLink({ origin: X, secret: fx.secret, f: '-' }), X, '-');
  ok('spaces at both ends', '  ' + good + '  ');
  ok('a line feed inside, as a chat app wraps it', good.slice(0, 60) + '\n' + good.slice(60));
  ok('CR LF and a tab inside', good.slice(0, 40) + '\r\n' + good.slice(40, 90) + '\t' + good.slice(90));
  ok('a space inside the secret part', good.slice(0, good.length - 40) + ' ' + good.slice(good.length - 40));
  ok('another page carries the fragment: nothing before the # is authenticated or checked', 'https://example.net/some/page?x=1#' + fragment);
  ok('the longest origin the grammar allows', compose[3].url, longOrigin);
  const at512 = pad(LINK_MAX_LENGTH - fragment.length) + fragment;
  if (at512.length !== LINK_MAX_LENGTH) throw new Error('links: 512 fixture');
  ok('exactly 512 characters in all (a longer page address in front of the fragment)', at512);
  ok('513 characters as received, 512 once the line feed is removed: the length is taken after the white space is stripped', at512.slice(0, 100) + '\n' + at512.slice(100));
  ok('the fragment given with its #', '#' + fragment);

  no('513 characters in all', pad(LINK_MAX_LENGTH + 1 - fragment.length) + fragment);
  no('empty', '');
  no('only white space', ' \n ');
  no('three parts: no F', `https://andvaripass.com/l#v2.${O}.${S}`);
  no('five parts', frag(O, S, fx.f) + '.x');
  no('the version is v1', frag(O, S, fx.f, 'v1'));
  no('the version is V2', frag(O, S, fx.f, 'V2'));
  no('no version part', `https://andvaripass.com/l#${O}.${S}.${fx.f}`);
  no('the whole URL with no fragment', 'https://andvaripass.com/l');
  no('an empty fragment', 'https://andvaripass.com/l#');
  no('O is padded base64url', frag(O + '=', S, fx.f));
  no('O carries stray bits in its last character', frag(O.slice(0, -1) + 'B', S, fx.f));
  no('O is not base64url', frag('https://vault.example.org', S, fx.f));
  no('O decodes to an origin with a path', frag(b64u(utf8(X + '/')), S, fx.f));
  no('O decodes to an http LAN address', frag(b64u(utf8('http://192.168.1.10')), S, fx.f));
  no('O decodes to an uppercase host', frag(b64u(utf8('https://Vault.example.org')), S, fx.f));
  no('O decodes to an origin with port 443', frag(b64u(utf8(X + ':443')), S, fx.f));
  no('O decodes to bytes that are not UTF-8', frag(b64u(Uint8Array.of(0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0xff, 0x2e, 0x61, 0x62)), S, fx.f));
  no('O is empty', frag('', S, fx.f));
  no('S is 31 bytes', frag(O, b64u(fx.secret.slice(0, 31)), fx.f));
  no('S is 33 bytes', frag(O, b64u(new Uint8Array(33).fill(7)), fx.f));
  no('S is padded', frag(O, S + '=', fx.f));
  no('S carries stray bits in its last character', frag(O, S.slice(0, -1) + (S.endsWith('B') ? 'C' : 'B'), fx.f));
  no('S uses the standard alphabet', frag(O, b64u(new Uint8Array(32).fill(0xfb)).replaceAll('-', '+').replaceAll('_', '/'), fx.f));
  no('F is 15 bytes', frag(O, S, b64u(new Uint8Array(15).fill(1))));
  no('F is 17 bytes', frag(O, S, b64u(new Uint8Array(17).fill(1))));
  no('F is empty', frag(O, S, ''));
  no('F is two dashes', frag(O, S, '--'));
  no('F is padded', frag(O, S, fx.f + '=='));
  no('F carries stray bits in its last character', frag(O, S, fx.f.slice(0, -1) + (fx.f.endsWith('B') ? 'C' : 'B')));
  no('a device link (three parts) is not a link', `https://andvaripass.com/d#v2.${O}.${S}`);
  no('a kit payload is not a link', `andvari-kit:2:${O}:${'0'.repeat(64)}:${b64u(utf8('alice@example.com'))}:${S}`);
  no('a form feed inside: it is not white space, so it is not removed and the link is malformed', good.slice(0, 60) + String.fromCodePoint(0x0c) + good.slice(60));
  no('a vertical tab at the end', good + String.fromCodePoint(0x0b));
  no('a NO-BREAK SPACE inside', good.slice(0, 60) + String.fromCodePoint(0xa0) + good.slice(60));
  return { compose, parse };
}

// ---- offers and answers in their envelopes ----

function envelopeRows(fx) {
  const d = fx.d;
  const other = deriveLink(fixed('links/secret/other'));
  const offerEnvelope = envelopeSeal(d.offerKey, nonce24('offer'), d.offerAd, fx.offer.frame);
  const answerEnvelope = envelopeSeal(d.answerKey, nonce24('answer'), d.answerAd, fx.answer.frame);
  const setupJson = buildStatement('setup-offer', { linkId: d.linkId, origin: X, instanceId: ids.instance, name: nameOf('Example Vault'), kind: 'private', recoveryFp: 'none', expiresAt: at(0) + DAY });
  const enrolJson = buildStatement('enrol-offer', { linkId: d.linkId, origin: X, instanceId: ids.instance, cardHash: fx.cards[1].hash, email: b64u(utf8('carol@example.com')), expiresAt: at(0) + DAY });
  const setupEnvelope = envelopeSeal(d.offerKey, nonce24('setup'), d.offerAd, utf8(setupJson));
  const enrolEnvelope = envelopeSeal(d.offerKey, nonce24('enrol'), d.offerAd, utf8(enrolJson));

  const seal = [
    { name: 'connect-offer', why: 'Envelope(offerKey, the signed 0x06 frame, AD = "andvari/v2|link-offer|" + linkId)', keyB64: b64u(d.offerKey), nonceB64: b64u(nonce24('offer')), adUtf8: d.offerAd, plaintextB64: b64u(fx.offer.frame), envelopeB64: b64u(offerEnvelope) },
    { name: 'answer', why: 'Envelope(answerKey, the signed 0x07 frame, AD = "andvari/v2|link-answer|" + linkId)', keyB64: b64u(d.answerKey), nonceB64: b64u(nonce24('answer')), adUtf8: d.answerAd, plaintextB64: b64u(fx.answer.frame), envelopeB64: b64u(answerEnvelope) },
    { name: 'setup-offer', why: 'the setup offer: canonical JSON with no frame and no signature, authenticated only by the AEAD', keyB64: b64u(d.offerKey), nonceB64: b64u(nonce24('setup')), adUtf8: d.offerAd, plaintextB64: b64u(utf8(setupJson)), plaintextUtf8: setupJson, envelopeB64: b64u(setupEnvelope) },
    { name: 'enrol-offer', why: 'an enrol offer bound to an address', keyB64: b64u(d.offerKey), nonceB64: b64u(nonce24('enrol')), adUtf8: d.offerAd, plaintextB64: b64u(utf8(enrolJson)), plaintextUtf8: enrolJson, envelopeB64: b64u(enrolEnvelope) },
  ];
  const open = [];
  const tryOpen = (name, opens, why, key, ad, envelope) => {
    if ((envelopeOpen(key, ad, envelope) !== null) !== opens) throw new Error('links envelope fixture: ' + name);
    open.push({ name, why, keyB64: b64u(key), adUtf8: ad, envelopeB64: b64u(envelope), expect: { opens } });
  };
  tryOpen('offer-under-its-key-and-ad', true, 'The offer opens under the link\'s offer key and AD.', d.offerKey, d.offerAd, offerEnvelope);
  tryOpen('offer-under-another-link-id', false, 'AD binding: the right key with another link\'s id in the AD.', d.offerKey, other.offerAd, offerEnvelope);
  tryOpen('offer-of-another-link', false, 'Swapped link ids: the server serves this link\'s offer on another link; the recipient derives the other link\'s key and AD.', other.offerKey, other.offerAd, offerEnvelope);
  tryOpen('offer-under-the-answer-key', false, 'The offer and the answer have separate keys.', d.answerKey, d.offerAd, offerEnvelope);
  tryOpen('offer-under-the-answer-ad', false, 'The offer and the answer have separate ADs.', d.offerKey, d.answerAd, offerEnvelope);
  tryOpen('answer-under-its-key-and-ad', true, 'The answer opens under the link\'s answer key and AD.', d.answerKey, d.answerAd, answerEnvelope);
  tryOpen('answer-as-an-offer', false, 'An answer served where the offer belongs.', d.offerKey, d.offerAd, answerEnvelope);
  tryOpen('answer-of-another-link', false, 'Swapped link ids for the answer.', other.answerKey, other.answerAd, answerEnvelope);
  return { seal, open, offerEnvelope, answerEnvelope, setupJson, enrolJson, setupEnvelope, enrolEnvelope };
}

// ---- the recipient ----

function recipientRows(fx, env) {
  const rows = [];
  const names = new Set();
  const d = fx.d;
  const link = composeLink({ origin: X, secret: fx.secret, f: fx.f });
  const hostLink = composeLink({ origin: X, secret: fx.secret, f: '-' });
  const now = at(1);
  const cards = fx.cards.map((c) => c.frame);
  const body = (overrides = {}) => ({
    kind: 'connect', offer: b64u(env.offerEnvelope), expiresAt: fx.offerValues.expiresAt, state: 'open',
    creatorUserId: alice.userId, creatorIdentityPub: alice.key, reveal: null, ...overrides,
  });
  const hostBody = (kind, envelope, expiresAt = at(0) + DAY) => ({ kind, offer: b64u(envelope), expiresAt, state: 'open', creatorUserId: null, creatorIdentityPub: null, reveal: null });
  const sealOffer = (label, plaintext, key = d.offerKey, ad = d.offerAd) => b64u(envelopeSeal(key, nonce24('recipient/' + label), ad, plaintext));
  const flip = (frame) => {
    const out = frame.slice();
    out[37 + 10] ^= 0x01;
    return out;
  };

  const sameFrames = (a, b) => a.length === b.length && a.every((frame, i) => b64u(frame) === b64u(b[i]));
  const add = (name, verdict, why, input, expectExtra = {}) => {
    const full = { link, now, server: { status: 200, body: body() }, cards, pin: null, contacts: {}, baked: null, ...input };
    const result = openLink(full);
    if (result.verdict !== verdict) throw new Error(`links recipient "${name}": the design says ${verdict}, the oracle says ${result.verdict}`);
    if (names.has(name)) throw new Error('links: duplicate recipient row ' + name);
    names.add(name);
    const expect = { verdict };
    if (verdict === 'ok') {
      expect.kind = result.kind;
      if (result.from) Object.assign(expect, { from: result.from, fromKey: result.fromKey, name: result.name, offerHash: result.offerHash, pinned: result.pinned, keyChanged: result.keyChanged });
      if (result.pinRoot !== undefined) expect.pinRoot = result.pinRoot;
    }
    // pinRoot is stated on the ok rows of a link to the origin the build bakes, and on no other row.
    const toBakedOrigin = full.baked !== null && parseLink(full.link)?.origin === full.baked.origin;
    if ((expect.pinRoot !== undefined) !== (verdict === 'ok' && toBakedOrigin)) throw new Error(`links recipient "${name}": pinRoot belongs on the ok rows at the baked origin only`);
    for (const [k, v] of Object.entries(expectExtra)) if (JSON.stringify(expect[k]) !== JSON.stringify(v)) throw new Error(`links recipient "${name}": expected ${k} = ${JSON.stringify(v)}`);
    const chainName = Object.keys(fx.chains).find((chain) => sameFrames(fx.chains[chain].map((c) => c.frame), full.cards));
    if (chainName === undefined) throw new Error(`links recipient "${name}": the chain it is served is not one of cardChains`);
    // `baked` is written only on the rows that give it: the others open a link to an origin no build bakes.
    rows.push({ name, why, link: full.link, now: full.now, server: full.server, cards: chainName, pin: full.pin, ...(full.baked ? { baked: full.baked } : {}), contacts: full.contacts, expect });
  };
  const offerWith = (signer, overrides) => signed('link-offer', signer, { ...fx.offerValues, ...overrides });
  const served = (label, frameOrBytes, bodyOverrides = {}) => ({ server: { status: 200, body: body({ offer: sealOffer(label, frameOrBytes), ...bodyOverrides }) } });

  // ---- accepted ----
  add('connect', 'ok', 'bob opens alice\'s connect link: the offer opens, is hers (F), names this link and origin, has not expired, matches what the server reports, and its cardHash is in the served chain.', {}, { kind: 'connect', keyChanged: false });
  const registerOffer = offerWith(alice, { kind: 'register', expiresAt: at(0) + 3 * DAY });
  add('register', 'ok', 'A register link: the same checks, kind register.', served('register', registerOffer.frame, { kind: 'register', expiresAt: at(0) + 3 * DAY }), { kind: 'register' });
  add('setup', 'ok', 'A setup link: host JSON, F is "-", and the instance serves no card yet.', { link: hostLink, cards: [], server: { status: 200, body: hostBody('setup', env.setupEnvelope) } }, { kind: 'setup' });
  add('enrol', 'ok', 'An enrol link: host JSON, F is "-". (Its cardHash is the host\'s own claim and never a pin root; the Trust Gate or the baked root pins the origin.)', { link: hostLink, server: { status: 200, body: hostBody('enrol', env.enrolEnvelope) } }, { kind: 'enrol' });
  add('known-contact-same-key', 'ok', 'alice is already a contact with this key: nothing to prompt.', { contacts: { [alice.userId]: alice.key } }, { keyChanged: false });
  add('known-contact-another-key', 'ok', 'alice is already a contact with ANOTHER key. Every check passes, and the result carries the key_changed prompt, which is not a verdict: nothing is replaced until a comparison code matches.', { contacts: { [alice.userId]: carol.key } }, { keyChanged: true });

  // ---- the link and the server's answer ----
  add('link-does-not-parse', 'bad_link', 'The link has three parts.', { link: link.slice(0, link.lastIndexOf('.')) });
  add('server-404', 'link_unknown', 'GET /links/{linkId} answers 404: unknown or revoked.', { server: { status: 404, body: null } });
  add('server-410', 'link_expired', 'GET /links/{linkId} answers 410: an open link past its expiry.', { server: { status: 410, body: null } });
  add('server-answered', 'link_used', 'The link was answered by someone else: the server answers 200 with state answered and no offer; the app shows "already used".', { server: { status: 200, body: { kind: 'connect', state: 'answered', reveal: null } } });

  // ---- the envelope ----
  const other = deriveLink(fixed('links/secret/other'));
  add('offer-of-another-link', 'unopenable', 'Swapped link ids: the server serves the offer of another link.', { server: { status: 200, body: body({ offer: sealOffer('other-link', fx.offer.frame, other.offerKey, other.offerAd) }) } });
  add('offer-under-another-ad', 'unopenable', 'The offer was sealed with another link id in its AD.', { server: { status: 200, body: body({ offer: sealOffer('other-ad', fx.offer.frame, d.offerKey, other.offerAd) }) } });
  add('offer-sealed-under-the-answer-key', 'unopenable', 'An envelope made under the answer key.', { server: { status: 200, body: body({ offer: sealOffer('answer-key', fx.offer.frame, d.answerKey, d.offerAd) }) } });
  add('offer-truncated', 'unopenable', 'An envelope of 30 bytes.', { server: { status: 200, body: body({ offer: b64u(env.offerEnvelope.slice(0, 30)) }) } });

  // ---- recognising what opened (§6.4) ----
  add('plaintext-is-neither', 'unknown_format', 'The envelope opens to bytes that start with neither the frame magic nor {.', served('neither', utf8('hello, world')));
  const version3 = fx.offer.frame.slice();
  version3[3] = 0x03;
  add('frame-of-another-format', 'unknown_format', 'The envelope opens to a frame with format byte 0x03.', served('version3', version3));
  add('host-json-with-another-purpose', 'unknown_format', 'VR-15: a { plaintext whose purpose is neither setup-offer nor enrol-offer (here the bare statement of a link offer).', { link: hostLink, server: { status: 200, body: { ...hostBody('enrol', utf8('')), offer: sealOffer('json-other-purpose', utf8(fx.offer.statement)) } } });
  add('signed-frame-on-a-host-link', 'kind_mismatch', 'kind_mismatch from the form alone: the server reports kind enrol, the envelope opens to a signed frame.', served('frame-on-host', fx.offer.frame, { kind: 'enrol' }));
  add('host-json-on-a-connect-link', 'kind_mismatch', 'kind_mismatch from the form alone: the server reports kind connect, the envelope opens to host JSON.', served('json-on-connect', utf8(env.enrolJson)));
  add('register-offer-on-a-connect-link', 'kind_mismatch', 'The signed offer\'s own kind is register, the server reports connect: checked right after the strict parse.', served('register-on-connect', registerOffer.frame));
  add('setup-offer-on-an-enrol-link', 'kind_mismatch', 'The host JSON is a setup offer, the server reports enrol.', { link: hostLink, cards: [], server: { status: 200, body: hostBody('enrol', env.setupEnvelope) } });

  // ---- the parse ----
  add('answer-frame-as-the-offer', 'bad_frame', 'The envelope opens to a signed 0x07 frame: a signed frame here must be purpose 0x06.', served('answer-frame', fx.answer.frame));
  add('offer-not-canonical', 'non_canonical', 'A signed offer with a space after a colon.', served('space', signedRaw(OFFER, alice, fx.offer.statement.replace('"kind":', '"kind": ')).frame));
  add('offer-version-3', 'bad_statement', 'A signed, canonical offer with "v":3.', served('v3', signedRaw(OFFER, alice, rawStatement(withToken(tokens('link-offer', fx.offerValues), 'v', '3'))).frame));
  add('host-json-not-canonical', 'non_canonical', 'An enrol offer with a space after a colon.', { link: hostLink, server: { status: 200, body: { ...hostBody('enrol', utf8('')), offer: sealOffer('json-space', utf8(env.enrolJson.replace('"origin":', '"origin": '))) } } });
  add('host-json-purpose-is-a-number', 'non_canonical', 'VR-15: a JSON object whose purpose is not a string.', { link: hostLink, server: { status: 200, body: { ...hostBody('enrol', utf8('')), offer: sealOffer('json-purpose-number', utf8('{"v":2,"purpose":7}')) } } });
  add('host-json-is-not-json', 'non_canonical', 'A plaintext that starts with { but is not JSON.', { link: hostLink, server: { status: 200, body: { ...hostBody('enrol', utf8('')), offer: sealOffer('json-broken', utf8('{"v":2,"purpose":"enrol-offer"')) } } });
  add('host-json-version-3', 'bad_statement', 'A canonical enrol offer with "v":3.', { link: hostLink, server: { status: 200, body: { ...hostBody('enrol', utf8('')), offer: sealOffer('json-v3', utf8(env.enrolJson.replace('"v":2', '"v":3'))) } } });

  // ---- host JSON is RFC 8259 exactly (§2.4): what is not a JSON object with a string purpose is
  //      non_canonical, and only a well-formed object with a foreign purpose is unknown_format ----
  const BS = String.fromCharCode(92); // a backslash, so that an escape can be spelled in a fixture
  const hostJson = (label, text) => ({ link: hostLink, server: { status: 200, body: { ...hostBody('enrol', utf8('')), offer: sealOffer('rfc8259/' + label, utf8(text)) } } });
  const nest = (arrays) => '{"v":2,"purpose":"other-offer","x":' + '['.repeat(arrays) + ']'.repeat(arrays) + '}';
  add('host-json-foreign-purpose', 'unknown_format', 'A well-formed JSON object whose purpose is neither setup-offer nor enrol-offer.', hostJson('foreign', '{"v":2,"purpose":"other-offer"}'));
  add('host-json-foreign-purpose-with-white-space', 'unknown_format', 'The same with white space between its tokens: RFC 8259 allows it, so the object is recognised and its purpose is foreign. (White space matters only to a template\'s own strict parse.)', hostJson('foreign-ws', '{ "v" : 2 , "purpose" : "other-offer" }'));
  add('host-json-bare-token', 'non_canonical', 'A bare token as a value: not RFC 8259. A lenient library parser that reads it would go on to the foreign purpose and answer unknown_format.', hostJson('bare', '{"v":2,"purpose":"other-offer","x":bare}'));
  add('host-json-nan', 'non_canonical', 'NaN is not a JSON value.', hostJson('nan', '{"v":2,"purpose":"other-offer","x":NaN}'));
  add('host-json-trailing-comma', 'non_canonical', 'A trailing comma.', hostJson('comma', '{"v":2,"purpose":"other-offer",}'));
  add('host-json-trailing-bytes', 'non_canonical', 'Bytes after the object.', hostJson('trailing', '{"v":2,"purpose":"other-offer"}x'));
  add('host-json-second-object', 'non_canonical', 'A second object after the first.', hostJson('second', '{"v":2,"purpose":"other-offer"}{}'));
  add('host-json-key-twice', 'non_canonical', 'A key that appears twice at the top level.', hostJson('twice', '{"v":2,"purpose":"other-offer","v":2}'));
  add('host-json-purpose-twice-valid-last', 'non_canonical', 'purpose twice, a foreign one first and enrol-offer last: refused whichever value comes last.', hostJson('purpose-twice-a', '{"v":2,"purpose":"other-offer","purpose":"enrol-offer"}'));
  add('host-json-purpose-twice-foreign-last', 'non_canonical', 'purpose twice, enrol-offer first and a foreign one last.', hostJson('purpose-twice-b', '{"v":2,"purpose":"enrol-offer","purpose":"other-offer"}'));
  add('host-json-escaped-purpose-key', 'unknown_format', 'The key purpose spelled with an escape (' + BS + 'u0070urpose): it is the same key, so this is a JSON object with a string purpose, and that purpose is foreign.', hostJson('escaped-key', '{"v":2,"' + BS + 'u0070urpose":"other-offer"}'));
  add('host-json-escaped-purpose-key-twice', 'non_canonical', 'purpose once plainly and once spelled with an escape: the same key twice.', hostJson('escaped-twice', '{"v":2,"purpose":"other-offer","' + BS + 'u0070urpose":"enrol-offer"}'));
  add('host-json-escaped-purpose-key-in-an-enrol-offer', 'non_canonical', 'A whole enrol offer whose purpose key is spelled with an escape: it is recognised as an enrol offer, and then the template\'s re-encode compare refuses it.', hostJson('escaped-enrol', env.enrolJson.replace('"purpose"', '"' + BS + 'u0070urpose"')));
  add('host-json-nest-32', 'unknown_format', 'Exactly 32 containers open at once (the outer object and 31 arrays inside one another): allowed, so the foreign purpose decides.', hostJson('nest-32', nest(31)));
  add('host-json-nest-33', 'non_canonical', '33 containers open at once (the outer object and 32 arrays): deeper than 32.', hostJson('nest-33', nest(32)));
  add('host-json-no-purpose', 'non_canonical', 'A JSON object with no purpose.', hostJson('no-purpose', '{"v":2}'));
  add('host-json-purpose-null', 'non_canonical', 'purpose is null, not a string.', hostJson('purpose-null', '{"v":2,"purpose":null}'));
  add('host-json-leading-space', 'unknown_format', 'An enrol offer with a space in front: the plaintext starts with neither the frame magic nor {, so it is not host JSON at all.', hostJson('leading-space', ' ' + env.enrolJson));
  add('host-json-array', 'unknown_format', 'A JSON array holding an enrol offer: it does not start with {.', hostJson('array', '[' + env.enrolJson + ']'));

  // ---- the helper: F, signer, signature ----
  const evesOffer = offerWith(eve, { from: eve.userId, fromKey: eve.key, name: nameOf('Alice') });
  add('offer-under-another-key', 'creator_mismatch', 'T-B6: someone who learned the secret swapped in an offer under their own key (eve\'s, validly signed, calling herself Alice). The offer\'s fromKey does not hash to the link\'s F.', served('eve', evesOffer.frame, { creatorUserId: eve.userId, creatorIdentityPub: eve.key }));
  add('signed-offer-on-a-link-without-f', 'creator_mismatch', 'A connect offer behind a link whose F is "-": a signed offer needs a fingerprint.', { link: hostLink });
  add('host-json-on-a-link-with-f', 'creator_mismatch', 'An enrol offer behind a link that carries a creator fingerprint: F must be "-" for host-minted links.', { server: { status: 200, body: hostBody('enrol', env.enrolEnvelope) } });
  add('offer-signed-by-another-key', 'signer_not_pinned_key', 'The offer names alice and her key (which matches F), but eve signed it: the signer does not map to fromKey.', served('eve-signs', signed('link-offer', eve, fx.offerValues).frame));
  add('offer-signature-flipped', 'bad_signature', 'alice\'s offer with one signature bit flipped.', served('flipped', flip(fx.offer.frame)));
  const changedName = fx.offer.statement.replace(nameOf('Alice'), nameOf('Alicf'));
  add('offer-changed-after-signing', 'bad_signature', 'The name changed after signing (still canonical).', served('changed', assembleFrame(OFFER, fx.offer.signerPub, fx.offer.signature, utf8(changedName))));

  // ---- the fields ----
  add('offer-names-another-link', 'link_mismatch', 'alice signed an offer whose linkId is another link\'s; it sits in this link\'s envelope.', served('other-link-id', offerWith(alice, { linkId: other.linkId }).frame));
  add('offer-names-another-origin', 'origin_mismatch', 'The offer\'s origin is not the origin in the link.', served('other-origin', offerWith(alice, { origin: 'https://other.example.org' }).frame));
  add('offer-expired', 'offer_expired', 'now is past the offer\'s expiresAt (the server still served it as open).', { now: fx.offerValues.expiresAt + 1 });
  add('offer-expires-now', 'offer_expired', 'now equals expiresAt: the rule is expiresAt > now.', { now: fx.offerValues.expiresAt });
  add('server-reports-another-creator', 'reported_creator_mismatch', 'The server reports another creatorUserId than the offer\'s from.', { server: { status: 200, body: body({ creatorUserId: carol.userId }) } });
  add('server-reports-another-key', 'reported_creator_mismatch', 'The server reports another creatorIdentityPub than the offer\'s fromKey.', { server: { status: 200, body: body({ creatorIdentityPub: carol.key }) } });
  add('host-json-names-another-link', 'link_mismatch', 'An enrol offer whose linkId is another link\'s.', { link: hostLink, server: { status: 200, body: { ...hostBody('enrol', utf8('')), offer: sealOffer('json-other-link', utf8(env.enrolJson.replace(d.linkId, other.linkId))) } } });
  add('host-json-names-another-origin', 'origin_mismatch', 'A setup offer whose origin is not the link\'s.', { link: hostLink, cards: [], server: { status: 200, body: { ...hostBody('setup', utf8('')), offer: sealOffer('json-other-origin', utf8(env.setupJson.replace(X, 'https://other.example.org'))) } } });
  add('host-json-expired', 'offer_expired', 'A setup offer past its expiresAt.', { link: hostLink, cards: [], now: at(0) + DAY + 1, server: { status: 200, body: hostBody('setup', env.setupEnvelope) } });

  // ---- pinning ----
  add('card-not-in-chain', 'card_not_in_chain', 'The served chain does not contain the offer\'s cardHash (it ends one card earlier).', { cards: cards.slice(0, 1) });
  add('offer-names-another-instance', 'instance_mismatch', 'The offer\'s cardHash is in the served chain, under another instanceId than the offer names.', served('other-instance', offerWith(alice, { instanceId: ids.otherInstance }).frame));
  add('chain-forks-from-the-pin', 'fork', 'This device already pins a card for that origin, from another chain: the served chain contains the offer\'s card but does not extend the pin.',
    { pin: { card0Hash: fx.otherCards[0].hash, seq: 0, hash: fx.otherCards[0].hash } });
  add('chain-extends-the-pin', 'ok', 'This device already pins card 0 of the same chain.', { pin: { card0Hash: fx.cards[0].hash, seq: 0, hash: fx.cards[0].hash } });
  const moved = fx.movedCards.map((c) => c.frame);
  const pinAtCard1 = { card0Hash: fx.cards[0].hash, seq: 1, hash: fx.cards[1].hash };
  add('no-card-served', 'withheld', 'The link\'s origin serves no card at all: an empty chain is withheld for every root, a link offer included.', { cards: [] });
  add('chain-names-another-origin', 'origin_mismatch', 'The pinning origin_mismatch, not the field check: the offer names the link\'s origin, and its cardHash is in the served chain under its instanceId, but the chain\'s newest card names another origin than the one this device dialed. Cards are public, so a look-alike address can serve the real instance\'s genuine chain; a device with no pin refuses.', { cards: moved });
  add('chain-withheld-below-the-pin', 'withheld', 'This device pins card 1; the served chain ends at card 0. The chain is compared with the existing pin first and anything but ok stops: withheld. (Without the pin the same chain is card_not_in_chain.)', { cards: cards.slice(0, 1), pin: pinAtCard1 });
  add('setup-on-an-instance-that-is-set-up', 'already_set_up', 'A setup link opened on an instance that already serves cards.', { link: hostLink, server: { status: 200, body: hostBody('setup', env.setupEnvelope) } });
  add('enrol-no-card-served', 'withheld', 'An enrol link is not a root: its origin is pinned as a typed address, behind the Trust Gate, and an empty chain is withheld for every root.', { link: hostLink, cards: [], server: { status: 200, body: hostBody('enrol', env.enrolEnvelope) } });
  add('enrol-chain-names-another-origin', 'origin_mismatch', 'An enrol link whose origin serves a chain that names another origin in its newest card: the Trust Gate would otherwise show another instance\'s name and key for this address.', { link: hostLink, cards: moved, server: { status: 200, body: hostBody('enrol', env.enrolEnvelope) } });

  // ---- the order: two things wrong at once ----
  add('order-form-kind-before-parse', 'kind_mismatch', 'A signed frame that is not canonical, on a link the server reports as enrol: the form decides before any parse.', served('order-1', signedRaw(OFFER, alice, fx.offer.statement.replace('"kind":', '"kind": ')).frame, { kind: 'enrol' }));
  add('order-parse-before-own-kind', 'non_canonical', 'A register offer that is not canonical, on a connect link.', served('order-2', signedRaw(OFFER, alice, registerOffer.statement.replace('"kind":', '"kind": ')).frame));
  add('order-own-kind-before-creator', 'kind_mismatch', 'eve\'s register offer on alice\'s connect link.', served('order-3', offerWith(eve, { kind: 'register', from: eve.userId, fromKey: eve.key }).frame));
  add('order-creator-before-signer', 'creator_mismatch', 'An offer that names eve\'s key and was signed by carol.', served('order-4', offerWith(carol, { from: eve.userId, fromKey: eve.key }).frame));
  add('order-signer-before-signature', 'signer_not_pinned_key', 'Signed by eve, with the signature broken as well.', served('order-5', flip(signed('link-offer', eve, fx.offerValues).frame)));
  add('order-signature-before-fields', 'bad_signature', 'The helper\'s checks run before the field checks: another linkId under a broken signature.', served('order-6', flip(offerWith(alice, { linkId: other.linkId }).frame)));
  add('order-link-before-origin', 'link_mismatch', 'Another linkId and another origin.', served('order-7', offerWith(alice, { linkId: other.linkId, origin: 'https://other.example.org' }).frame));
  add('order-origin-before-expiry', 'origin_mismatch', 'Another origin, and expired.', { ...served('order-8', offerWith(alice, { origin: 'https://other.example.org' }).frame), now: fx.offerValues.expiresAt + 1 });
  add('order-expiry-before-reported-creator', 'offer_expired', 'Expired, and the server reports another creator.', { now: fx.offerValues.expiresAt + 1, server: { status: 200, body: body({ creatorUserId: carol.userId }) } });
  add('order-reported-creator-before-pinning', 'reported_creator_mismatch', 'The server reports another creator, and the chain lacks the offer\'s card.', { cards: cards.slice(0, 1), server: { status: 200, body: body({ creatorUserId: carol.userId }) } });
  add('order-host-kind-before-the-template-parse', 'kind_mismatch', 'A setup offer that is not canonical (a space after a colon), on a link the server reports as enrol. The purpose is recognised before the template is parsed, so kind_mismatch is known first.',
    { link: hostLink, cards: [], server: { status: 200, body: { ...hostBody('enrol', utf8('')), offer: sealOffer('order-11', utf8(env.setupJson.replace('"origin":', '"origin": '))) } } });
  add('order-host-kind-before-the-template-parse-enrol', 'kind_mismatch', 'The other way round: an enrol offer with "v":3 on a link the server reports as setup.',
    { link: hostLink, cards: [], server: { status: 200, body: { ...hostBody('setup', utf8('')), offer: sealOffer('order-12', utf8(env.enrolJson.replace('"v":2', '"v":3'))) } } });
  add('order-pin-before-the-offer-root', 'fork', 'This device pins a card of another chain, and the served chain lacks the offer\'s card: the comparison with the existing pin comes first, so fork, not card_not_in_chain.',
    { cards: cards.slice(0, 1), pin: { card0Hash: fx.otherCards[0].hash, seq: 0, hash: fx.otherCards[0].hash } });
  add('order-origin-before-card-not-in-chain', 'origin_mismatch', 'The served chain names another origin in its newest card, and the offer names a card it does not hold: origin_mismatch comes first.', { ...served('order-10', offerWith(alice, { cardHash: fx.otherCards[1].hash }).frame), cards: moved });
  add('order-expiry-before-already-set-up', 'offer_expired', 'A setup offer past its expiresAt, on an instance that already serves cards: the field checks come before the pinning step.', { link: hostLink, now: at(0) + DAY + 1, server: { status: 200, body: hostBody('setup', env.setupEnvelope) } });
  add('order-envelope-before-format', 'unopenable', 'An unopenable envelope on a link the server reports as enrol.', { server: { status: 200, body: body({ kind: 'enrol', offer: sealOffer('order-9', fx.offer.frame, other.offerKey, other.offerAd) }) } });

  // ---- an enrol link to the public instance, opened by a build that bakes it (§6.8 step 5, §4.4) ----
  // The offer names the public instance's own id and newest card. An enrol offer's cardHash and
  // instanceId are the host's claim and pin nothing, and the design gives no check of them against
  // the served chain: on every ok row here they agree with it, and on every other row a check that
  // comes earlier in §2.4's order decides, so no row rests on what an engine makes of them.
  const publicLink = composeLink({ origin: P, secret: fx.secret, f: '-' });
  const publicEnrolJson = buildStatement('enrol-offer', {
    linkId: d.linkId, origin: P, instanceId: fx.baked.instanceId, cardHash: fx.publicCards[1].hash, email: b64u(utf8('carol@example.com')), expiresAt: at(0) + DAY,
  });
  const publicEnrol = hostBody('enrol', envelopeSeal(d.offerKey, nonce24('recipient/enrol-public'), d.offerAd, utf8(publicEnrolJson)));
  const chainOf = (chain) => fx.chains[chain].map((c) => c.frame);
  const onPublic = (chain, extra = {}) => ({ link: publicLink, baked: fx.baked, cards: chainOf(chain), server: { status: 200, body: publicEnrol }, ...extra });
  const publicPin = (index) => ({ card0Hash: fx.publicCards[0].hash, seq: index, hash: fx.publicCards[index].hash });

  add('enrol-public-instance', 'ok', 'An enrol link whose origin is the one this build bakes (the public instance): the baked root pins it, in place of the typed-address rule and its Trust Gate. Card 0 of the served chain hashes to the baked card0Hash under the baked instanceId, and the newest card names the baked origin.',
    onPublic('public-both-cards'), { kind: 'enrol', pinRoot: 'baked' });
  add('enrol-public-instance-card-0-differs', 'card0_mismatch', 'The baked origin serves a chain whose card 0 names the baked instanceId and origin but does not hash to the baked card0Hash (a new chain after an operator reset, or another server answering for the address). Under the typed-address rule this chain would reach the Trust Gate; the baked root refuses it.',
    onPublic('public-other-card-0'));
  add('enrol-public-instance-id-differs', 'instance_mismatch', 'Card 0 hashes to the baked card0Hash, but this build bakes another instanceId: both baked constants must match. (Card 0 carries its instanceId, so only a build whose two constants disagree gets here.)',
    onPublic('public-both-cards', { baked: { ...fx.baked, instanceId: ids.instance } }));
  add('enrol-public-instance-both-differ', 'card0_mismatch', 'The baked origin serves another instance that names that origin as its own: neither card 0\'s hash nor its instanceId matches. card0_mismatch comes before instance_mismatch in the pinning order.',
    onPublic('public-impostor'));
  add('enrol-public-instance-no-card-served', 'withheld', 'The baked origin serves no card: a baked root against an empty chain is withheld.', onPublic('no-card'));
  add('enrol-public-instance-serves-another-chain', 'origin_mismatch', 'The baked origin serves another instance\'s genuine chain, whose cards name that instance\'s own origin. origin_mismatch comes first, before card0_mismatch and instance_mismatch, which this chain would fail too.',
    onPublic('both-cards'));
  add('enrol-public-instance-newest-card-names-another-origin', 'origin_mismatch', 'The public instance\'s own chain (card 0 matches both baked constants), with a newest card that names another origin than the baked one this device dialed. A first pin never follows a card to another address.',
    onPublic('public-moved'));
  add('enrol-public-instance-chain-extends-the-pin', 'ok', 'This device already pins card 0 of the public instance\'s chain: the served chain extends the pin, and the baked root holds.',
    onPublic('public-both-cards', { pin: publicPin(0) }), { kind: 'enrol', pinRoot: 'baked' });
  add('enrol-public-instance-withheld-below-the-pin', 'withheld', 'This device pins card 1 of the public instance\'s chain; the baked origin serves card 0 only. The chain is compared with the existing pin first and anything but ok stops: withheld. (Without the pin the baked root passes this chain.)',
    onPublic('public-card-0-only', { pin: publicPin(1) }));
  add('order-pin-before-the-baked-root', 'fork', 'This device pins card 1 of the public instance\'s chain, and the baked origin serves another card 0: the comparison with the existing pin comes first, so fork, not card0_mismatch.',
    onPublic('public-other-card-0', { pin: publicPin(1) }));
  add('order-expiry-before-the-baked-root', 'offer_expired', 'An enrol offer past its expiresAt, on a baked origin that serves another card 0: the field checks come before the pinning step.',
    onPublic('public-other-card-0', { now: at(0) + DAY + 1 }));
  add('enrol-another-origin-on-a-build-that-bakes', 'ok', 'The link and chain of the row `enrol`, opened by a build that bakes the public instance. The link\'s origin is not the baked one, so the baked root has no say: the typed-address rule, then the Trust Gate. (The served card 0 is not the baked one, and need not be.)',
    { link: hostLink, baked: fx.baked, server: { status: 200, body: hostBody('enrol', env.enrolEnvelope) } }, { kind: 'enrol' });

  // ---- a very deep host offer (§2.4, the host JSON row): the 32-container limit is decided on the
  //      bytes, or by a parser that stops at the limit, before any general JSON parser sees the text.
  //      These are the deepest texts an offer can carry: one more array would not fit the envelope. ----
  const envelopeBytes = (plaintextLength) => plaintextLength + ENVELOPE_OVERHEAD;
  const fitsAnOffer = (plaintextLength) => envelopeBytes(plaintextLength) <= OFFER_MAX_BYTES && Math.ceil((envelopeBytes(plaintextLength) * 4) / 3) <= OFFER_MAX_CHARS;
  const deepText = (prefix, arrays) => prefix + '['.repeat(arrays) + ']'.repeat(arrays) + '}';
  /** The most arrays, one inside another, that `prefix` can open and close again inside an offer envelope. */
  const deepest = (prefix) => {
    let arrays = 0;
    while (fitsAnOffer(deepText(prefix, arrays + 1).length)) arrays++;
    return arrays;
  };
  const deepRow = (name, prefix, arrays, why) => {
    if (deepest(prefix) !== arrays) throw new Error(`links recipient "${name}": ${deepest(prefix)} arrays is the most this text can hold in an offer`);
    if (arrays + 1 <= HOST_JSON_MAX_DEPTH) throw new Error(`links recipient "${name}": not deeper than the limit`);
    const input = hostJson(name, deepText(prefix, arrays));
    const offer = input.server.body.offer;
    // The envelope is 2,048 bytes, 2,731 characters: one byte and one character under the cap of
    // 2,049 bytes and 2,732 characters (§6.3, §6.6), and one more array would add two bytes.
    if (mustUnb64u(offer).length !== OFFER_MAX_BYTES - 1 || offer.length !== OFFER_MAX_CHARS - 1) throw new Error(`links recipient "${name}": the envelope must be as large as this text can make it under the cap`);
    add(name, 'non_canonical', why, input);
  };
  const foreignPrefix = '{"v":2,"purpose":"other-offer","x":';
  if (deepText(foreignPrefix, 31) !== nest(31)) throw new Error('links: the deep host offer must be the text of the nest-32 and nest-33 rows');
  deepRow('host-json-nest-986', foreignPrefix, 985,
    'The text of host-json-nest-32 and host-json-nest-33 with 986 containers open at once (the outer object and 985 arrays inside one another): as deep as that text can go in an offer, whose envelope is then exactly 2,048 bytes, 2,731 of the 2,732 characters allowed. It is refused for its depth, on the bytes or by a parser that stops at the limit, before any general JSON parser sees it: a parser that recurses once per level can be made to overflow its stack by this text, and that is a crash, not a verdict. (A parser that read all of it would find a purpose the client does not recognise and answer unknown_format.)');
  deepRow('host-json-nest-986-enrol-offer', '{"v":2,"purpose":"enrol-offer","x":', 985,
    'The same depth behind a purpose the client recognises: {"v":2,"purpose":"enrol-offer","x": and then 985 arrays inside one another, on a link the server reports as enrol. Still non_canonical: a recognisable purpose at the front does not carry a text past the depth limit, and no look-ahead for the purpose may hand this text to a general JSON parser either.');
  deepRow('host-json-nest-1001-no-purpose', '{"x":', 1000,
    'A thousand open brackets: {"x": and then 1,000 arrays inside one another, so 1,001 containers open at once, and no purpose anywhere. non_canonical, for the depth alone and before anything looks for a purpose. With a key this short the envelope holds exactly a thousand arrays.');

  // ---- a connect, register or setup link to the public instance, opened by a build that bakes it.
  //      At the baked origin the baked root always comes first, whatever the kind of link (§4.4,
  //      §6.8 step 5); then a connect or register link adds its own check, and a setup link is refused. ----
  /** What a build that bakes nothing answers for the same input: the link's own check, on its own. */
  const withoutBaked = (input) => openLink({ link, now, server: { status: 200, body: body() }, cards, pin: null, contacts: {}, ...input, baked: null }).verdict;
  const expectWithoutBaked = (name, input, verdict) => {
    if (withoutBaked(input) !== verdict) throw new Error(`links recipient "${name}": on a build that bakes nothing the row should be ${verdict}, the oracle says ${withoutBaked(input)}`);
  };
  const otherCard0 = fx.chains['public-other-card-0'][0];
  const publicConnectLink = composeLink({ origin: P, secret: fx.secret, f: fx.f });
  const publicOfferValues = { ...fx.offerValues, origin: P, instanceId: fx.baked.instanceId, cardHash: fx.publicCards[1].hash };
  const publicRegisterValues = { ...publicOfferValues, kind: 'register', expiresAt: at(0) + 3 * DAY };
  const sealedPublic = (label, values, bodyOverrides = {}) => ({ status: 200, body: body({ offer: sealOffer('public/' + label, signed('link-offer', alice, values).frame), ...bodyOverrides }) });
  const registerBody = { kind: 'register', expiresAt: at(0) + 3 * DAY };
  // The offers these rows are served: one sealed envelope each, shared by the rows that use it.
  const publicConnect = sealedPublic('connect', publicOfferValues);
  const publicConnectOtherCard0 = sealedPublic('connect-other-card-0', { ...publicOfferValues, cardHash: otherCard0.hash });
  const publicConnectOtherInstance = sealedPublic('connect-other-instance', { ...publicOfferValues, instanceId: ids.instance });
  const publicRegister = sealedPublic('register', publicRegisterValues, registerBody);
  const publicRegisterOtherCard0 = sealedPublic('register-other-card-0', { ...publicRegisterValues, cardHash: otherCard0.hash }, registerBody);
  const signedOnPublic = (chain, server, extra = {}) => ({ link: publicConnectLink, baked: fx.baked, cards: chainOf(chain), server, ...extra });
  const pinnedAtPublicCard1 = { seq: 1, hash: fx.publicCards[1].hash };

  let row = signedOnPublic('public-both-cards', publicConnect);
  add('connect-public-instance', 'ok', 'A connect link whose origin is the one this build bakes (the public instance). The baked root comes first, whatever started the connection: card 0 of the served chain hashes to the baked card0Hash under the baked instanceId, and the newest card names the baked origin. Then the link adds its own check on top: the chain holds the offer\'s cardHash under the offer\'s instanceId. The pin records root baked (expect.pinRoot), not link_offer: the build, not the link, vouches for the instance. No Trust Gate is shown.',
    row, { kind: 'connect', keyChanged: false, pinned: pinnedAtPublicCard1, pinRoot: 'baked' });
  expectWithoutBaked('connect-public-instance', row, 'ok');

  row = signedOnPublic('public-other-card-0', publicConnectOtherCard0);
  add('connect-public-instance-card-0-differs', 'card0_mismatch', 'The baked origin serves a chain whose card 0 does not hash to the baked card0Hash (a new chain after an operator reset, or another server answering for the address), and the link was made against that chain: the offer\'s cardHash is in it, under the offer\'s instanceId, so the link\'s own check would pass, and on a build that bakes nothing this link opens. The baked checks run first and refuse it.',
    row);
  expectWithoutBaked('connect-public-instance-card-0-differs', row, 'ok');

  row = signedOnPublic('public-both-cards', publicConnect, { baked: { ...fx.baked, instanceId: ids.instance } });
  add('connect-public-instance-id-differs', 'instance_mismatch', 'Card 0 hashes to the baked card0Hash, but this build bakes another instanceId: instance_mismatch, from the baked root. The offer names the chain\'s own instanceId and a card of the chain, so the link\'s own check would pass. (Card 0 carries its instanceId, so only a build whose two constants disagree gets here.)',
    row);
  expectWithoutBaked('connect-public-instance-id-differs', row, 'ok');

  row = signedOnPublic('public-card-0-only', publicConnect);
  add('connect-public-instance-card-not-in-chain', 'card_not_in_chain', 'The baked checks pass (the public instance\'s own card 0, under the baked instanceId, naming the baked origin), and the served chain does not hold the offer\'s cardHash (it ends one card earlier): the link\'s own check, on top of the baked root.',
    row);

  row = signedOnPublic('public-both-cards', publicConnectOtherInstance);
  add('connect-public-instance-offer-names-another-instance', 'instance_mismatch', 'The baked checks pass, and the offer\'s cardHash is in the served chain under another instanceId than the offer names: instance_mismatch, this time from the link\'s own check (the baked instanceId is the chain\'s).',
    row);

  row = signedOnPublic('no-card', publicConnect);
  add('connect-public-instance-no-card-served', 'withheld', 'The baked origin serves no card: an empty chain is withheld under the baked root, as under every root.',
    row);

  row = signedOnPublic('public-other-card-0', publicConnect);
  add('order-baked-root-before-the-offer-root', 'card0_mismatch', 'Two things wrong at once at the baked origin: card 0 does not hash to the baked card0Hash, and the served chain does not hold the offer\'s cardHash. The baked checks run first, so card0_mismatch; card_not_in_chain is what a build that bakes nothing answers.',
    row);
  expectWithoutBaked('order-baked-root-before-the-offer-root', row, 'card_not_in_chain');

  row = signedOnPublic('public-both-cards', publicRegister);
  add('register-public-instance', 'ok', 'A register link to the baked origin: the same order, kind register. The baked root first, then the offer\'s cardHash under the offer\'s instanceId; the pin\'s root is baked, and no Trust Gate is shown.',
    row, { kind: 'register', keyChanged: false, pinned: pinnedAtPublicCard1, pinRoot: 'baked' });
  expectWithoutBaked('register-public-instance', row, 'ok');

  row = signedOnPublic('public-other-card-0', publicRegisterOtherCard0);
  add('register-public-instance-card-0-differs', 'card0_mismatch', 'A register link made against another card 0 at the baked origin: its own check would pass (the offer\'s cardHash is in the served chain under the offer\'s instanceId), and the baked checks, which run first, refuse it.',
    row);
  expectWithoutBaked('register-public-instance-card-0-differs', row, 'ok');

  row = signedOnPublic('public-card-0-only', publicRegister);
  add('register-public-instance-card-not-in-chain', 'card_not_in_chain', 'A register link to the baked origin whose cardHash the served chain does not hold (it ends one card earlier): the baked checks pass, then the link\'s own check.',
    row);

  const publicSetupJson = buildStatement('setup-offer', {
    linkId: d.linkId, origin: P, instanceId: fx.baked.instanceId, name: nameOf('andvari'), kind: 'public', recoveryFp: 'none', expiresAt: at(0) + DAY,
  });
  const publicSetup = hostBody('setup', envelopeSeal(d.offerKey, nonce24('recipient/setup-public'), d.offerAd, utf8(publicSetupJson)));
  const setupOnPublic = (chain) => ({ link: publicLink, baked: fx.baked, cards: chainOf(chain), server: { status: 200, body: publicSetup } });

  row = setupOnPublic('no-card');
  add('setup-public-instance-no-card-served', 'withheld', 'A setup link whose origin is the one this build bakes, and that origin serves no card. At any other origin this is how a setup link opens (the row `setup`). Here the baked root comes first and an empty chain is withheld under it, so nothing is signed: a build that bakes an instance never signs that instance\'s card 0.',
    row);
  expectWithoutBaked('setup-public-instance-no-card-served', row, 'ok');

  row = setupOnPublic('public-both-cards');
  add('setup-public-instance-already-set-up', 'already_set_up', 'The baked origin serves the public instance\'s own chain, which passes the baked checks: a setup link is refused there, already_set_up.',
    row);

  row = setupOnPublic('public-other-card-0');
  add('setup-public-instance-card-0-differs', 'card0_mismatch', 'The baked origin serves another card 0. The baked checks run first, so card0_mismatch; already_set_up is what a build that bakes nothing answers.',
    row);
  expectWithoutBaked('setup-public-instance-card-0-differs', row, 'already_set_up');

  // A link to any other origin is unaffected by what the build bakes: the same answer, field for field.
  const unaffected = (name, twin) => {
    const expectOf = (rowName) => JSON.stringify(rows.find((r) => r.name === rowName).expect);
    if (expectOf(name) !== expectOf(twin)) throw new Error(`links recipient "${name}": a link to another origin must get the answer of "${twin}"`);
  };
  add('connect-another-origin-on-a-build-that-bakes', 'ok', 'The link and chain of the row `connect`, opened by a build that bakes the public instance. The link\'s origin is not the baked one, so what the build bakes has no say: the answer of `connect`, field for field, through the link-offer root, and no pinRoot.',
    { baked: fx.baked }, { kind: 'connect', keyChanged: false });
  unaffected('connect-another-origin-on-a-build-that-bakes', 'connect');
  add('setup-another-origin-on-a-build-that-bakes', 'ok', 'The link of the row `setup`, opened by a build that bakes the public instance: its origin is not the baked one and serves no card, so the setup link opens as it does on every build.',
    { link: hostLink, cards: [], baked: fx.baked, server: { status: 200, body: hostBody('setup', env.setupEnvelope) } }, { kind: 'setup' });
  unaffected('setup-another-origin-on-a-build-that-bakes', 'setup');
  unaffected('enrol-another-origin-on-a-build-that-bakes', 'enrol');

  // ---- new on 2026-11-15, third batch, at the end ----

  // An offer envelope above the cap (§2.4 "Opening a link", §6.6): unopenable, before any key is
  // derived. No offer frame can make one (a frame is at most 1,125 bytes, its envelope 1,167), so the
  // padding is in the sealed plaintext: the envelope opens under this link's key and AD, to the
  // connect offer frame followed by zero bytes. The row at the cap shows what an engine that opened
  // it would answer, and that the cap itself is allowed.
  const overCap = paddedEnvelope('recipient/over-the-cap', d.offerKey, d.offerAd, fx.offer.frame, OFFER_MAX_BYTES + 1);
  const atCap = paddedEnvelope('recipient/at-the-cap', d.offerKey, d.offerAd, fx.offer.frame, OFFER_MAX_BYTES);
  add('offer-envelope-over-the-cap', 'unopenable', `The offer envelope is ${overCap.chars} characters (${overCap.bytes} bytes), above the cap of 2,732 characters (§6.6): unopenable, refused before any key is derived. It is otherwise a good envelope: sealed under this link's offerKey with its AD, it opens, to alice's connect offer frame (that of \`link\`) followed by ${overCap.padding} zero bytes. No offer frame alone can make an envelope this large (a frame is at most 1,125 bytes), so the padding is inside the seal. An engine that skipped the cap would open it and answer bad_frame, as the row offer-envelope-at-the-cap does. (2,733 characters is not a length unpadded base64url can have, so 2,734 is the smallest envelope above the cap.)`,
    { server: { status: 200, body: body({ offer: b64u(overCap.envelope) }) } });
  add('offer-envelope-at-the-cap', 'bad_frame', `The same construction one byte smaller: ${atCap.bytes} bytes, exactly ${atCap.chars} characters, which the cap allows (an envelope is refused only when it is LARGER than 2,732 characters). It opens, to alice's connect offer frame followed by ${atCap.padding} zero bytes: a signed frame of ${atCap.plain} bytes, longer than 1,125, so bad_frame.`,
    { server: { status: 200, body: body({ offer: b64u(atCap.envelope) }) } });

  // kind_mismatch from a host offer's own purpose, right after it is recognised; a host offer that is
  // not recognised is non_canonical first, whatever kind it seems to name (§2.4, spec 03 §15.9 step 4).
  add('enrol-offer-on-a-setup-link', 'kind_mismatch', 'A well-formed enrol offer (the one of the row `enrol`) on a link the server reports as setup: its purpose is recognised, and it names the other host kind, so kind_mismatch, before the template is parsed. (The row setup-offer-on-an-enrol-link is the other way round.)',
    { link: hostLink, cards: [], server: { status: 200, body: hostBody('setup', env.enrolEnvelope) } });
  const tooDeepSetup = env.setupJson.slice(0, -1) + ',"x":' + '['.repeat(HOST_JSON_MAX_DEPTH) + ']'.repeat(HOST_JSON_MAX_DEPTH) + '}';
  add('host-json-too-deep-names-the-other-kind', 'non_canonical', 'The setup offer of the row `setup` with one more key, "x", holding 32 arrays one inside another: 33 containers open at once, on a link the server reports as enrol. Too deep, so it is not recognised, and a host offer that is not recognised is non_canonical first, whatever kind it seems to name. A reader that recognised it anyway would find a setup offer and answer kind_mismatch.',
    { link: hostLink, cards: [], server: { status: 200, body: { ...hostBody('enrol', utf8('')), offer: sealOffer('kind/too-deep', utf8(tooDeepSetup)) } } });
  const commaEnrol = env.enrolJson.slice(0, -1) + ',}';
  add('host-json-trailing-comma-names-the-other-kind', 'non_canonical', 'The enrol offer of the row `enrol` with a comma before its closing brace, on a link the server reports as setup. Not RFC 8259, so it is not recognised: non_canonical comes first, whatever kind it seems to name. A lenient parser that skipped the comma would recognise an enrol offer and answer kind_mismatch.',
    { link: hostLink, cards: [], server: { status: 200, body: { ...hostBody('setup', utf8('')), offer: sealOffer('kind/trailing-comma', utf8(commaEnrol)) } } });
  add('signed-frame-on-a-setup-link', 'kind_mismatch', 'kind_mismatch from the form alone: the server reports kind setup, and the envelope opens to a signed frame (alice\'s connect offer). (signed-frame-on-a-host-link is the same on an enrol link.)',
    served('frame-on-setup', fx.offer.frame, { kind: 'setup' }));
  add('host-json-on-a-register-link', 'kind_mismatch', 'kind_mismatch from the form alone: the server reports kind register, and the envelope opens to host JSON (the enrol offer of the row `enrol`). (host-json-on-a-connect-link is the same on a connect link.)',
    served('json-on-register', utf8(env.enrolJson), { kind: 'register' }));

  // Under an existing pin at the baked origin (§4.4, the paragraph after "At the baked origin the
  // baked root always comes first"): the pin is compared first, then the baked checks run on the
  // same chain. pin.root states the existing pin's root, here a Trust Gate pin.
  const trustGatePinOn = (card0) => ({ card0Hash: card0.hash, seq: 0, hash: card0.hash, root: 'trust_gate' });
  add('enrol-public-instance-raises-a-trust-gate-pin', 'ok', 'This device already pins the baked origin through the Trust Gate (pin.root trust_gate, made on card 0 of the public instance\'s own chain, for example by a build that did not bake it). The served chain extends the pin, and the baked checks then pass on the same chain: the pin\'s root becomes baked (expect.pinRoot), raised from trust_gate. No Trust Gate is shown.',
    onPublic('public-both-cards', { pin: trustGatePinOn(fx.publicCards[0]) }), { kind: 'enrol', pinRoot: 'baked' });
  add('enrol-public-instance-trust-gate-pin-on-another-card-0', 'card0_mismatch', 'This device pins the baked origin through the Trust Gate, on a chain whose card 0 is not the baked one, and the served chain is that chain, so it extends the pin. The pin comparison passes; the baked checks then run on the same chain and refuse it: card0_mismatch, and the device does not use that instance until the person forgets the server.',
    onPublic('public-other-card-0', { pin: trustGatePinOn(otherCard0) }));
  add('order-pin-before-the-baked-root-under-a-trust-gate-pin', 'fork', 'The same Trust Gate pin on another card 0, and the baked origin now serves the public instance\'s own chain, which forks from the pin (its card 0 differs). The pin comparison comes first: fork, although that chain would pass the baked checks.',
    onPublic('public-both-cards', { pin: trustGatePinOn(otherCard0) }));

  // A setup link at the baked origin: a served chain that fails the baked checks is card0_mismatch
  // (setup-public-instance-card-0-differs) or instance_mismatch (§4.4).
  row = { ...setupOnPublic('public-both-cards'), baked: { ...fx.baked, instanceId: ids.instance } };
  add('setup-public-instance-id-differs', 'instance_mismatch', 'A setup link to the baked origin, which serves the public instance\'s own chain: card 0 hashes to the baked card0Hash, but this build bakes another instanceId, so the chain fails the baked checks with instance_mismatch, not already_set_up. (Card 0 carries its instanceId, so only a build whose two constants disagree gets here.)',
    row);
  expectWithoutBaked('setup-public-instance-id-differs', row, 'already_set_up');

  // Fourth batch (spec 01 §5.5 and the email_b64n type): an enrol offer's email must already be an
  // emailNorm. A host offer that is recognised as an enrol offer on an enrol link and then fails the
  // template's value grammar is non_canonical.
  const carolB64 = b64u(utf8('carol@example.com'));
  const enrolWithEmail = (text) => {
    const out = env.enrolJson.replace('"email":"' + carolB64 + '"', '"email":"' + b64u(utf8(text)) + '"');
    if (out === env.enrolJson) throw new Error('links: the enrol offer fixture does not carry carol\'s address');
    return out;
  };
  add('enrol-offer-email-with-an-uppercase-letter', 'non_canonical', 'The enrol offer of the row `enrol` with its email the base64url of Carol@example.com: email_b64n must already be its own emailNorm, so an upper-case letter is non_canonical (spec 01 §5.1).',
    hostJson('email/uppercase', enrolWithEmail('Carol@example.com')));
  add('enrol-offer-email-in-a-display-name-form', 'non_canonical', 'The enrol offer of the row `enrol` with its email the base64url of carol<carol@example.com>: lower case, one @, every byte printable ASCII, but the local part is not a dot-atom, so the address has no emailNorm and email_b64n refuses it (spec 01 §5.5).',
    hostJson('email/display-name', enrolWithEmail('carol<carol@example.com>')));
  return rows;
}

/**
 * An envelope of exactly `envelopeBytes` bytes, sealed under `key` and `ad`, whose plaintext is
 * `frame` followed by zero bytes. It opens; the oracle checks that it does.
 */
function paddedEnvelope(label, key, ad, frame, envelopeBytes) {
  const plaintext = new Uint8Array(envelopeBytes - ENVELOPE_OVERHEAD);
  plaintext.set(frame);
  const envelope = envelopeSeal(key, nonce24(label), ad, plaintext);
  const opened = envelopeOpen(key, ad, envelope);
  if (envelope.length !== envelopeBytes || opened === null || b64u(opened) !== b64u(plaintext)) throw new Error('links: a padded envelope must open');
  const n = (x) => x.toLocaleString('en-US');
  return { envelope, padding: n(plaintext.length - frame.length), bytes: n(envelope.length), chars: n(b64u(envelope).length), plain: n(plaintext.length) };
}

// ---- the creator ----

function creatorRows(fx, env) {
  const rows = [];
  const names = new Set();
  const d = fx.d;
  const other = deriveLink(fixed('links/secret/other'));
  const now = at(3);
  const record = { secretB64: b64u(fx.secret), nonceAB64: b64u(fx.nonceA), kind: 'connect', offerHash: fx.offer.hash, expiresAt: fx.offerValues.expiresAt, shares: [] };
  const toInternal = (records) => Object.fromEntries(Object.entries(records).map(([id, r]) => [id, { secret: mustUnb64u(r.secretB64), nonceA: mustUnb64u(r.nonceAB64), kind: r.kind, offerHash: r.offerHash, expiresAt: r.expiresAt }]));
  const sealAnswer = (label, plaintext, key = d.answerKey, ad = d.answerAd) => b64u(envelopeSeal(key, nonce24('creator/' + label), ad, plaintext));
  const flip = (frame) => {
    const out = frame.slice();
    out[37 + 10] ^= 0x01;
    return out;
  };

  const add = (name, verdict, why, input, expectExtra = {}) => {
    const full = { now, records: { [d.linkId]: record }, served: { linkId: d.linkId, answer: b64u(env.answerEnvelope), answererUserId: bob.userId, answeredAt: at(2) }, contacts: {}, ...input };
    const result = processAnswer({ me: alice, records: toInternal(full.records), now: full.now, served: full.served, contacts: full.contacts });
    if (result.verdict !== verdict) throw new Error(`links creator "${name}": the design says ${verdict}, the oracle says ${result.verdict}`);
    if (names.has(name)) throw new Error('links: duplicate creator row ' + name);
    names.add(name);
    const expect = verdict === 'ok' ? { verdict, from: result.from, fromKey: result.fromKey, name: result.name, answerHash: result.answerHash, code: result.code, keyChanged: result.keyChanged } : { verdict };
    for (const [k, v] of Object.entries(expectExtra)) if (expect[k] !== v) throw new Error(`links creator "${name}": expected ${k} = ${v}`);
    rows.push({ name, why, me: 'alice', now: full.now, records: full.records, served: full.served, contacts: full.contacts, expect });
  };
  const answerWith = (signer, overrides) => signed('link-answer', signer, { ...fx.answerValues, ...overrides });
  const served = (label, frame, overrides = {}) => ({ served: { linkId: d.linkId, answer: sealAnswer(label, frame), answererUserId: bob.userId, answeredAt: at(2), ...overrides } });

  add('answer', 'ok', 'alice\'s creating device processes bob\'s answer: it pins bob with compared = false, then reveals nonceA. code.shows is the creator code, which her screen shows; code.accepts is the answerer code, the only typed input her app accepts, which bob\'s screen shows and hers never does.', {}, { keyChanged: false });
  add('known-contact-another-key', 'ok', 'bob is already a contact with another key: the key_changed prompt, not a verdict.', { contacts: { [bob.userId]: carol.key } }, { keyChanged: true });

  add('no-record', 'unknown_link', 'This device holds no record for the link (it was made on another device, or revoked): the answer is ignored.', { records: {} });
  add('record-expired', 'unknown_link', 'T-R3: the creator drops its record at expiresAt. An answer processed one millisecond later is ignored, whatever the server says.', { now: fx.offerValues.expiresAt + 1 });
  add('record-expires-now', 'unknown_link', 'now equals expiresAt: expiry is exclusive, the record is valid only while now < expiresAt.', { now: fx.offerValues.expiresAt });
  add('record-one-millisecond-before-expiry', 'ok', 'One millisecond before expiresAt the record still stands and the answer is processed.', { now: fx.offerValues.expiresAt - 1 }, { keyChanged: false });
  add('record-of-another-link', 'unknown_link', 'The device holds a record, but for another link.', { records: { [other.linkId]: { ...record, secretB64: b64u(fixed('links/secret/other')) } } });

  add('answer-sealed-under-the-offer-key', 'unopenable', 'The answer envelope was made under the offer key.', { served: { linkId: d.linkId, answer: sealAnswer('offer-key', fx.answer.frame, d.offerKey, d.answerAd), answererUserId: bob.userId, answeredAt: at(2) } });
  add('answer-of-another-link', 'unopenable', 'Swapped link ids: an answer made for another link.', { served: { linkId: d.linkId, answer: sealAnswer('other-link', fx.answer.frame, other.answerKey, other.answerAd), answererUserId: bob.userId, answeredAt: at(2) } });
  add('answer-truncated', 'unopenable', 'An envelope of 30 bytes.', { served: { linkId: d.linkId, answer: b64u(env.answerEnvelope.slice(0, 30)), answererUserId: bob.userId, answeredAt: at(2) } });

  add('offer-frame-as-the-answer', 'bad_frame', 'The envelope opens to a signed 0x06 frame.', served('offer-frame', fx.offer.frame));
  add('answer-not-canonical', 'non_canonical', 'A signed answer with a space after a colon.', served('space', signedRaw(ANSWER, bob, fx.answer.statement.replace('"to":', '"to": ')).frame));
  add('answer-version-3', 'bad_statement', 'A signed, canonical answer with "v":3.', served('v3', signedRaw(ANSWER, bob, rawStatement(withToken(tokens('link-answer', fx.answerValues), 'v', '3'))).frame));
  add('answer-is-plain-json', 'unknown_format', 'The envelope opens to a bare JSON statement, not a frame.', served('json', utf8(fx.answer.statement)));

  add('answer-signed-by-another-key', 'signer_not_pinned_key', 'The answer names bob and his key, but eve signed it: the signer must map to the answer\'s own fromKey.', served('eve-signs', signed('link-answer', eve, fx.answerValues).frame));
  add('answer-signature-flipped', 'bad_signature', 'bob\'s answer with one signature bit flipped.', served('flipped', flip(fx.answer.frame)));
  add('answer-names-another-link', 'link_mismatch', 'bob signed an answer whose linkId is another link\'s; it sits in this link\'s envelope.', served('other-link-id', answerWith(bob, { linkId: other.linkId }).frame));
  add('answer-to-another-offer', 'offer_mismatch', 'The answer\'s offerHash is not the hash of the offer this device made: bob was shown another offer.', served('other-offer', answerWith(bob, { offerHash: fx.answer.hash }).frame));
  add('answer-to-another-account', 'misaddressed', 'The answer\'s to is carol.', served('to-carol', answerWith(bob, { to: carol.userId }).frame));
  add('answer-to-another-key', 'misaddressed', 'The answer\'s toKey is not alice\'s key.', served('tokey-carol', answerWith(bob, { toKey: carol.key }).frame));
  add('server-reports-another-answerer', 'reported_answerer_mismatch', 'The server reports another answererUserId than the answer\'s from: nothing is pinned.', { served: { linkId: d.linkId, answer: b64u(env.answerEnvelope), answererUserId: eve.userId, answeredAt: at(2) } });

  add('order-signer-before-signature', 'signer_not_pinned_key', 'Signed by eve, with the signature broken as well.', served('order-1', flip(signed('link-answer', eve, fx.answerValues).frame)));
  add('order-signature-before-link', 'bad_signature', 'Another linkId under a broken signature.', served('order-2', flip(answerWith(bob, { linkId: other.linkId }).frame)));
  add('order-link-before-offer', 'link_mismatch', 'Another linkId and another offerHash.', served('order-3', answerWith(bob, { linkId: other.linkId, offerHash: fx.answer.hash }).frame));
  add('order-offer-before-addressing', 'offer_mismatch', 'Another offerHash, addressed to carol.', served('order-4', answerWith(bob, { offerHash: fx.answer.hash, to: carol.userId }).frame));
  add('order-addressing-before-reported-answerer', 'misaddressed', 'Addressed to carol, and the server reports another answerer.', served('order-5', answerWith(bob, { to: carol.userId }).frame, { answererUserId: eve.userId }));

  // ---- new on 2026-11-15, third batch, at the end: an answer envelope above the cap (§2.4
  //      "Processing an answer", §6.6), padded inside the seal as the recipient's offer is ----
  const overCap = paddedEnvelope('creator/over-the-cap', d.answerKey, d.answerAd, fx.answer.frame, OFFER_MAX_BYTES + 1);
  const atCap = paddedEnvelope('creator/at-the-cap', d.answerKey, d.answerAd, fx.answer.frame, OFFER_MAX_BYTES);
  add('answer-envelope-over-the-cap', 'unopenable', `The answer envelope is ${overCap.chars} characters (${overCap.bytes} bytes), above the cap of 2,732 characters (§6.6, FI-R6): unopenable, refused before any key is derived. It is otherwise a good envelope: sealed under this link's answerKey with its AD, it opens, to bob's answer frame (that of \`link\`) followed by ${overCap.padding} zero bytes. No answer frame alone can make an envelope this large (a frame is at most 1,125 bytes), so the padding is inside the seal. An engine that skipped the cap would open it and answer bad_frame, as the row answer-envelope-at-the-cap does.`,
    { served: { linkId: d.linkId, answer: b64u(overCap.envelope), answererUserId: bob.userId, answeredAt: at(2) } });
  add('answer-envelope-at-the-cap', 'bad_frame', `The same construction one byte smaller: ${atCap.bytes} bytes, exactly ${atCap.chars} characters, which the cap allows. It opens, to bob's answer frame followed by ${atCap.padding} zero bytes: a signed frame of ${atCap.plain} bytes, longer than 1,125, so bad_frame.`,
    { served: { linkId: d.linkId, answer: b64u(atCap.envelope), answererUserId: bob.userId, answeredAt: at(2) } });
  return rows;
}

export function build() {
  const fx = fixtures();
  const env = envelopeRows(fx);
  const chain = verifyCardChain(fx.cards.map((c) => c.frame));
  if (chain.verdict !== 'ok') throw new Error('links fixture chain');
  const url = urlRows(fx);
  const codes = commitRows(fx);
  const code = codeRows(fx);
  return {
    _about: [
      'Links v2 of design 2026-11-15-onboarding-trust §6, with the derivations of §2.3 and the verdict strings and order of §2.4.',
      'Hand-authored from the independent oracle in tools/vector-gen/oracle (Node WebCrypto and @noble; no andvari code). Regenerate with `npm run generate` there; `npm run check` fails on any difference. Secrets, nonces and envelope nonces are fixed.',
      'derive: from the 32-byte link secret s. linkId = b64url(HKDF(s, "andvari/v2|link|id", 16)); offerKey and answerKey = HKDF(s, "andvari/v2|link|offer" / "andvari/v2|link|answer", 32), with ADs "andvari/v2|link-offer|" + linkId and "andvari/v2|link-answer|" + linkId; registerToken = b64url(HKDF(s, "andvari/v2|link|register", 32)); tokenHash = b64url(SHA-256 over the 43 ASCII characters of the token). HKDF-SHA-256, empty salt.',
      'fingerprint: F = b64url(SHA-256(the creator\'s raw 32-byte identityPub)[0..16]), 22 characters.',
      'commit / reveal: commit = hexLower(SHA-256("andvari/v2|code-commit|" + b64url(nonce))). A reveal that does not hash to the offer\'s commit is bad_reveal.',
      'code: a link has TWO comparison codes, one per side (§2.3, §6.11). code(side) = u32be(SHA-256(inputUtf8)[0..4]) mod 10^6, zero-padded to 6 digits, with inputUtf8 = "andvari/v2|link|code|" + side + "|" + linkId + "|" + offerHash + "|" + answerHash + "|" + b64url(nonceA) + "|" + b64url(nonceB), and side the literal creator or answerer. The link\'s creator shows the creator code and the answerer shows the answerer code; each app accepts as typed input only the OTHER side\'s code, which it computes and never displays. A row gives the five inputs and then, under `creator` and under `answerer`, what THAT side\'s app does with the codes: `shows` is the six digits on its own screen (the code with its own literal; `inputUtf8` and `digestHex` are the derivation of `shows`), and `accepts` is the only six digits it accepts when typed, which is the other side\'s `shows`, repeated so that nobody has to work out which is which. A code row has no field called `code`. The two codes differ in every row but the last, code[8]: its nonceB was searched for, the first of the oracle\'s labelled nonces that gives both sides the same six digits, as about one link in a million has (§6.11 "Equal codes"). In that row `shows` and `accepts` are one value on both sides, and the row has the same fields as every other.',
      'typedCode: the check of typed text (§6.11 "Typed input", "A wrong code is not a verdict", "Equal codes"). `typedInto` is the side whose app the text is typed into; the five inputs are carried in the row itself and are those of one of the code rows (code[0], except in the rows whose `why` begins "The inputs of code[7]", whose two codes start with 0, or "The inputs of code[8]", whose two codes are equal); `typed` is the text as typed; and expect.accepted says whether that app accepts it (and so, on its own correct entry only, sets compared = true). The rule: every ASCII space (U+0020) is removed from `typed`, wherever it stands and however many there are, and what is left must be exactly six ASCII digits (U+0030 to U+0039), equal as text to the OTHER side\'s code. Nothing else is normalised, so none of these is accepted: the code without its leading zero (it is compared as text, not as a number), a tab, a no-break space or a dash between the digits, a seventh digit, the digits of another script, the empty string, spaces alone, and, where the two codes differ, the code on the app\'s own screen. Where the two codes are equal nothing special happens: each app accepts that code, and must not refuse it for being equal to its own. A wrong code is not a verdict: the design names no string for it (nothing was verified or refused, and the person may type again), so the expectation is a boolean. `typed` is to be passed on exactly as the JSON string decodes: it holds a tab in one row and characters outside ASCII in three, which this ASCII-only file writes as JSON escapes.',
      'Changed on 2026-11-15: the design gave each side of a link its own code (it first had one code, shown on both screens), and the rows for an enrol link to the public instance were written. (1) code: a row had `inputUtf8`, `digestHex` and `code` at its top level; these three are gone, and the row has `creator` and `answerer` instead, each {inputUtf8, digestHex, shows, accepts}. The side literal is new in every inputUtf8, so every digest and every six digits changed, and each `why` was reworded; the inputs of the first seven rows did not change, and the zero-padding row has another nonceB (both of its codes are below 100000). (2) typedCode is new. (3) creator: on the three ok rows expect.code was a six-digit string and is now {shows, accepts}, this device\'s two codes: shows is the creator code and accepts the answerer code. The `why` of the row `answer` was reworded; no verdict and no other field of a creator row changed. (4) recipient: the 88 rows that were there are unchanged byte for byte; twelve rows are new, at the end, each with a `baked` input; cardChains has five more chains (public-*), and the four that were there are unchanged. accounts, link, derive, fingerprint, commit, reveal, url and envelopes are unchanged byte for byte.',
      'Changed on 2026-11-15, second batch, with three rules written into the design: §6.11 ("Typed input", "A wrong code is not a verdict", "Equal codes"), §4.4 ("At the baked origin the baked root always comes first") and §2.4 (the depth of a host offer is decided before any general JSON parser sees it). (1) code: one row is new, the last, code[8], whose two codes are equal; the eight rows that were there are unchanged byte for byte. (2) typedCode: twenty rows are new, after the eight that were there, which are unchanged byte for byte. The shape of a row is the same, but two things a reader could rely on before no longer hold: a row\'s five inputs are not always those of code[0], and `typed` is not always six ASCII digits. (3) recipient: eighteen rows are new, at the end: three very deep host offers (host-json-nest-986, host-json-nest-986-enrol-offer, host-json-nest-1001-no-purpose), thirteen connect, register and setup links to the origin the build bakes (the rows whose names begin connect-public-instance, register-public-instance or setup-public-instance, and order-baked-root-before-the-offer-root) and two links to another origin on a build that bakes (connect-another-origin-on-a-build-that-bakes, setup-another-origin-on-a-build-that-bakes). expect.pinRoot is a new field, present only on the ok rows of a link to the baked origin: on the two new ones (connect-public-instance, register-public-instance) and on two that were there, enrol-public-instance and enrol-public-instance-chain-extends-the-pin, which gained that one field and nothing else. The other 98 recipient rows that were there are unchanged byte for byte, and so are cardChains, creator and every other section.',
      'Changed on 2026-11-15, third batch, with rules written into design §2.4 and §4.4. Every row that was there is unchanged byte for byte, and so are cardChains and every section but recipient and creator. (1) recipient: thirteen rows are new, at the end. An offer envelope above the cap of 2,732 characters is unopenable, refused before any key is derived (offer-envelope-over-the-cap: 2,734 characters, the smallest above the cap, of an envelope that opens under the link\'s key to the connect offer frame followed by zero bytes, since no offer frame alone makes an envelope that large), and the envelope at the cap is not (offer-envelope-at-the-cap: bad_frame, from the padded frame). kind_mismatch from a host offer\'s own purpose (enrol-offer-on-a-setup-link), and non_canonical first for a host offer that is not recognised, whatever kind it seems to name (host-json-too-deep-names-the-other-kind, host-json-trailing-comma-names-the-other-kind); kind_mismatch from the form for the two kinds the earlier rows did not use (signed-frame-on-a-setup-link, host-json-on-a-register-link). Under an existing Trust Gate pin at the baked origin (enrol-public-instance-raises-a-trust-gate-pin: ok, pinRoot baked; enrol-public-instance-trust-gate-pin-on-another-card-0: card0_mismatch; order-pin-before-the-baked-root-under-a-trust-gate-pin: fork). A setup link at the baked origin whose chain fails the baked checks on its instanceId (setup-public-instance-id-differs: instance_mismatch). `pin.root` is a new, optional field of a row\'s pin, present only on the three Trust Gate rows. (2) creator: two rows are new, at the end: answer-envelope-over-the-cap (unopenable) and answer-envelope-at-the-cap (bad_frame), built as the recipient\'s. (3) An offer or answer of a row may now be longer than 2,732 characters, on those two rows only.',
      'Changed on 2026-11-15, fourth batch, with the dot-atom and domain rule of emailNorm (spec 01 §5.5), which the email_b64n type of an enrol offer uses: two recipient rows are new, at the end, enrol-offer-email-with-an-uppercase-letter and enrol-offer-email-in-a-display-name-form (carol<carol@example.com>: lower case, one @, printable ASCII, refused only by the dot-atom rule), both non_canonical. Every other row is unchanged byte for byte, and every address the file already carried (carol@example.com in the enrol offer, alice@example.com) is its own emailNorm.',
      'url.compose: https://andvaripass.com/l#v2.<O>.<S>.<F>, O = b64url(UTF-8 origin), S = b64url(s), F the creator fingerprint or "-". url.parse: total parsing; expect.verdict ok with the three values, or bad_link. White space (space, tab, CR and LF, and nothing else: a form feed or a vertical tab stays and makes the link malformed) is removed first, wherever it stands; the input is the whole URL or only the fragment, with or without its #; nothing before the # is checked; exactly four parts; O must be canonical base64url of an origin of §2.2; S canonical and 32 bytes; F "-" or canonical and 16 bytes; at most 512 characters once the white space is removed.',
      'envelopes: seal rows are byte-exact (spec 02 §2 envelope, fixed nonce). open rows say whether an envelope opens under a key and AD.',
      'recipient: opening a link (§6.8). Inputs: the link text, `now`, the answer of GET /links/{linkId} (`server.status`, `server.body`), the card chain the origin serves (`cards` names an entry of `cardChains`), this device\'s pin for that origin (`pin`, or null), the account\'s contacts (userId -> pinned identity key) and, on the rows that have it, `baked`: what this build bakes, PUBLIC_INSTANCE = {origin, instanceId, card0Hash, kind} (§0.3; spec/public-instance.json holds placeholders until the cut-over, so each such row carries the constants it is graded with). A row without `baked` opens a link to an origin that no build bakes, and reads the same on every build. The first failure is the verdict, in §2.4\'s order: bad_link; link_unknown (404), link_expired (410), link_used (200, state answered); unopenable (the envelope does not open under offerKey with its AD, or `server.body.offer` is longer than 2,732 characters, which is refused before any key is derived); unknown_format, and kind_mismatch from the form alone; for a signed offer the parse verdicts, kind_mismatch (its own kind), creator_mismatch, signer_not_pinned_key, bad_signature; for host JSON non_canonical unless it is printable JSON with a string purpose (RFC 8259 exactly, with at most 32 containers open at once: the depth is decided on the bytes, or by a parser that stops at the limit, before any general JSON parser sees the text, so the three host-json-nest rows of about a thousand containers are non_canonical and must not overflow a stack), unknown_format for another purpose, kind_mismatch when the purpose names the other host kind (known before the template is parsed; a host offer that is not recognised is non_canonical or unknown_format first, whatever kind it seems to name), the template\'s parse, and creator_mismatch when F is not "-"; then link_mismatch, origin_mismatch (the offer\'s origin is not the link\'s), offer_expired (expiresAt > now must hold), reported_creator_mismatch; then the pinning step. Pinning: if this device holds a pin for the origin, the served chain is compared with it first and anything but ok stops (fork, withheld). Then, for a signed offer, the link-offer root of §2.4\'s pinning row: withheld for an empty chain, origin_mismatch when the chain\'s newest card names another origin than the link\'s, card_not_in_chain, instance_mismatch. For a setup offer: already_set_up when the instance serves any card. For an enrol offer, which is not a root: the typed-address root (withheld, origin_mismatch), after which the Trust Gate shows. At the origin the build bakes (the link\'s origin is `baked.origin`) the baked root always comes first, whatever the kind of link (§4.4, §6.8 step 5), after the comparison with an existing pin as for every root: withheld for an empty chain, origin_mismatch, card0_mismatch (card 0 does not hash to baked.card0Hash), instance_mismatch (baked.instanceId), in that order. Then the link adds its own check on top: a connect or register link, card_not_in_chain and instance_mismatch (the offer\'s cardHash must be in the chain under the offer\'s instanceId); an enrol link, nothing more, and no Trust Gate; a setup link is refused, already_set_up for every served chain that passed the baked checks (an empty one was withheld, so nothing is signed). A link to any other origin gets the same answer whether or not the row has `baked`. On ok, keyChanged says whether the key_changed prompt is due: a known contact with another key. expect.pinRoot stands on the ok rows of a link to the baked origin, and on no other row: it is the root that the pin for that origin records, in the words of passwordgate.json\'s `root`, and it is `baked` whatever kind of link was opened (a password pin: the build, not the link, vouches for the instance; an enrol link there leaves `baked`, not `enrol`, and a connect or register link `baked`, not `link_offer`). A row\'s `pin` is {card0Hash, seq, hash} or null, and may also carry `root`, the root that existing pin records, in passwordgate.json\'s words (baked, kit, setup, trust_gate, link_offer, enrol). `root` is optional: where it is absent the reader gives the pin its own default, as before this field existed. Three rows carry it, all `trust_gate`. It changes no verdict: under an existing pin at the baked origin the pin is compared first, as always, and the baked checks then run on the same chain (§4.4, "Under an existing pin at the baked origin"): when they pass, the pin\'s root becomes baked whatever it was (expect.pinRoot), and a pinned chain whose card 0 is not the baked one is card0_mismatch. On the one row with pinRoot whose pin has no `root` (enrol-public-instance-chain-extends-the-pin), that pin was itself made through the baked root, as every first pin at the baked origin is on a build that bakes it: a harness gives it the root `baked`, and it stays `baked`. On the rows without pinRoot this file does not state the root.',
      'creator: processing an answer on the creating device (§6.8). Inputs: the device\'s link records by linkId, `now`, and the served row {linkId, answer, answererUserId}. Order: unknown_link (no record, or now >= the record\'s expiresAt: expiry is exclusive); unopenable (the envelope does not open, or `served.answer` is longer than 2,732 characters, which is refused before any key is derived); the parse verdicts; signer_not_pinned_key (the signer must map to the answer\'s own fromKey); bad_signature; link_mismatch; offer_mismatch; misaddressed; reported_answerer_mismatch. On ok, answerHash = H(the answer frame) and `code` holds this device\'s two codes, named as in the code rows: code.shows is the creator code, which its screen shows, and code.accepts is the answerer code, the only typed input it accepts and one it never displays.',
      'No row, because they are flow rules and not verdicts: a move met while a link is opened under an existing pin (handled as a move first, and the link is opened again afterwards), and an answer of GET /links other than 200, 404 or 410 (a flow stop). No row has a field for the Trust Gate: whether it shows is in each row\'s `why`, and for a link to the baked origin it never shows.',
      'The extension handles no links and grades none of these rows (§17).',
    ],
    origin: X,
    instanceId: ids.instance,
    accounts: { alice: describe(alice), bob: describe(bob), carol: describe(carol), eve: describe(eve) },
    link: {
      secretB64: b64u(fx.secret), linkId: fx.d.linkId, f: fx.f, url: composeLink({ origin: X, secret: fx.secret, f: fx.f }),
      nonceAB64: b64u(fx.nonceA), nonceBB64: b64u(fx.nonceB),
      offer: { fields: fx.offer.values, statementUtf8: fx.offer.statement, frameB64: b64u(fx.offer.frame), offerHash: fx.offer.hash },
      answer: { fields: fx.answer.values, statementUtf8: fx.answer.statement, frameB64: b64u(fx.answer.frame), answerHash: fx.answer.hash },
    },
    cardChains: Object.fromEntries(Object.entries(fx.chains).map(([name, list]) => [name, list.map((c) => b64u(c.frame))])),
    derive: deriveRows(fx),
    fingerprint: fingerprintRows(),
    commit: codes.commit,
    reveal: codes.reveal,
    code,
    typedCode: typedCodeRows(fx, code),
    url,
    envelopes: { seal: env.seal, open: env.open },
    recipient: recipientRows(fx, env),
    creator: creatorRows(fx, env),
  };
}

export function grade(doc) {
  const failures = [];
  let rows = 0;
  const expect = (cond, what) => {
    rows++;
    if (!cond) failures.push(what);
  };
  const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

  for (const row of doc.derive) {
    const d = deriveLink(mustUnb64u(row.secretB64));
    expect(d.linkId === row.linkId && b64u(d.offerKey) === row.offerKeyB64 && d.offerAd === row.offerAdUtf8 && b64u(d.answerKey) === row.answerKeyB64
      && d.answerAd === row.answerAdUtf8 && d.registerToken === row.registerToken && d.tokenHash === row.tokenHash, 'derive: ' + row.why);
  }
  for (const row of doc.fingerprint) expect(creatorFingerprint(mustUnb64u(row.identityPubB64)) === row.f, 'fingerprint: ' + row.why);
  for (const row of doc.commit) expect(codeCommit(mustUnb64u(row.nonceB64)) === row.commit && row.inputUtf8 === 'andvari/v2|code-commit|' + row.nonceB64, 'commit ' + row.nonceB64);
  for (const row of doc.reveal) expect(checkReveal(row.commit, mustUnb64u(row.revealB64)) === row.expect.verdict, 'reveal: ' + row.why);
  const inputsOf = (row) => ({ linkId: row.linkId, offerHash: row.offerHash, answerHash: row.answerHash, nonceA: mustUnb64u(row.nonceAB64), nonceB: mustUnb64u(row.nonceBB64) });
  for (const row of doc.code) {
    const codes = linkCodes(inputsOf(row));
    for (const side of LINK_CODE_SIDES) {
      // The hashed string once more, spelled out from §2.3 and not taken from the function under test.
      const spelled = `andvari/v2|link|code|${side}|${row.linkId}|${row.offerHash}|${row.answerHash}|${row.nonceAB64}|${row.nonceBB64}`;
      expect(same(row[side], codes[side]) && row[side].inputUtf8 === spelled && /^[0-9]{6}$/.test(row[side].shows), `code (${side}): ` + row.why);
    }
    // Each side accepts the other side's code and no other; no bare `code`.
    expect(row.creator.accepts === row.answerer.shows && row.answerer.accepts === row.creator.shows && !Object.hasOwn(row, 'code'),
      'code (each side accepts the other\'s): ' + row.why);
  }
  // The two codes differ in every row but one, the last, which was searched for (§6.11 "Equal codes").
  const equalCodeRows = doc.code.filter((row) => row.creator.shows === row.answerer.shows);
  expect(equalCodeRows.length === 1 && equalCodeRows[0] === doc.code[doc.code.length - 1], 'code: exactly one row, the last, has two equal codes');
  const sameInputs = (a, b) => ['linkId', 'offerHash', 'answerHash', 'nonceAB64', 'nonceBB64'].every((k) => a[k] === b[k]);
  for (const row of doc.typedCode) {
    expect(acceptsTypedCode(row.typedInto, inputsOf(row), row.typed) === row.expect.accepted, 'typedCode: ' + row.why);
    // Every row carries the inputs of one of the code rows, so the digits it names can be read
    // there. The rule once more, spelled out from §6.11 against that code row's `accepts` and not
    // taken from the function under test: remove every ASCII space, then exactly six ASCII digits,
    // equal as text to the other side's code.
    const codeRow = doc.code.find((c) => sameInputs(c, row));
    const left = typeof row.typed === 'string' ? row.typed.split(' ').join('') : null;
    const spelled = codeRow !== undefined && left !== null && /^[0-9]{6}$/.test(left) && left === codeRow[row.typedInto].accepts;
    expect(codeRow !== undefined && spelled === row.expect.accepted, 'typedCode (the rule spelled out against its code row): ' + row.why);
  }
  // What the typedCode rows must show between them (§6.11): on both sides an entry with a space is
  // accepted, on both sides the shared code of the equal-codes row is accepted, and a code typed
  // without its leading zero is refused although it is the same number.
  const typedOn = (side, test) => doc.typedCode.some((row) => row.typedInto === side && test(row, doc.code.find((c) => sameInputs(c, row))));
  for (const side of LINK_CODE_SIDES) {
    expect(typedOn(side, (row) => row.expect.accepted && row.typed.includes(' ')), `typedCode: an accepted entry with a space, typed into the ${side}'s app`);
    expect(typedOn(side, (row, c) => row.expect.accepted && c === equalCodeRows[0] && row.typed === c[side].shows), `typedCode: the shared code of the equal-codes row is accepted in the ${side}'s app`);
    expect(typedOn(side, (row, c) => !row.expect.accepted && /^[1-9][0-9]{4}$/.test(row.typed) && '0' + row.typed === c[side].accepts), `typedCode: a dropped leading zero is refused in the ${side}'s app`);
  }
  for (const row of doc.url.compose) expect(composeLink({ origin: row.origin, secret: mustUnb64u(row.secretB64), f: row.f }) === row.url, 'compose: ' + row.why);
  for (const row of doc.url.parse) {
    const got = parseLink(row.input);
    const want = row.expect.verdict === 'ok' ? { origin: row.expect.origin, secretB64: row.expect.secretB64, f: row.expect.f } : null;
    expect(same(got === null ? null : { origin: got.origin, secretB64: b64u(got.secret), f: got.f }, want), 'parse: ' + row.why);
  }
  for (const row of doc.envelopes.seal) {
    const made = envelopeSeal(mustUnb64u(row.keyB64), mustUnb64u(row.nonceB64), row.adUtf8, mustUnb64u(row.plaintextB64));
    expect(b64u(made) === row.envelopeB64, 'envelope seal ' + row.name);
    if (row.plaintextUtf8 !== undefined) expect(b64u(utf8(row.plaintextUtf8)) === row.plaintextB64, 'envelope plaintextUtf8 ' + row.name);
  }
  for (const row of doc.envelopes.open) {
    expect((envelopeOpen(mustUnb64u(row.keyB64), row.adUtf8, mustUnb64u(row.envelopeB64)) !== null) === row.expect.opens, 'envelope open ' + row.name);
  }
  for (const row of doc.recipient) {
    const result = openLink({ link: row.link, now: row.now, server: row.server, cards: doc.cardChains[row.cards].map(mustUnb64u), pin: row.pin, contacts: row.contacts, baked: row.baked ?? null });
    const got = { verdict: result.verdict };
    if (result.verdict === 'ok') {
      got.kind = result.kind;
      if (result.from) Object.assign(got, { from: result.from, fromKey: result.fromKey, name: result.name, offerHash: result.offerHash, pinned: result.pinned, keyChanged: result.keyChanged });
      if (result.pinRoot !== undefined) got.pinRoot = result.pinRoot;
    }
    expect(same(got, row.expect), `recipient ${row.name}: oracle says ${JSON.stringify(got).slice(0, 120)}`);
    // pinRoot: `baked` on the ok rows of a link to the origin the build bakes, and on no other row.
    const toBakedOrigin = row.baked !== undefined && parseLink(row.link)?.origin === row.baked.origin;
    expect((row.expect.pinRoot === 'baked') === (row.expect.verdict === 'ok' && toBakedOrigin) && (row.expect.pinRoot === undefined || row.expect.pinRoot === 'baked'), `recipient ${row.name}: pinRoot`);
    // An offer larger than the cap of 2,732 characters (§6.6) is unopenable, and the rows that serve
    // one serve an envelope that would open under the link's key: its size is its only fault.
    if (row.server.body && row.server.body.offer !== undefined && row.server.body.offer.length > OFFER_MAX_CHARS) {
      const linkKeys = deriveLink(parseLink(row.link).secret);
      expect(row.expect.verdict === 'unopenable' && envelopeOpen(linkKeys.offerKey, linkKeys.offerAd, mustUnb64u(row.server.body.offer)) !== null, `recipient ${row.name}: an offer above the cap is unopenable, and opens but for its size`);
    }
  }
  expect(doc.recipient.some((row) => row.server.body && row.server.body.offer !== undefined && row.server.body.offer.length > OFFER_MAX_CHARS), 'recipient: a row serves an offer above the cap');
  // A link to another origin is unaffected by what the build bakes: the answer of its twin, field for field.
  const recipientExpect = (name) => JSON.stringify(doc.recipient.find((row) => row.name === name)?.expect);
  for (const kind of ['connect', 'setup', 'enrol']) {
    expect(recipientExpect(`${kind}-another-origin-on-a-build-that-bakes`) === recipientExpect(kind) && recipientExpect(kind) !== undefined, `recipient: the ${kind} link to another origin on a build that bakes`);
  }
  const me = { userId: doc.accounts.alice.userId, identityPub: mustUnb64u(doc.accounts.alice.identityPubB64) };
  for (const row of doc.creator) {
    const records = Object.fromEntries(Object.entries(row.records).map(([id, r]) => [id, { secret: mustUnb64u(r.secretB64), nonceA: mustUnb64u(r.nonceAB64), kind: r.kind, offerHash: r.offerHash, expiresAt: r.expiresAt }]));
    const result = processAnswer({ me, records, now: row.now, served: row.served, contacts: row.contacts });
    const got = result.verdict === 'ok'
      ? { verdict: 'ok', from: result.from, fromKey: result.fromKey, name: result.name, answerHash: result.answerHash, code: result.code, keyChanged: result.keyChanged }
      : { verdict: result.verdict };
    expect(same(got, row.expect), `creator ${row.name}: oracle says ${JSON.stringify(got).slice(0, 120)}`);
    // An answer larger than the cap is unopenable, and opens but for its size.
    if (row.served.answer.length > OFFER_MAX_CHARS) {
      const rec = records[row.served.linkId];
      const linkKeys = rec && deriveLink(rec.secret);
      expect(row.expect.verdict === 'unopenable' && linkKeys && envelopeOpen(linkKeys.answerKey, linkKeys.answerAd, mustUnb64u(row.served.answer)) !== null, `creator ${row.name}: an answer above the cap is unopenable, and opens but for its size`);
    }
  }
  expect(doc.creator.some((row) => row.served.answer.length > OFFER_MAX_CHARS), 'creator: a row serves an answer above the cap');
  // The file's worked example is consistent: the creating device's two codes are the first code row's, creator side.
  expect(same(doc.creator[0].expect.code, { shows: doc.code[0].creator.shows, accepts: doc.code[0].creator.accepts }) && hex(mustUnb64u(doc.link.nonceAB64)).length === 64,
    'the worked example\'s codes');
  return { rows, failures };
}
