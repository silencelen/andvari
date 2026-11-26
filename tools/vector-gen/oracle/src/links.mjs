// Links v2 (design §6): the URL, the derivations of §2.3, the committed comparison codes, one per
// side (§6.11), and the two verification orders of §6.8 with §2.4's verdict strings.

import { b64u, unb64u, mustUnb64u, utf8, utf8DecodeStrict, hex, u32be, bytesEqual, isPrintableAscii, latin1 } from './bytes.mjs';
import { sha256, hkdfSha256, envelopeOpen } from './prims.mjs';
import { isOrigin } from './grammar.mjs';
import { parseStatement, HOST_OFFER_PURPOSES } from './statement.mjs';
import { parseFrame, signerMapsTo, signatureValid, frameHash, MAGIC, PURPOSE_CODES } from './frame.mjs';
import { checkAgainstPin, pinFromRoot } from './card.mjs';
import { parseStrictJson, maxOpenContainers } from './json8259.mjs';
import { ROOTS as PIN_ROOTS } from './passwordgate.mjs';
import { keyFloor } from './keyfloor.mjs';

class Undefined extends Error {}

export const JOIN_BASE = 'https://andvaripass.com';
export const LINK_MAX_LENGTH = 512;
/**
 * The cap on an offer or answer envelope as sent (§6.3, §6.6; spec 03 §15): 2,732 characters of
 * base64url, that is 2,049 bytes of envelope. A larger one is unopenable, refused before any key is
 * derived (§2.4, the rows "Opening a link" and "Processing an answer").
 */
export const LINK_ENVELOPE_MAX_CHARS = 2732;

// ---- §2.3 derivations ----

export function deriveLink(secret) {
  keyFloor('links.derive', secret);
  const linkId = b64u(hkdfSha256(secret, 'andvari/v2|link|id', 16));
  const registerToken = b64u(hkdfSha256(secret, 'andvari/v2|link|register', 32));
  return {
    linkId,
    offerKey: hkdfSha256(secret, 'andvari/v2|link|offer', 32),
    offerAd: 'andvari/v2|link-offer|' + linkId,
    answerKey: hkdfSha256(secret, 'andvari/v2|link|answer', 32),
    answerAd: 'andvari/v2|link-answer|' + linkId,
    registerToken,
    tokenHash: b64u(sha256(registerToken)), // SHA-256 over the 43 ASCII characters of the token
  };
}

/** F = b64url(SHA-256(raw 32 bytes of the creator's identityPub)[0..16]). */
export function creatorFingerprint(identityPub) {
  return b64u(sha256(identityPub).slice(0, 16));
}

/** commit = hexLower(SHA-256("andvari/v2|code-commit|" + b64url(nonce))). */
export function codeCommit(nonce) {
  return hex(sha256('andvari/v2|code-commit|' + b64u(nonce)));
}

/** A six-digit code from the first four digest bytes, big endian, mod 10^6, zero-padded. */
export function codeFromInput(input) {
  const digest = sha256(input);
  return { digestHex: hex(digest), code: String(u32be(digest) % 1000000).padStart(6, '0') };
}

/** The two sides of a link: the literal that §2.3 puts into each side's code. */
export const LINK_CODE_SIDES = ['creator', 'answerer'];
const otherSide = (side) => (side === 'creator' ? 'answerer' : 'creator');

/** The hashed string of one side's code (§2.3): the side literal stands right after the label. */
export function linkCodeInput(side, { linkId, offerHash, answerHash, nonceA, nonceB }) {
  if (!LINK_CODE_SIDES.includes(side)) throw new Error('linkCodeInput: side is the literal creator or answerer');
  return ['andvari/v2|link|code', side, linkId, offerHash, answerHash, b64u(nonceA), b64u(nonceB)].join('|');
}

/**
 * The two codes of a link, one per side (§2.3, §6.11), as each side's app uses them. For each side:
 *   shows    the code with that side's literal: the one on that side's own screen
 *   accepts  the OTHER side's code: the only typed input that side's app accepts. The app computes
 *            it and never displays it.
 * `inputUtf8` and `digestHex` are the derivation of `shows`.
 */
export function linkCodes(inputs) {
  const own = {};
  for (const side of LINK_CODE_SIDES) {
    const inputUtf8 = linkCodeInput(side, inputs);
    own[side] = { inputUtf8, ...codeFromInput(inputUtf8) };
  }
  const out = {};
  for (const side of LINK_CODE_SIDES) {
    out[side] = { inputUtf8: own[side].inputUtf8, digestHex: own[side].digestHex, shows: own[side].code, accepts: own[otherSide(side)].code };
  }
  return out;
}

/**
 * The text rule for a typed comparison code (§6.11 "Typed input"; the device-link code of §8.2
 * step 5 is typed under the same rule). Every ASCII space (0x20) is removed, wherever it stands, and
 * what is left must be exactly six ASCII digits. Nothing else is normalised: a tab, a no-break space,
 * a dash, a digit of another script, a seventh digit or a missing one all leave something that is
 * not six ASCII digits. Returns the six digits, or null.
 *
 * Written twice, on purpose: once over the UTF-16 code units and once with a split and a pattern.
 * The two must agree, so that no row rests on what one engine's character classes take a digit or a
 * space to be.
 */
export function typedDigits(typed) {
  if (typeof typed !== 'string') return null;
  let digits = '';
  let other = false;
  for (let i = 0; i < typed.length; i++) {
    const unit = typed.charCodeAt(i);
    if (unit === 0x20) continue;
    if (unit >= 0x30 && unit <= 0x39) digits += typed[i];
    else other = true;
  }
  const byUnits = !other && digits.length === 6 ? digits : null;
  const stripped = typed.split(' ').join('');
  const byPattern = /^[0-9]{6}$/.test(stripped) ? stripped : null;
  if (byUnits !== byPattern) throw new Error('typedDigits: the two readings of the text rule disagree');
  return byUnits;
}

/**
 * Whether the typed text is `code` (§6.11): compared as TEXT, so a code typed without its leading
 * zero is not the code, although it is the same number. There is no verdict here, only yes or no.
 */
export function typedCodeIs(typed, code) {
  if (typeof code !== 'string' || !/^[0-9]{6}$/.test(code)) throw new Error('typedCodeIs: a code is six ASCII digits');
  return typedDigits(typed) === code;
}

/**
 * The check of the text typed into `side`'s app (§6.11): it is accepted only when, under the text
 * rule, it is the other side's code. The code on that side's own screen is not what its app compares
 * with. When the two codes of a link are the same six digits (one link in a million), nothing
 * special happens: the app still accepts exactly the other side's code, which is then also the one
 * on its own screen. So this function never looks at the side's own code at all.
 */
export function acceptsTypedCode(side, inputs, typed) {
  if (!LINK_CODE_SIDES.includes(side)) throw new Error('acceptsTypedCode: side is the literal creator or answerer');
  return typedCodeIs(typed, linkCodes(inputs)[side].accepts);
}

// ---- §6.1 the URL ----

export function composeLink({ origin, secret, f }) {
  return `${JOIN_BASE}/l#v2.${b64u(utf8(origin))}.${b64u(secret)}.${f}`;
}

/**
 * Total parse of an /l link: { origin, secret, f } or null. ASCII white space (space, tab, CR, LF)
 * is removed first, wherever it stands. The input is the whole URL or only the fragment; nothing
 * before the `#` is authenticated or checked. `parts` is 4 for a link (v2, O, S, F) and 3 for a
 * device link (v2, O, S; §8.1). The fragment may be given with or without its `#`. White space is
 * those four characters only: a form feed or a vertical tab is not removed, so the input is malformed.
 */
export function parseFragment(input, parts) {
  if (typeof input !== 'string') return null;
  const text = input.replace(/[ \t\r\n]/g, '');
  if (text.length > LINK_MAX_LENGTH) return null;
  const hash = text.indexOf('#');
  const fragment = hash === -1 ? text : text.slice(hash + 1);
  const fields = fragment.split('.');
  if (fields.length !== parts || fields[0] !== 'v2') return null;
  const originBytes = unb64u(fields[1]);
  if (originBytes === null) return null;
  const origin = utf8DecodeStrict(originBytes);
  if (origin === null || !isOrigin(origin)) return null;
  const secret = unb64u(fields[2]);
  if (secret === null || secret.length !== 32) return null;
  if (parts === 3) return { origin, secret };
  const f = fields[3];
  if (f !== '-') {
    const fBytes = unb64u(f);
    if (fBytes === null || fBytes.length !== 16) return null;
  }
  return { origin, secret, f };
}

export const parseLink = (input) => parseFragment(input, 4);

// ---- §6.8 the recipient ----

const startsWithMagic = (bytes) => bytes.length >= 4 && bytesEqual(bytes.slice(0, 4), MAGIC);

/**
 * The served chain against this device's pin for the link's origin, if it has one (§4.4, the rules
 * for the pin store): 'ok', or the pin's verdict (fork, withheld, or the chain's own), which stops.
 * Under a pin a newest card that names another origin is a move: it is handled as a move first and
 * the link is opened again afterwards, a flow rule that no row grades.
 */
function againstHeldPin(pin, cards, origin) {
  if (!pin) return 'ok';
  const held = checkAgainstPin(pin, cards);
  if (held.verdict !== 'ok') return held.verdict;
  if (held.newest.origin !== origin) throw new Undefined('a move met while a link is opened under an existing pin: a flow rule');
  return 'ok';
}

/** The host JSON row of §2.4: at most this many containers open at once, the outermost one counted. */
export const HOST_JSON_MAX_DEPTH = 32;

/**
 * Opening a link, in §2.4's order. `server` is the answer of GET /links/{linkId}: { status, body }.
 * `cards` is the chain served by the link's origin; `pin` this device's pin for that origin, if any;
 * `contacts` maps a userId to the identity key this account pinned for it. `baked` is what the build
 * bakes, PUBLIC_INSTANCE = { origin, instanceId, card0Hash } (§0.3), or null.
 *
 * `baked` matters only to a link whose origin is the baked one; a link to any other origin is
 * unaffected by what the build bakes. At the baked origin the baked root always comes first,
 * whatever the kind of link (§4.4, §6.8 step 5): after the comparison with an existing pin, the
 * baked checks run in §2.4's order (withheld for an empty chain, origin_mismatch, card0_mismatch,
 * instance_mismatch). Then the link adds its own check: a connect or register link, that the chain
 * holds the offer's cardHash under the offer's instanceId (card_not_in_chain, instance_mismatch); an
 * enrol link, nothing, and no Trust Gate; a setup link is refused, already_set_up, since a chain
 * that passed the baked checks is a served one. On ok at the baked origin the result carries
 * pinRoot = 'baked': the pin for that origin is a baked pin, whatever kind of link was opened.
 * `pin.root`, when given, is the root that existing pin records (passwordgate.json's words). It
 * changes no verdict: under an existing pin at the baked origin the pin is compared first and the
 * baked checks then run on the same chain (§4.4 "Under an existing pin at the baked origin"), so a
 * pinned chain with another card 0 that the served chain extends is card0_mismatch, and on ok the
 * pin's root becomes baked whatever it was (a Trust Gate pin is raised).
 */
export function openLink({ link, now, server, cards = [], pin = null, contacts = {}, baked = null }) {
  if (baked !== null && !(isOrigin(baked.origin) && typeof baked.instanceId === 'string' && typeof baked.card0Hash === 'string')) {
    throw new Error('openLink: baked is null or { origin, instanceId, card0Hash }');
  }
  if (pin !== null && pin.root !== undefined && !PIN_ROOTS.includes(pin.root)) throw new Error('openLink: pin.root is one of passwordgate.json\'s roots');
  const p = parseLink(link);
  if (p === null) return { verdict: 'bad_link' };
  const bakedOrigin = baked !== null && p.origin === baked.origin;

  if (server.status === 404) return { verdict: 'link_unknown' };
  if (server.status === 410) return { verdict: 'link_expired' };
  if (server.status !== 200) throw new Undefined('GET /links answers 200, 404 or 410');
  const body = server.body;
  // An answered link is served without its offer; a device that did not answer it shows "already used".
  if (body.state === 'answered') return { verdict: 'link_used' };
  if (body.state !== 'open') throw new Undefined('a 200 answer carries state open or answered');

  // An envelope above the cap is unopenable, refused before any key is derived (§2.4, §6.6).
  if (body.offer.length > LINK_ENVELOPE_MAX_CHARS) return { verdict: 'unopenable' };
  const d = deriveLink(p.secret);
  const envelope = unb64u(body.offer);
  const plain = envelope === null ? null : envelopeOpen(d.offerKey, d.offerAd, envelope);
  if (plain === null) return { verdict: 'unopenable' };

  const hostKind = body.kind === 'setup' || body.kind === 'enrol';

  if (startsWithMagic(plain)) {
    // A signed frame. kind_mismatch from the form alone, before any parse.
    if (hostKind) return { verdict: 'kind_mismatch' };
    const parsed = parseFrame(plain, PURPOSE_CODES['link-offer']);
    if (parsed.verdict !== 'ok') return { verdict: parsed.verdict };
    const o = parsed.values;
    if (o.kind !== body.kind) return { verdict: 'kind_mismatch' };
    const fromKey = mustUnb64u(o.fromKey);
    if (p.f === '-' || creatorFingerprint(fromKey) !== p.f) return { verdict: 'creator_mismatch' };
    if (!signerMapsTo(parsed.signerPub, fromKey)) return { verdict: 'signer_not_pinned_key' };
    if (!signatureValid(parsed)) return { verdict: 'bad_signature' };

    if (o.linkId !== d.linkId) return { verdict: 'link_mismatch' };
    if (o.origin !== p.origin) return { verdict: 'origin_mismatch' };
    if (!(o.expiresAt > now)) return { verdict: 'offer_expired' };
    if (o.from !== body.creatorUserId || o.fromKey !== body.creatorIdentityPub) return { verdict: 'reported_creator_mismatch' };

    // Pinning. A root never replaces an existing pin: the served chain is first compared with this
    // device's pin for the origin, and anything but ok stops. At the baked origin the baked root
    // comes next (§4.4: the build, not the link, vouches for the instance). Then the link-offer
    // check, which at the baked origin is the link's own check on top of the baked root.
    const held = againstHeldPin(pin, cards, p.origin);
    if (held !== 'ok') return { verdict: held };
    if (bakedOrigin) {
      const first = pinFromRoot({ root: 'baked', card0Hash: baked.card0Hash, instanceId: baked.instanceId }, cards, p.origin);
      if (first.verdict !== 'ok') return { verdict: first.verdict };
    }
    const root = pinFromRoot({ root: 'link_offer', cardHash: o.cardHash, instanceId: o.instanceId }, cards, p.origin);
    if (root.verdict !== 'ok') return { verdict: root.verdict };

    const known = contacts[o.from];
    return {
      verdict: 'ok',
      kind: o.kind,
      from: o.from,
      fromKey: o.fromKey,
      name: o.name,
      commit: o.commit,
      offerHash: frameHash(plain),
      pinned: { seq: root.pinned.seq, hash: root.pinned.hash },
      // A different key for a known contact is a prompt, not a verdict: nothing is replaced until a
      // comparison code matches (§6.8 step 6).
      keyChanged: known !== undefined && known !== o.fromKey,
      ...(bakedOrigin ? { pinRoot: 'baked' } : {}),
    };
  }

  if (plain.length > 0 && plain[0] === 0x7b) {
    // Host JSON. kind_mismatch from the form alone, before any parse.
    if (!hostKind) return { verdict: 'kind_mismatch' };
    // VR-15: printable ASCII and a JSON object with a string `purpose`, else non_canonical. "A JSON
    // object" is RFC 8259 exactly: no bare token, no NaN, no trailing comma or trailing bytes, no key
    // twice at the top level, at most 32 containers open at once. Only then is a purpose other than
    // the two unknown_format; then come the template's own steps.
    if (!isPrintableAscii(plain)) return { verdict: 'non_canonical' };
    const text = latin1(plain);
    // The depth is decided on the bytes, before any parser sees the text (§2.4): a flat count, so an
    // offer of a thousand open brackets is non_canonical whatever else it holds, a recognisable
    // purpose included. The reader below also stops at the limit, and the two must agree.
    const tooDeep = maxOpenContainers(text) > HOST_JSON_MAX_DEPTH;
    const json = parseStrictJson(text, { maxDepth: HOST_JSON_MAX_DEPTH });
    if (tooDeep && json.ok) throw new Error('openLink: the flat count and the reader disagree about the depth of a host offer');
    if (tooDeep) return { verdict: 'non_canonical' };
    if (!json.ok) return { verdict: 'non_canonical' };
    const obj = json.value;
    if (obj === null || typeof obj !== 'object' || Array.isArray(obj) || typeof obj.purpose !== 'string') return { verdict: 'non_canonical' };
    if (!HOST_OFFER_PURPOSES.includes(obj.purpose)) return { verdict: 'unknown_format' };
    // kind_mismatch as soon as it can be known: the purpose is recognised before the template is
    // parsed, so a host offer of the other kind is kind_mismatch even when it would not parse.
    const offerKind = obj.purpose === 'setup-offer' ? 'setup' : 'enrol';
    if (offerKind !== body.kind) return { verdict: 'kind_mismatch' };
    const parsed = parseStatement(obj.purpose, plain);
    if (parsed.verdict !== 'ok') return { verdict: parsed.verdict };
    if (p.f !== '-') return { verdict: 'creator_mismatch' };
    const o = parsed.values;
    if (o.linkId !== d.linkId) return { verdict: 'link_mismatch' };
    if (o.origin !== p.origin) return { verdict: 'origin_mismatch' };
    if (!(o.expiresAt > now)) return { verdict: 'offer_expired' };
    // Pinning, as for a signed offer: an existing pin first.
    const held = againstHeldPin(pin, cards, p.origin);
    if (held !== 'ok') return { verdict: held };
    if (bakedOrigin) {
      // At the baked origin the baked root comes first, whatever the kind (§4.4).
      const first = pinFromRoot({ root: 'baked', card0Hash: baked.card0Hash, instanceId: baked.instanceId }, cards, p.origin);
      if (first.verdict !== 'ok') return { verdict: first.verdict };
      // A setup link is refused there: an empty chain was withheld just above, so nothing is signed,
      // and a served chain that passed the baked checks is already_set_up. A build that bakes an
      // instance never signs that instance's card 0.
      if (offerKind === 'setup') return { verdict: 'already_set_up' };
      // An enrol link adds nothing more: no Trust Gate, and the pin's root is baked, not enrol.
      return { verdict: 'ok', kind: offerKind, offer: o, pinRoot: 'baked' };
    }
    if (offerKind === 'setup') {
      // A setup link is for an instance that serves no card yet.
      if (cards.length !== 0) return { verdict: 'already_set_up' };
    } else {
      // An enrol link is not a root (§4.4, U3): its own cardHash pins nothing. Its origin is pinned
      // as a typed address, behind the Trust Gate, and the pin it leaves records root enrol.
      const root = pinFromRoot({ root: 'typed' }, cards, p.origin);
      if (root.verdict !== 'ok') return { verdict: root.verdict };
    }
    return { verdict: 'ok', kind: offerKind, offer: o };
  }

  return { verdict: 'unknown_format' };
}

// ---- §6.8 the creator ----

/**
 * Processing an answer on the creating device, in §2.4's order. `records` is the device's link
 * records by linkId: { secret, nonceA, kind, offerHash, expiresAt }. A record is dropped at
 * expiresAt, so a later answer finds none (T-R3).
 */
export function processAnswer({ me, records, now, served, contacts = {} }) {
  const rec = records[served.linkId];
  // Expiry is exclusive: a record is valid while now < expiresAt and is gone at now = expiresAt.
  if (rec === undefined || now >= rec.expiresAt) return { verdict: 'unknown_link' };
  // An envelope above the cap is unopenable, refused before any key is derived (§2.4, §6.6).
  if (served.answer.length > LINK_ENVELOPE_MAX_CHARS) return { verdict: 'unopenable' };
  const d = deriveLink(rec.secret);
  if (d.linkId !== served.linkId) throw new Error('fixture: the record is filed under another linkId');

  const envelope = unb64u(served.answer);
  const plain = envelope === null ? null : envelopeOpen(d.answerKey, d.answerAd, envelope);
  if (plain === null) return { verdict: 'unopenable' };

  const parsed = parseFrame(plain, PURPOSE_CODES['link-answer']);
  if (parsed.verdict !== 'ok') return { verdict: parsed.verdict };
  const a = parsed.values;
  // The answer's own fromKey: proof of possession, which the comparison code authenticates later.
  if (!signerMapsTo(parsed.signerPub, mustUnb64u(a.fromKey))) return { verdict: 'signer_not_pinned_key' };
  if (!signatureValid(parsed)) return { verdict: 'bad_signature' };

  if (a.linkId !== d.linkId) return { verdict: 'link_mismatch' };
  if (a.offerHash !== rec.offerHash) return { verdict: 'offer_mismatch' };
  if (a.to !== me.userId || a.toKey !== b64u(me.identityPub)) return { verdict: 'misaddressed' };
  if (a.from !== served.answererUserId) return { verdict: 'reported_answerer_mismatch' };

  const answerHash = frameHash(plain);
  // This device is the link's creator: it shows the creator code, and accepts as typed input only
  // the answerer code, which it computes here and never displays (§6.11).
  const codes = linkCodes({ linkId: d.linkId, offerHash: rec.offerHash, answerHash, nonceA: rec.nonceA, nonceB: mustUnb64u(a.nonce) });
  const known = contacts[a.from];
  return {
    verdict: 'ok',
    from: a.from,
    fromKey: a.fromKey,
    name: a.name,
    answerHash,
    code: { shows: codes.creator.shows, accepts: codes.creator.accepts },
    keyChanged: known !== undefined && known !== a.fromKey,
  };
}

/** The answerer's check of the reveal against the offer's commitment (§6.11). */
export function checkReveal(commit, nonce) {
  return nonce.length === 32 && codeCommit(nonce) === commit ? 'ok' : 'bad_reveal';
}
