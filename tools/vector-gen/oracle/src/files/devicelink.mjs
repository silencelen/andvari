// devicelink.json: the device link of design §8 with §2.4's verdicts.

import { b64u, mustUnb64u, utf8, hex, unhex } from '../bytes.mjs';
import { sha256, boxSeal, envelopeSeal, x25519Base, isLowOrderX25519, LOW_ORDER_X25519_HEX } from '../prims.mjs';
import {
  deriveDeviceLink, bundleKey, bundleAd, claimMacInput, proofInput, approveMacInput, mac, proofHash, deviceCodeInput, codeCommit, codeFromInput, typedCodeVerdict,
  composeDeviceLink, parseDeviceLink, decodeOuter, decodeBundle, checkClaim, checkDeviceReveal, claimStill, openOuter, openBundle, keyHash,
  currentFromBundle, checkAccountStateCheckpoint, BUNDLE_MAX_BYTES, BUNDLE_MAX_ENTRIES,
} from '../devicelink.mjs';
import { compareWithHead } from '../vaultlog.mjs';
import { emailNorm, EMAIL_LOCAL_MAX } from '../grammar.mjs';
import { signed, nameOf } from '../build.mjs';
import { nearZeroKey } from '../keyfloor.mjs';
import { alice, bob, carol, dave, ids, fixed, T0, describe } from '../cast.mjs';

export const file = 'devicelink.json';

const cp = (...codes) => String.fromCodePoint(...codes);
const BS = String.fromCharCode(92);
const X = 'https://vault.example.org';
const SECRET = fixed('devicelink/secret');
const OTHER_SECRET = fixed('devicelink/other-secret');
const D = deriveDeviceLink(SECRET);
const N_SEC = fixed('devicelink/n-secret');
const N_PUB = x25519Base(N_SEC);
const OTHER_N_PUB = x25519Base(fixed('devicelink/other-n-secret'));
const NONCE_N = fixed('devicelink/nonce-n');
const NONCE_E = fixed('devicelink/nonce-e');
const UVK = fixed('devicelink/uvk');
const h = (label) => hex(fixed('devicelink/hash/' + label));
const CHAIN = [h('card-0'), h('card-1'), h('card-2')];
const EMAIL = 'alice@example.com';

function goodClaim() {
  const fields = { nPub: b64u(N_PUB), name: nameOf('Pixel 9'), platform: 'android', commitN: codeCommit(NONCE_N) };
  return { ...fields, mac: mac(D.macKey, claimMacInput({ linkId: D.linkId, ...fields })) };
}

const outerText = (o = {}) => JSON.stringify({ v: 2, origin: X, userId: alice.userId, email: EMAIL, ...o });
const sealOuter = (label, text, to = N_PUB) => boxSeal(to, typeof text === 'string' ? utf8(text) : text, fixed('devicelink/ephemeral/' + label));

function goodBundle(overrides = {}) {
  return {
    v: 2, origin: X, instanceId: ids.instance, card: { seq: 2, hash: CHAIN[2] }, userId: alice.userId, email: EMAIL,
    identityPub: alice.key, personalVaultId: ids.personalVault,
    contacts: [{ userId: bob.userId, keyHash: keyHash(bob.identityPub), verifiedAt: T0 + 1000 }, { userId: carol.userId, keyHash: keyHash(carol.identityPub), verifiedAt: T0 + 2000 }],
    vaults: [{ vaultId: ids.vault, seq: 4, hash: h('vault-head') }],
    accountState: { seq: 7, hash: hex(sha256('the served sealedState string')) },
    issuedAt: T0 + 5000,
    ...overrides,
  };
}
const sealInner = (label, bytes, secret = SECRET, uvk = UVK) => {
  const { linkId } = deriveDeviceLink(secret);
  return envelopeSeal(bundleKey(uvk, linkId), fixed('devicelink/inner-nonce/' + label, 24), bundleAd(linkId), typeof bytes === 'string' ? utf8(bytes) : bytes);
};

export function build() {
  const claim = goodClaim();
  const proof = mac(D.macKey, proofInput({ linkId: D.linkId, nPub: claim.nPub }));
  const outer = sealOuter('good', outerText());
  const approveMac = mac(D.macKey, approveMacInput({ linkId: D.linkId, outer }));
  const genesis = signed('account-genesis', alice, { userId: alice.userId, identityKey: alice.key, instanceId: ids.instance, personalVaultId: ids.personalVault, createdAt: T0 });
  const pin = { origin: X, instanceId: ids.instance };

  // ---- derivations ----
  // The third row is not 32 zero bytes: spec 01 "Keys in memory and the lock" rule 4 refuses an all-zero key,
  // so the lowest input a client derives from is 31 zero bytes and one 0x01. The zero secret is in keyfloor.json.
  const derive = [SECRET, OTHER_SECRET, nearZeroKey()].map((s, i) => {
    const d = deriveDeviceLink(s);
    return { why: ['the link secret used throughout this file', 'another secret', '31 zero bytes and one 0x01 byte (the lowest secret the key floor accepts; all zeros is refused as a wiped key)'][i], secretB64: b64u(s), linkId: d.linkId, macKeyB64: b64u(d.macKey) };
  });
  const bundleKeys = [[UVK, D.linkId, 'the bundle key: from the account\'s UVK and this link\'s id'], [UVK, deriveDeviceLink(OTHER_SECRET).linkId, 'the same UVK and another link: another key'], [fixed('devicelink/other-uvk'), D.linkId, 'another UVK and this link']]
    .map(([uvk, linkId, why]) => ({ why, uvkB64: b64u(uvk), linkId, infoUtf8: 'andvari/v2|device-link|bundle|' + linkId, bundleKeyB64: b64u(bundleKey(uvk, linkId)), adUtf8: bundleAd(linkId) }));

  // ---- the URL ----
  const url = composeDeviceLink({ origin: X, secret: SECRET });
  const O = b64u(utf8(X));
  const S = b64u(SECRET);
  const fragment = url.slice(url.indexOf('#') + 1);
  const parse = [];
  const pOk = (why, input) => {
    const got = parseDeviceLink(input);
    if (got === null || got.origin !== X || b64u(got.secret) !== S) throw new Error('devicelink parse fixture should parse: ' + why);
    parse.push({ why, input, expect: { verdict: 'ok', origin: X, secretB64: S } });
  };
  const pNo = (why, input) => {
    if (parseDeviceLink(input) !== null) throw new Error('devicelink parse fixture should be refused: ' + why);
    parse.push({ why, input, expect: { verdict: 'bad_link' } });
  };
  const padTo = (total) => 'https://andvaripass.com/' + 'p'.repeat(total - fragment.length - 'https://andvaripass.com/'.length - 1) + '#' + fragment;
  pOk('the whole URL', url);
  pOk('only the fragment', fragment);
  pOk('the fragment with its #', '#' + fragment);
  pOk('spaces at both ends', '  ' + url + ' ');
  pOk('a line feed, CR LF and a tab inside', url.slice(0, 30) + '\n' + url.slice(30, 60) + '\r\n' + url.slice(60, 80) + '\t' + url.slice(80));
  pOk('exactly 512 characters in all', padTo(512));
  pNo('513 characters in all', padTo(513));
  pNo('a form feed inside: it is not white space, so it is not removed', url.slice(0, 60) + cp(0x0c) + url.slice(60));
  pNo('a vertical tab at the end', url + cp(0x0b));
  pNo('four parts: an invite link is not a device link', url + '.-');
  pNo('two parts: no secret', `https://andvaripass.com/d#v2.${O}`);
  pNo('the version is v1', `https://andvaripass.com/d#v1.${O}.${S}`);
  pNo('O is padded', `https://andvaripass.com/d#v2.${O}=.${S}`);
  pNo('O carries stray bits', `https://andvaripass.com/d#v2.${O.slice(0, -1)}B.${S}`);
  pNo('O decodes to an origin with a path', `https://andvaripass.com/d#v2.${b64u(utf8(X + '/'))}.${S}`);
  pNo('O decodes to a plain-http LAN address', `https://andvaripass.com/d#v2.${b64u(utf8('http://192.168.1.10'))}.${S}`);
  pNo('S is 31 bytes', `https://andvaripass.com/d#v2.${O}.${b64u(SECRET.slice(0, 31))}`);
  pNo('S is 33 bytes', `https://andvaripass.com/d#v2.${O}.${b64u(new Uint8Array(33).fill(3))}`);
  pNo('S is padded', `https://andvaripass.com/d#v2.${O}.${S}=`);
  pNo('S carries stray bits', `https://andvaripass.com/d#v2.${O}.${S.slice(0, -1)}${S.endsWith('B') ? 'C' : 'B'}`);
  pNo('empty', '');

  // ---- commitment, reveal, code ----
  const commitN = codeCommit(NONCE_N);
  const reveal = [
    { why: 'the new device reveals the nonce it committed to in its claim', commitN, revealB64: b64u(NONCE_N), expect: { verdict: checkDeviceReveal(commitN, NONCE_N) } },
    { why: 'another nonce is revealed: the existing device cancels the link', commitN, revealB64: b64u(fixed('devicelink/nonce-n/other')), expect: { verdict: checkDeviceReveal(commitN, fixed('devicelink/nonce-n/other')) } },
    { why: 'the existing device\'s own nonceE is replayed as the reveal', commitN, revealB64: b64u(NONCE_E), expect: { verdict: checkDeviceReveal(commitN, NONCE_E) } },
  ];
  if (reveal.map((r) => r.expect.verdict).join() !== 'ok,bad_reveal,bad_reveal') throw new Error('devicelink reveal fixtures');
  const codeBase = { linkId: D.linkId, nPub: claim.nPub, nonceN: NONCE_N, nonceE: NONCE_E };
  const code = [];
  const addCode = (why, inputs) => {
    const inputUtf8 = deviceCodeInput(inputs);
    const c = codeFromInput(inputUtf8);
    code.push({ why, linkId: inputs.linkId, nPubB64: inputs.nPub, nonceNB64: b64u(inputs.nonceN), nonceEB64: b64u(inputs.nonceE), inputUtf8, digestHex: c.digestHex, code: c.code });
    return c.code;
  };
  const baseCode = addCode('the code the new device shows and the person types into the existing device', codeBase);
  for (const [why, change] of [
    ['another link', { linkId: deriveDeviceLink(OTHER_SECRET).linkId }], ['another nPub (a swapped claim)', { nPub: b64u(OTHER_N_PUB) }],
    ['another nonceN', { nonceN: fixed('devicelink/nonce-n/other') }], ['another nonceE', { nonceE: fixed('devicelink/nonce-e/other') }], ['the two nonces swapped', { nonceN: NONCE_E, nonceE: NONCE_N }],
  ]) {
    if (addCode('changing one input changes the code: ' + why, { ...codeBase, ...change }) === baseCode) throw new Error('devicelink: a code variant collides');
  }
  let paddedCode;
  for (let i = 0; ; i++) {
    const nonceE = fixed('devicelink/nonce-e/padded/' + i);
    if (codeFromInput(deviceCodeInput({ ...codeBase, nonceE })).code.startsWith('0')) {
      paddedCode = addCode('a code below 100000 keeps its leading zero', { ...codeBase, nonceE });
      break;
    }
  }
  const typed = [];
  /** `verdict` is what §8.2 step 5 says, under §6.11's text rule; the builder checks the oracle agrees before writing the row. */
  const addTyped = (why, shownCode, text, verdict) => {
    const got = typedCodeVerdict(shownCode, text);
    if (got !== verdict) throw new Error(`devicelink typedCode "${why}": the design says ${verdict}, the oracle says ${got}`);
    typed.push({ why, code: shownCode, typed: text, expect: { verdict } });
  };
  addTyped('the six digits typed into the existing device are the code', baseCode, baseCode, 'ok');
  addTyped('one digit off: the link is cancelled', baseCode, baseCode.slice(0, 5) + String((Number(baseCode[5]) + 1) % 10), 'code_mismatch');
  addTyped('five digits', baseCode, baseCode.slice(0, 5), 'code_mismatch');
  // The text rule of §6.11, which §8.2 step 5 puts the device-link code under: every ASCII space is
  // removed, and what is left must be exactly the six ASCII digits of the code.
  const shown = (digits) => digits.slice(0, 3) + ' ' + digits.slice(3);
  addTyped('the code as the new device shows it, with one space in the middle: every ASCII space (U+0020) is removed before the comparison (the text rule of §6.11, which §8.2 step 5 applies here)', baseCode, shown(baseCode), 'ok');
  addTyped('one space in front of the six digits and one after them: spaces are removed wherever they stand', baseCode, ' ' + baseCode + ' ', 'ok');
  // A code that starts with exactly one 0, so that "without its leading zero" is five digits and the same number.
  if (!/^0[1-9]/.test(paddedCode) || Number(paddedCode.slice(1)) !== Number(paddedCode)) throw new Error('devicelink: the dropped-zero typedCode row needs a code that starts with exactly one 0');
  addTyped('a code that starts with 0 (the last row of `code`), typed in full, its leading zero included', paddedCode, paddedCode, 'ok');
  addTyped('the same code typed without its leading zero: five digits, the same number and not the same text. The comparison is on text, not on numbers, so this is a mismatch and the link is cancelled', paddedCode, paddedCode.slice(1), 'code_mismatch');
  addTyped('a tab (U+0009) between the third and fourth digits: only the ASCII space is removed, and nothing else is normalised', baseCode, baseCode.slice(0, 3) + cp(0x09) + baseCode.slice(3), 'code_mismatch');
  addTyped('the six digits of the code and then a seventh: what is left once the spaces are removed must be exactly six digits, and the first six are not taken on their own', baseCode, baseCode + '0', 'code_mismatch');

  // ---- the three MACs ----
  const macs = {
    claim: [{ why: 'the claim MAC: nPub and commitN as their text, name as the claim\'s name field (base64url) as sent', macKeyB64: b64u(D.macKey), linkId: D.linkId, nPub: claim.nPub, name: claim.name, platform: claim.platform, commitN: claim.commitN, inputUtf8: claimMacInput({ linkId: D.linkId, ...claim }), mac: claim.mac }],
    pickup: [{ why: 'the pickup proof, and proofHash = hexLower(SHA-256 over the 43 ASCII characters of the proof)', macKeyB64: b64u(D.macKey), linkId: D.linkId, nPub: claim.nPub, inputUtf8: proofInput({ linkId: D.linkId, nPub: claim.nPub }), proof, proofHash: proofHash(proof) }],
    approve: [{ why: 'the approve MAC covers `outer` only: the lowercase hex SHA-256 of the raw sealed bytes', macKeyB64: b64u(D.macKey), linkId: D.linkId, outerB64: b64u(outer), outerSha256Hex: hex(sha256(outer)), inputUtf8: approveMacInput({ linkId: D.linkId, outer }), approveMac }],
  };

  // ---- the existing device, on the claim it reads back ----
  const claims = [];
  const cl = (name, verdict, why, c) => {
    const got = checkClaim({ secret: SECRET, claim: c });
    if (got !== verdict) throw new Error(`devicelink claim "${name}": the design says ${verdict}, the oracle says ${got}`);
    claims.push({ name, why, claim: c, expect: { verdict } });
  };
  const remac = (fields) => ({ ...fields, mac: mac(D.macKey, claimMacInput({ linkId: D.linkId, ...fields })) });
  cl('valid', 'ok', 'The claim the server stored, with a MAC only someone holding the link secret can make.', claim);
  cl('npub-swapped', 'bad_mac', 'The server swapped in its own nPub and kept the MAC.', { ...claim, nPub: b64u(OTHER_N_PUB) });
  cl('name-changed', 'bad_mac', 'The device name was changed.', { ...claim, name: nameOf('iPhone') });
  cl('platform-changed', 'bad_mac', 'The platform was changed.', { ...claim, platform: 'ios' });
  cl('commit-changed', 'bad_mac', 'commitN was replaced by the commitment to another nonce.', { ...claim, commitN: codeCommit(NONCE_E) });
  cl('mac-of-another-link', 'bad_mac', 'A MAC made with another link\'s key.', { ...claim, mac: mac(deriveDeviceLink(OTHER_SECRET).macKey, claimMacInput({ linkId: D.linkId, ...claim })) });
  cl('npub-of-31-bytes', 'bad_claim', 'nPub is not a b64_32.', remac({ ...claim, nPub: b64u(N_PUB.slice(0, 31)) }));
  cl('name-is-not-a-name', 'bad_claim', 'name holds U+202E, which the name type refuses, though the MAC over it is right.', remac({ ...claim, name: nameOf('Pixel' + cp(0x202e)) }));
  cl('name-is-plain-text', 'bad_claim', 'name is the text itself, not its base64url.', remac({ ...claim, name: 'Pixel 9' }));
  cl('name-of-65-bytes', 'bad_claim', 'name decodes to 65 bytes; the name type allows 1 to 64.', remac({ ...claim, name: nameOf('n'.repeat(65)) }));
  cl('platform-unknown', 'bad_claim', 'platform is not one of §2.3\'s values.', remac({ ...claim, platform: 'Android' }));
  cl('commit-uppercase', 'bad_claim', 'commitN is not lowercase hex.', remac({ ...claim, commitN: claim.commitN.toUpperCase() }));
  cl('mac-padded', 'bad_claim', 'mac is not a b64_32 (it is padded).', { ...claim, mac: claim.mac + '=' });
  cl('order-claim-before-mac', 'bad_claim', 'An unknown platform and a wrong MAC: bad_claim comes first.', { ...claim, platform: 'Android' });
  // nPub a low-order X25519 point (§2.4, the Device link row; RFC 7748 §6.1). The encodings are the
  // published list, each refused by @noble/curves' x25519; the MAC is right for the bytes sent, so
  // only the type check refuses them, before bad_mac.
  if (!LOW_ORDER_X25519_HEX.every((u) => isLowOrderX25519(unhex(u))) || isLowOrderX25519(N_PUB) || isLowOrderX25519(OTHER_N_PUB)) {
    throw new Error('devicelink: @noble and the published list disagree about the low-order points');
  }
  const lowOrder = (index) => b64u(unhex(LOW_ORDER_X25519_HEX[index]));
  cl('npub-low-order-zero', 'bad_claim', 'nPub is the all-zero point (u = 0, of order 2), a low-order X25519 point: every key agreement with it gives the all-zero value, so whatever outer is sealed to it is no secret. The MAC over these bytes is right.', remac({ ...claim, nPub: lowOrder(0) }));
  cl('npub-low-order-one', 'bad_claim', 'nPub is u = 1 (01 then 31 zero bytes), a point of order 4: low-order. The MAC over these bytes is right.', remac({ ...claim, nPub: lowOrder(1) }));
  cl('npub-low-order-eight', 'bad_claim', 'nPub is ' + LOW_ORDER_X25519_HEX[2] + ', a point of order 8 from the published list: low-order although its bytes look like any key, so a check for 0 and 1 alone does not catch it. The MAC over these bytes is right.', remac({ ...claim, nPub: lowOrder(2) }));
  const changed = [
    { why: 'a later poll shows the same claim', fixed: claim, later: claim, expect: { verdict: claimStill(claim, claim) } },
    ...[['nPub', b64u(OTHER_N_PUB)], ['name', nameOf('iPhone')], ['platform', 'ios'], ['commitN', codeCommit(NONCE_E)]].map(([k, v]) => ({
      why: `a later poll shows another ${k} than the claim the existing device fixed when it drew nonceE: the link is cancelled`, fixed: claim, later: { ...claim, [k]: v }, expect: { verdict: claimStill(claim, { ...claim, [k]: v }) },
    })),
  ];
  if (changed.map((r) => r.expect.verdict).join() !== 'ok,claim_changed,claim_changed,claim_changed,claim_changed') throw new Error('devicelink claim_changed fixtures');
  const nonceChanged = [
    { why: 'the poll serves the nonceE the new device already holds', heldB64: b64u(NONCE_E), servedB64: b64u(NONCE_E), expect: { verdict: 'ok' } },
    { why: 'a different nonceE is served after the first: the link is cancelled', heldB64: b64u(NONCE_E), servedB64: b64u(fixed('devicelink/nonce-e/other')), expect: { verdict: 'nonce_changed' } },
  ];

  // ---- the new device, before any password prompt ----
  const outers = [];
  const ou = (name, verdict, why, input = {}) => {
    const full = { outer, pinnedOrigin: X, approveMac, ...input };
    const got = openOuter({ outer: full.outer, nPub: N_PUB, nSec: N_SEC, pinnedOrigin: full.pinnedOrigin, secret: SECRET, approveMac: full.approveMac });
    if (got.verdict !== verdict) throw new Error(`devicelink outer "${name}": the design says ${verdict}, the oracle says ${got.verdict}`);
    const row = { name, why, outerB64: b64u(full.outer), pinnedOrigin: full.pinnedOrigin, approveMac: full.approveMac };
    if (input.text !== undefined) row.plaintextUtf8 = input.text;
    row.expect = verdict === 'ok' ? { verdict, outer: got.outer } : { verdict };
    outers.push(row);
  };
  const withText = (label, text) => {
    const sealed = sealOuter(label, text);
    return { outer: sealed, approveMac: mac(D.macKey, approveMacInput({ linkId: D.linkId, outer: sealed })), text };
  };
  ou('valid', 'ok', 'The existing device\'s outer opens, names the origin this device pinned before it claimed, and its MAC is right: only now may the password screen show.', { text: outerText() });
  ou('keys-in-another-order', 'ok', 'The four keys in another order.', withText('order', `{"email":"${EMAIL}","userId":"${alice.userId}","origin":"${X}","v":2}`));
  ou('email-with-an-escaped-quote', 'bad_outer', 'The JSON escape of " is well formed, but a quote is not in the dot-atom of spec 01 §5.5, so the address a"b@example.com has no emailNorm and email fails its type (this row was ok before the dot-atom rule; no emailNorm can now hold " or ' + BS + ').', withText('quote', outerText({ email: 'a"b@example.com' })));
  const macFor = (sealed) => ({ outer: sealed, approveMac: mac(D.macKey, approveMacInput({ linkId: D.linkId, outer: sealed })) });
  ou('sealed-to-another-key', 'outer_unopenable', 'The existing device sealed the outer to another key than this device\'s; the approveMac over those bytes is right.', macFor(sealOuter('other-key', outerText(), OTHER_N_PUB)));
  ou('truncated', 'outer_unopenable', 'The first 40 bytes of a seal, with the approveMac over those 40 bytes.', macFor(outer.slice(0, 40)));
  ou('extra-key', 'bad_outer', 'A fifth key.', withText('extra', outerText({ name: 'x' })));
  ou('missing-email', 'bad_outer', 'No email.', withText('missing', `{"v":2,"origin":"${X}","userId":"${alice.userId}"}`));
  ou('key-twice', 'bad_outer', 'origin twice.', withText('twice', `{"v":2,"origin":"${X}","origin":"${X}","userId":"${alice.userId}","email":"${EMAIL}"}`));
  ou('v-is-3', 'bad_outer', 'v is not the number 2.', withText('v3', outerText({ v: 3 })));
  ou('v-is-a-string', 'bad_outer', 'v is the string "2".', withText('vstr', outerText({ v: '2' })));
  ou('v-as-2.0', 'bad_outer', 'v written 2.0: numbers are in the int text form.', withText('v20', outerText().replace('"v":2', '"v":2.0')));
  ou('white-space', 'bad_outer', 'A space after a colon: the text is compact JSON.', withText('space', outerText().replace('"v":', '"v": ')));
  ou('escaped-slashes', 'bad_outer', 'Slashes written as ' + BS + '/: strings escape only " and ' + BS + '.', withText('slashes', outerText().replaceAll('/', BS + '/')));
  ou('origin-with-a-path', 'bad_outer', 'origin is not in the origin grammar.', withText('path', outerText({ origin: X + '/' })));
  ou('user-id-uppercase', 'bad_outer', 'userId is not a uuid.', withText('uuid', outerText({ userId: 'AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA' })));
  ou('email-not-normal', 'bad_outer', 'email is not its own emailNorm.', withText('email', outerText({ email: 'Alice@example.com' })));
  ou('not-json', 'bad_outer', 'Not JSON.', withText('notjson', 'v=2&origin=' + X));
  const badUtf8 = sealOuter('utf8', Uint8Array.of(0x7b, 0xff, 0x7d));
  ou('invalid-utf8', 'bad_outer', 'The plaintext is not valid UTF-8.', { outer: badUtf8, approveMac: mac(D.macKey, approveMacInput({ linkId: D.linkId, outer: badUtf8 })) });
  ou('origin-is-not-the-pinned-one', 'origin_mismatch', 'outer.origin differs from the origin pinned in step 0: refused before any password prompt.', withText('other-origin', outerText({ origin: 'https://evil.example.org' })));
  ou('pinned-another-origin', 'origin_mismatch', 'The genuine outer, on a device that pinned another origin for this link.', { pinnedOrigin: 'https://other.example.org' });
  const forged = sealOuter('forged', outerText({ email: 'victim@example.com' }));
  ou('outer-made-by-the-server', 'bad_mac', 'FC-3: a swapped outer. The server alone made up an outer for an email of its choosing and kept the genuine approveMac: it fails here, before anything is opened and before any password prompt.', { outer: forged });
  ou('approve-mac-of-another-link', 'bad_mac', 'An approveMac made with another link\'s key.', { approveMac: mac(deriveDeviceLink(OTHER_SECRET).macKey, approveMacInput({ linkId: D.linkId, outer })) });
  ou('order-decode-before-origin', 'bad_outer', 'A fifth key and another origin: bad_outer comes first.', withText('order-1', outerText({ origin: 'https://evil.example.org', name: 'x' })));
  ou('order-mac-before-unopenable', 'bad_mac', 'An outer sealed to another key and the genuine outer\'s approveMac: bad_mac comes first, the MAC is over the raw sealed bytes.', { outer: sealOuter('order-2', outerText(), OTHER_N_PUB) });
  ou('order-mac-before-decode', 'bad_mac', 'A fifth key and a wrong approveMac: bad_mac comes first.', { outer: sealOuter('order-3', outerText({ name: 'x' })) });
  ou('order-mac-before-origin', 'bad_mac', 'Another origin and a wrong approveMac: bad_mac comes first.', { outer: sealOuter('order-4', outerText({ origin: 'https://evil.example.org' })) });
  // Fourth batch (spec 01 §5.5): outer.email must be an emailNorm.
  ou('email-in-a-display-name-form', 'bad_outer', 'email is alice<alice@example.com>: lower case, one @, printable ASCII, but not a dot-atom local part, so it is not an emailNorm (spec 01 §5.5).', withText('email-display-name', outerText({ email: 'alice<alice@example.com>' })));

  // ---- the new device, after the pickup and the unlock ----
  const bundles = [];
  const bu = (name, verdict, why, input = {}) => {
    const full = { inner: null, sessionUserId: alice.userId, genesis: genesis.frame, pin, chain: CHAIN, ...input };
    const inner = full.inner ?? sealInner(name, JSON.stringify(full.bundle ?? goodBundle()));
    const got = openBundle({ inner, uvk: UVK, secret: SECRET, sessionUserId: full.sessionUserId, seed: alice.seed, genesis: full.genesis, pin: full.pin, chain: full.chain });
    if (got.verdict !== verdict) throw new Error(`devicelink bundle "${name}": the design says ${verdict}, the oracle says ${got.verdict}`);
    // A row names its session, genesis, pin and verified chain only where they differ from `bundleDefaults`.
    const row = { name, why, innerB64: b64u(inner) };
    if (input.sessionUserId !== undefined) row.sessionUserId = full.sessionUserId;
    if (input.genesis !== undefined) row.genesisB64 = b64u(full.genesis);
    if (input.pin !== undefined) row.pin = full.pin;
    if (input.chain !== undefined) row.verifiedChain = full.chain;
    if (input.text !== undefined && input.text.length < 2000) row.plaintextUtf8 = input.text;
    if (verdict !== 'ok') row.expect = { verdict };
    else if (input.summary) row.expect = { verdict, plaintextBytes: input.summary, contacts: got.bundle.contacts.length, vaults: got.bundle.vaults.length };
    else row.expect = { verdict, bundle: got.bundle };
    bundles.push(row);
  };
  const text = (label, t) => ({ inner: sealInner(label, t), text: typeof t === 'string' ? t : undefined });
  const J = (o) => JSON.stringify(goodBundle(o));
  const reversed = (v) => {
    if (Array.isArray(v)) return '[' + v.map(reversed).join(',') + ']';
    if (v !== null && typeof v === 'object') return '{' + Object.keys(v).reverse().map((k) => JSON.stringify(k) + ':' + reversed(v[k])).join(',') + '}';
    return JSON.stringify(v);
  };
  bu('valid', 'ok', 'The bundle opens under the key derived from the account\'s UVK and this link, decodes, names this account and its seed-derived key, and its card checkpoint is in the chain this device verified for the origin it pinned.', { text: J() });
  bu('checkpoint-below-the-verified-chain', 'ok', 'The bundle\'s card checkpoint is card 1; this device\'s verified chain goes on to card 2 and contains it.', text('ok-older-card', J({ card: { seq: 1, hash: CHAIN[1] } })));
  bu('no-contacts-no-vaults', 'ok', 'Empty contacts and vaults.', text('ok-empty', J({ contacts: [], vaults: [] })));
  bu('keys-in-another-order', 'ok', 'The twelve keys in the reverse order, and each inner object\'s keys too.', text('ok-reversed', reversed(goodBundle())));
  bu('account-state-seq-at-the-largest-int', 'ok', 'accountState.seq is 2^53 - 1, the largest int.', text('ok-max-int', J({ accountState: { seq: 9007199254740991, hash: h('x') } })));
  bu('inner-from-another-link', 'bundle_unopenable', 'FC-3: an inner made for another link of the same account fails here, on its AD and key.', { inner: sealInner('other-link', J(), OTHER_SECRET) });
  bu('inner-under-another-uvk', 'bundle_unopenable', 'An inner made by someone without this account\'s UVK.', { inner: sealInner('other-uvk', J(), SECRET, fixed('devicelink/other-uvk')) });
  bu('inner-truncated', 'bundle_unopenable', 'An envelope of 30 bytes.', { inner: sealInner('truncated', J()).slice(0, 30) });
  const otherVersion = sealInner('version', J());
  otherVersion[0] = 0x02;
  bu('inner-with-another-envelope-version', 'bundle_unopenable', 'The envelope\'s first byte is 0x02.', { inner: otherVersion });
  const without = (key) => {
    const b = goodBundle();
    delete b[key];
    return JSON.stringify(b);
  };
  bu('missing-key', 'bad_bundle', 'No accountState.', text('missing', without('accountState')));
  bu('extra-key', 'bad_bundle', 'An extra top-level key.', text('extra', J({ recovery: { posture: 'operator' } })));
  bu('extra-key-in-a-contact', 'bad_bundle', 'An extra key inside a contact entry.', text('extra-contact', J({ contacts: [{ userId: bob.userId, keyHash: keyHash(bob.identityPub), verifiedAt: T0 + 1000, label: 'Qm9i' }] })));
  bu('key-twice', 'bad_bundle', 'userId twice at the top level.', text('twice', J().replace('"userId":', `"userId":"${alice.userId}","userId":`)));
  bu('key-twice-inside-card', 'bad_bundle', 'seq twice inside card: no key twice at any level.', text('twice-card', J().replace('"card":{"seq":2,', '"card":{"seq":2,"seq":2,')));
  bu('v-is-3', 'bad_bundle', 'v is not the number 2.', text('v3', J({ v: 3 })));
  bu('v-as-2.0', 'bad_bundle', 'v written 2.0.', text('v20', J().replace('"v":2', '"v":2.0')));
  bu('seq-with-a-leading-zero', 'bad_bundle', 'card.seq written 02.', text('seq02', J().replace('"card":{"seq":2', '"card":{"seq":02')));
  bu('seq-in-exponent-form', 'bad_bundle', 'card.seq written 2e0.', text('seq2e0', J().replace('"card":{"seq":2', '"card":{"seq":2e0')));
  bu('negative-zero', 'bad_bundle', 'accountState.seq written -0.', text('negzero', J({ accountState: { seq: 0, hash: h('x') } }).replace('"accountState":{"seq":0', '"accountState":{"seq":-0')));
  bu('white-space', 'bad_bundle', 'A space after a colon.', text('space', J().replace('"v":', '"v": ')));
  bu('a-line-feed-at-the-end', 'bad_bundle', 'A trailing line feed.', text('lf', J() + '\n'));
  bu('unicode-escape', 'bad_bundle', 'An escape other than ' + BS + '" and ' + BS + BS + ' inside a string.', text('escape', J().replace('"email":"alice@', '"email":"' + BS + 'u0061lice@')));
  bu('origin-plain-http', 'bad_bundle', 'origin outside the origin grammar.', text('origin', J({ origin: 'http://192.168.1.10' })));
  bu('card-hash-uppercase', 'bad_bundle', 'card.hash is not lowercase hex.', text('hash', J({ card: { seq: 2, hash: CHAIN[2].toUpperCase() } })));
  bu('identity-pub-padded', 'bad_bundle', 'identityPub is not a b64_32.', text('idpub', J({ identityPub: alice.key + '=' })));
  bu('email-not-normal', 'bad_bundle', 'email is not an emailNorm.', text('email', J({ email: 'Alice@example.com' })));
  bu('verified-at-zero', 'bad_bundle', 'contacts[].verifiedAt is not an ms.', text('ms', J({ contacts: [{ userId: bob.userId, keyHash: keyHash(bob.identityPub), verifiedAt: 0 }] })));
  bu('contacts-is-an-object', 'bad_bundle', 'contacts is not an array.', text('contacts-object', J({ contacts: {} })));
  bu('account-state-seq-is-a-string', 'bad_bundle', 'accountState.seq is a string.', text('seq-string', J({ accountState: { seq: '7', hash: h('x') } })));
  bu('account-state-seq-is-2-to-the-53', 'bad_bundle', 'accountState.seq is 2^53, one more than the largest int.', text('int-over', J().replace('"accountState":{"seq":7', '"accountState":{"seq":9007199254740992')));
  bu('vaults-is-null', 'bad_bundle', 'vaults is null.', text('vaults-null', J().replace(/"vaults":\[[^\]]*\]/, '"vaults":null')));
  bu('issued-at-is-true', 'bad_bundle', 'issuedAt is true.', text('issued-true', J().replace(/"issuedAt":[0-9]+/, '"issuedAt":true')));
  bu('invalid-utf8', 'bad_bundle', 'The plaintext is not valid UTF-8.', { inner: sealInner('utf8', Uint8Array.of(0x7b, 0xff, 0x7d)) });
  bu('not-json', 'bad_bundle', 'Not JSON.', text('notjson', 'bundle'));

  // The size cap: a bundle of exactly 65,536 bytes decodes; one byte more does not.
  const sized = (bytes) => {
    const contact = (i) => ({ userId: '00000000-0000-4000-8000-' + String(i).padStart(12, '0'), keyHash: h('contact-' + (i % 7)), verifiedAt: T0 + i });
    const make = (n, emailLocal) => JSON.stringify(goodBundle({ contacts: Array.from({ length: n }, (_, i) => contact(i)), email: emailLocal + '@example.com' }));
    let n = 0;
    while (make(n + 1, 'a').length <= bytes) n++;
    const gap = bytes - make(n, 'a').length;
    const out = make(n, 'a'.repeat(1 + gap));
    if (out.length !== bytes || n >= BUNDLE_MAX_ENTRIES || 1 + gap > EMAIL_LOCAL_MAX || emailNorm('a'.repeat(1 + gap) + '@example.com') === null) throw new Error('devicelink: cannot size a bundle to ' + bytes);
    return out;
  };
  bu('exactly-65536-bytes', 'ok', `A bundle of exactly ${BUNDLE_MAX_BYTES} bytes, with several hundred contact checkpoints. This row gives the plaintext length and the entry counts in place of the decoded bundle.`, { inner: sealInner('size-ok', sized(BUNDLE_MAX_BYTES)), summary: BUNDLE_MAX_BYTES });
  bu('65537-bytes', 'bad_bundle', 'One byte over the 64 KiB cap.', { inner: sealInner('size-over', sized(BUNDLE_MAX_BYTES + 1)) });

  bu('user-id-is-not-the-sessions', 'identity_mismatch', 'The bundle names another userId than the session the pickup returned.', text('id-user', J({ userId: bob.userId })));
  bu('identity-pub-is-not-the-seeds', 'identity_mismatch', 'The bundle\'s identityPub is not the key derived from the unlocked seed.', text('id-key', J({ identityPub: bob.key })));
  bu('personal-vault-is-not-the-genesis', 'identity_mismatch', 'The bundle\'s personalVaultId is not the one the verified genesis names.', text('id-vault', J({ personalVaultId: ids.otherPersonalVault })));
  bu('genesis-signed-by-another-account', 'signer_not_pinned_key', 'The bundle is fine, but the genesis served with the account keys does not verify: a genesis verdict.',
    { genesis: signed('account-genesis', bob, { userId: alice.userId, identityKey: alice.key, instanceId: ids.instance, personalVaultId: ids.personalVault, createdAt: T0 }).frame });
  bu('genesis-of-another-user', 'user_mismatch', 'The genesis is signed by this account\'s key but names another userId than the session: a genesis verdict.',
    { genesis: signed('account-genesis', alice, { userId: bob.userId, identityKey: alice.key, instanceId: ids.instance, personalVaultId: ids.personalVault, createdAt: T0 }).frame });
  bu('genesis-truncated', 'bad_frame', 'The served genesis is 60 bytes of a frame: a genesis verdict from the parse.', { genesis: genesis.frame.slice(0, 60) });
  bu('genesis-of-another-instance', 'instance_mismatch', 'The genesis names another instance than the pinned card: a genesis verdict.',
    { genesis: signed('account-genesis', alice, { userId: alice.userId, identityKey: alice.key, instanceId: ids.otherInstance, personalVaultId: ids.personalVault, createdAt: T0 }).frame });
  bu('bundle-origin-is-not-the-pin', 'pin_mismatch', 'T2-B1: the bundle\'s origin is not the origin this device pinned in step 0. It signs out, removes that pin and shows "This isn\'t the server your other device uses. Nothing was linked."', text('pin-origin', J({ origin: 'https://other.example.org' })));
  bu('bundle-instance-is-not-the-pin', 'pin_mismatch', 'The bundle\'s instanceId is not the pinned card\'s.', text('pin-instance', J({ instanceId: ids.otherInstance })));
  bu('bundle-card-is-another-hash', 'pin_mismatch', 'The bundle\'s card checkpoint names another hash at seq 2 than this device\'s verified chain.', text('pin-card', J({ card: { seq: 2, hash: h('another-card-2') } })));
  bu('bundle-card-is-ahead-of-the-chain', 'pin_mismatch', 'The checkpoint is card 5; after fetching forward this device\'s chain still ends at card 2.', text('pin-ahead', J({ card: { seq: 5, hash: h('card-5') } })));
  bu('order-decode-before-identity', 'bad_bundle', 'An extra key and another userId: bad_bundle comes first.', text('order-1', J({ userId: bob.userId, extra: 1 })));
  bu('order-identity-before-pin', 'identity_mismatch', 'Another userId and another origin: identity_mismatch comes first.', text('order-2', J({ userId: bob.userId, origin: 'https://other.example.org' })));
  const genesisByBob = signed('account-genesis', bob, { userId: alice.userId, identityKey: alice.key, instanceId: ids.instance, personalVaultId: ids.personalVault, createdAt: T0 }).frame;
  const genesisElsewhere = signed('account-genesis', alice, { userId: alice.userId, identityKey: alice.key, instanceId: ids.otherInstance, personalVaultId: ids.personalVault, createdAt: T0 }).frame;
  bu('order-genesis-before-pin', 'signer_not_pinned_key', 'A genesis that does not verify and a bundle for another origin: the genesis verdict comes first.',
    { ...text('order-3', J({ origin: 'https://other.example.org' })), genesis: genesisByBob });
  bu('order-genesis-before-unopenable', 'signer_not_pinned_key', 'A genesis that does not verify and an inner from another link. The genesis is verified at the unlock, before the bundle is touched: its verdict comes first.',
    { inner: sealInner('order-4', J(), OTHER_SECRET), genesis: genesisByBob });
  bu('order-genesis-before-decode', 'instance_mismatch', 'A genesis that names another instance and a bundle with an extra key: the genesis verdict comes first.',
    { ...text('order-5', J({ extra: 1 })), genesis: genesisElsewhere });
  bu('order-genesis-before-identity', 'signer_not_pinned_key', 'A genesis that does not verify and a bundle that names another userId: the genesis verdict comes first.',
    { ...text('order-6', J({ userId: bob.userId })), genesis: genesisByBob });
  bu('order-genesis-before-identity-key', 'instance_mismatch', 'A genesis that names another instance and a bundle whose identityPub is not the seed\'s: the genesis verdict comes first.',
    { ...text('order-7', J({ identityPub: bob.key })), genesis: genesisElsewhere });
  // Fourth batch (spec 01 §5.5): the bundle's email must be an emailNorm, and one with the right
  // bytes, case and @ count that is not a dot-atom at a host is not.
  bu('email-in-a-display-name-form', 'bad_bundle', 'email is alice<alice@example.com>: lower case, one @, printable ASCII, but not a dot-atom local part, so it is not an emailNorm (spec 01 §5.5).', text('email-display-name', J({ email: 'alice<alice@example.com>' })));

  // ---- what the new device imports ----
  const stateContacts = {
    [bob.userId]: { userId: bob.userId, identityPub: bob.key },
    [carol.userId]: { userId: carol.userId, identityPub: dave.key },
  };
  const bundleContacts = [
    { userId: bob.userId, keyHash: keyHash(bob.identityPub), verifiedAt: T0 + 1000 },
    { userId: carol.userId, keyHash: keyHash(carol.identityPub), verifiedAt: T0 + 2000 },
    { userId: dave.userId, keyHash: keyHash(dave.identityPub), verifiedAt: T0 + 3000 },
  ];
  const currency = [{
    why: 'The bundle confers currency, never contacts. bob is in the merged account state with the same key hash: current. carol is there with ANOTHER key: not current. dave is in the bundle but not in the account state: not a contact at all.',
    bundleContacts, accountStateContacts: stateContacts, expect: { current: currentFromBundle(bundleContacts, stateContacts) },
  }];
  if (currency[0].expect.current.join() !== bob.userId) throw new Error('devicelink currency fixture');
  const keyHashRows = [alice, bob].map((a) => ({ identityPubB64: b64u(a.identityPub), keyHash: keyHash(a.identityPub) }));

  const cpRow = (why, held, hashes) => ({ why, held, servedHashes: hashes, expect: { verdict: compareWithHead(held, hashes) } });
  const checkpoints = [
    cpRow('a vault or card checkpoint against a served chain that holds it and goes on', { seq: 2, hash: CHAIN[2] }, [...CHAIN, h('card-3')]),
    cpRow('the served chain ends below the checkpoint: withholding', { seq: 2, hash: CHAIN[2] }, CHAIN.slice(0, 2)),
    cpRow('nothing is served', { seq: 2, hash: CHAIN[2] }, []),
    cpRow('the served chain has another hash at the checkpoint\'s seq: a fork', { seq: 2, hash: CHAIN[2] }, [CHAIN[0], CHAIN[1], h('another-card-2')]),
  ];
  if (checkpoints.map((r) => r.expect.verdict).join() !== 'ok,withheld,withheld,fork') throw new Error('devicelink checkpoint fixtures');
  const sealedState = 'AQF-the-served-sealedState-string';
  const asCheckpoint = { seq: 7, hash: hex(sha256(sealedState)) };
  const asRow = (why, served) => ({ why, checkpoint: asCheckpoint, served, expect: checkAccountStateCheckpoint(asCheckpoint, served) });
  const accountStateRows = [
    asRow('the served state is the one the bundle named: the same in-blob seq and the same hash over the sealedState string', { seq: 7, sealedState }),
    asRow('a newer state', { seq: 9, sealedState: 'AQF-a-newer-sealedState' }),
    asRow('a served state below the checkpoint: a rollback, kept out', { seq: 6, sealedState: 'AQF-an-older-sealedState' }),
    asRow('another blob at the same in-blob seq: a fork', { seq: 7, sealedState: 'AQF-another-sealedState' }),
  ];

  return {
    _about: [
      'Device linking of design 2026-11-15-onboarding-trust §8, with the derivations of §2.3 and the verdict strings and order of §2.4 (the row "Device link"). E is the existing device, N the new one.',
      'Hand-authored from the independent oracle in tools/vector-gen/oracle (Node WebCrypto and @noble; no andvari code). Regenerate with `npm run generate` there; `npm run check` fails on any difference. Secrets, nonces and ephemeral keys are fixed.',
      'derive: linkId = b64url(HKDF(s, "andvari/v2|device-link|id", 16)); macKey = HKDF(s, "andvari/v2|device-link|mac", 32). bundleKey = HKDF(UVK, "andvari/v2|device-link|bundle|" + linkId, 32), envelope AD "andvari/v2|device-link-bundle|" + linkId.',
      'url: https://andvaripass.com/d#v2.<O>.<S>, exactly three parts; parsing as for /l links (white space is space, tab, CR and LF; the fragment with or without its #; canonical base64url; a 32-byte secret; the origin grammar; at most 512 characters). expect.verdict ok or bad_link.',
      'commitN = hexLower(SHA-256("andvari/v2|code-commit|" + b64url(nonceN))); a reveal that does not hash to it is bad_reveal. code = u32be(SHA-256("andvari/v2|device-link|code|" + linkId + "|" + nPub + "|" + b64url(nonceN) + "|" + b64url(nonceE))[0..4]) mod 10^6, six digits. typedCode: the text typed into E (`typed`) against the code N shows (`code`, one of the `code` rows): ok, or code_mismatch, which cancels the link. It is compared as text under the rule of §6.11 that §8.2 step 5 applies here: every ASCII space (U+0020) is removed from `typed`, wherever it stands, and what is left must be exactly six ASCII digits equal to `code`. Nothing else is normalised: the code without its leading zero (five digits, the same number), a tab between the digits and a seventh digit are each code_mismatch. `typed` is to be passed on exactly as the JSON string decodes. The first three typedCode rows are unchanged; the six after them were added on 2026-11-15 with that rule.',
      'macs: all are b64url(HMAC-SHA-256(macKey, inputUtf8)). claim: "andvari/v2|device-link|claim|" + linkId + "|" + nPub + "|" + name + "|" + platform + "|" + commitN, with name the claim\'s name field as sent. pickup proof: "andvari/v2|device-link|pickup|" + linkId + "|" + nPub; proofHash = hexLower(SHA-256 over the proof\'s 43 ASCII characters). approve: "andvari/v2|device-link|approve|" + linkId + "|" + hexLower(SHA-256(raw outer)): it covers outer only (FC-3).',
      'claim: E checks the claim it reads back. bad_claim: a field outside its type (nPub a b64_32 that is not a low-order X25519 point, name the name type, platform one of §2.3\'s values, commitN a hex64, mac a b64_32); then bad_mac. A low-order point is one whose product with every clamped scalar is the all-zero value (RFC 7748 §6.1): after masking the top bit and reducing mod p, as RFC 7748 §5 decodes u, it is 0, 1, p - 1 or one of the two points of order 8; the rows use three canonical encodings from the published list (0, 1 and e0eb7a7c...b800), each under a MAC that is right for its bytes. Changed on 2026-11-15: the three rows npub-low-order-zero, npub-low-order-one and npub-low-order-eight are new, at the end of `claim`; every other row of this file is unchanged. claimChanged: a later poll against the claim E fixed when it drew nonceE. nonceChanged: N is served another nonceE than the first it held.',
      'outer: N\'s checks before any password prompt, with N\'s key pair `newDevice`, in this order. bad_mac first (approveMac covers the raw sealed bytes, so it is checked before anything is opened or parsed); outer_unopenable (the seal does not open); bad_outer (not exactly {v, origin, userId, email} with v the number 2, an origin, a uuid and an email that is its own emailNorm, in compact JSON); origin_mismatch (not the origin pinned in step 0). Only on ok may N show the password screen.',
      'bundle: N\'s checks after the pickup and the unlock, with the account\'s UVK and identity seed, the session\'s userId, the served genesis, the pin N made in step 0 ({origin, instanceId}) and `verifiedChain`, the hash at each seq of the card chain N has verified for that origin (after fetching forward). A row names sessionUserId, genesisB64, pin or verifiedChain only where it differs from `bundleDefaults`; plaintextUtf8, where given, is the text sealed in innerB64. The genesis verdicts come first (accountgenesis.json): the genesis is verified when the device unlocks, as at every unlock, before the bundle is touched. Then bundle_unopenable; bad_bundle (the strict decode of §8.3); identity_mismatch (the bundle\'s userId, identityPub or personalVaultId against the session, the seed-derived key and the verified genesis); pin_mismatch (the bundle\'s origin, instanceId or card checkpoint against the pin, also when the chain ends below the checkpoint).',
      'Compact JSON, for outer and the bundle: no white space outside strings; strings escape only " and the backslash; numbers in the int or ms text form (2.0, 2e0, 02 and -0 are refused); keys in any order; no key twice at any level.',
      'imports: a bundle contact makes a contact current only where the merged account state holds that userId with the same key hash (SHA-256 over the raw 32 key bytes). checkpoints: a vault or card checkpoint {seq, hash} against the served hashes: ok, withheld or fork (the function graded in vaultlog.json). accountState: a high-water mark of the document\'s in-blob seq, with hash = SHA-256 over the ASCII bytes of the served sealedState string: a served state below it is a rollback, another hash at the same seq a fork.',
      'The cap of 1,000 entries in contacts or vaults cannot be exercised on its own: 1,001 entries of the smallest form are already more than 65,536 bytes.',
      'The extension links no devices and grades none of these rows, and neither does the web client, which must not run or approve a device link (§13).',
      'Changed on 2026-11-15, fourth batch, with the dot-atom and domain rule of emailNorm (spec 01 §5.5): outer.email and the bundle\'s email must be emailNorms. One expectation changed: outer row email-with-an-escaped-quote (email a"b@example.com) was ok and is now bad_outer, because a quote is not in the dot-atom; no emailNorm can hold " or a backslash any more, so no valid outer has an escaped character. Two rows are new, each at the end of its section: outer email-in-a-display-name-form (bad_outer) and bundle email-in-a-display-name-form (bad_bundle), both with alice<alice@example.com>. No other row changed.',
    ],
    origin: X,
    account: { ...describe(alice), uvkB64: b64u(UVK), email: EMAIL },
    link: { secretB64: b64u(SECRET), linkId: D.linkId, macKeyB64: b64u(D.macKey), url },
    newDevice: { nSecB64: b64u(N_SEC), nPubB64: b64u(N_PUB), nonceNB64: b64u(NONCE_N), commitN },
    existingDevice: { nonceEB64: b64u(NONCE_E) },
    derive,
    bundleKey: bundleKeys,
    url: { compose: [{ origin: X, secretB64: S, url }], parse },
    reveal,
    code,
    typedCode: typed,
    macs,
    claim: claims,
    claimChanged: changed,
    nonceChanged,
    outer: outers,
    bundleDefaults: { sessionUserId: alice.userId, genesisB64: b64u(genesis.frame), pin, verifiedChain: CHAIN },
    bundle: bundles,
    imports: { keyHash: keyHashRows, currency },
    checkpoints,
    accountState: accountStateRows,
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
  const secret = mustUnb64u(doc.link.secretB64);
  const uvk = mustUnb64u(doc.account.uvkB64);
  const seed = mustUnb64u(doc.account.seedB64);
  const nPub = mustUnb64u(doc.newDevice.nPubB64);
  const nSec = mustUnb64u(doc.newDevice.nSecB64);

  for (const row of doc.derive) {
    const d = deriveDeviceLink(mustUnb64u(row.secretB64));
    expect(d.linkId === row.linkId && b64u(d.macKey) === row.macKeyB64, 'derive: ' + row.why);
  }
  for (const row of doc.bundleKey) expect(b64u(bundleKey(mustUnb64u(row.uvkB64), row.linkId)) === row.bundleKeyB64 && bundleAd(row.linkId) === row.adUtf8 && row.infoUtf8 === 'andvari/v2|device-link|bundle|' + row.linkId, 'bundleKey: ' + row.why);
  for (const row of doc.url.compose) expect(composeDeviceLink({ origin: row.origin, secret: mustUnb64u(row.secretB64) }) === row.url, 'url compose');
  for (const row of doc.url.parse) {
    const got = parseDeviceLink(row.input);
    const want = row.expect.verdict === 'ok' ? { origin: row.expect.origin, secretB64: row.expect.secretB64 } : null;
    expect(same(got === null ? null : { origin: got.origin, secretB64: b64u(got.secret) }, want), 'url parse: ' + row.why);
  }
  for (const row of doc.reveal) expect(checkDeviceReveal(row.commitN, mustUnb64u(row.revealB64)) === row.expect.verdict, 'reveal: ' + row.why);
  for (const row of doc.code) {
    const input = deviceCodeInput({ linkId: row.linkId, nPub: row.nPubB64, nonceN: mustUnb64u(row.nonceNB64), nonceE: mustUnb64u(row.nonceEB64) });
    const c = codeFromInput(input);
    expect(input === row.inputUtf8 && c.digestHex === row.digestHex && c.code === row.code, 'code: ' + row.why);
  }
  for (const row of doc.typedCode) {
    expect(typedCodeVerdict(row.code, row.typed) === row.expect.verdict, 'typedCode: ' + row.why);
    // The rule once more, spelled out from §6.11 and not taken from the function under test: remove
    // every ASCII space, then exactly six ASCII digits, equal as text to the code. `code` is the
    // code of one of the code rows.
    const left = row.typed.split(' ').join('');
    const spelled = /^[0-9]{6}$/.test(left) && left === row.code ? 'ok' : 'code_mismatch';
    expect(spelled === row.expect.verdict && doc.code.some((c) => c.code === row.code), 'typedCode (the rule spelled out): ' + row.why);
  }
  for (const row of doc.macs.claim) {
    const input = claimMacInput(row);
    expect(input === row.inputUtf8 && mac(mustUnb64u(row.macKeyB64), input) === row.mac, 'claim mac');
  }
  for (const row of doc.macs.pickup) {
    const input = proofInput(row);
    const proof = mac(mustUnb64u(row.macKeyB64), input);
    expect(input === row.inputUtf8 && proof === row.proof && proofHash(proof) === row.proofHash && row.proof.length === 43, 'pickup proof');
  }
  for (const row of doc.macs.approve) {
    const outer = mustUnb64u(row.outerB64);
    const input = approveMacInput({ linkId: row.linkId, outer });
    expect(input === row.inputUtf8 && hex(sha256(outer)) === row.outerSha256Hex && mac(mustUnb64u(row.macKeyB64), input) === row.approveMac, 'approve mac');
  }
  for (const row of doc.claim) expect(checkClaim({ secret, claim: row.claim }) === row.expect.verdict, `claim ${row.name}`);
  for (const row of doc.claimChanged) expect(claimStill(row.fixed, row.later) === row.expect.verdict, 'claimChanged: ' + row.why);
  for (const row of doc.nonceChanged) expect((row.heldB64 === row.servedB64 ? 'ok' : 'nonce_changed') === row.expect.verdict, 'nonceChanged: ' + row.why);
  for (const row of doc.outer) {
    const got = openOuter({ outer: mustUnb64u(row.outerB64), nPub, nSec, pinnedOrigin: row.pinnedOrigin, secret, approveMac: row.approveMac });
    expect(same(got.verdict === 'ok' ? { verdict: 'ok', outer: got.outer } : { verdict: got.verdict }, row.expect), `outer ${row.name}: oracle says ${got.verdict}`);
    if (row.plaintextUtf8 !== undefined && got.verdict !== 'outer_unopenable') expect(row.expect.verdict !== 'ok' || same(decodeOuter(utf8(row.plaintextUtf8)), row.expect.outer), `outer ${row.name}: plaintextUtf8`);
  }
  for (const row of doc.bundle) {
    const r = { ...doc.bundleDefaults, ...row };
    const got = openBundle({ inner: mustUnb64u(r.innerB64), uvk, secret, sessionUserId: r.sessionUserId, seed, genesis: mustUnb64u(r.genesisB64), pin: r.pin, chain: r.verifiedChain });
    let shown = { verdict: got.verdict };
    if (got.verdict === 'ok' && row.expect.bundle !== undefined) shown = { verdict: 'ok', bundle: got.bundle };
    else if (got.verdict === 'ok') shown = { verdict: 'ok', plaintextBytes: JSON.stringify(got.bundle).length, contacts: got.bundle.contacts.length, vaults: got.bundle.vaults.length };
    expect(same(shown, row.expect), `bundle ${row.name}: oracle says ${got.verdict}`);
    if (row.plaintextUtf8 !== undefined) {
      const decoded = decodeBundle(utf8(row.plaintextUtf8));
      if (row.expect.verdict === 'bad_bundle') expect(decoded === null, `bundle ${row.name}: plaintextUtf8 should not decode`);
      else if (['ok', 'identity_mismatch', 'pin_mismatch'].includes(row.expect.verdict)) expect(decoded !== null, `bundle ${row.name}: plaintextUtf8 should decode`);
    }
  }
  for (const row of doc.imports.keyHash) expect(keyHash(mustUnb64u(row.identityPubB64)) === row.keyHash, 'keyHash');
  for (const row of doc.imports.currency) expect(same(currentFromBundle(row.bundleContacts, row.accountStateContacts), row.expect.current), 'currency');
  for (const row of doc.checkpoints) expect(compareWithHead(row.held, row.servedHashes) === row.expect.verdict, 'checkpoint: ' + row.why);
  for (const row of doc.accountState) expect(same(checkAccountStateCheckpoint(row.checkpoint, row.served), row.expect), 'accountState: ' + row.why);
  return { rows, failures };
}
