// recovery-v3.json: the version-3 answer of operator-assisted recovery (spec 04 §7 steps 3 to 5;
// spec 01 §5.1 and §5.5; spec 03 §18.5 and §18.6): the
// 0x09 statement with the address and the commit value, its sizes as a function of the address,
// the commit hash, the answer token, the person's device opening it, the server's checks on an
// upload and on the commit value. Written from the specification text of 2026-11-16 alone, before
// that day's corrections; corrected to its text as corrected the same day.

import { b64u, mustUnb64u, utf8, hex } from '../bytes.mjs';
import { boxSeal, envelopeSeal, x25519Base, sha256, boxKeypairFromSeed, signPubFromSeed } from '../prims.mjs';
import { PURPOSE_CODES } from '../frame.mjs';
import { signed, signedRaw, rawStatement, withToken, withoutKey } from '../build.mjs';
import { signedV, tokensOfV, describeTemplate } from '../versioned.mjs';
import { identitySeedAd, emailB64Of } from '../recoverycopy.mjs';
import { makeAnswer, openAnswerV3, commitHashOf, checkCommit, fulfilChecks, emailChars, emailCharsOf, answerSizes } from '../answer3.mjs';
import { alice, bob, operator, recoveryA, recoveryB, fixed, ids, T0, HOUR, describe } from '../cast.mjs';

export const file = 'recovery-v3.json';

const ASSIST = PURPOSE_CODES['assisted-recovery'];
const ALICE = 'alice@example.org';
const BOB = 'bob@example.org';
const LONGEST = 'x'.repeat(64) + '@' + 'a'.repeat(63) + '.' + 'b'.repeat(63) + '.' + 'c'.repeat(61);
const ISSUED = T0 + 200 * HOUR;
const flip = (frame) => {
  const out = frame.slice();
  out[37 + 10] ^= 0x01;
  return out;
};

export function build() {
  const rSec = fixed('recovery/request-secret');
  const rPub = x25519Base(rSec);
  const otherRPub = x25519Base(fixed('recovery/other-request-secret'));
  const requestId = b64u(fixed('recovery/request-id', 16));
  const otherRequestId = b64u(fixed('recovery/other-request-id', 16));
  const uvk = fixed('recovery/uvk');
  const bobUvk = fixed('escrow-v3/uvk/bob');
  const commit = fixed('recovery-v3/commit');
  const seedNonce = fixed('recovery/seed-nonce', 24);
  const encryptedSeed = envelopeSeal(uvk, seedNonce, identitySeedAd(alice.userId), alice.seed);
  const bobEncryptedSeed = envelopeSeal(bobUvk, seedNonce, identitySeedAd(bob.userId), bob.seed);

  const answerInput = (overrides = {}) => ({
    recovery: recoveryA, instanceId: ids.instance, userId: alice.userId, emailB64: emailB64Of(ALICE), requestId, requestKey: b64u(rPub),
    commit, uvkB64: b64u(uvk), issuedAt: ISSUED, ...overrides,
  });

  // ---- the answer as the tool makes it ----
  const answers = [];
  const made = {};
  const answerRow = (name, why, address, overrides = {}) => {
    const input = answerInput({ emailB64: emailB64Of(address), ephemeral: fixed('recovery-v3/ephemeral/' + name), ...overrides });
    const a = makeAnswer(input);
    const n = utf8(address).length;
    const E = emailChars(n);
    const sizes = answerSizes(E);
    if (a.statement.length !== sizes.statement || a.frame.length !== sizes.frame || a.sealed.length !== sizes.sealed || a.values.email.length !== E) {
      throw new Error(`recovery-v3 answer ${name}: the sizes are not 376 + E, 477 + E, 525 + E`);
    }
    made[name] = a;
    answers.push({
      name, why,
      input: {
        instanceId: input.instanceId, userId: input.userId, address, emailB64: input.emailB64, requestId: input.requestId, requestKey: input.requestKey,
        commitB64: b64u(input.commit), uvkB64: input.uvkB64, issuedAt: input.issuedAt, signer: 'recoveryA', ephemeralSecretB64: b64u(input.ephemeral),
      },
      expect: {
        emailOctets: n, emailChars: E, statementUtf8: a.statement, statementBytes: a.statement.length, messageHex: hex(a.message), signatureB64: b64u(a.signature),
        frameB64: b64u(a.frame), frameBytes: a.frame.length, sealedB64: b64u(a.sealed), sealedBytes: a.sealed.length,
        commitHashInputUtf8: a.commitHashInput, commitHash: a.commitHash, token: a.token,
      },
    });
    return a;
  };
  const answer = answerRow('alice', 'The answer for alice\'s request: the 0x09 statement, version 3, keys in the template\'s order; email is her copy\'s own email field; commit is the tool\'s fresh value; signed by recovery key A\'s signing key and sealed to the request key. A 17-octet address: 548 bytes sealed, the example the text gives.', ALICE);
  answerRow('bob', 'The answer for a request of bob\'s (15 octets, so 20 characters of base64url and 545 bytes sealed), sealed to the same request key.', BOB, { userId: bob.userId, uvkB64: b64u(bobUvk), commit: fixed('recovery-v3/commit/bob') });
  answerRow('shortest-address', 'A 5-octet address: E = 7, 532 bytes sealed.', 'a@b.c', { commit: fixed('recovery-v3/commit/shortest') });
  answerRow('longest-address', 'A 254-octet address: E = 339, 864 bytes sealed (under the upload\'s 1,024).', LONGEST, { commit: fixed('recovery-v3/commit/longest') });

  // ---- sizes as a function of the address ----
  const sizes = [3, 5, 15, 16, 17, 18, 19, 254].map((n) => ({ emailOctets: n, emailChars: emailChars(n), ...answerSizes(emailChars(n)) }));
  for (const row of sizes) {
    if (row.emailOctets < 5) continue;
    const address = row.emailOctets === 254 ? LONGEST : 'a'.repeat(row.emailOctets - 4) + '@b.c';
    if (utf8(address).length !== row.emailOctets) throw new Error('recovery-v3 sizes: address length');
    const a = makeAnswer(answerInput({ emailB64: emailB64Of(address), ephemeral: fixed('recovery-v3/ephemeral/size') }));
    if (a.statement.length !== row.statement || a.frame.length !== row.frame || a.sealed.length !== row.sealed) throw new Error('recovery-v3 sizes ' + row.emailOctets);
    row.checkedWith = address;
  }

  // ---- the commit hash ----
  const commitHash = [commit, fixed('recovery-v3/commit/bob'), new Uint8Array(32).fill(0xff)].map((c, i) => {
    const h = commitHashOf(b64u(c));
    return { why: ['alice\'s answer\'s commit value', 'bob\'s answer\'s', 'thirty-two 0xff bytes'][i], commitB64: b64u(c), inputUtf8: h.input, commitHash: h.commitHash };
  });

  // ---- the device opens it ----
  const request = { instanceId: ids.instance, userId: alice.userId, requestId, requestKey: b64u(rPub), typedEmail: ALICE };
  const values3 = (overrides = {}) => ({ instanceId: ids.instance, userId: alice.userId, email: emailB64Of(ALICE), requestId, requestKey: b64u(rPub), commit: b64u(commit), uvk: b64u(uvk), issuedAt: ISSUED, ...overrides });
  const v3 = (overrides = {}, signer = recoveryA) => signedV('assisted-recovery', 3, signer, values3(overrides));
  const t3 = (overrides) => tokensOfV('assisted-recovery', 3, values3(overrides));
  const rawV = (tokens, signer = recoveryA) => signedRaw(ASSIST, signer, rawStatement(tokens));
  const sealTo = (label, frame, to = rPub) => boxSeal(to, frame, fixed('recovery-v3/ephemeral/open/' + label));
  const open = [];
  const names = new Set();
  const device = (name, want, why, m, ctx = {}) => {
    if (names.has(name)) throw new Error('recovery-v3: duplicate row ' + name);
    names.add(name);
    const frame = m === null ? null : m.frame ?? m;
    const sealed = ctx.sealed ?? sealTo(name, frame);
    const input = {
      sealed, rPub, rSec, recoveryPub: (ctx.cardKey ?? recoveryA).publicKey, request: { ...request, ...ctx.request },
      encryptedIdentitySeed: ctx.encryptedSeed ?? encryptedSeed, identityPub: ctx.identityPub ?? alice.identityPub,
    };
    const got = openAnswerV3(input);
    const g = got.verdict === 'ok' ? got : { verdict: got.verdict };
    if (JSON.stringify(g) !== JSON.stringify(want)) throw new Error(`recovery-v3 device "${name}": the text says ${JSON.stringify(want)}, the oracle says ${JSON.stringify(g)}`);
    const row = { name, why };
    if (m && m.signer) row.signer = m.signer.name;
    if (ctx.signerNote) row.signer = ctx.signerNote;
    if (m && m.statement !== undefined) row.statementUtf8 = m.statement;
    Object.assign(row, {
      sealedB64: b64u(sealed), cardRecoveryFp: (ctx.cardKey ?? recoveryA).fp, recoveryPubB64: b64u(input.recoveryPub), request: input.request,
      encryptedIdentitySeedB64: b64u(input.encryptedIdentitySeed), identityPubB64: b64u(input.identityPub), expect: want,
    });
    open.push(row);
  };
  const OK = { verdict: 'ok', uvkB64: b64u(uvk), commitB64: b64u(commit) };
  const V = (verdict) => ({ verdict });
  device('valid', OK, 'The answer the tool made for alice\'s request, opened by the device that asked with her address: every check passes, and the device keeps the UVK and the commit value for the commit.', answer, { sealed: answer.sealed });
  device('fresh-install', OK, 'A fresh install holds no userId and skips that comparison; it still compares the address it asked with.', answer, { sealed: answer.sealed, request: { userId: null } });
  device('typed-address-in-another-form', OK, 'The person typed " Alice@EXAMPLE.org" when asking: the device compares the emailNorm of what was typed.', answer, { sealed: answer.sealed, request: { typedEmail: ' Alice@EXAMPLE.org' } });
  device('sealed-to-another-key', V('unopenable'), 'Sealed to another request key.', answer, { sealed: sealTo('other-key', answer.frame, otherRPub) });
  device('seal-cut-short', V('unopenable'), 'The first 40 bytes of the sealed answer.', null, { sealed: answer.sealed.slice(0, 40) });
  device('escrow-frame-inside', V('bad_frame'), 'The seal opens to a 0x02 frame.', signedV('escrow-uvk', 3, alice, { userId: alice.userId, email: emailB64Of(ALICE), identityKey: alice.key, recoveryFp: recoveryA.fp, issuedAt: ISSUED, key: b64u(uvk) }));
  device('bare-statement-inside', V('unknown_format'), 'The seal opens to the statement alone.', { frame: utf8(answer.statement), statement: answer.statement });
  device('frame-of-three-bytes', V('bad_frame'), 'The seal opens to the three bytes "avs": spec 01 §5.1\'s bad_frame for a frame under four bytes comes first in its checking order (§7 step 4).', { frame: utf8('avs') });
  device('magic-only', V('bad_frame'), 'The seal opens to the four bytes avs\\x02 and nothing more: the magic is right, the frame is shorter than any frame.', { frame: Uint8Array.of(0x61, 0x76, 0x73, 0x02) });
  device('not-canonical', V('non_canonical'), 'A space after a colon.', signedRaw(ASSIST, recoveryA, answer.statement.replace('"commit":', '"commit": ')));
  device('email-none', V('non_canonical'), 'email "none".', rawV(withToken(t3(), 'email', '"none"')));
  device('email-not-normal', V('non_canonical'), 'email is the base64url of "Alice@example.org", which is not normal.', rawV(withToken(t3(), 'email', '"' + b64u(utf8('Alice@example.org')) + '"')));
  device('commit-of-16-bytes', V('non_canonical'), 'commit is 16 bytes: it is a b64_32.', rawV(withToken(t3(), 'commit', '"' + requestId + '"')));
  device('commit-missing', V('non_canonical'), 'The version-3 keys without commit: no template has that key set.', rawV(withoutKey(t3(), 'commit')));
  device('email-missing', V('non_canonical'), 'The version-3 keys without email, with commit: no template has that key set.', rawV(withoutKey(t3(), 'email')));
  const oldAnswer = signed('assisted-recovery', recoveryA, { instanceId: ids.instance, userId: alice.userId, requestId, requestKey: b64u(rPub), uvk: b64u(uvk), issuedAt: ISSUED });
  device('old-form', V('bad_statement'), 'A genuine answer of the old form (version 2, no email, no commit), signed by the right key for this very request: canonical under the version-2 template, so bad_statement. A device takes only a version-3 answer.', oldAnswer);
  device('version-3-keys-with-v-2', V('bad_statement'), 'The version-3 key set with "v":2.', rawV(withToken(t3(), 'v', '2')));
  device('version-2-keys-with-v-3', V('bad_statement'), 'The version-2 key set with "v":3: canonical under the version-2 template, which this reader does not accept.', signedRaw(ASSIST, recoveryA, oldAnswer.statement.replace('{"v":2,', '{"v":3,')));
  device('signed-by-the-operator-account', V('signer_not_pinned_key'), 'Signed by the operator account\'s identity key: a server without the recovery key cannot sign an answer.', v3({}, operator));
  device('signed-by-another-recovery-seed', V('signer_not_pinned_key'), 'Signed by recovery key B; the pinned card names A.', v3({}, recoveryB));
  device('card-names-another-key', V('signer_not_pinned_key'), 'The valid answer, but this device\'s pinned card names recovery key B.', answer, { sealed: answer.sealed, cardKey: recoveryB });
  device('signature-flipped', V('bad_signature'), 'One signature bit flipped.', { frame: flip(answer.frame), statement: answer.statement }, { signerNote: 'recoveryA, then one signature bit flipped' });
  device('answer-for-another-address', V('request_mismatch'), 'The recovery key really signed an answer for this request that names bob\'s address (the operator was given bob\'s copy); alice asked with hers.', v3({ email: emailB64Of(BOB) }));
  device('answer-for-another-address-on-a-fresh-install', V('request_mismatch'), 'The same on a fresh install, with bob\'s whole account behind it (his userId, his UVK, the server serving his identity): the address alone refuses it.', v3({ email: emailB64Of(BOB), userId: bob.userId, uvk: b64u(bobUvk) }), { request: { userId: null }, encryptedSeed: bobEncryptedSeed, identityPub: bob.identityPub });
  device('request-key-differs', V('request_mismatch'), 'Made for another request key.', v3({ requestKey: b64u(otherRPub) }));
  device('request-id-differs', V('request_mismatch'), 'Made for another request id (an answer uploaded to the wrong row of the same address, sealed to this row\'s key).', v3({ requestId: otherRequestId }));
  device('instance-differs', V('request_mismatch'), 'Made for another instance.', v3({ instanceId: ids.otherInstance }));
  device('user-differs', V('request_mismatch'), 'Names another userId than the device holds.', v3({ userId: bob.userId }));
  device('served-identity-is-another', V('identity_mismatch'), 'The seed opens under the delivered UVK, but the served identityPub is bob\'s.', answer, { sealed: answer.sealed, identityPub: bob.identityPub });
  device('seed-does-not-open', V('identity_mismatch'), 'The served identity-seed envelope does not open under the delivered UVK.', answer, { sealed: answer.sealed, encryptedSeed: envelopeSeal(fixed('recovery/other-uvk'), seedNonce, identitySeedAd(alice.userId), alice.seed) });
  device('order-parse-before-signer', V('bad_statement'), 'An answer of the old form signed by the operator account: the parse decides before the signer.', signed('assisted-recovery', operator, oldAnswer.values));
  device('order-signer-before-signature', V('signer_not_pinned_key'), 'Signed by recovery key B, then one signature bit flipped.', { frame: flip(v3({}, recoveryB).frame) }, { signerNote: 'recoveryB, then one signature bit flipped' });
  device('order-signature-before-request', V('bad_signature'), 'Names bob\'s address, then one signature bit flipped.', { frame: flip(v3({ email: emailB64Of(BOB) }).frame) }, { signerNote: 'recoveryA, then one signature bit flipped' });
  device('order-request-before-identity', V('request_mismatch'), 'Names bob\'s address, and the served identityPub is bob\'s.', v3({ email: emailB64Of(BOB) }), { identityPub: bob.identityPub });

  // ---- the server checks the commit value (spec 03 §18.5) ----
  const stored = commitHashOf(b64u(commit)).commitHash;
  const commitCheck = [];
  const ABSENT = Symbol('absent');
  const cc = (name, why, value, want, storedHash = stored) => {
    const got = checkCommit({ commit: value === ABSENT ? undefined : value, storedCommitHash: storedHash });
    if (JSON.stringify(got) !== JSON.stringify(want)) throw new Error(`recovery-v3 commitCheck ${name}: the text says ${JSON.stringify(want)}, the oracle says ${JSON.stringify(got)}`);
    const r = { name, why };
    if (value !== ABSENT) r.commit = value;
    Object.assign(r, { storedCommitHash: storedHash, expect: want });
    commitCheck.push(r);
  };
  const BAD = { verdict: 'bad_commit', wire: '400 bad_commit' };
  const MISMATCH = { verdict: 'commit_mismatch', wire: '403 commit_mismatch' };
  const commitB64 = b64u(commit);
  const lastBits = commitB64.slice(0, 42) + (commitB64[42] === 'B' ? 'C' : 'B');
  cc('the-value-from-the-answer', 'The commit value the device opened: its hash is the stored one.', commitB64, { verdict: 'ok' });
  cc('another-value', 'Another 32-byte value.', b64u(fixed('recovery-v3/commit/bob')), MISMATCH);
  cc('the-value-of-an-older-upload', 'The operator uploaded again: the stored hash is the newer answer\'s, so the older answer\'s value is refused.', commitB64, MISMATCH, commitHashOf(b64u(fixed('recovery-v3/commit/newer'))).commitHash);
  cc('the-hash-itself', 'The commit hash sent as the value: not a b64_32.', stored, BAD);
  cc('absent', 'No commit key in the body at all.', ABSENT, BAD);
  cc('null', 'commit is JSON null.', null, BAD);
  cc('a-number', 'commit is the JSON number 42 (not a string).', 42, BAD);
  cc('an-object', 'commit is a JSON object holding the right value (not a string).', { commit: b64u(commit) }, BAD);
  cc('31-bytes', 'A 31-byte value.', b64u(commit.slice(0, 31)), BAD);
  cc('padded', 'The value with a padding "=".', commitB64 + '=', BAD);
  cc('stray-bits-in-the-last-character', 'The last character changed so it carries bits past the 32 bytes: not canonical, so not a b64_32.', lastBits, BAD);

  // ---- the server checks an upload (spec 03 §18.6), the parts that need only the row ----
  const row = { rPub: b64u(rPub), emailNorm: ALICE };
  const good = { sealed: b64u(answer.sealed), requestKey: b64u(rPub), commitHash: answer.commitHash };
  const fulfil = [];
  const fu = (name, why, body, want, r = row) => {
    const got = fulfilChecks({ body, row: r });
    if (JSON.stringify(got) !== JSON.stringify(want)) throw new Error(`recovery-v3 fulfil ${name}: the text says ${JSON.stringify(want)}, the oracle says ${JSON.stringify(got)}`);
    fulfil.push({ name, why, body, row: r, expect: want });
  };
  const W = (code) => ({ verdict: code.split(' ')[1], wire: code });
  const bobSealed = b64u(made.bob.sealed);
  fu('the-token-parts', 'The three values the reader yields from alice\'s token, for her row.', good, { verdict: 'ok' });
  fu('sealed-padded', 'sealed with a padding "=": not canonical base64url.', { ...good, sealed: good.sealed + '=' }, W('400 bad_sealed'));
  fu('sealed-empty', 'sealed "": not 1 to 1,024 bytes.', { ...good, sealed: '' }, W('400 bad_sealed'));
  fu('sealed-over-1024-bytes', 'sealed of 1,025 bytes.', { ...good, sealed: b64u(new Uint8Array(1025).fill(7)) }, W('400 bad_sealed'));
  fu('request-key-of-31-bytes', 'requestKey is 31 bytes.', { ...good, requestKey: b64u(rPub.slice(0, 31)) }, W('400 bad_request_key'));
  fu('commit-hash-in-capitals', 'commitHash in upper-case hex.', { ...good, commitHash: good.commitHash.toUpperCase() }, W('400 bad_commit_hash'));
  fu('another-request-key', 'An answer made for another request of the same address (its token\'s key), uploaded to this row.', { ...good, requestKey: b64u(otherRPub) }, W('400 request_key_mismatch'));
  fu('answer-for-a-shorter-address', 'An answer the size of one for bob\'s 15-octet address (545 bytes) uploaded to alice\'s row (548).', { ...good, sealed: bobSealed }, W('400 bad_sealed'));
  fu('answer-cut-short', 'The sealed answer less its last byte.', { ...good, sealed: b64u(answer.sealed.slice(0, -1)) }, W('400 bad_sealed'));
  fu('answer-too-long', 'The sealed answer and one byte more.', { ...good, sealed: b64u(new Uint8Array([...answer.sealed, 0])) }, W('400 bad_sealed'));
  fu('order-sealed-before-request-key', 'sealed padded, and a 31-byte request key.', { ...good, sealed: good.sealed + '=', requestKey: b64u(rPub.slice(0, 31)) }, W('400 bad_sealed'));
  fu('order-shape-before-request-key-mismatch', 'commitHash in capitals and another request key: the shape comes before anything stored is read.', { ...good, commitHash: good.commitHash.toUpperCase(), requestKey: b64u(otherRPub) }, W('400 bad_commit_hash'));
  fu('order-request-key-before-size', 'Another request key and a cut answer.', { ...good, requestKey: b64u(otherRPub), sealed: b64u(answer.sealed.slice(0, -1)) }, W('400 request_key_mismatch'));
  const without = (key) => Object.fromEntries(Object.entries(good).filter(([k]) => k !== key));
  fu('sealed-absent', 'No sealed key in the body (absent is that field\'s refusal).', without('sealed'), W('400 bad_sealed'));
  fu('request-key-null', 'requestKey is null.', { ...good, requestKey: null }, W('400 bad_request_key'));
  fu('request-key-absent', 'No requestKey key in the body.', without('requestKey'), W('400 bad_request_key'));
  fu('commit-hash-a-number', 'commitHash is the JSON number 7.', { ...good, commitHash: 7 }, W('400 bad_commit_hash'));
  fu('commit-hash-absent', 'No commitHash key in the body.', without('commitHash'), W('400 bad_commit_hash'));
  fu('order-request-key-before-commit-hash', 'A 31-byte request key and a commitHash in capitals: the shape refusals in the order listed.', { ...good, requestKey: b64u(rPub.slice(0, 31)), commitHash: good.commitHash.toUpperCase() }, W('400 bad_request_key'));
  fu('order-sealed-before-commit-hash', 'sealed absent and commitHash absent.', { requestKey: good.requestKey }, W('400 bad_sealed'));

  // ---- the Kotlin implementation's worked example, from the same inputs ----
  const wk = workedExample();

  return {
    _about: [
      'The version-3 answer of operator-assisted recovery: spec 04 §7 steps 3 to 5, spec 01 §5.1 (the version-3 template of 0x09) and §5.5 (the commit hash), spec 03 §18.5 (the commit value) and §18.6 (the upload), in the specification as corrected on 2026-11-16 (first written from its text of that day before the corrections). Changed with those corrections: the device rows frame-of-three-bytes and magic-only (spec 01\'s checking order); commitCheck absent / null / a-number / an-object; fulfil\'s absent, null and non-string fields and its order rows. The old form is in recovery.json, whose request key, request id, UVK and identity-seed envelope this file reuses.',
      'Generated and graded by the independent oracle in tools/vector-gen/oracle (src/answer3.mjs, src/versioned.mjs), written from the specification text alone: `npm run check` regenerates this file byte for byte and recomputes every row. No andvari code was read or run to make it.',
      'Keys: the answer is signed by recovery key A\'s signing key (crypto_sign_seed_keypair of the seed that gives the X25519 recovery key; seed = SHA-256("andvari-vector-oracle|seed/recovery-a")) and sealed to the request key (rSec = SHA-256("andvari-vector-oracle|recovery/request-secret"), rPub its X25519 public key). Every other fixed value is the first bytes of SHA-256("andvari-vector-oracle|" + label): the commit values "recovery-v3/commit" (alice\'s) and "recovery-v3/commit/<row>", each seal\'s ephemeral X25519 secret "recovery-v3/ephemeral/<row>" or "recovery-v3/ephemeral/open/<row name>". A real commit value and a real ephemeral key are drawn from the CSPRNG; here they are fixed so the bytes reproduce. issuedAt is 1763884800000 (13 digits).',
      'answers: the statement {"v":3,"purpose":"assisted-recovery","instanceId","userId","email","requestId","requestKey","commit","uvk","issuedAt"}, its frame (purpose 0x09) and the sealed answer, the commit hash and the token andvari-answer:3:<requestId>:<requestKey>:<commitHash>:<unpadded base64url of the sealed answer>. Every value is recomputable from the input.',
      'sizes: with n the octets of the address and E = ceil(4n / 3) the characters of its unpadded base64url, the statement is 376 + E bytes, the frame 477 + E and the sealed answer 525 + E (issuedAt of 13 digits). checkedWith names the address an answer of that size was built with (n = 3 has none: no emailNorm is shorter than 5 octets).',
      'commitHash: hexLower(SHA-256("andvari/v2|recovery-request|commit|" + b64url(commit))).',
      'open: the person\'s device opens an answer (spec 04 §7 step 4), in order: unopenable; the frame and the strict parse under the version-3 template only (bad_frame, unknown_format, non_canonical, bad_statement; a statement canonical under the old version-2 template is bad_statement); signer_not_pinned_key (the signer must map to the recovery key the pinned card\'s recoveryFp names, recoveryPubB64); bad_signature; request_mismatch (instanceId, userId unless request.userId is null on a fresh install, requestId, requestKey, and email decoding to exactly emailNorm(request.typedEmail), on a fresh install too); identity_mismatch (the served seed does not open under the delivered UVK with Ad.idkey of the answer\'s userId, or opens to another key than identityPubB64). On ok the device keeps uvkB64 and commitB64. The request key pair is requestKey.',
      'commitCheck: the server\'s check of the commit value (spec 03 §18.5), after the poll secret and the request\'s state, which these rows leave out: commit a JSON string that is a b64_32 (absent, null, a number or any other non-string, or another text: 400 bad_commit; a row without a commit key is the absent body); its hash equals storedCommitHash (the newest upload\'s), else 403 commit_mismatch. The count of wrong values (the fifth cancels the request) needs stored state and has no rows.',
      'fulfil: the upload\'s checks that need nothing stored but the row (spec 03 §18.6), in the text\'s order; the password proof, request_unknown and request_state are left out. The body\'s shape, in this order (bad_sealed for a sealed that is not a string of canonical unpadded base64url of 1 to 1,024 bytes, bad_request_key for a requestKey that is not a string b64_32, bad_commit_hash for a commitHash that is not a string hex64; each absent, null or not a string is that field\'s refusal), then request_key_mismatch (requestKey is not the row\'s rPub), then the size: exactly 525 + E bytes for the row\'s emailNorm (bad_sealed).',
    ],
    _aboutWorkedExample: 'workedExample: the Kotlin implementation\'s worked example of each new form (core\'s AssistedRecoveryV3ExampleTest), recomputed by the oracle from the same fixed inputs. Its printout and this row are equal byte for byte: the escrow and answer statements and frames, the sizes, the commit hash and the token head; the oracle also read and opened the printout\'s randomised token. A grader checks that its own seal and sign give these frames.',
    templates: { 'assisted-recovery v3': describeTemplate('assisted-recovery', 3), 'assisted-recovery v2': describeTemplate('assisted-recovery', 2) },
    instanceId: ids.instance,
    keys: { recoveryA: { seedB64: b64u(recoveryA.seed), publicKeyB64: b64u(recoveryA.publicKey), signPubB64: b64u(recoveryA.signPub), fingerprint: recoveryA.fp }, recoveryB: { publicKeyB64: b64u(recoveryB.publicKey), fingerprint: recoveryB.fp }, alice: { ...describe(alice), address: ALICE }, bob: { ...describe(bob), address: BOB }, operator: describe(operator) },
    requestKey: { rSecB64: b64u(rSec), rPubB64: b64u(rPub), otherRPubB64: b64u(otherRPub) },
    answers,
    sizes,
    commitHash,
    open,
    commitCheck,
    fulfil,
    workedExample: [wk],
  };
}

/**
 * The Kotlin implementation's worked example of each new form (core's
 * AssistedRecoveryV3ExampleTest), recomputed by the oracle from the same fixed inputs: the
 * escrow statement version 3 and its frame, the answer statement version 3 and its frame, the sizes,
 * the commit hash and the token's head. The seals are randomised there, so only the frames are fixed.
 * A comparison found the oracle and the Kotlin printout equal byte for byte.
 */
function workedExample() {
  const fill = (n, b) => new Uint8Array(n).fill(b);
  const identitySeed = fill(32, 0x11), uvkW = fill(32, 0x22), recoverySeed = fill(32, 0x33), requestSeed = fill(32, 0x55), commitW = fill(32, 0x66);
  const userId = '1b4e28ba-2fa1-4d3b-8a5e-2c3f4d5e6a7b', address = 'alice@example.org', issuedAt = 1794858966854;
  const instanceId = '5d1f0c2e-7a3b-4c4d-9e5f-6a7b8c9d0e1f', requestIdW = b64u(fill(16, 0x44));
  const identity = boxKeypairFromSeed(identitySeed);
  const recovery = boxKeypairFromSeed(recoverySeed);
  const request = boxKeypairFromSeed(requestSeed);
  const recoveryFp = hex(sha256(recovery.publicKey));
  const escrow = signedV('escrow-uvk', 3, { seed: identitySeed, name: 'worked-example account' }, {
    userId, email: emailB64Of(address), identityKey: b64u(identity.publicKey), recoveryFp, issuedAt, key: b64u(uvkW),
  });
  const answerW = signedV('assisted-recovery', 3, { seed: recoverySeed, name: 'worked-example recovery key' }, {
    instanceId, userId, email: emailB64Of(address), requestId: requestIdW, requestKey: b64u(request.publicKey), commit: b64u(commitW), uvk: b64u(uvkW), issuedAt,
  });
  const h = commitHashOf(b64u(commitW));
  const sz = answerSizes(emailCharsOf(address));
  return {
    name: 'recovery-2-item-8',
    why: 'The Kotlin implementation\'s worked example (identity seed 32 x 0x11, UVK 32 x 0x22, recovery seed 32 x 0x33, request key from the seed 32 x 0x55, commit 32 x 0x66, requestId 16 x 0x44); every key pair is crypto_box_seed_keypair / crypto_sign_seed_keypair of its seed.',
    input: {
      identitySeedHex: hex(identitySeed), uvkHex: hex(uvkW), recoverySeedHex: hex(recoverySeed), requestSeedHex: hex(requestSeed), commitHex: hex(commitW),
      userId, address, issuedAt, instanceId, requestId: requestIdW,
    },
    expect: {
      identityPubB64: b64u(identity.publicKey), signerPubB64: b64u(signPubFromSeed(identitySeed)), recoveryPubB64: b64u(recovery.publicKey), recoveryFp,
      recoverySignerPubB64: b64u(signPubFromSeed(recoverySeed)), rPubB64: b64u(request.publicKey),
      escrowStatementUtf8: escrow.statement, escrowFrameHex: hex(escrow.frame), escrowSealedBytes: escrow.frame.length + 48,
      answerStatementUtf8: answerW.statement, answerFrameHex: hex(answerW.frame), answerSealedBytes: sz.sealed,
      commitHash: h.commitHash, tokenHead: ['andvari-answer', '3', requestIdW, b64u(request.publicKey), h.commitHash, ''].join(':'),
    },
  };
}

export function grade(doc) {
  const failures = [];
  let rows = 0;
  const expect = (cond, what) => {
    rows++;
    if (!cond) failures.push(what);
  };
  const signers = { recoveryA };
  for (const row of doc.answers) {
    const i = row.input;
    const a = makeAnswer({
      recovery: signers[i.signer], instanceId: i.instanceId, userId: i.userId, emailB64: i.emailB64, requestId: i.requestId, requestKey: i.requestKey,
      commit: mustUnb64u(i.commitB64), uvkB64: i.uvkB64, issuedAt: i.issuedAt, ephemeral: mustUnb64u(i.ephemeralSecretB64),
    });
    const e = row.expect;
    const sz = answerSizes(emailChars(e.emailOctets));
    expect(emailB64Of(i.address) === i.emailB64 && a.statement === e.statementUtf8 && hex(a.message) === e.messageHex && b64u(a.frame) === e.frameB64 && b64u(a.sealed) === e.sealedB64
      && a.commitHashInput === e.commitHashInputUtf8 && a.commitHash === e.commitHash && a.token === e.token
      && e.statementBytes === sz.statement && e.frameBytes === sz.frame && e.sealedBytes === sz.sealed && e.emailChars === emailCharsOf(i.address), `answers ${row.name}`);
  }
  for (const row of doc.sizes) {
    const sz = answerSizes(emailChars(row.emailOctets));
    expect(row.emailChars === Math.ceil((4 * row.emailOctets) / 3) && row.statement === sz.statement && row.frame === sz.frame && row.sealed === sz.sealed
      && (row.checkedWith === undefined || emailCharsOf(row.checkedWith) === row.emailChars), `sizes ${row.emailOctets}`);
  }
  for (const row of doc.commitHash) {
    const h = commitHashOf(row.commitB64);
    expect(h.input === row.inputUtf8 && h.commitHash === row.commitHash, `commitHash ${row.commitB64}`);
  }
  const rPub = mustUnb64u(doc.requestKey.rPubB64);
  const rSec = mustUnb64u(doc.requestKey.rSecB64);
  for (const row of doc.open) {
    const got = openAnswerV3({
      sealed: mustUnb64u(row.sealedB64), rPub, rSec, recoveryPub: mustUnb64u(row.recoveryPubB64), request: row.request,
      encryptedIdentitySeed: mustUnb64u(row.encryptedIdentitySeedB64), identityPub: mustUnb64u(row.identityPubB64),
    });
    const g = got.verdict === 'ok' ? got : { verdict: got.verdict };
    expect(JSON.stringify(g) === JSON.stringify(row.expect), `open ${row.name}: oracle says ${JSON.stringify(g)}`);
  }
  for (const row of doc.commitCheck) {
    const got = checkCommit({ commit: row.commit, storedCommitHash: row.storedCommitHash });
    expect(JSON.stringify(got) === JSON.stringify(row.expect), `commitCheck ${row.name}: oracle says ${JSON.stringify(got)}`);
  }
  for (const row of doc.fulfil) {
    const got = fulfilChecks({ body: row.body, row: row.row });
    expect(JSON.stringify(got) === JSON.stringify(row.expect), `fulfil ${row.name}: oracle says ${JSON.stringify(got)}`);
  }
  const wk = workedExample();
  expect(doc.workedExample.length === 1 && JSON.stringify(doc.workedExample[0]) === JSON.stringify(wk), 'workedExample recovery-2-item-8');
  return { rows, failures };
}
