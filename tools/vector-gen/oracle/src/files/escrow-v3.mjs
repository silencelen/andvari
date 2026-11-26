// escrow-v3.json: the recovery copy (escrow blob) in its version-3 form, which names the account's
// address inside what the account signs (spec 04 §3), and its opener, `recovery-cli assist` and the
// fleet `verify` (spec 04 §4 "Opening an escrow offline", steps 0 to 8). Written from the
// specification text of 2026-11-16 alone, before that day's corrections; corrected to its text as
// corrected the same day.

import { b64u, unb64u, mustUnb64u, utf8, hex } from '../bytes.mjs';
import { sha256, boxSeal, boxSealOpen, envelopeSeal } from '../prims.mjs';
import { emailNorm } from '../grammar.mjs';
import { PURPOSE_CODES } from '../frame.mjs';
import { signedRaw, rawStatement, withToken, withoutKey, swapKeys, signed } from '../build.mjs';
import { signedV, tokensOfV, describeTemplate } from '../versioned.mjs';
import { sealRecoveryCopy, openRecoveryCopy, openStrictCopy, openSharedCopy, verifyDumpRow, identitySeedAd, emailB64Of, normaliseAnchor, UNANCHORED_ACK } from '../recoverycopy.mjs';
import { runAssist, commandLine, downloadBytes } from '../assist.mjs';
import { makeAnswer } from '../answer3.mjs';
import { requestCode } from '../recovery.mjs';
import { x25519Base } from '../prims.mjs';
import { alice, bob, recoveryA, recoveryB, fixed, ids, T0, HOUR, describe } from '../cast.mjs';

export const file = 'escrow-v3.json';

const ESCROW = PURPOSE_CODES['escrow-uvk'];
const ALICE = 'alice@example.org';
const BOB = 'bob@example.org';
const LONGEST = 'x'.repeat(64) + '@' + 'a'.repeat(63) + '.' + 'b'.repeat(63) + '.' + 'c'.repeat(61);
const SHORTEST = 'a@b.c';
const ISSUED = T0 + 100 * HOUR;
const flip = (frame) => {
  const out = frame.slice();
  out[37 + 10] ^= 0x01;
  return out;
};

const uvkOf = { alice: fixed('recovery/uvk'), bob: fixed('escrow-v3/uvk/bob') };
const accountOf = { alice, bob };
const addressOf = { alice: ALICE, bob: BOB };
const fpOf = (a) => hex(sha256(a.identityPub));

/** The statement values of a version-3 copy of `who`, before any override. */
function copyValues(who, overrides = {}) {
  const a = accountOf[who];
  return { userId: a.userId, email: emailB64Of(addressOf[who]), identityKey: b64u(a.identityPub), recoveryFp: recoveryA.fp, issuedAt: ISSUED, key: b64u(uvkOf[who]), ...overrides };
}

/** A whole check's answer in the rows' terms. */
const verdictOf = (got) => (got.verdict === 'ok' ? got : got.verdict === 'email_mismatch' ? { verdict: got.verdict, copyEmail: got.copyEmail } : { verdict: got.verdict });

/**
 * Whether the shared check's inputs can carry an open row: not where an argument the operator left
 * out is absent (a null --user or --email, no anchor without --no-identity-anchor), both anchors are
 * given, the fleet dump's own fingerprint column is set, or the copy is not canonical base64url (the
 * shared check is handed bytes).
 */
function sharedCarries(input) {
  if (input.user == null) return false;
  if (input.mode === 'verify') return input.dumpFingerprint == null && unb64u(input.sealedB64) !== null;
  return input.email != null && input.noIdentityAnchor !== (input.identityFp != null);
}

export function build() {
  // ---- the identity files (POST /admin/accounts/{userId}/escrow answers them beside the copy) ----
  const nonce = fixed('escrow-v3/seed-nonce', 24);
  const files = {
    alice: { why: 'alice\'s identity file: her identity seed sealed under her UVK with Ad.idkey(her userId), and her identityPub.', key: 'alice', seedOf: 'alice', adOf: 'alice', pubOf: 'alice' },
    bob: { why: 'bob\'s identity file.', key: 'bob', seedOf: 'bob', adOf: 'bob', pubOf: 'bob' },
    'alice-seed-under-another-key': { why: 'alice\'s identityPub, but the seed envelope is sealed under another key than her UVK.', key: 'other', seedOf: 'alice', adOf: 'alice', pubOf: 'alice' },
    'alice-pub-with-bob-seed': { why: 'alice\'s identityPub, and an envelope under her UVK that holds bob\'s seed.', key: 'alice', seedOf: 'bob', adOf: 'alice', pubOf: 'alice' },
    'alice-seed-bound-to-bob': { why: 'alice\'s identityPub and seed under her UVK, but sealed with Ad.idkey(bob\'s userId).', key: 'alice', seedOf: 'alice', adOf: 'bob', pubOf: 'alice' },
    'alice-pub-of-31-bytes': { why: 'alice\'s identity file with the last byte of its identityPub left off: a key of 31 bytes.', key: 'alice', seedOf: 'alice', adOf: 'alice', pubOf: 'alice', cut: true },
  };
  const identityFiles = {};
  const fileBytes = {};
  for (const [name, f] of Object.entries(files)) {
    const key = f.key === 'other' ? fixed('escrow-v3/uvk/other') : uvkOf[f.key];
    const env = envelopeSeal(key, nonce, identitySeedAd(accountOf[f.adOf].userId), accountOf[f.seedOf].seed);
    const pub = f.cut ? accountOf[f.pubOf].identityPub.slice(0, 31) : accountOf[f.pubOf].identityPub;
    fileBytes[name] = { encryptedIdentitySeed: env, identityPub: pub };
    // userId: the account the download is for (its own userId field): the account whose identityPub it carries.
    identityFiles[name] = { why: f.why, userId: accountOf[f.pubOf].userId, encryptedIdentitySeedB64: b64u(env), identityPubB64: b64u(pub) };
  }
  // The download a row's identity file stands for, with the copy it carries (spec 04 §4 "Reading an escrow").
  const download = (name, sealed, over = {}) => {
    const f = identityFiles[name];
    return downloadBytes({ userId: f.userId, sealedB64: b64u(sealed), encryptedIdentitySeedB64: f.encryptedIdentitySeedB64, identityPubB64: f.identityPubB64, ...over });
  };

  // ---- sealing ----
  const seal = [];
  const sealRow = (name, why, who, address, ephemeralLabel) => {
    const a = accountOf[who];
    const ephemeral = fixed('escrow-v3/ephemeral/' + ephemeralLabel);
    const made = sealRecoveryCopy({ account: a, address, uvk: uvkOf[who], recoveryPub: recoveryA.publicKey, issuedAt: ISSUED, ephemeral });
    if (made.sealed === null) throw new Error('escrow-v3 seal ' + name);
    const norm = emailNorm(address);
    if (made.statement.length > 1024) throw new Error('escrow-v3: statement over 1,024 bytes');
    seal.push({
      name, why,
      input: { account: who, userId: a.userId, address, uvkB64: b64u(uvkOf[who]), recoveryPubB64: b64u(recoveryA.publicKey), issuedAt: ISSUED, ephemeralSecretB64: b64u(ephemeral) },
      expect: {
        emailNorm: norm, emailOctets: norm.length, emailB64: made.values.email, emailChars: made.values.email.length,
        statementUtf8: made.statement, statementBytes: made.statement.length, messageHex: hex(made.message), signatureB64: b64u(made.signature),
        frameB64: b64u(made.frame), frameBytes: made.frame.length, sealedB64: b64u(made.sealed), sealedBytes: made.sealed.length,
      },
    });
    return made;
  };
  const aliceCopy = sealRow('alice', 'alice\'s copy: the address she registered with, as its emailNorm, inside the statement her joint key signs; sealed to recovery key A.', 'alice', ALICE, 'alice');
  sealRow('address-written-as-its-emailnorm', 'The address as the person once typed it, with capitals and spaces around it: the copy carries its emailNorm, so the statement is the same as the row alice\'s, and so is the frame (a deterministic signature); only the seal differs, by its ephemeral key.', 'alice', '  Alice@Example.ORG ', 'alice-typed');
  const bobCopy = sealRow('bob', 'bob\'s copy, with his address.', 'bob', BOB, 'bob');
  sealRow('shortest-address', 'An address of five octets, the shortest an emailNorm can be (one-character local part, two one-character labels).', 'alice', SHORTEST, 'shortest');
  sealRow('longest-address', 'An address of 254 octets (a 64-character local part and a 189-character domain), 339 characters of base64url: the statement stays under 1,024 bytes.', 'alice', LONGEST, 'longest');

  const sealRefuse = [];
  for (const [name, address, why] of [
    ['no-at-sign', 'alice', 'Not an address: no emailNorm, so the client cannot name the address and seals nothing.'],
    ['one-label-domain', 'alice@localhost', 'The domain has one label: no emailNorm.'],
    ['empty', '', 'No address at all.'],
    ['interior-space', 'alice smith@example.org', 'An interior space: no emailNorm.'],
  ]) {
    const made = sealRecoveryCopy({ account: alice, address, uvk: uvkOf.alice, recoveryPub: recoveryA.publicKey, issuedAt: ISSUED, ephemeral: fixed('escrow-v3/ephemeral/refuse') });
    if (made.sealed !== null) throw new Error('escrow-v3 sealRefuse ' + name);
    sealRefuse.push({ name, why, address, expect: { sealed: false } });
  }

  // ---- opening ----
  const sealCopy = (label, frame, to = recoveryA.publicKey) => boxSeal(to, frame, fixed('escrow-v3/ephemeral/open/' + label));
  const v3 = (who, overrides = {}, signer = accountOf[who]) => signedV('escrow-uvk', 3, signer, copyValues(who, overrides));
  const v2 = (who, overrides = {}, signer = accountOf[who]) => {
    const { email, ...rest } = copyValues(who, overrides);
    return signedV('escrow-uvk', 2, signer, rest);
  };
  const raw = (who, tokens, signer = accountOf[who]) => signedRaw(ESCROW, signer, rawStatement(tokens));
  const t3 = (who, overrides) => tokensOfV('escrow-uvk', 3, copyValues(who, overrides));
  const t2 = (who) => {
    const { email, ...rest } = copyValues(who);
    return tokensOfV('escrow-uvk', 2, rest);
  };

  const base = {
    mode: 'assist', user: alice.userId, identityFp: fpOf(alice).slice(0, 32), noIdentityAnchor: false, identityFile: 'alice', email: ALICE,
  };
  const normal = [];
  const names = new Set();
  const open = (table, name, want, why, made, ctx = {}) => {
    if (names.has(name)) throw new Error('escrow-v3: duplicate row ' + name);
    names.add(name);
    const frame = made === null ? null : made.frame ?? made;
    const sealed = ctx.sealed ?? sealCopy(name, frame);
    let input = { ...base, ...ctx.input };
    // The fleet verify takes --user and the identity file only; it asks for nothing. A dump
    // row may also carry its fingerprint column.
    if (input.mode === 'verify') {
      input = { mode: 'verify', user: input.user, identityFile: input.identityFile, ...(input.dumpFingerprint != null ? { dumpFingerprint: input.dumpFingerprint } : {}) };
    }
    delete input.sealed;
    const sealedText = ctx.sealedText ?? b64u(sealed);
    const withFile = { ...input, identityFile: input.identityFile === null ? null : fileBytes[input.identityFile], recoverySeed: recoveryA.seed, sealed };
    const got = input.mode === 'verify' ? verifyDumpRow({ ...withFile, sealedText }) : openRecoveryCopy(withFile);
    const gotExpect = got.verdict === 'ok' ? got : got.verdict === 'email_mismatch' ? { verdict: got.verdict, copyEmail: got.copyEmail } : { verdict: got.verdict };
    if (JSON.stringify(gotExpect) !== JSON.stringify(want)) throw new Error(`escrow-v3 open "${name}": the text says ${JSON.stringify(want)}, the oracle says ${JSON.stringify(gotExpect)}`);
    const row = { name, why };
    if (made && made.statement !== undefined) row.statementUtf8 = made.statement;
    if (made && made.signer) row.signer = made.signer.name ?? made.signer;
    if (ctx.signerNote) row.signer = ctx.signerNote;
    row.input = { ...input, sealedB64: sealedText };
    row.expect = want;
    // Where the shared check's answer differs from the tool's (spec 04 §4 "Who reads what a person typed": only the command line reads
    // what a person typed), the row says it separately; the rows it may differ on are named below.
    const shared = sharedExpect(input, sealed, sealedText);
    if (shared !== null && JSON.stringify(shared) !== JSON.stringify(want)) {
      if (!SHARED_DIFFERS.has(name)) throw new Error(`escrow-v3 open "${name}": the shared check says ${JSON.stringify(shared)}, the tool ${JSON.stringify(want)}`);
      row.expectShared = shared;
    } else if (SHARED_DIFFERS.has(name)) {
      throw new Error(`escrow-v3 open "${name}": named as differing, but the shared check agrees with the tool`);
    }
    const opener = openerExpect(input, sealed);
    if (opener !== null) row.expectOpener = opener;
    table.push(row);
  };
  // The rows on which the tool and the shared check answer differently, by that rule.
  const SHARED_DIFFERS = new Set(['anchor-grouped-with-spaces', 'anchor-grouped-with-dashes', 'anchor-grouped-with-tabs', 'acknowledgment-with-spaces-around', 'acknowledgment-with-a-tab-after']);
  // What the shared check (core openForAssist / openForFleet: the whole check, reading nothing a
  // person typed) answers for a row's inputs; null where its inputs cannot carry the row: an
  // argument the operator left out (a null --user or --email, or no anchor without
  // --no-identity-anchor), both anchors given, a fleet dump's own column, or a copy that is not
  // canonical base64url (the shared check is handed bytes).
  function sharedExpect(input, sealed, sealedText) {
    if (!sharedCarries({ ...input, sealedB64: sealedText })) return null;
    return verdictOf(openStrictCopy({ ...input, identityFile: input.identityFile === null ? null : fileBytes[input.identityFile], recoverySeed: recoveryA.seed, sealed }));
  }
  // What the shared opener (steps 0 to 6 without --email, spec 04 §4 "Two layers") answers for an assist row's
  // inputs; null where the row is not one the opener's inputs can carry or the text leaves its answer
  // to escrow-v2.json: the fleet verify, both anchors given (the tool's own refusal), and the
  // pre-signed form (graded by escrow-v2.json). The acknowledgment is the opener's as given: it
  // removes nothing (spec 04 §4 "Who reads what a person typed"), so one typed with space or tab at its ends is refused here.
  function openerExpect(input, sealed) {
    if (input.mode !== 'assist') return null;
    if (input.noIdentityAnchor && input.identityFp != null) return null;
    const got = openSharedCopy({ ...input, identityFile: input.identityFile === null ? null : fileBytes[input.identityFile], recoverySeed: recoveryA.seed, sealed });
    return got.verdict === 'pre_signed' ? null : got;
  }
  const ok = (who, anchored, extra = {}) => ({
    verdict: 'ok', userId: accountOf[who].userId, email: extra.email ?? addressOf[who], emailB64: emailB64Of(extra.email ?? addressOf[who]),
    uvkB64: b64u(uvkOf[who]), identityKeyB64: b64u(accountOf[who].identityPub), anchored,
  });
  const V = (verdict) => ({ verdict });
  const N = normal;

  // valid
  open(N, 'valid-anchored-32-hex', ok('alice', true), 'alice\'s version-3 copy, opened by assist with her account ID as a 32-hex anchor, her identity file, and her address typed by the operator. Every step passes; the tool shows the address the copy names.', aliceCopy);
  open(N, 'valid-anchored-64-hex', ok('alice', true), 'The same with the full 64-hex identity fingerprint as the anchor.', aliceCopy, { input: { identityFp: fpOf(alice) } });
  open(N, 'valid-typed-address-in-another-form', ok('alice', true), 'The operator types "  ALICE@Example.Org " with capitals and spaces around it: step 0 keeps emailNorm(--email), which is the copy\'s address byte for byte.', aliceCopy, { input: { email: '  ALICE@Example.Org ' } });
  open(N, 'valid-unanchored-with-acknowledgment', ok('alice', false), 'Unanchored (--no-identity-anchor) with the typed acknowledgment: the identity file\'s key stands in for the anchor, and the copy still has to name the typed address.', aliceCopy, { input: { identityFp: null, noIdentityAnchor: true, unanchoredAck: UNANCHORED_ACK } });
  const longCopy = v3('alice', { email: emailB64Of(LONGEST) });
  open(N, 'valid-longest-address', ok('alice', true, { email: LONGEST }), 'A copy that names a 254-octet address, opened with that address typed.', longCopy, { input: { email: LONGEST } });
  open(N, 'verify-version-3', ok('alice', false), 'The fleet verify (steps 0 to 7, unanchored, no --email): a version-3 copy passes.', aliceCopy, { input: { mode: 'verify', email: null, identityFp: null, noIdentityAnchor: true, unanchoredAck: UNANCHORED_ACK } });

  // step 0
  open(N, 'user-absent', V('bad_user_id'), 'No --user.', aliceCopy, { input: { user: null } });
  open(N, 'user-in-capitals', V('bad_user_id'), '--user is an upper-case uuid: not a lowercase uuid.', aliceCopy, { input: { user: ids.vault.toUpperCase() } });
  open(N, 'user-one-digit-short', V('bad_user_id'), '--user has 11 digits in its last group.', aliceCopy, { input: { user: alice.userId.slice(0, -1) } });
  open(N, 'anchor-absent', V('bad_anchor'), 'No --identity-fp and no --no-identity-anchor.', aliceCopy, { input: { identityFp: null } });
  open(N, 'anchor-of-31-hex', V('bad_anchor'), 'An anchor of 31 hex characters.', aliceCopy, { input: { identityFp: fpOf(alice).slice(0, 31) } });
  open(N, 'anchor-of-65-hex', V('bad_anchor'), 'An anchor of 65 hex characters (more than a whole fingerprint).', aliceCopy, { input: { identityFp: fpOf(alice) + '0' } });
  open(N, 'anchor-in-capitals', V('bad_anchor'), 'An anchor in upper-case hex: the grammar is lowercase hex.', aliceCopy, { input: { identityFp: fpOf(alice).slice(0, 32).toUpperCase() } });
  open(N, 'identity-file-absent', V('identity_check_required'), 'No --identity-file.', aliceCopy, { input: { identityFile: null } });
  open(N, 'email-absent', V('bad_email'), 'assist without --email.', aliceCopy, { input: { email: null } });
  open(N, 'email-with-no-emailnorm', V('bad_email'), '--email "alice" has no emailNorm.', aliceCopy, { input: { email: 'alice' } });
  open(N, 'email-with-a-trailing-dot', V('bad_email'), '--email "alice@example.org." : a trailing dot fails the host grammar, so no emailNorm.', aliceCopy, { input: { email: 'alice@example.org.' } });
  open(N, 'email-empty', V('bad_email'), '--email "".', aliceCopy, { input: { email: '' } });
  open(N, 'order-user-before-anchor', V('bad_user_id'), 'No --user and an anchor of 31 hex.', aliceCopy, { input: { user: null, identityFp: fpOf(alice).slice(0, 31) } });
  open(N, 'order-anchor-before-identity-file', V('bad_anchor'), 'An anchor of 31 hex and no identity file.', aliceCopy, { input: { identityFp: fpOf(alice).slice(0, 31), identityFile: null } });
  open(N, 'order-step-0-before-the-seal', V('bad_email'), 'No --email, and a copy sealed to another recovery key: step 0 refuses before the seed is asked for.', null, { sealed: sealCopy('step0-seal', aliceCopy.frame, recoveryB.publicKey), input: { email: null } });

  // step 2
  open(N, 'anchor-is-another-account', V('identity_fp_mismatch'), 'The anchor is bob\'s account ID: alice\'s identity file does not start with it.', aliceCopy, { input: { identityFp: fpOf(bob).slice(0, 32) } });
  open(N, 'anchor-31-of-32-right', V('identity_fp_mismatch'), 'The last of 32 hex characters is wrong.', aliceCopy, { input: { identityFp: fpOf(alice).slice(0, 31) + (fpOf(alice)[31] === '0' ? '1' : '0') } });
  open(N, 'unanchored-without-acknowledgment', V('unanchored_not_acknowledged'), '--no-identity-anchor and no acknowledgment.', aliceCopy, { input: { identityFp: null, noIdentityAnchor: true } });
  open(N, 'unanchored-with-another-acknowledgment', V('unanchored_not_acknowledged'), '--no-identity-anchor and "yes" typed.', aliceCopy, { input: { identityFp: null, noIdentityAnchor: true, unanchoredAck: 'yes' } });
  open(N, 'order-anchor-before-the-seal', V('identity_fp_mismatch'), 'The wrong anchor, and a copy sealed to another recovery key.', null, { sealed: sealCopy('step2-seal', aliceCopy.frame, recoveryB.publicKey), input: { identityFp: fpOf(bob).slice(0, 32) } });

  // steps 3 and 4
  open(N, 'sealed-to-another-recovery-key', V('unopenable'), 'The copy is sealed to recovery key B; the sheet is A\'s.', null, { sealed: sealCopy('other-key', aliceCopy.frame, recoveryB.publicKey) });
  open(N, 'seal-cut-short', V('unopenable'), 'The first 40 bytes of the copy.', null, { sealed: aliceCopy.sealed.slice(0, 40) });
  open(N, 'bare-statement-inside', V('unknown_format'), 'The seal opens to the version-3 statement alone, with no frame.', { frame: utf8(aliceCopy.statement), statement: aliceCopy.statement });
  const v1Json = `{"v":1,"userId":"${alice.userId}","keyType":"uvk","key":"${b64u(uvkOf.alice)}","sha256":"${hex(sha256(uvkOf.alice))}"}`;

  // step 5: the frame and the parse
  const answerFrame = signed('assisted-recovery', recoveryA, { instanceId: ids.instance, userId: alice.userId, requestId: b64u(fixed('recovery/request-id', 16)), requestKey: alice.key, uvk: b64u(uvkOf.alice), issuedAt: ISSUED });
  open(N, 'assisted-recovery-frame-inside', V('bad_frame'), 'The seal opens to a 0x09 frame: the purpose is not 0x02.', answerFrame);
  open(N, 'not-canonical', V('non_canonical'), 'A space after a colon.', signedRaw(ESCROW, alice, aliceCopy.statement.replace('"email":', '"email": ')));
  open(N, 'email-none', V('non_canonical'), 'email "none": email_b64 is the email_b64n grammar without the literal none.', raw('alice', withToken(t3('alice'), 'email', '"none"')));
  open(N, 'email-not-normal', V('non_canonical'), 'email is the base64url of "Alice@example.org": its emailNorm is not itself, so it fails its type.', raw('alice', withToken(t3('alice'), 'email', '"' + b64u(utf8('Alice@example.org')) + '"')));
  open(N, 'email-padded', V('non_canonical'), 'email in padded base64url.', raw('alice', withToken(t3('alice'), 'email', '"' + emailB64Of(ALICE) + '="')));
  open(N, 'email-not-an-address', V('non_canonical'), 'email is the base64url of "alice", which has no emailNorm.', raw('alice', withToken(t3('alice'), 'email', '"' + b64u(utf8('alice')) + '"')));
  open(N, 'email-out-of-order', V('non_canonical'), 'The version-3 keys with email after identityKey: the key order is the template\'s.', raw('alice', swapKeys(t3('alice'), 'email', 'identityKey')));
  open(N, 'version-2-keys-and-email-last', V('non_canonical'), 'The version-2 keys with email appended at the end: no template has that key order.', raw('alice', [...withoutKey(t3('alice'), 'email').map(([k, x]) => (k === 'v' ? [k, '2'] : [k, x])), ['email', '"' + emailB64Of(ALICE) + '"']]));
  open(N, 'version-as-a-string', V('non_canonical'), '"v":"3": v is an int.', raw('alice', withToken(t3('alice'), 'v', '"3"')));
  open(N, 'version-3-keys-with-v-2', V('bad_statement'), 'The version-3 key set, canonical, with "v":2: under the version-3 template v must be 3.', raw('alice', withToken(t3('alice'), 'v', '2')));
  open(N, 'version-2-keys-with-v-3', V('bad_statement'), 'The version-2 key set, canonical, with "v":3: under the version-2 template v must be 2.', raw('alice', withToken(t2('alice'), 'v', '3')));
  open(N, 'version-4', V('bad_statement'), 'The version-3 key set with "v":4.', raw('alice', withToken(t3('alice'), 'v', '4')));
  // step 5: the anchor
  open(N, 'another-members-copy', V('user_mismatch'), 'F2/F3: the server puts bob\'s genuine copy under alice\'s request; the operator\'s --user is alice\'s.', bobCopy);
  open(N, 'names-another-recovery-key', V('recovery_fp_mismatch'), 'alice\'s statement names recovery key B\'s fingerprint, but the copy was sealed to and opened by A.', v3('alice', { recoveryFp: recoveryB.fp }));
  open(N, 'signed-by-another-member', V('signer_not_pinned_key'), 'alice\'s statement, word for word, signed by bob\'s key.', v3('alice', {}, bob));
  open(N, 'signature-flipped', V('bad_signature'), 'One signature bit flipped.', { frame: flip(aliceCopy.frame), statement: aliceCopy.statement }, { signerNote: 'alice, then one signature bit flipped' });
  open(N, 'names-another-identity', V('identity_mismatch'), 'alice\'s key really signed a statement whose identityKey is bob\'s: the statement must equal the anchor, not itself.', v3('alice', { identityKey: b64u(bob.identityPub) }));
  open(N, 'order-parse-before-user', V('non_canonical'), 'bob\'s copy with a space after a colon, under alice\'s --user.', signedRaw(ESCROW, bob, bobCopy.statement.replace('"key":', '"key": ')));
  open(N, 'order-user-before-recovery-fp', V('user_mismatch'), 'bob\'s copy naming recovery key B, under alice\'s --user.', v3('bob', { recoveryFp: recoveryB.fp }));
  open(N, 'order-recovery-fp-before-signer', V('recovery_fp_mismatch'), 'Names recovery key B and is signed by bob.', v3('alice', { recoveryFp: recoveryB.fp }, bob));
  open(N, 'order-signer-before-signature', V('signer_not_pinned_key'), 'Signed by bob, then one signature bit flipped.', { frame: flip(v3('alice', {}, bob).frame) }, { signerNote: 'bob, then one signature bit flipped' });
  open(N, 'order-signature-before-identity', V('bad_signature'), 'Names bob\'s identity key, then one signature bit flipped.', { frame: flip(v3('alice', { identityKey: b64u(bob.identityPub) }).frame) }, { signerNote: 'alice, then one signature bit flipped' });

  // step 6
  open(N, 'identity-seed-under-another-key', V('identity_check_failed'), 'The identity file\'s seed does not open under the copy\'s key.', aliceCopy, { input: { identityFile: 'alice-seed-under-another-key' } });
  open(N, 'identity-seed-is-another-identity', V('identity_check_failed'), 'The seed opens, but to bob\'s identity, not the anchored one.', aliceCopy, { input: { identityFile: 'alice-pub-with-bob-seed' } });
  open(N, 'identity-seed-bound-to-another-user', V('identity_check_failed'), 'The seed is sealed with Ad.idkey of bob\'s userId: it does not open under Ad.idkey(--user).', aliceCopy, { input: { identityFile: 'alice-seed-bound-to-bob' } });
  open(N, 'order-statement-before-identity-check', V('identity_mismatch'), 'Names bob\'s identity, and the identity file\'s seed does not open.', v3('alice', { identityKey: b64u(bob.identityPub) }), { input: { identityFile: 'alice-seed-under-another-key' } });

  // step 7
  const aliceV2 = v2('alice');
  open(N, 'old-form', V('no_address'), 'alice\'s genuine copy of the old form (version 2, no email): every check up to the identity check passes, and assist refuses it because it does not say whose it is.', aliceV2);
  open(N, 'old-form-unanchored', V('no_address'), 'The same, unanchored with the acknowledgment.', aliceV2, { input: { identityFp: null, noIdentityAnchor: true, unanchoredAck: UNANCHORED_ACK } });
  open(N, 'verify-old-form', V('no_address'), 'The fleet verify FAILs a copy of the old form with no_address (the annual drill).', aliceV2, { input: { mode: 'verify', email: null, identityFp: null, noIdentityAnchor: true, unanchoredAck: UNANCHORED_ACK } });
  open(N, 'order-identity-check-before-old-form', V('identity_check_failed'), 'A copy of the old form whose identity file fails the check: step 6 comes before step 7.', aliceV2, { input: { identityFile: 'alice-seed-under-another-key' } });
  open(N, 'order-old-form-before-address', V('no_address'), 'A copy of the old form and bob\'s address typed: there is no address to compare.', aliceV2, { input: { email: BOB } });

  // step 8
  open(N, 'copy-of-another-address', { verdict: 'email_mismatch', copyEmail: ALICE }, 'The operator is helping bob and typed his address; the copy (alice\'s, under her own userId and identity file) names hers. The tool says whose copy it is.', aliceCopy, { input: { email: BOB } });
  open(N, 'server-swaps-the-whole-account', { verdict: 'email_mismatch', copyEmail: BOB }, 'F2/F3 on a hostile host: the operator helps alice and types her address, but the server gave bob\'s userId, bob\'s identity file and bob\'s genuine copy, and the operator has no account ID to anchor with. Every check up to step 7 passes; the address stops it.', bobCopy, { input: { user: bob.userId, identityFile: 'bob', identityFp: null, noIdentityAnchor: true, unanchoredAck: UNANCHORED_ACK } });
  open(N, 'server-swaps-the-whole-account-anchored', V('identity_fp_mismatch'), 'The same swap when the operator has alice\'s account ID from her kit: the anchor already refuses bob\'s identity file.', bobCopy, { input: { user: bob.userId, identityFile: 'bob', identityFp: fpOf(alice).slice(0, 32) } });
  open(N, 'longest-address-against-another', { verdict: 'email_mismatch', copyEmail: LONGEST }, 'A copy naming the 254-octet address, with alice\'s address typed.', longCopy);
  open(N, 'verify-skips-the-address', ok('bob', false), 'The fleet verify has no --email and skips step 8: bob\'s copy passes under bob\'s userId.', bobCopy, { input: { mode: 'verify', email: null, user: bob.userId, identityFile: 'bob', identityFp: null, noIdentityAnchor: true, unanchoredAck: UNANCHORED_ACK } });
  open(N, 'order-identity-check-before-address', V('identity_check_failed'), 'Another address typed, and the identity file fails the check.', aliceCopy, { input: { email: BOB, identityFile: 'alice-seed-under-another-key' } });
  open(N, 'order-signature-before-address', V('bad_signature'), 'Another address typed, and a flipped signature bit.', { frame: flip(aliceCopy.frame) }, { input: { email: BOB }, signerNote: 'alice, then one signature bit flipped' });

  // ---- settled by the specification's corrections of 2026-11-16 (they were the `pending` rows before them) ----
  const grouped = fpOf(alice).slice(0, 32).match(/.{4}/g);
  open(N, 'anchor-grouped-with-spaces', ok('alice', true), 'The anchor as printed, in groups of four separated by spaces: the tool removes spaces, tabs and dashes from what was typed (spec 04 §4 step 0.2). The shared opener takes only lowercase hex (expectOpener: bad_anchor, which is escrow-v2.json\'s row "anchor with separators").', aliceCopy, { input: { identityFp: grouped.join(' ') } });
  open(N, 'anchor-grouped-with-dashes', ok('alice', true), 'The anchor in groups of four separated by dashes: the same.', aliceCopy, { input: { identityFp: grouped.join('-') } });
  open(N, 'anchor-grouped-with-tabs', ok('alice', true), 'The anchor in groups separated by tabs, and a space at each end: the tool removes tabs too.', aliceCopy, { input: { identityFp: ' ' + grouped.join('\t') + ' ' } });
  open(N, 'anchor-grouped-in-capitals', V('bad_anchor'), 'The anchor in groups, in upper-case hex: the tool does not change case.', aliceCopy, { input: { identityFp: grouped.join(' ').toUpperCase() } });
  open(N, 'anchor-grouped-with-a-colon', V('bad_anchor'), 'The anchor in groups separated by colons: only spaces, tabs and dashes are removed.', aliceCopy, { input: { identityFp: grouped.join(':') } });
  open(N, 'order-identity-file-before-email', V('identity_check_required'), 'No identity file and no --email: spec 04 §4 step 0 in its one order.', aliceCopy, { input: { identityFile: null, email: null } });
  open(N, 'order-anchor-before-email', V('bad_anchor'), 'An anchor of 31 hex and no --email.', aliceCopy, { input: { identityFp: fpOf(alice).slice(0, 31), email: null } });
  open(N, 'pre-v2-json-blob', V('unknown_format'), 'The seal opens to a genuine pre-signed JSON copy of alice\'s UVK (v1). The tools read nothing that does not start with the magic (spec 04 §4 step 4). The shared opener still reads the pre-signed form, for recover and escrow-v2.json, which grades it: no expectOpener here.', { frame: utf8(v1Json), statement: v1Json });
  open(N, 'plaintext-of-three-bytes', V('unknown_format'), 'The seal opens to the three bytes "avs": a plaintext under four bytes is unknown_format at step 4, before spec 01\'s frame rules.', { frame: utf8('avs') });
  open(N, 'plaintext-empty', V('unknown_format'), 'The seal opens to nothing at all (zero bytes): unknown_format at step 4.', { frame: new Uint8Array(0) });
  open(N, 'magic-only', V('bad_frame'), 'The seal opens to the four bytes avs\\x02 alone: step 4 passes, and the frame is shorter than any frame (step 5).', { frame: Uint8Array.of(0x61, 0x76, 0x73, 0x02) });

  // ---- step 0: both --identity-fp and --no-identity-anchor ----
  open(N, 'anchor-and-no-anchor-both-given', V('bad_anchor'), '--identity-fp (alice\'s, right) and --no-identity-anchor together: refused before anything is read.', aliceCopy, { input: { noIdentityAnchor: true, unanchoredAck: UNANCHORED_ACK } });
  open(N, 'order-both-anchors-before-identity-file', V('bad_anchor'), 'Both anchors given and no identity file.', aliceCopy, { input: { noIdentityAnchor: true, unanchoredAck: UNANCHORED_ACK, identityFile: null } });

  // ---- step 2 comes after step 0: the acknowledgment is asked only once the inputs passed ----
  open(N, 'order-identity-file-before-acknowledgment', V('identity_check_required'), 'Unanchored, no acknowledgment, and no identity file: identity_check_required is step 0, unanchored_not_acknowledged step 2.', aliceCopy, { input: { identityFp: null, noIdentityAnchor: true, identityFile: null } });
  open(N, 'order-email-before-acknowledgment', V('bad_email'), 'Unanchored, no acknowledgment, and no --email: bad_email is step 0, unanchored_not_acknowledged step 2.', aliceCopy, { input: { identityFp: null, noIdentityAnchor: true, email: null } });

  // ---- step 2: the typed acknowledgment is trimmed, then compared exactly ----
  open(N, 'acknowledgment-with-spaces-around', ok('alice', false), 'The acknowledgment typed with two spaces before it and one after: white space at both ends is removed.', aliceCopy, { input: { identityFp: null, noIdentityAnchor: true, unanchoredAck: '  ' + UNANCHORED_ACK + ' ' } });
  open(N, 'acknowledgment-with-a-tab-after', ok('alice', false), 'The acknowledgment and a tab after it.', aliceCopy, { input: { identityFp: null, noIdentityAnchor: true, unanchoredAck: UNANCHORED_ACK + '\t' } });
  open(N, 'acknowledgment-in-lower-case', V('unanchored_not_acknowledged'), 'The acknowledgment in lower case: compared exactly.', aliceCopy, { input: { identityFp: null, noIdentityAnchor: true, unanchoredAck: UNANCHORED_ACK.toLowerCase() } });
  open(N, 'acknowledgment-with-a-double-space-inside', V('unanchored_not_acknowledged'), 'Two spaces between two of its words: only the ends are trimmed.', aliceCopy, { input: { identityFp: null, noIdentityAnchor: true, unanchoredAck: UNANCHORED_ACK.replace(' recovery', '  recovery') } });

  // ---- the fleet verify: nothing asked, unanchored by design, nothing without the magic read ----
  open(N, 'verify-pre-v2-json-blob', V('unknown_format'), 'The fleet verify and a pre-signed JSON copy: unknown_format.', { frame: utf8(v1Json), statement: v1Json }, { input: { mode: 'verify' } });
  open(N, 'verify-another-members-copy', V('user_mismatch'), 'The fleet verify, alice\'s row, and bob\'s copy in it.', bobCopy, { input: { mode: 'verify' } });
  open(N, 'verify-identity-file-absent', V('identity_check_required'), 'The fleet verify with no identity file for the row.', aliceCopy, { input: { mode: 'verify', identityFile: null } });
  open(N, 'verify-identity-seed-under-another-key', V('identity_check_failed'), 'The fleet verify, and an identity file whose seed does not open under the copy\'s key.', aliceCopy, { input: { mode: 'verify', identityFile: 'alice-seed-under-another-key' } });

  // ---- every refusal has a name: the identity file's key, the fleet check's dump, other white space ----
  open(N, 'identity-pub-of-31-bytes', V('identity_check_failed'), 'The identity file\'s identityPub is 31 bytes: refused at step 0, after the inputs, by the tool and by the shared openers (spec 04 §4 step 0, the paragraph after the list).', aliceCopy, { input: { identityFile: 'alice-pub-of-31-bytes' } });
  open(N, 'order-email-before-the-identity-key', V('bad_email'), 'No --email and an identityPub of 31 bytes: the inputs of step 0 come before the identity file\'s key. The shared opener, which has no --email, refuses the key.', aliceCopy, { input: { identityFile: 'alice-pub-of-31-bytes', email: null } });
  open(N, 'acknowledgment-followed-by-a-form-feed', V('unanchored_not_acknowledged'), 'The acknowledgment and a form feed (U+000C) after it: only space and tab are removed from the ends of a typed line, by the tool, and the shared check removes nothing.', aliceCopy, { input: { identityFp: null, noIdentityAnchor: true, unanchoredAck: UNANCHORED_ACK + '\f' } });
  open(N, 'verify-dump-names-another-recovery-key', V('recovery_fp_mismatch'), 'The fleet verify, and a dump row whose fingerprint column is recovery key B\'s: the row says its copy is sealed to another recovery key than this sheet\'s.', aliceCopy, { input: { mode: 'verify', dumpFingerprint: recoveryB.fp } });
  open(N, 'verify-copy-with-a-space-after', V('bad_copy'), 'The fleet verify, and a dump row whose sealed column has a space after it: not canonical base64url exactly as given.', aliceCopy, { input: { mode: 'verify' }, sealedText: b64u(sealCopy('verify-copy-with-a-space-after', aliceCopy.frame)) + ' ' });

  // ---- the whole `recovery-cli assist` run (spec 04 §7 step 3 with §4) ----
  const rSec = fixed('recovery/request-secret');
  const rPub = x25519Base(rSec);
  const otherRPub = x25519Base(fixed('recovery/other-request-secret'));
  const requestId = b64u(fixed('recovery/request-id', 16));
  const CLOCK = T0 + 300 * HOUR;
  const assistBase = {
    instance: ids.instance, request: requestId, requestKey: b64u(rPub), requestCode: requestCode(rPub).code, email: ALICE,
    user: alice.userId, identityFp: fpOf(alice).slice(0, 32), noIdentityAnchor: false, identityFile: 'alice',
  };
  const assist = [];
  const run = (name, want, why, ctx = {}) => {
    if (names.has('assist/' + name)) throw new Error('escrow-v3: duplicate assist row ' + name);
    names.add('assist/' + name);
    const args = { ...assistBase, ...ctx.args };
    const typed = { unanchoredAck: null, confirmation: 'RECOVER ' + args.user?.slice(0, 8), ...ctx.typed };
    const sealed = ctx.sealed ?? aliceCopy.sealed;
    const clock = ctx.clock ?? CLOCK;
    const fileOverride = ctx.identityFileBytes ?? null;
    const got = runAssist({
      argv: commandLine(args, ctx.extraArgs ?? []),
      readFile: (path) => fileOverride ?? (identityFiles[path] ? download(path, sealed) : null),
      seedTyped: ctx.seedTyped ?? b64u(recoveryA.seed), unanchoredAck: typed.unanchoredAck, confirmation: typed.confirmation,
      clock, commit: fixed('escrow-v3/assist/commit'), ephemeral: fixed('escrow-v3/assist/ephemeral/' + name), recovery: recoveryA,
    });
    let g;
    if (got.verdict === 'ok') {
      const { commit: _c, ...values } = got.answer.values;
      g = { verdict: 'ok', answer: { values, statementBytes: got.answer.statement.length, sealedBytes: got.answer.sealed.length, tokenHead: [ 'andvari-answer', '3', args.request, args.requestKey, '' ].join(':') } };
    } else {
      g = got.verdict === 'email_mismatch' ? { verdict: got.verdict, copyEmail: got.copyEmail } : { verdict: got.verdict };
    }
    if (JSON.stringify(g) !== JSON.stringify(want)) throw new Error(`escrow-v3 assist "${name}": the text says ${JSON.stringify(want)}, the oracle says ${JSON.stringify(g)}`);
    const row = { name, why, args };
    if (ctx.extraArgs) row.extraArgs = ctx.extraArgs;
    Object.assign(row, { typed, clock, sealedB64: b64u(sealed) });
    if (fileOverride) row.identityFileB64 = b64u(fileOverride);
    if (ctx.seedTyped !== undefined) row.seedTyped = ctx.seedTyped;
    row.expect = want;
    assist.push(row);
  };
  const okAnswer = (issuedAt = CLOCK) => ({
    verdict: 'ok',
    answer: {
      values: { instanceId: ids.instance, userId: alice.userId, email: emailB64Of(ALICE), requestId, requestKey: b64u(rPub), uvk: b64u(uvkOf.alice), issuedAt },
      statementBytes: 399, sealedBytes: 548, tokenHead: `andvari-answer:3:${requestId}:${b64u(rPub)}:`,
    },
  });
  const UNANCH = { args: { identityFp: null, noIdentityAnchor: true }, typed: { unanchoredAck: UNANCHORED_ACK } };
  run('anchored', okAnswer(), 'Every argument right, alice\'s copy, RECOVER 11111111 typed: the tool makes the version-3 answer (its commit value is the tool\'s own random draw, so expect gives the statement\'s other values and the sizes).');
  run('unanchored', okAnswer(), 'Unanchored, with the acknowledgment typed.', UNANCH);
  run('request-code-in-groups', okAnswer(), 'The request code typed as the person reads it, six groups of four separated by spaces.', { args: { requestCode: requestCode(rPub).grouped } });
  run('confirmation-with-spaces-around', okAnswer(), 'RECOVER 11111111 typed with spaces around it: trimmed, then compared exactly.', { typed: { confirmation: '  RECOVER 11111111 ' } });
  run('instance-absent', V('bad_instance'), 'No --instance.', { args: { instance: null } });
  run('instance-in-capitals', V('bad_instance'), '--instance in upper case.', { args: { instance: ids.instance.toUpperCase() } });
  run('request-absent', V('bad_request_id'), 'No --request.', { args: { request: null } });
  run('request-of-32-bytes', V('bad_request_id'), '--request is 32 bytes (the request key typed in its place).', { args: { request: b64u(rPub) } });
  run('request-with-a-space-after', V('bad_request_id'), '--request with a space after it: not a b64_16 (spec 01 §5.1 grammar).', { args: { request: requestId + ' ' } });
  run('request-key-absent', V('bad_request_key'), 'No --request-key.', { args: { requestKey: null } });
  run('request-key-of-31-bytes', V('bad_request_key'), '--request-key of 31 bytes.', { args: { requestKey: b64u(rPub.slice(0, 31)) } });
  run('request-key-with-a-space-before', V('bad_request_key'), '--request-key with a space before it: not a canonical b64_32.', { args: { requestKey: ' ' + b64u(rPub) } });
  run('request-key-low-order-zero', V('low_order_request_key'), '--request-key is 32 zero bytes, a low-order point.', { args: { requestKey: b64u(new Uint8Array(32)) } });
  run('request-key-low-order-p', V('low_order_request_key'), '--request-key is the encoding of p, a low-order point.', { args: { requestKey: b64u(Uint8Array.from([0xed, ...new Array(30).fill(0xff), 0x7f])) } });
  run('request-code-absent', V('request_code_mismatch'), 'No --request-code.', { args: { requestCode: null } });
  run('request-code-of-another-key', V('request_code_mismatch'), 'The code of another request key: a server that swapped rPub is caught here.', { args: { requestCode: requestCode(otherRPub).code } });
  run('copy-of-another-address', { verdict: 'email_mismatch', copyEmail: ALICE }, 'bob\'s address typed; the copy is alice\'s.', { args: { email: BOB } });
  run('old-form', V('no_address'), 'alice\'s genuine copy of the old form.', { sealed: sealCopy('assist/old-form', aliceV2.frame) });
  run('not-confirmed-another-account', V('not_confirmed'), 'RECOVER and the first 8 characters of bob\'s userId.', { typed: { confirmation: 'RECOVER ' + bob.userId.slice(0, 8) } });
  run('not-confirmed-lower-case', V('not_confirmed'), '"recover 11111111": compared exactly.', { typed: { confirmation: 'recover 11111111' } });
  run('not-confirmed-nothing-typed', V('not_confirmed'), 'An empty line.', { typed: { confirmation: '' } });
  run('clock-of-12-digits', V('bad_clock'), 'The machine\'s clock reads 999999999999 ms (12 digits).', { clock: 999999999999 });
  run('clock-of-14-digits', V('bad_clock'), 'The clock reads 10^13 ms (14 digits).', { clock: 1e13 });
  run('order-instance-before-request', V('bad_instance'), 'No --instance and no --request.', { args: { instance: null, request: null } });
  run('order-request-before-request-key', V('bad_request_id'), 'A bad --request and a bad --request-key.', { args: { request: b64u(rPub), requestKey: null } });
  run('order-request-arguments-before-step-0', V('bad_request_key'), 'No --request-key and no --user: assist\'s own three arguments come before §4 step 0 (§7 step 3.1).', { args: { requestKey: null, user: null } });
  run('order-low-order-before-step-0', V('low_order_request_key'), 'A low-order request key and no --email.', { args: { requestKey: b64u(new Uint8Array(32)), email: null } });
  run('order-step-0-before-request-code', V('bad_email'), 'No --email and the code of another key: §4 step 0 before the code (§7 step 3.1, then 3.2).', { args: { email: null, requestCode: requestCode(otherRPub).code } });
  run('order-request-code-before-the-anchor', V('request_code_mismatch'), 'The code of another key and bob\'s account ID as the anchor: the code is checked before the identity file is read.', { args: { requestCode: requestCode(otherRPub).code, identityFp: fpOf(bob).slice(0, 32) } });
  run('order-request-code-before-the-seal', V('request_code_mismatch'), 'The code of another key and a copy sealed to recovery key B: the code is checked before the seed is asked for.', { args: { requestCode: requestCode(otherRPub).code }, sealed: sealCopy('assist/other-key', aliceCopy.frame, recoveryB.publicKey) });
  run('order-address-before-confirmation', { verdict: 'email_mismatch', copyEmail: ALICE }, 'bob\'s address typed, and nothing typed at RECOVER: step 8 refuses before the confirmation is asked.', { args: { email: BOB }, typed: { confirmation: '' } });

  // ---- every refusal has a name (spec 04 §4 "Every refusal has a name", "Reading the identity file"; §7 step 3.0) ----
  const copyText = b64u(aliceCopy.sealed);
  const seed31 = b64u(recoveryA.seed.slice(0, 31));
  const aliceFile = identityFiles.alice;
  const notADownload = utf8(JSON.stringify({ userId: alice.userId, sealed: copyText }));
  run('unknown-option-before-a-bad-instance', V('unknown_option'), 'An option assist does not have (--frob) and an --instance that is not a uuid: the command line is read, and refused, before any value is checked (§7 step 3.0).', { args: { instance: 'not-a-uuid' }, extraArgs: ['--frob'] });
  run('legacy-switch', V('legacy_refused'), 'The old --legacy switch.', { extraArgs: ['--legacy'] });
  run('more-than-one-copy', V('more_than_one_copy'), 'Two copies given on the command line.', { extraArgs: [copyText, copyText] });
  run('copy-given-in-place-of-the-download', okAnswer(), 'alice\'s copy given on the command line, and a download that carries bob\'s copy: the copy given is the one opened (spec 04 §4 step 0.5).', { extraArgs: [copyText], identityFileBytes: download('alice', bobCopy.sealed) });
  run('copy-given-with-a-space-after', V('bad_copy'), 'The copy given on the command line with a space after it: not canonical base64url exactly as given (step 0.5).', { extraArgs: [copyText + ' '] });
  run('order-copy-given-before-request-code', V('bad_copy'), 'A copy given with a space after it, and the code of another key: step 0.5 comes before the request code (§7 step 3.1, then 3.2).', { extraArgs: [copyText + ' '], args: { requestCode: requestCode(otherRPub).code } });
  run('request-flag-last-without-a-value', V('bad_request_id'), '--request given last, with no value after it: an absent argument, named by its own check.', { args: { request: null }, extraArgs: ['--request'] });
  run('user-flag-last-without-a-value', V('bad_user_id'), '--user given last, with no value after it.', { args: { user: null }, extraArgs: ['--user'] });
  run('identity-file-flag-last-without-a-value', V('identity_check_required'), '--identity-file given last, with no value after it.', { args: { identityFile: null }, extraArgs: ['--identity-file'] });
  run('identity-file-cannot-be-read', V('bad_identity_file'), '--identity-file names a file that cannot be read (args.identityFile is not an entry of identityFiles).', { args: { identityFile: 'no-such-file.json' } });
  run('identity-file-is-not-a-download', V('bad_identity_file'), 'The file is JSON with a userId and a copy, but not a recovery-copy download (no encryptedIdentitySeed, no identityPub).', { identityFileBytes: notADownload });
  const withFF = (() => {
    const text = JSON.stringify({ userId: aliceFile.userId, sealed: copyText, encryptedIdentitySeed: aliceFile.encryptedIdentitySeedB64, identityPub: aliceFile.identityPubB64, note: 'X' });
    const bytes = utf8(text);
    bytes[text.indexOf('"X"') + 1] = 0xff;
    return bytes;
  })();
  run('identity-file-is-not-utf-8', V('bad_identity_file'), 'alice\'s download with one more field whose one character is the byte 0xFF: not UTF-8, so refused before anything in it is read; a decoder that replaced the byte would have found a download.', { identityFileBytes: withFF });
  run('identity-file-user-id-not-a-uuid', V('bad_identity_file'), 'alice\'s download with its userId one digit short: a field outside its grammar ("Files": userId a lowercase uuid).', { identityFileBytes: download('alice', aliceCopy.sealed, { userId: alice.userId.slice(0, -1) }) });
  run('identity-file-seed-not-base64url', V('bad_identity_file'), 'alice\'s download with its encryptedIdentitySeed padded with "=": not canonical base64url.', { identityFileBytes: download('alice', aliceCopy.sealed, { encryptedIdentitySeedB64: aliceFile.encryptedIdentitySeedB64 + '=' }) });
  run('identity-file-of-another-account', V('identity_file_mismatch'), 'bob\'s download (its userId is bob\'s), under alice\'s --user.', { args: { identityFile: 'bob' } });
  run('identity-file-key-of-31-bytes', V('identity_check_failed'), 'alice\'s download with an identityPub of 31 bytes.', { args: { identityFile: 'alice-pub-of-31-bytes' } });
  run('order-identity-key-before-the-seed', V('identity_check_failed'), 'An identityPub of 31 bytes and a seed of 31 bytes typed: the identity file is read before the seed is asked for.', { args: { identityFile: 'alice-pub-of-31-bytes' }, seedTyped: seed31 });
  run('download-copy-with-a-space-after', V('bad_copy'), 'alice\'s download whose sealed field has a space after it.', { identityFileBytes: download('alice', aliceCopy.sealed, { sealedB64: copyText + ' ' }) });
  run('order-download-copy-before-the-seed', V('bad_copy'), 'The same, and a seed of 31 bytes typed: the copy is checked before the seed is asked for.', { identityFileBytes: download('alice', aliceCopy.sealed, { sealedB64: copyText + ' ' }), seedTyped: seed31 });
  run('seed-of-31-bytes', V('bad_seed'), 'The seed typed is 31 bytes of base64url (spec 04 §4 step 1).', { seedTyped: seed31 });
  run('order-clock-before-the-identity-file', V('bad_clock'), 'The clock reads 12 digits, and the identity file is not a download: the clock is checked with the arguments, before anything is read (§7 step 3.2).', { clock: 999999999999, identityFileBytes: notADownload });
  run('order-request-code-before-the-clock', V('request_code_mismatch'), 'The code of another key, and a clock of 12 digits: the code comes first (§7 step 3.2).', { args: { requestCode: requestCode(otherRPub).code }, clock: 999999999999 });

  // ---- how the command line reads what a person typed (spec 04 §4 "Who reads what a person typed"; §7 step 3.2) ----
  const code = requestCode(rPub);
  const groups = code.grouped.split(' ');
  run('request-code-with-dashes', okAnswer(), 'The request code in groups of four separated by dashes: spaces, tabs and dashes are removed.', { args: { requestCode: groups.join('-') } });
  run('request-code-in-upper-case', okAnswer(), 'The request code in upper case: its letters are compared without regard to case.', { args: { requestCode: code.code.toUpperCase() } });
  run('request-code-with-tabs', okAnswer(), 'The request code in groups separated by tabs.', { args: { requestCode: groups.join('\t') } });
  run('request-code-with-a-line-feed', V('request_code_mismatch'), 'The request code with a line feed after it: any character other than space, tab or dash is no match.', { args: { requestCode: code.code + '\n' } });
  run('request-code-with-a-carriage-return', V('request_code_mismatch'), 'The request code with a carriage return after it.', { args: { requestCode: code.code + '\r' } });
  run('request-code-with-no-break-spaces', V('request_code_mismatch'), 'The request code in groups separated by no-break spaces (U+00A0).', { args: { requestCode: groups.join('\u00A0') } });
  run('confirmation-followed-by-a-form-feed', V('not_confirmed'), 'RECOVER 11111111 and a form feed (U+000C): only space and tab are removed from the ends of a typed line.', { typed: { confirmation: 'RECOVER 11111111\f' } });
  run('confirmation-followed-by-a-no-break-space', V('not_confirmed'), 'RECOVER 11111111 and a no-break space (U+00A0).', { typed: { confirmation: 'RECOVER 11111111\u00A0' } });
  run('confirmation-followed-by-a-vertical-tab', V('not_confirmed'), 'RECOVER 11111111 and a vertical tab (U+000B).', { typed: { confirmation: 'RECOVER 11111111\u000b' } });

  return {
    _about: [
      'The recovery copy (escrow blob) in its version-3 form and its opener: spec 04 §3 and §4 "Opening an escrow offline" steps 0 to 8, spec 01 §5.1 (the version-3 template of 0x02, the email_b64 type) and §5.5 (emailNorm), in the specification as corrected on 2026-11-16 (first written from its text of that day before the corrections). The old form is in escrow-v2.json.',
      'Generated and graded by the independent oracle in tools/vector-gen/oracle (src/recoverycopy.mjs, src/versioned.mjs), written from the specification text alone: `npm run check` regenerates this file byte for byte and recomputes every row. No andvari code was read or run to make it.',
      'Keys: alice and bob are the corpus accounts of cast.mjs (alice\'s seed is the signedstatement.json joint key); the sheet is recovery key A (seed = the first 32 bytes of SHA-256("andvari-vector-oracle|seed/recovery-a")). alice\'s UVK is SHA-256("andvari-vector-oracle|recovery/uvk"), the one recovery.json uses; bob\'s is SHA-256("andvari-vector-oracle|escrow-v3/uvk/bob"). Every other fixed value is the first bytes of SHA-256("andvari-vector-oracle|" + label) for the label named in the source: the identity-seed nonce "escrow-v3/seed-nonce" (24 bytes), each seal\'s ephemeral X25519 secret "escrow-v3/ephemeral/<row>" (seal rows) or "escrow-v3/ephemeral/open/<row name>" (open rows). A real seal draws its ephemeral key at random; here it is fixed so the bytes reproduce. issuedAt is 1763524800000 everywhere.',
      'seal: what a client seals (spec 04 §3): the statement {"v":3,"purpose":"escrow-uvk","userId","email","identityKey","recoveryFp","issuedAt","key"} with email = unpadded base64url of the ASCII bytes of emailNorm(address), signed by the account\'s joint Ed25519 key in the spec 01 §5.1 frame (purpose 0x02), sealed with crypto_box_seal to the recovery public key. Every value is recomputable: statementUtf8, messageHex (M), signatureB64 (RFC 8032, deterministic), frameB64, sealedB64. sealRefuse: an address with no emailNorm seals nothing (the text names no verdict for it).',
      'open: the opener of spec 04 §4, steps in order, the first failure deciding. input.mode is "assist" or "verify" (the fleet verify: no --email, step 8 skipped); input.user = --user; input.identityFp = --identity-fp as typed, or null with input.noIdentityAnchor = true and input.unanchoredAck = what the operator typed; input.identityFile names an entry of identityFiles, or null for no --identity-file; input.email = --email as typed, or null; the sheet seed is sheet.seedB64; input.sealedB64 is the copy. Verdicts: 0 bad_user_id, bad_anchor, identity_check_required, bad_email, then identity_check_failed for an identityPub that is not 32 bytes; 2 identity_fp_mismatch or unanchored_not_acknowledged; 3 unopenable; 4 unknown_format; 5 bad_frame, unknown_format, non_canonical, bad_statement (the strict parse accepts the version-3 template and the old version-2 one, each under its own v), user_mismatch, recovery_fp_mismatch, signer_not_pinned_key, bad_signature, identity_mismatch; 6 identity_check_failed; 7 no_address (a copy that is not version 3); 8 email_mismatch, with expect.copyEmail the address the copy names (the tool says whose copy it is). On ok: userId, email (decoded), emailB64, uvkB64, identityKeyB64, anchored. expectShared, on the five rows where it differs from expect (a grouped anchor, an acknowledgment with space or tab at its ends), is what the shared check answers for the same inputs (see Layers).',
      'The anchor in unanchored mode is the identity file\'s identityPub (it is what the signer must map to and what the statement must equal); --identity-fp is normalised by the tool by removing spaces, tabs and dashes (case kept), then must be 32..64 lowercase hex and a prefix of hex(SHA-256(identityFile.identityPub)). Step 9 (the operator types RECOVER <first 8>) is interactive and has no rows.',
      'Layers (spec 04 §4 "Two layers" and "Who reads what a person typed"): `expect` is the TOOL\'s whole check (steps 0 to 8 for assist, 0 to 7 for the fleet verify), as the operator typed each argument: the command line removes spaces, tabs and dashes from --identity-fp, refuses --identity-fp given with --no-identity-anchor and removes space and tab from both ends of a typed confirmation. The SHARED check (core\'s openForAssist and openForFleet: the same steps 0 to 8, or 0 to 7) reads nothing a person typed: it takes the anchor as given (32..64 lowercase hex, else bad_anchor) and compares the acknowledgment exactly (else unanchored_not_acknowledged). Where its answer differs from the tool\'s, the row gives it as `expectShared` (five rows: the three grouped anchors, bad_anchor; the two acknowledgments with space or tab at their ends, unanchored_not_acknowledged); everywhere else the shared check answers `expect`. `expectOpener`, on assist rows, is what the SHARED opener answers for the same inputs without --email (steps 0 to 6): the anchor and the acknowledgment as given, as the shared check takes them, and on ok the form it opened (format v3 with its email, or v2). Rows have no expectOpener where the opener cannot take the inputs or the text leaves its answer elsewhere: the fleet verify, both anchors given, and the pre-signed form (escrow-v2.json grades it).',
      'The fleet verify (input.mode "verify") takes --user and the identity file only: it asks for nothing, runs unanchored by design and supplies the acknowledgment itself. Its input is one row of the dump: input.user its userId column, input.sealedB64 its sealed column as text (bad_copy when it is not canonical base64url exactly as given), input.identityFile its two identity columns (null when the dump lacks them: identity_check_required), and input.dumpFingerprint, when present, its fingerprint column: the recovery key the copy is sealed to, recovery_fp_mismatch when it is not this sheet\'s (the text does not say what the fleet check does with that column; the row follows the name the tool gives it).',
      'assist: the whole `recovery-cli assist` run (spec 04 §7 step 3), in this order: the command line as it is read (unknown_option, legacy_refused, more_than_one_copy, whichever comes first; a flag given last with no value is an absent argument); its own three request arguments (bad_instance, bad_request_id, bad_request_key, low_order_request_key), each exactly as given; §4 step 0 in its order, then a copy given on the command line (bad_copy); the request code (request_code_mismatch: spaces, tabs and dashes removed, letters compared without regard to case) and the clock (bad_clock outside 10^12 <= t < 10^13), before anything is read; the identity file as it is read (bad_identity_file: it cannot be read, is not strict UTF-8, or is not a download {userId, sealed, encryptedIdentitySeed, identityPub} with userId a lowercase uuid and encryptedIdentitySeed canonical base64url; identity_file_mismatch: its userId is not --user; identity_check_failed: its identityPub is not 32 bytes; bad_copy: the copy it carries, or the one given in its place, is not canonical base64url); the seed (bad_seed: not 32 bytes of base64url); §4 steps 2 to 8; the typed RECOVER <first 8 of the userId> (space and tab removed from both ends, then exact: not_confirmed); then the answer, which signs the clock checked above. The command line is args in the order --instance, --request, --request-key, --request-code, --user, --identity-fp, --identity-file, --email, each that is not null as its flag and its value; then --no-identity-anchor when args.noIdentityAnchor; then extraArgs, when the row has them, exactly as given (an option, or a copy given on the command line). The identity file at the path args.identityFile is the row\'s identityFileB64 (its exact bytes) when it has one; otherwise, when args.identityFile names an entry of identityFiles, the download {"userId","sealed","encryptedIdentitySeed","identityPub"} of that entry\'s userId, encryptedIdentitySeedB64 and identityPubB64 with the row\'s sealedB64 as its sealed, as JSON text in UTF-8; otherwise the file cannot be read. The seed typed is seedTyped when the row has it, else sheet.seedB64. typed.unanchoredAck and typed.confirmation are the lines the operator types, clock the machine\'s ms, sealedB64 the copy. The request key is recovery.json\'s (rSec = SHA-256("andvari-vector-oracle|recovery/request-secret")); the typed code is requestCode(rPub) of recovery.json. On ok, expect.answer gives the statement\'s values except the commit (a fresh random value), its size, the sealed size and the token\'s head up to the commit hash.',
      'Changed with the specification\'s corrections of 2026-11-16: the six `pending` rows are settled and moved into `open` (the pre-signed form, the anchor as typed, the order of step 0, a plaintext under four bytes); new open rows for the anchor as typed (tabs, capitals, colons), for a plaintext under four bytes (empty plaintext, magic only), for both anchors given, for the fleet verify (it asks for nothing; its rows carry no anchor or acknowledgment), for the acknowledgment trimmed and for the order of steps 0 and 2; `expectOpener` (the shared opener of spec 04 §4 "Two layers"); and the `assist` table.',
      'Changed after the comparison with the code (spec 04 §4 "Who reads what a person typed", "Files", "Every refusal has a name", "Reading the identity file"; §7 step 3.0 and 3.2): expectShared on the five open rows where the shared check differs from the command line, and expectOpener on the two acknowledgment rows (unanchored_not_acknowledged: the opener compares exactly); identityFiles entries carry the userId of their download, and a new entry has an identityPub of 31 bytes; new open rows for the identity file\'s key (identity_check_failed at step 0), an acknowledgment followed by a form feed, and the fleet dump\'s own refusals (recovery_fp_mismatch, bad_copy); the assist rows are read through the whole command line, the identity file and the seed (extraArgs, identityFileB64, seedTyped), and the clock is checked with the arguments, before anything is read; new assist rows for every refusal the text names (unknown_option, legacy_refused, more_than_one_copy, bad_copy, bad_identity_file, identity_file_mismatch, identity_check_failed, bad_seed, a flag given last with no value) and for how a typed request code and a typed confirmation are read.',
    ],
    templates: { 'escrow-uvk v3': describeTemplate('escrow-uvk', 3), 'escrow-uvk v2': describeTemplate('escrow-uvk', 2) },
    unanchoredAck: UNANCHORED_ACK,
    sheet: { name: 'recoveryA', seedB64: b64u(recoveryA.seed), recoveryPubB64: b64u(recoveryA.publicKey), recoveryFp: recoveryA.fp, otherRecoveryPubB64: b64u(recoveryB.publicKey), otherRecoveryFp: recoveryB.fp },
    accounts: {
      alice: { ...describe(alice), address: ALICE, identityFingerprint: fpOf(alice), uvkB64: b64u(uvkOf.alice) },
      bob: { ...describe(bob), address: BOB, identityFingerprint: fpOf(bob), uvkB64: b64u(uvkOf.bob) },
    },
    identityFiles,
    seal,
    sealRefuse,
    requestKey: { rSecB64: b64u(rSec), rPubB64: b64u(rPub), requestId, instanceId: ids.instance, requestCode: requestCode(rPub).code, requestCodeGrouped: requestCode(rPub).grouped },
    open: normal,
    assist,
  };
}

export function grade(doc) {
  const failures = [];
  let rows = 0;
  const expect = (cond, what) => {
    rows++;
    if (!cond) failures.push(what);
  };
  const acct = { alice, bob };
  for (const row of doc.seal) {
    const i = row.input;
    const made = sealRecoveryCopy({ account: acct[i.account], address: i.address, uvk: mustUnb64u(i.uvkB64), recoveryPub: mustUnb64u(i.recoveryPubB64), issuedAt: i.issuedAt, ephemeral: mustUnb64u(i.ephemeralSecretB64) });
    const e = row.expect;
    expect(made.sealed !== null && made.statement === e.statementUtf8 && b64u(made.frame) === e.frameB64 && b64u(made.sealed) === e.sealedB64 && hex(made.message) === e.messageHex
      && made.statement.length === e.statementBytes && made.frame.length === e.frameBytes && made.sealed.length === e.sealedBytes && made.values.email === e.emailB64 && emailNorm(i.address) === e.emailNorm, `seal ${row.name}`);
  }
  for (const row of doc.sealRefuse) {
    const made = sealRecoveryCopy({ account: alice, address: row.address, uvk: new Uint8Array(32).fill(1), recoveryPub: mustUnb64u(doc.sheet.recoveryPubB64), issuedAt: 1, ephemeral: new Uint8Array(32).fill(2) });
    expect(made.sealed === null && row.expect.sealed === false, `sealRefuse ${row.name}`);
  }
  const files = Object.fromEntries(Object.entries(doc.identityFiles).map(([k, f]) => [k, { encryptedIdentitySeed: mustUnb64u(f.encryptedIdentitySeedB64), identityPub: mustUnb64u(f.identityPubB64) }]));
  const seed = mustUnb64u(doc.sheet.seedB64);
  for (const row of doc.open) {
    const { sealedB64, ...input } = row.input;
    const withFile = { ...input, identityFile: input.identityFile === null ? null : files[input.identityFile], recoverySeed: seed, sealed: unb64u(sealedB64) };
    const got = input.mode === 'verify' ? verifyDumpRow({ ...withFile, sealedText: sealedB64 }) : openRecoveryCopy(withFile);
    const g = verdictOf(got);
    expect(JSON.stringify(g) === JSON.stringify(row.expect), `open ${row.name}: oracle says ${JSON.stringify(g)}`);
    if (sharedCarries(row.input)) {
      // The shared check answers expectShared where the row gives one, and expect everywhere else.
      const s = verdictOf(openStrictCopy(withFile));
      expect(JSON.stringify(s) === JSON.stringify(row.expectShared ?? row.expect), `open ${row.name} (shared check): oracle says ${JSON.stringify(s)}`);
    } else {
      expect(row.expectShared === undefined, `open ${row.name}: expectShared on a row the shared check cannot carry`);
    }
    if (row.expectOpener !== undefined) {
      const o = openSharedCopy(withFile);
      expect(JSON.stringify(o) === JSON.stringify(row.expectOpener), `open ${row.name} (shared opener): oracle says ${JSON.stringify(o)}`);
    }
  }
  const rPub = mustUnb64u(doc.requestKey.rPubB64);
  for (const row of doc.assist) {
    // The identity file at the path args.identityFile: the row's identityFileB64 when it has one, else the
    // download of the identityFiles entry of that name carrying the row's copy; no entry, no file.
    const readFile = (path) => {
      if (row.identityFileB64 !== undefined) return mustUnb64u(row.identityFileB64);
      const f = doc.identityFiles[path];
      return f ? downloadBytes({ userId: f.userId, sealedB64: row.sealedB64, encryptedIdentitySeedB64: f.encryptedIdentitySeedB64, identityPubB64: f.identityPubB64 }) : null;
    };
    const got = runAssist({
      argv: commandLine(row.args, row.extraArgs ?? []), readFile, seedTyped: row.seedTyped ?? doc.sheet.seedB64,
      unanchoredAck: row.typed.unanchoredAck, confirmation: row.typed.confirmation,
      clock: row.clock, commit: new Uint8Array(32).fill(9), ephemeral: new Uint8Array(32).fill(8), recovery: recoveryA,
    });
    let g;
    if (got.verdict === 'ok') {
      const { commit: _c, ...values } = got.answer.values;
      const opened = boxSealOpen(rPub, mustUnb64u(doc.requestKey.rSecB64), got.answer.sealed);
      g = { verdict: 'ok', answer: { values, statementBytes: got.answer.statement.length, sealedBytes: got.answer.sealed.length, tokenHead: got.answer.token.slice(0, got.answer.token.lastIndexOf(':', got.answer.token.lastIndexOf(':') - 1) + 1) } };
      if (opened === null) g = { verdict: 'sealed answer does not open with the request key' };
    } else {
      g = got.verdict === 'email_mismatch' ? { verdict: got.verdict, copyEmail: got.copyEmail } : { verdict: got.verdict };
    }
    expect(JSON.stringify(g) === JSON.stringify(row.expect), `assist ${row.name}: oracle says ${JSON.stringify(g)}`);
  }
  // The anchor normalisation agrees with the rows that use it.
  expect(normaliseAnchor('ab2f a2eb-e95d bddf 0f6a acce dbcd d89d') === 'ab2fa2ebe95dbddf0f6aaccedbcdd89d', 'normaliseAnchor');
  return { rows, failures };
}
