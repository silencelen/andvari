// The recovery copy (escrow blob) of spec 04 §3 in its version-3 form, and its opener, spec 04 §4
// "Opening an escrow offline" steps 0 to 8, for `recovery-cli assist` and the fleet `verify`.
// Written from the specification text of 2026-11-16 alone, before that day's corrections, then made
// to follow its corrected text of the same day; every choice the text still leaves open is marked
// CHOICE.

import { b64u, unb64u, hex, bytesEqual, latin1, utf8 } from './bytes.mjs';
import { sha256, boxSeal, boxSealOpen, boxKeypairFromSeed, envelopeOpen } from './prims.mjs';
import { emailNorm, isUuid } from './grammar.mjs';
import { MAGIC, signerMapsTo, signatureValid } from './frame.mjs';
import { parseFrameV, signedV, COPY_READER } from './versioned.mjs';

export const UNANCHORED_ACK = 'I understand this recovery is UNANCHORED';
export const identitySeedAd = (userId) => `andvari/v1|idkey|${userId}`;

/** The email_b64 of an address: unpadded base64url of the ASCII bytes of its emailNorm, or null when it has none. */
export function emailB64Of(address) {
  const norm = emailNorm(address);
  return norm === null ? null : b64u(utf8(norm));
}

/**
 * Seal a version-3 recovery copy (spec 04 §3). `address` is the account's registered address; the
 * client writes its emailNorm. "A client that cannot name the address seals nothing": an address
 * with no emailNorm gives { sealed: null }. CHOICE: the text names no verdict for that refusal.
 * `ephemeral` is the X25519 secret crypto_box_seal would draw at random.
 */
export function sealRecoveryCopy({ account, address, uvk, recoveryPub, issuedAt, ephemeral }) {
  const email = emailB64Of(address);
  if (email === null) return { sealed: null };
  const values = {
    userId: account.userId, email, identityKey: b64u(account.identityPub), recoveryFp: hex(sha256(recoveryPub)), issuedAt, key: b64u(uvk),
  };
  const made = signedV('escrow-uvk', 3, account, values);
  return { ...made, sealed: boxSeal(recoveryPub, made.frame, ephemeral) };
}

/**
 * --identity-fp as the TOOL reads it (spec 04 §4 step 0.2): spaces, tabs and dashes
 * removed, case kept; then 32..64 lowercase hex, or null (bad_anchor).
 */
export function normaliseAnchor(typed) {
  if (typeof typed !== 'string') return null;
  const s = typed.replace(/[ \t-]/g, '');
  return /^[0-9a-f]{32,64}$/.test(s) ? s : null;
}

/** The shared opener's anchor (step 0.2): 32..64 lowercase hex exactly, nothing removed. */
const strictAnchor = (typed) => (typeof typed === 'string' && /^[0-9a-f]{32,64}$/.test(typed) ? typed : null);

/**
 * A typed confirmation as the tool reads it (spec 04 §4 step 2): white space removed
 * from both ends, then compared exactly. CHOICE: "white space" is read as U+0020 and U+0009 only, the
 * two the reader of an answer trims; the rows use no other (the text does not say which characters).
 */
export const trimTyped = (s) => (typeof s === 'string' ? s.replace(/^[ \t]+|[ \t]+$/g, '') : s);

/**
 * Open a recovery copy offline. Input:
 *   mode            'assist' or 'verify' (the fleet verify: no --email, no anchor, nothing asked, unanchored
 *                   by design with the acknowledgment supplied by itself, step 8 skipped)
 *   user            --user
 *   identityFp      --identity-fp as typed (null when absent; given together with --no-identity-anchor is bad_anchor)
 *   noIdentityAnchor, unanchoredAck   --no-identity-anchor and the typed acknowledgment (trimmed)
 *   identityFile    { encryptedIdentitySeed, identityPub } (bytes), or null for no --identity-file
 *   email           --email as typed (assist), or null
 *   recoverySeed    the sheet seed
 *   sealed          the copy
 * Steps, the first failure deciding:
 *   0 bad_user_id, bad_anchor, identity_check_required, bad_email (assist)
 *   1 derive the recovery key pair            2 identity_fp_mismatch | unanchored_not_acknowledged
 *   3 unopenable    4 unknown_format          5 bad_frame, unknown_format, non_canonical, bad_statement,
 *     user_mismatch, recovery_fp_mismatch, signer_not_pinned_key, bad_signature, identity_mismatch
 *   6 identity_check_failed                   7 no_address (a copy that is not version 3)
 *   8 email_mismatch (assist only; the answer names the address the copy is for)
 */
export function openRecoveryCopy(input) {
  return wholeCheck(input, false);
}

/**
 * The same whole check as the SHARED check gives it (core's openForAssist and openForFleet, spec 04 §4
 * "Who reads what a person typed"): it is handed values already in their grammar and reads
 * nothing a person typed, so the anchor is taken as given (32..64 lowercase hex, else bad_anchor) and
 * the acknowledgment is compared exactly, nothing removed. It differs from the tool only where a
 * person's typing is read: a grouped anchor and an acknowledgment with space or tab at its ends.
 */
export function openStrictCopy(input) {
  return wholeCheck(input, true);
}

/**
 * One row of the fleet check's dump as the tool reads it (spec 04 §4 "Annual drill", "Files", "Every
 * refusal has a name"): { user, sealedText (the dump's `sealed` column), dumpFingerprint (its
 * `fingerprint` column, or null), identityFile, recoverySeed }. CHOICE: the text does not say what the
 * fleet check does with the dump's fingerprint column; the oracle reads it as the recovery key the copy
 * is sealed to, so one that is not this sheet's is recovery_fp_mismatch (the step 5 name for a copy
 * made for another recovery key). CHOICE: the order of these two checks and step 0.3 is not given;
 * no row combines them. Then the fleet check's steps 0 to 7.
 */
export function verifyDumpRow({ user, sealedText, dumpFingerprint, identityFile, recoverySeed }) {
  if (dumpFingerprint != null && dumpFingerprint !== hex(sha256(boxKeypairFromSeed(recoverySeed).publicKey))) return { verdict: 'recovery_fp_mismatch' };
  const sealed = typeof sealedText === 'string' ? unb64u(sealedText) : null;
  if (sealed === null || sealed.length === 0) return { verdict: 'bad_copy' };
  return wholeCheck({ mode: 'verify', user, identityFile, recoverySeed, sealed }, false);
}

function wholeCheck(input, strict) {
  const { mode, user, identityFp, noIdentityAnchor, unanchoredAck, identityFile, email, recoverySeed, sealed } = input;
  const verify = mode === 'verify';
  // ---- step 0: inputs, before the seed is asked for, in this order ----
  if (typeof user !== 'string' || !isUuid(user)) return { verdict: 'bad_user_id' };
  let anchor = null;
  // The fleet verify takes no anchor and asks for nothing: it runs unanchored by design.
  if (!verify) {
    if (noIdentityAnchor && identityFp != null) return { verdict: 'bad_anchor' };
    if (!noIdentityAnchor) {
      anchor = strict ? strictAnchor(identityFp) : normaliseAnchor(identityFp);
      if (anchor === null) return { verdict: 'bad_anchor' };
    }
  }
  if (!identityFile) return { verdict: 'identity_check_required' };
  let typedNorm = null;
  if (mode === 'assist') {
    typedNorm = typeof email === 'string' ? emailNorm(email) : null;
    if (typedNorm === null) return { verdict: 'bad_email' };
  }
  // The identity file's key, still at step 0, after the inputs (spec 04 §4 step 0, the paragraph after
  // the list). runAssist (assist.mjs) checks the positional copy (0.5) and, after this step, the request
  // code and the clock (§7 step 3.2); it reads the identity file only then.
  if (input.stopAfterStep0) return { verdict: 'step0_ok' };
  if (identityFile.identityPub.length !== 32) return { verdict: 'identity_check_failed' };
  const ack = verify ? UNANCHORED_ACK : strict ? unanchoredAck : trimTyped(unanchoredAck);
  return openFromStep1({ verify, anchor, unanchoredAck: ack, identityFile, user, typedNorm, recoverySeed, sealed, tool: true });
}

/**
 * The shared opener (spec 04 §4 "Two layers"): steps 0 to 6 without --email, answering
 * what it opened and in which form. Its anchor is taken as given (32..64 lowercase hex)
 * and the acknowledgment as given. A plaintext that does not start with the magic but with `{` is the
 * pre-signed form, which only this opener still reads (for `recover` and escrow-v2.json, which grades
 * it): the oracle answers { verdict: 'pre_signed' } there and the rows carry no opener expectation.
 */
export function openSharedCopy(input) {
  const { user, identityFp, noIdentityAnchor, unanchoredAck, identityFile, recoverySeed, sealed } = input;
  if (typeof user !== 'string' || !isUuid(user)) return { verdict: 'bad_user_id' };
  let anchor = null;
  if (!noIdentityAnchor) {
    anchor = strictAnchor(identityFp);
    if (anchor === null) return { verdict: 'bad_anchor' };
  }
  if (!identityFile) return { verdict: 'identity_check_required' };
  if (identityFile.identityPub.length !== 32) return { verdict: 'identity_check_failed' };
  return openFromStep1({ verify: false, anchor, unanchoredAck, identityFile, user, typedNorm: null, recoverySeed, sealed, tool: false });
}

function openFromStep1({ anchor, unanchoredAck, identityFile, user, typedNorm, recoverySeed, sealed, tool }) {
  // ---- step 1: the recovery key pair ----
  const recovery = boxKeypairFromSeed(recoverySeed);
  const recoveryFp = hex(sha256(recovery.publicKey));
  // ---- step 2: the anchor ----
  const anchoredIdentity = identityFile.identityPub;
  if (anchor !== null) {
    if (!hex(sha256(anchoredIdentity)).startsWith(anchor)) return { verdict: 'identity_fp_mismatch' };
  } else if (unanchoredAck !== UNANCHORED_ACK) {
    return { verdict: 'unanchored_not_acknowledged' };
  }
  // ---- step 3: open ----
  const plain = boxSealOpen(recovery.publicKey, recovery.secretKey, sealed);
  if (plain === null) return { verdict: 'unopenable' };
  // ---- step 4: format; a plaintext under four bytes is unknown_format here ----
  if (plain.length < 4 || !bytesEqual(plain.slice(0, 4), MAGIC)) {
    // The tools read nothing of it; the shared opener still reads the pre-signed form.
    if (!tool && plain.length > 0 && plain[0] === 0x7b) return { verdict: 'pre_signed' };
    return { verdict: 'unknown_format' };
  }
  // ---- step 5: frame, purpose 0x02, strict parse; the anchor ----
  const parsed = parseFrameV(plain, COPY_READER);
  if (parsed.verdict !== 'ok') return { verdict: parsed.verdict };
  const s = parsed.values;
  if (s.userId !== user) return { verdict: 'user_mismatch' };
  if (s.recoveryFp !== recoveryFp) return { verdict: 'recovery_fp_mismatch' };
  if (!signerMapsTo(parsed.signerPub, anchoredIdentity)) return { verdict: 'signer_not_pinned_key' };
  if (!signatureValid(parsed)) return { verdict: 'bad_signature' };
  if (s.userId !== user || s.identityKey !== b64u(anchoredIdentity) || s.recoveryFp !== recoveryFp) return { verdict: 'identity_mismatch' };
  // ---- step 6: the identity check ----
  const uvk = unb64u(s.key);
  const seed = envelopeOpen(uvk, identitySeedAd(user), identityFile.encryptedIdentitySeed);
  if (seed === null || seed.length !== 32 || !bytesEqual(boxKeypairFromSeed(seed).publicKey, anchoredIdentity)) return { verdict: 'identity_check_failed' };
  if (!tool) {
    // The shared opener stops here and says what it opened and in which form.
    const out = { verdict: 'ok', format: 'v' + parsed.version, userId: s.userId };
    if (parsed.version === 3) out.email = latin1(unb64u(s.email));
    return { ...out, uvkB64: s.key, identityKeyB64: s.identityKey, anchored: anchor !== null };
  }
  // ---- step 7: the copy says whose it is (the tools only) ----
  if (parsed.version !== 3) return { verdict: 'no_address' };
  const copyEmail = latin1(unb64u(s.email));
  // ---- step 8: the address (assist only) ----
  if (typedNorm !== null && copyEmail !== typedNorm) return { verdict: 'email_mismatch', copyEmail };
  return { verdict: 'ok', userId: s.userId, email: copyEmail, emailB64: s.email, uvkB64: s.key, identityKeyB64: s.identityKey, anchored: anchor !== null };
}
