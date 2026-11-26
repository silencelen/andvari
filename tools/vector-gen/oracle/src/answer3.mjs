// The version-3 answer of operator-assisted recovery (spec 04 §7 steps 3 to 5; spec 01 §5.1 and
// §5.5; spec 03 §18.5 and §18.6): the 0x09 statement with the address and the commit value, its
// sizes, the commit hash, the answer token, the person's device opening it, the server's shape and
// size checks on an upload and its check of the commit value. Written from the specification text of
// 2026-11-16 alone, before that day's corrections; every choice the text left open is marked CHOICE.

import { b64u, unb64u, hex, bytesEqual, latin1, utf8 } from './bytes.mjs';
import { sha256, boxSeal, boxSealOpen, boxKeypairFromSeed, envelopeOpen } from './prims.mjs';
import { emailNorm, isB64_32, isHex64 } from './grammar.mjs';
import { signerMapsTo, signatureValid } from './frame.mjs';
import { parseFrameV, signedV, ANSWER_READER } from './versioned.mjs';
import { identitySeedAd } from './recoverycopy.mjs';

export const COMMIT_PREFIX = 'andvari/v2|recovery-request|commit|';
export const TOKEN_PREFIX = 'andvari-answer';
export const TOKEN_VERSION = '3';

/** E: the length of the unpadded base64url of an address of n octets, ceil(4n / 3). */
export const emailChars = (n) => Math.ceil((4 * n) / 3);
/** spec 04 §7 step 3.4: statement 376 + E, frame 477 + E, sealed answer 525 + E bytes. */
export const answerSizes = (E) => ({ statement: 376 + E, frame: 477 + E, sealed: 525 + E });
/** E for an address given as its emailNorm text. */
export const emailCharsOf = (norm) => b64u(utf8(norm)).length;

/** commitHash = hexLower(SHA-256("andvari/v2|recovery-request|commit|" + b64url(commit))), from the b64url text. */
export function commitHashOf(commitB64) {
  const input = COMMIT_PREFIX + commitB64;
  return { input, commitHash: hex(sha256(input)) };
}

/**
 * What recovery-cli assist produces once the copy has opened (§7 step 3, items 4 to 6): the 0x09
 * statement, version 3, signed by the recovery-key signing key and sealed to the request key; the
 * commit hash; and the token. `emailB64` is the copy's own `email` field, copied byte for byte.
 */
export function makeAnswer({ recovery, instanceId, userId, emailB64, requestId, requestKey, commit, uvkB64, issuedAt, ephemeral }) {
  if (!(issuedAt >= 1e12 && issuedAt < 1e13)) throw new Error('makeAnswer: the tool refuses a clock outside 10^12 <= t < 10^13');
  const values = { instanceId, userId, email: emailB64, requestId, requestKey, commit: b64u(commit), uvk: uvkB64, issuedAt };
  const made = signedV('assisted-recovery', 3, recovery, values);
  const sealed = boxSeal(unb64u(requestKey), made.frame, ephemeral);
  const { input, commitHash } = commitHashOf(values.commit);
  const token = [TOKEN_PREFIX, TOKEN_VERSION, requestId, requestKey, commitHash, b64u(sealed)].join(':');
  return { ...made, sealed, commitHashInput: input, commitHash, token };
}

/**
 * The person's device opens an answer (§7 step 4), in order: unopenable; the 0x09 frame and strict
 * parse under the version-3 template (bad_frame, unknown_format, non_canonical, bad_statement; a
 * statement canonical under the version-2 template is bad_statement); signer_not_pinned_key;
 * bad_signature; request_mismatch (instanceId, userId unless the device holds none, requestId,
 * requestKey, and email decoding to exactly the emailNorm of the address typed when asking, on a
 * fresh install too); identity_mismatch. On ok the device keeps the UVK and the commit value.
 * `request` = { instanceId, userId | null, requestId, requestKey, typedEmail }.
 */
export function openAnswerV3({ sealed, rPub, rSec, recoveryPub, request, encryptedIdentitySeed, identityPub }) {
  const plain = boxSealOpen(rPub, rSec, sealed);
  if (plain === null) return { verdict: 'unopenable' };
  const parsed = parseFrameV(plain, ANSWER_READER);
  if (parsed.verdict !== 'ok') return { verdict: parsed.verdict };
  const a = parsed.values;
  if (!signerMapsTo(parsed.signerPub, recoveryPub)) return { verdict: 'signer_not_pinned_key' };
  if (!signatureValid(parsed)) return { verdict: 'bad_signature' };
  const typedNorm = emailNorm(request.typedEmail);
  if (typedNorm === null) throw new Error('openAnswerV3: a device asks only with an address that has an emailNorm');
  const userOk = request.userId === null || a.userId === request.userId;
  const emailOk = latin1(unb64u(a.email)) === typedNorm;
  if (a.instanceId !== request.instanceId || !userOk || a.requestId !== request.requestId || a.requestKey !== request.requestKey || !emailOk) {
    return { verdict: 'request_mismatch' };
  }
  const seed = envelopeOpen(unb64u(a.uvk), identitySeedAd(a.userId), encryptedIdentitySeed);
  if (seed === null || !bytesEqual(boxKeypairFromSeed(seed).publicKey, identityPub)) return { verdict: 'identity_mismatch' };
  return { verdict: 'ok', uvkB64: a.uvk, commitB64: a.commit };
}

/**
 * The server's check of the commit value (spec 03 §18.5), after the poll secret and the request's
 * state: `commit` present and a b64_32 (400 bad_commit); its hash equals the stored commitHash of the
 * newest upload (403 commit_mismatch). CHOICE: "present" means a JSON string; any other JSON value
 * is bad_commit too.
 */
export function checkCommit({ commit, storedCommitHash }) {
  if (typeof commit !== 'string' || !isB64_32(commit)) return { verdict: 'bad_commit', wire: '400 bad_commit' };
  if (commitHashOf(commit).commitHash !== storedCommitHash) return { verdict: 'commit_mismatch', wire: '403 commit_mismatch' };
  return { verdict: 'ok' };
}

/** "canonical base64url of 1 to 1,024 bytes" (spec 03 §18.6). */
function sealedBytes(sealed) {
  if (typeof sealed !== 'string') return null;
  const bytes = unb64u(sealed);
  return bytes !== null && bytes.length >= 1 && bytes.length <= 1024 ? bytes : null;
}

/**
 * The fulfil upload's checks that need no stored state but the row (spec 03 §18.6), in the text's
 * order, the password proof, request_unknown and request_state left out: the body's shape (bad_sealed,
 * bad_request_key, bad_commit_hash: CHOICE, in the order the text lists them); request_key_mismatch;
 * the size, exactly 525 + E bytes for the account's emailNorm (bad_sealed).
 * `row` = { rPub, emailNorm }.
 */
export function fulfilChecks({ body, row }) {
  const bytes = sealedBytes(body.sealed);
  if (bytes === null) return { verdict: 'bad_sealed', wire: '400 bad_sealed' };
  if (typeof body.requestKey !== 'string' || !isB64_32(body.requestKey)) return { verdict: 'bad_request_key', wire: '400 bad_request_key' };
  if (typeof body.commitHash !== 'string' || !isHex64(body.commitHash)) return { verdict: 'bad_commit_hash', wire: '400 bad_commit_hash' };
  if (body.requestKey !== row.rPub) return { verdict: 'request_key_mismatch', wire: '400 request_key_mismatch' };
  if (bytes.length !== answerSizes(emailCharsOf(row.emailNorm)).sealed) return { verdict: 'bad_sealed', wire: '400 bad_sealed' };
  return { verdict: 'ok' };
}
