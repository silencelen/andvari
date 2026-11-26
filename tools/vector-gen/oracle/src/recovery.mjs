// Operator recovery (design §4.5, §9.3) with §2.4's verdicts: the 0x08 rotation statement, chains
// of rotations, the first-consent walk of the card chain, the 0x09 assisted-recovery payload, the
// 0x0A veto, and the request code.

import { b64u, mustUnb64u, hex, bytesEqual } from './bytes.mjs';
import { sha256, edPubToX25519, boxSealOpen, envelopeOpen, boxKeypairFromSeed } from './prims.mjs';
import { parseFrame, signerMapsTo, signatureValid, PURPOSE_CODES } from './frame.mjs';
import { verifyCardChain } from './card.mjs';

class Undefined extends Error {}

/**
 * A 0x08 rotation checked by a verifier whose current fingerprint is `currentFp` (its consent, the
 * card's, or the fingerprint of the account's current escrow). §2.4's order: the parse verdicts;
 * fp_mismatch (fromFp is not that fingerprint); signer_not_pinned_key (the signer does not map to
 * the recovery key that fingerprint names); bad_signature; instance_mismatch.
 * The key a fingerprint names is the X25519 key whose SHA-256 it is, so the binding needs no stored
 * copy of the outgoing key: SHA-256(ed25519_pk_to_curve25519(signerPub)) must be currentFp.
 */
export function verifyRotation({ frame, currentFp, instanceId }) {
  const parsed = parseFrame(frame, PURPOSE_CODES['recovery-rotation']);
  if (parsed.verdict !== 'ok') return { verdict: parsed.verdict };
  const r = parsed.values;
  if (r.fromFp !== currentFp) return { verdict: 'fp_mismatch' };
  const image = edPubToX25519(parsed.signerPub);
  if (image === null || hex(sha256(image)) !== currentFp) return { verdict: 'signer_not_pinned_key' };
  if (!signatureValid(parsed)) return { verdict: 'bad_signature' };
  if (r.instanceId !== instanceId) return { verdict: 'instance_mismatch' };
  return { verdict: 'ok', toFp: r.toFp };
}

/**
 * PUT /escrow/self {sealed, fingerprint, rotations}: the chain from the fingerprint of the account's
 * current escrow to `fingerprint`, oldest first. The new escrow is stored only when every link
 * verifies in order and the last toFp equals `fingerprint`; otherwise 409 escrow_not_due.
 */
export function checkEscrowRotations({ currentEscrowFp, rotations, fingerprint, instanceId }) {
  if (rotations.length === 0) throw new Undefined('PUT /escrow/self with no rotation');
  let fp = currentEscrowFp;
  for (let i = 0; i < rotations.length; i++) {
    const r = verifyRotation({ frame: rotations[i], currentFp: fp, instanceId });
    if (r.verdict !== 'ok') return { accepted: false, wire: '409 escrow_not_due', failedAt: i, linkVerdict: r.verdict };
    fp = r.toFp;
  }
  if (fp !== fingerprint) return { accepted: false, wire: '409 escrow_not_due' };
  return { accepted: true };
}

/**
 * Whether valid rotations lead from fingerprint `from` to fingerprint `to`: one rotation, or a chain
 * of them, each verified against the fingerprint the chain has reached (so each is signed by the
 * key it rotates away from). The served order does not matter.
 */
function rotationsLead(rotations, from, to, instanceId) {
  const seen = new Set([from]);
  let frontier = [from];
  while (frontier.length > 0) {
    const next = [];
    for (const fp of frontier) {
      for (const frame of rotations) {
        const r = verifyRotation({ frame, currentFp: fp, instanceId });
        if (r.verdict !== 'ok') continue;
        if (r.toFp === to) return true;
        if (!seen.has(r.toFp)) {
          seen.add(r.toFp);
          next.push(r.toFp);
        }
      }
    }
    frontier = next;
  }
  return false;
}

/**
 * First consent (§4.5, FS-R2, FC-2): walk the served chain from card 0 to the newest card, whatever
 * the pin root. Every change of recoveryFp must be matched by a valid 0x08 rotation from the old
 * value to the new one, or by a chain of them that leads from the old value to the new one (a card
 * may jump from A to C while the served rotations go A to B and B to C). `uncovered` lists the
 * changes that are not; any of them means the unsigned-change warning with "Only me" preselected.
 * A change to or from `none` can have no rotation (fromFp and toFp are hex64), so it is uncovered.
 */
export function firstConsentWalk({ cards, rotations }) {
  const chain = verifyCardChain(cards);
  if (chain.verdict !== 'ok') throw new Undefined('the first-consent walk of a chain that does not verify');
  if (chain.cards.length === 0) throw new Undefined('the first-consent walk of an empty chain');
  const instanceId = chain.cards[0].instanceId;
  const uncovered = [];
  for (let i = 1; i < chain.cards.length; i++) {
    const from = chain.cards[i - 1].recoveryFp;
    const to = chain.cards[i].recoveryFp;
    if (from === to) continue;
    const covered = from !== 'none' && to !== 'none' && rotationsLead(rotations, from, to, instanceId);
    if (!covered) uncovered.push({ seq: i, from, to });
  }
  return { warning: uncovered.length > 0, uncovered };
}

/** hexLower(SHA-256("andvari/v2|recovery-request|code|" + b64url(rPub)))[0..24], six groups of four. */
export function requestCode(rPub) {
  const input = 'andvari/v2|recovery-request|code|' + b64u(rPub);
  const code = hex(sha256(input)).slice(0, 24);
  return { input, code, grouped: code.match(/.{4}/g).join(' ') };
}

export const identitySeedAd = (userId) => `andvari/v1|idkey|${userId}`;

/**
 * The requesting device opens a fulfilled request (§9.3 step 4), in §2.4's order: unopenable; the
 * parse verdicts; signer_not_pinned_key (the signer must map to the recovery public key that the
 * pinned card's recoveryFp names); bad_signature; request_mismatch (instanceId, userId, requestId or
 * requestKey); identity_mismatch (the identity seed does not open under the delivered UVK, or its
 * key is not the served identityPub).
 * A device that holds no userId (a fresh install: `request.userId` is null) skips the userId
 * comparison; the seed's AD binds the payload's userId, so a payload for another account then fails
 * as identity_mismatch.
 */
export function openAssistedRecovery({ sealed, rPub, rSec, recoveryPub, request, encryptedIdentitySeed, identityPub }) {
  const plain = boxSealOpen(rPub, rSec, sealed);
  if (plain === null) return { verdict: 'unopenable' };
  const parsed = parseFrame(plain, PURPOSE_CODES['assisted-recovery']);
  if (parsed.verdict !== 'ok') return { verdict: parsed.verdict };
  const a = parsed.values;
  if (!signerMapsTo(parsed.signerPub, recoveryPub)) return { verdict: 'signer_not_pinned_key' };
  if (!signatureValid(parsed)) return { verdict: 'bad_signature' };
  const userOk = request.userId === null || a.userId === request.userId;
  if (a.instanceId !== request.instanceId || !userOk || a.requestId !== request.requestId || a.requestKey !== request.requestKey) {
    return { verdict: 'request_mismatch' };
  }
  const seed = envelopeOpen(mustUnb64u(a.uvk), identitySeedAd(a.userId), encryptedIdentitySeed);
  if (seed === null || !bytesEqual(boxKeypairFromSeed(seed).publicKey, identityPub)) return { verdict: 'identity_mismatch' };
  return { verdict: 'ok', uvk: a.uvk };
}

/**
 * The 0x0A veto as the server verifies it, in §2.4's order: the parse verdicts;
 * signer_not_pinned_key (the signer must map to the account's stored identity key); bad_signature;
 * user_mismatch (the statement's userId is not the session's); request_mismatch (its requestId is not
 * the request's).
 */
export function verifyVeto({ frame, storedIdentityPub, sessionUserId, requestId }) {
  const parsed = parseFrame(frame, PURPOSE_CODES['recovery-veto']);
  if (parsed.verdict !== 'ok') return { verdict: parsed.verdict };
  if (!signerMapsTo(parsed.signerPub, storedIdentityPub)) return { verdict: 'signer_not_pinned_key' };
  if (!signatureValid(parsed)) return { verdict: 'bad_signature' };
  if (parsed.values.userId !== sessionUserId) return { verdict: 'user_mismatch' };
  if (parsed.values.requestId !== requestId) return { verdict: 'request_mismatch' };
  return { verdict: 'ok' };
}
