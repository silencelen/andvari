// The instance card of design §4: template (§4.1), chain (§4.2), the trust roots and a served chain
// against a pinned card (§4.4). Verdict strings and their order are §2.4's.

import { mustUnb64u, bytesEqual } from './bytes.mjs';
import { parseFrame, signerEquals, signatureValid, frameHash, PURPOSE_CODES } from './frame.mjs';
import { ZERO_HASH, compareWithHead } from './vaultlog.mjs';

/** The record a client pins for a verified card (§4.4). `card0Hash` is the hash of the chain's card 0. */
function record(values, hash, card0Hash) {
  return {
    instanceId: values.instanceId,
    card0Hash,
    seq: values.seq,
    hash,
    origin: values.origin,
    name: values.name,
    kind: values.kind,
    operator: values.operator,
    operatorSignKey: values.operatorSignKey,
    recoveryFp: values.recoveryFp,
  };
}

/**
 * Verify a served chain from card 0. Returns { verdict: 'ok', cards } with the record of every card,
 * or { verdict, failedAt, cards } with the records before the failing card.
 *
 * Per card, in §2.4's order (VR-10): the parse verdicts; instance_mismatch (an instanceId other than
 * the first card's); bad_seq; bad_prev; not_authorized (signerPub is not byte-equal to the key that
 * must sign: card 0's own operatorSignKey, or the previous card's); bad_signature; then, only on the
 * operator's own devices, operator_key_mismatch (VR-11). Cards have no precondition.
 *
 * `self` = { userId, signPub } is given only when the verifier is a device of an operator account:
 * `signPub` is the Ed25519 signing key that device derives from its own identity seed (§4.1). For
 * every card that names that account as `operator`, operatorSignKey must be that key BYTE FOR BYTE.
 * The comparison is never made through the X25519 image: a key and its negation have the same image,
 * the key's holder can sign under either, and a card naming the negation would pass an image check
 * and then lock the real key out of every later card. A card that names another account is not this
 * device's to check.
 */
export function verifyCardChain(frames, { self } = {}) {
  if (self !== undefined && !(typeof self.userId === 'string' && self.signPub instanceof Uint8Array && self.signPub.length === 32)) {
    throw new Error('verifyCardChain: self is { userId, signPub }, the Ed25519 key of 32 bytes');
  }
  const cards = [];
  for (let i = 0; i < frames.length; i++) {
    const fail = (verdict) => ({ verdict, failedAt: i, cards });
    const parsed = parseFrame(frames[i], PURPOSE_CODES['instance-card']);
    if (parsed.verdict !== 'ok') return fail(parsed.verdict);
    const c = parsed.values;
    if (i > 0 && c.instanceId !== cards[0].instanceId) return fail('instance_mismatch');
    if (c.seq !== i) return fail('bad_seq');
    if (c.prev !== (i === 0 ? ZERO_HASH : cards[i - 1].hash)) return fail('bad_prev');
    const mustSign = i === 0 ? c.operatorSignKey : cards[i - 1].operatorSignKey;
    if (!signerEquals(parsed.signerPub, mustUnb64u(mustSign))) return fail('not_authorized');
    if (!signatureValid(parsed)) return fail('bad_signature');
    if (self && c.operator === self.userId && !bytesEqual(mustUnb64u(c.operatorSignKey), self.signPub)) return fail('operator_key_mismatch');
    const hash = frameHash(frames[i]);
    cards.push(record(c, hash, i === 0 ? hash : cards[0].hash));
  }
  return { verdict: 'ok', cards };
}

/**
 * A served chain against a pinned card { card0Hash, seq, hash } (§4.4, §2.4's pinning row), for a
 * chain that itself verifies:
 *   fork      card 0 does not hash to the pin's card0Hash (however short the chain is), or another
 *             hash stands at the pinned seq
 *   withheld  the SAME chain ends below the pinned seq; an empty chain is withheld too (FC-4)
 *   ok        `newest` is the last verified card
 * A chain that does not verify returns its own verdict.
 */
export function checkAgainstPin(pin, frames) {
  const chain = verifyCardChain(frames);
  if (chain.verdict !== 'ok') return { verdict: chain.verdict, failedAt: chain.failedAt };
  if (chain.cards.length > 0 && chain.cards[0].hash !== pin.card0Hash) return { verdict: 'fork' };
  const verdict = compareWithHead(pin, chain.cards.map((c) => c.hash));
  if (verdict !== 'ok') return { verdict };
  return { verdict: 'ok', newest: chain.cards[chain.cards.length - 1] };
}

/**
 * The first pin from a root (§4.4), for a chain that itself verifies and a device that holds no pin
 * for the origin yet, in the order of §2.4's pinning row. `dialedOrigin` is the origin the client
 * dialed to fetch the chain.
 *   every root                             withheld for an empty chain; then origin_mismatch FIRST:
 *                                          the newest verified card's origin is not the dialed origin
 *                                          (cards are public, so any server can serve another
 *                                          instance's genuine chain)
 *   baked       { card0Hash, instanceId }  card0_mismatch; instance_mismatch
 *   kit         { card0Hash }              card0_mismatch
 *   link_offer  { cardHash, instanceId }   card_not_in_chain (the hash lookup comes first), then
 *                                          instance_mismatch for a card under another instanceId
 *   typed       {}                         the typed address behind the Trust Gate: trust on first use
 * On ok, `pinned` is the newest verified card.
 * (Under an existing pin a changed origin is a move, not a mismatch: that is checkAgainstPin's side.)
 */
export function pinFromRoot(root, frames, dialedOrigin) {
  if (typeof dialedOrigin !== 'string') throw new Error('pinFromRoot: the dialed origin is an input');
  if (!['baked', 'kit', 'link_offer', 'typed'].includes(root.root)) throw new Error('pinFromRoot: unknown root ' + root.root);
  const chain = verifyCardChain(frames);
  if (chain.verdict !== 'ok') return { verdict: chain.verdict, failedAt: chain.failedAt };
  const cards = chain.cards;
  if (cards.length === 0) return { verdict: 'withheld' };
  const newest = cards[cards.length - 1];
  if (newest.origin !== dialedOrigin) return { verdict: 'origin_mismatch' };
  if (root.root === 'baked' || root.root === 'kit') {
    if (cards[0].hash !== root.card0Hash) return { verdict: 'card0_mismatch' };
    if (root.root === 'baked' && cards[0].instanceId !== root.instanceId) return { verdict: 'instance_mismatch' };
  }
  if (root.root === 'link_offer') {
    const found = cards.find((c) => c.hash === root.cardHash);
    if (!found) return { verdict: 'card_not_in_chain' };
    if (found.instanceId !== root.instanceId) return { verdict: 'instance_mismatch' };
  }
  return { verdict: 'ok', pinned: newest };
}
