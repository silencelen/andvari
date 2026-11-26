// instancecard.json: card chains (§4.1, §4.2), every chain rule broken once, a served chain against
// a pinned card (§4.4: fork, withheld), the baked root, and the full-client check of operatorSignKey.

import { b64u, mustUnb64u, utf8 } from '../bytes.mjs';
import { edNegate, edPubToX25519 } from '../prims.mjs';
import { verifyCardChain, checkAgainstPin, pinFromRoot } from '../card.mjs';
import { assembleFrame, frameHash, PURPOSE_CODES } from '../frame.mjs';
import { ZERO_HASH } from '../vaultlog.mjs';
import { signed, signedRaw, tokens, withToken, rawStatement, nameOf } from '../build.mjs';
import { alice, operator, operator2, recoveryA, recoveryB, ids, T0, HOUR, describe } from '../cast.mjs';

export const file = 'instancecard.json';

const CARD = PURPOSE_CODES['instance-card'];
const at = (hours) => T0 + hours * HOUR;

const CARD0 = {
  instanceId: ids.instance, seq: 0, prev: ZERO_HASH, origin: 'https://vault.example.org', name: nameOf('Example Vault'),
  kind: 'private', operator: operator.userId, operatorSignKey: b64u(operator.signPub), recoveryFp: 'none', issuedAt: at(0),
};

/** A chain builder: each step takes the previous card's values and returns the changes. */
class CardChain {
  constructor() {
    this.cards = [];
  }
  get last() {
    return this.cards[this.cards.length - 1];
  }
  nextValues(changes, overrides = {}) {
    const prev = this.last;
    const base = prev ? { ...prev.values, seq: prev.values.seq + 1, prev: prev.hash } : null;
    return { ...(base ?? {}), ...changes, ...overrides };
  }
  draft(signer, changes, overrides = {}) {
    return signed('instance-card', signer, this.nextValues(changes, overrides));
  }
  append(signer, changes, why) {
    const card = this.draft(signer, changes);
    card.why = why;
    this.cards.push(card);
    return card;
  }
  prefix(count) {
    const copy = new CardChain();
    copy.cards = this.cards.slice(0, count);
    return copy;
  }
  get frames() {
    return this.cards.map((c) => c.frame);
  }
}

function buildChains() {
  const base = new CardChain();
  base.append(operator, CARD0, 'card 0: a private instance with no operator recovery; signerPub is its own operatorSignKey');
  base.append(operator, { name: nameOf('Example Family Vault'), issuedAt: at(1) }, 'a rename');
  base.append(operator, { origin: 'https://vault2.example.org:8443', issuedAt: at(2) }, 'a move: the origin changes');
  base.append(operator, { recoveryFp: recoveryA.fp, issuedAt: at(3) }, 'operator recovery is turned on: recoveryFp goes from none to a key fingerprint');
  base.append(operator, { recoveryFp: recoveryB.fp, issuedAt: at(4) }, 'a recovery-key rotation: recoveryFp changes (whether a 0x08 statement covers the change is recovery.json\'s matter, not the chain\'s)');
  base.append(operator, { operator: operator2.userId, operatorSignKey: b64u(operator2.signPub), issuedAt: at(5) },
    'a handover: the card names operator2 and its key, and is signed by the PREVIOUS card\'s key (the old operator)');
  base.append(operator2, { name: nameOf('Example Vault'), issuedAt: at(6) }, 'the first card the new operator signs');
  base.append(operator2, { kind: 'public', recoveryFp: 'none', issuedAt: at(7) }, 'a kind change, with operator recovery turned off: any field but instanceId may change');

  const pub = new CardChain();
  pub.append(operator, {
    instanceId: ids.otherInstance, seq: 0, prev: ZERO_HASH, origin: 'https://vault.andvaripass.com', name: nameOf('andvari'),
    kind: 'public', operator: operator.userId, operatorSignKey: b64u(operator.signPub), recoveryFp: 'none', issuedAt: at(0),
  }, 'card 0 of a public instance');
  pub.append(operator, { issuedAt: at(24) }, 'a card that changes nothing but issuedAt');

  return { base: { name: 'base', why: 'One instance through a rename, a move, operator recovery turned on, a recovery-key rotation, a handover and a kind change.', chain: base },
    public: { name: 'public', why: 'A public instance, as baked into store builds.', chain: pub } };
}

const flip = (frame) => {
  const out = frame.slice();
  out[37 + 10] ^= 0x01;
  return out;
};

function buildRejects(chains) {
  const rows = [];
  const reject = (name, verdict, after, why, make, signerNote) => {
    const chain = chains.base.chain.prefix(after);
    const made = make(chain);
    const frame = made.frame ?? made;
    const result = verifyCardChain([...chain.frames, frame]);
    if (result.verdict !== verdict || result.failedAt !== after) {
      throw new Error(`instancecard reject "${name}": the design says ${verdict} at ${after}, the oracle says ${result.verdict} at ${result.failedAt}`);
    }
    const row = { name, why, chain: 'base', after };
    if (signerNote) row.signer = signerNote;
    else if (made.signer) row.signer = made.signer.name;
    if (made.statement !== undefined) row.statementUtf8 = made.statement;
    row.frameB64 = b64u(frame);
    row.expect = { verdict };
    rows.push(row);
  };
  const rename = { name: nameOf('Renamed'), issuedAt: at(100) };
  const reframe = (card, signerPub, signature = card.signature) => assembleFrame(CARD, signerPub, signature, utf8(card.statement));

  // ---- the signer ----
  reject('signed-by-another-key', 'not_authorized', 1, 'Signed by the wrong key: operator2 signs card 1 before any handover. signerPub is operator2\'s key, not card 0\'s operatorSignKey.',
    (c) => c.draft(operator2, rename));
  reject('signer-negated-point', 'not_authorized', 1, 'A signerPub that is not byte-equal to the previous operatorSignKey: -A, the operator key with the sign bit of x flipped. It has the same X25519 image, which is why the card chain compares bytes.',
    (c) => {
      const good = c.draft(operator, rename);
      const negated = good.signerPub.slice();
      negated[31] ^= 0x80;
      return { frame: reframe(good, negated), statement: good.statement };
    }, 'operator; signerPub then replaced by -A');
  reject('signer-is-the-x25519-key', 'not_authorized', 1, 'signerPub replaced by the operator\'s X25519 identity key: the card names and compares the Ed25519 key.',
    (c) => {
      const good = c.draft(operator, rename);
      return { frame: reframe(good, operator.identityPub), statement: good.statement };
    }, 'operator; signerPub then replaced by the X25519 key');
  reject('signature-by-another-key', 'bad_signature', 1, 'signerPub is the right key, but the signature was made by operator2\'s key.',
    (c) => {
      const good = c.draft(operator, rename);
      const forged = c.draft(operator2, rename);
      return { frame: reframe(good, good.signerPub, forged.signature), statement: good.statement };
    }, 'operator2\'s signature under the operator\'s signerPub');
  reject('signature-flipped', 'bad_signature', 1, 'A valid card 1 with one signature bit flipped.',
    (c) => flip(c.draft(operator, rename).frame), 'operator, then one signature bit flipped');
  reject('statement-changed-after-signing', 'bad_signature', 1, 'The operator signed one origin; the statement in the frame names another (still canonical).',
    (c) => {
      const good = c.draft(operator, { origin: 'https://vault.example.org:8443', issuedAt: at(100) });
      const changed = good.statement.replace(':8443', ':9443');
      return { frame: assembleFrame(CARD, good.signerPub, good.signature, utf8(changed)), statement: changed };
    }, 'operator signed another statement');
  reject('card-0-signed-by-another-key', 'not_authorized', 0, 'Card 0 names the operator\'s key but operator2 signed it: card 0\'s signerPub must equal its own operatorSignKey.',
    () => signed('instance-card', operator2, CARD0));
  reject('card-0-names-another-key', 'not_authorized', 0, 'Card 0 signed by the operator but naming operator2\'s key as operatorSignKey.',
    () => signed('instance-card', operator, { ...CARD0, operator: operator2.userId, operatorSignKey: b64u(operator2.signPub) }));
  reject('handover-signed-by-the-new-operator', 'not_authorized', 5, 'A handover card signed by the account it hands over TO: the previous card\'s key must sign it.',
    (c) => c.draft(operator2, { operator: operator2.userId, operatorSignKey: b64u(operator2.signPub), issuedAt: at(100) }));
  reject('old-operator-after-handover', 'not_authorized', 6, 'After the handover the old operator signs another card: the previous card names operator2\'s key.',
    (c) => c.draft(operator, rename));

  // ---- the chain ----
  reject('prev-zero', 'bad_prev', 1, 'A broken prev: card 1 with prev = 64 zeros.',
    (c) => c.draft(operator, rename, { prev: ZERO_HASH }));
  reject('prev-names-older-card', 'bad_prev', 2, 'A broken prev: card 2 names the hash of card 0.',
    (c) => c.draft(operator, rename, { prev: c.cards[0].hash }));
  reject('seq-skips', 'bad_seq', 1, 'seq 2 where card 1 belongs.',
    (c) => c.draft(operator, rename, { seq: 2 }));
  reject('seq-repeats', 'bad_seq', 1, 'seq 0 again, with prev naming card 0.',
    (c) => c.draft(operator, rename, { seq: 0 }));
  reject('first-card-seq-1', 'bad_seq', 0, 'A self-signed first card with seq 1.',
    () => signed('instance-card', operator, { ...CARD0, seq: 1 }));
  reject('first-card-prev-not-zero', 'bad_prev', 0, 'A self-signed first card whose prev is not 64 zeros.',
    () => signed('instance-card', operator, { ...CARD0, prev: recoveryA.fp }));
  reject('instance-id-changed', 'instance_mismatch', 1, 'A changed instanceId: card 1, otherwise valid and signed by the operator, names another instance.',
    (c) => c.draft(operator, rename, { instanceId: ids.otherInstance }));

  // ---- the order of §2.4's card-chain row: two things wrong at once ----
  reject('order-parse-before-instance', 'non_canonical', 1, 'Not canonical and naming another instance: the parse comes first.',
    (c) => signedRaw(CARD, operator, c.draft(operator, rename, { instanceId: ids.otherInstance }).statement.replace('"seq":', '"seq": ')));
  reject('order-instance-before-seq', 'instance_mismatch', 1, 'Another instanceId and a wrong seq: instance_mismatch comes first, where the log has wrong_vault (VR-10).',
    (c) => c.draft(operator, rename, { instanceId: ids.otherInstance, seq: 5 }));
  reject('order-instance-before-signer', 'instance_mismatch', 1, 'Another instanceId, signed by another key.',
    (c) => c.draft(operator2, rename, { instanceId: ids.otherInstance }));
  reject('order-seq-before-prev', 'bad_seq', 1, 'Wrong seq and wrong prev: bad_seq comes first.',
    (c) => c.draft(operator, rename, { seq: 5, prev: ZERO_HASH }));
  reject('order-prev-before-signer', 'bad_prev', 1, 'Wrong prev, signed by another key: bad_prev comes first.',
    (c) => c.draft(operator2, rename, { prev: ZERO_HASH }));
  reject('order-signer-before-signature', 'not_authorized', 1, 'Signed by another key and the signature broken as well: not_authorized comes first.',
    (c) => flip(c.draft(operator2, rename).frame), 'operator2, then one signature bit flipped');

  // ---- the §2 parse, inside a chain ----
  reject('other-purpose-frame', 'bad_frame', 1, 'A well-formed account-genesis frame (purpose 0x05) where a card is expected.',
    () => signed('account-genesis', alice, { userId: alice.userId, identityKey: alice.key, instanceId: ids.instance, personalVaultId: ids.personalVault, createdAt: at(0) }));
  reject('truncated', 'bad_frame', 1, 'Card 1 cut off inside its signature.',
    (c) => c.draft(operator, rename).frame.slice(0, 70));
  reject('unknown-format', 'unknown_format', 1, 'Card 1 with format byte 0x03 in the magic.',
    (c) => {
      const frame = c.draft(operator, rename).frame.slice();
      frame[3] = 0x03;
      return frame;
    });
  reject('white-space', 'non_canonical', 1, 'Card 1, signed, with a space after a colon.',
    (c) => signedRaw(CARD, operator, c.draft(operator, rename).statement.replace('"seq":', '"seq": ')));
  reject('kind-family', 'non_canonical', 1, 'kind "family" is neither public nor private.',
    (c) => signedRaw(CARD, operator, rawStatement(withToken(tokens('instance-card', c.nextValues(rename)), 'kind', '"family"'))));
  reject('origin-plain-http-lan', 'non_canonical', 1, 'A move to a plain-http LAN address: the origin grammar cannot carry it (R4).',
    (c) => signedRaw(CARD, operator, rawStatement(withToken(tokens('instance-card', c.nextValues(rename)), 'origin', '"http://192.168.1.10:8080"'))));
  reject('version-3', 'bad_statement', 1, 'Card 1, signed and canonical, with "v":3.',
    (c) => signedRaw(CARD, operator, rawStatement(withToken(tokens('instance-card', c.nextValues(rename)), 'v', '3'))));
  return rows;
}

function buildPinned(chains) {
  const rows = [];
  const base = chains.base.chain;
  const add = (name, verdict, why, pinIndex, frames, pinChain = base) => {
    const pin = { card0Hash: pinChain.cards[0].hash, seq: pinChain.cards[pinIndex].values.seq, hash: pinChain.cards[pinIndex].hash };
    const result = checkAgainstPin(pin, frames);
    if (result.verdict !== verdict) throw new Error(`instancecard pinned "${name}": the design says ${verdict}, the oracle says ${result.verdict}`);
    const expect = verdict === 'ok' ? { verdict, newest: { seq: result.newest.seq, hash: result.newest.hash } } : { verdict };
    rows.push({ name, why, pin, frames: frames.map(b64u), expect });
  };

  add('pin-is-the-newest-card', 'ok', 'The served chain ends at the pinned card.', 1, base.prefix(2).frames);
  add('chain-extends-the-pin', 'ok', 'Two verified cards follow the pinned one; the newest verified card is card 3.', 1, base.prefix(4).frames);
  add('withheld-shorter-chain', 'withheld', 'Rollback: the chain ends below the pinned seq. Nothing stops; the client keeps its newer pinned card.', 2, base.prefix(2).frames);
  add('withheld-empty-chain', 'withheld', 'FC-4: no card is served at all (for example between an operator reset and the new card 0). The empty chain is withheld.', 1, []);

  const one = base.prefix(1);
  const otherCard1 = one.draft(operator, { name: nameOf('Another Name'), issuedAt: at(1) });
  add('fork-at-the-pinned-seq', 'fork', 'The chain holds a different, validly signed card at the pinned seq: the client stops using the instance.', 1, [...one.frames, otherCard1.frame]);

  const reset = new CardChain();
  reset.append(operator2, { ...CARD0, operator: operator2.userId, operatorSignKey: b64u(operator2.signPub), issuedAt: at(200) }, '');
  reset.append(operator2, { name: nameOf('Example Vault, again'), issuedAt: at(201) }, '');
  add('fork-after-an-operator-reset', 'fork', '§4.6: reset-instance-identity starts a new chain with the SAME instanceId. A device that pinned the old card 0 sees the new card 0 as a fork.', 0, reset.prefix(1).frames);
  add('fork-new-chain-reaches-the-pinned-seq', 'fork', 'A device that pinned card 1 of the old chain, once the new chain has a card 1.', 1, reset.frames);
  add('fork-reset-chain-below-the-pin', 'fork', 'A device that pinned card 1 of the old chain while the new chain has only its card 0. The served card 0 does not hash to the pin\'s card0Hash, so this is a fork at once, however short the chain is: a replaced chain is never mistaken for one that is merely withheld.', 1, reset.prefix(1).frames);
  add('fork-chain-of-another-instance', 'fork', 'A pinned card against a served chain of another instanceId: its card 0 differs, so it is a fork.', 1, chains.public.chain.frames);
  add('withheld-only-card-0', 'withheld', 'The same chain, served up to card 0 only, against a pin at card 2: card 0 matches the pin\'s card0Hash, so the chain is withheld, not forked.', 2, base.prefix(1).frames);
  return rows;
}

function buildRoots(chains) {
  const rows = [];
  const pub = chains.public.chain;
  const base = chains.base.chain;
  const X0 = base.cards[0].values.origin; // https://vault.example.org
  const X2 = base.cards[2].values.origin; // https://vault2.example.org:8443, after the move
  const LOOKALIKE = 'https://vau1t.example.org';
  /** `dialed` is the origin the client dialed to fetch the chain. */
  const add = (name, verdict, why, root, dialed, frames) => {
    const result = pinFromRoot(root, frames, dialed);
    if (result.verdict !== verdict) throw new Error(`instancecard root "${name}": the design says ${verdict}, the oracle says ${result.verdict}`);
    rows.push({ name, why, root, dialedOrigin: dialed, frames: frames.map(b64u), expect: verdict === 'ok' ? { verdict, pinned: result.pinned } : { verdict } });
  };

  // ---- baked ----
  const baked = { root: 'baked', origin: pub.cards[0].values.origin, instanceId: pub.cards[0].values.instanceId, card0Hash: pub.cards[0].hash, kind: 'public' };
  const P = baked.origin;
  add('baked-card-0-only', 'ok', 'Card 0 hashes to the baked card0Hash and names the baked instanceId: it is pinned.', baked, P, pub.prefix(1).frames);
  add('baked-newest-card-is-pinned', 'ok', 'Card 0 matches the baked constants and a verified card follows: the newest verified card is pinned.', baked, P, pub.frames);
  const otherPublic = new CardChain();
  otherPublic.append(operator2, { ...pub.cards[0].values, operator: operator2.userId, operatorSignKey: b64u(operator2.signPub), issuedAt: at(300) }, '');
  add('baked-card-0-differs', 'card0_mismatch', 'The served card 0 names the baked instanceId and the baked origin but does not hash to the baked card0Hash (a new chain after an operator reset, or another server answering for the address).', baked, P, otherPublic.frames);
  add('baked-instance-id-differs', 'instance_mismatch', 'Card 0 hashes to the baked card0Hash, but the baked instanceId is another: the two baked constants must both match.',
    { ...baked, instanceId: ids.instance }, P, pub.prefix(1).frames);
  const impostor = new CardChain();
  impostor.append(operator2, { ...CARD0, origin: P, operator: operator2.userId, operatorSignKey: b64u(operator2.signPub), issuedAt: at(301) }, '');
  add('baked-both-differ', 'card0_mismatch', 'The served chain is another instance that names the baked origin as its own: neither card 0\'s hash nor its instanceId matches. card0_mismatch comes before instance_mismatch in the pinning order.', baked, P, impostor.frames);
  add('baked-empty-chain', 'withheld', 'No card is served: a baked root against an empty chain is withheld.', baked, P, []);
  add('baked-another-instance-served-at-the-baked-origin', 'origin_mismatch', 'The baked address serves another instance\'s genuine chain, whose cards name that instance\'s own origin. origin_mismatch comes first, before card0_mismatch and instance_mismatch, which this chain would also fail.', baked, P, base.prefix(2).frames);
  const movedPublic = pub.prefix(2);
  movedPublic.append(operator, { origin: 'https://vault.andvari.example', issuedAt: at(48) }, '');
  add('baked-newest-card-names-another-origin', 'origin_mismatch', 'The genuine public chain: card 0 matches both baked constants, but its newest card names another origin than the baked one the client dialed. A first pin never follows a card to another address.', baked, P, movedPublic.frames);

  // ---- kit ----
  const kit = { root: 'kit', card0Hash: base.cards[0].hash };
  add('kit-card-0-matches', 'ok', 'Recovering with a kit: card 0 hashes to the kit\'s card0Hash, and the newest verified card names the dialed origin (the instance moved there in card 2); it is pinned.', kit, X2, base.prefix(3).frames);
  const reset = new CardChain();
  reset.append(operator2, { ...CARD0, operator: operator2.userId, operatorSignKey: b64u(operator2.signPub), issuedAt: at(200) }, '');
  add('kit-card-0-differs', 'card0_mismatch', 'A kit made before an operator reset: the served card 0 is the new chain\'s. The client falls back to the Trust Gate with its warning (§4.4).', kit, X0, reset.frames);
  add('kit-empty-chain', 'withheld', 'No card is served: a kit root against an empty chain is withheld.', kit, X0, []);
  add('kit-genuine-chain-at-another-origin', 'origin_mismatch', 'A look-alike address serves the real instance\'s genuine chain. Card 0 hashes to the kit\'s card0Hash, but the newest card names the real origin, not the one dialed: without this check the kit would vouch for the look-alike.', kit, LOOKALIKE, base.prefix(2).frames);
  add('kit-dialed-the-old-origin-after-a-move', 'origin_mismatch', 'The instance moved in card 2. The old address still serves the chain; its newest card names the new origin. A device with no pin dialed the old one: origin_mismatch. (Only under an existing pin is a changed origin a move.)', kit, X0, base.prefix(3).frames);
  add('order-origin-before-card-0', 'origin_mismatch', 'A look-alike address serves a chain whose card 0 does not hash to the kit\'s card0Hash either: origin_mismatch comes first.', kit, LOOKALIKE, reset.frames);

  // ---- link offer ----
  const offer = (index) => ({ root: 'link_offer', cardHash: base.cards[index].hash, instanceId: ids.instance });
  add('offer-card-is-the-newest', 'ok', 'The offer names the newest card of the served chain.', offer(2), X2, base.prefix(3).frames);
  add('offer-card-is-older', 'ok', 'The offer names card 1; the chain has moved on. The NEWEST verified card is pinned, not the one the offer names.', offer(1), X2, base.prefix(4).frames);
  add('offer-card-is-card-0', 'ok', 'The offer names card 0.', offer(0), X0, base.prefix(2).frames);
  add('offer-card-not-served-yet', 'card_not_in_chain', 'The offer names card 3, but the served chain ends at card 1.', offer(3), X0, base.prefix(2).frames);
  add('offer-card-from-another-chain', 'card_not_in_chain', 'The served chain is another chain for the same instanceId; it does not contain the offer\'s card.', offer(0), X0, reset.frames);
  add('offer-card-and-no-chain', 'withheld', 'No card is served at all: an empty chain is withheld for every root, a link offer included. (card_not_in_chain is for a served chain that lacks the offer\'s card.)', offer(0), X0, []);
  add('offer-card-under-another-instance', 'instance_mismatch', 'The offer\'s cardHash is in the served chain, but the offer names another instanceId than that card.', { ...offer(1), instanceId: ids.otherInstance }, X2, base.prefix(3).frames);
  add('offer-genuine-chain-at-another-origin', 'origin_mismatch', 'A look-alike address serves the real instance\'s genuine chain, which holds the offer\'s card under the offer\'s instanceId. The newest card names the real origin, not the one dialed.', offer(1), LOOKALIKE, base.prefix(2).frames);
  add('order-origin-before-card-not-in-chain', 'origin_mismatch', 'The dialed address serves a chain that names another origin and does not hold the offer\'s card: origin_mismatch comes first.', offer(3), LOOKALIKE, base.prefix(2).frames);
  add('order-origin-before-instance', 'origin_mismatch', 'The served chain names another origin, and the offer names another instanceId than its card: origin_mismatch comes first.', { ...offer(1), instanceId: ids.otherInstance }, LOOKALIKE, base.prefix(2).frames);

  // ---- a typed address, behind the Trust Gate ----
  const typed = { root: 'typed' };
  add('typed-address-names-itself', 'ok', 'A hand-typed address: trust on first use. The newest verified card names the dialed origin; after the Trust Gate it is pinned.', typed, X0, base.prefix(2).frames);
  add('typed-genuine-chain-at-another-origin', 'origin_mismatch', 'A look-alike address serves the real instance\'s genuine chain. Without this check the Trust Gate would show the real instance\'s name and operator key for the look-alike.', typed, LOOKALIKE, base.prefix(2).frames);
  add('typed-empty-chain', 'withheld', 'No card is served at the typed address: an empty chain is withheld for every root, the typed address included.', typed, X0, []);
  add('typed-old-origin-after-a-move', 'origin_mismatch', 'The old address of an instance that moved, typed on a device with no pin: its newest card names the new origin.', typed, X0, base.prefix(3).frames);
  return rows;
}

function buildOperatorDevice(chains) {
  const rows = [];
  const base = chains.base.chain;
  const add = (name, verdict, failedAt, why, self, frames) => {
    const result = verifyCardChain(frames, self ? { self } : {});
    if (result.verdict !== verdict || (verdict !== 'ok' && result.failedAt !== failedAt)) {
      throw new Error(`instancecard operatorDevice "${name}": the design says ${verdict} at ${failedAt}, the oracle says ${result.verdict} at ${result.failedAt}`);
    }
    const row = { name, why, self: self ? { userId: self.userId, signPubB64: b64u(self.signPub) } : null, frames: frames.map(b64u) };
    row.expect = verdict === 'ok' ? { verdict } : { verdict, failedAt };
    rows.push(row);
  };
  const one = base.prefix(1);
  const wrongKey = one.draft(operator, { operatorSignKey: b64u(operator2.signPub), issuedAt: at(1) });
  const wrongKeyCard0 = signed('instance-card', operator2, { ...CARD0, operatorSignKey: b64u(operator2.signPub) });
  const flipped = wrongKey.frame.slice();
  flipped[37 + 10] ^= 0x01;

  add('own-key-is-named', 'ok', null, 'The operator\'s own device, handed the Ed25519 key it derives from its own identity seed: card 0 and card 1 name its account with exactly that key.', operator, base.prefix(2).frames);
  add('own-account-another-key', 'operator_key_mismatch', 1, 'Card 1 is validly signed by card 0\'s key and still names the operator\'s ACCOUNT, but with operator2\'s key, which is not this device\'s own.', operator, [...one.frames, wrongKey.frame]);
  add('another-device-does-not-check', 'ok', null, 'The same two cards on any other device: no other client holds a trustworthy copy of the operator\'s key, so none checks it, and the chain rule alone holds (the next card must be signed by operator2\'s key).', null, [...one.frames, wrongKey.frame]);
  add('card-0-own-account-another-key', 'operator_key_mismatch', 0, 'A card 0 that names the operator\'s account with operator2\'s key, self-signed by that key.', operator, [wrongKeyCard0.frame]);
  add('handed-over', 'ok', null, 'The old operator\'s device after a handover: card 5 names operator2\'s account, which is not this device\'s to check.', operator, base.prefix(6).frames);
  add('new-operator-after-handover', 'ok', null, 'The new operator\'s device: cards 5 to 7 name its account with its own key; cards 0 to 4 name another account.', operator2, base.frames);
  add('order-signature-before-operator-key', 'bad_signature', 1, 'The mismatching card with a broken signature: bad_signature comes first.', operator, [...one.frames, flipped]);

  // A handover that names the NEGATION of the incoming operator's key (§4.1). -A is a valid point with
  // the same X25519 image as A, so a comparison through the image would pass it; the bytes differ.
  const negatedKey = edNegate(operator2.signPub);
  const five = base.prefix(5);
  const negatedHandover = five.draft(operator, { operator: operator2.userId, operatorSignKey: b64u(negatedKey), issuedAt: at(5) });
  if (b64u(edPubToX25519(negatedKey)) !== b64u(operator2.identityPub)) throw new Error('instancecard: -A must map to the incoming operator\'s identity key, or the row shows nothing');
  add('handover-names-the-negated-key', 'operator_key_mismatch', 5, 'A handover card, validly signed by the outgoing operator (card 4\'s key), that names the incoming operator\'s account with the NEGATION of its signing key: -A, the same y with the sign bit of x flipped. On the incoming operator\'s device operatorSignKey is not byte-equal to the key it derives from its identity seed. -A has the same X25519 image as A, so a comparison through the image would pass this card, and every later card would then have to be signed under -A, which locks the real key out.',
    operator2, [...five.frames, negatedHandover.frame]);
  add('handover-names-the-negated-key-on-another-device', 'ok', null, 'The same six cards on any other device: the chain\'s own checks pass, because the outgoing operator did sign the handover, and only the incoming operator\'s device can tell that the key named is not its own.',
    null, [...five.frames, negatedHandover.frame]);
  return rows;
}

function describeCard(card, record) {
  return { why: card.why, signer: card.signer.name, statementUtf8: card.statement, frameB64: b64u(card.frame), hash: card.hash, record };
}

export function build() {
  const chains = buildChains();
  const chainRows = Object.values(chains).map(({ name, why, chain }) => {
    const result = verifyCardChain(chain.frames);
    if (result.verdict !== 'ok') throw new Error(`instancecard chain "${name}" does not verify: ${result.verdict}`);
    return { name, why, cards: chain.cards.map((card, i) => describeCard(card, result.cards[i])) };
  });
  return {
    _about: [
      'The instance card of design 2026-11-15-onboarding-trust §4: template (§4.1), chain (§4.2), pinning (§4.4).',
      'Hand-authored from the independent oracle in tools/vector-gen/oracle (Node WebCrypto and @noble; no andvari code). Regenerate with `npm run generate` there; `npm run check` fails on any difference.',
      'chains: every card must verify in order. cards[i].record is the pin record of §4.4 for that card ({instanceId, card0Hash, seq, hash, origin, name, kind, operator, operatorSignKey, recoveryFp}); hash is H(frame) and card0Hash is the hash of the chain\'s card 0. Card 0\'s signerPub must equal its own operatorSignKey, card n\'s must equal card n-1\'s operatorSignKey, BYTE FOR BYTE (the Ed25519 form of §2.1), so a verifier without a Montgomery map can check the chain.',
      'reject: verify the first `after` cards of chain `base` (all valid), then `frameB64`. The verdict must be expect.verdict, raised at that card. Order per §2.4 (VR-10): the parse verdicts (bad_frame, unknown_format, non_canonical, bad_statement); instance_mismatch (an instanceId other than the first card\'s); bad_seq; bad_prev; not_authorized (signerPub is not byte-equal to the key that must sign); bad_signature. Cards have no precondition.',
      'pinned: a served chain that verifies (`frames`, from card 0) against a pinned card `pin` = {card0Hash, seq, hash} (§4.4, §2.4). fork: card 0 of the served chain does not hash to pin.card0Hash, however short the chain is, or another hash stands at the pinned seq (the client stops using the instance). withheld: the SAME chain ends below the pinned seq, or no card is served (a state, not a stop). ok: expect.newest is the last verified card.',
      'roots: the first pin of §4.4, on a device that holds no pin for the origin yet, for a served chain that verifies, in §2.4\'s pinning order. `dialedOrigin` is the origin the client dialed to fetch the chain. For every root an empty chain is withheld, and origin_mismatch comes FIRST of the mismatches: the newest verified card\'s origin is not the dialed origin (cards are public, so any server can serve another instance\'s genuine chain; this holds at an instance\'s old address after a move too, where the app may offer to dial the origin the card names and every check runs again there). Then, root baked {card0Hash, instanceId}: card0_mismatch if card 0 does not hash to card0Hash; then instance_mismatch for the baked instanceId. root kit {card0Hash}: card0_mismatch (the CLI\'s --trust-card is this root). root link_offer {cardHash, instanceId}: card_not_in_chain if no served card has that hash; instance_mismatch if the card with that hash is under another instanceId. root typed {}: a hand-typed address behind the Trust Gate, trust on first use. On ok, expect.pinned is the record of the NEWEST verified card. Under an existing pin a changed origin is a move, not a mismatch: the `pinned` rows are that side.',
      'operatorDevice (VR-11, §4.1): the chain verified on a device of an operator account, which is handed `self` = {userId, signPubB64}: its account, and the Ed25519 signing key it derives from its own identity seed. For a card that names that account as `operator`, operatorSignKey must equal self.signPub BYTE FOR BYTE, else operator_key_mismatch, checked after bad_signature. The comparison is on the Ed25519 key itself, never through its X25519 image: a key and its negation have the same image, the key\'s holder can sign under either, and a card naming the negation would pass an image check and then lock the real key out of every later card. Rows with self = null are any other client, which does not make this check; nor does the extension (§17). (The server makes the same byte comparison on a card it is sent, for the account that card names, against the signerPub of that account\'s stored genesis, and answers 400 bad_card; these rows are the device\'s.)',
      'Changed on 2026-11-15, with §4.1: in operatorDevice `self` was {userId, identityPubB64}, the X25519 identity key, and the check was ed25519_pk_to_curve25519(operatorSignKey) == self.identityPub. `self` is now {userId, signPubB64} and the check is byte equality. The verdict of each of the seven rows that were there is unchanged: `self` changed shape on the six that have one, and the `why` of the first three was reworded. The two handover-names-the-negated-key rows are new. No other section changed.',
      'The extension grades every row of this file except operatorDevice and the `roots` rows whose root is kit or link_offer: it handles no kits and no links, so those rows are another client\'s (§17, §12.2). It grades the baked and the typed-address roots.',
    ],
    instanceId: ids.instance,
    keys: {
      operator: describe(operator), operator2: describe(operator2), alice: describe(alice),
      recoveryA: { fingerprint: recoveryA.fp }, recoveryB: { fingerprint: recoveryB.fp },
    },
    chains: chainRows,
    reject: buildRejects(chains),
    pinned: buildPinned(chains),
    roots: buildRoots(chains),
    operatorDevice: buildOperatorDevice(chains),
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

  const chainFrames = {};
  for (const chain of doc.chains) {
    const frames = chain.cards.map((c) => mustUnb64u(c.frameB64));
    chainFrames[chain.name] = frames;
    const result = verifyCardChain(frames);
    expect(result.verdict === 'ok', `chain ${chain.name}: ${result.verdict}`);
    chain.cards.forEach((card, i) => {
      expect(frameHash(frames[i]) === card.hash, `chain ${chain.name}[${i}]: hash`);
      expect(result.cards && same(result.cards[i], card.record), `chain ${chain.name}[${i}]: record`);
      expect(new TextDecoder().decode(frames[i].slice(101)) === card.statementUtf8, `chain ${chain.name}[${i}]: statementUtf8`);
      expect(b64u(frames[i].slice(5, 37)) === doc.keys[card.signer].signPubB64, `chain ${chain.name}[${i}]: signer`);
    });
  }
  const names = new Set();
  for (const row of doc.reject) {
    expect(!names.has(row.name), `reject ${row.name}: duplicate name`);
    names.add(row.name);
    const result = verifyCardChain([...chainFrames[row.chain].slice(0, row.after), mustUnb64u(row.frameB64)]);
    expect(result.verdict === row.expect.verdict && result.failedAt === row.after, `reject ${row.name}: oracle says ${result.verdict} at ${result.failedAt}`);
  }
  for (const row of doc.pinned) {
    const result = checkAgainstPin(row.pin, row.frames.map(mustUnb64u));
    const ok = result.verdict === row.expect.verdict
      && (row.expect.verdict !== 'ok' || (result.newest.seq === row.expect.newest.seq && result.newest.hash === row.expect.newest.hash));
    expect(ok, `pinned ${row.name}: oracle says ${result.verdict}`);
  }
  for (const row of doc.roots) {
    const result = pinFromRoot(row.root, row.frames.map(mustUnb64u), row.dialedOrigin);
    const ok = result.verdict === row.expect.verdict && (row.expect.verdict !== 'ok' || same(result.pinned, row.expect.pinned));
    expect(ok, `root ${row.name}: oracle says ${result.verdict}`);
  }
  for (const row of doc.operatorDevice) {
    const self = row.self ? { userId: row.self.userId, signPub: mustUnb64u(row.self.signPubB64) } : undefined;
    const result = verifyCardChain(row.frames.map(mustUnb64u), self ? { self } : {});
    const ok = result.verdict === row.expect.verdict && (row.expect.verdict === 'ok' || result.failedAt === row.expect.failedAt);
    expect(ok, `operatorDevice ${row.name}: oracle says ${result.verdict} at ${result.failedAt}`);
  }
  return { rows, failures };
}
