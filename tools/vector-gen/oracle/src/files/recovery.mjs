// recovery.json: 0x08 rotations (alone, in chains, and against the card chain at first consent),
// the 0x09 assisted-recovery payload, the 0x0A veto and the request code (design §4.5, §9.3, §2.4).

import { b64u, mustUnb64u, utf8 } from '../bytes.mjs';
import { boxSeal, envelopeSeal, x25519Base } from '../prims.mjs';
import { verifyRotation, checkEscrowRotations, firstConsentWalk, requestCode, openAssistedRecovery, verifyVeto, identitySeedAd } from '../recovery.mjs';
import { verifyCardChain } from '../card.mjs';
import { assembleFrame, PURPOSE_CODES } from '../frame.mjs';
import { ZERO_HASH } from '../vaultlog.mjs';
import { signed, signedRaw, tokens, withToken, rawStatement, nameOf } from '../build.mjs';
import { alice, bob, operator, recoveryA, recoveryB, recoveryC, ids, fixed, T0, HOUR, describe } from '../cast.mjs';

export const file = 'recovery.json';

const ROT = PURPOSE_CODES['recovery-rotation'];
const ASSIST = PURPOSE_CODES['assisted-recovery'];
const VETO = PURPOSE_CODES['recovery-veto'];
const at = (hours) => T0 + hours * HOUR;
const flip = (frame) => {
  const out = frame.slice();
  out[37 + 10] ^= 0x01;
  return out;
};
const keyOf = (k) => ({ seedB64: b64u(k.seed), publicKeyB64: b64u(k.publicKey), signPubB64: b64u(k.signPub), fingerprint: k.fp });

function rotation(signer, from, to, overrides = {}) {
  return signed('recovery-rotation', signer, { instanceId: ids.instance, fromFp: from.fp, toFp: to.fp, issuedAt: at(10), ...overrides });
}

function cardChain(steps) {
  const cards = [];
  for (const [i, fp] of steps.entries()) {
    const prev = cards[i - 1];
    cards.push(signed('instance-card', operator, {
      instanceId: ids.instance, seq: i, prev: prev ? prev.hash : ZERO_HASH, origin: 'https://vault.example.org', name: nameOf('Example Vault'),
      kind: 'private', operator: operator.userId, operatorSignKey: b64u(operator.signPub), recoveryFp: fp, issuedAt: at(i),
    }));
  }
  if (verifyCardChain(cards.map((c) => c.frame)).verdict !== 'ok') throw new Error('recovery fixture chain');
  return cards;
}

export function build() {
  const rotAB = rotation(recoveryA, recoveryA, recoveryB);
  const rotBC = rotation(recoveryB, recoveryB, recoveryC, { issuedAt: at(20) });

  // ---- one rotation ----
  const rotationRows = [];
  const names = new Set();
  const rot = (name, verdict, why, made, context = {}) => {
    const frame = made.frame ?? made;
    const consented = context.consented ?? recoveryA;
    const instanceId = context.instanceId ?? ids.instance;
    const got = verifyRotation({ frame, currentFp: consented.fp, instanceId });
    if (got.verdict !== verdict) throw new Error(`recovery rotation "${name}": the design says ${verdict}, the oracle says ${got.verdict}`);
    if (names.has(name)) throw new Error('recovery: duplicate rotation row ' + name);
    names.add(name);
    const row = { name, why };
    if (made.signer) row.signer = made.signer.name;
    if (made.signerNote) row.signer = made.signerNote;
    if (made.statement !== undefined) row.statementUtf8 = made.statement;
    Object.assign(row, { frameB64: b64u(frame), currentFp: consented.fp, recoveryPubB64: b64u(consented.publicKey), instanceId });
    row.expect = verdict === 'ok' ? { verdict, toFp: got.toFp } : { verdict };
    rotationRows.push(row);
  };
  rot('signed-by-the-outgoing-seed', 'ok', 'A rotation from key A to key B, signed offline by the OUTGOING seed A. A verifier whose consent is A moves it to B.', rotAB);
  rot('second-rotation', 'ok', 'The next rotation, B to C, for a verifier whose fingerprint is now B.', rotBC, { consented: recoveryB });
  rot('signed-by-the-incoming-seed', 'signer_not_pinned_key', 'Signed by the wrong seed: the new key B signs its own promotion. The signer must map to the key that fromFp names.', rotation(recoveryB, recoveryA, recoveryB));
  rot('signed-by-an-unrelated-seed', 'signer_not_pinned_key', 'Signed by a third recovery seed.', rotation(recoveryC, recoveryA, recoveryB));
  rot('signed-by-the-operator-account', 'signer_not_pinned_key', 'Signed by the operator account\'s identity key: whoever holds the operator key and the server still cannot rotate the recovery key.', rotation(operator, recoveryA, recoveryB));
  rot('from-fp-is-not-the-consented-one', 'fp_mismatch', 'A valid rotation from B to C shown to a verifier whose consent is still A: it does not start from that fingerprint.', rotBC);
  rot('from-fp-is-the-new-key', 'fp_mismatch', 'A rotation back from B to A, signed by B, for a verifier at A.', rotation(recoveryB, recoveryB, recoveryA));
  rot('signature-flipped', 'bad_signature', 'The rotation with one signature bit flipped.', { frame: flip(rotAB.frame), statement: rotAB.statement, signerNote: 'recoveryA, then one signature bit flipped' });
  const changedTo = rotAB.statement.replace(recoveryB.fp, recoveryC.fp);
  rot('to-fp-changed-after-signing', 'bad_signature', 'toFp changed after signing (still canonical): the rotation would lead to another key.', { frame: assembleFrame(ROT, rotAB.signerPub, rotAB.signature, utf8(changedTo)), statement: changedTo, signerNote: 'recoveryA signed another statement' });
  rot('made-for-another-instance', 'instance_mismatch', 'A rotation the outgoing seed really signed, for another instance (one seed serving two instances): refused last.', rotation(recoveryA, recoveryA, recoveryB, { instanceId: ids.otherInstance }));
  rot('assisted-recovery-frame', 'bad_frame', 'A 0x09 frame where a rotation is expected.',
    signed('assisted-recovery', recoveryA, { instanceId: ids.instance, userId: alice.userId, requestId: b64u(fixed('recovery/request-id', 16)), requestKey: alice.key, uvk: b64u(fixed('recovery/uvk')), issuedAt: at(30) }));
  rot('not-canonical', 'non_canonical', 'A signed rotation with a space after a colon.', signedRaw(ROT, recoveryA, rotAB.statement.replace('"fromFp":', '"fromFp": ')));
  rot('to-fp-none', 'non_canonical', 'toFp "none": both fingerprints are hex64, so no rotation statement can turn operator recovery off or on.', signedRaw(ROT, recoveryA, rawStatement(withToken(tokens('recovery-rotation', rotAB.values), 'toFp', '"none"'))));
  rot('version-3', 'bad_statement', 'A signed, canonical rotation with "v":3.', signedRaw(ROT, recoveryA, rawStatement(withToken(tokens('recovery-rotation', rotAB.values), 'v', '3'))));
  rot('order-parse-before-fp', 'non_canonical', 'Not canonical, and from another fingerprint.', signedRaw(ROT, recoveryB, rotBC.statement.replace('"fromFp":', '"fromFp": ')));
  rot('order-fp-before-signer', 'fp_mismatch', 'From another fingerprint (B), and signed by a seed that is not B either.', rotation(recoveryC, recoveryB, recoveryC));
  rot('order-signer-before-signature', 'signer_not_pinned_key', 'Signed by the incoming seed, with the signature broken as well.', { frame: flip(rotation(recoveryB, recoveryA, recoveryB).frame), signerNote: 'recoveryB, then one signature bit flipped' });
  rot('order-signature-before-instance', 'bad_signature', 'For another instance, with a broken signature.', { frame: flip(rotation(recoveryA, recoveryA, recoveryB, { instanceId: ids.otherInstance }).frame), signerNote: 'recoveryA, then one signature bit flipped' });

  // ---- chains, as the rotations array of PUT /escrow/self ----
  const frames = {
    'A-to-B': rotAB.frame,
    'B-to-C': rotBC.frame,
    'A-to-B-signed-by-B': rotation(recoveryB, recoveryA, recoveryB).frame,
    'B-to-C-signed-by-A': rotation(recoveryA, recoveryB, recoveryC, { issuedAt: at(20) }).frame,
    'A-to-B-for-another-instance': rotation(recoveryA, recoveryA, recoveryB, { instanceId: ids.otherInstance }).frame,
    'A-to-C': rotation(recoveryA, recoveryA, recoveryC).frame,
  };
  const escrow = [];
  const esc = (name, why, list, fingerprint, want, start = recoveryA) => {
    const got = checkEscrowRotations({ currentEscrowFp: start.fp, rotations: list.map((n) => frames[n]), fingerprint: fingerprint.fp, instanceId: ids.instance });
    if (JSON.stringify(got) !== JSON.stringify(want)) throw new Error(`recovery escrow chain "${name}": the design says ${JSON.stringify(want)}, the oracle says ${JSON.stringify(got)}`);
    escrow.push({ name, why, currentEscrowFp: start.fp, rotations: list, fingerprint: fingerprint.fp, instanceId: ids.instance, expect: want });
  };
  const NOT_DUE = { accepted: false, wire: '409 escrow_not_due' };
  esc('one-rotation', 'The account\'s escrow is sealed to A; the client re-seals to B with the one rotation that leads there.', ['A-to-B'], recoveryB, { accepted: true });
  esc('chain-of-two', 'Consent followed two rotations: the chain A to B, B to C, oldest first, and a blob sealed to C.', ['A-to-B', 'B-to-C'], recoveryC, { accepted: true });
  esc('chain-in-the-wrong-order', 'The same two rotations newest first: the first link does not start from the current escrow\'s fingerprint.', ['B-to-C', 'A-to-B'], recoveryC, { ...NOT_DUE, failedAt: 0, linkVerdict: 'fp_mismatch' });
  esc('chain-stops-short', 'One rotation, but the new blob claims to be sealed to C: the last toFp is not the fingerprint.', ['A-to-B'], recoveryC, NOT_DUE);
  esc('chain-overshoots', 'Two rotations for a blob sealed to B.', ['A-to-B', 'B-to-C'], recoveryB, NOT_DUE);
  esc('second-link-signed-by-the-wrong-seed', 'The second link is signed by A, not by the key it rotates away from.', ['A-to-B', 'B-to-C-signed-by-A'], recoveryC, { ...NOT_DUE, failedAt: 1, linkVerdict: 'signer_not_pinned_key' });
  esc('first-link-signed-by-the-incoming-seed', 'The only link is signed by the incoming key.', ['A-to-B-signed-by-B'], recoveryB, { ...NOT_DUE, failedAt: 0, linkVerdict: 'signer_not_pinned_key' });
  esc('link-for-another-instance', 'A rotation made for another instance.', ['A-to-B-for-another-instance'], recoveryB, { ...NOT_DUE, failedAt: 0, linkVerdict: 'instance_mismatch' });
  esc('gap-in-the-chain', 'The chain skips a key: after A to B the next link must start at B, not at A again.', ['A-to-B', 'A-to-C'], recoveryC, { ...NOT_DUE, failedAt: 1, linkVerdict: 'fp_mismatch' });
  esc('escrow-already-at-the-new-key', 'The account\'s escrow is already sealed to B: a chain that starts at A does not start from it.', ['A-to-B'], recoveryB, { ...NOT_DUE, failedAt: 0, linkVerdict: 'fp_mismatch' }, recoveryB);

  // ---- the first-consent walk ----
  const chains = {
    'never-changed': { why: 'recoveryFp is A from card 0 on.', cards: cardChain([recoveryA.fp, recoveryA.fp]) },
    'rotated-once': { why: 'A at cards 0 and 1, B from card 2.', cards: cardChain([recoveryA.fp, recoveryA.fp, recoveryB.fp, recoveryB.fp]) },
    'rotated-twice': { why: 'A at card 0, B at card 1, C at card 2.', cards: cardChain([recoveryA.fp, recoveryB.fp, recoveryC.fp]) },
    'turned-on-later': { why: 'No operator recovery at card 0; card 1 names key A.', cards: cardChain(['none', recoveryA.fp, recoveryA.fp]) },
    'off-and-on-again': { why: 'A at card 0, none at card 1, B at card 2.', cards: cardChain([recoveryA.fp, 'none', recoveryB.fp]) },
    jumped: { why: 'A at card 0, C at card 1: the card jumps over key B.', cards: cardChain([recoveryA.fp, recoveryC.fp]) },
  };
  const walk = [];
  const consent = (name, why, chainName, list, pin, uncovered) => {
    const cards = chains[chainName].cards;
    const got = firstConsentWalk({ cards: cards.map((c) => c.frame), rotations: list.map((n) => frames[n]) });
    const want = { warning: uncovered.length > 0, uncovered: uncovered.map((seq) => ({ seq, from: cards[seq - 1].values.recoveryFp, to: cards[seq].values.recoveryFp })) };
    if (JSON.stringify(got) !== JSON.stringify(want)) throw new Error(`recovery first consent "${name}": the design says ${JSON.stringify(want)}, the oracle says ${JSON.stringify(got)}`);
    walk.push({ name, why, cards: chainName, rotations: list, pin, expect: want });
  };
  const pinAt = (root, chainName, seq) => ({ root, seq, cardHash: chains[chainName].cards[seq].hash });
  consent('no-change', 'The key never changed: nothing to cover, no warning.', 'never-changed', [], pinAt('baked', 'never-changed', 0), []);
  consent('change-covered', 'One change, A to B, and the rotation the outgoing seed signed is served with the chain.', 'rotated-once', ['A-to-B'], pinAt('baked', 'rotated-once', 0), []);
  consent('change-not-covered', 'A chain with a recoveryFp change that no rotation covers: the unsigned-change warning, with "Only me" preselected.', 'rotated-once', [], pinAt('kit', 'rotated-once', 0), [2]);
  consent('link-offer-pin-newer-than-the-change', 'FC-2: this device\'s pin came from a link offer whose cardHash is card 3, AFTER the change at card 2. The walk still starts at card 0, so the uncovered change is found.', 'rotated-once', [], pinAt('link_offer', 'rotated-once', 3), [2]);
  consent('trust-gate-pin-newer-than-the-change', 'The same for a Trust Gate pin made at card 3.', 'rotated-once', [], pinAt('trust_gate', 'rotated-once', 3), [2]);
  consent('setup-pin', 'The same chain on the operator\'s own setup pin.', 'rotated-once', [], pinAt('setup', 'rotated-once', 0), [2]);
  consent('rotation-signed-by-the-incoming-seed', 'A "rotation" for the change exists, but the incoming key signed it: it does not cover the change.', 'rotated-once', ['A-to-B-signed-by-B'], pinAt('baked', 'rotated-once', 0), [2]);
  consent('rotation-for-another-instance', 'The rotation was made for another instance.', 'rotated-once', ['A-to-B-for-another-instance'], pinAt('baked', 'rotated-once', 0), [2]);
  consent('two-changes-both-covered', 'Two changes and both rotations (served in any order).', 'rotated-twice', ['B-to-C', 'A-to-B'], pinAt('enrol', 'rotated-twice', 2), []);
  consent('two-changes-second-not-covered', 'Two changes; only the first has a rotation.', 'rotated-twice', ['A-to-B'], pinAt('baked', 'rotated-twice', 0), [2]);
  consent('two-changes-shortcut-rotation', 'A rotation straight from A to C does not cover the two steps the chain took.', 'rotated-twice', ['A-to-C'], pinAt('baked', 'rotated-twice', 0), [1, 2]);
  consent('turned-on-after-card-0', 'Operator recovery was turned on after card 0 (none to A). recoveryFp changed and no rotation statement can cover a change from none, so the warning shows: only a key named by card 0 needs none.', 'turned-on-later', [], pinAt('baked', 'turned-on-later', 0), [1]);
  consent('off-and-on-again', 'A, then none, then B: two changes, neither of which a rotation can cover. Turning operator recovery off and on is not a way around the outgoing seed\'s signature.', 'off-and-on-again', ['A-to-B'], pinAt('baked', 'off-and-on-again', 0), [1, 2]);
  consent('jump-covered-by-a-chain', 'The card jumps from A to C while the served rotations go A to B and B to C: a chain of rotations that leads from the old value to the new one covers the change. No warning.', 'jumped', ['A-to-B', 'B-to-C'], pinAt('baked', 'jumped', 0), []);
  consent('jump-covered-by-a-chain-served-newest-first', 'The same two rotations served in the other order: the order they are served in does not matter.', 'jumped', ['B-to-C', 'A-to-B'], pinAt('kit', 'jumped', 0), []);
  consent('jump-covered-by-one-rotation', 'The same jump with one rotation straight from A to C.', 'jumped', ['A-to-C'], pinAt('baked', 'jumped', 0), []);
  consent('jump-with-the-first-rotation-only', 'Only A to B is served: nothing leads on to C, so the jump is not covered. The warning shows.', 'jumped', ['A-to-B'], pinAt('baked', 'jumped', 0), [1]);
  consent('jump-with-the-second-rotation-only', 'Only B to C is served: nothing leads from A.', 'jumped', ['B-to-C'], pinAt('baked', 'jumped', 0), [1]);
  consent('jump-chain-with-a-link-signed-by-the-wrong-seed', 'A to B is valid, but the B to C link is signed by A, not by the key it rotates away from: the chain does not reach C.', 'jumped', ['A-to-B', 'B-to-C-signed-by-A'], pinAt('baked', 'jumped', 0), [1]);

  // ---- the request code ----
  const rSec = fixed('recovery/request-secret');
  const rPub = x25519Base(rSec);
  const otherRPub = x25519Base(fixed('recovery/other-request-secret'));
  const codeRows = [rPub, otherRPub].map((key, i) => {
    const c = requestCode(key);
    return { why: i === 0 ? 'the request code the person reads to the operator: 96 bits of the request key\'s hash, six groups of four' : 'another request key gives another code, which is how recovery-cli assist catches a swapped rPub', rPubB64: b64u(key), inputUtf8: c.input, code: c.code, grouped: c.grouped };
  });

  // ---- the assisted-recovery payload ----
  const requestId = b64u(fixed('recovery/request-id', 16));
  const uvk = fixed('recovery/uvk');
  const request = { instanceId: ids.instance, userId: alice.userId, requestId, requestKey: b64u(rPub) };
  const payloadValues = { ...request, uvk: b64u(uvk), issuedAt: at(200) };
  const payload = signed('assisted-recovery', recoveryA, payloadValues);
  const seedEnvelope = (key, seed) => envelopeSeal(key, fixed('recovery/seed-nonce', 24), identitySeedAd(alice.userId), seed);
  const encryptedSeed = seedEnvelope(uvk, alice.seed);
  const sealTo = (label, frame, to = rPub) => boxSeal(to, frame, fixed('recovery/ephemeral/' + label));
  const assisted = [];
  const assist = (name, verdict, why, made, context = {}) => {
    const frame = made.frame ?? made;
    const sealed = context.sealed ?? sealTo(name, frame);
    const input = {
      sealed, rPub, rSec, recoveryPub: (context.cardKey ?? recoveryA).publicKey, request: context.request ?? request,
      encryptedIdentitySeed: context.encryptedSeed ?? encryptedSeed, identityPub: context.identityPub ?? alice.identityPub,
    };
    const got = openAssistedRecovery(input);
    if (got.verdict !== verdict) throw new Error(`recovery assisted "${name}": the design says ${verdict}, the oracle says ${got.verdict}`);
    const row = { name, why };
    if (made.signer) row.signer = made.signer.name;
    if (made.signerNote) row.signer = made.signerNote;
    if (made.statement !== undefined) row.statementUtf8 = made.statement;
    Object.assign(row, {
      sealedB64: b64u(sealed), cardRecoveryFp: (context.cardKey ?? recoveryA).fp, recoveryPubB64: b64u(input.recoveryPub), request: input.request,
      encryptedIdentitySeedB64: b64u(input.encryptedIdentitySeed), identityPubB64: b64u(input.identityPub),
    });
    row.expect = verdict === 'ok' ? { verdict, uvkB64: got.uvk } : { verdict };
    assisted.push(row);
  };
  const withPayload = (signer, overrides) => signed('assisted-recovery', signer, { ...payloadValues, ...overrides });
  assist('valid', 'ok', 'The operator\'s answer: a 0x09 statement signed by the recovery-key signing key, sealed to the request key. The signer maps to the key the pinned card\'s recoveryFp names, the request fields match, and the identity seed opens under the delivered UVK to the served identityPub.', payload);
  assist('sealed-to-another-key', 'unopenable', 'The seal was made to another request key.', payload, { sealed: sealTo('other-key', payload.frame, otherRPub) });
  assist('seal-truncated', 'unopenable', 'The first 40 bytes of a seal.', payload, { sealed: sealTo('truncated', payload.frame).slice(0, 40) });
  assist('rotation-frame-inside', 'bad_frame', 'The seal opens to a 0x08 frame.', rotAB);
  assist('bare-json-inside', 'unknown_format', 'The seal opens to a bare JSON statement, not a frame.', { frame: utf8(payload.statement), statement: payload.statement });
  assist('not-canonical', 'non_canonical', 'A signed payload with a space after a colon.', signedRaw(ASSIST, recoveryA, payload.statement.replace('"uvk":', '"uvk": ')));
  assist('request-id-of-32-bytes', 'non_canonical', 'FI-B13: requestId is b64_16; a 32-byte value fails its type.', signedRaw(ASSIST, recoveryA, rawStatement(withToken(tokens('assisted-recovery', payloadValues), 'requestId', '"' + b64u(uvk) + '"'))));
  assist('signed-by-an-identity-key', 'signer_not_pinned_key', 'Signed by an identity key instead of the recovery key: a server that holds no recovery key (here with the operator account\'s key) cannot make a payload the app accepts.', withPayload(operator, {}));
  assist('signed-by-the-account-itself', 'signer_not_pinned_key', 'Signed by the account\'s own identity key.', withPayload(alice, {}));
  assist('signed-by-another-recovery-seed', 'signer_not_pinned_key', 'Signed by a recovery seed that is not the one the pinned card names.', withPayload(recoveryB, {}));
  assist('card-names-another-key', 'signer_not_pinned_key', 'The payload is the valid one, but this device\'s pinned card names recovery key B.', payload, { cardKey: recoveryB });
  assist('signature-flipped', 'bad_signature', 'The payload with one signature bit flipped.', { frame: flip(payload.frame), statement: payload.statement, signerNote: 'recoveryA, then one signature bit flipped' });
  assist('request-key-differs', 'request_mismatch', 'A requestKey that differs from the request: the recovery key really signed it, for another device\'s request key.', withPayload(recoveryA, { requestKey: b64u(otherRPub) }));
  assist('request-id-differs', 'request_mismatch', 'Another requestId.', withPayload(recoveryA, { requestId: b64u(fixed('recovery/other-request-id', 16)) }));
  assist('instance-differs', 'request_mismatch', 'Another instanceId.', withPayload(recoveryA, { instanceId: ids.otherInstance }));
  assist('user-differs', 'request_mismatch', 'Another userId than the request is for.', withPayload(recoveryA, { userId: bob.userId }), { request: { ...request, userId: alice.userId } });
  assist('served-identity-key-is-another', 'identity_mismatch', 'The seed opens under the delivered UVK, but the identityPub the server serves is another key.', payload, { identityPub: bob.identityPub });
  assist('seed-is-another-identity', 'identity_mismatch', 'The served seed envelope opens under the delivered UVK to ANOTHER seed than the one behind the served identityPub.', payload, { encryptedSeed: seedEnvelope(uvk, bob.seed) });
  assist('seed-does-not-open', 'identity_mismatch', 'The served identity-seed envelope does not open under the delivered UVK (it was sealed under another key): identity_mismatch too.', payload, { encryptedSeed: seedEnvelope(fixed('recovery/other-uvk'), alice.seed) });
  assist('seed-sealed-for-another-account', 'identity_mismatch', 'The served envelope is sealed under the delivered UVK but for another account\'s userId: its AD does not match, so it does not open.',
    payload, { encryptedSeed: envelopeSeal(uvk, fixed('recovery/seed-nonce', 24), identitySeedAd(bob.userId), alice.seed) });
  const freshInstall = { ...request, userId: null };
  assist('fresh-install', 'ok', 'A fresh install holds no userId (request.userId is null): it skips the userId comparison. The seed\'s AD binds the payload\'s userId, and the seed opens to the served identityPub.', payload, { request: freshInstall });
  assist('user-differs-on-a-fresh-install', 'identity_mismatch', 'The payload of the row user-differs, opened by a fresh install. There is no userId to compare, so it is not request_mismatch; the served seed, sealed for the account this request was made for, does not open under the AD of the payload\'s userId: identity_mismatch.',
    withPayload(recoveryA, { userId: bob.userId }), { request: freshInstall });
  assist('order-signer-before-signature', 'signer_not_pinned_key', 'Signed by an identity key, with the signature broken as well.', { frame: flip(withPayload(operator, {}).frame), signerNote: 'operator, then one signature bit flipped' });
  assist('order-signature-before-request', 'bad_signature', 'Another requestKey under a broken signature.', { frame: flip(withPayload(recoveryA, { requestKey: b64u(otherRPub) }).frame), signerNote: 'recoveryA, then one signature bit flipped' });
  assist('order-request-before-identity', 'request_mismatch', 'Another requestId, and the served identityPub is another key.', withPayload(recoveryA, { requestId: b64u(fixed('recovery/other-request-id', 16)) }), { identityPub: bob.identityPub });

  // ---- the veto ----
  const vetoValues = { requestId, userId: alice.userId, issuedAt: at(150) };
  const goodVeto = signed('recovery-veto', alice, vetoValues);
  const veto = [];
  const vet = (name, verdict, why, made, context = {}) => {
    const frame = made.frame ?? made;
    const input = { frame, storedIdentityPub: context.stored ?? alice.identityPub, sessionUserId: context.session ?? alice.userId, requestId: context.requestId ?? requestId };
    const got = verifyVeto(input);
    if (got.verdict !== verdict) throw new Error(`recovery veto "${name}": the design says ${verdict}, the oracle says ${got.verdict}`);
    const row = { name, why };
    if (made.signer) row.signer = made.signer.name;
    if (made.signerNote) row.signer = made.signerNote;
    if (made.statement !== undefined) row.statementUtf8 = made.statement;
    Object.assign(row, { frameB64: b64u(frame), storedIdentityPubB64: b64u(input.storedIdentityPub), sessionUserId: input.sessionUserId, requestId: input.requestId, expect: { verdict } });
    veto.push(row);
  };
  vet('valid', 'ok', 'A signed-in device of the account cancels the request: a 0x0A statement signed by the account key, checked by the server against the identity key it stores.', goodVeto);
  vet('signed-by-another-account', 'signer_not_pinned_key', 'The statement names alice, but bob\'s key signed it.', signed('recovery-veto', bob, vetoValues));
  vet('signature-flipped', 'bad_signature', 'The veto with one signature bit flipped.', { frame: flip(goodVeto.frame), statement: goodVeto.statement, signerNote: 'alice, then one signature bit flipped' });
  vet('names-another-user', 'user_mismatch', 'alice signed a veto whose userId is another account\'s; the session is hers.', signed('recovery-veto', alice, { ...vetoValues, userId: bob.userId }));
  vet('names-another-request', 'request_mismatch', 'A veto alice really signed, for another request than the one in the path.', signed('recovery-veto', alice, { ...vetoValues, requestId: b64u(fixed('recovery/other-request-id', 16)) }));
  vet('rotation-frame', 'bad_frame', 'A 0x08 frame where a veto is expected.', rotAB);
  vet('not-canonical', 'non_canonical', 'A signed veto with a space after a colon.', signedRaw(VETO, alice, goodVeto.statement.replace('"userId":', '"userId": ')));
  vet('version-3', 'bad_statement', 'A signed, canonical veto with "v":3.', signedRaw(VETO, alice, rawStatement(withToken(tokens('recovery-veto', vetoValues), 'v', '3'))));
  vet('order-signer-before-signature', 'signer_not_pinned_key', 'Signed by bob, with the signature broken as well.', { frame: flip(signed('recovery-veto', bob, vetoValues).frame), signerNote: 'bob, then one signature bit flipped' });
  vet('order-signature-before-user', 'bad_signature', 'Another userId under a broken signature.', { frame: flip(signed('recovery-veto', alice, { ...vetoValues, userId: bob.userId }).frame), signerNote: 'alice, then one signature bit flipped' });
  vet('order-user-before-request', 'user_mismatch', 'Another userId and another requestId.', signed('recovery-veto', alice, { ...vetoValues, userId: bob.userId, requestId: b64u(fixed('recovery/other-request-id', 16)) }));

  return {
    _about: [
      'Operator recovery of design 2026-11-15-onboarding-trust §4.5 and §9.3, with the verdict strings and order of §2.4. It applies to private instances; under variant R the public instance has none of it.',
      'Hand-authored from the independent oracle in tools/vector-gen/oracle (Node WebCrypto and @noble; no andvari code). Regenerate with `npm run generate` there; `npm run check` fails on any difference. Seals use fixed ephemeral keys.',
      'keys: three instance recovery keys. One seed gives the X25519 recovery key (crypto_box_seed_keypair) and the Ed25519 recovery-key signing key (crypto_sign_seed_keypair); fingerprint = hexLower(SHA-256(the X25519 public key)), the value a card carries as recoveryFp.',
      'rotation: a 0x08 statement checked by a verifier whose current fingerprint is `currentFp` (its consent, the card\'s, or the fingerprint of the account\'s current escrow), on instance `instanceId`. Order: the parse verdicts; fp_mismatch (fromFp is not currentFp); signer_not_pinned_key (the signer does not map to the recovery key currentFp names, given as recoveryPubB64; equivalently SHA-256 of the signer\'s X25519 image is not currentFp); bad_signature; instance_mismatch. On ok the verifier\'s fingerprint becomes expect.toFp.',
      'escrowRotations: the `rotations` array of PUT /escrow/self (FI-R1), by the names in `rotationFrames`: the chain from the fingerprint of the account\'s current escrow to `fingerprint`, oldest first. The server stores the new escrow only when every link verifies in order (each against the fingerprint the chain has reached) and the last toFp equals `fingerprint`; otherwise 409 escrow_not_due. expect.failedAt and expect.linkVerdict name the link that fails, where one does.',
      'firstConsent (FS-R2, FC-2): when a person turns operator recovery on, the client walks the served card chain (`cardChains[cards]`) FROM CARD 0, whatever its pin root, with the served rotations. Every change of recoveryFp between two cards must be matched by a valid rotation from the old value to the new one, or by a chain of valid rotations that leads from the old value to the new one, whatever order they are served in (a card may jump from A to C while the rotations go A to B and B to C). expect.uncovered lists the changes that are not; expect.warning says whether the unsigned-change warning shows (with "Only me" preselected). `pin` is this device\'s pin and is there to show that it does not matter. A change to or from none can have no rotation.',
      'requestCode: hexLower(SHA-256("andvari/v2|recovery-request|code|" + b64url(rPub)))[0..24], shown as six groups of four.',
      'assisted: the requesting device opens a fulfilled request. Inputs: `sealedB64` (crypto_box_seal to the request key; the request key pair is `requestKey`), the recovery public key that the pinned card\'s recoveryFp names, the request {instanceId, userId, requestId, requestKey}, and the served encryptedIdentitySeed (Envelope(UVK, seed, "andvari/v1|idkey|{userId}")) and identityPub. Order: unopenable; the parse verdicts; signer_not_pinned_key; bad_signature; request_mismatch; identity_mismatch (the seed does not open under the delivered UVK, or its X25519 key is not the served identityPub). A device that holds no userId, a fresh install, has request.userId null and skips the userId comparison: the seed\'s AD binds the payload\'s userId instead. On ok, expect.uvkB64.',
      'veto: the 0x0A statement as the server verifies it, against the account\'s stored identity key, the session\'s userId and the request id of the path. Order: the parse verdicts; signer_not_pinned_key; bad_signature; user_mismatch; request_mismatch. On the wire (spec 03 §18.3) signer_not_pinned_key, user_mismatch and request_mismatch all answer 400 bad_signer, and bad_signature is its own 400 bad_signature; the parse answers 400 bad_frame, 400 non_canonical or 400 bad_statement.',
      'Not graded: PUT /escrow/self with an empty rotations array.',
      'The extension handles none of this: it never seals an escrow and cannot verify a 0x08 statement (§12.2).',
    ],
    instanceId: ids.instance,
    keys: { recoveryA: keyOf(recoveryA), recoveryB: keyOf(recoveryB), recoveryC: keyOf(recoveryC), operator: describe(operator), alice: describe(alice), bob: describe(bob) },
    requestKey: { rSecB64: b64u(rSec), rPubB64: b64u(rPub) },
    rotation: rotationRows,
    rotationFrames: Object.fromEntries(Object.entries(frames).map(([k, f]) => [k, b64u(f)])),
    escrowRotations: escrow,
    cardChains: Object.fromEntries(Object.entries(chains).map(([k, c]) => [k, { why: c.why, frames: c.cards.map((card) => b64u(card.frame)), recoveryFps: c.cards.map((card) => card.values.recoveryFp) }])),
    firstConsent: walk,
    requestCode: codeRows,
    assisted,
    veto,
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
  for (const row of doc.rotation) {
    const got = verifyRotation({ frame: mustUnb64u(row.frameB64), currentFp: row.currentFp, instanceId: row.instanceId });
    expect(same(got.verdict === 'ok' ? { verdict: 'ok', toFp: got.toFp } : { verdict: got.verdict }, row.expect), `rotation ${row.name}: oracle says ${got.verdict}`);
  }
  const frames = Object.fromEntries(Object.entries(doc.rotationFrames).map(([k, v]) => [k, mustUnb64u(v)]));
  for (const row of doc.escrowRotations) {
    const got = checkEscrowRotations({ currentEscrowFp: row.currentEscrowFp, rotations: row.rotations.map((n) => frames[n]), fingerprint: row.fingerprint, instanceId: row.instanceId });
    expect(same(got, row.expect), `escrowRotations ${row.name}: oracle says ${JSON.stringify(got)}`);
  }
  for (const row of doc.firstConsent) {
    const got = firstConsentWalk({ cards: doc.cardChains[row.cards].frames.map(mustUnb64u), rotations: row.rotations.map((n) => frames[n]) });
    expect(same(got, row.expect), `firstConsent ${row.name}: oracle says ${JSON.stringify(got)}`);
  }
  for (const row of doc.requestCode) {
    const c = requestCode(mustUnb64u(row.rPubB64));
    expect(c.input === row.inputUtf8 && c.code === row.code && c.grouped === row.grouped && row.code.length === 24, 'requestCode: ' + row.why.slice(0, 40));
  }
  const rPub = mustUnb64u(doc.requestKey.rPubB64);
  const rSec = mustUnb64u(doc.requestKey.rSecB64);
  for (const row of doc.assisted) {
    const got = openAssistedRecovery({
      sealed: mustUnb64u(row.sealedB64), rPub, rSec, recoveryPub: mustUnb64u(row.recoveryPubB64), request: row.request,
      encryptedIdentitySeed: mustUnb64u(row.encryptedIdentitySeedB64), identityPub: mustUnb64u(row.identityPubB64),
    });
    expect(same(got.verdict === 'ok' ? { verdict: 'ok', uvkB64: got.uvk } : { verdict: got.verdict }, row.expect), `assisted ${row.name}: oracle says ${got.verdict}`);
  }
  for (const row of doc.veto) {
    const got = verifyVeto({ frame: mustUnb64u(row.frameB64), storedIdentityPub: mustUnb64u(row.storedIdentityPubB64), sessionUserId: row.sessionUserId, requestId: row.requestId });
    expect(got.verdict === row.expect.verdict, `veto ${row.name}: oracle says ${got.verdict}`);
  }
  return { rows, failures };
}
