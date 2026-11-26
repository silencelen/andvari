// next/accountstate.json (rewritten): the sealed account-state document, its decode, the merge of
// every record (design §5.4, spec 02 §9) and the acceptance answer (§3.6 (d), VR-16).

import { b64u, mustUnb64u, utf8, hex, utf8DecodeStrict } from '../bytes.mjs';
import { envelopeSeal, envelopeOpen } from '../prims.mjs';
import { decodeAccountState, mergeAccountState, acceptance, extensionAccepts, accountStateAd, sealedChars, LIMITS } from '../accountstate.mjs';
import { nameOf } from '../build.mjs';
import { alice, bob, carol, dave, eve, ids, fixed, T0, describe } from '../cast.mjs';

export const file = 'next/accountstate.json';

const cp = (...codes) => String.fromCodePoint(...codes);
const UVK = fixed('accountstate/uvk');
const USER = alice.userId;
const PHONE = 'd0000000-0000-4000-8000-000000000001';
const LAPTOP = 'd0000000-0000-4000-8000-000000000002';
const h = (label) => hex(fixed('accountstate/hash/' + label));
const GEN_A = h('genesis-a');
const GEN_B = h('genesis-b');
const t = (n) => T0 + n * 1000;

const doc = (seq, parts = {}) => {
  const d = { v: 2, userId: USER, seq, contacts: {}, contactTombstones: {}, vaults: {}, accepted: {}, ...parts };
  return d;
};
const contact = (who, overrides = {}) => ({
  userId: who.userId, identityPub: who.key, label: nameOf(who.name[0].toUpperCase() + who.name.slice(1)), method: 'link',
  verifiedAt: t(100), compared: false, madeOn: PHONE, ...overrides,
});
const contacts = (...list) => Object.fromEntries(list.map((c) => [c.userId, c]));
const vaultRec = (seq, hashLabel, genesisHash = GEN_A) => ({ genesisHash, seq, hash: h(hashLabel) });
const accepted = (addSeq, decision, at = t(200), owner = bob.userId) => ({ owner, addSeq, at, decision });
const recovery = (posture, at, fp = posture === 'private' ? 'none' : h('recovery-fp')) => ({ posture, fp, at });
const compact = (d) => JSON.stringify(d);

function sampleDoc() {
  return doc(7, {
    contacts: contacts(contact(bob, { compared: true }), contact(carol, { verifiedAt: t(150), madeOn: LAPTOP })),
    contactTombstones: { [dave.userId]: t(120) },
    vaults: { [ids.vault]: vaultRec(4, 'vault-head-4'), [ids.otherVault]: vaultRec(0, 'other-genesis', h('other-genesis')) },
    accepted: { [ids.vault]: accepted(1, 'accept'), [ids.otherVault]: { owner: USER, addSeq: 0, at: t(50), decision: 'accept' } },
    recovery: recovery('private', t(10)),
  });
}

function decodeRows(sample) {
  const rows = [];
  const add = (name, why, text, expected) => {
    const got = decodeAccountState(text, USER);
    const want = expected === 'refused' ? { refused: true } : { refused: false, dropped: expected.dropped, doc: expected.doc };
    if (JSON.stringify(got) !== JSON.stringify(want)) throw new Error(`accountstate decode "${name}": the design says ${JSON.stringify(want).slice(0, 200)}, the oracle says ${JSON.stringify(got).slice(0, 200)}`);
    rows.push({ name, why, plaintext: text, expect: want });
  };
  const withPart = (key, value) => ({ ...sample, [key]: value });

  add('sample', 'The sample document: one object, every record valid.', compact(sample), { dropped: 0, doc: sample });
  const reversed = { ...sample };
  for (const k of ['contacts', 'contactTombstones', 'vaults', 'accepted']) reversed[k] = Object.fromEntries(Object.keys(sample[k]).sort().reverse().map((key) => [key, sample[k][key]]));
  add('map-keys-in-another-order', 'Writers emit each map\'s keys in ascending byte order; readers accept any order.', compact(reversed), { dropped: 0, doc: sample });
  const { recovery: _r, ...noRecovery } = sample;
  add('no-recovery-record', 'recovery is absent until a choice has been recorded.', compact(noRecovery), { dropped: 0, doc: noRecovery });
  const future = { ...sample, futureRecords: { hello: [1, 2, 3] } };
  add('unknown-key-is-kept', 'An unknown key in the document is preserved, never dropped, so a newer build\'s records survive.', compact(future), { dropped: 0, doc: future });

  add('version-1', 'A document with another v is refused whole.', compact({ ...sample, v: 1 }), 'refused');
  add('version-3', 'A document with another v is refused whole.', compact({ ...sample, v: 3 }), 'refused');
  add('version-as-a-string', 'v is the number 2.', compact({ ...sample, v: '2' }), 'refused');
  add('another-accounts-document', 'A document whose userId is not the account\'s is refused whole (another account\'s state under this account\'s key).', compact({ ...sample, userId: bob.userId }), 'refused');
  add('not-json', 'Not JSON.', compact(sample).slice(1), 'refused');
  add('a-json-array', 'A JSON array, not an object.', '[' + compact(sample) + ']', 'refused');

  const dropBob = { ...sample, contacts: contacts(sample.contacts[carol.userId]) };
  add('contact-method-setup', 'A contact whose method is "setup": method has the single value "link", any other is refused. The record is dropped and counted; the rest of the document is used.',
    compact(withPart('contacts', contacts({ ...sample.contacts[bob.userId], method: 'setup' }, sample.contacts[carol.userId]))), { dropped: 1, doc: dropBob });
  add('contact-method-typed', 'A pre-cut-over pin method.', compact(withPart('contacts', contacts({ ...sample.contacts[bob.userId], method: 'typed' }, sample.contacts[carol.userId]))), { dropped: 1, doc: dropBob });
  add('contact-user-id-is-not-its-key', 'A contact\'s userId must equal its map key.',
    compact(withPart('contacts', { [bob.userId]: { ...sample.contacts[bob.userId], userId: eve.userId }, [carol.userId]: sample.contacts[carol.userId] })), { dropped: 1, doc: dropBob });
  add('contact-key-of-31-bytes', 'A malformed identity key.', compact(withPart('contacts', contacts({ ...sample.contacts[bob.userId], identityPub: b64u(bob.identityPub.slice(0, 31)) }, sample.contacts[carol.userId]))), { dropped: 1, doc: dropBob });
  add('contact-map-key-is-not-a-uuid', 'A malformed map key.', compact(withPart('contacts', { bob: { ...sample.contacts[bob.userId], userId: 'bob' }, [carol.userId]: sample.contacts[carol.userId] })), { dropped: 1, doc: dropBob });
  add('contact-label-is-not-a-name', 'A label that fails the name type (it holds U+202E RIGHT-TO-LEFT OVERRIDE).', compact(withPart('contacts', contacts({ ...sample.contacts[bob.userId], label: nameOf('Bob' + cp(0x202e)) }, sample.contacts[carol.userId]))), { dropped: 1, doc: dropBob });
  const { compared: _c, ...noCompared } = sample.contacts[bob.userId];
  add('contact-without-compared', 'A contact that lacks one of §6.9\'s fields.', compact(withPart('contacts', { [bob.userId]: noCompared, [carol.userId]: sample.contacts[carol.userId] })), { dropped: 1, doc: dropBob });
  add('accepted-unknown-decision', 'An accepted record with an unknown decision.',
    compact(withPart('accepted', { ...sample.accepted, [ids.vault]: { ...sample.accepted[ids.vault], decision: 'maybe' } })), { dropped: 1, doc: withPart('accepted', { [ids.otherVault]: sample.accepted[ids.otherVault] }) });
  add('vault-record-uppercase-hash', 'A vault record whose genesisHash is not lowercase hex.',
    compact(withPart('vaults', { ...sample.vaults, [ids.vault]: { ...sample.vaults[ids.vault], genesisHash: GEN_A.toUpperCase() } })), { dropped: 1, doc: withPart('vaults', { [ids.otherVault]: sample.vaults[ids.otherVault] }) });
  add('tombstone-is-a-string', 'A tombstone whose value is not a number of milliseconds.', compact(withPart('contactTombstones', { [dave.userId]: String(t(120)) })), { dropped: 1, doc: withPart('contactTombstones', {}) });
  add('recovery-unknown-posture', 'A recovery record with an unknown posture is dropped like any other record.', compact(withPart('recovery', { posture: 'public', fp: 'none', at: t(10) })), { dropped: 1, doc: noRecovery });
  add('two-bad-records', 'Two bad records are both dropped and counted.',
    compact({ ...sample, contacts: contacts({ ...sample.contacts[bob.userId], method: 'setup' }, sample.contacts[carol.userId]), accepted: { ...sample.accepted, [ids.vault]: { ...sample.accepted[ids.vault], decision: 'maybe' } } }),
    { dropped: 2, doc: { ...dropBob, accepted: { [ids.otherVault]: sample.accepted[ids.otherVault] } } });

  // ---- the edges ----
  const noted = withPart('contacts', contacts({ ...sample.contacts[bob.userId], nickname: 'Bobby' }, sample.contacts[carol.userId]));
  add('contact-with-an-unknown-field', 'A record that carries a field this build does not know is kept, and the field is preserved as written, as an unknown top-level key is.', compact(noted), { dropped: 0, doc: noted });
  const notedVault = withPart('vaults', { ...sample.vaults, [ids.vault]: { ...sample.vaults[ids.vault], members: 3 } });
  add('vault-record-with-an-unknown-field', 'The same for a vault record.', compact(notedVault), { dropped: 0, doc: notedVault });
  const notedAccepted = withPart('accepted', { ...sample.accepted, [ids.vault]: { ...sample.accepted[ids.vault], device: PHONE } });
  add('accepted-record-with-an-unknown-field', 'The same for an accepted record.', compact(notedAccepted), { dropped: 0, doc: notedAccepted });
  const notedRecovery = withPart('recovery', { ...sample.recovery, device: PHONE });
  add('recovery-record-with-an-unknown-field', 'The same for the recovery record.', compact(notedRecovery), { dropped: 0, doc: notedRecovery });
  const { compared: _c2, ...lacking } = sample.contacts[bob.userId];
  add('contact-with-an-unknown-field-and-a-missing-one', 'An unknown field does not make up for a missing one: the record still fails its shape and is dropped.',
    compact(withPart('contacts', { [bob.userId]: { ...lacking, nickname: 'Bobby' }, [carol.userId]: sample.contacts[carol.userId] })), { dropped: 1, doc: dropBob });
  const { contacts: _noContacts, ...withoutContacts } = sample;
  add('no-contacts-map', 'A document that lacks one of the four maps is read as having that map empty.', compact(withoutContacts), { dropped: 0, doc: { ...sample, contacts: {} } });
  add('no-maps-at-all', 'A document with v, userId and seq only: all four maps are read as empty.', compact({ v: 2, userId: USER, seq: 7 }), { dropped: 0, doc: doc(7) });
  add('seq-is-a-string', 'A document whose seq is not an int is refused whole.', compact({ ...sample, seq: '7' }), 'refused');
  const { seq: _noSeq, ...withoutSeq } = sample;
  add('no-seq', 'A document with no seq.', compact(withoutSeq), 'refused');
  add('seq-is-negative', 'seq is -1.', compact({ ...sample, seq: -1 }), 'refused');
  add('seq-is-a-fraction', 'seq is 7.5.', compact({ ...sample, seq: 7.5 }), 'refused');
  add('seq-is-2-to-the-53', 'seq is 2^53, one more than the largest int.', compact(sample).replace('"seq":7,', '"seq":9007199254740992,'), 'refused');
  return rows;
}

function mergeRows() {
  const rows = [];
  const names = new Set();
  /**
   * `expected` holds the merged document and the flags the design names. `servedCas` is the server's
   * compare-and-set token beside the blob: it is never the document's counter (FI-B14).
   */
  const add = (name, records, why, { local, served, highWater, servedCas, limits }, expected) => {
    const result = mergeAccountState(local, served, highWater, limits ? { ...LIMITS, ...limits } : LIMITS);
    const want = { rollback: expected.rollback ?? false, doc: expected.doc, keyChange: expected.keyChange ?? [], genesisAnomalies: expected.genesisAnomalies ?? [], forks: expected.forks ?? [] };
    if (expected.notWritten) want.notWritten = expected.notWritten;
    const got = { rollback: result.rollback, doc: result.doc, keyChange: result.keyChange, genesisAnomalies: result.genesisAnomalies, forks: result.forks };
    if (result.notWritten) got.notWritten = result.notWritten;
    if (JSON.stringify(got) !== JSON.stringify(want)) throw new Error(`accountstate merge "${name}": the design says\n${JSON.stringify(want)}\nthe oracle says\n${JSON.stringify(got)}`);
    if (names.has(name)) throw new Error('accountstate: duplicate merge row ' + name);
    names.add(name);
    const row = { name, records, why, local, served, servedCasSeq: servedCas ?? (served ? served.seq + 40 : null), highWater };
    if (limits) row.limits = limits;
    row.expect = want;
    rows.push(row);
  };
  const B = contact(bob);
  const C = contact(carol);

  // ---- contacts ----
  add('contact-union', ['contacts'], 'Each copy holds a contact the other lacks: both are kept.',
    { local: doc(3, { contacts: contacts(B) }), served: doc(4, { contacts: contacts(C) }), highWater: 3 },
    { doc: doc(4, { contacts: contacts(B, C) }) });
  const newerB = contact(bob, { verifiedAt: t(200), label: nameOf('Robert'), madeOn: LAPTOP });
  add('newest-verified-at-wins', ['contacts'], 'The same person and key in both copies: the record with the newest verifiedAt wins, whole (label and madeOn included).',
    { local: doc(3, { contacts: contacts(B) }), served: doc(4, { contacts: contacts(newerB) }), highWater: 3 },
    { doc: doc(4, { contacts: contacts(newerB) }) });
  add('older-served-record-loses', ['contacts'], 'The served record is the older one: the local record stays.',
    { local: doc(3, { contacts: contacts(newerB) }), served: doc(4, { contacts: contacts(B) }), highWater: 3 },
    { doc: doc(4, { contacts: contacts(newerB) }) });
  add('compared-is-or', ['contacts'], 'compared merges as OR between records with the same key: the newer record wins, and the match made on the other device stays matched.',
    { local: doc(3, { contacts: contacts(contact(bob, { compared: true })) }), served: doc(4, { contacts: contacts(newerB) }), highWater: 3 },
    { doc: doc(4, { contacts: contacts({ ...newerB, compared: true }) }) });
  add('compared-is-or-from-the-older-served-record', ['contacts'], 'The same from the other side: the local record is newer, the served one carries the match.',
    { local: doc(3, { contacts: contacts(newerB) }), served: doc(4, { contacts: contacts(contact(bob, { compared: true })) }), highWater: 3 },
    { doc: doc(4, { contacts: contacts({ ...newerB, compared: true }) }) });
  const otherKeyB = contact(bob, { identityPub: eve.key, verifiedAt: t(300), compared: true, madeOn: LAPTOP });
  add('key-change-is-not-merged', ['contacts'], 'The served copy holds ANOTHER key for bob, newer and marked compared. It is never merged silently: the record with the key this device already uses stays as it is (compared stays false, there is no OR across keys), and the other goes to the key-change prompt.',
    { local: doc(3, { contacts: contacts(B) }), served: doc(4, { contacts: contacts(otherKeyB) }), highWater: 3 },
    { doc: doc(4, { contacts: contacts(B) }), keyChange: [{ userId: bob.userId, identityPub: eve.key }] });
  add('tombstone-removes-a-pin', ['contacts'], 'A tombstone not older than a pin removes it: bob was removed on another device at the very millisecond of the pin.',
    { local: doc(3, { contacts: contacts(B, C) }), served: doc(4, { contacts: contacts(C), contactTombstones: { [bob.userId]: t(100) } }), highWater: 3 },
    { doc: doc(4, { contacts: contacts(C), contactTombstones: { [bob.userId]: t(100) } }) });
  add('tombstone-older-than-the-pin', ['contacts'], 'A tombstone one millisecond older than the pin does not remove it; the tombstone itself is kept.',
    { local: doc(3, { contacts: contacts(B) }), served: doc(4, { contactTombstones: { [bob.userId]: t(100) - 1 } }), highWater: 3 },
    { doc: doc(4, { contacts: contacts(B), contactTombstones: { [bob.userId]: t(100) - 1 } }) });
  add('newer-pin-outlives-a-tombstone', ['contacts'], 'bob was removed here, then connected again on another device: the newer pin stands beside the older tombstone (the newest human act wins).',
    { local: doc(3, { contactTombstones: { [bob.userId]: t(150) } }), served: doc(4, { contacts: contacts(newerB), contactTombstones: {} }), highWater: 3 },
    { doc: doc(4, { contacts: contacts(newerB), contactTombstones: { [bob.userId]: t(150) } }) });
  add('tombstones-take-the-later-time', ['contacts'], 'Tombstones for one person in both copies: the later time is kept.',
    { local: doc(3, { contactTombstones: { [bob.userId]: t(150) } }), served: doc(4, { contactTombstones: { [bob.userId]: t(250) } }), highWater: 3 },
    { doc: doc(4, { contactTombstones: { [bob.userId]: t(250) } }) });
  const labelLow = contact(bob, { label: nameOf('Bob') });
  const labelHigh = contact(bob, { label: nameOf('Rob'), madeOn: PHONE });
  add('tie-goes-to-the-larger-label', ['contacts'], 'The same key and the same verifiedAt: the larger label wins (Um9i, "Rob", over Qm9i, "Bob"). This tie-break exists only so that every device reaches the same document.',
    { local: doc(3, { contacts: contacts(labelLow) }), served: doc(4, { contacts: contacts(labelHigh) }), highWater: 3 },
    { doc: doc(4, { contacts: contacts(labelHigh) }) });
  // "C1" is QzE and "CA" is Q0E: as decoded text "CA" is the larger, as stored base64url "QzE" is.
  const storedLarger = contact(bob, { label: nameOf('C1') });
  const textLarger = contact(bob, { label: nameOf('CA') });
  if (!(storedLarger.label > textLarger.label) || !(utf8DecodeStrict(mustUnb64u(storedLarger.label)) < utf8DecodeStrict(mustUnb64u(textLarger.label)))) throw new Error('accountstate: the stored-text tie fixture');
  add('tie-compares-the-label-as-stored', ['contacts'], 'The label tie is on the field\'s text exactly as stored, its base64url string, byte by byte. "C1" is stored as QzE and "CA" as Q0E: the decoded text "CA" is the larger, but the stored QzE is, so "C1" wins.',
    { local: doc(3, { contacts: contacts(textLarger) }), served: doc(4, { contacts: contacts(storedLarger) }), highWater: 3 },
    { doc: doc(4, { contacts: contacts(storedLarger) }) });
  add('tie-compares-the-label-as-stored-local', ['contacts'], 'The same with the winning record on this device.',
    { local: doc(3, { contacts: contacts(storedLarger) }), served: doc(4, { contacts: contacts(textLarger) }), highWater: 3 },
    { doc: doc(4, { contacts: contacts(storedLarger) }) });
  add('tie-goes-to-the-larger-made-on', ['contacts'], 'The same key, verifiedAt and label: the larger madeOn wins.',
    { local: doc(3, { contacts: contacts(contact(bob, { madeOn: LAPTOP })) }), served: doc(4, { contacts: contacts(contact(bob, { madeOn: PHONE })) }), highWater: 3 },
    { doc: doc(4, { contacts: contacts(contact(bob, { madeOn: LAPTOP })) }) });

  // ---- vaults ----
  const V = ids.vault;
  add('vault-record-arrives', ['vaults'], 'The served copy holds a record for a vault this device has none for: it is taken.',
    { local: doc(3), served: doc(4, { vaults: { [V]: vaultRec(2, 'head-2') } }), highWater: 3 },
    { doc: doc(4, { vaults: { [V]: vaultRec(2, 'head-2') } }) });
  add('vault-higher-seq-wins', ['vaults'], 'The same genesis: the record with the higher seq wins.',
    { local: doc(3, { vaults: { [V]: vaultRec(2, 'head-2') } }), served: doc(4, { vaults: { [V]: vaultRec(5, 'head-5') } }), highWater: 3 },
    { doc: doc(4, { vaults: { [V]: vaultRec(5, 'head-5') } }) });
  add('vault-lower-served-seq-loses', ['vaults'], 'The served record is behind (records are batched, so a stale one is normal): the local record stays.',
    { local: doc(3, { vaults: { [V]: vaultRec(5, 'head-5') } }), served: doc(4, { vaults: { [V]: vaultRec(2, 'head-2') } }), highWater: 3 },
    { doc: doc(4, { vaults: { [V]: vaultRec(5, 'head-5') } }) });
  add('vault-same-record', ['vaults'], 'The same record in both copies.',
    { local: doc(3, { vaults: { [V]: vaultRec(5, 'head-5') } }), served: doc(4, { vaults: { [V]: vaultRec(5, 'head-5') } }), highWater: 3 },
    { doc: doc(4, { vaults: { [V]: vaultRec(5, 'head-5') } }) });
  add('vault-genesis-is-immutable', ['vaults'], 'A copy with ANOTHER genesis for the same vaultId, even at a higher seq: an anomaly, and the local record stays.',
    { local: doc(3, { vaults: { [V]: vaultRec(2, 'head-2') } }), served: doc(4, { vaults: { [V]: vaultRec(9, 'head-9', GEN_B) } }), highWater: 3 },
    { doc: doc(4, { vaults: { [V]: vaultRec(2, 'head-2') } }), genesisAnomalies: [V] });
  add('vault-same-seq-another-hash', ['vaults'], 'The same genesis and seq with a different hash: a fork (§3.9). The merged document keeps the LOCAL record, and the fork is reported.',
    { local: doc(3, { vaults: { [V]: vaultRec(5, 'head-5') } }), served: doc(4, { vaults: { [V]: vaultRec(5, 'head-5-other') } }), highWater: 3 },
    { doc: doc(4, { vaults: { [V]: vaultRec(5, 'head-5') } }), forks: [V] });
  add('vault-fork-keeps-the-local-record', ['vaults'], 'The same fork from the other device: each keeps its own record and each reports the fork.',
    { local: doc(3, { vaults: { [V]: vaultRec(5, 'head-5-other') } }), served: doc(4, { vaults: { [V]: vaultRec(5, 'head-5') } }), highWater: 3 },
    { doc: doc(4, { vaults: { [V]: vaultRec(5, 'head-5-other') } }), forks: [V] });

  // ---- accepted ----
  add('accepted-higher-add-seq-wins', ['accepted'], 'The person was added again at seq 9 and declined there: the record for the higher addSeq wins, though it is older.',
    { local: doc(3, { accepted: { [V]: accepted(4, 'accept', t(500)) } }), served: doc(4, { accepted: { [V]: accepted(9, 'decline', t(300)) } }), highWater: 3 },
    { doc: doc(4, { accepted: { [V]: accepted(9, 'decline', t(300)) } }) });
  add('accepted-decline-beats-a-newer-accept', ['accepted'], 'The same addSeq: decline wins whatever `at` says. The served accept is newer (a fast clock, or a replay), and the decline stays: a leave is final for that add.',
    { local: doc(3, { accepted: { [V]: accepted(4, 'decline', t(300)) } }), served: doc(4, { accepted: { [V]: accepted(4, 'accept', t(500)) } }), highWater: 3 },
    { doc: doc(4, { accepted: { [V]: accepted(4, 'decline', t(300)) } }) });
  add('accepted-older-decline-arrives', ['accepted'], 'The same from the other side: this device holds the newer accept, the served copy an older decline for the same addSeq. The decline wins.',
    { local: doc(3, { accepted: { [V]: accepted(4, 'accept', t(500)) } }), served: doc(4, { accepted: { [V]: accepted(4, 'decline', t(300)) } }), highWater: 3 },
    { doc: doc(4, { accepted: { [V]: accepted(4, 'decline', t(300)) } }) });
  add('accepted-same-decision-newest-at', ['accepted'], 'The same addSeq and the same decision: the newest `at` wins.',
    { local: doc(3, { accepted: { [V]: accepted(4, 'accept', t(300)) } }), served: doc(4, { accepted: { [V]: accepted(4, 'accept', t(500), carol.userId) } }), highWater: 3 },
    { doc: doc(4, { accepted: { [V]: accepted(4, 'accept', t(500), carol.userId) } }) });
  add('accepted-two-declines-newest-at', ['accepted'], 'Two declines for the same addSeq: the newest `at` wins, here the local one.',
    { local: doc(3, { accepted: { [V]: accepted(4, 'decline', t(500)) } }), served: doc(4, { accepted: { [V]: accepted(4, 'decline', t(300), carol.userId) } }), highWater: 3 },
    { doc: doc(4, { accepted: { [V]: accepted(4, 'decline', t(500)) } }) });
  add('accepted-tie-goes-to-decline', ['accepted'], 'The same addSeq and the same `at`: decline wins.',
    { local: doc(3, { accepted: { [V]: accepted(4, 'accept', t(300)) } }), served: doc(4, { accepted: { [V]: accepted(4, 'decline', t(300)) } }), highWater: 3 },
    { doc: doc(4, { accepted: { [V]: accepted(4, 'decline', t(300)) } }) });
  add('accepted-tie-goes-to-decline-local', ['accepted'], 'The same with the decline on this device.',
    { local: doc(3, { accepted: { [V]: accepted(4, 'decline', t(300)) } }), served: doc(4, { accepted: { [V]: accepted(4, 'accept', t(300)) } }), highWater: 3 },
    { doc: doc(4, { accepted: { [V]: accepted(4, 'decline', t(300)) } }) });
  add('accepted-tie-goes-to-the-larger-owner', ['accepted'], 'The same addSeq, `at` and decision, another owner: the larger owner wins.',
    { local: doc(3, { accepted: { [V]: accepted(4, 'accept', t(300), bob.userId) } }), served: doc(4, { accepted: { [V]: accepted(4, 'accept', t(300), carol.userId) } }), highWater: 3 },
    { doc: doc(4, { accepted: { [V]: accepted(4, 'accept', t(300), carol.userId) } }) });
  add('accepted-creation-record-and-a-later-add', ['accepted'], 'This device holds the creation record (addSeq 0); another device recorded the decline of a later add at seq 6: the higher addSeq wins.',
    { local: doc(3, { accepted: { [V]: accepted(0, 'accept', t(50), USER) } }), served: doc(4, { accepted: { [V]: accepted(6, 'decline', t(700), bob.userId) } }), highWater: 3 },
    { doc: doc(4, { accepted: { [V]: accepted(6, 'decline', t(700), bob.userId) } }) });

  // ---- recovery ----
  add('recovery-first-record', ['recovery'], 'This device has no recovery record; the served copy has one.',
    { local: doc(3), served: doc(4, { recovery: recovery('private', t(10)) }), highWater: 3 },
    { doc: doc(4, { recovery: recovery('private', t(10)) }) });
  add('recovery-newest-at-wins', ['recovery'], 'The newest `at` wins: the person turned operator recovery on later, on another device. (A device acts on an operator record only with its own mirror.)',
    { local: doc(3, { recovery: recovery('private', t(10)) }), served: doc(4, { recovery: recovery('operator', t(20)) }), highWater: 3 },
    { doc: doc(4, { recovery: recovery('operator', t(20)) }) });
  add('recovery-older-operator-record-loses', ['recovery'], 'An older operator record does not come back over a newer private one.',
    { local: doc(3, { recovery: recovery('private', t(20)) }), served: doc(4, { recovery: recovery('operator', t(10)) }), highWater: 3 },
    { doc: doc(4, { recovery: recovery('private', t(20)) }) });
  add('recovery-tie-goes-to-private', ['recovery'], 'The same `at`: the tie goes to private.',
    { local: doc(3, { recovery: recovery('operator', t(20)) }), served: doc(4, { recovery: recovery('private', t(20)) }), highWater: 3 },
    { doc: doc(4, { recovery: recovery('private', t(20)) }) });
  const fpLow = '0'.repeat(63) + '1';
  const fpHigh = 'f'.repeat(64);
  add('recovery-tie-goes-to-the-smaller-fp', ['recovery'], 'The same `at` and posture, another fingerprint: the smaller fp wins.',
    { local: doc(3, { recovery: recovery('operator', t(20), fpHigh) }), served: doc(4, { recovery: recovery('operator', t(20), fpLow) }), highWater: 3 },
    { doc: doc(4, { recovery: recovery('operator', t(20), fpLow) }) });

  add('recovery-tie-between-none-and-a-fingerprint', ['recovery'], 'The same `at` and posture, one record with fp "none" and one with a fingerprint: the comparison is on the text as stored, and every fingerprint is smaller than "none".',
    { local: doc(3, { recovery: recovery('private', t(20), 'none') }), served: doc(4, { recovery: recovery('private', t(20), fpHigh) }), highWater: 3 },
    { doc: doc(4, { recovery: recovery('private', t(20), fpHigh) }) });

  // ---- the in-blob seq, rollback and withholding ----
  const full = doc(12, { contacts: contacts(B, C), vaults: { [V]: vaultRec(5, 'head-5') }, accepted: { [V]: accepted(4, 'accept') }, recovery: recovery('private', t(10)) });
  const older = doc(5, { contacts: contacts(B), vaults: { [V]: vaultRec(2, 'head-2') } });
  add('served-copy-below-the-high-water-mark', ['seq'], 'The served document\'s own seq (5) is below this device\'s high-water mark (12): a rollback. Nothing the local copy holds is lost.',
    { local: full, served: older, highWater: 12 }, { rollback: true, doc: full });
  add('served-copy-withheld', ['seq'], 'The server serves no blob after this device has seen one: a rollback; the local copy stands.',
    { local: full, served: null, highWater: 12 }, { rollback: true, doc: full });
  add('nothing-served-yet', ['seq'], 'No blob has ever been served or seen (high-water mark 0): not a rollback.',
    { local: doc(0), served: null, highWater: 0 }, { rollback: false, doc: doc(0) });
  add('cas-token-is-not-the-counter', ['seq'], 'FI-B14: the seq the server serves BESIDE the blob is only its compare-and-set token. Here it is 3, below the high-water mark, while the document\'s own seq is 12: not a rollback.',
    { local: full, served: full, highWater: 12, servedCas: 3 }, { rollback: false, doc: full });
  add('high-cas-token-low-counter', ['seq'], 'FI-B14 the other way: the token beside the blob is 99, but the document inside says seq 5, below the high-water mark of 12: a rollback, whatever the token says.',
    { local: full, served: older, highWater: 12, servedCas: 99 }, { rollback: true, doc: full });
  add('fresh-device', ['seq'], 'A device with no local copy takes the served document.',
    { local: null, served: full, highWater: 0 }, { doc: full });

  // ---- unknown keys ----
  add('unknown-key-from-the-served-copy', ['unknown'], 'A newer build wrote a key this build does not know: it survives the merge.',
    { local: doc(3, { contacts: contacts(B) }), served: doc(4, { futureRecords: { x: 1 } }), highWater: 3 },
    { doc: doc(4, { contacts: contacts(B), futureRecords: { x: 1 } }) });
  add('unknown-key-in-the-local-copy', ['unknown'], 'The same with the unknown key in the local copy.',
    { local: doc(3, { futureRecords: { x: 1 } }), served: doc(4, { contacts: contacts(B) }), highWater: 3 },
    { doc: doc(4, { contacts: contacts(B), futureRecords: { x: 1 } }) });
  add('unknown-key-in-both-larger-seq', ['unknown'], 'An unknown key present in both copies stays as the copy with the larger seq has it: here the served one.',
    { local: doc(3, { futureRecords: { x: 1 } }), served: doc(4, { futureRecords: { x: 2 } }), highWater: 3 },
    { doc: doc(4, { futureRecords: { x: 2 } }) });
  add('unknown-key-in-both-local-seq-larger', ['unknown'], 'The local copy has the larger seq (the served one is a rollback): the unknown key stays as the local copy has it.',
    { local: doc(12, { futureRecords: { x: 1 } }), served: doc(5, { futureRecords: { x: 2 } }), highWater: 12 },
    { rollback: true, doc: doc(12, { futureRecords: { x: 1 } }) });
  add('unknown-key-in-both-equal-seq', ['unknown'], 'Both copies have the same seq: the unknown key stays as the LOCAL copy has it.',
    { local: doc(4, { futureRecords: { x: 1 } }), served: doc(4, { futureRecords: { x: 2 } }), highWater: 4 },
    { doc: doc(4, { futureRecords: { x: 1 } }) });

  // ---- the rest of a merge: record by record, whatever the seq values ----
  add('same-seq-different-contents', ['seq'], 'Two documents with the same in-blob seq and different contents (two devices wrote from the same base): merged record by record; the result\'s seq is that seq, and a write then uses it plus one.',
    { local: doc(4, { contacts: contacts(B), accepted: { [V]: accepted(4, 'accept', t(300)) } }), served: doc(4, { contacts: contacts(C), accepted: { [V]: accepted(4, 'decline', t(200)) } }), highWater: 4 },
    { doc: doc(4, { contacts: contacts(B, C), accepted: { [V]: accepted(4, 'decline', t(200)) } }) });
  add('rollback-is-merged-the-same-way', ['seq'], 'A served copy that is a rollback is still merged record by record. It would bring bob back and an accept for the add this account has since declined: bob is removed again by the tombstone the local copy holds, and the decline stays. The result\'s seq is the larger of the two.',
    { local: doc(12, { contacts: contacts(C), contactTombstones: { [bob.userId]: t(150) }, accepted: { [V]: accepted(4, 'decline', t(400)) }, vaults: { [V]: vaultRec(5, 'head-5') } }),
      served: doc(5, { contacts: contacts(B, C), accepted: { [V]: accepted(4, 'accept', t(300)) }, vaults: { [V]: vaultRec(2, 'head-2') } }), highWater: 12 },
    { rollback: true, doc: doc(12, { contacts: contacts(C), contactTombstones: { [bob.userId]: t(150) }, accepted: { [V]: accepted(4, 'decline', t(400)) }, vaults: { [V]: vaultRec(5, 'head-5') } }) });
  add('rollback-holds-a-record-the-local-copy-lacks', ['seq'], 'A rolled-back copy holds a contact this device has no record and no tombstone of: it is merged in like any other (a rollback is reported, and merged the same way).',
    { local: doc(12, { contacts: contacts(C) }), served: doc(5, { contacts: contacts(B) }), highWater: 12 },
    { rollback: true, doc: doc(12, { contacts: contacts(B, C) }) });

  // ---- the caps, with small limits so the documents stay small ----
  const D = contact(dave, { verifiedAt: t(300) });
  const E = contact(eve, { verifiedAt: t(400) });
  const C2 = contact(carol, { verifiedAt: t(200) });
  add('contacts-at-the-cap', ['contacts', 'caps'], 'Three contacts under a limit of three: nothing is dropped.',
    { local: doc(3, { contacts: contacts(B, C2) }), served: doc(4, { contacts: contacts(D) }), highWater: 3, limits: { contacts: 3 } },
    { doc: doc(4, { contacts: contacts(B, C2, D) }) });
  add('contacts-cap-keeps-the-newest', ['contacts', 'caps'], 'The merge would hold four contacts under a limit of three: the newest by verifiedAt are kept, and bob, the oldest, is dropped.',
    { local: doc(3, { contacts: contacts(B, C2) }), served: doc(4, { contacts: contacts(D, E) }), highWater: 3, limits: { contacts: 3 } },
    { doc: doc(4, { contacts: contacts(C2, D, E) }) });
  add('contacts-cap-tie-keeps-the-smaller-user-id', ['contacts', 'caps'], 'A limit of two. dave is the newest; bob and carol have the same verifiedAt, and among equals the smaller userId is kept: bob.',
    { local: doc(3, { contacts: contacts(B, C) }), served: doc(4, { contacts: contacts(D) }), highWater: 3, limits: { contacts: 2 } },
    { doc: doc(4, { contacts: contacts(B, D) }) });
  add('tombstones-cap-keeps-the-newest', ['contacts', 'caps'], 'Three tombstones under a limit of two: the newest by removedAt are kept.',
    { local: doc(3, { contactTombstones: { [bob.userId]: t(100), [carol.userId]: t(200) } }), served: doc(4, { contactTombstones: { [dave.userId]: t(300) } }), highWater: 3, limits: { tombstones: 2 } },
    { doc: doc(4, { contactTombstones: { [carol.userId]: t(200), [dave.userId]: t(300) } }) });
  add('tombstones-cap-tie-keeps-the-smaller-user-id', ['contacts', 'caps'], 'A limit of two. dave\'s tombstone is the newest; bob\'s and carol\'s have the same removedAt, and the smaller userId is kept: bob.',
    { local: doc(3, { contactTombstones: { [bob.userId]: t(100), [carol.userId]: t(100) } }), served: doc(4, { contactTombstones: { [dave.userId]: t(300) } }), highWater: 3, limits: { tombstones: 2 } },
    { doc: doc(4, { contactTombstones: { [bob.userId]: t(100), [dave.userId]: t(300) } }) });

  // ---- the size limit, with small limits. Every decision is at least 10% away from the limit. ----
  const junk = (n, ch = 'j') => ch.repeat(n);
  const midpoint = (over, under) => {
    const limit = Math.round((sealedChars(over) + sealedChars(under)) / 2);
    if (sealedChars(over) < 1.1 * limit || sealedChars(under) > 0.9 * limit) throw new Error('accountstate: a size fixture sits too close to its limit');
    return limit;
  };
  {
    const keep = doc(4, { contacts: contacts(B), futureRecords: junk(120, 'f') });
    const all = { ...keep, junk: junk(1500) };
    add('size-drops-the-largest-unknown-key', ['unknown', 'size'], 'The merged document would not fit its size limit. Unknown keys are dropped first, the largest first: the large `junk` goes, and with it gone the document fits, so the small unknown key and every known record stay.',
      { local: doc(3, { contacts: contacts(B), junk: junk(1500) }), served: doc(4, { futureRecords: junk(120, 'f') }), highWater: 3, limits: { sealedChars: midpoint(all, keep) } },
      { doc: keep });
  }
  {
    const keep = doc(4, { contacts: contacts(B), small: junk(150, 's') });
    const mid = { ...keep, middle: junk(900, 'm') };
    const all = { ...mid, large: junk(1500, 'l') };
    const limit = midpoint(mid, keep);
    if (sealedChars(all) < 1.1 * limit) throw new Error('accountstate: size fixture');
    add('size-drops-unknown-keys-until-it-fits', ['unknown', 'size'], 'Three unknown keys. The largest is dropped and the document still does not fit; the next largest is dropped and it fits; the smallest stays.',
      { local: doc(3, { contacts: contacts(B), large: junk(1500, 'l'), small: junk(150, 's') }), served: doc(4, { middle: junk(900, 'm') }), highWater: 3, limits: { sealedChars: limit } },
      { doc: keep });
  }
  const V2 = ids.otherVault;
  const V3 = ids.personalVault;
  const V4 = ids.otherPersonalVault;
  const leftAt = (seconds) => accepted(1, 'decline', t(seconds));
  {
    const records = {
      vaults: { [V]: vaultRec(3, 'left-1'), [V2]: vaultRec(3, 'left-2'), [V3]: vaultRec(3, 'kept'), [V4]: vaultRec(3, 'left-4') },
      accepted: { [V]: leftAt(100), [V2]: leftAt(300), [V3]: accepted(1, 'accept', t(50)), [V4]: leftAt(200) },
      recovery: recovery('private', t(10)),
    };
    const all = doc(4, records);
    const without = (...gone) => doc(4, {
      vaults: Object.fromEntries(Object.entries(records.vaults).filter(([k]) => !gone.includes(k))),
      accepted: Object.fromEntries(Object.entries(records.accepted).filter(([k]) => !gone.includes(k))),
      recovery: records.recovery,
    });
    add('size-drops-the-oldest-left-vault', ['vaults', 'accepted', 'size'], 'No unknown key is left to drop and the document still does not fit. The vaults and accepted records of vaults the account has left go next, the oldest first. "Left" is read from the document alone, accepted[vaultId].decision = decline, and "oldest" is that record\'s `at`. The vault declined at t+100 s goes, both of its records, and the document fits. The accepted vault, though its record is older, and the recovery record stay.',
      { local: doc(3, { vaults: { [V]: records.vaults[V], [V3]: records.vaults[V3] }, accepted: { [V]: records.accepted[V], [V3]: records.accepted[V3] }, recovery: records.recovery }),
        served: doc(4, { vaults: { [V2]: records.vaults[V2], [V4]: records.vaults[V4] }, accepted: { [V2]: records.accepted[V2], [V4]: records.accepted[V4] } }), highWater: 3, limits: { sealedChars: midpoint(all, without(V)) } },
      { doc: without(V) });
    const limit2 = midpoint(without(V), without(V, V4));
    if (sealedChars(all) < 1.1 * limit2) throw new Error('accountstate: size fixture');
    add('size-drops-left-vaults-oldest-first', ['vaults', 'accepted', 'size'], 'A tighter limit: the oldest left vault (t+100 s) goes, then the next oldest (t+200 s), and the document fits. The vault left last (t+300 s) and the accepted vault stay.',
      { local: doc(3, { vaults: { [V]: records.vaults[V], [V3]: records.vaults[V3] }, accepted: { [V]: records.accepted[V], [V3]: records.accepted[V3] }, recovery: records.recovery }),
        served: doc(4, { vaults: { [V2]: records.vaults[V2], [V4]: records.vaults[V4] }, accepted: { [V2]: records.accepted[V2], [V4]: records.accepted[V4] } }), highWater: 3, limits: { sealedChars: limit2 } },
      { doc: without(V, V4) });
    const withJunk = { ...all, junk: junk(1500) };
    const limit3 = midpoint(all, without(V));
    if (sealedChars(withJunk) < 1.1 * limit3) throw new Error('accountstate: size fixture');
    add('size-unknown-keys-go-before-left-vaults', ['unknown', 'vaults', 'accepted', 'size'], 'An unknown key and four vault records over the limit: the unknown key is dropped first; the document still does not fit, so the oldest left vault goes too.',
      { local: doc(3, { vaults: { [V]: records.vaults[V], [V3]: records.vaults[V3] }, accepted: { [V]: records.accepted[V], [V3]: records.accepted[V3] }, recovery: records.recovery, junk: junk(1500) }),
        served: doc(4, { vaults: { [V2]: records.vaults[V2], [V4]: records.vaults[V4] }, accepted: { [V2]: records.accepted[V2], [V4]: records.accepted[V4] } }), highWater: 3, limits: { sealedChars: limit3 } },
      { doc: without(V) });
  }

  // ---- the edges ----
  const nicknamed = { ...newerB, nickname: 'Rob' };
  add('unknown-field-of-the-winning-record-is-kept', ['contacts'], 'The served record is the newer one and carries a field this build does not know: the record wins whole, and the field is preserved as written.',
    { local: doc(3, { contacts: contacts(B) }), served: doc(4, { contacts: contacts(nicknamed) }), highWater: 3 },
    { doc: doc(4, { contacts: contacts(nicknamed) }) });
  add('unknown-field-of-a-vault-record-is-kept', ['vaults'], 'The same for a vault record: the record with the higher seq wins whole, with its unknown field.',
    { local: doc(3, { vaults: { [V]: vaultRec(2, 'head-2') } }), served: doc(4, { vaults: { [V]: { ...vaultRec(5, 'head-5'), members: 3 } } }), highWater: 3 },
    { doc: doc(4, { vaults: { [V]: { ...vaultRec(5, 'head-5'), members: 3 } } }) });
  add('tombstone-dropped-at-the-cap-still-removes-its-contact', ['contacts', 'caps'], 'A limit of one tombstone. Tombstones are applied to the contacts of both copies BEFORE the tombstone cap: bob\'s tombstone removes his pin, and only then does the cap drop it as the older of the two.',
    { local: doc(3, { contacts: contacts(B) }), served: doc(4, { contactTombstones: { [bob.userId]: t(150), [carol.userId]: t(300) } }), highWater: 3, limits: { tombstones: 1 } },
    { doc: doc(4, { contactTombstones: { [carol.userId]: t(300) } }) });
  {
    const records = {
      vaults: { [V]: vaultRec(3, 'left-1'), [V2]: vaultRec(3, 'left-2'), [V3]: vaultRec(3, 'kept') },
      accepted: { [V]: leftAt(100), [V2]: leftAt(100), [V3]: accepted(1, 'accept', t(50)) },
    };
    const all = doc(4, records);
    const after = doc(4, { vaults: { [V2]: records.vaults[V2], [V3]: records.vaults[V3] }, accepted: { [V2]: records.accepted[V2], [V3]: records.accepted[V3] } });
    if (!(V < V2)) throw new Error('accountstate: the equal-at fixture needs V < V2');
    add('size-left-vaults-with-the-same-at', ['vaults', 'accepted', 'size'], 'Two left vaults whose decline records have the same `at`: the smaller vaultId goes first.',
      { local: doc(3, { vaults: { [V2]: records.vaults[V2], [V3]: records.vaults[V3] }, accepted: { [V2]: records.accepted[V2], [V3]: records.accepted[V3] } }),
        served: doc(4, { vaults: { [V]: records.vaults[V] }, accepted: { [V]: records.accepted[V] } }), highWater: 3, limits: { sealedChars: midpoint(all, after) } },
      { doc: after });
  }
  {
    const four = doc(4, { contacts: contacts(B, C2, D, E), recovery: recovery('private', t(10)) });
    const limit = Math.round(sealedChars(four) / 2);
    add('size-nothing-left-to-drop', ['contacts', 'size'], 'The merged document is twice its size limit and holds nothing the design lets a device drop: no unknown key and no left vault. It is not written (account_state_full); the merged document is still used for reading.',
      { local: doc(3, { contacts: contacts(B, C2), recovery: recovery('private', t(10)) }), served: doc(4, { contacts: contacts(D, E) }), highWater: 3, limits: { sealedChars: limit } },
      { doc: four, notWritten: 'account_state_full' });
  }
  const LAST = 9007199254740991;
  add('seq-cannot-be-advanced', ['seq'], 'The served document\'s seq is 2^53 - 1, the largest int: a write would need that plus one. The documents are merged and read as usual, and nothing is written (account_state_damaged).',
    { local: doc(5, { contacts: contacts(B) }), served: doc(LAST, { contacts: contacts(C) }), highWater: 5, servedCas: 12 },
    { doc: doc(LAST, { contacts: contacts(B, C) }), notWritten: 'account_state_damaged' });
  return rows;
}

function acceptanceRows() {
  const rows = [];
  const add = (name, why, record, latestAddSeq, answer, extensionOpens) => {
    if (acceptance(record, latestAddSeq) !== answer || extensionAccepts(record) !== extensionOpens) throw new Error('accountstate acceptance fixture: ' + name);
    rows.push({ name, why, record, latestAddSeq, expect: { answer, extensionOpens } });
  };
  add('accepted', 'The record answers the account\'s latest add with accept.', accepted(4, 'accept'), 4, 'accept', true);
  add('declined', 'The record answers the latest add with decline: the vault stays hidden on every device.', accepted(4, 'decline'), 4, 'decline', false);
  add('no-record', 'No record for the vault: the person is asked.', null, 4, 'ask', false);
  add('accepted-an-earlier-add', 'FS-R6: the account left or was removed and was added again at seq 9. The record names the add at seq 4, so it answers nothing and the person is asked again. The extension reads decision only and cannot tell (R24).', accepted(4, 'accept'), 9, 'ask', true);
  add('declined-an-earlier-add', 'A decline of an earlier add does not answer the new one either: the person is asked.', accepted(4, 'decline'), 9, 'ask', false);
  add('record-ahead-of-the-log', 'The record names an add this device\'s verified log does not have yet (addSeq 9, latest verified add 4): it does not answer that add.', accepted(9, 'accept'), 4, 'ask', true);
  add('creation-record-after-a-re-add', 'The creator left its own vault and was added again at seq 5. Its creation record has addSeq 0 (the genesis), which answers no add: the person is asked.', { owner: USER, addSeq: 0, at: t(50), decision: 'accept' }, 5, 'ask', true);
  add('decline-written-on-leaving', 'A device that signs or verifies a leave or remove of this account writes decline for the current addSeq, so the extension keeps a replayed wrap of that vault closed.', accepted(4, 'decline', t(900)), 4, 'decline', false);
  return rows;
}

export function build() {
  const sample = sampleDoc();
  const nonce = fixed('accountstate/nonce', 24);
  const plaintext = compact(sample);
  const blob = envelopeSeal(UVK, nonce, accountStateAd(USER), utf8(plaintext));
  const otherKeyBlob = envelopeSeal(fixed('accountstate/other-uvk'), nonce, accountStateAd(USER), utf8(plaintext));
  return {
    _about: [
      'The UVK-sealed account state of design 2026-11-15-onboarding-trust §5.4 and spec 02 §9. This file REPLACES spec/test-vectors/accountstate.json at integration; until then it lives in spec/test-vectors/next/ and the old file stays where the old tests read it.',
      'Hand-authored from the independent oracle in tools/vector-gen/oracle (@noble; no andvari code). Regenerate with `npm run generate` there; `npm run check` fails on any difference.',
      'The blob: Envelope(key = UVK, plaintext = the JSON document, ad = "andvari/v1|account-state|{userId}"). `sampleBlobB64` opens to `samplePlaintext`; rejectOpen rows must not open in this account\'s slot.',
      'The document: {"v":2,"userId","seq","contacts":{userId: contact},"contactTombstones":{userId: removedAt ms},"vaults":{vaultId: {genesisHash, seq, hash}},"accepted":{vaultId: {owner, addSeq, at, decision}},"recovery":{posture, fp, at}}. A contact is {userId, identityPub, label, method: "link", verifiedAt, compared, madeOn} and its userId equals its map key. recovery is absent until a choice is recorded. Documents in this file are compared as JSON values: key order carries no meaning (writers emit map keys in ascending byte order, readers accept any order).',
      'decode: `plaintext` decoded for the account `userId`. expect.refused is true for a document with another v, another account\'s userId, a seq that is not an int, or no JSON object at all. Otherwise expect.dropped counts the records that failed their own shape and were dropped, and expect.doc is what remains. A document that lacks one of the four maps is read as having that map empty. Unknown top-level keys are kept, and a record that carries a field this build does not know is kept too, with the field preserved as written (a record still needs every field of its own shape).',
      'merge: this device\'s copy `local` (or null) merged with the served document `served` (or null when the server serves none), with `highWater` = this device\'s high-water mark of the IN-BLOB seq. `servedCasSeq` is the seq the server serves beside the blob, its compare-and-set token: no rule reads it (FI-B14). expect.rollback: the served document\'s own seq is below the high-water mark, or nothing is served after something was seen. expect.doc: the merged document. expect.keyChange: served contact records with another key than the one this device uses, which go to the key-change prompt and are not merged. expect.genesisAnomalies: vaults whose served record names another genesis (the local record stays). expect.forks: vaults with the same genesis and seq and another hash (the merged document keeps the LOCAL record). expect.notWritten, where present, says that the merged document is used for reading only: account_state_full (it still does not fit after every drop) or account_state_damaged (its seq cannot be advanced). A row without it may be written.',
      '`limits`, where a row gives it, replaces §5.4\'s limits for that row: contacts (1,000), tombstones (1,000) and sealedChars (1,048,576). A merge takes its limits as an input so that the cap rules can be graded on small documents; the apps pass the constants. sealedChars is the length of the sealed state as it is sent: base64 of the envelope, which is the compact JSON document plus 42 bytes. Every size decision in this file is at least 10% away from its limit, on both sides and at every step, so the exact serialization cannot change an outcome.',
      'The rules. contacts: per userId the newest verifiedAt wins; compared is OR between records with the same key; another key is never merged; tombstones keep the later time, and a tombstone not older than a pin removes it; ties go to the larger label, then the larger madeOn. vaults: genesisHash is immutable; otherwise the higher seq wins; a fork keeps the local record. accepted: the higher addSeq; for the same addSeq decline wins whatever `at` says; between two records with the same decision the newest at, then the larger owner. recovery: the newest at, then private, then the smaller fp. Every tie is compared on the field\'s text exactly as stored, byte by byte: a label is its base64url string, and "none" sorts after every fingerprint.',
      'The rest of a merge. Two documents are merged record by record whatever their seq values, a rolled-back served copy included (it is reported, and anything it would bring back is removed again by the tombstone the local copy holds); the result\'s seq is the larger of the two, and a write then uses that plus one. An unknown top-level key is kept; one present in both copies stays as the copy with the larger seq has it, and as the local copy has it when the two are equal. Tombstones are applied to the contacts of both copies before any cap, so a tombstone that the cap then drops has still removed its contact in that merge. At the caps the newest are kept (verifiedAt for contacts, removedAt for tombstones), and among equals the smaller userId. A merged document over its size limit drops unknown keys first, the largest first; if it still does not fit, the vaults and accepted records of vaults the account has left go next, the oldest first; recovery is never dropped. "Left" means accepted[vaultId].decision = decline, and "oldest" is the smallest `at` of that record, then the smaller vaultId. A document that still does not fit is not written (account_state_full), and neither is one whose seq is the largest int (account_state_damaged); the merged document is still used for reading.',
      'acceptance (§3.6 (d), VR-16): an accepted record against the seq of this account\'s latest add in the verified log. expect.answer: the record\'s decision when its addSeq is that seq, otherwise ask. expect.extensionOpens: the Chrome and Firefox extension reads decision only (FN-1), so it opens a wrap of the vault exactly when the record says accept.',
      'Not graded, because the texts do not say: a document in which one of the four maps is present and is not an object; a high-water mark above both documents\' seq; two unknown keys of nearly the same size; a document that still does not fit after some records were dropped (whether it is then read with or without those drops).',
      'Graded by core and the web twin; by the extension for the rows whose `records` is ["vaults"] and for the acceptance rows\' extensionOpens (§17).',
    ],
    userId: USER,
    uvkB64: b64u(UVK),
    adUtf8: accountStateAd(USER),
    account: describe(alice),
    sample,
    samplePlaintext: plaintext,
    sampleNonceB64: b64u(nonce),
    sampleBlobB64: b64u(blob),
    rejectOpen: [
      { name: 'another-users-slot', why: 'The same blob opened with another account\'s AD.', adUtf8: accountStateAd(bob.userId), uvkB64: b64u(UVK), blobB64: b64u(blob) },
      { name: 'another-key', why: 'A blob sealed under another key (injected by someone without the UVK).', adUtf8: accountStateAd(USER), uvkB64: b64u(UVK), blobB64: b64u(otherKeyBlob) },
    ],
    decode: decodeRows(sample),
    merge: mergeRows(),
    acceptance: acceptanceRows(),
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
  const uvk = mustUnb64u(doc.uvkB64);

  const opened = envelopeOpen(uvk, doc.adUtf8, mustUnb64u(doc.sampleBlobB64));
  expect(opened !== null && new TextDecoder().decode(opened) === doc.samplePlaintext, 'the sample blob opens to the sample plaintext');
  expect(b64u(envelopeSeal(uvk, mustUnb64u(doc.sampleNonceB64), doc.adUtf8, utf8(doc.samplePlaintext))) === doc.sampleBlobB64, 'the sample blob reproduces');
  expect(same(decodeAccountState(doc.samplePlaintext, doc.userId), { refused: false, dropped: 0, doc: doc.sample }), 'the sample plaintext decodes to the sample');
  for (const row of doc.rejectOpen) expect(envelopeOpen(mustUnb64u(row.uvkB64), row.adUtf8, mustUnb64u(row.blobB64)) === null, 'rejectOpen ' + row.name);
  for (const row of doc.decode) {
    const got = decodeAccountState(row.plaintext, doc.userId);
    expect(same(got, row.expect), `decode ${row.name}: oracle says ${JSON.stringify(got).slice(0, 160)}`);
  }
  for (const row of doc.merge) {
    const result = mergeAccountState(row.local, row.served, row.highWater, row.limits ? { ...LIMITS, ...row.limits } : LIMITS);
    const got = { rollback: result.rollback, doc: result.doc, keyChange: result.keyChange, genesisAnomalies: result.genesisAnomalies, forks: result.forks };
    if (result.notWritten) got.notWritten = result.notWritten;
    expect(same(got, row.expect), `merge ${row.name}: oracle says ${JSON.stringify(got).slice(0, 200)}`);
  }
  for (const row of doc.acceptance) {
    expect(acceptance(row.record, row.latestAddSeq) === row.expect.answer && extensionAccepts(row.record) === row.expect.extensionOpens, 'acceptance ' + row.name);
  }
  return { rows, failures };
}
