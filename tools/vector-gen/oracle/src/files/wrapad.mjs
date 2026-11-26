// wrapad.json: the genesis-bound AD of a shared vault's UVK wraps (§2.3, T-B3), the unchanged
// personal wrap, and the wrap path of §3.6's adoption conditions.

import { b64u, mustUnb64u } from '../bytes.mjs';
import { envelopeSeal, envelopeOpen } from '../prims.mjs';
import { sharedWrapAd, personalWrapAd, personalGrantAd, adoptByWrap, extensionOpensWrap } from '../grant.mjs';
import { verifyLog, vkCommit } from '../vaultlog.mjs';
import { LogBuilder } from '../build.mjs';
import { alice, bob, carol, eve, ids, fixed, T0, MINUTE, DAY, describe } from '../cast.mjs';

export const file = 'wrapad.json';

const VK = fixed('wrapad/vk');
const OTHER_VK = fixed('wrapad/other-vk');
const UVK = { alice: fixed('wrapad/uvk/alice'), bob: fixed('wrapad/uvk/bob') };
const nonce = (label) => fixed('wrapad/nonce/' + label, 24);
const id16 = (label) => b64u(fixed('wrapad/' + label, 16));
const at = (minutes) => T0 + minutes * MINUTE;

// The `wrap` block of the existing personalwrap.json: same inputs, so the bytes must be the same.
const PERSONAL = {
  userId: '33333333-3333-4333-8333-333333333333',
  vaultId: '55555555-5555-4555-8555-555555555555',
  uvkB64: 'ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8',
  vkB64: 'gIGCg4SFhoeIiYqLjI2Oj5CRkpOUlZaXmJmam5ydnp8',
  personalWrapB64: 'AQFAQUJDREVGR0hJSktMTU5PUFFSU1RVVle6oO8qouN7WP_3ZbNo7myqacRVcEKClNSsGFu0EqJXjQfC5QIdfyTs-_GXFkVbzeg',
};

function buildLogs() {
  const make = (steps) => {
    const log = new LogBuilder(ids.vault);
    for (const [signer, fields] of steps) log.append(signer, fields);
    const result = verifyLog({ vaultId: ids.vault, frames: log.frames });
    if (result.verdict !== 'ok') throw new Error('wrapad fixture log does not verify: ' + result.verdict);
    return log;
  };
  const genesis = (owner, when = at(0)) => [owner, { kind: 'genesis', actor: owner.userId, at: when, ownerKey: owner.key, vkCommit: vkCommit(VK, ids.vault) }];
  const add = (owner, when, member, label) =>
    [owner, { kind: 'add', actor: owner.userId, at: when, member: member.userId, memberKey: member.key, role: 'writer', grantId: id16('grant/' + label) }];
  const remove = (owner, when, member) => [owner, { kind: 'remove', actor: owner.userId, at: when, member: member.userId }];
  const transfer = (from, to, start, label) => [
    [from, { kind: 'offer', actor: from.userId, at: at(start), to: to.userId, toKey: to.key, offerId: id16('offer/' + label), expiresAt: at(start) + DAY }],
    [to, { kind: 'accept', actor: to.userId, at: at(start + 1), offerId: id16('offer/' + label) }],
  ];
  return {
    A: { why: 'The real log: alice creates the vault and adds bob at seq 1.', log: make([genesis(alice), add(alice, at(1), bob, 'bob')]) },
    'A-longer': { why: 'Log A two entries later: carol is added and her role changed.', log: make([genesis(alice), add(alice, at(1), bob, 'bob'), add(alice, at(2), carol, 'carol'), [alice, { kind: 'role', actor: alice.userId, at: at(3), member: carol.userId, role: 'reader' }]]) },
    B: { why: 'A log the server made up (T-B3): its own genesis, signed by eve, with the COPIED vkCommit, then an add for bob.', log: make([genesis(eve), add(eve, at(1), bob, 'bob-by-eve')]) },
    'A-readded': { why: 'Log A, then bob is removed at seq 2 and added again at seq 3.', log: make([genesis(alice), add(alice, at(1), bob, 'bob'), remove(alice, at(2), bob), add(alice, at(3), bob, 'bob-again')]) },
    'A-removed': { why: 'Log A, then bob is removed.', log: make([genesis(alice), add(alice, at(1), bob, 'bob'), remove(alice, at(2), bob)]) },
    'A-transferred': { why: 'Log A, then alice hands the vault to bob. alice, the genesis owner, is now a writer and was never added.', log: make([genesis(alice), add(alice, at(1), bob, 'bob'), ...transfer(alice, bob, 2, 'to-bob')]) },
    'A-owner-readded': { why: 'Log A, the vault handed to bob, alice leaves at seq 4 and bob adds her again at seq 5 (FN-2).', log: make([
      genesis(alice), add(alice, at(1), bob, 'bob'), ...transfer(alice, bob, 2, 'to-bob'),
      [alice, { kind: 'leave', actor: alice.userId, at: at(4) }], add(bob, at(5), alice, 'alice-again'),
    ]) },
  };
}

export function build() {
  const logs = buildLogs();
  const hashA = logs.A.log.entries[0].hash;
  const hashB = logs.B.log.entries[0].hash;

  // ---- AD construction ----
  const ad = [
    { why: 'a shared vault\'s owner wrap or member self-wrap: the AD names the genesis hash of the log the wrapping device verified', kind: 'shared', vaultId: ids.vault, userId: bob.userId, genesisHash: hashA, adUtf8: sharedWrapAd(ids.vault, bob.userId, hashA) },
    { why: 'the same vault and user under another genesis', kind: 'shared', vaultId: ids.vault, userId: bob.userId, genesisHash: hashB, adUtf8: sharedWrapAd(ids.vault, bob.userId, hashB) },
    { why: 'the owner\'s wrap of the same vault', kind: 'shared', vaultId: ids.vault, userId: alice.userId, genesisHash: hashA, adUtf8: sharedWrapAd(ids.vault, alice.userId, hashA) },
    { why: 'the personal wrap keeps its v1 AD, with no genesis hash (a personal vault has no log)', kind: 'personal', vaultId: PERSONAL.vaultId, userId: PERSONAL.userId, adUtf8: personalWrapAd(PERSONAL.vaultId, PERSONAL.userId) },
  ];

  // ---- byte-exact seals ----
  const wraps = {
    bobSelf: envelopeSeal(UVK.bob, nonce('bob-self'), sharedWrapAd(ids.vault, bob.userId, hashA), VK),
    aliceOwner: envelopeSeal(UVK.alice, nonce('alice-owner'), sharedWrapAd(ids.vault, alice.userId, hashA), VK),
    bobOtherKey: envelopeSeal(UVK.bob, nonce('bob-other-key'), sharedWrapAd(ids.vault, bob.userId, hashA), OTHER_VK),
    bobOwnerAfterAccept: envelopeSeal(UVK.bob, nonce('bob-owner'), sharedWrapAd(ids.vault, bob.userId, hashA), VK),
  };
  const personalNonce = mustUnb64u(PERSONAL.personalWrapB64).slice(2, 26);
  const personalWrap = envelopeSeal(mustUnb64u(PERSONAL.uvkB64), personalNonce, personalWrapAd(PERSONAL.vaultId, PERSONAL.userId), mustUnb64u(PERSONAL.vkB64));
  if (b64u(personalWrap) !== PERSONAL.personalWrapB64) throw new Error('wrapad: the personal wrap is not byte-identical to personalwrap.json');

  const seal = [
    { name: 'member-self-wrap', why: 'bob\'s self-wrap of the vault key, posted after he adopted it from a grant', uvkB64: b64u(UVK.bob), nonceB64: b64u(nonce('bob-self')), adUtf8: sharedWrapAd(ids.vault, bob.userId, hashA), vkB64: b64u(VK), wrappedVkB64: b64u(wraps.bobSelf) },
    { name: 'owner-wrap', why: 'alice\'s owner wrap, posted with the genesis', uvkB64: b64u(UVK.alice), nonceB64: b64u(nonce('alice-owner')), adUtf8: sharedWrapAd(ids.vault, alice.userId, hashA), vkB64: b64u(VK), wrappedVkB64: b64u(wraps.aliceOwner) },
    { name: 'personal-wrap-unchanged', why: 'the personal wrap, with the inputs of personalwrap.json\'s `wrap` block: the envelope is byte-identical to that file\'s personalWrapB64', uvkB64: PERSONAL.uvkB64, nonceB64: b64u(personalNonce), adUtf8: personalWrapAd(PERSONAL.vaultId, PERSONAL.userId), vkB64: PERSONAL.vkB64, wrappedVkB64: b64u(personalWrap) },
  ];

  // ---- opening ----
  const open = [];
  const tryOpen = (name, opens, why, uvk, wrapped, adUtf8) => {
    const vk = envelopeOpen(uvk, adUtf8, wrapped);
    if ((vk !== null) !== opens) throw new Error(`wrapad open "${name}": expected opens=${opens}`);
    open.push({ name, why, uvkB64: b64u(uvk), wrappedVkB64: b64u(wrapped), adUtf8, expect: opens ? { opens: true, vkB64: b64u(vk) } : { opens: false } });
  };
  tryOpen('self-wrap-under-its-genesis', true, 'bob\'s self-wrap opens with the AD that names genesis A.', UVK.bob, wraps.bobSelf, sharedWrapAd(ids.vault, bob.userId, hashA));
  tryOpen('refused-under-another-genesis', false, 'A wrap made for genesis A is refused under genesis B: the server cannot move it onto a log it fabricated.', UVK.bob, wraps.bobSelf, sharedWrapAd(ids.vault, bob.userId, hashB));
  tryOpen('refused-for-another-vault', false, 'The same wrap under another vault id.', UVK.bob, wraps.bobSelf, sharedWrapAd(ids.otherVault, bob.userId, hashA));
  tryOpen('refused-for-another-user', false, 'The same wrap in another user\'s slot.', UVK.bob, wraps.bobSelf, sharedWrapAd(ids.vault, alice.userId, hashA));
  tryOpen('refused-under-another-uvk', false, 'bob\'s wrap under alice\'s UVK.', UVK.alice, wraps.bobSelf, sharedWrapAd(ids.vault, bob.userId, hashA));
  tryOpen('refused-without-the-genesis-hash', false, 'The AD without its last component is not the AD of any wrap.', UVK.bob, wraps.bobSelf, `andvari/v2|vk-shared|${ids.vault}|${bob.userId}`);
  tryOpen('refused-with-an-uppercase-hash', false, 'The genesis hash is lowercase hex; the AD is compared as bytes.', UVK.bob, wraps.bobSelf, sharedWrapAd(ids.vault, bob.userId, hashA.toUpperCase()));
  tryOpen('shared-wrap-is-no-personal-wrap', false, 'A shared-vault wrap never opens under the personal-wrap AD.', UVK.bob, wraps.bobSelf, personalWrapAd(ids.vault, bob.userId));
  tryOpen('shared-wrap-is-no-v1-wrap', false, 'A shared-vault wrap never opens under the v1 vk AD of a personal vault\'s owner grant.', UVK.bob, wraps.bobSelf, personalGrantAd(ids.vault, bob.userId));
  tryOpen('personal-wrap-under-its-ad', true, 'The personal wrap opens under andvari/v1|vk-personal, as before.', mustUnb64u(PERSONAL.uvkB64), personalWrap, personalWrapAd(PERSONAL.vaultId, PERSONAL.userId));
  tryOpen('personal-wrap-is-no-shared-wrap', false, 'A personal wrap never opens under a shared-vault AD.', mustUnb64u(PERSONAL.uvkB64), personalWrap, sharedWrapAd(PERSONAL.vaultId, PERSONAL.userId, hashA));

  // ---- §3.6 through the account's own wrap ----
  const adopt = [];
  const accepted = (owner, addSeq, decision = 'accept') => ({ [ids.vault]: { owner: owner.userId, addSeq, at: at(60), decision } });
  const record = (log, seq, hash) => ({ [ids.vault]: { genesisHash: log.entries[0].hash, seq, hash: hash ?? log.entries[seq].hash } });
  const tryAdopt = (name, expected, why, me, uvk, logName, wrap, accountState, frames, extension, mark) => {
    const logFrames = frames ?? logs[logName].log.frames;
    const result = adoptByWrap({ me, uvk, vaultId: ids.vault, logFrames, wrap, accountState });
    const want = expected === 'adopt' ? { adopt: true, vkB64: b64u(VK) } : { adopt: false, failed: expected };
    const got = result.adopt ? { adopt: true, vkB64: b64u(result.vk) } : { adopt: false, failed: result.failed };
    if (JSON.stringify(got) !== JSON.stringify(want)) throw new Error(`wrapad adopt "${name}": the design says ${JSON.stringify(want)}, the oracle says ${JSON.stringify(got)}`);
    if (mark !== undefined && !Number.isSafeInteger(accountState.seq)) throw new Error(`wrapad adopt "${name}": a row with a mark needs the document's seq`);
    want.extensionOpens = extensionOpensWrap({ me, uvk, vaultId: ids.vault, wrap, accountState, highWater: mark ?? null });
    if (extension !== undefined && want.extensionOpens !== extension) throw new Error(`wrapad adopt "${name}": the design says the extension ${extension ? 'opens' : 'stays closed'}, the oracle says otherwise`);
    const row = { name, why, me: me.name, uvkB64: b64u(uvk), log: logName, wrappedVkB64: b64u(wrap), accountState };
    if (mark !== undefined) row.extensionHighWater = mark;
    row.expect = want;
    if (frames) row.frames = frames.map(b64u);
    adopt.push(row);
  };
  const A = logs.A.log;

  tryAdopt('self-wrap-accepted', 'adopt', 'bob\'s self-wrap opens under this log\'s genesis hash, an accepted record answers his add at seq 1, and the vault record agrees.', bob, UVK.bob, 'A', wraps.bobSelf, { vaults: record(A, 1), accepted: accepted(alice, 1) });
  tryAdopt('no-vault-record-yet', 'adopt', 'No vault record: (e) holds, and the device writes the record once the log verifies (T2-R-d).', bob, UVK.bob, 'A', wraps.bobSelf, { vaults: {}, accepted: accepted(alice, 1) });
  tryAdopt('record-behind-the-served-head', 'adopt', 'The record is two entries behind the served head and its hash matches the served chain at that seq.', bob, UVK.bob, 'A-longer', wraps.bobSelf, { vaults: record(A, 1), accepted: accepted(alice, 1) });
  tryAdopt('no-accepted-record', ['d'], 'FC-7: the wrap opens, but no accepted record answers the add. The person is asked.', bob, UVK.bob, 'A', wraps.bobSelf, { vaults: record(A, 1), accepted: {} });
  tryAdopt('declined', ['d'], 'The account\'s record for this add says decline.', bob, UVK.bob, 'A', wraps.bobSelf, { vaults: record(A, 1), accepted: accepted(alice, 1, 'decline') });
  tryAdopt('accepted-an-earlier-add', ['d'], 'FC-7: bob was removed and added again at seq 3. The server replays his old self-wrap, which still opens (same genesis), and his record answers the add at seq 1: it does not answer the latest add, so the device does not adopt.', bob, UVK.bob, 'A-readded', wraps.bobSelf, { vaults: {}, accepted: accepted(alice, 1) });
  tryAdopt('accepted-the-latest-add', 'adopt', 'The same log with a record for the add at seq 3.', bob, UVK.bob, 'A-readded', wraps.bobSelf, { vaults: {}, accepted: accepted(alice, 3) });
  tryAdopt('fabricated-genesis', ['d', 'e'], 'T-B3: the server serves log B, its own genesis with the copied commitment. bob\'s real self-wrap does not open under B\'s genesis hash, and his account\'s vault record names genesis A: "a different genesis fails both".', bob, UVK.bob, 'B', wraps.bobSelf, { vaults: record(A, 1), accepted: accepted(alice, 1) });
  tryAdopt('fabricated-genesis-fresh-account-state', ['d'], 'The same with no vault record yet: the wrap AD alone refuses it.', bob, UVK.bob, 'B', wraps.bobSelf, { vaults: {}, accepted: accepted(eve, 1) });
  tryAdopt('record-names-another-genesis', ['e'], 'The wrap opens and the add is accepted, but the account\'s vault record names another genesis for this vault id.', bob, UVK.bob, 'A', wraps.bobSelf, { vaults: record(logs.B.log, 1), accepted: accepted(alice, 1) });
  tryAdopt('record-ahead-of-the-served-head', ['e'], 'The record says the account verified seq 3; the served log ends at seq 1.', bob, UVK.bob, 'A', wraps.bobSelf, { vaults: record(logs['A-longer'].log, 3), accepted: accepted(alice, 1) });
  tryAdopt('record-has-another-hash-at-its-seq', ['e'], 'The record\'s hash at seq 1 is not the served entry\'s.', bob, UVK.bob, 'A', wraps.bobSelf, { vaults: record(A, 1, logs.B.log.entries[1].hash), accepted: accepted(alice, 1) });
  tryAdopt('not-a-member', ['b'], 'bob was removed: he is not in the log\'s members, whatever his wrap and records say.', bob, UVK.bob, 'A-removed', wraps.bobSelf, { vaults: {}, accepted: accepted(alice, 1) });
  tryAdopt('key-fails-the-commitment', ['c'], 'A self-wrap that opens but holds another key than the one the genesis committed to.', bob, UVK.bob, 'A', wraps.bobOtherKey, { vaults: record(A, 1), accepted: accepted(alice, 1) });
  const broken = A.frames.map((f) => f.slice());
  broken[1][37 + 10] ^= 0x01;
  tryAdopt('log-does-not-verify', ['a'], 'The served log\'s second entry has a broken signature.', bob, UVK.bob, 'A', wraps.bobSelf, { vaults: {}, accepted: accepted(alice, 1) }, broken);

  const created = { [ids.vault]: { owner: alice.userId, addSeq: 0, at: at(0), decision: 'accept' } };
  tryAdopt('genesis-owner', 'adopt', 'alice created the vault and the log has no add of her: her own owner wrap is enough for a full client. Her device wrote the creation record {owner: herself, addSeq: 0, decision: accept} and the vault record, so the extension opens the wrap too.', alice, UVK.alice, 'A', wraps.aliceOwner, { vaults: record(A, 0), accepted: created }, undefined, true);
  tryAdopt('genesis-owner-no-records', 'adopt', 'The same with no account-state records at all: a full client adopts whatever the record says, the extension has nothing to go on and stays closed.', alice, UVK.alice, 'A', wraps.aliceOwner, { vaults: {}, accepted: {} }, undefined, false);
  tryAdopt('genesis-owner-record-says-decline', 'adopt', 'The record for the vault says decline: a full client still adopts (the genesis owner path needs no record), the extension reads decision only and stays closed.', alice, UVK.alice, 'A', wraps.aliceOwner, { vaults: record(A, 0), accepted: { [ids.vault]: { owner: alice.userId, addSeq: 0, at: at(0), decision: 'decline' } } }, undefined, false);
  tryAdopt('genesis-owner-added-again-creation-record', ['d'], 'FN-2: alice left and was added again at seq 5. Her creation record has addSeq 0, which answers nothing once the log has an add of her: a full client asks. The extension cannot check addSeq and still opens the old wrap (R24); a device that verified her leave would have written decline.', alice, UVK.alice, 'A-owner-readded', wraps.aliceOwner, { vaults: record(A, 0), accepted: created }, undefined, true);
  tryAdopt('genesis-owner-after-handing-over', 'adopt', 'alice handed the vault to bob and is a writer now. The log still has no add of her, so the genesis-owner path applies.', alice, UVK.alice, 'A-transferred', wraps.aliceOwner, { vaults: {}, accepted: {} });
  tryAdopt('genesis-owner-added-again', ['d'], 'FN-2: alice left and bob added her again. The log now has an add of her, so she is asked like anyone else: her old owner wrap opens, but nothing answers the add at seq 5.', alice, UVK.alice, 'A-owner-readded', wraps.aliceOwner, { vaults: {}, accepted: {} });
  tryAdopt('genesis-owner-added-again-accepted', 'adopt', 'The same with an accepted record for the add at seq 5.', alice, UVK.alice, 'A-owner-readded', wraps.aliceOwner, { vaults: {}, accepted: accepted(bob, 5) });
  tryAdopt('new-owner-wrap', 'adopt', 'bob accepted the ownership and posted his owner wrap under the genesis-bound AD; his accepted record still answers his add at seq 1.', bob, UVK.bob, 'A-transferred', wraps.bobOwnerAfterAccept, { vaults: {}, accepted: accepted(alice, 1) });

  // ---- the extension's high-water mark (§12.2 rule 1) ----
  const served = (seq, decision = 'accept') => ({ seq, vaults: record(A, 1), accepted: accepted(alice, 1, decision) });
  tryAdopt('extension-document-at-the-mark', 'adopt', 'The extension has opened a document with in-blob seq 6 before; the served document has seq 6 and says accept: it opens the wrap.', bob, UVK.bob, 'A', wraps.bobSelf, served(6), undefined, true, 6);
  tryAdopt('extension-document-above-the-mark', 'adopt', 'The served document has seq 7, above the mark 6, and says accept: it opens.', bob, UVK.bob, 'A', wraps.bobSelf, served(7), undefined, true, 6);
  tryAdopt('extension-document-below-the-mark', 'adopt', 'The served document has seq 5, below the mark 6. The extension opens no shared-vault wrap from it, although its record says accept. (A full client that held these records as its merged state would adopt; its own rollback rule is graded in accountstate.json.)', bob, UVK.bob, 'A', wraps.bobSelf, served(5), undefined, false, 6);
  tryAdopt('extension-document-below-the-mark-decline', ['d'], 'Below the mark with a decline record: closed twice over.', bob, UVK.bob, 'A', wraps.bobSelf, served(5, 'decline'), undefined, false, 6);
  tryAdopt('extension-document-at-the-mark-decline', ['d'], 'At the mark, but the record says decline: closed, by the record.', bob, UVK.bob, 'A', wraps.bobSelf, served(6, 'decline'), undefined, false, 6);
  tryAdopt('extension-first-open-no-mark', 'adopt', 'The same document with no mark: an extension that has opened no document yet has nothing to compare with, and opens on the record alone.', bob, UVK.bob, 'A', wraps.bobSelf, served(5), undefined, true);
  tryAdopt('extension-replay-after-a-removal', ['b'], 'The attack the mark stops. bob was removed (the log says so, and a full client refuses on (b)). The server serves his account state from BEFORE the removal, seq 5 with accept, together with his old self-wrap. The extension opened seq 6, the document that recorded decline, earlier: the served one is below its mark, so the wrap stays closed.', bob, UVK.bob, 'A-removed', wraps.bobSelf, served(5), undefined, false, 6);
  tryAdopt('extension-replay-after-a-removal-no-mark', ['b'], 'The same replay against an extension with no mark (a fresh profile): it cannot tell, and opens the old wrap. That wrap holds the key bob already had (R24).', bob, UVK.bob, 'A-removed', wraps.bobSelf, served(5), undefined, true);

  return {
    _about: [
      'The genesis-bound wrap AD of design 2026-11-15-onboarding-trust §2.3 (T-B3) and the wrap path of §3.6\'s adoption conditions.',
      'Hand-authored from the independent oracle in tools/vector-gen/oracle (Node WebCrypto and @noble; no andvari code). Regenerate with `npm run generate` there; `npm run check` fails on any difference. Nonces are fixed, so every envelope reproduces.',
      'ad: the AD string for a wrap. Shared vault (owner wrap and member self-wrap): andvari/v2|vk-shared|{vaultId}|{userId}|{genesisHash}, genesisHash = H(the genesis frame of the vault\'s log), lowercase hex. The personal wrap keeps andvari/v1|vk-personal|{vaultId}|{userId}.',
      'seal: wrappedVkB64 = Envelope(key = UVK, nonce, plaintext = VK, ad) in the envelope format of spec 02 §2 (0x01 0x01, 24-byte nonce, XChaCha20-Poly1305). open: whether the envelope opens under `adUtf8`; a wrong genesis, vault, user or key is an AEAD failure and nothing more.',
      'adopt: §3.6 for a key that comes from the account\'s OWN wrap. Inputs: the account `me` with its UVK, the served log (`logs[log].frames`, or the row\'s own `frames`), the wrap from its grant row, and the two account-state records that matter: vaults[vaultId] = {genesisHash, seq, hash} and accepted[vaultId] = {owner, addSeq, at, decision}. expect.adopt is whether the device starts using the key. When it does not, expect.failed lists EVERY condition of §3.6 that does not hold, as the letters the design gives them, in alphabetical order (the design gives them no order of evaluation): a the log verifies; b this account is in the members; c the key passes the commitment; d the wrap opens under this log\'s genesis hash AND (the account is the genesis owner with no add of itself in the log, or an accepted record with decision accept answers its latest add); e the account\'s vault record agrees (no record passes).',
      'expect.extensionOpens is the same row in the Chrome and Firefox extension, by §12.2 rule 1 (FN-1): it verifies no log, takes the genesis hash from accountState.vaults[vaultId].genesisHash, and opens the wrap only when accountState.accepted[vaultId].decision is accept; it cannot check addSeq, membership or the commitment. A device that creates a vault writes accepted[vaultId] = {owner: its own account, addSeq: 0, decision: accept}, and a device that signs or verifies a leave or remove of the account writes decline (§5.4), which is what keeps the extension right.',
      'Rows with `extensionHighWater` carry the rest of that rule: the extension keeps the highest in-blob seq it has opened and opens no shared-vault wrap while the served document (accountState.seq) is below it, whatever its records say. A row without the field is an extension that has opened no document yet: it behaves as the paragraph above says. On these rows expect.adopt is still the full client\'s answer when the two records are its merged account state; the mark is the extension\'s alone.',
      'A key that comes from a grant is graded in sharedgrant-v2.json; the merges of the vaults and accepted records are in accountstate.json.',
    ],
    vaultId: ids.vault,
    vkB64: b64u(VK),
    vkCommitHex: vkCommit(VK, ids.vault),
    accounts: {
      alice: { ...describe(alice), uvkB64: b64u(UVK.alice) },
      bob: { ...describe(bob), uvkB64: b64u(UVK.bob) },
      carol: describe(carol),
      eve: describe(eve),
    },
    logs: Object.fromEntries(Object.entries(logs).map(([name, { why, log }]) => [name, { why, genesisHash: log.entries[0].hash, frames: log.frames.map(b64u) }])),
    ad,
    seal,
    open,
    adopt,
  };
}

export function grade(doc) {
  const failures = [];
  let rows = 0;
  const expect = (cond, what) => {
    rows++;
    if (!cond) failures.push(what);
  };
  const cast = { alice, bob };
  for (const row of doc.ad) {
    const made = row.kind === 'shared' ? sharedWrapAd(row.vaultId, row.userId, row.genesisHash) : personalWrapAd(row.vaultId, row.userId);
    expect(made === row.adUtf8, 'ad: ' + row.why);
  }
  for (const row of doc.seal) {
    const made = envelopeSeal(mustUnb64u(row.uvkB64), mustUnb64u(row.nonceB64), row.adUtf8, mustUnb64u(row.vkB64));
    expect(b64u(made) === row.wrappedVkB64, 'seal ' + row.name);
  }
  for (const row of doc.open) {
    const vk = envelopeOpen(mustUnb64u(row.uvkB64), row.adUtf8, mustUnb64u(row.wrappedVkB64));
    expect((vk !== null) === row.expect.opens && (vk === null || b64u(vk) === row.expect.vkB64), 'open ' + row.name);
  }
  for (const [name, log] of Object.entries(doc.logs)) {
    const frames = log.frames.map(mustUnb64u);
    expect(verifyLog({ vaultId: doc.vaultId, frames }).verdict === 'ok', 'log ' + name);
  }
  for (const row of doc.adopt) {
    const frames = (row.frames ?? doc.logs[row.log].frames).map(mustUnb64u);
    const result = adoptByWrap({ me: cast[row.me], uvk: mustUnb64u(row.uvkB64), vaultId: doc.vaultId, logFrames: frames, wrap: mustUnb64u(row.wrappedVkB64), accountState: row.accountState });
    const got = result.adopt ? { adopt: true, vkB64: b64u(result.vk) } : { adopt: false, failed: result.failed };
    got.extensionOpens = extensionOpensWrap({ me: cast[row.me], uvk: mustUnb64u(row.uvkB64), vaultId: doc.vaultId, wrap: mustUnb64u(row.wrappedVkB64), accountState: row.accountState, highWater: row.extensionHighWater ?? null });
    expect(JSON.stringify(got) === JSON.stringify(row.expect), `adopt ${row.name}: oracle says ${JSON.stringify(got)}`);
  }
  return { rows, failures };
}
