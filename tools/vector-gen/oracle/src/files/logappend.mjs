// logappend.json (server only): §3.7's access rules, as rows of stored chain, grant table, caller
// and posted frame -> wire answer.

import { b64u, mustUnb64u } from '../bytes.mjs';
import { appendAnswer, grantsAfter, describeGrants } from '../logappend.mjs';
import { verifyLog, vkCommit, ZERO_HASH, OFFER_MAX_MS } from '../vaultlog.mjs';
import { parseFrame, PURPOSE_CODES } from '../frame.mjs';
import { LogBuilder, signedRaw } from '../build.mjs';
import { alice, bob, carol, dave, eve, ids, fixed, T0, MINUTE, HOUR, DAY, describe } from '../cast.mjs';

export const file = 'logappend.json';

const LOG = PURPOSE_CODES['vault-log'];
const id16 = (label) => b64u(fixed('logappend/' + label, 16));
const VK = fixed('logappend/vk');
const COMMIT = vkCommit(VK, ids.vault);
const at = (minutes) => T0 + minutes * MINUTE;
/** The server's clock in every row. Every stored entry is before it; every posted entry is at it unless the row says otherwise. */
const NOW = T0 + 2 * HOUR;
const CAST = { alice, bob, carol, dave, eve };

const genesis = (owner, when) => ({ kind: 'genesis', actor: owner.userId, at: when, ownerKey: owner.key, vkCommit: COMMIT });
const add = (actor, when, member, role, label = member.name) => ({ kind: 'add', actor: actor.userId, at: when, member: member.userId, memberKey: member.key, role, grantId: id16('grant/' + label) });
const remove = (actor, when, member) => ({ kind: 'remove', actor: actor.userId, at: when, member: member.userId });
const leave = (actor, when) => ({ kind: 'leave', actor: actor.userId, at: when });
const offer = (actor, when, to, label, expiresAt) => ({ kind: 'offer', actor: actor.userId, at: when, to: to.userId, toKey: to.key, offerId: id16('offer/' + label), expiresAt });
const cancel = (actor, when, label) => ({ kind: 'cancel', actor: actor.userId, at: when, offerId: id16('offer/' + label) });
const accept = (actor, when, label) => ({ kind: 'accept', actor: actor.userId, at: when, offerId: id16('offer/' + label) });
const del = (actor, when, label) => ({ kind: 'delete', actor: actor.userId, at: when, deleteId: id16('delete/' + label) });
const restore = (actor, when, label) => ({ kind: 'restore', actor: actor.userId, at: when, deleteId: id16('delete/' + label) });

function buildChains() {
  const chains = {};
  const make = (name, why, steps, purged = false) => {
    const log = new LogBuilder(ids.vault);
    for (const [signer, fields] of steps) log.append(signer, fields);
    const result = verifyLog({ vaultId: ids.vault, frames: log.frames });
    if (result.verdict !== 'ok') throw new Error(`logappend chain "${name}" does not verify: ${result.verdict}`);
    chains[name] = { why, log, purged };
  };
  const live = [
    [alice, genesis(alice, at(0))],
    [alice, add(alice, at(1), bob, 'writer')],
    [alice, add(alice, at(2), carol, 'reader')],
  ];
  make('none', 'No vault has this id: nothing is stored.', []);
  make('live', 'alice created the vault and added bob as writer and carol as reader.', live);
  make('deleted', 'live, then the owner deleted the vault: every grant is revoked by the delete, and the vault is in its grace period.', [...live, [alice, del(alice, at(3), 'd1')]]);
  make('purged', 'deleted, and the grace period has ended: the server purged the vault and keeps its row as a tombstone with the log. The chain is the same four entries.', [...live, [alice, del(alice, at(3), 'd1')]], true);
  make('left', 'live, then bob left: his own entry revoked his grant.', [...live, [bob, leave(bob, at(3))]]);
  make('declined', 'alice created the vault and added bob; bob declined, which signs a leave.', [live[0], live[1], [bob, leave(bob, at(2))]]);
  make('removed', 'live, then the owner removed bob.', [...live, [alice, remove(alice, at(3), bob)]]);
  make('readded', 'removed, then the owner added bob again.', [...live, [alice, remove(alice, at(3), bob)], [alice, add(alice, at(4), bob, 'writer', 'bob-again')]]);
  make('left-in-grace', 'deleted, then bob left during the grace period: his revocation is no longer the delete\'s.', [...live, [alice, del(alice, at(3), 'd1')], [bob, leave(bob, at(4))]]);
  make('restored-after-a-leave', 'left-in-grace, then the owner restored the vault: the restore re-granted carol and skipped bob.', [...live, [alice, del(alice, at(3), 'd1')], [bob, leave(bob, at(4))], [alice, restore(alice, at(5), 'd1')]]);
  const offered = [...live, [alice, offer(alice, at(3), bob, 'o1', at(3) + 7 * DAY)]];
  make('offered', 'live, then the owner offered the vault to bob for 7 days.', offered);
  make('transferred', 'offered, then bob accepted: bob is the owner and alice a writer.', [...offered, [bob, accept(bob, at(4), 'o1')]]);
  return chains;
}

const flip = (frame) => {
  const out = frame.slice();
  out[37 + 10] ^= 0x01;
  return out;
};

function buildRows(chains) {
  const rows = [];
  const names = new Set();
  /**
   * `entry` is a `signed` result or { frame, note }. `expected` is the wire answer the design gives;
   * the builder checks that the oracle's model of §3.7 returns exactly that before the row is written.
   */
  const post = (name, chainName, caller, entry, expected, why) => {
    const stored = chains[chainName].log.frames;
    const frame = entry.frame;
    const got = appendAnswer({ vaultId: ids.vault, stored, purged: chains[chainName].purged, caller: { userId: caller.userId, identityPub: caller.identityPub }, frame });
    if (JSON.stringify(got) !== JSON.stringify(expected)) throw new Error(`logappend "${name}": the design says ${JSON.stringify(expected)}, the oracle says ${JSON.stringify(got)}`);
    if (names.has(name)) throw new Error('logappend: duplicate row ' + name);
    names.add(name);
    const row = { name, why, stored: chainName, caller: caller.name };
    const parsed = parseFrame(frame, LOG);
    if (parsed.verdict === 'ok') row.entry = parsed.values;
    else if (entry.note) row.entryNote = entry.note;
    row.frameB64 = b64u(frame);
    row.expect = expected;
    if (expected.status === 200 && expected.appended) {
      // Step 8 is outside this file: make sure the row passes it at the server's clock `now`.
      const e = parsed.values;
      if (e.at > NOW + 10 * MINUTE) throw new Error(`logappend "${name}": at is ahead of the server's ceiling`);
      if (e.kind === 'offer' && !(NOW < e.expiresAt && e.expiresAt <= NOW + OFFER_MAX_MS)) throw new Error(`logappend "${name}": the offer is outside the server's window`);
      if (e.kind === 'accept') {
        const before = verifyLog({ vaultId: ids.vault, frames: stored }).states.at(-1);
        if (!(NOW < before.pending.expiresAt)) throw new Error(`logappend "${name}": the offer has expired by the server's clock`);
      }
      row.grantsAfter = describeGrants(grantsAfter([...stored, frame]));
    }
    rows.push(row);
  };
  const ok = { status: 200, appended: true };
  const retry = { status: 200, appended: false };
  const refuse = (status, error) => ({ status, error });
  const moved = (chainName) => {
    const head = chains[chainName].log.head;
    return { status: 409, error: 'log_head_moved', seq: head.seq, hash: head.hash, at: head.at };
  };
  const draft = (chainName, signer, fields, overrides) => chains[chainName].log.draft(signer, fields, overrides);
  const storedEntry = (chainName, index) => chains[chainName].log.entries[index];
  const live = chains.live.log;

  // ---- the plain cases ----
  post('owner-adds-a-member', 'live', alice, draft('live', alice, add(alice, NOW, dave, 'reader')), ok, 'The owner appends an add at the stored head plus one.');
  post('member-leaves', 'live', bob, draft('live', bob, leave(bob, NOW)), ok, 'A member appends its own leave: any member may. The entry\'s effect revokes its grant.');
  post('genesis-creates-the-vault', 'none', alice, draft('none', alice, genesis(alice, NOW)), ok, 'A genesis for an unused vault id: there is no vault and no grant to resolve.');

  // ---- step 5: retry before access (FC-1) ----
  post('retried-add', 'live', alice, storedEntry('live', 1), retry, 'A frame byte-identical to one already stored, posted again by its actor: 200, and nothing changes. The stored frame need not be the head.');
  post('retried-genesis', 'live', alice, storedEntry('live', 0), retry, 'The stored genesis posted again by its creator: the retry rule comes before the genesis rule, so this is 200, not vault_id_taken.');
  post('retried-delete', 'deleted', alice, storedEntry('deleted', 3), retry, 'A retried byte-identical delete: 200, although the delete revoked the owner\'s own grant.');
  post('retried-leave', 'left', bob, storedEntry('left', 3), retry, 'A retried leave whose own effect revoked the caller\'s grant: 200, before any grant check.');
  post('retried-decline', 'declined', bob, storedEntry('declined', 2), retry, 'A decline is a leave. Its retry gets the same 200.');
  post('retried-leave-in-grace', 'left-in-grace', bob, storedEntry('left-in-grace', 4), retry, 'The retry of a leave that was appended during the grace period.');
  post('retried-leave-after-the-restore', 'restored-after-a-leave', bob, storedEntry('restored-after-a-leave', 4), retry, 'The same stored leave posted again after the owner restored the vault: still a byte-identical stored frame from its actor.');
  post('stored-frame-posted-by-another-account', 'live', dave, storedEntry('live', 1), refuse(400, 'bad_signer'), 'A stored frame posted by an account that is not its actor. The retry rule needs actor = the caller, which step 4 checks first: bad_signer, and a non-member learns nothing.');

  // ---- step 5: no grant ----
  post('non-member-post', 'live', dave, draft('live', dave, leave(dave, NOW)), refuse(403, 'no_grant'), 'A non-member posts an entry at the right position: no_grant, with no head in the answer. (The verifier would say precondition; it is never reached.)');
  post('non-member-post-at-a-stale-position', 'live', dave, draft('live', dave, leave(dave, NOW), { seq: 1, prev: live.entries[0].hash }), refuse(403, 'no_grant'),
    'A non-member posts at a position that is not the head plus one. Access (step 5) comes before position (step 6), so the answer is no_grant and carries no head: a non-member never learns it.');
  post('non-member-posts-an-owner-kind', 'live', dave, draft('live', dave, add(dave, NOW, eve, 'reader')), refuse(403, 'no_grant'), 'A non-member posts an add as itself: the grant is resolved before the role, so no_grant, not not_vault_owner.');
  post('unknown-vault', 'none', alice, draft('live', alice, add(alice, NOW, dave, 'reader')), refuse(403, 'no_grant'), 'An entry other than a genesis for a vault id that does not exist: no_grant, the same answer a non-member gets.');
  post('removed-member-posts', 'removed', bob, draft('removed', bob, leave(bob, NOW)), refuse(403, 'no_grant'), 'bob was removed. A grant revoked for any reason but the vault\'s delete never counts.');
  post('removed-member-posts-at-a-stale-position', 'removed', bob, draft('removed', bob, leave(bob, NOW), { seq: 3, prev: chains.removed.log.entries[1].hash }), refuse(403, 'no_grant'),
    'The removed member at a stale position: still no_grant, and no head.');
  post('resigned-leave', 'left', bob, draft('left', bob, leave(bob, NOW)), refuse(403, 'no_grant'), 'bob\'s leave is stored. He signs ANOTHER leave (a new `at`) instead of re-posting the same bytes: it is not a retry, and his grant is revoked by his own leave.');
  post('readded-member-leaves', 'readded', bob, draft('readded', bob, leave(bob, NOW)), ok, 'bob was removed and added again: the add re-activated his grant.');

  // ---- step 5: the role ----
  post('writer-adds', 'live', bob, draft('live', bob, add(bob, NOW, dave, 'reader')), refuse(403, 'not_vault_owner'), 'A writer posts an add: the caller has a grant, but its role does not allow the kind.');
  post('reader-deletes', 'live', carol, draft('live', carol, del(carol, NOW, 'd9')), refuse(403, 'not_vault_owner'), 'A reader posts a delete.');
  post('writer-restores-a-live-vault', 'live', bob, draft('live', bob, restore(bob, NOW, 'd1')), refuse(403, 'not_vault_owner'), 'A writer posts a restore on a vault that is not deleted: its grant is active, so the role decides. Compare non-owner-restores-while-deleted.');

  // ---- step 5 on a deleted vault (N13, FC-1) ----
  post('owner-restores-a-deleted-vault', 'deleted', alice, draft('deleted', alice, restore(alice, NOW, 'd1')), ok, 'The owner\'s grant is revoked by the delete; it counts for restore. The restore re-grants every grant still revoked by the delete.');
  post('second-different-delete', 'deleted', alice, draft('deleted', alice, del(alice, NOW, 'd2')), refuse(400, 'precondition'), 'A second delete with another deleteId, at the head plus one. The owner\'s revoked grant counts for delete, the position is right, and the shared verifier refuses it: the vault is already deleted.');
  post('resigned-delete-at-the-stored-position', 'deleted', alice, draft('deleted', alice, del(alice, NOW, 'd1'), { seq: 3, prev: chains.deleted.log.entries[2].hash }), moved('deleted'),
    'The owner re-signs its delete with a new `at` for the position the stored delete holds: not a retry (other bytes), and another entry at a stored position is log_head_moved, with the stored head.');
  post('member-leaves-in-the-grace-period', 'deleted', bob, draft('deleted', bob, leave(bob, NOW)), ok, 'A member\'s grant revoked by the delete counts for leave. Appending it rewrites the revocation, so a later restore skips this member (FI-R7).');
  post('reader-leaves-in-the-grace-period', 'deleted', carol, draft('deleted', carol, leave(carol, NOW)), ok, 'The same for the reader.');
  post('non-owner-restores-while-deleted', 'deleted', bob, draft('deleted', bob, restore(bob, NOW, 'd1')), refuse(403, 'no_grant'), 'A grant revoked by the delete counts for restore only when it is the owner\'s. A writer\'s does not count: no_grant, not not_vault_owner.');
  post('non-owner-deletes-while-deleted', 'deleted', bob, draft('deleted', bob, del(bob, NOW, 'd2')), refuse(403, 'no_grant'), 'The same for a delete by a non-owner.');
  post('owner-adds-while-deleted', 'deleted', alice, draft('deleted', alice, add(alice, NOW, dave, 'reader')), refuse(403, 'no_grant'), 'The owner\'s revoked grant counts for restore and delete, and for no other owner kind: an add on a deleted vault is no_grant. (The verifier would say precondition; access comes first.)');
  post('owner-restores-with-another-delete-id', 'deleted', alice, draft('deleted', alice, restore(alice, NOW, 'd2')), refuse(400, 'precondition'), 'A restore that names another deleteId than the stored delete: the grant counts, the verifier refuses.');
  post('non-member-post-on-a-deleted-vault', 'deleted', dave, draft('deleted', dave, leave(dave, NOW)), refuse(403, 'no_grant'), 'A non-member\'s post on a deleted vault.');
  post('owner-restores-after-a-leave-in-grace', 'left-in-grace', alice, draft('left-in-grace', alice, restore(alice, NOW, 'd1')), ok, 'bob left during the grace period. The restore re-grants carol and the owner; bob stays out.');
  post('leaver-stays-out-after-the-restore', 'restored-after-a-leave', bob, draft('restored-after-a-leave', bob, leave(bob, NOW)), refuse(403, 'no_grant'), 'After the restore, the member who left in the grace period has no grant.');
  post('other-member-is-back-after-the-restore', 'restored-after-a-leave', carol, draft('restored-after-a-leave', carol, leave(carol, NOW)), ok, 'carol, whose grant the restore re-activated, posts as a member again.');

  // ---- after the purge ----
  post('owner-restores-after-the-purge', 'purged', alice, draft('purged', alice, restore(alice, NOW, 'd1')), refuse(403, 'no_grant'), 'The grace period has ended and the vault is purged. Every append other than a genesis is refused with no_grant, the owner\'s restore included: the exception for a grant revoked by the delete holds only before the purge. Compare owner-restores-a-deleted-vault.');
  post('member-leaves-after-the-purge', 'purged', bob, draft('purged', bob, leave(bob, NOW)), refuse(403, 'no_grant'), 'A member\'s leave after the purge: no_grant. Compare member-leaves-in-the-grace-period.');
  post('owner-deletes-after-the-purge', 'purged', alice, draft('purged', alice, del(alice, NOW, 'd2')), refuse(403, 'no_grant'), 'A second delete after the purge: no_grant, where before the purge it was precondition.');
  post('non-member-post-after-the-purge', 'purged', dave, draft('purged', dave, leave(dave, NOW)), refuse(403, 'no_grant'), 'A non-member\'s post on a purged vault: the same no_grant.');
  post('retried-delete-after-the-purge', 'purged', alice, storedEntry('purged', 3), retry, 'A byte-identical retry of a stored frame after the purge: the retry rule comes first and changes nothing, so it is still 200.');
  post('genesis-for-a-purged-vault-id', 'purged', dave, draft('none', dave, genesis(dave, NOW)), refuse(409, 'vault_id_taken'), 'A vault id is never reused: a genesis for the id of a purged vault is vault_id_taken, as for a live one.');

  // ---- step 5: genesis ----
  post('genesis-for-a-vault-id-in-use', 'live', dave, draft('none', dave, genesis(dave, NOW)), refuse(409, 'vault_id_taken'), 'Another account posts a genesis for a vault id that exists.');
  post('resigned-genesis', 'live', alice, draft('none', alice, genesis(alice, NOW)), refuse(409, 'vault_id_taken'), 'The creator signs a NEW genesis (another `at`) for its own vault id: other bytes, so not a retry.');

  // ---- step 6: position, for a member ----
  post('member-at-a-stale-position', 'live', alice, draft('live', alice, add(alice, NOW, dave, 'reader'), { seq: 2, prev: live.entries[1].hash }), moved('live'),
    'The owner posts at the position the stored head already holds: log_head_moved with the stored head {seq, hash, at}. Compare non-member-post-at-a-stale-position.');
  post('member-ahead-of-the-head', 'live', alice, draft('live', alice, add(alice, NOW, dave, 'reader'), { seq: 4 }), moved('live'), 'seq is the head plus two.');
  post('member-with-another-prev', 'live', alice, draft('live', alice, add(alice, NOW, dave, 'reader'), { prev: live.entries[1].hash }), moved('live'), 'seq is the head plus one, but prev is not the stored head\'s hash.');

  // ---- step 7: the shared verifier's verdicts on the wire ----
  post('add-of-a-member', 'live', alice, draft('live', alice, add(alice, NOW, bob, 'reader', 'bob-twice')), refuse(400, 'precondition'), 'The owner adds an account that is already a member: the verifier\'s precondition.');
  post('accept-without-an-offer', 'live', bob, draft('live', bob, accept(bob, NOW, 'o1')), refuse(400, 'precondition'), 'A member posts an accept while no offer is pending.');
  post('at-before-the-head', 'live', alice, draft('live', alice, add(alice, at(1), dave, 'reader')), refuse(400, 'precondition'), '`at` is earlier than the stored head\'s: `at` never decreases along a log.');
  post('owner-leaves', 'live', alice, draft('live', alice, leave(alice, NOW)), refuse(400, 'precondition'), 'The owner posts a leave: any member may post the kind, and the verifier refuses the owner\'s.');
  post('target-accepts', 'offered', bob, draft('offered', bob, accept(bob, NOW, 'o1')), ok, 'The offer\'s target accepts: the old owner\'s grant becomes writer and the target\'s becomes owner.');
  post('target-cancels', 'offered', bob, draft('offered', bob, cancel(bob, NOW, 'o1')), ok, 'The offer\'s target cancels it.');
  post('owner-cancels', 'offered', alice, draft('offered', alice, cancel(alice, NOW, 'o1')), ok, 'The owner cancels its offer.');
  post('bystander-cancels', 'offered', carol, draft('offered', carol, cancel(carol, NOW, 'o1')), refuse(403, 'not_vault_owner'), 'A member who is neither the owner nor the target posts a cancel. Any member may post the kind, so step 5 passes; the verifier says not_authorized, which reaches the wire as not_vault_owner.');
  post('bystander-accepts', 'offered', carol, draft('offered', carol, accept(carol, NOW, 'o1')), refuse(403, 'not_vault_owner'), 'A member who is not the target posts an accept: the verifier\'s not_authorized, as not_vault_owner.');
  post('old-owner-adds-after-the-transfer', 'transferred', alice, draft('transferred', alice, add(alice, NOW, dave, 'reader')), refuse(403, 'not_vault_owner'), 'alice handed the vault to bob: her server-side role is writer now.');
  post('new-owner-adds-after-the-transfer', 'transferred', bob, draft('transferred', bob, add(bob, NOW, dave, 'reader')), ok, 'The new owner adds a member.');
  post('genesis-naming-another-owner-key', 'none', alice, draft('none', alice, { ...genesis(alice, NOW), ownerKey: bob.key }), refuse(403, 'not_vault_owner'),
    'A genesis signed by the caller that names another account\'s key as ownerKey. Steps 4 to 6 pass; the verifier wants the genesis signed by its own ownerKey: not_authorized, as not_vault_owner.');

  // ---- steps 3 and 4, and their place before step 5 ----
  const next = draft('live', alice, add(alice, NOW, dave, 'reader'));
  post('frame-of-another-purpose', 'live', alice, { frame: signedRaw(PURPOSE_CODES['instance-card'], alice, next.statement).frame, note: 'the vault-log statement framed and signed under purpose 0x04' }, refuse(400, 'bad_frame'), 'A frame of another purpose than 0x03.');
  const otherMagic = next.frame.slice();
  otherMagic[3] = 0x03;
  post('frame-with-another-magic', 'live', alice, { frame: otherMagic, note: 'the entry with format byte 0x03 in its magic' }, refuse(400, 'bad_frame'), 'unknown_format reaches the wire as bad_frame.');
  post('frame-truncated', 'live', alice, { frame: next.frame.slice(0, 60), note: 'the first 60 bytes of the entry' }, refuse(400, 'bad_frame'), 'A frame shorter than the shortest frame.');
  post('statement-not-canonical', 'live', alice, { frame: signedRaw(LOG, alice, next.statement.replace('"seq":', '"seq": ')).frame, note: 'the entry signed with a space after a colon' }, refuse(400, 'non_canonical'), 'A statement that is not canonical.');
  post('statement-version-3', 'live', alice, { frame: signedRaw(LOG, alice, next.statement.replace('{"v":2,', '{"v":3,')).frame, note: 'the entry signed with "v":3' }, refuse(400, 'bad_statement'), 'A canonical statement with another v.');
  post('entry-for-another-vault', 'live', alice, draft('live', alice, add(alice, NOW, dave, 'reader'), { vaultId: ids.otherVault }), refuse(400, 'wrong_vault'), 'The frame names another vault than the path.');
  post('actor-is-not-the-caller', 'live', bob, next, refuse(400, 'bad_signer'), 'bob posts an entry whose actor is alice (her valid next entry, never stored).');
  post('signed-with-another-key', 'live', bob, draft('live', eve, leave(bob, NOW)), refuse(400, 'bad_signer'), 'The actor is the caller, but the frame is signed with another account\'s key: the signer does not map to the caller\'s stored identity key.');
  post('signature-does-not-verify', 'live', alice, { frame: flip(next.frame), note: 'alice\'s next entry with one signature bit flipped' }, refuse(400, 'bad_signature'), 'The actor and the signer key are the caller\'s; the signature does not verify.');
  post('order-signer-before-signature', 'live', bob, { frame: flip(next.frame), note: 'alice\'s next entry with one signature bit flipped' }, refuse(400, 'bad_signer'), 'An actor that is not the caller, and a broken signature: bad_signer comes first.');
  post('order-frame-before-access', 'live', dave, { frame: signedRaw(LOG, dave, draft('live', dave, leave(dave, NOW)).statement.replace('"seq":', '"seq": ')).frame, note: 'a non-member\'s leave signed with a space after a colon' }, refuse(400, 'non_canonical'), 'A non-member posts a frame that is not canonical: step 3 comes before step 5.');
  post('order-vault-before-signer', 'live', bob, draft('live', alice, add(alice, NOW, dave, 'reader'), { vaultId: ids.otherVault }), refuse(400, 'wrong_vault'), 'Another vault in the frame, and an actor that is not the caller: wrong_vault comes first.');
  post('order-signer-before-access', 'live', dave, next, refuse(400, 'bad_signer'), 'A non-member posts the owner\'s entry: step 4 comes before step 5, so bad_signer, not no_grant.');
  return rows;
}

export function build() {
  const chains = buildChains();
  return {
    _about: [
      'The server\'s access rules for POST /api/v1/vaults/{vaultId}/log (design 2026-11-15-onboarding-trust §3.7, FC-1; spec 03 §10.3 and §10.4). Server-only: the JVM suite grades it, no client does.',
      'Hand-authored from the independent oracle in tools/vector-gen/oracle (Node WebCrypto and @noble; no andvari code). Regenerate with `npm run generate` there; `npm run check` fails on any difference.',
      'A row: the vault `vaultId` holds the chain `chains[stored]` (frames in order; `none` is a vault id nobody has used); the server\'s grant table is `chains[stored].grants`; `chains[stored].purged` says whether the vault\'s grace period has ended and the server purged it (the log is kept with the tombstone); the account `caller` posts `frameB64` as `entry`; `expect` is the wire answer. `entry`, where present, is the parsed statement, for reading.',
      'expect: { status, error } for a refusal. A log_head_moved answer carries the stored head as seq, hash and at; NO other answer carries a head, and no_grant in particular never does. { status: 200, appended } for a success: appended true means the entry was stored at the head plus one, and `grantsAfter` is then the grant table after its effect; appended false is the retry answer, a 200 that changes nothing.',
      'grants: one row per account that has ever held a grant: { userId, role, revokedBy }. revokedBy is null for an active grant, or the kind of the entry that revoked it: "delete" (the revocation the design calls reason vault_delete), "leave" or "remove". The server\'s own reason names are not graded. A harness that builds the state by posting the chain\'s frames in order, each as its actor, can assert this table.',
      'The checks, in the design\'s order. Step 3: the strict parse and purpose 0x03 (bad_frame, also for unknown_format; non_canonical; bad_statement), then the frame\'s vaultId against the path (wrong_vault). Step 4: the actor is the caller and the signer maps to the caller\'s stored identity key (bad_signer), then the signature (bad_signature). Step 5: a frame byte-identical to a stored one answers 200 before any grant check; a genesis needs an unused vault id (409 vault_id_taken); every other kind needs the caller\'s grant (403 no_grant, also for an unknown vault), where a grant revoked by the vault\'s delete counts for restore and delete by the owner and for leave, a grant revoked for any other reason never counts, and after the purge no grant counts at all (every append but a genesis is 403 no_grant, the owner\'s restore included; the retry of a stored frame is still 200); then the role must allow the kind (403 not_vault_owner: add, role, remove, offer, delete and restore need owner). Step 6: seq and prev are the stored head plus one (409 log_head_moved). Step 7: the shared verifier, whose not_authorized is 403 not_vault_owner and whose precondition is 400 precondition.',
      'Outside this file: the session and the body caps with the side data a kind takes (the harness sends well-formed metaBlob, wrappedVk and grant where the kind needs them), the rate buckets, and step 8. Every row is built to pass step 8: the server\'s clock is `now`, every stored `at` is before it, every posted `at` is at it or earlier, the stored offer expires after it, and every account of the cast is active, connected to the owner and under its limits.',
    ],
    vaultId: ids.vault,
    otherVaultId: ids.otherVault,
    now: NOW,
    accounts: Object.fromEntries(Object.entries(CAST).map(([name, a]) => [name, describe(a)])),
    chains: Object.fromEntries(Object.entries(chains).map(([name, { why, log, purged }]) => [name, {
      why,
      purged,
      frames: log.frames.map(b64u),
      entries: log.entries.map((e) => ({ seq: e.values.seq, kind: e.values.kind, actor: e.values.actor, at: e.values.at, hash: e.hash })),
      head: log.head,
      grants: describeGrants(grantsAfter(log.frames)),
    }])),
    rows: buildRows(chains),
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
  for (const [name, chain] of Object.entries(doc.chains)) {
    const frames = chain.frames.map(mustUnb64u);
    const result = verifyLog({ vaultId: doc.vaultId, frames });
    const head = result.verdict === 'ok' && result.states.length ? result.states.at(-1).head : null;
    expect(result.verdict === 'ok' && same(head, chain.head) && same(describeGrants(grantsAfter(frames)), chain.grants), `chain ${name}`);
  }
  const names = new Set();
  for (const row of doc.rows) {
    expect(!names.has(row.name), `row ${row.name}: duplicate name`);
    names.add(row.name);
    const stored = doc.chains[row.stored].frames.map(mustUnb64u);
    const account = doc.accounts[row.caller];
    const frame = mustUnb64u(row.frameB64);
    const got = appendAnswer({ vaultId: doc.vaultId, stored, purged: doc.chains[row.stored].purged, caller: { userId: account.userId, identityPub: mustUnb64u(account.identityPubB64) }, frame });
    expect(same(got, row.expect), `row ${row.name}: oracle says ${JSON.stringify(got)}`);
    if (row.grantsAfter !== undefined) expect(same(describeGrants(grantsAfter([...stored, frame])), row.grantsAfter), `row ${row.name}: grantsAfter`);
    expect((row.grantsAfter !== undefined) === (row.expect.status === 200 && row.expect.appended === true), `row ${row.name}: grantsAfter only on an append`);
  }
  return { rows, failures };
}

export { ZERO_HASH };
