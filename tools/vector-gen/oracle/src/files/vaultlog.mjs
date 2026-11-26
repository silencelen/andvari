// vaultlog.json: chains with the state after every entry, one rejection per condition of §3.3, the
// order of the checks, forks, and the key commitment of §3.4.

import { b64u, mustUnb64u, utf8 } from '../bytes.mjs';
import { verifyLog, vkCommit, compareWithHead, OFFER_MAX_MS, ZERO_HASH } from '../vaultlog.mjs';
import { assembleFrame, frameHash, PURPOSE_CODES } from '../frame.mjs';
import { LogBuilder, signed, signedRaw, tokens, withToken, rawStatement, nameOf } from '../build.mjs';
import { alice, bob, carol, dave, eve, operator, ids, fixed, T0, MINUTE, HOUR, DAY, MAX_MS, describe } from '../cast.mjs';
import { nearZeroKey } from '../keyfloor.mjs';

export const file = 'vaultlog.json';

const LOG = PURPOSE_CODES['vault-log'];
const id16 = (label) => b64u(fixed('vaultlog/' + label, 16));
const VK = fixed('vaultlog/vk');
const OTHER_VK = fixed('vaultlog/other-vk');
const COMMIT = vkCommit(VK, ids.vault);
const at = (minutes) => T0 + minutes * MINUTE;

const genesis = (owner, when) => ({ kind: 'genesis', actor: owner.userId, at: when, ownerKey: owner.key, vkCommit: COMMIT });
const add = (actor, when, member, role, grantLabel) => ({
  kind: 'add', actor: actor.userId, at: when, member: member.userId, memberKey: member.key, role, grantId: id16('grant/' + grantLabel),
});
const role = (actor, when, member, newRole) => ({ kind: 'role', actor: actor.userId, at: when, member: member.userId, role: newRole });
const remove = (actor, when, member) => ({ kind: 'remove', actor: actor.userId, at: when, member: member.userId });
const leave = (actor, when) => ({ kind: 'leave', actor: actor.userId, at: when });
const offer = (actor, when, to, offerLabel, expiresAt) => ({
  kind: 'offer', actor: actor.userId, at: when, to: to.userId, toKey: to.key, offerId: id16('offer/' + offerLabel), expiresAt,
});
const cancel = (actor, when, offerLabel) => ({ kind: 'cancel', actor: actor.userId, at: when, offerId: id16('offer/' + offerLabel) });
const accept = (actor, when, offerLabel) => ({ kind: 'accept', actor: actor.userId, at: when, offerId: id16('offer/' + offerLabel) });
const del = (actor, when, deleteLabel) => ({ kind: 'delete', actor: actor.userId, at: when, deleteId: id16('delete/' + deleteLabel) });
const restore = (actor, when, deleteLabel) => ({ kind: 'restore', actor: actor.userId, at: when, deleteId: id16('delete/' + deleteLabel) });

function buildChains() {
  const chains = {};
  const make = (name, why, steps) => {
    const log = new LogBuilder(ids.vault);
    const notes = [];
    for (const [signer, fields, note] of steps) {
      log.append(signer, fields);
      notes.push(note);
    }
    chains[name] = { name, why, log, notes };
  };

  make('lifecycle', 'Every kind once, with an ownership transfer in the middle: after the accept the new owner signs.', [
    [alice, genesis(alice, at(0)), 'alice creates the vault'],
    [alice, add(alice, at(1), bob, 'writer', 'bob'), 'the owner adds bob as writer'],
    [alice, add(alice, at(2), carol, 'reader', 'carol'), 'the owner adds carol as reader'],
    [alice, role(alice, at(3), carol, 'writer'), 'carol becomes a writer'],
    [alice, offer(alice, at(4), bob, 'o1', at(4) + 7 * DAY), 'the owner offers the vault to bob for 7 days'],
    [alice, cancel(alice, at(5), 'o1'), 'the owner cancels the offer'],
    [alice, offer(alice, at(6), bob, 'o2', at(6) + OFFER_MAX_MS), 'a second offer, with the longest lifetime allowed: at + 14 d + 10 min'],
    [bob, accept(bob, at(7), 'o2'), 'bob accepts: bob is the owner, alice becomes a writer'],
    [bob, remove(bob, at(8), carol), 'the new owner removes carol'],
    [alice, leave(alice, at(9)), 'the former owner, now a writer, leaves'],
    [bob, del(bob, at(10), 'd1'), 'the owner deletes the vault'],
    [bob, restore(bob, at(11), 'd1'), 'the owner restores it'],
    [bob, add(bob, at(12), dave, 'reader', 'dave'), 'the owner adds dave'],
  ]);

  make('offer-paths', 'Every way a pending offer ends other than accept: cancel by the target, a role change of the target, its removal, its leaving.', [
    [alice, genesis(alice, at(0)), 'alice creates the vault'],
    [alice, add(alice, at(1), bob, 'writer', 'bob'), 'add bob'],
    [alice, add(alice, at(2), carol, 'writer', 'carol'), 'add carol'],
    [alice, offer(alice, at(3), bob, 'o1', at(3) + DAY), 'offer to bob'],
    [bob, cancel(bob, at(4), 'o1'), 'the target cancels, signing with the key the offer named'],
    [alice, offer(alice, at(5), carol, 'o2', at(5) + DAY), 'offer to carol'],
    [alice, role(alice, at(6), carol, 'reader'), 'a role change of the target clears the offer'],
    [alice, offer(alice, at(7), carol, 'o3', at(7) + DAY), 'offer to carol again'],
    [alice, remove(alice, at(8), carol), 'removing the target clears the offer'],
    [alice, offer(alice, at(9), bob, 'o4', at(9) + DAY), 'offer to bob'],
    [bob, leave(bob, at(10)), 'the target leaves: the offer is cleared'],
  ]);

  const e1 = at(2) + 1;
  const e2 = e1 + 1 + HOUR;
  const e3 = e2 + 1 + HOUR;
  make('expiry', 'The time rules: equal `at` values, the shortest offer, an entry at the expiry instant, clearing by a later entry, a new offer over an expired one, accept at the last instant.', [
    [alice, genesis(alice, at(0)), 'alice creates the vault'],
    [alice, add(alice, at(0), bob, 'writer', 'bob'), 'same `at` as the entry before: allowed, `at` only must not decrease'],
    [alice, add(alice, at(1), carol, 'writer', 'carol'), 'add carol'],
    [alice, offer(alice, at(2), bob, 'o1', e1), 'the shortest offer: expiresAt = at + 1'],
    [alice, role(alice, e1, carol, 'reader'), 'an entry with at = expiresAt: the offer is not cleared (only at > expiresAt clears)'],
    [alice, role(alice, e1 + 1, carol, 'writer'), 'an entry with at = expiresAt + 1: the expired offer is cleared before the entry is applied'],
    [alice, offer(alice, e1 + 1, carol, 'o2', e2), 'a new offer, to carol, for an hour'],
    [alice, offer(alice, e2 + 1, bob, 'o3', e3), 'an offer while another is pending but expired (pending.expiresAt < at): allowed, it replaces it'],
    [bob, accept(bob, e3, 'o3'), 'accept with at = expiresAt: still in time'],
  ]);

  make('deleted', 'A deleted vault: the pending offer is cleared, a member can still leave, and the leaver stays out after the restore.', [
    [alice, genesis(alice, at(0)), 'alice creates the vault'],
    [alice, add(alice, at(1), bob, 'writer', 'bob'), 'add bob'],
    [alice, add(alice, at(2), carol, 'reader', 'carol'), 'add carol'],
    [alice, offer(alice, at(3), bob, 'o1', at(3) + DAY), 'offer to bob'],
    [alice, del(alice, at(4), 'd1'), 'delete: deleted = {d1}, and the pending offer is cleared'],
    [carol, leave(carol, at(5)), 'carol leaves while the vault is deleted (B2)'],
    [alice, restore(alice, at(6), 'd1'), 'restore: carol stays out'],
    [alice, del(alice, at(7), 'd2'), 'delete again, with a new deleteId'],
    [alice, restore(alice, at(8), 'd2'), 'restore again'],
  ]);

  make('max-at', 'T2-R-a: the shared verifier has no clock. A leave dated 2^53 - 1 is accepted; later entries can only carry that same `at`.', [
    [alice, genesis(alice, at(0)), 'alice creates the vault'],
    [alice, add(alice, at(1), bob, 'writer', 'bob'), 'add bob'],
    [alice, add(alice, at(2), carol, 'writer', 'carol'), 'add carol'],
    [bob, leave(bob, MAX_MS), 'bob leaves with at = 2^53 - 1 = 9007199254740991: the verifier ACCEPTS it (the 10-minute ceiling is the server\'s, 400 at_ahead)'],
    [alice, role(alice, MAX_MS, carol, 'reader'), 'the log is not dead: an entry with the same `at` still verifies'],
  ]);

  return chains;
}

function describeEntry(entry, state, note) {
  return {
    why: note,
    signer: entry.signer.name,
    statementUtf8: entry.statement,
    frameB64: b64u(entry.frame),
    hash: entry.hash,
    state,
  };
}

/** Flip one bit of the signature (byte 37 of the frame is its first byte). */
function flipSignature(frame) {
  const out = frame.slice();
  out[37 + 10] ^= 0x01;
  return out;
}

function buildRejects(chains) {
  const rows = [];
  /**
   * `make(log)` returns the offending frame (a `signed` result, or raw bytes) for a LogBuilder holding
   * the first `after` entries of `chain`. `verdict` is what the design says; the builder checks that
   * the oracle's verifier returns exactly that before the row is written.
   */
  const reject = (name, verdict, chain, after, why, make, options = {}) => {
    const log = chains[chain].log.prefix(after);
    const made = make(log);
    const frame = made.frame ?? made;
    const vaultId = options.vaultId ?? ids.vault;
    const result = verifyLog({ vaultId, frames: [...log.frames, frame] });
    if (result.verdict !== verdict || result.failedAt !== after) {
      throw new Error(`vaultlog reject "${name}": the design says ${verdict} at ${after}, the oracle verifier says ${result.verdict} at ${result.failedAt}`);
    }
    const row = { name, why, chain, after };
    if (options.vaultId) row.vaultId = options.vaultId;
    if (made.signer) row.signer = made.signer.name;
    if (options.signerNote) row.signer = options.signerNote;
    if (made.statement !== undefined) row.statementUtf8 = made.statement;
    row.frameB64 = b64u(frame);
    row.expect = { verdict };
    rows.push(row);
  };
  const next = (log) => log.head.at + MINUTE;

  // ---- add ----
  reject('add-by-member', 'not_authorized', 'lifecycle', 3, 'A non-owner add: bob, a writer, adds dave and signs as himself.',
    (log) => log.draft(bob, add(bob, next(log), dave, 'reader', 'dave')));
  reject('add-owner-named-member-signed', 'not_authorized', 'lifecycle', 3, 'The statement names the owner as actor, but bob\'s key signed it.',
    (log) => log.draft(bob, add(alice, next(log), dave, 'reader', 'dave')));
  reject('add-owner-signed-member-named', 'not_authorized', 'lifecycle', 3, 'The owner\'s key signed, but the actor is bob: the actor must be the owner.',
    (log) => log.draft(alice, add(bob, next(log), dave, 'reader', 'dave')));
  reject('add-by-outsider', 'not_authorized', 'lifecycle', 3, 'eve, who is not in the vault, adds herself.',
    (log) => log.draft(eve, add(eve, next(log), eve, 'writer', 'eve')));
  reject('add-existing-member', 'precondition', 'lifecycle', 3, 'The owner adds bob, who is already a member.',
    (log) => log.draft(alice, add(alice, next(log), bob, 'reader', 'bob-again')));
  reject('add-the-owner', 'precondition', 'lifecycle', 3, 'The owner adds herself: the owner is in members.',
    (log) => log.draft(alice, add(alice, next(log), alice, 'writer', 'alice')));
  reject('add-after-delete', 'precondition', 'deleted', 5, 'add after delete: the vault is deleted.',
    (log) => log.draft(alice, add(alice, next(log), dave, 'reader', 'dave')));

  // ---- role ----
  reject('role-by-member', 'not_authorized', 'lifecycle', 3, 'bob, a writer, changes carol\'s role.',
    (log) => log.draft(bob, role(bob, next(log), carol, 'writer')));
  reject('role-of-non-member', 'precondition', 'lifecycle', 3, 'A role change for dave, who is not a member.',
    (log) => log.draft(alice, role(alice, next(log), dave, 'writer')));
  reject('role-of-owner', 'precondition', 'lifecycle', 3, 'A role change for the owner.',
    (log) => log.draft(alice, role(alice, next(log), alice, 'writer')));
  reject('role-after-delete', 'precondition', 'deleted', 5, 'A role change while the vault is deleted.',
    (log) => log.draft(alice, role(alice, next(log), carol, 'writer')));

  // ---- remove ----
  reject('remove-by-member', 'not_authorized', 'lifecycle', 3, 'bob, a writer, removes carol.',
    (log) => log.draft(bob, remove(bob, next(log), carol)));
  reject('remove-non-member', 'precondition', 'lifecycle', 3, 'Removing dave, who is not a member.',
    (log) => log.draft(alice, remove(alice, next(log), dave)));
  reject('remove-the-owner', 'precondition', 'lifecycle', 3, 'The owner removes herself.',
    (log) => log.draft(alice, remove(alice, next(log), alice)));
  reject('remove-after-delete', 'precondition', 'deleted', 5, 'A remove while the vault is deleted.',
    (log) => log.draft(alice, remove(alice, next(log), carol)));

  // ---- leave ----
  reject('leave-by-owner', 'precondition', 'lifecycle', 3, 'leave by the owner: the signer key exists (it is the owner key), the row condition actor != owner fails.',
    (log) => log.draft(alice, leave(alice, next(log))));
  reject('leave-by-non-member', 'precondition', 'lifecycle', 3, 'FI-B1: leave by dave, who is not in members. The key the row names, members[actor].key, does not exist.',
    (log) => log.draft(dave, leave(dave, next(log))));
  reject('leave-by-non-member-bad-signature', 'precondition', 'lifecycle', 3, 'FI-B1: checking stops at the undefined key, so the same leave with a broken signature is still precondition, not bad_signature.',
    (log) => flipSignature(log.draft(dave, leave(dave, next(log))).frame), { signerNote: 'dave, then one signature bit flipped' });
  reject('leave-signed-by-another-member', 'not_authorized', 'lifecycle', 3, 'A leave naming carol, signed by bob: the signer must map to members[carol].key.',
    (log) => log.draft(bob, leave(carol, next(log))));
  reject('leave-twice', 'precondition', 'offer-paths', 11, 'bob left in the last entry; a second leave finds him outside members.',
    (log) => log.draft(bob, leave(bob, next(log))));

  // ---- offer ----
  reject('offer-by-member', 'not_authorized', 'lifecycle', 3, 'bob, a writer, offers the vault to carol.',
    (log) => log.draft(bob, offer(bob, next(log), carol, 'x1', next(log) + DAY)));
  reject('offer-to-non-member', 'precondition', 'lifecycle', 3, 'An offer to dave, who is not a member.',
    (log) => log.draft(alice, offer(alice, next(log), dave, 'x1', next(log) + DAY)));
  reject('offer-to-owner', 'precondition', 'lifecycle', 3, 'An offer to the owner herself.',
    (log) => log.draft(alice, offer(alice, next(log), alice, 'x1', next(log) + DAY)));
  reject('offer-wrong-tokey', 'precondition', 'lifecycle', 3, 'An offer to bob with a wrong toKey (carol\'s key): toKey must equal members[to].key.',
    (log) => log.draft(alice, { ...offer(alice, next(log), bob, 'x1', next(log) + DAY), toKey: carol.key }));
  reject('offer-while-pending', 'precondition', 'lifecycle', 5, 'An offer while another is pending and not expired.',
    (log) => log.draft(alice, offer(alice, next(log), carol, 'x1', next(log) + DAY)));
  reject('offer-too-long', 'precondition', 'lifecycle', 3, 'An offer one millisecond too long: expiresAt = at + 14 d + 10 min + 1.',
    (log) => log.draft(alice, offer(alice, next(log), bob, 'x1', next(log) + OFFER_MAX_MS + 1)));
  reject('offer-expires-at-at', 'precondition', 'lifecycle', 3, 'An offer with expiresAt = at: the row needs at < expiresAt.',
    (log) => log.draft(alice, offer(alice, next(log), bob, 'x1', next(log))));
  reject('offer-expires-before-at', 'precondition', 'lifecycle', 3, 'An offer that expired before it was signed.',
    (log) => log.draft(alice, offer(alice, next(log), bob, 'x1', next(log) - 1)));
  reject('offer-after-delete', 'precondition', 'deleted', 5, 'An offer while the vault is deleted.',
    (log) => log.draft(alice, offer(alice, next(log), bob, 'x1', next(log) + DAY)));
  reject('offer-at-max-ms', 'precondition', 'max-at', 4, 'T2-R-a: after the leave dated 2^53 - 1, an offer must carry at = 2^53 - 1, and no expiresAt can be later: at = expiresAt = 2^53 - 1 fails at < expiresAt. Ownership of this vault is frozen, which is why the SERVER refuses a far-future `at`; the verifier itself stays clock-free.',
    (log) => log.draft(alice, offer(alice, MAX_MS, carol, 'x1', MAX_MS)));

  // ---- cancel ----
  reject('cancel-by-third-party', 'not_authorized', 'lifecycle', 5, 'cancel by a third party: carol is neither the owner nor the offer\'s target.',
    (log) => log.draft(carol, cancel(carol, next(log), 'o1')));
  reject('cancel-target-named-other-key', 'not_authorized', 'lifecycle', 5, 'A cancel naming the target (bob) but signed by carol.',
    (log) => log.draft(carol, cancel(bob, next(log), 'o1')));
  reject('cancel-owner-named-target-signed', 'not_authorized', 'lifecycle', 5, 'A cancel naming the owner as actor but signed with the target\'s key: for the owner the signer must be the owner key.',
    (log) => log.draft(bob, cancel(alice, next(log), 'o1')));
  reject('cancel-wrong-offer-id-owner', 'precondition', 'lifecycle', 5, 'The owner cancels an offerId that is not the pending one.',
    (log) => log.draft(alice, cancel(alice, next(log), 'not-this-one')));
  reject('cancel-wrong-offer-id-target', 'precondition', 'lifecycle', 5, 'The target cancels an offerId that is not the pending one.',
    (log) => log.draft(bob, cancel(bob, next(log), 'not-this-one')));
  reject('cancel-no-pending-owner', 'precondition', 'lifecycle', 3, 'The owner cancels when nothing is pending: the key exists, the row condition pending != none fails.',
    (log) => log.draft(alice, cancel(alice, next(log), 'o1')));
  reject('cancel-no-pending-target', 'precondition', 'lifecycle', 6, 'FI-B1: a cancel by the (former) target with no pending offer; o1 was cancelled by the owner in the entry before. The key the row names, pending.toKey, does not exist.',
    (log) => log.draft(bob, cancel(bob, next(log), 'o1')));
  reject('cancel-after-expiry-owner', 'precondition', 'expiry', 4, 'The owner cancels with at = expiresAt + 1: the expired offer is cleared before the entry is checked, so nothing is pending.',
    (log) => log.draft(alice, cancel(alice, log.head.at + 2, 'o1')));

  // ---- accept ----
  reject('accept-by-non-target', 'not_authorized', 'lifecycle', 5, 'accept by a non-target: carol accepts the offer made to bob.',
    (log) => log.draft(carol, accept(carol, next(log), 'o1')));
  reject('accept-target-named-owner-signed', 'not_authorized', 'lifecycle', 5, 'An accept naming the target but signed by the owner\'s key.',
    (log) => log.draft(alice, accept(bob, next(log), 'o1')));
  reject('accept-by-owner', 'not_authorized', 'lifecycle', 5, 'The owner accepts her own offer: the actor must be pending.to.',
    (log) => log.draft(alice, accept(alice, next(log), 'o1')));
  reject('accept-wrong-offer-id', 'precondition', 'lifecycle', 5, 'The target accepts with the wrong offerId.',
    (log) => log.draft(bob, accept(bob, next(log), 'not-this-one')));
  reject('accept-after-expiry', 'precondition', 'lifecycle', 5, 'accept after expiry (at = expiresAt + 1): the clearing runs before step 5, so pending is none and the key the row names does not exist (FI-B1).',
    (log) => log.draft(bob, accept(bob, at(4) + 7 * DAY + 1, 'o1')));
  reject('accept-no-pending', 'precondition', 'lifecycle', 3, 'FI-B1: accept with no pending offer.',
    (log) => log.draft(bob, accept(bob, next(log), 'o1')));
  reject('accept-cancelled-offer', 'precondition', 'lifecycle', 6, 'Accepting an offer the owner cancelled.',
    (log) => log.draft(bob, accept(bob, next(log), 'o1')));
  reject('accept-after-owner-signed-past-expiry', 'precondition', 'expiry', 6, 'T-R1: the owner signed an entry dated after the expiry, which cleared the offer; a late accept is impossible whatever `at` it carries.',
    (log) => log.draft(bob, accept(bob, log.head.at, 'o1')));
  reject('accept-after-delete', 'precondition', 'deleted', 5, 'The delete cleared the pending offer.',
    (log) => log.draft(bob, accept(bob, next(log), 'o1')));

  // ---- delete, restore ----
  reject('delete-by-member', 'not_authorized', 'lifecycle', 3, 'bob, a writer, deletes the vault.',
    (log) => log.draft(bob, del(bob, next(log), 'x1')));
  reject('delete-while-deleted', 'precondition', 'deleted', 5, 'A second delete while the vault is deleted.',
    (log) => log.draft(alice, del(alice, next(log), 'x1')));
  reject('restore-wrong-delete-id', 'precondition', 'deleted', 5, 'restore with the wrong deleteId.',
    (log) => log.draft(alice, restore(alice, next(log), 'not-this-one')));
  reject('restore-not-deleted', 'precondition', 'lifecycle', 3, 'A restore of a vault that is not deleted.',
    (log) => log.draft(alice, restore(alice, next(log), 'd1')));
  reject('restore-by-member', 'not_authorized', 'deleted', 5, 'bob, a writer, restores the vault.',
    (log) => log.draft(bob, restore(bob, next(log), 'd1')));

  // ---- time ----
  reject('at-decreases', 'precondition', 'lifecycle', 3, 'T-R1: `at` one millisecond below the previous entry\'s.',
    (log) => log.draft(alice, add(alice, log.head.at - 1, dave, 'reader', 'dave')));

  // ---- chain ----
  reject('seq-skips', 'bad_seq', 'lifecycle', 3, 'seq = head.seq + 2.',
    (log) => log.draft(alice, add(alice, next(log), dave, 'reader', 'dave'), { seq: log.head.seq + 2 }));
  reject('seq-repeats', 'bad_seq', 'lifecycle', 3, 'seq = head.seq, with prev still naming the head.',
    (log) => log.draft(alice, add(alice, next(log), dave, 'reader', 'dave'), { seq: log.head.seq }));
  reject('prev-names-older-entry', 'bad_prev', 'lifecycle', 3, 'prev is the hash of the entry before the head.',
    (log) => log.draft(alice, add(alice, next(log), dave, 'reader', 'dave'), { prev: log.entries[log.entries.length - 2].hash }));
  reject('prev-zero', 'bad_prev', 'lifecycle', 3, 'prev is 64 zeros on a later entry.',
    (log) => log.draft(alice, add(alice, next(log), dave, 'reader', 'dave'), { prev: ZERO_HASH }));
  reject('wrong-vault', 'wrong_vault', 'lifecycle', 3, 'An entry the owner really signed, at the right position, for another vault id.',
    (log) => log.draft(alice, add(alice, next(log), dave, 'reader', 'dave'), { vaultId: ids.otherVault }));
  reject('wrong-vault-genesis', 'wrong_vault', 'lifecycle', 0, 'The genesis of vault aaaa… served as the log of vault bbbb…: the verifier is told which vault it is checking.',
    () => chains.lifecycle.log.entries[0], { vaultId: ids.otherVault });

  // ---- §3.2's template rules, and position (VR-1) ----
  reject('genesis-seq-not-zero', 'bad_statement', 'lifecycle', 0, 'A genesis the creator signed with seq 1. "A genesis has seq 0" is a template rule, so the parse refuses it before any position check.',
    (log) => log.draft(alice, genesis(alice, at(0)), { seq: 1 }));
  reject('genesis-prev-not-zero', 'bad_statement', 'lifecycle', 0, 'A genesis whose prev is not 64 zeros.',
    (log) => log.draft(alice, genesis(alice, at(0)), { prev: COMMIT }));
  reject('first-entry-add-with-seq-0', 'bad_statement', 'lifecycle', 0, 'A first entry that is an add with seq 0: every kind but genesis has seq >= 1.',
    (log) => log.draft(alice, add(alice, at(0), bob, 'writer', 'bob')));
  reject('later-entry-with-seq-0', 'bad_statement', 'lifecycle', 3, 'An add with seq 0 after three entries: the template rule fails at the parse, before bad_seq.',
    (log) => log.draft(alice, add(alice, next(log), dave, 'reader', 'dave'), { seq: 0 }));
  reject('genesis-with-a-later-seq', 'bad_statement', 'lifecycle', 3, 'A genesis whose seq and prev fit position 3: still bad_statement, a genesis has seq 0.',
    (log) => log.draft(alice, genesis(alice, next(log))));
  reject('first-entry-add-with-seq-1', 'bad_seq', 'lifecycle', 0, 'A first entry that is a well-formed add with seq 1: position is bad_seq.',
    (log) => log.draft(alice, add(alice, at(0), bob, 'writer', 'bob'), { seq: 1 }));
  reject('genesis-placed-later', 'bad_seq', 'lifecycle', 3, 'The chain\'s own valid genesis frame served again at position 3: bad_seq.',
    () => chains.lifecycle.log.entries[0]);
  reject('another-genesis-placed-later', 'bad_seq', 'lifecycle', 3, 'Another valid genesis for the same vault at position 3: bad_seq.',
    () => new LogBuilder(ids.vault).draft(bob, genesis(bob, at(5))));

  // ---- the order of the checks: two things wrong at once ----
  reject('order-vault-before-seq', 'wrong_vault', 'lifecycle', 3, 'Wrong vault and wrong seq: wrong_vault comes first.',
    (log) => log.draft(alice, add(alice, next(log), dave, 'reader', 'dave'), { vaultId: ids.otherVault, seq: log.head.seq + 5 }));
  reject('order-seq-before-prev', 'bad_seq', 'lifecycle', 3, 'Wrong seq and wrong prev: bad_seq comes first.',
    (log) => log.draft(alice, add(alice, next(log), dave, 'reader', 'dave'), { seq: log.head.seq + 5, prev: ZERO_HASH }));
  reject('order-prev-before-authorization', 'bad_prev', 'lifecycle', 3, 'Wrong prev, signed by a non-owner: bad_prev comes first.',
    (log) => log.draft(bob, add(bob, next(log), dave, 'reader', 'dave'), { prev: ZERO_HASH }));
  reject('order-authorization-before-signature', 'not_authorized', 'lifecycle', 3, 'A non-owner add whose signature is also broken: not_authorized comes first.',
    (log) => flipSignature(log.draft(bob, add(bob, next(log), dave, 'reader', 'dave')).frame), { signerNote: 'bob, then one signature bit flipped' });
  reject('order-signature-before-precondition', 'bad_signature', 'lifecycle', 3, 'The owner adds an existing member and the signature is broken: bad_signature comes first.',
    (log) => flipSignature(log.draft(alice, add(alice, next(log), bob, 'reader', 'bob-again')).frame), { signerNote: 'alice, then one signature bit flipped' });
  reject('order-parse-before-vault', 'non_canonical', 'lifecycle', 3, 'A statement with a space after a colon, for another vault: the parse comes first.',
    (log) => {
      const values = log.nextValues(add(alice, next(log), dave, 'reader', 'dave'), { vaultId: ids.otherVault });
      const text = rawStatement(tokens('vault-log', values)).replace('"seq":', '"seq": ');
      return signedRaw(LOG, alice, text);
    });

  // ---- the §2 parse, inside a log ----
  reject('other-purpose-frame', 'bad_frame', 'lifecycle', 3, 'A well-formed instance-card frame (purpose 0x04) where a log entry is expected.',
    () => signed('instance-card', operator, {
      instanceId: ids.instance, seq: 0, prev: ZERO_HASH, origin: 'https://vault.example.org', name: nameOf('Example Vault'),
      kind: 'private', operator: operator.userId, operatorSignKey: b64u(operator.signPub), recoveryFp: 'none', issuedAt: T0,
    }));
  reject('truncated-frame', 'bad_frame', 'lifecycle', 3, 'The next entry cut off inside its signature.',
    (log) => log.draft(alice, add(alice, next(log), dave, 'reader', 'dave')).frame.slice(0, 70));
  reject('unknown-format', 'unknown_format', 'lifecycle', 3, 'The next entry with format byte 0x03 in the magic.',
    (log) => {
      const frame = log.draft(alice, add(alice, next(log), dave, 'reader', 'dave')).frame.slice();
      frame[3] = 0x03;
      return frame;
    });
  reject('unknown-kind', 'non_canonical', 'lifecycle', 3, 'kind "rename" is not one of the ten kinds: the value fails its type, and no template exists to re-encode it.',
    (log) => {
      const values = log.nextValues(remove(alice, next(log), carol));
      return signedRaw(LOG, alice, rawStatement(withToken(tokens('vault-log', values), 'kind', '"rename"')));
    });
  reject('role-owner-in-add', 'non_canonical', 'lifecycle', 3, 'An add with "role":"owner": the role type is writer or reader.',
    (log) => {
      const values = log.nextValues(add(alice, next(log), dave, 'reader', 'dave'));
      return signedRaw(LOG, alice, rawStatement(withToken(tokens('vault-log', values), 'role', '"owner"')));
    });
  reject('add-without-grant-id', 'non_canonical', 'lifecycle', 3, 'An add with no grantId: every key of the kind\'s template is required.',
    (log) => {
      const values = log.nextValues(add(alice, next(log), dave, 'reader', 'dave'));
      return signedRaw(LOG, alice, rawStatement(tokens('vault-log', values).filter(([k]) => k !== 'grantId')));
    });
  reject('leave-with-extra-field', 'non_canonical', 'lifecycle', 3, 'A leave carrying a member field: leave has no extra fields.',
    (log) => {
      const values = log.nextValues(leave(bob, next(log)));
      return signedRaw(LOG, bob, rawStatement([...tokens('vault-log', values), ['member', '"' + carol.userId + '"']]));
    });
  reject('version-3', 'bad_statement', 'lifecycle', 3, 'A canonical entry with "v":3.',
    (log) => {
      const values = log.nextValues(add(alice, next(log), dave, 'reader', 'dave'));
      return signedRaw(LOG, alice, rawStatement(withToken(tokens('vault-log', values), 'v', '3')));
    });
  reject('purpose-literal-mismatch', 'bad_statement', 'lifecycle', 3, 'Purpose code 0x03 with the literal "instance-card" and an add\'s key set.',
    (log) => {
      const values = log.nextValues(add(alice, next(log), dave, 'reader', 'dave'));
      return signedRaw(LOG, alice, rawStatement(withToken(tokens('vault-log', values), 'purpose', '"instance-card"')));
    });

  // ---- signature and signer key ----
  reject('signature-flipped', 'bad_signature', 'lifecycle', 3, 'A valid add by the owner with one signature bit flipped.',
    (log) => flipSignature(log.draft(alice, add(alice, next(log), dave, 'reader', 'dave')).frame), { signerNote: 'alice, then one signature bit flipped' });
  reject('statement-changed-after-signing', 'bad_signature', 'lifecycle', 3, 'The owner signed role reader; the statement in the frame says writer (still canonical).',
    (log) => {
      const good = log.draft(alice, add(alice, next(log), dave, 'reader', 'dave'));
      const changed = good.statement.replace('"role":"reader"', '"role":"writer"');
      return { frame: assembleFrame(LOG, good.signerPub, good.signature, utf8(changed)), statement: changed };
    }, { signerNote: 'alice signed another statement' });
  reject('signer-negated-point', 'bad_signature', 'lifecycle', 3, 'signerPub replaced by -A, the owner key with the sign bit of x flipped, under the signature the owner made as A. A and -A have the same X25519 image, so the signer binding passes, and this frame then fails the signature check only because nobody signed again. That check stops a third party, who cannot sign for -A; it does not stop the key\'s holder, who can sign validly under A or under -A. The vault log binds its signer through the image and so does not tell the two apart; where they must be told apart, what refuses -A is a byte comparison of the signer key (the card chain and the operator\'s own key in instancecard.json, §4.1; the extension\'s genesis check in accountgenesis.json).',
    (log) => {
      const good = log.draft(alice, add(alice, next(log), dave, 'reader', 'dave'));
      const negated = good.signerPub.slice();
      negated[31] ^= 0x80;
      return { frame: assembleFrame(LOG, negated, good.signature, utf8(good.statement)), statement: good.statement };
    }, { signerNote: 'alice; signerPub then replaced by -A' });
  reject('signer-identity-point', 'not_authorized', 'lifecycle', 3, 'signerPub is the Edwards identity point (small order): it has no X25519 image, so it maps to nobody\'s key.',
    (log) => {
      const good = log.draft(alice, add(alice, next(log), dave, 'reader', 'dave'));
      const identity = new Uint8Array(32);
      identity[0] = 1;
      return { frame: assembleFrame(LOG, identity, good.signature, utf8(good.statement)), statement: good.statement };
    }, { signerNote: 'alice; signerPub then replaced by 0100…00' });
  reject('signer-all-zero', 'not_authorized', 'lifecycle', 3, 'signerPub is 32 zero bytes (a point of order 4).',
    (log) => {
      const good = log.draft(alice, add(alice, next(log), dave, 'reader', 'dave'));
      return { frame: assembleFrame(LOG, new Uint8Array(32), good.signature, utf8(good.statement)), statement: good.statement };
    }, { signerNote: 'alice; signerPub then replaced by 32 zero bytes' });

  // ---- genesis ----
  reject('genesis-signer-not-owner-key', 'not_authorized', 'lifecycle', 0, 'A genesis whose ownerKey is alice\'s but which bob signed: the creator must sign with the key the genesis names.',
    (log) => log.draft(bob, genesis(alice, at(0))));
  reject('genesis-signature-flipped', 'bad_signature', 'lifecycle', 0, 'The genesis with one signature bit flipped.',
    () => flipSignature(chains.lifecycle.log.entries[0].frame), { signerNote: 'alice, then one signature bit flipped' });

  return rows;
}

function buildForks(chains) {
  const rows = [];
  const base = chains.lifecycle.log;
  const fork = (name, verdict, failedAt, why, seenCount, frames) => {
    const seen = base.entries.slice(0, seenCount).map((e) => ({ seq: e.values.seq, hash: e.hash }));
    const result = verifyLog({ vaultId: ids.vault, frames, seen: new Map(seen.map((s) => [s.seq, s.hash])) });
    if (result.verdict !== verdict || (verdict !== 'ok' && result.failedAt !== failedAt)) {
      throw new Error(`vaultlog fork "${name}": expected ${verdict} at ${failedAt}, the oracle verifier says ${result.verdict} at ${result.failedAt}`);
    }
    const expect = verdict === 'ok' ? { verdict } : { verdict, failedAt };
    rows.push({ name, why, seen, frames: frames.map(b64u), expect });
  };

  const two = base.prefix(2);
  const other = two.draft(alice, add(alice, at(2), carol, 'writer', 'carol'));
  fork('same-entries-again', 'ok', null, 'The device saw entries 0..2 and is served the same three frames: no fork.', 3, base.prefix(3).frames);
  fork('different-entry-at-seen-seq', 'fork', 2, 'Two entries at one position: the device saw "add carol as reader" at seq 2 and is served a different, validly signed "add carol as writer" at seq 2.', 3,
    [...two.frames, other.frame]);
  const branch = new LogBuilder(ids.vault);
  branch.entries = [...two.entries, other];
  const continued = branch.draft(alice, role(alice, at(3), carol, 'reader'));
  fork('fork-stops-the-replay', 'fork', 2, 'The other branch continues with a valid entry at seq 3; the verdict is fork at seq 2 and nothing after it is applied.', 3,
    [...two.frames, other.frame, continued.frame]);
  fork('different-invalid-entry-is-not-a-fork', 'bad_signature', 2, 'A different entry at a seen position that does not verify is its own verdict: a fork needs two VALID entries.', 3,
    [...two.frames, flipSignature(other.frame)]);
  const otherGenesis = new LogBuilder(ids.vault).draft(alice, genesis(alice, at(0) + 1));
  fork('different-genesis', 'fork', 0, 'Another validly signed genesis for the same vault id.', 1, [otherGenesis.frame]);
  fork('beyond-what-was-seen', 'ok', null, 'The device saw entries 0..2; entries 3 and 4 are new and extend the same chain.', 3, base.prefix(5).frames);
  return rows;
}

function buildCheckpoints(chains) {
  const rows = [];
  const base = chains.lifecycle.log;
  const add = (name, verdict, why, heldIndex, frames) => {
    const held = { seq: base.entries[heldIndex].values.seq, hash: base.entries[heldIndex].hash };
    const log = verifyLog({ vaultId: ids.vault, frames });
    if (log.verdict !== 'ok') throw new Error(`vaultlog checkpoint "${name}": the served chain must verify`);
    const got = compareWithHead(held, log.states.map((st) => st.head.hash));
    if (got !== verdict) throw new Error(`vaultlog checkpoint "${name}": the design says ${verdict}, the oracle says ${got}`);
    rows.push({ name, why, held, frames: frames.map(b64u), expect: { verdict } });
  };
  const two = base.prefix(2);
  const other = two.draft(alice, add_(at(2)));
  const branch = new LogBuilder(ids.vault);
  branch.entries = [...two.entries, other];
  const continued = branch.draft(alice, role(alice, at(3), carol, 'reader'));
  const otherGenesis = new LogBuilder(ids.vault).draft(alice, genesis(alice, at(0) + 1));

  add('head-is-the-checkpoint', 'ok', 'The served chain ends at the held head.', 2, base.prefix(3).frames);
  add('chain-extends-the-checkpoint', 'ok', 'The served chain holds the held hash at its seq and goes on.', 2, base.prefix(6).frames);
  add('checkpoint-at-the-genesis', 'ok', 'A held head at seq 0.', 0, base.prefix(4).frames);
  add('withheld-chain-ends-below', 'withheld', 'Withholding: the served chain ends at seq 2, below the held head at seq 4. The device keeps its own state.', 4, base.prefix(3).frames);
  add('withheld-one-short', 'withheld', 'The served chain ends one entry below the held head.', 3, base.prefix(3).frames);
  add('withheld-nothing-served', 'withheld', 'No entry is served at all.', 1, []);
  add('fork-another-entry-at-the-checkpoint', 'fork', 'The served chain has a different, validly signed entry at the held seq.', 2, [...two.frames, other.frame]);
  add('fork-on-a-longer-chain', 'fork', 'The other branch goes on past the held seq: still a fork.', 2, [...two.frames, other.frame, continued.frame]);
  add('fork-another-genesis', 'fork', 'A held head at seq 0 against another validly signed genesis.', 0, [otherGenesis.frame]);
  return rows;

  function add_(when) {
    return { kind: 'add', actor: alice.userId, at: when, member: carol.userId, memberKey: carol.key, role: 'writer', grantId: id16('grant/carol') };
  }
}

function buildCommitRows() {
  const row = (why, vk, vaultId) => ({ why, vkB64: b64u(vk), vaultId, vkCommit: vkCommit(vk, vaultId) });
  const derive = [
    row('the vault key of every chain in this file', VK, ids.vault),
    row('the same key under another vault id gives another commitment', VK, ids.otherVault),
    row('another key under the same vault id', OTHER_VK, ids.vault),
    // Not an all-zero key: spec 01 "Keys in memory and the lock" rule 4 refuses one (a zero key matches no
    // commitment), so the lowest key a client derives from is 31 zero bytes and one 0x01. The zero key is in keyfloor.json.
    row('31 zero bytes and one 0x01 byte (the lowest key the key floor accepts; an all-zero key is refused as a wiped key)', nearZeroKey(), ids.vault),
  ];
  const check = [
    { why: 'the committed key', vaultId: ids.vault, vkCommit: COMMIT, candidateVkB64: b64u(VK), matches: true },
    { why: 'another key: refused, nothing is decrypted or written under it', vaultId: ids.vault, vkCommit: COMMIT, candidateVkB64: b64u(OTHER_VK), matches: false },
    { why: 'the right key checked against the commitment of another vault id', vaultId: ids.otherVault, vkCommit: COMMIT, candidateVkB64: b64u(VK), matches: false },
  ];
  return { derive, check };
}

export function build() {
  const chains = buildChains();
  const chainRows = Object.values(chains).map(({ name, why, log, notes }) => {
    const result = verifyLog({ vaultId: ids.vault, frames: log.frames });
    if (result.verdict !== 'ok') throw new Error(`vaultlog chain "${name}" does not verify: ${result.verdict} at ${result.failedAt}`);
    return { name, why, entries: log.entries.map((entry, i) => describeEntry(entry, result.states[i], notes[i])) };
  });

  return {
    _about: [
      'The vault log of design 2026-11-15-onboarding-trust §3: templates (§3.1), chain (§3.2), state and transitions (§3.3), key commitment (§3.4).',
      'Hand-authored from the independent oracle in tools/vector-gen/oracle (Node WebCrypto and @noble; no andvari code). Regenerate with `npm run generate` there; `npm run check` fails on any difference.',
      'The verifier under test takes the vault id it is checking and the frames from the genesis on, and replays them. It has NO clock: nothing in this file depends on the current time (T2-R-a).',
      'chains: every entry must verify, and the state after entry i must equal entries[i].state. state.head.at is the `at` of the last entry (the value the time rule compares against); members maps userId -> {key, role}; pending and deleted are null for none.',
      'reject: replay the first `after` entries of chain `chain` (all valid), then `frameB64`. The verdict must be expect.verdict, raised at that frame, and the verified state stays the state after entry after-1. A row with its own `vaultId` checks the log as that vault. `signer` names the cast account whose seed signed the frame.',
      'Verdicts in check order (§3.3): bad_frame, unknown_format, non_canonical, bad_statement (the §2 parse); wrong_vault; bad_seq; bad_prev; not_authorized; bad_signature; precondition; fork. Expired-offer clearing runs before not_authorized, and a signer key that does not exist in the state is precondition there (FI-B1).',
      'forks: `seen` is the hash this device already saw at each sequence number. A different entry at a seen position that passes every other check is fork; expect.failedAt is the index of that frame.',
      'checkpoints (§2.4, VR-17): a served chain that verifies (`frames`, from the genesis) compared with a held head `held` = {seq, hash}: a verified head, a device-link checkpoint or the account\'s vault record. withheld: the chain ends below the held seq. fork: the chain has another hash at the held seq. ok otherwise. It is one pure function of the held head and the served hashes, shared by core and the web twin; instancecard.json\'s `pinned` rows grade the same function on card chains.',
      'Template rules (VR-1): "a genesis has seq 0 and a zero prev; every other kind has seq >= 1" is checked by the parse (bad_statement). Position is bad_seq and bad_prev alone: a valid genesis placed later is bad_seq, and so is a first entry whose seq is not 0.',
      'vkCommit.derive: hexLower(HKDF-SHA-256(ikm = VK, salt = empty, info = "andvari/v2|vk-commit|" + vaultId, L = 32)). vkCommit.check: whether a candidate key may be used under a state that committed to `vkCommit` (§3.4).',
    ],
    vaultId: ids.vault,
    otherVaultId: ids.otherVault,
    vkB64: b64u(VK),
    vkCommitHex: COMMIT,
    offerMaxLifetimeMs: OFFER_MAX_MS,
    maxMs: MAX_MS,
    accounts: {
      alice: describe(alice), bob: describe(bob), carol: describe(carol), dave: describe(dave), eve: describe(eve),
    },
    vkCommit: buildCommitRows(),
    chains: chainRows,
    reject: buildRejects(chains),
    forks: buildForks(chains),
    checkpoints: buildCheckpoints(chains),
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

  for (const row of doc.vkCommit.derive) expect(vkCommit(mustUnb64u(row.vkB64), row.vaultId) === row.vkCommit, 'vkCommit derive: ' + row.why);
  for (const row of doc.vkCommit.check) {
    expect((vkCommit(mustUnb64u(row.candidateVkB64), row.vaultId) === row.vkCommit) === row.matches, 'vkCommit check: ' + row.why);
  }

  const chainFrames = {};
  for (const chain of doc.chains) {
    const frames = chain.entries.map((e) => mustUnb64u(e.frameB64));
    chainFrames[chain.name] = frames;
    const result = verifyLog({ vaultId: doc.vaultId, frames });
    expect(result.verdict === 'ok', `chain ${chain.name}: verdict ${result.verdict}`);
    chain.entries.forEach((entry, i) => {
      expect(frameHash(frames[i]) === entry.hash, `chain ${chain.name}[${i}]: hash`);
      expect(result.states && same(result.states[i], entry.state), `chain ${chain.name}[${i}]: state`);
      expect(new TextDecoder().decode(frames[i].slice(101)) === entry.statementUtf8, `chain ${chain.name}[${i}]: statementUtf8`);
      const account = doc.accounts[entry.signer];
      expect(account && b64u(frames[i].slice(5, 37)) === account.signPubB64, `chain ${chain.name}[${i}]: signer`);
    });
  }

  const names = new Set();
  for (const row of doc.reject) {
    expect(!names.has(row.name), `reject ${row.name}: duplicate name`);
    names.add(row.name);
    const prefix = chainFrames[row.chain].slice(0, row.after);
    const result = verifyLog({ vaultId: row.vaultId ?? doc.vaultId, frames: [...prefix, mustUnb64u(row.frameB64)] });
    expect(result.verdict === row.expect.verdict && result.failedAt === row.after, `reject ${row.name}: oracle says ${result.verdict} at ${result.failedAt}`);
  }

  for (const row of doc.forks) {
    const seen = new Map(row.seen.map((s) => [s.seq, s.hash]));
    const result = verifyLog({ vaultId: doc.vaultId, frames: row.frames.map(mustUnb64u), seen });
    const ok = result.verdict === row.expect.verdict && (row.expect.verdict === 'ok' || result.failedAt === row.expect.failedAt);
    expect(ok, `fork ${row.name}: oracle says ${result.verdict} at ${result.failedAt}`);
  }
  for (const row of doc.checkpoints) {
    const log = verifyLog({ vaultId: doc.vaultId, frames: row.frames.map(mustUnb64u) });
    const got = log.verdict === 'ok' ? compareWithHead(row.held, log.states.map((st) => st.head.hash)) : 'served chain: ' + log.verdict;
    expect(got === row.expect.verdict, `checkpoint ${row.name}: oracle says ${got}`);
  }
  return { rows, failures };
}
