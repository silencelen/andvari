// The vault log of design §3: chain rules (§3.2), state and transitions (§3.3), key commitment (§3.4).
// A pure function of the bytes: no clock, no network, no contact pins.

import { mustUnb64u, hex } from './bytes.mjs';
import { hkdfSha256 } from './prims.mjs';
import { keyFloor } from './keyfloor.mjs';
import { parseFrame, signerMapsTo, signatureValid, frameHash, PURPOSE_CODES } from './frame.mjs';

export const ZERO_HASH = '0'.repeat(64);
/** An offer may run at most 14 days and 10 minutes past its own `at` (§3.3). */
export const OFFER_MAX_MS = 14 * 24 * 60 * 60 * 1000 + 10 * 60 * 1000;

/** §3.4: vkCommit = hexLower(HKDF-SHA-256(ikm = VK, salt = empty, info = "andvari/v2|vk-commit|" + vaultId, L = 32)). */
export function vkCommit(vk, vaultId) {
  keyFloor('vaultlog.vkCommit', vk);
  return hex(hkdfSha256(vk, 'andvari/v2|vk-commit|' + vaultId, 32));
}

const clone = (state) => structuredClone(state);

/**
 * Check one entry against the state before it (null before the genesis) and return
 * { verdict: 'ok', state } or { verdict } with the first failing check of §3.3's order:
 *   1 bad_frame / unknown_format / non_canonical / bad_statement   2 wrong_vault   3 bad_seq
 *   4 bad_prev   5 not_authorized   6 bad_signature   7 precondition   8 fork
 * `seen` maps a sequence number to the frame hash this device already saw there.
 */
export function applyEntry(before, vaultId, frame, seen = new Map()) {
  const parsed = parseFrame(frame, PURPOSE_CODES['vault-log']);
  if (parsed.verdict !== 'ok') return { verdict: parsed.verdict };
  const e = parsed.values;

  if (e.vaultId !== vaultId) return { verdict: 'wrong_vault' };
  if (e.seq !== (before ? before.head.seq + 1 : 0)) return { verdict: 'bad_seq' };
  if (e.prev !== (before ? before.head.hash : ZERO_HASH)) return { verdict: 'bad_prev' };

  // §3.2's template rules (a genesis has seq 0 and a zero prev, every other kind has seq >= 1) were
  // checked by the parse as bad_statement, and the position by bad_seq and bad_prev just above. So a
  // genesis is here exactly when this is the first entry.
  if ((e.kind === 'genesis') !== (before === null)) throw new Error('oracle: a genesis off position 0 survived the parse and the position checks');

  const hash = frameHash(frame);
  const head = { seq: e.seq, hash, at: e.at };

  if (e.kind === 'genesis') {
    // Signed by the creator: the frame's signer must map to the statement's own ownerKey.
    if (!signerMapsTo(parsed.signerPub, mustUnb64u(e.ownerKey))) return { verdict: 'not_authorized' };
    if (!signatureValid(parsed)) return { verdict: 'bad_signature' };
    if (seen.has(e.seq) && seen.get(e.seq) !== hash) return { verdict: 'fork' };
    return {
      verdict: 'ok',
      state: {
        vaultId: e.vaultId,
        head,
        owner: e.actor,
        ownerKey: e.ownerKey,
        vkCommit: e.vkCommit,
        members: { [e.actor]: { key: e.ownerKey, role: 'owner' } },
        pending: null,
        deleted: null,
      },
    };
  }

  // Time rule (FI-B1): an offer that expired before this entry's `at` is cleared before step 5.
  const S = clone(before);
  if (S.pending && e.at > S.pending.expiresAt) S.pending = null;

  // Step 5: which key must have signed, and as which account. A key that does not exist in S is
  // `precondition`, and checking stops there (FI-B1).
  let signerKey;
  let actorOk;
  switch (e.kind) {
    case 'add': case 'role': case 'remove': case 'offer': case 'delete': case 'restore':
      signerKey = S.ownerKey;
      actorOk = e.actor === S.owner;
      break;
    case 'leave':
      if (!Object.hasOwn(S.members, e.actor)) return { verdict: 'precondition' };
      signerKey = S.members[e.actor].key;
      actorOk = true;
      break;
    case 'cancel':
      if (e.actor === S.owner) {
        signerKey = S.ownerKey;
        actorOk = true;
      } else {
        if (!S.pending) return { verdict: 'precondition' };
        signerKey = S.pending.toKey;
        actorOk = e.actor === S.pending.to;
      }
      break;
    case 'accept':
      if (!S.pending) return { verdict: 'precondition' };
      signerKey = S.pending.toKey;
      actorOk = e.actor === S.pending.to;
      break;
    default:
      throw new Error('unreachable kind ' + e.kind);
  }
  if (!actorOk || !signerMapsTo(parsed.signerPub, mustUnb64u(signerKey))) return { verdict: 'not_authorized' };

  // Step 6.
  if (!signatureValid(parsed)) return { verdict: 'bad_signature' };

  // Step 7: `at` never decreases, then every condition of the kind's row.
  const pre = (() => {
    if (e.at < before.head.at) return false;
    const live = S.deleted === null;
    const isMember = (id) => Object.hasOwn(S.members, id);
    switch (e.kind) {
      case 'add':
        return live && !isMember(e.member);
      case 'role': case 'remove':
        return live && isMember(e.member) && e.member !== S.owner;
      case 'leave':
        return e.actor !== S.owner;
      case 'offer':
        return live && isMember(e.to) && e.to !== S.owner && e.toKey === S.members[e.to].key
          && BigInt(e.at) < BigInt(e.expiresAt) && BigInt(e.expiresAt) <= BigInt(e.at) + BigInt(OFFER_MAX_MS)
          && S.pending === null;
      case 'cancel':
        return S.pending !== null && e.offerId === S.pending.offerId;
      case 'accept':
        return live && e.offerId === S.pending.offerId && e.at <= S.pending.expiresAt;
      case 'delete':
        return live;
      case 'restore':
        return S.deleted !== null && S.deleted.deleteId === e.deleteId;
      default:
        throw new Error('unreachable kind ' + e.kind);
    }
  })();
  if (!pre) return { verdict: 'precondition' };

  // Step 8.
  if (seen.has(e.seq) && seen.get(e.seq) !== hash) return { verdict: 'fork' };

  // Effects.
  const dropPendingFor = (id) => {
    if (S.pending && S.pending.to === id) S.pending = null;
  };
  switch (e.kind) {
    case 'add':
      S.members[e.member] = { key: e.memberKey, role: e.role };
      break;
    case 'role':
      S.members[e.member].role = e.role;
      dropPendingFor(e.member);
      break;
    case 'remove':
      delete S.members[e.member];
      dropPendingFor(e.member);
      break;
    case 'leave':
      delete S.members[e.actor];
      dropPendingFor(e.actor);
      break;
    case 'offer':
      S.pending = { offerId: e.offerId, to: e.to, toKey: e.toKey, expiresAt: e.expiresAt };
      break;
    case 'cancel':
      S.pending = null;
      break;
    case 'accept':
      S.members[S.owner].role = 'writer';
      S.owner = S.pending.to;
      S.ownerKey = S.pending.toKey;
      S.members[S.owner].role = 'owner';
      S.pending = null;
      break;
    case 'delete':
      S.deleted = { deleteId: e.deleteId };
      S.pending = null;
      break;
    case 'restore':
      S.deleted = null;
      break;
    default:
      throw new Error('unreachable kind ' + e.kind);
  }
  S.head = head;
  return { verdict: 'ok', state: S };
}

/**
 * Checkpoints (§2.4, VR-17): a served, verified chain against a held head { seq, hash }. `hashes[i]`
 * is the hash at sequence number i of the served chain. One pure function for vault logs (a verified
 * head, a device-link checkpoint, the account's vault record) and for card chains (the pinned card).
 *   withheld  the chain ends below the held head (an empty chain included)
 *   fork      the chain has another hash at the head's seq
 *   ok        the chain holds the held hash at the head's seq
 */
export function compareWithHead(held, hashes) {
  if (hashes.length - 1 < held.seq) return 'withheld';
  return hashes[held.seq] === held.hash ? 'ok' : 'fork';
}

/**
 * Replay `frames` from the genesis. Returns { verdict: 'ok', states } with the state after every
 * entry, or { verdict, failedAt, states } where `states` holds the states of the entries before the
 * failing one (the verified state stays at the last good entry, §3.9).
 */
export function verifyLog({ vaultId, frames, seen = new Map() }) {
  let state = null;
  const states = [];
  for (let i = 0; i < frames.length; i++) {
    const r = applyEntry(state, vaultId, frames[i], seen);
    if (r.verdict !== 'ok') return { verdict: r.verdict, failedAt: i, states };
    state = r.state;
    states.push(state);
  }
  return { verdict: 'ok', states };
}
