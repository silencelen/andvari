// The server's side of a vault-log append (design §3.7, spec 03 §10.3 and §10.4): which wire answer
// a posted frame gets, from the stored chain, the grant table and the caller.
//
// Steps 1 and 2 (the session, the body caps and the side data) and step 8 (the clock ceiling, the
// offer window, the add limits and the quotas) are outside this model: a row is built so that they
// pass. Steps 3 to 7 are modelled, in the design's order.

import { bytesEqual } from './bytes.mjs';
import { parseFrame, signerMapsTo, signatureValid, PURPOSE_CODES } from './frame.mjs';
import { verifyLog } from './vaultlog.mjs';

const LOG = PURPOSE_CODES['vault-log'];
const OWNER_KINDS = ['add', 'role', 'remove', 'offer', 'delete', 'restore'];

/**
 * The server's grant table after a stored chain, by the effects of spec 03 §10.3: a map
 * userId -> { role, revokedBy } where revokedBy is null for an active grant, or the kind of the
 * entry that revoked it: 'delete' (the reason the design calls vault_delete), 'leave' or 'remove'.
 */
export function grantsAfter(frames) {
  const grants = new Map();
  for (const frame of frames) {
    const parsed = parseFrame(frame, LOG);
    if (parsed.verdict !== 'ok') throw new Error('grantsAfter: a stored frame does not parse');
    const e = parsed.values;
    switch (e.kind) {
      case 'genesis':
        grants.set(e.actor, { role: 'owner', revokedBy: null });
        break;
      case 'add': // creates the member's grant, or re-activates a revoked one, with the role
        grants.set(e.member, { role: e.role, revokedBy: null });
        break;
      case 'role':
        grants.get(e.member).role = e.role;
        break;
      case 'remove':
        grants.get(e.member).revokedBy = 'remove';
        break;
      case 'leave': // on a deleted vault this rewrites the vault_delete revocation, so a restore skips it
        grants.get(e.actor).revokedBy = 'leave';
        break;
      case 'accept':
        for (const g of grants.values()) if (g.role === 'owner') g.role = 'writer';
        grants.get(e.actor).role = 'owner';
        break;
      case 'delete':
        for (const g of grants.values()) if (g.revokedBy === null) g.revokedBy = 'delete';
        break;
      case 'restore':
        for (const g of grants.values()) if (g.revokedBy === 'delete') g.revokedBy = null;
        break;
      case 'offer': case 'cancel':
        break;
      default:
        throw new Error('grantsAfter: unknown kind ' + e.kind);
    }
  }
  return grants;
}

/** The grant table as rows carry it. */
export const describeGrants = (grants) => [...grants.entries()].map(([userId, g]) => ({ userId, role: g.role, revokedBy: g.revokedBy }));

/**
 * POST /vaults/{vaultId}/log with `frame`, by the account `caller` = { userId, identityPub }, against
 * the `stored` chain of that vault (an empty array when no vault has this id). `purged` says that
 * the vault's grace period ended and the server purged it: the log is kept, and every append other
 * than a genesis is refused with no_grant, the owner's restore included.
 * Returns { status: 200, appended } or { status, error } (with seq, hash and at for log_head_moved).
 */
export function appendAnswer({ vaultId, stored, purged = false, caller, frame }) {
  const log = verifyLog({ vaultId, frames: stored });
  if (log.verdict !== 'ok') throw new Error('appendAnswer: the stored chain does not verify');
  if (purged && (stored.length === 0 || log.states[log.states.length - 1].deleted === null)) throw new Error('appendAnswer: only a deleted vault can be purged');

  // Step 3: the strict parse, purpose 0x03, and the frame's vaultId against the path.
  const parsed = parseFrame(frame, LOG);
  if (parsed.verdict === 'bad_frame' || parsed.verdict === 'unknown_format') return { status: 400, error: 'bad_frame' };
  if (parsed.verdict !== 'ok') return { status: 400, error: parsed.verdict };
  const e = parsed.values;
  if (e.vaultId !== vaultId) return { status: 400, error: 'wrong_vault' };

  // Step 4: the actor is the caller, the signer maps to the caller's stored identity key, and the
  // signature verifies.
  if (e.actor !== caller.userId || !signerMapsTo(parsed.signerPub, caller.identityPub)) return { status: 400, error: 'bad_signer' };
  if (!signatureValid(parsed)) return { status: 400, error: 'bad_signature' };

  // Step 5: retry, then access.
  // The retry rule comes first and changes nothing, on a purged vault too.
  if (stored.some((f) => bytesEqual(f, frame))) return { status: 200, appended: false };
  if (e.kind === 'genesis') {
    // The vault id must be unused by any vault, live or tombstoned.
    if (stored.length > 0) return { status: 409, error: 'vault_id_taken' };
  } else {
    if (stored.length === 0) return { status: 403, error: 'no_grant' };
    // After the purge no grant counts: the vault_delete exception ends with the grace period.
    if (purged) return { status: 403, error: 'no_grant' };
    const g = grantsAfter(stored).get(caller.userId);
    // A grant revoked by the vault's delete counts for restore and delete by the owner, and for
    // leave. A grant revoked for any other reason never counts.
    const counts = g !== undefined && (g.revokedBy === null
      || (g.revokedBy === 'delete' && (e.kind === 'leave' || ((e.kind === 'restore' || e.kind === 'delete') && g.role === 'owner'))));
    if (!counts) return { status: 403, error: 'no_grant' };
    if (OWNER_KINDS.includes(e.kind) && g.role !== 'owner') return { status: 403, error: 'not_vault_owner' };
  }

  // Step 6: position. It comes after step 5, so the head is never shown to a non-member.
  if (e.kind !== 'genesis') {
    const head = log.states[log.states.length - 1].head;
    if (e.seq !== head.seq + 1 || e.prev !== head.hash) return { status: 409, error: 'log_head_moved', seq: head.seq, hash: head.hash, at: head.at };
  }

  // Step 7: the shared verifier over the stored chain plus the new entry.
  const next = verifyLog({ vaultId, frames: [...stored, frame] });
  if (next.verdict === 'ok') return { status: 200, appended: true };
  if (next.failedAt !== stored.length) throw new Error('appendAnswer: the verifier stopped inside the stored chain');
  if (next.verdict === 'not_authorized') return { status: 403, error: 'not_vault_owner' };
  if (next.verdict === 'precondition') return { status: 400, error: 'precondition' };
  throw new Error('appendAnswer: verdict ' + next.verdict + ' cannot reach the verifier after steps 3 to 6');
}
