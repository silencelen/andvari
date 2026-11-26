// Grants (design §3.5): a sealed purpose-0x01 statement checked against the vault's verified log.
// Also the wrap ADs of §2.3 and the wrap-adoption conditions of §3.6.

import { b64u, mustUnb64u } from './bytes.mjs';
import { boxSealOpen, envelopeOpen } from './prims.mjs';
import { splitFrame, parseFrame, signerMapsTo, signatureValid, frameHash, PURPOSE_CODES } from './frame.mjs';
import { parseStatement } from './statement.mjs';
import { verifyLog, vkCommit } from './vaultlog.mjs';

/**
 * The log is replayed before any grant is opened: if it does not verify, the result is the log's own
 * verdict, even when the grant has a fault of its own. Then the ten checks of §3.5, in order; the
 * first failure is the verdict.
 * `me` is the receiving account { userId, identityPub, identitySecret }.
 * Returns { verdict: 'ok', vk, from, grantId, issuedAt } or { verdict }.
 */
export function verifyGrant({ me, rowVaultId, sealed, logFrames }) {
  const log = verifyLog({ vaultId: rowVaultId, frames: logFrames });
  if (log.verdict !== 'ok') return { verdict: log.verdict };

  // 1. The seal opens.
  const plain = boxSealOpen(me.identityPub, me.identitySecret, sealed);
  if (plain === null) return { verdict: 'unopenable' };

  // 2. Frame purpose 0x01, by the frame checks of §2.4, which hold for every purpose: bad_frame if
  //    shorter than 4 bytes, unknown_format for another magic, bad_frame for a bad length or a
  //    purpose other than 0x01.
  const parts = splitFrame(plain, PURPOSE_CODES['vault-grant']);
  if (parts.verdict !== 'ok') return { verdict: parts.verdict };

  // 3. Strict parse.
  const parsed = parseStatement('vault-grant', parts.statementBytes);
  if (parsed.verdict !== 'ok') return { verdict: parsed.verdict };
  const g = parsed.values;

  // 4. Addressed to this account and its seed-derived key.
  if (g.to !== me.userId || g.toKey !== b64u(me.identityPub)) return { verdict: 'misaddressed' };

  // 5. The row's vault.
  if (g.vaultId !== rowVaultId) return { verdict: 'vault_mismatch' };

  // 6. This account's LATEST add has the statement's grantId and names this account's key. A grant
  //    bound to an earlier add of the account, or to none, is no_add_entry.
  const entries = logFrames.map((f) => parseFrame(f, PURPOSE_CODES['vault-log']).values);
  let addIndex = -1;
  entries.forEach((e, index) => {
    if (e.kind === 'add' && e.member === me.userId) addIndex = index;
  });
  if (addIndex === -1) return { verdict: 'no_add_entry' };
  const addEntry = entries[addIndex];
  if (addEntry.grantId !== g.grantId || addEntry.memberKey !== b64u(me.identityPub)) return { verdict: 'no_add_entry' };
  const O = addEntry.actor;
  const K = log.states[addIndex - 1].ownerKey; // the owner key at that entry

  // 7. From the owner who signed that add.
  if (g.from !== O || !signerMapsTo(parts.signerPub, mustUnb64u(K))) return { verdict: 'not_authorized' };

  // 8. The signature.
  if (!signatureValid(parts)) return { verdict: 'bad_signature' };

  // 9. The key is the one the genesis committed to.
  const finalState = log.states[log.states.length - 1];
  if (vkCommit(mustUnb64u(g.vk), rowVaultId) !== finalState.vkCommit) return { verdict: 'vk_commit_mismatch' };

  // 10. No later remove or leave of this account. (No add can follow one: addIndex is the latest.)
  const out = entries.slice(addIndex + 1).some((e) => (e.kind === 'remove' && e.member === me.userId) || (e.kind === 'leave' && e.actor === me.userId));
  if (out !== !Object.hasOwn(finalState.members, me.userId)) throw new Error('oracle: step 10 and the final member list disagree');
  if (out) return { verdict: 'removed' };

  return { verdict: 'ok', vk: g.vk, from: g.from, grantId: g.grantId, issuedAt: g.issuedAt };
}

// ---- wrap ADs (§2.3) ----

/** Shared-vault UVK wrap AD (owner wrap and member self-wrap), bound to the log's genesis. */
export const sharedWrapAd = (vaultId, userId, genesisHash) => `andvari/v2|vk-shared|${vaultId}|${userId}|${genesisHash}`;
/** The personal wrap keeps its v1 AD (§2.3). */
export const personalWrapAd = (vaultId, userId) => `andvari/v1|vk-personal|${vaultId}|${userId}`;
/** The personal vault's owner-grant wrap, also unchanged (spec 02 §2). */
export const personalGrantAd = (vaultId, userId) => `andvari/v1|vk|${vaultId}|${userId}`;

/**
 * §3.6, for a key that comes from the account's OWN wrap (owner wrap or member self-wrap): which of
 * the conditions (a)-(e) fails first is not ordered by the design, so this returns the SET of failed
 * conditions and the vector rows fail at most one.
 *
 * accountState = { vaults: { [vaultId]: {genesisHash, seq, hash} }, accepted: { [vaultId]: {owner, addSeq, at, decision} } }
 */
export function adoptByWrap({ me, uvk, vaultId, logFrames, wrap, accountState }) {
  const failed = new Set();
  const log = verifyLog({ vaultId, frames: logFrames });
  if (log.verdict !== 'ok') return { adopt: false, failed: ['a'] }; // (a) the log verifies
  const entries = logFrames.map((f) => parseFrame(f, PURPOSE_CODES['vault-log']).values);
  const S = log.states[log.states.length - 1];
  const genesisHash = frameHash(logFrames[0]);

  if (!Object.hasOwn(S.members, me.userId)) failed.add('b'); // (b) this account is a member

  // (d) the wrap opens under the AD naming this log's genesis hash, and either the account is the
  //     genesis owner with no add of itself in the log (FN-2), or an accepted record with
  //     decision = accept answers its latest add (FC-7).
  const vk = envelopeOpen(uvk, sharedWrapAd(vaultId, me.userId, genesisHash), wrap);
  const myAdds = entries.filter((e) => e.kind === 'add' && e.member === me.userId).map((e) => e.seq);
  const latestAdd = myAdds.length ? myAdds[myAdds.length - 1] : null;
  const isGenesisOwner = entries[0].actor === me.userId;
  const accepted = accountState.accepted?.[vaultId];
  const consent = (isGenesisOwner && latestAdd === null)
    || (latestAdd !== null && accepted !== undefined && accepted.addSeq === latestAdd && accepted.decision === 'accept');
  if (vk === null || !consent) failed.add('d');

  // (c) the key passes the commitment (only a key that opened can be checked).
  if (vk !== null && vkCommit(vk, vaultId) !== S.vkCommit) failed.add('c');

  // (e) the account's vault record agrees; no record passes.
  const rec = accountState.vaults?.[vaultId];
  if (rec !== undefined) {
    const below = S.head.seq < rec.seq;
    const differs = !below && log.states[rec.seq].head.hash !== rec.hash;
    if (rec.genesisHash !== genesisHash || below || differs) failed.add('e');
  }

  if (failed.size) return { adopt: false, failed: [...failed].sort() };
  return { adopt: true, vk };
}

/**
 * The Chrome and Firefox extension's reduced rule (§12.2 rule 1, FN-1). It verifies no log: it takes
 * the genesis hash from the account state's vaults[vaultId].genesisHash (a withheld or wrong value
 * fails the AEAD and the vault stays closed), and opens a shared-vault wrap, an owner wrap included,
 * only when accepted[vaultId].decision is accept. It cannot check addSeq.
 * It also keeps the highest in-blob seq it has opened (`highWater`, null before the first open) and
 * opens no shared-vault wrap while the served document (accountState.seq) is below it.
 */
export function extensionOpensWrap({ me, uvk, vaultId, wrap, accountState, highWater = null }) {
  if (highWater !== null && accountState.seq < highWater) return false;
  const rec = accountState.vaults?.[vaultId];
  const acc = accountState.accepted?.[vaultId];
  if (rec === undefined || acc === undefined || acc.decision !== 'accept') return false;
  return envelopeOpen(uvk, sharedWrapAd(vaultId, me.userId, rec.genesisHash), wrap) !== null;
}
