// The account genesis record (design §5): the checks every unlock makes, in §2.4's order (VR-13).

import { b64u } from './bytes.mjs';
import { boxKeypairFromSeed, signPubFromSeed, envelopeOpen } from './prims.mjs';
import { parseFrame, signerEquals, signatureValid, PURPOSE_CODES } from './frame.mjs';
import { personalWrapAd } from './grant.mjs';

/**
 * §5.2 at unlock, after deriving the identity keys from the seed. First failure wins:
 *   the parse verdicts; signer_not_pinned_key; bad_signature; identity_mismatch (identityKey is not
 *   the seed-derived key); user_mismatch; instance_mismatch; personal_vault_mismatch.
 * The signer is bound by byte equality with the Ed25519 key the device derives from the seed, on
 * every client (§2.4, the Signer binding row 0x05; spec 01 §5.1): never through its X25519 image,
 * which the negation -A shares with A. (The server, which holds no seed, checks through the image;
 * this function is a device's check, not the server's.)
 * `servedWrapVaultId` is the vaultId of the served personal wrap, or null when none is served.
 */
export function verifyGenesis({ frame, seed, sessionUserId, pinnedInstanceId, servedWrapVaultId }) {
  const parsed = parseFrame(frame, PURPOSE_CODES['account-genesis']);
  if (parsed.verdict !== 'ok') return { verdict: parsed.verdict };
  const g = parsed.values;
  const identity = boxKeypairFromSeed(seed).publicKey;
  if (!signerEquals(parsed.signerPub, signPubFromSeed(seed))) return { verdict: 'signer_not_pinned_key' };
  if (!signatureValid(parsed)) return { verdict: 'bad_signature' };
  if (g.identityKey !== b64u(identity)) return { verdict: 'identity_mismatch' };
  if (g.userId !== sessionUserId) return { verdict: 'user_mismatch' };
  if (g.instanceId !== pinnedInstanceId) return { verdict: 'instance_mismatch' };
  if (servedWrapVaultId !== null && servedWrapVaultId !== g.personalVaultId) return { verdict: 'personal_vault_mismatch' };
  return { verdict: 'ok', genesis: g };
}

/**
 * §5.3: a served wrap that opens and names personalVaultId is in force on any device. A withheld or
 * unopenable wrap leaves no personal vault (an anomaly, not the identity fault).
 */
export function personalWrapInForce({ wrap, uvk, userId, personalVaultId }) {
  if (wrap === null || wrap.vaultId !== personalVaultId) return false;
  return envelopeOpen(uvk, personalWrapAd(wrap.vaultId, userId), wrap.wrappedVk) !== null;
}
