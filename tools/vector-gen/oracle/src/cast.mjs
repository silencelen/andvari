// Fixed identities, ids and secrets. Nothing here is random: two runs give the same bytes.
//
// alice, bob and carol reuse the seeds of the existing corpus (sharedgrant-v2.json's owner, member
// and third, signedstatement.json's jointKey and other), so the joint-key mapping of every new
// vector is anchored to accounts the old vectors already pin. Every other secret is the first bytes
// of SHA-256("andvari-vector-oracle|" + label).

import { b64u, mustUnb64u, hex } from './bytes.mjs';
import { sha256, boxKeypairFromSeed, signPubFromSeed } from './prims.mjs';

/** Deterministic fixture bytes for a label. */
export function fixed(label, length = 32) {
  if (length > 32) throw new Error('fixed: at most 32 bytes');
  return sha256('andvari-vector-oracle|' + label).slice(0, length);
}

function account(name, userId, seed) {
  const box = boxKeypairFromSeed(seed);
  const signPub = signPubFromSeed(seed);
  return {
    name,
    userId,
    seed,
    identityPub: box.publicKey, // X25519, crypto_box_seed_keypair(seed)
    identitySecret: box.secretKey,
    signPub, // Ed25519, crypto_sign_seed_keypair(seed): the joint key
    key: b64u(box.publicKey), // the identity key as statements carry it
  };
}

export const alice = account('alice', '11111111-1111-4111-8111-111111111111', mustUnb64u('DRQbIikwNz5FTFNaYWhvdn2Ei5KZoKeutbzDytHY3-Y'));
export const bob = account('bob', '22222222-2222-4222-8222-222222222222', mustUnb64u('oKOmqayvsrW4u77BxMfKzdDT1tnc3-Ll6Ovu8fT3-v0'));
export const carol = account('carol', '33333333-3333-4333-8333-333333333333', mustUnb64u('8-Y_Ot4gdxwTpqxkvkFy1zpMKs1R5t4Il73QMCTuB1I'));
export const dave = account('dave', '44444444-4444-4444-8444-444444444444', fixed('seed/dave'));
export const eve = account('eve', '55555555-5555-4555-8555-555555555555', fixed('seed/eve'));
export const operator = account('operator', '99999999-9999-4999-8999-999999999999', fixed('seed/operator'));
export const operator2 = account('operator2', '88888888-8888-4888-8888-888888888888', fixed('seed/operator2'));

export const accounts = { alice, bob, carol, dave, eve, operator, operator2 };

/** An instance recovery key: one seed gives the X25519 key (spec 04 §1) and the Ed25519 signing key (§2.3). */
function recoveryKey(name, seed) {
  const box = boxKeypairFromSeed(seed);
  return {
    name,
    seed,
    publicKey: box.publicKey,
    secretKey: box.secretKey,
    signPub: signPubFromSeed(seed),
    fp: hex(sha256(box.publicKey)), // recoveryFp: SHA-256 of the recovery public key
  };
}
export const recoveryA = recoveryKey('recoveryA', fixed('seed/recovery-a'));
export const recoveryB = recoveryKey('recoveryB', fixed('seed/recovery-b'));
export const recoveryC = recoveryKey('recoveryC', fixed('seed/recovery-c'));

export const ids = {
  instance: 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',
  otherInstance: 'ffffffff-ffff-4fff-8fff-ffffffffffff',
  vault: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  otherVault: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
  personalVault: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
  otherPersonalVault: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
};

/** 2025-11-15T00:00:00Z, the `at` of the design's example genesis (§3.1). */
export const T0 = 1763164800000;
export const MINUTE = 60 * 1000;
export const HOUR = 60 * MINUTE;
export const DAY = 24 * HOUR;
export const MAX_MS = 2 ** 53 - 1;

/** The public description of an account for a vector file. */
export function describe(a) {
  return {
    userId: a.userId,
    seedB64: b64u(a.seed),
    identityPubB64: b64u(a.identityPub),
    signPubB64: b64u(a.signPub),
  };
}
