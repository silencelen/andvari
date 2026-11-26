import type { AccountKeysV2 } from "../api/wire";
import { adIdkey } from "../crypto/ad";
import { ctEquals, fromB64, toB64, toHexLower } from "../crypto/bytes";
import { openKey } from "../crypto/envelope";
import { allZero } from "../crypto/keyfloor";
import { shortForm } from "../crypto/fingerprint";
import { boxKeypairFromSeed, type KeyPairBytes, sha256Sync, signKeypairFromSeed } from "../crypto/provider";
import { type VerifiedGenesis, personalWrapInForce, verifyGenesis } from "../crypto/trust/genesis";
import { fromB64Canonical, fromB64Exact } from "../crypto/trust/grammar";

/**
 * The identity checks every session open runs (design §5.2, §5.3, §2.4 VR-13), in the core engine's
 * `AccountOpen` order: the identity seed opens under the UVK; the served `identityPub` equals the
 * seed-derived key; a genesis is served; the genesis verifies against the seed-derived key, the session's
 * user, the PINNED card's instanceId and the served wrap's vaultId; this browser's own earlier record of the
 * identity key agrees. Then the personal wrap: in force only when it names the genesis vault and opens.
 *
 * Run at sign-in, after registration (on the server's echo of what this browser sent), and at every unlock.
 * Any failure is the identity security fault (`IDENTITY_MISMATCH` copy); every key is wiped on a refusal.
 */
export interface OpenedAccount {
  readonly userId: string;
  readonly uvk: Uint8Array;
  readonly identity: KeyPairBytes;
  readonly signing: KeyPairBytes;
  readonly genesis: VerifiedGenesis;
  /** Set only when the served personal wrap names the genesis vault AND opens: otherwise no personal vault is in force (an anomaly). */
  readonly personalVaultId: string | null;
  readonly personalVk: Uint8Array | null;
}

export type AccountOpenResult = { readonly kind: "opened"; readonly account: OpenedAccount } | { readonly kind: "identity_fault"; readonly reason: string };

export const SEED_UNOPENABLE = "seed_unopenable";
/** The account key that was opened is all zeros: the wrap (or recovery copy) is damaged. */
export const UVK_DAMAGED = "uvk_damaged";
export const IDENTITY_PUB_MISMATCH = "identity_pub_mismatch";
export const NO_GENESIS = "no_genesis";
export const SELF_IDENTITY_MISMATCH = "self_identity_mismatch";

/** The account ID shown on a kit and in notices: the 32-hex short identity fingerprint (spec 01 §5). */
export function accountId(identityPub: Uint8Array): string {
  return shortForm(toHexLower(sha256Sync(identityPub)));
}

export function wipeOpened(a: OpenedAccount): void {
  a.uvk.fill(0);
  a.identity.privateKey.fill(0);
  a.signing.privateKey.fill(0);
  a.personalVk?.fill(0);
}

/** Opens [keys] with [uvk] (taken: wiped on every refusal, owned by the result on success). */
export function openAccount(userId: string, uvk: Uint8Array, keys: AccountKeysV2, pinnedInstanceId: string, knownIdentityPub: Uint8Array | null): AccountOpenResult {
  // Core Account.unlock / unlockFromUvk twin: an account key or a seed of zeros is damaged keys, refused as such on
  // every opening (password, copy, sign-in, recovery), never read as a lock.
  if (allZero(uvk)) return { kind: "identity_fault", reason: UVK_DAMAGED };
  let seed: Uint8Array;
  try {
    seed = openKey(uvk, fromB64(keys.encryptedIdentitySeed), adIdkey(userId), "the identity seed");
  } catch {
    uvk.fill(0);
    return { kind: "identity_fault", reason: SEED_UNOPENABLE };
  }
  let identity: KeyPairBytes;
  let signing: KeyPairBytes;
  try {
    identity = boxKeypairFromSeed(seed);
    signing = signKeypairFromSeed(seed);
  } finally {
    seed.fill(0);
  }
  return checkOpened(userId, uvk, identity, signing, keys.identityPub, keys.genesis, keys.personalWrap, pinnedInstanceId, knownIdentityPub);
}

/** The checks after the seed is open (graded by accountopen.test.ts on accountgenesis.json). */
export function checkOpened(
  userId: string,
  uvk: Uint8Array,
  identity: KeyPairBytes,
  signing: KeyPairBytes,
  servedIdentityPub: string,
  genesisB64: string | null,
  wrap: { vaultId: string; wrappedVk: string } | null,
  pinnedInstanceId: string,
  knownIdentityPub: Uint8Array | null,
): AccountOpenResult {
  const fault = (reason: string): AccountOpenResult => {
    uvk.fill(0);
    identity.privateKey.fill(0);
    signing.privateKey.fill(0);
    return { kind: "identity_fault", reason };
  };
  const served = fromB64Exact(servedIdentityPub, 32);
  if (served === null || !ctEquals(served, identity.publicKey)) return fault(IDENTITY_PUB_MISMATCH);
  if (genesisB64 === null) return fault(NO_GENESIS);
  const frame = fromB64Canonical(genesisB64);
  if (frame === null) return fault("bad_frame");
  const v = verifyGenesis(frame, { signPub: signing.publicKey, identityPub: identity.publicKey, userId, instanceId: pinnedInstanceId, personalVaultId: wrap?.vaultId ?? null });
  if (!v.ok) return fault(v.verdict);
  if (knownIdentityPub !== null && !ctEquals(knownIdentityPub, identity.publicKey)) return fault(SELF_IDENTITY_MISMATCH);
  let wrapped: Uint8Array | null = null;
  if (wrap) wrapped = fromB64Canonical(wrap.wrappedVk);
  const vk = wrap && wrapped ? personalWrapInForce(v.value, uvk, { vaultId: wrap.vaultId, wrappedVk: wrapped }) : null;
  return {
    kind: "opened",
    account: { userId, uvk, identity, signing, genesis: v.value, personalVaultId: vk ? v.value.fields.personalVaultId : null, personalVk: vk },
  };
}

/** The identity key as the self-identity record keeps it. */
export const identityPubB64 = (a: OpenedAccount): string => toB64(a.identity.publicKey);
