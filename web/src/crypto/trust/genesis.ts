import { ctEquals, toB64 } from "../bytes";
import { adVkPersonal } from "../ad";
import { open } from "../envelope";
import { allZero } from "../keyfloor";
import { ed25519PkToCurve25519, type KeyPairBytes } from "../provider";
import { CryptoError } from "../sodium";
import { type Checked, ok, refused } from "./checked";
import { encodeStatement, parseFrame } from "./codec";
import { frameHash, type FrameVerdict, signatureValid, signerIs, signFrame } from "./frame";
import { fromB64Exact } from "./grammar";

/**
 * The account genesis record (design 2026-11-15 §5, purpose 0x05): signed once, at registration, by the
 * account's own identity key. It binds the account to its instance and to its one personal vault, so a
 * server can swap neither later. Twin of core `AccountGenesis`, graded off the same `accountgenesis.json`.
 *
 * ```
 * {"v":2,"purpose":"account-genesis","userId":<uuid>,"identityKey":<b64_32>,"instanceId":<uuid>,
 *  "personalVaultId":<uuid>,"createdAt":<ms>}
 * ```
 */

export interface GenesisFields {
  readonly userId: string;
  /** The account's X25519 identity key, `b64_32` text. */
  readonly identityKey: string;
  readonly instanceId: string;
  /** The account's one personal vault, forever (§5.3). */
  readonly personalVaultId: string;
  readonly createdAt: number;
}

/** §2.4 "Account genesis" (VR-13), in check order. Every one is the same identity security fault (`IDENTITY_MISMATCH` copy). */
export type GenesisVerdict =
  | FrameVerdict
  | "signer_not_pinned_key"
  | "bad_signature"
  | "identity_mismatch"
  | "user_mismatch"
  | "instance_mismatch"
  | "personal_vault_mismatch";

declare const verifiedGenesis: unique symbol;

/** A genesis that passed every check of {@link verifyGenesis}. `hash` is `H(frame)`. */
export interface VerifiedGenesis {
  readonly [verifiedGenesis]: true;
  readonly fields: GenesisFields;
  readonly hash: string;
}

/** What an unlock checks the genesis against (§5.2). */
export interface GenesisExpectation {
  /**
   * The Ed25519 signing key derived from the identity SEED at this unlock (`crypto_sign_seed_keypair`). The
   * genesis's `signerPub` must equal it byte for byte (§2.4, the Signer binding row 0x05): its X25519 image
   * is not enough, because the negated key shares it.
   */
  readonly signPub: Uint8Array;
  /** The X25519 key derived from the identity SEED at this unlock, never the served `identityPub`: what `identityKey` must equal. */
  readonly identityPub: Uint8Array;
  /** The session's `userId`. */
  readonly userId: string;
  /** The pinned card's `instanceId`. */
  readonly instanceId: string;
  /** The served `personalWrap.vaultId`, or null when no wrap is served. */
  readonly personalVaultId: string | null;
}

/**
 * Encode and sign the genesis with `signer`, the account's joint Ed25519 key, at registration (§5.2: the
 * registering client signs exactly one; that single call site is the sign-up flow's to keep). Throws
 * `CryptoError` outside the grammar and for a signer that does not map to `identityKey`.
 */
export function signGenesis(signer: KeyPairBytes, genesis: GenesisFields): Uint8Array {
  let image: Uint8Array;
  try {
    image = ed25519PkToCurve25519(signer.publicKey);
  } catch (e) {
    throw new CryptoError("account genesis: the signer is not a usable Ed25519 key", { cause: e });
  }
  if (toB64(image) !== genesis.identityKey) throw new CryptoError("account genesis: signed by the identity key it names");
  const statement = encodeStatement("account-genesis", {
    userId: genesis.userId, identityKey: genesis.identityKey, instanceId: genesis.instanceId,
    personalVaultId: genesis.personalVaultId, createdAt: String(genesis.createdAt),
  });
  return signFrame(signer, "account-genesis", statement);
}

/**
 * §5.2 at EVERY unlock, online and offline (against the genesis cached with the AccountKeys, R14), in
 * §2.4's order; the first failure is the verdict:
 *
 * 1. the parse verdicts;
 * 2. `signer_not_pinned_key`: `signerPub` is not, byte for byte, the seed-derived Ed25519 key; `bad_signature`;
 * 3. `identity_mismatch`: `identityKey` is not the seed-derived X25519 key;
 * 4. `user_mismatch`: `userId` is not the session's;
 * 5. `instance_mismatch`: `instanceId` is not the pinned card's;
 * 6. `personal_vault_mismatch`: a served wrap names another vault than `personalVaultId`.
 */
export function verifyGenesis(frame: Uint8Array, expect: GenesisExpectation): Checked<VerifiedGenesis, GenesisVerdict> {
  const parsed = parseFrame(frame, "account-genesis");
  if (!parsed.ok) return parsed;
  const { raw, parts } = parsed.value;
  if (!signerIs(parts, expect.signPub)) return refused("signer_not_pinned_key");
  if (!signatureValid(parts)) return refused("bad_signature");
  const named = fromB64Exact(raw.identityKey!, 32);
  if (named === null || expect.identityPub.length !== 32 || !ctEquals(named, expect.identityPub)) return refused("identity_mismatch");
  if (raw.userId !== expect.userId) return refused("user_mismatch");
  if (raw.instanceId !== expect.instanceId) return refused("instance_mismatch");
  if (expect.personalVaultId !== null && raw.personalVaultId !== expect.personalVaultId) return refused("personal_vault_mismatch");
  const fields: GenesisFields = {
    userId: raw.userId!, identityKey: raw.identityKey!, instanceId: raw.instanceId!, personalVaultId: raw.personalVaultId!,
    createdAt: Number(raw.createdAt),
  };
  return ok(Object.freeze({ fields: Object.freeze(fields), hash: frameHash(frame) }) as VerifiedGenesis);
}

/**
 * §5.3: the personal vault's key when a served wrap is IN FORCE, on any device, with no question: it
 * names the verified genesis's `personalVaultId` and opens under `uvk` with
 * `andvari/v1|vk-personal|{vaultId}|{userId}`. Null for a withheld, foreign or unopenable wrap: "no
 * personal vault", an anomaly, not the identity fault.
 */
export function personalWrapInForce(
  genesis: VerifiedGenesis,
  uvk: Uint8Array,
  wrap: { readonly vaultId: string; readonly wrappedVk: Uint8Array } | null,
): Uint8Array | null {
  if (wrap === null || wrap.vaultId !== genesis.fields.personalVaultId) return null;
  try {
    const vk = open(uvk, wrap.wrappedVk, adVkPersonal(genesis.fields.personalVaultId, genesis.fields.userId));
    // Core AccountOpen.check twin: a wrap that opens to zeros does not open, so no personal vault is in force.
    if (vk.length === 32 && !allZero(vk)) return vk; // the caller's to wipe
    vk.fill(0);
    return null;
  } catch {
    return null;
  }
}
