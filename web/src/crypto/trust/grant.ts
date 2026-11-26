import { toB64 } from "../bytes";
import { requireKey } from "../keyfloor";
import { type KeyPairBytes, sealOpen, sealTo } from "../provider";
import { CryptoError } from "../sodium";
import { type Checked, ok, refused } from "./checked";
import { encodeStatement, parseFrame, type ParsedFrame, secretOf } from "./codec";
import { type FrameVerdict, signatureValid, signerMapsTo, signFrame, wipeFrameParts } from "./frame";
import { fromB64Exact } from "./grammar";
import { type AddRecord, keyMatches, latestAddOf, type VaultState } from "./vaultlog";

/**
 * Vault grants under the amended binding of design 2026-11-15 §3.5 (purpose 0x01; the statement
 * template is unchanged from spec 01 §6). A grant is honoured only when the vault's VERIFIED LOG
 * carries the owner-signed `add` entry it belongs to, and its key matches the commitment fixed at
 * genesis. Twin of core `VaultGrant`, graded off `next/sharedgrant-v2.json`. It replaced the
 * removed `signedgrant.ts`, which trusted a contact pin and a held key instead of the log.
 */

export interface GrantFields {
  readonly from: string;
  readonly to: string;
  /** The recipient's X25519 identity key, `b64_32` text. */
  readonly toKey: string;
  readonly vaultId: string;
  /** A `b64_16` the `add` entry repeats. */
  readonly grantId: string;
  readonly issuedAt: number;
  readonly vk: Uint8Array;
}

/** §3.5's ten checks, in order. `unknown_format` is step 2 under §2.4's frame order (another magic). */
export type VaultGrantVerdict =
  | "unopenable"
  | FrameVerdict
  | "misaddressed"
  | "vault_mismatch"
  | "no_add_entry"
  | "not_authorized"
  | "bad_signature"
  | "vk_commit_mismatch"
  | "removed";

/**
 * A grant that passed all ten checks. `add` is the `add` entry it was bound to: its `actor` is the
 * owner who shared the vault and its `seq` the `addSeq` an `accepted` record must answer (FS-R6).
 * Passing these checks is NOT adoption (§3.6). `vk` is the caller's to wipe once it is wrapped under the UVK.
 */
export interface OpenedGrant {
  readonly vk: Uint8Array;
  readonly from: string;
  readonly grantId: string;
  readonly issuedAt: number;
  readonly add: AddRecord;
}

/**
 * Encode and sign a grant with `signer`, the OWNER's joint Ed25519 key. Throws `CryptoError` outside the
 * grammar or for `from == to`. The vault key is written into the statement from its bytes and never
 * becomes a string. The frame returned holds it in the clear: seal it ({@link sealVaultGrant}) and wipe it.
 */
export function signVaultGrant(signer: KeyPairBytes, grant: GrantFields): Uint8Array {
  if (grant.vk.length !== 32) throw new CryptoError("vault grant: vk must be 32 bytes");
  requireKey(grant.vk); // spec 01 rule 4: a wiped vault key is never granted (KeysGoneError)
  const statement = encodeStatement(
    "vault-grant",
    { from: grant.from, to: grant.to, toKey: grant.toKey, vaultId: grant.vaultId, grantId: grant.grantId, issuedAt: String(grant.issuedAt) },
    { vk: grant.vk },
  );
  try {
    return signFrame(signer, "vault-grant", statement);
  } finally {
    statement.fill(0);
  }
}

/** `crypto_box_seal` of a signed grant frame to the member's identity key, the `memberKey` of its `add` entry. */
export function sealVaultGrant(memberKey: Uint8Array, frame: Uint8Array): Uint8Array {
  if (memberKey.length !== 32) throw new CryptoError("vault grant: member key must be 32 bytes");
  return sealTo(memberKey, frame);
}

/**
 * The recipient's checks, in §3.5's order; the first failure is the verdict.
 *
 * 1. The seal opens with this account's identity key pair (`unopenable`).
 * 2. A frame of purpose 0x01 (`bad_frame`; `unknown_format` for another magic).
 * 3. Strict parse (`non_canonical`, `bad_statement`).
 * 4. `to` is this account and `toKey` its SEED-DERIVED key (`misaddressed`).
 * 5. `vaultId` is the vault of the grant row it arrived on (`vault_mismatch`).
 * 6. In `state`, the vault's verified log state, THIS ACCOUNT'S LATEST `add` entry has this `grantId`
 *    and this account's key as `memberKey`. O is its actor and K the owner key at that entry. A grant
 *    bound to an earlier `add` of the account, or to none, is `no_add_entry` (also when `state` is
 *    null or another vault's). After a remove and a re-add only the new `add`'s grant opens, so a
 *    server cannot put an old grant back and have the prompt name an earlier owner.
 * 7. `from` is O, and the signer maps to K (`not_authorized`).
 * 8. The signature verifies (`bad_signature`).
 * 9. `commit(vk)` is the state's `vkCommit` (`vk_commit_mismatch`).
 * 10. This account is a member at the verified head (`removed`).
 *
 * The opened frame, its parts and every copy of the key this function makes are wiped before it
 * returns, except the `vk` it hands back. Two copies are out of its reach: libsodium's, inside its
 * WebAssembly memory, and WebCrypto's, inside the key object the commitment's HMAC imports.
 */
export async function openVaultGrant(
  me: { readonly userId: string; readonly identityPub: Uint8Array; readonly identityPriv: Uint8Array },
  rowVaultId: string,
  sealed: Uint8Array,
  state: VaultState | null,
): Promise<Checked<OpenedGrant, VaultGrantVerdict>> {
  // Spec 01 rule 4: a wiped identity key opens nothing, and is a lock (KeysGoneError), never an unopenable grant.
  requireKey(me.identityPriv);
  let frame: Uint8Array;
  try {
    frame = sealOpen(me.identityPub, me.identityPriv, sealed);
  } catch {
    return refused("unopenable");
  }
  // The frame holds the vault key in the clear. Whatever the outcome, the frame, its split parts and
  // (unless it is handed to the caller) the decoded key are wiped before this returns.
  let parsed: ParsedFrame | null = null;
  let vk: Uint8Array | null = null;
  let handedOver = false;
  try {
    const p = parseFrame(frame, "vault-grant");
    if (!p.ok) return p;
    parsed = p.value;
    const { raw, parts } = parsed;
    const myKey = toB64(me.identityPub);
    if (raw.to !== me.userId || raw.toKey !== myKey) return refused("misaddressed");
    if (raw.vaultId !== rowVaultId) return refused("vault_mismatch");

    if (state === null || state.vaultId !== rowVaultId) return refused("no_add_entry");
    const add = latestAddOf(state, me.userId); // this account's latest add: the state keeps no earlier one
    if (add === null || add.grantId !== raw.grantId || add.memberKey !== myKey) return refused("no_add_entry");

    const ownerKey = fromB64Exact(add.ownerKey, 32);
    if (raw.from !== add.actor || ownerKey === null || !signerMapsTo(parts, ownerKey)) return refused("not_authorized");
    if (!signatureValid(parts)) return refused("bad_signature");

    vk = secretOf(parsed, "vk"); // straight from the statement bytes: the key is never a string
    if (!(await keyMatches(state.vaultId, state.vkCommit, vk))) return refused("vk_commit_mismatch");
    if (!Object.prototype.hasOwnProperty.call(state.members, me.userId)) return refused("removed");
    handedOver = true;
    return ok({ vk, from: raw.from!, grantId: raw.grantId!, issuedAt: Number(raw.issuedAt), add });
  } finally {
    frame.fill(0);
    if (parsed !== null) wipeFrameParts(parsed.parts);
    if (vk !== null && !handedOver) vk.fill(0);
  }
}
