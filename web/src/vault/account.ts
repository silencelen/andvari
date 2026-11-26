import { adAccountState, adIdkey, adItem, adUsage, adUvk, adVaultMeta, adVk, adVkPersonal } from "../crypto/ad";
import { type AccountStateDoc, decodeAccountState, encodeAccountState } from "./accountstate";
import { usageKey } from "../crypto/usagekey";
import type { OpenedAccount } from "./accountopen";
import { ctEquals, fromB64, fromUtf8, toB64, utf8 } from "../crypto/bytes";
import { open, openKey, seal, structuralRefusal } from "../crypto/envelope";
import { allZero } from "../crypto/keyfloor";
import { fingerprint as recoveryFingerprint, sealUvkV3 } from "../crypto/escrow";
import { assertServerKdfParams, authKey as deriveAuthKey, masterKey, wrapKey as deriveWrapKey, type KdfParams } from "../crypto/keys";
import { generate as generateMemberRecovery, openUvk as openMemberRecoveryUvk } from "../crypto/member-recovery";
import { boxKeypairFromSeed, randomBytes, signKeypairFromSeed } from "../crypto/provider";
import { identityFingerprint, shortIdentityFingerprint } from "../crypto/fingerprint";
import { CryptoError } from "../crypto/sodium";
import { emailNorm, plainTextOf } from "../crypto/trust/grammar";
import { itemDocProblem, vaultMetaName } from "./itemdoc-shape";
import { type ItemLogHead, stampLogHead } from "./itemhead";
import type { SealProvenance } from "./itemhome";
import { type SessionKeys, SessionWrap } from "./sessionwrap";
import { VAULT_KEY_NOT_VERIFIED } from "../ui/copy";
import type {
  AccountKeys,
  EscrowUpload,
  ItemDoc,
  ItemVersion,
  PersonalWrap,
  RecoveryCommitRequest,
  RecoverySelfSetupRequest,
  RecoveryVerifyResponse,
  RegisterRequest,
  WireGrant,
  WireItem,
} from "../api/types";

/**
 * Where the personal vault came from (security review 2026-10, root cause A §4.3). Design §5.3: it is the genesis
 * vault, in force only when its served wrap opened at unlock. "confirmed": the wrap opened. "absent": none was served.
 * "unreadable": one was served and did not open (an anomaly). Nothing designates, proposes or re-designates a personal
 * vault, and no cached wrap stands in for a served one (design §15's web row).
 */
export type PersonalStatus = "confirmed" | "absent" | "unreadable";

/** A6b carry-forward (A1b): the reauth could not be checked because this session unlocked with a salt the account no
 *  longer has (a password change or a KDF upgrade since). Core twin `ReauthStaleSessionException` /
 *  `HouseholdCopy.REAUTH_STALE_SESSION`, byte-equal (vault-copy.test.ts). Lives here since A9 (M-1): the one fenced
 *  reauth derivation ({@link Account.reauthAuthKey}) raises it. */
export class ReauthStaleSessionError extends Error {
  constructor() {
    super("Lock and unlock andvari, then try again.");
    this.name = "ReauthStaleSessionError";
  }
}

/** A6b: the master password given for a reauth does not open this account's key. Core twin `ReauthFailedException` /
 *  `HouseholdCopy.REAUTH_FAILED`, byte-equal (vault-copy.test.ts). Lives here since the A9 review (LOW-1): the one
 *  fenced reauth derivation PROVES the password and raises it. */
export class ReauthFailedError extends Error {
  constructor() {
    super("That master password isn't right.");
    this.name = "ReauthFailedError";
  }
}

/** Highest item formatVersion this client can decrypt (spec 02 §3 fail-closed; core parity). */
export const ITEM_FORMAT_VERSION = 2;

/**
 * Lowest formatVersion a doc may seal at (spec 02 §3): card-bearing docs 2, logins/notes 1.
 * The floor is the one plaintext signal a zero-knowledge server gets — it turns a pre-card
 * client's rewrite (a plain decode silently drops the unknown `card` key) into a
 * server-refused fv downgrade instead of silent loss, while fv1 docs stay fully readable
 * on every fielded client.
 */
export function docFloor(doc: ItemDoc): number {
  return doc.card != null || doc.type === "card" ? 2 : 1;
}

/** encryptItem's result: the sealed blob plus the formatVersion it was sealed (and AD-bound)
 *  at — read the wire fv from HERE, never restate it, or the two diverge into an AD mismatch.
 *  (The wire ItemUpload in api/types adds attachmentIds, which the store derives from the doc.) */
export interface ItemUpload {
  formatVersion: number;
  blob: string;
}

/**
 * spec 01 §5 MUST (F31, core Account.unlock parity): the server-sent `identityPub` did
 * not match the public key derived from the account's sealed identity seed — a
 * pubkey-substitution attempt (or corrupted account row). Deliberately a DISTINCT type
 * from CryptoError so the auth surfaces can never present it as "wrong master password".
 */
export class IdentityMismatchError extends Error {
  constructor() {
    super("Server identity key mismatch — possible tampering. Do not proceed; contact your admin.");
    this.name = "IdentityMismatchError";
  }
}

/**
 * Audit H67 — the sentence, and the type that guarantees no ladder can relabel it. TWIN of core
 * `HouseholdCopy.ACCOUNT_KEYS_DAMAGED` and the extension's `keys_damaged` unlock row; byte-identical
 * on all three canons (ASCII apostrophe, no em dash), so a reword is a deliberate three-sided change.
 */
export const VAULT_KEYS_DAMAGED =
  "This account's stored keys are damaged or from a newer version, so sign-in cannot continue. Contact your admin or restore from a backup.";

/**
 * spec 01 §4, spec 02 §2 (audit H67, core `VaultKeyDamagedException` parity): a server-supplied
 * ACCOUNT-KEY blob — `wrappedUvk`, or (R38) its sibling `encryptedIdentitySeed` — is not a
 * well-formed envelope AT ALL: not decodable base64url, or its public header says "too short" /
 * an envelope version or AEAD alg this build does not know. (R42: the normative bullet is spec 01
 * §4, not §5 — the twins' citations must point at the same section.)
 *
 * WHY THIS IS ITS OWN TYPE, at length, because the entire point is that it must never be relabelled:
 * only the AEAD tag failure at the END of an envelope open is genuinely indistinguishable from a
 * wrong master password — it is precisely what a wrong password produces. These refusals are decided
 * from the blob's PUBLIC header, BEFORE the wrap key is applied, so no password could ever have made
 * them pass. Folding them into "Wrong email or master password" (which every client did before this
 * row) tells a household member whose account row was corrupted by a partial DB restore — or who is
 * on an old build a newer server just fed a v2 envelope — to reset a password that works, and then to
 * burn their recovery secret when the reset does not help. Deliberately NOT a CryptoError (the
 * {@link IdentityMismatchError} precedent): every unlock ladder maps a CryptoError to "wrong master
 * password", so living outside that type is what makes the collapse structurally impossible rather
 * than merely un-coded-for today. TERMINAL, never retryable: the same blob fails identically forever.
 */
export class VaultKeyDamagedError extends Error {
  constructor(detail: string, cause?: unknown) {
    super(VAULT_KEYS_DAMAGED);
    this.name = "VaultKeyDamagedError";
    /** Debug detail only — the SENTENCE is `message`; surfaces render that, never this. */
    (this as { detail?: string }).detail = detail;
    if (cause !== undefined) (this as { cause?: unknown }).cause = cause;
  }
}

/**
 * INV-WRITE-KEY (security review 2026-10, root cause A §5.1; core `VaultKeyNotVerifiedException` twin): nothing is
 * sealed under this vault's key, because the verified log does not let this account write to it (design §3.9: not
 * a member of a verified log, or a reader). Not a CryptoError, so no save ladder can read it as "wrong master
 * password".
 */
export class VaultKeyNotVerifiedError extends Error {
  constructor(readonly vaultId: string) {
    super(VAULT_KEY_NOT_VERIFIED);
    this.name = "VaultKeyNotVerifiedError";
  }
}

/**
 * A decrypted item document failed the spec 02 §3.2 shape check ({@link itemDocProblem}). Thrown by
 * {@link Account.decryptItem}; every store path catches a decrypt failure and files the item under
 * undecryptable — QUARANTINED, kept by identity for a backup, never rendered. Not a CryptoError:
 * the envelope opened fine, its author is what is wrong (core MalformedItemException twin).
 */
export class MalformedItemError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "MalformedItemError";
  }
}

/** A vault meta document that opened under the VK but is not a JSON object (security review 2026-10, branch A11, q55;
 *  core MalformedVaultMetaException twin): its author, a holder of the vault key, is what is wrong. */
export class MalformedVaultMetaError extends Error {
  constructor(vaultId: string) {
    super(`the meta document of vault ${vaultId} is not a JSON object`);
    this.name = "MalformedVaultMetaError";
  }
}

function uuidv4(): string {
  return crypto.randomUUID();
}

/**
 * An unlocked account: holds the in-memory UVK, identity key, and the personal
 * vault key, and encrypts/decrypts items. All AEAD is AD-bound to (userId, vaultId,
 * itemId) per spec 02 §2. Nothing here is persisted in the clear.
 */
export class Account {
  /** vaultId → role from the latest grant seen (spec 03 §10: role changes re-deliver the grant). */
  private readonly vaultRoles = new Map<string, string>();

  /** Spec 01 §7: the wrap this session keeps (the salt, cost and wrapped UVK the password opened or this tab sealed),
   *  against which every re-authentication is proven on this device. None held: no reauth passes (fail closed). */
  private sessionWrapValue: SessionWrap = new SessionWrap(null);

  /** Root cause A §3.1: vaults whose served row carried a wrap of ours that opened to a DIFFERENT key than the one
   *  held ("vault key mismatch"; the held key was kept). Core: `vkMismatchVaults`. */
  private readonly vkMismatchVaults = new Set<string>();

  /**
   * Shared vaults governed by a signed vault log (design §3): their keys are installed and removed only by the log
   * store's adoption (§3.6), and their roles come from the verified log, never from a served row.
   */
  private readonly logGoverned = new Set<string>();
  private logRoles: ((vaultId: string) => string | null) | null = null;
  private logWrites: ((vaultId: string) => boolean) | null = null;
  /**
   * Beside each key of a log-governed vault: the number of the log's `add` entry under which this session adopted it
   * (NaN for a key that is never a working key: one opened only to seal a held copy). Absent for a key put in the ring
   * without one (only test fixtures do).
   */
  private readonly keyAdds = new Map<string, number>();
  /**
   * The number of the `add` entry through which the vault's verified log names this account now: null where the log
   * does not name it (removed, deleted, or nothing verified). Attached by the store with the shared-vault layer.
   */
  private logMember: ((vaultId: string) => number | null | undefined) | null = null;

  /** itemId → highest formatVersion this session decrypted or sealed it at. Reseals take
   *  max(docFloor, this): the server enforces per-item monotonic fv, so an edit must never
   *  re-seal below the version it arrived at. In-memory only by design — web holds no
   *  durable cache, and every doc reaching a reseal was decrypted here first. */
  private readonly itemFv = new Map<string, number>();

  private constructor(
    readonly userId: string,
    private readonly uvk: Uint8Array,
    private readonly identityPriv: Uint8Array,
    readonly identityPub: Uint8Array,
    /**
     * The JOINT Ed25519 signing key (security review 2026-10, root cause A §1.1, owner decision: joint key):
     * crypto_sign_seed_keypair over the same identity seed, so `ed25519PkToCurve25519(signPub)`
     * equals `identityPub` and no fingerprint changes. Derived at enrol/unlock, held for the session
     * exactly like `identityPriv`, never persisted. Twin of core `Account.signPub`.
     */
    readonly signPub: Uint8Array,
    private readonly signSecret: Uint8Array,
    personalVaultId: string,
    private readonly vaultKeys: Map<string, Uint8Array>,
  ) {
    this.personalVaultIdValue = personalVaultId;
  }

  /**
   * The personal vault (security review 2026-10, root cause A §4): named by `AccountKeys.personalWrap`
   * (only this user's UVK can mint it, {@link applyPersonalWrap}), the wrap enrolment minted, or the opened session's
   * genesis vault (design §5.3). "" = no personal vault: no default destination, no usage ledger.
   * NEVER set from a server `type` label or `role`. Core twin: `Account.personalVaultId`.
   */
  get personalVaultId(): string {
    return this.personalVaultIdValue;
  }

  private personalVaultIdValue: string;

  /** Where the personal vault came from (core `PersonalStatus` twin). */
  get personalStatus(): PersonalStatus {
    return this.personalStatusValue;
  }

  private personalStatusValue: PersonalStatus = "absent";

  /** Vaults whose key opened from a UVK wrap of OURS (own grant row or the personal wrap), never a seal. */
  private readonly uvkWrappedVaults = new Set<string>();

  /**
   * Enrollment (spec 01/04, design 2026-07-12 §F.4): generate all keys client-side, CONDITIONALLY
   * seal org escrow, ALWAYS mint the per-member self-service recovery piece, and produce the one-shot
   * register request plus the SHOWN-ONCE `recoverySecret`.
   *
   * Escrow is policy-driven by the org key: pass `recoveryPublicKey` (+ its already-verified
   * `recoveryFingerprint`, the human out-of-band anchor — never a server-sourced value the client
   * auto-trusted) for a `required` invite → the UVK is sealed to the org key with the same
   * verified-fingerprint discipline as before. Pass neither for a `waived` invite → no escrow blob.
   * The member-recovery piece is MANDATORY regardless, so an account can never be created with
   * neither recovery path.
   *
   * `recoverySecret` (the raw 32 CSPRNG bytes) is returned for the UI to display ONCE and then drop
   * (§F.7 shown-once discipline); it is NEVER persisted here.
   */
  static async enroll(params: {
    inviteToken: string;
    email: string;
    displayName: string;
    password: string;
    kdfParams: KdfParams;
    /** `required` invite → the org recovery PUBLIC key to seal escrow to; omit for a `waived` invite. */
    recoveryPublicKey?: Uint8Array | null;
    /** The org recovery FULL fingerprint the human anchored (printed sheet / in-person QR). Required
     *  when sealing escrow; enroll refuses to seal a UVK to a key whose fingerprint differs. */
    recoveryFingerprint?: string | null;
    /** F28: stable per-browser-install id (see ui/session.ts installId) — additive; the fielded server ignores it. */
    installId?: string;
  }): Promise<{ request: RegisterRequest; account: Account; recoverySecret: Uint8Array }> {
    const userId = uuidv4();
    const personalVaultId = uuidv4();
    const kdfSalt = randomBytes(16);
    // ZEROIZATION (audit H80, spec 01 §2; the TWIN of core Account.enroll): the MK lives only
    // long enough to split into its two purposes, and authKey, wrapKey and the raw identity seed
    // die once the request carries their encoded/sealed forms. Best-effort in a managed runtime,
    // but it takes the buffers a whole account re-derives from off the heap the moment they are
    // dead instead of leaving them to GC — the difference between a memory disclosure costing a
    // session and costing the account. The UVK and VK are NOT wiped: the returned Account owns
    // them for the session, and wiping them would be wiping the unlocked vault.
    const mk = masterKey(params.password, kdfSalt, params.kdfParams);
    let authKey: Uint8Array;
    let wrapKey: Uint8Array;
    try {
      authKey = await deriveAuthKey(mk);
      wrapKey = await deriveWrapKey(mk);
    } finally {
      mk.fill(0);
    }

    const uvk = randomBytes(32);
    const identitySeed = randomBytes(32);
    const vk = randomBytes(32);
    // The joint signing secret embeds the seed: wiped with it if anything below throws before the
    // Account takes ownership.
    let signingForCleanup: Uint8Array | null = null;
    try {
      const identity = boxKeypairFromSeed(identitySeed);
      const signing = signKeypairFromSeed(identitySeed);
      signingForCleanup = signing.privateKey;
      const wrappedUvk = seal(wrapKey, uvk, adUvk(userId));
      const encryptedIdentitySeed = seal(uvk, identitySeed, adIdkey(userId));
      const wrappedVk = seal(uvk, vk, adVk(personalVaultId, userId));
      const metaBlob = seal(vk, utf8(JSON.stringify({ name: "Personal" })), adVaultMeta(personalVaultId));

      // Org escrow is CONDITIONAL (§F.4): sealed only for a `required` invite (org key present),
      // preserving the verified-fingerprint discipline — refuse to seal the UVK to a key whose
      // fingerprint the enrollee did not confirm out-of-band. Waived ⇒ no escrow blob (undefined
      // ⇒ JSON.stringify omits the key, which the server requires when the invite is waived).
      let escrow: EscrowUpload | undefined;
      if (params.recoveryPublicKey != null) {
        const fp = params.recoveryFingerprint;
        if (fp == null) throw new CryptoError("recoveryFingerprint is required when sealing org escrow");
        const computedFp = await recoveryFingerprint(params.recoveryPublicKey);
        if (computedFp !== fp) throw new CryptoError("recovery public key does not match its fingerprint");
        // Escrow v2 (security review 2026-10, root cause A §2.1): signed with the joint key, binding
        // this account's userId and identity key and the FULL org fingerprint (core Account.enroll parity).
        // Spec 04 §3: every seal is version 3, naming the address this enrolment sends; one with no emailNorm seals nothing.
        const sealed = await sealUvkV3({
          recoveryPub: params.recoveryPublicKey, verifiedRecoveryFp: fp, userId, emailNorm: emailNorm(params.email) ?? "", identityPub: identity.publicKey, signer: signing, uvk, issuedAt: Date.now(),
        });
        escrow = { sealed: toB64(sealed), fingerprint: fp };
      }

      // Per-member self-service recovery piece — MANDATORY for every new account (§F.4). The 256-bit
      // recoverySecret is GENERATED (never user input) and returned to be SHOWN ONCE.
      const recovery = await generateMemberRecovery(userId, uvk);

      const request: RegisterRequest = {
        inviteToken: params.inviteToken,
        userId,
        email: params.email,
        displayName: params.displayName,
        kdfSalt: toB64(kdfSalt),
        kdfParams: params.kdfParams,
        authKey: toB64(authKey),
        wrappedUvk: toB64(wrappedUvk),
        identityPub: toB64(identity.publicKey),
        encryptedIdentitySeed: toB64(encryptedIdentitySeed),
        escrow,
        memberRecovery: { recoveryWrappedUvk: recovery.recoveryWrappedUvk, recoveryAuthKey: recovery.recoveryAuthKey },
        personalVault: { vaultId: personalVaultId, wrappedVk: toB64(wrappedVk), metaBlob: toB64(metaBlob) },
        device: { platform: "web", name: deviceName(), installId: params.installId },
        // Root cause A §4.1: "personal" is this UVK-authenticated wrap from day one.
        personalWrap: { vaultId: personalVaultId, wrappedVk: toB64(seal(uvk, vk, adVkPersonal(personalVaultId, userId))) },
      };

      const vaultKeys = new Map([[personalVaultId, vk]]);
      const account = new Account(userId, uvk, identity.privateKey, identity.publicKey, signing.publicKey, signing.privateKey, personalVaultId, vaultKeys);
      account.vaultRoles.set(personalVaultId, "owner");
      account.personalStatusValue = "confirmed";
      account.sessionWrapValue = new SessionWrap({ kdfSalt: request.kdfSalt, kdfParams: request.kdfParams, wrappedUvk: request.wrappedUvk }); // the wrap enrolment sealed
      account.uvkWrappedVaults.add(personalVaultId);
      signingForCleanup = null; // owned by the returned Account now
      return { request, account, recoverySecret: recovery.recoverySecret };
    } finally {
      signingForCleanup?.fill(0);
      authKey.fill(0);
      wrapKey.fill(0);
      identitySeed.fill(0);
    }
  }

  /**
   * Self-service account recovery (design §F.3, client half of `POST /recovery/self/commit`). Opens
   * the SAME UVK from the recovery piece, routes it through the shared unlock tail so the spec 01 §5
   * identity-pubkey HARD-FAIL fires (a server that substituted an identity key is caught BEFORE
   * commit), then derives fresh {kdfSalt, authKey, wrapKey} from `newPassword` and re-wraps the UVK —
   * producing the commit body. It MUST NOT regenerate UVK / identitySeed / identityPub: the new
   * `newWrappedUvk` wraps the invariant UVK, so both the org-escrow and member-recovery blobs stay
   * valid. A wrong secret / hostile blob fails closed (AEAD tag), surfacing as CryptoError; a
   * substituted identity key surfaces as the distinct {@link IdentityMismatchError}.
   */
  static async recover(params: {
    recoverySecret: Uint8Array;
    verify: RecoveryVerifyResponse;
    newPassword: string;
    newKdfParams: KdfParams;
  }): Promise<RecoveryCommitRequest> {
    const userId = params.verify.userId;
    // 1. Recover the SAME UVK (fail-closed: wrong secret / wrong-or-tampered blob → AEAD tag fail).
    const uvk = await openMemberRecoveryUvk(params.recoverySecret, params.verify.recoveryWrappedUvk, userId);
    // 2. Run the SHARED unlock tail purely for its identity-pubkey hard-fail (§F.8): it opens
    //    encryptedIdentitySeed under the recovered UVK and refuses if the seed-derived pubkey does
    //    not equal verify.identityPub. The returned Account is discarded — only the check matters.
    Account.unlockFromUvk(userId, uvk, {
      kdfSalt: "",
      kdfParams: params.newKdfParams,
      wrappedUvk: "",
      encryptedIdentitySeed: params.verify.encryptedIdentitySeed,
      identityPub: params.verify.identityPub,
      escrowFingerprint: "",
    }).discardProbeSecrets(); // A9: the probe is never a session; its identity and signing secrets die here
    // 3. Derive fresh password material and re-wrap the SAME UVK (invariant).
    // ZEROIZATION (audit H80, spec 01 §2; core Account.recover parity): the new MK, authKey and
    // wrapKey die once the commit body carries their encoded forms — and so does the recovered
    // UVK, because recover() returns a body, not a session (the commit revokes every session and
    // the member signs in afresh, so no caller holds this copy; the step-2 probe Account shares
    // the reference and is already unreachable).
    const newKdfSalt = randomBytes(16);
    const newMk = masterKey(params.newPassword, newKdfSalt, params.newKdfParams);
    let newAuthKey: Uint8Array;
    let newWrapKey: Uint8Array;
    try {
      newAuthKey = await deriveAuthKey(newMk);
      newWrapKey = await deriveWrapKey(newMk);
    } finally {
      newMk.fill(0);
    }
    try {
      return {
        recoveryTicket: params.verify.recoveryTicket,
        newAuthKey: toB64(newAuthKey),
        newKdfSalt: toB64(newKdfSalt),
        newKdfParams: params.newKdfParams,
        newWrappedUvk: toB64(seal(newWrapKey, uvk, adUvk(userId))),
      };
    } finally {
      newAuthKey.fill(0);
      newWrapKey.fill(0);
      uvk.fill(0);
    }
  }

  /** Derive the login authKey from a password + the account's stored salt/params.
   *  ZEROIZATION (audit H80, spec 01 §2 "MK never leaves the KDF step"): MK and the raw authKey
   *  are dead the moment the base64 credential exists — the MK is what the UVK wrap key ALSO
   *  re-derives from, so it never outlives this call. Every MK-derivation site in this class
   *  does the same: {@link enroll}, {@link unlock}, {@link recover}, {@link buildPasswordChange}. */
  static async deriveAuthKey(password: string, kdfSalt: string, params: KdfParams): Promise<string> {
    // PRE-SESSION ONLY (security review 2026-10, branch A9, M-1): the sign-in derivation over the prelogin values,
    // where no session salt exists yet. Fenced on the params regardless (spec 05 T1); every IN-SESSION password proof
    // goes through {@link reauthAuthKey}; a tripwire (api-review-2.test.ts) fails on any other product caller.
    assertServerKdfParams(params);
    const mk = masterKey(password, fromB64(kdfSalt), params);
    try {
      const authKey = await deriveAuthKey(mk);
      try {
        return toB64(authKey);
      } finally {
        authKey.fill(0);
      }
    } finally {
      mk.fill(0);
    }
  }

  /**
   * Unlock a device that has only the password + the server's account keys.
   * Rebuilds UVK and identity; vault keys are added later from grants.
   */
  static async unlock(userId: string, password: string, keys: AccountKeys, selfIdentityPub: Uint8Array | null = null): Promise<Account> {
    // ZEROIZATION (audit H80, spec 01 §2; core Account.unlock parity): after the wrappedUvk open
    // the session needs only the UVK — MK and wrapKey are wiped on the way out, success or
    // failure (a wrong password must not leave the MK it derived on the heap either).
    const mk = masterKey(password, fromB64(keys.kdfSalt), keys.kdfParams);
    let wrapKey: Uint8Array;
    try {
      wrapKey = await deriveWrapKey(mk);
    } finally {
      mk.fill(0);
    }
    // H67 (core Account.unlock parity): STRUCTURE first, secret second. A blob that is not
    // decodable base64url, or whose public header is too short / carries an envelope version or alg
    // this build does not know, is refused BEFORE the wrap key is applied and surfaces as the
    // distinct terminal VaultKeyDamagedError — those refusals cannot possibly mean "wrong password"
    // (no password participates in them), and saying so sent members to reset a working password.
    // Only what remains — the AEAD tag failure, the one genuinely ambiguous outcome — keeps the
    // "wrong master password" relabel.
    let uvk: Uint8Array;
    try {
      let envelope: Uint8Array;
      try {
        envelope = fromB64(keys.wrappedUvk);
      } catch (e) {
        throw new VaultKeyDamagedError("wrappedUvk is not valid base64url", e);
      }
      const refusal = structuralRefusal(envelope);
      if (refusal !== null) throw new VaultKeyDamagedError(`wrappedUvk: ${refusal}`);
      try {
        uvk = open(wrapKey, envelope, adUvk(userId));
      } catch {
        throw new CryptoError("wrong master password");
      }
      // Core Account.unlock twin: a wrap that opens to zeros is damaged keys, never a lock and never a wrong password.
      if (allZero(uvk)) throw new VaultKeyDamagedError("wrappedUvk opened to a key of zeros");
    } finally {
      wrapKey.fill(0);
    }
    // Password path validates the password by the wrappedUvk open above; from here the work is
    // identical to the recovery (UVK-in-hand) path — one shared tail, so the identity-pubkey
    // hard-fail can never diverge between them (core Account.unlock parity).
    const account = Account.unlockFromUvk(userId, uvk, keys, selfIdentityPub);
    account.sessionWrapValue = new SessionWrap({ kdfSalt: keys.kdfSalt, kdfParams: keys.kdfParams, wrappedUvk: keys.wrappedUvk }); // the wrap the password opened
    return account;
  }

  /**
   * Shared unlock tail (spec 01 §5) reached by BOTH {@link unlock} (after it recovers the UVK from
   * the password) and {@link recover} (given the UVK from the member-recovery piece). The identity
   * keypair is DERIVED from the UVK-sealed seed — which the server cannot forge — so a server-sent
   * `identityPub` that does not equal the derived key is a pubkey-substitution attempt: hard-fail
   * with the DISTINCT {@link IdentityMismatchError}, never softened to "wrong password" (including
   * when the field is MALFORMED — garbage where the identity key belongs is exactly the tampering
   * this check exists to name). Keeping it single-sourced is the invariant that stops the recovery
   * path from ever skipping the check.
   *
   * R38 (H67's missing leg, spec 01 §4 + §5): `encryptedIdentitySeed` carries the SAME
   * public-header gate as `wrappedUvk` — it is the sibling account-key blob in the same row,
   * damaged by the same events (a partial DB restore, a newer server serving an envelope version
   * this build does not implement), and without the gate a structurally broken seed collapsed
   * into "Wrong email or master password" one line after H67 stopped saying exactly that. Safe on
   * the UVK-in-hand path too: a wrong or stale UVK can only produce an AEAD TAG failure, never a
   * base64/version/alg refusal, so the "validation by consequence" signal that path relies on is
   * untouched.
   */
  private static unlockFromUvk(userId: string, uvk: Uint8Array, keys: AccountKeys, selfIdentityPub: Uint8Array | null = null): Account {
    let seedEnvelope: Uint8Array;
    try {
      seedEnvelope = fromB64(keys.encryptedIdentitySeed);
    } catch (e) {
      throw new VaultKeyDamagedError("encryptedIdentitySeed is not valid base64url", e);
    }
    const seedRefusal = structuralRefusal(seedEnvelope);
    if (seedRefusal !== null) throw new VaultKeyDamagedError(`encryptedIdentitySeed: ${seedRefusal}`);
    const identitySeed = open(uvk, seedEnvelope, adIdkey(userId));
    // Core unlockFromUvk twin: a seed of zeros is damaged keys, on every unlock and on recovery, never a lock.
    if (allZero(identitySeed)) throw new VaultKeyDamagedError("encryptedIdentitySeed opened to a seed of zeros");
    // ZEROIZATION (audit H80): the seed's only job is to derive the keypairs the Account holds —
    // a compromise of the seed IS a compromise of the identity key, so it gets the MK's care. Both
    // the X25519 identity and the joint Ed25519 signing key (root cause A §1.1) come from it here.
    let identity: ReturnType<typeof boxKeypairFromSeed>;
    let signing: ReturnType<typeof signKeypairFromSeed>;
    try {
      identity = boxKeypairFromSeed(identitySeed);
      signing = signKeypairFromSeed(identitySeed);
    } finally {
      identitySeed.fill(0);
    }
    let serverIdentityPub: Uint8Array | null = null;
    try {
      serverIdentityPub = fromB64(keys.identityPub);
    } catch {
      /* undecodable → treated as a mismatch below */
    }
    if (serverIdentityPub === null || !ctEquals(identity.publicKey, serverIdentityPub)) {
      // The signing secret embeds the seed (libsodium's seed ‖ pk layout): never leave it behind.
      signing.privateKey.fill(0);
      identity.privateKey.fill(0);
      throw new IdentityMismatchError();
    }
    // Design §2.4 (core parity): this browser's own record of the identity key wins over anything the
    // server can change — a recovery that swapped the identity seed is refused on every device that
    // unlocked the account before. (Web code is server-served, spec 05 T6, so on web this guards an
    // honest bundle against a server that only tampers with data, not one that rewrites the app.)
    if (selfIdentityPub !== null && !ctEquals(identity.publicKey, selfIdentityPub)) {
      signing.privateKey.fill(0);
      identity.privateKey.fill(0);
      throw new IdentityMismatchError();
    }
    const account = new Account(userId, uvk, identity.privateKey, identity.publicKey, signing.publicKey, signing.privateKey, "", new Map());
    // Root cause A §4.3: the personal vault comes from the UVK-authenticated wrap and nothing else.
    account.applyPersonalWrap(keys.personalWrap ?? null);
    return account;
  }

  /**
   * The session this browser opened on the post-cut-over flow (vault/accountopen.ts ran every unlock check:
   * seed, served identity key, genesis against the pinned instance, own identity record, personal wrap in
   * force). Takes ownership of [opened]'s keys. The personal vault is the genesis vault, and only when its wrap
   * opened; otherwise there is none (an anomaly the vault shows). [wrap] is the wrap the unlock opened or sealed (spec
   * 01 §7: every re-authentication is proven against it); null keeps none, and then no re-authentication passes.
   */
  static fromOpened(opened: OpenedAccount, wrap: SessionKeys | null): Account {
    const vaultKeys = new Map<string, Uint8Array>();
    const pv = opened.personalVaultId;
    if (pv !== null && opened.personalVk !== null) vaultKeys.set(pv, opened.personalVk);
    const account = new Account(
      opened.userId,
      opened.uvk,
      opened.identity.privateKey,
      opened.identity.publicKey,
      opened.signing.publicKey,
      opened.signing.privateKey,
      pv ?? "",
      vaultKeys,
    );
    if (pv !== null && opened.personalVk !== null) {
      account.personalStatusValue = "confirmed";
      account.uvkWrappedVaults.add(pv);
      account.vaultRoles.set(pv, "owner");
    }
    account.sessionWrapValue = new SessionWrap(wrap);
    return account;
  }

  /** The wrap this session keeps (spec 01 §7), shared with the Settings flows of the same session. */
  get sessionWrap(): SessionWrap {
    return this.sessionWrapValue;
  }

  /**
   * Apply the personal vault's grant row from sync or the cache (spec 03 §10). The personal key came from the
   * UVK-authenticated personal wrap at unlock (design §5.3), and a shared vault's key comes only from its verified log
   * (design §3.6), so no row installs a key here. The row carries the role, and this account's own UVK wrap of the
   * personal vault, which is opened only to compare: a wrap that opens to ANOTHER key raises the "vault key
   * mismatch" notice and the held key stands. A wrap that does not open changes nothing. Nothing else on the row is
   * read: no v2 grant, no v1 seal.
   *
   * Throws a CryptoError for any other row: another vault, another account's row, or no personal key held.
   */
  addGrant(grant: WireGrant) {
    const held = this.personalVaultId ? this.vaultKeys.get(this.personalVaultId) : undefined;
    if (!held || grant.vaultId !== this.personalVaultId || grant.userId !== this.userId) {
      throw new CryptoError(`a grant row for ${grant.vaultId} is not this account's personal vault: its key comes only from its log`);
    }
    if (grant.role) this.vaultRoles.set(grant.vaultId, grant.role);
    const fromWrap = this.ownWrapOrNull(grant);
    if (fromWrap !== null && !ctEquals(fromWrap, held)) this.vkMismatchVaults.add(grant.vaultId);
    fromWrap?.fill(0);
  }

  /** The key this account's own UVK wrap on the row (`wrappedVk`) opens to, or null when it is absent or does not open. */
  private ownWrapOrNull(grant: WireGrant): Uint8Array | null {
    if (!grant.wrappedVk) return null;
    try {
      const envelope = fromB64(grant.wrappedVk);
      if (structuralRefusal(envelope) !== null) return null;
      return openKey(this.uvk, envelope, adVk(grant.vaultId, this.userId), "a grant's wrap");
    } catch {
      return null;
    }
  }

  /** True when a served row for this vault carried a wrap of ours that opened to another key than the one held (the
   *  "vault key mismatch" anomaly, root cause A §3.1). Display only: the held key is canonical. */
  vkMismatch(vaultId: string): boolean {
    return this.vkMismatchVaults.has(vaultId);
  }

  vkMismatchVaultIds(): string[] {
    return [...this.vkMismatchVaults];
  }

  /**
   * Seal the usage ledger (spec 02 §8.2). Keyed by HKDF from the PERSONAL VAULT KEY, not the
   * UVK — see usagekey.ts: the extension's UVK is memory-only (breaker B1) and an evicted MV3
   * worker restores a session with vault keys but no UVK, so a UVK-bound ledger would be
   * unwritable from the client that does most of the filling. The AD still binds the blob to
   * this userId, so a hostile endpoint cannot serve one member's ledger into another's slot.
   *
   * Throws when there is no personal vault (a recovery-shaped Account holds none) — callers
   * treat that exactly like "no ledger", which is the honest degradation.
   */
  async sealUsage(plaintext: Uint8Array): Promise<string> {
    return toB64(seal(await usageKey(this.vk(this.personalVaultId)), plaintext, adUsage(this.userId)));
  }

  /** Open a usage ledger sealed by [sealUsage] — on this device or any other client. Throws on a
   *  wrong key or a substituted blob, which callers treat as "no ledger", never as an empty one. */
  async openUsage(sealedUsage: string): Promise<Uint8Array> {
    return open(await usageKey(this.vk(this.personalVaultId)), fromB64(sealedUsage), adUsage(this.userId));
  }

  /** The EFFECTIVE role (core `roleFor` twin): the verified log's for a log-governed vault, else the served row's. */
  roleFor(vaultId: string): string | null {
    if (this.logGoverned.has(vaultId)) return this.logRoles?.(vaultId) ?? null;
    return this.vaultRoles.get(vaultId) ?? null;
  }

  /** The role exactly as the server declared it. DISPLAY ONLY (security review 2026-10, root cause A, branch A6b): it
   *  never unlocks an owner-only signing action; the store's owned-vaults record does. */
  serverRoleFor(vaultId: string): string | null {
    return this.vaultRoles.get(vaultId) ?? null;
  }

  /**
   * THE in-session password proof (spec 01 §7, "the proof runs against the device's own wrap"; security review 2026-10,
   * branch A9, M-1; core `reauthAuthKey` twin): the login authKey of `password`, derived only after the password opened
   * the wrap this session keeps ({@link sessionWrap}) to the UVK it holds, under that wrap's own salt and cost. Nothing is
   * fetched for it and no value a server names goes into it. {@link ReauthFailedError}: the password opens no kept wrap,
   * found out here. {@link ReauthStaleSessionError}: this session keeps no wrap. {@link KdfPolicyError}: the kept cost
   * is outside the bounds. Every password-derived upload goes through here or through the Settings flows' `reauth`,
   * which proves against the same kept wrap; {@link deriveAuthKey} is for sign-in only.
   */
  async reauthAuthKey(password: string): Promise<string> {
    const r = await this.sessionWrapValue.prove(password, this.userId, this.uvk);
    switch (r.kind) {
      case "proven":
        return r.currentAuthKey;
      case "wrong_password":
        throw new ReauthFailedError();
      case "weakened":
        throw r.error;
      case "no_wrap":
        throw new ReauthStaleSessionError();
    }
  }

  /** A9 (LOW): an Account built only as a PROBE (the recovery identity hard-fail, {@link recover}) is never a session.
   *  Wipe the identity and signing secrets it derived; the UVK it shares with the caller is the caller's to wipe. */
  discardProbeSecrets(): void {
    this.identityPriv.fill(0);
    this.signSecret.fill(0);
  }

  /** Membership revoked (sync `removedGrants`): wipe and forget the VK, and the role. The key is zero-filled
   *  here, before its map entry goes; the log key ring's own delete found no entry left to wipe. */
  removeVault(vaultId: string) {
    this.vaultKeys.get(vaultId)?.fill(0);
    this.vaultKeys.delete(vaultId);
    this.keyAdds.delete(vaultId);
    this.vaultRoles.delete(vaultId);
    this.uvkWrappedVaults.delete(vaultId);
    this.vkMismatchVaults.delete(vaultId);
  }

  /**
   * Short identity fingerprint (spec 01 §5, 32 hex / 128 bits), displayed as 8 groups of 4.
   * Computed over the SEED-DERIVED identityPub this class holds — enroll/unlock derive
   * it via boxKeypairFromSeed(identitySeed), never from a server-sent value — so a
   * malicious server cannot pass the out-of-band check with a substituted key.
   */
  identityFingerprintShort(): Promise<string> {
    return shortIdentityFingerprint(this.identityPub);
  }

  /** Full identity fingerprint (spec 01 §5, 64 hex) over the SEED-DERIVED identityPub — printed on
   *  the per-member recovery sheet (spec 04 §6) beside the short form as the recovery CLI's anchor. */
  identityFingerprintFull(): Promise<string> {
    return identityFingerprint(this.identityPub);
  }

  /**
   * Root cause A §4.3 (core `Account.applyPersonalWrap` twin): adopt the personal vault from
   * `AccountKeys.personalWrap`, `Envelope(UVK, VK, adVkPersonal(vaultId, userId))`. Absent → "absent"
   * (no personal vault). Opens → "confirmed", its VK held FIRST. Does not open → "unreadable" (an anomaly),
   * no personal vault, and no fallback to any label. A server `type` label or `role` never reaches this decision.
   * Design §5.3: decided once. While a personal vault is in force, a later apply (another vault's wrap, junk or none)
   * changes nothing: there is no notice to confirm a switch with, so there is no switch.
   */
  applyPersonalWrap(wrap: PersonalWrap | null) {
    if (this.personalStatusValue === "confirmed") return;
    if (!wrap) {
      this.personalStatusValue = "absent";
      this.personalVaultIdValue = "";
      return;
    }
    if (this.openAndInstallPersonalWrap(wrap)) this.personalStatusValue = "confirmed";
    else {
      this.personalStatusValue = "unreadable";
      this.personalVaultIdValue = "";
    }
  }

  /** The VK a personal wrap opens to under our UVK with the `vk-personal` AD, or null. */
  private openPersonalWrap(wrap: PersonalWrap): Uint8Array | null {
    try {
      const vk = openKey(this.uvk, fromB64(wrap.wrappedVk), adVkPersonal(wrap.vaultId, this.userId), "the personal wrap");
      return vk.length === 32 ? vk : null;
    } catch {
      return null;
    }
  }

  /** Hold a key a personal wrap (ours, UVK-authentic) opened to, WITHOUT making its vault the personal one. */
  private holdKeyFromPersonalWrap(vaultId: string, vk: Uint8Array): void {
    const held = this.vaultKeys.get(vaultId);
    if (held && !ctEquals(held, vk)) this.vkMismatchVaults.add(vaultId);
    this.vaultKeys.set(vaultId, vk);
    this.uvkWrappedVaults.add(vaultId);
  }

  private openAndInstallPersonalWrap(wrap: PersonalWrap): boolean {
    const vk = this.openPersonalWrap(wrap);
    if (!vk) return false;
    this.holdKeyFromPersonalWrap(wrap.vaultId, vk);
    this.personalVaultIdValue = wrap.vaultId;
    return true;
  }

  /** True when this vault's key opened from a UVK wrap of ours (never a seal). */
  keyFromOwnUvkWrap(vaultId: string): boolean {
    return this.uvkWrappedVaults.has(vaultId) && this.vaultKeys.has(vaultId);
  }

  /** Seal an account-state document (root cause A §4.2) under the UVK, bound to this userId. */
  sealAccountState(doc: AccountStateDoc): string {
    if (doc.userId !== this.userId) throw new CryptoError("account state belongs to another user");
    return toB64(seal(this.uvk, utf8(encodeAccountState(doc)), adAccountState(this.userId)));
  }

  /** Open an account-state blob: CryptoError when it does not open under our UVK/AD (substituted or
   *  injected), AccountStateError when it opens but is not a v1 document for this user. */
  openAccountState(sealed: string): AccountStateDoc {
    return decodeAccountState(this.userId, fromUtf8(open(this.uvk, fromB64(sealed), adAccountState(this.userId))));
  }

  hasVault(vaultId: string): boolean {
    return this.vaultKeys.has(vaultId);
  }

  /**
   * The key ring the vault log store adopts shared-vault keys into (design §3.6): the same map items are encrypted
   * with. A key installed here marks its vault as log-governed; a removal drops the key and the role.
   */
  logKeyRing(): {
    get(vaultId: string): Uint8Array | undefined;
    has(vaultId: string): boolean;
    set(vaultId: string, vk: Uint8Array, addSeq?: number): void;
    delete(vaultId: string): void;
    addOf(vaultId: string): number | undefined;
  } {
    return {
      get: (vaultId) => (this.logGoverned.has(vaultId) ? this.vaultKeys.get(vaultId) : undefined),
      has: (vaultId) => this.logGoverned.has(vaultId) && this.vaultKeys.has(vaultId),
      set: (vaultId, vk, addSeq) => {
        if (vaultId === this.personalVaultId) throw new CryptoError("the personal vault is not log-governed");
        this.logGoverned.add(vaultId);
        this.vaultKeys.set(vaultId, vk);
        if (addSeq === undefined) this.keyAdds.delete(vaultId);
        else this.keyAdds.set(vaultId, addSeq);
      },
      delete: (vaultId) => {
        if (!this.logGoverned.has(vaultId)) return;
        this.vaultKeys.get(vaultId)?.fill(0);
        this.vaultKeys.delete(vaultId);
        this.vaultRoles.delete(vaultId);
        this.keyAdds.delete(vaultId);
      },
      addOf: (vaultId) => (this.logGoverned.has(vaultId) && this.vaultKeys.has(vaultId) ? this.keyAdds.get(vaultId) : undefined),
    };
  }

  /** Attaches the question "through which `add` does the verified log name this account now" ({@link keyWorks}). */
  attachLogMember(memberAdd: (vaultId: string) => number | null | undefined): void {
    this.logMember = memberAdd;
  }

  /**
   * Whether the key held for [vaultId] may be used now: always for a vault no log governs; for a log-governed one only
   * while the `add` it was adopted under is the one the verified log names now. A road that moves the log without the
   * removal's rule running after it (another tab, a chase of an item's head, a read outside a pull) leaves the key in
   * the ring but working for nothing: the vault is not listed, no item of it is opened or shown, nothing is sealed.
   */
  keyWorks(vaultId: string): boolean {
    if (!this.logGoverned.has(vaultId) || this.logMember === null) return true;
    if (!this.vaultKeys.has(vaultId)) return false;
    return this.keyAdds.get(vaultId) === this.logMember(vaultId);
  }

  /**
   * The one question asked before any change of [vaultId] leaves this browser (a save, a delete, a restore, a rename,
   * each step of a move or a copy out, an attachment, an entry of the vault's log): for a shared vault, once the logs
   * are attached, true only while its key is held and works ({@link keyWorks}). A shared vault whose key this session
   * never took up (a new start that holds it unopened until a removal is carried out) has none, so nothing of it is
   * sent. The personal vault, and a store with no logs attached, are not decided by a log.
   */
  mayWrite(vaultId: string): boolean {
    if (this.logMember === null || vaultId === this.personalVaultId) return true;
    return this.logGoverned.has(vaultId) && this.vaultKeys.has(vaultId) && this.keyWorks(vaultId);
  }

  /**
   * Roles of log-governed vaults come from [roleOf] (the verified log's member list), never from the served row;
   * [writeAllowed] is the log store's write gate (a verified log this account is a member of), asked at every seal.
   */
  attachLogRoles(roleOf: (vaultId: string) => string | null, writeAllowed: (vaultId: string) => boolean = () => false): void {
    this.logRoles = roleOf;
    this.logWrites = writeAllowed;
  }

  isLogGoverned(vaultId: string): boolean {
    return this.logGoverned.has(vaultId);
  }

  private vk(vaultId: string): Uint8Array {
    const vk = this.vaultKeys.get(vaultId);
    if (!vk) throw new CryptoError(`no key for vault ${vaultId}`);
    return vk;
  }

  /**
   * Master-password change (spec 01 §6): fresh salt + KDF, new auth/wrap keys, and
   * the EXISTING UVK re-sealed under the new wrap key. The UVK never rotates —
   * vault keys, identity seed, and escrow all stay valid.
   */
  async buildPasswordChange(
    newPassword: string,
    params: KdfParams,
  ): Promise<{ newKdfSalt: string; newKdfParams: KdfParams; newAuthKey: string; newWrappedUvk: string }> {
    const newKdfSalt = randomBytes(16);
    // ZEROIZATION (audit H80, spec 01 §2): same discipline as {@link deriveAuthKey} — the new
    // MK, authKey and wrapKey are dead once the change request carries their encoded forms.
    const mk = masterKey(newPassword, newKdfSalt, params);
    let newAuthKey: Uint8Array;
    let newWrapKey: Uint8Array;
    try {
      newAuthKey = await deriveAuthKey(mk);
      newWrapKey = await deriveWrapKey(mk);
    } finally {
      mk.fill(0);
    }
    try {
      const newWrappedUvk = seal(newWrapKey, this.uvk, adUvk(this.userId));
      return {
        newKdfSalt: toB64(newKdfSalt),
        newKdfParams: params,
        newAuthKey: toB64(newAuthKey),
        newWrappedUvk: toB64(newWrappedUvk),
      };
    } finally {
      newAuthKey.fill(0);
      newWrapKey.fill(0);
    }
  }

  /** INV-WRITE-KEY as a question: may an item be sealed under `vaultId`'s held key at all? (core `canSealUnder`) */
  canSealUnder(vaultId: string): boolean {
    // A log-governed vault: only on a verified log this account is a member of, and never as a reader (design §3.9).
    if (this.logGoverned.has(vaultId)) return (this.logWrites?.(vaultId) ?? false) && this.roleFor(vaultId) !== "reader" && this.keyWorks(vaultId);
    return true;
  }

  /**
   * THE item seal for anything pushed (security review 2026-10, root cause A §5.1 INV-SEAL; branch A1b; core
   * `Account.sealItem` twin): item plaintext is sealed under `VK_v` only for its provenance vault `v`, and never under a
   * key INV-WRITE-KEY refuses (a log-governed vault the verified log does not let this account write to). The
   * formatVersion — also bound into the AD — is max(docFloor, the fv this itemId was last decrypted/sealed at), so
   * callers never thread fv explicitly. The wire fv and the AD fv come from this ONE computation.
   */
  sealItem(provenance: SealProvenance, itemId: string, doc: ItemDoc): ItemUpload {
    if (!this.canSealUnder(provenance.vaultId)) throw new VaultKeyNotVerifiedError(provenance.vaultId); // INV-WRITE-KEY
    // Design §3.9: a write to a shared vault carries that vault's verified log head; any other write carries none.
    const head = this.isLogGoverned(provenance.vaultId) ? this.logHeads(provenance.vaultId) : null;
    return this.sealUnder(provenance.vaultId, itemId, stampLogHead(doc, head));
  }

  private logHeads: (vaultId: string) => ItemLogHead | null = () => null;

  /** The verified head of each log-governed vault, which every write to it carries (spec 02 §3 `logHead`). */
  attachLogHeads(headOf: (vaultId: string) => ItemLogHead | null): void {
    this.logHeads = headOf;
  }

  /**
   * Test and fixture shim for {@link sealItem}: the plaintext's provenance is whatever the CALLER asserts `vaultId` is,
   * so product code never calls this (a source tripwire in itemhome.vectors.test.ts fails the suite if it does).
   */
  encryptItem(vaultId: string, itemId: string, doc: ItemDoc): ItemUpload {
    return this.sealItem({ kind: "chosen", vaultId }, itemId, doc);
  }

  /**
   * A LOCAL re-seal, never pushed: plaintext DECRYPTED from `vaultId` (provenance (a)) sealed again under the same key
   * for this device's own ciphertext-only storage — the holding-area snapshot (store.moveToHolding), a queued write's
   * pre-edit snapshot, and the revert of a refused write. Not a new provenance and not something the household
   * receives, so INV-WRITE-KEY does not apply: a removed vault this account could only read is parked like any other.
   */
  resealLocal(vaultId: string, itemId: string, doc: ItemDoc): ItemUpload {
    return this.sealUnder(vaultId, itemId, doc);
  }

  /** The holding-area snapshot: {@link resealLocal}. */
  resealForHolding(vaultId: string, itemId: string, doc: ItemDoc): ItemUpload {
    return this.resealLocal(vaultId, itemId, doc);
  }

  private sealUnder(vaultId: string, itemId: string, doc: ItemDoc): ItemUpload {
    const fv = Math.max(docFloor(doc), this.itemFv.get(itemId) ?? 1);
    this.itemFv.set(itemId, fv);
    const blob = seal(this.vk(vaultId), utf8(JSON.stringify(doc)), adItem(vaultId, itemId, fv));
    return { formatVersion: fv, blob: toB64(blob) };
  }

  /** An item opened under the ring's key; for a log-governed vault only while that key works ({@link keyWorks}). */
  decryptItem(item: WireItem): ItemDoc {
    if (!this.keyWorks(item.vaultId)) throw new CryptoError(`the key of vault ${item.vaultId} does not work now`);
    return this.decryptItemWith(item, () => this.vk(item.vaultId));
  }

  /**
   * A held vault's item (design §3.8, §3.12), under the key the caller opened from this account's own wrap for it and
   * checked against the log's commitment; the key is not put in the ring, so nothing is written under it.
   */
  decryptHeldItem(item: WireItem, vk: Uint8Array): ItemDoc {
    return this.decryptItemWith(item, () => vk);
  }

  /** [vk] is read only after the format gate, so a newer format fails as such before any key is looked up. */
  private decryptItemWith(item: WireItem, vk: () => Uint8Array): ItemDoc {
    if (!item.blob) throw new CryptoError("item has no blob (tombstone?)");
    // Fail closed on documents from a NEWER format: unknown-field preservation (spec 02 §3)
    // is scoped WITHIN a formatVersion, and editing a v3 doc here would re-seal it silently
    // downgraded. CryptoError rides the existing catch paths ("undecryptable").
    if (item.formatVersion > ITEM_FORMAT_VERSION) throw new CryptoError(`item formatVersion ${item.formatVersion} is newer than this client supports`);
    const plain = open(vk(), fromB64(item.blob), adItem(item.vaultId, item.itemId, item.formatVersion));
    // CONTRACT (spec 02 §3): the parsed doc may carry fields this client version does not
    // know — they MUST survive a rewrite. Never rebuild a decrypted doc field-by-field;
    // edit via spread/structuredClone only, so unknown keys round-trip through encryptItem.
    let parsed: unknown;
    try {
      parsed = JSON.parse(fromUtf8(plain));
    } catch {
      throw new MalformedItemError("item document is not JSON");
    }
    // spec 02 §3.2 (security review 2026-10): the plaintext opened under the VK, but any writer
    // of a shared vault holds that VK — check its shape BEFORE anything reads it. Every caller
    // already treats a throw here as undecryptable: the item is quarantined, never rendered.
    const problem = itemDocProblem(parsed);
    if (problem !== null) throw new MalformedItemError(`item document is malformed: ${problem}`);
    const doc = parsed as ItemDoc;
    // Remember the fv monotonically (an OLDER archived version arriving via
    // decryptItemVersion must not lower it) so a later re-seal can't downgrade.
    this.itemFv.set(item.itemId, Math.max(this.itemFv.get(item.itemId) ?? 1, item.formatVersion));
    return doc;
  }

  /**
   * Item history: decrypt one archived {@link ItemVersion} under the vault VK. Reuses
   * {@link decryptItem} — the item AD binds (vaultId, itemId, formatVersion), NOT rev, so an old
   * version opens under the CURRENT key (until a VK rotation, which resets history; see the
   * design doc). The caller supplies vaultId (the version DTO carries none) from the live item.
   */
  decryptItemVersion(vaultId: string, itemId: string, version: ItemVersion): ItemDoc {
    return this.decryptItem({
      itemId,
      vaultId,
      rev: version.rev,
      createdAt: 0,
      updatedAt: version.archivedAt,
      deleted: false,
      conflict: false,
      formatVersion: version.formatVersion,
      attachmentIds: [],
      blob: version.blob,
    });
  }

  decryptVaultName(vaultId: string, metaBlob: string): string {
    try {
      // spec 02 §4: only a JSON string is a name (core/extension parity — vaultMetaName).
      return vaultMetaName(this.decryptVaultMeta(vaultId, metaBlob)) ?? "(vault)";
    } catch {
      return "(vault)";
    }
  }

  /** The full vault-meta plaintext object (spec 02 §4) — `name`, the monotonic `metaV`
   *  counter, and any unknown fields a future client wrote. Throws if the VK is missing or
   *  the blob doesn't open. Callers that only need the name use decryptVaultName. */
  /** The vault meta document. Security review 2026-10, branch A11 (q55): any holder of the VK authors this plaintext,
   *  so anything but a JSON object (null, a string, an array, a number, not JSON at all) is refused with
   *  {@link MalformedVaultMetaError} instead of being cast; a blob that does not open still throws as before. */
  decryptVaultMeta(vaultId: string, metaBlob: string): Record<string, unknown> {
    const plain = open(this.vk(vaultId), fromB64(metaBlob), adVaultMeta(vaultId));
    let meta: unknown;
    try {
      meta = JSON.parse(fromUtf8(plain));
    } catch {
      throw new MalformedVaultMetaError(vaultId);
    }
    if (meta === null || typeof meta !== "object" || Array.isArray(meta)) throw new MalformedVaultMetaError(vaultId);
    return meta as Record<string, unknown>;
  }

  /**
   * Rename (spec 03 §11 / Q6): read-modify-write the metaBlob under the SAME VK/AD — change
   * ONLY `name`, PRESERVE every unknown field (spec 02 §4), and increment the monotonic
   * plaintext `metaV` counter (anti-replay). Returns the new metaBlob (base64url). The name
   * stays E2E ciphertext; the server only ever sees an opaque blob.
   */
  buildRenameMeta(vaultId: string, metaBlob: string, newName: string): string {
    // INV-WRITE-KEY "whatever the path" (A9 LOW): a name is sealed under the VK like an item, so a vault the verified
    // log does not let this account write to is refused here too, through the same {@link canSealUnder}.
    if (!this.canSealUnder(vaultId)) throw new VaultKeyNotVerifiedError(vaultId);
    // A11 (q55): a co-member-authored non-object meta is replaced by a clean one (the new name, the counter restarted
    // from 0 like any junk metaV), never spread into the new document and never a crash.
    let meta: Record<string, unknown>;
    try {
      meta = this.decryptVaultMeta(vaultId, metaBlob);
    } catch (e) {
      if (!(e instanceof MalformedVaultMetaError)) throw e;
      meta = {};
    }
    // spec 02 §4: metaV counts ONLY as a non-negative integer ≤ 2^53 (Number.MAX_SAFE_INTEGER),
    // else 0 — the SAME rule store.ts metaVOf applies, so write and apply agree on every client
    // (the safe-integer cap makes a >2^63 literal read 0 here AND on Kotlin's core parseMetaV).
    const v = meta.metaV;
    const metaV = typeof v === "number" && Number.isSafeInteger(v) && v >= 0 ? v : 0;
    const next = { ...meta, name: newName, metaV: metaV + 1 };
    return toB64(seal(this.vk(vaultId), utf8(JSON.stringify(next)), adVaultMeta(vaultId)));
  }

  newItemId(): string {
    return uuidv4();
  }

  /**
   * Migration/rotation path (design §F.3, client half of `PUT /recovery/self-setup`): add or rotate
   * THIS account's per-member self-service recovery piece over the in-memory UVK. `currentAuthKey` is
   * re-derived from a fresh master-password prompt by the caller and re-verified server-side (like
   * changePassword) before the block is stored. The generated `recoverySecret` is SHOWN ONCE then
   * dropped (§F.7); the UVK is invariant, so the existing org-escrow blob stays valid too (§C.3).
   */
  async setupMemberRecovery(currentAuthKey: string): Promise<{ request: RecoverySelfSetupRequest; recoverySecret: Uint8Array }> {
    const recovery = await generateMemberRecovery(this.userId, this.uvk);
    return {
      request: {
        currentAuthKey,
        memberRecovery: { recoveryWrappedUvk: recovery.recoveryWrappedUvk, recoveryAuthKey: recovery.recoveryAuthKey },
      },
      recoverySecret: recovery.recoverySecret,
    };
  }
}

/**
 * This browser's name in the account's device list and the new-device email: "Chrome on Linux", not the user agent's
 * "web Chrome/149.0.0.0" (browser walk, 2026-11-16). Edge and Opera carry "Chrome/" too, so they are looked for first.
 */
export function deviceName(ua: string | null = typeof navigator !== "undefined" ? navigator.userAgent : null): string {
  if (!ua) return "Web browser";
  const browser = /Edg(e|A|iOS)?\//.test(ua) ? "Edge" : /OPR\/|Opera/.test(ua) ? "Opera" : /Firefox\/|FxiOS\//.test(ua) ? "Firefox" : /Chrome\/|CriOS\//.test(ua) ? "Chrome" : /Safari\//.test(ua) ? "Safari" : "Web browser";
  const os = /iPhone/.test(ua) ? "iPhone" : /iPad/.test(ua) ? "iPad" : /Android/.test(ua) ? "Android" : /CrOS/.test(ua) ? "ChromeOS" : /Windows/.test(ua) ? "Windows" : /Macintosh|Mac OS X/.test(ua) ? "Mac" : /Linux/.test(ua) ? "Linux" : null;
  // Spec 03 §0.1 `text` (server 2026-11-16): a name made up here never carries a character the server refuses.
  return plainTextOf(os ? `${browser} on ${os}` : browser).slice(0, 256) || "Web browser";
}
