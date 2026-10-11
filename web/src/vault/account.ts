import { adAccountState, adIdkey, adItem, adUsage, adUvk, adVaultMeta, adVk, adVkPersonal } from "../crypto/ad";
import { type AccountStateDoc, decodeAccountState, encodeAccountState } from "./accountstate";
import { usageKey } from "../crypto/usagekey";
import { ctEquals, fromB64, fromUtf8, toB64, toHexLower, utf8 } from "../crypto/bytes";
import { open, seal, structuralRefusal } from "../crypto/envelope";
import { fingerprint as recoveryFingerprint, sealUvkV2 } from "../crypto/escrow";
import { authKey as deriveAuthKey, masterKey, wrapKey as deriveWrapKey, type KdfParams } from "../crypto/keys";
import { lifecycleKey } from "../crypto/lifecycleproof";
import { generate as generateMemberRecovery, openUvk as openMemberRecoveryUvk } from "../crypto/member-recovery";
import { boxKeypairFromSeed, randomBytes, sha256Sync, signKeypairFromSeed } from "../crypto/provider";
import { identityFingerprint, openSharedGrant, sealSharedGrant, shortIdentityFingerprint } from "../crypto/sharedgrant";
import { buildGrantFrame, decideLegacyGrant, type GrantOutcome, type GrantPin, type GrantVerdict, LEGACY_IN_WINDOW, type LegacyGrantMode, openSignedGrant, sealGrantFrame } from "../crypto/signedgrant";
import type { Contact } from "./accountstate";
import { CryptoError } from "../crypto/sodium";
import { itemDocProblem, vaultMetaName } from "./itemdoc-shape";
import type {
  AccountKeys,
  CreateVaultRequest,
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
 * Where the personal vault came from (security review 2026-10, root cause A §4.3, §8.5; A5b). Core twin:
 * `Account.PersonalStatus`. "unreadable-cached": a junk served wrap, the device's valid cached wrap kept in
 * force (L-1). "changed": a served wrap that opens names another vault than the device's; the device keeps
 * its own until the human confirms (M-2, L-2).
 */
export type PersonalStatus = "confirmed" | "withheld" | "absent" | "unreadable" | "unreadable-cached" | "changed";

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
/**
 * A grant row carries OUR UVK wrap (`wrappedVk`) and it does not open — structurally broken or an
 * AEAD tag failure (security review 2026-10, root cause A §3.1; spec 01 §4 extended to VK wraps).
 * The UVK already proved itself at unlock, so this is a damaged or substituted row: the vault shows
 * as "key unreadable — tell your admin" and the seal on the same row is NEVER tried instead (a seal
 * is crypto_box_seal to our public key, which the server can mint). Core twin:
 * `VaultGrantKeyUnreadableException`.
 */
export class VaultGrantKeyUnreadableError extends Error {
  constructor(
    readonly vaultId: string,
    reason: string,
  ) {
    super(`vault key for ${vaultId} is unreadable (${reason})`);
    this.name = "VaultGrantKeyUnreadableError";
  }
}

/**
 * INV-WRITE-KEY (security review 2026-10, root cause A §5.1, §8.2; branch A6; core `VaultKeyNotVerifiedException`
 * twin): this vault's key came ONLY from a v1 `sealedVk` (server-mintable) and nobody vouched for it yet — no
 * verified v2 grant, no pre-upgrade evidence, no human "Accept". Readable; nothing is ever sealed under it. Not a
 * CryptoError, so no save ladder can read it as "wrong master password".
 */
export class VaultKeyNotVerifiedError extends Error {
  constructor(readonly vaultId: string) {
    super("This shared vault isn't verified on this device yet, so it is read-only. Review it under Shared vaults first.");
    this.name = "VaultKeyNotVerifiedError";
  }
}

/** How this device vouched for a v1-only key (§8.2): pre-upgrade evidence, or the human's Accept. */
export type LegacyVouchKind = "frozen" | "confirmed";

/** A vouch is bound to the KEY it was given for: `tag` = lowercase hex SHA-256 of that vault key (A6 review HIGH-1). */
export interface LegacyVouch {
  tag: string;
  kind: LegacyVouchKind;
}

/** The tag a legacy-key vouch is bound to: lowercase hex SHA-256 of the vault key. */
export function legacyTagOf(vk: Uint8Array): string {
  return toHexLower(sha256Sync(vk));
}

/** Where a held vault key came from (root cause A §3.1 precedence; core `Account.KeySource`). */
export type KeySource = "personal-wrap" | "uvk-wrap" | "signed-grant" | "legacy-seal";

/** §1.6: a v2 grant from a sender not pinned (or not current) here. Not adopted; `fromUserId` is unverified. */
export interface PendingGrant {
  vaultId: string;
  fromUserId: string;
  grantIdB64: string;
}

class GrantPendingSignal extends Error {
  constructor(readonly pending: PendingGrant) {
    super("grant pending verification");
  }
}

class GrantRefusedSignal extends Error {
  constructor(readonly verdict: GrantVerdict) {
    super(`grant refused: ${verdict}`);
  }
}

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

  /**
   * Vaults whose VK arrived by MEMBER grant (`sealedVk`) rather than wrapped under our own
   * UVK — see {@link keyArrivedByMemberGrant}. In-memory only, like the keys it annotates;
   * the store rebuilds it by replaying the cached grant rows on every hydrate, so it cannot
   * go stale across a reload. Kotlin twin: `Account.memberGrantedVaults`.
   */
  private readonly memberGrantedVaults = new Set<string>();

  /** Root cause A §3.1: vaults whose row carried a seal that opened to a DIFFERENT key than the one
   *  we hold from our own UVK wrap ("vault key mismatch"; ours was kept). Core: `vkMismatchVaults`. */
  private readonly vkMismatchVaults = new Set<string>();

  /** Vaults whose UVK wrap is present but does not open ("key unreadable — tell your admin"). */
  private readonly unreadableKeyVaults = new Set<string>();

  /** Root cause A (branch A6): where each held key came from, recorded when it is adopted. */
  private readonly keySources = new Map<string, KeySource>();
  /** For keys from a verified v2 grant: the sender the VERIFIED statement names. */
  private readonly signedGrantFrom = new Map<string, string>();
  /** v1-only keys this device vouches for (§8.2), each bound to the key it was given for (HIGH-1). */
  private readonly legacyVouches = new Map<string, LegacyVouch>();
  /**
   * Per-vault held-key memory (security review 2026-10, root cause A, branch A7; core `heldKeyTags` twin; closes
   * R15(g) on a device that held the vault): vaultId → SHA-256 (hex) of the FIRST key this device adopted for it, by
   * any rule. No step of root cause A re-keys a vault (§8.7), so a later different key is vk_mismatch through
   * {@link vouchGate}, like a vouch. Persisted by the store beside the vouches; dropped with the vault. It vouches for
   * nothing: it never lifts a legacy key's read-only state and never makes a seal key acceptable on its own.
   */
  private readonly heldKeyTags = new Map<string, string>();
  /** §1.6 pending invitations by vaultId. */
  private readonly pendingGrantsByVault = new Map<string, PendingGrant>();
  /** §1.4 anomaly verdicts by vaultId (nothing adopted). */
  private readonly grantAnomaliesByVault = new Map<string, GrantVerdict>();

  /**
   * Pins as the grant verifier sees them (§1.4 step 7). The store wires this to the account-state contacts,
   * reporting a pin as current only when it may skip verification on this device (A5 review L-3). Default: no one.
   */
  grantPins: (userId: string) => GrantPin | null = () => null;

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
   * (only this user's UVK can mint it, {@link applyPersonalWrap}), a wrap this device cached, or minted from
   * the human's CONFIRMED answer (never an automatic pick: A5 review H-1, A5b). "" = no personal vault: no default destination, no usage ledger.
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
        const sealed = await sealUvkV2({
          recoveryPub: params.recoveryPublicKey, verifiedRecoveryFp: fp, userId, identityPub: identity.publicKey, signer: signing, uvk, issuedAt: Date.now(),
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
      account.personalWrapValue = request.personalWrap!;
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
    });
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
    } finally {
      wrapKey.fill(0);
    }
    // Password path validates the password by the wrappedUvk open above; from here the work is
    // identical to the recovery (UVK-in-hand) path — one shared tail, so the identity-pubkey
    // hard-fail can never diverge between them (core Account.unlock parity).
    return Account.unlockFromUvk(userId, uvk, keys, selfIdentityPub);
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
   * Apply a grant from sync (spec 01 §6). The role update is UNCONDITIONAL — a role
   * change re-delivers the grant while the VK is already held, and MUST still take
   * effect; the key-open is attempted only when the VK is missing, by {@link openGrantVk}'s
   * canonical-key precedence (security review 2026-10, root cause A §3.1).
   *
   * Throws {@link VaultGrantKeyUnreadableError} when the row carries our UVK wrap and it does not
   * open: the vault stays keyless (no seal fallback) and {@link keyUnreadable} says so.
   */
  addGrant(grant: WireGrant) {
    if (grant.role) this.vaultRoles.set(grant.vaultId, grant.role);
    const held = this.vaultKeys.get(grant.vaultId);
    if (held) {
      // A key held ONLY from a v1 seal is confirmed by a verified v2 grant carrying the SAME key (the owner's
      // re-issue, §8.2 step 3). A v2 grant never silently REPLACES a held key (A6 review MED-2): a different key is
      // the vk_mismatch anomaly, and the held key and its source stay (an unvouched one stays read-only). A field
      // that is present but fails §1.4 in any way is an anomaly too (LOW-2).
      if (this.keySources.get(grant.vaultId) === "legacy-seal" && grant.signedGrant) {
        const o = this.openSigned(grant, null);
        if (o.verdict === "adopt") {
          // Round 3 MEDIUM-B: promotion goes through the vouch gate too — a held key that contradicts this device's
          // vouch is never promoted, even when a verified grant carries that same key.
          if (ctEquals(o.vk, held) && this.vouchGate(grant.vaultId, held) !== "mismatch") {
            this.keySources.set(grant.vaultId, "signed-grant");
            this.signedGrantFrom.set(grant.vaultId, o.from);
            this.pendingGrantsByVault.delete(grant.vaultId);
            this.grantAnomaliesByVault.delete(grant.vaultId);
          } else {
            this.grantAnomaliesByVault.set(grant.vaultId, "vk_mismatch");
          }
          return;
        }
        if (o.verdict === "pending_invitation") this.pendingGrantsByVault.set(grant.vaultId, { vaultId: grant.vaultId, fromUserId: o.from, grantIdB64: o.grantIdB64 });
        else {
          this.grantAnomaliesByVault.set(grant.vaultId, o.verdict);
          return;
        }
      }
      // Already held: the row cannot change our key, but a re-delivered row that now carries a
      // DIFFERENT key is still worth surfacing.
      if (this.rowCarriesOtherKey(grant, held)) this.vkMismatchVaults.add(grant.vaultId);
      return;
    }
    let opened: { vk: Uint8Array; source: KeySource; sealMismatch: boolean; from?: string; anomaly?: GrantVerdict };
    try {
      opened = this.openGrantVk(grant);
    } catch (e) {
      if (e instanceof VaultGrantKeyUnreadableError) this.unreadableKeyVaults.add(grant.vaultId);
      if (e instanceof GrantPendingSignal) {
        // §1.6: not adopted, and no fallback to the v1 seal on the same row.
        this.pendingGrantsByVault.set(grant.vaultId, e.pending);
        this.grantAnomaliesByVault.delete(grant.vaultId);
        return;
      }
      if (e instanceof GrantRefusedSignal) {
        this.grantAnomaliesByVault.set(grant.vaultId, e.verdict);
        this.pendingGrantsByVault.delete(grant.vaultId);
        return;
      }
      throw e;
    }
    const viaSeal = opened.source === "legacy-seal" || opened.source === "signed-grant";
    this.recordHeldKey(grant.vaultId, opened.vk);
    this.vaultKeys.set(grant.vaultId, opened.vk);
    this.keySources.set(grant.vaultId, opened.source);
    if (opened.from) this.signedGrantFrom.set(grant.vaultId, opened.from);
    this.pendingGrantsByVault.delete(grant.vaultId);
    if (opened.anomaly) this.grantAnomaliesByVault.set(grant.vaultId, opened.anomaly);
    else this.grantAnomaliesByVault.delete(grant.vaultId);
    this.unreadableKeyVaults.delete(grant.vaultId);
    if (opened.sealMismatch) this.vkMismatchVaults.add(grant.vaultId);
    if (opened.source === "uvk-wrap" && grant.userId === this.userId) this.uvkWrappedVaults.add(grant.vaultId);
    // Provenance of the KEY, recorded at the one moment it is knowable (audit H64), and never
    // re-stamped by a later re-delivery (the early return above). Since root cause A §3.2 a
    // member's own row can carry a UVK self-wrap, so "opened from a seal" alone no longer separates
    // shared from mine-alone: a row is member-granted when the key came from a seal, OR it carries
    // any seal, OR its role is not owner. Only an owner row with a bare UVK wrap and no seal is a
    // personal candidate, which is what enrolment mints. Since root cause A §4 this bit no longer
    // decides "personal" (the personal wrap does); it feeds display and the §8.5 candidate filter.
    if (viaSeal || !!grant.sealedVk || !!grant.signedGrant || grant.role !== "owner") this.memberGrantedVaults.add(grant.vaultId);
  }

  /** Run §1.4 on the row's v2 grant; `heldVk` only when held from our OWN wrap. */
  private openSigned(grant: WireGrant, heldVk: Uint8Array | null): GrantOutcome {
    let sealed: Uint8Array;
    try {
      sealed = fromB64(grant.signedGrant ?? "");
    } catch {
      return { verdict: "unopenable", anomaly: false };
    }
    return openSignedGrant({
      myUserId: this.userId, myIdentityPub: this.identityPub, myIdentityPriv: this.identityPriv, rowVaultId: grant.vaultId,
      sealed, pinFor: this.grantPins, heldVk,
    });
  }

  /**
   * Canonical-key precedence (security review 2026-10, root cause A §3.1) — core `openGrantVk` twin.
   * The VK comes from the FIRST of: (1) the personal wrap (§4, applied at unlock, so a row for that vault
   * is only compared against it); (2) our own UVK wrap
   * `wrappedVk` (owner wrap, post-transfer new-owner wrap, member self-wrap §3.2); (3) a v2 signed
   * grant (§1.4, not yet built); (4) a v1 `sealedVk`, legacy only. A seal is never preferred over a
   * UVK wrap: when the wrap opens, a seal on the same row is opened only to compare (same → silent,
   * different → `sealMismatch`, unopenable → ignored). A wrap that is present but does not open
   * throws {@link VaultGrantKeyUnreadableError} and the seal is never tried.
   */
  private openGrantVk(grant: WireGrant): { vk: Uint8Array; source: KeySource; sealMismatch: boolean; from?: string; anomaly?: GrantVerdict } {
    if (grant.wrappedVk) {
      let vk: Uint8Array;
      try {
        const envelope = fromB64(grant.wrappedVk);
        const refusal = structuralRefusal(envelope);
        if (refusal !== null) throw new VaultGrantKeyUnreadableError(grant.vaultId, refusal);
        vk = open(this.uvk, envelope, adVk(grant.vaultId, this.userId));
      } catch (e) {
        if (e instanceof VaultGrantKeyUnreadableError) throw e;
        throw new VaultGrantKeyUnreadableError(grant.vaultId, "wrap does not open");
      }
      // A wrap that OPENS under our UVK was minted by one of our own clients: a wrong length is a
      // buggy writer (core audit F32 parity: CryptoError), still terminal, still no seal fallback.
      if (vk.length !== 32) throw new CryptoError(`vault key for ${grant.vaultId} is not 32 bytes`);
      const sealVk = grant.sealedVk ? this.openSealOrNull(grant.vaultId, grant.sealedVk) : null;
      // A v2 grant beside our wrap is compared too; only a VERIFIED one can disagree with it.
      const signedDiffers = !!grant.signedGrant && this.openSigned(grant, vk).verdict === "vk_mismatch";
      // Rule 2 is canonical (A1) and is USED even against this device's vouch, but flagged (round 3 LOW-F).
      const gate = this.vouchGate(grant.vaultId, vk) === "mismatch" ? ("vk_mismatch" as GrantVerdict) : undefined;
      // A6 final review LOW-H: the gate's mismatch also lands in vkMismatchVaults (the "vault key mismatch" notice).
      return { vk, source: "uvk-wrap", sealMismatch: (sealVk !== null && !ctEquals(sealVk, vk)) || signedDiffers || gate !== undefined, anomaly: gate };
    }
    // (3) v2 signed grant, verified per root cause A §1.4 against our PIN for the sender it names.
    if (grant.signedGrant) {
      // The v1 seal on this row, only if it opens to the key this device VOUCHED for (HIGH-1: a vouch is bound to
      // its key; a different v1 key for the same vault is not covered).
      const vouched = this.vouchedSealKey(grant);
      const o = this.openSigned(grant, null);
      if (o.verdict === "adopt") {
        // MED-2 / re-review MEDIUM-A: decided from the device-local vouch TAG, not from whether the server kept
        // the v1 seal. A verified grant naming a DIFFERENT key than the vouched one is vk_mismatch: keep the vouched
        // key when the seal still opens to it, otherwise refuse the row with no key. Never adopt it.
        if (this.vouchGate(grant.vaultId, o.vk) === "mismatch") {
          if (vouched) return { vk: vouched, source: "legacy-seal", sealMismatch: false, anomaly: "vk_mismatch" };
          throw new GrantRefusedSignal("vk_mismatch");
        }
        return { vk: o.vk, source: "signed-grant", sealMismatch: false, from: o.from };
      }
      if (o.verdict === "pending_invitation") {
        // Never satisfied by the v1 seal on the same row, EXCEPT for the key this device already vouched for (§8.2
        // freeze or the human's Accept) whose self-wrap has not reached the row yet.
        if (vouched) return { vk: vouched, source: "legacy-seal", sealMismatch: false };
        throw new GrantPendingSignal({ vaultId: grant.vaultId, fromUserId: o.from, grantIdB64: o.grantIdB64 });
      }
      // LOW-2: a field that is PRESENT and fails §1.4 in ANY way (anomaly or not) refuses the row: no v1 fallback.
      throw new GrantRefusedSignal(o.verdict);
    }
    // (4) v1 `sealedVk`, compatibility window only: legacy-read-only until vouched for (§8.2). The decision runs
    // through the graded function (LOW-3): post-window, a key with no pre-upgrade evidence is refused outright.
    if (grant.sealedVk) {
      const vk = openSharedGrant(this.identityPub, this.identityPriv, grant.vaultId, fromB64(grant.sealedVk));
      // Round 3 LOW-E: a seal for another key than this device's vouch is vk_mismatch, not a read-only key waiting
      // for an "Accept anyway" that would overwrite the vouch.
      if (this.vouchGate(grant.vaultId, vk) === "mismatch") throw new GrantRefusedSignal("vk_mismatch");
      if (this.legacyModeFor(grant.vaultId, vk) === "refused") throw new CryptoError(`legacy grant for ${grant.vaultId} refused (compatibility window closed)`);
      return { vk, source: "legacy-seal", sealMismatch: false };
    }
    throw new CryptoError(`grant for ${grant.vaultId} carries no key`);
  }

  /**
   * THE vouch gate (A6 re-review round 3: one rule, every key-source path; core `Account.vouchGate` twin). While
   * this device holds a §8.2 vouch for `vaultId`, a key whose SHA-256 differs from the vouch tag is "mismatch": it
   * is never adopted writable, never promoted, never self-wrapped, owner-wrapped, signed onward or transferred, and
   * never offered for "Accept anyway". Only rule 2 (our own UVK wrap, canonical per A1) still USES such a key, and
   * flags vk_mismatch. Every key-source decision in this class routes through here.
   */
  vouchGate(vaultId: string, key: Uint8Array | null | undefined): "no-vouch" | "ok" | "mismatch" {
    // A7: the held-key tag is the same kind of device-local memory as a vouch, and goes through the same gate.
    const v = this.legacyVouches.get(vaultId);
    const h = this.heldKeyTags.get(vaultId);
    if (!v && !h) return "no-vouch";
    if (!key) return "mismatch";
    const t = legacyTagOf(key);
    if (v && v.tag !== t) return "mismatch";
    if (h && h !== t) return "mismatch";
    return "ok";
  }

  /** Restore a persisted held-key tag (the store's durable record wins over an in-memory one). */
  rememberHeldKey(vaultId: string, tag: string): void {
    if (/^[0-9a-f]{64}$/.test(tag)) this.heldKeyTags.set(vaultId, tag);
  }

  /** The held-key tags to persist. */
  heldKeyTagsSnapshot(): Map<string, string> {
    return new Map(this.heldKeyTags);
  }

  /** Record the tag of a key just adopted for `vaultId`, unless one is recorded or the key contradicts the gate. */
  private recordHeldKey(vaultId: string, vk: Uint8Array): void {
    if (this.heldKeyTags.has(vaultId) || this.vouchGate(vaultId, vk) === "mismatch") return;
    this.heldKeyTags.set(vaultId, legacyTagOf(vk));
  }

  /** True when the key HELD for `vaultId` contradicts this device's vouch for it. */
  heldKeyContradictsVouch(vaultId: string): boolean {
    return this.vaultKeys.has(vaultId) && this.vouchGate(vaultId, this.vaultKeys.get(vaultId)) === "mismatch";
  }

  /** The row's v1 seal key, only when this device holds a §8.2 VOUCH and the gate says it IS the vouched key (a
   *  held-key tag alone never makes a seal key acceptable). */
  private vouchedSealKey(grant: WireGrant): Uint8Array | null {
    if (!grant.sealedVk || !this.legacyVouches.has(grant.vaultId)) return null;
    const k = this.openSealOrNull(grant.vaultId, grant.sealedVk);
    return k && this.vouchGate(grant.vaultId, k) === "ok" ? k : null;
  }

  /**
   * §8.2 / §8.6 (A6 review LOW-3): the legacy decision for [vk] as a v1-only key of [vaultId], routed through the
   * graded `decideLegacyGrant`. A vouch counts only for the key it was given for (HIGH-1).
   */
  private legacyModeFor(vaultId: string, vk: Uint8Array): LegacyGrantMode {
    const v = this.legacyVouches.get(vaultId);
    const matches = !!v && legacyTagOf(vk) === v.tag;
    return decideLegacyGrant(LEGACY_IN_WINDOW, matches && v!.kind === "frozen", matches && v!.kind === "confirmed");
  }

  private heldLegacyMode(vaultId: string): LegacyGrantMode | null {
    const held = this.vaultKeys.get(vaultId);
    if (!held || this.keySources.get(vaultId) !== "legacy-seal") return null;
    return this.legacyModeFor(vaultId, held);
  }

  private openSealOrNull(vaultId: string, sealedVk: string): Uint8Array | null {
    try {
      return openSharedGrant(this.identityPub, this.identityPriv, vaultId, fromB64(sealedVk));
    } catch {
      return null;
    }
  }

  /** A re-delivered row for a vault whose key we hold: does any key it carries differ from it? */
  private rowCarriesOtherKey(grant: WireGrant, held: Uint8Array): boolean {
    let fromWrap: Uint8Array | null = null;
    if (grant.wrappedVk) {
      try {
        fromWrap = open(this.uvk, fromB64(grant.wrappedVk), adVk(grant.vaultId, this.userId));
      } catch {
        fromWrap = null;
      }
    }
    const fromSeal = grant.sealedVk ? this.openSealOrNull(grant.vaultId, grant.sealedVk) : null;
    let fromSigned: Uint8Array | null = null;
    if (grant.signedGrant) {
      const o = this.openSigned(grant, null);
      if (o.verdict === "adopt") fromSigned = o.vk;
    }
    return [fromWrap, fromSeal, fromSigned].some((k) => k !== null && !ctEquals(k, held));
  }

  /** True when a row for this vault carried a seal whose key differs from the one we hold (the
   *  "vault key mismatch" anomaly, root cause A §3.1). Display only: the held key is canonical. */
  vkMismatch(vaultId: string): boolean {
    return this.vkMismatchVaults.has(vaultId);
  }

  vkMismatchVaultIds(): string[] {
    return [...this.vkMismatchVaults];
  }

  /** True when this vault's grant carries our UVK wrap and it does not open (no seal fallback). */
  keyUnreadable(vaultId: string): boolean {
    return this.unreadableKeyVaults.has(vaultId);
  }

  keyUnreadableVaultIds(): string[] {
    return [...this.unreadableKeyVaults];
  }

  /** Root cause A §3.2: we hold this vault's key and our row has no UVK wrap yet — a candidate for
   *  {@link buildSelfWrap}. NOT a trust signal: {@link selfWrapAuthorized} is the gate (a verified v2 grant, or a
   *  v1 key this device froze or the human confirmed). Core twin: `Account.needsSelfWrap`. */
  needsSelfWrap(grant: WireGrant): boolean {
    return this.vaultKeys.has(grant.vaultId) && !grant.wrappedVk && (!!grant.sealedVk || !!grant.signedGrant) && grant.role !== "owner" && grant.userId === this.userId;
  }

  /**
   * Root cause A §3.2 / §8.2, the ONLY gate on minting a member self-wrap (core `selfWrapAuthorized`): a key from
   * a v2 grant VERIFIED against our pin for its sender, or a v1 key this device vouched for (freeze or Accept). A
   * key only an unconfirmed v1 seal vouches for is never wrapped (the A1 trust-laundering bug).
   */
  selfWrapAuthorized(vaultId: string): boolean {
    if (!this.vaultKeys.has(vaultId) || this.heldKeyContradictsVouch(vaultId)) return false;
    const src = this.keySources.get(vaultId);
    if (src === "signed-grant") return true;
    const mode = this.heldLegacyMode(vaultId);
    return mode === "frozen" || mode === "confirmed";
  }

  /** Where this vault's held key came from (null when not held). */
  keySource(vaultId: string): KeySource | null {
    return this.vaultKeys.has(vaultId) ? (this.keySources.get(vaultId) ?? null) : null;
  }

  /** INV-WRITE-KEY: a key only an unconfirmed v1 seal vouches for. Readable; never written under. */
  isLegacyReadOnly(vaultId: string): boolean {
    return this.heldLegacyMode(vaultId) === "read_only";
  }

  legacyReadOnlyVaultIds(): string[] {
    return [...this.vaultKeys.keys()].filter((id) => this.isLegacyReadOnly(id));
  }

  /** The tag of the key held for `vaultId` (lowercase hex SHA-256), or null when none is held. */
  legacyKeyTag(vaultId: string): string | null {
    const k = this.vaultKeys.get(vaultId);
    return k ? legacyTagOf(k) : null;
  }

  /**
   * §8.2: this device vouches for the v1-only key of `vaultId` (freeze evidence: "frozen"; the human's Accept:
   * "confirmed"), BOUND to the key with tag `tag` (default: the key held now). With no tag and no held key nothing is
   * recorded: a vouch for "whatever key arrives" is exactly what HIGH-1 forbids.
   */
  authorizeLegacyKey(vaultId: string, tag?: string, kind: LegacyVouchKind = "confirmed"): void {
    const t = tag ?? this.legacyKeyTag(vaultId);
    if (!t || !/^[0-9a-f]{64}$/.test(t)) return;
    this.legacyVouches.set(vaultId, { tag: t, kind });
  }

  /** The vouch recorded for `vaultId`, for the store to persist. */
  legacyVouch(vaultId: string): LegacyVouch | null {
    return this.legacyVouches.get(vaultId) ?? null;
  }

  /** True when a v2 grant for `vaultId` is waiting on verification (§1.6). */
  hasPendingGrant(vaultId: string): boolean {
    return this.pendingGrantsByVault.has(vaultId);
  }

  /** True when a v2 grant for `vaultId` failed §1.4 (the review card must not offer TOFU over it, LOW-2). */
  hasGrantAnomaly(vaultId: string): boolean {
    return this.grantAnomaliesByVault.has(vaultId);
  }

  /** The sender the VERIFIED v2 grant for `vaultId` names (null unless the key came from one). */
  signedGrantSender(vaultId: string): string | null {
    return this.keySources.get(vaultId) === "signed-grant" ? (this.signedGrantFrom.get(vaultId) ?? null) : null;
  }

  pendingGrants(): PendingGrant[] {
    return [...this.pendingGrantsByVault.values()];
  }

  grantAnomalies(): Map<string, GrantVerdict> {
    return new Map(this.grantAnomaliesByVault);
  }

  /**
   * Owner side (root cause A §1.5): grant v2 for `vaultId` to the member `pin` names — `toKey` is the PINNED key and
   * the frame is sealed to it, never to a key fresh from `/users/lookup`. Refuses a key this account itself holds only
   * from an unconfirmed v1 seal (signing it would launder it to the member). The signing secret never leaves here.
   */
  buildSignedGrant(vaultId: string, pin: Contact): string {
    if (this.isLegacyReadOnly(vaultId) || this.heldKeyContradictsVouch(vaultId)) throw new VaultKeyNotVerifiedError(vaultId);
    if (pin.userId === this.userId) throw new CryptoError("a vault grant cannot be addressed to its sender");
    const pinKey = fromB64(pin.identityPub);
    const frame = buildGrantFrame(
      { publicKey: this.signPub, privateKey: this.signSecret },
      { purpose: "vault-grant", from: this.userId, to: pin.userId, toKey: pinKey, vaultId, grantId: randomBytes(16), issuedAt: Date.now(), vk: this.vk(vaultId) },
    );
    return toB64(sealGrantFrame(pinKey, frame));
  }

  /**
   * True when this vault's VK reached us through a member grant (`sealedVk`,
   * `crypto_box_seal` to our identity pubkey) rather than wrapped under our own UVK.
   *
   * WHY this is security-relevant and not bookkeeping: a `sealedVk` is ANONYMOUS — anybody
   * holding our public identity key can mint one, and the VK inside it is by construction a
   * key at least one other person already has. A `wrappedVk` opens only under our UVK with AD
   * `andvari/v1|vk|{vaultId}|{userId}`, so it is unforgeable evidence that this client itself
   * sealed that key for itself (enrollment, shared-vault creation, password-change re-wrap,
   * transfer accept). "Which vault is mine alone" must rest on the second kind of evidence.
   *
   * Since the member self-wrap (root cause A §3.2) a member's row can carry a `wrappedVk` too, so
   * this also answers true for a row that carries any seal or whose role is not owner (see addGrant).
   */
  keyArrivedByMemberGrant(vaultId: string): boolean {
    return this.memberGrantedVaults.has(vaultId);
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

  /**
   * The EFFECTIVE role (core `roleFor` twin): the server-declared role, except that a vault whose key is
   * legacy-read-only (INV-WRITE-KEY) reads as `reader`, so every write path that refuses readers refuses it too.
   */
  roleFor(vaultId: string): string | null {
    if (this.isLegacyReadOnly(vaultId)) return "reader";
    return this.vaultRoles.get(vaultId) ?? null;
  }

  /** The role exactly as the server declared it. */
  serverRoleFor(vaultId: string): string | null {
    return this.vaultRoles.get(vaultId) ?? null;
  }

  /** Membership revoked (sync `removedGrants`): forget the VK and the role. */
  removeVault(vaultId: string) {
    this.vaultKeys.delete(vaultId);
    this.vaultRoles.delete(vaultId);
    this.memberGrantedVaults.delete(vaultId); // provenance dies with the key it describes (H64)
    this.uvkWrappedVaults.delete(vaultId);
    this.vkMismatchVaults.delete(vaultId);
    this.unreadableKeyVaults.delete(vaultId);
    this.keySources.delete(vaultId);
    this.signedGrantFrom.delete(vaultId);
    this.legacyVouches.delete(vaultId);
    this.heldKeyTags.delete(vaultId); // A7: the held-key memory dies with the vault, like a vouch
    this.pendingGrantsByVault.delete(vaultId);
    this.grantAnomaliesByVault.delete(vaultId);
  }

  /**
   * Seal this vault's VK to a member's identity key (spec 01 §6 member grant). The
   * caller MUST have verified `memberIdentityPub`'s fingerprint out of band first.
   * Throws if we do not hold the vault key.
   */
  wrapVkForMember(memberIdentityPub: Uint8Array, vaultId: string): string {
    return toB64(sealSharedGrant(memberIdentityPub, vaultId, this.vk(vaultId)));
  }

  /**
   * Build a shared-vault create request (spec 03 §10): fresh vaultId + VK, metaBlob
   * under VK, and the owner's wrappedVk under the UVK — the same formula as the
   * personal vault at enrollment. Registers the VK + owner role locally so the vault
   * is usable immediately; call removeVault(vaultId) if the server rejects the create.
   */
  buildCreateSharedVault(name: string): { request: CreateVaultRequest; vaultId: string } {
    const vaultId = uuidv4();
    const vk = randomBytes(32);
    const request: CreateVaultRequest = {
      vaultId,
      metaBlob: toB64(seal(vk, utf8(JSON.stringify({ name })), adVaultMeta(vaultId))),
      wrappedVk: toB64(seal(this.uvk, vk, adVk(vaultId, this.userId))),
    };
    this.vaultKeys.set(vaultId, vk);
    this.heldKeyTags.set(vaultId, legacyTagOf(vk)); // A7: a fresh vault's key is this device's from the first moment
    this.vaultRoles.set(vaultId, "owner");
    this.keySources.set(vaultId, "uvk-wrap");
    this.uvkWrappedVaults.add(vaultId);
    return { request, vaultId };
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
   * (no personal vault until the §8.5 migration resolves). Opens → "confirmed", its VK held FIRST.
   * Does not open → "unreadable" (an anomaly), no personal vault, and no fallback to any label.
   * Replaces the pre-A5 `setPersonalVault(label candidate)`: a server `type` label or `role` never
   * reaches this decision any more.
   */
  applyPersonalWrap(wrap: PersonalWrap | null) {
    if (!wrap) {
      if (this.personalStatusValue === "absent" || this.personalStatusValue === "unreadable") {
        this.personalStatusValue = "absent";
        this.personalVaultIdValue = "";
      }
      return;
    }
    this.pendingPersonalChangeValue = null;
    if (this.openAndInstallPersonalWrap(wrap)) this.personalStatusValue = "confirmed";
    else {
      this.personalStatusValue = "unreadable";
      this.personalVaultIdValue = "";
      this.personalWrapValue = null;
    }
  }

  /**
   * The wrap THIS DEVICE cached the last time it authenticated one (UVK-sealed), applied after the served wrap
   * was judged (A5 review H-1; A5b L-1). Core twin: `applyCachedPersonalWrap`.
   *  - "absent" (none served): success → "withheld"; a cached blob that does not open → "unreadable";
   *  - "unreadable" (junk served): success → "unreadable-cached", the cached wrap in force; else no change.
   */
  applyCachedPersonalWrap(wrap: PersonalWrap) {
    if (this.personalStatusValue === "absent") {
      if (this.openAndInstallPersonalWrap(wrap)) this.personalStatusValue = "withheld";
      else {
        this.personalStatusValue = "unreadable";
        this.personalVaultIdValue = "";
      }
    } else if (this.personalStatusValue === "unreadable") {
      if (this.openAndInstallPersonalWrap(wrap)) this.personalStatusValue = "unreadable-cached";
    }
  }

  /**
   * A5b M-2 / L-2 (core `holdPersonalChange` twin): the served wrap opened ("confirmed") but this device's
   * cached wrap names a DIFFERENT vault. If the cached wrap opens, it stays in force and the served one waits
   * in {@link pendingPersonalChange} ("changed") until the human confirms. False when nothing was held.
   */
  holdPersonalChange(cached: PersonalWrap): boolean {
    const served = this.personalWrapValue;
    if (!served || this.personalStatusValue !== "confirmed" || cached.vaultId === served.vaultId) return false;
    if (!this.openAndInstallPersonalWrap(cached)) return false; // mutates only on success
    this.pendingPersonalChangeValue = served;
    this.personalStatusValue = "changed";
    return true;
  }

  /** The human confirmed a "changed" notice: the served wrap (already authenticated) is now in force. Mints nothing. */
  acceptPersonalChange(): void {
    const served = this.pendingPersonalChangeValue;
    if (!served || this.personalStatusValue !== "changed") throw new Error("no personal-vault change is pending");
    if (!this.openAndInstallPersonalWrap(served)) throw new Error("the served personal wrap no longer opens");
    this.pendingPersonalChangeValue = null;
    this.personalStatusValue = "confirmed";
  }

  /** The served wrap waiting for the human while the status is "changed". */
  get pendingPersonalChange(): PersonalWrap | null {
    return this.pendingPersonalChangeValue;
  }

  private pendingPersonalChangeValue: PersonalWrap | null = null;

  /** The wrap that decided the personal vault (served or cached), for the device's local cache. */
  get personalWrap(): PersonalWrap | null {
    return this.personalWrapValue;
  }

  private personalWrapValue: PersonalWrap | null = null;

  private openAndInstallPersonalWrap(wrap: PersonalWrap): boolean {
    let vk: Uint8Array | null = null;
    try {
      vk = open(this.uvk, fromB64(wrap.wrappedVk), adVkPersonal(wrap.vaultId, this.userId));
    } catch {
      vk = null;
    }
    if (!vk || vk.length !== 32) return false;
    const held = this.vaultKeys.get(wrap.vaultId);
    if (held && !ctEquals(held, vk)) this.vkMismatchVaults.add(wrap.vaultId);
    this.vaultKeys.set(wrap.vaultId, vk);
    this.keySources.set(wrap.vaultId, "personal-wrap");
    this.unreadableKeyVaults.delete(wrap.vaultId);
    this.uvkWrappedVaults.add(wrap.vaultId);
    this.personalVaultIdValue = wrap.vaultId;
    this.personalWrapValue = wrap;
    return true;
  }

  /** True when this vault's key opened from a UVK wrap of ours (never a seal): re-designation may offer it. */
  keyFromOwnUvkWrap(vaultId: string): boolean {
    return this.uvkWrappedVaults.has(vaultId) && this.vaultKeys.has(vaultId);
  }

  /** Mint the personal wrap for `vaultId` (§4.1), round-trip verified. Refuses a vault whose key did not
   *  open from our own UVK wrap, so a seal-delivered key is never laundered into "personal". */
  buildPersonalWrap(vaultId: string): PersonalWrap {
    if (!this.keyFromOwnUvkWrap(vaultId)) throw new CryptoError(`vault ${vaultId} is not wrapped under this account's key`);
    const vk = this.vk(vaultId);
    const wrapped = seal(this.uvk, vk, adVkPersonal(vaultId, this.userId));
    if (!ctEquals(open(this.uvk, wrapped, adVkPersonal(vaultId, this.userId)), vk)) throw new CryptoError("personal wrap failed round-trip verification");
    return { vaultId, wrappedVk: toB64(wrapped) };
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

  /**
   * Seal an item doc under its vault VK. The formatVersion — also bound into the AD —
   * is max(docFloor, the fv this itemId was last decrypted/sealed at), so callers never
   * thread fv explicitly: new docs seal at their floor, existing items re-seal
   * monotonically (decryptItem/decryptItemVersion feed the per-item memory). The wire
   * fv and the AD fv come from this ONE computation.
   */
  encryptItem(vaultId: string, itemId: string, doc: ItemDoc): ItemUpload {
    if (this.isLegacyReadOnly(vaultId)) throw new VaultKeyNotVerifiedError(vaultId); // INV-WRITE-KEY
    return this.sealItem(vaultId, itemId, doc);
  }

  /**
   * The holding-area snapshot (spec 03 §11, store.moveToHolding): re-seal plaintext that was DECRYPTED from this
   * vault, under the same key, for this device's own ciphertext-only storage. Never pushed, never a new
   * provenance, so INV-WRITE-KEY (which guards what the household receives) does not apply: a removed
   * legacy-read-only vault is parked exactly like any other.
   */
  resealForHolding(vaultId: string, itemId: string, doc: ItemDoc): ItemUpload {
    return this.sealItem(vaultId, itemId, doc);
  }

  private sealItem(vaultId: string, itemId: string, doc: ItemDoc): ItemUpload {
    const fv = Math.max(docFloor(doc), this.itemFv.get(itemId) ?? 1);
    this.itemFv.set(itemId, fv);
    const blob = seal(this.vk(vaultId), utf8(JSON.stringify(doc)), adItem(vaultId, itemId, fv));
    return { formatVersion: fv, blob: toB64(blob) };
  }

  decryptItem(item: WireItem): ItemDoc {
    if (!item.blob) throw new CryptoError("item has no blob (tombstone?)");
    // Fail closed on documents from a NEWER format: unknown-field preservation (spec 02 §3)
    // is scoped WITHIN a formatVersion, and editing a v3 doc here would re-seal it silently
    // downgraded. CryptoError rides the existing catch paths ("undecryptable").
    if (item.formatVersion > ITEM_FORMAT_VERSION) throw new CryptoError(`item formatVersion ${item.formatVersion} is newer than this client supports`);
    const plain = open(this.vk(item.vaultId), fromB64(item.blob), adItem(item.vaultId, item.itemId, item.formatVersion));
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
  decryptVaultMeta(vaultId: string, metaBlob: string): Record<string, unknown> {
    const plain = open(this.vk(vaultId), fromB64(metaBlob), adVaultMeta(vaultId));
    return JSON.parse(fromUtf8(plain)) as Record<string, unknown>;
  }

  // ---- vault lifecycle (spec 03 §11) ----

  /**
   * The lifecycle key for a vault: `HKDF-SHA-256(VK, "andvari/v1|lifecycle")` — domain-
   * separated from the AEAD key. Callers mint/verify destructive-op proofs under it; the VK
   * itself never leaves this class (ZK: proofs are MACs the server can neither mint nor open).
   */
  lifecycleKeyFor(vaultId: string): Promise<Uint8Array> {
    return lifecycleKey(this.vk(vaultId));
  }

  /**
   * Transfer accept (spec 03 §11): the new owner re-wraps the VK it ALREADY holds (via its
   * sealed member grant) under its OWN UVK — identical construction to vault creation
   * (`seal(UVK, VK, adVk(vaultId, me))`). Round-trip-verified before returning, so a garbage
   * wrap that would lock the new owner out never gets posted (the "garbage-wrap" break).
   */
  buildOwnerWrap(vaultId: string): string {
    // A transfer accept must not launder a key only an unconfirmed v1 seal vouches for (root cause A §8.2).
    if (this.isLegacyReadOnly(vaultId) || this.heldKeyContradictsVouch(vaultId)) throw new VaultKeyNotVerifiedError(vaultId);
    return this.roundTripWrap(vaultId, "owner wrap");
  }

  /**
   * Member self-wrap (security review 2026-10, root cause A §3.2): the VK this member already holds,
   * wrapped under its OWN UVK exactly as {@link buildOwnerWrap} does, round-trip verified, for
   * `PUT /vaults/{id}/grant/self-wrap`. Once it is on the row every device of this member takes the
   * key from the wrap and the seal stops being load-bearing. Only for a key whose origin is
   * authenticated (see needsSelfWrap). Core twin: `Account.buildSelfWrap`.
   */
  buildSelfWrap(vaultId: string): string {
    if (!this.selfWrapAuthorized(vaultId)) throw new VaultKeyNotVerifiedError(vaultId);
    return this.roundTripWrap(vaultId, "self wrap");
  }

  private roundTripWrap(vaultId: string, what: string): string {
    const vk = this.vk(vaultId);
    const wrapped = seal(this.uvk, vk, adVk(vaultId, this.userId));
    if (!ctEquals(open(this.uvk, wrapped, adVk(vaultId, this.userId)), vk)) {
      throw new CryptoError(`${what} failed round-trip verification`);
    }
    return toB64(wrapped);
  }

  /**
   * Rename (spec 03 §11 / Q6): read-modify-write the metaBlob under the SAME VK/AD — change
   * ONLY `name`, PRESERVE every unknown field (spec 02 §4), and increment the monotonic
   * plaintext `metaV` counter (anti-replay). Returns the new metaBlob (base64url). The name
   * stays E2E ciphertext; the server only ever sees an opaque blob.
   */
  buildRenameMeta(vaultId: string, metaBlob: string, newName: string): string {
    if (this.isLegacyReadOnly(vaultId)) throw new VaultKeyNotVerifiedError(vaultId);
    const meta = this.decryptVaultMeta(vaultId, metaBlob);
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
   * F57: build a fresh escrow blob re-sealing this account's UVK to the current org recovery key
   * after a re-ceremony (spec 04 §4). SECURITY: `verifiedFingerprint` MUST be the value the user
   * confirmed against the NEW printed recovery sheet (short-form). We bind the server-fetched
   * `recoveryPubB64` to that fingerprint and refuse to seal on mismatch, so a hostile server
   * cannot redirect the UVK escrow to an attacker-held recovery key. The UVK only ever leaves
   * the client sealed to the verified recovery public key (zero-knowledge).
   */
  async resealEscrowFor(recoveryPubB64: string, verifiedFingerprint: string): Promise<{ sealed: string; fingerprint: string }> {
    const pub = fromB64(recoveryPubB64);
    if ((await recoveryFingerprint(pub)) !== verifiedFingerprint) {
      throw new CryptoError("recovery public key does not match the verified fingerprint — refusing to re-seal escrow");
    }
    // Escrow v2 (security review 2026-10, root cause A §2.1 / §8.4) — also the v1 → v2 migration seal.
    // The server keeps the previous blob as `escrow_legacy` until a fleet drill passes on this one.
    // The joint signing secret never leaves this class: there is deliberately no public
    // `signStatement` (module-private parity with core's `internal`, A3 review).
    const sealed = await sealUvkV2({
      recoveryPub: pub,
      verifiedRecoveryFp: verifiedFingerprint,
      userId: this.userId,
      identityPub: this.identityPub,
      signer: { publicKey: this.signPub, privateKey: this.signSecret },
      uvk: this.uvk,
      issuedAt: Date.now(),
    });
    return { sealed: toB64(sealed), fingerprint: verifiedFingerprint };
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

export function deviceName(): string {
  if (typeof navigator !== "undefined" && navigator.userAgent) {
    const ua = navigator.userAgent;
    const m = ua.match(/(Chrome|Firefox|Safari|Edg)\/[\d.]+/);
    return `web ${m ? m[0] : "browser"}`;
  }
  return "web";
}
