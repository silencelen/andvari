import { adIdkey, adItem, adUsage, adUvk, adVaultMeta, adVk } from "../crypto/ad";
import { usageKey } from "../crypto/usagekey";
import { ctEquals, fromB64, fromUtf8, toB64, utf8 } from "../crypto/bytes";
import { open, seal, structuralRefusal } from "../crypto/envelope";
import { fingerprint as recoveryFingerprint, sealUvk } from "../crypto/escrow";
import { authKey as deriveAuthKey, masterKey, wrapKey as deriveWrapKey, type KdfParams } from "../crypto/keys";
import { lifecycleKey } from "../crypto/lifecycleproof";
import { generate as generateMemberRecovery, openUvk as openMemberRecoveryUvk } from "../crypto/member-recovery";
import { boxKeypairFromSeed, randomBytes } from "../crypto/provider";
import { openSharedGrant, sealSharedGrant, shortIdentityFingerprint } from "../crypto/sharedgrant";
import { CryptoError } from "../crypto/sodium";
import type {
  AccountKeys,
  CreateVaultRequest,
  EscrowUpload,
  ItemDoc,
  ItemVersion,
  RecoveryCommitRequest,
  RecoverySelfSetupRequest,
  RecoveryVerifyResponse,
  RegisterRequest,
  WireGrant,
  WireItem,
} from "../api/types";

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
    public personalVaultId: string, // "" until discovered from the personal-vault grant on first sync
    private readonly vaultKeys: Map<string, Uint8Array>,
  ) {}

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
    try {
      const identity = boxKeypairFromSeed(identitySeed);
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
        escrow = { sealed: toB64(await sealUvk(params.recoveryPublicKey, userId, uvk)), fingerprint: fp };
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
      };

      const vaultKeys = new Map([[personalVaultId, vk]]);
      const account = new Account(userId, uvk, identity.privateKey, identity.publicKey, personalVaultId, vaultKeys);
      account.vaultRoles.set(personalVaultId, "owner");
      return { request, account, recoverySecret: recovery.recoverySecret };
    } finally {
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
  static async unlock(userId: string, password: string, keys: AccountKeys): Promise<Account> {
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
    return Account.unlockFromUvk(userId, uvk, keys);
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
  private static unlockFromUvk(userId: string, uvk: Uint8Array, keys: AccountKeys): Account {
    let seedEnvelope: Uint8Array;
    try {
      seedEnvelope = fromB64(keys.encryptedIdentitySeed);
    } catch (e) {
      throw new VaultKeyDamagedError("encryptedIdentitySeed is not valid base64url", e);
    }
    const seedRefusal = structuralRefusal(seedEnvelope);
    if (seedRefusal !== null) throw new VaultKeyDamagedError(`encryptedIdentitySeed: ${seedRefusal}`);
    const identitySeed = open(uvk, seedEnvelope, adIdkey(userId));
    // ZEROIZATION (audit H80): the seed's only job is to derive the keypair the Account holds —
    // a compromise of the seed IS a compromise of the identity key, so it gets the MK's care.
    let identity: ReturnType<typeof boxKeypairFromSeed>;
    try {
      identity = boxKeypairFromSeed(identitySeed);
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
      throw new IdentityMismatchError();
    }
    return new Account(userId, uvk, identity.privateKey, identity.publicKey, "", new Map());
  }

  /**
   * Apply a grant from sync (spec 01 §6). The role update is UNCONDITIONAL — a role
   * change re-delivers the grant while the VK is already held, and MUST still take
   * effect; the key-open is attempted only when the VK is missing. Member grants carry
   * `sealedVk` (crypto_box_seal to our identity key); personal/owner grants carry
   * `wrappedVk` under the UVK.
   */
  addGrant(grant: WireGrant) {
    if (grant.role) this.vaultRoles.set(grant.vaultId, grant.role);
    if (this.vaultKeys.has(grant.vaultId)) return;
    const arrivedByMemberGrant = !!grant.sealedVk;
    const vk = arrivedByMemberGrant
      ? openSharedGrant(this.identityPub, this.identityPriv, grant.vaultId, fromB64(grant.sealedVk!))
      : open(this.uvk, fromB64(grant.wrappedVk), adVk(grant.vaultId, this.userId));
    this.vaultKeys.set(grant.vaultId, vk);
    // Provenance of the KEY, recorded at the one moment it is knowable (audit H64). Never
    // re-stamped by a later re-delivery — the early return above means the grant that actually
    // opened the key is the one that says how it arrived, so a hostile server cannot launder a
    // member-granted vault by re-sending it with a wrappedVk, and a post-transfer owner grant
    // carrying BOTH forms (spec 02 §4) does not retroactively make a vault we joined as a
    // member look like one we minted.
    if (arrivedByMemberGrant) this.memberGrantedVaults.add(grant.vaultId);
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

  /** Role from the latest grant for this vault, or null if none seen. */
  roleFor(vaultId: string): string | null {
    return this.vaultRoles.get(vaultId) ?? null;
  }

  /** Membership revoked (sync `removedGrants`): forget the VK and the role. */
  removeVault(vaultId: string) {
    this.vaultKeys.delete(vaultId);
    this.vaultRoles.delete(vaultId);
    this.memberGrantedVaults.delete(vaultId); // provenance dies with the key it describes (H64)
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
    this.vaultRoles.set(vaultId, "owner");
    return { request, vaultId };
  }

  /**
   * Short identity fingerprint (spec 01 §5), grouped by the UI as `xxxx xxxx xxxx xxxx`.
   * Computed over the SEED-DERIVED identityPub this class holds — enroll/unlock derive
   * it via boxKeypairFromSeed(identitySeed), never from a server-sent value — so a
   * malicious server cannot pass the out-of-band check with a substituted key.
   */
  identityFingerprintShort(): Promise<string> {
    return shortIdentityFingerprint(this.identityPub);
  }

  /**
   * The store calls this when it sees the personal vault among synced vaults. First writer
   * wins; the value survives for the life of the unlocked account, and it is what
   * {@link sealUsage} keys the usage ledger from and what save() defaults to.
   *
   * REFUSES a vault whose VK arrived by member grant (audit H64). `type === "personal"` is a
   * server plaintext column (spec 02 §4) bound into no AD, and after enrollment nothing the
   * client holds authenticates WHICH vault is its own: `personalVaultId` is rebuilt on every
   * unlock from the first row the server labels personal whose key we happen to hold. A
   * hostile server could therefore withhold the real personal row and relabel a SHARED vault
   * the user is merely a member of; `usageKey = HKDF(VK, "andvari/v1|usage")` would then be
   * computable by every other member of that vault, and `adUsage(userId)` is public — so a
   * colluding co-member could read the victim's per-item behavioural log, the one thing the
   * single-blob ledger design (spec 02 §8.2) exists to keep private.
   *
   * The refusal costs an honest account nothing: a personal vault is minted locally at
   * enrollment and its grant is ALWAYS `wrappedVk` under our own UVK, so "arrived sealed" and
   * "is my personal vault" are disjoint by construction.
   *
   * Fail-closed on purpose: when every held candidate is member-granted, `personalVaultId`
   * stays empty rather than pick one. Empty means "no personal vault", which sealUsage/
   * openUsage already surface as "no ledger" (render "—", never error) and which makes a save
   * with no explicit vault fail loudly instead of silently filing new logins into somebody
   * else's shared vault.
   *
   * Residue, deliberate: an OWNER-created SHARED vault's grant is also `wrappedVk`, so this
   * rule cannot tell it from a personal one. Closing that needs `"type":"personal"` inside the
   * authenticated vaultMeta plaintext — a spec 02 §4 wire change deferred to a spec revision.
   * Kotlin twin: `Account.setPersonalVault`.
   */
  setPersonalVault(vaultId: string) {
    if (this.keyArrivedByMemberGrant(vaultId)) return;
    if (!this.personalVaultId) this.personalVaultId = vaultId;
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
    const doc = JSON.parse(fromUtf8(plain)) as ItemDoc;
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
      return (this.decryptVaultMeta(vaultId, metaBlob).name as string) ?? "(vault)";
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
    const vk = this.vk(vaultId);
    const wrapped = seal(this.uvk, vk, adVk(vaultId, this.userId));
    if (!ctEquals(open(this.uvk, wrapped, adVk(vaultId, this.userId)), vk)) {
      throw new CryptoError("owner wrap failed round-trip verification");
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
    const sealed = await sealUvk(pub, this.userId, this.uvk);
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
