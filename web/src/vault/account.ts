import { adIdkey, adItem, adUvk, adVaultMeta, adVk } from "../crypto/ad";
import { ctEquals, fromB64, fromUtf8, toB64, utf8 } from "../crypto/bytes";
import { open, seal } from "../crypto/envelope";
import { fingerprint as recoveryFingerprint, sealUvk } from "../crypto/escrow";
import { authKey as deriveAuthKey, masterKey, wrapKey as deriveWrapKey, type KdfParams } from "../crypto/keys";
import { lifecycleKey } from "../crypto/lifecycleproof";
import { boxKeypairFromSeed, randomBytes } from "../crypto/provider";
import { openSharedGrant, sealSharedGrant, shortIdentityFingerprint } from "../crypto/sharedgrant";
import { CryptoError } from "../crypto/sodium";
import type { AccountKeys, CreateVaultRequest, ItemDoc, ItemVersion, RegisterRequest, WireGrant, WireItem } from "../api/types";

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
   * Enrollment: generate all keys client-side, seal escrow to the org recovery key,
   * and produce the one-shot register request (spec 01/04). The caller must have
   * confirmed the recovery fingerprint out-of-band first.
   */
  static async enroll(params: {
    inviteToken: string;
    email: string;
    displayName: string;
    password: string;
    kdfParams: KdfParams;
    recoveryPublicKey: Uint8Array;
    recoveryFingerprint: string;
    /** F28: stable per-browser-install id (see ui/session.ts installId) — additive; the fielded server ignores it. */
    installId?: string;
  }): Promise<{ request: RegisterRequest; account: Account }> {
    const userId = uuidv4();
    const personalVaultId = uuidv4();
    const kdfSalt = randomBytes(16);
    const mk = masterKey(params.password, kdfSalt, params.kdfParams);
    const authKey = await deriveAuthKey(mk);
    const wrapKey = await deriveWrapKey(mk);

    const uvk = randomBytes(32);
    const identitySeed = randomBytes(32);
    const identity = boxKeypairFromSeed(identitySeed);
    const vk = randomBytes(32);

    const wrappedUvk = seal(wrapKey, uvk, adUvk(userId));
    const encryptedIdentitySeed = seal(uvk, identitySeed, adIdkey(userId));
    const wrappedVk = seal(uvk, vk, adVk(personalVaultId, userId));
    const metaBlob = seal(vk, utf8(JSON.stringify({ name: "Personal" })), adVaultMeta(personalVaultId));

    // Escrow: the org fingerprint must match what the client was told (defense-in-depth;
    // the human already compared it to the printed sheet).
    const computedFp = await recoveryFingerprint(params.recoveryPublicKey);
    if (computedFp !== params.recoveryFingerprint) {
      throw new CryptoError("recovery public key does not match its fingerprint");
    }
    const sealed = await sealUvk(params.recoveryPublicKey, userId, uvk);

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
      escrow: { sealed: toB64(sealed), fingerprint: params.recoveryFingerprint },
      personalVault: { vaultId: personalVaultId, wrappedVk: toB64(wrappedVk), metaBlob: toB64(metaBlob) },
      device: { platform: "web", name: deviceName(), installId: params.installId },
    };

    const vaultKeys = new Map([[personalVaultId, vk]]);
    const account = new Account(userId, uvk, identity.privateKey, identity.publicKey, personalVaultId, vaultKeys);
    account.vaultRoles.set(personalVaultId, "owner");
    return { request, account };
  }

  /** Derive the login authKey from a password + the account's stored salt/params. */
  static async deriveAuthKey(password: string, kdfSalt: string, params: KdfParams): Promise<string> {
    const mk = masterKey(password, fromB64(kdfSalt), params);
    return toB64(await deriveAuthKey(mk));
  }

  /**
   * Unlock a device that has only the password + the server's account keys.
   * Rebuilds UVK and identity; vault keys are added later from grants.
   */
  static async unlock(userId: string, password: string, keys: AccountKeys): Promise<Account> {
    const mk = masterKey(password, fromB64(keys.kdfSalt), keys.kdfParams);
    const wrapKey = await deriveWrapKey(mk);
    let uvk: Uint8Array;
    try {
      uvk = open(wrapKey, fromB64(keys.wrappedUvk), adUvk(userId));
    } catch {
      throw new CryptoError("wrong master password");
    }
    const identitySeed = open(uvk, fromB64(keys.encryptedIdentitySeed), adIdkey(userId));
    const identity = boxKeypairFromSeed(identitySeed);
    // spec 01 §5 (core parity): fingerprints and sealed-grant opening use the
    // SEED-derived keypair, which the server cannot forge — so a server-sent
    // identityPub that does not equal the derived key is a substitution attempt.
    // Hard-fail with a distinct error; this must NEVER read as "wrong password" —
    // including when the field is MALFORMED (fromB64 throws CryptoError, which the
    // auth surfaces map to "wrong master password"): garbage where the identity key
    // belongs is tampering/corruption, the very thing this check exists to name.
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
    const vk = grant.sealedVk
      ? openSharedGrant(this.identityPub, this.identityPriv, grant.vaultId, fromB64(grant.sealedVk))
      : open(this.uvk, fromB64(grant.wrappedVk), adVk(grant.vaultId, this.userId));
    this.vaultKeys.set(grant.vaultId, vk);
  }

  /** Role from the latest grant for this vault, or null if none seen. */
  roleFor(vaultId: string): string | null {
    return this.vaultRoles.get(vaultId) ?? null;
  }

  /** Membership revoked (sync `removedGrants`): forget the VK and the role. */
  removeVault(vaultId: string) {
    this.vaultKeys.delete(vaultId);
    this.vaultRoles.delete(vaultId);
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

  /** The store calls this when it sees the personal vault among synced vaults. */
  setPersonalVault(vaultId: string) {
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
    const mk = masterKey(newPassword, newKdfSalt, params);
    const newAuthKey = await deriveAuthKey(mk);
    const newWrapKey = await deriveWrapKey(mk);
    const newWrappedUvk = seal(newWrapKey, this.uvk, adUvk(this.userId));
    return {
      newKdfSalt: toB64(newKdfSalt),
      newKdfParams: params,
      newAuthKey: toB64(newAuthKey),
      newWrappedUvk: toB64(newWrappedUvk),
    };
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
    const metaV = typeof meta.metaV === "number" ? meta.metaV : 0;
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
}

export function deviceName(): string {
  if (typeof navigator !== "undefined" && navigator.userAgent) {
    const ua = navigator.userAgent;
    const m = ua.match(/(Chrome|Firefox|Safari|Edg)\/[\d.]+/);
    return `web ${m ? m[0] : "browser"}`;
  }
  return "web";
}
