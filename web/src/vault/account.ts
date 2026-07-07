import { adIdkey, adItem, adUvk, adVaultMeta, adVk } from "../crypto/ad";
import { fromB64, fromUtf8, toB64, utf8 } from "../crypto/bytes";
import { open, seal } from "../crypto/envelope";
import { fingerprint as recoveryFingerprint, sealUvk } from "../crypto/escrow";
import { authKey as deriveAuthKey, masterKey, wrapKey as deriveWrapKey, type KdfParams } from "../crypto/keys";
import { boxKeypairFromSeed, randomBytes } from "../crypto/provider";
import { openSharedGrant, sealSharedGrant, shortIdentityFingerprint } from "../crypto/sharedgrant";
import { CryptoError } from "../crypto/sodium";
import type { AccountKeys, CreateVaultRequest, ItemDoc, RegisterRequest, WireGrant, WireItem } from "../api/types";

const ITEM_FORMAT_VERSION = 1;

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
      device: { platform: "web", name: deviceName() },
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

  encryptItem(vaultId: string, itemId: string, doc: ItemDoc): string {
    const blob = seal(this.vk(vaultId), utf8(JSON.stringify(doc)), adItem(vaultId, itemId, ITEM_FORMAT_VERSION));
    return toB64(blob);
  }

  decryptItem(item: WireItem): ItemDoc {
    if (!item.blob) throw new CryptoError("item has no blob (tombstone?)");
    const plain = open(this.vk(item.vaultId), fromB64(item.blob), adItem(item.vaultId, item.itemId, item.formatVersion));
    return JSON.parse(fromUtf8(plain)) as ItemDoc;
  }

  decryptVaultName(vaultId: string, metaBlob: string): string {
    try {
      const plain = open(this.vk(vaultId), fromB64(metaBlob), adVaultMeta(vaultId));
      return (JSON.parse(fromUtf8(plain)) as { name: string }).name;
    } catch {
      return "(vault)";
    }
  }

  newItemId(): string {
    return uuidv4();
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
