import { adIdkey, adItem, adUvk, adVaultMeta, adVk } from "../crypto/ad";
import { fromB64, fromUtf8, toB64, utf8 } from "../crypto/bytes";
import { open, seal } from "../crypto/envelope";
import { fingerprint as recoveryFingerprint, sealUvk } from "../crypto/escrow";
import { authKey as deriveAuthKey, masterKey, wrapKey as deriveWrapKey, type KdfParams } from "../crypto/keys";
import { boxKeypairFromSeed, randomBytes } from "../crypto/provider";
import { CryptoError } from "../crypto/sodium";
import type { AccountKeys, ItemDoc, RegisterRequest, WireGrant, WireItem } from "../api/types";

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

  /** Add a vault key from its grant (personal-vault VK wrapped under UVK). */
  addPersonalGrant(grant: WireGrant) {
    const vk = open(this.uvk, fromB64(grant.wrappedVk), adVk(grant.vaultId, this.userId));
    this.vaultKeys.set(grant.vaultId, vk);
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
