/** Wire DTOs — mirror core/model/Wire.kt (the server's JSON contract). */

export interface KdfParams {
  v: number;
  alg: string;
  ops: number;
  memBytes: number;
}

export interface PreloginResponse {
  kdfSalt: string;
  kdfParams: KdfParams;
}

export interface AccountKeys {
  kdfSalt: string;
  kdfParams: KdfParams;
  wrappedUvk: string;
  encryptedIdentitySeed: string;
  identityPub: string;
  escrowFingerprint: string;
}

export interface SessionResponse {
  userId: string;
  deviceId: string;
  accessToken: string;
  refreshToken: string;
  accountKeys: AccountKeys;
  isAdmin: boolean;
  mustChangePassword: boolean;
}

export interface WireVault {
  vaultId: string;
  type: string;
  rev: number;
  metaBlob: string;
  createdAt: number;
}

export interface WireGrant {
  vaultId: string;
  userId: string;
  role: string;
  wrappedVk: string;
  rev: number;
}

export interface WireItem {
  itemId: string;
  vaultId: string;
  rev: number;
  createdAt: number;
  updatedAt: number;
  deleted: boolean;
  conflict: boolean;
  formatVersion: number;
  attachmentIds: string[];
  blob: string | null;
}

export interface SyncResponse {
  rev: number;
  full: boolean;
  vaults: WireVault[];
  grants: WireGrant[];
  items: WireItem[];
  removedGrants: string[];
}

export interface ItemUpload {
  formatVersion: number;
  attachmentIds: string[];
  blob: string;
}

export interface Mutation {
  mutationId: string;
  op: "put" | "delete";
  itemId: string;
  vaultId: string;
  baseItemRev: number;
  item?: ItemUpload;
}

export interface MutationResult {
  mutationId: string;
  status: "applied" | "conflict" | "duplicate" | "denied";
  newItemRev?: number;
  serverItem?: WireItem;
}

export interface PushResponse {
  rev: number;
  results: MutationResult[];
}

export interface ClientPolicy {
  minVersion: Record<string, string>;
  kdfParams: KdfParams;
  autoLockSeconds: number;
  clipboardClearSeconds: number;
  offlineCacheAllowed: boolean;
  sessionAccessTtlSeconds: number;
  sessionRefreshTtlDays: number;
  recoveryFingerprint: string;
  serverTime: number;
}

export interface EscrowUpload {
  sealed: string;
  fingerprint: string;
}

export interface RegisterRequest {
  inviteToken: string;
  userId: string;
  email: string;
  displayName: string;
  kdfSalt: string;
  kdfParams: KdfParams;
  authKey: string;
  wrappedUvk: string;
  identityPub: string;
  encryptedIdentitySeed: string;
  escrow: EscrowUpload;
  personalVault: { vaultId: string; wrappedVk: string; metaBlob: string };
  device: { platform: string; name: string };
}

/** The plaintext item document (spec 02 §3). */
export interface ItemDoc {
  type: "login" | "note";
  name: string;
  notes?: string;
  favorite?: boolean;
  login?: {
    username?: string;
    password?: string;
    uris?: string[];
    totp?: string;
    passwordHistory?: { password: string; retiredAt: number }[];
  };
  attachments?: { id: string; name: string; size: number; fileKey: string }[];
}
