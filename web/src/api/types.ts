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

/** Single-use WS auth ticket (spec 03 §6): minted over authenticated REST, ~30 s TTL. */
export interface WsTicketResponse {
  ticket: string;
  expiresInSeconds: number;
}

export interface AccountKeys {
  kdfSalt: string;
  kdfParams: KdfParams;
  wrappedUvk: string;
  encryptedIdentitySeed: string;
  identityPub: string;
  escrowFingerprint: string;
  // F57: true when this account's escrow is sealed to a PRIOR org recovery key (re-ceremony)
  // and must be re-sealed to the current one. `escrowFingerprint` is the CURRENT org fingerprint
  // (the re-seal target + pubkey-verification anchor). Optional for back-compat with old servers.
  escrowStale?: boolean;
}

export interface SessionResponse {
  userId: string;
  deviceId: string;
  accessToken: string;
  refreshToken: string;
  accountKeys: AccountKeys;
  isAdmin: boolean;
  mustChangePassword: boolean;
  totpEnrolled: boolean;
}

export interface WireVault {
  vaultId: string;
  type: string;
  rev: number;
  metaBlob: string;
  createdAt: number;
  // ---- vault lifecycle (spec 03 §11) — all additive; old clients ignore unknown keys ----
  /** A pending ownership-transfer offer riding the vault row (re-delivered to every member). */
  pendingTransfer?: PendingTransfer | null;
  /** The last completed transfer — every member verifies its seq-chained acceptProof. */
  lastTransfer?: TransferRecord | null;
  /** On a live vault that WAS restored: the restoreProof over the consumed deleteId. A
   *  client re-receiving the restored vault verifies restore(VK, vaultId, deleteId) and
   *  durably marks the deleteId consumed, so a replayed old tombstone bearing it is stale. */
  restoreProof?: string | null;
  deleteId?: string | null;
}

/** A pending ownership-transfer offer (spec 03 §11). `proof` is the VK-derived offer MAC —
 *  the target's 0.5.0 client verifies it BEFORE rendering consent; the server only relays it. */
export interface PendingTransfer {
  toUserId: string;
  offerId: string;
  proof: string;
  expiresAt: number;
  seq: number;
}

/** The last completed transfer (spec 03 §11). Members verify `acceptProof` under their held
 *  VK using `wrapHash` (= hexLower(sha256(utf8(new owner's wrappedVk))), which they never
 *  receive) — a server-side role rewrite or wrap swap is then detectable. */
export interface TransferRecord {
  offerId: string;
  newOwnerUserId: string;
  acceptProof: string;
  seq: number;
  wrapHash?: string | null;
}

/** Why the caller lost a grant (spec 03 §11). `reason` derives from the caller's OWN grant's
 *  revokedReason. Tombstone fields ride only 'deleted'; removeProof/removeNonce only
 *  'removed'/'left' when the removing owner supplied a removal proof. */
export interface RemovedGrantInfo {
  vaultId: string;
  reason: "removed" | "left" | "deleted" | "transferred";
  deletedAt?: number | null;
  purgeAt?: number | null;
  deleteId?: string | null;
  deleteProof?: string | null;
  removeProof?: string | null;
  removeNonce?: string | null;
}

export interface WireGrant {
  vaultId: string;
  userId: string;
  role: string;
  wrappedVk: string;
  rev: number;
  /** Member grants (spec 01 §6): crypto_box_seal to the member identityPub; owner/personal use wrappedVk. */
  sealedVk?: string | null;
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

/** One archived ciphertext version of an item (item history feature; server keeps the last 10). */
export interface ItemVersion {
  rev: number;
  blob: string;
  formatVersion: number;
  archivedAt: number;
}

export interface ItemVersionsResponse {
  itemId: string;
  versions: ItemVersion[];
}

export interface SyncResponse {
  rev: number;
  full: boolean;
  vaults: WireVault[];
  grants: WireGrant[];
  items: WireItem[];
  removedGrants: string[];
  /** Additive companion detail for removedGrants (spec 03 §4/§11) — never the purge trigger
   *  itself; drives the 0.5.0 proof-verified notice / holding-area flow. */
  removedGrantsInfo?: RemovedGrantInfo[];
}

// ---- shared vaults (spec 03 §10) ----

export interface CreateVaultRequest {
  vaultId: string;
  metaBlob: string;
  wrappedVk: string;
}

export interface CreateVaultResponse {
  rev: number;
}

export interface UserLookupResponse {
  userId: string;
  displayName: string;
  identityPub: string;
}

export interface VaultMemberAdd {
  userId: string;
  role: string;
  sealedVk: string;
}

export interface VaultMemberSummary {
  userId: string;
  email: string;
  displayName: string;
  role: string;
  identityPub: string;
  addedAt: number;
  /** F22 rider (spec 03 §10): account status ('active'|'disabled') — additive; feeds the
   *  transfer target picker and the disabled-member badge. */
  status?: string | null;
}

// ---- vault lifecycle (spec 03 §11) ----

export interface VaultDeleteRequest {
  deleteId: string;
  proof: string;
}

export interface VaultDeleteResponse {
  rev: number;
  purgeAt: number;
}

export interface VaultRestoreRequest {
  deleteId: string;
  proof: string;
}

/** One in-grace deleted vault of the caller's (owner-only; ciphertext they already owned). */
export interface DeletedVaultSummary {
  vaultId: string;
  metaBlob: string;
  wrappedVk: string;
  deletedAt: number;
  purgeAt: number;
  deleteId: string;
}

export interface TransferOfferRequest {
  toUserId: string;
  offerId: string;
  expiresAt: number;
  proof: string;
}

export interface TransferOfferResponse {
  rev: number;
  expiresAt: number;
}

export interface TransferAcceptRequest {
  offerId: string;
  wrappedVk: string;
  proof: string;
}

export interface VaultMetaUpdateRequest {
  metaBlob: string;
  baseVaultRev?: number;
}

/** Optional removal-proof body for the existing member-remove route (spec 03 §10/§11). */
export interface VaultMemberRemoveRequest {
  proof?: string;
  nonce?: string;
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
  /** Attachment quotas (spec 02 §6) — plaintext byte limits. */
  attachmentMaxBytes: number;
  itemAttachmentsMaxBytes: number;
  userAttachmentsMaxBytes: number;
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
  /** installId (F28) is web-additive: a stable per-browser id the server currently
   *  ignores (DeviceInfo has only platform+name; its Json is ignoreUnknownKeys) —
   *  the intended upsert key once the server stops inserting a device row per login. */
  device: { platform: string; name: string; installId?: string };
}

// ---- attachments (spec 02 §6) ----

/** Server bookkeeping for one encrypted blob; filename + fileKey live inside item ciphertext. */
export interface AttachmentMeta {
  attachmentId: string;
  itemId: string;
  vaultId: string;
  size: number;
  sha256: string;
  createdAt: number;
}

// ---- server TOTP (spec 03 §2, break-glass hardening) ----

export interface TotpStatus {
  enrolled: boolean;
  pendingSetup: boolean;
}

export interface TotpSetupResponse {
  secretBase32: string;
  otpauthUri: string;
}

// ---- password change ----

export interface PasswordChangeRequest {
  currentAuthKey: string;
  newAuthKey: string;
  newKdfSalt: string;
  newKdfParams: KdfParams;
  newWrappedUvk: string;
}

// ---- admin ----

export interface AdminUserSummary {
  userId: string;
  email: string;
  displayName: string;
  isAdmin: boolean;
  status: string;
  createdAt: number;
  deviceCount: number;
  escrowFingerprint: string | null;
}

export interface InviteResponse {
  inviteToken: string;
  email: string;
  expiresAt: number;
}

export interface AdminDeviceSummary {
  deviceId: string;
  platform: string;
  name: string;
  clientVersion: string | null;
  createdAt: number;
  lastSeenAt: number | null;
  revokedAt: number | null;
}

export interface AdminStatus {
  serverVersion: string;
  serverTime: number;
  escrowConfigured: boolean;
  recoveryFingerprint: string;
  breakGlassConfigured: boolean;
  lastPublicRequestAt: number | null;
  userCount: number;
  itemCount: number;
  attachmentCount: number;
  attachmentBytes: number;
  dbBytes: number;
  totpEnrolledCount: number;
  downloadsManifest: boolean;
}

export interface AuditEvent {
  id: number;
  at: number;
  type: string;
  userId: string | null;
  deviceId: string | null;
  ip: string | null;
  meta: string | null;
}

/** An attachment reference inside the item plaintext (name + fileKey never leave the client unencrypted). */
export interface AttachmentRef {
  id: string;
  name: string;
  size: number;
  fileKey: string;
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
  attachments?: AttachmentRef[];
}
