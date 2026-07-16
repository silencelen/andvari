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
  /** design §F.2: true when this existing account has NO member_recovery row yet (migration nudge).
   *  On the next full-password unlock the client offers "set up your recovery phrase"
   *  (PUT /recovery/self-setup). Additive/defaulted — old servers omit it (⇒ treated as false). */
  recoverySetupNeeded?: boolean;
  /** design §F.9: the durable, cross-device signal that this account's recovery piece was actually
   *  CAPTURED (the user saw + confirmed the phrase), not merely registered. Register sets it false;
   *  POST /recovery/self/confirm and PUT /recovery/self-setup set it true. The web vault-entry gate
   *  BLOCKS on `!== true` and forces setup-and-reveal — so an interrupted reveal (silent-total-loss
   *  for a waived account) is caught on the next unlock, on ANY device. Additive/defaulted: an old
   *  server omits it ⇒ treated as unconfirmed ⇒ the gate re-nudges (harmless; escrow backstop intact). */
  recoveryConfirmed?: boolean;
}

/**
 * design §F.2 — the per-member self-service recovery block sent at register / self-setup. The server
 * stores `recoveryVerifier = crypto_pwhash_str(recoveryAuthKey)` + `recoveryWrappedUvk`; it NEVER
 * persists `recoveryAuthKey` raw (identical to how `authKey → verifier` works). MANDATORY on every
 * NEW registration (§F.4). Both fields base64url.
 */
export interface MemberRecoveryBlock {
  recoveryWrappedUvk: string;
  recoveryAuthKey: string;
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
  /** Piece-binding (design 2026-07-13): opaque id of the recovery piece THIS register committed,
   *  presented by the enroll path's `POST /recovery/self/confirm` so the confirm attests the current
   *  piece. Populated ONLY by register; login/refresh leave it undefined. Additive/optional. */
  recoveryPieceId?: string | null;
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

/** Item undelete: a tombstoned item the user can restore (its name lives in the last version). */
export interface DeletedItem {
  itemId: string;
  vaultId: string;
  deletedAt: number;
}

export interface DeletedItemsResponse {
  items: DeletedItem[];
}

export interface ItemRestoreResponse {
  rev: number;
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
  /** THE durable-cache wire field (design 2026-07-15 §2.1, binding — the owner-decision term
   *  "durableCacheAllowed" IS this field; no parallel field exists). Tighten-only: false ⇒
   *  prohibition + wipe of this origin's own cache; true is necessary but never sufficient. */
  offlineCacheAllowed: boolean;
  sessionAccessTtlSeconds: number;
  sessionRefreshTtlDays: number;
  recoveryFingerprint: string;
  serverTime: number;
  /** Attachment quotas (spec 02 §6) — plaintext byte limits. */
  attachmentMaxBytes: number;
  itemAttachmentsMaxBytes: number;
  userAttachmentsMaxBytes: number;
  // ---- multi-tenant / endpoint-agnostic pivot (design 2026-07-15 §2.1/§2.2) ----
  // Additive/optional — old servers omit them; mirrors core Wire.kt ClientPolicy +
  // extension/src/api.ts ClientPolicyResponse, byte-consistent.
  /** §2.1 enum: "closed" | "invite-only" | "landing" | "open". Absent (old server) OR unknown value
   *  (newer server) ⇒ treat as "invite-only": plain invite-gated enroll, never open-register UI,
   *  no stranger nudge. Register success stays server-enforced (invite-ROW gate) either way. */
  signupMode?: string;
  /** §2.6 — per-instance login-factor stance. A UI pre-prompt HINT only; the reactive server errors
   *  (totp_required / public_login_requires_totp) stay authoritative. Never gates a client-side
   *  protection (§2.3 trust table). Absent ⇒ false. */
  totpRequired?: boolean;
  /** Decorative label — NEVER rendered as a verified identity, never in the trust gate (§2.3). */
  instanceName?: string | null;
  /** Server-claimed own origin — proxy-misconfig diagnostic only; never a trust anchor (§2.3). */
  canonicalOrigin?: string | null;
  /** Rendered as a raw https URL only (§2.3 R8 rule) — never as trusted branding. */
  selfHostDocsUrl?: string | null;
}

/** Client-side ceilings for the server-declared policy timers (design 2026-07-15 §2.3, breaker B1-1).
 *  Byte-pinned mirror of core `ClientPolicyClamps` (Kotlin) — locked three-way (core/web/ext) by
 *  `web/src/policy-clamps.test.ts`; bump all three together. The fields are CLIENT-FLOOR-ONLY: a
 *  hostile server may make the client safer, never laxer — a 0/absent/oversized `autoLockSeconds`
 *  clamps to the ceiling, so a server cannot disable auto-lock or pin the clipboard for hours.
 *  Wave 1 defines the constants only; call-site clamping (useAutoLock.ts etc.) is wave-2 work. */
export const AUTO_LOCK_MAX_SECONDS = 900;
export const CLIPBOARD_CLEAR_MAX_SECONDS = 300;

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
  /** design §F.2/§F.4: escrow becomes OPTIONAL — present iff the invite's escrowPolicy == "required"
   *  (org backstop). FORBIDDEN when waived (server rejects `escrow_not_allowed_when_waived`). */
  escrow?: EscrowUpload;
  /** design §F.4: MANDATORY for every NEW registration — the self-service recovery piece, so an
   *  account can never be created with neither recovery path. */
  memberRecovery: MemberRecoveryBlock;
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

// ---- per-member self-service recovery (design §F.3) ----

/** `POST /recovery/self/verify` request. The recovery secret is high-entropy and derivation is
 *  HKDF-only (no server salt/params), so there is nothing to prelogin-fetch first. Anti-enumeration:
 *  unknown email OR a known email with no member_recovery row runs a fixed DUMMY_RECOVERY_VERIFIER
 *  and returns a uniform 401 (§F.5). */
export interface RecoveryVerifyRequest {
  email: string;
  recoveryAuthKey: string;
}

/** `POST /recovery/self/verify` success response. `recoveryTicket` is single-use, short-TTL,
 *  userId-bound. `userId` is REQUIRED to compute Ad.recovery(userId) (open recoveryWrappedUvk) and
 *  Ad.idkey(userId) (the identity-pubkey hard-fail). `encryptedIdentitySeed` + `identityPub` feed
 *  that hard-fail so a substituted identity key is caught BEFORE commit. */
export interface RecoveryVerifyResponse {
  userId: string;
  recoveryTicket: string;
  recoveryWrappedUvk: string;
  encryptedIdentitySeed: string;
  identityPub: string;
}

/** `POST /recovery/self/commit` request. The ticket is validated (live, unconsumed, then consumed).
 *  The reset overwrites verifier/wrappedUvk/kdf and revokes sessions but — unlike admin recovery —
 *  does NOT set status='active' or mustChangePassword (the user just chose the new password). The UVK
 *  is invariant (recover re-wraps the SAME UVK), so the org-escrow + member-recovery blobs stay valid. */
export interface RecoveryCommitRequest {
  recoveryTicket: string;
  newAuthKey: string;
  newKdfSalt: string;
  newKdfParams: KdfParams;
  newWrappedUvk: string;
}

/** `PUT /recovery/self-setup` request (authenticated migration/rotation path). The server requires a
 *  FRESH master-password reauth — it verifies `currentAuthKey` against the login verifier exactly
 *  like changePassword — before storing `memberRecovery`. */
export interface RecoverySelfSetupRequest {
  currentAuthKey: string;
  memberRecovery: MemberRecoveryBlock;
}

/** `PUT /recovery/self-setup` success response (design 2026-07-13 piece-binding). Carries the fresh,
 *  server-minted opaque `pieceId` of the piece this setup committed; the capture gate threads it into
 *  the subsequent `POST /recovery/self/confirm`. A pre-binding server answered `"ok"` (non-JSON) →
 *  `client.recoverySelfSetup` yields `{ pieceId: null }` (legacy, unbound confirm). */
export interface RecoverySelfSetupResponse {
  pieceId?: string | null;
}

/** `POST /recovery/self/confirm` request body (design 2026-07-13 piece-binding). Optional: sending the
 *  revealed `pieceId` binds the confirm to the current piece; a mismatch is refused
 *  `409 recovery_piece_stale`. An empty body is the legacy (device-scoped) path. No key material. */
export interface RecoverySelfConfirmRequest {
  pieceId?: string | null;
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
  /** design §F.9 posture reconciliation (additive; optional): whether this member has a member_recovery
   *  row (a self-service recovery piece). Lets the Admin UI distinguish "waived (intended)" (no escrow
   *  but a member piece) from "no recovery / needs setup" (neither) when `escrowFingerprint == null`.
   *  Old servers omit it. */
  recoveryEnrolled?: boolean;
  /** design §F.4 (2026-07-13): the invite's escrow posture persisted onto the user at register
   *  ("required" | "waived"). Paired with `recoveryEnrolled`, it distinguishes an intended waiver from
   *  a required-member whose escrow blob is missing (hostile flip / escrow deletion). Undefined for
   *  pre-v8 users (shown as legacy). Additive/optional. */
  escrowPolicy?: string | null;
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
  emailConfigured: boolean;
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

/** Card fields (spec 02 §3, formatVersion 2) — all ciphertext inside the item envelope;
 *  the server sees only the plaintext formatVersion integer. Canonical stored forms
 *  (adapters derive display/fill variants): number digits-only, expMonth "01".."12",
 *  expYear 4-digit, securityCode 3-4 digits (storing it is an explicit per-card choice),
 *  brand visa|mastercard|amex|discover derived from the IIN at every save — display-only,
 *  never authored, so it can't go stale. Mirrors core CardData. */
export interface CardData {
  cardholderName?: string;
  number?: string;
  expMonth?: string;
  expYear?: string;
  securityCode?: string;
  brand?: string;
}

/** The plaintext item document (spec 02 §3). `type` is chosen at creation, never changes. */
export interface ItemDoc {
  type: "login" | "note" | "card";
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
  card?: CardData;
  attachments?: AttachmentRef[];
}
