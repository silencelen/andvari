import type { KdfParams } from "../crypto/keys";
import { type Json, type JsonObject, Reader } from "./decode";
import type { AttachmentMeta, DeletedItemsResponse, ItemVersionsResponse, MutationResult, PushResponse } from "./types";
import { UUID_RE } from "./wireids";

/**
 * The web client's view of the wire protocol after the cut-over (spec 03, design 2026-11-15). Request
 * bodies are typed exactly as spec 03 §0.2 writes them; every response the web reads has a decoder
 * here that checks each known field's type and ignores unknown ones (§0.1).
 *
 * Only the routes the web may call are here (design §13): no link, device-link, operator or
 * assisted-recovery request route has a type, a decoder or a caller in this bundle.
 */

// ---------------------------------------------------------------------------------------------------
// Shared

export type Platform = "android" | "ios" | "windows" | "macos" | "linux" | "web" | "cli" | "extension";

/** A log head as the log routes serve it (spec 03 §0.1 `head`). */
export interface LogHead {
  seq: number;
  hash: string;
  at: number;
}

/** A log head as `/sync` serves it on a vault row (spec 03 §4). */
export interface SyncLogHead {
  seq: number;
  hash: string;
}

/** The device object of every device-creating request (spec 03 §0.3, design §8.7). */
export interface NewDevice {
  platform: Platform;
  name: string;
  deviceSecret: string;
}

/** Login's device object: a device that already holds a row on this account also sends its id (S3-Q2). */
export interface LoginDevice extends NewDevice {
  deviceId?: string;
}

export interface MemberRecoveryBlock {
  recoveryWrappedUvk: string;
  recoveryAuthKey: string;
}

export interface EscrowUpload {
  sealed: string;
  fingerprint: string;
}

export interface AccountStatePut {
  sealedState: string;
  baseSeq: number;
}

/**
 * `kdfParams` (spec 01 §2: `{v, alg, ops, memBytes}`). Every listed field is present on the wire (spec 03 §0.1
 * "Field presence"): an absent field is refused, never read as a default, since a client that guessed a default
 * the server did not mean would derive the wrong master key. The client's own fence (`assertServerKdfParams`)
 * still applies before anything is derived.
 */
function kdf(r: Reader, v: unknown, field: string): KdfParams {
  const o = r.obj(v, field);
  return {
    v: r.int(o.v, `${field}.v`),
    alg: r.str(o.alg, `${field}.alg`),
    ops: r.int(o.ops, `${field}.ops`),
    memBytes: r.int(o.memBytes, `${field}.memBytes`),
  };
}

function logHead(r: Reader, v: unknown, field: string): LogHead {
  const o = r.obj(v, field);
  return { seq: r.int(o.seq, `${field}.seq`), hash: r.hex64(o.hash, `${field}.hash`), at: r.int(o.at, `${field}.at`) };
}

// ---------------------------------------------------------------------------------------------------
// Instance and policy (rows 1, 2)

export type SignupMode = "open" | "links" | "closed";

export interface SignupPolicy {
  mode: SignupMode;
  full: boolean;
  ageConfirmRequired: boolean;
  powBits: number;
}

export interface ClientPolicyV2 {
  minVersion: Record<string, string>;
  kdfParams: KdfParams;
  autoLockSeconds: number;
  clipboardClearSeconds: number;
  offlineCacheAllowed: boolean;
  sessionAccessTtlSeconds: number;
  sessionRefreshTtlDays: number;
  attachmentMaxBytes: number;
  itemAttachmentsMaxBytes: number;
  serverTime: number;
  signup: SignupPolicy;
  totpRequired: boolean;
  /** DECORATIVE (spec 03 §1.1): never rendered as a verified identity. The signed name is the card's. */
  instanceName: string | null;
  canonicalOrigin: string | null;
  selfHostDocsUrl: string | null;
}

export function decodeClientPolicy(body: Json): ClientPolicyV2 {
  const r = new Reader("client-policy");
  const o = r.obj(body, "body");
  const mv = r.obj(o.minVersion, "minVersion");
  const minVersion: Record<string, string> = {};
  for (const [k, v] of Object.entries(mv)) minVersion[k] = r.str(v, `minVersion.${k}`);
  const s = r.obj(o.signup, "signup");
  return {
    minVersion,
    kdfParams: kdf(r, o.kdfParams, "kdfParams"),
    autoLockSeconds: r.int(o.autoLockSeconds, "autoLockSeconds"),
    clipboardClearSeconds: r.int(o.clipboardClearSeconds, "clipboardClearSeconds"),
    offlineCacheAllowed: r.bool(o.offlineCacheAllowed, "offlineCacheAllowed"),
    sessionAccessTtlSeconds: r.int(o.sessionAccessTtlSeconds, "sessionAccessTtlSeconds"),
    sessionRefreshTtlDays: r.int(o.sessionRefreshTtlDays, "sessionRefreshTtlDays"),
    attachmentMaxBytes: r.int(o.attachmentMaxBytes, "attachmentMaxBytes"),
    itemAttachmentsMaxBytes: r.int(o.itemAttachmentsMaxBytes, "itemAttachmentsMaxBytes"),
    serverTime: r.int(o.serverTime, "serverTime"),
    signup: {
      mode: r.oneOf(s.mode, "signup.mode", ["open", "links", "closed"] as const),
      full: r.bool(s.full, "signup.full"),
      ageConfirmRequired: r.bool(s.ageConfirmRequired, "signup.ageConfirmRequired"),
      powBits: r.int(s.powBits, "signup.powBits"),
    },
    totpRequired: r.bool(o.totpRequired, "totpRequired"),
    instanceName: r.optStr(o.instanceName, "instanceName"),
    canonicalOrigin: r.optStr(o.canonicalOrigin, "canonicalOrigin"),
    selfHostDocsUrl: r.optStr(o.selfHostDocsUrl, "selfHostDocsUrl"),
  };
}

/** `GET /instance` (spec 03 §17.1). The `setup` block is for an operator resuming setup; the web never reads it. */
export interface InstanceResponse {
  cards: string[];
  rotations: string[];
}

export function decodeInstance(body: Json): InstanceResponse {
  const r = new Reader("instance");
  const o = r.obj(body, "body");
  const cards = r.arr(o.cards, "cards").map((c, i) => r.b64(c, `cards[${i}]`, 2048));
  const rotations = o.rotations === undefined || o.rotations === null ? [] : r.arr(o.rotations, "rotations").map((c, i) => r.b64(c, `rotations[${i}]`, 2048));
  return { cards, rotations };
}

// ---------------------------------------------------------------------------------------------------
// Sign-up and registration (rows 6–8)

export interface SignupStartRequest {
  email: string;
  ageConfirmed: boolean;
  pow?: { date: string; nonce: number };
}

export interface SignupVerifyRequest {
  email: string;
  code: string;
}

export interface SignupVerifyResponse {
  signupTicket: string;
  expiresAt: number;
}

export function decodeSignupVerify(body: Json): SignupVerifyResponse {
  const r = new Reader("signup/verify");
  const o = r.obj(body, "body");
  return { signupTicket: r.b64(o.signupTicket, "signupTicket", 64), expiresAt: r.ms(o.expiresAt, "expiresAt") };
}

/**
 * `POST /auth/register` as the web sends it (spec 03 §14.3). The web registers only with a sign-up
 * ticket: the link, enrol and setup forms of `auth` are link flows, which the web has no code for (§13).
 */
export interface RegisterRequestV2 {
  auth: { signupTicket: string };
  email: string;
  displayName: string;
  userId: string;
  kdfSalt: string;
  kdfParams: KdfParams;
  authKey: string;
  wrappedUvk: string;
  identityPub: string;
  encryptedIdentitySeed: string;
  genesis: string;
  personalVault: { vaultId: string; wrappedVk: string; metaBlob: string };
  personalWrap: { vaultId: string; wrappedVk: string };
  memberRecovery: MemberRecoveryBlock;
  recovery: { posture: "private" } | { posture: "operator"; escrow: EscrowUpload };
  ageConfirmed: boolean;
  device: NewDevice;
}

// ---------------------------------------------------------------------------------------------------
// Sessions (rows 9–16)

export interface PreloginResponseV2 {
  kdfSalt: string;
  kdfParams: KdfParams;
}

export function decodePrelogin(body: Json): PreloginResponseV2 {
  const r = new Reader("prelogin");
  const o = r.obj(body, "body");
  return { kdfSalt: r.b64(o.kdfSalt, "kdfSalt", 64), kdfParams: kdf(r, o.kdfParams, "kdfParams") };
}

export interface LoginRequestV2 {
  email: string;
  authKey: string;
  device: LoginDevice;
  totp?: string;
}

/** `AccountKeys` (spec 03 §3). `personalWrap` and `genesis` are decoded as present-or-null: their absence is the identity fault at unlock (§3), never a decode error. */
export interface AccountKeysV2 {
  kdfSalt: string;
  kdfParams: KdfParams;
  wrappedUvk: string;
  encryptedIdentitySeed: string;
  identityPub: string;
  recoveryConfirmed: boolean;
  personalWrap: { vaultId: string; wrappedVk: string } | null;
  genesis: string | null;
}

function accountKeys(r: Reader, v: unknown, field: string): AccountKeysV2 {
  const o = r.obj(v, field);
  let personalWrap: AccountKeysV2["personalWrap"] = null;
  if (o.personalWrap !== undefined && o.personalWrap !== null) {
    const w = r.obj(o.personalWrap, `${field}.personalWrap`);
    personalWrap = { vaultId: r.uuid(w.vaultId, `${field}.personalWrap.vaultId`), wrappedVk: r.b64(w.wrappedVk, `${field}.personalWrap.wrappedVk`, 1024) };
  }
  return {
    kdfSalt: r.b64(o.kdfSalt, `${field}.kdfSalt`, 64),
    kdfParams: kdf(r, o.kdfParams, `${field}.kdfParams`),
    wrappedUvk: r.b64(o.wrappedUvk, `${field}.wrappedUvk`, 1024),
    encryptedIdentitySeed: r.b64(o.encryptedIdentitySeed, `${field}.encryptedIdentitySeed`, 1024),
    identityPub: r.b64_32(o.identityPub, `${field}.identityPub`),
    recoveryConfirmed: r.bool(o.recoveryConfirmed, `${field}.recoveryConfirmed`),
    personalWrap,
    genesis: o.genesis === undefined || o.genesis === null ? null : r.b64(o.genesis, `${field}.genesis`, 2048),
  };
}

export function decodeAccountKeys(body: Json): AccountKeysV2 {
  return accountKeys(new Reader("account/keys"), body, "body");
}

export type AccountRole = "operator" | "member";

export interface SessionResponseV2 {
  userId: string;
  deviceId: string;
  accessToken: string;
  refreshToken: string;
  accountKeys: AccountKeysV2;
  role: AccountRole;
  totpEnrolled: boolean;
  mustEnrollTotp: boolean;
  recoveryPieceId: string | null;
}

export function decodeSession(endpoint: string, body: Json): SessionResponseV2 {
  const r = new Reader(endpoint);
  const o = r.obj(body, "body");
  return {
    userId: r.userId(o.userId, "userId"),
    deviceId: r.uuid(o.deviceId, "deviceId"),
    accessToken: r.b64(o.accessToken, "accessToken", 128),
    refreshToken: r.b64(o.refreshToken, "refreshToken", 128),
    accountKeys: accountKeys(r, o.accountKeys, "accountKeys"),
    role: r.oneOf(o.role, "role", ["operator", "member"] as const),
    totpEnrolled: r.bool(o.totpEnrolled, "totpEnrolled"),
    mustEnrollTotp: r.bool(o.mustEnrollTotp, "mustEnrollTotp"),
    recoveryPieceId: r.optStr(o.recoveryPieceId, "recoveryPieceId"),
  };
}

// ---------------------------------------------------------------------------------------------------
// Account (rows 17–31)

export interface AccountStateResponseV2 {
  sealedState: string | null;
  seq: number;
}

/** `ACCOUNT_STATE_SEALED_MAX` (spec 03 §3): 1 MiB of base64. */
export const ACCOUNT_STATE_SEALED_MAX = 1_048_576;

export function decodeAccountState(endpoint: string, body: Json): AccountStateResponseV2 {
  const r = new Reader(endpoint);
  const o = r.obj(body, "body");
  return {
    sealedState: o.sealedState === null || o.sealedState === undefined ? null : r.b64(o.sealedState, "sealedState", ACCOUNT_STATE_SEALED_MAX),
    seq: r.int(o.seq, "seq"),
  };
}

export interface PasswordChangeRequestV2 {
  currentAuthKey: string;
  newAuthKey: string;
  newKdfSalt: string;
  newKdfParams: KdfParams;
  newWrappedUvk: string;
}

export interface AccountRecoveryPut {
  posture: "private" | "operator";
  escrow?: EscrowUpload;
  currentAuthKey: string;
  accountState: AccountStatePut;
}

export interface EscrowSelfPut {
  sealed: string;
  fingerprint: string;
  rotations: string[];
}

export type DeviceHow = "registered" | "password" | "linked" | "recovered";

/** A row of `GET /account/devices` (spec 03 §16.7). */
export interface DeviceRow {
  deviceId: string;
  platform: string;
  name: string;
  clientVersion: string | null;
  createdAt: number;
  lastSeenAt: number | null;
  live: boolean;
  how: DeviceHow;
  linkedFrom: string | null;
  current: boolean;
}

export function decodeDevices(body: Json): { rows: DeviceRow[]; refused: Reader["refused"] } {
  const r = new Reader("account/devices");
  const rows = r.rows(body, "devices", ["deviceId", "linkedFrom"], (o, i) => ({
    deviceId: o.deviceId as string,
    // Self-reported by the other device: shown as text only.
    platform: r.str(o.platform, `devices[${i}].platform`),
    name: r.str(o.name, `devices[${i}].name`),
    clientVersion: r.optStr(o.clientVersion, `devices[${i}].clientVersion`),
    createdAt: r.int(o.createdAt, `devices[${i}].createdAt`),
    lastSeenAt: r.optInt(o.lastSeenAt, `devices[${i}].lastSeenAt`),
    live: r.bool(o.live, `devices[${i}].live`),
    how: r.oneOf(o.how, `devices[${i}].how`, ["registered", "password", "linked", "recovered"] as const),
    linkedFrom: (o.linkedFrom as string | undefined) ?? null,
    current: o.current === undefined ? false : r.bool(o.current, `devices[${i}].current`),
  }));
  return { rows, refused: r.refused };
}

/** A row of `GET /account/recovery-requests` (spec 03 §18.3). `platform` is self-reported by the requester. */
export interface RecoveryRequestSummary {
  requestId: string;
  state: string;
  createdAt: number;
  verifiedAt: number;
  holdEndsAt: number;
  platform: string;
}

export function decodeRecoveryRequests(body: Json): RecoveryRequestSummary[] {
  const r = new Reader("account/recovery-requests");
  return r.arr(body, "body").map((raw, i) => {
    const o = r.obj(raw, `[${i}]`);
    return {
      requestId: r.b64_16(o.requestId, `[${i}].requestId`),
      state: r.str(o.state, `[${i}].state`),
      createdAt: r.int(o.createdAt, `[${i}].createdAt`),
      verifiedAt: r.int(o.verifiedAt, `[${i}].verifiedAt`),
      holdEndsAt: r.int(o.holdEndsAt, `[${i}].holdEndsAt`),
      platform: r.str(o.platform, `[${i}].platform`),
    };
  });
}

export interface AccountDeleteBlockerV2 {
  kind: string;
  vaultId: string | null;
  others: number;
}

/** `GET /account/delete/preview` (spec 03 §13), with the memberships whose leaves the deletion needs (design §3.11). */
export interface AccountDeletePreviewV2 {
  blockers: AccountDeleteBlockerV2[];
  deletedVaults: string[];
  leftVaults: string[];
  memberships: { vaultId: string; head: LogHead }[];
  totpRequired: boolean;
}

function blockers(r: Reader, v: unknown, field: string): AccountDeleteBlockerV2[] {
  return r.arr(v, field).map((raw, i) => {
    const o = r.obj(raw, `${field}[${i}]`);
    return {
      kind: r.str(o.kind, `${field}[${i}].kind`),
      vaultId: o.vaultId === undefined || o.vaultId === null ? null : r.uuid(o.vaultId, `${field}[${i}].vaultId`),
      others: r.int(o.others, `${field}[${i}].others`),
    };
  });
}

export function decodeDeletePreview(body: Json): AccountDeletePreviewV2 {
  const r = new Reader("account/delete/preview");
  const o = r.obj(body, "body");
  return {
    blockers: blockers(r, o.blockers, "blockers"),
    deletedVaults: r.arr(o.deletedVaults, "deletedVaults").map((v, i) => r.uuid(v, `deletedVaults[${i}]`)),
    leftVaults: r.arr(o.leftVaults, "leftVaults").map((v, i) => r.uuid(v, `leftVaults[${i}]`)),
    memberships: r.arr(o.memberships, "memberships").map((raw, i) => {
      const m = r.obj(raw, `memberships[${i}]`);
      return { vaultId: r.uuid(m.vaultId, `memberships[${i}].vaultId`), head: logHead(r, m.head, `memberships[${i}].head`) };
    }),
    totpRequired: r.bool(o.totpRequired, "totpRequired"),
  };
}

export interface AccountDeleteRequestV2 {
  confirmEmail: string;
  currentAuthKey: string;
  totp?: string;
  /** One 0x03 `leave` frame per shared vault where the account holds a non-owner grant (design §3.11). */
  leaves: string[];
}

// ---------------------------------------------------------------------------------------------------
// Recovery with the kit (rows 32–35)

export interface RecoveryVerifyResponseV2 {
  recoveryTicket: string;
  userId: string;
  recoveryWrappedUvk: string;
  encryptedIdentitySeed: string;
  identityPub: string;
}

export function decodeRecoveryVerify(body: Json): RecoveryVerifyResponseV2 {
  const r = new Reader("recovery/self/verify");
  const o = r.obj(body, "body");
  return {
    recoveryTicket: r.b64(o.recoveryTicket, "recoveryTicket", 128),
    userId: r.userId(o.userId, "userId"),
    recoveryWrappedUvk: r.b64(o.recoveryWrappedUvk, "recoveryWrappedUvk", 1024),
    encryptedIdentitySeed: r.b64(o.encryptedIdentitySeed, "encryptedIdentitySeed", 1024),
    identityPub: r.b64_32(o.identityPub, "identityPub"),
  };
}

export interface RecoveryCommitRequestV2 {
  recoveryTicket: string;
  newAuthKey: string;
  newKdfSalt: string;
  newKdfParams: KdfParams;
  newWrappedUvk: string;
  newMemberRecovery: MemberRecoveryBlock;
  device: NewDevice;
}

export interface RecoverySelfSetupRequestV2 {
  currentAuthKey: string;
  memberRecovery: MemberRecoveryBlock;
}

// ---------------------------------------------------------------------------------------------------
// Sync (row 36)

export interface SyncVaultV2 {
  vaultId: string;
  type: "personal" | "shared";
  rev: number;
  metaBlob: string;
  createdAt: number;
  /** Shared vaults only: the head the device compares with its verified head (design §3.8). A hint to fetch, never a verdict. */
  logHead: SyncLogHead | null;
}

export interface SyncGrantV2 {
  vaultId: string;
  userId: string;
  role: string;
  wrappedVk: string;
  rev: number;
  /** A sealed 0x01 grant (design §3.5), present on a member's row until it adopts the vault. */
  signedGrant: string | null;
}

export interface SyncItemV2 {
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

export interface RemovedGrantInfoV2 {
  vaultId: string;
  reason: "removed" | "left" | "deleted";
  deletedAt: number | null;
  purgeAt: number | null;
}

export interface SyncResponseV2 {
  rev: number;
  full: boolean;
  vaults: SyncVaultV2[];
  grants: SyncGrantV2[];
  items: SyncItemV2[];
  removedGrants: string[];
  removedGrantsInfo: RemovedGrantInfoV2[];
  /** The count of link answers waiting for this account's native devices; the web shows nothing for it (§13). */
  linkAnswers: number;
  /** The count of live assisted-recovery requests against this account (design §9.3 step 2): a cue to list them. */
  recoveryRequests: number;
  /** The account's own use and limits (spec 03 §14.4, "What an account is told"); null when the answer gave none that reads. */
  quota: QuotaUse | null;
  /**
   * Spec 03 §4 (additive): the account state's counter, which every write of it advances by one. Null when the answer
   * carried none, or one that is not a counter: the state is then read as before (vault/accountdocstore.ts
   * stateMayHaveMoved), so a bad value never skips a read.
   */
  accountStateSeq: number | null;
}

/** One meter of spec 03 §14.4: whole numbers, at least 0. */
export interface QuotaMeter {
  readonly used: number;
  readonly limit: number;
}

/** Spec 03 §14.4's `quota`: the four meters, by their quota names. */
export interface QuotaUse {
  readonly accountBytes: QuotaMeter;
  readonly items: QuotaMeter;
  readonly ownedSharedVaults: QuotaMeter;
  readonly openLinks: QuotaMeter;
}

export const QUOTA_NAMES = ["accountBytes", "items", "ownedSharedVaults", "openLinks"] as const;
export type QuotaName = (typeof QUOTA_NAMES)[number];

/**
 * Spec 03 §14.4: the `quota` object of a sync answer, read leniently. Anything that cannot be the four meters of whole,
 * non-negative numbers (absent, not an object, a meter missing, a number negative, fractional, a string, or past what
 * this client reads exactly, 2^53 − 1) is null, "unknown": never a refusal of the answer, and never room. A key the
 * client does not know is ignored (a later quota would add one).
 */
export function readQuota(raw: unknown): QuotaUse | null {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return null;
  const o = raw as Record<string, unknown>;
  const meter = (v: unknown): QuotaMeter | null => {
    if (typeof v !== "object" || v === null || Array.isArray(v)) return null;
    const { used, limit } = v as Record<string, unknown>;
    const whole = (n: unknown): n is number => typeof n === "number" && Number.isSafeInteger(n) && n >= 0;
    return whole(used) && whole(limit) ? { used, limit } : null;
  };
  const accountBytes = meter(o.accountBytes);
  const items = meter(o.items);
  const ownedSharedVaults = meter(o.ownedSharedVaults);
  const openLinks = meter(o.openLinks);
  if (accountBytes === null || items === null || ownedSharedVaults === null || openLinks === null) return null;
  return { accountBytes, items, ownedSharedVaults, openLinks };
}

export function decodeItem(r: Reader, o: JsonObject, field: string): SyncItemV2 {
  return {
    itemId: o.itemId as string,
    vaultId: o.vaultId as string,
    rev: r.int(o.rev, `${field}.rev`),
    createdAt: r.int(o.createdAt, `${field}.createdAt`),
    updatedAt: r.int(o.updatedAt, `${field}.updatedAt`),
    deleted: r.bool(o.deleted, `${field}.deleted`),
    conflict: r.bool(o.conflict, `${field}.conflict`),
    formatVersion: r.int(o.formatVersion, `${field}.formatVersion`),
    attachmentIds: r.arr(o.attachmentIds, `${field}.attachmentIds`).map((a, j) => r.str(a, `${field}.attachmentIds[${j}]`)),
    blob: o.blob === null || o.blob === undefined ? null : r.b64(o.blob, `${field}.blob`, 12 * 1024 * 1024),
  };
}

export function decodeSync(body: Json): { value: SyncResponseV2; refused: Reader["refused"] } {
  const r = new Reader("sync");
  const o = r.obj(body, "body");
  const vaults = r.rows(o.vaults, "vaults", ["vaultId"], (v, i) => {
    let head: SyncLogHead | null = null;
    if (v.logHead !== undefined && v.logHead !== null) {
      const h = r.obj(v.logHead, `vaults[${i}].logHead`);
      head = { seq: r.int(h.seq, `vaults[${i}].logHead.seq`), hash: r.hex64(h.hash, `vaults[${i}].logHead.hash`) };
    }
    return {
      vaultId: v.vaultId as string,
      type: r.oneOf(v.type, `vaults[${i}].type`, ["personal", "shared"] as const),
      rev: r.int(v.rev, `vaults[${i}].rev`),
      metaBlob: r.str(v.metaBlob, `vaults[${i}].metaBlob`),
      createdAt: r.int(v.createdAt, `vaults[${i}].createdAt`),
      logHead: head,
    };
  });
  const grants = r.rows(o.grants, "grants", ["vaultId", "userId"], (g, i) => ({
    vaultId: g.vaultId as string,
    userId: g.userId as string,
    role: r.str(g.role, `grants[${i}].role`),
    wrappedVk: r.str(g.wrappedVk, `grants[${i}].wrappedVk`),
    rev: r.int(g.rev, `grants[${i}].rev`),
    signedGrant: g.signedGrant === undefined || g.signedGrant === null ? null : r.b64(g.signedGrant, `grants[${i}].signedGrant`, 2100),
  }));
  const items = r.rows(o.items, "items", ["itemId", "vaultId"], (it, i) => decodeItem(r, it, `items[${i}]`));
  const removedGrants: string[] = [];
  r.arr(o.removedGrants, "removedGrants").forEach((v) => {
    if (typeof v === "string" && UUID_RE.test(v)) removedGrants.push(v);
    else r.refused.push({ field: "removedGrants", value: String(v) });
  });
  const removedGrantsInfo =
    o.removedGrantsInfo === undefined || o.removedGrantsInfo === null
      ? []
      : r.rows(o.removedGrantsInfo, "removedGrantsInfo", ["vaultId"], (g, i) => ({
          vaultId: g.vaultId as string,
          reason: r.oneOf(g.reason, `removedGrantsInfo[${i}].reason`, ["removed", "left", "deleted"] as const),
          deletedAt: r.optInt(g.deletedAt, `removedGrantsInfo[${i}].deletedAt`),
          purgeAt: r.optInt(g.purgeAt, `removedGrantsInfo[${i}].purgeAt`),
        }));
  return {
    value: {
      rev: r.int(o.rev, "rev"),
      full: r.bool(o.full, "full"),
      vaults,
      grants,
      items,
      removedGrants,
      removedGrantsInfo,
      linkAnswers: o.linkAnswers === undefined ? 0 : r.int(o.linkAnswers, "linkAnswers"),
      recoveryRequests: o.recoveryRequests === undefined ? 0 : r.int(o.recoveryRequests, "recoveryRequests"),
      quota: readQuota(o.quota),
      accountStateSeq: typeof o.accountStateSeq === "number" && Number.isSafeInteger(o.accountStateSeq) && o.accountStateSeq >= 0 ? o.accountStateSeq : null,
    },
    refused: r.refused,
  };
}

// ---------------------------------------------------------------------------------------------------
// Sync push, item trash and history, attachments, the usage ledger (rows 24, 37–43; spec 03 §3, §5, §5.1, §9)

/**
 * `POST /sync/push` (spec 03 §5). `status` is decoded as text: `applied`, `conflict`, `denied` and `rejected` are
 * the four the server sends, and a status this client does not know is "definitive: dequeue", so it must reach
 * the drain rather than refuse the whole answer. A `serverItem` whose id is malformed is dropped and reported
 * (the A10 rule): the result itself still stands.
 */
export function decodePush(body: Json): { value: PushResponse; refused: Reader["refused"] } {
  const r = new Reader("sync/push");
  const o = r.obj(body, "body");
  const results = r.arr(o.results, "results").map((raw, i): MutationResult => {
    const m = r.obj(raw, `results[${i}]`);
    const out: MutationResult = { mutationId: r.str(m.mutationId, `results[${i}].mutationId`), status: r.str(m.status, `results[${i}].status`) as MutationResult["status"] };
    const rev = r.optInt(m.newItemRev, `results[${i}].newItemRev`);
    if (rev !== null) out.newItemRev = rev;
    if (m.serverItem !== undefined && m.serverItem !== null) {
      const s = r.obj(m.serverItem, `results[${i}].serverItem`);
      const bad = ["itemId", "vaultId"].filter((k) => !(typeof s[k] === "string" && UUID_RE.test(s[k] as string)));
      if (bad.length > 0) for (const k of bad) r.refused.push({ field: `results.serverItem.${k}`, value: String(s[k]) });
      else out.serverItem = decodeItem(r, s, `results[${i}].serverItem`);
    }
    const reason = r.optStr(m.reason, `results[${i}].reason`);
    if (reason !== null) out.reason = reason;
    // Spec 03 §5: `serverItemOmitted: true` carries no item. A non-boolean, or an item beside it, is not this shape:
    // the item is not used and the field is reported (the result itself still settles its mutation).
    const omitted = m.serverItemOmitted;
    if (omitted !== undefined && omitted !== null && typeof omitted !== "boolean") {
      r.refused.push({ field: "results.serverItemOmitted", value: String(omitted) });
    } else if (omitted === true) {
      if (out.serverItem !== undefined) {
        r.refused.push({ field: "results.serverItem", value: "beside serverItemOmitted" });
        delete out.serverItem;
      }
      out.serverItemOmitted = true;
    }
    return out;
  });
  return { value: { rev: r.int(o.rev, "rev"), results }, refused: r.refused };
}

/** `GET /items/{itemId}/versions` (spec 03 §4): the archived ciphertext versions, newest rev first. */
export function decodeItemVersions(body: Json): ItemVersionsResponse {
  const r = new Reader("items/versions");
  const o = r.obj(body, "body");
  return {
    itemId: r.uuid(o.itemId, "itemId"),
    versions: r.arr(o.versions, "versions").map((raw, i) => {
      const v = r.obj(raw, `versions[${i}]`);
      return {
        rev: r.int(v.rev, `versions[${i}].rev`),
        blob: r.b64(v.blob, `versions[${i}].blob`, 12 * 1024 * 1024),
        formatVersion: r.int(v.formatVersion, `versions[${i}].formatVersion`),
        archivedAt: r.int(v.archivedAt, `versions[${i}].archivedAt`),
      };
    }),
  };
}

/** `GET /items/deleted` (spec 03 §5.1). */
export function decodeDeletedItems(body: Json): { value: DeletedItemsResponse; refused: Reader["refused"] } {
  const r = new Reader("items/deleted");
  const o = r.obj(body, "body");
  const items = r.rows(o.items, "items", ["itemId", "vaultId"], (it, i) => ({
    itemId: it.itemId as string,
    vaultId: it.vaultId as string,
    deletedAt: r.int(it.deletedAt, `items[${i}].deletedAt`),
  }));
  return { value: { items }, refused: r.refused };
}

/** `POST /attachments/{id}` (spec 03 §9): what the server stored. The ids must be the ones the upload named. */
export function decodeAttachmentMeta(body: Json): AttachmentMeta {
  const r = new Reader("attachments");
  const o = r.obj(body, "body");
  return {
    attachmentId: r.uuid(o.attachmentId, "attachmentId"),
    itemId: r.uuid(o.itemId, "itemId"),
    vaultId: r.uuid(o.vaultId, "vaultId"),
    size: r.int(o.size, "size"),
    sha256: r.hex64(o.sha256, "sha256"),
    createdAt: r.int(o.createdAt, "createdAt"),
  };
}

/** `GET /usage` (spec 03 §3). `sealedUsage: null` means no ledger was ever written, never "nothing is used". */
export interface UsageResponseV2 {
  sealedUsage: string | null;
  updatedAt: number;
}

export function decodeUsage(body: Json): UsageResponseV2 {
  const r = new Reader("usage");
  const o = r.obj(body, "body");
  return {
    sealedUsage: o.sealedUsage === null || o.sealedUsage === undefined ? null : r.b64(o.sealedUsage, "sealedUsage", 4 * 1024 * 1024),
    updatedAt: r.int(o.updatedAt, "updatedAt"),
  };
}

// ---------------------------------------------------------------------------------------------------
// Shared vaults and the vault log (rows 46–51)

/** `POST /vaults/{id}/log` (spec 03 §10.3). The side data each kind needs is in §10.2. */
export interface LogAppendRequest {
  entry: string;
  grant?: string;
  wrappedVk?: string;
  metaBlob?: string;
  /**
   * `delete` only, unsigned, beside the entry (spec 03 §10.3): the sync `rev` up to which this client read the vault's
   * items. The server refuses the deletion (`409 vault_items_moved`, nothing stored) when any item of the vault, live or
   * in the trash, has a newer revision. An older server ignores it.
   */
  itemsAtMost?: number;
}

export interface LogAppendResponse {
  rev: number;
  head: LogHead;
  /** The server's grace end while the vault is in its grace (§10.3); null on an older server. Display only: {@link LogDeleted}. */
  deleted: LogDeleted | null;
}

/**
 * `deleted: {deletedAt, purgeAt}` (`ms` both; spec 03 §10.3, §10.6, §11.1): when the server stored the vault's `delete`
 * and when its grace ends. It is the server's word, for the "restorable until" a screen shows and nothing else: whether a
 * vault is deleted is the verified log's `delete`, and nothing is refused, hidden or purged because of these times.
 */
export interface LogDeleted {
  deletedAt: number;
  purgeAt: number;
}

/** The lenient reading of `deleted`: anything but two whole numbers ≥ 0 with `purgeAt` not before `deletedAt` reads as
 *  absent (null), so a malformed advisory field never fails the answer it rides on. Core `LogDeletedLenient` twin. */
export function readLogDeleted(v: unknown): LogDeleted | null {
  if (typeof v !== "object" || v === null || Array.isArray(v)) return null;
  const { deletedAt, purgeAt } = v as Record<string, unknown>;
  const whole = (n: unknown): n is number => typeof n === "number" && Number.isSafeInteger(n) && n >= 0;
  return whole(deletedAt) && whole(purgeAt) && purgeAt >= deletedAt ? { deletedAt, purgeAt } : null;
}

export function decodeLogAppend(body: Json): LogAppendResponse {
  const r = new Reader("vaults/log");
  const o = r.obj(body, "body");
  return { rev: r.int(o.rev, "rev"), head: logHead(r, o.head, "head"), deleted: readLogDeleted(o.deleted) };
}

/** One page of `GET /vaults/{id}/log` (spec 03 §10.6): entries with `seq > after`, at most 500. */
export interface LogPage {
  entries: string[];
  head: LogHead;
  purged: { purgedAt: number } | null;
  /** The server's grace end while the vault is in its grace (§10.6); null on an older server. Display only: {@link LogDeleted}. */
  deleted: LogDeleted | null;
}

export function decodeLogPage(body: Json): LogPage {
  const r = new Reader("vaults/log");
  const o = r.obj(body, "body");
  const entries = r.arr(o.entries, "entries").map((e, i) => r.b64(e, `entries[${i}]`, 2048));
  if (entries.length > 500) r.fail("entries");
  let purged: LogPage["purged"] = null;
  if (o.purged !== undefined && o.purged !== null) purged = { purgedAt: r.int(r.obj(o.purged, "purged").purgedAt, "purged.purgedAt") };
  return { entries, head: logHead(r, o.head, "head"), purged, deleted: readLogDeleted(o.deleted) };
}

/** A row of `GET /vaults/{id}/members` (spec 03 §10.7). Every field is the server's: a label is shown only where the log's key equals a pinned key (design §3.9). */
export interface VaultMemberSummaryV2 {
  userId: string;
  email: string;
  displayName: string;
  role: string;
  identityPub: string;
  addedAt: number;
  status: string | null;
}

export function decodeMembers(body: Json): { rows: VaultMemberSummaryV2[]; refused: Reader["refused"] } {
  const r = new Reader("vaults/members");
  const rows = r.rows(body, "members", ["userId"], (m, i) => ({
    userId: m.userId as string,
    email: r.str(m.email, `members[${i}].email`),
    displayName: r.str(m.displayName, `members[${i}].displayName`),
    role: r.str(m.role, `members[${i}].role`),
    identityPub: r.str(m.identityPub, `members[${i}].identityPub`),
    addedAt: r.int(m.addedAt, `members[${i}].addedAt`),
    status: r.optStr(m.status, `members[${i}].status`),
  }));
  return { rows, refused: r.refused };
}

/** A row of `GET /vaults/deleted` (spec 03 §11.2). */
export interface DeletedVaultSummaryV2 {
  vaultId: string;
  metaBlob: string;
  wrappedVk: string;
  deletedAt: number;
  purgeAt: number;
  deleteId: string;
}

export function decodeDeletedVaults(body: Json): { rows: DeletedVaultSummaryV2[]; refused: Reader["refused"] } {
  const r = new Reader("vaults/deleted");
  const rows = r.rows(body, "vaults", ["vaultId"], (v, i) => ({
    vaultId: v.vaultId as string,
    metaBlob: r.str(v.metaBlob, `vaults[${i}].metaBlob`),
    wrappedVk: r.str(v.wrappedVk, `vaults[${i}].wrappedVk`),
    deletedAt: r.int(v.deletedAt, `vaults[${i}].deletedAt`),
    purgeAt: r.int(v.purgeAt, `vaults[${i}].purgeAt`),
    deleteId: r.b64_16(v.deleteId, `vaults[${i}].deleteId`),
  }));
  return { rows, refused: r.refused };
}

export function decodeRev(endpoint: string, body: Json): number {
  const r = new Reader(endpoint);
  return r.int(r.obj(body, "body").rev, "rev");
}

export function decodeDeletedAt(body: Json): number {
  const r = new Reader("account/delete");
  return r.int(r.obj(body, "body").deletedAt, "deletedAt");
}

export function decodeRecoveryPieceId(body: Json): string {
  const r = new Reader("recovery/self-setup");
  return r.str(r.obj(body, "body").pieceId, "pieceId");
}

// ---------------------------------------------------------------------------------------------------
// Errors (spec 03 §0.1)

/**
 * The fields a few refusals carry beside `error` and `message` (spec 03 §0.1). Decoded only for the
 * code that defines them; anything else is ignored.
 */
export type ErrorExtras =
  | { kind: "log_head_moved"; head: LogHead }
  | { kind: "quota_exceeded"; quota: string | null }
  | { kind: "account_delete_log_stale"; vaultIds: string[] }
  | { kind: "account_delete_blocked"; blockers: AccountDeleteBlockerV2[] };

export function decodeErrorExtras(code: string, body: Json): ErrorExtras | null {
  const r = new Reader(`error ${code}`);
  try {
    const o = r.obj(body, "body");
    switch (code) {
      case "log_head_moved":
        return { kind: code, head: { seq: r.int(o.seq, "seq"), hash: r.hex64(o.hash, "hash"), at: r.int(o.at, "at") } };
      case "quota_exceeded":
        return { kind: code, quota: r.optStr(o.quota, "quota") };
      case "account_delete_log_stale":
        return { kind: code, vaultIds: r.arr(o.vaultIds, "vaultIds").map((v, i) => r.uuid(v, `vaultIds[${i}]`)) };
      case "account_delete_blocked":
        return { kind: code, blockers: o.blockers === undefined ? [] : blockers(r, o.blockers, "blockers") };
      default:
        return null;
    }
  } catch {
    // A refusal whose extras are malformed is still the refusal; it only carries no extras.
    return null;
  }
}
