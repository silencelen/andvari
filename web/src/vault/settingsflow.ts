import { ApiError } from "../api/client";
import type { KeyValue } from "../api/devicesecret";
import type { TotpSetupResponse } from "../api/types";
import type {
  AccountDeleteBlockerV2,
  AccountDeletePreviewV2,
  AccountDeleteRequestV2,
  AccountKeysV2,
  AccountRecoveryPut,
  AccountStateResponseV2,
  DeviceRow,
  EscrowSelfPut,
  InstanceResponse,
  LogHead,
  PasswordChangeRequestV2,
  RecoveryRequestSummary,
  RecoverySelfSetupRequestV2,
} from "../api/wire";
import { adUvk } from "../crypto/ad";
import { toB64 } from "../crypto/bytes";
import { seal } from "../crypto/envelope";
import { sealUvkV3 } from "../crypto/escrow";
import { assertServerKdfParams, authKey as deriveAuthKey, type KdfParams, KdfPolicyError, masterKey, wrapKey as deriveWrapKey } from "../crypto/keys";
import { randomBytes } from "../crypto/provider";
import { emailNorm, fromB64Canonical, fromB64Exact, isB64_16, isUuid, NONE } from "../crypto/trust/grammar";
import { recoveryKeyMatches, type VerifiedCard, verifyCardChain } from "../crypto/trust/instancecard";
import { type FpChange, rotationChain, rotationsLink, signVeto, unsignedChanges } from "../crypto/trust/recovery";
import { logPosition, logPositionAfter, signLogEntry, type VaultState } from "../crypto/trust/vaultlog";
import type { OpenedAccount } from "./accountopen";
import type { AccountStateStore } from "./accountdocstore";
import { type FreshKit, type KitWire, reauthDecision, rotateKit } from "./kitflow";
import type { GateDecision } from "./passwordgate";
import type { PinStore, WebPin } from "./pinstore";
import { passesReKeyFence, shouldUpgrade } from "./kdfupgrade";
import { readMirror, recordRecoveryChoice, type RecoveryMirror } from "./recoverymirror";
import { type SessionKeys, SessionWrap } from "./sessionwrap";

/**
 * Settings on the post-cut-over routes (design §13: what the web may do inside a session): changing the master
 * password, the recovery posture with its first consent, rotating the kit, the account's own devices, cancelling a
 * recovery request, and deleting the account with its leaves.
 *
 * Every re-authenticated call (spec 03 §0.1 `session†`) goes through ONE path, {@link reauth}: the password rule is
 * asked for a re-authentication at this session's origin and account (§4.4); then the typed password is proven on
 * this device against the wrap the session keeps (spec 01 §7, {@link SessionWrap}), under that wrap's own salt and
 * cost, and `currentAuthKey` comes from the same pass. Nothing is fetched for the proof (the wire's one read of the
 * account's keys settles a password change left pending, and nothing it answers goes into a key), and a wrong password
 * sends nothing at all: no proof, no statement, no request of the
 * action's own. No result or error carries a secret.
 */

export interface SettingsWire extends KitWire {
  changePassword(req: PasswordChangeRequestV2): Promise<void>;
  /**
   * `GET /account/keys`: read ONLY to settle a password change whose answer never came, before another is sent
   * ({@link changePassword}). Never for a proof: nothing it answers goes into a key that is sent.
   */
  accountKeys(): Promise<Pick<AccountKeysV2, "kdfSalt" | "kdfParams" | "wrappedUvk">>;
  devices(): Promise<DeviceRow[]>;
  revokeDevice(deviceId: string, currentAuthKey: string): Promise<void>;
  setRequireLink(enabled: boolean, currentAuthKey: string): Promise<void>;
  totpDisable(code: string, currentAuthKey: string): Promise<void>;
  totpSetup(currentAuthKey: string): Promise<TotpSetupResponse>;
  instance(): Promise<InstanceResponse>;
  recoveryPubkey(): Promise<string>;
  putRecovery(req: AccountRecoveryPut): Promise<AccountStateResponseV2>;
  recoveryRequests(): Promise<RecoveryRequestSummary[]>;
  vetoRecoveryRequest(requestId: string, statement: string): Promise<void>;
  deletePreview(): Promise<AccountDeletePreviewV2>;
  deleteAccountWithLeaves(req: AccountDeleteRequestV2): Promise<number>;
  recoverySelfSetup(req: RecoverySelfSetupRequestV2): Promise<string>;
  putEscrowSelf(req: EscrowSelfPut): Promise<void>;
}

/** The session these flows act for. `account` is the `emailNorm` of the signed-in account. */
export interface SettingsSession {
  readonly wire: SettingsWire;
  readonly pins: PinStore;
  readonly origin: string;
  readonly account: string;
  readonly opened: OpenedAccount;
  /** The wrap this session keeps, the same one its Account proves against (spec 01 §7). */
  readonly wrap: SessionWrap;
  /** The offline copy's keeper of the account keys and the pending wraps; absent where this session keeps no copy. */
  readonly copy?: CopyKeeper;
}

/** What a write beside the offline copy did: written; nothing to write (this browser keeps no copy); or it failed. */
export type CopyWrite = "written" | "none" | "failed";

/**
 * The offline copy's side of a password change (spec 01 §7, as core keeps its pending record beside its keys): the
 * wraps of changes sent with no answer are kept beside the copy before each request goes, so that after a reload the
 * copy opens with either password until the server's word settles them.
 */
export interface CopyKeeper {
  /** Replaces the pending wraps kept beside the copy with [pending] (oldest first). */
  keepPending(pending: readonly SessionKeys[]): Promise<CopyWrite>;
  /** The copy's account keys take [own] (the server's word), and the pending wraps kept beside it become [pending]. */
  settle(own: SessionKeys, pending: readonly SessionKeys[]): Promise<CopyWrite>;
}

/** A change the server made: the wrap it holds now, and whether this browser's offline copy took it. */
export interface PasswordChanged {
  readonly keys: SessionKeys;
  /** `failed`: the copy still opens with the old password (and the new) until the next online unlock repairs it. */
  readonly copy: CopyWrite;
}

export type { SessionKeys };

export type Reauthed<T> =
  | { readonly kind: "done"; readonly value: T }
  /** The typed password does not open this account's keys: caught here, and nothing was sent. (The server's `403 reauth_failed` is {@link proofRefused}.) */
  | { readonly kind: "wrong_password" }
  /** The password rule did not say proceed: nothing was derived or sent. */
  | { readonly kind: "password_rule"; readonly decision: Exclude<GateDecision, "proceed"> }
  /** `401 credential_changed`, or the session is gone: sign in again. */
  | { readonly kind: "session_ended" }
  /** `429 rate_limited`: too many wrong proofs on this account (the proofs' own back-off): wait; nothing was checked or changed. */
  | { readonly kind: "rate_limited" }
  | { readonly kind: "refused"; readonly code: string }
  /** No answer, a 5xx, or an answer that is not the route's: the change may or may not have landed. */
  | { readonly kind: "unknown"; readonly error: unknown };

type Refusal = Exclude<Reauthed<never>, { kind: "done" }>;

/**
 * Spec 01 §7: the server refused a proof (`403 reauth_failed`) while this session is marked as holding keys the server
 * does not ({@link SessionWrap.serverKeysNotKnown}): the password proved here, against this browser's own wrap, and the
 * server checks it against another. Said as that, never as a wrong password.
 */
export const SERVER_KEYS_NOT_KNOWN = "server_keys_not_known";

/**
 * Spec 01 §7: the server refused a proof (`403 reauth_failed`) that was made on this device: the typed password opened
 * this session's own wrap here before anything was sent (a wrong password is found here and sends nothing), so the
 * server's refusal is not a wrong password. Said as the server's refusal, with the way on (sign in again if it keeps
 * refusing).
 */
export const PROOF_REFUSED = "proof_refused";

/**
 * A proof the server refused. Every proof is made here first ({@link SessionWrap.prove}), so it is never a wrong
 * password: while the session is marked, keys the server holds that are not this browser's; otherwise the server's
 * refusal of a proof this password made here.
 */
export function proofRefused(wrap: Pick<SessionWrap, "serverKeysNotKnown"> | undefined): Refusal {
  return { kind: "refused", code: wrap?.serverKeysNotKnown === true ? SERVER_KEYS_NOT_KNOWN : PROOF_REFUSED };
}

/** How a thrown call maps to a result: never a guess about whether it landed. [wrap] is the session's, for {@link proofRefused}. */
export function refusalOf(e: unknown, wrap?: Pick<SessionWrap, "serverKeysNotKnown">): Refusal {
  // KDF parameters outside this client's own fence: a distinct security block, raised before anything derives
  // under them and before anything is sent. Never "wrong password", never "may have landed".
  if (e instanceof KdfPolicyError) return { kind: "refused", code: e.code };
  if (!(e instanceof ApiError)) return { kind: "unknown", error: e };
  if (e.code === "reauth_failed") return proofRefused(wrap);
  if (e.code === "credential_changed" || e.status === 401) return { kind: "session_ended" };
  // Spec 03 (server 2026-11-16): proofs made on a live session are counted on a back-off of their own, per account
  // (wrong proofs never arm the sign-in's, so nobody can keep a person from signing in by sending them); while it holds,
  // the proof is refused before it is checked. Never "wrong password", and nothing is retried by itself.
  if (e.status === 429) return { kind: "rate_limited" };
  if (e.status === 0 || e.status >= 500) return { kind: "unknown", error: e };
  return { kind: "refused", code: e.code };
}

/**
 * The one re-authentication path: the password rule, then the proof on this device against the session's own wrap
 * ({@link SessionWrap.prove}). Answers `currentAuthKey` under that wrap's own salt and cost, with the wrap that proved;
 * or why nothing may be sent. Nothing is dialed: not the account's keys, not a prelogin.
 */
export async function reauth(
  s: SettingsSession,
  password: string,
): Promise<{ readonly kind: "key"; readonly currentAuthKey: string; readonly wrap: SessionKeys; readonly copyFailed: boolean } | Refusal> {
  const d = reauthDecision(s.pins, { origin: s.origin, account: s.account });
  if (d !== "proceed") return { kind: "password_rule", decision: d };
  // A proof is never sent while a password change hangs: which password the server holds is found out first.
  const st = await settlePendingChange(s.wrap, s.wire, s.copy);
  if (st.kind !== "settled") return st;
  const p = await s.wrap.prove(password, s.opened.userId, s.opened.uvk);
  switch (p.kind) {
    case "proven":
      return { kind: "key", currentAuthKey: p.currentAuthKey, wrap: p.wrap, copyFailed: st.copyFailed };
    case "wrong_password":
      return { kind: "wrong_password" };
    case "weakened":
      return refusalOf(p.error);
    case "no_wrap":
      return { kind: "refused", code: NO_SESSION_WRAP };
  }
}

/**
 * A password change sent with no answer (spec 01 §7) is settled against the account's keys as the server holds them
 * before any proof goes ({@link SessionWrap.settle}): the server holds the new wrap (the change was made) or the
 * session's own (it was not), and the proof is made with that one only. The offline copy takes the result. Where the
 * keys cannot be read (no answer) nothing is sent and the change is said as not confirmed
 * ({@link PASSWORD_CHANGE_UNCONFIRMED}, never a wrong password, never the server's refusal of a proof); where the server
 * holds neither wrap (a change made elsewhere since), {@link PENDING_CHANGE_UNSETTLED}. Nothing derived from a password
 * is sent here. `settled` with nothing pending reads nothing.
 */
export async function settlePendingChange(
  wrap: SessionWrap,
  wire: Pick<SettingsWire, "accountKeys">,
  copy?: CopyKeeper,
): Promise<{ readonly kind: "settled"; readonly copyFailed: boolean } | Refusal> {
  if (wrap.pendingAll.length === 0) return { kind: "settled", copyFailed: false };
  let served: SessionKeys;
  try {
    const k = await wire.accountKeys();
    served = { kdfSalt: k.kdfSalt, kdfParams: k.kdfParams, wrappedUvk: k.wrappedUvk };
  } catch (e) {
    const f = refusalOf(e, wrap);
    return f.kind === "unknown" ? { kind: "refused", code: PASSWORD_CHANGE_UNCONFIRMED } : f;
  }
  if (wrap.settle(served) === "elsewhere") return { kind: "refused", code: PENDING_CHANGE_UNSETTLED };
  const copyFailed = copy !== undefined && wrap.current !== null && (await copy.settle(wrap.current, wrap.pendingAll)) === "failed";
  return { kind: "settled", copyFailed };
}

/**
 * The refusal of a proof while a password change of this session has no answer and the server's keys could not be read
 * to find out which password it holds ({@link settlePendingChange}): nothing was sent, and either the password before
 * the change or the new one may be the server's.
 */
export const PASSWORD_CHANGE_UNCONFIRMED = "password_change_unconfirmed";

/** The refusal when this tab keeps no wrap for its session: nothing can be proven, so nothing is derived or sent. */
export const NO_SESSION_WRAP = "no_session_wrap";

/**
 * The refusal of a second password change while an earlier one is unsettled and the server holds neither its wrap nor
 * this session's (a change made elsewhere since): nothing is sent, and both wraps are kept for the next unlock.
 */
export const PENDING_CHANGE_UNSETTLED = "pending_change_unsettled";

/** The quiet re-key found no upgrade due against the wrap the password proved: nothing was derived under a new cost or sent. */
export const REKEY_NOT_DUE = "rekey_not_due";

/**
 * The server's refusal of a recovery copy whose size is not the one form it stores for the account's address (spec 03
 * §3.1, §3.2: `400 escrow_wrong_form` at registration, at `PUT /account/recovery` and at `PUT /escrow/self`). This web
 * client seals that form; the code still has its own sentence (ESCROW_WRONG_FORM_TEXT), never shown raw.
 */
export const ESCROW_WRONG_FORM = "escrow_wrong_form";

/** [reauth], then [send] with the key; every refusal is typed. */
async function reauthed<T>(s: SettingsSession, password: string, send: (currentAuthKey: string) => Promise<T>): Promise<Reauthed<T>> {
  const r = await reauth(s, password);
  if (r.kind !== "key") return r;
  try {
    return { kind: "done", value: await send(r.currentAuthKey) };
  } catch (e) {
    return refusalOf(e, s.wrap);
  }
}

// ---- The master password (spec 03 §3) ----------------------------------------------------------------------

/**
 * The cost of a new wrap for an account that exists (spec 01 §7; a password change and the quiet raising): figure by
 * figure, the higher of the account's present cost (the one the proven wrap was made at) and the cost the server serves,
 * so that a server whose floor was raised takes it; never lower than the present cost on either figure, whatever a
 * policy names. A served cost outside this browser's own limits (another scheme, below the floor, above the ceiling,
 * not whole KiB) is not followed at all. When the quiet raising is due is a separate rule (kdfupgrade.ts shouldUpgrade).
 * Before, the served cost was taken only when it was at least as high on BOTH figures, so an account above it on one
 * figure and below on the other could not change its password on a server with a raised floor.
 */
export function newPasswordCost(present: KdfParams, policy: KdfParams | null): KdfParams {
  if (policy === null || !passesReKeyFence(policy) || policy.v !== present.v || policy.alg !== present.alg) return present;  const ops = Math.max(present.ops, policy.ops);
  const memBytes = Math.max(present.memBytes, policy.memBytes);
  return ops === present.ops && memBytes === present.memBytes ? present : { ...present, ops, memBytes };
}

/**
 * `PUT /account/password`†: a new salt, a new login verifier and the SAME UVK wrapped under the new password's key, at
 * {@link newPasswordCost}. The caller applies the master-password floor to [newPassword] first (the screens do, as at
 * sign-up). The current password is proven on this device first; a wrong one sends nothing. The new wrap is kept as
 * pending before the request goes (spec 01 §7): the server's "made" makes it the session's own, an answer that the
 * change was not made drops it, and no answer or a server error leaves it pending, so either password proves until a
 * later answer settles it. On success the server revoked every other session; this one continues.
 *
 * The offline copy ([SettingsSession.copy]) keeps the pending wraps beside its keys, written before the request goes,
 * and takes the new keys once the change is made; a failed write there is said in the result, never swallowed. A
 * second change while an earlier one is unanswered first settles that one against the server's keys,
 * so a refusal of the second can never take the first's wrap with it.
 */
export async function changePassword(
  s: SettingsSession,
  currentPassword: string,
  newPassword: string,
  policyKdfParams: KdfParams | null,
  /** The quiet re-key (vault/kdfupgrade.ts): sent only while an upgrade is due against the wrap the password proved. */
  opts: { onlyIfUpgrade?: boolean } = {},
): Promise<Reauthed<PasswordChanged>> {
  // A pending wrap is never overwritten or dropped by a later change. An earlier change whose
  // answer never came is first settled against what the server holds ({@link reauth} does it for every proof), and the
  // password is proven against what that leaves (the old one proves nothing once the server holds the new).
  const r = await reauth(s, currentPassword);
  if (r.kind !== "key") return r;
  let copyFailed = r.copyFailed;
  // A re-key at the same cost would be sideways: after a settle the proved wrap may already be at the policy's cost.
  if (opts.onlyIfUpgrade === true && (policyKdfParams === null || !shouldUpgrade(r.wrap.kdfParams, policyKdfParams))) return { kind: "refused", code: REKEY_NOT_DUE };
  const kdfParams = newPasswordCost(r.wrap.kdfParams, policyKdfParams);
  try {
    // H1: belt and braces; the present cost was fenced when it was kept, and a policy is taken only inside the bounds.
    assertServerKdfParams(kdfParams);
  } catch (e) {
    return refusalOf(e);
  }
  const salt = randomBytes(16);
  const mk = masterKey(newPassword, salt, kdfParams);
  let ak: Uint8Array | null = null;
  let wk: Uint8Array | null = null;
  try {
    ak = await deriveAuthKey(mk);
    wk = await deriveWrapKey(mk);
    const next: SessionKeys = { kdfSalt: toB64(salt), kdfParams, wrappedUvk: toB64(seal(wk, s.opened.uvk, adUvk(s.opened.userId))) };
    s.wrap.beginChange(next);
    // Kept beside the offline copy before the request goes: a lost answer and a reload still open the copy with the new
    // password. A failed write does not stop the change (the server's word is what counts); it is said when it is made.
    if (s.copy && (await s.copy.keepPending(s.wrap.pendingAll)) === "failed") copyFailed = true;
    const key = r.currentAuthKey;
    try {
      await s.wire.changePassword({ currentAuthKey: key, newAuthKey: toB64(ak), newKdfSalt: next.kdfSalt, newKdfParams: kdfParams, newWrappedUvk: next.wrappedUvk });
    } catch (e) {
      const refusal = refusalOf(e, s.wrap);
      // An answer from the server that the change was not made drops this change's pending wrap, and only it; no answer
      // leaves it.
      if (refusal.kind !== "unknown") {
        s.wrap.changeRefused(next);
        if (s.copy) await s.copy.keepPending(s.wrap.pendingAll);
      }
      return refusal;
    }
    s.wrap.changeMade(next);
    // The copy takes the change's own keys, never a fetch, and nothing is pending any more (spec 05 T3).
    const copy = s.copy ? await s.copy.settle(next, []) : "none";
    return { kind: "done", value: { keys: next, copy: copyFailed && copy !== "none" ? "failed" : copy } };
  } finally {
    mk.fill(0);
    ak?.fill(0);
    wk?.fill(0);
  }
}

// ---- The kit, and the account's own devices (spec 03 §12, §16.7, §16.8) -----------------------------------

/** "Make a new recovery kit": the old kit stops working when the server stores the new piece; the caller shows and confirms it. */
export function rotateKitFor(s: SettingsSession, password: string): Promise<Reauthed<FreshKit>> {
  return reauthed(s, password, (key) => rotateKit(s.wire, s.opened, key));
}

/** Revokes another of the account's own devices (it is no longer a known device, §8.6). */
export async function revokeDevice(s: SettingsSession, deviceId: string, password: string): Promise<Reauthed<void>> {
  if (!isUuid(deviceId)) return { kind: "refused", code: "bad_device_id" };
  return reauthed(s, password, (key) => s.wire.revokeDevice(deviceId, key));
}

/** "New devices must be linked" (§8.7). */
export function setRequireLink(s: SettingsSession, enabled: boolean, password: string): Promise<Reauthed<boolean>> {
  return reauthed(s, password, async (key) => {
    await s.wire.setRequireLink(enabled, key);
    return enabled;
  });
}

// ---- Two-step sign-in (spec 03 §2, §0.1 row 16) -------------------------------------------------------------

/**
 * What turning two-step sign-in off came to. Nothing changed in each case except `done`, and `unknown`, which is
 * never read as either.
 */
export type TwoStepOff =
  | { readonly kind: "done" }
  /** The typed password does not open this session's wrap: caught here, and nothing was sent. */
  | { readonly kind: "wrong_password" }
  /** `400 bad_totp_code`: the password was right; the code is wrong, expired or already used. */
  | { readonly kind: "wrong_code" }
  /**
   * `429 rate_limited`: the proofs' back-off, the codes' back-off or the route's per-minute limit. Nothing was checked;
   * [retryAfterS] is the wait the server named (null when it named none). Nothing is sent again by itself.
   */
  | { readonly kind: "wait"; readonly retryAfterS: number | null }
  | { readonly kind: "password_rule"; readonly decision: Exclude<GateDecision, "proceed"> }
  /** `401` (the session is gone) or `credential_changed`: sign in again. */
  | { readonly kind: "session_ended" }
  | { readonly kind: "refused"; readonly code: string }
  | { readonly kind: "unknown"; readonly error: unknown };

/**
 * Turns two-step sign-in off (server rule of 2026-11-16: the master password as well as a current code). The password
 * goes through {@link reauth} like every other re-authentication: a wrong one, or a rule that does not say proceed,
 * sends nothing. Then one request carries the code and the proof; it is never sent again by itself.
 */
export async function turnOffTwoStep(s: SettingsSession, code: string, password: string): Promise<TwoStepOff> {
  const r = await reauth(s, password);
  if (r.kind !== "key") return r.kind === "rate_limited" ? { kind: "wait", retryAfterS: null } : r;
  try {
    await s.wire.totpDisable(code, r.currentAuthKey);
    return { kind: "done" };
  } catch (e) {
    if (e instanceof ApiError && e.status === 429) return { kind: "wait", retryAfterS: e.retryAfterS };
    if (e instanceof ApiError && e.code === "bad_totp_code") return { kind: "wrong_code" };
    const f = refusalOf(e, s.wrap);
    return f.kind === "rate_limited" ? { kind: "wait", retryAfterS: null } : f;
  }
}

/** What setting two-step sign-in up came to: the pending secret to confirm, or why nothing was set up. */
export type TwoStepSetup =
  | { readonly kind: "setup"; readonly setup: TotpSetupResponse }
  /** The typed password does not open this session's wrap: caught here, and nothing was sent. */
  | { readonly kind: "wrong_password" }
  /** `429`: the proofs' back-off or the route's per-minute limit; [retryAfterS] the wait the server named, or null. */
  | { readonly kind: "wait"; readonly retryAfterS: number | null }
  | { readonly kind: "password_rule"; readonly decision: Exclude<GateDecision, "proceed"> }
  | { readonly kind: "session_ended" }
  | { readonly kind: "refused"; readonly code: string }
  | { readonly kind: "unknown"; readonly error: unknown };

/** A setup's answer whose `otpauth` label does not name the account it was asked for: the server's fault (core's twin). */
export const LABEL_NOT_THIS_ACCOUNT = "label_not_this_account";
/** The issuer the server names in every label (`otpauth://totp/andvari:<address>?…&issuer=andvari`, spec 03 §2). */
const TOTP_ISSUER = "andvari";

/**
 * The normalised address an `otpauth://totp/` URI's label names under the product's issuer, or null when it names none
 * this browser can read: another issuer in the label or in an `issuer` parameter, no `issuer:` prefix, a percent escape
 * that does not decode, or an address outside the grammar. Core's `WireTwoStep.labelAccount`, step for step.
 */
export function labelAccount(uri: string): string | null {
  const prefix = "otpauth://totp/";
  if (!uri.startsWith(prefix)) return null;
  const rest = uri.slice(prefix.length);
  const q = rest.indexOf("?");
  const label = percentDecoded(q < 0 ? rest : rest.slice(0, q));
  if (label === null) return null;
  const colon = label.indexOf(":");
  if (colon <= 0 || label.slice(0, colon) !== TOTP_ISSUER) return null;
  if (q >= 0) {
    for (const param of rest.slice(q + 1).split("&")) {
      if (!param.startsWith("issuer=")) continue;
      if (percentDecoded(param.slice("issuer=".length)) !== TOTP_ISSUER) return null;
    }
  }
  return emailNorm(label.slice(colon + 1).trim());
}

/** [s] with its `%XX` escapes decoded as UTF-8; null when an escape is broken or the bytes are not UTF-8. */
function percentDecoded(s: string): string | null {
  if (!s.includes("%")) return s;
  const out: number[] = [];
  let i = 0;
  while (i < s.length) {
    if (s[i] === "%") {
      const hex = s.slice(i + 1, i + 3);
      if (!/^[0-9A-Fa-f]{2}$/.test(hex)) return null;
      out.push(parseInt(hex, 16));
      i += 3;
    } else {
      const end = s.indexOf("%", i) < 0 ? s.length : s.indexOf("%", i);
      for (const b of new TextEncoder().encode(s.slice(i, end))) out.push(b);
      i = end;
    }
  }
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(new Uint8Array(out));
  } catch {
    return null;
  }
}

/**
 * Sets two-step sign-in up (server rule of 2026-11-17: the master password at every setup, also on an account that has
 * none and right after a sign-in). As when turning it off, the password goes through {@link reauth}: a wrong one, or a
 * rule that does not say proceed, sends nothing. Then one request carries the proof; it is never sent again by itself.
 */
export async function setUpTwoStep(s: SettingsSession, password: string): Promise<TwoStepSetup> {
  const r = await reauth(s, password);
  if (r.kind !== "key") return r.kind === "rate_limited" ? { kind: "wait", retryAfterS: null } : r;
  try {
    const setup = await s.wire.totpSetup(r.currentAuthKey);
    // Design §8 (decided on 2026-11-17), as the shared code's WireTwoStep checks it: the setup is shown only when its label
    // names this account under the product's name. An authenticator app files a key under its label, and some replace an
    // entry with the same one, so a setup that names anything else is the server's fault and nothing of it is shown.
    if (labelAccount(setup.otpauthUri) !== s.account) return { kind: "refused", code: LABEL_NOT_THIS_ACCOUNT };
    return { kind: "setup", setup };
  } catch (e) {
    if (e instanceof ApiError && e.status === 429) return { kind: "wait", retryAfterS: e.retryAfterS };
    const f = refusalOf(e, s.wrap);
    return f.kind === "rate_limited" ? { kind: "wait", retryAfterS: null } : f;
  }
}

// ---- The recovery posture (design §4.5, §7.7; spec 03 §3.1) ------------------------------------------------

/**
 * Operator recovery as this browser may offer it, made only from the card it PINNED: kind `private` (variant R is
 * compiled in: never for a `public` card, whatever it says), a `recoveryFp`, the served recovery key hashing to
 * that `recoveryFp` at full length, and the first-consent walk over the whole verified chain from card 0.
 * `unsignedChanges` non-empty: show the unsigned-change warning with "Only me" preselected (FS-R2).
 */
export interface OperatorOffer {
  /** The pinned card's `name` (base64url): render it decoded, as plain text, beside the origin. Never a server-reported name. */
  readonly name: string;
  readonly origin: string;
  readonly unsignedChanges: readonly FpChange[];
  readonly pinHash: string;
  readonly fp: string;
  readonly recoveryPub: Uint8Array;
}

/** True when [pin] offers operator recovery at all. */
export const operatorRecoveryOffered = (pin: WebPin): boolean => pin.kind === "private" && pin.recoveryFp !== NONE;

export type OperatorOfferResult = { readonly kind: "offer"; readonly offer: OperatorOffer } | { readonly kind: "unavailable"; readonly reason: string };

/**
 * The offer, or why there is none. The pin store keeps no chain, so the chain and the rotations are fetched and
 * verified again at this moment; the walk runs only when that chain is the pin's own (its card 0, ending at the
 * pinned card).
 */
export async function operatorOffer(s: Pick<SettingsSession, "wire" | "pins" | "origin">): Promise<OperatorOfferResult> {
  const r = await servedRecovery(s);
  if (r.kind !== "served") return r;
  const { pin, cards, rotations, key } = r;
  if (key === null) return { kind: "unavailable", reason: "recovery_key_mismatch" };
  return { kind: "offer", offer: { name: pin.name, origin: pin.origin, unsignedChanges: unsignedChanges(cards, rotations), pinHash: pin.hash, fp: pin.recoveryFp, recoveryPub: key } };
}

/**
 * What the pinned origin serves for operator recovery, checked: the pin refreshed, the card chain verified from the
 * pin's own card 0 to the pinned card, the rotations as served, and the recovery key only when it hashes to the
 * pinned card's `recoveryFp` at full length (else `key` is null).
 */
async function servedRecovery(s: Pick<SettingsSession, "wire" | "pins" | "origin">): Promise<
  | { readonly kind: "served"; readonly pin: WebPin; readonly cards: readonly VerifiedCard[]; readonly rotations: Uint8Array[]; readonly key: Uint8Array | null }
  | { readonly kind: "unavailable"; readonly reason: string }
> {
  const start = s.pins.pinFor(s.origin);
  if (start === null) return { kind: "unavailable", reason: "no_pin" };
  if (!operatorRecoveryOffered(start)) return { kind: "unavailable", reason: "not_offered" };
  const status = await s.pins.refresh(s.origin);
  if (status.kind !== "ok") return { kind: "unavailable", reason: "card_unverified" };
  const pin = status.pin;
  if (!operatorRecoveryOffered(pin)) return { kind: "unavailable", reason: "not_offered" };
  let served: InstanceResponse;
  let keyText: string;
  try {
    served = await s.wire.instance();
    keyText = await s.wire.recoveryPubkey();
  } catch {
    return { kind: "unavailable", reason: "unreachable" };
  }
  const frames: Uint8Array[] = [];
  for (const c of served.cards) {
    const f = fromB64Canonical(c);
    if (f === null) return { kind: "unavailable", reason: "card_unverified" };
    frames.push(f);
  }
  const rotations: Uint8Array[] = [];
  for (const r of served.rotations) {
    const f = fromB64Canonical(r);
    if (f === null) return { kind: "unavailable", reason: "card_unverified" };
    rotations.push(f);
  }
  const chain = verifyCardChain(frames);
  const cards = chain.cards;
  if (chain.verdict !== null || cards.length === 0 || cards[0]!.hash !== pin.card0Hash || cards[cards.length - 1]!.hash !== pin.hash) {
    return { kind: "unavailable", reason: "card_unverified" };
  }
  const key = fromB64Exact(keyText, 32);
  return { kind: "served", pin, cards, rotations, key: key !== null && recoveryKeyMatches(pin.recoveryFp, key) ? key : null };
}

export type PostureChoice =
  | { readonly posture: "private" }
  | {
      readonly posture: "operator";
      /** The offer this browser made and showed ({@link operatorOffer}). */
      readonly offer: OperatorOffer;
      /** The box "I understand that the operator could open my vault and act as me." */
      readonly understood: boolean;
      /** Only with an offer that carries unsigned changes: the person chose "Keep it with the new key" on the warning. */
      readonly keepDespiteUnsignedChange: boolean;
    };

/**
 * `PUT /account/recovery`†: the person's choice, written to the UVK-sealed account state in the same request as
 * the escrow change, stamped later than the record it supersedes, and then to this browser's own mirror (§4.5).
 * Turning operator recovery on seals the UVK to the offered key only (it hashed to the pinned card's `recoveryFp`
 * at full length), after every check that needs no secret: the offer is still the pin's, the box is ticked, and an
 * unsigned change was explicitly kept.
 */
export async function setRecoveryPosture(
  s: SettingsSession,
  state: AccountStateStore,
  storage: KeyValue,
  choice: PostureChoice,
  password: string,
  nowMs: number,
): Promise<Reauthed<RecoveryMirror>> {
  const pre = postureRefusal(s, choice);
  if (pre !== null) return pre;
  const r = await reauth(s, password);
  if (r.kind !== "key") return r;
  return writePosture(s, state, storage, choice, r.currentAuthKey, nowMs);
}

/** Every check of a posture choice that needs no secret, or null when it may go on. */
function postureRefusal(s: SettingsSession, choice: PostureChoice): Refusal | null {
  if (choice.posture !== "operator") return null;
  const pin = s.pins.pinFor(s.origin);
  if (pin === null) return { kind: "refused", code: "no_pin" };
  const o = choice.offer;
  if (!operatorRecoveryOffered(pin)) return { kind: "refused", code: "operator_recovery_unavailable" };
  if (o.origin !== s.origin || o.pinHash !== pin.hash || o.fp !== pin.recoveryFp) return { kind: "refused", code: "stale_offer" };
  if (!choice.understood) return { kind: "refused", code: "consent_required" };
  if (o.unsignedChanges.length > 0 && !choice.keepDespiteUnsignedChange) return { kind: "refused", code: "unsigned_change" };
  return null;
}

export type KeepOutcome =
  | Reauthed<RecoveryMirror>
  /** The pinned origin offers no operator recovery that this browser can check now: nothing was sealed or written. */
  | { readonly kind: "unavailable" }
  /** The walk from card 0 found an unsigned change: keeping it is the takeover warning's choice. Nothing was written. */
  | { readonly kind: "unsigned_change"; readonly change: FpChange };

/**
 * "Keep" on the unlock's escrow question (design §4.5): the password is proven on this device FIRST (spec 01 §7: a
 * wrong one sends nothing, not even the reads of the card chain and the recovery key), then the offer is made from
 * what the pinned origin serves now, then the choice is written as {@link setRecoveryPosture} writes it.
 * [keepDespiteUnsignedChange]: the person is answering the unsigned-change warning, and chose to keep the new key.
 */
export async function keepOperatorRecovery(
  s: SettingsSession,
  state: AccountStateStore,
  storage: KeyValue,
  password: string,
  keepDespiteUnsignedChange: boolean,
  nowMs: number,
): Promise<KeepOutcome> {
  const r = await reauth(s, password);
  if (r.kind !== "key") return r;
  const o = await operatorOffer(s);
  if (o.kind !== "offer") return { kind: "unavailable" };
  const first = o.offer.unsignedChanges[0];
  if (first !== undefined && !keepDespiteUnsignedChange) return { kind: "unsigned_change", change: first };
  const choice: PostureChoice = { posture: "operator", offer: o.offer, understood: true, keepDespiteUnsignedChange };
  const pre = postureRefusal(s, choice);
  if (pre !== null) return pre;
  return writePosture(s, state, storage, choice, r.currentAuthKey, nowMs);
}

/** The posture write behind a proven password: the escrow sealed for an operator choice, then the one request. */
async function writePosture(
  s: SettingsSession,
  state: AccountStateStore,
  storage: KeyValue,
  choice: PostureChoice,
  currentAuthKey: string,
  nowMs: number,
): Promise<Reauthed<RecoveryMirror>> {
  const fp = choice.posture === "operator" ? choice.offer.fp : NONE;
  let escrow: { sealed: string; fingerprint: string } | undefined;
  if (choice.posture === "operator") {
    try {
      // Spec 04 §3: the copy names the signed-in session's address; one that is not already an emailNorm seals nothing.
      const sealed = await sealUvkV3({
        recoveryPub: choice.offer.recoveryPub, verifiedRecoveryFp: fp, userId: s.opened.userId, emailNorm: s.account, identityPub: s.opened.identity.publicKey,
        signer: s.opened.signing, uvk: s.opened.uvk, issuedAt: nowMs,
      });
      escrow = { sealed: toB64(sealed), fingerprint: fp };
    } catch {
      return { kind: "refused", code: "operator_recovery_unavailable" };
    }
  }
  const sent = escrow;
  const w = await recordRecoveryChoice(state, storage, s.opened.userId, { posture: choice.posture, fp }, nowMs, (put) =>
    s.wire.putRecovery({ posture: choice.posture, ...(sent ? { escrow: sent } : {}), currentAuthKey, accountState: put }),
  );
  switch (w.kind) {
    case "written":
    case "unchanged": {
      const rec = w.document.recovery;
      if (!rec) return { kind: "refused", code: "not_recorded" };
      // The escrow this browser knows the account holds now: the one it just sealed, or none.
      writeEscrowSeen(storage, s.opened.userId, sent ? sent.fingerprint : null);
      return { kind: "done", value: { posture: rec.posture, fp: rec.fp, at: rec.at } };
    }
    case "refused":
      return w.code === "reauth_failed" ? proofRefused(s.wrap) : { kind: "refused", code: w.code };
    case "contended":
      return { kind: "refused", code: "stale_state" };
    case "unknown":
      return { kind: "unknown", error: w.error };
  }
}

// ---- The escrow at unlock (design §4.5: own mirror, signed rotation, re-consent) -----------------------------

const escrowSeenKey = (userId: string): string => `andvari.escrowfp.${userId}`;

/** The fingerprint of the escrow this browser last sealed or re-sealed for the account (core `EscrowSeen`), or null. */
export function readEscrowSeen(storage: KeyValue, userId: string): string | null {
  const v = storage.get(escrowSeenKey(userId));
  return v !== null && /^[0-9a-f]{64}$/.test(v) ? v : null;
}

export function writeEscrowSeen(storage: KeyValue, userId: string, fp: string | null): void {
  if (fp === null) storage.remove(escrowSeenKey(userId));
  else storage.set(escrowSeenKey(userId), fp);
}

/** What §4.5 wants at this unlock (core `EscrowDecision`, the same rules in the same order). */
export type EscrowDecision =
  | { readonly kind: "none" }
  /** Re-seal now, unasked: the own mirror agrees and signed rotations lead from the escrow this browser saw. */
  | { readonly kind: "seal_now"; readonly toFp: string; readonly rotations: readonly Uint8Array[] }
  /** "Your account lets the operator of *name* (*origin*) restore it. Keep that?" [Not now] [Keep] [Turn it off]. */
  | { readonly kind: "ask"; readonly name: string; readonly origin: string }
  /** The recovery key changed with no rotation signed by the old key: the takeover warning, default off. */
  | { readonly kind: "unsigned_change"; readonly name: string; readonly origin: string; readonly fromFp: string; readonly toFp: string };

export interface EscrowInputs {
  readonly pin: WebPin;
  /** The account-state `recovery` record (the person's consent), or null. */
  readonly record: RecoveryMirror | null;
  /** This browser's own mirror of the record, or null. */
  readonly mirror: RecoveryMirror | null;
  /** The escrow this browser last saw ({@link readEscrowSeen}), or null. */
  readonly escrowFp: string | null;
  readonly rotations: readonly Uint8Array[];
  /** The full-length SHA-256 of the served recovery key, when it was fetched (null otherwise). */
  readonly servedKeyFp: string | null;
}

/**
 * Design §4.5, §7.7 (core `EscrowRules.decide`): a `public` card never (variant R); no `operator` record or no
 * recovery offered, nothing; the card's `recoveryFp` neither the consented `fp` nor reached from it by signed
 * rotations, the unsigned-change warning; the escrow this browser saw already names it, nothing; the served key must
 * hash to it, or nothing is sealed; a silent re-seal only with the own mirror AND a rotation chain from the escrow
 * seen; otherwise ask.
 */
export function decideEscrow(i: EscrowInputs): EscrowDecision {
  const pin = i.pin;
  if (pin.kind === "public") return { kind: "none" };
  const record = i.record;
  if (record === null || record.posture !== "operator" || pin.recoveryFp === NONE) return { kind: "none" };
  const target = pin.recoveryFp;
  if (target !== record.fp && !rotationsLink(i.rotations, pin.instanceId, record.fp, target)) {
    return { kind: "unsigned_change", name: pin.name, origin: pin.origin, fromFp: record.fp, toFp: target };
  }
  if (i.escrowFp === target) return { kind: "none" };
  if (i.servedKeyFp !== target) return { kind: "none" };
  const m = i.mirror;
  const own = m !== null && m.posture === record.posture && m.fp === record.fp && m.at === record.at;
  const chain = i.escrowFp === null ? null : rotationChain(i.rotations, pin.instanceId, i.escrowFp, target);
  return own && chain !== null && chain.length > 0 ? { kind: "seal_now", toFp: target, rotations: chain } : { kind: "ask", name: pin.name, origin: pin.origin };
}

export type EscrowAtUnlock =
  /** Nothing to ask; `resealed` when a silent re-seal was made now (the record and mirror follow the rotation). */
  | { readonly kind: "settled"; readonly resealed: boolean }
  | { readonly kind: "ask"; readonly decision: Extract<EscrowDecision, { kind: "ask" | "unsigned_change" }> }
  /** The record, the card or the key could not be read now, or the re-seal was refused: nothing sealed; ask again next unlock. */
  | { readonly kind: "unavailable"; readonly reason: string };

/**
 * Run at each unlock (design §4.5). Reads the account state, then decides from the record, this browser's own
 * mirror, the escrow it saw, the pinned card and the served rotations and key. A silent re-seal goes to
 * `PUT /escrow/self` with the rotation chain (no password), and then the consent follows the rotation in the account
 * state and this browser's mirror. Never seals anything for an `ask` or an `unsigned_change`: those are the person's.
 */
export async function escrowAtUnlock(s: SettingsSession, state: AccountStateStore, storage: KeyValue, nowMs: number): Promise<EscrowAtUnlock> {
  const read = await state.read();
  if (read.kind !== "ok") return { kind: "unavailable", reason: read.kind };
  const rec = read.document.recovery;
  const record: RecoveryMirror | null = rec ? { posture: rec.posture, fp: rec.fp, at: rec.at } : null;
  const start = s.pins.pinFor(s.origin);
  if (start === null) return { kind: "unavailable", reason: "no_pin" };
  if (record === null || record.posture !== "operator" || !operatorRecoveryOffered(start)) return { kind: "settled", resealed: false };
  const served = await servedRecovery(s);
  if (served.kind !== "served") return { kind: "unavailable", reason: served.reason };
  const userId = s.opened.userId;
  const d = decideEscrow({
    pin: served.pin, record, mirror: readMirror(storage, userId), escrowFp: readEscrowSeen(storage, userId), rotations: served.rotations,
    servedKeyFp: served.key !== null ? served.pin.recoveryFp : null,
  });
  if (d.kind === "none") return { kind: "settled", resealed: false };
  if (d.kind !== "seal_now") return { kind: "ask", decision: d };
  let sealed: Uint8Array;
  try {
    // The re-seal after a signed rotation is version 3 too (spec 04 §3), naming the session's address.
    sealed = await sealUvkV3({
      recoveryPub: served.key!, verifiedRecoveryFp: d.toFp, userId, emailNorm: s.account, identityPub: s.opened.identity.publicKey, signer: s.opened.signing, uvk: s.opened.uvk, issuedAt: nowMs,
    });
  } catch {
    return { kind: "unavailable", reason: "operator_recovery_unavailable" };
  }
  try {
    await s.wire.putEscrowSelf({ sealed: toB64(sealed), fingerprint: d.toFp, rotations: d.rotations.map(toB64) });
  } catch (e) {
    return { kind: "unavailable", reason: e instanceof ApiError ? e.code : "unreachable" };
  }
  writeEscrowSeen(storage, userId, d.toFp);
  // The consent follows the signed rotation, and this browser's own mirror with it (a verified re-seal made here).
  await recordRecoveryChoice(state, storage, userId, { posture: "operator", fp: d.toFp }, nowMs);
  return { kind: "settled", resealed: true };
}

// ---- Cancelling a recovery request (design §9.3 step 2) ----------------------------------------------------

/** The account's live assisted-recovery requests (the cue is `/sync`'s `recoveryRequests` count). `404` on a public instance. */
export async function listRecoveryRequests(s: Pick<SettingsSession, "wire">): Promise<RecoveryRequestSummary[] | null> {
  try {
    return await s.wire.recoveryRequests();
  } catch (e) {
    if (e instanceof ApiError && e.status === 404) return [];
    return null;
  }
}

export type VetoOutcome = { readonly kind: "vetoed" } | { readonly kind: "refused"; readonly code: string } | { readonly kind: "session_ended" } | { readonly kind: "unknown"; readonly error: unknown };

/**
 * "Someone asked the operator to reset your account. If this wasn't you, cancel it." The veto is a statement signed
 * with the account's key (purpose 0x0A, built by the trust twin), sent with this session; it needs no password.
 */
export async function vetoRecoveryRequest(s: Pick<SettingsSession, "wire" | "opened">, requestId: string, nowMs: number): Promise<VetoOutcome> {
  if (!isB64_16(requestId)) return { kind: "refused", code: "bad_request_id" };
  let statement: string;
  try {
    statement = toB64(signVeto(s.opened.signing, { requestId, userId: s.opened.userId, issuedAt: nowMs }));
  } catch {
    return { kind: "refused", code: "bad_statement" };
  }
  try {
    await s.wire.vetoRecoveryRequest(requestId, statement);
    return { kind: "vetoed" };
  } catch (e) {
    const r = refusalOf(e);
    if (r.kind === "refused" || r.kind === "session_ended" || r.kind === "unknown") return r;
    return { kind: "refused", code: r.kind };
  }
}

// ---- Deleting the account (design §3.11; spec 03 §13) -------------------------------------------------------

/** FS-R7: from a head this browser has not verified, a `head.at` more than one day ahead of its clock is refused. */
export const FUTURE_LIMIT_MS = 24 * 60 * 60 * 1000;
/** At most 500 leaves (the membership limit). */
export const MAX_LEAVES = 500;

/**
 * One `leave` for every membership of the preview, or null when a head is too far ahead (then nothing is signed
 * for any vault). A head this browser VERIFIED (the served seq and hash are exactly its own verified head) is
 * placed from its own verified state, `at` included: the served `at` beside a verified head is the server's word
 * and is never signed after. Every other head is the server's alone, and is held to the one-day bound.
 */
export function buildLeaves(
  me: string,
  signer: OpenedAccount["signing"],
  memberships: readonly { readonly vaultId: string; readonly head: LogHead }[],
  verifiedState: (vaultId: string) => VaultState | null,
  nowMs: number,
): string[] | null {
  const positions: { seq: number; prev: string; at: number }[] = [];
  for (const m of memberships) {
    const v = verifiedState(m.vaultId);
    if (v !== null && v.head.seq === m.head.seq && v.head.hash === m.head.hash) positions.push(logPosition(v, nowMs));
    else if (m.head.at - nowMs > FUTURE_LIMIT_MS) return null;
    else positions.push(logPositionAfter(m.head.seq, m.head.hash, m.head.at, nowMs));
  }
  return memberships.map((m, i) => toB64(signLogEntry(signer, { kind: "leave", vaultId: m.vaultId, seq: positions[i]!.seq, prev: positions[i]!.prev, actor: me, at: positions[i]!.at })));
}

export type DeletionOutcome =
  | { readonly kind: "deleted"; readonly deletedAt: number }
  | { readonly kind: "email_mismatch" }
  | { readonly kind: "blocked"; readonly blockers: readonly AccountDeleteBlockerV2[] }
  | { readonly kind: "totp_needed" }
  | { readonly kind: "bad_totp" }
  /** "One of your shared vaults reports a time far in the future. Try again later." Nothing was signed or sent. */
  | { readonly kind: "future_head" }
  /** A leave was stale: fetch the preview again and retry. */
  | { readonly kind: "log_stale"; readonly vaultIds: readonly string[] }
  /** "Your device's clock is ahead." */
  | { readonly kind: "clock_ahead" }
  | { readonly kind: "wrong_password" }
  | { readonly kind: "password_rule"; readonly decision: Exclude<GateDecision, "proceed"> }
  | { readonly kind: "session_ended" }
  /** `429 rate_limited`: too many wrong passwords; nothing was checked or deleted. */
  | { readonly kind: "rate_limited" }
  | { readonly kind: "refused"; readonly code: string }
  /** The preview could not be read: nothing was sent. */
  | { readonly kind: "unreachable" }
  /** No clear answer to the deletion itself: it may have committed. Never reported as success or as failure. */
  | { readonly kind: "unknown"; readonly error: unknown };

/**
 * `POST /account/delete`† with one leave per membership, built from a FRESH preview at this moment. The typed address
 * is checked first, then the password is proven on this device (spec 01 §7: a wrong one fetches not even the preview),
 * then the preview's checks: blockers, the missing code, the head times. Only `deleted` means the account is gone;
 * the caller then wipes this browser's state for the account.
 */
export async function deleteAccount(
  s: SettingsSession,
  input: {
    typedEmail: string;
    password: string;
    totp?: string;
    verifiedState: (vaultId: string) => VaultState | null;
    nowMs: number;
    /**
     * Brings each membership's log up to the served head before the leaves are placed (the session's log store), so
     * a leave is placed from this browser's own verified head wherever the log verifies (§3.11). Must not throw.
     */
    refreshLogs?: (memberships: readonly { readonly vaultId: string; readonly head: LogHead }[]) => Promise<void>;
  },
): Promise<DeletionOutcome> {
  if (input.typedEmail.trim().toLowerCase() !== s.account) return { kind: "email_mismatch" };
  const r = await reauth(s, input.password);
  if (r.kind !== "key") return r.kind === "unknown" ? { kind: "unreachable" } : r;
  // The design's rule for a deletion's leaves: a stale leave is answered by reading the heads again and retrying. The
  // server's refusal rolls its whole transaction back (the code's step included), so the same proof and code go again.
  // The person is told only when every try met a vault that moved on.
  let out: DeletionOutcome = { kind: "log_stale", vaultIds: [] };
  for (let attempt = 0; attempt < DELETE_TRIES; attempt++) {
    out = await deleteOnce(s, input, r.currentAuthKey);
    if (out.kind !== "log_stale") return out;
  }
  return out;
}

/** How many times a deletion is sent while a shared vault's log keeps moving on (each try reads the heads again). */
export const DELETE_TRIES = 3;

/** One try: a FRESH preview, the leaves placed from it, one request. */
async function deleteOnce(
  s: SettingsSession,
  input: Parameters<typeof deleteAccount>[1],
  currentAuthKey: string,
): Promise<DeletionOutcome> {
  const r = { currentAuthKey };
  let p: AccountDeletePreviewV2;
  try {
    p = await s.wire.deletePreview();
  } catch (e) {
    return e instanceof ApiError && e.status === 401 ? { kind: "session_ended" } : { kind: "unreachable" };
  }
  if (p.blockers.length > 0) return { kind: "blocked", blockers: p.blockers };
  if (p.totpRequired && !input.totp) return { kind: "totp_needed" };
  if (p.memberships.length > MAX_LEAVES) return { kind: "refused", code: "bad_leaves" };
  if (new Set(p.memberships.map((m) => m.vaultId)).size !== p.memberships.length) return { kind: "refused", code: "bad_preview" };
  if (input.refreshLogs) await input.refreshLogs(p.memberships).catch(() => {});
  let leaves: string[] | null;
  try {
    leaves = buildLeaves(s.opened.userId, s.opened.signing, p.memberships, input.verifiedState, input.nowMs);
  } catch {
    // A served head outside the grammar cannot be signed after: refuse the preview, sign nothing.
    return { kind: "refused", code: "bad_preview" };
  }
  if (leaves === null) return { kind: "future_head" };
  try {
    // Exempt from the question a change of a vault asks: everything it writes into a vault's log is this account's leave.
    const deletedAt = await s.wire.deleteAccountWithLeaves({ confirmEmail: input.typedEmail, currentAuthKey: r.currentAuthKey, ...(p.totpRequired && input.totp ? { totp: input.totp } : {}), leaves });
    return { kind: "deleted", deletedAt };
  } catch (e) {
    if (!(e instanceof ApiError) || e.status === 0 || e.status >= 500) return { kind: "unknown", error: e };
    if (e.status === 429) return { kind: "rate_limited" };
    switch (e.code) {
      case "account_delete_blocked":
        return { kind: "blocked", blockers: e.extras?.kind === "account_delete_blocked" ? e.extras.blockers : [] };
      case "account_delete_log_stale":
        return { kind: "log_stale", vaultIds: e.extras?.kind === "account_delete_log_stale" ? e.extras.vaultIds : [] };
      case "at_ahead":
        return { kind: "clock_ahead" };
      case "totp_code_required":
        return { kind: "totp_needed" };
      case "bad_totp_code":
        return { kind: "bad_totp" };
      case "reauth_failed":
        // The proof was made here (above): the server's refusal of it is never a wrong password.
        return proofRefused(s.wrap);
      case "confirm_email_mismatch":
        return { kind: "email_mismatch" };
      case "credential_changed":
        return { kind: "session_ended" };
      default:
        return e.status === 401 ? { kind: "session_ended" } : { kind: "refused", code: e.code };
    }
  }
}
