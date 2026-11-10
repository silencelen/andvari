import { AccountDeleteBlockedError, ApiError, type ApiClient } from "../api/client";
import type { AccountDeleteBlocker, AccountDeletePreview } from "../api/types";
import { KdfPolicyError, WEAK_KDF_MESSAGE } from "../crypto/keys";
import { ReauthFailedError, ReauthStaleSessionError, type Account } from "../vault/account";
import { UNREACHABLE } from "./errors";

/**
 * Settings → Delete account (spec 03 §13; design docs/design/2026-11-10-account-deletion.md §11). The pure half of the
 * flow — what the card says and does — kept out of the component so the node test environment can pin it
 * (account-delete.test.ts). The card (DeleteAccount.tsx) renders these and owns only the state.
 */

/** The typed confirmation matches the account's address, trimmed and case-folded — exactly how the server compares it
 *  (it re-checks: `400 confirm_email_mismatch`). A session saved before the address was recorded knows none: then any
 *  non-empty entry passes HERE and the server decides. */
export function emailConfirmed(typed: string, accountEmail: string): boolean {
  const t = typed.trim().toLowerCase();
  if (!t) return false;
  const a = accountEmail.trim().toLowerCase();
  return a === "" || t === a;
}

/** The code field holds what an authenticator shows ("123 456"); the server wants the digits. */
export const totpDigits = (code: string): string => code.replace(/\s/g, "");

export type BlockerLink = { kind: "vault"; vaultId: string } | { kind: "admin" };

export interface BlockerLine {
  text: string;
  link: BlockerLink | null;
  linkLabel: string;
}

const people = (n: number): string => (n === 1 ? "1 other person" : `${n} other people`);

/**
 * One sentence per blocker, in the server's order, each with the place that resolves it. A vault is named by the name
 * this browser decrypts for it (the server knows vaults only as ids); one it cannot name is still listed. An unknown kind
 * is listed as a blocker this version cannot explain — never dropped (spec 03 §13: a client never proceeds past one).
 */
export function blockerLines(blockers: AccountDeleteBlocker[], vaultName: (vaultId: string) => string | null): BlockerLine[] {
  return blockers.map((b) => {
    if (b.kind === "shared_vault") {
      const name = b.vaultId ? vaultName(b.vaultId) : null;
      const verb = b.others === 1 ? "still uses it" : "still use it";
      if (name !== null && b.vaultId) {
        return {
          text: `You own “${name}”, and ${people(b.others)} ${verb}. Delete it, or make one of them its owner, first.`,
          link: { kind: "vault", vaultId: b.vaultId },
          linkLabel: `Open “${name}” settings →`,
        };
      }
      return {
        text: `You own a shared vault that ${people(b.others)} ${verb}. Delete it, or make one of them its owner, first — you'll find it under Sharing.`,
        link: null,
        linkLabel: "",
      };
    }
    if (b.kind === "last_admin") {
      return {
        text: `You're the only admin of this andvari server, and ${people(b.others)} ${b.others === 1 ? "has an account" : "have accounts"} on it. Invite someone as an admin first (Administration → invite, with “admin” ticked), then come back.`,
        link: { kind: "admin" },
        linkLabel: "Open Administration →",
      };
    }
    return {
      text: "The server reports something else that stops this account being deleted, which this version of andvari can't explain. Reload to update, or ask whoever runs your server.",
      link: null,
      linkLabel: "",
    };
  });
}

/** The line shown when the server refused without naming anything it could decode — still a refusal. */
export const BLOCKED_UNEXPLAINED = "The server refused to delete your account and didn't say why. Nothing was deleted.";

const quoted = (names: string[]): string => {
  const q = names.map((n) => `“${n}”`);
  return q.length <= 1 ? q.join("") : `${q.slice(0, -1).join(", ")} and ${q[q.length - 1]}`;
};

/**
 * What the preview means, in the member's words: what goes for good, and the vaults it leaves. `personalVaultId` names
 * the vault this browser knows as the personal one (so it reads "your Personal vault", not a list entry).
 */
export function deletionSummary(
  preview: AccountDeletePreview,
  vaultName: (vaultId: string) => string | null,
  personalVaultId: string | null,
): { deletes: string[]; leaves: string[] } {
  const others = preview.deletedVaults.filter((v) => v !== personalVaultId);
  const named = others.map(vaultName).filter((n): n is string => n !== null);
  const unnamed = others.length - named.length;
  const vaults: string[] = [];
  if (personalVaultId !== null && preview.deletedVaults.includes(personalVaultId)) vaults.push("your Personal vault");
  if (named.length > 0) vaults.push(`${named.length === 1 ? "the vault" : "the vaults"} only you use, ${quoted(named)}`);
  if (unnamed > 0) vaults.push(unnamed === 1 ? "1 other vault only you hold" : `${unnamed} other vaults only you hold`);
  const deletes = [
    "Your account, and its sign-in on every device.",
    ...(vaults.length > 0 ? [`${capitalize(joinAnd(vaults))} — every item, attachment and earlier version in them.`] : []),
    "Your recovery phrase and your household recovery backup: nobody, an admin included, can bring the account back.",
    "Invites you sent that nobody has used yet.",
  ];
  const leftNamed = preview.leftVaults.map(vaultName).filter((n): n is string => n !== null);
  const leftUnnamed = preview.leftVaults.length - leftNamed.length;
  const leaves: string[] = [];
  if (preview.leftVaults.length > 0) {
    const what = [
      ...(leftNamed.length > 0 ? [quoted(leftNamed)] : []),
      ...(leftUnnamed > 0 ? [leftUnnamed === 1 ? "1 other shared vault" : `${leftUnnamed} other shared vaults`] : []),
    ];
    leaves.push(`You'll leave ${joinAnd(what)}. What you saved there stays for the people who still use ${preview.leftVaults.length === 1 ? "it" : "them"}.`);
  }
  return { deletes, leaves };
}

function joinAnd(parts: string[]): string {
  return parts.length <= 1 ? parts.join("") : `${parts.slice(0, -1).join(", ")} and ${parts[parts.length - 1]}`;
}

function capitalize(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

/** Why the preview could not be loaded. */
export function previewErrorText(e: unknown): string {
  if (e instanceof ApiError && e.code === "account_delete_public_disabled") return PUBLIC_ORIGIN_REFUSED;
  if (e instanceof ApiError && e.code === "totp_enrollment_required") return TOTP_ENROLL_FIRST;
  if (e instanceof TypeError) return UNREACHABLE;
  return "Couldn't check what deleting your account would do — try again.";
}

const PUBLIC_ORIGIN_REFUSED =
  "Deleting an account isn't available from this emergency address. Use your household's usual andvari address.";
const TOTP_ENROLL_FIRST = "This server requires two-factor sign-in: turn it on above first, then delete the account.";

/** One sentence per refusal of the deletion request (or of the local password proof that precedes it). Every one of them
 *  means NOTHING was deleted — the server refuses before its transaction writes anything. */
export function deleteErrorText(e: unknown): string {
  if (e instanceof ReauthFailedError) return e.message; // caught locally — the password never left this browser
  if (e instanceof ReauthStaleSessionError) return e.message;
  if (e instanceof KdfPolicyError) return WEAK_KDF_MESSAGE;
  if (e instanceof TypeError) return UNREACHABLE;
  if (e instanceof ApiError) {
    switch (e.code) {
      case "reauth_failed":
        return new ReauthFailedError().message;
      case "totp_code_required":
        return "Enter the code from your authenticator app.";
      case "bad_totp_code":
        return "That code is wrong or was already used — wait for the next one and try again.";
      case "confirm_email_mismatch":
        return "That isn't this account's email address.";
      case "account_delete_public_disabled":
        return PUBLIC_ORIGIN_REFUSED;
      case "totp_enrollment_required":
        return TOTP_ENROLL_FIRST;
      case "credential_changed":
        return "Your password was changed, or this device was signed out, while deleting — nothing was deleted. Sign in again and retry.";
      case "rate_limited":
        return "Too many attempts — wait a while, then try again.";
      case "upgrade_required":
        return "This tab is running an older version — reload to update, then try again.";
    }
    if (e.status === 401) return "Your session ended — nothing was deleted. Sign in again and retry.";
  }
  return "Something went wrong and your account was not deleted — try again.";
}

/** Shown when the deletion request itself never got an answer: the server may or may not have committed it. */
export const OUTCOME_UNKNOWN =
  "The server couldn't be reached while deleting, so this tab doesn't know whether your account was deleted. Reload andvari and sign in: if your account is gone, the deletion went through.";

export type DeletionOutcome =
  | { kind: "deleted"; deletedAt: number }
  | { kind: "blocked"; blockers: AccountDeleteBlocker[] }
  | { kind: "error"; message: string }
  | { kind: "unknown" };

/**
 * The submit. The master-password proof is derived through the account's fenced reauth (`Account.reauthAuthKey`: the KDF
 * floor, only this session's salt, and the derivation proved by opening this session's UVK), so a wrong password is caught
 * HERE and never sent. Then the one request. A transport failure on that request is the ambiguous case — it may have
 * committed — and is reported as such, never as a failure; any earlier failure means nothing was sent.
 */
export async function runAccountDeletion(
  client: Pick<ApiClient, "accountKeys" | "deleteAccount">,
  account: Pick<Account, "reauthAuthKey">,
  input: { email: string; password: string; totp: string; totpRequired: boolean },
): Promise<DeletionOutcome> {
  let currentAuthKey: string;
  try {
    currentAuthKey = await account.reauthAuthKey(input.password, await client.accountKeys());
  } catch (e) {
    return { kind: "error", message: deleteErrorText(e) };
  }
  const totp = input.totpRequired ? totpDigits(input.totp) : "";
  try {
    const r = await client.deleteAccount({ confirmEmail: input.email.trim(), currentAuthKey, ...(totp ? { totp } : {}) });
    return { kind: "deleted", deletedAt: r.deletedAt };
  } catch (e) {
    if (e instanceof AccountDeleteBlockedError) return { kind: "blocked", blockers: e.blockers };
    if (e instanceof TypeError) return { kind: "unknown" };
    return { kind: "error", message: deleteErrorText(e) };
  }
}

/** The notice on the sign-in card after a deletion this browser ran. */
export const ACCOUNT_DELETED_NOTICE =
  "Your andvari account was deleted. Everything only it held is gone from the server, and this browser kept nothing of it.";
