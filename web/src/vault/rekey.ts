import type { KdfParams } from "../crypto/keys";
import { shouldUpgrade } from "./kdfupgrade";
import { changePassword, REKEY_NOT_DUE, type SettingsSession } from "./settingsflow";

/**
 * The quiet re-key after an unlock (spec 01 §7, "KDF upgrade (F61, normative)"). After a successful unlock with the full
 * master password that reached the server, the account's password-hashing cost (the wrap the unlock opened, as the
 * server served it) is compared with the policy's, fetched now; when an upgrade is due the account is re-keyed with the
 * password just verified, through the web's one password change ({@link changePassword}): the current password proven
 * on this device against the session's own wrap (the in-session proof), any pending change settled against the
 * server's keys first, the new wrap kept as pending (beside the offline copy too) before the request goes, and the
 * session's wrap and the copy's keys taking the new wrap only once the server made the change.
 *
 * - Upgrade only: never sideways or down, and never to a cost outside this client's own floor and ceiling, whatever the
 *   server names ({@link shouldUpgrade}; the policy is also fenced where it is read).
 * - Full-password unlocks only: an unlock from the offline copy, a read-only copy, a sign-up or a kit recovery never
 *   counts and never triggers it. The web has no quick unlock (spec 01 §8.3).
 * - The server unreachable (no policy, or no answer to the change): skipped, without a word.
 * - A failure changes nothing a person sees, and the account opens as before: a refusal leaves the session's wrap as it
 *   was; no answer leaves both wraps, which open with the same password, until the next unlock settles them.
 * - The password is not kept for this: the caller awaits it inside the unlock, and nothing here holds it after.
 *
 * Choices the specification leaves to the client, written down: it runs inline, before the vault is shown (§7: an
 * interactive unlock SHOULD); a policy that cannot be read is the same as no connection; and nothing is retried within
 * the session, the next full-password unlock checks again.
 */
export type QuietReKey =
  /** Not a full-password unlock that reached the server: nothing was looked at. */
  | "not_counted"
  /** The policy could not be read: nothing was sent. */
  | "no_policy"
  /** No upgrade is due: nothing was derived or sent. */
  | "not_due"
  | "rekeyed"
  /** The change was refused or got no answer: nothing a person sees changes; the next unlock checks again. */
  | "failed";

export interface QuietReKeyInputs {
  readonly settings: SettingsSession;
  /** The master password the unlock just verified. */
  readonly password: string;
  /** How the vault was opened: only `full_password_online` counts. */
  readonly unlock: "full_password_online" | "offline_copy" | "read_only_copy";
  /** `GET /client-policy`, fetched now (never a value kept from earlier). */
  readonly policy: () => Promise<{ readonly kdfParams: KdfParams }>;
}

export async function quietReKey(i: QuietReKeyInputs): Promise<QuietReKey> {
  if (i.unlock !== "full_password_online") return "not_counted";
  const own = i.settings.wrap.current;
  if (own === null) return "not_counted";
  let policy: KdfParams;
  try {
    policy = (await i.policy()).kdfParams;
  } catch {
    return "no_policy";
  }
  if (!shouldUpgrade(own.kdfParams, policy)) return "not_due";
  try {
    const r = await changePassword(i.settings, i.password, i.password, policy, { onlyIfUpgrade: true });
    if (r.kind === "done") return "rekeyed";
    return r.kind === "refused" && r.code === REKEY_NOT_DUE ? "not_due" : "failed";
  } catch {
    return "failed";
  }
}
