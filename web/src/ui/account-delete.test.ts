import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it, vi } from "vitest";
import { AccountDeleteBlockedError, AccountDeleteUnknownError, ApiError } from "../api/client";
import type { AccountDeletePreview } from "../api/types";
import { ReauthFailedError, ReauthStaleSessionError } from "../vault/account";
import {
  ACCOUNT_DELETED_NOTICE,
  ACCOUNT_FORGOTTEN_NOTICE,
  afterCheck,
  afterOutcome,
  BLOCKED_UNEXPLAINED,
  blockerLines,
  checkDeletion,
  checkedResult,
  deleteErrorText,
  DELETION_MOST_LIKELY_DONE,
  deletionSummary,
  type DeletionWatch,
  type DeletionWatchEvent,
  emailConfirmed,
  IDLE_DELETION_WATCH,
  initialFlow,
  NOT_DELETED_AFTER_CHECK,
  OUTCOME_UNKNOWN,
  runAccountDeletion,
  SESSION_ENDED,
  SESSION_ENDED_OUTCOME_UNKNOWN,
  settledOutcome,
  stepDeletionWatch,
} from "./account-delete";
import { DeleteAccountBody, deleteFormReady, DeletionOutcomeUnknownCard, type DeleteAccountView } from "./DeleteAccount";
import { UNREACHABLE } from "./errors";

/**
 * Settings → Delete account (spec 03 §13; design 2026-11-10 §11): the flow's pure half — the typed-address check, the
 * blocker and consequence sentences, one error sentence per refusal, the submit's order (the password is proved LOCALLY
 * before anything is sent; the code rides only when the account needs one; a lost answer is "unknown", never a failure) —
 * and the card body as a static render (the repository's node-env UI posture: renderToStaticMarkup runs no effects).
 */

const V_FAMILY = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const V_TRIPS = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const V_PERSONAL = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
const V_KIDS = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
const names: Record<string, string> = { [V_FAMILY]: "Family", [V_TRIPS]: "Trips", [V_PERSONAL]: "Personal", [V_KIDS]: "Kids" };
const vaultName = (id: string): string | null => names[id] ?? null;

describe("emailConfirmed — the typed address, compared the way the server compares it", () => {
  it("matches trimmed and case-folded", () => {
    expect(emailConfirmed("  Me@Example.COM ", "me@example.com")).toBe(true);
    expect(emailConfirmed("me@example.org", "me@example.com")).toBe(false);
    expect(emailConfirmed("   ", "me@example.com")).toBe(false);
  });

  it("with no known address (an old session), any entry passes here and the server decides", () => {
    expect(emailConfirmed("whoever@x.com", "")).toBe(true);
    expect(emailConfirmed("", "")).toBe(false);
  });
});

describe("blockerLines — one sentence per blocker, with where to resolve it", () => {
  it("names an owned vault and links to its settings", () => {
    const [line] = blockerLines([{ kind: "shared_vault", vaultId: V_FAMILY, others: 2 }], vaultName);
    expect(line!.text).toBe("You own “Family”, and 2 other people still use it. Delete it, or make one of them its owner, first.");
    expect(line!.link).toEqual({ kind: "vault", vaultId: V_FAMILY });
    expect(line!.linkLabel).toBe("Open “Family” settings →");
  });

  it("still lists a vault this browser cannot name (no link to nowhere)", () => {
    const [line] = blockerLines([{ kind: "shared_vault", vaultId: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", others: 1 }], vaultName);
    expect(line!.text).toContain("You own a shared vault that 1 other person still uses");
    expect(line!.link).toBeNull();
  });

  it("explains the last-admin role and links to Administration", () => {
    const [line] = blockerLines([{ kind: "last_admin", others: 3 }], vaultName);
    expect(line!.text).toContain("You're the only admin of this andvari server, and 3 other people have accounts on it.");
    expect(line!.link).toEqual({ kind: "admin" });
  });

  it("says exactly that no existing account can be made an admin — only a new one invited as an admin resolves it", () => {
    const [line] = blockerLines([{ kind: "last_admin", others: 1 }], vaultName);
    expect(line!.text).toContain("1 other person has an account on it.");
    expect(line!.text).toContain("andvari can't make an existing account an admin — an account is an admin only if it was invited as one.");
    expect(line!.text).toContain("Invite a new admin first (Administration → Users → Invite a user, with “Admin” ticked, for an address that has no account yet)");
    // There is no promote route (spec 03 §11), so neither surface may point at a "make admin" control that does not exist.
    const admin = readFileSync(fileURLToPath(new URL("./Admin.tsx", import.meta.url)), "utf8");
    expect(admin).toContain("andvari can't make an existing account an admin: invite a new admin first");
    for (const text of [line!.text, admin]) expect(text).not.toMatch(/make (another|one of them|someone|a member) (account )?an admin/i);
  });

  it("an unknown kind is a blocker it cannot explain — listed, never dropped, in the server's order", () => {
    const lines = blockerLines([{ kind: "future_rule", others: 0 }, { kind: "shared_vault", vaultId: V_FAMILY, others: 1 }], vaultName);
    expect(lines).toHaveLength(2);
    expect(lines[0]!.text).toContain("can't explain");
    expect(lines[0]!.link).toBeNull();
    expect(lines[1]!.text).toContain("“Family”, and 1 other person still uses it");
  });
});

describe("deletionSummary — what goes for good, and what the member leaves", () => {
  const preview = (over: Partial<AccountDeletePreview> = {}): AccountDeletePreview => ({
    blockers: [],
    deletedVaults: [V_PERSONAL, V_TRIPS],
    leftVaults: [V_FAMILY],
    totpRequired: false,
    ...over,
  });

  it("names the personal vault and the solely held ones, and the vaults left behind", () => {
    const s = deletionSummary(preview(), vaultName, V_PERSONAL);
    expect(s.deletes[0]).toBe("Your account, and its sign-in on every device.");
    expect(s.deletes[1]).toBe("Your Personal vault and the vault only you use, “Trips” — every item, attachment and earlier version in them.");
    expect(s.deletes.some((l) => l.includes("recovery phrase") && l.includes("nobody, an admin included"))).toBe(true);
    expect(s.leaves).toEqual(["You'll leave “Family”. What you saved there stays for the people who still use it."]);
  });

  it("counts vaults it cannot name rather than hiding them", () => {
    const s = deletionSummary(preview({ deletedVaults: [V_PERSONAL, "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"], leftVaults: [V_FAMILY, V_KIDS, "ffffffff-ffff-4fff-8fff-ffffffffffff"] }), vaultName, V_PERSONAL);
    expect(s.deletes[1]).toContain("1 other vault only you hold");
    expect(s.leaves[0]).toBe("You'll leave “Family” and “Kids” and 1 other shared vault. What you saved there stays for the people who still use them.");
  });

  it("says nothing about leaving when there is nothing to leave", () => {
    expect(deletionSummary(preview({ leftVaults: [] }), vaultName, V_PERSONAL).leaves).toEqual([]);
  });
});

describe("deleteErrorText — one sentence per refusal, none of them claiming a deletion", () => {
  const api = (status: number, code: string) => new ApiError(status, code, "m");

  it("maps every refusal the route answers", () => {
    expect(deleteErrorText(new ReauthFailedError())).toBe("That master password isn't right.");
    expect(deleteErrorText(api(403, "reauth_failed"))).toBe("That master password isn't right.");
    expect(deleteErrorText(new ReauthStaleSessionError())).toBe("Lock and unlock andvari, then try again.");
    expect(deleteErrorText(api(400, "totp_code_required"))).toBe("Enter the code from your authenticator app.");
    expect(deleteErrorText(api(400, "bad_totp_code"))).toContain("wrong or was already used");
    expect(deleteErrorText(api(400, "confirm_email_mismatch"))).toBe("That isn't this account's email address.");
    expect(deleteErrorText(api(403, "account_delete_public_disabled"))).toContain("emergency address");
    expect(deleteErrorText(api(401, "credential_changed"))).toContain("nothing was deleted");
    expect(deleteErrorText(api(429, "rate_limited"))).toContain("Too many attempts");
    expect(deleteErrorText(api(401, "invalid_credentials"))).toContain("nothing was deleted");
    expect(deleteErrorText(new TypeError("Failed to fetch"))).toBe(UNREACHABLE);
    expect(deleteErrorText(api(500, "internal"))).toBe("Something went wrong and your account was not deleted — try again.");
  });
});

describe("runAccountDeletion — the submit", () => {
  const keys = { kdfSalt: "s", kdfParams: { v: 1, alg: "argon2id13", ops: 3, memBytes: 67_108_864 }, wrappedUvk: "w" };

  function fakes(opts: { reauth?: () => Promise<string>; del?: () => Promise<{ deletedAt: number }>; keys?: () => Promise<unknown> } = {}) {
    const order: string[] = [];
    const client = {
      accountKeys: vi.fn(async () => { order.push("keys"); return (opts.keys ? await opts.keys() : keys) as never; }),
      deleteAccount: vi.fn(async (req: unknown) => { order.push("delete"); void req; return opts.del ? opts.del() : { deletedAt: 7 }; }),
    };
    const account = { reauthAuthKey: vi.fn(async () => { order.push("reauth"); return opts.reauth ? opts.reauth() : "AUTHKEY"; }) };
    return { client, account, order };
  }

  it("proves the password locally first, then sends one request with the typed address and the code's digits", async () => {
    const f = fakes();
    const out = await runAccountDeletion(f.client, f.account, { email: "  me@x.com ", password: "pw", totp: "123 456", totpRequired: true });
    expect(out).toEqual({ kind: "deleted", deletedAt: 7 });
    expect(f.order).toEqual(["keys", "reauth", "delete"]);
    expect(f.account.reauthAuthKey).toHaveBeenCalledWith("pw", keys);
    expect(f.client.deleteAccount).toHaveBeenCalledWith({ confirmEmail: "me@x.com", currentAuthKey: "AUTHKEY", totp: "123456" });
  });

  it("sends no code when the account has none, whatever was typed", async () => {
    const f = fakes();
    await runAccountDeletion(f.client, f.account, { email: "me@x.com", password: "pw", totp: "999999", totpRequired: false });
    expect(f.client.deleteAccount).toHaveBeenCalledWith({ confirmEmail: "me@x.com", currentAuthKey: "AUTHKEY" });
  });

  it("a wrong password never reaches the server", async () => {
    const f = fakes({ reauth: async () => { throw new ReauthFailedError(); } });
    const out = await runAccountDeletion(f.client, f.account, { email: "me@x.com", password: "nope", totp: "", totpRequired: false });
    expect(out).toEqual({ kind: "error", message: "That master password isn't right." });
    expect(f.client.deleteAccount).not.toHaveBeenCalled();
  });

  it("a refusal with blockers comes back as blockers", async () => {
    const f = fakes({ del: async () => { throw new AccountDeleteBlockedError([{ kind: "last_admin", vaultId: null, others: 2 }]); } });
    expect(await runAccountDeletion(f.client, f.account, { email: "me@x.com", password: "pw", totp: "", totpRequired: false }))
      .toEqual({ kind: "blocked", blockers: [{ kind: "last_admin", vaultId: null, others: 2 }] });
  });

  it("a lost answer to the deletion itself is UNKNOWN — but a failure before it was sent is an ordinary error", async () => {
    const lost = fakes({ del: async () => { throw new TypeError("Failed to fetch"); } });
    expect(await runAccountDeletion(lost.client, lost.account, { email: "me@x.com", password: "pw", totp: "", totpRequired: false })).toEqual({ kind: "unknown" });
    const early = fakes({ keys: async () => { throw new TypeError("Failed to fetch"); } });
    expect(await runAccountDeletion(early.client, early.account, { email: "me@x.com", password: "pw", totp: "", totpRequired: false })).toEqual({ kind: "error", message: UNREACHABLE, unanswered: true });
    expect(early.client.deleteAccount).not.toHaveBeenCalled();
  });

  it("a 5xx or a reply that is not the server's is UNKNOWN too — never \"not deleted\"", async () => {
    const proxy = fakes({ del: async () => { throw new AccountDeleteUnknownError(502); } });
    expect(await runAccountDeletion(proxy.client, proxy.account, { email: "me@x.com", password: "pw", totp: "", totpRequired: false })).toEqual({ kind: "unknown" });
  });

  it("a 401 — on the request, or on the keys fetch before it — is session_gone, not an error sentence", async () => {
    const onDelete = fakes({ del: async () => { throw new ApiError(401, "invalid_credentials", "authentication failed"); } });
    expect(await runAccountDeletion(onDelete.client, onDelete.account, { email: "me@x.com", password: "pw", totp: "", totpRequired: false })).toEqual({ kind: "session_gone" });
    const onKeys = fakes({ keys: async () => { throw new ApiError(401, "invalid_credentials", "authentication failed"); } });
    expect(await runAccountDeletion(onKeys.client, onKeys.account, { email: "me@x.com", password: "pw", totp: "", totpRequired: false })).toEqual({ kind: "session_gone" });
    expect(onKeys.client.deleteAccount).not.toHaveBeenCalled();
  });

  it("onSend fires just before the request, and never when the password is refused locally", async () => {
    const sent: string[] = [];
    const ok = fakes();
    await runAccountDeletion(ok.client, ok.account, { email: "me@x.com", password: "pw", totp: "", totpRequired: false }, () => sent.push(ok.order.join(",")));
    expect(sent).toEqual(["keys,reauth"]);
    const wrong = fakes({ reauth: async () => { throw new ReauthFailedError(); } });
    await runAccountDeletion(wrong.client, wrong.account, { email: "me@x.com", password: "no", totp: "", totpRequired: false }, () => sent.push("sent"));
    expect(sent).toEqual(["keys,reauth"]);
  });

  it("a server refusal carries its code, so the card can tell 'a code is needed' from any other refusal", async () => {
    const f = fakes({ del: async () => { throw new ApiError(400, "totp_code_required", "a code is required"); } });
    expect(await runAccountDeletion(f.client, f.account, { email: "me@x.com", password: "pw", totp: "", totpRequired: false }))
      .toEqual({ kind: "error", message: "Enter the code from your authenticator app.", code: "totp_code_required" });
  });
});

describe("TOTP enrolled after the preview — the server asks for a code the card did not know about", () => {
  const start = initialFlow();
  const needCode = { kind: "error", message: "Enter the code from your authenticator app.", code: "totp_code_required" } as const;

  it("totp_code_required turns the code field on, with the sentence that asks for it", () => {
    expect(start.totpRequired).toBe(false);
    const s = afterOutcome(start, needCode);
    expect(s.totpRequired).toBe(true);
    expect(s.err).toBe("Enter the code from your authenticator app.");
  });

  it("no other refusal does, and once on it stays on (a wrong code next must not hide the field)", () => {
    for (const code of ["reauth_failed", "bad_totp_code", "confirm_email_mismatch", "rate_limited"]) {
      expect(afterOutcome(start, { kind: "error", message: "x", code }).totpRequired, code).toBe(false);
    }
    expect(afterOutcome(start, { kind: "error", message: "x" }).totpRequired).toBe(false);
    const on = afterOutcome(start, needCode);
    expect(afterOutcome(on, { kind: "error", message: "That code is wrong", code: "bad_totp_code" }).totpRequired).toBe(true);
    expect(afterOutcome(on, { kind: "unknown" }).totpRequired).toBe(true);
  });

  it("a check's fresh preview turns it on too", () => {
    const preview = { blockers: [], deletedVaults: [], leftVaults: [], totpRequired: true };
    expect(afterCheck(afterOutcome(start, { kind: "unknown" }), { kind: "still_here", preview }).totpRequired).toBe(true);
  });

  it("the card asks for the code when either the preview or the flow says so, and sends it on submit", () => {
    const card = readFileSync(fileURLToPath(new URL("./DeleteAccount.tsx", import.meta.url)), "utf8");
    expect(card).toContain("const totpRequired = flow.totpRequired || (preview?.totpRequired ?? false);");
    expect(card).toContain("runAccountDeletion(client, account, { email: typedEmail, password, totp, totpRequired },");
    expect(card).toContain("deleteFormReady({ typedEmail, accountEmail: email, password, totp, totpRequired })");
  });
});

describe("the card's flow after an answer — unknown is never \"not deleted\", and a 401 never says the account is gone", () => {
  const start = initialFlow();

  it("unknown is sticky, and a 401 after it says the account may still exist (App signs out, nothing is forgotten)", () => {
    const unknown = afterOutcome(start, { kind: "unknown" });
    expect(unknown.unknown).toBe(true);
    expect(unknown.err).toBe("");
    expect(afterOutcome(unknown, { kind: "session_gone" }).err).toBe(SESSION_ENDED_OUTCOME_UNKNOWN);
    expect(SESSION_ENDED_OUTCOME_UNKNOWN).toContain("can't tell whether your account was deleted");
  });

  it("a 401 with no unknown before it is the ordinary 'session ended' (refused before anything was deleted)", () => {
    expect(afterOutcome(start, { kind: "session_gone" }).err).toBe(SESSION_ENDED);
  });

  it("a definitive answer clears unknown; a failure that never reached the server does not", () => {
    const unknown = afterOutcome(start, { kind: "unknown" });
    expect(afterOutcome(unknown, { kind: "blocked", blockers: [{ kind: "last_admin", vaultId: null, others: 1 }] })).toMatchObject({ unknown: false, refused: [{ kind: "last_admin", vaultId: null, others: 1 }] });
    expect(afterOutcome(unknown, { kind: "error", message: "That master password isn't right.", code: "reauth_failed" })).toMatchObject({ unknown: false, err: "That master password isn't right." });
    expect(afterOutcome(unknown, { kind: "error", message: UNREACHABLE, unanswered: true })).toMatchObject({ unknown: true, err: UNREACHABLE });
  });

  it("the check: still here settles it; a 401 only ends the session; no answer changes nothing", () => {
    const unknown = afterOutcome(start, { kind: "unknown" });
    const preview = { blockers: [], deletedVaults: [], leftVaults: [], totpRequired: false };
    expect(afterCheck(unknown, { kind: "still_here", preview })).toMatchObject({ unknown: false, info: NOT_DELETED_AFTER_CHECK });
    expect(afterCheck(unknown, { kind: "session_ended" })).toMatchObject({ unknown: true, err: SESSION_ENDED_OUTCOME_UNKNOWN });
    expect(afterCheck(unknown, { kind: "unknown" })).toMatchObject({ unknown: true, err: UNREACHABLE });
  });
});

describe("checkDeletion — the preview answers 200 only while the account exists", () => {
  it("200 → still here; 401 → the session ended (NOT 'deleted'); anything else → still unknown", async () => {
    const preview = { blockers: [], deletedVaults: [], leftVaults: [], totpRequired: true };
    expect(await checkDeletion({ accountDeletePreview: async () => preview })).toEqual({ kind: "still_here", preview });
    expect(await checkDeletion({ accountDeletePreview: async () => { throw new ApiError(401, "invalid_credentials", "m"); } })).toEqual({ kind: "session_ended" });
    expect(await checkDeletion({ accountDeletePreview: async () => { throw new TypeError("Failed to fetch"); } })).toEqual({ kind: "unknown" });
    expect(await checkDeletion({ accountDeletePreview: async () => { throw new ApiError(502, "http_502", "m"); } })).toEqual({ kind: "unknown" });
  });
});

/**
 * App's side of the request (stepDeletionWatch): a session end that lands while the request is in flight is held, and
 * always acted on when it settles — never dropped; only such an end, with the answer lost, offers to forget the account.
 */
describe("stepDeletionWatch — a held session end is acted on, never dropped; Forget only for the deletion's own", () => {
  const A = "aaaaaaaa-0000-4000-8000-00000000000a"; // the account deleting itself
  const B = "bbbbbbbb-0000-4000-8000-00000000000b"; // another account signed in later in the same tab
  const run = (events: DeletionWatchEvent[], from: DeletionWatch = IDLE_DELETION_WATCH) => {
    let w = from;
    const actions = events.map((e) => {
      const r = stepDeletionWatch(w, e);
      w = r.watch;
      return r.action;
    });
    return { watch: w, actions, last: actions[actions.length - 1]! };
  };
  const revoked = (userId: string | null = A) => ({ kind: "session_end", end: "revoked", userId }) as const;
  const started = (userId = A) => ({ kind: "started", userId }) as const;
  const settled = (outcome: "deleted" | "refused" | "unsent" | "unknown" | "session_gone", userId = A) => ({ kind: "settled", outcome, userId }) as const;
  const checked = (result: "still_here" | "session_ended" | "unreachable", userId = A) => ({ kind: "checked", result, userId }) as const;
  const sessionStart = { kind: "session_start" } as const;

  it("idle, a session end is the ordinary sign-out", () => {
    expect(run([revoked()]).last).toEqual({ kind: "end_session", userId: A, end: "revoked" });
  });

  it("in flight it is held; the answer lost → the deletion's own revocation, most likely: offer to forget", () => {
    const r = run([started(), revoked(), settled("unknown")]);
    expect(r.actions[1], "held, not acted on yet").toEqual({ kind: "none" });
    expect(r.last).toEqual({ kind: "offer_forget", userId: A, end: "revoked" });
    expect(r.watch).toEqual(IDLE_DELETION_WATCH);
  });

  it("a revocation during an unknown outcome still ends the session — whichever comes first", () => {
    // The answer is lost first, then the revocation lands: it cannot be tied to the deletion → sign out, keep the records.
    expect(run([started(), settled("unknown"), revoked()]).last).toEqual({ kind: "end_session", userId: A, end: "revoked", notice: SESSION_ENDED_OUTCOME_UNKNOWN });
    // The revocation lands first and the request then times out (unknown): it is acted on, not dropped.
    expect(run([started(), revoked(), settled("unknown")]).last.kind).toBe("offer_forget");
  });

  it("the server refused (nothing deleted): a held end was real → the ordinary sign-out; no end → nothing", () => {
    expect(run([started(), revoked(), settled("refused")]).last).toEqual({ kind: "end_session", userId: A, end: "revoked" });
    expect(run([started(), settled("refused")]).last).toEqual({ kind: "none" });
    // …and the refusal proves the account exists, so a later end is ordinary again.
    expect(run([started(), settled("unknown"), started(), settled("refused"), revoked()]).last).toEqual({ kind: "end_session", userId: A, end: "revoked" });
  });

  it("a 401 on the request ends the session: 'nothing was deleted', or — after an unknown outcome — 'can't tell'", () => {
    expect(run([started(), settled("session_gone")]).last).toEqual({ kind: "end_session", userId: A, end: "expired", notice: SESSION_ENDED });
    expect(run([started(), settled("unknown"), started(), settled("session_gone")]).last).toEqual({ kind: "end_session", userId: A, end: "expired", notice: SESSION_ENDED_OUTCOME_UNKNOWN });
    expect(run([started(), revoked(), settled("session_gone")]).last).toEqual({ kind: "end_session", userId: A, end: "revoked" });
  });

  it("after an unknown outcome, a 401 on the check never offers to forget — the account may still exist", () => {
    const r = run([started(), settled("unknown"), checked("session_ended")]);
    expect(r.last).toEqual({ kind: "end_session", userId: A, end: "expired", notice: SESSION_ENDED_OUTCOME_UNKNOWN });
    expect(r.actions.some((a) => a.kind === "offer_forget")).toBe(false);
    expect(run([started(), settled("unknown"), started(), settled("session_gone")]).actions.some((a) => a.kind === "offer_forget")).toBe(false);
  });

  it("the check finding the account still here settles the unknown; an unreachable check changes nothing", () => {
    expect(run([started(), settled("unknown"), checked("still_here"), revoked()]).last).toEqual({ kind: "end_session", userId: A, end: "revoked" });
    expect(run([started(), settled("unknown"), checked("unreachable")]).watch.unknown).toBe(true);
  });

  it("a request that never reached the server learns nothing: an earlier unknown stands", () => {
    expect(run([started(), settled("unknown"), settled("unsent")]).watch.unknown).toBe(true);
  });

  it("the hold expires if no settle ever arrives: a held end is then acted on like a lost answer", () => {
    expect(run([started(), revoked(), { kind: "hold_expired" }]).last).toEqual({ kind: "offer_forget", userId: A, end: "revoked" });
    const none = run([started(), { kind: "hold_expired" }]);
    expect(none.last).toEqual({ kind: "none" });
    expect(none.watch).toEqual({ userId: A, inFlight: false, held: null, unknown: true });
    expect(run([{ kind: "hold_expired" }]).last, "nothing in flight: nothing to expire").toEqual({ kind: "none" });
  });

  it("the deletion confirmed: nothing for the watch to do (App's wipe takes over)", () => {
    expect(run([started(), revoked(), settled("deleted")])).toMatchObject({ last: { kind: "none" }, watch: IDLE_DELETION_WATCH });
  });

  it("a new session clears an outcome nothing settled — the next session's ordinary end never says 'can't tell'", () => {
    // Unknown, then the tab locks or signs out, and a session begins again — the same account or another.
    expect(run([started(), settled("unknown"), sessionStart, revoked(A)]).last).toEqual({ kind: "end_session", userId: A, end: "revoked" });
    expect(run([started(), settled("unknown"), sessionStart, revoked(B)]).last).toEqual({ kind: "end_session", userId: B, end: "revoked" });
    expect(run([started(), settled("unknown"), sessionStart]).watch).toEqual(IDLE_DELETION_WATCH);
    // A request still in flight keeps its watch (its own settle consumes it).
    expect(run([started(), sessionStart]).watch).toEqual({ userId: A, inFlight: true, held: null, unknown: false });
  });

  it("an end of another account is never held, never 'can't tell', never routed to the old account's Forget", () => {
    // A's request is in flight (the tab locked meanwhile, say); B signs in and B's session ends.
    const r = run([started(A), sessionStart, revoked(B)]);
    expect(r.last, "B's end is B's ordinary sign-out, at once").toEqual({ kind: "end_session", userId: B, end: "revoked" });
    expect(r.watch.held, "nothing held for A").toBeNull();
    // A's request then ends without an answer: nothing of B's is carried into A's Forget.
    expect(stepDeletionWatch(r.watch, settled("unknown", A)).action).toEqual({ kind: "none" });
    // After A's unknown outcome, B's end is never worded "can't tell"; nor is an end of a session this tab cannot name.
    expect(run([started(A), settled("unknown", A), revoked(B)]).last).toEqual({ kind: "end_session", userId: B, end: "revoked" });
    expect(run([started(A), revoked(null), settled("unknown", A)]).actions).toEqual([
      { kind: "none" },
      { kind: "end_session", userId: null, end: "revoked" },
      { kind: "none" },
    ]);
  });

  it("a stale watch of another account gives way to this account's request", () => {
    const r = run([started(A), settled("unknown", A), started(B), revoked(B), settled("unknown", B)]);
    expect(r.last, "B's own held end, B's own Forget").toEqual({ kind: "offer_forget", userId: B, end: "revoked" });
  });

  it("maps the card's outcomes and checks onto settles", () => {
    expect(settledOutcome({ kind: "deleted", deletedAt: 1 })).toBe("deleted");
    expect(settledOutcome({ kind: "blocked", blockers: [] })).toBe("refused");
    expect(settledOutcome({ kind: "error", message: "x", code: "reauth_failed" })).toBe("refused");
    expect(settledOutcome({ kind: "error", message: "x" }), "a local refusal after the keys fetch answered").toBe("refused");
    expect(settledOutcome({ kind: "error", message: UNREACHABLE, unanswered: true })).toBe("unsent");
    expect(settledOutcome({ kind: "unknown" })).toBe("unknown");
    expect(settledOutcome({ kind: "session_gone" })).toBe("session_gone");
    expect(checkedResult({ kind: "unknown" })).toBe("unreachable");
    expect(checkedResult({ kind: "session_ended" })).toBe("session_ended");
  });
});

describe("deleteFormReady", () => {
  const base = { typedEmail: "me@x.com", accountEmail: "me@x.com", password: "pw", totp: "", totpRequired: false };
  it("needs the matching address, a password, and six digits when a code is required", () => {
    expect(deleteFormReady(base)).toBe(true);
    expect(deleteFormReady({ ...base, typedEmail: "you@x.com" })).toBe(false);
    expect(deleteFormReady({ ...base, password: "" })).toBe(false);
    expect(deleteFormReady({ ...base, totpRequired: true, totp: "12 34" })).toBe(false);
    expect(deleteFormReady({ ...base, totpRequired: true, totp: "123 456" })).toBe(true);
  });
});

describe("DeleteAccountBody — static render", () => {
  const view = (over: Partial<DeleteAccountView> = {}): DeleteAccountView => ({
    open: true,
    loading: false,
    previewError: "",
    summary: { deletes: ["Your account, and its sign-in on every device."], leaves: ["You'll leave “Family”."] },
    blockers: null,
    totpRequired: false,
    typedEmail: "",
    password: "",
    totp: "",
    canSubmit: false,
    busy: false,
    err: "",
    info: "",
    unknownOutcome: false,
    checking: false,
    ...over,
  });
  const noop = () => {};
  const render = (v: DeleteAccountView, withBackup = true) =>
    renderToStaticMarkup(
      createElement(DeleteAccountBody, {
        view: v, onOpen: noop, onCancel: noop, onTypedEmail: noop, onPassword: noop, onTotp: noop, onSubmit: noop, onLink: noop,
        onCheck: noop, onBackup: withBackup ? noop : undefined,
      }),
    );

  it("closed: one paragraph and one button, no form", () => {
    const html = render(view({ open: false }));
    expect(html).toContain("Delete my account…");
    expect(html).not.toContain('type="password"');
  });

  it("open: says what goes, what is left, that it can't be undone, and offers a backup first", () => {
    const html = render(view());
    expect(html).toContain("Deleting your account removes, for good:");
    expect(html).toContain("You&#x27;ll leave “Family”.");
    expect(html).toContain("This can&#x27;t be undone.");
    expect(html).toContain("Back up your vault first");
    expect(html).toContain("Type your email address to confirm");
    expect(html).toContain('type="password"');
    expect(html, "no code field when the account has none").not.toContain("authenticator");
    expect(html).toMatch(/<button type="submit"[^>]*disabled=""[^>]*>Delete my account permanently/);
  });

  it("asks for the code when the account has TOTP, and enables the button only when ready", () => {
    const html = render(view({ totpRequired: true, canSubmit: true }));
    expect(html).toContain("Code from your authenticator app");
    expect(html).toMatch(/<button type="submit"[^>]*>Delete my account permanently/);
    expect(html).not.toMatch(/<button type="submit"[^>]*disabled/);
  });

  it("with blockers: lists each with its link and offers NO form", () => {
    const lines = blockerLines([{ kind: "shared_vault", vaultId: V_FAMILY, others: 2 }, { kind: "last_admin", others: 1 }], vaultName);
    const html = render(view({ blockers: lines }));
    expect(html).toContain("Your account can&#x27;t be deleted yet:");
    expect(html).toContain("Open “Family” settings →");
    expect(html).toContain("Open Administration →");
    expect(html).not.toContain('type="password"');
    expect(html).not.toContain("Delete my account permanently");
  });

  it("a refusal that named nothing still renders as blocked", () => {
    const html = render(view({ blockers: [] }));
    expect(html).toContain(BLOCKED_UNEXPLAINED.replace(/'/g, "&#x27;"));
    expect(html).not.toContain('type="password"');
  });

  it("an unknown outcome says so, offers the check, and keeps the form for a retry — it never says \"not deleted\"", () => {
    const html = render(view({ unknownOutcome: true }));
    expect(html).toContain("didn&#x27;t answer in a way that says whether your account was deleted");
    expect(html).toContain("Check whether it went through");
    expect(html).toContain('type="password"');
    expect(html).not.toContain("not deleted");
    expect(render(view({ previewError: "Couldn't check" }))).toContain("Couldn&#x27;t check");
    expect(OUTCOME_UNKNOWN).toContain("reload andvari and sign in");
  });

  it("the card itself never offers to forget the account (only App's card does, for the deletion's own session end)", () => {
    for (const v of [view({ unknownOutcome: true }), view({ unknownOutcome: true, err: SESSION_ENDED_OUTCOME_UNKNOWN })]) {
      expect(render(v)).not.toContain("Forget this account");
    }
  });

  it("App's outcome-unknown card: the deletion most likely went through — forget it here, or sign in to check", () => {
    const html = renderToStaticMarkup(createElement(DeletionOutcomeUnknownCard, { notice: "2 offline changes could not be synced.", onForget: noop, onSignIn: noop }));
    expect(html).toContain(DELETION_MOST_LIKELY_DONE.replace(/'/g, "&#x27;"));
    expect(DELETION_MOST_LIKELY_DONE).toContain("most likely went through");
    expect(html).toContain("Forget this account on this browser");
    expect(html).toContain("Sign in to check");
    expect(html).toContain("2 offline changes could not be synced.");
    expect(html, "no decrypted vault, no form").not.toContain('type="password"');
  });

  it("the check's 'still here' is said as information", () => {
    expect(render(view({ info: NOT_DELETED_AFTER_CHECK }))).toContain("Your account is still here");
  });
});

/**
 * The hand-offs, pinned on the source (the signout-revoke idiom: these are closures inside large views with no seam to
 * render in this node env). The card submits only through runAccountDeletion (so the password is proved locally first);
 * App's handler wipes through wipeLocalAccountState and lands on the deletion notice; Vault hands Settings the handler.
 */
describe("wiring", () => {
  const read = (p: string) => readFileSync(fileURLToPath(new URL(p, import.meta.url)), "utf8");

  it("the card never calls client.deleteAccount itself — only runAccountDeletion does", () => {
    const card = read("./DeleteAccount.tsx");
    expect(card).toContain("runAccountDeletion(client, account,");
    expect(card).not.toContain("client.deleteAccount(");
  });

  it("App wipes this browser's state for the account and lands signed out with the deletion notice", () => {
    const app = read("./App.tsx");
    const start = app.indexOf("const onAccountDeleted = useCallback(");
    expect(start, "App.onAccountDeleted moved — update the pin").toBeGreaterThan(-1);
    const body = app.slice(start, app.indexOf("}, []);", start));
    expect(body).toContain("wipeLocalAccountState(userId, email)");
    expect(body).toContain("setTokens(null)");
    expect(body).toContain("clearBreachCache()");
    expect(body).toContain('notice: end === "confirmed" ? ACCOUNT_DELETED_NOTICE : ACCOUNT_FORGOTTEN_NOTICE');
    expect(body.indexOf("wipeLocalAccountState"), "the session is cleared before the pair is dropped").toBeLessThan(body.indexOf("setTokens(null)"));
    expect(body).toContain("deletedAccountRef.current = userId");
    expect(app).toContain("onAccountDeleted={(end) => onAccountDeleted(deletingUserId, vaultEmail, end)}");
    expect(ACCOUNT_DELETED_NOTICE).toContain("account was deleted");
    expect(ACCOUNT_FORGOTTEN_NOTICE, "a forgotten account may, rarely, still exist — the notice says so").toContain("if it still exists");
  });

  it("every session end goes through the deletion watch; its actions sign out or offer to forget; the hold is bounded", () => {
    const app = read("./App.tsx");
    expect(app).toContain('const onRevoked = useCallback((kind: SessionEndKind) => stepDeletion({ kind: "session_end", end: kind, userId: liveUserId() }), [stepDeletion]);');
    const step = app.slice(app.indexOf("const stepDeletion = useCallback("), app.indexOf("const onRevoked = useCallback("));
    expect(step).toContain("stepDeletionWatch(deletionWatchRef.current, e)");
    expect(step).toContain("if (!watch.inFlight) clearDeletionHold();");
    const act = app.slice(app.indexOf("const applyDeletionAction = useCallback("), app.indexOf("const stepDeletion = useCallback("));
    expect(act, "an action applies only to the account whose session this tab holds now").toContain('if (a.kind === "none" || a.userId === null || a.userId !== liveUserId()) return;');
    expect(act).toContain("endSession(a.end, a.notice);");
    expect(act, "offer_forget: the session is wiped and App lands on the outcome-unknown card").toContain("void signOut(undefined, a.end, { userId: a.userId,");
    const live = app.slice(app.indexOf("const liveUserId = (): string | null => {"), app.indexOf("const applyDeletionAction = useCallback("));
    expect(live).toContain('return p.kind === "vault" ? p.account.userId : p.kind === "unlock" ? p.session.userId : null;');
    const track = app.slice(app.indexOf("const onDeletionTrack = useCallback("));
    expect(track).toContain('stepDeletion({ kind: "hold_expired" });');
    expect(track).toContain("}, DELETION_HOLD_LIMIT_MS);");
    expect(track, "the card's events carry the account they are for").toContain("stepDeletion({ ...event, userId: who.userId });");
    const unlocked = app.slice(app.indexOf("const onUnlocked = (account: Account"), app.indexOf("setPhase({ kind: \"vault\", account, store, meta });"));
    expect(unlocked, "a new session clears the watch unless a request is in flight").toContain('stepDeletion({ kind: "session_start" });');
    expect(app).toContain("onDeletionTrack={(event) => onDeletionTrack(event, { userId: deletingUserId, email: vaultEmail })}");
    expect(app).toContain('onForget={() => onAccountDeleted(p.userId, p.email, "forgotten")}');
    const card = read("./DeleteAccount.tsx");
    expect(card, "the card reports the request's start just before the POST").toContain('onTrack?.({ kind: "started" });');
    expect(card).toContain('onTrack?.({ kind: "settled", outcome: settledOutcome(outcome) });');
    expect(card, "a request App was told about always reports its end").toContain('if (started && !settled) onTrack?.({ kind: "settled", outcome: "unknown" });');
    expect(card).toContain('onTrack?.({ kind: "checked", result: checkedResult(c) });');
  });

  it("a sign-out the server's revoked frame started concurrently leaves the landing to the deletion", () => {
    const app = read("./App.tsx");
    const start = app.indexOf("const signOut = useCallback(");
    const body = app.slice(start, app.indexOf("}, []);", start));
    const guard = body.indexOf("if (uid !== null && deletedAccountRef.current === uid) return;");
    expect(guard, "signOut's deletion guard moved — update the pin").toBeGreaterThan(-1);
    expect(guard, "…and it sits before the sign-out's own landing").toBeLessThan(body.lastIndexOf("setPhase("));
  });

  it("Vault hands Settings the deletion handler and the blocker links", () => {
    const vault = read("./Vault.tsx");
    expect(vault).toContain("onAccountDeleted={onAccountDeleted}");
    expect(vault).toContain("onDeletionTrack={onDeletionTrack}");
    expect(vault).toContain("setSharingSettingsVaultId(vaultId)");
    expect(read("./Settings.tsx")).toContain("<DeleteAccountCard");
  });
});
