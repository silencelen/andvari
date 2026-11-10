import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it, vi } from "vitest";
import { AccountDeleteBlockedError, ApiError } from "../api/client";
import type { AccountDeletePreview } from "../api/types";
import { ReauthFailedError, ReauthStaleSessionError } from "../vault/account";
import {
  ACCOUNT_DELETED_NOTICE,
  BLOCKED_UNEXPLAINED,
  blockerLines,
  deleteErrorText,
  deletionSummary,
  emailConfirmed,
  OUTCOME_UNKNOWN,
  runAccountDeletion,
} from "./account-delete";
import { DeleteAccountBody, deleteFormReady, type DeleteAccountView } from "./DeleteAccount";
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
    expect(line!.text).toContain("Invite someone as an admin first");
    expect(line!.link).toEqual({ kind: "admin" });
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
    expect(await runAccountDeletion(early.client, early.account, { email: "me@x.com", password: "pw", totp: "", totpRequired: false })).toEqual({ kind: "error", message: UNREACHABLE });
    expect(early.client.deleteAccount).not.toHaveBeenCalled();
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
    unknownOutcome: false,
    ...over,
  });
  const noop = () => {};
  const render = (v: DeleteAccountView, withBackup = true) =>
    renderToStaticMarkup(
      createElement(DeleteAccountBody, {
        view: v, onOpen: noop, onCancel: noop, onTypedEmail: noop, onPassword: noop, onTotp: noop, onSubmit: noop, onLink: noop,
        onBackup: withBackup ? noop : undefined,
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

  it("says when the outcome is unknown, and shows a preview failure", () => {
    expect(render(view({ unknownOutcome: true }))).toContain("doesn&#x27;t know whether your account was deleted");
    expect(render(view({ previewError: "Couldn't check" }))).toContain("Couldn&#x27;t check");
    expect(OUTCOME_UNKNOWN).toContain("Reload andvari and sign in");
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
    expect(body).toContain("notice: ACCOUNT_DELETED_NOTICE");
    expect(body.indexOf("wipeLocalAccountState"), "the session is cleared before the pair is dropped").toBeLessThan(body.indexOf("setTokens(null)"));
    expect(body).toContain("deletedAccountRef.current = userId");
    expect(app).toContain("onAccountDeleted={() => onAccountDeleted(deletingUserId, vaultEmail)}");
    expect(ACCOUNT_DELETED_NOTICE).toContain("account was deleted");
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
    expect(vault).toContain("setSharingSettingsVaultId(vaultId)");
    expect(read("./Settings.tsx")).toContain("<DeleteAccountCard");
  });
});
