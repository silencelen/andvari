import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { SIGN_OUT_QUESTION, signOutQuestion } from "./SignOutLink";

/**
 * bug-web--0 (polish audit 2026-07-27): the revocation HELPER is unit-tested in session.test.ts,
 * but it only fixes the bug where it is CALLED — and its whole contract is positional (issue the
 * POST while the token pair is still held, i.e. before the teardown) and conditional (user
 * sign-out only; lock deliberately keeps the session, spec 05 T3). Neither survives a refactor
 * that a helper test would notice. Pinned on the source (the trash-purge/vault-copy idiom) —
 * these are component closures with no seam to call.
 */

const here = (p: string) => fileURLToPath(new URL(p, import.meta.url));
const appTsx = readFileSync(here("./App.tsx"), "utf8");
const welcomeTsx = readFileSync(here("./Welcome.tsx"), "utf8");

/** Source of a `const <name> = useCallback(…)` closure, sliced to the next top-level const. */
function closure(src: string, name: string, until: string): string {
  const start = src.indexOf(`const ${name} = useCallback`);
  expect(start, `${name} moved or is no longer a useCallback — update the pin`).toBeGreaterThan(-1);
  const end = src.indexOf(`const ${until} = `, start);
  expect(end, `${until} moved — update the pin`).toBeGreaterThan(start);
  return src.slice(start, end);
}

describe("App.signOut — revokes before the local teardown, and only for a USER sign-out", () => {
  const signOut = closure(appTsx, "signOut", "lockChannelRef");

  it("routes the user sign-out through revokeSessionBestEffort", () => {
    expect(signOut).toContain("revokeSessionBestEffort(clientRef.current)");
  });

  it("gates it on kind === \"user\" — an expired/revoked session is already dead server-side", () => {
    expect(signOut).toMatch(/if \(kind === "user"\) await revokeSessionBestEffort\(/);
  });

  it("issues it BEFORE the teardown — logout() reads the pair synchronously at call time", () => {
    expect(signOut.indexOf("revokeSessionBestEffort(")).toBeLessThan(signOut.indexOf("clearSession()"));
    expect(signOut.indexOf("revokeSessionBestEffort(")).toBeLessThan(signOut.indexOf("setTokens(null)"));
  });
});

/**
 * Audit H33 named a web sign-out seam where the usage flush would run after the revocation. At
 * HEAD there is no such seam: Vault exposes NO sign-out control — its only App.signOut route is
 * `onRevoked` (a session already dead server-side, where no flush can land) — so a USER sign-out
 * is reachable only from the Unlock card, AFTER a lock has unmounted Vault and its unmount flush
 * has run with the tokens still held (a lock keeps them, spec 05 T3). The ledger's teardown flush
 * therefore always precedes the revocation on web without any sign-out hook. Pinned so that the
 * day someone adds a "Sign out" control to Vault, this test names the flush-before-revoke rule
 * (the G03/H33 shape on the natives and the extension) as the thing that control must honour.
 */
describe("App.signOut — the usage-ledger flush cannot be revoked out from under it (H33)", () => {
  const vaultTsx = readFileSync(here("./Vault.tsx"), "utf8");

  it("Vault has no sign-out seam — its Props expose onLock and onRevoked only", () => {
    const props = vaultTsx.slice(vaultTsx.indexOf("interface Props {"), vaultTsx.indexOf("export function Vault("));
    expect(props).toContain("onLock: () => void;");
    expect(props).toContain("onRevoked: (kind: SessionEndKind) => void;");
    expect(props).not.toMatch(/onSignOut|onForget/);
  });

  it("the Vault unmount flushes the usage buffer BEFORE dispose, on a lock that keeps the tokens", () => {
    expect(vaultTsx).toContain("void usage.flush().finally(() => usage.dispose());");
    // App's lock keeps the persisted session + tokens (the "never revokes" pins below), so this
    // unmount flush rides a live pair; the user sign-out on the Unlock card comes after it.
    expect(closure(appTsx, "lockLocal", "lock")).not.toContain("setTokens(null)");
  });
});

describe("App lock — never revokes", () => {
  it("the lock path keeps the session server-side (spec 05 T3)", () => {
    // Locking drops this tab's KEYS only; the persisted session and its tokens survive so the
    // user comes back through the master-password-only Unlock card. Revoking here would turn
    // every auto-lock into a full sign-out on every device.
    expect(closure(appTsx, "lockLocal", "lock")).not.toContain("revokeSessionBestEffort");
    expect(closure(appTsx, "lock", "onRevoked")).not.toContain("revokeSessionBestEffort");
  });
});

describe("Welcome's two sign-out teardowns — the paths App.signOut cannot reach", () => {
  const calls = [...welcomeTsx.matchAll(/void revokeSessionBestEffort\(client\);/g)];

  it("both the capture-gate sign-out and the reveal idle-timeout revoke", () => {
    // (1) signOutOfCapture — sign-out from the recovery-capture gate; (2) the RecoveryReveal
    // auto-lock expiry, which is a full sign-out of a session already saved at register.
    expect(calls).toHaveLength(2);
  });

  it("each fires before its own clearSession()/setTokens(null)", () => {
    for (const m of calls) {
      const after = welcomeTsx.slice(m.index!, m.index! + 240);
      expect(after).toContain("clearSession();");
      expect(after).toContain("client.setTokens(null);");
    }
  });
});

/**
 * Audit F07: the sign-out confirm fired ONLY when unsynced work existed, so a fully-synced device
 * took the whole destructive §E.4 path — session cleared, offline copy deleteDatabase'd — off one
 * click of "Sign out / use a different account", a control that reads like an account switcher.
 * Offline (train, outage, server down) that leaves the member unable to open their vault at all,
 * with no dialog and no warning. Both natives already confirmed unconditionally and named the
 * cost; the web is the twin that didn't, so it reuses their sentence verbatim.
 *
 * H135 (audit 2026-09-13) kept that gate and moved the ASKING out of App.signOut into the control
 * itself: `window.confirm` was the last native dialog in an app whose every other destructive
 * action arms an inline two-step confirm (the Editor's own comment: "house style — no native
 * dialogs"), it is unthemed and tab-blocking, and it cannot reach the persistent Announcer a
 * screen-reader user is listening to. So the gate now lives in SignOutLink, which BOTH user
 * sign-out seams (the Unlock card and the recovery-capture gate) render; App.signOut is the
 * unconditional wipe choke point. These pin all three legs — the probes, the sentence, and the
 * fact that nothing raises a dialog any more.
 */
describe("H135 — the sign-out confirm is the inline arm, and App.signOut raises no dialog", () => {
  const signOutLink = readFileSync(here("./SignOutLink.tsx"), "utf8");

  it("App.tsx CALLS no window.confirm (prose may still name the retired dialog)", () => {
    expect(appTsx).not.toMatch(/window\.confirm\s*\(/);
  });

  it("both user sign-out seams go through SignOutLink — nothing calls onForget()/onSignOut raw", () => {
    expect(welcomeTsx).toContain("<SignOutLink userId={session.userId} onSignOut={() => onForget()} />");
    expect(welcomeTsx).toContain("<SignOutLink userId={account.userId} onSignOut={onSignOut} />");
    // The old bare links are gone: a raw link would wipe with no confirm at all now.
    expect(welcomeTsx).not.toMatch(/className="link" onClick=\{\(\) => onForget\(\)\}/);
    expect(welcomeTsx).not.toMatch(/className="link" onClick=\{onSignOut\}/);
  });

  it("the armed label is the extension popup's, so both browser surfaces read identically", () => {
    expect(signOutLink).toContain('"Sign out? Click again to confirm"');
  });

  it("confirms on unsynced work OR a standing offline copy, not on unsynced work alone", async () => {
    // No queue, but a durable copy on the device: still a thing to lose ⇒ still asks.
    expect(await signOutQuestion("u1", { queued: async () => 0, durable: async () => true })).toBe(SIGN_OUT_QUESTION);
    // Neither ⇒ one click, no confirm (the pre-F07 behaviour, kept for the device with nothing at stake).
    expect(await signOutQuestion("u1", { queued: async () => 0, durable: async () => false })).toBeNull();
  });

  it("uses the natives' sentence, so all three clients state the same cost", () => {
    expect(SIGN_OUT_QUESTION).toBe(
      "Sign out of this device? This removes the vault copy and any unsynced changes from this device. You'll need your master password — and a connection to your server — to sign back in.",
    );
  });

  it("still names the unsynced count when there is one (breaker #9 — the queue dies with the cache)", async () => {
    expect(await signOutQuestion("u1", { queued: async () => 1, durable: async () => false })).toContain(
      "1 unsynced change will be permanently lost.",
    );
    expect(await signOutQuestion("u1", { queued: async () => 4, durable: async () => true })).toContain(
      "4 unsynced changes will be permanently lost.",
    );
  });

  it("a FAILED probe asks rather than wipes — not knowing is a reason to confirm", async () => {
    const boom = async (): Promise<never> => {
      throw new Error("idb closed");
    };
    expect(await signOutQuestion("u1", { queued: boom, durable: async () => false })).toBe(SIGN_OUT_QUESTION);
    expect(await signOutQuestion("u1", { queued: async () => 0, durable: boom })).toBe(SIGN_OUT_QUESTION);
  });

  it("no session id ⇒ nothing persisted to lose ⇒ no question", async () => {
    expect(await signOutQuestion(null)).toBeNull();
  });
});
