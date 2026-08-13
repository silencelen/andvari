import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

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
 * cost; the web is the twin that didn't, so it now reuses their sentence verbatim.
 */
describe("App.signOut — a durable offline copy is itself a thing to lose", () => {
  const signOut = closure(appTsx, "signOut", "lockChannelRef");

  it("confirms on unsynced work OR a standing offline copy, not on unsynced work alone", () => {
    expect(signOut).toContain("const durableCopy = uid ? (await offlineCopyStamp(uid)) !== null : false;");
    expect(signOut).toContain('if (kind === "user" && (unsynced > 0 || durableCopy))');
    expect(signOut, "the unsynced-only gate is the audited defect").not.toContain('if (kind === "user" && unsynced > 0)');
  });

  it("uses the natives' sentence, so all three clients state the same cost", () => {
    expect(signOut).toContain(
      "Sign out of this device? This removes the vault copy and any unsynced changes from this device. You'll need your master password — and a connection to your server — to sign back in.",
    );
  });

  it("still names the unsynced count when there is one (breaker #9 — the queue dies with the cache)", () => {
    expect(signOut).toContain('unsynced > 0 ? ` ${unsynced} unsynced ${unsynced === 1 ? "change" : "changes"} will be permanently lost.` : ""');
  });

  it("only a USER sign-out can be blocked — expired/revoked cannot ask (spec 02 §8)", () => {
    expect(signOut).toContain('kind === "user" &&');
    expect(signOut).toContain("if (!ok) return;");
  });
});
