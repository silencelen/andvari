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
