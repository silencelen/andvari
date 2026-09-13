import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { BUNDLE_EMPTY, BUNDLE_NOT_A_BUNDLE, checkRecoveryBundle } from "./recoverybundle";

/**
 * H24 (audit 2026-09-13): the escrow-recovery ceremony's final step — upload the recovery-cli
 * bundle (POST /admin/recovery) — had no surface in any shipped client while self-hosting.md
 * said "upload the result in the admin panel". The pre-flight verdicts are pinned here; the
 * wiring (the panel posts the CLI's bytes VERBATIM through ApiClient.adminRecovery) is pinned
 * on the source below and on the client in client.admin-recovery.test.ts.
 */

const USER = "11111111-2222-3333-4444-555555555555";
const bundle = (over: Record<string, unknown> = {}) =>
  JSON.stringify({
    userId: USER,
    tempAuthKey: "a",
    tempWrappedUvk: "w",
    tempKdfSalt: "s",
    tempKdfParams: { v: 1, alg: "argon2id13", ops: 3, memBytes: 67108864 },
    ...over,
  });

describe("checkRecoveryBundle — the admin panel's pre-flight for a recovery-cli bundle", () => {
  it("accepts the CLI's bundle and hands the TEXT back verbatim (trimmed), never re-serialized", () => {
    const text = "  " + JSON.stringify(JSON.parse(bundle()), null, 2) + "\n"; // the CLI pretty-prints + trailing newline
    const r = checkRecoveryBundle(text, USER);
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.text).toBe(text.trim()); // the pretty-printed bytes, not a compacted re-encode
  });

  it("empty input asks for the bundle by the file name the CLI writes", () => {
    expect(checkRecoveryBundle("   ", USER)).toEqual({ ok: false, reason: BUNDLE_EMPTY });
  });

  it("non-JSON, non-object and field-less input is 'not a bundle' — one sentence, naming the unedited file", () => {
    for (const bad of ["not json", "[]", "42", "{}", JSON.stringify({ userId: USER })]) {
      expect(checkRecoveryBundle(bad, USER), bad).toEqual({ ok: false, reason: BUNDLE_NOT_A_BUNDLE });
    }
  });

  it("PRC-1: tempKdfParams as a STRING (the shape that 400'd the ceremony) is refused up front", () => {
    expect(checkRecoveryBundle(bundle({ tempKdfParams: "{}" }), USER)).toEqual({ ok: false, reason: BUNDLE_NOT_A_BUNDLE });
    expect(checkRecoveryBundle(bundle({ tempKdfParams: null }), USER)).toEqual({ ok: false, reason: BUNDLE_NOT_A_BUNDLE });
  });

  it("a bundle for ANOTHER member is refused on this row — the server would accept any existing userId", () => {
    const other = "99999999-8888-7777-6666-555555555555";
    const r = checkRecoveryBundle(bundle({ userId: other }), USER);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toContain("different account");
    if (!r.ok) expect(r.reason).toContain(other.slice(0, 8));
  });
});

describe("Admin.tsx wires the upload (source pin — UserRows is a closure with no render seam here)", () => {
  const adminTsx = readFileSync(fileURLToPath(new URL("./Admin.tsx", import.meta.url)), "utf8");

  it("offers 'Apply recovery bundle' beside 'Download backstop key' and posts through adminRecovery", () => {
    expect(adminTsx).toContain("Download backstop key");
    expect(adminTsx).toContain("Apply recovery bundle");
    expect(adminTsx).toContain("onApplyRecovery={(text) => client.adminRecovery(text)}");
    // The pre-flight runs BEFORE the post, on the row's own userId.
    expect(adminTsx).toMatch(/checkRecoveryBundle\(bundleText, u\.userId\)/);
  });

  it("tells the admin to hand over the temporary password OUT OF BAND once the server says ok", () => {
    expect(adminTsx).toContain("out of band");
    expect(adminTsx).toContain("next sign-in forces a new master password");
  });
});
