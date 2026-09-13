import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

/**
 * H06 (audit 2026-09-13): the web Sharing screen is the ONLY production caller of member removal
 * on any client (Android/desktop have no member management), and it called the route with no
 * body — so the spec 03 §11 removal proof, whose minting helper existed and was vector-pinned,
 * was wired to nothing, and every legitimate removal reached the removed member as the
 * "server may be misbehaving" anomaly. The mint itself is tested against the real crypto in
 * store.lifecycle.test.ts; what has to hold HERE is the call site: the screen's remove closure
 * goes through store.removeVaultMember (which mints) and never through the bodyless client
 * method. Pinned on the source (the signout-revoke idiom) — MemberPanel is a closure inside a
 * ~1000-line view with no seam to render in this node env.
 */
const src = readFileSync(fileURLToPath(new URL("./Sharing.tsx", import.meta.url)), "utf8");

describe("Sharing.tsx member removal carries the spec 03 §11 removal proof", () => {
  it("removes through store.removeVaultMember (mints nonce + proof), never the bodyless client call", () => {
    const start = src.indexOf("const remove = (userId: string) =>");
    expect(start, "MemberPanel.remove moved — update the pin").toBeGreaterThan(-1);
    const end = src.indexOf("const pending = ", start);
    const closure = src.slice(start, end);
    expect(closure).toContain("store.removeVaultMember(vault.vaultId, userId)");
    expect(src, "a bodyless client.removeVaultMember from the UI re-opens H06").not.toContain("client.removeVaultMember(");
  });
});
