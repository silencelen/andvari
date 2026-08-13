import { describe, expect, it } from "vitest";
import type { ItemDoc } from "../api/types";
import type { VaultItem } from "../vault/store";
import { duplicateClusters, siteKeysOf } from "./duplicates";

/**
 * Duplicate-entry checker pins (owner-requested 2026-08-12; ROADMAP P6). The clustering, the
 * exact/differs verdict, the fail-closed survivor choice and the composed merge doc are all
 * decided in the pure module — pin them here so Health.tsx stays a dumb renderer/writer.
 */

let seq = 0;
const login = (
  itemId: string,
  over: Partial<NonNullable<ItemDoc["login"]>> & { uris?: string[] } = {},
  docOver: Partial<ItemDoc> = {},
  updatedAt = ++seq,
): VaultItem => ({
  itemId,
  vaultId: "v1",
  rev: 1,
  updatedAt,
  formatVersion: 1,
  doc: {
    type: "login",
    name: itemId,
    login: { username: "u@example.com", password: "hunter2", uris: ["https://example.com"], ...over },
    ...docOver,
  },
});

describe("siteKeysOf — the registrable-domain site key", () => {
  it("keys by eTLD+1 (subdomains collapse), falls back to the host for unresolvable ones, and keeps app packages distinct", () => {
    const keys = siteKeysOf({
      type: "login",
      name: "x",
      // "not a uri" survives as its own key DELIBERATELY: parseSavedUri is the autofill
      // matching authority and it tolerates free-text hosts — two copies saved with the same
      // free-text uri are the same "site" to matching, so they are to the checker too.
      login: { uris: ["https://accounts.example.com/login", "http://192.168.1.10:8443", "androidapp://com.example.app", "not a uri", ""] },
    });
    expect(keys).toEqual(new Set(["example.com", "192.168.1.10", "app:com.example.app", "not a uri"]));
  });
});

describe("duplicateClusters — grouping and the exact/differs verdict", () => {
  it("clusters same site + same normalized username; different usernames and different sites stay apart", () => {
    const clusters = duplicateClusters([
      login("a"),
      login("b", { username: " U@Example.com " }), // normalization joins; display keeps the raw string
      login("c", { username: "other@example.com" }),
      login("d", { uris: ["https://elsewhere.com"] }),
    ]);
    expect(clusters).toHaveLength(1);
    expect(clusters[0]!.members.map((m) => m.itemId).sort()).toEqual(["a", "b"]);
    expect(clusters[0]!.kind).toBe("exact");
    expect(clusters[0]!.members.find((m) => m.itemId === "b")!.username).toBe(" U@Example.com ");
  });

  it("subdomain vs apex is the SAME site (eTLD+1), and a two-site item bridges clusters transitively", () => {
    const clusters = duplicateClusters([
      login("a", { uris: ["https://www.example.com"] }),
      login("b", { uris: ["https://accounts.example.com"] }),
      login("bridge", { uris: ["https://example.com", "https://elsewhere.com"] }),
      login("c", { uris: ["https://elsewhere.com"] }),
    ]);
    expect(clusters).toHaveLength(1);
    expect(clusters[0]!.members).toHaveLength(4);
    expect(clusters[0]!.sites).toEqual(["elsewhere.com", "example.com"]);
  });

  it("an item with no resolvable site never clusters — equal credentials alone are not a duplicate", () => {
    expect(duplicateClusters([login("a", { uris: [] }), login("b", { uris: [] })])).toHaveLength(0);
  });

  it("diverging passwords make a 'differs' cluster, newest member first, with no merge plan", () => {
    const clusters = duplicateClusters([login("old", { password: "stale" }, {}, 100), login("new", { password: "fresh" }, {}, 200)]);
    expect(clusters).toHaveLength(1);
    expect(clusters[0]!.kind).toBe("differs");
    expect(clusters[0]!.members.map((m) => m.itemId)).toEqual(["new", "old"]); // newest first — the likely-current copy leads
    expect(clusters[0]!.merge).toBeUndefined();
    expect(clusters[0]!.mergeRefusal).toBeUndefined(); // refusals are an exact-cluster concept
  });
});

describe("duplicateClusters — the fail-closed merge plan", () => {
  it("survivor = newest; uris union (survivor first, raw-string dedupe); favorite survives from any copy", () => {
    const clusters = duplicateClusters([
      login("old", { uris: ["https://example.com", "https://old.example.com"] }, { favorite: true }, 100),
      login("new", { uris: ["https://example.com/login"] }, {}, 200),
    ]);
    const plan = clusters[0]!.merge!;
    expect(plan.survivorId).toBe("new");
    expect(plan.loserIds).toEqual(["old"]);
    expect(plan.doc.login!.uris).toEqual(["https://example.com/login", "https://example.com", "https://old.example.com"]);
    expect(plan.doc.favorite).toBe(true); // the loser's favorite is not lost
    expect(plan.doc.login!.password).toBe("hunter2");
  });

  it("the one one-time code (or the one notes text) forces the survivor to its carrier", () => {
    const clusters = duplicateClusters([
      login("carrier", { totp: "otpauth://totp/x?secret=GEZDGNBV" }, {}, 100),
      login("newer-bare", {}, {}, 200), // newer, but merging onto it would drop the code
    ]);
    expect(clusters[0]!.merge!.survivorId).toBe("carrier");
    expect(clusters[0]!.merge!.doc.login!.totp).toBe("otpauth://totp/x?secret=GEZDGNBV");
  });

  it("diverging one-time codes / diverging notes / data split across copies all REFUSE", () => {
    const twoTotps = duplicateClusters([
      login("a", { totp: "otpauth://totp/x?secret=GEZDGNBV" }),
      login("b", { totp: "otpauth://totp/x?secret=JBSWY3DP" }),
    ]);
    expect(twoTotps[0]!.merge).toBeUndefined();
    expect(twoTotps[0]!.mergeRefusal).toContain("different one-time codes");

    const twoNotes = duplicateClusters([login("a", {}, { notes: "alpha" }), login("b", {}, { notes: "beta" })]);
    expect(twoNotes[0]!.mergeRefusal).toContain("different notes");

    // The code lives on one copy, the notes on another — no member can carry both.
    const split = duplicateClusters([
      login("has-totp", { totp: "otpauth://totp/x?secret=GEZDGNBV" }),
      login("has-notes", {}, { notes: "the recovery codes" }),
    ]);
    expect(split[0]!.merge).toBeUndefined();
    expect(split[0]!.mergeRefusal).toContain("merge by hand");
  });

  it("attachments pin the survivor to their holder; two holders refuse", () => {
    const att = [{ id: "att1", name: "f", size: 1, key: "k" }] as unknown as NonNullable<ItemDoc["attachments"]>;
    const oneHolder = duplicateClusters([login("holder", {}, { attachments: att }, 100), login("newer", {}, {}, 200)]);
    expect(oneHolder[0]!.merge!.survivorId).toBe("holder");

    const twoHolders = duplicateClusters([login("a", {}, { attachments: att }), login("b", {}, { attachments: att })]);
    expect(twoHolders[0]!.merge).toBeUndefined();
    expect(twoHolders[0]!.mergeRefusal).toContain("attachments");
  });

  it("exact clusters sort ahead of differs clusters", () => {
    const clusters = duplicateClusters([
      login("d1", { password: "one", uris: ["https://zeta.com"] }),
      login("d2", { password: "two", uris: ["https://zeta.com"] }),
      login("e1", { uris: ["https://alpha.com"] }),
      login("e2", { uris: ["https://alpha.com"] }),
    ]);
    expect(clusters.map((c) => c.kind)).toEqual(["exact", "differs"]);
  });
});
