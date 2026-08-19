import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import type { ItemDoc } from "../api/types";
import type { VaultItem } from "../vault/store";
import { type RoleFor, clusterSignature, duplicateClusters, planDismiss, planKeep, siteKeysOf } from "./duplicates";

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
  vaultId = "v1",
): VaultItem => ({
  itemId,
  vaultId,
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

/** The same login sitting in a SECOND vault — the shape "Copy to vault…" and the shared-vault
 *  delete rescue (copyAllToPersonal) mint by design, and the one every fixture used to omit. */
const inVault = (item: VaultItem, vaultId: string): VaultItem => ({ ...item, vaultId });

/** The personal-vault lookup: a personal vault carries no grant, so it genuinely has no role.
 *  Spelled out at every call below because `roleFor` is REQUIRED — the parameter used to default
 *  to exactly this, which meant a caller who forgot it got "every vault is writable" and lost the
 *  reader refusal without a compile error. Stating it is the point. */
const noRole: RoleFor = () => null;

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
    ], noRole);
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
    ], noRole);
    expect(clusters).toHaveLength(1);
    expect(clusters[0]!.members).toHaveLength(4);
    expect(clusters[0]!.sites).toEqual(["elsewhere.com", "example.com"]);
  });

  it("an item with no resolvable site never clusters — equal credentials alone are not a duplicate", () => {
    expect(duplicateClusters([login("a", { uris: [] }), login("b", { uris: [] })], noRole)).toHaveLength(0);
  });

  it("diverging passwords make a 'differs' cluster, newest member first, with no merge plan", () => {
    const clusters = duplicateClusters([login("old", { password: "stale" }, {}, 100), login("new", { password: "fresh" }, {}, 200)], noRole);
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
    ], noRole);
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
    ], noRole);
    expect(clusters[0]!.merge!.survivorId).toBe("carrier");
    expect(clusters[0]!.merge!.doc.login!.totp).toBe("otpauth://totp/x?secret=GEZDGNBV");
  });

  it("diverging one-time codes / diverging notes / data split across copies all REFUSE", () => {
    const twoTotps = duplicateClusters([
      login("a", { totp: "otpauth://totp/x?secret=GEZDGNBV" }),
      login("b", { totp: "otpauth://totp/x?secret=JBSWY3DP" }),
    ], noRole);
    expect(twoTotps[0]!.merge).toBeUndefined();
    expect(twoTotps[0]!.mergeRefusal).toContain("different one-time codes");

    const twoNotes = duplicateClusters([login("a", {}, { notes: "alpha" }), login("b", {}, { notes: "beta" })], noRole);
    expect(twoNotes[0]!.mergeRefusal).toContain("different notes");

    // The code lives on one copy, the notes on another — no member can carry both.
    const split = duplicateClusters([
      login("has-totp", { totp: "otpauth://totp/x?secret=GEZDGNBV" }),
      login("has-notes", {}, { notes: "the recovery codes" }),
    ], noRole);
    expect(split[0]!.merge).toBeUndefined();
    expect(split[0]!.mergeRefusal).toContain("merge by hand");
  });

  it("attachments pin the survivor to their holder; two holders refuse", () => {
    const att = [{ id: "att1", name: "f", size: 1, key: "k" }] as unknown as NonNullable<ItemDoc["attachments"]>;
    const oneHolder = duplicateClusters([login("holder", {}, { attachments: att }, 100), login("newer", {}, {}, 200)], noRole);
    expect(oneHolder[0]!.merge!.survivorId).toBe("holder");

    const twoHolders = duplicateClusters([login("a", {}, { attachments: att }), login("b", {}, { attachments: att })], noRole);
    expect(twoHolders[0]!.merge).toBeUndefined();
    expect(twoHolders[0]!.mergeRefusal).toContain("attachments");
  });

  it("exact clusters sort ahead of differs clusters", () => {
    const clusters = duplicateClusters([
      login("d1", { password: "one", uris: ["https://zeta.com"] }),
      login("d2", { password: "two", uris: ["https://zeta.com"] }),
      login("e1", { uris: ["https://alpha.com"] }),
      login("e2", { uris: ["https://alpha.com"] }),
    ], noRole);
    expect(clusters.map((c) => c.kind)).toEqual(["exact", "differs"]);
  });
});

/**
 * audit F03 — the vault boundary. The checker deliberately clusters ACROSS vaults (the app mints
 * cross-vault twins itself: "Copy to vault…" and the shared-vault delete rescue), because those
 * are the duplicates a household actually accumulates. What it must never do is MERGE across one:
 * `store.remove` on a shared-vault copy takes it off every other member's devices, silently.
 * Report-only, exactly like the diverging-TOTP refusal. Every fixture above is single-vault, so
 * this whole boundary was unpinned when the checker shipped.
 */
describe("duplicateClusters — the vault boundary", () => {
  it("a cluster spanning two vaults is still REPORTED, with both members and their vaultIds", () => {
    const clusters = duplicateClusters([login("household"), inVault(login("personal-copy"), "v2")], noRole);
    expect(clusters).toHaveLength(1);
    expect(clusters[0]!.kind).toBe("exact"); // identical passwords — the copy leg clones the doc
    expect(clusters[0]!.members.map((m) => m.vaultId).sort()).toEqual(["v1", "v2"]);
  });

  it("…and REFUSES the merge — no survivor, no loserIds, a reason the UI can print", () => {
    const clusters = duplicateClusters([login("household"), inVault(login("personal-copy"), "v2")], noRole);
    expect(clusters[0]!.merge).toBeUndefined();
    expect(clusters[0]!.mergeRefusal).toBe("These copies are in different vaults — merge by hand.");
  });

  it("the refusal outranks every data refusal — a cross-vault cluster never says 'different notes'", () => {
    const clusters = duplicateClusters([
      login("household", {}, { notes: "alpha" }),
      inVault(login("personal-copy", {}, { notes: "beta" }), "v2"),
    ], noRole);
    expect(clusters[0]!.mergeRefusal).toContain("different vaults");
  });

  it("three copies across two vaults refuse as one cluster (the transitive bridge doesn't launder it)", () => {
    const clusters = duplicateClusters([
      login("a"),
      login("b"),
      inVault(login("c"), "v2"),
    ], noRole);
    expect(clusters).toHaveLength(1);
    expect(clusters[0]!.members).toHaveLength(3);
    expect(clusters[0]!.merge).toBeUndefined();
    expect(clusters[0]!.mergeRefusal).toContain("different vaults");
  });

  it("same-vault clusters are unaffected — the merge plan still lands", () => {
    const clusters = duplicateClusters([login("a", {}, {}, 100), login("b", {}, {}, 200)], noRole);
    expect(clusters[0]!.merge!.survivorId).toBe("b");
    expect(clusters[0]!.merge!.loserIds).toEqual(["a"]);
  });

  it("a view-only (reader) vault refuses too — a denied remove would half-complete the merge", () => {
    const readerVault = duplicateClusters([login("a", {}, {}, 100), login("b", {}, {}, 200)], () => "reader");
    expect(readerVault[0]!.merge).toBeUndefined();
    expect(readerVault[0]!.mergeRefusal).toContain("only view");
    // No reader-held item can ever reach loserIds — the invariant, stated as an assertion.
    expect(readerVault.flatMap((c) => c.merge?.loserIds ?? [])).toEqual([]);
  });

  it("writer and owner roles (and a vault with no role at all — personal) merge normally", () => {
    for (const role of ["writer", "owner", null]) {
      const clusters = duplicateClusters([login("a", {}, {}, 100), login("b", {}, {}, 200)], () => role);
      expect(clusters[0]!.merge!.loserIds, `role ${role}`).toEqual(["a"]);
    }
  });

  /**
   * The refusal above is only worth anything if every caller actually supplies a lookup. `roleFor`
   * used to default to `() => null` — "no role information, treat every vault as writable" — so a
   * caller that simply omitted it got merge plans over view-only vaults with no compile error and
   * no test failure. Two halves, because neither alone catches a re-added default: the type
   * checker refuses the omission, and the source no longer carries one to fall back on.
   */
  it("omitting the role lookup is a TYPE error, not a silent fail-open", () => {
    // @ts-expect-error — roleFor is required; deleting this line must break `npm run typecheck`.
    expect(duplicateClusters([])).toEqual([]); // empty in, empty out — roleFor is never reached
  });

  it("the signature carries no default that could reinstate the fail-open", () => {
    const dupes = readFileSync(fileURLToPath(new URL("./duplicates.ts", import.meta.url)), "utf8");
    expect(dupes).toContain("export function duplicateClusters(items: VaultItem[], roleFor: RoleFor): DuplicateCluster[]");
    expect(dupes, "roleFor grew a default again").not.toMatch(/roleFor: RoleFor\s*=/);
  });
});

/**
 * Audit F13 — the checker's own bundle footprint. Clustering keys on the registrable domain, so
 * duplicates.ts imports vault/psl, which imports the vendored ~144 kB public-suffix snapshot.
 * That made Vault → Health → duplicates → psl → pslData a fully static chain into the ENTRY
 * chunk: the purest never-changes-between-releases data in the tree riding the highest-churn
 * chunk, re-downloaded and re-parsed by every client on every polish release — the exact inverse
 * of what manualChunks exists for. It is its own hash-stable chunk now; keep it that way, and
 * keep the config's rationale describing the tree that exists.
 */
describe("the PSL snapshot stays out of the app chunk", () => {
  const viteConfig = readFileSync(fileURLToPath(new URL("../../vite.config.ts", import.meta.url)), "utf8");

  it("pslData is named in manualChunks", () => {
    expect(viteConfig).toMatch(/psl:\s*\[fileURLToPath\(new URL\("\.\/src\/vault\/pslData\.ts"/);
  });

  it("the config no longer claims the blob is in no web bundle at all", () => {
    expect(viteConfig).not.toContain("It is in no web bundle at all");
    expect(viteConfig).not.toContain("naming it here only mints an empty chunk");
  });

  it("duplicates.ts is still the importer that put it there (the pin's premise)", () => {
    const dupes = readFileSync(fileURLToPath(new URL("./duplicates.ts", import.meta.url)), "utf8");
    expect(dupes).toContain('import { pslResolve } from "../vault/psl";');
  });
});

describe("planKeep — the differs resolution (owner decision 2026-08-18)", () => {
  const cluster = () => [
    login("stale", { password: "old-pass" }, {}, 10),
    login("current", { password: "new-pass", uris: ["https://example.com", "https://sso.example.com"] }, {}, 20),
    login("older", { password: "ancient" }, {}, 5),
  ];

  it("keeps the CHOSEN copy (not the newest), unions uris, retires every distinct losing password", () => {
    const items = cluster();
    const { keep, keepRefusal } = planKeep(items, ["stale", "current", "older"], "current", noRole, 777);
    expect(keepRefusal).toBeUndefined();
    expect(keep!.survivorId).toBe("current");
    expect(keep!.loserIds).toEqual(["stale", "older"]); // newest-first
    expect(keep!.doc.login!.password).toBe("new-pass");
    expect(keep!.doc.login!.uris).toEqual(["https://example.com", "https://sso.example.com"]);
    expect(keep!.doc.login!.passwordHistory).toEqual([
      { password: "old-pass", retiredAt: 777 },
      { password: "ancient", retiredAt: 777 },
    ]);
  });

  it("never duplicates a password already held — current, in history, or shared by two losers", () => {
    const items = [
      login("a", { password: "keep-me", passwordHistory: [{ password: "old-pass", retiredAt: 1 }] }, {}, 30),
      login("b", { password: "old-pass" }, {}, 20), // already in history → not re-added
      login("c", { password: "twin" }, {}, 10),
      login("d", { password: "twin" }, {}, 5), //     second carrier of "twin" → once
    ];
    const { keep } = planKeep(items, ["a", "b", "c", "d"], "a", noRole, 9);
    expect(keep!.doc.login!.passwordHistory).toEqual([
      { password: "old-pass", retiredAt: 1 },
      { password: "twin", retiredAt: 9 },
    ]);
  });

  it("refuses cross-vault, reader vaults, diverging codes/notes, and losers with attachments", () => {
    const base = cluster();
    expect(planKeep([base[0]!, inVault(base[1]!, "v2"), base[2]!], ["stale", "current", "older"], "current", noRole, 0).keepRefusal).toMatch(/different vaults/);
    expect(planKeep(base, ["stale", "current", "older"], "current", () => "reader", 0).keepRefusal).toMatch(/only view/);
    const withTotp = [login("stale", { password: "old", totp: "otpauth://totp/x?secret=GEZDGNBV" }, {}, 10), login("current", { password: "new" }, {}, 20)];
    expect(planKeep(withTotp, ["stale", "current"], "current", noRole, 0).keepRefusal).toMatch(/one-time codes/);
    const withNotes = [login("stale", { password: "old" }, { notes: "loser-only note" }, 10), login("current", { password: "new" }, {}, 20)];
    expect(planKeep(withNotes, ["stale", "current"], "current", noRole, 0).keepRefusal).toMatch(/different notes/);
    const withAtt = [login("stale", { password: "old" }, { attachments: [{ id: "f", name: "n", size: 1, fileKey: "k" }] }, 10), login("current", { password: "new" }, {}, 20)];
    expect(planKeep(withAtt, ["stale", "current"], "current", noRole, 0).keepRefusal).toMatch(/attachments/);
  });

  it("a member id missing from the live items refuses — a stale cluster snapshot must never write", () => {
    expect(planKeep(cluster(), ["stale", "current", "vanished"], "current", noRole, 0).keepRefusal).toMatch(/changed under you/);
  });
});

describe("clusterSignature / dupeAck — the not-a-duplicate acknowledgment (owner decision 2026-08-18)", () => {
  it("a cluster is dismissed only while EVERY member carries the signature of its current constitution", () => {
    const sig = clusterSignature(["a", "b"]);
    const dismissedPair = [login("a", {}, { dupeAck: sig }, 10), login("b", {}, { dupeAck: sig }, 20)];
    expect(duplicateClusters(dismissedPair, noRole)[0]!.dismissed).toBe(true);
    // A third copy arrives: same site+user, new membership → new signature → resurfaces.
    const withNewcomer = [...dismissedPair, login("c", {}, {}, 30)];
    const c = duplicateClusters(withNewcomer, noRole)[0]!;
    expect(c.dismissed).toBe(false);
    expect(c.signature).toBe(clusterSignature(["a", "b", "c"]));
  });

  it("signature is order-insensitive", () => {
    expect(clusterSignature(["b", "a"])).toBe(clusterSignature(["a", "b"]));
  });

  it("planDismiss stamps every member; empty signature clears the key rather than writing it blank", () => {
    const items = [login("a"), login("b")];
    const sig = clusterSignature(["a", "b"]);
    const { writes } = planDismiss(items, ["a", "b"], sig, noRole);
    expect(writes!.map((w) => w.doc.dupeAck)).toEqual([sig, sig]);
    const cleared = planDismiss(writes!.map((w, i) => ({ ...items[i]!, doc: w.doc })), ["a", "b"], "", noRole);
    expect(cleared.writes!.every((w) => !("dupeAck" in w.doc))).toBe(true);
  });

  it("planDismiss allows cross-vault (nothing is removed) but refuses a reader vault", () => {
    const items = [login("a"), inVault(login("b"), "v2")];
    expect(planDismiss(items, ["a", "b"], clusterSignature(["a", "b"]), noRole).writes).toHaveLength(2);
    expect(planDismiss(items, ["a", "b"], clusterSignature(["a", "b"]), (v) => (v === "v2" ? "reader" : null)).dismissRefusal).toMatch(/only view/);
  });
});
