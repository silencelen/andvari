import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import type { ItemDoc } from "../api/types";
import type { VaultItem } from "../vault/store";
import { BREACH_SCAN_FAILED, BREACH_SCAN_INCOMPLETE, type BreachEntry, breachVerdict, healthRows } from "./Health";

/**
 * bug-web--1 (polish audit 2026-07-27): Health's rows used to memoize on the identity-stable
 * `store` prop, so the view froze at open-time while the WS dirty-bell applied live changes.
 * The fix derives rows from Vault's `items` state via this PURE function — a fresh array in,
 * fresh rows out, so the [items]-keyed memo recomputes exactly when Vault re-renders after a
 * sync (the vaultsInfo/needsUpdate convention). Pin the derivation itself here.
 */

const login = (itemId: string, password: string, over: Partial<NonNullable<ItemDoc["login"]>> = {}, name = itemId): VaultItem => ({
  itemId,
  vaultId: "v1",
  rev: 1,
  updatedAt: 0,
  formatVersion: 1,
  doc: { type: "login", name, login: { username: "u", password, ...over } },
});

describe("healthRows — pure derivation from the items array", () => {
  it("keeps only logins WITH passwords, and flags reuse across the rest", () => {
    const items: VaultItem[] = [
      login("a", "correct horse battery staple"),
      login("b", "hunter2"),
      login("c", "hunter2", { totp: "otpauth://totp/x?secret=GEZDGNBV" }),
      login("d", "", {}), // password-less login — not a health row
      { itemId: "n", vaultId: "v1", rev: 1, updatedAt: 0, formatVersion: 1, doc: { type: "note", name: "note", notes: "x" } },
    ];
    const rows = healthRows(items);
    expect(rows.map((r) => r.itemId)).toEqual(["a", "b", "c"]);
    expect(rows.find((r) => r.itemId === "a")!.reused).toBe(0);
    expect(rows.find((r) => r.itemId === "b")!.reused).toBe(1); // one OTHER item shares it
    expect(rows.find((r) => r.itemId === "c")!.hasTotp).toBe(true);
    expect(rows.find((r) => r.itemId === "b")!.hasTotp).toBe(false);
  });

  it("a changed password lands in the next derivation — the live-sync staleness bug's core", () => {
    const before = healthRows([login("a", "hunter2")]);
    const after = healthRows([login("a", "correct horse battery staple")]);
    expect(after.find((r) => r.itemId === "a")!.strength).toBeGreaterThan(before.find((r) => r.itemId === "a")!.strength);
  });

  it("an untitled login still gets a display name", () => {
    expect(healthRows([login("a", "pw", {}, "")])[0]!.name).toBe("(untitled)");
  });
});

/**
 * tests--2 (polish audit 2026-07-27): the derivation tests above are PURE — they call healthRows
 * directly, so they pass just as happily against the frozen store-keyed memo and cannot fail for
 * the bug this file documents. What has to hold is the WIRING: Vault's live `items` state in,
 * `[items]` as the memo key out. No seam to call for a memo dependency array, so pin the source
 * (the trash-purge/token-lockstep idiom) — a revert now breaks a test rather than the view.
 */
const here = (p: string) => fileURLToPath(new URL(p, import.meta.url));
const healthTsx = readFileSync(here("./Health.tsx"), "utf8");
const vaultTsx = readFileSync(here("./Vault.tsx"), "utf8");

describe("Health rows — keyed on the live items array, not the identity-stable store", () => {
  it("the rows memo recomputes on a new items identity", () => {
    expect(healthTsx).toContain("useMemo<Row[]>(() => healthRows(items), [items])");
  });

  it("every derivation memo keys on `items` — never the identity-stable store", () => {
    // Evolved 2026-08-12: the duplicate checker's guided MERGE legitimately re-introduced a
    // `store` prop as a WRITE path, so the old "no store prop at all" formulation went stale.
    // The bug this pins was never about the prop's existence — it was rows DERIVING from an
    // identity-stable dependency, so the [items]-keyed memo never recomputed. Pin the memos'
    // dependency lists directly: both derivations exist, both key on [items], and no useMemo in
    // the file lists `store` as a dependency.
    const props = healthTsx.slice(healthTsx.indexOf("interface Props {"), healthTsx.indexOf("interface Row {"));
    expect(props, "Health's Props moved — update the pin").toContain("items: VaultItem[];");
    expect(healthTsx).toContain("useMemo<Row[]>(() => healthRows(items), [items])");
    // Evolved 2026-08-13 (audit F03): the checker now also takes a vault-role lookup, so the
    // clusters memo keys on [items, roleFor] — roleFor itself is a useCallback over the
    // items-keyed vaultsInfo memo, so the whole chain still re-derives on a new items identity.
    expect(healthTsx).toContain("useMemo<DuplicateCluster[]>(() => duplicateClusters(items, roleFor), [items, roleFor])");
    expect(healthTsx).toContain("const vaultsInfo = useMemo(() => store.vaults(), [items])");
    for (const deps of healthTsx.matchAll(/useMemo[^;]*?\[([^\]]*)\]\s*\)/g)) {
      expect(deps[1], "a useMemo grew an identity-stable store dependency").not.toMatch(/\bstore\b/);
    }
  });

  it("Vault feeds it the state it refreshes after every applied sync", () => {
    expect(vaultTsx).toMatch(/<Health items=\{items\}/);
  });
});

/**
 * Audit F03 — the duplicate checker's rendering half. `DuplicateMember` always carried `vaultId`
 * and the renderer never read it: two identically-named rows, no vault named anywhere, and a
 * Merge button whose confirm named only the survivor — while `store.remove` on a shared-vault
 * copy takes it off every household member's devices. The pure refusals are pinned in
 * duplicates.test.ts; these are the three rendering obligations that go with them.
 */
describe("Health duplicates — every row names its vault, and so does the confirm", () => {
  it("the vault badge is the one Vault's list rows use, on EVERY member row", () => {
    expect(healthTsx).toContain('<span className="tag" style={{ color: "var(--gold-text)" }}>{vaultLabel(m.vaultId)}</span>');
    // Same fallback wording as Vault.tsx's badge when a name can't be resolved.
    expect(healthTsx).toContain('vaultNameById.get(vaultId) ?? "shared"');
  });

  it("the confirm names the vault kept AND the vault emptied", () => {
    expect(healthTsx).toContain("Keep “{survivorName}” in “{survivorVault}” and move");
    expect(healthTsx).toContain("in “{loserVaults}” to Deleted items (kept 30 days)?");
  });

  it("the panel's own intro says cross-vault copies are never merged", () => {
    expect(healthTsx).toContain("Copies sitting in different vaults are listed but never merged");
  });

  it("the roles come from the same source as the names, and reach the pure module", () => {
    expect(healthTsx).toContain("const vaultsInfo = useMemo(() => store.vaults(), [items])");
    expect(healthTsx).toContain('vaultsInfo.find((v) => v.vaultId === vaultId)?.role ?? null');
  });
});

/**
 * The differs resolution + dismissal (owner decisions 2026-08-18) — rendering obligations that
 * go with the planKeep/planDismiss pins in duplicates.test.ts.
 */
describe("Health duplicates — the differs resolution keeps its promises on screen", () => {
  it("the keep-confirm says where the losers go AND that their passwords are retained", () => {
    expect(healthTsx).toContain("to Deleted items (kept 30 days)?");
    expect(healthTsx).toContain("stay in the kept item's password history");
  });

  it("the password test is the human signing in — an external link, never a client probe", () => {
    expect(healthTsx).toContain('target="_blank" rel="noreferrer"');
    expect(healthTsx).not.toMatch(/fetch\(|XMLHttpRequest/);
  });

  it("a dismissed group collapses to a quiet line with its Restore", () => {
    expect(healthTsx).toContain("Marked not duplicates");
    expect(healthTsx).toContain('onClick={() => void runDismiss(c, true)}');
  });
});

/**
 * H26 (audit 2026-09-13; G35's other half): the breach cache is keyed by itemId while it describes
 * the PASSWORD. G35 made an ABSENT key render "—"; a CHANGED password kept the key and so kept the
 * old verdict — a rotated password stayed red, and (worse) a green "none" survived an edit to a
 * breached password. Each entry now carries the rev the scan saw and a verdict is reported only
 * while the item still sits at it. Never a false "none".
 */
describe("breachVerdict — a verdict is only as current as the rev it was scanned at", () => {
  const cache = (entries: [string, BreachEntry][]) => new Map<string, BreachEntry>(entries);

  it("reports the count while the item is at the scanned rev (a real 'none' stays 'none')", () => {
    const c = cache([["a", { count: 12345, rev: 3 }], ["b", { count: 0, rev: 1 }]]);
    expect(breachVerdict(c, { itemId: "a", rev: 3 })).toBe(12345);
    expect(breachVerdict(c, { itemId: "b", rev: 1 })).toBe(0);
  });

  it("an item EDITED since the scan (rev moved) is unscanned — the old count, red or green, is withdrawn", () => {
    const c = cache([["a", { count: 12345, rev: 3 }], ["b", { count: 0, rev: 1 }]]);
    expect(breachVerdict(c, { itemId: "a", rev: 4 }), "rotated a breached password").toBeUndefined();
    expect(breachVerdict(c, { itemId: "b", rev: 2 }), "edited a clean one to who-knows-what").toBeUndefined();
  });

  it("G35 still holds: an absent key (added/restored since, or the range failed) and a null cache are unscanned", () => {
    expect(breachVerdict(cache([["a", { count: 1, rev: 1 }]]), { itemId: "z", rev: 1 })).toBeUndefined();
    expect(breachVerdict(null, { itemId: "a", rev: 1 })).toBeUndefined();
  });

  it("healthRows carries the rev the verdict is keyed on, so the scan and the row read the same number", () => {
    const rows = healthRows([{ ...login("a", "hunter2"), rev: 7 }]);
    expect(rows[0]!.rev).toBe(7);
  });

  it("the Health view derives every breach cell, the tile and the sort through breachVerdict (source pin)", () => {
    const src = readFileSync(here("./Health.tsx"), "utf8");
    expect(src).toContain("const count = breachVerdict(breachByItem, r);");
    expect(src).toContain("rows.filter((r) => (breachVerdict(breachByItem, r) ?? 0) > 0).length");
    expect(src).toContain("const n = (r: Row) => breachVerdict(breachByItem, r) ?? 0;");
    // The scan writes the rev beside the count — without it every verdict is instantly stale.
    // (H73 moved this pin: the count is no longer defaulted to 0, because a row whose range
    // FAILED must be absent from the map rather than present at a fabricated zero.)
    expect(src).toContain("{ count: result.get(r.password)!, rev: r.rev }");
    // The pre-fix direct read is gone.
    expect(src).not.toContain("breachByItem?.get(r.itemId)");
  });
});

/**
 * H73/H74 (audit 2026-09-13): web was the LAXER twin on both counts. It aborted the whole scan on
 * the first range that failed — throwing away every verdict already earned, so a large vault on a
 * flaky relay could never complete a scan on web while the phone completed the same one — and its
 * failure sentence named "the HIBP relay", an internal the household cannot act on.
 *
 * Neither leg can be driven end to end here: `scan` is a closure inside the component and the web
 * suite has no DOM/effects harness (the house pattern is renderToStaticMarkup, which runs no
 * effects). So the CONTROL FLOW is pinned as source shape and the two sentences are pinned
 * byte-equal against the Android original they were ported from — the drift this row is about is
 * exactly what a byte-equality pin catches and a paraphrase test does not.
 */
describe("H73/H74 — the breach scan fails open per range and speaks the phone's words", () => {
  const healthTsx = readFileSync(here("./Health.tsx"), "utf8");
  const androidVm = readFileSync(
    here("../../../app-android/src/main/kotlin/io/silencelen/andvari/app/AndvariViewModel.kt"),
    "utf8",
  );
  /** Pull a Kotlin string literal by its opening words — the twin is the source of truth. */
  const kotlinSentence = (starts: string): string => {
    const m = androidVm.match(new RegExp('"(' + starts + '[^"]*)"'));
    if (!m) throw new Error("Android twin no longer contains a sentence starting: " + starts);
    return m[1]!;
  };

  it("the failure sentence is the Android twin's, byte for byte — no 'HIBP relay' internal", () => {
    expect(BREACH_SCAN_FAILED).toBe(kotlinSentence("Breach scan failed"));
    // The jargon survives only in the comment that records why it went.
    expect(BREACH_SCAN_FAILED).not.toContain("HIBP");
    expect(healthTsx.split("\n").filter((l) => l.includes("HIBP relay") && !l.trimStart().startsWith("*"))).toEqual([]);
  });

  it("the incomplete sentence is the Android twin's, byte for byte", () => {
    expect(BREACH_SCAN_INCOMPLETE).toBe(kotlinSentence("Breach scan incomplete"));
  });

  it("both failure paths speak through the one constant — no hand-written copy left in the scan", () => {
    const scan = healthTsx.slice(healthTsx.indexOf("const scan = async () =>"), healthTsx.indexOf("const weak = rows.filter"));
    expect(scan).not.toMatch(/setScanErr\("[^"]/); // only setScanErr("") and setScanErr(BREACH_SCAN_FAILED)
    expect(scan.match(/setScanErr\(BREACH_SCAN_FAILED\)/g)?.length).toBe(2); // all-failed + throw
  });

  it("a failed range is caught PER RANGE and only its passwords are dropped (source pin)", () => {
    const scan = healthTsx.slice(healthTsx.indexOf("const scan = async () =>"), healthTsx.indexOf("const weak = rows.filter"));
    // The await is inside a try of its own — one bad range no longer unwinds the whole loop.
    expect(scan).toContain("body = await client.hibpRange(prefix);");
    expect(scan).toContain("if (body === null) failedRanges++;");
    // Rows whose range failed are ABSENT from the map, which breachVerdict reports as unscanned
    // ("—"), never as a fabricated clean 0.
    expect(scan).toContain("rows.filter((r) => result.has(r.password))");
    // Every range failed is no scan at all: keep the previous map, say so, publish nothing.
    expect(scan).toContain("if (failedRanges === byPrefix.size) {");
  });

  it("an incomplete scan's zero leaves the Breached tile neutral, never a green clean bill", () => {
    expect(healthTsx).toContain("breached === null || (breached === 0 && scanIncomplete) ? undefined");
    expect(healthTsx).toContain("setScanIncomplete(failedRanges > 0);");
  });
});
