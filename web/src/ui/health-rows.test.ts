import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import type { ItemDoc } from "../api/types";
import type { VaultItem } from "../vault/store";
import { healthRows } from "./Health";

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

  it("Health takes no `store` prop — the never-changing dependency the bug memoized on", () => {
    const props = healthTsx.slice(healthTsx.indexOf("interface Props {"), healthTsx.indexOf("interface Row {"));
    expect(props, "Health's Props moved — update the pin").toContain("items: VaultItem[];");
    expect(props).not.toMatch(/^\s*store\??:/m); // a declared prop, not the doc comment's mention
  });

  it("Vault feeds it the state it refreshes after every applied sync", () => {
    expect(vaultTsx).toMatch(/<Health items=\{items\}/);
  });
});
