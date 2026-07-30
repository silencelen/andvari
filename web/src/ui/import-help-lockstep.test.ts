import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

/**
 * ux-parity--7 (polish audit 2026-07-27): the "How do I export from…?" help table exists twice —
 * core `ImportHelp.SOURCES` (android + desktop) and web `Vault.tsx`'s `IMPORT_SOURCES` (the usual
 * non-KMP mirror) — and BOTH sides' comments said to "keep the two in lockstep" while nothing
 * checked it. For export instructions, drift is not cosmetic: the failure mode is telling a family
 * member to click a menu item that this year's browser moved, in the one place they have already
 * given up and gone looking for help.
 *
 * Same idiom as token-lockstep.test.ts / BrowserAllowlistLockstepTest: parse the REAL sources off
 * disk, so a one-sided edit fails here instead of shipping. Core is the reference implementation.
 *
 * The comparison is the ordered sequence of string literals inside each table, which for both
 * languages is exactly `label, …steps, note?` per source — so it pins the labels, the step WORDING,
 * the step ORDER and COUNT, and which sources carry a note, in one assertion.
 */

const here = (p: string) => fileURLToPath(new URL(p, import.meta.url));
const vaultTsx = readFileSync(here("./Vault.tsx"), "utf8");
const importHelpKt = readFileSync(
  here("../../../core/src/commonMain/kotlin/io/silencelen/andvari/core/client/ImportHelp.kt"),
  "utf8",
);

/**
 * Double-quoted literals in source order, skipping comments. String-aware on purpose: a naive
 * comment strip would eat `"Open chrome://password-manager/settings …"` at the `//`, silently
 * shortening the very steps this test pins (a vacuous pass is the one outcome worth engineering
 * against).
 */
function literals(block: string): string[] {
  const out: string[] = [];
  let i = 0;
  while (i < block.length) {
    if (block[i] === '"') {
      let s = "";
      let j = i + 1;
      while (j < block.length && block[j] !== '"') {
        if (block[j] === "\\") { s += block[j + 1]; j += 2; continue; }
        s += block[j];
        j++;
      }
      out.push(s);
      i = j + 1;
      continue;
    }
    if (block[i] === "/" && block[i + 1] === "/") { i = block.indexOf("\n", i) + 1 || block.length; continue; }
    if (block[i] === "/" && block[i + 1] === "*") { i = block.indexOf("*/", i) + 2; continue; }
    i++;
  }
  return out;
}

/** The table body between `open` and the first `close` at column 0 of its own line. */
function tableBody(src: string, declaration: string, open: string, close: string): string {
  const at = src.indexOf(declaration);
  expect(at, `${declaration} moved or was renamed — update the pin`).toBeGreaterThan(-1);
  const from = src.indexOf(open, at);
  const to = src.indexOf(close, from);
  expect(to, `could not find the end of ${declaration}`).toBeGreaterThan(from);
  return src.slice(from + open.length, to);
}

const coreSources = literals(tableBody(importHelpKt, "val SOURCES", "listOf(", "\n    )"));
const webSources = literals(tableBody(vaultTsx, "const IMPORT_SOURCES", "= [", "\n];"));

describe("import help table — core ImportHelp ↔ web IMPORT_SOURCES lockstep", () => {
  it("both tables are non-empty (the parsers actually found them)", () => {
    // Guards the shape this whole test exists to prevent: two empty lists compare equal.
    expect(coreSources.length).toBeGreaterThan(20);
    expect(webSources.length).toBe(coreSources.length);
  });

  it("every label, step and note is byte-equal, in the same order", () => {
    expect(webSources).toEqual(coreSources);
  });

  it("still covers the sources the import screen advertises", () => {
    // The screen's own "Works with password exports from …" line names these; a table that
    // quietly loses one leaves that sentence promising help it no longer has.
    for (const label of ["Chrome", "Edge", "Brave", "Opera", "Firefox", "Bitwarden", "1Password", "LastPass"]) {
      expect(coreSources, `${label} left ImportHelp`).toContain(label);
    }
  });
});
