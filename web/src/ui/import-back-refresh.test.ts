import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

/**
 * Browser walk, 2026-11-16: after "Import complete. Added 400 items", "‹ Back to vault" returned to a list without
 * them until the next sync (a minute later with live updates down); only Done refreshed it.
 */
describe("the vault list after an import", () => {
  it("leaving a finished import by Back shows what it added, as Done does", () => {
    const vault = readFileSync(fileURLToPath(new URL("./Vault.tsx", import.meta.url)), "utf8");
    const at = vault.indexOf("<ImportPanel");
    const panel = vault.slice(at, vault.indexOf("/>", at));
    expect(panel).toContain("onClose={() => { setImportOpen(false); refresh(); }}");
    expect(panel).toContain("onDone={() => { setImportOpen(false); refresh(); }}");
  });
});
