import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

/**
 * Design §4.4: a read-only copy (a forked pin, a session the server ended) is read, copied from, filled from and exported;
 * nothing is sent and nothing is written. The walk's C16 and C18 still showed + Login, + Note, + Card and Sync now on it.
 */
const vault = readFileSync(fileURLToPath(new URL("./Vault.tsx", import.meta.url)), "utf8");

describe("a read-only copy offers nothing that writes or asks the server", () => {
  it("the add buttons, Import and Sync now are not offered; the item opens read-only; export stays", () => {
    expect(vault).toContain('{!readOnlyCopy && <button className="ghost" onClick={() => startNew("login")}>+ Login</button>}');
    expect(vault).toContain('{!readOnlyCopy && <button className="ghost" onClick={() => startNew("note")}>+ Note</button>}');
    expect(vault).toContain('{CARD_CREATE_ENABLED && !readOnlyCopy && <button className="ghost" onClick={() => startNew("card")}>+ Card</button>}');
    expect(vault).toContain('{!readOnlyCopy && <button type="button" className="ghost" aria-label="Import"');
    expect(vault).toContain("{!online && !readOnlyCopy && (");
    expect(vault).toContain('readOnly={readOnlyCopy || account.roleFor(current.vaultId) === "reader" || store.moveDeleteWaiting(current.vaultId) || !store.mayWrite(current.vaultId)}');
    expect(vault.match(/<ExportMenu\b/g)).toHaveLength(1);
    expect(vault).not.toMatch(/readOnlyCopy && <ExportMenu|!readOnlyCopy && <ExportMenu/);
  });
});
