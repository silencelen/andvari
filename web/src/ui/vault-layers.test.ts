import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { fmtDay } from "./format";

/**
 * quality-deadcode--6 / --7 (polish audit 2026-07-27). Two duplications in the vault views that
 * had already cost correctness, not just lines:
 *
 *  --6: the "close every open layer" cluster (editing / import / export / selected / sharing
 *       settings) was hand-inlined at ten navigation and opener call sites, each with its own
 *       subset. sharingSettingsVaultId — the layer added last — was missing from three, so the
 *       recovery banner's "Go to Settings →" left a Sharing settings layer (and any open
 *       Import/Export panel) armed behind the view switch, to reappear on the way back with the
 *       F76 back guard still counting it. One closeLayers() now, exceptions stated by opening
 *       the wanted layer AFTER it rather than by omitting a setter.
 *  --7: fmtDay existed twice, byte-identical, in Vault.tsx and Sharing.tsx while ui/format.ts —
 *       the designated formatting home — had neither.
 *
 * Both are component-closure shapes with no seam to call, so they are pinned on the source (the
 * trash-purge / token-lockstep idiom).
 */
const here = (p: string) => fileURLToPath(new URL(p, import.meta.url));
const vaultTsx = readFileSync(here("./Vault.tsx"), "utf8");
const sharingTsx = readFileSync(here("./Sharing.tsx"), "utf8");
const formatTs = readFileSync(here("./format.ts"), "utf8");

/** Vault.tsx with line comments dropped — the fix's own comment names the shapes it removed. */
const vaultCode = vaultTsx
  .replace(/\{\/\*[\s\S]*?\*\/\}/g, "")
  .split("\n")
  .filter((l) => !l.trim().startsWith("//") && !l.trim().startsWith("*"))
  .join("\n");

/** closeLayers' body, sliced to the opener that follows it. */
function closeLayersBody(): string {
  const start = vaultCode.indexOf("const closeLayers = useCallback(");
  const end = vaultCode.indexOf("const startNew =", start);
  expect(start, "closeLayers moved — update the pin").toBeGreaterThan(-1);
  expect(end, "startNew moved — update the pin").toBeGreaterThan(start);
  return vaultCode.slice(start, end);
}

describe("quality-deadcode--6 — one layer-clearing routine, not ten subsets", () => {
  it("closeLayers clears ALL five layers", () => {
    const body = closeLayersBody();
    for (const setter of [
      "setEditing(null)",
      "setImportOpen(false)",
      "setExportMode(null)",
      "setSelected(null)",
      "setSharingSettingsVaultId(null)",
    ]) {
      expect(body, `closeLayers dropped ${setter}`).toContain(setter);
    }
  });

  it("no call site re-inlines a subset of the cluster", () => {
    // Every remaining mention of a multi-layer setter is a SINGLE-layer close: closeLayers
    // itself, closeTop's one-layer-per-Back ladder, and each panel's own onClose/onCancel.
    const count = (needle: string) => vaultCode.split(needle).length - 1;
    expect(count("setImportOpen(false)"), "closeLayers + closeTop + ImportPanel onClose/onDone").toBe(4);
    expect(count("setExportMode(null)"), "closeLayers + closeTop + ExportPanel onClose").toBe(3);
    expect(count("setSharingSettingsVaultId(null)"), "closeLayers + closeTop + Sharing onCloseSettings").toBe(3);
  });

  it("the recovery banner's Settings jump closes every layer (it used to clear only two)", () => {
    const banner = vaultCode.slice(vaultCode.indexOf("Recovery sign-in"), vaultCode.indexOf("escrowStale &&"));
    expect(banner).toContain('setView("settings"); closeLayers();');
    expect(banner).not.toContain("setEditing(null); setSelected(null)");
  });

  it("the openers close everything and then open exactly one layer", () => {
    for (const opener of [
      "closeLayers(); setImportOpen(true);",
      'closeLayers(); setExportMode("backup");',
      'closeLayers(); setExportMode("csv");',
      'closeLayers(); setView("health");',
      'closeLayers(); setView("trash");',
    ]) {
      expect(vaultCode, `opener drifted: ${opener}`).toContain(opener);
    }
  });

  it("post-write teardown is NOT routed through it (save/remove are not navigation)", () => {
    const save = vaultCode.slice(vaultCode.indexOf("const save = async"), vaultCode.indexOf("const remove = async"));
    expect(save).not.toContain("closeLayers");
  });
});

describe("quality-deadcode--7 — fmtDay has exactly one home", () => {
  it("ui/format.ts owns it", () => {
    expect(formatTs).toContain("export function fmtDay(");
    expect(fmtDay(Date.UTC(2026, 6, 14, 12))).toMatch(/14|July/); // locale-shaped, not ISO
    expect(fmtDay(undefined)).toBe("soon");
  });

  it("neither view declares its own copy any more", () => {
    expect(vaultTsx).not.toMatch(/function fmtDay\(/);
    expect(sharingTsx).not.toMatch(/function fmtDay\(/);
    expect(vaultTsx).toMatch(/import \{ fmtDay, humanSize \} from "\.\/format"/);
    expect(sharingTsx).toMatch(/import \{ fmtDay \} from "\.\/format"/);
  });
});
