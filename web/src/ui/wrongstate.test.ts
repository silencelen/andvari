import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import type { MoveResult } from "../vault/store";
import { deviceListFailedText } from "./AccountDevices";
import {
  DEVICES_RELOAD_FAILED,
  DEVICES_REVOKED,
  DEVICES_UNAVAILABLE,
  fill,
  IMPORT_TOTP_DIFFERS,
  IMPORT_TOTP_DIFFERS_PREVIEW,
  MOVE_CHANGED_MEANWHILE,
  MOVE_CHANGED_MOVED_ON,
  MOVE_DONE,
  MOVE_DONE_ALONE,
  MOVE_DONE_ALONE_BANNER,
  MOVE_DONE_BANNER,
  MOVE_DONE_NO_DAY,
  MOVE_DONE_ALONE_NO_DAY,
  MOVE_DONE_BANNER_NO_DAY,
  MOVE_DONE_ALONE_BANNER_NO_DAY,
  withoutLastSentence,
} from "./copy";
import { moveResultText } from "./Sharing";
import { importTotpDiffersText } from "./Vault";

const src = (p: string) => readFileSync(fileURLToPath(new URL(p, import.meta.url)), "utf8");

/** Lines that were said in a state where they are untrue: each is now said only where it is true. */
describe("lines said in the wrong state", () => {
  it("a revoke the server confirmed whose list reload failed says the device was signed out, never 'nothing changed'", () => {
    expect(deviceListFailedText(true)).toBe(`${DEVICES_REVOKED} ${DEVICES_RELOAD_FAILED}`);
    expect(deviceListFailedText(true)).not.toContain(DEVICES_UNAVAILABLE);
    expect(deviceListFailedText(false)).toBe(DEVICES_UNAVAILABLE);
    // The reload after a revoke goes to the info line (what the Announcer reads with it), not to the error.
    const card = src("./AccountDevices.tsx");
    expect(card).toContain("await load(true);");
    expect(card).toMatch(/if \(afterRevoke\) setInfo\(t\);/);
  });

  it("the import's preview says what will be imported, the finished screen what was", () => {
    expect(importTotpDiffersText(true)).toBe(IMPORT_TOTP_DIFFERS_PREVIEW);
    expect(importTotpDiffersText(false)).toBe(IMPORT_TOTP_DIFFERS);
    const vault = src("./Vault.tsx");
    expect(vault).toContain("<ReportTiles report={report} done={false} />\n          <ReportBuckets report={report} preview />");
  });

  const base: MoveResult = { newVaultId: "n", name: "Family 2", copied: 2, oldDeleted: null, oldKept: null, notAdded: [], added: 0, uncopyable: 0, changed: 0, discarded: null };

  it("a move kept because the old vault's log moved on says so, never '0 items changed after they were copied'", () => {
    const t = moveResultText({ ...base, oldKept: "moved_on" }, "Family");
    expect(t).toContain(fill(MOVE_CHANGED_MOVED_ON, "", "Family"));
    expect(t).not.toContain(fill(MOVE_CHANGED_MEANWHILE, "0 items", "Family"));
  });

  it("a move finished from the banner names Sharing's trash icon, not one 'above'", () => {
    const done = { ...base, oldDeleted: { purgeAt: 1_800_000_000_000 } };
    for (const [added, panel, banner] of [[1, MOVE_DONE, MOVE_DONE_BANNER], [0, MOVE_DONE_ALONE, MOVE_DONE_ALONE_BANNER]] as const) {
      const r = { ...done, added };
      expect(moveResultText(r, "Family", "Family 2", null, true).startsWith(fill(banner, "Family 2", "Family", "").slice(0, 20))).toBe(true);
      expect(moveResultText(r, "Family", "Family 2", null, true)).not.toBe(moveResultText(r, "Family", "Family 2", null, false));
      expect(moveResultText(r, "Family", "Family 2", null, false).startsWith(fill(panel, "Family 2", "Family", "").slice(0, 20))).toBe(true);
    }
    // The banner's own call passes it; the panel's does not.
    const sharing = src("./Sharing.tsx");
    expect(sharing).toMatch(/setSaid\(\{ vaultId: m\.vaultId, text: moveResultText\([^;]*, true\), ok: true \}\)/);
  });

  it("a finished move whose old vault's restore day the server did not serve names no day and points to the deleted vaults, in the panel and in the banner", () => {
    const done = { ...base, oldDeleted: { purgeAt: null } };
    for (const [added, panel, banner] of [[1, MOVE_DONE_NO_DAY, MOVE_DONE_BANNER_NO_DAY], [0, MOVE_DONE_ALONE_NO_DAY, MOVE_DONE_ALONE_BANNER_NO_DAY]] as const) {
      const r = { ...done, added };
      expect(moveResultText(r, "Family", "Family 2", null, false)).toBe(fill(panel, "Family 2", "Family"));
      expect(moveResultText(r, "Family", "Family 2", null, true)).toBe(fill(banner, "Family 2", "Family"));
    }
    expect(MOVE_DONE_ALONE_NO_DAY).toBe(withoutLastSentence(MOVE_DONE_NO_DAY));
  });

  it("'won't be deleted, delete it yourself' is not shown while the old vault's deletion waits; 'the server deleted' names no one", () => {
    const sharing = src("./Sharing.tsx");
    expect(sharing).toContain("{someoneLeftOut && !deleteWaiting && <p className=\"muted\">{fill(MOVE_KEEPS_OLD, vault.name)}</p>}");
    expect(sharing).toContain("{someoneLeftOut && deleteWaiting && <p className=\"muted\">{fill(MOVE_KEEPS_OLD_WAITING, vault.name)}</p>}");
    const vault = src("./Vault.tsx");
    expect(vault).toContain("fill(MOVE_DELETED_OUTSIDE, name, newName)");
    expect(vault).not.toContain("fill(MOVE_STORED_OUTSIDE");
  });
});
