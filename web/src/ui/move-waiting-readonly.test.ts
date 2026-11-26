import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import type { ApiClient } from "../api/client";
import { LogActionError, MoveWaitingError, type VaultInfo, type VaultItem, type VaultStore } from "../vault/store";
import { fill, LOG_APPEND_UNCONFIRMED, MOVE_WAITING_READ_ONLY, MOVE_WAITING_REFUSED } from "./copy";
import { logActionText } from "./logactiontext";
import { saveErrorText } from "./saveerror";
import { friendlyError } from "./Sharing";
import { Detail } from "./Vault";

/**
 * Design §3.13 as decided on 2026-11-17: from the moment a move's deletion of the old vault is signed and until the move
 * is finished, the vault is read-only in this browser (the store refuses every road, store.move-everything.test.ts). The
 * screens offer nothing that would be refused, and one line says why and points to finishing the move.
 */
const here = dirname(fileURLToPath(import.meta.url));
const vault = readFileSync(join(here, "Vault.tsx"), "utf8");

describe("a vault whose move's deletion waits is read-only on the screens", () => {
  it("is no target for a new item, an import or a move into it", () => {
    expect(vault).toContain('const newItemVaultChoices = store.vaults().filter((v) => (v.type === "personal" || v.role === "owner" || v.role === "writer") && !store.moveDeleteWaiting(v.vaultId) && store.mayWrite(v.vaultId));');
    expect(vault).toContain('const vaultChoices = store.vaults().filter((v) => (v.type === "personal" || v.role === "owner" || v.role === "writer") && !store.moveDeleteWaiting(v.vaultId) && store.mayWrite(v.vaultId));');
    // The detail's move targets are the same list.
    expect(vault).toContain("moveTargets={newItemVaultChoices.filter((v) => v.vaultId !== current.vaultId)}");
  });

  it("its items open read-only (no edit, no delete, no move out), with the one line above them and above the list filtered to it", () => {
    expect(vault).toContain('readOnly={readOnlyCopy || account.roleFor(current.vaultId) === "reader" || store.moveDeleteWaiting(current.vaultId) || !store.mayWrite(current.vaultId)}');
    expect(vault).toContain("{moveWaitingLine(current.vaultId)}");
    expect(vault).toContain('{effVaultFilter !== "all" && moveWaitingLine(effVaultFilter)}');
    expect(vault).toContain("fill(MOVE_WAITING_READ_ONLY, vaultNameById.get(vaultId) ?? MOVE_UNNAMED_OLD)");
    expect(fill(MOVE_WAITING_READ_ONLY, "Family")).toBe("“Family” is read-only while its deletion waits for the server. Finish the move to go on.");
  });

  it("the walk of 2026-11-17: the read-only line keeps its distance from the banner above it, and copying late items refreshes the list", () => {
    expect(vault).toContain('<div className="msg info" style={{ display: "block", marginTop: 12 }} role="status">{fill(MOVE_WAITING_READ_ONLY,');
    expect(vault).toContain("<NoticesBanner notices={notices} onDismiss={dismissNotice} store={store} onCopied={refresh} />");
    expect(vault).toContain("onCopied?.();");
  });

  it("its trash rows offer no restore and no \"Delete forever\", with the read-only line above the list; a refusal anyway reads the move's sentence", () => {
    expect(vault).toContain('const readOnly = roleFor(d.vaultId) === "reader" || store.moveDeleteWaiting(d.vaultId) || !store.mayWrite(d.vaultId);');
    expect(vault).toContain("[...new Set((items ?? []).map((d) => d.vaultId))].filter((v) => store.moveDeleteWaiting(v)).map((v) => (");
    expect(vault).toContain("onClick={() => purge(d.itemId, d.vaultId)}");
    expect(vault.match(/e instanceof MoveWaitingError\n\s+\? MOVE_WAITING_REFUSED/g)).toHaveLength(2);
  });

  it("a change tried anyway is refused with the sentence that points to finishing the move, wherever it was tried", () => {
    const e = new MoveWaitingError("v");
    expect(saveErrorText(e, true)).toBe(MOVE_WAITING_REFUSED);
    expect(friendlyError(e)).toBe(MOVE_WAITING_REFUSED);
    expect(logActionText(new LogActionError({ kind: "not_allowed", reason: "move_delete_waiting" }))).toBe(MOVE_WAITING_REFUSED);
    expect(logActionText(new LogActionError({ kind: "not_allowed", reason: "append_pending" }))).toBe(LOG_APPEND_UNCONFIRMED);
    expect(MOVE_WAITING_REFUSED).toContain("Finish the move");
  });
});

/**
 * Decided on 23 November 2026: a shared vault whose log is frozen or withheld here can be read, and no device writes to
 * it. The store refuses every item write (VaultStore.mayWrite, store.closed-vault-writes.test.ts); the screens ask the
 * same question beside the conditions they already have for a member who may only read and for a move's wait.
 */
describe("a shared vault whose log lets nobody write is read-only on the screens", () => {
  it("is no target for a new item, an import or a move into it; its items and its trash rows are view only", () => {
    expect(vault.match(/const (newItemVaultChoices|vaultChoices) = store\.vaults\(\)\.filter\(.*!store\.moveDeleteWaiting\(v\.vaultId\) && store\.mayWrite\(v\.vaultId\)\);/g)).toHaveLength(2);
    expect(vault).toContain("moveTargets={newItemVaultChoices.filter((v) => v.vaultId !== current.vaultId)}");
    expect(vault).toContain('account.roleFor(current.vaultId) === "reader" || store.moveDeleteWaiting(current.vaultId) || !store.mayWrite(current.vaultId)}');
    expect(vault).toContain('roleFor(d.vaultId) === "reader" || store.moveDeleteWaiting(d.vaultId) || !store.mayWrite(d.vaultId);');
    // Asked in those four places and nowhere else on this screen.
    expect(vault.match(/store\.mayWrite\(/g)).toHaveLength(4);
  });

  // Decided on 23 November 2026 with the rule: people copy such a vault's items into a new vault, so copying an item out
  // stays open on the screen for a member whose role may write. A member whose role may only read is offered what the
  // screen offers such a member on any shared vault: no Edit, no Delete, no Move and no "Copy to vault…".
  it("an item of it offers a member whose role may write \"Copy to vault…\" and nothing that writes into it", () => {
    expect(vault).toContain('copyOut={!readOnlyCopy && account.roleFor(current.vaultId) !== "reader" && !store.moveDeleteWaiting(current.vaultId) && account.mayWrite(current.vaultId)}');
    const shown = detail({ readOnly: true, copyOut: true });
    expect(shown).toContain(">Copy to vault…</button>");
    expect(shown).not.toContain("Move to vault…");
    expect(shown).not.toContain(">Edit</button>");
    expect(shown).not.toContain(">Delete</button>");
    expect(shown).not.toContain("Delete forever");
    expect(shown).toContain(" · view only");
  });

  it("a member whose role may only read is offered no copy, no move, no edit and no delete, on an ordinary shared vault and on a closed one", () => {
    // For such a member the screen's readOnly is true on either vault (the role is asked first), and copyOut is false.
    expect(vault).toContain('readOnly={readOnlyCopy || account.roleFor(current.vaultId) === "reader" ||');
    expect(vault).toContain('copyOut={!readOnlyCopy && account.roleFor(current.vaultId) !== "reader" &&');
    const shown = detail({ readOnly: true, copyOut: false });
    expect(shown).toContain(" · view only");
    expect(shown).not.toContain("Copy to vault…");
    expect(shown).not.toContain("Move to vault…");
    expect(shown).not.toContain(">Edit</button>");
    expect(shown).not.toContain(">Delete</button>");
  });

  it("an item of a vault that may be written offers Edit, Delete, \"Move to vault…\" and \"Copy to vault…\" as before", () => {
    const shown = detail({ readOnly: false, copyOut: true });
    for (const control of [">Edit</button>", ">Delete</button>", ">Move to vault…</button>", ">Copy to vault…</button>"]) expect(shown).toContain(control);
  });
});

/** The item detail of the screen, drawn with [p] the way the screen passes them, for a login of a shared vault. */
function detail(p: { readOnly: boolean; copyOut: boolean }): string {
  const item: VaultItem = { itemId: "i1", vaultId: "shared", rev: 1, updatedAt: 0, formatVersion: 1, doc: { type: "login", name: "bank", login: { username: "a", password: "pw" } } };
  const targets: VaultInfo[] = [{ vaultId: "personal", type: "personal", name: "Personal", role: "owner" }];
  const noop = (): void => {};
  return renderToStaticMarkup(
    createElement(Detail, {
      item,
      client: {} as ApiClient,
      store: {} as VaultStore,
      policy: null,
      readOnly: p.readOnly,
      copyOut: p.copyOut,
      vaultName: "Family",
      moveTargets: targets,
      onUsed: noop,
      onEdit: noop,
      onDelete: async () => {},
      onMoved: noop,
      onBack: noop,
    }),
  );
}
