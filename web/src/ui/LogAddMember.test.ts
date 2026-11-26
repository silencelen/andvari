import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import type { SharedLogSession } from "../vault/sharedlogs";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { ChangeNotStoredError, LogActionError, type VaultStore } from "../vault/store";
import { LOG_ADD_NONE, LOG_NOT_COMPARED, LOG_NOT_CURRENT_CONTACT, LOG_NOT_TAKEN, LOG_READ_ONLY } from "./copy";
import { addFromPanel, LogAddMember } from "./LogAddMember";
import { logActionText } from "./logactiontext";
import { runNotingHeld } from "./Sharing";

/** Adding a member to a log-governed vault picks a CURRENT contact (design §6.9), rendered statically from a fake session. */

const V = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
const A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const B = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const C = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
const D = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";

function fake(contacts: { userId: string; label: string; current: boolean; compared: boolean }[], members: string[]): SharedLogSession {
  return {
    contacts: {
      list: () =>
        contacts.map((c) => ({
          record: { userId: c.userId, identityPub: "k", label: "", method: "link", verifiedAt: 1, compared: c.compared, madeOn: A, extra: new Map() },
          current: c.current ? "confirmed" : null,
          labelText: c.label,
        })),
    },
    logs: { verifiedState: () => ({ members: Object.fromEntries(members.map((m) => [m, { role: "writer", key: "k" }])) }) },
  } as unknown as SharedLogSession;
}

const render = (shared: SharedLogSession) => renderToStaticMarkup(createElement(LogAddMember, { vaultId: V, store: {} as VaultStore, shared, onAdded: async () => {}, onHeld: () => {} }));

describe("LogAddMember", () => {
  it("lists only current contacts who are not members, as plain text; an uncompared one cannot be picked", () => {
    const html = render(
      fake(
        [
          { userId: B, label: "Bob <i>x</i>", current: true, compared: true },
          { userId: C, label: "Carol", current: true, compared: false },
          { userId: D, label: "Dave", current: false, compared: true },
          { userId: A, label: "Already in", current: true, compared: true },
        ],
        [A],
      ),
    );
    expect(html).toContain("Bob &lt;i&gt;x&lt;/i&gt;");
    expect(html).toContain("Carol");
    expect(html).not.toContain("Dave");
    expect(html).not.toContain("Already in");
    expect(html).toContain(LOG_NOT_COMPARED.replace(/'/g, "&#x27;"));
    expect((html.match(/disabled=""/g) ?? []).length).toBe(2); // Carol's radio and the Add button (nothing picked)
  });

  it("says so when no contact can be added", () => {
    expect(render(fake([{ userId: D, label: "Dave", current: false, compared: true }], []))).toContain(LOG_ADD_NONE.replace(/'/g, "&#x27;"));
  });

  it("each refusal of the log reads as its own sentence", () => {
    expect(logActionText(new LogActionError({ kind: "not_allowed", reason: "not_a_current_contact" }))).toBe(LOG_NOT_CURRENT_CONTACT);
    expect(logActionText(new LogActionError({ kind: "read_only", vaultId: V }))).toBe(LOG_READ_ONLY);
    expect(logActionText(new LogActionError({ kind: "refused", vaultId: V, code: "not_owner" }))).toBe(LOG_NOT_TAKEN.replace("{0}", "not_owner"));
  });

  it("an addition held ('cannot tell', or the server asked to slow down) redraws the member panel at once, so its waiting line and Withdraw show now", async () => {
    for (const known of ["unknown", "not_stored"] as const) {
      const e = new ChangeNotStoredError(V, "add", known);
      let held = 0;
      let added = 0;
      const line = await addFromPanel({ addVaultMember: async () => Promise.reject(e) }, V, B, "writer", async () => void added++, () => void held++);
      expect([held, added], known).toEqual([1, 0]);
      expect(line).toBe(logActionText(e));
    }
    // A refusal holds nothing: no redraw for a waiting line, the line says why.
    let held = 0;
    const refused = new LogActionError({ kind: "refused", vaultId: V, code: "not_owner" });
    expect(await addFromPanel({ addVaultMember: async () => Promise.reject(refused) }, V, B, "writer", async () => {}, () => void held++)).toBe(logActionText(refused));
    expect(held).toBe(0);
    // Made: "" and the panel's own redraw.
    let added = 0;
    expect(await addFromPanel({ addVaultMember: async () => {} }, V, B, "writer", async () => void added++, () => void held++)).toBe("");
    expect([held, added]).toEqual([0, 1]);
  });

  it("the member panel passes that redraw to the addition", () => {
    // The panel draws the waiting line (WaitingChange) and holds no subscription to the store: the addition's own
    // callback is what redraws it.
    const src = readFileSync(fileURLToPath(new URL("./Sharing.tsx", import.meta.url)), "utf8");
    const at = src.indexOf("<LogAddMember");
    expect(at).toBeGreaterThan(0);
    expect(src.slice(at, src.indexOf("/>", at))).toMatch(/onHeld=\{\(\) => setTick\(/);
  });

  it("an ownership offer or a vault's deletion that is held ('cannot tell', or slow down) redraws the panel at once too, and the error still reaches the control", async () => {
    for (const action of ["offer", "delete"] as const) {
      for (const known of ["unknown", "not_stored"] as const) {
        const e = new ChangeNotStoredError(V, action, known);
        let held = 0;
        await expect(runNotingHeld(async () => Promise.reject(e), () => void held++)).rejects.toBe(e);
        expect(held, `${action} ${known}`).toBe(1);
      }
    }
    let held = 0;
    const refused = new LogActionError({ kind: "refused", vaultId: V, code: "not_owner" });
    await expect(runNotingHeld(async () => Promise.reject(refused), () => void held++)).rejects.toBe(refused);
    expect(await runNotingHeld(async () => 7, () => void held++)).toBe(7);
    expect(held).toBe(0);
    // On the code before: the two controls set an error in their own state only, and the panel drew no waiting line.
    const src = readFileSync(fileURLToPath(new URL("./Sharing.tsx", import.meta.url)), "utf8");
    expect(src).toContain("runNotingHeld(() => store.offerTransfer(vault.vaultId, target), onHeld)");
    expect(src).toContain("runNotingHeld(() => store.deleteSharedVault(vault.vaultId), onHeld)");
    for (const tag of ["<TransferOfferControl", "<DeleteVaultControl"]) {
      const at = src.indexOf(tag);
      expect(at, tag).toBeGreaterThan(0);
      expect(src.slice(at, src.indexOf("/>", at)), tag).toMatch(/onHeld=\{\(\) => setTick\(/);
    }
  });
});
