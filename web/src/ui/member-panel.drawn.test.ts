import { createElement } from "react";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import type { ApiClient } from "../api/client";
import type { HeldChange } from "../vault/logstore";
import type { SharedLogSession } from "../vault/sharedlogs";
import { ChangeNotStoredError, type VaultStore } from "../vault/store";
import { buttonNamed, click, closePage, draw, type Drawn, openPage } from "./dom.testkit";
import { heldWaitingText } from "./heldtext";
import { MemberPanel } from "./Sharing";

/**
 * The member panel, drawn: an addition whose answer was lost (or that the server asked to slow down) is held, and the
 * panel's line that it waits, with its Withdraw where it may be withdrawn, appears at once after the person's click on
 * Add, with nothing else redrawing the panel (no sync, no other change of the vault).
 */
const V = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
const ME = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const B = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

/** The store as the panel reads it: one owner, one current contact (Bob) to add, and the change it holds, if any. */
function fakeStore(known: "unknown" | "not_stored") {
  let held: HeldChange | null = null;
  const shared = {
    contacts: { list: () => [{ record: { userId: B, identityPub: "k", label: "", method: "link", verifiedAt: 1, compared: true, madeOn: ME, extra: new Map() }, current: "confirmed", labelText: "Bob" }] },
    logs: { verifiedState: () => ({ members: { [ME]: { role: "owner", key: "k" } } }), refusedOffer: () => null, dismissRefusedOffer: () => {} },
  } as unknown as SharedLogSession;
  const known_ = {
    memberRoster: () => ({ rows: [{ userId: ME, role: "owner", label: null, self: true }], mayBeIncomplete: false, stale: false }),
    sharedLogs: () => shared,
    pendingTransferFor: () => null,
    moveDeleteWaiting: () => false,
    movePlan: () => null,
    heldChangeFor: () => held,
    list: () => [],
    addVaultMember: async () => {
      held = { vaultId: V, kind: "add", member: B, memberLabel: "Bob", heldAt: 1, known, withdrawable: known === "not_stored" };
      throw new ChangeNotStoredError(V, "add", known);
    },
  };
  // Every other question the panel's parts ask of the store has no answer here.
  return new Proxy(known_, { get: (t, k) => (k in t ? t[k as keyof typeof t] : () => null) }) as unknown as VaultStore;
}

describe("the member panel draws the line for a change that waits at once", () => {
  let drawn: Drawn | null = null;
  beforeAll(() => {
    openPage();
  });
  afterAll(async () => {
    await closePage();
  });
  afterEach(async () => {
    await drawn?.unmount();
    drawn = null;
  });

  for (const known of ["unknown", "not_stored"] as const) {
    it(`an addition held (${known}): its waiting line shows right after the click on Add`, async () => {
      const store = fakeStore(known);
      const onChanged = vi.fn();
      const client = { vaultMembers: async () => [] } as unknown as ApiClient;
      drawn = await draw(
        createElement(MemberPanel, {
          vault: { vaultId: V, type: "shared", name: "Family", role: "owner" },
          store,
          client,
          onChanged,
          onBackup: () => {},
          copying: null,
          setCopying: () => {},
          copiedNote: "",
          setCopiedNote: () => {},
          onDeletedNote: () => {},
          onMovedNote: () => {},
        }),
      );
      const page = drawn.page;
      const line = heldWaitingText({ vaultId: V, kind: "add", member: B, memberLabel: "Bob", heldAt: 1, known, withdrawable: known === "not_stored" }) as string;
      expect(page.textContent).not.toContain(line);
      await click(page.querySelector(`input[type=radio][value="${B}"], input[type=radio]`) as Element);
      await click(buttonNamed(page, "Add"));
      expect(page.textContent).toContain(line);
      expect(onChanged).not.toHaveBeenCalled(); // nothing else redrew the panel
    });
  }
});
