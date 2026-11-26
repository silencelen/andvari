import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import type { ApiClient } from "../api/client";
import { initSodium } from "../crypto/sodium";
import { memoryClientState } from "../vault/accountstatesync";
import { FakeSharedLogs, testAccount } from "../vault/fakesharedlogs.testkit";
import { NullCache } from "../vault/idbcache";
import type { HeldChange } from "../vault/logstore";
import { VaultStore } from "../vault/store";
import { fill, RESEND_GIVEN_UP_ADD, RESEND_NOT_MADE_ADD, RESEND_NOT_MADE_CHANGE, RESEND_NOT_MADE_REMOVE, RESEND_SOMEONE } from "./copy";
import { noticeBody } from "./Vault";

/**
 * A change kept to be sent again that does not happen when it is sent again is said at that moment, where the person
 * sees it (the vault screen's notices), with what it was and whom it named: a removal never quietly does not happen.
 * A change that is made, or still waits, says nothing here (its panel shows it waiting).
 */
const B = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const V = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";

/** A server with nothing new: its sync answer fills no vault. */
const emptyWire = {
  sync: async () => ({ rev: 1, full: false, vaults: [], grants: [], items: [], removedGrants: [] }),
  pushMutations: async () => ({ rev: 1, results: [] }),
};

function change(kind: HeldChange["kind"], memberLabel: string | null = "Bea"): HeldChange {
  return { vaultId: V, kind, member: kind === "delete" ? null : B, memberLabel, heldAt: 0, known: "unknown", withdrawable: false };
}

describe("the unlock's re-send of held changes says each one that did not happen", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("refused, its place taken, not in the log, given up: one notice each, with what it was (the sentences; the vault's name is the real store's, in store.move-everything.test.ts)", async () => {
    const account = testAccount();
    const store = new VaultStore(emptyWire as unknown as ApiClient, account, new NullCache(), memoryClientState(), emptyWire as never);
    const logs = new FakeSharedLogs(account).attachTo(store);
    logs.resent = [{ change: change("remove"), outcome: { kind: "head_moved", vaultId: V } }];
    await store.resendHeldChanges();
    // Before the session's first pull a vault it cannot name yet waits for that pull.
    expect(store.notices()).toEqual([]);
    await store.sync();
    const n = store.notices();
    expect(n).toHaveLength(1);
    expect(n[0]).toMatchObject({ kind: "held-not-made", vaultId: V, heldKind: "remove", memberName: "Bea", reason: "head_moved" });
    expect(noticeBody({ ...n[0]!, vaultName: "Family" }).body).toBe(fill(RESEND_NOT_MADE_REMOVE, "Bea", "Family"));
    expect(noticeBody(n[0]!).warn).toBe(true);

    for (const [c, outcome, body] of [
      [change("add"), { kind: "refused", vaultId: V, code: "not_connected" }, fill(RESEND_NOT_MADE_ADD, "Bea", "Family")],
      [change("add", null), { kind: "not_made", vaultId: V }, fill(RESEND_NOT_MADE_ADD, RESEND_SOMEONE, "Family")],
      [change("delete"), { kind: "refused", vaultId: V, code: "no_grant" }, fill(RESEND_NOT_MADE_CHANGE, "Family")],
      [change("add"), { kind: "given_up", vaultId: V, made: "unknown" }, fill(RESEND_GIVEN_UP_ADD, "Bea", "Family")],
      [change("add"), { kind: "given_up", vaultId: V, made: false }, fill(RESEND_NOT_MADE_ADD, "Bea", "Family")],
    ] as const) {
      for (const old of store.notices()) store.dismissNotice(old.id);
      logs.resent = [{ change: c, outcome }];
      await store.resendHeldChanges();
      const [one] = store.notices();
      expect(noticeBody({ ...one!, vaultName: "Family" }).body).toBe(body);
    }
  });

  it("the unlock sends them again through the store, which says the outcomes (never the log store's bare re-send)", () => {
    const open = readFileSync(fileURLToPath(new URL("./opensession.ts", import.meta.url)), "utf8");
    expect(open).toContain("await store.resendHeldChanges()");
    expect(open).not.toContain("retryPending(");
  });

  it("made, or still waiting: nothing is said", async () => {
    const account = testAccount();
    const store = new VaultStore({} as ApiClient, account, new NullCache(), memoryClientState(), {} as never);
    const logs = new FakeSharedLogs(account).attachTo(store);
    logs.resent = [
      { change: change("remove"), outcome: { kind: "pending", vaultId: V, known: "unknown" } },
      { change: change("add"), outcome: { kind: "appended", vaultId: V, state: {} as never } },
    ];
    await store.resendHeldChanges();
    expect(store.notices()).toEqual([]);
  });
});
