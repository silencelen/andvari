// What a person removed from a shared vault changed before the removal, and what a resync's failed removal keeps: real
// VaultStore, SharedLogSession and VaultLogStore against the fake server of fakesyncserver.testkit.ts.
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { beforeAll, describe, expect, it, vi } from "vitest";
import { initSodium } from "../crypto/sodium";
import { fill, SHARE_ASK_WAITING, SHARE_ASK_WAITING_ONE } from "../ui/copy";
import { SharedPrompts } from "../ui/SharedPrompts";
import { ALICE, BOB, type Browser, family, freshDb, listed, namesIn, noticesOf } from "./fakesyncserver.testkit";
import { openVaultCache } from "./idbcache";

type Wire = { pushMutations: (...a: unknown[]) => Promise<unknown> };
const wireOf = (b: Browser): Wire => (b.store as unknown as { wire: Wire }).wire;

async function offline(b: Browser, fn: () => Promise<unknown>): Promise<void> {
  const wire = wireOf(b);
  const send = wire.pushMutations;
  wire.pushMutations = () => Promise.reject(new TypeError("offline"));
  try {
    await fn();
  } finally {
    wire.pushMutations = send;
  }
}

const removeAndAddAgain = async (alice: Browser, vaultId: string): Promise<void> => {
  await alice.store.removeVaultMember(vaultId, BOB);
  await alice.store.sync();
  await alice.store.addVaultMember(vaultId, BOB, "writer");
  await alice.store.sync();
};

/** The question answers no for [vaultId] alone, as it does for a key that no longer works; every other layer as it is. */
function questionSaysNo(who: Browser, vaultId: string): void {
  const account = who.account as unknown as { mayWrite: (v: string) => boolean };
  const asked = account.mayWrite.bind(account);
  account.mayWrite = (v) => v !== vaultId && asked(v);
}

/** Bob deletes "bank" offline (queued); the owner removes and adds him again; a read outside a pull moves his log. */
async function keyNoLongerWorks() {
  freshDb();
  const { server, alice, bob, old } = await family(await openVaultCache(BOB));
  const bank = bob.store.list().find((i) => i.vaultId === old)!;
  await removeAndAddAgain(alice, old);
  await bob.shared.logs.refresh(old, null, null, true);
  expect(bob.store.mayWrite(old)).toBe(false);
  return { server, alice, bob, old, bank };
}

const rowsAtRest = async (vaultId: string): Promise<number> => (await (await openVaultCache(BOB)).envelopes()).filter((w) => w.vaultId === vaultId).length;
const heldAtRest = async (vaultId: string): Promise<number[]> =>
  (await (await openVaultCache(BOB)).heldVaults()).filter((h) => h.vault.vaultId === vaultId && h.setAside !== true).map((h) => h.items.length);

describe("a person removed and added again", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("the question to join again says how many changes made before the removal wait here, and a yes then sends them", async () => {
    vi.stubGlobal("navigator", { storage: { persisted: async () => true } });
    try {
      freshDb();
      const { server, alice, bob, old } = await family(await openVaultCache(BOB));
      const bankId = bob.store.list().find((i) => i.vaultId === old)!.itemId;
      await offline(bob, () => bob.store.remove(bankId));
      await removeAndAddAgain(alice, old);
      await bob.shared.logs.refresh(old, null, null, true);
      await bob.store.sync().catch(() => {});
      await bob.store.sync().catch(() => {});
      const ask = bob.shared.pendingAsks().find((a) => a.vaultId === old)!;
      const drawn = renderToStaticMarkup(createElement(SharedPrompts, { shared: bob.shared, onChanged: () => {} }));
      const before = server.writes.length;
      expect((await bob.shared.answer(ask, true)).kind).toBe("adopted");
      await bob.store.sync().catch(() => {});
      await bob.store.sync().catch(() => {});
      expect({
        waiting: ask.waiting,
        lineDrawn: drawn.includes(fill(SHARE_ASK_WAITING_ONE, ask.vaultName)),
        toldBefore: noticesOf(bob, old).slice(0, 1),
        listed: listed(bob.store, old),
        writes: server.writes.slice(before),
        deletedOnServer: server.items.get(bankId)?.deleted,
      }).toEqual({ waiting: 1, lineDrawn: true, toldBefore: ["removed"], listed: true, writes: [`selfwrap:${old}`, `push:${old}`], deletedOnServer: true });
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("with nothing changed before the removal, the question says nothing more", async () => {
    freshDb();
    const { alice, bob, old } = await family(await openVaultCache(BOB));
    await removeAndAddAgain(alice, old);
    await bob.store.sync().catch(() => {});
    await bob.store.sync().catch(() => {});
    const ask = bob.shared.pendingAsks().find((a) => a.vaultId === old)!;
    const drawn = renderToStaticMarkup(createElement(SharedPrompts, { shared: bob.shared, onChanged: () => {} }));
    expect({ waiting: ask.waiting, one: drawn.includes(fill(SHARE_ASK_WAITING_ONE, ask.vaultName)), many: drawn.includes(SHARE_ASK_WAITING.slice(0, 12)) }).toEqual({ waiting: 0, one: false, many: false });
  });

  // Removed once (a held copy), added again, a yes, the vault listed again with its item; removed again; the next pull is
  // a resync, and the removal's road throws part-way: once having put an older held copy of the vault back in memory,
  // once having taken the vault's row out of the working set. Either way the vault's rows stay at rest as they were.
  for (const how of ["an older held copy", "the vault's row gone"] as const) {
    it(`a resync whose removal road throws keeps the vault's rows at rest (${how})`, async () => {
      freshDb();
      const { server, alice, bob, old } = await family(await openVaultCache(BOB));
      await removeAndAddAgain(alice, old);
      await bob.store.sync().catch(() => {});
      await bob.store.sync().catch(() => {});
      const inside = bob.store as unknown as { holding: Map<string, unknown>; vaultsById: Map<string, unknown>; handleLogRemoval: (...a: unknown[]) => Promise<boolean> };
      const older = inside.holding.get(old);
      expect({ older: older !== undefined, atRest: await heldAtRest(old) }).toEqual({ older: true, atRest: [1] });
      expect((await bob.shared.answer(bob.shared.pendingAsks().find((a) => a.vaultId === old)!, true)).kind).toBe("adopted");
      await bob.store.sync().catch(() => {});
      await bob.store.sync().catch(() => {});
      expect({ listed: listed(bob.store, old), names: namesIn(bob, old), held: inside.holding.has(old), rows: await rowsAtRest(old) }).toEqual({ listed: true, names: ["bank"], held: false, rows: 1 });
      await alice.store.removeVaultMember(old, BOB);
      await alice.store.sync();
      server.forgetHistory();
      inside.handleLogRemoval = async () => {
        if (how === "an older held copy") inside.holding.set(old, older);
        else inside.vaultsById.delete(old);
        throw new Error("the removal's road failed part-way");
      };
      await bob.store.sync().catch(() => {});
      expect({ rows: await rowsAtRest(old), heldAtRest: await heldAtRest(old) }).toEqual({ rows: 1, heldAtRest: [] });
    });
  }
});

// Each place of the closed list (api/sends.test.ts) that asks, reached at that very call while the question says no:
// nothing is sent. Each was shown red with its question taken back.
describe("each place that asks mayWrite is asked at the call that sends", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("vault/store.ts pushMutations, in sendItemChanges: a writer whose key no longer works sends no change", async () => {
    const { server, bob, old, bank } = await keyNoLongerWorks();
    const before = server.writes.length;
    const send = (bob.store as unknown as { sendItemChanges: (m: unknown[]) => Promise<unknown> }).sendItemChanges.bind(bob.store);
    const out = await send([{ mutationId: crypto.randomUUID(), op: "delete", itemId: bank.itemId, vaultId: old, baseItemRev: bank.rev }]).then(
      () => "sent",
      (e: unknown) => (e as Error).name,
    );
    expect({ out, writes: server.writes.slice(before), deleted: server.items.get(bank.itemId)?.deleted }).toEqual({ out: "VaultKeyNotVerifiedError", writes: [], deleted: false });
  });

  it("vault/store.ts restoreItem, in restoreDeleted: the owner, with the question saying no, brings nothing back", async () => {
    freshDb();
    const { server, alice, old } = await family(await openVaultCache(BOB));
    const bank = alice.store.list().find((i) => i.vaultId === old)!;
    await alice.store.remove(bank.itemId);
    questionSaysNo(alice, old);
    const before = server.writes.length;
    await alice.store.restoreDeleted(bank.itemId, old, bank.doc).catch(() => {});
    expect(server.writes.slice(before)).toEqual([]);
  });

  it("vault/store.ts purgeItem, in purgeDeleted: the owner, with the question saying no, removes nothing for good", async () => {
    freshDb();
    const { server, alice, old } = await family(await openVaultCache(BOB));
    const bank = alice.store.list().find((i) => i.vaultId === old)!;
    await alice.store.remove(bank.itemId);
    questionSaysNo(alice, old);
    const before = server.writes.length;
    await alice.store.purgeDeleted(bank.itemId, old).catch(() => {});
    expect(server.writes.slice(before)).toEqual([]);
  });

  it("vault/store.ts uploadAttachment, in uploadInto: the owner, with the question saying no, uploads nothing", async () => {
    freshDb();
    const { server, alice, old } = await family(await openVaultCache(BOB));
    const bank = alice.store.list().find((i) => i.vaultId === old)!;
    questionSaysNo(alice, old);
    const before = server.writes.length;
    const upload = (alice.store as unknown as { uploadInto: (v: string, id: string, itemId: string, b: Uint8Array) => Promise<unknown> }).uploadInto.bind(alice.store);
    await upload(old, crypto.randomUUID(), bank.itemId, new Uint8Array([1, 2, 3])).catch(() => {});
    expect(server.writes.slice(before)).toEqual([]);
  });

  it("vault/store.ts updateVaultMeta, in renameVault: the owner, with the question saying no, renames nothing", async () => {
    freshDb();
    const { server, alice, old } = await family(await openVaultCache(BOB));
    questionSaysNo(alice, old);
    const before = server.writes.length;
    await alice.store.renameVault(old, "Other").catch(() => {});
    expect(server.writes.slice(before)).toEqual([]);
  });

  it("vault/logstore.ts appendLog, in postOnce: the owner, with the question saying no, posts no entry of the vault's log", async () => {
    freshDb();
    const { server, alice, old } = await family(await openVaultCache(BOB));
    questionSaysNo(alice, old);
    const before = server.writes.length;
    const outs: string[] = [];
    for (const action of [
      { kind: "role", member: BOB, role: "reader" },
      { kind: "remove", member: BOB },
      { kind: "offer", to: BOB, expiresInMs: 60_000 },
      { kind: "delete" },
    ] as const)
      outs.push((await alice.shared.logs.append(old, action)).kind);
    expect({ outs, writes: server.writes.slice(before) }).toEqual({ outs: ["not_allowed", "not_allowed", "not_allowed", "not_allowed"], writes: [] });
  });
});

// Each exempt place opens for exactly what it is exempt for, and for nothing else.
describe("each exemption opens for exactly that", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("a leave: a writer whose key no longer works posts the leave, and only the leave", async () => {
    const { server, alice, bob, old } = await keyNoLongerWorks();
    questionSaysNo(alice, old);
    const before = server.writes.length;
    await alice.shared.logs.append(old, { kind: "role", member: BOB, role: "reader" });
    await bob.shared.logs.append(old, { kind: "role", member: ALICE, role: "reader" }).catch(() => {});
    await bob.store.leaveSharedVault(old).catch(() => {});
    expect(server.writes.slice(before)).toEqual([`log-leave:${old}`]);
  });

  it("a new log's first entry: with the question saying no for every vault, a new vault is created, and nothing more is posted to it", async () => {
    freshDb();
    const { server, alice } = await family(await openVaultCache(BOB));
    const account = alice.account as unknown as { mayWrite: (v: string) => boolean };
    const asked = account.mayWrite.bind(account);
    const before = server.writes.length;
    account.mayWrite = () => false;
    const made = await alice.shared.logs.append(null, { kind: "create", name: "New" });
    const fresh = made.kind === "appended" ? made.vaultId : "";
    const add = { kind: "add", contactUserId: BOB, role: "writer", releaseUncompared: true } as const;
    const after = (await alice.shared.logs.append(fresh, add)).kind;
    const closed = server.writes.slice(before);
    // Control: the same add with the question answering as it does posts, so what stopped it above was the question.
    account.mayWrite = asked;
    const open = (await alice.shared.logs.append(fresh, add)).kind;
    expect({ made: made.kind, after, closed, open }).toEqual({ made: "appended", after: "not_allowed", closed: [`log-genesis:${fresh}`], open: "appended" });
  });

  it("the owner's restore, an honest log: it goes out, and the vault is listed again", async () => {
    freshDb();
    const { server, alice, old } = await family(await openVaultCache(BOB));
    await alice.store.deleteSharedVault(old);
    const deleteId = alice.shared.logs.verifiedState(old)!.deleteId!;
    expect(alice.store.mayWrite(old)).toBe(false);
    const before = server.writes.length;
    await alice.store.restoreSharedVault(old, deleteId);
    expect({ writes: server.writes.slice(before), listed: listed(alice.store, old), names: namesIn(alice, old) }).toEqual({ writes: [`log-restore:${old}`], listed: true, names: ["bank"] });
  });

  it("the owner's restore while the log is withheld at that moment sends nothing", async () => {
    freshDb();
    const { server, alice, old } = await family(await openVaultCache(BOB));
    await alice.store.deleteSharedVault(old);
    const n = server.logs.get(old)!.length;
    server.logCut.set(old, n - 1);
    await alice.shared.logs.refresh(old, null, null, true);
    const st = alice.shared.logs.status(old).kind;
    const before = server.writes.length;
    await alice.store.restoreSharedVault(old, "x").catch(() => {});
    const deleteId = (alice.shared.logs as unknown as { loadState: (v: string) => { deleteId: string | null } | null }).loadState(old)?.deleteId ?? "none";
    await alice.store.restoreSharedVault(old, deleteId).catch(() => {});
    expect({ st, writes: server.writes.slice(before) }).toEqual({ st: "withheld", writes: [] });
  });

  it("a member who is not the owner cannot post a restore of a vault deleted by its owner", async () => {
    freshDb();
    const { server, alice, bob, old } = await family(await openVaultCache(BOB));
    await alice.store.deleteSharedVault(old);
    await bob.shared.logs.refresh(old, null, null, true);
    const deleteId = bob.shared.logs.verifiedState(old)?.deleteId ?? "none";
    const before = server.writes.length;
    const out = await bob.shared.logs.append(old, { kind: "restore" });
    await bob.store.restoreSharedVault(old, deleteId).catch(() => {});
    expect({ out: out.kind, writes: server.writes.slice(before) }).toEqual({ out: "not_allowed", writes: [] });
  });

  it("the wrap of a key for oneself: posted once, after the yes, and not while the question to join again waits", async () => {
    freshDb();
    const { server, alice, bob, old } = await family(await openVaultCache(BOB));
    await removeAndAddAgain(alice, old);
    const before = server.writes.length;
    await bob.store.sync().catch(() => {});
    await bob.store.sync().catch(() => {});
    const asked = server.writes.slice(before);
    const ask = bob.shared.pendingAsks().find((a) => a.vaultId === old)!;
    expect((await bob.shared.answer(ask, true)).kind).toBe("adopted");
    await bob.store.sync().catch(() => {});
    await bob.store.sync().catch(() => {});
    expect({ asked, wraps: server.writes.slice(before).filter((w) => w.startsWith("selfwrap:")), others: server.writes.slice(before).filter((w) => !w.startsWith("selfwrap:")) }).toEqual({
      asked: [],
      wraps: [`selfwrap:${old}`],
      others: [],
    });
  });
});
