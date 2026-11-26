// The one attempt before a policy's wipe asks the store's question for every change at the moment its request is handed
// to the transport: where this tab has the account open, the open store's `mayWrite`; where it has not, only the
// personal vault that this browser's own session record names. A change the answer holds back is counted as one that
// could not be sent. Real VaultStore, SharedLogSession and VaultLogStore against the fake server of
// fakesyncserver.testkit.ts.
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import type { Mutation, PushResponse } from "../api/types";
import { initSodium } from "../crypto/sodium";
import { applyOrgOfflineCachePolicy, policyWipeQuestion, saveSession } from "../ui/session";
import { BOB, type Browser, browser, family, freshDb } from "./fakesyncserver.testkit";
import { openVaultCache, readWaiting } from "./idbcache";
import { sendWaitingOnce, senderForCopy } from "./policywipe";

function webStorage(): Storage {
  const m = new Map<string, string>();
  return {
    get length() {
      return m.size;
    },
    clear: () => m.clear(),
    getItem: (k: string) => m.get(k) ?? null,
    key: (i: number) => [...m.keys()][i] ?? null,
    removeItem: (k: string) => void m.delete(k),
    setItem: (k: string, v: string) => void m.set(k, v),
  } as Storage;
}

type Wire = { pushMutations: (...a: unknown[]) => Promise<unknown> };
const wireOf = (b: Browser): Wire => (b.store as unknown as { wire: Wire }).wire;

/** Runs [fn] with the item wire's sends failing as a request with no answer: what [fn] changes is queued. */
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

/** Bob deletes "bank" offline (queued), then the owner removes and adds him again, and a read outside a pull moves his log. */
async function queuedThenMoved() {
  freshDb();
  const { server, alice, bob, old } = await family(await openVaultCache(BOB));
  const bankId = bob.store.list().find((i) => i.vaultId === old)!.itemId;
  await offline(bob, () => bob.store.remove(bankId));
  expect({ queued: await bob.store.queuedMutationCount(), deleted: server.items.get(bankId)?.deleted }).toEqual({ queued: 1, deleted: false });
  await removeAndAddAgain(alice, old);
  await bob.shared.logs.refresh(old, null, null, true);
  expect(bob.store.mayWrite(old)).toBe(false);
  return { server, alice, bob, old, bankId };
}

const client = { getTokens: () => ({}), boundUserId: BOB };

/** The account open in a tab, as App.loadPolicy hands it to the question. */
const openIn = (b: Browser) => ({ userId: b.account.userId, personalVaultId: b.account.personalVaultId, pulled: () => b.store.pulledInThisSession(), mayWrite: (v: string) => b.store.mayWrite(v) });

describe("the one attempt before a policy's wipe asks mayWrite for every change", () => {
  beforeAll(async () => {
    await initSodium();
  });
  beforeEach(() => {
    vi.stubGlobal("localStorage", webStorage());
    vi.stubGlobal("sessionStorage", webStorage());
    vi.stubGlobal("navigator", { storage: { persisted: async () => true } });
  });
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("with the account open in this tab: a change queued for a vault whose key no longer works is not sent, and is counted as not sent", async () => {
    const { server, bob, bankId } = await queuedThenMoved();
    const before = server.writes.length;
    const mayWrite = policyWipeQuestion(openIn(bob), BOB);
    const send = senderForCopy(client, wireOf(bob) as never, BOB, mayWrite);
    expect(bob.store.pulledInThisSession()).toBe(true);
    const notice = await applyOrgOfflineCachePolicy(false, BOB, { send, server: "srv", mayWrite }, { deleteWaitMs: 50 });
    expect({ writes: server.writes.slice(before), deletedOnServer: server.items.get(bankId)?.deleted, notice }).toEqual({
      writes: [],
      deletedOnServer: false,
      notice: { server: "srv", unsent: 1, unsure: 0 },
    });
  });

  it("control: without the policy, the same state sends nothing through the store's own drain", async () => {
    const { server, bob, bankId } = await queuedThenMoved();
    const before = server.writes.length;
    await (bob.store as unknown as { flushQueue: () => Promise<void> }).flushQueue();
    expect({ writes: server.writes.slice(before), deletedOnServer: server.items.get(bankId)?.deleted }).toEqual({ writes: [], deletedOnServer: false });
  });

  it("at a start, with no account open: only the personal vault's changes are sent, a shared vault's are counted as not sent, though its key works", async () => {
    freshDb();
    const { server, bob, old } = await family(await openVaultCache(BOB));
    const personal = bob.account.personalVaultId;
    const bank = bob.store.list().find((i) => i.vaultId === old)!;
    await offline(bob, async () => {
      await bob.store.save(bank.itemId, { ...bank.doc, name: "bank edited" }, [], undefined, old);
      await bob.store.save(null, { type: "note", name: "mine", notes: "x" }, [], undefined, personal);
    });
    expect(await bob.store.queuedMutationCount()).toBe(2);
    expect(bob.store.mayWrite(old)).toBe(true);
    // The session record this browser keeps, as the unlock that opened the account wrote it.
    saveSession({ baseUrl: "", userId: BOB, personalVaultId: personal, email: "bob@example.com", tokens: null });
    const before = server.writes.length;
    const mayWrite = policyWipeQuestion(null, BOB);
    const send = senderForCopy(client, wireOf(bob) as never, BOB, mayWrite);
    const notice = await applyOrgOfflineCachePolicy(false, BOB, { send, server: "srv", mayWrite }, { deleteWaitMs: 50 });
    expect({ writes: server.writes.slice(before), notice }).toEqual({ writes: [`push:${personal}`], notice: { server: "srv", unsent: 1, unsure: 0 } });
  });

  it("at an unlock, before the first pull: the open store answers no for a shared vault (its key not yet taken), yes for the personal vault, and the numbers say so", async () => {
    freshDb();
    const { server, bob, old } = await family(await openVaultCache(BOB));
    const personal = bob.account.personalVaultId;
    const bank = bob.store.list().find((i) => i.vaultId === old)!;
    await offline(bob, async () => {
      await bob.store.save(bank.itemId, { ...bank.doc, name: "bank edited" }, [], undefined, old);
      await bob.store.save(null, { type: "note", name: "mine", notes: "x" }, [], undefined, personal);
    });
    // The next unlock of the same browser profile: the account is open in the tab, its first pull has not run.
    const again = await browser(server, bob.person, bob.contacts, { cache: await openVaultCache(BOB), again: bob.profile, sync: false });
    const mayWrite = policyWipeQuestion(openIn(again), BOB);
    // The store would answer yes for the shared vault from its log at rest; the question before the first pull says no.
    const asked = { store: again.store.mayWrite(old), pulled: again.store.pulledInThisSession(), shared: mayWrite(old), personal: mayWrite(personal) };
    const before = server.writes.length;
    const send = senderForCopy(client, wireOf(again) as never, BOB, mayWrite);
    const notice = await applyOrgOfflineCachePolicy(false, BOB, { send, server: "srv", mayWrite }, { deleteWaitMs: 50 });
    expect({ asked, writes: server.writes.slice(before), notice }).toEqual({
      asked: { store: true, pulled: false, shared: false, personal: true },
      writes: [`push:${personal}`],
      notice: { server: "srv", unsent: 1, unsure: 0 },
    });
  });

  it("at an unlock before the first pull, after a removal and a new add made while this browser was away: the queued change is not sent", async () => {
    freshDb();
    const { server, alice, bob, old } = await family(await openVaultCache(BOB));
    const bank = bob.store.list().find((i) => i.vaultId === old)!;
    await offline(bob, () => bob.store.remove(bank.itemId));
    await removeAndAddAgain(alice, old);
    const again = await browser(server, bob.person, bob.contacts, { cache: await openVaultCache(BOB), again: bob.profile, sync: false });
    const mayWrite = policyWipeQuestion(openIn(again), BOB);
    const asked = mayWrite(old);
    const before = server.writes.length;
    const send = senderForCopy(client, wireOf(again) as never, BOB, mayWrite);
    const notice = await applyOrgOfflineCachePolicy(false, BOB, { send, server: "srv", mayWrite }, { deleteWaitMs: 50 });
    expect({ asked, writes: server.writes.slice(before), deletedOnServer: server.items.get(bank.itemId)?.deleted, notice }).toEqual({
      asked: false,
      writes: [],
      deletedOnServer: false,
      notice: { server: "srv", unsent: 1, unsure: 0 },
    });
  });

  it("a second caller of the sender: a change of a vault whose key no longer works after a real removal is not sent", async () => {
    // Another caller than the policy's attempt (say, a sign-out that sends what waits once) reads the waiting queue and
    // hands the whole of it to the sender, asking nothing itself. The sender asks the question it was made with.
    const { server, bob, old, bankId } = await queuedThenMoved();
    const personal = bob.account.personalVaultId;
    await offline(bob, () => bob.store.save(null, { type: "note", name: "mine", notes: "x" }, [], undefined, personal));
    const waiting = await readWaiting(BOB);
    expect(waiting.kind === "read" ? waiting.pending.map((m) => m.vaultId).sort() : waiting.kind).toEqual([old, personal].sort());
    const before = server.writes.length;
    const send = senderForCopy(client, wireOf(bob) as never, BOB, policyWipeQuestion(openIn(bob), BOB))!;
    await send(waiting.kind === "read" ? [...waiting.pending] : [], new AbortController().signal);
    expect({ writes: server.writes.slice(before), deletedOnServer: server.items.get(bankId)?.deleted }).toEqual({ writes: [`push:${personal}`], deletedOnServer: false });
  });

  it("a second caller hands the sender only changes of a vault whose key no longer works: no request at all", async () => {
    const { server, bob, old } = await queuedThenMoved();
    const waiting = await readWaiting(BOB);
    const pending = waiting.kind === "read" ? [...waiting.pending] : [];
    expect(pending.map((m) => m.vaultId)).toEqual([old]);
    // A wrapper around the real route that counts the requests, acting at its start.
    const wire = wireOf(bob);
    const real = wire.pushMutations.bind(wire);
    let requests = 0;
    const counted: Wire = {
      pushMutations: (...a: unknown[]) => {
        requests++;
        return real(...a);
      },
    };
    const before = server.writes.length;
    const send = senderForCopy(client, counted as never, BOB, policyWipeQuestion(openIn(bob), BOB))!;
    const answer = await send(pending, new AbortController().signal);
    expect({ requests, writes: server.writes.slice(before), results: answer.results }).toEqual({ requests: 0, writes: [], results: [] });
  });

  it("a change whose answer turns to no after the queue was read is not handed to the transport, and counts as not sent", async () => {
    const rows: Mutation[] = Array.from({ length: 250 }, (_, i) => ({ mutationId: `m${i}`, op: "delete", itemId: `i${i}`, vaultId: "v", baseItemRev: 1 }));
    let allowed = true;
    const handed: number[] = [];
    const send = async (batch: Mutation[]): Promise<PushResponse> => {
      handed.push(batch.length);
      allowed = false; // the log moves while the first request is out: every later change of "v" may not be written
      return { rev: 1, results: batch.map((m) => ({ mutationId: m.mutationId, status: "applied" as const })) };
    };
    const r = await sendWaitingOnce(rows, send, (v) => allowed && v === "v");
    expect({ handed, taken: r.taken.size, unsure: r.unsure.size, requests: r.requests, end: r.end }).toEqual({ handed: [200], taken: 200, unsure: 0, requests: 1, end: "done" });
  });

  it("the question without an open account names only the personal vault of this browser's own record of that account", () => {
    const P = "11111111-1111-4111-8111-111111111111";
    const S = "22222222-2222-4222-8222-222222222222";
    expect(policyWipeQuestion(null, BOB)(P)).toBe(false); // no record: nothing
    saveSession({ baseUrl: "", userId: BOB, personalVaultId: P, email: "bob@example.com", tokens: null });
    const q = policyWipeQuestion(null, BOB);
    expect([q(P), q(S), q("")]).toEqual([true, false, false]);
    expect(policyWipeQuestion(null, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")(P)).toBe(false); // the record is another account's
    saveSession({ baseUrl: "", userId: BOB, personalVaultId: "", email: "bob@example.com", tokens: null });
    expect(policyWipeQuestion(null, BOB)("")).toBe(false); // a record that names no personal vault
    // With the account open in this tab and its first pull run, the open store answers, whatever the record says; before
    // that pull, only the open account's own personal vault, asked at each change.
    let pulled = false;
    const open = policyWipeQuestion({ userId: BOB, personalVaultId: P, pulled: () => pulled, mayWrite: (v) => v === S }, BOB);
    const beforePull = [open(P), open(S)];
    pulled = true;
    expect({ beforePull, afterPull: [open(P), open(S)] }).toEqual({ beforePull: [true, false], afterPull: [false, true] });
    // An open account that is not the copy's answers nothing for it: the record decides.
    saveSession({ baseUrl: "", userId: BOB, personalVaultId: P, email: "bob@example.com", tokens: null });
    const other = policyWipeQuestion({ userId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", personalVaultId: S, pulled: () => true, mayWrite: () => true }, BOB);
    expect([other(P), other(S)]).toEqual([true, false]);
  });
});
