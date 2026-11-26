// A sync the server answers with "start again from nothing" (410 resync_required: an honest server's answer to a cursor
// before the history it keeps, and an answer any server can give whenever it likes), through the real VaultStore,
// SharedLogSession and VaultLogStore against a fake server:
//  - before the resync replaces anything, the browser takes what it holds of every shared vault; each one the fresh list
//    no longer grants takes the ordinary road of a removal learned at a sync: the held copy, made from what the browser
//    held before (never from what the server serves now), and the notice that road gives. A vault still granted is left
//    as the fresh list has it, and a resync in which nothing was removed says nothing;
//  - a resync cut short (the fresh list never arrives, or its commit never lands) loses nothing: the next start answers
//    the same 410 from the same offline copy and gives the same notice and held copy;
//  - the first full pull after a sign-in, or a reload with no offline copy, can hold nothing and does not know the
//    vault's name; where this browser's own records hold a shared vault frozen here, or the mark of the person's own
//    leave of it, that the fresh list no longer grants, it says so in a line without the name, and the mark is used up
//    by that line, not in silence.
// The fake server keeps one revision per grant row, as the real one does, and lists a revoked row as removed when its
// revision is above the cursor (a full pull lists every revoked row of the account).
import "fake-indexeddb/auto";
import { IDBFactory as FakeIDBFactory } from "fake-indexeddb";
import { beforeAll, describe, expect, it, onTestFinished, vi } from "vitest";
import { ApiClient, ApiError } from "../api/client";
import { memoryStorage } from "../api/devicesecret";
import type { AttachmentMeta, Mutation, MutationResult, PushResponse, SyncResponse, WireGrant, WireItem, WireVault } from "../api/types";
import type { AccountStateResponseV2, LogAppendRequest, LogAppendResponse, LogPage } from "../api/wire";
import { adAccountState } from "../crypto/ad";
import { toB64, toHexLower, utf8 } from "../crypto/bytes";
import { seal } from "../crypto/envelope";
import { boxKeypairFromSeed, randomBytes, sha256Sync, signKeypairFromSeed } from "../crypto/provider";
import { initSodium } from "../crypto/sodium";
import { fromB64Canonical } from "../crypto/trust/grammar";
import { parseLogEntry } from "../crypto/trust/vaultlog";
import { fill, VAULT_GONE_UNCHECKED_NOTICE, VAULT_LEFT_FROZEN_NOTICE } from "../ui/copy";
import { noticeBody } from "../ui/Vault";
import { Account } from "./account";
import { type AccountDocument, type ContactRecord, EMPTY_DOCUMENT, encodeDocument, withVaultHead } from "./accountdoc";
import { openVaultCache, type VaultCache } from "./idbcache";
import { SharedLogSession } from "./sharedlogs";
import { type ItemWire, VaultStore } from "./store";

interface Grant {
  role: "owner" | "writer" | "reader";
  wrappedVk: string;
  signedGrant: string | null;
  revoked: boolean;
  rev: number;
}

class Server {
  rev = 1;
  logs = new Map<string, string[]>();
  metas = new Map<string, string>();
  grants = new Map<string, Map<string, Grant>>();
  items = new Map<string, WireItem>();
  attachments = new Map<string, { vaultId: string; body: Uint8Array }>();
  states = new Map<string, { sealed: string | null; seq: number }>();
  pushed = new Map<string, MutationResult>();
  leaveRevokes = true;
  personals = new Map<string, string>();
  /** A cursor at or above 1 and below this is answered 410 (the honest server's rule: history before it is gone). */
  oldest = 0;
  /** The next this-many delta syncs are answered 410 whatever their cursor (a server that answers so when it likes). */
  fail410 = 0;
  /** The full list after a 410 does not arrive (the network drops). */
  freshDown = false;
  /** A full list names no removed vault at all. */
  hideRemoved = false;
  /** A full list also serves the items and the vault row of these vaults, whose grant it no longer serves. */
  serveUngranted = new Set<string>();
  /** Pushes fail on the network. */
  pushDown = false;
  /** Rewrites an answer before the browser sees it (a server that serves what it likes). */
  tamper: ((r: SyncResponse) => SyncResponse) | null = null;

  private head(vaultId: string): { seq: number; hash: string; at: number } {
    const all = this.logs.get(vaultId) ?? [];
    const last = all[all.length - 1];
    if (last === undefined) return { seq: -1, hash: "", at: 0 };
    const parsed = parseLogEntry(fromB64Canonical(last)!);
    return { seq: all.length - 1, hash: toHexLower(sha256Sync(fromB64Canonical(last)!)), at: parsed.ok ? parsed.value.entry.at : 0 };
  }

  private canWrite(userId: string, vaultId: string): boolean {
    if (this.personals.get(vaultId) === userId) return true;
    const g = this.grants.get(vaultId)?.get(userId);
    return g !== undefined && !g.revoked && g.role !== "reader";
  }

  /** The cursor is gone from now on: every cursor at or below the current revision is answered 410. */
  forgetHistory(): void {
    this.oldest = ++this.rev;
  }

  wireFor(userId: string) {
    const s = this;
    return {
      onRefusedIds: undefined as unknown,
      async sync(since: number): Promise<SyncResponse> {
        if (since > 0 && (s.fail410 > 0 || since < s.oldest)) {
          if (s.fail410 > 0) s.fail410--;
          throw new ApiError(410, "resync_required", "cursor gone");
        }
        if (since === 0 && s.freshDown) throw new TypeError("offline");
        const vaults: WireVault[] = [];
        const grants: WireGrant[] = [];
        const removed: string[] = [];
        const live = new Set<string>();
        for (const [vaultId, rows] of s.grants) {
          const g = rows.get(userId);
          if (g === undefined) continue;
          const h = s.head(vaultId);
          const row = { vaultId, type: "shared", rev: s.rev, metaBlob: s.metas.get(vaultId) ?? "", createdAt: 0, logHead: { seq: h.seq, hash: h.hash } } as WireVault;
          if (g.revoked) {
            if (g.rev > since && !(since === 0 && s.hideRemoved)) removed.push(vaultId);
            if (since === 0 && s.serveUngranted.has(vaultId)) {
              vaults.push(row);
              live.add(vaultId);
            }
            continue;
          }
          live.add(vaultId);
          vaults.push(row);
          grants.push({ vaultId, userId, role: g.role, wrappedVk: g.wrappedVk, rev: g.rev, signedGrant: g.signedGrant });
        }
        const items = [...s.items.values()].filter((it) => live.has(it.vaultId) || s.personals.get(it.vaultId) === userId);
        const r = { rev: s.rev, full: since === 0, vaults, grants, items, removedGrants: removed } as SyncResponse;
        return s.tamper ? s.tamper(r) : r;
      },
      async pushMutations(mutations: Mutation[]): Promise<PushResponse> {
        if (s.pushDown) throw new TypeError("offline");
        const results: MutationResult[] = [];
        for (const m of mutations) {
          const done = s.pushed.get(m.mutationId);
          if (done) {
            results.push(done);
            continue;
          }
          if (!s.canWrite(userId, m.vaultId)) {
            results.push({ mutationId: m.mutationId, status: "denied" });
            continue;
          }
          const prev = s.items.get(m.itemId);
          const rev = ++s.rev;
          s.items.set(m.itemId, {
            itemId: m.itemId,
            vaultId: m.vaultId,
            rev,
            createdAt: 0,
            updatedAt: rev,
            deleted: m.op === "delete",
            conflict: false,
            formatVersion: m.item?.formatVersion ?? prev?.formatVersion ?? 1,
            attachmentIds: m.item?.attachmentIds ?? [],
            blob: m.item?.blob ?? prev?.blob ?? "",
          });
          const r: MutationResult = { mutationId: m.mutationId, status: "applied", newItemRev: rev };
          s.pushed.set(m.mutationId, r);
          results.push(r);
        }
        return { rev: s.rev, results };
      },
      async uploadAttachment(id: string, itemId: string, vaultId: string, body: Uint8Array): Promise<AttachmentMeta> {
        if (!s.canWrite(userId, vaultId)) throw new ApiError(403, "no_grant", "no grant");
        s.attachments.set(id, { vaultId, body: body.slice() });
        return { attachmentId: id, itemId, vaultId, size: body.length, sha256: "", createdAt: 0 };
      },
      async deletedItems(): Promise<{ items: { itemId: string; vaultId: string; deletedAt: number }[] }> {
        return { items: [...s.items.values()].filter((it) => it.deleted && s.grants.get(it.vaultId)?.get(userId)?.revoked === false).map((it) => ({ itemId: it.itemId, vaultId: it.vaultId, deletedAt: it.updatedAt })) };
      },
      async itemVersions(): Promise<{ versions: never[] }> {
        return { versions: [] };
      },
      async purgeItem(itemId: string): Promise<void> {
        s.items.delete(itemId);
      },
      async downloadAttachment(id: string): Promise<Uint8Array> {
        const a = s.attachments.get(id);
        if (!a || s.grants.get(a.vaultId)?.get(userId)?.revoked !== false) throw new ApiError(404, "not_found", "no attachment");
        return a.body.slice();
      },
      async logPage(vaultId: string, after: number | null): Promise<LogPage> {
        const all = s.logs.get(vaultId) ?? [];
        return { entries: all.slice(after === null ? 0 : after + 1), head: s.head(vaultId), purged: null, deleted: null };
      },
      async appendLog(vaultId: string, req: LogAppendRequest): Promise<LogAppendResponse> {
        const parsed = parseLogEntry(fromB64Canonical(req.entry)!);
        if (!parsed.ok) throw new ApiError(400, "bad_entry", "bad entry");
        const e = parsed.value.entry;
        s.logs.set(vaultId, [...(s.logs.get(vaultId) ?? []), req.entry]);
        if (req.metaBlob) s.metas.set(vaultId, req.metaBlob);
        const rev = ++s.rev;
        const rows = s.grants.get(vaultId) ?? new Map<string, Grant>();
        if (e.kind === "genesis") rows.set(e.actor, { role: "owner", wrappedVk: req.wrappedVk ?? "", signedGrant: null, revoked: false, rev });
        if (e.kind === "add") rows.set(e.member, { role: e.role, wrappedVk: "", signedGrant: req.grant ?? null, revoked: false, rev });
        if (e.kind === "role") Object.assign(rows.get(e.member)!, { role: e.role, rev });
        if (e.kind === "remove") Object.assign(rows.get(e.member)!, { revoked: true, rev });
        if (e.kind === "leave" && s.leaveRevokes) Object.assign(rows.get(e.actor)!, { revoked: true, rev });
        if (e.kind === "delete") for (const g of rows.values()) Object.assign(g, { revoked: true, rev });
        s.grants.set(vaultId, rows);
        return { rev: s.rev, head: s.head(vaultId), deleted: null };
      },
      async putSelfWrap(vaultId: string, wrappedVk: string): Promise<number> {
        const row = s.grants.get(vaultId)?.get(userId);
        const rev = ++s.rev;
        if (row) Object.assign(row, { wrappedVk, rev });
        return rev;
      },
      async accountState(): Promise<AccountStateResponseV2> {
        const st = s.states.get(userId) ?? { sealed: null, seq: 0 };
        return { sealedState: st.sealed, seq: st.seq };
      },
      async putAccountState(sealedState: string, baseSeq: number): Promise<AccountStateResponseV2> {
        const st = s.states.get(userId) ?? { sealed: null, seq: 0 };
        if (baseSeq !== st.seq) throw new ApiError(409, "stale_state", "stale");
        s.states.set(userId, { sealed: sealedState, seq: st.seq + 1 });
        return { sealedState, seq: st.seq + 1 };
      },
    };
  }

  seedState(userId: string, uvk: Uint8Array, doc: AccountDocument): void {
    this.states.set(userId, { sealed: toB64(seal(uvk, utf8(encodeDocument(userId, doc)), adAccountState(userId))), seq: 1 });
  }
}

const A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const B = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

function person(userId: string) {
  const seed = randomBytes(32);
  return { userId, identity: boxKeypairFromSeed(seed), signing: signKeypairFromSeed(seed), uvk: randomBytes(32) };
}
type Person = ReturnType<typeof person>;

function contact(of: Person, name: string): ContactRecord {
  return { userId: of.userId, identityPub: toB64(of.identity.publicKey), label: toB64(utf8(name)), method: "link", verifiedAt: 1, compared: true, madeOn: "ffffffff-ffff-4fff-8fff-ffffffffffff", extra: new Map() };
}

interface Profile {
  storage: ReturnType<typeof memoryStorage>;
  personalVaultId: string;
  personalVk: Uint8Array;
}

/**
 * One session of [p] in a browser. [again]: the same browser profile as an earlier session of this account (a reload, a
 * second tab, or a sign-in after a sign-out: the account's records at rest stay, the key ring does not).
 */
async function browser(server: Server, p: Person, contacts: readonly ContactRecord[], opts: { cache?: VaultCache; again?: Profile } = {}) {
  const { cache, again } = opts;
  if (again === undefined) server.seedState(p.userId, p.uvk, { ...EMPTY_DOCUMENT, contacts: new Map(contacts.map((c) => [c.userId, c])) });
  const profile: Profile = again ?? { storage: memoryStorage(), personalVaultId: crypto.randomUUID(), personalVk: randomBytes(32) };
  server.personals.set(profile.personalVaultId, p.userId);
  const account = Account.fromOpened(
    { userId: p.userId, uvk: p.uvk, identity: p.identity, signing: p.signing, genesis: null as never, personalVaultId: profile.personalVaultId, personalVk: profile.personalVk.slice() },
    null,
  );
  const wire = server.wireFor(p.userId);
  const shared = new SharedLogSession(p, wire, profile.storage, account.logKeyRing());
  await shared.refreshState();
  for (const c of contacts) shared.currency.mark(c.userId, c.identityPub, "confirmed");
  const store = new VaultStore(wire as unknown as ApiClient, account, cache, undefined, wire as unknown as ItemWire);
  store.attachSharedLogs(shared);
  if (cache) await store.hydrate();
  if (again !== undefined) await store.resendHeldChanges();
  await store.sync();
  return { account, store, shared, profile, person: p, contacts };
}
type Browser = Awaited<ReturnType<typeof browser>>;

/** Alice owns "Family" (one login, "bank"); bob is a writer of it who accepted. */
async function family(bobCache?: VaultCache) {
  const server = new Server();
  const a = person(A);
  const b = person(B);
  const alice = await browser(server, a, [contact(b, "Bob")]);
  const bob = await browser(server, b, [contact(a, "Alice")], { cache: bobCache });
  const old = await alice.store.createSharedVault("Family");
  await alice.store.addVaultMember(old, B, "writer");
  await alice.store.save(null, { type: "login", name: "bank", login: { username: "a", password: "pw1" } }, [], undefined, old);
  await bob.store.sync();
  expect((await bob.shared.answer(bob.shared.pendingAsks()[0]!, true)).kind).toBe("adopted");
  await bob.store.sync();
  expect(listed(bob.store, old)).toBe(true);
  return { server, alice, bob, old };
}

const listed = (store: VaultStore, vaultId: string): boolean => store.vaults().some((v) => v.vaultId === vaultId);
const noticesOf = (who: Browser, vaultId: string): string[] => who.store.notices().filter((n) => n.vaultId === vaultId).map((n) => n.kind);
const heldOf = (who: Browser): string[] => who.store.heldVaults().map((h) => h.vaultId);
const namesIn = (who: Browser, vaultId: string): string[] => who.store.list().filter((i) => i.vaultId === vaultId).map((i) => i.doc.name);

/** [who]'s copy of [vaultId] frozen: the account's record of the vault names another genesis. */
async function freezeByRecord(who: Browser, vaultId: string): Promise<void> {
  await who.shared.accountState.update((doc) => {
    const rec = doc.vaults.get(vaultId)!;
    return { ...doc, vaults: new Map([...doc.vaults, [vaultId, { ...rec, genesisHash: "ab".repeat(32) }]]) };
  });
  await who.shared.logs.refresh(vaultId, null, null, true);
  expect(who.shared.logs.status(vaultId)).toMatchObject({ kind: "frozen" });
  expect(listed(who.store, vaultId)).toBe(true);
}

async function bobFrozen(bobCache?: VaultCache) {
  const f = await family(bobCache);
  await freezeByRecord(f.bob, f.old);
  return f;
}

/**
 * [who]'s copy of [vaultId] frozen beside the account's record, on the same genesis: the record names an entry one place
 * after the verified head, and the owner ([owner]) stores another one there.
 */
async function freezeBesideRecord(who: Browser, owner: Browser, vaultId: string): Promise<void> {
  const s = who.shared.logs.verifiedState(vaultId)!;
  await who.shared.accountState.update((doc) => withVaultHead(doc, vaultId, s.genesisHash, s.head.seq + 1, "ab".repeat(32)));
  await owner.store.sync();
  await owner.store.setMemberRole(vaultId, B, "writer");
  await who.shared.logs.refresh(vaultId, null, null, true);
  expect(who.shared.logs.status(vaultId)).toMatchObject({ kind: "frozen", atSeq: s.head.seq + 1 });
  expect(listed(who.store, vaultId)).toBe(true);
}

async function bobFrozenBeside(bobCache?: VaultCache) {
  const f = await family(bobCache);
  await freezeBesideRecord(f.bob, f.alice, f.old);
  return f;
}

/** A fresh, empty IndexedDB for this test's browser. */
const freshDb = (): void => {
  (globalThis as { indexedDB?: IDBFactory }).indexedDB = new FakeIDBFactory() as unknown as IDBFactory;
};

/** [cache] with its pull commits failing while [state.fail] holds (the page closed before the commit landed). */
function commitsFail(cache: VaultCache, state: { fail: boolean }): VaultCache {
  return new Proxy(cache, {
    get(target, prop) {
      if (prop === "applyPull" && state.fail) return async () => Promise.reject(new Error("the page was closed"));
      const v = Reflect.get(target, prop, target) as unknown;
      return typeof v === "function" ? (v as (...a: unknown[]) => unknown).bind(target) : v;
    },
  });
}

describe("a sync answered 'start again from nothing' keeps the removal's notice and held copy", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("a frozen vault the owner removed: the notice and the held copy, made from what this browser held", async () => {
    freshDb();
    const { server, alice, bob, old } = await bobFrozen(await openVaultCache(B));
    await alice.store.removeVaultMember(old, B);
    server.forgetHistory();
    await bob.store.sync();
    expect(listed(bob.store, old)).toBe(false);
    expect(noticesOf(bob, old)).toEqual(["anomaly"]);
    expect(heldOf(bob)).toEqual([old]);
    expect(bob.store.heldVaults()[0]).toMatchObject({ name: "Family", itemCount: 1 });
    // The held copy is at rest: a reload with the offline copy finds it, and lists the vault no more.
    const again = await browser(server, bob.person, bob.contacts, { cache: await openVaultCache(B), again: bob.profile });
    expect(heldOf(again)).toEqual([old]);
    expect(listed(again.store, old)).toBe(false);
  });

  it("a vault that is not frozen, the owner's removal: the notice of the ordinary road and the held copy", async () => {
    freshDb();
    const { server, alice, bob, old } = await family(await openVaultCache(B));
    await alice.store.removeVaultMember(old, B);
    server.forgetHistory();
    await bob.store.sync();
    expect(listed(bob.store, old)).toBe(false);
    expect(noticesOf(bob, old)).toEqual(["removed"]);
    expect(heldOf(bob)).toEqual([old]);
    expect(bob.store.heldVaults()[0]).toMatchObject({ name: "Family", itemCount: 1 });
  });

  it("the same removal learned by a delta sync gives the same notice and held copy (the comparison)", async () => {
    for (const frozen of [false, true]) {
      freshDb();
      const { alice, bob, old } = frozen ? await bobFrozen(await openVaultCache(B)) : await family(await openVaultCache(B));
      await alice.store.removeVaultMember(old, B);
      await bob.store.sync();
      expect(noticesOf(bob, old)).toEqual([frozen ? "anomaly" : "removed"]);
      expect(heldOf(bob)).toEqual([old]);
    }
  });

  it("a frozen vault the person left on this browser, the server took the leave: the own-leave notice, the held copy, and the mark used up", async () => {
    freshDb();
    const { server, bob, old } = await bobFrozen(await openVaultCache(B));
    await bob.store.leaveSharedVault(old).catch(() => {});
    expect(server.grants.get(old)!.get(B)!.revoked).toBe(true);
    expect(bob.shared.logs.ownFrozenLeaveTaken(old)).toBe(true);
    server.forgetHistory();
    await bob.store.sync();
    expect(listed(bob.store, old)).toBe(false);
    expect(noticesOf(bob, old)).toEqual(["left-frozen"]);
    expect(noticeBody(bob.store.notices().find((n) => n.vaultId === old)!)).toEqual({ warn: true, body: fill(VAULT_LEFT_FROZEN_NOTICE, "Family") });
    expect(heldOf(bob)).toEqual([old]);
    expect(bob.store.heldVaults()[0]!.itemCount).toBe(1);
    expect(bob.shared.logs.ownFrozenLeaveTaken(old)).toBe(false);
  });

  it("a server that names no removal in its full list: the vault it no longer grants still takes the removal's road", async () => {
    freshDb();
    const { server, alice, bob, old } = await bobFrozen(await openVaultCache(B));
    await alice.store.removeVaultMember(old, B);
    server.hideRemoved = true;
    server.forgetHistory();
    await bob.store.sync();
    expect(listed(bob.store, old)).toBe(false);
    expect(noticesOf(bob, old)).toEqual(["anomaly"]);
    expect(heldOf(bob)).toEqual([old]);
  });

  it("a resync in which nothing was removed says nothing and keeps every vault as the fresh list has it", async () => {
    freshDb();
    const { server, bob, old } = await bobFrozen(await openVaultCache(B));
    server.forgetHistory();
    await bob.store.sync();
    expect(listed(bob.store, old)).toBe(true);
    expect(namesIn(bob, old)).toEqual(["bank"]);
    expect(bob.store.notices()).toEqual([]);
    expect(heldOf(bob)).toEqual([]);
  });

  it("several shared vaults, one of them removed: only that one is held and told; the other stays listed with its items", async () => {
    freshDb();
    const { server, alice, bob, old } = await family(await openVaultCache(B));
    const work = await alice.store.createSharedVault("Work");
    await alice.store.addVaultMember(work, B, "reader");
    await alice.store.save(null, { type: "login", name: "mail", login: { username: "w", password: "pw2" } }, [], undefined, work);
    await bob.store.sync();
    expect((await bob.shared.answer(bob.shared.pendingAsks()[0]!, true)).kind).toBe("adopted");
    await bob.store.sync();
    expect(listed(bob.store, work)).toBe(true);
    await alice.store.removeVaultMember(old, B);
    server.forgetHistory();
    await bob.store.sync();
    expect(listed(bob.store, old)).toBe(false);
    expect(noticesOf(bob, old)).toEqual(["removed"]);
    expect(heldOf(bob)).toEqual([old]);
    expect(listed(bob.store, work)).toBe(true);
    expect(namesIn(bob, work)).toEqual(["mail"]);
    expect(noticesOf(bob, work)).toEqual([]);
  });

  it("the held copy is what this browser held, not what the server serves now: a larger or changed fresh list of the vault adds nothing", async () => {
    freshDb();
    const { server, alice, bob, old } = await bobFrozen(await openVaultCache(B));
    // After the removal the owner writes a new item and changes the old one; the server then serves the vault's row and
    // items in its full list although it no longer grants it to bob.
    await alice.store.removeVaultMember(old, B);
    await alice.store.sync();
    await alice.store.save(null, { type: "login", name: "written-after-the-removal", login: { username: "x", password: "later" } }, [], undefined, old);
    const bank = alice.store.list().find((i) => i.doc.name === "bank")!;
    await alice.store.save(bank.itemId, { ...bank.doc, name: "bank-changed" }, [], undefined, old);
    server.serveUngranted.add(old);
    server.forgetHistory();
    await bob.store.sync();
    expect(listed(bob.store, old)).toBe(false);
    expect(noticesOf(bob, old)).toEqual(["anomaly"]);
    const held = (await (await openVaultCache(B)).heldVaults()).find((h) => h.vault.vaultId === old)!;
    expect(held.items.map((i) => i.itemId)).toEqual([bank.itemId]);
    expect(bob.store.heldVaults()[0]).toMatchObject({ name: "Family", itemCount: 1 });
    // Copied out, it gives the item as this browser held it.
    expect((await bob.store.copyHeldToPersonal(old)).copied).toBe(1);
    expect(namesIn(bob, bob.profile.personalVaultId)).toEqual(["bank"]);
    // Nothing of what the server served of it stays in the live view or at rest.
    expect(bob.store.list().filter((i) => i.vaultId === old)).toEqual([]);
    const again = await browser(server, bob.person, bob.contacts, { cache: await openVaultCache(B), again: bob.profile });
    expect(again.store.list().filter((i) => i.vaultId === old)).toEqual([]);
  });

  it("a server that answers 410 again and again: one notice and one held copy, not one per answer", async () => {
    freshDb();
    const { server, alice, bob, old } = await bobFrozen(await openVaultCache(B));
    await alice.store.removeVaultMember(old, B);
    server.fail410 = 5;
    await bob.store.sync();
    const first = bob.store.heldVaults()[0]!;
    await bob.store.sync();
    await bob.store.sync();
    expect(noticesOf(bob, old)).toEqual(["anomaly"]);
    expect(bob.store.heldVaults()).toEqual([first]);
    const again = await browser(server, bob.person, bob.contacts, { cache: await openVaultCache(B), again: bob.profile });
    await again.store.sync();
    expect(noticesOf(again, old)).toEqual([]);
    expect(again.store.heldVaults().map((h) => [h.vaultId, h.itemCount, h.expungeAt])).toEqual([[old, 1, first.expungeAt]]);
  });

  it("the vault granted again later: it is listed again and its held copy goes, as after any removal", async () => {
    freshDb();
    const { server, alice, bob, old } = await family(await openVaultCache(B));
    await alice.store.removeVaultMember(old, B);
    server.forgetHistory();
    await bob.store.sync();
    expect(heldOf(bob)).toEqual([old]);
    await alice.store.sync();
    await alice.store.addVaultMember(old, B, "writer");
    await bob.store.sync();
    expect((await bob.shared.answer(bob.shared.pendingAsks()[0]!, true)).kind).toBe("adopted");
    await bob.store.sync();
    expect(listed(bob.store, old)).toBe(true);
    expect(namesIn(bob, old)).toEqual(["bank"]);
    expect(heldOf(bob)).toEqual([]);
    expect(noticesOf(bob, old)).toContain("restored");
  });

  it("two tabs answered 410 at the same moment: each tab tells it, and one held copy is kept", async () => {
    freshDb();
    const { server, alice, bob, old } = await family(await openVaultCache(B));
    const tab2 = await browser(server, bob.person, bob.contacts, { cache: await openVaultCache(B), again: bob.profile });
    expect(listed(tab2.store, old)).toBe(true);
    await alice.store.removeVaultMember(old, B);
    server.forgetHistory();
    await Promise.all([bob.store.sync(), tab2.store.sync()]);
    for (const tab of [bob, tab2]) {
      expect(listed(tab.store, old)).toBe(false);
      expect(noticesOf(tab, old)).toEqual(["removed"]);
      expect(heldOf(tab)).toEqual([old]);
    }
    const third = await browser(server, bob.person, bob.contacts, { cache: await openVaultCache(B), again: bob.profile });
    expect(third.store.heldVaults().map((h) => [h.vaultId, h.itemCount])).toEqual([[old, 1]]);
    expect(listed(third.store, old)).toBe(false);
  });

  it("a change of the vault waiting to be sent is kept with the held copy, as after any removal", async () => {
    freshDb();
    const { server, alice, bob, old } = await family(await openVaultCache(B));
    // The browser lets a change wait to be sent only where its storage is persistent.
    vi.stubGlobal("navigator", { storage: { persisted: async () => true } });
    onTestFinished(() => {
      vi.unstubAllGlobals();
    });
    server.pushDown = true;
    const bank = bob.store.list().find((i) => i.vaultId === old)!;
    await bob.store.save(bank.itemId, { ...bank.doc, name: "bank-edited-offline" }, [], undefined, old);
    server.pushDown = false;
    await alice.store.removeVaultMember(old, B);
    server.forgetHistory();
    expect((await (await openVaultCache(B)).pending()).map((m) => m.itemId)).toEqual([bank.itemId]);
    await bob.store.sync();
    expect(listed(bob.store, old)).toBe(false);
    expect(noticesOf(bob, old)).toContain("removed");
    const held = (await (await openVaultCache(B)).heldVaults()).find((h) => h.vault.vaultId === old)!;
    expect(held.items).toHaveLength(1);
    expect(held.parked.map((m) => m.itemId)).toEqual([bank.itemId]);
  });

  it("the person's own leave whose sync is answered 410: quiet, as on the ordinary road", async () => {
    freshDb();
    const { server, bob, old } = await family(await openVaultCache(B));
    server.forgetHistory();
    await bob.store.leaveSharedVault(old);
    expect(listed(bob.store, old)).toBe(false);
    expect(noticesOf(bob, old)).toEqual([]);
    expect(heldOf(bob)).toEqual([]);
  });

  it("the owner's own deletion whose sync is answered 410: held without a notice, as on the ordinary road", async () => {
    freshDb();
    const server = new Server();
    const a = person(A);
    const alice = await browser(server, a, [], { cache: await openVaultCache(A) });
    const old = await alice.store.createSharedVault("Family");
    await alice.store.save(null, { type: "login", name: "bank", login: { username: "a", password: "pw1" } }, [], undefined, old);
    server.forgetHistory();
    await alice.store.deleteSharedVault(old);
    expect(listed(alice.store, old)).toBe(false);
    expect(alice.store.notices().filter((n) => n.vaultId === old)).toEqual([]);
    expect(alice.store.heldVaults().map((h) => [h.vaultId, h.byMe, h.itemCount])).toEqual([[old, true, 1]]);
  });

  it("a move out of a vault whose every sync is answered 410: the same outcome as on the ordinary road", async () => {
    const outcomes: unknown[] = [];
    for (const answered410 of [false, true]) {
      freshDb();
      const server = new Server();
      const a = person(A);
      const b = person(B);
      const alice = await browser(server, a, [contact(b, "Bob")], { cache: await openVaultCache(A) });
      const old = await alice.store.createSharedVault("Family");
      await alice.store.addVaultMember(old, B, "writer");
      await alice.store.save(null, { type: "login", name: "bank", login: { username: "a", password: "pw1" } }, [], undefined, old);
      if (answered410) server.fail410 = 1000;
      const r = await alice.store.moveEverything(old, { name: "Family 2", add: [B] });
      server.fail410 = 0;
      await alice.store.sync();
      outcomes.push({
        oldListed: listed(alice.store, old),
        newNames: namesIn(alice, r.newVaultId),
        notices: alice.store.notices().map((n) => [n.vaultId === old ? "old" : n.vaultId === r.newVaultId ? "new" : "other", n.kind]),
        held: alice.store.heldVaults().map((h) => [h.vaultId === old, h.byMe, h.itemCount]),
      });
    }
    expect(outcomes[1]).toEqual(outcomes[0]);
    expect(outcomes[0]).toMatchObject({ oldListed: false, newNames: ["bank"], held: [[true, true, 1]] });
  });

  it("a vault the fresh list leaves out although its verified log still names this account: kept, as on the ordinary road, also across a reload", async () => {
    freshDb();
    const { server, bob, old } = await family(await openVaultCache(B));
    // The server leaves the vault out of its full list without a removal: the row is gone from its answer only.
    const row = server.grants.get(old)!.get(B)!;
    row.revoked = true;
    server.hideRemoved = true;
    server.forgetHistory();
    await bob.store.sync();
    expect(listed(bob.store, old)).toBe(true);
    expect(namesIn(bob, old)).toEqual(["bank"]);
    expect(bob.store.notices()).toEqual([]);
    expect(heldOf(bob)).toEqual([]);
    // A reload whose delta sync still leaves it out: what it shows comes from the offline copy alone.
    const again = await browser(server, bob.person, bob.contacts, { cache: await openVaultCache(B), again: bob.profile });
    expect(listed(again.store, old)).toBe(true);
    expect(namesIn(again, old)).toEqual(["bank"]);
  });
});

describe("a resync cut short loses nothing and lets no removal pass in silence at the next start", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("the fresh list never arrives: nothing is wiped, and the next start gives the notice and the held copy", async () => {
    freshDb();
    const { server, alice, bob, old } = await bobFrozenBeside(await openVaultCache(B));
    await alice.store.removeVaultMember(old, B);
    server.forgetHistory();
    server.freshDown = true;
    await expect(bob.store.sync()).rejects.toThrow();
    expect(listed(bob.store, old)).toBe(true);
    expect(namesIn(bob, old)).toEqual(["bank"]);
    server.freshDown = false;
    const again = await browser(server, bob.person, bob.contacts, { cache: await openVaultCache(B), again: bob.profile });
    expect(listed(again.store, old)).toBe(false);
    expect(noticesOf(again, old)).toEqual(["anomaly"]);
    expect(again.store.heldVaults().map((h) => [h.vaultId, h.name, h.itemCount])).toEqual([[old, "Family", 1]]);
  });

  it("the page closes before the resync's commit lands: the next start gives the notice and the held copy", async () => {
    freshDb();
    const cut = { fail: false };
    const { server, alice, bob, old } = await bobFrozenBeside(commitsFail(await openVaultCache(B), cut));
    await alice.store.removeVaultMember(old, B);
    server.forgetHistory();
    cut.fail = true;
    await bob.store.sync();
    // This tab told it already; nothing of it reached the offline copy.
    expect(noticesOf(bob, old)).toEqual(["anomaly"]);
    expect(await (await openVaultCache(B)).heldVaults()).toEqual([]);
    const again = await browser(server, bob.person, bob.contacts, { cache: await openVaultCache(B), again: bob.profile });
    expect(listed(again.store, old)).toBe(false);
    expect(noticesOf(again, old)).toEqual(["anomaly"]);
    expect(again.store.heldVaults().map((h) => [h.vaultId, h.name, h.itemCount])).toEqual([[old, "Family", 1]]);
  });
});

describe("the first full pull with no offline copy tells a removal of a vault frozen here without its name", () => {
  beforeAll(async () => {
    await initSodium();
  });

  const gone = (who: Browser) => who.store.notices().filter((n) => n.kind === "unchecked-gone");

  it("a frozen vault removed while this browser was closed, reopened with no offline copy: one line without the name", async () => {
    const { alice, bob, old, server } = await bobFrozen();
    await alice.store.removeVaultMember(old, B);
    const again = await browser(server, bob.person, bob.contacts, { again: bob.profile });
    expect(listed(again.store, old)).toBe(false);
    expect(gone(again).map((n) => n.vaultId)).toEqual([old]);
    expect(noticeBody(gone(again)[0]!)).toEqual({ warn: true, body: VAULT_GONE_UNCHECKED_NOTICE });
    expect(heldOf(again)).toEqual([]);
  });

  it("a frozen vault the person left on this browser, removed while it was closed: the line, and the mark used up by it", async () => {
    const { bob, old, server } = await bobFrozen();
    server.leaveRevokes = false;
    await bob.store.leaveSharedVault(old).catch(() => {});
    expect(bob.shared.logs.ownFrozenLeaveTaken(old)).toBe(true);
    Object.assign(server.grants.get(old)!.get(B)!, { revoked: true, rev: ++server.rev });
    const again = await browser(server, bob.person, bob.contacts, { again: bob.profile });
    expect(gone(again).map((n) => n.vaultId)).toEqual([old]);
    expect(again.shared.logs.ownFrozenLeaveTaken(old)).toBe(false);
  });

  it("the line is said again at each such start until the person dismisses it, then no more; a vault granted again is listed with no line", async () => {
    const { alice, bob, old, server } = await bobFrozen();
    await alice.store.removeVaultMember(old, B);
    const first = await browser(server, bob.person, bob.contacts, { again: bob.profile });
    expect(gone(first).map((n) => n.vaultId)).toEqual([old]);
    const second = await browser(server, bob.person, bob.contacts, { again: bob.profile });
    expect(gone(second).map((n) => n.vaultId)).toEqual([old]);
    second.store.dismissNotice(gone(second)[0]!.id);
    const third = await browser(server, bob.person, bob.contacts, { again: bob.profile });
    expect(gone(third)).toEqual([]);
  });

  it("a vault that is not frozen, removed while this browser was closed: quiet, as the first full pull is", async () => {
    const { alice, bob, old, server } = await family();
    await alice.store.removeVaultMember(old, B);
    const again = await browser(server, bob.person, bob.contacts, { again: bob.profile });
    expect(listed(again.store, old)).toBe(false);
    expect(again.store.notices()).toEqual([]);
  });

  it("a frozen vault whose invitation the account's records say the person declined: no line", async () => {
    const { alice, bob, old, server } = await bobFrozen();
    await bob.shared.accountState.update((doc) => {
      const rec = doc.accepted.get(old)!;
      return { ...doc, accepted: new Map([...doc.accepted, [old, { ...rec, decision: "decline" as const }]]) };
    });
    await alice.store.removeVaultMember(old, B);
    const again = await browser(server, bob.person, bob.contacts, { again: bob.profile });
    expect(gone(again)).toEqual([]);
  });

  it("a frozen vault still granted: no line", async () => {
    const { bob, old, server } = await bobFrozen();
    const again = await browser(server, bob.person, bob.contacts, { again: bob.profile });
    expect(gone(again)).toEqual([]);
  });

  it("a sign-out right after a resync's removal: the held copy goes with the offline copy, and the next sign-in says the line", async () => {
    freshDb();
    const { server, alice, bob, old } = await bobFrozen(await openVaultCache(B));
    await alice.store.removeVaultMember(old, B);
    server.forgetHistory();
    await bob.store.sync();
    expect(heldOf(bob)).toEqual([old]);
    // The sign-out wipes the offline copy; the account's records on this browser stay.
    freshDb();
    const again = await browser(server, bob.person, bob.contacts, { cache: await openVaultCache(B), again: bob.profile });
    expect(heldOf(again)).toEqual([]);
    expect(gone(again).map((n) => n.vaultId)).toEqual([old]);
  });
});

/** This account's grant row of [vaultId] as the server serves it now. */
function grantRowOf(server: Server, vaultId: string, userId: string): WireGrant {
  const g = server.grants.get(vaultId)!.get(userId)!;
  return { vaultId, userId, role: g.role, wrappedVk: g.wrappedVk, rev: g.rev, signedGrant: g.signedGrant };
}

/** Full answers that also serve [row] (a grant row with no vault row and no item of its vault), naming no removal of it. */
const bareGrantRow = (row: WireGrant) => (r: SyncResponse): SyncResponse =>
  r.full ? ({ ...r, grants: [...r.grants, row], removedGrants: r.removedGrants.filter((id) => id !== row.vaultId) } as SyncResponse) : r;

describe("a vault counts as still granted by a full list only when the list carries both its grant row and its vault row", () => {
  beforeAll(async () => {
    await initSodium();
  });

  for (const frozen of [true, false]) {
    it(`a ${frozen ? "frozen" : "verified"} vault the owner removed, answered 410 with only a grant row of it: the notice and the held copy, also after a reload`, async () => {
      freshDb();
      const { server, alice, bob, old } = await family(await openVaultCache(B));
      if (frozen) await freezeByRecord(bob, old);
      const row = grantRowOf(server, old, B);
      await alice.store.removeVaultMember(old, B);
      server.tamper = bareGrantRow(row);
      server.forgetHistory();
      await bob.store.sync();
      expect(listed(bob.store, old)).toBe(false);
      expect(noticesOf(bob, old)).toEqual([frozen ? "anomaly" : "removed"]);
      expect(bob.store.heldVaults().map((h) => [h.vaultId, h.name, h.itemCount])).toEqual([[old, "Family", 1]]);
      // Later deltas never name the removal.
      server.tamper = (r) => (r.full ? r : ({ ...r, removedGrants: r.removedGrants.filter((id) => id !== old) } as SyncResponse));
      await bob.store.sync();
      expect(heldOf(bob)).toEqual([old]);
      const again = await browser(server, bob.person, bob.contacts, { cache: await openVaultCache(B), again: bob.profile });
      expect(listed(again.store, old)).toBe(false);
      expect(again.store.heldVaults().map((h) => [h.vaultId, h.itemCount])).toEqual([[old, 1]]);
    });
  }

  it("a vault still granted whose vault row the full list leaves out: its verified log names the account, so it is kept with its items, also after a reload", async () => {
    freshDb();
    const { server, bob, old } = await family(await openVaultCache(B));
    const row = grantRowOf(server, old, B);
    server.tamper = (r) => (r.full ? ({ ...r, vaults: r.vaults.filter((v) => v.vaultId !== old), items: r.items.filter((i) => i.vaultId !== old), grants: [...r.grants.filter((g) => g.vaultId !== old), row] } as SyncResponse) : r);
    server.forgetHistory();
    await bob.store.sync();
    expect(listed(bob.store, old)).toBe(true);
    expect(namesIn(bob, old)).toEqual(["bank"]);
    expect(bob.store.notices()).toEqual([]);
    expect(heldOf(bob)).toEqual([]);
    server.tamper = (r) => ({ ...r, vaults: r.vaults.filter((v) => v.vaultId !== old), items: r.items.filter((i) => i.vaultId !== old) }) as SyncResponse;
    const again = await browser(server, bob.person, bob.contacts, { cache: await openVaultCache(B), again: bob.profile });
    expect(listed(again.store, old)).toBe(true);
    expect(namesIn(again, old)).toEqual(["bank"]);
  });

  it("a vault the full list both lists and names as removed takes the removal's road, from what was held", async () => {
    freshDb();
    const { server, alice, bob, old } = await family(await openVaultCache(B));
    const row = grantRowOf(server, old, B);
    const vaultRow = { vaultId: old, type: "shared", rev: server.rev, metaBlob: server.metas.get(old) ?? "", createdAt: 0 } as WireVault;
    await alice.store.removeVaultMember(old, B);
    server.tamper = (r) => (r.full ? ({ ...r, grants: [...r.grants, row], vaults: [...r.vaults, vaultRow] } as SyncResponse) : r);
    server.forgetHistory();
    await bob.store.sync();
    expect(listed(bob.store, old)).toBe(false);
    expect(noticesOf(bob, old)).toEqual(["removed"]);
    expect(bob.store.heldVaults().map((h) => [h.vaultId, h.itemCount])).toEqual([[old, 1]]);
  });

  it("a sign-in with no offline copy whose full list serves only a grant row of a frozen vault the owner removed: the line without the name", async () => {
    const { alice, bob, old, server } = await bobFrozen();
    const row = grantRowOf(server, old, B);
    await alice.store.removeVaultMember(old, B);
    server.tamper = bareGrantRow(row);
    const again = await browser(server, bob.person, bob.contacts, { again: bob.profile });
    expect(listed(again.store, old)).toBe(false);
    expect(again.store.notices().filter((n) => n.kind === "unchecked-gone").map((n) => n.vaultId)).toEqual([old]);
  });

  it("the line without the name, once dismissed, is not brought back by a delta that serves only a grant row of the vault", async () => {
    const { alice, bob, old, server } = await bobFrozen();
    const row = grantRowOf(server, old, B);
    await alice.store.removeVaultMember(old, B);
    const first = await browser(server, bob.person, bob.contacts, { again: bob.profile });
    const gone = (w: Browser) => w.store.notices().filter((n) => n.kind === "unchecked-gone");
    expect(gone(first)).toHaveLength(1);
    first.store.dismissNotice(gone(first)[0]!.id);
    for (let i = 0; i < 3; i++) {
      server.rev++;
      server.tamper = (r) => (r.full ? r : ({ ...r, grants: [...r.grants, { ...row, rev: server.rev }] } as SyncResponse));
      await first.store.sync();
      server.tamper = null;
      server.fail410 = 1;
      await first.store.sync();
      expect(gone(first)).toEqual([]);
    }
  });
});

describe("a held copy the person removed is not written again by another tab", () => {
  beforeAll(async () => {
    await initSodium();
  });

  for (const answered410 of [true, false]) {
    it(`two tabs: the first learns the removal${answered410 ? " at a 410" : ""} and the person removes the held copy there; the second tab's own ${answered410 ? "410" : "delta sync"} keeps no copy and says nothing`, async () => {
      freshDb();
      const { server, alice, bob, old } = await family(await openVaultCache(B));
      const tab2 = await browser(server, bob.person, bob.contacts, { cache: await openVaultCache(B), again: bob.profile });
      await alice.store.removeVaultMember(old, B);
      if (answered410) server.forgetHistory();
      await bob.store.sync();
      expect(heldOf(bob)).toEqual([old]);
      await bob.store.removeHeldCopy(old);
      await tab2.store.sync();
      expect(listed(tab2.store, old)).toBe(false);
      expect(heldOf(tab2)).toEqual([]);
      expect(noticesOf(tab2, old)).toEqual([]);
      expect((await (await openVaultCache(B)).heldVaults()).map((h) => h.vault.vaultId)).toEqual([]);
    });
  }

  it("after the person removed the held copy, the vault granted again and removed again: the notice and a new held copy", async () => {
    freshDb();
    const { server, alice, bob, old } = await family(await openVaultCache(B));
    await alice.store.removeVaultMember(old, B);
    server.forgetHistory();
    await bob.store.sync();
    await bob.store.removeHeldCopy(old);
    await alice.store.sync();
    await alice.store.addVaultMember(old, B, "writer");
    await bob.store.sync();
    expect((await bob.shared.answer(bob.shared.pendingAsks()[0]!, true)).kind).toBe("adopted");
    await bob.store.sync();
    expect(listed(bob.store, old)).toBe(true);
    bob.store.clearNotices();
    await alice.store.sync();
    await alice.store.removeVaultMember(old, B);
    await bob.store.sync();
    expect(noticesOf(bob, old)).toEqual(["removed"]);
    expect(heldOf(bob)).toEqual([old]);
  });
});
