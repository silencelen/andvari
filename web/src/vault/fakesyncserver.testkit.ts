// A fake sync server and browser for tests that drive the real VaultStore, SharedLogSession and VaultLogStore end to
// end: shared vaults with signed logs, grant rows with one revision each (as the real server keeps them), a cursor whose
// history can be forgotten (answered 410, "start again from nothing"), and [tamper], which rewrites any answer before
// the browser sees it, as a server that serves what it likes could.
import "fake-indexeddb/auto";
import { IDBFactory as FakeIDBFactory } from "fake-indexeddb";
import { expect } from "vitest";
import { ApiClient, ApiError } from "../api/client";
import { memoryStorage } from "../api/devicesecret";
import type { AttachmentMeta, ItemVersion, Mutation, MutationResult, PushResponse, SyncResponse, WireGrant, WireItem, WireVault } from "../api/types";
import type { AccountStateResponseV2, LogAppendRequest, LogAppendResponse, LogPage } from "../api/wire";
import { adAccountState } from "../crypto/ad";
import { toB64, toHexLower, utf8 } from "../crypto/bytes";
import { seal } from "../crypto/envelope";
import { boxKeypairFromSeed, randomBytes, sha256Sync, signKeypairFromSeed } from "../crypto/provider";
import { fromB64Canonical } from "../crypto/trust/grammar";
import { parseLogEntry } from "../crypto/trust/vaultlog";
import { Account } from "./account";
import { type AccountDocument, type ContactRecord, EMPTY_DOCUMENT, encodeDocument } from "./accountdoc";
import type { VaultCache } from "./idbcache";
import { SharedLogSession } from "./sharedlogs";
import { type ItemWire, VaultStore } from "./store";

interface Grant {
  role: "owner" | "writer" | "reader";
  wrappedVk: string;
  signedGrant: string | null;
  revoked: boolean;
  rev: number;
}

export class FakeSyncServer {
  rev = 1;
  logs = new Map<string, string[]>();
  metas = new Map<string, string>();
  grants = new Map<string, Map<string, Grant>>();
  items = new Map<string, WireItem>();
  attachments = new Map<string, { vaultId: string; body: Uint8Array }>();
  states = new Map<string, { sealed: string | null; seq: number }>();
  pushed = new Map<string, MutationResult>();
  personals = new Map<string, string>();
  /** A cursor at or above 1 and below this is answered 410 (the honest server's rule: history before it is gone). */
  oldest = 0;
  /** Rewrites a sync answer before the browser sees it (a server that serves what it likes). */
  tamper: ((r: SyncResponse, since: number, userId: string) => SyncResponse) | null = null;
  /** The log entries of a vault the server serves are cut to its first this-many (a server that withholds the newest). */
  logCut = new Map<string, number>();
  /** Called as each page of a vault's log is asked for, before it is served (a test looks at a browser in the middle of a sync). */
  onLogPage: ((vaultId: string) => void) | null = null;
  /** Every request that would change something, as `<request>:<vault id>`, in the order received. */
  writes: string[] = [];
  /**
   * Whether the server keeps a trash, as an honest server does: then it serves the deleted items of the vaults a person
   * may read, and each item's earlier versions, newest first. Off by default (it serves an empty trash and no versions).
   */
  keepsTrash = false;
  /** Each item's earlier versions, newest first, as a put over it or its deletion left them. */
  versions = new Map<string, ItemVersion[]>();

  private served(vaultId: string): string[] {
    const all = this.logs.get(vaultId) ?? [];
    const cut = this.logCut.get(vaultId);
    return cut === undefined ? all : all.slice(0, cut);
  }

  /** The head of [vaultId]'s log as the server serves it. */
  head(vaultId: string): { seq: number; hash: string; at: number } {
    const all = this.served(vaultId);
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

  /** This account's grant row of [vaultId] as the server held it when this is called (served later as it was). */
  grantRowOf(vaultId: string, userId: string): WireGrant {
    const g = this.grants.get(vaultId)!.get(userId)!;
    return { vaultId, userId, role: g.role, wrappedVk: g.wrappedVk, rev: g.rev, signedGrant: g.signedGrant } as WireGrant;
  }

  /** [vaultId]'s own row as the server would serve it now, with its log head. */
  vaultRowOf(vaultId: string): WireVault {
    const h = this.head(vaultId);
    return { vaultId, type: "shared", rev: this.rev, metaBlob: this.metas.get(vaultId) ?? "", createdAt: 0, logHead: { seq: h.seq, hash: h.hash } } as WireVault;
  }

  wireFor(userId: string) {
    const s = this;
    return {
      onRefusedIds: undefined as unknown,
      async sync(since: number): Promise<SyncResponse> {
        if (since > 0 && since < s.oldest) throw new ApiError(410, "resync_required", "cursor gone");
        const vaults: WireVault[] = [];
        const grants: WireGrant[] = [];
        const removed: string[] = [];
        const live = new Set<string>();
        for (const [vaultId, rows] of s.grants) {
          const g = rows.get(userId);
          if (g === undefined) continue;
          if (g.revoked) {
            if (g.rev > since) removed.push(vaultId);
            continue;
          }
          live.add(vaultId);
          vaults.push(s.vaultRowOf(vaultId));
          grants.push({ vaultId, userId, role: g.role, wrappedVk: g.wrappedVk, rev: g.rev, signedGrant: g.signedGrant });
        }
        // Every item of a vault served, at every sync (a delta re-serves unchanged rows; the browser applies them again).
        const items = [...s.items.values()].filter((it) => live.has(it.vaultId) || s.personals.get(it.vaultId) === userId);
        const r = { rev: s.rev, full: since === 0, vaults, grants, items, removedGrants: removed } as SyncResponse;
        return s.tamper ? s.tamper(r, since, userId) : r;
      },
      async pushMutations(mutations: Mutation[]): Promise<PushResponse> {
        const results: MutationResult[] = [];
        for (const m of mutations) {
          s.writes.push(`push:${m.vaultId}`);
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
          if (prev !== undefined && !prev.deleted && prev.blob !== null) s.versions.set(m.itemId, [{ rev: prev.rev, blob: prev.blob, formatVersion: prev.formatVersion, archivedAt: rev }, ...(s.versions.get(m.itemId) ?? [])]);
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
        s.writes.push(`upload:${vaultId}`);
        if (!s.canWrite(userId, vaultId)) throw new ApiError(403, "no_grant", "no grant");
        s.attachments.set(id, { vaultId, body: body.slice() });
        return { attachmentId: id, itemId, vaultId, size: body.length, sha256: "", createdAt: 0 };
      },
      async deletedItems(): Promise<{ items: { itemId: string; vaultId: string; deletedAt: number }[] }> {
        if (!s.keepsTrash) return { items: [] };
        const readable = (vaultId: string): boolean => s.personals.get(vaultId) === userId || s.grants.get(vaultId)?.get(userId)?.revoked === false;
        return { items: [...s.items.values()].filter((it) => it.deleted && readable(it.vaultId)).map((it) => ({ itemId: it.itemId, vaultId: it.vaultId, deletedAt: it.updatedAt })) };
      },
      async itemVersions(itemId: string): Promise<{ itemId: string; versions: ItemVersion[] }> {
        return { itemId, versions: s.keepsTrash ? (s.versions.get(itemId) ?? []) : [] };
      },
      async purgeItem(itemId: string): Promise<void> {
        s.writes.push(`purge:${s.items.get(itemId)?.vaultId ?? ""}`);
        s.items.delete(itemId);
      },
      async restoreItem(itemId: string, upload: { formatVersion: number; attachmentIds: string[]; blob: string }): Promise<{ rev: number }> {
        const prev = s.items.get(itemId);
        s.writes.push(`restore:${prev?.vaultId ?? ""}`);
        if (prev === undefined || !s.canWrite(userId, prev.vaultId)) throw new ApiError(403, "no_grant", "no grant");
        const rev = ++s.rev;
        s.items.set(itemId, { ...prev, rev, updatedAt: rev, deleted: false, formatVersion: upload.formatVersion, attachmentIds: upload.attachmentIds, blob: upload.blob });
        return { rev };
      },
      async updateVaultMeta(vaultId: string, body: { metaBlob: string }): Promise<{ rev: number }> {
        s.writes.push(`meta:${vaultId}`);
        if (!s.canWrite(userId, vaultId)) throw new ApiError(403, "no_grant", "no grant");
        s.metas.set(vaultId, body.metaBlob);
        return { rev: ++s.rev };
      },
      async downloadAttachment(id: string): Promise<Uint8Array> {
        const a = s.attachments.get(id);
        if (!a || s.grants.get(a.vaultId)?.get(userId)?.revoked !== false) throw new ApiError(404, "not_found", "no attachment");
        return a.body.slice();
      },
      async deletedVaults(): Promise<never[]> {
        return [];
      },
      async logPage(vaultId: string, after: number | null): Promise<LogPage> {
        s.onLogPage?.(vaultId);
        const all = s.served(vaultId);
        return { entries: all.slice(after === null ? 0 : after + 1), head: s.head(vaultId), purged: null, deleted: null };
      },
      async appendLog(vaultId: string, req: LogAppendRequest): Promise<LogAppendResponse> {
        const parsed = parseLogEntry(fromB64Canonical(req.entry)!);
        if (!parsed.ok) throw new ApiError(400, "bad_entry", "bad entry");
        const e = parsed.value.entry;
        s.writes.push(`log-${e.kind}:${vaultId}`);
        s.logs.set(vaultId, [...(s.logs.get(vaultId) ?? []), req.entry]);
        if (req.metaBlob) s.metas.set(vaultId, req.metaBlob);
        const rev = ++s.rev;
        const rows = s.grants.get(vaultId) ?? new Map<string, Grant>();
        if (e.kind === "genesis") rows.set(e.actor, { role: "owner", wrappedVk: req.wrappedVk ?? "", signedGrant: null, revoked: false, rev });
        if (e.kind === "add") rows.set(e.member, { role: e.role, wrappedVk: "", signedGrant: req.grant ?? null, revoked: false, rev });
        if (e.kind === "role") Object.assign(rows.get(e.member)!, { role: e.role, rev });
        if (e.kind === "remove") Object.assign(rows.get(e.member)!, { revoked: true, rev });
        if (e.kind === "leave") Object.assign(rows.get(e.actor)!, { revoked: true, rev });
        if (e.kind === "delete") for (const g of rows.values()) Object.assign(g, { revoked: true, rev });
        if (e.kind === "restore") for (const g of rows.values()) Object.assign(g, { revoked: false, rev });
        s.grants.set(vaultId, rows);
        return { rev: s.rev, head: s.head(vaultId), deleted: null };
      },
      async putSelfWrap(vaultId: string, wrappedVk: string): Promise<number> {
        s.writes.push(`selfwrap:${vaultId}`);
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

export const ALICE = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
export const BOB = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

export function person(userId: string) {
  const seed = randomBytes(32);
  return { userId, identity: boxKeypairFromSeed(seed), signing: signKeypairFromSeed(seed), uvk: randomBytes(32) };
}
export type Person = ReturnType<typeof person>;

export function contact(of: Person, name: string): ContactRecord {
  return { userId: of.userId, identityPub: toB64(of.identity.publicKey), label: toB64(utf8(name)), method: "link", verifiedAt: 1, compared: true, madeOn: "ffffffff-ffff-4fff-8fff-ffffffffffff", extra: new Map() };
}

export interface Profile {
  storage: ReturnType<typeof memoryStorage>;
  personalVaultId: string;
  personalVk: Uint8Array;
}

/**
 * One session of [p] in a browser. [again]: the same browser profile as an earlier session of this account (a reload, a
 * second tab, or a sign-in after a sign-out: the account's records at rest stay, the key ring does not).
 */
export async function browser(server: FakeSyncServer, p: Person, contacts: readonly ContactRecord[], opts: { cache?: VaultCache; again?: Profile; sync?: boolean } = {}) {
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
  if (opts.sync !== false) await store.sync();
  return { account, store, shared, profile, person: p, contacts };
}
export type Browser = Awaited<ReturnType<typeof browser>>;

/** Alice owns "Family" (one login, "bank"); bob is a writer of it who accepted. */
export async function family(bobCache?: VaultCache) {
  const server = new FakeSyncServer();
  const a = person(ALICE);
  const b = person(BOB);
  const alice = await browser(server, a, [contact(b, "Bob")]);
  const bob = await browser(server, b, [contact(a, "Alice")], { cache: bobCache });
  const old = await alice.store.createSharedVault("Family");
  await alice.store.addVaultMember(old, BOB, "writer");
  await alice.store.save(null, { type: "login", name: "bank", login: { username: "a", password: "pw1" } }, [], undefined, old);
  await bob.store.sync();
  expect((await bob.shared.answer(bob.shared.pendingAsks()[0]!, true)).kind).toBe("adopted");
  await bob.store.sync();
  expect(listed(bob.store, old)).toBe(true);
  return { server, alice, bob, old };
}

export const listed = (store: VaultStore, vaultId: string): boolean => store.vaults().some((v) => v.vaultId === vaultId);
export const noticesOf = (who: Browser, vaultId: string): string[] => who.store.notices().filter((n) => n.vaultId === vaultId).map((n) => n.kind);
export const heldOf = (who: Browser): string[] => who.store.heldVaults().map((h) => h.vaultId);
export const namesIn = (who: Browser, vaultId: string): string[] => who.store.list().filter((i) => i.vaultId === vaultId).map((i) => i.doc.name);

/** [who]'s copy of [vaultId] frozen: the account's record of the vault names another genesis. */
export async function freezeByRecord(who: Browser, vaultId: string): Promise<void> {
  await who.shared.accountState.update((doc) => {
    const rec = doc.vaults.get(vaultId)!;
    return { ...doc, vaults: new Map([...doc.vaults, [vaultId, { ...rec, genesisHash: "ab".repeat(32) }]]) };
  });
  await who.shared.logs.refresh(vaultId, null, null, true);
  expect(who.shared.logs.status(vaultId)).toMatchObject({ kind: "frozen" });
  expect(listed(who.store, vaultId)).toBe(true);
}

/** A fresh, empty IndexedDB for this test's browser. */
export const freshDb = (): void => {
  (globalThis as { indexedDB?: IDBFactory }).indexedDB = new FakeIDBFactory() as unknown as IDBFactory;
};

/**
 * A page that closes at one of its writes. Each write of the session counts one, in the order made: every write to its
 * storage (the records of the vaults' logs and of the account) and every pull commit of its offline copy. The write
 * numbered [at] (from 0, counted from when [n] was last set to 0) and every one after it never land: a storage write is
 * dropped, a commit fails. [n]: the writes counted so far; [committed]: whether a pull commit landed since [n] was set.
 */
export interface Closing {
  at: number;
  n: number;
  committed: boolean;
}

/** [storage] and [cache] as a page that closes at [c] writes to them. */
export function closingAt(storage: Profile["storage"], cache: VaultCache, c: Closing): { storage: Profile["storage"]; cache: VaultCache } {
  const lands = (): boolean => c.n++ < c.at;
  return {
    storage: {
      map: storage.map,
      get: (k) => storage.get(k),
      set: (k, v) => {
        if (lands()) storage.set(k, v);
      },
      remove: (k) => {
        if (lands()) storage.remove(k);
      },
    },
    cache: new Proxy(cache, {
      get(target, prop) {
        if (prop === "applyPull") {
          return async (...a: Parameters<VaultCache["applyPull"]>) => {
            if (!lands()) throw new Error("the page was closed");
            const r = await target.applyPull(...a);
            c.committed = true;
            return r;
          };
        }
        const v = Reflect.get(target, prop, target) as unknown;
        return typeof v === "function" ? (v as (...a: unknown[]) => unknown).bind(target) : v;
      },
    }),
  };
}

/** [cache] with its pull commits failing while [state.fail] holds (the page closed before the commit landed). */
export function commitsFail(cache: VaultCache, state: { fail: boolean }): VaultCache {
  return new Proxy(cache, {
    get(target, prop) {
      if (prop === "applyPull" && state.fail) return async () => Promise.reject(new Error("the page was closed"));
      const v = Reflect.get(target, prop, target) as unknown;
      return typeof v === "function" ? (v as (...a: unknown[]) => unknown).bind(target) : v;
    },
  });
}
