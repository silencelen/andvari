// A person's own leave of a shared vault frozen on this browser (the server's record of it contradicts itself), through
// the real VaultStore, SharedLogSession and VaultLogStore against a fake server:
//  - a removal of such a vault learned at a sync is never quiet: the notice and the held copy stay, also after the
//    person's own leave. The mark of a leave the server took is bound to the grant row it was made for and only changes
//    the notice's words (the person left it here; nothing since can be checked); it is used up by the next removal and
//    goes at a re-add, after which the ordinary notice shows (in the same tab, across a reload, across a sign-out);
//    another account in the same browser has its own marks;
//  - a vault the person left, and was told the server took, is not listed again at a reload because the server keeps
//    serving its grant row;
//  - a declined invitation on a frozen vault says what the browser knows of its answer: stored, refused, or cannot tell.
// The fake server keeps one revision per grant row, as the real one does: a row's revision moves only when the row is
// written (a genesis, an add, a role, a remove, a leave, a delete, a self-wrap), and every pull serves every live row.
import "fake-indexeddb/auto";
import { IDBFactory as FakeIDBFactory } from "fake-indexeddb";
import { beforeAll, describe, expect, it } from "vitest";
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
import { logPosition, parseLogEntry, signLogEntry } from "../crypto/trust/vaultlog";
import { SHARE_DECLINE_FROZEN_REFUSED, SHARE_DECLINE_FROZEN_STORED, SHARE_DECLINE_FROZEN_UNKNOWN, SHARE_DECLINE_NOT_STORED, SHARE_DECLINE_WAITING } from "../ui/copy";
import { shareAnswerText } from "../ui/SharedPrompts";
import { fill, VAULT_LEFT_FROZEN_NOTICE } from "../ui/copy";
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
  seen = new Map<string, Set<string>>();
  pushed = new Map<string, MutationResult>();
  appends: string[] = [];
  noAnswer: { kind: string; store: boolean } | null = null;
  slowDown: string | null = null;
  leaveRevokes = false;
  personals = new Map<string, string>();

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

  wireFor(userId: string) {
    const s = this;
    return {
      onRefusedIds: undefined as unknown,
      async sync(since: number): Promise<SyncResponse> {
        const vaults: WireVault[] = [];
        const grants: WireGrant[] = [];
        const removed: string[] = [];
        const seen = s.seen.get(userId) ?? new Set<string>();
        for (const [vaultId, rows] of s.grants) {
          const g = rows.get(userId);
          if (g === undefined) continue;
          if (g.revoked) {
            if (seen.has(vaultId)) removed.push(vaultId);
            seen.delete(vaultId);
            continue;
          }
          seen.add(vaultId);
          const h = s.head(vaultId);
          vaults.push({ vaultId, type: "shared", rev: s.rev, metaBlob: s.metas.get(vaultId) ?? "", createdAt: 0, logHead: { seq: h.seq, hash: h.hash } } as WireVault);
          grants.push({ vaultId, userId, role: g.role, wrappedVk: g.wrappedVk, rev: g.rev, signedGrant: g.signedGrant });
        }
        s.seen.set(userId, seen);
        const items = [...s.items.values()].filter((it) => seen.has(it.vaultId) || s.personals.get(it.vaultId) === userId);
        return { rev: s.rev, full: since === 0, vaults, grants, items, removedGrants: removed } as SyncResponse;
      },
      async pushMutations(mutations: Mutation[]): Promise<PushResponse> {
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
        const lost = s.noAnswer !== null && s.noAnswer.kind === e.kind ? s.noAnswer : null;
        if (lost !== null && !lost.store) throw new ApiError(0, "network", "no answer");
        if (s.slowDown === e.kind) throw new ApiError(429, "rate_limited", "slow down");
        s.logs.set(vaultId, [...(s.logs.get(vaultId) ?? []), req.entry]);
        s.appends.push(`${e.kind}:${vaultId}`);
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
        if (lost !== null) throw new ApiError(0, "network", "no answer");
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
const C = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";

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
 * One session of [p] in a browser. [again]: the same browser profile as an earlier session of this account (a reload, or
 * a sign-in after a sign-out: the account's records at rest stay, the key ring does not). [storage]: a browser whose
 * storage another account's session already uses.
 */
async function browser(server: Server, p: Person, contacts: readonly ContactRecord[], opts: { cache?: VaultCache; again?: Profile; storage?: ReturnType<typeof memoryStorage> } = {}) {
  const { cache, again } = opts;
  if (again === undefined) server.seedState(p.userId, p.uvk, { ...EMPTY_DOCUMENT, contacts: new Map(contacts.map((c) => [c.userId, c])) });
  const profile: Profile = again ?? { storage: opts.storage ?? memoryStorage(), personalVaultId: crypto.randomUUID(), personalVk: randomBytes(32) };
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

/** Alice owns "Family" with one login; bob is a writer who accepted, carol a reader who has not answered yet. */
async function family(bobCache?: VaultCache) {
  const server = new Server();
  const a = person(A);
  const b = person(B);
  const c = person(C);
  const alice = await browser(server, a, [contact(b, "Bob"), contact(c, "Carol")]);
  const bob = await browser(server, b, [contact(a, "Alice")], { cache: bobCache });
  const old = await alice.store.createSharedVault("Family");
  await alice.store.addVaultMember(old, B, "writer");
  await alice.store.addVaultMember(old, C, "reader");
  await alice.store.save(null, { type: "login", name: "bank", login: { username: "a", password: "pw1" } }, [], undefined, old);
  await bob.store.sync();
  expect((await bob.shared.answer(bob.shared.pendingAsks()[0]!, true)).kind).toBe("adopted");
  await bob.store.sync();
  return { server, alice, bob, old, carolPerson: c };
}

const listed = (store: VaultStore, vaultId: string): boolean => store.vaults().some((v) => v.vaultId === vaultId);
const noticesOf = (who: Browser, vaultId: string): string[] => who.store.notices().filter((n) => n.vaultId === vaultId).map((n) => n.kind);
const heldOf = (who: Browser): string[] => who.store.heldVaults().map((h) => h.vaultId);

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

async function bobFrozenByRecord(bobCache?: VaultCache) {
  const f = await family(bobCache);
  await freezeByRecord(f.bob, f.old);
  f.server.leaveRevokes = true;
  return f;
}

/**
 * [who]'s copy of [vaultId] frozen beside the account's record, on the same genesis: the record names an entry one place
 * after the verified head, and the server serves [who] once another entry there, validly signed by the owner ([owner]),
 * and then the log as it was (so a leave signed here lands at the server's next position, as on a vault frozen by its
 * record).
 */
async function freezeBesideRecord(server: Server, who: Browser, owner: Browser, vaultId: string): Promise<void> {
  const s = who.shared.logs.verifiedState(vaultId)!;
  const o = owner.shared.logs.verifiedState(vaultId)!;
  expect(o.head.seq).toBe(s.head.seq);
  await who.shared.accountState.update((doc) => withVaultHead(doc, vaultId, s.genesisHash, s.head.seq + 1, "ab".repeat(32)));
  const pos = logPosition(o, o.at + 1000);
  const beside = toB64(signLogEntry(owner.person.signing, { kind: "role", vaultId, seq: pos.seq, prev: pos.prev, actor: owner.person.userId, at: pos.at, member: C, role: "writer" }));
  const log = server.logs.get(vaultId)!;
  server.logs.set(vaultId, [...log, beside]);
  await who.shared.logs.refresh(vaultId, null, null, true);
  server.logs.set(vaultId, log);
  expect(who.shared.logs.status(vaultId)).toMatchObject({ kind: "frozen", atSeq: s.head.seq + 1 });
  expect(listed(who.store, vaultId)).toBe(true);
}

async function bobFrozenBeside(bobCache?: VaultCache) {
  const f = await family(bobCache);
  await freezeBesideRecord(f.server, f.bob, f.alice, f.old);
  f.server.leaveRevokes = true;
  return f;
}

/** Bob's leave of the frozen vault, which the server stores and answers naming it (it revokes his row). */
async function bobLeavesTaken(server: Server, bob: Browser, old: string): Promise<void> {
  await bob.store.leaveSharedVault(old).catch(() => {});
  expect(server.grants.get(old)!.get(B)!.revoked).toBe(true);
  expect(bob.shared.logs.ownFrozenLeaveTaken(old)).toBe(true);
}

/**
 * The owner adds bob again before bob's browser synced, and bob accepts on another device of his (its self-wrap of the
 * same key, under the same genesis, is put on his row). The server's row is live again, with a new revision.
 */
async function aliceAddsBobAgain(server: Server, alice: Browser, old: string, bobsWrap: string): Promise<void> {
  await alice.store.sync();
  await alice.store.addVaultMember(old, B, "writer");
  const row = server.grants.get(old)!.get(B)!;
  expect(row.revoked).toBe(false);
  Object.assign(row, { wrappedVk: bobsWrap, rev: ++server.rev });
}

describe("a person's own leave of a frozen shared vault", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("taken by the server, the person added again before this browser synced, then removed by the owner: the removal keeps its notice and its held copy", async () => {
    const { server, alice, bob, old } = await bobFrozenByRecord();
    const bobsWrap = server.grants.get(old)!.get(B)!.wrappedVk;
    await bobLeavesTaken(server, bob, old);
    await aliceAddsBobAgain(server, alice, old, bobsWrap);
    await bob.store.sync();
    // The pull delivered bob's row again: the leave the mark was made for is no longer the state of his grant.
    expect(bob.shared.logs.ownFrozenLeaveTaken(old)).toBe(false);
    expect(listed(bob.store, old)).toBe(true);
    // Later the owner removes bob, which bob did not ask for.
    await alice.store.sync();
    await alice.store.removeVaultMember(old, B);
    expect(server.grants.get(old)!.get(B)!.revoked).toBe(true);
    await bob.store.sync();
    // On the code before: no notice and no held copy (the mark of the earlier leave made this removal quiet).
    expect(listed(bob.store, old)).toBe(false);
    expect(noticesOf(bob, old)).toEqual(["anomaly"]);
    expect(heldOf(bob)).toEqual([old]);
  });

  it("taken by the server, then the person added again AND removed by the owner while this browser was closed: one pull learns the removal, with the own-leave notice and the held copy", async () => {
    const { server, alice, bob, old } = await bobFrozenByRecord();
    await bobLeavesTaken(server, bob, old);
    // This browser is closed. The owner adds bob again (he accepts on another device), and later removes him.
    await alice.store.sync();
    await alice.store.addVaultMember(old, B, "writer");
    expect(server.grants.get(old)!.get(B)!.revoked).toBe(false);
    await alice.store.sync();
    await alice.store.removeVaultMember(old, B);
    expect(server.grants.get(old)!.get(B)!.revoked).toBe(true);
    // This browser is opened again: its one pull lists the vault as removed, and no row of bob's was served in between,
    // so the mark of his leave still stands. A frozen vault's log cannot show which removal this is: never quiet.
    await bob.store.sync();
    expect(listed(bob.store, old)).toBe(false);
    expect(noticesOf(bob, old)).toEqual(["left-frozen"]);
    const notice = bob.store.notices().find((n) => n.vaultId === old)!;
    expect(noticeBody(notice)).toEqual({ warn: true, body: fill(VAULT_LEFT_FROZEN_NOTICE, "Family") });
    expect(heldOf(bob)).toEqual([old]);
    expect(bob.store.heldVaults()[0]!.itemCount).toBe(1);
    expect(bob.shared.logs.ownFrozenLeaveTaken(old)).toBe(false);
  });

  it("the same removal by the owner with no leave before it: the notice and the held copy (the comparison)", async () => {
    const { server, alice, bob, old } = await bobFrozenByRecord();
    await alice.store.removeVaultMember(old, B);
    expect(server.grants.get(old)!.get(B)!.revoked).toBe(true);
    await bob.store.sync();
    expect(noticesOf(bob, old)).toEqual(["anomaly"]);
    expect(heldOf(bob)).toEqual([old]);
  });

  it("the mark is used up by the removal it explained: the own-leave notice and the held copy once, then the mark is gone from the browser", async () => {
    const { server, bob, old } = await bobFrozenByRecord();
    await bobLeavesTaken(server, bob, old);
    const key = `andvari.log2.${B}.${old}.ownLeave`;
    expect(bob.profile.storage.map.has(key)).toBe(true);
    await bob.store.sync();
    // Before: quiet (no notice, nothing held).
    expect(listed(bob.store, old)).toBe(false);
    expect(noticesOf(bob, old)).toEqual(["left-frozen"]);
    expect(heldOf(bob)).toEqual([old]);
    expect(bob.shared.logs.ownFrozenLeaveTaken(old)).toBe(false);
    expect(bob.profile.storage.map.has(key)).toBe(false);
  });

  for (const via of ["a reload with the offline copy", "a sign-out and a new sign-in with no offline copy (a full first pull)"] as const) {
    it(`across ${via}: the leave taken, the person added again meanwhile, then removed by the owner: the notice and the held copy`, async () => {
      (globalThis as { indexedDB?: IDBFactory }).indexedDB = new FakeIDBFactory() as unknown as IDBFactory;
      const offline = via.startsWith("a reload");
      const { server, alice, bob, old } = await bobFrozenBeside(offline ? await openVaultCache(B) : undefined);
      const bobsWrap = server.grants.get(old)!.get(B)!.wrappedVk;
      await bobLeavesTaken(server, bob, old);
      await aliceAddsBobAgain(server, alice, old, bobsWrap);
      const again = await browser(server, bob.person, bob.contacts, { cache: offline ? await openVaultCache(B) : undefined, again: bob.profile });
      expect(again.shared.logs.status(old).kind).toBe("frozen");
      expect(again.shared.logs.ownFrozenLeaveTaken(old)).toBe(false);
      expect(listed(again.store, old)).toBe(true);
      await alice.store.sync();
      await alice.store.removeVaultMember(old, B);
      await again.store.sync();
      // On the code before: quiet (the mark outlived the re-add, at rest). A reload that learns the re-add from its delta
      // pull also tells it as an addition ("added"); that line is not this test's.
      expect(listed(again.store, old)).toBe(false);
      expect(noticesOf(again, old).filter((k) => k !== "added")).toEqual(["anomaly"]);
      expect(heldOf(again)).toEqual([old]);
    });
  }

  it("another account in the same browser: its removal from a vault frozen for it keeps its notice, whatever the first account's mark says", async () => {
    const { server, alice, bob, old, carolPerson } = await bobFrozenByRecord();
    const carol = await browser(server, carolPerson, [contact(alice.person, "Alice")], { storage: bob.profile.storage });
    expect((await carol.shared.answer(carol.shared.pendingAsks()[0]!, true)).kind).toBe("adopted");
    await carol.store.sync();
    await freezeByRecord(carol, old);
    await bobLeavesTaken(server, bob, old);
    expect(carol.shared.logs.ownFrozenLeaveTaken(old)).toBe(false);
    await alice.store.sync();
    await alice.store.removeVaultMember(old, C);
    await carol.store.sync();
    expect(listed(carol.store, old)).toBe(false);
    expect(noticesOf(carol, old)).toEqual(["anomaly"]);
    expect(heldOf(carol)).toEqual([old]);
    // Bob's own mark is his, and still waits for his removal.
    expect(bob.shared.logs.ownFrozenLeaveTaken(old)).toBe(true);
  });

  for (const offline of [false, true]) {
    it(`taken by a server that keeps serving the person's grant row: not listed again at a reload (${offline ? "with" : "without"} the offline copy)`, async () => {
      (globalThis as { indexedDB?: IDBFactory }).indexedDB = new FakeIDBFactory() as unknown as IDBFactory;
      // Frozen beside the record (one genesis): a vault that still opens at a reload, so the mark alone keeps it closed.
      const { server, bob, old } = await bobFrozenBeside(offline ? await openVaultCache(B) : undefined);
      server.leaveRevokes = false;
      await bob.store.leaveSharedVault(old).catch(() => {});
      expect(server.grants.get(old)!.get(B)!.revoked).toBe(false);
      expect(bob.shared.logs.ownFrozenLeaveTaken(old)).toBe(true);
      await bob.store.sync();
      // The row served again unchanged is no re-add: the mark stays.
      expect(bob.shared.logs.ownFrozenLeaveTaken(old)).toBe(true);
      const again = await browser(server, bob.person, bob.contacts, { cache: offline ? await openVaultCache(B) : undefined, again: bob.profile });
      // On the code before: listed again, items and all, from the person's own wrap.
      expect(listed(again.store, old)).toBe(false);
      expect(again.store.list().filter((i) => i.vaultId === old)).toEqual([]);
      expect(again.account.logKeyRing().has(old)).toBe(false);
      // A second reload is the same.
      const third = await browser(server, bob.person, bob.contacts, { cache: offline ? await openVaultCache(B) : undefined, again: bob.profile });
      expect(listed(third.store, old)).toBe(false);
    });
  }
});

describe("a declined invitation on a vault frozen while it was offered says what the browser knows of the answer", () => {
  beforeAll(async () => {
    await initSodium();
  });

  /**
   * Carol is offered the vault, and a fork in her view freezes it: bob's leave, which she verified, is taken out of the
   * log and alice's change stored in its place.
   */
  async function carolOfferedFrozen() {
    const { server, alice, bob, old, carolPerson } = await family();
    const carol = await browser(server, carolPerson, [contact(alice.person, "Alice")]);
    const [ask] = carol.shared.pendingAsks();
    expect(ask).toBeDefined();
    const at = server.logs.get(old)!.length;
    await bob.store.leaveSharedVault(old);
    await carol.store.sync();
    server.logs.set(old, server.logs.get(old)!.slice(0, at));
    await alice.store.setMemberRole(old, B, "reader");
    await carol.store.sync();
    expect(carol.shared.logs.status(old)).toMatchObject({ kind: "frozen", atSeq: at });
    server.leaveRevokes = true;
    return { server, carol, ask: carol.shared.pendingAsks()[0] ?? ask!, old };
  }

  const others = (line: string): string[] => [SHARE_DECLINE_FROZEN_STORED, SHARE_DECLINE_FROZEN_REFUSED, SHARE_DECLINE_FROZEN_UNKNOWN, SHARE_DECLINE_NOT_STORED, SHARE_DECLINE_WAITING].filter((l) => l !== line);

  for (const [what, setUp, frozen, leave, line] of [
    ["the server stores it, but its answer cannot name it at the position signed here", (_s: Server) => {}, "unknown", "not_stored", () => SHARE_DECLINE_FROZEN_UNKNOWN],
    ["the server refuses it (429)", (s: Server) => void (s.slowDown = "leave"), "refused", "not_stored", () => SHARE_DECLINE_FROZEN_REFUSED],
    ["its answer is lost and nothing was stored", (s: Server) => void (s.noAnswer = { kind: "leave", store: false }), "unknown", "not_stored", () => SHARE_DECLINE_FROZEN_UNKNOWN],
    ["its answer is lost after the server stored it", (s: Server) => void (s.noAnswer = { kind: "leave", store: true }), "unknown", "not_stored", () => SHARE_DECLINE_FROZEN_UNKNOWN],
  ] as const) {
    it(`frozen by a fork, ${what}: its own line`, async () => {
      const { server, carol, ask, old } = await carolOfferedFrozen();
      setUp(server);
      const answered = await carol.shared.answer(ask, false);
      server.noAnswer = null;
      server.slowDown = null;
      // On the code before: every one of these was { leave: "not_stored", frozen: true } and said "can't tell", also where
      // the browser knew that the server stored it or refused it.
      expect(answered).toMatchObject({ kind: "declined", vaultId: old, leave, frozen });
      const said = shareAnswerText(answered);
      expect(said).toBe(line());
      for (const other of others(line())) expect(said).not.toBe(other);
    });
  }

  it("a decline the server answered as stored on a frozen vault says so, never 'can't tell'", () => {
    // No freeze reaches this answer end to end in these tests: an invitation frozen by its record is refused before the
    // decline is signed, and a fork leaves the server's answer unable to name the leave. The line is pinned from the
    // answer's own shape.
    const said = shareAnswerText({ kind: "declined", vaultId: "v", leave: "stored", frozen: "stored" });
    expect(said).toBe(SHARE_DECLINE_FROZEN_STORED);
    for (const other of others(SHARE_DECLINE_FROZEN_STORED)) expect(said).not.toBe(other);
  });

  it("a decline whose answer was lost on a vault that is not frozen keeps the general line", () => {
    expect(shareAnswerText({ kind: "declined", vaultId: "v", leave: "not_stored" })).toBe(SHARE_DECLINE_NOT_STORED);
    expect(shareAnswerText({ kind: "declined", vaultId: "v", leave: "stored" })).toBeNull();
  });
});
