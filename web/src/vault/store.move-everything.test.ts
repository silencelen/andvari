import "fake-indexeddb/auto"; // bob's offline copy, for the holding area's lifetime
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
import { parseLogEntry } from "../crypto/trust/vaultlog";
import { Account } from "./account";
import { type AccountDocument, type ContactRecord, EMPTY_DOCUMENT, encodeDocument } from "./accountdoc";
import { openVaultCache, type VaultCache } from "./idbcache";
import { SharedLogSession } from "./sharedlogs";
import { VAULT_META_MOVE_OF } from "./logstore";
import { ChangeNotStoredError, HeldKeyGoneError, type ItemWire, LogActionError, MoveStoppedError, MoveWaitingError, OldVaultFrozenError, VaultStore } from "./store";
import { MOVE_OLD_FROZEN } from "../ui/copy";
import { MOVE_CHANGED_AFTER_READ, MOVE_CHANGED_MEANWHILE, MOVE_DONE_NO_DAY, RESEND_DELETE_MADE_NO_DAY, RESEND_DELETE_MADE_UNNAMED_NO_DAY, RESEND_FOUND_MADE_HALF_MADE_DELETE_NO_DAY } from "../ui/copy";
import { RESEND_DELETE_ASK, RESEND_DELETE_ASK_GIVEN_UP, RESEND_DELETE_ASK_KEEP, RESEND_DELETE_ASK_NOW, RESEND_DELETE_ASK_UNNAMED, RESEND_DELETE_MADE, RESEND_DELETE_MADE_UNNAMED, RESEND_FOUND_MADE_REMOVE, RESEND_FOUND_NOT_MADE } from "../ui/copy";
import { fill, RESEND_NOT_MADE_REMOVE, LOG_UNKNOWN, LOG_UNKNOWN_CREATE, MOVE_STOPPED_DELETE_HELD, MOVE_STOPPED_DELETE_WAITING, MOVE_UNFINISHED } from "../ui/copy";
import { logActionText } from "../ui/logactiontext";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { QuotaShortError, sealedBlobLength } from "./quota";
import { OWNER_OUT_OF_SPACE } from "../ui/copy";
import { fmtDate, fmtDay, humanSize } from "../ui/format";
import { MOVE_UNNAMED_VAULT, RESEND_FOUND_MADE_HALF_MADE_DELETE } from "../ui/copy";
import { quotaLineText } from "../ui/quotatext";
import { discardText, friendlyError, moveErrorText, moveResultText } from "../ui/Sharing";
import { shareAnswerText } from "../ui/SharedPrompts";
import { ROSTER_FROZEN, ROSTER_STALE, SHARE_DECLINE_FROZEN_UNKNOWN, SHARE_DECLINE_NOT_STORED } from "../ui/copy";
import { rosterNoteText } from "../ui/Sharing";
import { LOG_FROZEN, LOG_FROZEN_NOT_SENT, LOG_LEAVE_FROZEN_REFUSED, LOG_LEAVE_FROZEN_TAKEN, LOG_LEAVE_FROZEN_UNKNOWN, LOG_NOT_STORED, LOG_READ_ONLY } from "../ui/copy";
import { MOVE_DISCARD_HOLDERS_FOUND, MOVE_DISCARD_HOLDERS_FOUND_UNREAD } from "../ui/copy";
import { MOVE_DISCARD_HOLDERS, MOVE_DISCARD_KEPT, MOVE_DISCARD_NOT_HELD,MOVE_DISCARD_UNREAD,MOVE_DISCARDED, MOVE_STOPPED_COPY, MOVE_STOPPED_COPY_REMOVED, MOVE_STOPPED_START_REMOVED } from "../ui/copy";
import { HeldDeleteAsk, importPushOutcome, MoveLateCopy, noticeBody } from "../ui/Vault";
import { readdirSync } from "node:fs";
import { saveErrorText } from "../ui/saveerror";
import { MOVE_WAITING_REFUSED, MOVE_STORED_COPY, MOVE_STORED_LATE, MOVE_STORED_NOTHING_LATE, MOVE_DELETED_OUTSIDE, MOVE_STORED_UNSEEN } from "../ui/copy";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

/**
 * "Move everything to a new vault" (design §3.13) through the sync store, against a fake server that keeps the
 * vault logs, grant rows, items, attachments and account states, and that can be told to drop the connection or to
 * answer that the owner is out of space part-way through.
 */

interface Grant {
  role: "owner" | "writer" | "reader";
  wrappedVk: string;
  signedGrant: string | null;
  revoked: boolean;
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
  /** Puts the server still takes before the connection drops (null: no limit). */
  putsBeforeDrop: number | null = null;
  /** Puts the server still takes before the owner's account is full (null: no limit). */
  putsBeforeFull: number | null = null;
  appends: string[] = [];
  /** An `add` of this member is refused (a 409 the log store reports as refused). */
  refuseAddOf: string | null = null;
  /** An `add` of this member is acknowledged but not stored (a server that loses it). */
  loseAddOf: string | null = null;
  /** The `quota` each sync answer carries (spec 03 §14.4), as the wire client decoded it; undefined: none. */
  quota: unknown = undefined;
  /** A `remove` of this member is acknowledged but not stored. */
  loseRemoveOf: string | null = null;
  /** Run before each append is answered: another member's change landing while a move runs. */
  beforeAppend: ((kind: string, vaultId: string) => Promise<void>) | null = null;
  /**
   * An append of this entry kind gets no answer (the connection drops): with `store`, the server stored it first (the
   * answer was lost, "it came late"); with `offline`, every sync fails from then on until it is set back.
   */
  noAnswer: { kind: string; store: boolean; offline?: boolean } | null = null;
  /** Every append that reached the server, stored or not, as `kind:vaultId`. */
  attempts: string[] = [];
  /** The connection is down for syncs. */
  offline = false;
  /** Every read of a vault's log fails (the connection drops). */
  logReadsFail = false;
  /** Every read of the trash fails (the connection drops). */
  trashReadsFail = false;
  /** Run after a sync answer is made and before it is returned, with the user it is for (a held answer). */
  afterSyncAnswer: ((userId: string) => Promise<void>) | null = null;
  /** An append of this entry kind is answered 429: the server asks to slow down, nothing stored. */
  slowDown: string | null = null;
  /** Syncs the server still answers before every later one fails (null: no limit). */
  syncsBeforeOffline: number | null = null;
  /** The read point each `delete` that reached the server named, in order (null: none). */
  points: (number | null)[] = [];
  /** A deleted vault's log read carries the grace end, as the server's does; false: an older server's read, none. */
  graceOnRead = false;
  /** A `delete`'s append answer carries no grace end (an older server's answer). */
  noGraceOnAppend = false;
  /** Run when a sync arrives, before it is answered. */
  beforeSync: (() => void) | null = null;
  /** An append of this entry kind is answered as stored at its position, naming it, while nothing is stored (a lie). */
  lieAbout: string | null = null;
  /** A stored `leave` revokes the leaver's grant, as the real server's does (VaultLogRoutes); off for the older tests. */
  leaveRevokes = false;

  private head(vaultId: string): { seq: number; hash: string; at: number } {
    const all = this.logs.get(vaultId) ?? [];
    const last = all[all.length - 1];
    if (last === undefined) return { seq: -1, hash: "", at: 0 };
    const parsed = parseLogEntry(fromB64Canonical(last)!);
    return { seq: all.length - 1, hash: toHexLower(sha256Sync(fromB64Canonical(last)!)), at: parsed.ok ? parsed.value.entry.at : 0 };
  }

  /** Personal vaults, by id: their owner. */
  personals = new Map<string, string>();

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
        if (s.offline) throw new ApiError(0, "network", "offline");
        if (s.syncsBeforeOffline !== null && s.syncsBeforeOffline-- <= 0) throw new ApiError(0, "network", "offline");
        s.beforeSync?.();
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
          grants.push({ vaultId, userId, role: g.role, wrappedVk: g.wrappedVk, rev: s.rev, signedGrant: g.signedGrant });
        }
        s.seen.set(userId, seen);
        const items = [...s.items.values()].filter((it) => seen.has(it.vaultId) || s.personals.get(it.vaultId) === userId);
        const answer = { rev: s.rev, full: since === 0, vaults, grants, items, removedGrants: removed, ...(s.quota !== undefined ? { quota: s.quota } : {}) } as SyncResponse;
        if (s.afterSyncAnswer) await s.afterSyncAnswer(userId);
        return answer;
      },
      async pushMutations(mutations: Mutation[]): Promise<PushResponse> {
        const results: MutationResult[] = [];
        for (const m of mutations) {
          const done = s.pushed.get(m.mutationId);
          if (done) {
            results.push(done);
            continue;
          }
          if (m.op === "put") {
            if (s.putsBeforeDrop !== null && s.putsBeforeDrop-- <= 0) throw new ApiError(0, "network", "the connection dropped");
            if (s.putsBeforeFull !== null && s.putsBeforeFull-- <= 0) {
              results.push({ mutationId: m.mutationId, status: "rejected", reason: "quota_exceeded" });
              continue;
            }
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
        if (s.trashReadsFail) throw new ApiError(0, "network", "offline");
        return { items: [...s.items.values()].filter((it) => it.deleted && s.grants.get(it.vaultId)?.get(userId)?.revoked === false).map((it) => ({ itemId: it.itemId, vaultId: it.vaultId, deletedAt: it.updatedAt })) };
      },
      async itemVersions(): Promise<{ versions: never[] }> {
        return { versions: [] };
      },
      async purgeItem(itemId: string): Promise<void> {
        s.attempts.push(`purge:${itemId}`);
        s.items.delete(itemId);
      },
      async downloadAttachment(id: string): Promise<Uint8Array> {
        const a = s.attachments.get(id);
        if (!a || s.grants.get(a.vaultId)?.get(userId)?.revoked !== false) throw new ApiError(404, "not_found", "no attachment");
        return a.body.slice();
      },
      async logPage(vaultId: string, after: number | null): Promise<LogPage> {
        if (s.logReadsFail) throw new ApiError(0, "network", "offline");
        const all = s.logs.get(vaultId) ?? [];
        // With [graceOnRead], a deleted vault's read carries the server's grace end (spec 03 §10.6): ten days on.
        const del = all.map((e) => parseLogEntry(fromB64Canonical(e)!)).find((p) => p.ok && p.value.entry.kind === "delete");
        const deleted = s.graceOnRead && del?.ok === true ? { deletedAt: del.value.entry.at, purgeAt: del.value.entry.at + 10 * 86_400_000 } : null;
        return { entries: all.slice(after === null ? 0 : after + 1), head: s.head(vaultId), purged: null, deleted };
      },
      async appendLog(vaultId: string, req: LogAppendRequest): Promise<LogAppendResponse> {
        const parsed = parseLogEntry(fromB64Canonical(req.entry)!);
        if (!parsed.ok) throw new ApiError(400, "bad_entry", "bad entry");
        const e = parsed.value.entry;
        if (e.kind === "genesis" && s.putsBeforeDrop === 0) throw new ApiError(0, "network", "the connection dropped");
        if (s.beforeAppend) await s.beforeAppend(e.kind, vaultId);
        s.attempts.push(`${e.kind}:${vaultId}`);
        const lost = s.noAnswer !== null && s.noAnswer.kind === e.kind ? s.noAnswer : null;
        const noAnswer = (): never => {
          if (lost!.offline === true) s.offline = true;
          throw new ApiError(0, "network", "no answer");
        };
        if (lost !== null && !lost.store) noAnswer();
        if (s.lieAbout === e.kind) return { rev: s.rev, head: { seq: e.seq, hash: toHexLower(sha256Sync(fromB64Canonical(req.entry)!)), at: e.at }, deleted: null };
        if (s.slowDown === e.kind) throw new ApiError(429, "rate_limited", "slow down");
        if (e.kind === "add" && e.member === s.refuseAddOf) throw new ApiError(409, "member_refused", "refused");
        if (e.kind === "add" && e.member === s.loseAddOf) return { rev: s.rev, head: s.head(vaultId), deleted: null };
        if (e.kind === "remove" && e.member === s.loseRemoveOf) return { rev: s.rev, head: s.head(vaultId), deleted: null };
        // The real server's rule (spec 03 §10.3, VaultLogRoutes): a `delete` that names its read point is refused, with
        // nothing stored, when any item row of the vault, live or in the trash, has a newer revision.
        if (e.kind === "delete") s.points.push(req.itemsAtMost ?? null);
        if (e.kind === "delete" && req.itemsAtMost !== undefined && [...s.items.values()].some((it) => it.vaultId === vaultId && it.rev > req.itemsAtMost!)) {
          throw new ApiError(409, "vault_items_moved", "an item of the vault changed after the read");
        }
        s.logs.set(vaultId, [...(s.logs.get(vaultId) ?? []), req.entry]);
        s.appends.push(`${e.kind}:${vaultId}`);
        if (req.metaBlob) s.metas.set(vaultId, req.metaBlob);
        const rows = s.grants.get(vaultId) ?? new Map<string, Grant>();
        if (e.kind === "genesis") rows.set(e.actor, { role: "owner", wrappedVk: req.wrappedVk ?? "", signedGrant: null, revoked: false });
        if (e.kind === "add") rows.set(e.member, { role: e.role, wrappedVk: "", signedGrant: req.grant ?? null, revoked: false });
        if (e.kind === "role") rows.get(e.member)!.role = e.role;
        if (e.kind === "remove") rows.get(e.member)!.revoked = true;
        if (e.kind === "leave" && s.leaveRevokes) rows.get(e.actor)!.revoked = true;
        if (e.kind === "delete") for (const g of rows.values()) g.revoked = true;
        s.grants.set(vaultId, rows);
        s.rev++;
        if (lost !== null) noAnswer();
        return { rev: s.rev, head: s.head(vaultId), deleted: e.kind === "delete" && !s.noGraceOnAppend ? { deletedAt: e.at, purgeAt: e.at + 7 * 86_400_000 } : null };
      },
      async putSelfWrap(vaultId: string, wrappedVk: string): Promise<number> {
        const row = s.grants.get(vaultId)?.get(userId);
        if (row) row.wrappedVk = wrappedVk;
        return ++s.rev;
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

type Person = ReturnType<typeof person>;

function person(userId: string) {
  const seed = randomBytes(32);
  return { userId, identity: boxKeypairFromSeed(seed), signing: signKeypairFromSeed(seed), uvk: randomBytes(32) };
}

function contact(of: Person, name: string, compared = true): ContactRecord {
  return { userId: of.userId, identityPub: toB64(of.identity.publicKey), label: toB64(utf8(name)), method: "link", verifiedAt: 1, compared, madeOn: "ffffffff-ffff-4fff-8fff-ffffffffffff", extra: new Map() };
}

/** One person's browser: an Account, its sync store over the fake, and its shared-vault layer. */
interface Profile {
  storage: ReturnType<typeof memoryStorage>;
  personalVaultId: string;
  personalVk: Uint8Array;
}

async function browser(server: Server, p: Person, contacts: readonly ContactRecord[], cache?: VaultCache, again?: Profile) {
  // [again]: the same browser profile unlocked once more (its device storage kept, the session's memory gone).
  if (again === undefined) server.seedState(p.userId, p.uvk, { ...EMPTY_DOCUMENT, contacts: new Map(contacts.map((c) => [c.userId, c])) });
  const profile: Profile = again ?? { storage: memoryStorage(), personalVaultId: crypto.randomUUID(), personalVk: randomBytes(32) };
  const personalVaultId = profile.personalVaultId;
  server.personals.set(personalVaultId, p.userId);
  const account = Account.fromOpened(
    { userId: p.userId, uvk: p.uvk, identity: p.identity, signing: p.signing, genesis: null as never, personalVaultId, personalVk: profile.personalVk.slice() },
    null,
  );
  const wire = server.wireFor(p.userId);
  const shared = new SharedLogSession(p, wire, profile.storage, account.logKeyRing());
  await shared.refreshState();
  for (const c of contacts) shared.currency.mark(c.userId, c.identityPub, "confirmed");
  const store = new VaultStore(wire as unknown as ApiClient, account, cache, undefined, wire as unknown as ItemWire);
  store.attachSharedLogs(shared);
  if (cache) await store.hydrate();
  // An unlock re-posts what an earlier session left held, as the app's opening does (ui/opensession.ts), then syncs.
  if (again !== undefined) await store.resendHeldChanges();
  await store.sync();
  return { account, store, shared, wire, profile, person: p, contacts };
}

/** Alice owns "Family" with bob (writer) and carol (reader) in it, and two items, one with an attachment. */
async function family(carolCompared = true, bobCache?: VaultCache, aliceCache?: VaultCache) {
  const server = new Server();
  const a = person(A);
  const b = person(B);
  const c = person(C);
  const alice = await browser(server, a, [contact(b, "Bob"), contact(c, "Carol", carolCompared)], aliceCache);
  const bob = await browser(server, b, [contact(a, "Alice")], bobCache);
  const old = await alice.store.createSharedVault("Family");
  await alice.store.addVaultMember(old, B, "writer");
  if (carolCompared) await alice.store.addVaultMember(old, C, "reader");
  // A contact whose codes were never compared: shared once through another app's release choice (§6.7 step 8).
  else expect((await alice.shared.logs.append(old, { kind: "add", contactUserId: C, role: "reader", releaseUncompared: true })).kind).toBe("appended");
  await alice.store.save(null, { type: "login", name: "bank", login: { username: "a", password: "pw1" } }, [], undefined, old);
  const fileKey = toB64(randomBytes(32));
  const attId = crypto.randomUUID();
  await alice.store.save(null, { type: "note", name: "deeds", notes: "n", attachments: [{ id: attId, name: "deed.txt", size: 5, fileKey }] }, [{ id: attId, data: utf8("hello") }], undefined, old);
  await bob.store.sync();
  expect((await bob.shared.answer(bob.shared.pendingAsks()[0]!, true)).kind).toBe("adopted");
  await bob.store.sync();
  expect(bob.store.list().filter((i) => i.vaultId === old).map((i) => i.doc.name).sort()).toEqual(["bank", "deeds"]);
  return { server, alice, bob, old, carolPerson: c };
}

const names = (store: VaultStore, vaultId: string): string[] => store.list().filter((i) => i.vaultId === vaultId).map((i) => i.doc.name).sort();

describe("Move everything to a new vault (design §3.13)", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("from the remove dialog: removes carol, makes a new vault, copies every item with fresh ids, re-adds bob, then deletes the old vault", async () => {
    const { server, alice, bob, old } = await family();
    const plan = alice.store.movePlan(old, C)!;
    expect(plan.sourceStays).toBe(false);
    expect(plan.members.map((m) => [m.userId, m.role, m.label, m.canBeAdded])).toEqual([[B, "writer", "Bob", true]]);
    expect(plan.itemCount).toBe(2);
    const oldIds = alice.store.list().filter((i) => i.vaultId === old).map((i) => i.itemId);
    const oldAttachment = alice.store.list().find((i) => i.doc.name === "deeds")!.doc.attachments![0]!;

    const progress: string[] = [];
    const r = await alice.store.moveEverything(old, { name: "Family 2", add: [B], removing: C }, (d, t) => progress.push(`${d}/${t}`));
    expect(r.oldKept).toBeNull();
    expect(r.oldDeleted?.purgeAt).toBeGreaterThan(Date.now());
    expect(r.copied).toBe(2);
    expect(progress).toContain("2/2");

    // The order the design gives: remove (the dialog's own), genesis, the copies, add, then delete.
    const onOld = server.appends.filter((x) => x.endsWith(old)).map((x) => x.split(":")[0]);
    expect(onOld.slice(-2)).toEqual(["remove", "delete"]);
    const onNew = server.appends.filter((x) => x.endsWith(r.newVaultId)).map((x) => x.split(":")[0]);
    expect(onNew).toEqual(["genesis", "add"]);

    // The new vault: a new key, the same items under fresh ids, the attachment under a fresh id and file key.
    expect(alice.account.hasVault(r.newVaultId)).toBe(true);
    expect(names(alice.store, r.newVaultId)).toEqual(["bank", "deeds"]);
    const moved = alice.store.list().filter((i) => i.vaultId === r.newVaultId);
    expect(moved.some((i) => oldIds.includes(i.itemId))).toBe(false);
    const att = moved.find((i) => i.doc.name === "deeds")!.doc.attachments![0]!;
    expect(att.id).not.toBe(oldAttachment.id);
    expect(att.fileKey).not.toBe(oldAttachment.fileKey);
    expect(new TextDecoder().decode(await alice.store.downloadAttachment(moved.find((i) => i.doc.name === "deeds")!, att))).toBe("hello");
    expect(alice.store.vaults().find((v) => v.vaultId === r.newVaultId)?.name).toBe("Family 2");

    // The old vault is deleted (in its grace), and gone from alice's list; carol is out of its log before the delete.
    expect(alice.shared.logs.verifiedState(old)?.deleteId).not.toBeNull();
    expect(alice.shared.logs.verifiedState(old)?.members[C]).toBeUndefined();
    expect(alice.store.vaults().some((v) => v.vaultId === old)).toBe(false);
    // The new vault's members are alice and bob; carol was never added.
    expect(Object.keys(alice.shared.logs.verifiedState(r.newVaultId)!.members).sort()).toEqual([A, B]);

    // Bob is asked (§3.6), accepts, and reads everything; the old vault left his browser.
    await bob.store.sync();
    const ask = bob.shared.pendingAsks().find((x) => x.vaultId === r.newVaultId);
    expect(ask).toMatchObject({ owner: A, ownerLabel: "Alice", vaultName: "Family 2" });
    expect(bob.account.hasVault(r.newVaultId)).toBe(false);
    expect((await bob.shared.answer(ask!, true)).kind).toBe("adopted");
    await bob.store.sync();
    expect(names(bob.store, r.newVaultId)).toEqual(["bank", "deeds"]);
    expect(bob.account.roleFor(r.newVaultId)).toBe("writer");
    expect(bob.account.hasVault(old)).toBe(false);
  });

  it("stopped by a dropped connection part-way: nothing is in neither vault, and the next run carries on into the same new vault", async () => {
    const { server, alice, old } = await family();
    server.putsBeforeDrop = 1;
    let stopped: unknown = null;
    try {
      await alice.store.moveEverything(old, { name: "Family 2", add: [B, C] });
    } catch (e) {
      stopped = e;
    }
    expect(stopped).toBeInstanceOf(MoveStoppedError);
    const s = stopped as MoveStoppedError;
    expect([s.stage, s.copied, s.total, s.newName]).toEqual(["copy", 1, 2, "Family 2"]);
    // Every item is still in the old vault, which nothing changed; one is also in the new one.
    expect(names(alice.store, old)).toEqual(["bank", "deeds"]);
    expect(alice.shared.logs.verifiedState(old)?.deleteId).toBeNull();
    expect(names(alice.store, s.newVaultId!)).toHaveLength(1);
    expect(alice.store.movePlan(old)?.resume).toMatchObject({ name: "Family 2", newVaultId: s.newVaultId, copied: 1 });

    server.putsBeforeDrop = null;
    const r = await alice.store.moveEverything(old, { name: "ignored on a resume", add: [B, C] });
    expect(r.newVaultId).toBe(s.newVaultId);
    expect(r.name).toBe("Family 2");
    expect(names(alice.store, r.newVaultId)).toEqual(["bank", "deeds"]);
    expect(server.appends.filter((x) => x.startsWith("genesis:"))).toHaveLength(2); // "Family" and the one new vault
    expect(r.oldDeleted).not.toBeNull();
    expect(Object.keys(alice.shared.logs.verifiedState(r.newVaultId)!.members).sort()).toEqual([A, B, C]);
    expect(alice.shared.logs.verifiedState(r.newVaultId)!.members[C]!.role).toBe("reader");
  });

  it("the line that the old vault's deletion went through names the day only where the server served it; otherwise it points to the deleted vaults", async () => {
    for (const served of [true, false]) {
      const { server, alice, old } = await family();
      server.noGraceOnAppend = !served;
      const r = await alice.store.moveEverything(old, { name: "Family 2", add: [B, C] });
      expect(r.oldDeleted).not.toBeNull();
      if (served) {
        expect(r.oldDeleted!.purgeAt).toEqual(expect.any(Number));
        expect(moveResultText(r, "Family")).toContain(fill(MOVE_DONE_NO_DAY, "Family 2", "Family").slice(0, 30));
        expect(moveResultText(r, "Family")).not.toContain(fill(MOVE_DONE_NO_DAY, "Family 2", "Family"));
      } else {
        // On the code before: a day computed from the entry's time and this app's usual grace.
        expect(r.oldDeleted!.purgeAt).toBeNull();
        expect(moveResultText(r, "Family")).toContain(fill(MOVE_DONE_NO_DAY, "Family 2", "Family"));
      }
    }
  });

  it("a member removed after a stopped run never keeps the new key: a fresh vault, and the half-made one goes once the move finished", async () => {
    const { server, alice, bob, old } = await family();
    // The first run adds bob, then stops at carol's add.
    server.refuseAddOf = C;
    const e = await alice.store.moveEverything(old, { name: "Family 2", add: [B, C] }).catch((x: unknown) => x);
    expect(e).toBeInstanceOf(MoveStoppedError);
    const s = e as MoveStoppedError;
    expect(s.stage).toBe("add");
    expect(Object.keys(alice.shared.logs.verifiedState(s.newVaultId!)!.members).sort()).toEqual([A, B]);
    server.refuseAddOf = null;

    // From "Remove" on bob: the panel offers no resume (bob holds the half-made vault's key), and the move starts afresh.
    expect(alice.store.movePlan(old, B)?.resume).toBeNull();
    const r = await alice.store.moveEverything(old, { name: "Family 3", add: [C], removing: B });
    expect(r.newVaultId).not.toBe(s.newVaultId);
    expect(r.name).toBe("Family 3");
    expect(Object.keys(alice.shared.logs.verifiedState(r.newVaultId)!.members).sort()).toEqual([A, C]);
    expect(names(alice.store, r.newVaultId)).toEqual(["bank", "deeds"]);
    expect(r.oldDeleted).not.toBeNull();
    expect(r.discarded).toEqual({ vaultId: s.newVaultId, name: "Family 2", deleted: true });
    // The half-made vault is deleted: bob's grant to it is gone with it, and he reads nothing of either.
    expect(server.grants.get(s.newVaultId!)!.get(B)!.revoked).toBe(true);
    await bob.store.sync();
    expect(bob.account.hasVault(r.newVaultId)).toBe(false);
    expect(names(bob.store, s.newVaultId!)).toEqual([]);
  });

  /** The first run adds bob to "Family 2" and stops at carol's add; bob accepts "Family 2" on his side. */
  async function bobInHalfMade() {
    const f = await family();
    f.server.refuseAddOf = C;
    const s = (await f.alice.store.moveEverything(f.old, { name: "Family 2", add: [B, C] }).catch((x: unknown) => x)) as MoveStoppedError;
    expect(s.stage).toBe("add");
    f.server.refuseAddOf = null;
    await f.bob.store.sync();
    const ask = f.bob.shared.pendingAsks().find((x) => x.vaultId === s.newVaultId);
    expect((await f.bob.shared.answer(ask!, true)).kind).toBe("adopted");
    await f.bob.store.sync();
    expect(names(f.bob.store, s.newVaultId!)).toEqual(["bank", "deeds"]);
    return { ...f, half: s.newVaultId! };
  }

  it("a member the stopped run added saves an item into the half-made vault: the next run does NOT delete it, and the line names it", async () => {
    const { server, alice, bob, old, half } = await bobInHalfMade();
    await bob.store.save(null, { type: "login", name: "bob's own", login: { username: "b", password: "pw" } }, [], undefined, half);
    const r = await alice.store.moveEverything(old, { name: "Family 3", add: [C], removing: B });
    expect(r.oldDeleted).not.toBeNull();
    // On the code before: { deleted: true } and bob's item gone with the vault.
    expect(r.discarded).toEqual({ vaultId: half, name: "Family 2", deleted: false, kept: true, foreign: 1, holders: ["Bob"], copies: 2 });
    expect(server.appends).not.toContain(`delete:${half}`);
    expect(server.grants.get(half)!.get(B)!.revoked).toBe(false);
    await bob.store.sync();
    expect(names(bob.store, half)).toEqual(["bank", "bob's own", "deeds"]);
    expect(alice.store.vaults().find((v) => v.vaultId === half)?.name).toBe("Family 2");
    const line = moveResultText(r, "Family");
    expect(line).toContain(fill(MOVE_DISCARD_KEPT, "Family 2"));
    expect(line).not.toContain(fill(MOVE_DISCARDED, "Family 2"));
  });

  it("a copy changed in the half-made vault since the move made it keeps the vault too", async () => {
    const { server, alice, bob, old, half } = await bobInHalfMade();
    const copy = bob.store.list().find((i) => i.vaultId === half && i.doc.name === "bank")!;
    await bob.store.save(copy.itemId, { ...copy.doc, notes: "changed by bob" }, [], undefined, half);
    const r = await alice.store.moveEverything(old, { name: "Family 3", add: [C], removing: B });
    expect(r.discarded).toEqual({ vaultId: half, name: "Family 2", deleted: false, kept: true, foreign: 1, holders: ["Bob"], copies: 2 });
    expect(server.appends).not.toContain(`delete:${half}`);
  });

  it("a member's own item that lies in the half-made vault's trash keeps the vault: the trash is read too", async () => {
    const { server, alice, bob, old, half } = await bobInHalfMade();
    await bob.store.save(null, { type: "login", name: "bob's own", login: { username: "b", password: "pw" } }, [], undefined, half);
    const own = bob.store.list().find((i) => i.vaultId === half && i.doc.name === "bob's own")!;
    await bob.store.remove(own.itemId);
    expect(server.items.get(own.itemId)?.deleted).toBe(true);
    const r = await alice.store.moveEverything(old, { name: "Family 3", add: [C], removing: B });
    expect(r.oldDeleted).not.toBeNull();
    // On the code before: { deleted: true }, the line "held only copies", and bob's item gone with the vault.
    expect(r.discarded).toEqual({ vaultId: half, name: "Family 2", deleted: false, kept: true, foreign: 1, holders: ["Bob"], copies: 2 });
    expect(server.attempts).not.toContain(`delete:${half}`);
    expect(server.grants.get(half)!.get(B)!.revoked).toBe(false);
    expect(moveResultText(r, "Family")).toContain(fill(MOVE_DISCARD_KEPT, "Family 2"));
    expect(moveResultText(r, "Family")).not.toContain("only copies");
  });

  it("the read that decides is never older than a bell this browser already got: a save announced during the read is read too", async () => {
    const { server, alice, bob, old, half } = await bobInHalfMade();
    // The read of the half-made vault is answered with what the server held when it was asked; bob saves into the vault
    // before that answer arrives, and alice's browser hears the bell for his save first.
    let inDiscard = false;
    const proto = alice.store as unknown as { discardHalfMade: (run: unknown) => Promise<unknown> };
    const real = proto.discardHalfMade.bind(alice.store);
    proto.discardHalfMade = async (run) => {
      inDiscard = true;
      try {
        return await real(run);
      } finally {
        inDiscard = false;
      }
    };
    let held = false;
    server.afterSyncAnswer = async (userId) => {
      if (userId !== A || !inDiscard || held) return;
      held = true;
      await bob.store.save(null, { type: "login", name: "bob's own", login: { username: "b", password: "pw" } }, [], undefined, half);
      alice.store.noteRev(server.rev);
    };
    const r = await alice.store.moveEverything(old, { name: "Family 3", add: [C], removing: B });
    server.afterSyncAnswer = null;
    expect(held).toBe(true);
    // On the code before: { deleted: true }, decided on the answer from before bob's save, and his item gone with it.
    expect(r.discarded).toEqual({ vaultId: half, name: "Family 2", deleted: false, kept: true, foreign: 1, holders: ["Bob"], copies: 2 });
    expect(server.attempts).not.toContain(`delete:${half}`);
    await bob.store.sync();
    expect(names(bob.store, half)).toEqual(["bank", "bob's own", "deeds"]);
  });

  it("a run stopped before a lock is remembered at rest: the next move after the unlock finds the half-made vault, and one that holds a member's own item is named with who can still open it", async () => {
    const { server, alice, bob, old, half } = await bobInHalfMade();
    await bob.store.save(null, { type: "login", name: "bob's own", login: { username: "b", password: "pw" } }, [], undefined, half);
    // A lock (or a reload, or a closed tab): the same profile unlocked again, the session's memory gone.
    alice.store.close();
    const again = await browser(server, alice.person, alice.contacts, undefined, alice.profile);
    const r = await again.store.moveEverything(old, { name: "Family 3", add: [C], removing: B });
    expect(r.oldDeleted).not.toBeNull();
    // On the code before: discarded null, and nothing said of "Family 2", which bob (removed by this very move) still holds.
    expect(r.discarded).toEqual({ vaultId: half, name: "Family 2", deleted: false, kept: true, foreign: 1, holders: ["Bob"], copies: 2 });
    const line = moveResultText(r, "Family");
    expect(line).toContain(fill(MOVE_DISCARD_KEPT, "Family 2"));
    expect(line).toContain(fill(MOVE_DISCARD_HOLDERS, "Bob", "Family 2", "2 items"));
    expect(server.attempts).not.toContain(`delete:${half}`);
    expect(server.grants.get(half)!.get(B)!.revoked).toBe(false);
    // The move finished: its record is gone, and the next move of anything finds nothing of it.
    expect(again.shared.logs.moveRecord(old)).toBeNull();
  });

  it("after a lock, a half-made vault that holds only the copies is deleted before the next run copies anything", async () => {
    const { server, alice, bob, old, half } = await bobInHalfMade();
    alice.store.close();
    const again = await browser(server, alice.person, alice.contacts, undefined, alice.profile);
    const before = server.appends.length;
    const r = await again.store.moveEverything(old, { name: "Family 3", add: [C], removing: B });
    // On the code before: no delete of "Family 2" at all, and bob kept copies of everything.
    expect(r.discarded).toEqual({ vaultId: half, name: "Family 2", deleted: true });
    expect(appendsSince(server, before, { [old]: "old", [half]: "half-made", [r.newVaultId]: "new" })).toEqual(["remove:old", "delete:half-made", "genesis:new", "add:new", "delete:old"]);
    expect(server.grants.get(half)!.get(B)!.revoked).toBe(true);
    await bob.store.sync();
    expect(names(bob.store, half)).toEqual([]);
  });

  /** Alice's second browser: the same account, its own storage, and no record of any run of a move. */
  const secondBrowser = (server: Server, alice: Awaited<ReturnType<typeof family>>["alice"]) =>
    browser(server, alice.person, alice.contacts, undefined, { storage: memoryStorage(), personalVaultId: alice.profile.personalVaultId, personalVk: alice.profile.personalVk });

  it("a move's new vault says in its own sealed meta which vault it is the target of; a reader that does not know the entry reads the name as before", async () => {
    const { server, alice, old, half } = await bobInHalfMade();
    const meta = alice.account.decryptVaultMeta(half, server.metas.get(half)!);
    // On the code before: { name: "Family 2" } only.
    expect(meta).toEqual({ name: "Family 2", [VAULT_META_MOVE_OF]: old });
    expect(alice.account.decryptVaultName(half, server.metas.get(half)!)).toBe("Family 2");
    // A vault made by hand says nothing of the kind.
    const own = await alice.store.createSharedVault("Own");
    expect(alice.account.decryptVaultMeta(own, server.metas.get(own)!)).toEqual({ name: "Own" });
  });

  it("the next move on a browser that never saw the stopped run finds its target by that entry, reads it, and names it with who can still open it", async () => {
    const { server, alice, old, half } = await bobInHalfMade();
    const other = await secondBrowser(server, alice);
    expect(other.shared.logs.moveRecord(old)).toBeNull();
    const r = await other.store.moveEverything(old, { name: "Family 3", add: [C], removing: B });
    expect(r.oldDeleted).not.toBeNull();
    // On the code before: discarded null, and nothing said of "Family 2", which bob (removed by this very move) holds.
    // The copies are not known here: everything in it counts, so it is kept.
    // Not said as "copies" (they are not known to be), and the number is what the read counted.
    expect(r.discarded).toEqual({ vaultId: half, name: "Family 2", deleted: false, kept: true, foreign: 2, holders: ["Bob"], copies: 2, found: true });
    expect(moveResultText(r, "Family")).toContain(fill(MOVE_DISCARD_KEPT, "Family 2"));
    expect(moveResultText(r, "Family")).toContain(fill(MOVE_DISCARD_HOLDERS_FOUND, "Bob", "Family 2", "2 items"));
    expect(server.attempts).not.toContain(`delete:${half}`);
    // The new run's own target says so too, and is not taken for the old one.
    expect(other.account.decryptVaultMeta(r.newVaultId, server.metas.get(r.newVaultId)!)[VAULT_META_MOVE_OF]).toBe(old);
  });

  it("a target found by that entry is counted as the read from the server finds it, not as this browser held it before: an item saved and a row trashed since are in the number, and the line says its trash is counted", async () => {
    const { server, alice, bob, old, half } = await bobInHalfMade();
    const other = await secondBrowser(server, alice);
    expect(names(other.store, half)).toEqual(["bank", "deeds"]);
    // Since this browser last read it: bob saves an item of his own there and puts the copy of "bank" in the trash.
    await bob.store.save(null, { type: "login", name: "bob's own", login: { username: "b", password: "pw" } }, [], undefined, half);
    await bob.store.remove(bob.store.list().find((i) => i.vaultId === half && i.doc.name === "bank")!.itemId);
    const r = await other.store.moveEverything(old, { name: "Family 3", add: [C], removing: B });
    // On the code before: copies 2 (counted from what this browser held before the read), beside the read's own 3.
    expect(r.discarded).toMatchObject({ vaultId: half, kept: true, foreign: 3, copies: 3, found: true, holders: ["Bob"] });
    expect(moveResultText(r, "Family")).toContain(fill(MOVE_DISCARD_HOLDERS_FOUND, "Bob", "Family 2", "3 items"));
    // Where the read fails, no number is said.
    expect(discardText({ vaultId: half, name: "Family 2", deleted: false, unread: true, holders: ["Bob"], found: true }, "Family 3", "Family 2", true)).toContain(fill(MOVE_DISCARD_HOLDERS_FOUND_UNREAD, "Bob", "Family 2"));
  });

  it("the room check before a move counts the new vault's description as it will be sealed, with the entry that names the old vault", async () => {
    const { alice, old } = await family();
    const size = alice.store.moveSize(old, null, "Family 2");
    // On the code before: the name alone, about 48 bytes short.
    expect(size.metaBytes).toBe(sealedBlobLength(new TextEncoder().encode(JSON.stringify({ name: "Family 2", [VAULT_META_MOVE_OF]: old })).length));
    expect(size.metaBytes).toBeGreaterThan(sealedBlobLength(new TextEncoder().encode(JSON.stringify({ name: "Family 2" })).length));
  });

  it("an empty target an earlier run left, found by that entry on a browser that never saw the run, is deleted before the next run makes its own", async () => {
    const { server, alice, old } = await family();
    // The first run makes its vault, and the connection drops at its first copy.
    server.beforeAppend = async (kind) => {
      if (kind === "genesis") server.putsBeforeDrop = 0;
    };
    const s = (await alice.store.moveEverything(old, { name: "Family 2", add: [B] }).catch((x: unknown) => x)) as MoveStoppedError;
    server.beforeAppend = null;
    server.putsBeforeDrop = null;
    expect(s.stage).toBe("copy");
    const half = s.newVaultId!;
    const other = await secondBrowser(server, alice);
    expect(names(other.store, half)).toEqual([]);
    const before = server.appends.length;
    const r = await other.store.moveEverything(old, { name: "Family 3", add: [B] });
    // On the code before: discarded null, and "Family 2" left behind unsaid.
    expect(r.discarded).toEqual({ vaultId: half, name: "Family 2", deleted: true });
    // Carol, left out, keeps the old vault: it stays. The half-made vault goes before the new one is made.
    expect(appendsSince(server, before, { [old]: "old", [half]: "half-made", [r.newVaultId]: "new" })).toEqual(["delete:half-made", "genesis:new", "add:new"]);
  });

  it("a move that removes a member and then stops says that member can still open the half-made vault it could not delete", async () => {
    const { server, alice, bob, old, half } = await bobInHalfMade();
    await bob.store.save(null, { type: "login", name: "bob's own", login: { username: "b", password: "pw" } }, [], undefined, half);
    alice.store.close();
    const again = await browser(server, alice.person, alice.contacts, undefined, alice.profile);
    server.putsBeforeDrop = 1;
    const e = (await again.store.moveEverything(old, { name: "Family 3", add: [C], removing: B }).catch((x: unknown) => x)) as MoveStoppedError;
    server.putsBeforeDrop = null;
    expect(e).toBeInstanceOf(MoveStoppedError);
    expect(e.stage).toBe("copy");
    expect(e.discarded).toEqual({ vaultId: half, name: "Family 2", deleted: false, kept: true, foreign: 1, holders: ["Bob"], copies: 2 });
    const line = moveErrorText(e, "Family");
    expect(line).toContain(fill(MOVE_DISCARD_KEPT, "Family 2"));
    expect(line).toContain(fill(MOVE_DISCARD_HOLDERS, "Bob", "Family 2", "2 items"));
    // The stopped run is itself kept at rest from its new vault on, for the move after the next lock.
    expect(again.shared.logs.moveRecord(old)).toMatchObject({ newVaultId: e.newVaultId, stopped: true, removed: true });
  });

  it("a copy the move made that lies in the half-made vault's trash is the move's own: the vault is still deleted", async () => {
    const { server, alice, bob, old, half } = await bobInHalfMade();
    const copy = bob.store.list().find((i) => i.vaultId === half && i.doc.name === "bank")!;
    await bob.store.remove(copy.itemId);
    const r = await alice.store.moveEverything(old, { name: "Family 3", add: [C], removing: B });
    expect(r.discarded).toEqual({ vaultId: half, name: "Family 2", deleted: true });
    expect(server.appends.filter((a) => a === `delete:${half}`)).toHaveLength(1);
  });

  it("a half-made vault whose trash cannot be read is not read: nothing is deleted, and no line says it held only copies", async () => {
    const { server, alice, old, half } = await bobInHalfMade();
    server.trashReadsFail = true;
    const r = await alice.store.moveEverything(old, { name: "Family 3", add: [C], removing: B });
    // On the code before: { deleted: true } (the trash was never asked).
    expect(r.discarded).toEqual({ vaultId: half, name: "Family 2", deleted: false, unread: true, holders: ["Bob"], copies: 2 });
    expect(server.attempts).not.toContain(`delete:${half}`);
    expect(moveResultText(r, "Family")).toContain(fill(MOVE_DISCARD_UNREAD, "Family 2"));
    server.trashReadsFail = false;
    await alice.store.sync();
    expect(server.appends.filter((a) => a === `delete:${half}`)).toHaveLength(1);
  });

  it("a half-made vault that cannot be read is not deleted, and no line says it held only copies; the next sync reads it and deletes it", async () => {
    const { server, alice, old, half } = await bobInHalfMade();
    // The connection drops right after the removal is stored: the half-made vault is read (before anything is copied)
    // and cannot be, and the run stops at its next step. Its stop names the half-made vault and who can still open it.
    server.beforeAppend = async (kind, vaultId) => {
      if (kind === "remove" && vaultId === old) server.offline = true;
    };
    const e = (await alice.store.moveEverything(old, { name: "Family 3", add: [C], removing: B }).catch((x: unknown) => x)) as MoveStoppedError;
    server.beforeAppend = null;
    expect(e).toBeInstanceOf(MoveStoppedError);
    expect(e.discarded).toEqual({ vaultId: half, name: "Family 2", deleted: false, unread: true, holders: ["Bob"], copies: 2 });
    const line = moveErrorText(e, "Family");
    expect(line).toContain(fill(MOVE_DISCARD_UNREAD, "Family 2"));
    expect(line).toContain(fill(MOVE_DISCARD_HOLDERS, "Bob", "Family 2", "2 items"));
    expect(line).not.toContain("only copies");
    expect(server.appends).not.toContain(`delete:${half}`);
    server.offline = false;
    await alice.store.sync();
    expect(server.appends.filter((a) => a === `delete:${half}`)).toHaveLength(1);
  });

  it("a half-made vault due outside a run that holds an item someone saved there is not deleted: a notice names it", async () => {
    const { server, alice, bob, old, half } = await bobInHalfMade();
    // The next run goes into a fresh vault; the half-made vault cannot be read while it runs (its trash read fails), so
    // it stays due. The run stops at its delete, whose answer is lost and stored later.
    server.noAnswer = { kind: "delete", store: false };
    server.trashReadsFail = true;
    const s = (await alice.store.moveEverything(old, { name: "Family 3", add: [C], removing: B }).catch((x: unknown) => x)) as MoveStoppedError;
    expect([s.stage, s.deleteWaiting, s.discarded?.unread]).toEqual(["delete", true, true]);
    server.noAnswer = null;
    server.trashReadsFail = false;
    await bob.store.save(null, { type: "login", name: "bob's own", login: { username: "b", password: "pw" } }, [], undefined, half);
    // The server stores the held deletion of the old vault whenever it likes, outside any run of the move.
    await serverStoresHeldDelete(server, alice, old);
    await alice.store.sync();
    expect(alice.store.notices().find((x) => x.vaultId === old)?.kind).toBe("move-stored");
    expect(server.appends).not.toContain(`delete:${half}`);
    const n = alice.store.notices().find((x) => x.kind === "half-made-kept");
    expect(n).toMatchObject({ vaultId: half, vaultName: "Family 2" });
    expect(noticeBody(n!).body).toBe(fill(MOVE_DISCARD_KEPT, "Family 2"));
  });

  it("after the removal the move signs first is stored, no stop says the old vault \"wasn't changed\"", async () => {
    for (const [drop, stage, key] of [
      [0, "create", MOVE_STOPPED_START_REMOVED],
      [1, "copy", MOVE_STOPPED_COPY_REMOVED],
    ] as const) {
      const { server, alice, old } = await family();
      server.putsBeforeDrop = drop;
      const e = (await alice.store.moveEverything(old, { name: "Family 2", add: [B], removing: C }).catch((x: unknown) => x)) as MoveStoppedError;
      server.putsBeforeDrop = null;
      expect(e.stage).toBe(stage);
      expect(alice.shared.logs.verifiedState(old)?.members[C], "the removal is stored").toBeUndefined();
      expect(e.oldChanged).toBe(true);
      const line = moveErrorText(e, "Family");
      // On the code before: MOVE_STOPPED_START / MOVE_STOPPED_COPY, "… “Family” wasn't changed."
      expect(line).not.toContain("wasn't changed");
      expect(line.startsWith(stage === "create" ? fill(key, "Family") : fill(key, "1", "2 items", "Family 2", "Family"))).toBe(true);
    }
    // Without a removal the old vault was not changed, and the line says so as before.
    const { server, alice, old } = await family();
    server.putsBeforeDrop = 1;
    const e = (await alice.store.moveEverything(old, { name: "Family 2", add: [B, C] }).catch((x: unknown) => x)) as MoveStoppedError;
    server.putsBeforeDrop = null;
    expect(e.oldChanged).toBe(false);
    expect(moveErrorText(e, "Family")).toContain(fill(MOVE_STOPPED_COPY, "1", "2 items", "Family 2", "Family"));
  });

  it("a removal an earlier run stored: the next run's stop at its opening sync does not say the old vault \"wasn't changed\"", async () => {
    const { server, alice, old } = await family();
    server.putsBeforeDrop = 1;
    const first = (await alice.store.moveEverything(old, { name: "Family 2", add: [B], removing: C }).catch((x: unknown) => x)) as MoveStoppedError;
    server.putsBeforeDrop = null;
    expect([first.stage, first.oldChanged]).toEqual(["copy", true]);
    server.offline = true;
    const e = (await alice.store.moveEverything(old, { name: "Family 2", add: [B], removing: C }).catch((x: unknown) => x)) as MoveStoppedError;
    server.offline = false;
    expect(e.stage).toBe("create");
    // On the code before: oldChanged false and "Nothing was moved, and “Family” wasn't changed."
    expect(e.oldChanged).toBe(true);
    expect(moveErrorText(e, "Family")).not.toContain("wasn't changed");
    expect(moveErrorText(e, "Family").startsWith(fill(MOVE_STOPPED_START_REMOVED, "Family"))).toBe(true);
  });

  it("a removal an earlier run stored: a next run that is not carried on does not say the old vault \"wasn't changed\" either", async () => {
    const { server, alice, old } = await family();
    // Run 1 removes carol (stored), adds bob, and stops at its delete step: the read before the delete fails.
    server.beforeAppend = async (kind, vaultId) => {
      if (kind === "add" && vaultId !== old) server.offline = true;
    };
    const first = (await alice.store.moveEverything(old, { name: "Family 2", add: [B], removing: C }).catch((x: unknown) => x)) as MoveStoppedError;
    server.beforeAppend = null;
    server.offline = false;
    expect([first.stage, first.deleteWaiting, first.oldChanged]).toEqual(["delete", false, true]);
    // Run 2 leaves bob out, so it is not carried on (bob holds the half-made vault's key); it stops while copying.
    server.putsBeforeDrop = 1;
    const e = (await alice.store.moveEverything(old, { name: "Family 3", add: [] }).catch((x: unknown) => x)) as MoveStoppedError;
    server.putsBeforeDrop = null;
    expect(e.stage).toBe("copy");
    expect(e.newVaultId).not.toBe(first.newVaultId);
    // On the code before: "… Everything is still in “Family”, which wasn't changed."
    expect(e.oldChanged).toBe(true);
    expect(moveErrorText(e, "Family")).not.toContain("wasn't changed");
    expect(moveErrorText(e, "Family")).toContain(fill(MOVE_STOPPED_COPY_REMOVED, "1", "2 items", "Family 3", "Family"));
  });

  it("a half-made vault no longer among this account's vaults is not said as \"checked again later\": nothing was deleted, nothing is due", async () => {
    const { server, alice, old, half } = await bobInHalfMade();
    // The half-made vault is deleted by the person themselves before the next run (from another device, or here).
    await alice.store.deleteSharedVault(half);
    expect(alice.account.hasVault(half)).toBe(false);
    const r = await alice.store.moveEverything(old, { name: "Family 3", add: [C], removing: B });
    expect(r.oldDeleted).not.toBeNull();
    // On the code before: { unread: true } and MOVE_DISCARD_UNREAD ("andvari checks it again later"), with nothing due.
    expect(r.discarded).toEqual({ vaultId: half, name: "Family 2", deleted: false, notHeld: true });
    const line = moveResultText(r, "Family");
    expect(line).toContain(fill(MOVE_DISCARD_NOT_HELD, "Family 2"));
    expect(line).not.toContain(fill(MOVE_DISCARD_UNREAD, "Family 2"));
    expect(server.attempts.filter((a) => a === `delete:${half}`)).toHaveLength(1);
  });

  it("the same after a plain remove followed by the move: the run is not carried on while someone in its vault is out of the plan", async () => {
    const { server, alice, old } = await family();
    server.refuseAddOf = C;
    const s = (await alice.store.moveEverything(old, { name: "Family 2", add: [B, C] }).catch((x: unknown) => x)) as MoveStoppedError;
    server.refuseAddOf = null;
    await alice.store.removeVaultMember(old, B);
    const r = await alice.store.moveEverything(old, { name: "Family 3", add: [C] });
    expect(r.newVaultId).not.toBe(s.newVaultId);
    expect(Object.keys(alice.shared.logs.verifiedState(r.newVaultId)!.members).sort()).toEqual([A, C]);
    expect(r.discarded).toEqual({ vaultId: s.newVaultId, name: "Family 2", deleted: true });
    // And with nothing out of the plan, a stopped run is carried on into the same vault (as before).
    const again = await family();
    again.server.refuseAddOf = C;
    const t = (await again.alice.store.moveEverything(again.old, { name: "Family 2", add: [B, C] }).catch((x: unknown) => x)) as MoveStoppedError;
    again.server.refuseAddOf = null;
    const u = await again.alice.store.moveEverything(again.old, { name: "ignored", add: [B, C] });
    expect([u.newVaultId, u.discarded]).toEqual([t.newVaultId, null]);
  });

  it("the half-made vault's deletion whose answer never came is waiting (sent again after the next unlock's read), never 'delete it yourself'", async () => {
    const { server, alice, old } = await family();
    server.refuseAddOf = C;
    const s = (await alice.store.moveEverything(old, { name: "Family 2", add: [B, C] }).catch((x: unknown) => x)) as MoveStoppedError;
    server.refuseAddOf = null;
    await alice.store.removeVaultMember(old, B);
    server.beforeAppend = async (kind, vaultId) => {
      if (kind === "delete" && vaultId === s.newVaultId) throw new ApiError(0, "network", "no answer");
    };
    const r = await alice.store.moveEverything(old, { name: "Family 3", add: [C] });
    server.beforeAppend = null;
    expect(r.oldDeleted).not.toBeNull();
    expect(r.discarded).toEqual({ vaultId: s.newVaultId, name: "Family 2", deleted: false, waiting: true, holders: ["Bob"], copies: 2 });
    expect(alice.shared.logs.holds(s.newVaultId!)).toBe(true);
    // The log store's general re-post leaves it alone: it is never sent unread.
    await alice.shared.logs.retryPending();
    expect(server.attempts).not.toContain(`delete:${s.newVaultId}`);
    // The next unlock reads the vault (nothing but the copies) and only then sends it again: deleted, once.
    const again = await browser(server, alice.person, alice.contacts, undefined, alice.profile);
    expect(server.appends.filter((a) => a === `delete:${s.newVaultId}`)).toHaveLength(1);
    expect(again.shared.logs.holds(s.newVaultId!)).toBe(false);
  });

  /**
   * Bob is in the half-made vault ({@link bobInHalfMade}); the next run removes him and finishes, and the half-made
   * vault's deletion, signed after a read that found only copies, gets no answer (nothing stored): it is held.
   */
  async function halfMadeDeleteHeld() {
    const f = await bobInHalfMade();
    f.server.beforeAppend = async (kind, vaultId) => {
      if (kind === "delete" && vaultId === f.half) throw new ApiError(0, "network", "no answer");
    };
    const r = await f.alice.store.moveEverything(f.old, { name: "Family 3", add: [C], removing: B });
    f.server.beforeAppend = null;
    expect(r.discarded).toEqual({ vaultId: f.half, name: "Family 2", deleted: false, waiting: true, holders: ["Bob"], copies: 2 });
    expect(f.alice.shared.logs.holds(f.half)).toBe(true);
    return f;
  }

  it("the unlock never sends a half-made vault's held deletion unread: bob saved into it meanwhile, so it stays, the deletion is dropped, and a notice names it", async () => {
    const { server, alice, bob, half } = await halfMadeDeleteHeld();
    await bob.store.save(null, { type: "login", name: "bob's own", login: { username: "b", password: "pw" } }, [], undefined, half);
    const again = await browser(server, alice.person, alice.contacts, undefined, alice.profile);
    // On the code before: the unlock re-posted the held deletion byte for byte, and bob's item went with the vault.
    expect(server.attempts).not.toContain(`delete:${half}`);
    expect(server.grants.get(half)!.get(B)!.revoked).toBe(false);
    expect(again.shared.logs.holds(half), "the held deletion is dropped").toBe(false);
    const n = again.store.notices().filter((x) => x.kind === "half-made-kept");
    expect(n).toHaveLength(1);
    expect(n[0]).toMatchObject({ vaultId: half, vaultName: "Family 2" });
    expect(noticeBody(n[0]!).body).toBe(fill(MOVE_DISCARD_KEPT, "Family 2"));
    // Never sent later either: another sync, another unlock.
    await again.store.sync();
    await browser(server, alice.person, alice.contacts, undefined, alice.profile);
    expect(server.attempts).not.toContain(`delete:${half}`);
    await bob.store.sync();
    expect(names(bob.store, half)).toEqual(["bank", "bob's own", "deeds"]);
    expect(again.store.vaults().find((v) => v.vaultId === half)?.name).toBe("Family 2");
  });

  it("a half-made vault's deletion dropped unsent after its answer was lost is remembered: a log that later holds it says the vault was deleted after all, with its restore (a day only where the server served it)", async () => {
    for (const served of [true, false]) {
    const { server, alice, bob, half } = await halfMadeDeleteHeld();
    server.graceOnRead = served;
    const frame = (JSON.parse(alice.profile.storage.get(`andvari.log2.${A}.${half}.pending`)!) as { frame: string }).frame;
    await bob.store.save(null, { type: "login", name: "bob's own", login: { username: "b", password: "pw" } }, [], undefined, half);
    // The unlock reads the vault, keeps it (bob's item), and drops the held deletion unsent.
    const again = await browser(server, alice.person, alice.contacts, undefined, alice.profile);
    expect(again.shared.logs.holds(half)).toBe(false);
    expect(again.store.notices().filter((x) => x.kind === "held-found-made")).toEqual([]);
    // The deletion had reached the server after all (its answer was lost), and the server appends it later.
    await server.wireFor(A).appendLog(half, { entry: frame });
    await again.store.sync();
    // On the code before: nothing was remembered, so nothing was said, and "Family 2" was gone unsaid.
    const n = again.store.notices().filter((x) => x.kind === "held-found-made");
    expect(n).toHaveLength(1);
    expect(n[0]).toMatchObject({ vaultId: half, heldKind: "delete", halfMade: true });
    expect(n[0]!.signedAt).toBeGreaterThan(0);
    if (served) {
      // The server's own day, ten days after the deletion's entry.
      expect(n[0]!.purgeAt).toBe(n[0]!.signedAt! + 10 * 86_400_000);
      expect(noticeBody(n[0]!).body).toBe(fill(RESEND_FOUND_MADE_HALF_MADE_DELETE, n[0]!.vaultName || MOVE_UNNAMED_VAULT, fmtDate(n[0]!.signedAt), fmtDay(n[0]!.purgeAt)));
    } else {
      // No day served: none named, and the line points to the deleted vaults. On the code before: a computed day.
      expect(n[0]!.purgeAt).toBeUndefined();
      expect(noticeBody(n[0]!).body).toBe(fill(RESEND_FOUND_MADE_HALF_MADE_DELETE_NO_DAY, n[0]!.vaultName || MOVE_UNNAMED_VAULT, fmtDate(n[0]!.signedAt)));
    }
    expect(noticeBody(n[0]!).body).not.toContain("withdrew");
    // Said once: the next sync says nothing more of it.
    await again.store.sync();
    expect(again.store.notices().filter((x) => x.kind === "held-found-made")).toHaveLength(1);
    }
  });

  it("where the unlock cannot read the half-made vault, nothing is sent; it is read again at the next sync, and deleted there while it holds only copies", async () => {
    const { server, alice, half } = await halfMadeDeleteHeld();
    // The unlock's first sync is answered; the read of the half-made vault that follows is not.
    server.syncsBeforeOffline = 1;
    const again = await browser(server, alice.person, alice.contacts, undefined, alice.profile);
    expect(server.attempts).not.toContain(`delete:${half}`);
    expect(again.shared.logs.holds(half)).toBe(true);
    expect(again.store.notices().filter((x) => x.kind === "half-made-kept")).toEqual([]);
    server.syncsBeforeOffline = null;
    await again.store.sync();
    expect(server.appends.filter((a) => a === `delete:${half}`)).toHaveLength(1);
    expect(again.shared.logs.holds(half)).toBe(false);
  });

  it("spec 03 §10.3: a member saves into the half-made vault between the read and the deletion: the deletion names its read, the server refuses it, nothing is held, and the vault is read again, kept and named", async () => {
    const { server, alice, bob, old, half } = await bobInHalfMade();
    // Bob's save lands after alice's read of the half-made vault and before her deletion of it reaches the server.
    let saved = false;
    server.beforeAppend = async (kind, vaultId) => {
      if (kind !== "delete" || vaultId !== half || saved) return;
      saved = true;
      await bob.store.save(null, { type: "login", name: "bob's own", login: { username: "b", password: "pw" } }, [], undefined, half);
    };
    const r = await alice.store.moveEverything(old, { name: "Family 3", add: [C], removing: B });
    server.beforeAppend = null;
    expect(saved).toBe(true);
    expect(r.oldDeleted).not.toBeNull();
    // The deletion named the read that decided it (the first `delete` to reach the server: the half-made vault is dealt
    // with before anything is copied), and was refused.
    expect(server.points[0]).toEqual(expect.any(Number));
    expect(server.attempts.filter((a) => a === `delete:${half}`)).toHaveLength(1);
    // On the code before: the deletion named no read, the server stored it, and bob's item went with the vault.
    expect(server.appends).not.toContain(`delete:${half}`);
    expect(r.discarded).toEqual({ vaultId: half, name: "Family 2", deleted: false, kept: true, foreign: 1, holders: ["Bob"], copies: 2 });
    expect(alice.shared.logs.holds(half), "nothing is held of the refused deletion").toBe(false);
    expect(server.grants.get(half)!.get(B)!.revoked).toBe(false);
    await bob.store.sync();
    expect(names(bob.store, half)).toEqual(["bank", "bob's own", "deeds"]);
    const line = moveResultText(r, "Family");
    expect(line).toContain(fill(MOVE_DISCARD_KEPT, "Family 2"));
    expect(line).not.toContain(fill(MOVE_DISCARDED, "Family 2"));
    // Never sent later either.
    await alice.store.sync();
    expect(server.attempts.filter((a) => a === `delete:${half}`)).toHaveLength(1);
  });

  it("spec 03 §10.3: a held deletion of a half-made vault is sent again with the point of the read just made, and a save after that read refuses it: kept, nothing held, a notice names it", async () => {
    const { server, alice, bob, half } = await halfMadeDeleteHeld();
    const kept = JSON.parse(alice.profile.storage.get(`andvari.log2.${A}.${half}.pending`)!) as { itemsAtMost?: number };
    // The held record keeps the point of the read that signed it.
    expect(kept.itemsAtMost).toEqual(expect.any(Number));
    server.points = [];
    // Something changes elsewhere meanwhile, so the next read is at a newer position.
    await bob.store.save(null, { type: "login", name: "bob's personal", login: { username: "b", password: "pw" } });
    let saved = false;
    server.beforeAppend = async (kind, vaultId) => {
      if (kind !== "delete" || vaultId !== half || saved) return;
      saved = true;
      await bob.store.save(null, { type: "login", name: "bob's own", login: { username: "b", password: "pw" } }, [], undefined, half);
    };
    const again = await browser(server, alice.person, alice.contacts, undefined, alice.profile);
    server.beforeAppend = null;
    expect(saved).toBe(true);
    // The re-post carried the newer read's point, not the one it kept; on the code before it carried none, and the
    // server stored it with bob's item in the vault.
    expect(server.points).toHaveLength(1);
    expect(server.points[0]!).toBeGreaterThan(kept.itemsAtMost!);
    expect(server.appends).not.toContain(`delete:${half}`);
    expect(again.shared.logs.holds(half)).toBe(false);
    const n = again.store.notices().filter((x) => x.kind === "half-made-kept");
    expect(n).toHaveLength(1);
    expect(n[0]).toMatchObject({ vaultId: half, vaultName: "Family 2" });
    await bob.store.sync();
    expect(names(bob.store, half)).toEqual(["bank", "bob's own", "deeds"]);
  });

  it("spec 03 §10.3: refused at every read (a row saved and purged between each read and its deletion): three reads, nothing deleted, nothing held, and the next sync reads it again and deletes it", async () => {
    const { server, alice, old, half } = await bobInHalfMade();
    let refusedFor = 0;
    let row: string | null = null;
    server.beforeAppend = async (kind, vaultId) => {
      if (kind !== "delete" || vaultId !== half) return;
      // A member's row lands in the vault's trash just before the deletion's check, newer than the read...
      refusedFor++;
      row = crypto.randomUUID();
      const rev = ++server.rev;
      server.items.set(row, { itemId: row, vaultId: half, rev, createdAt: 0, updatedAt: rev, deleted: true, conflict: false, formatVersion: 1, attachmentIds: [], blob: "" });
    };
    // ...and is purged before the next read, which then finds nothing but the copies again.
    server.beforeSync = () => {
      if (row !== null) server.items.delete(row);
      row = null;
    };
    const r = await alice.store.moveEverything(old, { name: "Family 3", add: [C], removing: B });
    server.beforeAppend = null;
    server.beforeSync = null;
    // The member purges the last row too.
    if (row !== null) server.items.delete(row);
    // Each dealing with it (before the copies, then at each of the run's own syncs, where it is due again) ends after
    // three reads: a whole number of rounds of three, never a loop without end.
    expect(refusedFor).toBeGreaterThanOrEqual(3);
    expect(refusedFor % 3).toBe(0);
    expect(r.oldDeleted).not.toBeNull();
    expect(r.discarded).toEqual({ vaultId: half, name: "Family 2", deleted: false, unread: true, holders: ["Bob"], copies: 2 });
    expect(server.appends).not.toContain(`delete:${half}`);
    expect(alice.shared.logs.holds(half)).toBe(false);
    await alice.store.sync();
    expect(server.appends.filter((a) => a === `delete:${half}`)).toHaveLength(1);
  });

  it("a plain held deletion of a vault known to be half-made (one held from before the deletion was marked) is not sent by the unlock's re-post either", async () => {
    const { server, alice, half } = await halfMadeDeleteHeld();
    // The held record as an earlier version kept it: no mark.
    const key = [...alice.profile.storage.map.keys()].find((k) => k.endsWith(`.${half}.pending`))!;
    const rec = JSON.parse(alice.profile.storage.map.get(key)!) as Record<string, unknown>;
    expect(rec.halfMade).toBeDefined();
    delete rec.halfMade;
    alice.profile.storage.set(key, JSON.stringify(rec));
    expect(alice.shared.logs.heldHalfMadeDeletes()).toEqual([]);
    expect(await alice.shared.logs.resendPending(new Set([half]))).toEqual([]);
    expect(server.attempts).not.toContain(`delete:${half}`);
  });

  it("a move's own steps say what is known of a held change: the removal and the addition carry it", async () => {
    const lostRemove = await family();
    lostRemove.server.loseRemoveOf = B;
    const e1 = (await lostRemove.alice.store.moveEverything(lostRemove.old, { name: "Family 2", add: [C], removing: B }).catch((x: unknown) => x)) as MoveStoppedError;
    expect(e1.stage).toBe("remove");
    expect(e1.cause).toBeInstanceOf(ChangeNotStoredError);
    expect((e1.cause as ChangeNotStoredError).known).toBe("unknown");
    const lostAdd = await family();
    lostAdd.server.loseAddOf = C;
    const e2 = (await lostAdd.alice.store.moveEverything(lostAdd.old, { name: "Family 2", add: [B, C] }).catch((x: unknown) => x)) as MoveStoppedError;
    expect(e2.stage).toBe("add");
    expect(e2.cause).toBeInstanceOf(ChangeNotStoredError);
    expect([(e2.cause as ChangeNotStoredError).action, (e2.cause as ChangeNotStoredError).known]).toEqual(["add", "unknown"]);
  });

  it("an item changed in the old vault after its copy keeps the old vault, \"changed meanwhile\"", async () => {
    const { server, alice, bob, old } = await family();
    const bank = bob.store.list().find((i) => i.vaultId === old && i.doc.name === "bank")!;
    // While alice adds the members (after every item was copied), bob changes the bank login in the old vault.
    let changedOnce = false;
    server.beforeAppend = async (kind, vaultId) => {
      if (kind !== "add" || vaultId === old || changedOnce) return;
      changedOnce = true;
      await bob.store.save(bank.itemId, { ...bank.doc, login: { username: "a", password: "pw2" } }, [], undefined, old);
    };
    const r = await alice.store.moveEverything(old, { name: "Family 2", add: [B, C] });
    expect(changedOnce).toBe(true);
    expect(r.oldDeleted).toBeNull();
    expect([r.oldKept, r.changed]).toEqual(["changed_meanwhile", 1]);
    expect(alice.shared.logs.verifiedState(old)?.deleteId).toBeNull();
    expect(alice.store.list().find((i) => i.vaultId === old && i.doc.name === "bank")!.doc.login?.password).toBe("pw2");
  });

  it("spec 03 §10.3: a member saves into the old vault between the move's last read and its deletion: the deletion names that read, the server refuses it, nothing is held, the old vault stays \"changed meanwhile\", and moving again carries the late item", async () => {
    const { server, alice, bob, old } = await family();
    // Bob's save lands after alice's last read of the old vault (her checks passed) and before her deletion reaches the server.
    let saved = false;
    server.beforeAppend = async (kind, vaultId) => {
      if (kind !== "delete" || vaultId !== old || saved) return;
      saved = true;
      await bob.store.save(null, { type: "login", name: "late", login: { username: "b", password: "pw" } }, [], undefined, old);
    };
    server.points = [];
    const r = await alice.store.moveEverything(old, { name: "Family 2", add: [B, C] });
    server.beforeAppend = null;
    expect(saved).toBe(true);
    // The deletion named the read the checks rest on, and was refused once; on the code before it named no read, the
    // server stored it, and bob's item went into the old vault's grace with it.
    expect(server.points).toEqual([expect.any(Number)]);
    expect(server.attempts.filter((a) => a === `delete:${old}`)).toHaveLength(1);
    expect(server.appends).not.toContain(`delete:${old}`);
    // Nothing is held, the old vault stays, and the result says it changed meanwhile (the move's own read saw no change).
    expect([r.oldDeleted, r.oldKept, r.changed]).toEqual([null, "changed_meanwhile", 0]);
    expect(alice.shared.logs.holds(old)).toBe(false);
    expect(alice.shared.logs.verifiedState(old)?.deleteId).toBeNull();
    expect(alice.store.moveDeleteWaiting(old)).toBe(false);
    expect(alice.store.unfinishedMoves()).toEqual([]);
    const line = moveResultText(r, "Family");
    expect(line).toContain(fill(MOVE_CHANGED_AFTER_READ, "", "Family"));
    expect(line).not.toContain(fill(MOVE_CHANGED_MEANWHILE, "0 items", "Family"));
    // Never sent again by itself.
    await alice.store.sync();
    expect(server.attempts.filter((a) => a === `delete:${old}`)).toHaveLength(1);
    expect(names(alice.store, old)).toEqual(["bank", "deeds", "late"]);
    // Moving again carries what is late, and only then is the old vault deleted.
    const again = await alice.store.moveEverything(old, { name: "Family 3", add: [B, C] });
    expect(again.oldDeleted).not.toBeNull();
    expect(names(alice.store, again.newVaultId)).toEqual(["bank", "deeds", "late"]);
    expect(server.appends.filter((a) => a === `delete:${old}`)).toHaveLength(1);
  });

  it("spec 03 §10.3: the move's held deletion of the old vault is sent again with the point of the newer read, and a save after that read refuses it: nothing held, the old vault stays \"changed meanwhile\"", async () => {
    const { server, alice, bob, old } = await family();
    server.noAnswer = { kind: "delete", store: false };
    const e = await alice.store.moveEverything(old, { name: "Family 2", add: [B, C] }).catch((x: unknown) => x);
    expect((e as MoveStoppedError).stage).toBe("delete");
    expect(alice.shared.logs.holds(old)).toBe(true);
    server.noAnswer = null;
    const kept = JSON.parse(alice.profile.storage.get(`andvari.log2.${A}.${old}.pending`)!) as { itemsAtMost?: number };
    // The held record keeps the point of the read that signed it.
    expect(kept.itemsAtMost).toEqual(expect.any(Number));
    // Something changes elsewhere meanwhile, so the next run's read is at a newer position.
    await bob.store.save(null, { type: "login", name: "bob's personal", login: { username: "b", password: "pw" } });
    let saved = false;
    server.beforeAppend = async (kind, vaultId) => {
      if (kind !== "delete" || vaultId !== old || saved) return;
      saved = true;
      await bob.store.save(null, { type: "login", name: "late", login: { username: "b", password: "pw" } }, [], undefined, old);
    };
    server.points = [];
    const r = await alice.store.moveEverything(old, { name: "ignored", add: [B, C] });
    server.beforeAppend = null;
    expect(saved).toBe(true);
    // The re-post named the newer read, not the one it kept; on the code before the move's deletion named no read at
    // all, and the server stored it with bob's late item in the old vault.
    expect(server.points).toHaveLength(1);
    expect(server.points[0]!).toBeGreaterThan(kept.itemsAtMost!);
    expect(server.appends).not.toContain(`delete:${old}`);
    expect([r.oldDeleted, r.oldKept, r.changed]).toEqual([null, "changed_meanwhile", 0]);
    expect(alice.shared.logs.holds(old)).toBe(false);
    expect(alice.store.moveDeleteWaiting(old)).toBe(false);
    expect(alice.store.unfinishedMoves()).toEqual([]);
    expect(moveResultText(r, "Family")).toContain(fill(MOVE_CHANGED_AFTER_READ, "", "Family"));
    await alice.store.sync();
    expect(server.attempts.filter((a) => a === `delete:${old}`)).toHaveLength(2);
    expect(names(alice.store, old)).toEqual(["bank", "deeds", "late"]);
  });

  it("an add the server never stored stops the move at \"add\"; the old vault stays, and the next run adds them", async () => {
    const { server, alice, old } = await family();
    server.loseAddOf = C;
    const e = await alice.store.moveEverything(old, { name: "Family 2", add: [B, C] }).catch((x: unknown) => x);
    expect(e).toBeInstanceOf(MoveStoppedError);
    const s = e as MoveStoppedError;
    expect(s.stage).toBe("add");
    expect(alice.shared.logs.verifiedState(old)?.deleteId).toBeNull();
    expect([...server.grants.get(s.newVaultId!)!.keys()].sort()).toEqual([A, B]);
    // Lost again on the next run: still a stop, never "added".
    expect(((await alice.store.moveEverything(old, { name: "x", add: [B, C] }).catch((x: unknown) => x)) as MoveStoppedError).stage).toBe("add");
    server.loseAddOf = null;
    const r = await alice.store.moveEverything(old, { name: "x", add: [B, C] });
    expect(r.newVaultId).toBe(s.newVaultId);
    expect([r.oldDeleted !== null, r.notAdded]).toEqual([true, []]);
    expect(Object.keys(alice.shared.logs.verifiedState(r.newVaultId)!.members).sort()).toEqual([A, B, C]);
  });

  it("the third check's stray sender: finishing a stopped move re-posts only the move's own entries for its new vault, never the person's own held deletion of it", async () => {
    const { server, alice, old } = await family();
    // Stopped by a dropped connection part-way through the copy: nothing of the move is held for the new vault.
    server.putsBeforeDrop = 1;
    const s = (await alice.store.moveEverything(old, { name: "Family 2", add: [B, C] }).catch((x: unknown) => x)) as MoveStoppedError;
    server.putsBeforeDrop = null;
    expect(s).toBeInstanceOf(MoveStoppedError);
    const target = s.newVaultId!;
    expect(alice.shared.logs.holds(target)).toBe(false);
    // The person deletes the stopped move's new vault from its own panel, and the answer is lost (nothing stored).
    server.noAnswer = { kind: "delete", store: false };
    expect(await alice.store.deleteSharedVault(target).then(() => "deleted", (e: unknown) => e)).toBeInstanceOf(ChangeNotStoredError);
    server.noAnswer = null;
    expect(alice.store.heldChangeFor(target)?.kind).toBe("delete");
    const tries = () => server.attempts.filter((a) => a === `delete:${target}`).length;
    expect(tries()).toBe(1);
    // "Finish" on the unfinished move. On the code before: the deletion was sent by the move, not at the person's word.
    await alice.store.moveEverything(old, { name: "Family 2", add: [B, C] }).catch((x: unknown) => x);
    expect(tries()).toBe(1);
    expect(server.appends.filter((a) => a === `delete:${target}`)).toEqual([]);
    expect(alice.store.heldChangeFor(target)?.kind).toBe("delete");
  });

  it("the additions a move makes are the move's own: one held after a stop is shown as waiting but not withdrawn by itself", async () => {
    const { server, alice, old } = await family();
    server.slowDown = "add";
    const s = (await alice.store.moveEverything(old, { name: "Family 2", add: [B, C] }).catch((x: unknown) => x)) as MoveStoppedError;
    server.slowDown = null;
    expect(s.stage).toBe("add");
    const held = alice.store.heldChangeFor(s.newVaultId!);
    // On the code before: withdrawable (known not stored); now not, as the move's own step.
    expect(held).toMatchObject({ kind: "add", known: "not_stored", withdrawable: false });
    expect(alice.store.withdrawHeldChange(s.newVaultId!)).toBe(false);
    expect(alice.shared.logs.holds(s.newVaultId!)).toBe(true);
    // A removal the person makes outside a move, held the same way, can be withdrawn.
    server.beforeAppend = async (kind) => {
      if (kind === "remove") throw new ApiError(0, "network", "no answer");
    };
    await alice.store.removeVaultMember(old, C).catch(() => null);
    server.beforeAppend = null;
    expect(alice.store.heldChangeFor(old)).toMatchObject({ kind: "remove", known: "unknown", withdrawable: true });
  });

  it("the remove the dialog was opened for, when the server never stored it, stops the move before anything is made", async () => {
    const { server, alice, old } = await family();
    server.loseRemoveOf = C;
    const e = await alice.store.moveEverything(old, { name: "Family 2", add: [B], removing: C }).catch((x: unknown) => x);
    expect(e).toBeInstanceOf(MoveStoppedError);
    expect([(e as MoveStoppedError).stage, (e as MoveStoppedError).newVaultId]).toEqual(["remove", null]);
    expect(server.appends.filter((x) => x.startsWith("genesis:"))).toHaveLength(1); // "Family" only
    expect(alice.shared.logs.verifiedState(old)?.deleteId).toBeNull();
  });

  it("the old vault's delete gets no answer: the move stops at its delete step, the old vault still exists, and the panel says moving again finishes it", async () => {
    const { server, alice, old } = await family();
    server.noAnswer = { kind: "delete", store: false };
    const e = await alice.store.moveEverything(old, { name: "Family 2", add: [B, C] }).catch((x: unknown) => x);
    expect(e).toBeInstanceOf(MoveStoppedError);
    const s = e as MoveStoppedError;
    expect([s.stage, s.cause instanceof ChangeNotStoredError]).toEqual(["delete", true]);
    // Not deleted: still listed, its log has no delete, its items are there, and the frame is held for re-posting.
    expect(alice.store.vaults().some((v) => v.vaultId === old)).toBe(true);
    expect(alice.shared.logs.verifiedState(old)?.deleteId).toBeNull();
    expect(names(alice.store, old)).toEqual(["bank", "deeds"]);
    expect(alice.shared.logs.holds(old)).toBe(true);
    // Signed and waiting, and it cannot be taken back: never "kept", never "deleted".
    const said = moveErrorText(e, "Family");
    expect(said).toBe(fill(MOVE_STOPPED_DELETE_HELD, "2", "2 items", "Family 2", "Family"));
    expect(said).toContain("signed and waiting for the server");
    expect(said).toContain("can't be taken back");
    expect(said).not.toMatch(/\bkept\b|\bdeleted\b/);
    expect(alice.store.movePlan(old)?.resume).toMatchObject({ name: "Family 2", newVaultId: s.newVaultId, copied: 2 });
    // The old vault's panel says the same; the first screen lists the move as unfinished.
    expect(alice.store.moveDeleteWaiting(old)).toBe(true);
    expect(alice.store.unfinishedMoves()).toEqual([{ vaultId: old, name: "Family", newVaultId: s.newVaultId, newName: "Family 2", added: [B, C] }]);
    // While it waits, this device signs nothing else on that vault's log.
    expect(await alice.shared.logs.append(old, { kind: "role", member: B, role: "reader" })).toEqual({ kind: "not_allowed", reason: "move_delete_waiting" });

    // The next run finishes it: the same new vault, the held delete re-posted byte for byte (no second delete signed).
    server.noAnswer = null;
    const r = await alice.store.moveEverything(old, { name: "ignored", add: [B, C] });
    expect([r.newVaultId, r.name, r.oldKept, r.discarded]).toEqual([s.newVaultId, "Family 2", null, null]);
    expect(r.oldDeleted?.purgeAt).toBeGreaterThan(Date.now());
    expect(alice.shared.logs.verifiedState(old)?.deleteId).not.toBeNull();
    expect(alice.shared.logs.holds(old)).toBe(false);
    expect(alice.store.vaults().some((v) => v.vaultId === old)).toBe(false);
    expect(server.appends.filter((x) => x === `delete:${old}`)).toHaveLength(1);
    expect(server.attempts.filter((x) => x === `delete:${old}`)).toHaveLength(2);
    expect(server.appends.filter((x) => x.startsWith("genesis:"))).toHaveLength(2);
    expect(alice.store.unfinishedMoves()).toEqual([]);
    expect(alice.shared.logs.moveRecord(old)).toBeNull();
  });

  it("it came late (the server stored the delete, its answer was lost with the connection): never shown as done, never as \"deleted by its owner\", and the next run finds it stored without sending it again", async () => {
    const { server, alice, old } = await family();
    server.noAnswer = { kind: "delete", store: true, offline: true };
    const e = await alice.store.moveEverything(old, { name: "Family 2", add: [B, C] }).catch((x: unknown) => x);
    expect(e).toBeInstanceOf(MoveStoppedError);
    expect((e as MoveStoppedError).stage).toBe("delete");
    // The connection is back: the pull finds the old vault deleted. It is this account's own delete: no banner, nothing
    // held as "deleted by its owner".
    server.noAnswer = null;
    server.offline = false;
    await alice.store.sync();
    // Design §3.13 as decided on 2026-11-17: a move's delete stored outside a run of the move is never quiet. The copy
    // is held (as this account's own deletion, never "deleted by its owner"), and the notice says nothing was left out.
    const notes = alice.store.notices().filter((n) => n.vaultId === old);
    expect(notes.map((n) => [n.kind, n.lateAdded, n.lateChanged, n.newVaultName])).toEqual([["move-stored", 0, 0, "Family 2"]]);
    expect(noticeBody(notes[0]!).body).toBe(`${fill(MOVE_DELETED_OUTSIDE, "Family", "Family 2")} ${fill(MOVE_STORED_NOTHING_LATE, "Family 2")} ${MOVE_STORED_UNSEEN}`);
    expect(alice.store.heldVaults().find((h) => h.vaultId === old)).toMatchObject({ byMe: true, verified: true, itemCount: 2 });
    expect(alice.store.vaults().some((v) => v.vaultId === old)).toBe(false);
    // The held frame can never be posted again: the move is not listed as unfinished, and nothing more is sent.
    expect(alice.shared.logs.holds(old)).toBe(false);
    expect(alice.store.unfinishedMoves()).toEqual([]);
    expect(alice.store.moveLate(old)).toBeNull();
    await alice.store.sync();
    expect(server.attempts.filter((x) => x === `delete:${old}`)).toHaveLength(1);
    expect(alice.store.movePlan(old)).toBeNull();
  });

  it("while the move's deletion waits, no road signs anything else on the old vault's log or puts anything into it; the move's own run still finishes", async () => {
    const { server, alice, old, target } = await stoppedWithDeleteHeld();
    const D = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
    const sent = (): string => JSON.stringify([server.attempts, server.appends, [...server.items.values()].map((i) => [i.itemId, i.vaultId, i.rev, i.deleted])]);
    const before = sent();
    const refused = async (road: string, run: () => Promise<unknown>): Promise<void> => {
      const e = await run().then(() => "made", (x: unknown) => x);
      expect(e, road).toBeInstanceOf(MoveWaitingError);
      expect(saveErrorText(e, true), road).toBe(MOVE_WAITING_REFUSED);
      expect(sent(), `${road} sent nothing`).toBe(before);
    };
    // The members' panel, an ownership offer, a rename, a role change, the vault's own delete.
    await refused("add a member", () => alice.store.addVaultMember(old, D, "writer"));
    await refused("change a role", () => alice.store.setMemberRole(old, B, "reader"));
    await refused("remove a member", () => alice.store.removeVaultMember(old, C));
    await refused("offer ownership", () => alice.store.offerTransfer(old, B));
    await refused("cancel an offer", () => alice.store.cancelTransfer(old));
    await refused("delete the vault", () => alice.store.deleteSharedVault(old));
    await refused("rename", () => alice.store.renameVault(old, "Renamed"));
    // Any caller of the log's own code (an answer to a share, anything that runs by itself) is refused there too.
    for (const action of [{ kind: "leave" }, { kind: "offer", to: B, expiresInMs: 86_400_000 }, { kind: "add", contactUserId: B, role: "reader", releaseUncompared: true }] as const) {
      expect(await alice.shared.logs.append(old, action), action.kind).toEqual({ kind: "not_allowed", reason: "move_delete_waiting" });
    }
    expect(logActionText(new LogActionError({ kind: "not_allowed", reason: "move_delete_waiting" }))).toBe(MOVE_WAITING_REFUSED);
    // The unlock's re-posting of held changes leaves the move's delete alone.
    await alice.shared.logs.retryPending();
    expect(sent()).toBe(before);
    // Items: nothing new, no change, no delete, no restore, no import, nothing moved in or out. A copy out is allowed.
    const bank = alice.store.list().find((i) => i.vaultId === old && i.doc.name === "bank")!;
    expect(alice.account.canSealUnder(old), "nothing is sealed under its key").toBe(false);
    await refused("a new item", () => alice.store.save(null, { type: "note", name: "new", notes: "n" }, [], undefined, old));
    await refused("an edit", () => alice.store.save(bank.itemId, { ...bank.doc, name: "bank 2" }, [], undefined, old));
    await refused("an item deleted", () => alice.store.remove(bank.itemId));
    await refused("an item restored", () => alice.store.restoreDeleted(bank.itemId, old, bank.doc));
    await refused("an import", () => alice.store.importDocs([{ itemId: crypto.randomUUID(), doc: { type: "note", name: "imp", notes: "" } }], undefined, old));
    await alice.store.save(null, { type: "note", name: "mine", notes: "n" }, [], undefined, alice.account.personalVaultId);
    const mine = alice.store.list().find((i) => i.doc.name === "mine")!;
    const now = sent();
    const intoOld = await alice.store.runGesture(alice.store.newMoveGesture(mine.itemId, old, true)).then(() => "made", (x: unknown) => x);
    expect(intoOld).toBeInstanceOf(MoveWaitingError);
    const outOfOld = await alice.store.runGesture(alice.store.newMoveGesture(bank.itemId, alice.account.personalVaultId, true)).then(() => "made", (x: unknown) => x);
    expect(outOfOld).toBeInstanceOf(MoveWaitingError);
    expect(sent()).toBe(now);
    await alice.store.runGesture(alice.store.newMoveGesture(bank.itemId, alice.account.personalVaultId, false));
    expect(alice.store.list().filter((i) => i.vaultId === old).map((i) => i.doc.name).sort()).toEqual(["bank", "deeds"]);
    // Only the move's own finishing run re-posts the held delete, byte for byte.
    const appendsBefore = server.appends.length;
    const r = await alice.store.moveEverything(old, { name: "ignored", add: [B, C] });
    expect(r.oldDeleted).not.toBeNull();
    expect(appendsSince(server, appendsBefore, { [old]: "old", [target]: "new" })).toEqual(["delete:old"]);
    expect(alice.account.canSealUnder(old)).toBe(false);
  });

  it("the web has no road that releases a share from a link: no source outside the tests signs an add without compared codes", () => {
    const root = fileURLToPath(new URL("..", import.meta.url));
    const files = (readdirSync(root, { recursive: true }) as string[]).filter((f) => /\.(ts|tsx)$/.test(f) && !/\.test\.|testkit|journeys/.test(f));
    const hits = files.filter((f) => readFileSync(`${root}/${f}`, "utf8").includes("releaseUncompared: true"));
    expect(hits).toEqual([]);
    expect(readFileSync(`${root}/vault/contactbook.ts`, "utf8")).toContain("The web never processes or answers a link and is never linked");
  });

  /** The server stores the move's held delete of [old] whenever it likes (it kept the signed frame), here and now. */
  const serverStoresHeldDelete = async (server: Server, alice: Awaited<ReturnType<typeof family>>["alice"], old: string): Promise<void> => {
    const frame = (JSON.parse(alice.profile.storage.get(`andvari.log2.${A}.${old}.pending`)!) as { frame: string }).frame;
    await server.wireFor(A).appendLog(old, { entry: frame });
  };

  it("the delete is lost, an item is added to the old vault, the server stores the delete later: the person is told, the count is right, and the copy lands in the new vault once", async () => {
    const { server, alice, bob, old, target } = await stoppedWithDeleteHeld();
    await bob.store.sync();
    await bob.store.save(null, { type: "note", name: "late", notes: "added after the copies" }, [], undefined, old);
    await alice.store.sync(); // alice's browser receives the late item
    await serverStoresHeldDelete(server, alice, old);
    await alice.store.sync();
    const n = alice.store.notices().find((x) => x.vaultId === old);
    expect([n?.kind, n?.lateAdded, n?.lateChanged, n?.newVaultId]).toEqual(["move-stored", 1, 0, target]);
    expect(noticeBody(n!).body).toBe(`${fill(MOVE_DELETED_OUTSIDE, "Family", "Family 2")} ${fill(MOVE_STORED_LATE, "1 item", "1", "0", "Family 2")} ${MOVE_STORED_UNSEEN}`);
    expect(alice.store.heldVaults().find((h) => h.vaultId === old)).toMatchObject({ byMe: true, itemCount: 3 });
    expect(alice.store.moveLate(old)).toEqual({ newVaultId: target, added: 1, changed: 0 });
    // The offer: copied from the held copy into the new vault, once.
    const r = await alice.store.copyLateIntoMove(old);
    expect(r).toEqual({ copied: 1, attachmentsLeftOut: 0, unreadable: 0 });
    expect(names(alice.store, target)).toEqual(["bank", "deeds", "late"]);
    expect([...server.items.values()].filter((it) => it.vaultId === target && !it.deleted)).toHaveLength(3);
    expect(alice.store.moveLate(old)).toBeNull();
    await expect(alice.store.copyLateIntoMove(old)).rejects.toBeInstanceOf(HeldKeyGoneError);
    expect([...server.items.values()].filter((it) => it.vaultId === target && !it.deleted)).toHaveLength(3);
    // The offer under the notice is gone once nothing is late.
    expect(renderToStaticMarkup(createElement(MoveLateCopy, { notice: n!, store: alice.store }))).toBe("");
  });

  it("an item changed after its copy, then the delete stored later: the changed item replaces its own copy in the new vault", async () => {
    const { server, alice, bob, old, target } = await stoppedWithDeleteHeld();
    const copyIds = new Set(alice.store.list().filter((i) => i.vaultId === target).map((i) => i.itemId));
    await bob.store.sync();
    const bank = bob.store.list().find((i) => i.vaultId === old && i.doc.name === "bank")!;
    await bob.store.save(bank.itemId, { ...bank.doc, login: { username: "a", password: "pw2" } }, [], undefined, old);
    await alice.store.sync();
    await serverStoresHeldDelete(server, alice, old);
    await alice.store.sync();
    const n = alice.store.notices().find((x) => x.vaultId === old)!;
    expect([n.lateAdded, n.lateChanged]).toEqual([0, 1]);
    const html = renderToStaticMarkup(createElement(MoveLateCopy, { notice: n, store: alice.store }));
    expect(html).toContain(fill(MOVE_STORED_COPY, "Family 2"));
    expect((await alice.store.copyLateIntoMove(old)).copied).toBe(1);
    const inNew = alice.store.list().filter((i) => i.vaultId === target);
    expect(new Set(inNew.map((i) => i.itemId))).toEqual(copyIds);
    expect(inNew.find((i) => i.doc.name === "bank")!.doc.login?.password).toBe("pw2");
    expect([...server.items.values()].filter((it) => it.vaultId === target && !it.deleted)).toHaveLength(2);
  });

  it("what another member added that this browser never received is not counted, and the sentence says it can't be saved here", async () => {
    const { server, alice, bob, old } = await stoppedWithDeleteHeld();
    await bob.store.sync();
    await bob.store.save(null, { type: "note", name: "unseen", notes: "alice never got this" }, [], undefined, old);
    await serverStoresHeldDelete(server, alice, old); // before alice's browser pulled the item
    await alice.store.sync();
    const n = alice.store.notices().find((x) => x.vaultId === old)!;
    expect([n.kind, n.lateAdded, n.lateChanged]).toEqual(["move-stored", 0, 0]);
    expect(noticeBody(n).body.endsWith(MOVE_STORED_UNSEEN)).toBe(true);
  });

  it("the shared code's rule of 2026-11-17: an item in the trash of a vault whose move's deletion waits is not deleted for good either", async () => {
    const { server, alice, bob, old } = await stoppedWithDeleteHeld();
    // Bob (whose browser holds no move) deletes the bank login into the trash; alice's browser lists it there.
    await bob.store.sync();
    const bank = bob.store.list().find((i) => i.vaultId === old && i.doc.name === "bank")!;
    await bob.store.remove(bank.itemId);
    await alice.store.sync();
    expect((await alice.store.deletedItems()).map((d) => [d.itemId, d.vaultId])).toEqual([[bank.itemId, old]]);
    const before = JSON.stringify(server.attempts);
    for (const named of [old, alice.account.personalVaultId]) {
      // Refused for the vault the caller names, and for the vault the trash listed it in, whatever the caller names.
      const e = await alice.store.purgeDeleted(bank.itemId, named).then(() => "purged", (x: unknown) => x);
      expect(e).toBeInstanceOf(MoveWaitingError);
      expect(saveErrorText(e, true)).toBe(MOVE_WAITING_REFUSED);
    }
    expect(JSON.stringify(server.attempts), "nothing was sent").toBe(before);
    // Bob's browser holds no waiting deletion of it, and his own purge goes out.
    await bob.store.purgeDeleted(bank.itemId, old);
    expect(server.attempts.at(-1)).toBe(`purge:${bank.itemId}`);
  });

  it("the shared code's rule of 2026-11-17: the move's delete is signed only over the head its checks were made on; a change read in between signs nothing", async () => {
    const { server, alice, bob, old } = await family();
    // Between the move's last checks and its delete, bob leaves the old vault and alice's browser reads it.
    const logs = alice.shared.logs;
    const append = logs.append.bind(logs);
    let injected = false;
    logs.append = async (vaultId, action, opts) => {
      if (vaultId === old && action.kind === "delete" && opts?.forMove === true && !injected) {
        injected = true;
        await bob.shared.logs.append(old, { kind: "leave" });
        await logs.refresh(old, null, null, true);
      }
      return append(vaultId, action, opts);
    };
    const r = await alice.store.moveEverything(old, { name: "Family 2", add: [B, C] });
    expect(injected).toBe(true);
    expect(server.attempts.filter((x) => x === `delete:${old}`), "no delete was signed or sent").toEqual([]);
    // Said as a log that moved on, not as "0 items changed after they were copied".
    expect([r.oldDeleted, r.oldKept, r.changed]).toEqual([null, "moved_on", 0]);
    expect(alice.store.moveDeleteWaiting(old)).toBe(false);
  });

  it("the shared code's rule of 2026-11-17: a half-made vault an earlier run replaced is deleted once the move's deletion is found stored outside the move", async () => {
    const { server, alice, old } = await family();
    // The first run stops at carol's add, leaving "Family 2" half made, with bob in it.
    server.refuseAddOf = C;
    const first = (await alice.store.moveEverything(old, { name: "Family 2", add: [B, C] }).catch((x: unknown) => x)) as MoveStoppedError;
    server.refuseAddOf = null;
    const half = first.newVaultId!;
    // From "Remove" on bob: a fresh vault "Family 3" (bob holds the half-made one's key), and its delete of the old vault
    // gets no answer, so it is held. The half-made vault cannot be read while this run goes (its trash read fails), so it
    // is not deleted before the copies, and stays due.
    server.noAnswer = { kind: "delete", store: false };
    server.trashReadsFail = true;
    const second = (await alice.store.moveEverything(old, { name: "Family 3", add: [C], removing: B }).catch((x: unknown) => x)) as MoveStoppedError;
    server.noAnswer = null;
    server.trashReadsFail = false;
    expect([second.stage, second.cause instanceof ChangeNotStoredError, second.newVaultId === half]).toEqual(["delete", true, false]);
    expect(alice.account.hasVault(half), "the half-made vault waits for the move's end").toBe(true);
    // The server stores the held delete whenever it likes, outside any run of the move.
    await serverStoresHeldDelete(server, alice, old);
    await alice.store.sync();
    expect(alice.store.notices().find((x) => x.vaultId === old)?.kind).toBe("move-stored");
    // The move is over: the half-made vault is deleted, and bob's grant to it goes with it.
    expect(server.appends.filter((x) => x === `delete:${half}`)).toHaveLength(1);
    expect(server.grants.get(half)!.get(B)!.revoked).toBe(true);
    expect(alice.account.hasVault(half)).toBe(false);
    expect(alice.account.hasVault(second.newVaultId!)).toBe(true);
    await alice.store.sync();
    expect(server.appends.filter((x) => x === `delete:${half}`), "deleted once").toHaveLength(1);
  });

  it("a half-made vault whose deletion is due is remembered across a reload, in the copy, and deleted by the next session", async () => {
    // Alice's browser keeps the offline copy, in a profile of its own.
    (globalThis as { indexedDB?: IDBFactory }).indexedDB = new FakeIDBFactory() as unknown as IDBFactory;
    const { server, alice, old } = await family(true, undefined, await openVaultCache(A));
    server.refuseAddOf = C;
    const first = (await alice.store.moveEverything(old, { name: "Family 2", add: [B, C] }).catch((x: unknown) => x)) as MoveStoppedError;
    server.refuseAddOf = null;
    const half = first.newVaultId!;
    // The half-made vault cannot be read while this run goes (its trash read fails): it stays due.
    server.noAnswer = { kind: "delete", store: false };
    server.trashReadsFail = true;
    await alice.store.moveEverything(old, { name: "Family 3", add: [C], removing: B }).catch((x: unknown) => x);
    server.noAnswer = null;
    server.trashReadsFail = false;
    // The held delete is stored outside the move; the half-made vault's own deletion is refused this time.
    await serverStoresHeldDelete(server, alice, old);
    server.beforeAppend = async (kind, vaultId) => {
      if (kind === "delete" && vaultId === half) throw new ApiError(403, "forbidden", "not now");
    };
    await alice.store.sync();
    expect(alice.store.notices().find((x) => x.vaultId === old)?.kind).toBe("move-stored");
    expect(alice.account.hasVault(half)).toBe(true);
    expect(server.appends.filter((x) => x === `delete:${half}`)).toEqual([]);
    alice.store.close();
    server.beforeAppend = null;
    // A reload: the same profile and its copy, a new session with no memory of the move. Its first sync deletes it.
    const again = await browser(server, alice.person, alice.contacts, await openVaultCache(A), alice.profile);
    expect(server.appends.filter((x) => x === `delete:${half}`)).toHaveLength(1);
    expect(again.account.hasVault(half)).toBe(false);
    // Done, and so forgotten in the copy too: the next session deletes nothing more.
    const c = await openVaultCache(A);
    expect(await c.halfMadeDue()).toEqual([]);
    c.close();
    await again.store.sync();
    expect(server.appends.filter((x) => x === `delete:${half}`)).toHaveLength(1);
  });

  /** Alice's move of "Family" stopped with its delete held (no answer); the connection is back. */
  async function stoppedWithDeleteHeld() {
    const f = await family();
    f.server.noAnswer = { kind: "delete", store: false };
    const e = (await f.alice.store.moveEverything(f.old, { name: "Family 2", add: [B, C] }).catch((x: unknown) => x)) as MoveStoppedError;
    expect([e.stage, e.cause instanceof ChangeNotStoredError]).toEqual(["delete", true]);
    f.server.noAnswer = null;
    return { ...f, target: e.newVaultId! };
  }
  /** The order every append reached the server in, from [from] on, as `kind:vault` with the vaults named. */
  const appendsSince = (server: Server, from: number, names: Record<string, string>) => server.appends.slice(from).map((a) => { const [k, v] = a.split(":"); return `${k}:${names[v!] ?? v}`; });

  it("another member adds an item between the stop and the next run: it is in the new vault before the delete is re-posted", async () => {
    const { server, alice, bob, old, target } = await stoppedWithDeleteHeld();
    // Bob, still a member of the old vault (the delete is not stored), adds an item there.
    await bob.store.sync();
    await bob.store.save(null, { type: "note", name: "late", notes: "added after the copies" }, [], undefined, old);
    const putsBefore = server.items.size;
    const appendsBefore = server.appends.length;
    // The delete's re-post sees the copy of "late" already in the new vault.
    let lateInNewAtDelete: boolean | null = null;
    server.beforeAppend = async (kind, vaultId) => {
      if (kind === "delete" && vaultId === old) lateInNewAtDelete = [...server.items.values()].filter((it) => it.vaultId === target && !it.deleted).length === 3 && alice.store.list().some((i) => i.vaultId === target && i.doc.name === "late");
    };
    const r = await alice.store.moveEverything(old, { name: "ignored", add: [B, C] });
    expect(lateInNewAtDelete).toBe(true);
    expect([r.newVaultId, r.oldKept]).toEqual([target, null]);
    expect(r.oldDeleted).not.toBeNull();
    expect(names(alice.store, target)).toEqual(["bank", "deeds", "late"]);
    expect(server.items.size).toBe(putsBefore + 1);
    // Exactly one delete was stored, re-posted byte for byte (two attempts, one signature), and nothing else was signed.
    expect(appendsSince(server, appendsBefore, { [old]: "old", [target]: "new" })).toEqual(["delete:old"]);
    expect(server.attempts.filter((x) => x === `delete:${old}`)).toHaveLength(2);
  });

  it("an item changed between the stop and the next run: the new vault holds its new revision once, never two copies", async () => {
    const { server, alice, bob, old, target } = await stoppedWithDeleteHeld();
    const copyIds = new Set(alice.store.list().filter((i) => i.vaultId === target).map((i) => i.itemId));
    await bob.store.sync();
    const bank = bob.store.list().find((i) => i.vaultId === old && i.doc.name === "bank")!;
    await bob.store.save(bank.itemId, { ...bank.doc, login: { username: "a", password: "pw2" } }, [], undefined, old);
    const r = await alice.store.moveEverything(old, { name: "ignored", add: [B, C] });
    expect([r.oldKept, r.changed]).toEqual([null, 0]);
    expect(r.oldDeleted).not.toBeNull();
    const inNew = alice.store.list().filter((i) => i.vaultId === target);
    expect(inNew.map((i) => i.doc.name).sort()).toEqual(["bank", "deeds"]);
    expect(inNew.find((i) => i.doc.name === "bank")!.doc.login?.password).toBe("pw2");
    // The same two copies, by id: the changed one replaced its own copy.
    expect(new Set(inNew.map((i) => i.itemId))).toEqual(copyIds);
    // Bob (who accepts the new vault) reads it the same, from the server.
    await bob.store.sync();
    const live = [...server.items.values()].filter((it) => it.vaultId === target && !it.deleted);
    expect(live).toHaveLength(2);
    expect(server.attempts.filter((x) => x === `delete:${old}`)).toHaveLength(2);
  });

  it("a copy that cannot be made on the next run stops it there, and the delete stays waiting (and says so)", async () => {
    const { server, alice, bob, old, target } = await stoppedWithDeleteHeld();
    await bob.store.sync();
    await bob.store.save(null, { type: "note", name: "late", notes: "n" }, [], undefined, old);
    server.putsBeforeDrop = 0;
    const e = (await alice.store.moveEverything(old, { name: "ignored", add: [B, C] }).catch((x: unknown) => x)) as MoveStoppedError;
    expect([e.stage, e.deleteWaiting, e.newVaultId]).toEqual(["copy", true, target]);
    const said = moveErrorText(e, "Family");
    expect(said.startsWith(fill(MOVE_STOPPED_DELETE_WAITING, "2", "3 items", "Family 2", "Family"))).toBe(true);
    expect(said).not.toMatch(/\bkept\b|\bdeleted\b/);
    expect(server.attempts.filter((x) => x === `delete:${old}`)).toHaveLength(1);
    expect(alice.shared.logs.holdsMoveDelete(old)).toBe(true);
    server.putsBeforeDrop = null;
    const r = await alice.store.moveEverything(old, { name: "ignored", add: [B, C] });
    expect(r.oldDeleted).not.toBeNull();
    expect(names(alice.store, target)).toEqual(["bank", "deeds", "late"]);
  });

  it("a membership change stored meanwhile takes the held delete's place: it is dropped, and the old vault goes only by a new delete signed under §3.13's rules", async () => {
    const { server, alice, bob, old, target } = await stoppedWithDeleteHeld();
    const held = (JSON.parse(alice.profile.storage.get(`andvari.log2.${A}.${old}.pending`)!) as { frame: string; forMove?: boolean }).frame;
    // Bob leaves the old vault: his `leave` is stored where alice's delete would have gone.
    await bob.store.sync();
    await bob.store.leaveSharedVault(old);
    expect(server.appends[server.appends.length - 1]).toBe(`leave:${old}`);
    const appendsBefore = server.appends.length;
    const r = await alice.store.moveEverything(old, { name: "ignored", add: [B, C] });
    // The held delete was never posted again: it can never be stored at its place.
    expect(server.attempts.filter((x) => x === `delete:${old}`)).toHaveLength(2);
    expect(server.logs.get(old)!.includes(held)).toBe(false);
    // An ordinary run from there, with the old vault's members read again (bob is gone): bob holds the half-made vault's
    // key and is not in the move any more, so a fresh vault is made, carol added, and a NEW delete signed once
    // every condition held. The half-made vault (bob still holds its key) is read and deleted first, before anything is
    // copied (design §3.13 as decided on 2026-11-18; it went last before that decision).
    expect(r.newVaultId).not.toBe(target);
    expect(r.oldDeleted).not.toBeNull();
    expect(r.discarded).toMatchObject({ vaultId: target, deleted: true });
    const signedNow = server.logs.get(old)![server.logs.get(old)!.length - 1]!;
    expect(signedNow).not.toBe(held);
    expect(appendsSince(server, appendsBefore, { [old]: "old", [target]: "half-made", [r.newVaultId]: "new" })).toEqual(["delete:half-made", "genesis:new", "add:new", "delete:old"]);
    expect(alice.store.unfinishedMoves()).toEqual([]);
  });

  it("an unlock between the stop and the next run re-posts nothing of the move; the first screen offers to finish it, and finishing does", async () => {
    const { server, alice, old, target } = await stoppedWithDeleteHeld();
    const attempts = server.attempts.length;
    // A reload: the same browser profile, a new session (no memory of the run), and the unlock's re-posting of held changes.
    const again = await browser(server, alice.person, alice.contacts, undefined, alice.profile);
    expect(server.attempts.slice(attempts)).toEqual([]);
    expect(again.shared.logs.holds(old)).toBe(true);
    expect(again.store.vaults().some((v) => v.vaultId === old)).toBe(true);
    const [m] = again.store.unfinishedMoves();
    expect(m).toEqual({ vaultId: old, name: "Family", newVaultId: target, newName: "Family 2", added: [B, C] });
    expect(fill(MOVE_UNFINISHED, m!.name!, m!.newName!)).toBe("Moving “Family” into “Family 2” isn't finished. The deletion of “Family” is signed and waiting for the server, and it can't be taken back.");
    expect(again.store.moveDeleteWaiting(old)).toBe(true);
    // The move's own record says which copy is which item's, so finishing carries on into the same vault.
    expect(again.store.movePlan(old)?.resume).toMatchObject({ name: "Family 2", newVaultId: target, copied: 2 });
    const r = await again.store.finishMove(m!);
    expect([r.newVaultId, r.oldKept]).toEqual([target, null]);
    expect(r.oldDeleted).not.toBeNull();
    expect(server.attempts.slice(attempts)).toEqual([`delete:${old}`]);
    expect(names(again.store, target)).toEqual(["bank", "deeds"]);
    expect(again.store.unfinishedMoves()).toEqual([]);
    expect(again.shared.logs.moveRecord(old)).toBeNull();
  });

  it("the old vault freezes under the move's held deletion (the server answered it stored, then served another entry there): the deletion is dropped, the move stops with its own line, never 'waiting' or 'finish the move', and the old vault is not reopened", async () => {
    const { server, alice, bob, old, target } = await stoppedWithDeleteHeld();
    // Finishing the move re-posts the held deletion; the server answers it stored at its position and stores nothing.
    server.lieAbout = "delete";
    const first = await alice.store.moveEverything(old, { name: "ignored", add: [B, C] }).catch((x: unknown) => x);
    server.lieAbout = null;
    expect(first).toBeInstanceOf(MoveStoppedError);
    expect(alice.shared.logs.heldKnown(old)).toBe("stored");
    // Bob leaves the old vault: the server stores his leave where it said alice's deletion is.
    await bob.store.sync();
    await bob.store.leaveSharedVault(old);
    const attempts = server.attempts.length;
    // One sync of alice's: the read shows the contradiction.
    await alice.store.sync();
    expect(alice.shared.logs.status(old).kind).toBe("frozen");
    expect(alice.shared.logs.writeAllowed(old)).toBe(false);
    // The deletion is dropped: nothing waits, nothing is shown as waiting, nothing is sent.
    expect(alice.shared.logs.holds(old)).toBe(false);
    expect(alice.store.heldChangeFor(old)).toBeNull();
    expect(alice.store.moveDeleteWaiting(old)).toBe(false);
    expect(alice.store.unfinishedMoves()).toEqual([{ vaultId: old, name: "Family", newVaultId: target, newName: "Family 2", added: [B, C], oldFrozen: true }]);
    // Moving again stops at once, with the move's own line; nothing is posted and the old vault stays frozen.
    const e = await alice.store.moveEverything(old, { name: "ignored", add: [B, C] }).catch((x: unknown) => x);
    expect(e).toBeInstanceOf(MoveStoppedError);
    expect((e as MoveStoppedError).cause).toBeInstanceOf(OldVaultFrozenError);
    expect((e as MoveStoppedError).deleteWaiting).toBe(false);
    expect(moveErrorText(e, "Family")).toBe(fill(MOVE_OLD_FROZEN, "Family", "Family 2"));
    expect(server.attempts.slice(attempts)).toEqual([]);
    expect(alice.shared.logs.status(old).kind).toBe("frozen");
    expect(names(alice.store, target)).toEqual(["bank", "deeds"]);
    // A reload and the unlock's re-sending post nothing, and the move is said as frozen until it is dismissed.
    const again = await browser(server, alice.person, alice.contacts, undefined, alice.profile);
    await again.store.resendHeldChanges();
    expect(server.attempts.slice(attempts)).toEqual([]);
    expect(again.store.unfinishedMoves().map((m) => [m.vaultId, m.oldFrozen])).toEqual([[old, true]]);
    expect(again.store.notices().filter((n) => n.vaultId === old)).toEqual([]);
    again.store.dismissFrozenMove(old);
    expect(again.store.unfinishedMoves()).toEqual([]);
    // The new vault, which holds the items, is never taken for a half-made one.
    expect(again.shared.logs.moveRecord(old)).toBeNull();
    expect(again.store.vaults().some((v) => v.vaultId === target)).toBe(true);
  });

  it("after a reload, an item changed meanwhile still replaces its own copy: the kept record names each copy", async () => {
    const { server, alice, bob, old, target } = await stoppedWithDeleteHeld();
    await bob.store.sync();
    const bank = bob.store.list().find((i) => i.vaultId === old && i.doc.name === "bank")!;
    await bob.store.save(bank.itemId, { ...bank.doc, login: { username: "a", password: "pw3" } }, [], undefined, old);
    const again = await browser(server, alice.person, alice.contacts, undefined, alice.profile);
    const r = await again.store.finishMove(again.store.unfinishedMoves()[0]!);
    expect(r.oldDeleted).not.toBeNull();
    const live = [...server.items.values()].filter((it) => it.vaultId === target && !it.deleted);
    expect(live).toHaveLength(2);
    expect(again.store.list().find((i) => i.vaultId === target && i.doc.name === "bank")!.doc.login?.password).toBe("pw3");
  });

  it("every other sharing action a screen shows as made counts only when the server stored it", async () => {
    const { server, alice, old } = await family();
    const notStored = async (kind: string, run: () => Promise<unknown>): Promise<void> => {
      server.noAnswer = { kind, store: false };
      const e = await run().then(() => "made", (x: unknown) => x);
      server.noAnswer = null;
      expect(e, kind).toBeInstanceOf(ChangeNotStoredError);
      // No answer came: whether it is stored cannot be told, so it is said as that (never "it isn't made").
      expect((e as ChangeNotStoredError).known, kind).toBe("unknown");
      expect(logActionText(e as ChangeNotStoredError)).toBe(kind === "genesis" ? LOG_UNKNOWN_CREATE : LOG_UNKNOWN);
    };
    await notStored("role", () => alice.store.setMemberRole(old, B, "reader"));
    expect(alice.shared.logs.verifiedState(old)?.members[B]?.role).toBe("writer");
    // While one frame is held, the vault takes nothing else (§3.7); re-posted, it lands, and the next action goes.
    expect(((await alice.shared.logs.retryHeld(old)) as { kind: string }).kind).toBe("appended");
    await notStored("remove", () => alice.store.removeVaultMember(old, C));
    expect(alice.shared.logs.verifiedState(old)?.members[C]).toBeDefined();
    await alice.shared.logs.retryHeld(old);
    await notStored("offer", () => alice.store.offerTransfer(old, B));
    expect(alice.store.pendingTransferFor(old)).toBeNull();
    await alice.shared.logs.retryHeld(old);
    await notStored("delete", () => alice.store.deleteSharedVault(old));
    expect(alice.store.vaults().some((v) => v.vaultId === old)).toBe(true);
    await notStored("genesis", () => alice.store.createSharedVault("Work"));
  });

  it("spec 03 §14.4: the store keeps the newest sync answer's quota; an answer without one is unknown, not the one before", async () => {
    const { server, alice } = await family();
    expect(alice.store.quota()).toBeNull();
    const q = { accountBytes: { used: 500, limit: 1_000 }, items: { used: 3, limit: 10 }, ownedSharedVaults: { used: 1, limit: 2 }, openLinks: { used: 0, limit: 20 } };
    server.quota = q;
    await alice.store.sync();
    expect(alice.store.quota()).toEqual(q);
    server.quota = { ...q, items: { used: 9, limit: 10 } };
    await alice.store.sync();
    expect(alice.store.quota()?.items).toEqual({ used: 9, limit: 10 });
    server.quota = undefined;
    await alice.store.sync();
    expect(alice.store.quota()).toBeNull();
  });

  it("a full account stops the copy and says so; the old vault is untouched", async () => {
    const { server, alice, old } = await family();
    server.putsBeforeFull = 0;
    const e = await alice.store.moveEverything(old, { name: "Family 2", add: [B, C] }).catch((x: unknown) => x);
    expect(e).toBeInstanceOf(MoveStoppedError);
    expect((e as MoveStoppedError).stage).toBe("copy");
    expect(((e as MoveStoppedError).cause as ApiError).code).toBe("quota_exceeded");
    expect(names(alice.store, old)).toEqual(["bank", "deeds"]);
    expect(alice.shared.logs.verifiedState(old)?.deleteId).toBeNull();
  });

  it("a remaining member this browser cannot add keeps the old vault, and the result names them", async () => {
    const { alice, old } = await family(false);
    const plan = alice.store.movePlan(old)!;
    expect(plan.members.map((m) => [m.userId, m.canBeAdded])).toEqual([[B, true], [C, false]]);
    const r = await alice.store.moveEverything(old, { name: "Family 2", add: plan.members.map((m) => m.userId) });
    expect(r.notAdded).toEqual([C]);
    expect(r.oldKept).toBe("not_added");
    expect(r.oldDeleted).toBeNull();
    expect(alice.shared.logs.verifiedState(old)?.deleteId).toBeNull();
    expect(names(alice.store, r.newVaultId)).toEqual(["bank", "deeds"]);
    expect(names(alice.store, old)).toEqual(["bank", "deeds"]);
  });

  it("on a vault whose history does not check out: copies out, adds only whom the owner ticked, and leaves the old vault as it is", async () => {
    const { server, alice, old } = await family();
    // The server serves an entry that does not verify (a repeat of the last one): the log fails here (§3.9).
    const log = server.logs.get(old)!;
    log.push(log[log.length - 1]!);
    await alice.store.sync();
    expect(alice.shared.logs.status(old).kind).toBe("failed");
    const plan = alice.store.movePlan(old)!;
    expect(plan.sourceStays).toBe(true);
    expect(plan.members.map((m) => m.userId).sort()).toEqual([B, C]);
    const before = server.appends.length;
    const r = await alice.store.moveEverything(old, { name: "Family 2", add: [B] });
    expect(r.oldKept).toBe("source_stays");
    expect(r.oldDeleted).toBeNull();
    // Nothing is signed on the old log; the new vault holds everything, with bob only.
    expect(server.appends.slice(before).filter((x) => x.endsWith(old))).toEqual([]);
    expect(names(alice.store, r.newVaultId)).toEqual(["bank", "deeds"]);
    expect(Object.keys(alice.shared.logs.verifiedState(r.newVaultId)!.members).sort()).toEqual([A, B]);
    expect(names(alice.store, old)).toEqual(["bank", "deeds"]);
  });

  it("is offered to the owner only", async () => {
    const { bob, old } = await family();
    expect(bob.store.movePlan(old)).toBeNull();
    await expect(bob.store.moveEverything(old, { name: "Mine", add: [] })).rejects.toThrow();
  });
});

/** A `quota` as the server serves it (spec 03 §14.4): roomy unless a meter is given. */
function quota(over: Partial<Record<"accountBytes" | "items" | "ownedSharedVaults" | "openLinks", { used: number; limit: number }>> = {}) {
  return { accountBytes: { used: 0, limit: 1e9 }, items: { used: 0, limit: 1e6 }, ownedSharedVaults: { used: 1, limit: 50 }, openLinks: { used: 0, limit: 20 }, ...over };
}

describe("a held change that did not happen at the unlock's re-send: its notice names the vault and survives the tab", () => {
  beforeAll(async () => {
    await initSodium();
  });

  /** Alice removes bob from "Family"; the answer never comes (nothing stored); the server refuses the re-send later. */
  async function removalRefusedAtUnlock() {
    const { server, alice, old } = await family();
    server.beforeAppend = async (kind) => {
      if (kind === "remove") throw new ApiError(0, "network", "no answer");
    };
    expect(await alice.store.removeVaultMember(old, B).then(() => "made", (e: unknown) => e)).toBeInstanceOf(ChangeNotStoredError);
    expect(alice.shared.logs.holds(old)).toBe(true);
    const tries = { n: 0 };
    server.beforeAppend = async (kind) => {
      if (kind !== "remove") return;
      tries.n++;
      throw new ApiError(403, "not_owner", "refused");
    };
    return { server, alice, old, tries };
  }

  it("with the offline copy off, the notice made at the unlock (before the first sync) names the vault", async () => {
    const { server, alice, old } = await removalRefusedAtUnlock();
    // The next unlock, no offline copy: the store's vault list is empty until the first pull.
    const again = await browser(server, alice.person, alice.contacts, undefined, alice.profile);
    const n = again.store.notices().filter((x) => x.kind === "held-not-made");
    // On the code before: one notice with vaultName "" ("Removing Bea from “a vault” didn't happen…").
    expect(n).toHaveLength(1);
    expect(n[0]).toMatchObject({ vaultId: old, vaultName: "Family", heldKind: "remove", reason: "not_owner" });
    expect(noticeBody(n[0]!).body).toBe(fill(RESEND_NOT_MADE_REMOVE, "Bob", "Family"));
  });

  it("a tab closed right after the unlock loses nothing: the notice comes again at the next unlock, the change is never sent again, and it goes once dismissed", async () => {
    const { server, alice, tries } = await removalRefusedAtUnlock();
    const first = await browser(server, alice.person, alice.contacts, undefined, alice.profile);
    expect(first.store.notices().filter((x) => x.kind === "held-not-made")).toHaveLength(1);
    expect(tries.n).toBe(1);
    // The tab closes without the notice being dismissed. On the code before, the next unlock says nothing.
    const second = await browser(server, alice.person, alice.contacts, undefined, alice.profile);
    const n = second.store.notices().filter((x) => x.kind === "held-not-made");
    expect(n).toHaveLength(1);
    expect(n[0]).toMatchObject({ vaultName: "Family", heldKind: "remove" });
    expect(tries.n, "never sent again").toBe(1);
    second.store.dismissNotice(n[0]!.id);
    const third = await browser(server, alice.person, alice.contacts, undefined, alice.profile);
    expect(third.store.notices().filter((x) => x.kind === "held-not-made")).toEqual([]);
    expect(tries.n).toBe(1);
  });

  it("a removal whose answer was lost is withdrawn: never sent again, the vault read at once, and the person told it wasn't made", async () => {
    const { server, alice, old } = await family();
    server.beforeAppend = async (kind) => {
      if (kind === "remove") throw new ApiError(0, "network", "no answer");
    };
    await alice.store.removeVaultMember(old, B).catch(() => null);
    server.beforeAppend = null;
    expect(alice.store.heldChangeFor(old)).toMatchObject({ kind: "remove", known: "unknown", withdrawable: true });
    // On the code before: false ("it may already be made, so it cannot be withdrawn").
    expect(alice.store.withdrawHeldChange(old)).toBe(true);
    await alice.store.sync();
    const n = alice.store.notices().filter((x) => x.kind === "held-found-not-made");
    expect(n).toHaveLength(1);
    expect(noticeBody(n[0]!).body).toBe(fill(RESEND_FOUND_NOT_MADE, "Family"));
    const again = await browser(server, alice.person, alice.contacts, undefined, alice.profile);
    expect(server.attempts.filter((a) => a === `remove:${old}`)).toHaveLength(0);
    expect(again.store.notices().filter((x) => x.kind.startsWith("held-found"))).toEqual([]);
  });

  it("a removal stored though its answer was lost, then withdrawn: the person is told it was made after all, with the way to undo it", async () => {
    const { server, alice, old } = await family();
    server.noAnswer = { kind: "remove", store: true };
    // The read after "cannot tell" fails too, so the removal stays held.
    server.logReadsFail = true;
    await alice.store.removeVaultMember(old, B).catch(() => null);
    server.noAnswer = null;
    server.logReadsFail = false;
    expect(alice.store.heldChangeFor(old)).toMatchObject({ kind: "remove", known: "unknown", withdrawable: true });
    expect(alice.store.withdrawHeldChange(old)).toBe(true);
    await alice.store.sync();
    const n = alice.store.notices().filter((x) => x.kind === "held-found-made");
    expect(n).toHaveLength(1);
    expect(n[0]).toMatchObject({ vaultId: old, vaultName: "Family", heldKind: "remove", memberName: "Bob" });
    expect(noticeBody(n[0]!).body).toBe(fill(RESEND_FOUND_MADE_REMOVE, "Bob", "Family"));
  });

  it("made after all, found at the unlock before the first pull, with the offline copy off: the notice names the vault, and a lock before it was dismissed loses nothing", async () => {
    const { server, alice, old } = await family();
    server.noAnswer = { kind: "remove", store: true };
    server.logReadsFail = true;
    await alice.store.removeVaultMember(old, B).catch(() => null);
    server.noAnswer = null;
    // On the train: the withdrawal's own read fails too, so the vault is read at the next unlock, before its first pull.
    expect(alice.store.withdrawHeldChange(old)).toBe(true);
    await new Promise((r) => setTimeout(r, 20));
    server.logReadsFail = false;
    const again = await browser(server, alice.person, alice.contacts, undefined, alice.profile);
    const n = again.store.notices().filter((x) => x.kind === "held-found-made");
    // On the code before: one notice naming no vault (vaultName ""), and the change forgotten at once.
    expect(n).toHaveLength(1);
    expect(n[0]).toMatchObject({ vaultId: old, vaultName: "Family", heldKind: "remove", memberName: "Bob" });
    // Locked before the person dismissed it: the next unlock says it again (on the code before: nothing).
    const third = await browser(server, alice.person, alice.contacts, undefined, alice.profile);
    const m = third.store.notices().filter((x) => x.kind === "held-found-made");
    expect(m).toHaveLength(1);
    expect(m[0]).toMatchObject({ vaultName: "Family", heldKind: "remove" });
    third.store.dismissNotice(m[0]!.id);
    const fourth = await browser(server, alice.person, alice.contacts, undefined, alice.profile);
    expect(fourth.store.notices().filter((x) => x.kind === "held-found-made")).toEqual([]);
  });

  /** Alice deletes "Family"; the answer never comes (nothing stored). */
  async function deletionLost() {
    const { server, alice, old } = await family();
    server.noAnswer = { kind: "delete", store: false };
    expect(await alice.store.deleteSharedVault(old).then(() => "deleted", (e: unknown) => e)).toBeInstanceOf(ChangeNotStoredError);
    server.noAnswer = null;
    const tries = () => server.attempts.filter((a) => a === `delete:${old}`).length;
    expect(tries()).toBe(1);
    return { server, alice, old, tries };
  }

  it("a vault's deletion whose answer was lost is not sent again at the unlock: a notice names the vault and offers the two acts, and it is sent only once the person chose to delete it now", async () => {
    const { server, alice, old, tries } = await deletionLost();
    const again = await browser(server, alice.person, alice.contacts, undefined, alice.profile);
    // On the code before: sent again at once, and the vault deleted without a question.
    expect(tries()).toBe(1);
    expect(again.store.vaults().some((v) => v.vaultId === old)).toBe(true);
    const ask = again.store.notices().filter((x) => x.kind === "held-delete-ask");
    expect(ask).toHaveLength(1);
    expect(ask[0]).toMatchObject({ vaultId: old, vaultName: "Family" });
    expect(noticeBody(ask[0]!)).toEqual({ warn: true, body: fill(RESEND_DELETE_ASK, "Family") });
    const html = renderToStaticMarkup(createElement(HeldDeleteAsk, { notice: ask[0]!, store: again.store, onDone: () => {} }));
    expect(html).toContain(RESEND_DELETE_ASK_NOW);
    expect(html).toContain(RESEND_DELETE_ASK_KEEP);
    // Another sync sends nothing either.
    await again.store.sync();
    expect(tries()).toBe(1);
    await again.store.sendHeldDeletion(old);
    expect(tries()).toBe(2);
    expect(again.store.vaults().some((v) => v.vaultId === old)).toBe(false);
    expect(again.store.notices().filter((x) => x.kind === "held-delete-ask")).toEqual([]);
  });

  it("keep the vault: the deletion is withdrawn, never sent, and nothing is asked again", async () => {
    const { server, alice, old, tries } = await deletionLost();
    const again = await browser(server, alice.person, alice.contacts, undefined, alice.profile);
    expect(again.store.notices().filter((x) => x.kind === "held-delete-ask")).toHaveLength(1);
    expect(again.store.withdrawHeldChangeAs(old)).toBe("unknown");
    expect(again.store.notices().filter((x) => x.kind === "held-delete-ask")).toEqual([]);
    const third = await browser(server, alice.person, alice.contacts, undefined, alice.profile);
    expect(tries()).toBe(1);
    expect(third.store.notices().filter((x) => x.kind === "held-delete-ask")).toEqual([]);
    expect(third.store.vaults().some((v) => v.vaultId === old)).toBe(true);
  });

  it("the third check's S1: a deletion the server stored, whose answer was lost, is looked for before anyone is asked: no question, nothing sent, and the notice says the vault was deleted and until when it can be restored (with and without the offline copy)", async () => {
    for (const offline of [false, true]) {
      if (offline) (globalThis as { indexedDB?: IDBFactory }).indexedDB = new FakeIDBFactory() as unknown as IDBFactory;
      const { server, alice, old } = await family(true, undefined, offline ? await openVaultCache(A) : undefined);
      server.noAnswer = { kind: "delete", store: true };
      // The read after "cannot tell" fails too, so the deletion stays held.
      server.logReadsFail = true;
      expect(await alice.store.deleteSharedVault(old).then(() => "deleted", (e: unknown) => e)).toBeInstanceOf(ChangeNotStoredError);
      server.noAnswer = null;
      server.logReadsFail = false;
      expect(alice.shared.logs.holds(old)).toBe(true);
      alice.store.close();
      const tries = () => server.attempts.filter((a) => a === `delete:${old}`).length;
      const again = await browser(server, alice.person, alice.contacts, offline ? await openVaultCache(A) : undefined, alice.profile);
      // On the code before: "Your deletion of “Family” isn't confirmed…" (without the copy: of “the new vault”), and
      // "keep the vault" kept nothing.
      expect(again.store.notices().filter((x) => x.kind === "held-delete-ask"), `offline copy ${offline}`).toEqual([]);
      expect(tries(), "nothing is sent").toBe(1);
      expect(again.store.vaults().some((v) => v.vaultId === old)).toBe(false);
      const made = again.store.notices().filter((x) => x.kind === "held-delete-made");
      expect(made).toHaveLength(1);
      expect(made[0]).toMatchObject({ vaultId: old, vaultName: offline ? "Family" : "" });
      // This server served no day until which the vault can be restored (its log read carries no `deleted`): the line
      // names none and points to the deleted vaults. On the code before: a day computed from the entry's time.
      expect(made[0]!.purgeAt).toBeUndefined();
      expect(noticeBody(made[0]!)).toEqual({ warn: true, body: offline ? fill(RESEND_DELETE_MADE_NO_DAY, "Family") : RESEND_DELETE_MADE_UNNAMED_NO_DAY });
      // Kept until it is dismissed: a lock before then loses nothing.
      again.store.close();
      const third = await browser(server, alice.person, alice.contacts, offline ? await openVaultCache(A) : undefined, alice.profile);
      const kept = third.store.notices().filter((x) => x.kind === "held-delete-made");
      expect(kept).toHaveLength(1);
      third.store.dismissNotice(kept[0]!.id);
      third.store.close();
      const fourth = await browser(server, alice.person, alice.contacts, offline ? await openVaultCache(A) : undefined, alice.profile);
      expect(fourth.store.notices().filter((x) => x.kind.startsWith("held-"))).toEqual([]);
      expect(tries()).toBe(1);
      fourth.store.close();
    }
  });

  it("the third check's S3: a 'not made' found at the unlock before the first sync, then a lock before that sync answers: the next unlock still says it, once", async () => {
    const { server, alice, old } = await family();
    server.beforeAppend = async (kind) => {
      if (kind === "remove") throw new ApiError(0, "network", "no answer");
    };
    await alice.store.removeVaultMember(old, B).catch(() => null);
    server.beforeAppend = null;
    // On the train: the withdrawal's own read fails, so the vault is read at the next unlock.
    server.logReadsFail = true;
    expect(alice.store.withdrawHeldChange(old)).toBe(true);
    await new Promise((r) => setTimeout(r, 20));
    server.logReadsFail = false;
    alice.store.close();
    // The next unlock reads the vault before its first sync (no offline copy: nothing can be named yet), and is locked
    // before that sync answers.
    server.offline = true;
    const locked = await browser(server, alice.person, alice.contacts, undefined, alice.profile).catch((e: unknown) => e);
    server.offline = false;
    expect(locked).toBeInstanceOf(Error);
    const again = await browser(server, alice.person, alice.contacts, undefined, alice.profile);
    const n = again.store.notices().filter((x) => x.kind === "held-found-not-made");
    // On the code before: none (it was marked told at the locked unlock, its notice held in memory only).
    expect(n).toHaveLength(1);
    expect(n[0]).toMatchObject({ vaultId: old, vaultName: "Family" });
    again.store.close();
    const third = await browser(server, alice.person, alice.contacts, undefined, alice.profile);
    expect(third.store.notices().filter((x) => x.kind === "held-found-not-made")).toEqual([]);
    expect(server.appends.filter((a) => a === `remove:${old}`), "never sent again, never made").toEqual([]);
  });

  it("the third check's day out: the day of a deletion that waits runs out between the question and the tap: it is given up there, nothing is sent, and the line says so with how to delete the vault again", async () => {
    const { server, alice, old, tries } = await deletionLost();
    const again = await browser(server, alice.person, alice.contacts, undefined, alice.profile);
    expect(again.store.notices().filter((x) => x.kind === "held-delete-ask")).toHaveLength(1);
    // The day runs out while the question is on the screen.
    const storage = alice.profile.storage;
    const key = [...storage.map.keys()].find((k) => k.endsWith(`.${old}.pending`))!;
    storage.set(key, JSON.stringify({ ...(JSON.parse(storage.map.get(key)!) as object), heldAt: Date.now() - 86_400_000 }));
    const e = await again.store.sendHeldDeletion(old).then(() => "deleted", (x: unknown) => x);
    // On the code before: refused with "nothing_held", a line that names a code.
    expect(e).toBeInstanceOf(LogActionError);
    expect(logActionText(e as LogActionError)).toBe(RESEND_DELETE_ASK_GIVEN_UP);
    expect(tries(), "nothing is sent").toBe(1);
    expect(again.shared.logs.holds(old)).toBe(false);
    expect(again.store.vaults().some((v) => v.vaultId === old)).toBe(true);
    // The give-up's own notice says what its read found (the log does not hold it).
    expect(again.store.notices().filter((x) => x.kind === "held-not-made" && x.vaultId === old && x.heldKind === "delete")).toHaveLength(1);
  });

  it("a sync that moves a vault's log settles its waiting change by a look: a removal the log shows no longer reads as waiting, and nothing is sent", async () => {
    const { server, alice, old } = await family();
    server.noAnswer = { kind: "remove", store: true };
    // The read after "cannot tell" fails, so the removal stays held while the server has it.
    server.logReadsFail = true;
    await alice.store.removeVaultMember(old, B).catch(() => null);
    server.noAnswer = null;
    server.logReadsFail = false;
    expect(alice.store.heldChangeFor(old)).toMatchObject({ kind: "remove", known: "unknown" });
    const tries = server.attempts.filter((a) => a === `remove:${old}`).length;
    // Another device's change moves the vault's log; this browser's next sync reads it.
    server.rev++;
    await alice.store.sync();
    // On the code before: still { kind: "remove", known: "unknown" } beside a member list without bob, until an unlock.
    expect(alice.store.heldChangeFor(old)).toBeNull();
    expect(alice.shared.logs.verifiedState(old)?.members[B]).toBeUndefined();
    expect(server.attempts.filter((a) => a === `remove:${old}`).length, "nothing is sent").toBe(tries);
    expect(alice.store.notices().filter((x) => x.kind.startsWith("held-"))).toEqual([]);
  });

  it("the same look where another entry took the change's place: it did not happen, and that is said", async () => {
    const { server, alice, old } = await family();
    server.beforeAppend = async (kind) => {
      if (kind === "remove") throw new ApiError(0, "network", "no answer");
    };
    await alice.store.removeVaultMember(old, B).catch(() => null);
    server.beforeAppend = null;
    expect(alice.store.heldChangeFor(old)?.kind).toBe("remove");
    // Alice's other browser changes bob's role meanwhile: that entry takes the removal's position.
    const other = await browser(server, alice.person, alice.contacts, undefined, { storage: memoryStorage(), personalVaultId: alice.profile.personalVaultId, personalVk: alice.profile.personalVk });
    await other.store.setMemberRole(old, B, "reader");
    await alice.store.sync();
    expect(alice.store.heldChangeFor(old)).toBeNull();
    const n = alice.store.notices().filter((x) => x.kind === "held-not-made" && x.vaultId === old);
    expect(n).toHaveLength(1);
    expect(n[0]).toMatchObject({ heldKind: "remove", reason: "head_moved" });
    expect(server.appends.filter((a) => a === `remove:${old}`)).toEqual([]);
  });

  it("the question about a deletion that waits has words of its own for a vault it cannot name, never a move's \"new vault\"", () => {
    const body = noticeBody({ id: "n", vaultId: "v", vaultName: "", kind: "held-delete-ask", heldKind: "delete" }).body;
    expect(body).toBe(RESEND_DELETE_ASK_UNNAMED);
    expect(body).not.toContain(MOVE_UNNAMED_VAULT);
  });
});

describe("spec 03 §14.4: the check for space before \"Move everything\" and before an import", () => {
  beforeAll(async () => {
    await initSodium();
  });

  /** The move is refused before anything is signed or written: no append, no put, no upload; the old vault as it was. */
  async function refusedBeforeStart(over: Parameters<typeof quota>[0], removing: string | null = null): Promise<QuotaShortError> {
    const { server, alice, old } = await family();
    server.quota = quota(over);
    const appends = server.appends.length;
    const items = server.items.size;
    const files = server.attachments.size;
    const e = await alice.store.moveEverything(old, { name: "Family 2", add: [B, ...(removing === C ? [] : [C])], removing }).catch((x: unknown) => x);
    expect(e).toBeInstanceOf(QuotaShortError);
    expect([server.appends.length, server.items.size, server.attachments.size]).toEqual([appends, items, files]);
    expect(Object.keys(alice.shared.logs.verifiedState(old)!.members).sort()).toEqual([A, B, C]);
    expect(alice.store.movePlan(old)?.resume).toBeNull();
    return e as QuotaShortError;
  }

  it("short on space: the move does not start, and the panel says which limit and by how much", async () => {
    const { alice, old } = await family();
    const size = alice.store.moveSize(old, null, "Family 2");
    expect(size.items).toBe(2);
    expect(size.bytes).toBeGreaterThan(size.metaBytes);
    const e = await refusedBeforeStart({ accountBytes: { used: 10_000, limit: 10_000 + size.bytes - 1 } });
    expect(e.limits).toEqual([{ quota: "accountBytes", used: 10_000, limit: 10_000 + size.bytes - 1, adds: size.bytes, by: 1 }]);
    const text = moveErrorText(e, "Family");
    expect(text.startsWith(`${OWNER_OUT_OF_SPACE} `)).toBe(true);
    expect(text).toContain(`1 B of space over the limit of ${humanSize(10_000 + size.bytes - 1)}`);
    expect(text).toContain("operator can raise");
  });

  it("short on items, and from the remove dialog: the member's remove is not signed either", async () => {
    const e = await refusedBeforeStart({ items: { used: 4_999, limit: 5_000 } }, C);
    expect(e.limits.map((l) => [l.quota, l.by])).toEqual([["items", 1]]);
    expect(moveErrorText(e, "Family")).toContain("1 item over the limit of 5000 items");
  });

  it("short on shared vaults: the new vault would be one too many", async () => {
    const e = await refusedBeforeStart({ ownedSharedVaults: { used: 3, limit: 3 } });
    expect(e.limits.map((l) => [l.quota, l.by])).toEqual([["ownedSharedVaults", 1]]);
    expect(moveErrorText(e, "Family")).toContain("1 shared vault over the limit of 3 shared vaults");
  });

  it("short on two limits at once names both; open links are never grown by a move, so a full meter there is room", async () => {
    const e = await refusedBeforeStart({ items: { used: 10, limit: 10 }, ownedSharedVaults: { used: 9, limit: 2 } });
    expect(e.limits.map((l) => [l.quota, l.by])).toEqual([["items", 2], ["ownedSharedVaults", 8]]);
    expect(moveErrorText(e, "Family")).toContain("2 items over the limit of 10 items and 8 shared vaults over the limit of 2 shared vaults");
    const { server, alice, old } = await family();
    server.quota = quota({ openLinks: { used: 25, limit: 20 } });
    expect((await alice.store.moveEverything(old, { name: "Family 2", add: [B, C] })).oldKept).toBeNull();
  });

  it("exactly at every limit is room: the move runs to its end", async () => {
    const { server, alice, old } = await family();
    const size = alice.store.moveSize(old, null, "Family 2");
    server.quota = quota({ accountBytes: { used: 500, limit: 500 + size.bytes }, items: { used: 7, limit: 9 }, ownedSharedVaults: { used: 4, limit: 5 } });
    const r = await alice.store.moveEverything(old, { name: "Family 2", add: [B, C] });
    expect(r.oldKept).toBeNull();
    expect(names(alice.store, r.newVaultId)).toEqual(["bank", "deeds"]);
    // The figure the check used is the bytes the copy wrote: each blob as sealed, plus the file's stored size.
    const written = [...server.items.values()].filter((it) => it.vaultId === r.newVaultId).reduce((s, it) => s + (it.blob?.length ?? 0), 0);
    const files = [...server.attachments.values()].filter((a) => a.vaultId === r.newVaultId).reduce((s, a) => s + a.body.length - 24, 0);
    expect(written + files).toBe(size.bytes);
  });

  it("unknown (no quota served; the wire reads one that cannot be meters as none, vault/quota.test.ts): the move starts and the server decides", async () => {
    for (const served of [undefined, null]) {
      const { server, alice, old } = await family();
      server.quota = served;
      server.putsBeforeFull = 0;
      const e = await alice.store.moveEverything(old, { name: "Family 2", add: [B, C] }).catch((x: unknown) => x);
      // It started (a new vault was made), and the server's refusal part-way is handled as before.
      expect(e).toBeInstanceOf(MoveStoppedError);
      expect([(e as MoveStoppedError).stage, ((e as MoveStoppedError).cause as ApiError).code]).toEqual(["copy", "quota_exceeded"]);
      expect(moveErrorText(e, "Family")).toContain(OWNER_OUT_OF_SPACE);
    }
  });

  it("a resumed move counts only what is not copied yet, and no new vault", async () => {
    const { server, alice, old } = await family();
    server.putsBeforeDrop = 1;
    const s = (await alice.store.moveEverything(old, { name: "Family 2", add: [B, C] }).catch((x: unknown) => x)) as MoveStoppedError;
    expect([s.stage, s.copied]).toEqual(["copy", 1]);
    server.putsBeforeDrop = null;
    const whole = alice.store.moveSize(old, null, "Family 2");
    // Room for one more item and no new shared vault: short for a fresh move, room for the rest of this one.
    server.quota = quota({ items: { used: 10, limit: 11 }, ownedSharedVaults: { used: 2, limit: 2 }, accountBytes: { used: 0, limit: whole.bytes - 1 } });
    expect(alice.store.movePlan(old)?.resume?.copied).toBe(1);
    const r = await alice.store.moveEverything(old, { name: "ignored", add: [B, C] });
    expect(r.newVaultId).toBe(s.newVaultId);
    expect(r.oldKept).toBeNull();
    // A fresh move of what is left now would be short on both the new vault and the items.
    const { server: s2, alice: a2, old: o2 } = await family();
    s2.quota = quota({ items: { used: 10, limit: 11 }, ownedSharedVaults: { used: 2, limit: 2 } });
    const e = await a2.store.moveEverything(o2, { name: "Family 2", add: [B, C] }).catch((x: unknown) => x);
    expect((e as QuotaShortError).limits.map((l) => l.quota)).toEqual(["items", "ownedSharedVaults"]);
  });

  it("a sync that fails before the check is the answer: nothing is checked on an older value, and nothing starts", async () => {
    const { server, alice, old } = await family();
    server.quota = quota();
    await alice.store.sync();
    const wire = alice.wire as { sync: (since: number) => Promise<SyncResponse> };
    const real = wire.sync;
    wire.sync = async () => {
      throw new ApiError(0, "network", "offline");
    };
    const appends = server.appends.length;
    const e = await alice.store.moveEverything(old, { name: "Family 2", add: [B, C] }).catch((x: unknown) => x);
    wire.sync = real;
    expect(e).toBeInstanceOf(MoveStoppedError);
    expect([(e as MoveStoppedError).stage, (e as MoveStoppedError).newVaultId]).toEqual(["create", null]);
    expect(server.appends.length).toBe(appends);
  });

  const csv = (n: number, prefix = "site") =>
    Array.from({ length: n }, (_, i) => ({ itemId: crypto.randomUUID(), doc: { type: "login" as const, name: `${prefix} ${i}`, login: { username: "u", password: `p${i}` } } }));
  const sealedBytes = (rows: ReturnType<typeof csv>) => rows.reduce((s, r) => s + sealedBlobLength(utf8(JSON.stringify(r.doc)).length), 0);

  it("an import: short on items or on space, nothing is sent; exactly at the limit, everything lands, at the bytes the check counted", async () => {
    const { server, alice } = await family();
    const rows = csv(3);
    const personal = alice.account.personalVaultId;
    const before = server.items.size;
    server.quota = quota({ items: { used: 8, limit: 10 } });
    const e1 = await alice.store.importDocs(rows).catch((x: unknown) => x);
    expect((e1 as QuotaShortError).limits).toEqual([{ quota: "items", used: 8, limit: 10, adds: 3, by: 1 }]);
    expect(server.items.size).toBe(before);
    expect(importPushOutcome(e1)).toEqual({ fatal: true, message: `${OWNER_OUT_OF_SPACE} Nothing was started: this would go 1 item over the limit of 10 items. The server's operator can raise this account's limits.` });
    server.quota = quota({ accountBytes: { used: 100, limit: 100 + sealedBytes(rows) - 1 } });
    expect(((await alice.store.importDocs(rows).catch((x: unknown) => x)) as QuotaShortError).limits[0]).toMatchObject({ quota: "accountBytes", by: 1 });
    expect(server.items.size).toBe(before);
    server.quota = quota({ accountBytes: { used: 100, limit: 100 + sealedBytes(rows) }, items: { used: 7, limit: 10 } });
    await alice.store.importDocs(rows);
    const landed = rows.map((r) => server.items.get(r.itemId)!);
    expect(landed.every((it) => it.vaultId === personal)).toBe(true);
    expect(landed.reduce((s, it) => s + (it.blob?.length ?? 0), 0)).toBe(sealedBytes(rows));
  });

  it("an import retried after a stop counts only the rows the server does not hold yet", async () => {
    const { server, alice } = await family();
    const rows = csv(3);
    server.putsBeforeDrop = 1; // the first chunk's second put drops the connection
    await expect(alice.store.importDocs(rows)).rejects.toThrow();
    server.putsBeforeDrop = null;
    const held = rows.filter((r) => server.items.has(r.itemId)).length;
    expect(held).toBe(1);
    server.quota = quota({ items: { used: 9, limit: 11 } }); // room for the 2 left, not for 3
    await alice.store.importDocs(rows);
    expect(rows.every((r) => server.items.has(r.itemId))).toBe(true);
  });

  it("an import into a shared vault someone else owns is not checked against this account's meters", async () => {
    const { server, bob, old } = await family();
    server.quota = quota({ items: { used: 10, limit: 10 } });
    await bob.store.importDocs(csv(2, "bob"), undefined, old);
    expect(bob.store.list().filter((i) => i.vaultId === old && i.doc.name.startsWith("bob"))).toHaveLength(2);
  });
});

describe("spec 03 §14.4: Settings' line of the account's use and limits", () => {
  it("one line with used and limit for each of the four meters, and nothing when the server gave none", () => {
    expect(quotaLineText(null)).toBeNull();
    const q = { accountBytes: { used: 1_536, limit: 104_857_600 }, items: { used: 40, limit: 5_000 }, ownedSharedVaults: { used: 2, limit: 50 }, openLinks: { used: 0, limit: 20 } };
    expect(quotaLineText(q)).toBe("On this server this account uses 1.5 KiB of its 100 MiB of space, 40 of 5000 items, 2 of 50 shared vaults and 0 of 20 open links.");
  });

  it("Settings renders that line from the store's newest quota, and only there", () => {
    const src = readFileSync(fileURLToPath(new URL("../ui/Settings.tsx", import.meta.url)), "utf8");
    expect(src).toMatch(/const line = quotaLineText\(store\.quota\(\)\);\s*if \(line === null\) return null;/);
    expect(src).toContain("<QuotaLine store={store} />");
  });
});

describe("the holding area: copying items out of a vault this account was removed from (design §3.8, §3.12)", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("removed by the owner, bob copies the held items into his personal vault; the attachment the server no longer serves is left out and counted", async () => {
    const { alice, bob, old } = await family();
    await alice.store.removeVaultMember(old, B);
    await bob.store.sync();
    expect(bob.account.hasVault(old)).toBe(false);
    const held = bob.store.heldVaults();
    expect(held.map((h) => [h.vaultId, h.reason, h.verified, h.itemCount, h.canCopyOut])).toEqual([[old, "removed", true, 2, true]]);

    const progress: string[] = [];
    const r = await bob.store.copyHeldToPersonal(old, (d, t) => progress.push(`${d}/${t}`));
    expect(r).toEqual({ copied: 2, attachmentsLeftOut: 1, unreadable: 0 });
    expect(progress.at(-1)).toBe("2/2");
    const personal = bob.account.personalVaultId!;
    const mine = bob.store.list().filter((i) => i.vaultId === personal);
    expect(mine.map((i) => i.doc.name).sort()).toEqual(["bank", "deeds"]);
    expect(mine.find((i) => i.doc.name === "bank")!.doc).toMatchObject({ login: { username: "a", password: "pw1" } });
    expect(mine.find((i) => i.doc.name === "deeds")!.doc.attachments).toEqual([]);
    // The held vault's key stays out of use: nothing is written under it.
    expect(bob.account.hasVault(old)).toBe(false);

    // A second run after a stop copies nothing twice: the same new ids land on the server's dedup.
    const again = await bob.store.copyHeldToPersonal(old);
    expect(again.copied).toBe(2);
    expect(bob.store.list().filter((i) => i.vaultId === personal)).toHaveLength(2);
  });

  it("a held copy goes at its date, after a sync and at the next start, from memory and from IndexedDB", async () => {
    const cache = await openVaultCache(B);
    expect(cache.durable).toBe(true);
    const { alice, bob, old } = await family(true, cache);
    await alice.store.removeVaultMember(old, B);
    await bob.store.sync();
    const [held] = bob.store.heldVaults();
    expect(held).toMatchObject({ vaultId: old, canCopyOut: true });
    // On disk: the held record, with its re-sealed items and the kept wrap of the vault's key.
    expect((await cache.heldVaults()).map((h) => [h.vault.vaultId, h.items.length, h.ownWrap !== undefined])).toEqual([[old, 2, true]]);

    // A start (a new tab on the same browser) the day after its date: the record is dropped at hydrate, disk included.
    const now = Date.now;
    const later = held!.expungeAt + 86_400_000;
    try {
      Date.now = () => later;
      const tab = new VaultStore(bob.wire as unknown as ApiClient, bob.account, await openVaultCache(B), undefined, bob.wire as unknown as ItemWire);
      tab.attachSharedLogs(bob.shared);
      await tab.hydrate();
      expect(tab.heldVaults()).toEqual([]);
      expect(await cache.heldVaults()).toEqual([]);
      await expect(tab.copyHeldToPersonal(old)).rejects.toBeInstanceOf(Error);
      // The tab still open drops it at its next sync.
      expect(bob.store.heldVaults()).toHaveLength(1);
      await bob.store.sync();
      expect(bob.store.heldVaults()).toEqual([]);
    } finally {
      Date.now = now;
    }
    cache.close();
  });

  it("a held copy kept without its key offers no copy-out, and says so by refusing", async () => {
    const { alice, bob, old } = await family();
    await alice.store.removeVaultMember(old, B);
    await bob.store.sync();
    // A record made before the wrap was kept (an older holding area): no wrap on it.
    const holding = (bob.store as unknown as { holding: Map<string, { ownWrap?: string }> }).holding;
    delete holding.get(old)!.ownWrap;
    expect(bob.store.heldVaults()[0]!.canCopyOut).toBe(false);
    await expect(bob.store.copyHeldToPersonal(old)).rejects.toThrow(HeldKeyGoneError);
  });
});

describe("a refusal that comes from a freeze says so, by what happened (a vault whose server contradicts itself)", () => {
  beforeAll(async () => {
    await initSodium();
  });

  /** Every line a refusal on a vault that cannot be changed here may say: the one expected, and none of the others. */
  function saysOnly(e: unknown, line: string): void {
    expect(e).toBeInstanceOf(LogActionError);
    const said = friendlyError(e);
    expect(said).toBe(line);
    for (const other of [LOG_READ_ONLY, LOG_FROZEN, LOG_FROZEN_NOT_SENT, LOG_LEAVE_FROZEN_TAKEN, LOG_LEAVE_FROZEN_REFUSED, LOG_LEAVE_FROZEN_UNKNOWN, LOG_UNKNOWN, LOG_NOT_STORED].filter((l) => l !== line)) expect(said).not.toBe(other);
  }

  /**
   * The sequence: the server answers the person's own change of [kind] as stored at its position (naming it) and
   * stores nothing; bob's leave is stored at that position while the answer is out; the change's own follow-up read
   * finds the contradiction.
   */
  function contradictAtOwnRead(server: Server, bob: Awaited<ReturnType<typeof family>>["bob"], old: string, kind: string): void {
    server.lieAbout = kind;
    server.beforeAppend = async (k) => {
      if (k !== kind) return;
      server.beforeAppend = null;
      server.lieAbout = null;
      await bob.store.leaveSharedVault(old);
      server.lieAbout = kind;
    };
  }

  for (const [what, kind, act] of [
    ["a change of a member's role", "role", (s: VaultStore, v: string) => s.setMemberRole(v, C, "writer")],
    ["the person's own deletion of the vault", "delete", (s: VaultStore, v: string) => s.deleteSharedVault(v)],
  ] as const) {
    it(`${what}, answered as stored and contradicted at its own follow-up read: the frozen line, which says nothing of whether it was made`, async () => {
      const { server, alice, bob, old } = await family();
      await bob.store.sync();
      contradictAtOwnRead(server, bob, old, kind);
      const e = await act(alice.store, old).then(() => "done", (x: unknown) => x);
      server.lieAbout = null;
      expect(alice.shared.logs.status(old).kind).toBe("frozen");
      expect((e as LogActionError).outcome).toMatchObject({ kind: "read_only", frozen: "sent" });
      saysOnly(e, LOG_FROZEN);
      // The next change is refused before it is signed: nothing is sent, and the line may say so.
      const attempts = server.attempts.length;
      const next = await alice.store.setMemberRole(old, B, "reader").then(() => "done", (x: unknown) => x);
      expect(server.attempts.slice(attempts)).toEqual([]);
      expect((next as LogActionError).outcome).toMatchObject({ kind: "read_only", frozen: "unsent" });
      saysOnly(next, LOG_FROZEN_NOT_SENT);
    });
  }

  it("the person's own deletion kept for their word, sent at 'delete it now' and contradicted at its own follow-up read: the frozen line", async () => {
    const { server, alice, bob, old } = await family();
    server.noAnswer = { kind: "delete", store: false };
    expect(await alice.store.deleteSharedVault(old).then(() => "deleted", (e: unknown) => e)).toBeInstanceOf(ChangeNotStoredError);
    server.noAnswer = null;
    const again = await browser(server, alice.person, alice.contacts, undefined, alice.profile);
    expect(again.store.notices().filter((x) => x.kind === "held-delete-ask")).toHaveLength(1);
    await bob.store.sync();
    contradictAtOwnRead(server, bob, old, "delete");
    const e = await again.store.sendHeldDeletion(old).then(() => "deleted", (x: unknown) => x);
    server.lieAbout = null;
    expect(again.shared.logs.status(old).kind).toBe("frozen");
    saysOnly(e, LOG_FROZEN);
    // A tap after the freeze (the question was still on the screen): the deletion was dropped with the freeze, after it
    // was sent when it was signed; nothing is sent now, and nothing is said of whether it was made.
    const attempts = server.attempts.length;
    const tap = await again.store.sendHeldDeletion(old).then(() => "deleted", (x: unknown) => x);
    expect(server.attempts.slice(attempts)).toEqual([]);
    saysOnly(tap, LOG_FROZEN);
  });

  it("a vault frozen before the change: refused before anything is sent, for every change of the vault's own actions", async () => {
    const { server, alice, bob, old } = await family();
    await bob.store.sync();
    contradictAtOwnRead(server, bob, old, "role");
    await alice.store.setMemberRole(old, C, "writer").catch(() => undefined);
    server.lieAbout = null;
    expect(alice.shared.logs.status(old).kind).toBe("frozen");
    const attempts = server.attempts.length;
    for (const act of [
      () => alice.store.setMemberRole(old, C, "reader"),
      () => alice.store.removeVaultMember(old, C),
      () => alice.store.offerTransfer(old, C),
      () => alice.store.deleteSharedVault(old),
    ]) {
      const e = await act().then(() => "done", (x: unknown) => x);
      expect((e as LogActionError).outcome).toMatchObject({ kind: "read_only", frozen: "unsent" });
      saysOnly(e, LOG_FROZEN_NOT_SENT);
    }
    expect(server.attempts.slice(attempts)).toEqual([]);
  });

  it("a vault whose history merely fails to check out (not frozen) keeps the general line", () => {
    saysOnly(new LogActionError({ kind: "read_only", vaultId: "v" }), LOG_READ_ONLY);
  });

  // ---- a member's leave of a frozen vault (allowed: the person's way out) ----

  const listed = (store: VaultStore, vaultId: string): boolean => store.vaults().some((v) => v.vaultId === vaultId);

  it("a vault frozen by its server's contradiction of bob's own leave: that leave says the frozen line; his next leave is stored, read back in the log, and the vault goes from the list at once, with no notice", async () => {
    const { server, alice, bob, old } = await family();
    server.leaveRevokes = true;
    await bob.store.sync();
    // Bob's leave is answered as stored at its position while alice's role change is stored there.
    server.lieAbout = "leave";
    server.beforeAppend = async (kind) => {
      if (kind !== "leave") return;
      server.beforeAppend = null;
      await alice.store.setMemberRole(old, C, "writer");
    };
    const first = await bob.store.leaveSharedVault(old).then(() => "left", (x: unknown) => x);
    server.lieAbout = null;
    expect(bob.shared.logs.status(old).kind).toBe("frozen");
    saysOnly(first, LOG_FROZEN);
    expect(listed(bob.store, old)).toBe(true);
    // The later entries of a vault frozen so still verify: the leave is read back, and it is a leave like any other.
    const second = await bob.store.leaveSharedVault(old).then(() => "left", (x: unknown) => x);
    expect(second).toBe("left");
    expect(server.appends[server.appends.length - 1]).toBe(`leave:${old}`);
    expect(listed(bob.store, old)).toBe(false);
    expect(bob.store.notices().filter((n) => n.vaultId === old)).toEqual([]);
    expect(bob.shared.logs.holds(old)).toBe(false);
  });

  /**
   * Bob's vault frozen by a fork: carol's leave, which bob verified, is taken out of the server's log and alice's role
   * change is stored in its place. Bob's verified history ends before that position for good, so a later read never
   * shows anything he sends.
   */
  async function bobFrozenByFork(bobCache?: VaultCache) {
    const { server, alice, bob, old, carolPerson } = await family(true, bobCache);
    const carol = await browser(server, carolPerson, [contact(alice.person, "Alice")]);
    expect((await carol.shared.answer(carol.shared.pendingAsks()[0]!, true)).kind).toBe("adopted");
    await bob.store.sync();
    const at = server.logs.get(old)!.length;
    await carol.store.leaveSharedVault(old);
    await bob.store.sync();
    expect(bob.shared.logs.verifiedState(old)?.head.seq).toBe(at);
    server.logs.set(old, server.logs.get(old)!.slice(0, at));
    await alice.store.setMemberRole(old, C, "writer");
    await bob.store.sync();
    expect(bob.shared.logs.status(old)).toMatchObject({ kind: "frozen", atSeq: at });
    expect(listed(bob.store, old)).toBe(true);
    server.leaveRevokes = true;
    return { server, alice, bob, old };
  }

  /**
   * Bob's vault frozen because his account's record of it names another genesis (a read with nothing new to fetch stops
   * there): his verified history keeps its head, so a leave he signs lands at the server's next position, and no read
   * here shows it afterwards.
   */
  async function bobFrozenByRecord(bobCache?: VaultCache) {
    const { server, alice, bob, old } = await family(true, bobCache);
    await bob.store.sync();
    await bob.shared.accountState.update((doc) => {
      const rec = doc.vaults.get(old)!;
      return { ...doc, vaults: new Map([...doc.vaults, [old, { ...rec, genesisHash: "ab".repeat(32) }]]) };
    });
    await bob.shared.logs.refresh(old, null, null, true);
    expect(bob.shared.logs.status(old)).toMatchObject({ kind: "frozen", atSeq: 0 });
    expect(listed(bob.store, old)).toBe(true);
    server.leaveRevokes = true;
    return { server, alice, bob, old };
  }

  it("a leave of a vault frozen before it, which the server stores and answers naming it: says that the server took it and that this browser can no longer check the vault, never 'nothing changed'; the removal at the next sync says that the person left it here, and keeps a held copy", async () => {
    const { server, bob, old } = await bobFrozenByRecord();
    const e = await bob.store.leaveSharedVault(old).then(() => "left", (x: unknown) => x);
    expect(server.appends[server.appends.length - 1]).toBe(`leave:${old}`);
    expect(server.grants.get(old)!.get(B)!.revoked).toBe(true);
    // On the code before: LOG_READ_ONLY ("… right now … Nothing changed").
    expect((e as LogActionError).outcome).toMatchObject({ kind: "read_only", leave: "stored" });
    saysOnly(e, LOG_LEAVE_FROZEN_TAKEN);
    // The row stays until the next sync (the leave cannot be read back here); nothing of it is held.
    expect(listed(bob.store, old)).toBe(true);
    expect(bob.shared.logs.holds(old)).toBe(false);
    await bob.store.sync();
    // The server's removal cannot be read in a log that does not verify, so it is never quiet: the notice says that the
    // person left the vault here (the server's answer named the leave) and that nothing since can be checked, and the
    // copy is held. Earlier: quiet, with no notice and no held copy.
    expect(listed(bob.store, old)).toBe(false);
    expect(bob.store.notices().filter((n) => n.vaultId === old).map((n) => n.kind)).toEqual(["left-frozen"]);
    expect(bob.store.heldVaults().map((h) => h.vaultId)).toEqual([old]);
  });

  it("an own leave of a frozen vault that the server took, learned at the next sync after a reload of a browser with the offline copy: the own-leave notice and a held copy", async () => {
    (globalThis as { indexedDB?: IDBFactory }).indexedDB = new FakeIDBFactory() as unknown as IDBFactory;
    const { server, bob, old } = await bobFrozenByRecord(await openVaultCache(B));
    const e = await bob.store.leaveSharedVault(old).then(() => "left", (x: unknown) => x);
    saysOnly(e, LOG_LEAVE_FROZEN_TAKEN);
    // The removal reaches a reloaded tab: the vault was listed there from the offline copy, and its first sync learns it.
    const again = await browser(server, bob.person, bob.contacts, await openVaultCache(B), bob.profile);
    // Earlier: quiet, with no notice and no held copy.
    expect(listed(again.store, old)).toBe(false);
    expect(again.store.notices().filter((n) => n.vaultId === old).map((n) => n.kind)).toEqual(["left-frozen"]);
    expect(again.store.heldVaults().map((h) => h.vaultId)).toEqual([old]);
    // Every item the offline copy held is in the held copy, opened through the person's own wrap at the removal.
    expect(again.store.heldVaults()[0]!.itemCount).toBe([...server.items.values()].filter((i) => i.vaultId === old && !i.deleted).length);
    expect(again.store.heldVaults()[0]!.itemCount).toBeGreaterThan(0);
  });

  it("a leave of a frozen vault whose answer was lost while the server took it: the removal at the next sync cannot be tied to the person's own act, so its notice stays", async () => {
    const { server, bob, old } = await bobFrozenByRecord();
    server.noAnswer = { kind: "leave", store: true };
    const e = await bob.store.leaveSharedVault(old).then(() => "left", (x: unknown) => x);
    server.noAnswer = null;
    saysOnly(e, LOG_LEAVE_FROZEN_UNKNOWN);
    expect(server.grants.get(old)!.get(B)!.revoked).toBe(true);
    await bob.store.sync();
    expect(listed(bob.store, old)).toBe(false);
    expect(bob.store.notices().filter((n) => n.vaultId === old).map((n) => n.kind)).toEqual(["anomaly"]);
    expect(bob.store.heldVaults().map((h) => h.vaultId)).toEqual([old]);
  });

  it("a removal of a frozen vault after a leave the server refused is no act of the person's: its notice stays", async () => {
    const { server, bob, old } = await bobFrozenByRecord();
    server.slowDown = "leave";
    saysOnly(await bob.store.leaveSharedVault(old).then(() => "left", (x: unknown) => x), LOG_LEAVE_FROZEN_REFUSED);
    server.slowDown = null;
    // The owner removes bob afterwards: the log here cannot show it.
    server.grants.get(old)!.get(B)!.revoked = true;
    await bob.store.sync();
    expect(listed(bob.store, old)).toBe(false);
    expect(bob.store.notices().filter((n) => n.vaultId === old).map((n) => n.kind)).toEqual(["anomaly"]);
  });

  it("the members' line of a frozen vault says that it is frozen, never that its history doesn't check out 'right now'", async () => {
    for (const frozen of [bobFrozenByRecord, bobFrozenByFork]) {
      const { bob, old } = await frozen();
      const r = bob.store.memberRoster(old)!;
      expect(r.frozen).toBe(true);
      // On the code before: ROSTER_STALE ("This shared vault's history doesn't check out right now. …").
      expect(rosterNoteText(r)).toBe(ROSTER_FROZEN);
      expect(rosterNoteText(r)).not.toBe(ROSTER_STALE);
    }
    // A log that only fails to verify, or is withheld, keeps the general line; a verified one says nothing.
    expect(rosterNoteText({ rows: [], mayBeIncomplete: false, stale: true, frozen: false })).toBe(ROSTER_STALE);
    expect(rosterNoteText({ rows: [], mayBeIncomplete: false, stale: false, frozen: false })).toBeNull();
  });

  // A record that names another genesis is not this vault's chain (decided on 23 November 2026): the session that froze
  // it keeps the key it held, and a reload takes none. Nothing is sent by either reload.
  for (const offline of [false, true]) {
    it(`a vault frozen by a record of another genesis is not listed after a reload (${offline ? "with" : "without"} the offline copy): no key is taken, and still frozen`, async () => {
      if (offline) (globalThis as { indexedDB?: IDBFactory }).indexedDB = new FakeIDBFactory() as unknown as IDBFactory;
      const cache = async (): Promise<VaultCache | undefined> => (offline ? await openVaultCache(B) : undefined);
      const { server, bob, old } = await bobFrozenByRecord(await cache());
      expect(listed(bob.store, old)).toBe(true);
      const attempts = server.attempts.length;
      const again = await browser(server, bob.person, bob.contacts, await cache(), bob.profile);
      expect(again.shared.logs.status(old).kind).toBe("frozen");
      expect(again.account.logKeyRing().has(old), "no key after the reload").toBe(false);
      expect(listed(again.store, old), "not listed after the reload").toBe(false);
      expect(server.attempts.slice(attempts).filter((a) => a.endsWith(`:${old}`))).toEqual([]);
      const third = await browser(server, bob.person, bob.contacts, await cache(), bob.profile);
      expect(listed(third.store, old)).toBe(false);
    });
  }

  for (const [what, frozenBy] of [["frozen by a fork", "fork"]] as const) {
    for (const offline of [false, true]) {
      it(`a vault ${what} stays listed after a reload (${offline ? "with" : "without"} the offline copy), with its items, and still frozen`, async () => {
        if (offline) (globalThis as { indexedDB?: IDBFactory }).indexedDB = new FakeIDBFactory() as unknown as IDBFactory;
        const cache = async (): Promise<VaultCache | undefined> => (offline ? await openVaultCache(B) : undefined);
        const { server, bob, old } = frozenBy === "fork" ? await bobFrozenByFork(await cache()) : await bobFrozenByRecord(await cache());
        expect(listed(bob.store, old)).toBe(true);
        const attempts = server.attempts.length;
        const again = await browser(server, bob.person, bob.contacts, await cache(), bob.profile);
        expect(again.shared.logs.status(old).kind).toBe("frozen");
        expect(listed(again.store, old), "listed after the reload").toBe(true);
        expect(names(again.store, old)).toEqual(["bank", "deeds"]);
        expect(again.store.memberRoster(old)?.frozen).toBe(true);
        // Nothing was signed or sent on the frozen vault's log by the reload.
        expect(server.attempts.slice(attempts).filter((a) => a.endsWith(`:${old}`))).toEqual([]);
        // A second reload, too.
        const third = await browser(server, bob.person, bob.contacts, await cache(), bob.profile);
        expect(listed(third.store, old)).toBe(true);
      });
    }
  }

  it("a leave of a vault frozen by a fork, answered as stored at a position where this browser verified another entry: the answer is contradicted, so andvari can't tell, never 'taken'", async () => {
    const { server, bob, old } = await bobFrozenByFork();
    server.lieAbout = "leave";
    const e = await bob.store.leaveSharedVault(old).then(() => "left", (x: unknown) => x);
    server.lieAbout = null;
    // On the code before: LOG_READ_ONLY.
    saysOnly(e, LOG_LEAVE_FROZEN_UNKNOWN);
    expect(listed(bob.store, old)).toBe(true);
  });

  it("a leave of a vault frozen before it, which the server refuses: says it was refused, never that it is sent again; nothing is sent again, and the vault stays listed", async () => {
    const { server, bob, old } = await bobFrozenByRecord();
    server.slowDown = "leave";
    const e = await bob.store.leaveSharedVault(old).then(() => "left", (x: unknown) => x);
    server.slowDown = null;
    // On the code before: ChangeNotStoredError, LOG_NOT_STORED ("andvari sends it again the next time you unlock").
    saysOnly(e, LOG_LEAVE_FROZEN_REFUSED);
    const tries = server.attempts.filter((a) => a === `leave:${old}`).length;
    const again = await browser(server, bob.person, bob.contacts, undefined, bob.profile);
    await again.store.resendHeldChanges();
    expect(server.attempts.filter((a) => a === `leave:${old}`).length, "nothing sent again").toBe(tries);
    await bob.store.sync();
    expect(listed(bob.store, old)).toBe(true);
    expect(bob.shared.logs.status(old).kind).toBe("frozen");
  });

  for (const [what, frozenBy] of [
    ["frozen by its record", "record"],
    ["frozen by a fork", "fork"],
  ] as const) {
    it(`a leave of a vault ${what} before it, whose answer never comes: says andvari can't tell whether the server took it, never that it is sent again; nothing is sent again`, async () => {
      const { server, bob, old } = frozenBy === "record" ? await bobFrozenByRecord() : await bobFrozenByFork();
      server.noAnswer = { kind: "leave", store: false };
      const e = await bob.store.leaveSharedVault(old).then(() => "left", (x: unknown) => x);
      server.noAnswer = null;
      // On the code before: ChangeNotStoredError, LOG_UNKNOWN ("It sends it again the next time you unlock").
      saysOnly(e, LOG_LEAVE_FROZEN_UNKNOWN);
      const tries = server.attempts.filter((a) => a === `leave:${old}`).length;
      const again = await browser(server, bob.person, bob.contacts, undefined, bob.profile);
      await again.store.resendHeldChanges();
      expect(server.attempts.filter((a) => a === `leave:${old}`).length, "nothing sent again").toBe(tries);
    });
  }

  it("a decline (a leave) of a shared vault frozen while it was offered, whose answer never comes: never 'it tries again the next time you unlock'; nothing is sent again", async () => {
    const { server, alice, bob, old, carolPerson } = await family();
    const carol = await browser(server, carolPerson, [contact(alice.person, "Alice")]);
    const [ask] = carol.shared.pendingAsks();
    expect(ask).toBeDefined();
    // A fork in carol's view: bob's leave, which she verified, is taken out and alice's change stored in its place.
    const at = server.logs.get(old)!.length;
    await bob.store.leaveSharedVault(old);
    await carol.store.sync();
    server.logs.set(old, server.logs.get(old)!.slice(0, at));
    await alice.store.setMemberRole(old, B, "reader");
    await carol.store.sync();
    expect(carol.shared.logs.status(old)).toMatchObject({ kind: "frozen", atSeq: at });
    server.noAnswer = { kind: "leave", store: false };
    const answered = await carol.shared.answer(carol.shared.pendingAsks()[0] ?? ask!, false);
    server.noAnswer = null;
    // Earlier: { leave: "waiting" }, SHARE_DECLINE_WAITING ("which it tries again the next time you unlock"); then the
    // decline's general line, SHARE_DECLINE_NOT_STORED ("… until it goes through"), which nothing here makes true.
    expect(answered).toMatchObject({ kind: "declined", leave: "not_stored", frozen: "unknown" });
    expect(shareAnswerText(answered)).toBe(SHARE_DECLINE_FROZEN_UNKNOWN);
    expect(shareAnswerText(answered)).not.toBe(SHARE_DECLINE_NOT_STORED);
    // A decline whose answer was lost on a vault that is not frozen keeps the general line.
    expect(shareAnswerText({ kind: "declined", vaultId: old, leave: "not_stored" })).toBe(SHARE_DECLINE_NOT_STORED);
    const tries = server.attempts.filter((a) => a === `leave:${old}`).length;
    const again = await browser(server, carolPerson, [contact(alice.person, "Alice")], undefined, carol.profile);
    await again.store.resendHeldChanges();
    expect(server.attempts.filter((a) => a === `leave:${old}`).length, "nothing sent again").toBe(tries);
  });
});
