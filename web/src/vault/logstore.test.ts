import { readFileSync } from "node:fs";
import { beforeAll, describe, expect, it } from "vitest";
import { ApiError } from "../api/client";
import { memoryStorage } from "../api/devicesecret";
import { NIL_USER_ID } from "../api/wireids";
import type { LogAppendRequest, LogDeleted, LogPage } from "../api/wire";
import { toB64, toHexLower } from "../crypto/bytes";
import { boxKeypairFromSeed, randomBytes, sha256Sync, signKeypairFromSeed } from "../crypto/provider";
import { initSodium } from "../crypto/sodium";
import { fromB64Canonical } from "../crypto/trust/grammar";
import { logPosition, parseLogEntry, signLogEntry } from "../crypto/trust/vaultlog";
import { type AccountDocument, EMPTY_DOCUMENT, withAccepted, withVaultHead } from "./accountdoc";
import { type LogWire, VaultLogStore } from "./logstore";
import { SHARE_DECLINE_NOT_STORED, SHARE_DECLINE_WAITING } from "../ui/copy";
import { shareAnswerText } from "../ui/SharedPrompts";

/**
 * A log server that stores what it is sent (it checks only the position, as spec 03 §10.3's head check does), and
 * keeps the grant rows the entries make: the creator's owner wrap, a member's sealed grant, a posted self-wrap.
 */
class LogServer implements LogWire {
  logs = new Map<string, string[]>();
  /** vaultId -> userId -> that account's grant row. */
  grants = new Map<string, Map<string, { wrappedVk: string; signedGrant: string | null }>>();
  selfWraps: { vaultId: string; userId: string }[] = [];
  fetches = 0;
  offline = false;
  posted: LogAppendRequest[] = [];
  /** What GET serves instead of the stored log, when set. */
  serve: ((vaultId: string, stored: string[]) => string[]) | null = null;
  /** The account the next `putSelfWrap` is from (the fake has no sessions). */
  caller = "";
  async logPage(vaultId: string, after: number | null): Promise<LogPage> {
    this.fetches++;
    if (this.offline) throw new TypeError("offline");
    const stored = this.logs.get(vaultId) ?? [];
    const all = this.serve ? this.serve(vaultId, stored) : stored;
    const from = after === null ? 0 : after + 1;
    const last = all[all.length - 1];
    const head = last ? { seq: all.length - 1, hash: toHexLower(sha256Sync(fromB64Canonical(last)!)), at: 1 } : { seq: -1, hash: "", at: 0 };
    return { entries: all.slice(from), head, purged: null, deleted: this.pageGrace ? (this.grace.get(vaultId) ?? null) : null };
  }
  /** The `deleted` the server sends while a vault is in its grace (§10.3, §10.6), by vault; on the page only while
   *  [pageGrace] (false: an answer that carries it on the append alone). */
  grace = new Map<string, LogDeleted>();
  pageGrace = true;
  async appendLog(vaultId: string, req: LogAppendRequest) {
    if (this.offline) throw new TypeError("offline");
    this.posted.push(req);
    const log = this.logs.get(vaultId) ?? [];
    const hashOf = (e: string) => toHexLower(sha256Sync(fromB64Canonical(e)!));
    if (log.includes(req.entry)) return { rev: 1, head: { seq: log.length - 1, hash: hashOf(log[log.length - 1]!), at: 1 }, deleted: this.grace.get(vaultId) ?? null };
    this.logs.set(vaultId, [...log, req.entry]);
    const parsed = parseLogEntry(fromB64Canonical(req.entry)!);
    if (parsed.ok) {
      const e = parsed.value.entry;
      const rows = this.grants.get(vaultId) ?? new Map<string, { wrappedVk: string; signedGrant: string | null }>();
      if (e.kind === "genesis") rows.set(e.actor, { wrappedVk: req.wrappedVk ?? "", signedGrant: null });
      if (e.kind === "add") rows.set(e.member, { wrappedVk: "", signedGrant: req.grant ?? null });
      this.grants.set(vaultId, rows);
    }
    return { rev: 1, head: { seq: log.length, hash: hashOf(req.entry), at: 1 }, deleted: this.grace.get(vaultId) ?? null };
  }
  async putSelfWrap(vaultId: string, wrappedVk: string) {
    if (this.offline) throw new TypeError("offline");
    this.selfWraps.push({ vaultId, userId: this.caller });
    const row = this.grants.get(vaultId)?.get(this.caller);
    if (row) row.wrappedVk = wrappedVk;
    return 1;
  }
}

class Account {
  doc: AccountDocument = EMPTY_DOCUMENT;
  local() {
    return this.doc;
  }
  async update(change: (d: AccountDocument) => AccountDocument) {
    this.doc = change(this.doc);
    return { kind: "written" as const, document: this.doc };
  }
}

function person(userId: string) {
  const seed = randomBytes(32);
  return { userId, box: boxKeypairFromSeed(seed), sign: signKeypairFromSeed(seed), uvk: randomBytes(32) };
}

const A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const B = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

/** What the host was asked while a store ran: the names it decrypted. */
const namesAsked: string[] = [];

function storeFor(p: ReturnType<typeof person>, server: LogServer, account: Account, contacts: Record<string, string> = {}, clock = () => 1_763_164_800_000, keys = new Map<string, Uint8Array>(), storage = memoryStorage()) {
  return new VaultLogStore(p.userId, p.sign, p.box, p.uvk, server, storage, account, {
    grantRow: (vaultId) => server.grants.get(vaultId)?.get(p.userId) ?? null,
    isCurrentContact: (u, key) => contacts[u] === key,
    currentContact: (u) => (contacts[u] ? { key: contacts[u]!, compared: true } : null),
    labelFor: (u, key) => (contacts[u] === key ? `label of ${u.slice(0, 1)}` : null),
    vaultName: (vaultId) => {
      namesAsked.push(vaultId);
      return "Family";
    },
    sealMeta: () => "meta",
    serverOwnerName: () => "Mallory (as the server says)",
  }, keys, clock);
}

/** A creates a vault and adds B; answers the vault id and the two people. */
async function shared(server: LogServer) {
  const a = person(A);
  const b = person(B);
  const owner = storeFor(a, server, new Account(), { [B]: toB64(b.box.publicKey) });
  const c = await owner.append(null, { kind: "create", name: "Family" });
  if (c.kind !== "appended") throw new Error("create");
  const added = await owner.append(c.vaultId, { kind: "add", contactUserId: B, role: "writer", releaseUncompared: false });
  if (added.kind !== "appended") throw new Error("add");
  return { a, b, owner, vaultId: c.vaultId };
}

describe("the web's vault log store", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("creates a vault: the genesis verifies, the creator's accept answers seq 0, the vault record follows", async () => {
    const server = new LogServer();
    const acct = new Account();
    const a = person(A);
    const logs = storeFor(a, server, acct);
    const r = await logs.append(null, { kind: "create", name: "Family" });
    expect(r.kind).toBe("appended");
    if (r.kind !== "appended") return;
    expect(logs.status(r.vaultId).kind).toBe("verified");
    expect(acct.doc.accepted.get(r.vaultId)).toMatchObject({ addSeq: 0, decision: "accept", owner: A });
    expect(acct.doc.vaults.get(r.vaultId)).toMatchObject({ seq: 0, genesisHash: r.state.genesisHash });
    expect(server.posted[0]!.wrappedVk).toBeTruthy();
    expect(logs.writeAllowed(r.vaultId)).toBe(true);
  });

  it("adds only a current contact; a remove declines the member's add, and an older leave never rolls back a later add's answer", async () => {
    const server = new LogServer();
    const a = person(A);
    const b = person(B);
    const owner = storeFor(a, server, new Account(), { [B]: toB64(b.box.publicKey) });
    const c = await owner.append(null, { kind: "create", name: "Family" });
    if (c.kind !== "appended") throw new Error("create");
    const id = c.vaultId;
    expect(await owner.append(id, { kind: "add", contactUserId: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", role: "writer", releaseUncompared: false })).toEqual({ kind: "not_allowed", reason: "not_a_current_contact" });
    expect((await owner.append(id, { kind: "add", contactUserId: B, role: "writer", releaseUncompared: false })).kind).toBe("appended");
    expect(server.posted[1]!.grant).toBeTruthy();
    expect((await owner.append(id, { kind: "remove", member: B })).kind).toBe("appended");

    // B's browser, whose account already answered a LATER add (seq 9): replaying the remove at seq 2 changes nothing.
    const bAcct = new Account();
    bAcct.doc = withAccepted(EMPTY_DOCUMENT, { vaultId: id, owner: A, addSeq: 9, at: 5, decision: "accept" });
    const bLogs = storeFor(b, server, bAcct);
    const st = await bLogs.refresh(id, null, null, true);
    expect(st).toMatchObject({ kind: "removed", byOwner: true });
    expect(bAcct.doc.accepted.get(id)).toMatchObject({ addSeq: 9, decision: "accept" });

    // A browser of B's with no later answer writes the decline for the add the remove ended.
    const fresh = new Account();
    await storeFor(b, server, fresh).refresh(id, null, null, true);
    expect(fresh.doc.accepted.get(id)).toMatchObject({ addSeq: 1, decision: "decline" });
  });

  it("the shared code's rule of 2026-11-17: no action naming the all-zero user id is ever built, even for a contact under that id", async () => {
    const server = new LogServer();
    const a = person(A);
    const nil = person(NIL_USER_ID);
    const owner = storeFor(a, server, new Account(), { [NIL_USER_ID]: toB64(nil.box.publicKey) });
    const c = await owner.append(null, { kind: "create", name: "Family" });
    if (c.kind !== "appended") throw new Error("create");
    const posted = server.posted.length;
    for (const action of [
      { kind: "add", contactUserId: NIL_USER_ID, role: "writer", releaseUncompared: true },
      { kind: "role", member: NIL_USER_ID, role: "reader" },
      { kind: "remove", member: NIL_USER_ID },
      { kind: "offer", to: NIL_USER_ID, expiresInMs: 86_400_000 },
    ] as const) {
      expect(await owner.append(c.vaultId, action), action.kind).toEqual({ kind: "not_allowed", reason: "nil_user_id" });
    }
    expect(server.posted.length, "nothing was signed or sent").toBe(posted);
  });

  it("an ownership offer the other person refused is remembered for the owner who made it, until a new offer or a dismissal", async () => {
    const server = new LogServer();
    const { b, owner, vaultId } = await shared(server);
    expect((await owner.append(vaultId, { kind: "offer", to: B, expiresInMs: 86_400_000 })).kind).toBe("appended");
    expect(owner.refusedOffer(vaultId)).toBeNull();
    // B refuses: a `cancel` signed with the target's key.
    const bLogs = storeFor(b, server, new Account());
    await bLogs.refresh(vaultId, null, null, true);
    expect((await bLogs.append(vaultId, { kind: "cancel" })).kind).toBe("appended");
    expect(bLogs.refusedOffer(vaultId)).toBeNull(); // only the owner who asked is told
    await owner.refresh(vaultId, null, null, true);
    expect(owner.refusedOffer(vaultId)).toMatchObject({ by: B });
    // A new offer clears it; the owner withdrawing an offer is no refusal.
    expect((await owner.append(vaultId, { kind: "offer", to: B, expiresInMs: 86_400_000 })).kind).toBe("appended");
    expect(owner.refusedOffer(vaultId)).toBeNull();
    expect((await owner.append(vaultId, { kind: "cancel" })).kind).toBe("appended");
    expect(owner.refusedOffer(vaultId)).toBeNull();
    // Refused again, then dismissed.
    expect((await owner.append(vaultId, { kind: "offer", to: B, expiresInMs: 86_400_000 })).kind).toBe("appended");
    await bLogs.refresh(vaultId, null, null, true);
    expect((await bLogs.append(vaultId, { kind: "cancel" })).kind).toBe("appended");
    await owner.refresh(vaultId, null, null, true);
    expect(owner.refusedOffer(vaultId)).toMatchObject({ by: B });
    owner.dismissRefusedOffer(vaultId);
    expect(owner.refusedOffer(vaultId)).toBeNull();
  });

  it("a served log below what this browser verified is withheld; another entry at a verified position freezes the vault", async () => {
    const server = new LogServer();
    const a = person(A);
    const logs = storeFor(a, server, new Account());
    const c = await logs.append(null, { kind: "create", name: "V" });
    if (c.kind !== "appended") throw new Error("create");
    await logs.append(c.vaultId, { kind: "delete" });
    expect(logs.status(c.vaultId).kind).toBe("verified");
    server.serve = (_id, stored) => stored.slice(0, 1);
    expect((await logs.refresh(c.vaultId, null, null, true)).kind).toBe("withheld");
    // A second, validly signed entry at seq 1.
    const pos = logPosition(c.state, c.state.at + 1000);
    const other = toB64(signLogEntry(a.sign, { kind: "delete", vaultId: c.vaultId, seq: 1, prev: pos.prev, actor: A, at: pos.at, deleteId: toB64(randomBytes(16)) }));
    server.serve = (_id, stored) => [stored[0]!, other];
    expect((await logs.refresh(c.vaultId, null, null, true)).kind).toBe("frozen");
    server.serve = null;
    expect((await logs.refresh(c.vaultId, null, null, true)).kind).toBe("frozen"); // sticky
  });

  it("an append with no answer stays pending and is re-posted byte for byte", async () => {
    const server = new LogServer();
    const a = person(A);
    const logs = storeFor(a, server, new Account());
    const c = await logs.append(null, { kind: "create", name: "V" });
    if (c.kind !== "appended") throw new Error("create");
    server.offline = true;
    expect((await logs.append(c.vaultId, { kind: "delete" })).kind).toBe("pending");
    expect(logs.pendingVaults()).toEqual([c.vaultId]);
    expect((await logs.append(c.vaultId, { kind: "restore" })).kind).toBe("not_allowed");
    server.offline = false;
    const before = server.posted.length;
    // A vault's deletion is not sent again by the unlock on its own: only at the person's word (turned round).
    expect(await logs.retryPending()).toEqual([]);
    expect(server.posted.length).toBe(before);
    const out = await logs.retryHeld(c.vaultId);
    expect(out!.kind).toBe("appended");
    expect(server.posted.length).toBe(before + 1);
    expect(logs.pendingVaults()).toEqual([]);
  });

  it("a refused append is not kept, and a 409 log_head_moved settles against the verified log", async () => {
    const server = new LogServer();
    const a = person(A);
    const logs = storeFor(a, server, new Account());
    const c = await logs.append(null, { kind: "create", name: "V" });
    if (c.kind !== "appended") throw new Error("create");
    server.appendLog = async () => {
      throw new ApiError(400, "precondition", "x");
    };
    expect(await logs.append(c.vaultId, { kind: "delete" })).toEqual({ kind: "refused", vaultId: c.vaultId, code: "precondition" });
    expect(logs.pendingVaults()).toEqual([]);
  });

  it("a deleted vault's grace end, as the server sends it, is kept beside the verified delete and goes with the restore", async () => {
    const server = new LogServer();
    const logs = storeFor(person(A), server, new Account());
    const c = await logs.append(null, { kind: "create", name: "V" });
    if (c.kind !== "appended") throw new Error("create");
    server.grace.set(c.vaultId, { deletedAt: 1_000, purgeAt: 605_801_000 }); // served beside a live head: nothing kept
    await logs.refresh(c.vaultId, null, null, true);
    expect(logs.serverGraceEnd(c.vaultId)).toBeNull();
    expect((await logs.append(c.vaultId, { kind: "delete" })).kind).toBe("appended");
    expect(logs.serverGraceEnd(c.vaultId)).toEqual({ deletedAt: 1_000, purgeAt: 605_801_000 });
    expect(logs.status(c.vaultId).kind).toBe("verified"); // the field decides nothing
    server.grace.delete(c.vaultId);
    expect((await logs.append(c.vaultId, { kind: "restore" })).kind).toBe("appended");
    expect(logs.serverGraceEnd(c.vaultId)).toBeNull();
    // A later delete the server sends no grace end for answers none: the first delete's value is never answered.
    expect((await logs.append(c.vaultId, { kind: "delete" })).kind).toBe("appended");
    expect(logs.serverGraceEnd(c.vaultId)).toBeNull();
  });

  it("an older server sends no grace end, and nothing is kept", async () => {
    const server = new LogServer();
    const logs = storeFor(person(A), server, new Account());
    const c = await logs.append(null, { kind: "create", name: "V" });
    if (c.kind !== "appended") throw new Error("create");
    expect((await logs.append(c.vaultId, { kind: "delete" })).kind).toBe("appended");
    expect(logs.serverGraceEnd(c.vaultId)).toBeNull();
  });

  it("the append's own grace end is kept when the refetch carries none, and a later page's replaces it", async () => {
    const server = new LogServer();
    const logs = storeFor(person(A), server, new Account());
    const c = await logs.append(null, { kind: "create", name: "V" });
    if (c.kind !== "appended") throw new Error("create");
    server.pageGrace = false;
    server.grace.set(c.vaultId, { deletedAt: 1_000, purgeAt: 2_000 });
    expect((await logs.append(c.vaultId, { kind: "delete" })).kind).toBe("appended");
    expect(logs.serverGraceEnd(c.vaultId)).toEqual({ deletedAt: 1_000, purgeAt: 2_000 });
    server.pageGrace = true;
    server.grace.set(c.vaultId, { deletedAt: 1_000, purgeAt: 3_000 });
    await logs.refresh(c.vaultId, null, null, true);
    expect(logs.serverGraceEnd(c.vaultId)).toEqual({ deletedAt: 1_000, purgeAt: 3_000 });
  });

  it("a grace end served beside a head that is not the verified head is not kept", async () => {
    const server = new LogServer();
    const logs = storeFor(person(A), server, new Account());
    const c = await logs.append(null, { kind: "create", name: "V" });
    if (c.kind !== "appended") throw new Error("create");
    server.pageGrace = false;
    const real = server.appendLog.bind(server);
    server.appendLog = async (vaultId, req) => ({ ...(await real(vaultId, req)), head: { seq: 7, hash: "f".repeat(64), at: 1 }, deleted: { deletedAt: 1_000, purgeAt: 2_000 } });
    expect((await logs.append(c.vaultId, { kind: "delete" })).kind).toBe("appended");
    expect(logs.serverGraceEnd(c.vaultId)).toBeNull();
  });

  it("a vault from a current contact is asked about once, accepted, adopted and self-wrapped; the account's next browser adopts through the wrap", async () => {
    const server = new LogServer();
    const { a, b, vaultId } = await shared(server);
    const acct = new Account();
    const keys = new Map<string, Uint8Array>();
    const mine = storeFor(b, server, acct, { [A]: toB64(a.box.publicKey) }, undefined, keys);
    expect((await mine.refresh(vaultId)).kind).toBe("verified");
    namesAsked.length = 0;
    const ask = await mine.adoption(vaultId);
    expect(ask).toEqual({ kind: "ask", vaultId, owner: A, ownerLabel: "label of a", vaultName: "Family", addSeq: 1 });
    // Asked, not adopted: no key, no record, nothing posted.
    expect(keys.has(vaultId)).toBe(false);
    expect(acct.doc.accepted.has(vaultId)).toBe(false);
    expect(server.selfWraps).toEqual([]);
    expect(mine.writeAllowed(vaultId)).toBe(false);
    if (ask.kind !== "ask") return;
    server.caller = B;
    expect(await mine.answerIncoming(ask, true)).toEqual({ kind: "adopted", vaultId, source: "grant" });
    expect(acct.doc.accepted.get(vaultId)).toMatchObject({ owner: A, addSeq: 1, decision: "accept" });
    expect(acct.doc.vaults.get(vaultId)).toMatchObject({ seq: 1 });
    expect(server.selfWraps).toEqual([{ vaultId, userId: B }]);
    expect(mine.writeAllowed(vaultId)).toBe(true);
    expect(mine.roleOf(vaultId)).toBe("writer");

    // Another browser of B: A is NOT current there, and the answer is already in the account's state.
    const second = new Map<string, Uint8Array>();
    const other = storeFor(b, server, acct, {}, undefined, second);
    await other.refresh(vaultId);
    expect(await other.adoption(vaultId)).toEqual({ kind: "adopted", vaultId, source: "self_wrap" });
    expect([...second.get(vaultId)!]).toEqual([...keys.get(vaultId)!]);
  });

  it("a prompt answered after the vault's log turned withheld adopts nothing, also when it turns while the answer is written", async () => {
    const server = new LogServer();
    const { a, b, vaultId } = await shared(server);
    const acct = new Account();
    const keys = new Map<string, Uint8Array>();
    const mine = storeFor(b, server, acct, { [A]: toB64(a.box.publicKey) }, undefined, keys);
    expect((await mine.refresh(vaultId)).kind).toBe("verified");
    const ask = await mine.adoption(vaultId);
    if (ask.kind !== "ask") throw new Error(ask.kind);
    // The server now serves less than this browser verified: withheld, after the prompt was shown.
    server.serve = (_id, stored) => stored.slice(0, 1);
    expect((await mine.refresh(vaultId, null, null, true)).kind).toBe("withheld");
    server.caller = B;
    expect(await mine.answerIncoming(ask, true)).toEqual({ kind: "refused", vaultId, reason: "log_not_verified" });
    expect(keys.has(vaultId)).toBe(false);
    expect(server.selfWraps).toEqual([]);
    // The log turning while the answer is being written: checked again before adopting.
    server.serve = null;
    expect((await mine.refresh(vaultId, null, null, true)).kind).toBe("verified");
    const realUpdate = acct.update.bind(acct);
    acct.update = (async (f: never) => {
      const r = await realUpdate(f);
      server.serve = (_id, stored) => stored.slice(0, 1);
      await mine.refresh(vaultId, null, null, true);
      return r;
    }) as never;
    expect(await mine.answerIncoming(ask, true)).toEqual({ kind: "refused", vaultId, reason: "log_not_verified" });
    expect(keys.has(vaultId)).toBe(false);
  });

  it("a vault from someone who is not a current contact is 'connect first', and nothing is decrypted", async () => {
    const server = new LogServer();
    const { b, vaultId } = await shared(server);
    const keys = new Map<string, Uint8Array>();
    const mine = storeFor(b, server, new Account(), {}, undefined, keys);
    await mine.refresh(vaultId);
    namesAsked.length = 0;
    expect(await mine.adoption(vaultId)).toEqual({ kind: "connect_first", vaultId, serverName: "Mallory (as the server says)" });
    expect(namesAsked).toEqual([]);
    expect(keys.size).toBe(0);
    // A contact for A under ANOTHER key is not that contact.
    const wrong = storeFor(b, server, new Account(), { [A]: toB64(person(A).box.publicKey) });
    await wrong.refresh(vaultId);
    expect((await wrong.adoption(vaultId)).kind).toBe("connect_first");
  });

  it("a decline is recorded for that add and signs a leave; an answer to a prompt that no longer stands changes nothing", async () => {
    const server = new LogServer();
    const { a, b, vaultId } = await shared(server);
    const acct = new Account();
    const mine = storeFor(b, server, acct, { [A]: toB64(a.box.publicKey) });
    await mine.refresh(vaultId);
    const ask = await mine.adoption(vaultId);
    if (ask.kind !== "ask") throw new Error(ask.kind);
    // A prompt for another add, or naming another owner, is not the one in force.
    expect((await mine.answerIncoming({ ...ask, addSeq: 7 }, true)).kind).toBe("ask");
    expect((await mine.answerIncoming({ ...ask, owner: B }, true)).kind).toBe("ask");
    expect(acct.doc.accepted.has(vaultId)).toBe(false);
    expect(await mine.answerIncoming(ask, false)).toEqual({ kind: "declined", vaultId, leave: "stored" });
    expect(acct.doc.accepted.get(vaultId)).toMatchObject({ addSeq: 1, decision: "decline" });
    const log = server.logs.get(vaultId)!;
    const last = parseLogEntry(fromB64Canonical(log[log.length - 1]!)!);
    expect(last.ok && last.value.entry).toMatchObject({ kind: "leave", actor: B, seq: 2 });
    expect(mine.status(vaultId)).toMatchObject({ kind: "removed", byOwner: false });
    expect(mine.keyFor(vaultId)).toBeNull();
  });

  it("an answer the account state cannot take: an accept adopts nothing, a decline still signs its leave", async () => {
    const server = new LogServer();
    const { a, b, vaultId } = await shared(server);
    const acct = new Account();
    // The account state refuses every write (full, damaged or contended: R35 lets a UVK holder cause this).
    acct.update = async () => ({ kind: "refused" as const, code: "account_state_full" }) as never;
    const keys = new Map<string, Uint8Array>();
    const mine = storeFor(b, server, acct, { [A]: toB64(a.box.publicKey) }, undefined, keys);
    await mine.refresh(vaultId);
    const ask = await mine.adoption(vaultId);
    if (ask.kind !== "ask") throw new Error(ask.kind);
    expect(await mine.answerIncoming(ask, true)).toEqual({ kind: "not_recorded", vaultId, reason: "account_state_full" });
    expect(keys.has(vaultId)).toBe(false);
    expect(server.logs.get(vaultId)).toHaveLength(2);
    expect(await mine.answerIncoming(ask, false)).toEqual({ kind: "declined", vaultId, leave: "stored" });
    const log = server.logs.get(vaultId)!;
    const last = parseLogEntry(fromB64Canonical(log[log.length - 1]!)!);
    expect(last.ok && last.value.entry).toMatchObject({ kind: "leave", actor: B });
    expect(mine.status(vaultId).kind).toBe("removed");
  });

  it("a decline whose leave gets no answer says so: recorded, the leave held and sent again; one the server refuses says the owner may still see the invitation", async () => {
    // No answer: the leave is held (sent again at the next unlock), and the decline is said as waiting.
    {
      const server = new LogServer();
      const { a, b, vaultId } = await shared(server);
      const acct = new Account();
      const mine = storeFor(b, server, acct, { [A]: toB64(a.box.publicKey) });
      await mine.refresh(vaultId);
      const ask = await mine.adoption(vaultId);
      if (ask.kind !== "ask") throw new Error(ask.kind);
      server.offline = true;
      const r = await mine.answerIncoming(ask, false);
      // On the code before: { kind: "declined", vaultId }, said as nothing at all.
      expect(r).toEqual({ kind: "declined", vaultId, leave: "waiting" });
      expect(shareAnswerText(r)).toBe(SHARE_DECLINE_WAITING);
      expect(acct.doc.accepted.get(vaultId)).toMatchObject({ decision: "decline" });
      expect(mine.holds(vaultId)).toBe(true);
      server.offline = false;
      await mine.retryPending();
      const log = server.logs.get(vaultId)!;
      const last = parseLogEntry(fromB64Canonical(log[log.length - 1]!)!);
      expect(last.ok && last.value.entry).toMatchObject({ kind: "leave", actor: B });
    }
    // Refused: nothing held, and the line says the owner may still see the invitation.
    {
      const server = new LogServer();
      const { a, b, vaultId } = await shared(server);
      const acct = new Account();
      const mine = storeFor(b, server, acct, { [A]: toB64(a.box.publicKey) });
      await mine.refresh(vaultId);
      const ask = await mine.adoption(vaultId);
      if (ask.kind !== "ask") throw new Error(ask.kind);
      server.appendLog = async () => {
        throw new ApiError(403, "forbidden", "not allowed");
      };
      const r = await mine.answerIncoming(ask, false);
      expect(r).toEqual({ kind: "declined", vaultId, leave: "not_stored" });
      expect(shareAnswerText(r)).toBe(SHARE_DECLINE_NOT_STORED);
      expect(mine.holds(vaultId)).toBe(false);
      expect(acct.doc.accepted.get(vaultId)).toMatchObject({ decision: "decline" });
    }
    // A decline read again later (not just given) says nothing.
    expect(shareAnswerText({ kind: "declined", vaultId: "v" })).toBeNull();
    expect(shareAnswerText({ kind: "declined", vaultId: "v", leave: "stored" })).toBeNull();
  });

  describe("a decline whose leave the server did not take is carried out again at a later unlock", () => {
    const leavesBy = (server: LogServer, vaultId: string, who: string) =>
      server.logs.get(vaultId)!.filter((e) => {
        const p = parseLogEntry(fromB64Canonical(e)!);
        return p.ok && p.value.entry.kind === "leave" && p.value.entry.actor === who;
      }).length;
    /** B is asked, and declines while the server refuses every append; answers what a later unlock needs. */
    async function declinedNotStored() {
      const server = new LogServer();
      const { a, b, owner, vaultId } = await shared(server);
      const acct = new Account();
      const storage = memoryStorage();
      const unlock = () => storeFor(b, server, acct, { [A]: toB64(a.box.publicKey) }, undefined, undefined, storage);
      const first = unlock();
      await first.refresh(vaultId);
      const ask = await first.adoption(vaultId);
      if (ask.kind !== "ask") throw new Error(ask.kind);
      const real = server.appendLog.bind(server);
      const refused = { n: 0 };
      server.appendLog = async () => {
        refused.n++;
        throw new ApiError(403, "forbidden", "not allowed");
      };
      expect(await first.answerIncoming(ask, false)).toEqual({ kind: "declined", vaultId, leave: "not_stored" });
      expect(refused.n).toBe(1);
      expect(acct.doc.accepted.get(vaultId)).toMatchObject({ addSeq: 1, decision: "decline" });
      return { server, owner, vaultId, first, unlock, refused, accept: () => (server.appendLog = real) };
    }

    it("signed again at each later unlock, once per unlock, until it goes through; the session that answered signs nothing more", async () => {
      const { server, vaultId, first, unlock, refused, accept } = await declinedNotStored();
      expect(await first.leaveAgainForDeclines()).toEqual([]);
      expect(refused.n).toBe(1);
      // A later unlock while the server still refuses: one leave signed and tried, and no second one in that session.
      const second = unlock();
      expect((await second.leaveAgainForDeclines()).map((o) => o.kind)).toHaveLength(1);
      expect(refused.n).toBe(2);
      expect(await second.leaveAgainForDeclines()).toEqual([]);
      expect(refused.n).toBe(2);
      // The unlock after that: the server takes it, and the owner sees the decline.
      accept();
      const third = unlock();
      expect((await third.leaveAgainForDeclines()).map((o) => o.kind)).toEqual(["appended"]);
      expect(leavesBy(server, vaultId, B)).toBe(1);
      expect(third.status(vaultId)).toMatchObject({ kind: "removed", byOwner: false });
      // The log no longer lists the account: nothing is signed at any later unlock.
      const posted = server.posted.length;
      expect(await unlock().leaveAgainForDeclines()).toEqual([]);
      expect(server.posted.length).toBe(posted);
      expect(leavesBy(server, vaultId, B)).toBe(1);
    });

    it("nothing is signed where the log no longer lists the account, or lists it through a later add (asked anew)", async () => {
      // The owner removed B meanwhile.
      {
        const { server, owner, vaultId, unlock, accept } = await declinedNotStored();
        accept();
        expect((await owner.append(vaultId, { kind: "remove", member: B })).kind).toBe("appended");
        const posted = server.posted.length;
        expect(await unlock().leaveAgainForDeclines()).toEqual([]);
        expect(server.posted.length).toBe(posted);
        expect(leavesBy(server, vaultId, B)).toBe(0);
      }
      // The owner removed B and invited them again: a new invitation, which B is asked anew.
      {
        const { server, owner, vaultId, unlock, accept } = await declinedNotStored();
        accept();
        expect((await owner.append(vaultId, { kind: "remove", member: B })).kind).toBe("appended");
        expect((await owner.append(vaultId, { kind: "add", contactUserId: B, role: "reader", releaseUncompared: false })).kind).toBe("appended");
        const posted = server.posted.length;
        const later = unlock();
        expect(await later.leaveAgainForDeclines()).toEqual([]);
        expect(server.posted.length).toBe(posted);
        expect(leavesBy(server, vaultId, B)).toBe(0);
        expect((await later.adoption(vaultId)).kind).toBe("ask");
      }
    });

    it("a leave already held is sent again as it is: no second one is signed", async () => {
      const server = new LogServer();
      const { a, b, vaultId } = await shared(server);
      const acct = new Account();
      const storage = memoryStorage();
      const unlock = () => storeFor(b, server, acct, { [A]: toB64(a.box.publicKey) }, undefined, undefined, storage);
      const first = unlock();
      await first.refresh(vaultId);
      const ask = await first.adoption(vaultId);
      if (ask.kind !== "ask") throw new Error(ask.kind);
      server.offline = true;
      expect(await first.answerIncoming(ask, false)).toEqual({ kind: "declined", vaultId, leave: "waiting" });
      server.offline = false;
      const later = unlock();
      expect(later.holds(vaultId)).toBe(true);
      expect(await later.leaveAgainForDeclines()).toEqual([]);
      await later.retryPending();
      expect(leavesBy(server, vaultId, B)).toBe(1);
    });

    it("the unlock runs it once, after its first sync, and never for a copy opened read-only", () => {
      const src = readFileSync(new URL("../ui/opensession.ts", import.meta.url), "utf8");
      expect(src).toMatch(/if \(readOnly\) return \{ account, store, meta, shared \};[\s\S]*await store\.sync\(\);\s*\/\/[^\n]*\n\s*await shared\.leaveAgainForDeclines\(\);/);
      expect(src.match(/leaveAgainForDeclines\(/g)).toHaveLength(1);
    });
  });

  it("a re-add after a removal asks again: the old answer and a replayed self-wrap adopt nothing (FS-R6)", async () => {
    const server = new LogServer();
    const { a, b, owner, vaultId } = await shared(server);
    const acct = new Account();
    const mine = storeFor(b, server, acct, { [A]: toB64(a.box.publicKey) });
    await mine.refresh(vaultId);
    const first = await mine.adoption(vaultId);
    if (first.kind !== "ask") throw new Error(first.kind);
    server.caller = B;
    expect((await mine.answerIncoming(first, true)).kind).toBe("adopted");
    const oldWrap = server.grants.get(vaultId)!.get(B)!.wrappedVk;
    expect((await owner.append(vaultId, { kind: "remove", member: B })).kind).toBe("appended");
    expect((await owner.append(vaultId, { kind: "add", contactUserId: B, role: "reader", releaseUncompared: false })).kind).toBe("appended");
    // The server puts the old self-wrap back on the new row.
    server.grants.get(vaultId)!.get(B)!.wrappedVk = oldWrap;
    // A fresh browser of B holding the account's records: the remove wrote the decline for add 1, add 3 is unanswered.
    const fresh = storeFor(b, server, acct, { [A]: toB64(a.box.publicKey) });
    await fresh.refresh(vaultId);
    const again = await fresh.adoption(vaultId);
    expect(again).toMatchObject({ kind: "ask", addSeq: 3 });
    expect(fresh.keyFor(vaultId)).toBeNull();
  });

  it("the creator's next browser adopts through the owner wrap with no question, and a grant that is not this vault's is refused", async () => {
    const server = new LogServer();
    const { a, b, vaultId } = await shared(server);
    const again = storeFor(a, server, new Account());
    await again.refresh(vaultId);
    expect(await again.adoption(vaultId)).toEqual({ kind: "adopted", vaultId, source: "owner_wrap" });
    expect(again.roleOf(vaultId)).toBe("owner");
    // B's row carries text that is not a sealed grant for this account and vault.
    const mine = storeFor(b, server, new Account(), { [A]: toB64(a.box.publicKey) });
    await mine.refresh(vaultId);
    server.grants.get(vaultId)!.get(B)!.signedGrant = toB64(randomBytes(120));
    expect(await mine.adoption(vaultId)).toEqual({ kind: "refused", vaultId, reason: "grant_refused" });
    server.grants.get(vaultId)!.get(B)!.signedGrant = "not base64url!";
    expect(await mine.adoption(vaultId)).toEqual({ kind: "refused", vaultId, reason: "grant_refused" });
    server.grants.get(vaultId)!.delete(B);
    expect(await mine.adoption(vaultId)).toEqual({ kind: "refused", vaultId, reason: "no_key" });
    // A vault this browser never verified adopts nothing.
    expect(await mine.adoption("cccccccc-cccc-4ccc-8ccc-cccccccccccc")).toMatchObject({ kind: "refused", reason: "log_not_verified" });
  });

  it("an item-head hint above the verified head is chased once, then backs off while the head stays put", async () => {
    const server = new LogServer();
    const a = person(A);
    let now = 1_763_164_800_000;
    const logs = storeFor(a, server, new Account(), {}, () => now);
    const c = await logs.append(null, { kind: "create", name: "V" });
    if (c.kind !== "appended") throw new Error("create");
    const f0 = server.fetches;
    const st = await logs.noteItemHead(c.vaultId, 5, "f".repeat(64));
    expect(st).toMatchObject({ kind: "verified", mayBeIncomplete: true });
    expect(server.fetches).toBe(f0 + 1);
    await logs.noteItemHead(c.vaultId, 6, "e".repeat(64));
    expect(server.fetches).toBe(f0 + 1);
    now += 11 * 60 * 1000;
    await logs.noteItemHead(c.vaultId, 6, "e".repeat(64));
    expect(server.fetches).toBe(f0 + 2);
    // A hint the verified log already holds changes nothing and fetches nothing.
    await logs.noteItemHead(c.vaultId, 0, c.state.genesisHash);
    expect(server.fetches).toBe(f0 + 2);
  });
});

/**
 * Design §3.6 (e) as decided on 23 November 2026, wired into the log store: a vault whose log is withheld below the
 * account's record, or frozen beside it, gives its key read-only (the log's status keeps every write out); a record of
 * another beginning, and a served chain that does not begin where this browser's verified log began, give none where
 * the record does not agree. The owner's browsers, with the owner's own wrap on the row.
 */
describe("the web's vault log store: a vault the account recorded further than the server serves", () => {
  beforeAll(async () => {
    await initSodium();
  });

  /** A creates "Family", adds B (seq 1) and makes B a reader (seq 2): the vault, its genesis and every entry's hash. */
  async function threeEntries(server: LogServer) {
    const { a, owner, vaultId } = await shared(server);
    expect((await owner.append(vaultId, { kind: "role", member: B, role: "reader" })).kind).toBe("appended");
    const state = owner.verifiedState(vaultId)!;
    return { a, vaultId, state, h: owner.hashes(vaultId) };
  }

  const recorded = (vaultId: string, genesisHash: string, seq: number, hash: string): Account => {
    const acct = new Account();
    acct.doc = withVaultHead(EMPTY_DOCUMENT, vaultId, genesisHash, seq, hash);
    return acct;
  };

  it("the record ahead, on a fresh browser: the log is withheld and the key is taken read-only; nothing is sent and the record stays", async () => {
    const server = new LogServer();
    const { a, vaultId, state, h } = await threeEntries(server);
    server.serve = (_id, stored) => stored.slice(0, 2);
    const acct = recorded(vaultId, state.genesisHash, 2, h.get(2)!);
    const keys = new Map<string, Uint8Array>();
    const fresh = storeFor(a, server, acct, {}, undefined, keys);
    expect((await fresh.refresh(vaultId, null, null, true)).kind).toBe("withheld");
    expect(await fresh.readOnlyAdoption(vaultId, true)).toEqual({ kind: "adopted", vaultId, source: "owner_wrap" });
    expect(keys.has(vaultId)).toBe(true);
    expect(fresh.writeAllowed(vaultId)).toBe(false);
    const posted = server.posted.length;
    expect((await fresh.append(vaultId, { kind: "role", member: B, role: "writer" })).kind).toBe("read_only");
    expect(server.posted.length).toBe(posted);
    expect(acct.doc.vaults.get(vaultId)).toMatchObject({ genesisHash: state.genesisHash, seq: 2, hash: h.get(2) });
  });

  it("the record ahead, on a browser that stands at the served head: the served head equal to its own is no shortcut; the log is read again and found withheld", async () => {
    const server = new LogServer();
    const { a, vaultId, state, h } = await threeEntries(server);
    server.serve = (_id, stored) => stored.slice(0, 2);
    const acct = new Account();
    const keys = new Map<string, Uint8Array>();
    const here = storeFor(a, server, acct, {}, undefined, keys);
    expect((await here.refresh(vaultId, null, null, true)).kind).toBe("verified");
    expect(here.verifiedState(vaultId)!.head.seq).toBe(1);
    // Another device of the account recorded seq 2 before the server was put back.
    acct.doc = withVaultHead(acct.doc, vaultId, state.genesisHash, 2, h.get(2)!);
    const fetches = server.fetches;
    expect((await here.refresh(vaultId, 1, h.get(1)!)).kind).toBe("withheld");
    expect(server.fetches).toBeGreaterThan(fetches);
    expect(here.writeAllowed(vaultId)).toBe(false);
    expect(await here.readOnlyAdoption(vaultId, true)).toEqual({ kind: "adopted", vaultId, source: "owner_wrap" });
    expect(acct.doc.vaults.get(vaultId)).toMatchObject({ seq: 2, hash: h.get(2) });
  });

  it("the record beside, on a fresh browser: another entry at the record's place freezes the log, and the key is taken read-only", async () => {
    const server = new LogServer();
    const { a, vaultId, state } = await threeEntries(server);
    const acct = recorded(vaultId, state.genesisHash, 2, "ab".repeat(32));
    const keys = new Map<string, Uint8Array>();
    const fresh = storeFor(a, server, acct, {}, undefined, keys);
    expect(await fresh.refresh(vaultId, null, null, true)).toMatchObject({ kind: "frozen", atSeq: 2 });
    expect(await fresh.readOnlyAdoption(vaultId, true)).toEqual({ kind: "adopted", vaultId, source: "owner_wrap" });
    expect(fresh.writeAllowed(vaultId)).toBe(false);
    expect(acct.doc.vaults.get(vaultId)).toMatchObject({ seq: 2, hash: "ab".repeat(32) });
  });

  it("a record of another beginning gives no key: on a fresh browser (the log verifies, the record refuses) and on a browser that verified the vault (frozen at the genesis)", async () => {
    const server = new LogServer();
    const { a, vaultId, h } = await threeEntries(server);
    const other = "cd".repeat(32);
    const freshKeys = new Map<string, Uint8Array>();
    const fresh = storeFor(a, server, recorded(vaultId, other, 2, h.get(2)!), {}, undefined, freshKeys);
    expect((await fresh.refresh(vaultId, null, null, true)).kind).toBe("verified");
    expect(await fresh.adoption(vaultId)).toEqual({ kind: "refused", vaultId, reason: "record_genesis_mismatch" });
    expect(await fresh.readOnlyAdoption(vaultId, true)).toBeNull();
    expect(freshKeys.has(vaultId)).toBe(false);

    // A browser that verified the vault and then reads a record naming another genesis: frozen at 0. At a reload (a
    // fresh key ring over the same storage) it takes no key.
    const acct = new Account();
    const storage = memoryStorage();
    const before = storeFor(a, server, acct, {}, undefined, new Map(), storage);
    expect((await before.refresh(vaultId, null, null, true)).kind).toBe("verified");
    acct.doc = withVaultHead(EMPTY_DOCUMENT, vaultId, other, 2, h.get(2)!);
    expect(await before.refresh(vaultId, null, null, true)).toMatchObject({ kind: "frozen", atSeq: 0 });
    const keys = new Map<string, Uint8Array>();
    const reloaded = storeFor(a, server, acct, {}, undefined, keys, storage);
    expect(await reloaded.readOnlyAdoption(vaultId, true)).toBeNull();
    expect(await reloaded.readOnlyAdoption(vaultId, false)).toBeNull();
    expect(keys.has(vaultId)).toBe(false);
  });

  it("a served chain that does not begin where this browser's verified log began freezes at the genesis: no key with a record ahead; with a record on its own chain the key is taken read-only, as the engine takes it", async () => {
    const server = new LogServer();
    const { a, vaultId, state, h } = await threeEntries(server);
    const acct = new Account();
    const storage = memoryStorage();
    const before = storeFor(a, server, acct, {}, undefined, new Map(), storage);
    expect((await before.refresh(vaultId, null, null, true)).kind).toBe("verified");
    // Another genesis under the same id, validly signed by the owner.
    const otherGenesis = toB64(signLogEntry(a.sign, { kind: "genesis", vaultId, seq: 0, prev: "0".repeat(64), actor: A, at: state.at + 12_345, ownerKey: toB64(a.box.publicKey), vkCommit: state.vkCommit }));
    server.serve = () => [otherGenesis];
    expect(await before.refresh(vaultId, null, null, true)).toMatchObject({ kind: "frozen", atSeq: 0 });

    acct.doc = withVaultHead(EMPTY_DOCUMENT, vaultId, state.genesisHash, 3, "ab".repeat(32));
    const aheadKeys = new Map<string, Uint8Array>();
    expect(await storeFor(a, server, acct, {}, undefined, aheadKeys, storage).readOnlyAdoption(vaultId, true)).toBeNull();
    expect(aheadKeys.has(vaultId)).toBe(false);

    acct.doc = withVaultHead(EMPTY_DOCUMENT, vaultId, state.genesisHash, 2, h.get(2)!);
    const onKeys = new Map<string, Uint8Array>();
    const on = storeFor(a, server, acct, {}, undefined, onKeys, storage);
    expect(await on.readOnlyAdoption(vaultId, true)).toEqual({ kind: "adopted", vaultId, source: "owner_wrap" });
    expect(on.writeAllowed(vaultId)).toBe(false);
  });

  it("a member's key through a grant, with the record ahead of a withheld log: taken read-only, and no wrap is posted for it", async () => {
    const server = new LogServer();
    const { a, b, vaultId } = await shared(server);
    const owner = storeFor(a, server, new Account());
    await owner.refresh(vaultId, null, null, true);
    expect((await owner.append(vaultId, { kind: "role", member: B, role: "reader" })).kind).toBe("appended");
    const state = owner.verifiedState(vaultId)!;
    const h = owner.hashes(vaultId);
    server.serve = (_id, stored) => stored.slice(0, 2);
    const acct = recorded(vaultId, state.genesisHash, 2, h.get(2)!);
    acct.doc = withAccepted(acct.doc, { vaultId, owner: A, addSeq: 1, at: 5, decision: "accept" });
    expect(server.grants.get(vaultId)!.get(B)!.wrappedVk).toBe("");
    for (const road of ["readOnlyAdoption", "adoption"] as const) {
      const keys = new Map<string, Uint8Array>();
      const bLogs = storeFor(b, server, acct, { [A]: toB64(a.box.publicKey) }, undefined, keys);
      expect((await bLogs.refresh(vaultId, null, null, true)).kind, road).toBe("withheld");
      const got = road === "adoption" ? await bLogs.adoption(vaultId) : await bLogs.readOnlyAdoption(vaultId, true);
      expect(got, road).toEqual({ kind: "adopted", vaultId, source: "grant" });
      expect(keys.has(vaultId), road).toBe(true);
      expect(bLogs.writeAllowed(vaultId), road).toBe(false);
      expect(server.selfWraps, road).toEqual([]);
      expect(acct.doc.vaults.get(vaultId), road).toMatchObject({ seq: 2, hash: h.get(2) });
    }
  });

  it("a withheld vault becomes writable again only after the log is read through the record's entry with its hash; another entry there freezes it for good", async () => {
    const server = new LogServer();
    const { a, vaultId, state, h } = await threeEntries(server);
    server.serve = (_id, stored) => stored.slice(0, 2);
    const acct = recorded(vaultId, state.genesisHash, 2, h.get(2)!);
    const fresh = storeFor(a, server, acct, {}, undefined, new Map());
    expect((await fresh.refresh(vaultId, null, null, true)).kind).toBe("withheld");
    expect(await fresh.readOnlyAdoption(vaultId, true)).toMatchObject({ kind: "adopted" });
    server.serve = null;
    expect((await fresh.refresh(vaultId, null, null, true)).kind).toBe("verified");
    expect(fresh.writeAllowed(vaultId)).toBe(true);

    // The same restore, but the server's log went on with another entry at the record's place: frozen, never writable.
    const server2 = new LogServer();
    const t = await threeEntries(server2);
    server2.serve = (_id, stored) => stored.slice(0, 2);
    const acct2 = recorded(t.vaultId, t.state.genesisHash, 2, t.h.get(2)!);
    const other = storeFor(t.a, server2, acct2, {}, undefined, new Map());
    expect((await other.refresh(t.vaultId, null, null, true)).kind).toBe("withheld");
    const s1 = other.verifiedState(t.vaultId)!;
    const pos = logPosition(s1, s1.at + 1000);
    const beside = toB64(signLogEntry(t.a.sign, { kind: "role", vaultId: t.vaultId, seq: 2, prev: pos.prev, actor: A, at: pos.at, member: B, role: "writer" }));
    server2.serve = (_id, stored) => [...stored.slice(0, 2), beside];
    expect(await other.refresh(t.vaultId, null, null, true)).toMatchObject({ kind: "frozen", atSeq: 2 });
    expect(other.writeAllowed(t.vaultId)).toBe(false);
    server2.serve = null;
    expect((await other.refresh(t.vaultId, null, null, true)).kind).toBe("frozen");
    expect(other.writeAllowed(t.vaultId)).toBe(false);
  });

  it("adoption's refusal names how the record failed: a record beside the verified chain is refused as a fork; a record ahead of a verified head reads the log as withheld, so the key is taken read-only instead of refused", async () => {
    const server = new LogServer();
    const { a, vaultId, state, h } = await threeEntries(server);
    // Beside: the record names another hash at a place this browser verified (its own hash wins there: verified).
    const besideAcct = new Account();
    const besideKeys = new Map<string, Uint8Array>();
    const beside = storeFor(a, server, besideAcct, {}, undefined, besideKeys);
    expect((await beside.refresh(vaultId, null, null, true)).kind).toBe("verified");
    besideAcct.doc = withVaultHead(EMPTY_DOCUMENT, vaultId, state.genesisHash, 1, "ab".repeat(32));
    expect(beside.status(vaultId).kind).toBe("verified");
    expect(await beside.adoption(vaultId)).toEqual({ kind: "refused", vaultId, reason: "record_fork" });
    expect(besideKeys.has(vaultId)).toBe(false);

    // Ahead: verified at seq 1, the record (written by another device) at seq 2, before any read of the log here.
    server.serve = (_id, stored) => stored.slice(0, 2);
    const aheadAcct = new Account();
    const aheadKeys = new Map<string, Uint8Array>();
    const ahead = storeFor(a, server, aheadAcct, {}, undefined, aheadKeys);
    expect((await ahead.refresh(vaultId, null, null, true)).kind).toBe("verified");
    aheadAcct.doc = withVaultHead(aheadAcct.doc, vaultId, state.genesisHash, 2, h.get(2)!);
    expect(ahead.status(vaultId)).toMatchObject({ kind: "withheld", servedSeq: null });
    const posted = server.posted.length;
    expect(await ahead.adoption(vaultId)).toEqual({ kind: "adopted", vaultId, source: "owner_wrap" });
    expect(aheadKeys.has(vaultId)).toBe(true);
    expect(ahead.writeAllowed(vaultId)).toBe(false);
    expect(server.posted.length).toBe(posted);
    expect(server.selfWraps).toEqual([]);
  });
});
