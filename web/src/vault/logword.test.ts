import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { ApiClient } from "../api/client";
import { memoryStorage } from "../api/devicesecret";
import { WireApi } from "../api/wireclient";
import { toB64, toHexLower } from "../crypto/bytes";
import { boxKeypairFromSeed, randomBytes, sha256Sync, signKeypairFromSeed } from "../crypto/provider";
import { initSodium } from "../crypto/sodium";
import { fromB64Canonical } from "../crypto/trust/grammar";
import { parseLogEntry } from "../crypto/trust/vaultlog";
import { type AccountDocument, EMPTY_DOCUMENT } from "./accountdoc";
import { type AppendOpts, type LogAction, VaultLogStore } from "./logstore";

/**
 * The server's word about a held change of a shared vault (a success answer at or beyond the change's position) holds
 * whatever becomes of the change's record afterwards, and a log that later shows another entry at that position freezes
 * the vault at ONE read, with nothing else called and nothing said of the change. With the REAL transport (ApiClient,
 * WireApi), only `fetch` played by a stand-in log server that can lie.
 */
const ORIGIN = "https://vault.example.org";
const A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const B = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const DAY = 86_400_000;

type Mode =
  | "ok"
  // Lies: nothing is stored, and the answer is a 200 in the route's shape.
  | "lie_at_position"
  | "lie_at_other_hash"
  | "lie_far_beyond"
  // Refusals and a lost answer.
  | "refuse_no_grant"
  | "no_answer";

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
const hashOf = (e: string) => toHexLower(sha256Sync(fromB64Canonical(e)!));
const seqOf = (e: string): number => {
  const p = parseLogEntry(fromB64Canonical(e)!);
  if (!p.ok) throw new Error("not a log entry");
  return p.value.entry.seq;
};

class LogServer {
  logs = new Map<string, string[]>();
  grants = new Map<string, Map<string, { wrappedVk: string; signedGrant: string | null }>>();
  /** How the next POST is answered; back to "ok" after it. */
  next: Mode = "ok";
  posts = 0;
  /** How many of the next GETs fail as a lost connection. */
  failGets = 0;
  /** Run inside the next POST, before it is answered (a person's tap while the request is out). */
  duringPost: (() => void) | null = null;

  head(vaultId: string): { seq: number; hash: string } {
    const log = this.logs.get(vaultId)!;
    return { seq: log.length - 1, hash: hashOf(log[log.length - 1]!) };
  }

  install(): void {
    vi.stubGlobal("fetch", async (url: string, init: RequestInit = {}) => {
      const u = new URL(url);
      const m = /^\/api\/v1\/vaults\/([^/]+)\/log$/.exec(u.pathname);
      if (m === null) return json({ error: "not_found", message: "x" }, 404);
      const vaultId = decodeURIComponent(m[1]!);
      if ((init.method ?? "GET") === "GET") {
        if (this.failGets > 0) {
          this.failGets--;
          throw new TypeError("Failed to fetch");
        }
        const all = this.logs.get(vaultId) ?? [];
        const after = u.searchParams.get("after");
        const from = after === null ? 0 : Number(after) + 1;
        return json({ entries: all.slice(from), head: { ...this.head(vaultId), at: 1 }, purged: null, deleted: null });
      }
      this.posts++;
      const mode = this.next;
      this.next = "ok";
      const during = this.duringPost;
      this.duringPost = null;
      during?.();
      const req = JSON.parse(String(init.body)) as { entry: string; grant?: string; wrappedVk?: string };
      const log = this.logs.get(vaultId) ?? [];
      const seq = seqOf(req.entry);
      if (mode === "lie_at_position") return json({ rev: 1, head: { seq, hash: hashOf(req.entry), at: 1 }, deleted: null });
      if (mode === "lie_at_other_hash") return json({ rev: 1, head: { seq, hash: "cd".repeat(32), at: 1 }, deleted: null });
      if (mode === "lie_far_beyond") return json({ rev: 1, head: { seq: seq + 7, hash: "ab".repeat(32), at: 1 }, deleted: null });
      if (mode === "refuse_no_grant") return json({ error: "no_grant", message: "x" }, 403);
      if (mode === "no_answer") throw new TypeError("Failed to fetch");
      const known = log.includes(req.entry);
      if (!known && seq !== log.length) return json({ error: "log_head_moved", message: "x" }, 409);
      if (!known) {
        this.logs.set(vaultId, [...log, req.entry]);
        const parsed = parseLogEntry(fromB64Canonical(req.entry)!);
        if (parsed.ok) {
          const e = parsed.value.entry;
          const rows = this.grants.get(vaultId) ?? new Map<string, { wrappedVk: string; signedGrant: string | null }>();
          if (e.kind === "genesis") rows.set(e.actor, { wrappedVk: req.wrappedVk ?? "", signedGrant: null });
          if (e.kind === "add") rows.set(e.member, { wrappedVk: "", signedGrant: req.grant ?? null });
          this.grants.set(vaultId, rows);
        }
      }
      return json({ rev: 1, head: { ...this.head(vaultId), at: 1 }, deleted: null });
    });
  }
}

class Account {
  doc: AccountDocument = EMPTY_DOCUMENT;
  /** The account state cannot be read: every read of it throws (a read of the vault's log that ends in an exception). */
  unreadable = false;
  local() {
    if (this.unreadable) throw new Error("the account state cannot be read");
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

type Person = ReturnType<typeof person>;

function browser(server: LogServer, a: Person, b: Person, keys: Map<string, Uint8Array>, clock: { now: number }, storage = memoryStorage(), account = new Account()) {
  const client = new ApiClient(ORIGIN);
  client.boundUserId = A;
  client.setTokens({ accessToken: "A-access", refreshToken: "A-refresh" });
  const contacts: Record<string, string> = { [B]: toB64(b.box.publicKey) };
  return new VaultLogStore(a.userId, a.sign, a.box, a.uvk, new WireApi(client), storage, account, {
    grantRow: (vaultId) => server.grants.get(vaultId)?.get(a.userId) ?? null,
    isCurrentContact: (u, key) => contacts[u] === key,
    currentContact: (u) => (contacts[u] ? { key: contacts[u]!, compared: true } : null),
    labelFor: (u) => (u === B ? "Bea" : null),
    vaultName: () => "Family",
    sealMeta: () => "meta",
    serverOwnerName: () => null,
  }, keys, () => clock.now);
}

/** The owner's vault with Bea a writer, on this browser and on the owner's other device (both verified to its head). */
async function vaultWithBea() {
  const server = new LogServer();
  server.install();
  const a = person(A);
  const b = person(B);
  const keys = new Map<string, Uint8Array>();
  const clock = { now: 1_763_164_800_000 };
  const storage = memoryStorage();
  const account = new Account();
  const logs = browser(server, a, b, keys, clock, storage, account);
  const c = await logs.append(null, { kind: "create", name: "Family" });
  if (c.kind !== "appended") throw new Error(`create: ${c.kind}`);
  const vaultId = c.vaultId;
  expect((await logs.append(vaultId, { kind: "add", contactUserId: B, role: "writer", releaseUncompared: false })).kind).toBe("appended");
  const other = browser(server, a, b, keys, clock);
  await other.refresh(vaultId, null, null, true);
  /** The same browser after a reload: a second store over the same storage. */
  const reloaded = () => browser(server, a, b, keys, clock, storage);
  return { server, logs, other, vaultId, clock, reloaded, storage, account, position: server.logs.get(vaultId)!.length };
}

type Setup = Awaited<ReturnType<typeof vaultWithBea>>;

const ROLE: LogAction = { kind: "role", member: B, role: "reader" };

/** The owner's other device signs Bea's removal, which the server stores at the next free position. */
async function otherEntry(v: Setup): Promise<void> {
  expect((await v.other.append(v.vaultId, { kind: "remove", member: B })).kind, "the other device's entry is stored").toBe("appended");
  expect(v.server.logs.get(v.vaultId)!.length - 1, "another entry at the change's position").toBe(v.position);
}

/** ONE read of the vault's log, as a sync makes it with the head the server serves; it posts nothing. */
async function oneRead(v: Setup): Promise<void> {
  const posts = v.server.posts;
  const head = v.server.head(v.vaultId);
  await v.logs.refresh(v.vaultId, head.seq, head.hash);
  expect(v.server.posts, "the read posts nothing").toBe(posts);
}

function reads(v: Setup) {
  return { status: v.logs.status(v.vaultId).kind, writable: v.logs.writeAllowed(v.vaultId) };
}

function expectFrozen(v: Setup): void {
  expect(reads(v)).toEqual({ status: "frozen", writable: false });
  expect(v.logs.status(v.vaultId)).toMatchObject({ kind: "frozen", atSeq: v.position });
  expect(v.reloaded().status(v.vaultId).kind, "the mark survives a reload").toBe("frozen");
}

describe("the server's word about a held change of a shared vault (real transport)", () => {
  beforeAll(async () => {
    await initSodium();
  });
  afterEach(() => vi.unstubAllGlobals());

  describe("a success answer at the change's own position with ANOTHER hash is the server's word", () => {
    for (const [what, action, opts] of [
      ["a change of a member's role", ROLE, {}],
      ["a move's own deletion of the old vault", { kind: "delete" }, { forMove: true }],
    ] as const satisfies readonly (readonly [string, LogAction, AppendOpts])[]) {
      it(`${what}: answered so while nothing is stored; another entry there; one read: frozen, and its place is not said taken`, async () => {
        const v = await vaultWithBea();
        v.server.next = "lie_at_other_hash";
        expect(await v.logs.append(v.vaultId, action, opts)).toMatchObject({ kind: "pending" });
        expect(reads(v)).toEqual({ status: "verified", writable: true });
        await otherEntry(v);
        await oneRead(v);
        expectFrozen(v);
        // The sync's look after its pull says nothing of the change: no "its place was taken".
        v.logs.settleHeldFromLog();
        expect(v.logs.settledChanges()).toEqual([]);
        expect(await v.logs.checkWatched()).toEqual([]);
      });
    }
  });

  describe("the server's word survives every other ending of the change's record", () => {
    for (const lie of ["lie_at_position", "lie_far_beyond"] as const) {
      it(`a re-send refused after an answer ${lie === "lie_at_position" ? "at its position" : "beyond it"}: the change stays held, nothing is said as refused; another entry there and one read freeze the vault`, async () => {
        const v = await vaultWithBea();
        v.server.next = lie;
        expect(await v.logs.append(v.vaultId, ROLE)).toMatchObject({ kind: "pending" });
        const known = v.logs.heldKnown(v.vaultId);
        // The unlock's re-send is refused by the server.
        v.server.next = "refuse_no_grant";
        const posts = v.server.posts;
        const resent = await v.logs.resendPending();
        expect(v.server.posts, "the re-send went out").toBe(posts + 1);
        expect(resent.map((r) => r.outcome.kind)).toEqual(["pending"]);
        expect(v.logs.heldKnown(v.vaultId), "still held, as it was").toBe(known);
        expect(v.logs.settledChanges(), "nothing is said as refused").toEqual([]);
        await otherEntry(v);
        await oneRead(v);
        expectFrozen(v);
        expect(await v.logs.checkWatched()).toEqual([]);
      });
    }

    it("a half-made vault's deletion answered at its position, then dropped: remembered with the server's word; another entry there and one read freeze the vault, and nothing is said", async () => {
      const v = await vaultWithBea();
      v.server.next = "lie_at_position";
      expect(await v.logs.append(v.vaultId, { kind: "delete" }, { halfMade: { copies: new Map() } })).toMatchObject({ kind: "pending", known: "stored" });
      // The store's road: the vault is looked at (its position still free), then found to hold something the move did not
      // make, and the deletion is dropped.
      expect(await v.logs.lookHeld(v.vaultId)).toMatchObject({ kind: "pending", known: "stored" });
      expect(v.logs.dropHeldHalfMadeDelete(v.vaultId)).toBe(true);
      expect(v.logs.holds(v.vaultId)).toBe(false);
      await otherEntry(v);
      await oneRead(v);
      expectFrozen(v);
      expect(await v.logs.checkWatched(), "nothing is said of it").toEqual([]);
    });

    for (const lie of ["lie_at_position", "lie_at_other_hash", "lie_far_beyond"] as const) {
      it(`withdrawn while its re-send is out, and that re-send answered ${lie}: the remembered change carries the word; another entry there and one read freeze the vault, and "not made" is never said`, async () => {
        const v = await vaultWithBea();
        v.server.next = "no_answer";
        expect(await v.logs.append(v.vaultId, ROLE)).toMatchObject({ kind: "pending", known: "unknown" });
        v.server.next = lie;
        let withdrawn = false;
        v.server.duringPost = () => {
          withdrawn = v.logs.withdrawHeld(v.vaultId);
        };
        await v.logs.retryHeld(v.vaultId);
        expect(withdrawn, "the person withdrew it while the re-send was out").toBe(true);
        expect(v.logs.holds(v.vaultId)).toBe(false);
        await otherEntry(v);
        await oneRead(v);
        expectFrozen(v);
        expect(await v.logs.checkWatched(), "nothing is said of it").toEqual([]);
        expect(await v.logs.checkWatched({ read: true }), "nor at a later read").toEqual([]);
      });
    }

    it("given up a day after an answer beyond it: remembered with the word; another entry there and one read freeze the vault", async () => {
      const v = await vaultWithBea();
      v.server.next = "lie_far_beyond";
      expect(await v.logs.append(v.vaultId, ROLE)).toMatchObject({ kind: "pending", known: "unknown" });
      v.clock.now += DAY + 1;
      const resent = await v.logs.resendPending();
      expect(resent.map((r) => r.outcome)).toEqual([{ kind: "given_up", vaultId: v.vaultId, made: "unknown" }]);
      await otherEntry(v);
      await oneRead(v);
      expectFrozen(v);
      expect(await v.logs.checkWatched()).toEqual([]);
    });
  });

  describe("the contradiction is looked for when the server's word is recorded, against the log as verified already", () => {
    for (const [what, action, opts] of [
      ["a move's own deletion of the old vault", { kind: "delete" }, { forMove: true }],
      ["a change of a member's role", ROLE, {}],
    ] as const satisfies readonly (readonly [string, LogAction, AppendOpts])[]) {
      for (const failing of ["fails", "throws"] as const) {
        it(`${what}: its answer lost; another entry verified at its position; a re-send answered beyond it whose follow-up read ${failing}: frozen at the answer`, async () => {
          const v = await vaultWithBea();
          v.server.next = "no_answer";
          expect(await v.logs.append(v.vaultId, action, opts)).toMatchObject({ kind: "pending", known: "unknown" });
          await otherEntry(v);
          // This browser verifies the other entry: no word yet, so nothing freezes.
          await v.logs.refresh(v.vaultId, null, null, true);
          expect(reads(v)).toEqual({ status: "verified", writable: true });
          expect(v.logs.holds(v.vaultId)).toBe(true);
          v.server.next = "lie_far_beyond";
          if (failing === "fails") v.server.failGets = 1;
          else v.account.unreadable = true;
          const out = await v.logs.retryHeld(v.vaultId);
          v.account.unreadable = false;
          expect(out).toEqual({ kind: "read_only", vaultId: v.vaultId, frozen: "sent" });
          expectFrozen(v);
          expect(v.logs.holds(v.vaultId)).toBe(false);
        });
      }
    }
  });

  describe("after the freeze nothing of the change is sent, shown or asked", () => {
    const ROWS: readonly (readonly [string, Mode, LogAction])[] = [
      ["a role change answered at its position", "lie_at_position", ROLE],
      ["a role change answered beyond it", "lie_far_beyond", ROLE],
      ["the person's own deletion answered at its position", "lie_at_position", { kind: "delete" }],
      ["the person's own deletion answered beyond it", "lie_far_beyond", { kind: "delete" }],
    ];
    for (const [what, lie, action] of ROWS) {
      it(`${what}: dropped at the freeze; no unlock posts it, also a day later; not shown, not withdrawable, not asked about; no "given up"`, async () => {
        const v = await vaultWithBea();
        v.server.next = lie;
        expect(await v.logs.append(v.vaultId, action)).toMatchObject({ kind: "pending" });
        await otherEntry(v);
        await oneRead(v);
        expectFrozen(v);
        const posts = v.server.posts;
        for (const logs of [v.logs, v.reloaded()]) {
          expect(logs.holds(v.vaultId)).toBe(false);
          expect(logs.heldChange(v.vaultId), "the members' panel shows no waiting change").toBeNull();
          expect(logs.heldKnown(v.vaultId)).toBeNull();
          expect(logs.withdrawHeld(v.vaultId), "no Withdraw").toBe(false);
          expect(logs.pendingVaults()).toEqual([]);
          expect(logs.heldDeletionsToAsk(), "no question about a kept deletion").toEqual([]);
          expect(await logs.deletionsToAsk()).toEqual([]);
          expect(await logs.retryHeld(v.vaultId), "no road posts it").toBeNull();
          expect(await logs.giveUpHeldDeletion(v.vaultId)).toBeNull();
          expect(await logs.resendPending(), "the unlock posts nothing").toEqual([]);
        }
        v.clock.now += DAY + 1;
        expect(await v.reloaded().resendPending(), "a day later, nothing either").toEqual([]);
        expect(v.server.posts, "nothing was posted to the frozen vault").toBe(posts);
        expect(v.logs.settledChanges(), "no notice: not refused, not given up, not taken").toEqual([]);
        expect(await v.logs.checkWatched()).toEqual([]);
        expect(await v.logs.append(v.vaultId, ROLE), "the next change").toEqual({ kind: "read_only", vaultId: v.vaultId, frozen: "unsent" });
      });
    }

    it("a change held at rest for a vault that froze before this rule is dropped at the first look, and never sent", async () => {
      const v = await vaultWithBea();
      v.server.next = "lie_at_position";
      expect(await v.logs.append(v.vaultId, ROLE)).toMatchObject({ kind: "pending", known: "stored" });
      const held = v.storage.get(`andvari.log2.${A}.${v.vaultId}.pending`)!;
      await otherEntry(v);
      await oneRead(v);
      expectFrozen(v);
      // The record as the earlier code left it beside the freeze.
      v.storage.set(`andvari.log2.${A}.${v.vaultId}.pending`, held);
      v.storage.set(`andvari.log2.${A}.pending-index`, v.vaultId);
      const again = v.reloaded();
      const posts = v.server.posts;
      expect(await again.resendPending()).toEqual([]);
      expect(again.heldChange(v.vaultId)).toBeNull();
      expect(v.server.posts).toBe(posts);
      expect(v.storage.get(`andvari.log2.${A}.${v.vaultId}.pending`)).toBeNull();
      expect(again.pendingVaults()).toEqual([]);
    });

    it("a move's own deletion dropped by the freeze marks its move as frozen (the move's own line), and the move's road finds nothing to send", async () => {
      const v = await vaultWithBea();
      v.server.next = "lie_at_position";
      expect(await v.logs.append(v.vaultId, { kind: "delete" }, { forMove: true })).toMatchObject({ kind: "pending", known: "stored" });
      v.logs.saveMoveRecord(v.vaultId, { newVaultId: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", copied: [], added: [B], discard: null, discardCopies: null });
      expect(v.logs.heldMoveDeletes()).toEqual([v.vaultId]);
      await otherEntry(v);
      await oneRead(v);
      expectFrozen(v);
      expect(v.logs.holdsMoveDelete(v.vaultId)).toBe(false);
      expect(v.logs.heldMoveDeletes()).toEqual([]);
      expect(v.logs.moveRecord(v.vaultId)).toMatchObject({ oldFrozen: true });
      expect(v.reloaded().frozenMoves()).toEqual([v.vaultId]);
      expect(v.logs.moveRecord(v.vaultId)?.stopped, "never taken for a stopped run (its new vault holds the items)").toBeUndefined();
    });

    it("a notice that its place was taken, kept for the change, is taken back by the freeze over it", async () => {
      const v = await vaultWithBea();
      v.server.next = "lie_far_beyond";
      expect(await v.logs.append(v.vaultId, ROLE)).toMatchObject({ kind: "pending", known: "unknown" });
      const held = JSON.parse(v.storage.get(`andvari.log2.${A}.${v.vaultId}.pending`)!) as { frame: string };
      expect(v.logs.withdrawHeld(v.vaultId)).toBe(true);
      // A "its place was taken" kept for the same change (as an earlier version, or another tab's look, could keep it).
      v.storage.set(`andvari.log2.${A}.${v.vaultId}.settled`, JSON.stringify([{ pending: { vaultId: v.vaultId, frame: held.frame }, outcome: { kind: "head_moved", vaultId: v.vaultId } }]));
      v.storage.set(`andvari.log2.${A}.settled-index`, v.vaultId);
      expect(v.logs.settledChanges()).toHaveLength(1);
      await otherEntry(v);
      await oneRead(v);
      expectFrozen(v);
      expect(v.logs.settledChanges()).toEqual([]);
      expect(await v.logs.checkWatched()).toEqual([]);
    });
  });
});
