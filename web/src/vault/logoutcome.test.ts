import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { ApiClient } from "../api/client";
import { memoryStorage } from "../api/devicesecret";
import { WireApi } from "../api/wireclient";
import { toB64, toHexLower } from "../crypto/bytes";
import { boxKeypairFromSeed, randomBytes, sha256Sync, signKeypairFromSeed } from "../crypto/provider";
import { initSodium } from "../crypto/sodium";
import { fromB64Canonical } from "../crypto/trust/grammar";
import { parseLogEntry } from "../crypto/trust/vaultlog";
import {
  fill,
  RESEND_FOUND_MADE_REMOVE,
  RESEND_GIVEN_UP_DELETE,
  RESEND_GIVEN_UP_OFFER,
  RESEND_GIVEN_UP_REMOVE,
  RESEND_GIVEN_UP_ROLE,
  RESEND_NOT_MADE_CHANGE,
  RESEND_NOT_MADE_REMOVE,
  RESEND_WAITING_ADD_NOT_STORED,
  RESEND_WAITING_ADD_UNKNOWN,
  RESEND_WAITING_DELETE_UNKNOWN,
  RESEND_WAITING_OFFER_UNKNOWN,
  RESEND_WAITING_REMOVE_UNKNOWN,
  RESEND_WAITING_ROLE_UNKNOWN,
  RESEND_WITHDRAWN_UNKNOWN,
  LOG_APPEND_UNCONFIRMED,
  LOG_APPEND_UNREAD,
  LOG_NOT_MADE,
  LOG_NOT_SENT,
  LOG_NOT_STORED,
  LOG_NOT_TAKEN,
  LOG_STORED_UNREAD,
  LOG_UNKNOWN,
  LOG_UNKNOWN_ADD,
  LOG_UNKNOWN_ADD_UNREAD,
  LOG_UNKNOWN_CREATE,
  LOG_UNKNOWN_UNREAD,
  SHARE_ANSWER_UNKNOWN,
  SHARE_NOT_RECORDED,
} from "../ui/copy";
import { heldNoticeText, heldWaitingText } from "../ui/heldtext";
import { logActionText } from "../ui/logactiontext";
import { shareAnswerText } from "../ui/SharedPrompts";
import { type AccountDocument, EMPTY_DOCUMENT, withAccepted } from "./accountdoc";
import { AccountStateStore } from "./accountdocstore";
import { type AppendOutcome, FIRST_POST_OUT_MAX_MS, type LogAction, VaultLogStore, WATCHES_PER_VAULT_MAX } from "./logstore";
import { withdrawnText } from "../ui/Sharing";
import { ChangeNotStoredError, LogActionError } from "./store";

/**
 * After a change to a shared vault's log, the outcome said is the outcome known. With the REAL transport (ApiClient and
 * its traffic gate, WireApi) and only `fetch` played by a log server that stores what it is sent, for every kind of
 * change and every way its answer can end:
 *  - stored only from the server's own complete answer (a 2xx under the JSON type whose head names the frame), also
 *    when the follow-up read fails;
 *  - not sent only when nothing left the browser (nothing is held);
 *  - "isn't made" only from the server's own refusal of the frame's first post (a `429` keeps it and sends it again);
 *  - everything else "can't tell" (no answer, an answer cut off, a 5xx, a page or JSON that is not the server's, an
 *    answer the gate dropped), held and sent again, never made twice.
 */
const ORIGIN = "https://vault.example.org";
const A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const B = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

type Mode =
  | "ok"
  | "no_answer"
  | "no_answer_stored"
  | "server_error_stored"
  | "cut_off_stored"
  | "html_stored"
  | "front_json_stored"
  | "other_head_stored"
  | "gate_after_stored"
  | "beyond_unstored"
  | "beyond_unstored_reads_fail"
  | "beyond_stored"
  | "beyond_stored_short_read"
  | "beyond_named_head"
  | "beyond_wrong_hash"
  | "rate_limited"
  | "refused"
  | "ok_reads_fail";

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
const hashOf = (e: string) => toHexLower(sha256Sync(fromB64Canonical(e)!));

/** A body whose first part arrives and whose rest never can be read. */
function cutOff(): Response {
  let sent = false;
  const body = new ReadableStream<Uint8Array>({
    pull(c) {
      if (!sent) {
        sent = true;
        c.enqueue(new TextEncoder().encode('{"rev":1,"head":'));
        return;
      }
      c.error(new TypeError("the connection broke"));
    },
  });
  return new Response(body, { status: 200, headers: { "Content-Type": "application/json" } });
}

class LogServer {
  logs = new Map<string, string[]>();
  grants = new Map<string, Map<string, { wrappedVk: string; signedGrant: string | null }>>();
  /** How the next POST is answered; back to "ok" after it. */
  next: Mode = "ok";
  readsFail = false;
  /** Reads serve only the first this-many entries (a stale or withheld tail); null: the whole log. */
  readsShort: number | null = null;
  posts = 0;
  gate: string | null = null;
  /** Frames posted under `no_answer` (not stored then): a server that keeps one may append it later ({@link appendLate}). */
  lost: string[] = [];

  /** The server appends a frame it got earlier without storing it then (its position is still free). */
  appendLate(vaultId: string, entry: string): void {
    this.logs.set(vaultId, [...(this.logs.get(vaultId) ?? []), entry]);
  }

  install(): void {
    vi.stubGlobal("fetch", async (url: string, init: RequestInit = {}) => {
      const u = new URL(url);
      const m = /^\/api\/v1\/vaults\/([^/]+)\/log$/.exec(u.pathname);
      if (m === null) return json({ error: "not_found", message: "x" }, 404);
      const vaultId = decodeURIComponent(m[1]!);
      if ((init.method ?? "GET") === "GET") {
        if (this.readsFail) throw new TypeError("offline");
        const all = (this.logs.get(vaultId) ?? []).slice(0, this.readsShort ?? undefined);
        const after = u.searchParams.get("after");
        const from = after === null ? 0 : Number(after) + 1;
        const last = all[all.length - 1]!;
        return json({ entries: all.slice(from), head: { seq: all.length - 1, hash: hashOf(last), at: 1 }, purged: null, deleted: null });
      }
      this.posts++;
      const mode = this.next;
      this.next = "ok";
      const req = JSON.parse(String(init.body)) as { entry: string; grant?: string; wrappedVk?: string };
      if (mode === "no_answer") {
        this.lost.push(req.entry);
        throw new TypeError("Failed to fetch");
      }
      if (mode === "rate_limited") return json({ error: "rate_limited", message: "x" }, 429);
      if (mode === "refused") return json({ error: "not_owner", message: "x" }, 403);
      if (mode === "beyond_unstored" || mode === "beyond_unstored_reads_fail") {
        // Nothing stored; JSON in the route's shape whose head lies beyond the frame sent (names no frame).
        const parsed = parseLogEntry(fromB64Canonical(req.entry)!);
        if (mode === "beyond_unstored_reads_fail") this.readsFail = true;
        return json({ rev: 1, head: { seq: (parsed.ok ? parsed.value.entry.seq : 0) + 1, hash: "1".repeat(64), at: 1 }, deleted: null });
      }
      if (mode === "beyond_named_head" || mode === "beyond_wrong_hash") {
        // Nothing stored (another entry holds the frame's place); answered 200 with the log's real head beyond the frame,
        // or with that position and a hash the log does not hold there.
        const log = this.logs.get(vaultId) ?? [];
        const last = log[log.length - 1]!;
        return json({ rev: 1, head: { seq: log.length - 1, hash: mode === "beyond_named_head" ? hashOf(last) : "1".repeat(64), at: 1 }, deleted: null });
      }
      const log = this.logs.get(vaultId) ?? [];
      const known = log.includes(req.entry);
      // As the server: a new entry is taken only at the next position; another entry already there is `log_head_moved`.
      const at = parseLogEntry(fromB64Canonical(req.entry)!);
      if (!known && at.ok && at.value.entry.seq !== log.length) return json({ error: "log_head_moved", message: "x" }, 409);
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
      const stored = this.logs.get(vaultId)!;
      const head = { seq: stored.length - 1, hash: hashOf(stored[stored.length - 1]!), at: 1 };
      switch (mode) {
        case "no_answer_stored":
          throw new TypeError("Failed to fetch");
        case "server_error_stored":
          return new Response("<html>Bad gateway</html>", { status: 502, headers: { "Content-Type": "text/html" } });
        case "cut_off_stored":
          return cutOff();
        case "html_stored":
          return new Response("<html>Welcome to the hotel network</html>", { status: 200, headers: { "Content-Type": "text/html" } });
        case "front_json_stored":
          return json({});
        case "other_head_stored":
          // JSON in the route's shape whose head is not the frame sent, and no read back: nothing says it is stored.
          this.readsFail = true;
          return json({ rev: 1, head: { seq: head.seq, hash: "0".repeat(64), at: 1 }, deleted: null });
        case "beyond_stored":
          // Stored, and answered with a head beyond the frame (as for a byte-identical frame stored earlier).
          return json({ rev: 1, head: { seq: head.seq + 1, hash: "1".repeat(64), at: 1 }, deleted: null });
        case "beyond_stored_short_read": {
          // The check's P1c: stored, answered with a head beyond the frame, and the reads afterwards end one short of
          // the frame (a stale or withheld tail).
          const parsed = parseLogEntry(fromB64Canonical(req.entry)!);
          this.readsShort = parsed.ok ? parsed.value.entry.seq : 0;
          return json({ rev: 1, head: { seq: head.seq + 1, hash: "1".repeat(64), at: 1 }, deleted: null });
        }
        case "gate_after_stored":
          this.gate = "forked";
          return json({ rev: 1, head, deleted: null });
        case "ok_reads_fail":
          this.readsFail = true;
          return json({ rev: 1, head, deleted: null });
        default:
          return json({ rev: 1, head, deleted: null });
      }
    });
  }

  count(vaultId: string, frameKind: string): number {
    return (this.logs.get(vaultId) ?? []).filter((e) => {
      const p = parseLogEntry(fromB64Canonical(e)!);
      return p.ok && p.value.entry.kind === frameKind;
    }).length;
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

function browser(server: LogServer, a = person(A), clock: () => number = () => 1_763_164_800_000, b = person(B), keys = new Map<string, Uint8Array>(), storage = memoryStorage()) {
  const client = new ApiClient(ORIGIN);
  client.boundUserId = A;
  client.setTokens({ accessToken: "A-access", refreshToken: "A-refresh" });
  client.trafficGate = () => server.gate;
  const contacts: Record<string, string> = { [B]: toB64(b.box.publicKey) };
  const logs = new VaultLogStore(a.userId, a.sign, a.box, a.uvk, new WireApi(client), storage, new Account(), {
    grantRow: (vaultId) => server.grants.get(vaultId)?.get(a.userId) ?? null,
    isCurrentContact: (u, key) => contacts[u] === key,
    currentContact: (u) => (contacts[u] ? { key: contacts[u]!, compared: true } : null),
    labelFor: (u) => (u === B ? "Bea" : null),
    vaultName: () => "Family",
    sealMeta: () => "meta",
    serverOwnerName: () => "the server's name",
  }, keys, clock);
  return { logs, client, a, b, keys, storage };
}

/** The line a screen shows for [out], exactly as the store raises it (storedLogAction / logAction). */
function lineFor(out: AppendOutcome, kind: LogAction["kind"]): string | null {
  if (out.kind === "appended") return null;
  if (out.kind === "pending") return logActionText(new ChangeNotStoredError(out.vaultId, kind, out.known));
  return logActionText(new LogActionError(out));
}

const KINDS = ["create", "add", "role", "remove", "offer", "delete"] as const;
type Kind = (typeof KINDS)[number];

const ACTION: Record<Kind, LogAction> = {
  create: { kind: "create", name: "Work" },
  add: { kind: "add", contactUserId: B, role: "writer", releaseUncompared: false },
  role: { kind: "role", member: B, role: "reader" },
  remove: { kind: "remove", member: B },
  offer: { kind: "offer", to: B, expiresInMs: 86_400_000 },
  delete: { kind: "delete" },
};

/** A vault this browser created; with B a member unless the change under test is B's addition. */
async function ready(server: LogServer, kind: Kind, clock?: () => number) {
  const br = browser(server, undefined, clock);
  const { logs, client } = br;
  if (kind === "create") return { logs, client, vaultId: null as string | null, br };
  const c = await logs.append(null, { kind: "create", name: "Family" });
  if (c.kind !== "appended") throw new Error(`create: ${c.kind}`);
  if (kind !== "add") {
    const added = await logs.append(c.vaultId, ACTION.add);
    if (added.kind !== "appended") throw new Error(`add: ${added.kind}`);
  }
  return { logs, client, vaultId: c.vaultId as string | null, br };
}

/**
 * A held deletion of a vault at the next unlock: the unlock's re-send sends nothing for it and asks the person instead;
 * at their word ("delete it now") it is sent again, byte for byte.
 */
async function sentAtTheirWord(logs: VaultLogStore, server: LogServer, vaultId: string): Promise<AppendOutcome[]> {
  const posts = server.posts;
  expect(await logs.resendPending(), "the unlock sends no deletion on its own").toEqual([]);
  expect(server.posts).toBe(posts);
  expect(logs.heldDeletionsToAsk()).toEqual([vaultId]);
  const out = await logs.retryHeld(vaultId);
  return out === null ? [] : [out];
}

const unknownLine = (kind: Kind) => (kind === "add" ? LOG_UNKNOWN_ADD : kind === "create" ? LOG_UNKNOWN_CREATE : LOG_UNKNOWN);
const entryKind = (kind: Kind) => (kind === "create" ? "genesis" : kind);

describe("after a change to a shared vault, the outcome said is the outcome known (real transport)", () => {
  beforeAll(async () => {
    await initSodium();
  });
  afterEach(() => vi.unstubAllGlobals());

  for (const kind of KINDS) {
    describe(`a ${kind}`, () => {
      it("the server's own complete answer: stored and shown as made", async () => {
        const server = new LogServer();
        server.install();
        const { logs, vaultId } = await ready(server, kind);
        const out = await logs.append(vaultId, ACTION[kind]);
        expect(out.kind).toBe("appended");
        expect(lineFor(out, kind)).toBeNull();
      });

      for (const mode of ["no_answer", "no_answer_stored", "server_error_stored", "cut_off_stored", "html_stored", "front_json_stored", "other_head_stored", "gate_after_stored"] as const) {
        it(`${mode}: can't tell, held, sent again at the next unlock and made once`, async () => {
          const server = new LogServer();
          server.install();
          const { logs, vaultId } = await ready(server, kind);
          server.next = mode;
          const out = await logs.append(vaultId, ACTION[kind]);
          expect(out).toMatchObject({ kind: "pending", known: "unknown" });
          expect(lineFor(out, kind)).toBe(unknownLine(kind));
          const id = (out as { vaultId: string }).vaultId;
          expect(logs.holds(id)).toBe(true);
          // Another change of the same vault waits for it, and says it isn't confirmed (never "hasn't reached the server").
          if (kind !== "create" && kind !== "delete") {
            const second = await logs.append(id, { kind: "role", member: B, role: "writer" });
            expect(second).toEqual({ kind: "not_allowed", reason: "append_pending" });
            expect(lineFor(second, "role")).toBe(LOG_APPEND_UNCONFIRMED);
          }
          // The next unlock sends it again, byte for byte: it is made exactly once.
          server.gate = null;
          server.readsFail = false;
          // A deletion is sent again only at the person's word (the unlock asks): turned round from "sent again at the
          // next unlock" by the rule of 18 November 2026 that a vault's deletion waits for its owner's say.
          const again = kind === "delete" ? await sentAtTheirWord(logs, server, id) : await logs.retryPending();
          expect(again.map((o) => o.kind)).toEqual(["appended"]);
          expect(server.count(id, entryKind(kind))).toBe(1);
          expect(logs.holds(id)).toBe(false);
        });
      }

      it("429: isn't made yet, kept, sent again at the next unlock", async () => {
        const server = new LogServer();
        server.install();
        const { logs, vaultId } = await ready(server, kind);
        server.next = "rate_limited";
        const out = await logs.append(vaultId, ACTION[kind]);
        expect(out).toMatchObject({ kind: "pending", known: "not_stored" });
        expect(lineFor(out, kind)).toBe(LOG_NOT_STORED);
        const id = (out as { vaultId: string }).vaultId;
        expect(server.count(id, entryKind(kind))).toBe(0);
        expect((kind === "delete" ? await sentAtTheirWord(logs, server, id) : await logs.retryPending()).map((o) => o.kind)).toEqual(["appended"]);
        expect(server.count(id, entryKind(kind))).toBe(1);
      });

      it("a 200 whose follow-up read failed is STORED, and the next change reads it back first", async () => {
        const server = new LogServer();
        server.install();
        const { logs, vaultId } = await ready(server, kind);
        server.next = "ok_reads_fail";
        const out = await logs.append(vaultId, ACTION[kind]);
        expect(out).toMatchObject({ kind: "pending", known: "stored" });
        expect(lineFor(out, kind)).toBe(LOG_STORED_UNREAD);
        const id = (out as { vaultId: string }).vaultId;
        expect(logs.heldKnown(id)).toBe("stored");
        if (kind === "create" || kind === "delete") return;
        // Still unreadable: the next change says the earlier one is stored and not read back.
        const blocked = await logs.append(id, { kind: "role", member: B, role: "writer" });
        expect(blocked).toEqual({ kind: "not_allowed", reason: "append_unread" });
        expect(lineFor(blocked, "role")).toBe(LOG_APPEND_UNREAD);
        // Readable again: the stored change is read back (nothing posted for it) and the next change is made.
        server.readsFail = false;
        const posts = server.posts;
        const next = await logs.append(id, kind === "remove" ? ACTION.add : kind === "role" ? ACTION.remove : { kind: "role", member: B, role: "reader" });
        expect(next.kind).toBe("appended");
        expect(server.posts).toBe(posts + 1);
        expect(server.count(id, entryKind(kind))).toBe(1);
      });

      it("the gate before anything left the browser: not sent, nothing held, nothing changed", async () => {
        const server = new LogServer();
        server.install();
        const { logs, vaultId } = await ready(server, kind);
        const posts = server.posts;
        server.gate = "forked";
        const out = await logs.append(vaultId, ACTION[kind]);
        expect(out.kind).toBe("not_sent");
        expect(lineFor(out, kind)).toBe(LOG_NOT_SENT);
        expect(server.posts).toBe(posts);
        expect(logs.pendingVaults()).toEqual([]);
      });

      it("the server's refusal (a 4xx): not made, nothing held", async () => {
        const server = new LogServer();
        server.install();
        const { logs, vaultId } = await ready(server, kind);
        server.next = "refused";
        const out = await logs.append(vaultId, ACTION[kind]);
        expect(out).toMatchObject({ kind: "refused", code: "not_owner" });
        expect(lineFor(out, kind)).toBe(LOG_NOT_TAKEN.replace("{0}", "not_owner"));
        expect(logs.pendingVaults()).toEqual([]);
      });

      it("a head beyond the frame, nothing stored, and the read afterwards fails: can't tell, never 'stored' (the check's P1a)", async () => {
        const server = new LogServer();
        server.install();
        const { logs, vaultId } = await ready(server, kind);
        server.next = "beyond_unstored_reads_fail";
        const out = await logs.append(vaultId, ACTION[kind]);
        expect(out).toMatchObject({ kind: "pending", known: "unknown" });
        expect(lineFor(out, kind)).toBe(unknownLine(kind));
        const id = (out as { vaultId: string }).vaultId;
        expect(logs.heldKnown(id)).toBe("unknown");
        expect(server.count(id, entryKind(kind))).toBe(0);
        if (kind !== "create" && kind !== "delete") {
          expect(await logs.append(id, { kind: "role", member: B, role: "writer" }), "never 'an earlier change is stored'").toEqual({ kind: "not_allowed", reason: "append_pending" });
        }
        // The next unlock sends it again (a deletion: at the person's word); it is made once.
        server.readsFail = false;
        expect((kind === "delete" ? await sentAtTheirWord(logs, server, id) : await logs.retryPending()).map((o) => o.kind)).toEqual(["appended"]);
        expect(server.count(id, entryKind(kind))).toBe(1);
      });

      it("a head beyond the frame, nothing stored, and the read afterwards ends before that head: can't tell, held, never 'not made' (the second check's reading of P1b)", async () => {
        const server = new LogServer();
        server.install();
        const { logs, vaultId } = await ready(server, kind);
        server.next = "beyond_unstored";
        const out = await logs.append(vaultId, ACTION[kind]);
        // The answer named a head (frame + 1) that the log as read does not reach: no read for "not made".
        expect(out).toMatchObject({ kind: "pending", known: "unknown" });
        expect(lineFor(out, kind)).toBe(unknownLine(kind));
        const id = (out as { vaultId: string }).vaultId;
        expect(logs.heldKnown(id)).toBe("unknown");
        expect(server.count(id, entryKind(kind))).toBe(0);
        // The next unlock sends it again (a deletion: at the person's word); it is made once.
        expect((kind === "delete" ? await sentAtTheirWord(logs, server, id) : await logs.retryPending()).map((o) => o.kind)).toEqual(["appended"]);
        expect(server.count(id, entryKind(kind))).toBe(1);
      });

      if (kind !== "create") {
        it("STORED, answered with a head beyond the frame, and the read afterwards one short of the frame: can't tell, held, never 'not made' (the second check's P1c)", async () => {
          const server = new LogServer();
          server.install();
          const { logs, vaultId } = await ready(server, kind);
          server.next = "beyond_stored_short_read";
          const out = await logs.append(vaultId, ACTION[kind]);
          expect(server.count(vaultId!, entryKind(kind)), "the server stored it").toBe(1);
          // On the code before: { kind: "not_made" }, "Nothing changed. Make the change again", while the server holds it.
          expect(out).toMatchObject({ kind: "pending", known: "unknown" });
          expect(lineFor(out, kind)).not.toBe(LOG_NOT_MADE);
          expect(lineFor(out, kind)).toBe(unknownLine(kind));
          expect(logs.heldKnown(vaultId!)).toBe("unknown");
          if (kind === "add") expect(server.grants.get(vaultId!)?.get(B)?.signedGrant, "the member holds the vault's key").toBeTruthy();
          // Once the reads serve the whole log, the next unlock's re-post finds it stored: made, once.
          server.readsShort = null;
          expect((kind === "delete" ? await sentAtTheirWord(logs, server, vaultId!) : await logs.retryPending()).map((o) => o.kind)).toEqual(["appended"]);
          expect(server.count(vaultId!, entryKind(kind))).toBe(1);
        });
      }

      it("a head beyond the frame, and the read afterwards holds the frame: stored and shown as made", async () => {
        const server = new LogServer();
        server.install();
        const { logs, vaultId } = await ready(server, kind);
        server.next = "beyond_stored";
        const out = await logs.append(vaultId, ACTION[kind]);
        expect(out.kind).toBe("appended");
        expect(logs.pendingVaults()).toEqual([]);
      });
    });
  }

  /** [ready] for a removal of B, then the owner's other device signs two role changes of B (the frame's place taken). */
  async function placeTaken(server: LogServer) {
    const r = await ready(server, "remove");
    const other = browser(server, r.br.a);
    await other.logs.refresh(r.vaultId!, null, null, true);
    for (const role of ["reader", "writer"] as const) expect((await other.logs.append(r.vaultId!, { kind: "role", member: B, role })).kind).toBe("appended");
    return r;
  }

  it("an answer whose head lies beyond the frame says the server holds it: where the read reaches that head with its hash and another entry holds the frame's place, the vault is frozen there, the change dropped, never 'not made'", async () => {
    const server = new LogServer();
    server.install();
    const { logs, vaultId } = await placeTaken(server);
    const position = server.logs.get(vaultId!)!.length - 2;
    server.next = "beyond_named_head";
    const out = await logs.append(vaultId!, ACTION.remove);
    // On the code before: { kind: "not_made" }, "Nothing changed", the record dropped and the vault left open. The freeze
    // drops the change and says nothing of it (the vault is read-only, frozen after the change was sent).
    expect(out).toEqual({ kind: "read_only", vaultId, frozen: "sent" });
    expect(lineFor(out, "remove")).not.toBe(LOG_NOT_MADE);
    expect(logs.status(vaultId!)).toMatchObject({ kind: "frozen", atSeq: position });
    expect(logs.writeAllowed(vaultId!)).toBe(false);
    expect(logs.holds(vaultId!)).toBe(false);
    expect(server.count(vaultId!, "remove")).toBe(0);
  });

  it("a read that holds another entry at the position the answer named is the fork it is: frozen there, the change dropped, never 'not made'", async () => {
    const server = new LogServer();
    server.install();
    const { logs, vaultId } = await placeTaken(server);
    server.next = "beyond_wrong_hash";
    const out = await logs.append(vaultId!, ACTION.remove);
    expect(out).toEqual({ kind: "read_only", vaultId, frozen: "sent" });
    expect(lineFor(out, "remove")).not.toBe(LOG_NOT_MADE);
    expect(logs.status(vaultId!).kind).toBe("frozen");
    expect(logs.holds(vaultId!)).toBe(false);
    expect(server.count(vaultId!, "remove")).toBe(0);
  });

  it("the unlock's re-post: a removal stored, its answer lost; re-posted, answered beyond, read stale: can't tell and held, never 'not made' (the second check's P1-resend)", async () => {
    const server = new LogServer();
    server.install();
    const { logs, vaultId } = await ready(server, "remove");
    server.next = "no_answer_stored";
    expect(await logs.append(vaultId!, ACTION.remove)).toMatchObject({ kind: "pending", known: "unknown" });
    expect(server.count(vaultId!, "remove")).toBe(1);
    server.next = "beyond_stored_short_read";
    // On the code before: [{ kind: "not_made" }] and the record dropped, while the server has removed them.
    const resent = await logs.resendPending();
    expect(resent.map((r) => r.outcome)).toEqual([{ kind: "pending", vaultId, known: "unknown" }]);
    expect(logs.holds(vaultId!)).toBe(true);
    server.readsShort = null;
    expect((await logs.retryPending()).map((o) => o.kind)).toEqual(["appended"]);
    expect(server.count(vaultId!, "remove")).toBe(1);
  });

  it("an added member whose answer was lost: can't tell, and once the log is read the member list shows them", async () => {
    const server = new LogServer();
    server.install();
    const { logs, vaultId } = await ready(server, "add");
    server.next = "no_answer_stored";
    const out = await logs.append(vaultId, ACTION.add);
    expect(lineFor(out, "add")).toBe(LOG_UNKNOWN_ADD);
    expect(logs.verifiedState(vaultId!)?.members[B]).toBeUndefined();
    // Looking (nothing posted): the add is in the verified log, with the vault's key sealed to them.
    const posts = server.posts;
    expect((await logs.lookHeld(vaultId!))?.kind).toBe("appended");
    expect(server.posts).toBe(posts);
    expect(logs.verifiedState(vaultId!)?.members[B]).toBeDefined();
    expect(server.grants.get(vaultId!)?.get(B)?.signedGrant).toBeTruthy();
  });
});

describe("after 'cannot tell', the members the person is sent to are read from the server first", () => {
  beforeAll(async () => {
    await initSodium();
  });
  afterEach(() => vi.unstubAllGlobals());

  it("stored after all: the read shows it made; not stored: the line sends them to members read just now; the read fails: the line says the list may be old", async () => {
    for (const [mode, readsFail] of [["no_answer_stored", false], ["no_answer", false], ["no_answer", true]] as const) {
      const server = new LogServer();
      server.install();
      const { logs, vaultId } = await ready(server, "add");
      server.next = mode;
      const out = await logs.append(vaultId, ACTION.add);
      expect(out).toMatchObject({ kind: "pending", known: "unknown" });
      server.readsFail = readsFail;
      const posts = server.posts;
      const look = await logs.readAfterUnknown(vaultId!);
      expect(server.posts, "nothing is posted").toBe(posts);
      if (mode === "no_answer_stored") {
        expect(look.outcome?.kind).toBe("appended");
        expect(logs.verifiedState(vaultId!)?.members[B], "the member list read from the server shows them").toBeDefined();
        continue;
      }
      expect(look).toEqual({ outcome: { kind: "pending", vaultId, known: "unknown" }, read: !readsFail });
      expect(logActionText(new ChangeNotStoredError(vaultId!, "add", "unknown", look.read))).toBe(readsFail ? LOG_UNKNOWN_ADD_UNREAD : LOG_UNKNOWN_ADD);
      expect(logActionText(new ChangeNotStoredError(vaultId!, "remove", "unknown", look.read))).toBe(readsFail ? LOG_UNKNOWN_UNREAD : LOG_UNKNOWN);
    }
  });
});

describe("a change kept to be sent again: shown as waiting, withdrawn, given up, and said when it does not happen (real transport)", () => {
  beforeAll(async () => {
    await initSodium();
  });
  afterEach(() => vi.unstubAllGlobals());

  /** The owner's other device: the same person and key ring, its own browser storage, the log read from the server. */
  async function otherDevice(server: LogServer, br: ReturnType<typeof browser>, vaultId: string) {
    const d = browser(server, br.a, undefined, br.b, br.keys);
    await d.logs.refresh(vaultId, null, null, true);
    return d;
  }

  it("a removal with no answer, then the owner's other device changes the member's role: at the next unlock the removal did not happen, and it is said with whom it named (the check's P2)", async () => {
    const server = new LogServer();
    server.install();
    const { logs, vaultId, br } = await ready(server, "remove");
    server.next = "no_answer";
    const out = await logs.append(vaultId, ACTION.remove);
    expect(lineFor(out, "remove")).toBe(LOG_UNKNOWN);
    // Shown as waiting where the members are. It may already be made, and it can still be withdrawn (not done here):
    // turned round from "it cannot be withdrawn" by the rule of 18 November 2026 that a change can be withdrawn in both states.
    const waiting = logs.heldChange(vaultId!);
    expect(waiting).toMatchObject({ kind: "remove", member: B, memberLabel: "Bea", known: "unknown", withdrawable: true });
    expect(heldWaitingText(waiting)).toBe(fill(RESEND_WAITING_REMOVE_UNKNOWN, "Bea"));
    const other = await otherDevice(server, br, vaultId!);
    expect((await other.logs.append(vaultId, { kind: "role", member: B, role: "reader" })).kind).toBe("appended");
    const done = await logs.resendPending();
    expect(done.map((d) => d.outcome.kind)).toEqual(["head_moved"]);
    expect(done[0]!.change).toMatchObject({ kind: "remove", member: B, memberLabel: "Bea" });
    expect(server.count(vaultId!, "remove")).toBe(0);
    expect(logs.holds(vaultId!)).toBe(false);
    // What the person reads: the removal did not happen, and the member can still open the vault.
    expect(heldNoticeText({ kind: "held-not-made", heldKind: done[0]!.change.kind, memberName: done[0]!.change.memberLabel ?? undefined, vaultName: "Family" })).toBe(fill(RESEND_NOT_MADE_REMOVE, "Bea", "Family"));
  });

  it("a first post answered 409 log_head_moved whose follow-up read fails: isn't made yet; the re-send at the next unlock is refused, and that is said (the check's P3)", async () => {
    const server = new LogServer();
    server.install();
    const { logs, vaultId, br } = await ready(server, "remove");
    // Another entry takes the position first (the owner's other device), then the post is answered 409 and the read fails.
    const other = await otherDevice(server, br, vaultId!);
    const real = globalThis.fetch;
    let first = true;
    vi.stubGlobal("fetch", async (url: string, init: RequestInit = {}) => {
      if ((init.method ?? "GET") === "POST" && first) {
        first = false;
        expect((await other.logs.append(vaultId, { kind: "role", member: B, role: "reader" })).kind).toBe("appended");
        server.readsFail = true;
        return json({ error: "log_head_moved", message: "x" }, 409);
      }
      return real(url, init);
    });
    // The other device's own append runs through the stub's fall-through to the log server.
    const out = await logs.append(vaultId, ACTION.remove);
    vi.stubGlobal("fetch", real);
    expect(out).toMatchObject({ kind: "pending", known: "not_stored" });
    expect(lineFor(out, "remove")).toBe(LOG_NOT_STORED);
    // Known not stored: shown as waiting and may be withdrawn (not done here).
    expect(logs.heldChange(vaultId!)).toMatchObject({ kind: "remove", known: "not_stored", withdrawable: true });
    server.readsFail = false;
    const done = await logs.resendPending();
    expect(done.map((d) => d.outcome.kind)).toEqual(["head_moved"]);
    expect(server.count(vaultId!, "remove")).toBe(0);
    expect(heldNoticeText({ kind: "held-not-made", heldKind: "remove", memberName: "Bea", vaultName: "Family" })).toBe(fill(RESEND_NOT_MADE_REMOVE, "Bea", "Family"));
  });

  it("an addition the server asked to slow down: shown as waiting, and withdrawn before it is sent; nothing is sent for it again", async () => {
    const server = new LogServer();
    server.install();
    const { logs, vaultId } = await ready(server, "add");
    server.next = "rate_limited";
    const out = await logs.append(vaultId, ACTION.add);
    expect(out).toMatchObject({ kind: "pending", known: "not_stored" });
    const waiting = logs.heldChange(vaultId!);
    expect(waiting).toMatchObject({ kind: "add", member: B, memberLabel: "Bea", known: "not_stored", withdrawable: true });
    expect(heldWaitingText(waiting)).toBe(fill(RESEND_WAITING_ADD_NOT_STORED, "Bea"));
    expect(logs.withdrawHeld(vaultId!)).toBe(true);
    expect(logs.heldChange(vaultId!)).toBeNull();
    const posts = server.posts;
    expect(await logs.resendPending()).toEqual([]);
    expect(server.posts).toBe(posts);
    expect(server.count(vaultId!, "add")).toBe(0);
  });

  it("a re-post whose answer is lost is no longer 'not stored': 'cannot tell', still withdrawable, with the words of that state", async () => {
    const server = new LogServer();
    server.install();
    const { logs, vaultId } = await ready(server, "add");
    server.next = "rate_limited";
    await logs.append(vaultId, ACTION.add);
    server.next = "no_answer_stored";
    expect((await logs.resendPending()).map((d) => d.outcome)).toEqual([{ kind: "pending", vaultId, known: "unknown" }]);
    // Turned round: it pinned "can no longer be withdrawn".
    expect(logs.heldChange(vaultId!)).toMatchObject({ known: "unknown", withdrawable: true });
    expect(heldWaitingText(logs.heldChange(vaultId!))).toBe(fill(RESEND_WAITING_ADD_UNKNOWN, "Bea"));
    // Another 429 to a re-post settles nothing: still "cannot tell".
    server.next = "rate_limited";
    await logs.resendPending();
    expect(logs.heldChange(vaultId!)).toMatchObject({ known: "unknown", withdrawable: true });
  });

  it("a change whose answer was lost can be withdrawn, for every kind a person could regret: never sent again, the log read, and what it found said once", async () => {
    const waitingKey = { add: RESEND_WAITING_ADD_UNKNOWN, remove: RESEND_WAITING_REMOVE_UNKNOWN, role: RESEND_WAITING_ROLE_UNKNOWN, offer: RESEND_WAITING_OFFER_UNKNOWN, delete: RESEND_WAITING_DELETE_UNKNOWN } as const;
    for (const kind of ["add", "remove", "role", "offer", "delete"] as const) {
      for (const stored of [false, true]) {
        const server = new LogServer();
        server.install();
        const { logs, vaultId } = await ready(server, kind);
        server.next = stored ? "no_answer_stored" : "no_answer";
        expect(await logs.append(vaultId, ACTION[kind])).toMatchObject({ kind: "pending", known: "unknown" });
        const waiting = logs.heldChange(vaultId!);
        expect(waiting, kind).toMatchObject({ kind, known: "unknown", withdrawable: true });
        expect(heldWaitingText(waiting)).toBe(kind === "delete" ? waitingKey.delete : fill(waitingKey[kind], "Bea"));
        expect(logs.withdrawHeld(vaultId!), kind).toBe(true);
        expect(logs.holds(vaultId!)).toBe(false);
        const posts = server.posts;
        expect(await logs.resendPending()).toEqual([]);
        expect(server.posts, "never sent again").toBe(posts);
        // The log is read as soon as it can be: here at once.
        const found = await logs.checkWatched({ vaultId: vaultId!, read: true });
        expect(found.map((f) => [f.found, f.why, f.change.kind]), `${kind} stored=${stored}`).toEqual([[stored ? "made" : "not_made", "withdrawn", kind]]);
        if (kind !== "delete") expect(found[0]!.change.memberLabel).toBe("Bea");
        // Turned round by the rule that "not made" counts as told only once its notice is made: until the store notes
        // it (when it makes the notice), the look says it again; then once only.
        if (!stored) expect((await logs.checkWatched({ read: true })).map((f) => f.found)).toEqual(["not_made"]);
        logs.noteWatchTold(vaultId!, found[0]!.id);
        expect(await logs.checkWatched({ read: true })).toEqual([]);
        vi.unstubAllGlobals();
      }
    }
  });

  it("a withdrawn change whose read fails is read again at the next look, and told then", async () => {
    const server = new LogServer();
    server.install();
    const { logs, vaultId } = await ready(server, "remove");
    server.next = "no_answer";
    await logs.append(vaultId, ACTION.remove);
    expect(logs.withdrawHeld(vaultId!)).toBe(true);
    server.readsFail = true;
    expect(await logs.checkWatched({ read: true })).toEqual([]);
    server.readsFail = false;
    // No read reached the server yet, so the next look reads it without being asked to.
    expect((await logs.checkWatched()).map((f) => f.found)).toEqual(["not_made"]);
  });

  it("an answer that arrives for a change withdrawn while it was out does not bring the record back; the log says it was made after all", async () => {
    const server = new LogServer();
    server.install();
    const { logs, vaultId } = await ready(server, "remove");
    server.next = "no_answer";
    await logs.append(vaultId, ACTION.remove);
    // At the next unlock its re-send is out when the person withdraws it; the server then stores it and answers.
    const real = globalThis.fetch;
    let withdrew = false;
    vi.stubGlobal("fetch", async (url: string, init: RequestInit = {}) => {
      if ((init.method ?? "GET") === "POST" && !withdrew) {
        withdrew = true;
        expect(logs.withdrawHeld(vaultId!)).toBe(true);
      }
      return real(url, init);
    });
    await logs.resendPending();
    vi.stubGlobal("fetch", real);
    expect(withdrew).toBe(true);
    expect(server.count(vaultId!, "remove")).toBe(1);
    // On the code before: the "unknown" removal could not be withdrawn at all; and the answer's own save of the record
    // would have brought a withdrawn one back.
    expect(logs.holds(vaultId!), "not brought back").toBe(false);
    expect(logs.heldChange(vaultId!)).toBeNull();
    expect((await logs.checkWatched()).map((f) => [f.found, f.change.kind])).toEqual([["made", "remove"]]);
    expect(heldNoticeText({ kind: "held-found-made", heldKind: "remove", memberName: "Bea", vaultName: "Family" })).toBe(fill(RESEND_FOUND_MADE_REMOVE, "Bea", "Family"));
  });

  it("CL.5: a change given up while its outcome could not be told is remembered by its hash and position; if the log later holds it, that is said", async () => {
    let now = 1_763_164_800_000;
    const clock = () => now;
    const server = new LogServer();
    server.install();
    const { logs, vaultId } = await ready(server, "remove", clock);
    server.next = "no_answer";
    await logs.append(vaultId, ACTION.remove);
    now += 86_400_000;
    const done = await logs.resendPending();
    // The log, read then, does not hold it: said as not made.
    expect(done.map((d) => d.outcome)).toEqual([{ kind: "given_up", vaultId, made: false }]);
    expect(await logs.checkWatched({ read: true })).toEqual([]);
    // The server appends the frame it got later, while its position is free.
    server.appendLate(vaultId!, server.lost[0]!);
    const found = await logs.checkWatched({ read: true });
    expect(found.map((f) => [f.found, f.why, f.change.kind, f.change.memberLabel])).toEqual([["made", "given_up", "remove", "Bea"]]);
    // Once told, forgotten.
    expect(await logs.checkWatched({ read: true })).toEqual([]);
    expect(logs.watchedVaults()).toEqual([]);
  });

  it("CL.5: once another entry takes the position, the remembered change can never be made and is forgotten", async () => {
    const server = new LogServer();
    server.install();
    const { logs, vaultId } = await ready(server, "remove");
    server.next = "no_answer";
    await logs.append(vaultId, ACTION.remove);
    expect(logs.withdrawHeld(vaultId!)).toBe(true);
    const told = await logs.checkWatched({ read: true });
    expect(told.map((f) => f.found)).toEqual(["not_made"]);
    // Its notice is made (the store notes it then).
    logs.noteWatchTold(vaultId!, told[0]!.id);
    // The person's next change of this vault takes the place.
    expect((await logs.append(vaultId, { kind: "role", member: B, role: "reader" })).kind).toBe("appended");
    expect(await logs.checkWatched({ read: true })).toEqual([]);
    expect(logs.watchedVaults()).toEqual([]);
  });

  it("a change of role, a hand-over and a deletion that waited a day are given up like an addition, and one whose outcome is unknown never reads 'Nothing changed'", async () => {
    const key = { role: RESEND_GIVEN_UP_ROLE, offer: RESEND_GIVEN_UP_OFFER, delete: RESEND_GIVEN_UP_DELETE } as const;
    for (const kind of ["role", "offer", "delete"] as const) {
      let now = 1_763_164_800_000;
      const server = new LogServer();
      server.install();
      const { logs, vaultId } = await ready(server, kind, () => now);
      server.next = "no_answer";
      await logs.append(vaultId, ACTION[kind]);
      now += 86_400_000;
      server.readsFail = true;
      const posts = server.posts;
      const done = await logs.resendPending();
      // On the code before: sent again (only additions and removals were given up).
      expect(done.map((d) => d.outcome), kind).toEqual([{ kind: "given_up", vaultId, made: "unknown" }]);
      expect(server.posts).toBe(posts);
      const text = heldNoticeText({ kind: "held-given-up", heldKind: kind, memberName: "Bea", vaultName: "Family" });
      expect(text).toBe(kind === "delete" ? fill(key.delete, "Bea", "Family") : fill(key[kind], "Bea", "Family"));
      expect(text).not.toBe(fill(RESEND_NOT_MADE_CHANGE, "Family"));
      vi.unstubAllGlobals();
    }
  });

  it("a record held from before it carried its time counts its day from the first time it is seen", async () => {
    let now = 1_763_164_800_000;
    const server = new LogServer();
    server.install();
    const { logs, vaultId, br } = await ready(server, "remove", () => now);
    server.next = "no_answer";
    await logs.append(vaultId, ACTION.remove);
    const key = [...br.storage.map.keys()].find((k) => k.endsWith(`.${vaultId}.pending`))!;
    const rec = JSON.parse(br.storage.map.get(key)!) as Record<string, unknown>;
    delete rec.heldAt;
    br.storage.set(key, JSON.stringify(rec));
    now += 5 * 86_400_000;
    // First seen now: shown with that time, and sent again (not given up) until a day from now.
    expect(logs.heldChange(vaultId!)?.heldAt).toBe(now);
    server.next = "no_answer";
    expect((await logs.resendPending()).map((d) => d.outcome.kind)).toEqual(["pending"]);
    now += 86_400_000;
    server.readsFail = true;
    expect((await logs.resendPending()).map((d) => d.outcome)).toEqual([{ kind: "given_up", vaultId, made: "unknown" }]);
  });

  it("an addition or removal that waited a day is not sent again: given up and said (not made when the log, read then, lacks it; else cannot tell)", async () => {
    let now = 1_763_164_800_000;
    const clock = () => now;
    for (const [mode, readsFail, made] of [["rate_limited", false, false], ["no_answer", false, false], ["no_answer", true, "unknown"]] as const) {
      const server = new LogServer();
      server.install();
      const { logs, vaultId } = await ready(server, "remove", clock);
      server.next = mode;
      await logs.append(vaultId, ACTION.remove);
      now += 86_400_000;
      server.readsFail = readsFail;
      const posts = server.posts;
      const done = await logs.resendPending();
      expect(done.map((d) => d.outcome)).toEqual([{ kind: "given_up", vaultId, made }]);
      expect(server.posts, "nothing is posted for a change given up").toBe(posts);
      expect(logs.holds(vaultId!)).toBe(false);
      const text = heldNoticeText({ kind: made === false ? "held-not-made" : "held-given-up", heldKind: "remove", memberName: "Bea", vaultName: "Family" });
      expect(text).toBe(made === false ? fill(RESEND_NOT_MADE_REMOVE, "Bea", "Family") : fill(RESEND_GIVEN_UP_REMOVE, "Bea", "Family"));
      vi.unstubAllGlobals();
    }
  });

  it("the check's P2: during a give-up's read the person withdraws the removal and signs a role change whose answer is lost; the role change stays held and is sent at the next unlock, and the removal is told by its withdrawal's own watch", async () => {
    let now = 1_763_164_800_000;
    const server = new LogServer();
    server.install();
    const { logs, vaultId } = await ready(server, "remove", () => now);
    server.next = "no_answer";
    await logs.append(vaultId, ACTION.remove);
    now += 86_400_000;
    const real = globalThis.fetch;
    let started = false;
    let inner: AppendOutcome | null = null;
    vi.stubGlobal("fetch", async (url: string, init: RequestInit = {}) => {
      if ((init.method ?? "GET") === "GET" && !started) {
        // The give-up's read is out: the vault screen (or another tab) withdraws, and a new change is signed.
        started = true;
        expect(logs.withdrawHeld(vaultId!)).toBe(true);
        server.next = "no_answer";
        inner = await logs.append(vaultId, ACTION.role);
      }
      return real(url, init);
    });
    const done = await logs.resendPending();
    vi.stubGlobal("fetch", real);
    expect(inner).toMatchObject({ kind: "pending", known: "unknown" });
    // On the code before: the role change was dropped (held? false), the removal said "given up", and its watch overwritten.
    expect(done).toEqual([]);
    expect(logs.heldChange(vaultId!)).toMatchObject({ kind: "role", known: "unknown" });
    expect(logs.settledChanges()).toEqual([]);
    expect((await logs.checkWatched({ vaultId: vaultId!, read: true })).map((f) => [f.found, f.why, f.change.kind])).toEqual([["not_made", "withdrawn", "remove"]]);
    const posts = server.posts;
    expect((await logs.resendPending()).map((d) => d.outcome.kind)).toEqual(["appended"]);
    expect(server.posts).toBe(posts + 1);
    expect(server.count(vaultId!, "role")).toBe(1);
  });

  it("the check's P1: an addition stored, answered with a head beyond the frame, the reads one short, then withdrawn: no 'not made' from that short read; once the reads are whole, made after all", async () => {
    const server = new LogServer();
    server.install();
    const { logs, vaultId } = await ready(server, "add");
    server.next = "beyond_stored_short_read";
    expect(await logs.append(vaultId, ACTION.add)).toMatchObject({ kind: "pending", known: "unknown" });
    expect(logs.withdrawHeld(vaultId!)).toBe(true);
    // On the code before: [["not_made", "withdrawn", "add"]] while Bea holds the grant.
    expect(await logs.checkWatched({ vaultId: vaultId!, read: true })).toEqual([]);
    expect(await logs.checkWatched({ read: true })).toEqual([]);
    server.readsShort = null;
    expect((await logs.checkWatched({ read: true })).map((f) => [f.found, f.why, f.change.kind])).toEqual([["made", "withdrawn", "add"]]);
  });

  it("the same answer, and the change given up a day later from a read still short of that head: 'cannot tell', never 'not made'", async () => {
    let now = 1_763_164_800_000;
    const server = new LogServer();
    server.install();
    const { logs, vaultId } = await ready(server, "remove", () => now);
    server.next = "beyond_stored_short_read";
    expect(await logs.append(vaultId, ACTION.remove)).toMatchObject({ kind: "pending", known: "unknown" });
    now += 86_400_000;
    // On the code before: made: false ("didn't happen. Nothing changed") while the removal is stored.
    expect((await logs.resendPending()).map((d) => d.outcome)).toEqual([{ kind: "given_up", vaultId, made: "unknown" }]);
    server.readsShort = null;
    expect((await logs.checkWatched({ read: true })).map((f) => [f.found, f.why, f.change.kind])).toEqual([["made", "given_up", "remove"]]);
  });

  it("made after all is kept at rest until its notice is dismissed: another tab, or the next unlock, still has it; dismissed, it is forgotten", async () => {
    const server = new LogServer();
    server.install();
    const { logs, vaultId, br } = await ready(server, "remove");
    server.next = "no_answer_stored";
    await logs.append(vaultId, ACTION.remove);
    expect(logs.withdrawHeld(vaultId!)).toBe(true);
    expect((await logs.checkWatched({ read: true })).map((f) => f.found)).toEqual(["made"]);
    // Said once by the look, and kept: on the code before it was forgotten the moment it was found.
    expect(await logs.checkWatched({ read: true })).toEqual([]);
    expect(logs.watchedVaults(), "no longer looked for").toEqual([]);
    const later = browser(server, br.a, undefined, br.b, br.keys, br.storage);
    const kept = later.logs.madeWatches();
    expect(kept.map((f) => [f.found, f.why, f.change.kind, f.change.memberLabel])).toEqual([["made", "withdrawn", "remove", "Bea"]]);
    later.logs.dismissWatched(vaultId!, kept[0]!.id);
    expect(logs.madeWatches()).toEqual([]);
  });

  it("the check's P5: while a change's first request is out it cannot be withdrawn, in this tab or another; once that request ended it can", async () => {
    for (const mode of ["no_answer", "ok"] as const) {
      const server = new LogServer();
      server.install();
      const { logs, vaultId, br } = await ready(server, "add");
      const tab2 = browser(server, br.a, undefined, br.b, br.keys, br.storage);
      const real = globalThis.fetch;
      let mid: unknown = null;
      vi.stubGlobal("fetch", async (url: string, init: RequestInit = {}) => {
        if ((init.method ?? "GET") === "POST" && mid === null) mid = { there: tab2.logs.heldChange(vaultId!), withdrew: tab2.logs.withdrawHeld(vaultId!), here: logs.heldChange(vaultId!)?.withdrawable };
        return real(url, init);
      });
      server.next = mode;
      const out = await logs.append(vaultId, ACTION.add);
      vi.stubGlobal("fetch", real);
      // On the code before: withdrawable mid-flight, withdrawn, then "not made" said while this browser's post landed.
      expect(mid, mode).toMatchObject({ there: { kind: "add", known: "unknown", withdrawable: false }, withdrew: false, here: false });
      if (mode === "ok") {
        expect(out.kind).toBe("appended");
        expect(logs.heldChange(vaultId!)).toBeNull();
      } else {
        expect(out).toMatchObject({ kind: "pending", known: "unknown" });
        expect(tab2.logs.heldChange(vaultId!)).toMatchObject({ withdrawable: true });
        expect(tab2.logs.withdrawHeld(vaultId!)).toBe(true);
      }
      vi.unstubAllGlobals();
    }
  });

  it("a mark of a first request left by a tab closed mid-request stands for a bounded time only", async () => {
    let now = 1_763_164_800_000;
    const server = new LogServer();
    server.install();
    const { logs, vaultId, br } = await ready(server, "add", () => now);
    server.next = "no_answer";
    await logs.append(vaultId, ACTION.add);
    const key = [...br.storage.map.keys()].find((k) => k.endsWith(`.${vaultId}.pending`))!;
    br.storage.set(key, JSON.stringify({ ...(JSON.parse(br.storage.map.get(key)!) as object), firstOutAt: now }));
    expect(logs.heldChange(vaultId!)?.withdrawable).toBe(false);
    now += FIRST_POST_OUT_MAX_MS;
    expect(logs.heldChange(vaultId!)?.withdrawable).toBe(true);
  });

  it("the line after Withdraw follows the state the change had when it was withdrawn, not the one drawn earlier", async () => {
    const server = new LogServer();
    server.install();
    const { logs, vaultId } = await ready(server, "add");
    server.next = "rate_limited";
    await logs.append(vaultId, ACTION.add);
    const drawn = logs.heldChange(vaultId!);
    expect(drawn?.known).toBe("not_stored");
    // A re-post at the unlock went out after the panel was drawn, and its answer was lost.
    server.next = "no_answer";
    await logs.resendPending();
    expect(logs.withdrawHeldAs(vaultId!)).toBe("unknown");
    expect(withdrawnText("unknown")).toBe(RESEND_WITHDRAWN_UNKNOWN);
    expect(logs.watchedVaults()).toEqual([vaultId]);
  });

  it("the check's P6: the changes remembered for one vault are bounded, the oldest going first; one whose position another entry took goes at once", async () => {
    let now = 1_763_164_800_000;
    const server = new LogServer();
    server.install();
    const { logs, vaultId, br } = await ready(server, "remove", () => now);
    for (let i = 0; i < 20; i++) {
      now += 1000;
      server.next = "no_answer";
      await logs.append(vaultId, ACTION.remove);
      expect(logs.withdrawHeld(vaultId!)).toBe(true);
    }
    const key = [...br.storage.map.keys()].find((k) => k.endsWith(`.${vaultId}.watch`))!;
    const kept = () => (JSON.parse(br.storage.map.get(key) ?? "[]") as { hash: string }[]).map((w) => w.hash);
    // On the code before: all 20 kept, with no bound.
    expect(kept()).toEqual(server.lost.slice(20 - WATCHES_PER_VAULT_MAX).map(hashOf));
    const found = await logs.checkWatched({ read: true });
    expect(found).toHaveLength(WATCHES_PER_VAULT_MAX);
    // Their notices are made (the store notes each one then).
    for (const f of found) logs.noteWatchTold(vaultId!, f.id);
    // The person's next change takes the position: at the next withdrawal only that one is kept.
    expect((await logs.append(vaultId, ACTION.role)).kind).toBe("appended");
    now += 1000;
    server.next = "no_answer";
    await logs.append(vaultId, ACTION.remove);
    expect(logs.withdrawHeld(vaultId!)).toBe(true);
    expect(kept()).toEqual([hashOf(server.lost[20]!)]);
  });

  it("a vault's deletion that waits is never sent by the unlock: the person is asked, and it is sent only at their word; keeping the vault withdraws it", async () => {
    for (const keep of [false, true]) {
      const server = new LogServer();
      server.install();
      const { logs, vaultId } = await ready(server, "delete");
      server.next = "no_answer";
      expect(await logs.append(vaultId, ACTION.delete)).toMatchObject({ kind: "pending", known: "unknown" });
      const posts = server.posts;
      // On the code before: sent again at once by the unlock's re-send.
      expect(await logs.resendPending()).toEqual([]);
      expect(server.posts).toBe(posts);
      expect(logs.heldDeletionsToAsk()).toEqual([vaultId]);
      if (keep) {
        expect(logs.withdrawHeldAs(vaultId!)).toBe("unknown");
        expect(logs.heldDeletionsToAsk()).toEqual([]);
        expect(await logs.resendPending()).toEqual([]);
        expect(server.posts).toBe(posts);
      } else {
        expect((await logs.retryHeld(vaultId!))?.kind).toBe("appended");
        expect(server.count(vaultId!, "delete")).toBe(1);
      }
      vi.unstubAllGlobals();
    }
    // A half-made vault's plain deletion (known so by the caller) is not asked about.
    const server = new LogServer();
    server.install();
    const { logs, vaultId } = await ready(server, "delete");
    server.next = "no_answer";
    await logs.append(vaultId, ACTION.delete);
    expect(logs.heldDeletionsToAsk(new Set([vaultId!]))).toEqual([]);
  });
});

describe("an answer to an incoming share says what is known of its write (real transport)", () => {
  beforeAll(async () => {
    await initSodium();
  });
  afterEach(() => vi.unstubAllGlobals());

  const USER = A;
  function accountStore(put: () => Response | Promise<Response>, gateAt: number | null = null) {
    const client = new ApiClient(ORIGIN);
    client.boundUserId = USER;
    client.setTokens({ accessToken: "A-access", refreshToken: "A-refresh" });
    let checks = 0;
    client.trafficGate = () => (++checks === gateAt ? "forked" : null);
    const puts: string[] = [];
    vi.stubGlobal("fetch", async (url: string, init: RequestInit = {}) => {
      const path = new URL(url).pathname;
      if (path !== "/api/v1/account/state") return json({ error: "not_found", message: "x" }, 404);
      if ((init.method ?? "GET") === "GET") return json({ sealedState: null, seq: 0 });
      puts.push(String(init.body));
      return put();
    });
    return { store: new AccountStateStore(USER, randomBytes(32), new WireApi(client), memoryStorage()), puts };
  }
  const accept = (d: AccountDocument): AccountDocument => withAccepted(d, { vaultId: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", owner: B, addSeq: 1, at: 1, decision: "accept" });

  it("no answer to the write: can't tell (it may be saved), never 'wasn't saved'", async () => {
    const { store, puts } = accountStore(() => {
      throw new TypeError("Failed to fetch");
    });
    const w = await store.update(accept);
    expect(w).toMatchObject({ kind: "unknown", sent: true });
    expect(puts).toHaveLength(1);
    expect(shareAnswerText({ kind: "not_recorded", vaultId: "v", reason: "unknown" })).toBe(SHARE_ANSWER_UNKNOWN);
  });

  it("a 5xx, an answer cut off, or a page that is not the server's: can't tell", async () => {
    for (const put of [() => new Response("<html>502</html>", { status: 502, headers: { "Content-Type": "text/html" } }), cutOff, () => new Response("<html>portal</html>", { status: 200, headers: { "Content-Type": "text/html" } })]) {
      const { store } = accountStore(put);
      expect(await store.update(accept)).toMatchObject({ kind: "unknown", sent: true });
      vi.unstubAllGlobals();
    }
  });

  it("the server's refusal, or the gate before the write left: wasn't saved, nothing changed", async () => {
    const refused = accountStore(() => json({ error: "account_state_full", message: "x" }, 413));
    expect(await refused.store.update(accept)).toMatchObject({ kind: "refused" });
    vi.unstubAllGlobals();
    // Checks: the read's before and after, then the write's before (the third): the write never leaves.
    const gated = accountStore(() => json({ sealedState: null, seq: 1 }), 3);
    expect(await gated.store.update(accept)).toMatchObject({ kind: "refused" });
    expect(gated.puts).toHaveLength(0);
    expect(shareAnswerText({ kind: "not_recorded", vaultId: "v", reason: "forked" })).toBe(SHARE_NOT_RECORDED);
    expect(shareAnswerText({ kind: "not_recorded", vaultId: "v", reason: "unreachable" })).toBe(SHARE_NOT_RECORDED);
    expect(shareAnswerText({ kind: "declined", vaultId: "v" })).toBeNull();
  });
});

describe("the third check of withdrawing: a give-up acts on the record as held once its read ended, and a held deletion is looked for before it is asked about (real transport)", () => {
  beforeAll(async () => {
    await initSodium();
  });
  afterEach(() => vi.unstubAllGlobals());

  const T0 = 1_763_164_800_000;
  const seqOf = (frame: string): number => {
    const p = parseLogEntry(fromB64Canonical(frame)!);
    if (!p.ok) throw new Error("frame");
    return p.value.entry.seq;
  };

  /**
   * A removal held a day (its answer lost, nothing stored); the unlock's re-send gives it up, and while that give-up's
   * read is out (answered from the log before), the same frame is posted again (a move's step, or another tab's unlock)
   * with the answer [mode], its own read one short of the frame.
   */
  async function repostDuringGiveUp(mode: Mode) {
    let now = T0;
    const server = new LogServer();
    server.install();
    const { logs, vaultId, br } = await ready(server, "remove", () => now);
    server.next = "no_answer";
    await logs.append(vaultId, ACTION.remove);
    const frame = server.lost[0]!;
    now += 86_400_000;
    const real = globalThis.fetch;
    let started = false;
    let inner: AppendOutcome | null = null;
    vi.stubGlobal("fetch", async (url: string, init: RequestInit = {}) => {
      if ((init.method ?? "GET") === "GET" && !started) {
        started = true;
        const res = await real(url, init);
        server.readsShort = seqOf(frame);
        server.next = mode;
        inner = await logs.retryHeld(vaultId!);
        return res;
      }
      return real(url, init);
    });
    const done = await logs.resendPending();
    vi.stubGlobal("fetch", real);
    return { server, logs, vaultId: vaultId!, br, frame, done: done.map((d) => d.outcome), inner: inner as AppendOutcome | null };
  }

  it("G4: the re-post is answered 'stored': the change is not given up as 'didn't happen', it stays held as stored, and is read back once the reads are whole", async () => {
    const { server, logs, vaultId, done, inner } = await repostDuringGiveUp("ok");
    expect(inner).toMatchObject({ kind: "pending", known: "stored" });
    expect(server.count(vaultId, "remove")).toBe(1);
    // On the code before: [{ kind: "given_up", made: false }] ("didn't happen. Nothing changed"), the record dropped.
    expect(done).toEqual([{ kind: "pending", vaultId, known: "stored" }]);
    expect(logs.heldKnown(vaultId)).toBe("stored");
    expect(logs.settledChanges()).toEqual([]);
    expect(logs.watchedVaults()).toEqual([]);
    server.readsShort = null;
    expect(await logs.lookHeld(vaultId)).toMatchObject({ kind: "appended" });
    expect(logs.holds(vaultId)).toBe(false);
  });

  it("G5: the re-post is answered with a head beyond the frame: given up as 'cannot tell', never 'not made', and the head it named is remembered", async () => {
    const { server, logs, vaultId, br, frame, done, inner } = await repostDuringGiveUp("beyond_stored_short_read");
    expect(inner).toMatchObject({ kind: "pending", known: "unknown" });
    // On the code before: made: false, and the remembered change without the head.
    expect(done).toEqual([{ kind: "given_up", vaultId, made: "unknown" }]);
    const key = [...br.storage.map.keys()].find((k) => k.endsWith(`.${vaultId}.watch`))!;
    const watched = JSON.parse(br.storage.map.get(key)!) as { hash: string; beyond?: { seq: number; hash: string } }[];
    expect(watched.map((w) => [w.hash, w.beyond])).toEqual([[hashOf(frame), { seq: seqOf(frame) + 1, hash: "1".repeat(64) }]]);
    expect(await logs.checkWatched({ read: true })).toEqual([]);
    server.readsShort = null;
    expect((await logs.checkWatched({ read: true })).map((f) => [f.found, f.why, f.change.kind])).toEqual([["made", "given_up", "remove"]]);
  });

  it("S1: a held deletion the server stored (its answer lost) is found in the log before anyone is asked: not asked about, nothing sent, kept as made until its notice is dismissed", async () => {
    const server = new LogServer();
    server.install();
    const { logs, vaultId, br } = await ready(server, "delete");
    server.next = "no_answer_stored";
    expect(await logs.append(vaultId, ACTION.delete)).toMatchObject({ kind: "pending", known: "unknown" });
    expect(logs.heldDeletionsToAsk()).toEqual([vaultId]);
    const posts = server.posts;
    // On the code before there was no look: the unlock asked "delete it now, or keep the vault" of a vault already gone.
    expect(await logs.deletionsToAsk()).toEqual([]);
    expect(server.posts, "the look posts nothing").toBe(posts);
    expect(logs.holds(vaultId!)).toBe(false);
    const made = logs.madeWatches();
    expect(made.map((f) => [f.found, f.why, f.change.kind, f.change.vaultId])).toEqual([["made", "answer_lost", "delete", vaultId]]);
    // Kept at rest: another tab, or the next unlock, has it until it is dismissed.
    const later = browser(server, br.a, undefined, br.b, br.keys, br.storage);
    expect(later.logs.madeWatches().map((f) => f.id)).toEqual([made[0]!.id]);
    later.logs.dismissWatched(vaultId!, made[0]!.id);
    expect(logs.madeWatches()).toEqual([]);
  });

  it("S1: a held deletion whose place another entry took did not happen and is said so; one still held, or whose read fails, is asked about", async () => {
    for (const how of ["taken", "held", "unread"] as const) {
      const server = new LogServer();
      server.install();
      const { logs, vaultId, br } = await ready(server, "delete");
      server.next = "no_answer";
      await logs.append(vaultId, ACTION.delete);
      if (how === "taken") {
        const other = browser(server, br.a, undefined, br.b, br.keys);
        await other.logs.refresh(vaultId!, null, null, true);
        expect((await other.logs.append(vaultId, ACTION.role)).kind).toBe("appended");
      }
      if (how === "unread") server.readsFail = true;
      const posts = server.posts;
      expect(await logs.deletionsToAsk(), how).toEqual(how === "taken" ? [] : [vaultId]);
      expect(server.posts).toBe(posts);
      expect(logs.madeWatches()).toEqual([]);
      expect(logs.settledChanges().map((s) => [s.change.kind, s.outcome.kind]), how).toEqual(how === "taken" ? [["delete", "head_moved"]] : []);
      vi.unstubAllGlobals();
    }
  });

  /** An addition answered with a head beyond it that names nothing (seq + 1, a hash no log holds); nothing stored. */
  async function additionAnsweredBeyond() {
    const server = new LogServer();
    server.install();
    const { logs, vaultId, br } = await ready(server, "add");
    server.next = "beyond_unstored";
    expect(await logs.append(vaultId, ACTION.add)).toMatchObject({ kind: "pending", known: "unknown" });
    return { server, logs, vaultId: vaultId!, br };
  }

  it("H2: the change withdrawn, and the server's next entry takes its position: the answer said the server holds the change, so the read that shows another entry there freezes the vault, never 'not made'", async () => {
    const { logs, vaultId } = await additionAnsweredBeyond();
    expect(logs.withdrawHeld(vaultId)).toBe(true);
    // The person's next change is appended at the frame's own position (seq 1), where the server's 200 said it holds the
    // withdrawn one: the read after it shows the contradiction and freezes the vault there.
    expect((await logs.append(vaultId, ACTION.add)).kind).toBe("appended");
    expect(logs.status(vaultId)).toMatchObject({ kind: "frozen", atSeq: 1 });
    // On the code before H2: [["not_made", "withdrawn"]]; nothing is said of the change.
    expect(await logs.checkWatched({ read: true })).toEqual([]);
    // Nothing more is signed on its log.
    expect((await logs.append(vaultId, ACTION.role)).kind).toBe("read_only");
    expect(logs.status(vaultId)).toMatchObject({ kind: "frozen", atSeq: 1 });
  });

  /**
   * A removal the server acknowledged (its answer's head named this very frame at its position), whose read back failed,
   * so it is held as stored; then the server serves ANOTHER entry at that position (made by the person's other device,
   * after the server dropped the acknowledged frame).
   */
  async function acknowledgedThenReplaced() {
    const server = new LogServer();
    server.install();
    const { logs, vaultId, br } = await ready(server, "remove");
    const other = browser(server, br.a, undefined, br.b, br.keys);
    await other.logs.refresh(vaultId!, null, null, true);
    server.next = "ok_reads_fail";
    expect(await logs.append(vaultId, ACTION.remove)).toMatchObject({ kind: "pending", known: "stored" });
    const log = server.logs.get(vaultId!)!;
    const frame = log[log.length - 1]!;
    server.logs.set(vaultId!, log.slice(0, -1));
    server.readsFail = false;
    expect((await other.logs.append(vaultId!, ACTION.role)).kind).toBe("appended");
    const seq = seqOf(frame);
    expect(server.logs.get(vaultId!)!.length - 1, "another entry at the acknowledged frame's position").toBe(seq);
    return { server, logs, vaultId: vaultId!, seq };
  }

  it("a change the server acknowledged and later serves replaced by another entry is the fork it is: the vault is frozen there, the change dropped, never 'its place was taken'", async () => {
    const { logs, vaultId, seq } = await acknowledgedThenReplaced();
    // On the code before: null (dropped as a change whose place was taken: "didn't happen"), and the vault not frozen.
    expect(await logs.lookHeld(vaultId)).toEqual({ kind: "read_only", vaultId, frozen: "sent" });
    expect(logs.holds(vaultId)).toBe(false);
    expect(logs.status(vaultId)).toMatchObject({ kind: "frozen", atSeq: seq });
    expect(logs.settledChanges()).toEqual([]);
  });

  it("the look after a sync (nothing fetched): the same acknowledged change found replaced freezes the vault and is not concluded as taken", async () => {
    const { logs, vaultId, seq } = await acknowledgedThenReplaced();
    await logs.refresh(vaultId, null, null, true);
    // On the code before: [vaultId], the change concluded as "its place was taken".
    expect(logs.settleHeldFromLog()).toEqual([]);
    expect(logs.holds(vaultId)).toBe(false);
    expect(logs.status(vaultId)).toMatchObject({ kind: "frozen", atSeq: seq });
    expect(logs.settledChanges()).toEqual([]);
  });

  it("H2, the change still held: another entry at its position after an answer beyond it is never dropped as 'its place was taken': the vault freezes, and nothing is said of the change", async () => {
    const { server, logs, vaultId, br } = await additionAnsweredBeyond();
    const other = browser(server, br.a, undefined, br.b, br.keys);
    await other.logs.refresh(vaultId, null, null, true);
    expect((await other.logs.append(vaultId, ACTION.add)).kind).toBe("appended");
    // On the code before: null (dropped, as for a place taken).
    expect(await logs.lookHeld(vaultId)).toEqual({ kind: "read_only", vaultId, frozen: "sent" });
    expect(logs.status(vaultId).kind).toBe("frozen");
    expect(logs.settledChanges()).toEqual([]);
  });

  it("the look after a sync (nothing fetched, nothing posted): another entry at the change's position after an answer beyond it is no 'its place was taken' (the read froze the vault); the frame in the log settles it", async () => {
    const { server, logs, vaultId, br } = await additionAnsweredBeyond();
    const other = browser(server, br.a, undefined, br.b, br.keys);
    await other.logs.refresh(vaultId, null, null, true);
    expect((await other.logs.append(vaultId, ACTION.add)).kind).toBe("appended");
    await logs.refresh(vaultId, null, null, true);
    const posts = server.posts;
    expect(logs.settleHeldFromLog()).toEqual([]);
    expect(logs.status(vaultId).kind).toBe("frozen");
    expect(logs.holds(vaultId)).toBe(false);
    expect(logs.settledChanges()).toEqual([]);
    // A removal whose answer was lost and which the server stored: once the log this browser holds shows it, it is settled.
    const s2 = new LogServer();
    s2.install();
    const r = await ready(s2, "remove");
    s2.next = "no_answer_stored";
    await r.logs.append(r.vaultId, ACTION.remove);
    expect(r.logs.holds(r.vaultId!)).toBe(true);
    expect(r.logs.settleHeldFromLog(), "the log as held here does not show it yet").toEqual([]);
    await r.logs.refresh(r.vaultId!, null, null, true);
    const posts2 = s2.posts;
    expect(r.logs.settleHeldFromLog()).toEqual([r.vaultId]);
    expect(r.logs.holds(r.vaultId!)).toBe(false);
    expect(r.logs.settledChanges()).toEqual([]);
    expect([server.posts, s2.posts], "nothing is posted by the look").toEqual([posts, posts2]);
  });

  it("S3: a 'not made' found while its notice cannot be made yet is not marked told: a lock before the notice loses nothing, and the next session finds it again", async () => {
    const server = new LogServer();
    server.install();
    const { logs, vaultId, br } = await ready(server, "remove");
    server.next = "no_answer";
    await logs.append(vaultId, ACTION.remove);
    expect(logs.withdrawHeld(vaultId!)).toBe(true);
    const found = await logs.checkWatched({ read: true });
    expect(found.map((f) => f.found)).toEqual(["not_made"]);
    // The session locks before the notice is made. On the code before: [] (marked told by the look, notice in memory only).
    const next = browser(server, br.a, undefined, br.b, br.keys, br.storage);
    const again = await next.logs.checkWatched();
    expect(again.map((f) => [f.found, f.id])).toEqual([["not_made", found[0]!.id]]);
    next.logs.noteWatchTold(vaultId!, again[0]!.id);
    expect(await next.logs.checkWatched({ read: true })).toEqual([]);
  });

  it("the limit lets go first of the changes already told: one not told yet goes only when none of those is left", async () => {
    let now = T0;
    const server = new LogServer();
    server.install();
    const { logs, vaultId, br } = await ready(server, "remove", () => now);
    const withdrawOne = async () => {
      now += 1000;
      server.next = "no_answer";
      await logs.append(vaultId, ACTION.remove);
      expect(logs.withdrawHeld(vaultId!)).toBe(true);
    };
    await withdrawOne();
    await withdrawOne();
    // Both are found not made; only the second one's notice is made.
    const found = await logs.checkWatched({ read: true });
    expect(found).toHaveLength(2);
    logs.noteWatchTold(vaultId!, hashOf(server.lost[1]!));
    for (let i = 2; i <= WATCHES_PER_VAULT_MAX; i++) await withdrawOne();
    const key = [...br.storage.map.keys()].find((k) => k.endsWith(`.${vaultId}.watch`))!;
    const kept = (JSON.parse(br.storage.map.get(key)!) as { hash: string }[]).map((w) => w.hash);
    expect(kept).toHaveLength(WATCHES_PER_VAULT_MAX);
    // On the code before: the oldest (never told) went, and the told one stayed.
    expect(kept).toContain(hashOf(server.lost[0]!));
    expect(kept).not.toContain(hashOf(server.lost[1]!));
  });

  it("records at rest are kept by a reader that does not know every field: unknown fields ride along, an entry of a newer form or kind is left as it is and never acted on", async () => {
    const server = new LogServer();
    server.install();
    const { logs, vaultId, br } = await ready(server, "remove");
    server.next = "no_answer";
    await logs.append(vaultId, ACTION.remove);
    expect(logs.withdrawHeld(vaultId!)).toBe(true);
    const key = [...br.storage.map.keys()].find((k) => k.endsWith(`.${vaultId}.watch`))!;
    const [own] = JSON.parse(br.storage.map.get(key)!) as Record<string, unknown>[];
    const newer = { ...own!, hash: "f".repeat(64), form: 2, later: { a: 1 } };
    const otherKind = { ...own!, hash: "e".repeat(64), why: "a_later_kind" };
    br.storage.set(key, JSON.stringify([{ ...own!, note: "kept" }, newer, otherKind]));
    // On the code before: the newer entry was acted on (two findings) and the other kind dropped at the rewrite.
    const found = await logs.checkWatched({ read: true });
    expect(found.map((f) => f.id)).toEqual([own!.hash]);
    logs.noteWatchTold(vaultId!, own!.hash as string);
    const after = JSON.parse(br.storage.map.get(key)!) as Record<string, unknown>[];
    expect(after.find((w) => w.hash === own!.hash)).toMatchObject({ note: "kept", told: true });
    expect(after).toContainEqual(newer);
    expect(after).toContainEqual(otherKind);
    // The settled list too.
    const sKey = `andvari.log2.${A}.${vaultId}.settled`;
    const foreign = { pending: { vaultId, frame: own!.frame }, outcome: { kind: "given_up", vaultId, made: false }, form: 2 };
    const known = { pending: { vaultId, frame: own!.frame }, outcome: { kind: "head_moved", vaultId } };
    br.storage.set(sKey, JSON.stringify([known, foreign]));
    br.storage.set(`andvari.log2.${A}.settled-index`, vaultId!);
    expect(logs.settledChanges().map((s) => s.outcome.kind)).toEqual(["head_moved"]);
    // Its notice is dismissed: the list is rewritten, and the entry of a newer form stays as it was.
    logs.dismissSettled(vaultId!, own!.hash as string);
    expect(logs.settledChanges()).toEqual([]);
    expect(JSON.parse(br.storage.map.get(sKey)!)).toEqual([foreign]);
  });
});
