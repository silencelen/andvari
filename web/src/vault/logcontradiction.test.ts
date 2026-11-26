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
import { type AppendOutcome, type LogAction, VaultLogStore } from "./logstore";

/**
 * A server that answers a held change to a shared vault as stored while nothing is stored, and then serves another entry
 * at that change's position, has contradicted its own word: the vault freezes, at the read that shows it, with nothing
 * else called after that read (no look, no re-send, no settle, no withdrawal). With the REAL transport (ApiClient,
 * WireApi), only `fetch` played by a stand-in log server that can lie.
 *
 * The shapes of "the server called it stored": a `200` whose head is at the change's position with the change's own
 * hash, or a head beyond the change's position (as for a byte-identical frame it already holds). A head BELOW the
 * change's position is no answer about it, and a read that then shows another entry there freezes nothing.
 *
 * And no honest sequence freezes a vault: an answer lost (stored or not), a refusal because the head moved, a stored
 * change answered beyond it, each followed by another device's entry and one read, leave the vault verified and open.
 */
const ORIGIN = "https://vault.example.org";
const A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const B = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

type Mode =
  | "ok"
  // Lies: nothing is stored, and the answer is a 200 in the route's shape.
  | "lie_at_position"
  | "lie_far_beyond"
  | "lie_below"
  // Honest endings.
  | "no_answer"
  | "no_answer_stored"
  | "stored_answered_beyond";

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
  /** The frames posted under a lie (never stored). */
  liedAbout: string[] = [];

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
        const all = this.logs.get(vaultId) ?? [];
        const after = u.searchParams.get("after");
        const from = after === null ? 0 : Number(after) + 1;
        return json({ entries: all.slice(from), head: { ...this.head(vaultId), at: 1 }, purged: null, deleted: null });
      }
      this.posts++;
      const mode = this.next;
      this.next = "ok";
      const req = JSON.parse(String(init.body)) as { entry: string; grant?: string; wrappedVk?: string };
      const log = this.logs.get(vaultId) ?? [];
      if (mode === "lie_at_position" || mode === "lie_far_beyond" || mode === "lie_below") {
        this.liedAbout.push(req.entry);
        const seq = seqOf(req.entry);
        if (mode === "lie_at_position") return json({ rev: 1, head: { seq, hash: hashOf(req.entry), at: 1 }, deleted: null });
        if (mode === "lie_far_beyond") return json({ rev: 1, head: { seq: seq + 7, hash: "ab".repeat(32), at: 1 }, deleted: null });
        // Below: the log's own head, one short of the change's position.
        return json({ rev: 1, head: { ...this.head(vaultId), at: 1 }, deleted: null });
      }
      if (mode === "no_answer") throw new TypeError("Failed to fetch");
      const known = log.includes(req.entry);
      // As the server: a new entry is taken only at the next position; another entry already there is `log_head_moved`.
      if (!known && seqOf(req.entry) !== log.length) return json({ error: "log_head_moved", message: "x" }, 409);
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
      const head = this.head(vaultId);
      if (mode === "no_answer_stored") throw new TypeError("Failed to fetch");
      // A byte-identical frame it already holds is answered with the head, which may lie beyond the frame.
      if (mode === "stored_answered_beyond") return json({ rev: 1, head: { seq: head.seq + 1, hash: "1".repeat(64), at: 1 }, deleted: null });
      return json({ rev: 1, head: { ...head, at: 1 }, deleted: null });
    });
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

type Person = ReturnType<typeof person>;

function browser(server: LogServer, a: Person, b: Person, keys: Map<string, Uint8Array>) {
  const client = new ApiClient(ORIGIN);
  client.boundUserId = A;
  client.setTokens({ accessToken: "A-access", refreshToken: "A-refresh" });
  const contacts: Record<string, string> = { [B]: toB64(b.box.publicKey) };
  return new VaultLogStore(a.userId, a.sign, a.box, a.uvk, new WireApi(client), memoryStorage(), new Account(), {
    grantRow: (vaultId) => server.grants.get(vaultId)?.get(a.userId) ?? null,
    isCurrentContact: (u, key) => contacts[u] === key,
    currentContact: (u) => (contacts[u] ? { key: contacts[u]!, compared: true } : null),
    labelFor: (u) => (u === B ? "Bea" : null),
    vaultName: () => "Family",
    sealMeta: () => "meta",
    serverOwnerName: () => null,
  }, keys, () => 1_763_164_800_000);
}

/** The owner's vault with Bea a writer, on this browser and on the owner's other device (both verified to its head). */
async function vaultWithBea() {
  const server = new LogServer();
  server.install();
  const a = person(A);
  const b = person(B);
  const keys = new Map<string, Uint8Array>();
  const logs = browser(server, a, b, keys);
  const c = await logs.append(null, { kind: "create", name: "Family" });
  if (c.kind !== "appended") throw new Error(`create: ${c.kind}`);
  const vaultId = c.vaultId;
  expect((await logs.append(vaultId, { kind: "add", contactUserId: B, role: "writer", releaseUncompared: false })).kind).toBe("appended");
  const other = browser(server, a, b, keys);
  await other.refresh(vaultId, null, null, true);
  return { server, logs, other, vaultId };
}

type Change = "role" | "move_delete";

const CHANGE: Record<Change, { action: LogAction; forMove: boolean }> = {
  role: { action: { kind: "role", member: B, role: "reader" }, forMove: false },
  // The old vault's deletion signed by "Move everything" (design §3.13): only the move re-posts it.
  move_delete: { action: { kind: "delete" }, forMove: true },
};

/** What the vault reads on this browser, as the screens and every write read it. */
function reads(logs: VaultLogStore, vaultId: string) {
  return { status: logs.status(vaultId).kind, writable: logs.writeAllowed(vaultId) };
}

/**
 * [change] is signed and posted, and answered under [mode]; then the owner's other device signs Bea's removal, which the
 * server stores at the change's own position; then ONE read of the vault's log, as a sync makes it with the head the
 * server serves. Nothing else is called on this browser's store between the answer and the read, or after the read.
 */
async function answeredThenReplaced(mode: Mode, change: Change) {
  const { server, logs, other, vaultId } = await vaultWithBea();
  const position = server.logs.get(vaultId)!.length;
  server.next = mode;
  const out: AppendOutcome = await logs.append(vaultId, CHANGE[change].action, { forMove: CHANGE[change].forMove });
  const afterAnswer = { ...reads(logs, vaultId), held: logs.heldKnown(vaultId) };
  expect((await other.append(vaultId, { kind: "remove", member: B })).kind, "the other device's entry is stored").toBe("appended");
  const log = server.logs.get(vaultId)!;
  expect(log.length - 1, "another entry at the change's position").toBe(position);
  const posts = server.posts;
  const head = server.head(vaultId);
  await logs.refresh(vaultId, head.seq, head.hash);
  expect(server.posts, "the read posts nothing").toBe(posts);
  return { out, afterAnswer, logs, vaultId, position };
}

describe("a server that called a change stored and then serves another entry at its place: the vault freezes at the read (real transport)", () => {
  beforeAll(async () => {
    await initSodium();
  });
  afterEach(() => vi.unstubAllGlobals());

  for (const change of ["role", "move_delete"] as const) {
    describe(change === "role" ? "a change of a member's role" : "a move's own deletion of the old vault", () => {
      it("answered 200 at its position with its own hash while nothing is stored; another entry there; one read: frozen and not writable", async () => {
        const { out, afterAnswer, logs, vaultId, position } = await answeredThenReplaced("lie_at_position", change);
        // The server's word: stored (not read back yet). Nothing contradicts it yet.
        expect(out).toMatchObject({ kind: "pending", known: "stored" });
        expect(afterAnswer).toEqual({ status: "verified", writable: true, held: "stored" });
        // The read shows another entry where the server said this change is stored.
        expect(reads(logs, vaultId)).toEqual({ status: "frozen", writable: false });
        expect(logs.status(vaultId)).toMatchObject({ kind: "frozen", atSeq: position });
      });

      it("answered 200 with a head far beyond its position while nothing is stored; another entry there; one read: frozen and not writable", async () => {
        const { out, afterAnswer, logs, vaultId, position } = await answeredThenReplaced("lie_far_beyond", change);
        expect(out).toMatchObject({ kind: "pending", known: "unknown" });
        expect(afterAnswer).toEqual({ status: "verified", writable: true, held: "unknown" });
        expect(reads(logs, vaultId)).toEqual({ status: "frozen", writable: false });
        expect(logs.status(vaultId)).toMatchObject({ kind: "frozen", atSeq: position });
      });

      it("answered 200 with a head BELOW its position: no answer about it; another entry there; one read: not frozen", async () => {
        const { out, logs, vaultId } = await answeredThenReplaced("lie_below", change);
        expect(out).toMatchObject({ kind: "pending", known: "unknown" });
        expect(logs.status(vaultId).kind).toBe("verified");
        // The log store's own rule (a move's deletion that waits is kept read-only by the vault store above it).
        expect(logs.writeAllowed(vaultId)).toBe(true);
      });
    });
  }

  it("a change withdrawn after the server's answer named a head beyond it is remembered with that head: another entry at its position and one read freeze the vault, and nothing is said of the change", async () => {
    const { server, logs, other, vaultId } = await vaultWithBea();
    const position = server.logs.get(vaultId)!.length;
    server.next = "lie_far_beyond";
    expect(await logs.append(vaultId, CHANGE.role.action)).toMatchObject({ kind: "pending", known: "unknown" });
    expect(logs.withdrawHeld(vaultId)).toBe(true);
    expect((await other.append(vaultId, { kind: "remove", member: B })).kind).toBe("appended");
    const head = server.head(vaultId);
    await logs.refresh(vaultId, head.seq, head.hash);
    expect(reads(logs, vaultId)).toEqual({ status: "frozen", writable: false });
    expect(logs.status(vaultId)).toMatchObject({ kind: "frozen", atSeq: position });
    expect(await logs.checkWatched(), "nothing is said of the change").toEqual([]);
  });

  it("no honest sequence freezes a vault: an answer lost (stored or not), a refusal because the head moved, a stored change answered beyond it; each with another device's entry and one read", async () => {
    for (const change of ["role", "move_delete"] as const) {
      // Not stored, its answer lost: the other device's entry takes its place.
      const lost = await answeredThenReplaced("no_answer", change);
      expect(reads(lost.logs, lost.vaultId), `${change}: lost, not stored`).toEqual({ status: "verified", writable: true });
      vi.unstubAllGlobals();
    }
    for (const mode of ["no_answer_stored", "stored_answered_beyond", "ok"] as const) {
      // Stored: the other device's entry comes after it.
      const { server, logs, other, vaultId } = await vaultWithBea();
      server.next = mode;
      await logs.append(vaultId, CHANGE.role.action);
      await other.refresh(vaultId, null, null, true);
      expect((await other.append(vaultId, { kind: "remove", member: B })).kind).toBe("appended");
      const head = server.head(vaultId);
      await logs.refresh(vaultId, head.seq, head.hash);
      expect(reads(logs, vaultId), mode).toEqual({ status: "verified", writable: true });
      vi.unstubAllGlobals();
    }
    // Refused because another entry took the head first (409 log_head_moved): the change is not made, nothing freezes.
    const { server, logs, other, vaultId } = await vaultWithBea();
    expect((await other.append(vaultId, { kind: "remove", member: B })).kind).toBe("appended");
    const out = await logs.append(vaultId, CHANGE.role.action);
    expect(out.kind).not.toBe("appended");
    const head = server.head(vaultId);
    await logs.refresh(vaultId, head.seq, head.hash);
    expect(logs.status(vaultId).kind).toBe("verified");
  });
});
