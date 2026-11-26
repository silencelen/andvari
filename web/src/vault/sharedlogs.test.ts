import { beforeAll, describe, expect, it } from "vitest";
import { ApiError } from "../api/client";
import { memoryStorage } from "../api/devicesecret";
import type { AccountStateResponseV2, LogAppendRequest, LogPage } from "../api/wire";
import { adAccountState } from "../crypto/ad";
import { toB64, toHexLower, utf8 } from "../crypto/bytes";
import { seal } from "../crypto/envelope";
import { boxKeypairFromSeed, randomBytes, sha256Sync, signKeypairFromSeed } from "../crypto/provider";
import { initSodium } from "../crypto/sodium";
import { fromB64Canonical } from "../crypto/trust/grammar";
import { parseLogEntry } from "../crypto/trust/vaultlog";
import { Account } from "./account";
import { type AccountDocument, type ContactRecord, EMPTY_DOCUMENT, encodeDocument } from "./accountdoc";
import { stateMayHaveMoved } from "./accountdocstore";
import { SharedLogSession, vaultNameUnder } from "./sharedlogs";

/**
 * The session's shared-vault layer: the log store, the account state and the contact currency built together, and
 * the key ring of the session's Account (design §3.6). A fake server keeps the logs, the grant rows and the meta
 * blobs the entries post, and one account-state blob per account.
 */
class Server {
  logs = new Map<string, string[]>();
  grants = new Map<string, Map<string, { wrappedVk: string; signedGrant: string | null }>>();
  metas = new Map<string, string>();
  caller = "";
  states = new Map<string, { sealed: string | null; seq: number }>();

  wireFor(userId: string) {
    const s = this;
    return {
      async logPage(vaultId: string, after: number | null): Promise<LogPage> {
        const all = s.logs.get(vaultId) ?? [];
        const last = all[all.length - 1];
        const head = last ? { seq: all.length - 1, hash: toHexLower(sha256Sync(fromB64Canonical(last)!)), at: 1 } : { seq: -1, hash: "", at: 0 };
        return { entries: all.slice(after === null ? 0 : after + 1), head, purged: null, deleted: null };
      },
      async appendLog(vaultId: string, req: LogAppendRequest) {
        const log = s.logs.get(vaultId) ?? [];
        s.logs.set(vaultId, [...log, req.entry]);
        if (req.metaBlob) s.metas.set(vaultId, req.metaBlob);
        const parsed = parseLogEntry(fromB64Canonical(req.entry)!);
        if (parsed.ok) {
          const e = parsed.value.entry;
          const rows = s.grants.get(vaultId) ?? new Map();
          if (e.kind === "genesis") rows.set(e.actor, { wrappedVk: req.wrappedVk ?? "", signedGrant: null });
          if (e.kind === "add") rows.set(e.member, { wrappedVk: "", signedGrant: req.grant ?? null });
          s.grants.set(vaultId, rows);
        }
        return { rev: 1, head: { seq: log.length, hash: "x", at: 1 }, deleted: null };
      },
      async putSelfWrap(vaultId: string, wrappedVk: string) {
        const row = s.grants.get(vaultId)?.get(userId);
        if (row) row.wrappedVk = wrappedVk;
        return 1;
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

  /** Seeds [userId]'s served account state with [doc], sealed under [uvk]. */
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

function contact(of: ReturnType<typeof person>, name: string): ContactRecord {
  return { userId: of.userId, identityPub: toB64(of.identity.publicKey), label: toB64(utf8(name)), method: "link", verifiedAt: 1, compared: true, madeOn: "ffffffff-ffff-4fff-8fff-ffffffffffff", extra: new Map() };
}

function withContact(c: ContactRecord): AccountDocument {
  return { ...EMPTY_DOCUMENT, contacts: new Map([[c.userId, c]]) };
}

/** An Account the way enterVault builds it, with a personal vault so the key ring has one to refuse. */
function accountFor(p: ReturnType<typeof person>, personalVaultId: string): Account {
  return Account.fromOpened(
    { userId: p.userId, uvk: p.uvk, identity: p.identity, signing: p.signing, genesis: null as never, personalVaultId, personalVk: randomBytes(32) },
    null,
  );
}

const PV = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
const NOW = () => 1_763_164_800_000;

describe("the session's shared-vault layer", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("the Account's key ring never takes the personal vault, and a log-governed vault's role is the verified log's", () => {
    const b = person(B);
    const acct = accountFor(b, PV);
    const ring = acct.logKeyRing();
    expect(() => ring.set(PV, randomBytes(32))).toThrow();
    expect(ring.has(PV)).toBe(false);
    const v = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
    const vk = randomBytes(32);
    ring.set(v, vk);
    expect(acct.hasVault(v)).toBe(true);
    expect(acct.isLogGoverned(v)).toBe(true);
    expect(acct.roleFor(v)).toBeNull();
    // No write gate attached: nothing is sealed under a log-governed key.
    expect(acct.canSealUnder(v)).toBe(false);
    let role = "reader";
    acct.attachLogRoles((id) => (id === v ? role : null), (id) => id === v);
    expect(acct.roleFor(v)).toBe("reader");
    expect(acct.canSealUnder(v)).toBe(false);
    role = "writer";
    expect(acct.canSealUnder(v)).toBe(true);
    acct.attachLogRoles((id) => (id === v ? role : null), () => false);
    expect(acct.canSealUnder(v)).toBe(false);
    ring.delete(v);
    expect(acct.hasVault(v)).toBe(false);
    expect([...vk].every((x) => x === 0)).toBe(true);
  });

  it("a member's browser is asked, accepts, and the vault's key reaches the Account with the log's role", async () => {
    const server = new Server();
    const a = person(A);
    const b = person(B);
    // A's side: B is a contact, current on A's browser.
    server.seedState(A, a.uvk, withContact(contact(b, "Bob")));
    const aAcct = accountFor(a, "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee");
    const aSide = new SharedLogSession(a, server.wireFor(A), memoryStorage(), aAcct.logKeyRing(), NOW);
    await aSide.refreshState();
    aSide.currency.mark(B, toB64(b.identity.publicKey), "confirmed");
    const created = await aSide.logs.append(null, { kind: "create", name: "Family" });
    if (created.kind !== "appended") throw new Error(`create: ${created.kind}`);
    const v = created.vaultId;
    expect(aAcct.hasVault(v)).toBe(true);
    expect((await aSide.logs.append(v, { kind: "add", contactUserId: B, role: "writer", releaseUncompared: false })).kind).toBe("appended");

    // B's browser: A is a contact made elsewhere and confirmed here.
    server.seedState(B, b.uvk, withContact(contact(a, "Alice")));
    const bAcct = accountFor(b, PV);
    const bSide = new SharedLogSession(b, server.wireFor(B), memoryStorage(), bAcct.logKeyRing(), NOW);
    bAcct.attachLogRoles((id) => bSide.logs.roleOf(id));
    expect(await bSide.refreshState()).not.toBe("unreachable");
    bSide.currency.mark(A, toB64(a.identity.publicKey), "confirmed");
    bSide.noteGrantRow(v, server.grants.get(v)!.get(B)!);
    bSide.noteVaultMeta(v, server.metas.get(v)!);

    const asked = await bSide.onSharedVault(v, null);
    expect(asked).toMatchObject({ kind: "ask", vaultId: v, owner: A, ownerLabel: "Alice", vaultName: "Family" });
    expect(bAcct.hasVault(v)).toBe(false);
    expect(bSide.pendingAsks().map((x) => x.vaultId)).toEqual([v]);

    const answered = await bSide.answer(bSide.pendingAsks()[0]!, true);
    expect(answered.kind).toBe("adopted");
    expect(bAcct.hasVault(v)).toBe(true);
    expect(bAcct.roleFor(v)).toBe("writer");
    expect(bSide.pendingAsks()).toEqual([]);

    // A removal the log does not show keeps the vault; the owner's remove is read from the log.
    expect((await bSide.onRemoved(v)).kind).toBe("verified");
    expect((await aSide.logs.append(v, { kind: "remove", member: B })).kind).toBe("appended");
    expect(await bSide.onRemoved(v)).toMatchObject({ kind: "removed", byOwner: true });
    expect(bSide.logs.writeAllowed(v)).toBe(false);
  });

  it("after a reload the cached vault's key is adopted again from the log's verified state, with nothing fetched", async () => {
    const server = new Server();
    const a = person(A);
    const b = person(B);
    server.seedState(A, a.uvk, withContact(contact(b, "Bob")));
    const aAcct = accountFor(a, "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee");
    const aSide = new SharedLogSession(a, server.wireFor(A), memoryStorage(), aAcct.logKeyRing(), NOW);
    await aSide.refreshState();
    aSide.currency.mark(B, toB64(b.identity.publicKey), "confirmed");
    const created = await aSide.logs.append(null, { kind: "create", name: "Family" });
    if (created.kind !== "appended") throw new Error(`create: ${created.kind}`);
    const v = created.vaultId;
    expect((await aSide.logs.append(v, { kind: "add", contactUserId: B, role: "writer", releaseUncompared: false })).kind).toBe("appended");
    server.seedState(B, b.uvk, withContact(contact(a, "Alice")));
    const storage = memoryStorage(); // B's browser storage: it survives the reload
    const bAcct = accountFor(b, PV);
    const bSide = new SharedLogSession(b, server.wireFor(B), storage, bAcct.logKeyRing(), NOW);
    await bSide.refreshState();
    bSide.currency.mark(A, toB64(a.identity.publicKey), "confirmed");
    bSide.noteGrantRow(v, server.grants.get(v)!.get(B)!);
    bSide.noteVaultMeta(v, server.metas.get(v)!);
    await bSide.onSharedVault(v, null);
    expect((await bSide.answer(bSide.pendingAsks()[0]!, true)).kind).toBe("adopted");

    // The reload: a fresh Account, the same storage, the cached grant row; the server answers nothing at all.
    const reloaded = accountFor(b, PV);
    let calls = 0;
    const dead = new Proxy(server.wireFor(B), { get: () => async () => { calls++; throw new ApiError(0, "network", "offline"); } });
    const again = new SharedLogSession(b, dead, storage, reloaded.logKeyRing(), NOW);
    reloaded.attachLogRoles((id) => again.logs.roleOf(id), (id) => again.logs.writeAllowed(id));
    again.noteGrantRow(v, server.grants.get(v)!.get(B)!);
    expect(reloaded.hasVault(v)).toBe(false);
    expect((await again.onCachedVault(v))?.kind).toBe("adopted");
    expect(reloaded.hasVault(v)).toBe(true);
    expect(reloaded.roleFor(v)).toBe("writer");
    expect(calls).toBe(0);
    // A vault whose log was never verified here adopts nothing.
    expect(await again.onCachedVault("dddddddd-dddd-4ddd-8ddd-dddddddddddd")).toBeNull();
  });

  it("a share from someone who is not a current contact here decrypts nothing and names no one", async () => {
    const server = new Server();
    const a = person(A);
    const b = person(B);
    server.seedState(A, a.uvk, withContact(contact(b, "Bob")));
    const aSide = new SharedLogSession(a, server.wireFor(A), memoryStorage(), accountFor(a, "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee").logKeyRing(), NOW);
    await aSide.refreshState();
    aSide.currency.mark(B, toB64(b.identity.publicKey), "confirmed");
    const created = await aSide.logs.append(null, { kind: "create", name: "Family" });
    if (created.kind !== "appended") throw new Error("create");
    expect((await aSide.logs.append(created.vaultId, { kind: "add", contactUserId: B, role: "reader", releaseUncompared: false })).kind).toBe("appended");

    // B's account holds A as a contact, but A is not current on THIS browser (no confirmation, no one-tap list).
    server.seedState(B, b.uvk, withContact(contact(a, "Alice")));
    const bAcct = accountFor(b, PV);
    const bSide = new SharedLogSession(b, server.wireFor(B), memoryStorage(), bAcct.logKeyRing(), NOW);
    await bSide.refreshState();
    bSide.noteGrantRow(created.vaultId, server.grants.get(created.vaultId)!.get(B)!);
    bSide.noteVaultMeta(created.vaultId, server.metas.get(created.vaultId)!);
    expect(await bSide.onSharedVault(created.vaultId, null)).toEqual({ kind: "connect_first", vaultId: created.vaultId, serverName: null });
    expect(bAcct.hasVault(created.vaultId)).toBe(false);
    expect(bSide.pendingAsks()).toEqual([]);
  });

  it("the member list is the verified log's, labelled only where the log's key is a current contact's (§3.9)", async () => {
    const server = new Server();
    const a = person(A);
    const b = person(B);
    const c = person("dddddddd-dddd-4ddd-8ddd-dddddddddddd");
    server.seedState(A, a.uvk, { ...EMPTY_DOCUMENT, contacts: new Map([[B, contact(b, "Bob")], [c.userId, contact(c, "Cy")]]) });
    const aAcct = accountFor(a, "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee");
    const aSide = new SharedLogSession(a, server.wireFor(A), memoryStorage(), aAcct.logKeyRing(), NOW);
    expect(aSide.roster("ffffffff-0000-4000-8000-000000000000", A)).toBeNull();
    await aSide.refreshState();
    aSide.currency.mark(B, toB64(b.identity.publicKey), "confirmed");
    aSide.currency.mark(c.userId, toB64(c.identity.publicKey), "confirmed");
    const created = await aSide.logs.append(null, { kind: "create", name: "Family" });
    if (created.kind !== "appended") throw new Error("create");
    const v = created.vaultId;
    expect((await aSide.logs.append(v, { kind: "add", contactUserId: B, role: "writer", releaseUncompared: false })).kind).toBe("appended");
    expect((await aSide.logs.append(v, { kind: "add", contactUserId: c.userId, role: "reader", releaseUncompared: false })).kind).toBe("appended");
    const r = aSide.roster(v, A)!;
    expect(r.rows.map((x) => [x.userId, x.role, x.label, x.self])).toEqual([
      [A, "owner", null, true],
      [B, "writer", "Bob", false],
      [c.userId, "reader", "Cy", false],
    ]);
    expect(r.mayBeIncomplete).toBe(false);
    expect(r.stale).toBe(false);

    // Cy's contact record now names another key: the log's member key is no contact's here, so no label is shown.
    const other = person(c.userId);
    await aSide.accountState.update((d) => ({ ...d, contacts: new Map([...d.contacts, [c.userId, contact(other, "Cy")]]) }));
    expect(aSide.roster(v, A)!.rows.find((x) => x.userId === c.userId)!.label).toBeNull();
    // Bob's key is in the contacts but not current on this browser: no label either.
    aSide.currency.drop(B);
    expect(aSide.roster(v, A)!.rows.find((x) => x.userId === B)!.label).toBeNull();
  });

  it("the owner's own wrap opens only under the verified log's genesis and key commitment, and is not kept", async () => {
    const server = new Server();
    const a = person(A);
    server.seedState(A, a.uvk, EMPTY_DOCUMENT);
    const aAcct = accountFor(a, "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee");
    const aSide = new SharedLogSession(a, server.wireFor(A), memoryStorage(), aAcct.logKeyRing(), NOW);
    await aSide.refreshState();
    const created = await aSide.logs.append(null, { kind: "create", name: "Family" });
    if (created.kind !== "appended") throw new Error("create");
    const v = created.vaultId;
    const wrap = server.grants.get(v)!.get(A)!.wrappedVk;
    const vk = await aSide.logs.openOwnWrap(v, wrap);
    expect(vk).not.toBeNull();
    expect(vaultNameUnder(v, vk!, server.metas.get(v)!)).toBe("Family");
    // Another vault's log, a wrap under someone else's UVK, and no verified log at all: nothing opens.
    expect(await aSide.logs.openOwnWrap("ffffffff-0000-4000-8000-000000000000", wrap)).toBeNull();
    const stranger = toB64(seal(randomBytes(32), randomBytes(32), utf8("x")));
    expect(await aSide.logs.openOwnWrap(v, stranger)).toBeNull();
  });

  it("records how the session was made, so the one-tap list is due only on a browser that did not register", () => {
    const b = person(B);
    const storage = memoryStorage();
    const s = new SharedLogSession(b, new Server().wireFor(B), storage, accountFor(b, PV).logKeyRing(), NOW);
    expect(s.contacts.oneTapListDue()).toBe(true);
    s.setSessionHow("registered");
    expect(s.contacts.oneTapListDue()).toBe(false);
    expect(storage.get(`andvari.how.${B}`)).toBe("registered");
  });

  it("spec 03 §4: a pull reads the account state only when its counter moved from the one this browser last saw", async () => {
    const server = new Server();
    const a = person(A);
    server.seedState(A, a.uvk, EMPTY_DOCUMENT); // the server's counter is 1
    const wire = server.wireFor(A);
    let reads = 0;
    const counted = { ...wire, accountState: async () => (reads++, wire.accountState()) };
    const s = new SharedLogSession(a, counted, memoryStorage(), accountFor(a, PV).logKeyRing(), NOW);
    // Nothing held yet: read, whatever the pull says, and the answer's counter is kept.
    expect(s.accountState.heldCounter()).toBeNull();
    expect(await s.refreshState(1)).toBe("ok");
    expect(reads).toBe(1);
    expect(s.accountState.heldCounter()).toBe(1);
    // The same counter: no other device wrote since, so nothing is read.
    expect(await s.refreshState(1)).toBe("unchanged");
    expect(reads).toBe(1);
    // Another device wrote: the counter moved, so the state is read, and the new counter kept.
    server.seedState(A, a.uvk, EMPTY_DOCUMENT);
    server.states.get(A)!.seq = 2;
    expect(await s.refreshState(2)).toBe("ok");
    expect(reads).toBe(2);
    expect(s.accountState.heldCounter()).toBe(2);
    // No counter (an older server), one below the held one (a lie or a rollback), or one that is not a counter: read.
    for (const served of [null, undefined, 1, -1, 2.5]) {
      const before = reads;
      await s.refreshState(served);
      expect(reads, String(served)).toBe(before + 1);
    }
    // A write keeps the counter its answer gave, so the pull after this browser's own write reads nothing.
    expect((await s.accountState.update((d) => ({ ...d }))).kind).not.toBe("contended");
    const held = s.accountState.heldCounter();
    expect(held).toBe(server.states.get(A)!.seq);
    const before = reads;
    expect(await s.refreshState(held)).toBe("unchanged");
    expect(reads).toBe(before);
  });

  it("the decision itself: equal skips; anything else, or nothing to compare, reads", () => {
    expect(stateMayHaveMoved(4, 4)).toBe(false);
    expect(stateMayHaveMoved(5, 4)).toBe(true);
    expect(stateMayHaveMoved(3, 4)).toBe(true);
    expect(stateMayHaveMoved(4, null)).toBe(true);
    expect(stateMayHaveMoved(null, 4)).toBe(true);
    expect(stateMayHaveMoved(undefined, 4)).toBe(true);
    expect(stateMayHaveMoved(Number.NaN, 4)).toBe(true);
  });
});
