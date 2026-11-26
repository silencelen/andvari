// node --test. A shared vault that the server stops serving and later serves again, while the extension stays unlocked.
// The extension keeps no copy of a vault: every pull opens the rows of the vaults whose keys the session holds. A
// shared vault's key enters the session only at an unlock, after the unlock's checks (the account state's decision
// and the vault's genesis record, wraps.ts openSharedWrap). These tests show what one unlocked session does when a
// pull no longer grants a vault and a later pull grants it again: the person removed and added again, the same with
// the vault's key changed at the removal, and the vault deleted and put back under the same id. The real
// background.ts, driven through testing/bgharness.ts.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { rand, settle, signedInWorld } from "./testing/bgharness.ts";
import { drawPopup, textOf } from "./testing/popupkit.ts";
import { GRANTS_WAITING_ONE } from "./errors.ts";
import { adItem, seal, toB64 } from "./crypto.ts";
import { adVkShared } from "./wraps.ts";

const SITE = "https://shop.example";

type Row = { itemId: string; vaultId: string };
type Grant = { vaultId: string };
type Acct = {
  userId: string;
  uvk: Uint8Array;
  email: string;
  password: string;
  personalVaultId: string;
  vaultKeys: Map<string, Uint8Array>;
  grants: Grant[];
  items: Row[];
  state: { seq: number; vaults: Record<string, { genesisHash: string }> };
  addSharedVault(o?: { decision?: string; role?: string }): string;
  addItem(vaultId: string, doc: unknown): string;
};
type W = { popup: (m: unknown) => Promise<any>; page: (m: unknown, tab: number, origin: string) => Promise<any>; alarm: (name: string) => Promise<void> };

const login = (name: string) => ({ type: "login", name, login: { username: name, password: `${name}-pw`, uris: [SITE] } });
const names = async (w: W): Promise<string[]> => ((await w.popup({ type: "allItems" })).items as { name: string }[]).map((i) => i.name).sort();

/** An unlocked session that holds shared vault V's key and shows one item of V beside one personal item. */
async function sharedWorld() {
  let v = "";
  const made = await signedInWorld({
    setup: ({ acct }: { acct: Acct }) => {
      v = acct.addSharedVault();
      acct.addItem(acct.personalVaultId, login("own"));
      acct.addItem(v, login("shared"));
    },
  });
  const acct = made.acct as Acct;
  const w = made.w as W;
  assert.deepEqual(await names(w), ["own", "shared"], "the unlocked session shows V's item");
  return { ...made, acct, w, v };
}

/** The server serves V no longer to this account: no grant row and no item row of V. Returns what it held back. */
function withdraw(acct: Acct, v: string, { vault = false }: { vault?: boolean } = {}) {
  const grants = acct.grants.filter((g) => g.vaultId === v);
  const rows = acct.items.filter((it) => it.vaultId === v);
  acct.grants = acct.grants.filter((g) => g.vaultId !== v);
  acct.items = acct.items.filter((it) => it.vaultId !== v);
  const vk = acct.vaultKeys.get(v)!;
  if (vault) acct.vaultKeys.delete(v); // the vault itself is gone from the served vault list
  return { grants, rows, vk };
}

test("(a) removed and added again under the same key: no row of V is shown again before an unlock has made its checks", async () => {
  const { acct, w, v } = await sharedWorld();
  const held = withdraw(acct, v);
  await w.alarm("resync");
  assert.deepEqual(await names(w), ["own"], "the pull without V shows none of V's items");
  // Added again: the same grant row (a wrap of the same key) and the same rows.
  acct.grants.push(...held.grants);
  acct.items.push(...held.rows);
  await w.alarm("resync");
  assert.deepEqual(await names(w), ["own"], "V's items are not shown again on the server's word alone");
  assert.equal((await w.popup({ type: "status" })).waitingGrants, 1, "V is counted as a vault that waits, as a newly granted one is");
  // The unlock's checks pass for V (the account state still accepts it): its items come back with the unlock.
  await w.popup({ type: "lock" });
  assert.equal((await w.popup({ type: "unlock", email: acct.email, password: acct.password })).ok, true);
  assert.deepEqual(await names(w), ["own", "shared"], "after an unlock V's items are shown again");
});

test("(b) removed and added again, the server replaying rows sealed under the old key although the key was changed: none is shown", async () => {
  const { acct, w, v } = await sharedWorld();
  const held = withdraw(acct, v);
  await w.alarm("resync");
  assert.deepEqual(await names(w), ["own"]);
  // The key was changed at the removal: the new grant row wraps a new key. The server replays the old rows, sealed
  // under the old key, which this session still held.
  const newVk = rand(32);
  acct.vaultKeys.set(v, newVk);
  const genesisHash = acct.state.vaults[v]!.genesisHash;
  acct.grants.push({ ...held.grants[0]!, wrappedVk: toB64(seal(acct.uvk, newVk, adVkShared(v, acct.userId, genesisHash))) } as Grant);
  acct.items.push(...held.rows);
  await w.alarm("resync");
  assert.deepEqual(await names(w), ["own"], "rows sealed under the key of before the removal are not shown");
});

test("(c) V deleted and put back under the same id: no row of V is shown again before an unlock has made its checks", async () => {
  const { acct, w, v } = await sharedWorld();
  const held = withdraw(acct, v, { vault: true });
  await w.alarm("resync");
  assert.deepEqual(await names(w), ["own"], "the pull after the deletion shows none of V's items");
  acct.vaultKeys.set(v, held.vk);
  acct.grants.push(...held.grants);
  acct.items.push(...held.rows);
  await w.alarm("resync");
  assert.deepEqual(await names(w), ["own"], "the vault put back under the same id shows nothing on the server's word alone");
});

test("(d) the ordinary road: V served in every pull keeps its items, and an item another member adds appears", async () => {
  const { acct, w, v } = await sharedWorld();
  await w.alarm("resync");
  assert.deepEqual(await names(w), ["own", "shared"], "V's items stay shown");
  acct.addItem(v, login("added by a member"));
  await w.alarm("resync");
  assert.deepEqual(await names(w), ["added by a member", "own", "shared"], "an item added to V by another member appears");
  assert.equal((await w.popup({ type: "status" })).waitingGrants, 0, "nothing waits");
});

test("(e) as (a), with a worker restart between the removal and the return: the session restored from its sealed snapshot does not open V either", async () => {
  const { world, acct, w, v } = await sharedWorld();
  const held = withdraw(acct, v);
  await w.alarm("resync");
  assert.deepEqual(await names(w), ["own"], "the pull without V");
  // The browser stops the worker; a new life restores the session from its sealed snapshot.
  const next = (await (world as unknown as { start(): Promise<W> }).start()) as W;
  acct.grants.push(...held.grants);
  acct.items.push(...held.rows);
  await next.alarm("resync");
  assert.deepEqual(await names(next), ["own"], "a worker restored from the snapshot taken after the removal does not open V again");
});

// The server put back to an earlier day serves an account state whose in-blob seq is below the mark this browser kept
// (accountstate.ts applyServedState). This states today's behaviour; it changes nothing.
test("today: an account state served below this browser's mark keeps every shared vault closed at every unlock, said only in the console and as a waiting vault, until a state at or above the mark is served", async () => {
  const { server, acct, w } = await sharedWorld();
  const unlockAgain = async () => {
    await w.popup({ type: "lock" });
    assert.equal((await w.popup({ type: "unlock", email: acct.email, password: acct.password })).ok, true, "the unlock itself is not refused");
  };
  // Another client wrote the account state up to seq 5; this browser sees it at an unlock and keeps 5 as its mark.
  acct.state.seq = 5;
  await unlockAgain();
  assert.deepEqual(await names(w), ["own", "shared"]);
  // The server is put back to an earlier day: it serves the state at seq 2.
  server.servedState.set(acct.userId, (acct as unknown as { stateAt(seq: number): string }).stateAt(2));
  await w.alarm("resync");
  assert.deepEqual(await names(w), ["own", "shared"], "inside the session a pull does not read the account state: nothing changes");
  const warned: string[] = [];
  const warn = console.warn;
  console.warn = (...a: unknown[]) => void warned.push(a.map(String).join(" "));
  try {
    for (let i = 0; i < 3; i++) {
      await unlockAgain();
      assert.deepEqual(await names(w), ["own"], `unlock ${i + 1}: the shared vault stays closed`);
      assert.equal((await w.popup({ type: "status" })).waitingGrants, 1, "the popup counts it as a vault that waits for a full client");
    }
  } finally {
    console.warn = warn;
  }
  assert.equal(warned.filter((m) => m.includes("older account state")).length, 3, "each unlock says the rollback in the console only");
  // Another client writes a newer state (seq 6): the next unlock opens the vault again.
  server.servedState.set(acct.userId, (acct as unknown as { stateAt(seq: number): string }).stateAt(6));
  await unlockAgain();
  assert.deepEqual(await names(w), ["own", "shared"], "a state at or above the mark ends it");
  assert.equal((await w.popup({ type: "status" })).waitingGrants, 0);
});

test("today: after an account state served below the mark, a state served exactly at the mark opens the shared vaults at the next unlock", async () => {
  const { server, acct, w } = await sharedWorld();
  const stateAt = (seq: number) => (acct as unknown as { stateAt(seq: number): string }).stateAt(seq);
  const unlockAgain = async () => {
    await w.popup({ type: "lock" });
    assert.equal((await w.popup({ type: "unlock", email: acct.email, password: acct.password })).ok, true);
  };
  acct.state.seq = 5;
  await unlockAgain();
  assert.deepEqual(await names(w), ["own", "shared"], "the mark is 5");
  const warn = console.warn;
  console.warn = () => undefined;
  try {
    server.servedState.set(acct.userId, stateAt(2));
    await unlockAgain();
    assert.deepEqual(await names(w), ["own"], "below the mark: the shared vault stays closed");
  } finally {
    console.warn = warn;
  }
  server.servedState.set(acct.userId, stateAt(5));
  await unlockAgain();
  assert.deepEqual(await names(w), ["own", "shared"], "a state at the mark ends it");
  assert.equal((await w.popup({ type: "status" })).waitingGrants, 0);
});

// ---- Which answers say that a vault is no longer granted, and what goes with its key ----

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
/** The personal vault's own grant row, as the server serves it beside the shared ones. */
const personalRow = (acct: Acct) => ({ vaultId: acct.personalVaultId, userId: acct.userId, role: "owner", wrappedVk: "" });
/** The sync answer the harness server would give now, with parts replaced. */
function bodyOf(acct: Acct & { rev: number }, o: { grants?: unknown; items?: unknown; omitGrants?: boolean } = {}) {
  const b: Record<string, unknown> = {
    rev: acct.rev,
    vaults: [...acct.vaultKeys.keys()].map((vaultId) => ({ vaultId, type: "x" })),
    grants: o.grants ?? [personalRow(acct), ...acct.grants],
    items: o.items ?? acct.items,
  };
  if (o.omitGrants) delete b.grants;
  return b;
}
const isSync = (m: string, p: string) => m === "GET" && p.startsWith("/api/v1/sync?");
type Overridable = { override: ((m: string, p: string, body?: any) => Response | Promise<Response> | null) | null };
/** The server gives one sync answer built by [f], then its own answers again. */
function onceSync(server: Overridable, f: () => Response | Promise<Response>) {
  let used = false;
  server.override = (m, p) => {
    if (!isSync(m, p) || used) return null;
    used = true;
    return f();
  };
}

test("an answer that no longer grants V but still serves V's rows opens none of them in that pull", async () => {
  const { acct, w, v } = await sharedWorld();
  acct.grants = acct.grants.filter((g) => g.vaultId !== v); // the grant goes, the rows stay
  await w.alarm("resync");
  assert.deepEqual(await names(w), ["own"], "V's rows are not opened in the pull that no longer grants V");
});

test("an answer without a list of grants and with one malformed item id leaves V open once normal answers return", async () => {
  const { server, acct, w } = await sharedWorld();
  const bad = { itemId: "not-a-uuid", vaultId: acct.personalVaultId, rev: 1, deleted: false, formatVersion: 1, blob: "" };
  onceSync(server as unknown as Overridable, () => json(200, bodyOf(acct as Acct & { rev: number }, { omitGrants: true, items: [...acct.items, bad] })));
  await w.alarm("resync");
  await w.alarm("resync"); // an ordinary answer, which grants V
  assert.deepEqual(await names(w), ["own", "shared"], "one malformed answer does not close V until the next unlock");
});

test("an answer whose grant row of V carries a malformed userId leaves V open once normal answers return", async () => {
  const { server, acct, w, v } = await sharedWorld();
  const grants = [personalRow(acct), ...acct.grants.map((g) => (g.vaultId === v ? { ...g, userId: "x" } : g))];
  onceSync(server as unknown as Overridable, () => json(200, bodyOf(acct as Acct & { rev: number }, { grants })));
  await w.alarm("resync");
  await w.alarm("resync");
  assert.deepEqual(await names(w), ["own", "shared"], "one malformed grant row does not close V until the next unlock");
});

test("an answer with no list of grants and nothing malformed is dropped whole: the key set is left alone", async () => {
  const { server, acct, w } = await sharedWorld();
  onceSync(server as unknown as Overridable, () => json(200, bodyOf(acct as Acct & { rev: number }, { omitGrants: true })));
  await w.alarm("resync");
  assert.deepEqual(await names(w), ["own", "shared"], "the answer changes nothing");
  await w.alarm("resync");
  assert.deepEqual(await names(w), ["own", "shared"], "the next ordinary pull still opens V");
});

test("an answer with grants: null leaves the key set alone", async () => {
  const { server, acct, w } = await sharedWorld();
  onceSync(server as unknown as Overridable, () => json(200, { ...bodyOf(acct as Acct & { rev: number }), grants: null }));
  await w.alarm("resync");
  await w.alarm("resync");
  assert.deepEqual(await names(w), ["own", "shared"]);
});

test("a failed pull (an error answer, then no network) leaves the key set alone", async () => {
  const { world, server, w } = await sharedWorld();
  onceSync(server as unknown as Overridable, () => json(500, { error: "boom", message: "boom" }));
  await w.alarm("resync");
  assert.deepEqual(await names(w), ["own", "shared"]);
  const servers = (world as unknown as { servers: Map<string, unknown> }).servers;
  const origin = (server as unknown as { origin: string }).origin;
  servers.delete(origin);
  await w.alarm("resync");
  servers.set(origin, server);
  assert.deepEqual(await names(w), ["own", "shared"]);
  await w.alarm("resync");
  assert.deepEqual(await names(w), ["own", "shared"]);
});

test("a well-formed empty list of grants closes the shared vaults until the next unlock; the personal vault stays open", async () => {
  const { server, acct, w } = await sharedWorld();
  onceSync(server as unknown as Overridable, () => json(200, bodyOf(acct as Acct & { rev: number }, { grants: [] })));
  await w.alarm("resync");
  assert.deepEqual(await names(w), ["own"], "the personal vault stays open, V closes");
  await w.alarm("resync");
  assert.deepEqual(await names(w), ["own"], "V stays closed although the next answer grants it");
  assert.equal((await w.popup({ type: "status" })).waitingGrants, 1);
  await w.popup({ type: "lock" });
  assert.equal((await w.popup({ type: "unlock", email: acct.email, password: acct.password })).ok, true);
  assert.deepEqual(await names(w), ["own", "shared"], "the unlock opens V again");
});

test("the popup's line for a vault closed in this session and served again is the waiting line, which no longer sends the person to review it", async () => {
  const { server, acct, w } = await sharedWorld();
  onceSync(server as unknown as Overridable, () => json(200, bodyOf(acct as Acct & { rev: number }, { grants: [] })));
  await w.alarm("resync");
  await w.alarm("resync"); // V is served again
  const p = await drawPopup((msg) => w.popup(msg));
  try {
    await p.settle(150);
    assert.deepEqual(p.errors, []);
    const line = p.byId("grants-waiting");
    assert.equal(line.hidden, false, "the line is shown");
    const shown = textOf(line);
    assert.equal(shown, GRANTS_WAITING_ONE, "the line for one vault");
    // Nothing waits for review here: the released words, which send the person to a full client, are not shown.
    assert.notEqual(shown, "1 shared vault waiting — open andvari to review.");
  } finally {
    p.dispose();
  }
});

type Life = W & { life: unknown };
type Stoppable = { session: Map<string, unknown>; idbFault: ((db: string, op: string, key: unknown) => boolean) | null; start(): Promise<Life> };
const copyOf = (m: Map<string, unknown>) => new Map([...m].map(([k, x]) => [k, structuredClone(x)]));

/** V withdrawn and a new personal item in the same pull, so the pull waits on its homes write after the key was dropped.
 *  The worker is stopped there: the next life restores what storage.session held at that moment. */
async function stoppedMidPull() {
  const { world, acct, w, v } = await sharedWorld();
  const box = world as unknown as Stoppable;
  const held = withdraw(acct, v);
  acct.addItem(acct.personalVaultId, login("own 2"));
  let mid: Map<string, unknown> | null = null;
  box.idbFault = (db, op, key) => {
    if (mid === null && db === "andvari-trusted" && op === "put" && String(key).includes("itemHomes:")) mid = copyOf(box.session);
    return false;
  };
  await w.alarm("resync");
  box.idbFault = null;
  assert.notEqual(mid, null, "the homes write was seen");
  box.session.clear();
  for (const [k, x] of mid!) box.session.set(k, x);
  const next = await box.start();
  return { acct, next, held };
}

test("a worker stopped after the key was dropped and before the pull's end does not open V when V is served again", async () => {
  const { acct, next, held } = await stoppedMidPull();
  acct.grants.push(...held.grants);
  acct.items.push(...held.rows);
  await next.alarm("resync");
  assert.deepEqual(await names(next), ["own", "own 2"], "V is not opened again");
});

test("a worker stopped after the key was dropped and before the pull's end restores none of V's opened items", async () => {
  const { next } = await stoppedMidPull();
  assert.ok(!(await names(next)).includes("shared"), "no opened item of V comes back with the restored session");
});

test("a save of a personal item that starts while the pull that dropped V's key waits: none of V's opened items is shown or in the snapshot", async () => {
  const { world, server, acct, w, v } = await sharedWorld();
  const box = world as unknown as Stoppable;
  const ownId = ((await w.popup({ type: "allItems" })).items as { name: string; itemId: string }[]).find((i) => i.name === "own")!.itemId;
  withdraw(acct, v);
  acct.addItem(acct.personalVaultId, login("own 2"));
  let release: () => void = () => {};
  const gate = new Promise<void>((r) => (release = r));
  const rev = acct as Acct & { rev: number };
  (server as unknown as Overridable).override = (m, p, body) => {
    if (m !== "POST" || p !== "/api/v1/sync/push") return null;
    return gate.then(() => json(200, { rev: ++rev.rev, results: body.mutations.map((x: { mutationId: string }) => ({ mutationId: x.mutationId, status: "applied", newItemRev: rev.rev })) }));
  };
  let save: Promise<unknown> | null = null;
  box.idbFault = (db, op, key) => {
    if (save === null && db === "andvari-trusted" && op === "put" && String(key).includes("itemHomes:")) save = w.popup({ type: "setTotp", itemId: ownId, totp: "JBSWY3DPEHPK3PXP" });
    return false;
  };
  await w.alarm("resync");
  box.idbFault = null;
  assert.notEqual(save, null, "the save started while the pull waited");
  await settle();
  const shown = await names(w);
  const snapshot = copyOf(box.session);
  release();
  await save;
  await settle();
  assert.ok(!shown.includes("shared"), "after the pull that no longer grants V, none of V's opened items is shown");
  box.session.clear();
  for (const [k, x] of snapshot) box.session.set(k, x);
  const next = await box.start();
  assert.ok(!(await names(next)).includes("shared"), "none of V's opened items is in the snapshot written by that pull");
});

// ---- Two pulls at once ----

const matchNames = async (w: W): Promise<string[]> => ((await w.page({ type: "matches", host: "shop.example" }, 3, SITE)).matches as { name: string }[]).map((m) => m.name).sort();
type Holdable = { idbHold: ((db: string, op: string, key: unknown, value: unknown) => Promise<void> | null) | null };

/** Waits until [cond] holds, one turn of the event loop at a time (no timer decides an order); fails after [turns]. */
async function until(cond: () => boolean | Promise<boolean>, what: string, turns = 2000): Promise<void> {
  for (let i = 0; i < turns; i++) {
    if (await cond()) return;
    await settle(1);
  }
  assert.fail(`never reached: ${what}`);
}

/** The server serves item [itemId] again, sealed under its vault's key with [doc], at a new rev. */
function reseal(acct: Acct & { rev: number }, itemId: string, doc: unknown) {
  const row = acct.items.find((it) => it.itemId === itemId) as Row & { rev: number; formatVersion: number; blob: string };
  row.rev = ++acct.rev;
  row.blob = toB64(seal(acct.vaultKeys.get(row.vaultId)!, new TextEncoder().encode(JSON.stringify(doc)), adItem(row.vaultId, itemId, row.formatVersion)));
}

/** Pull B's answer still grants V and carries a new row of V ("shared 2") and a new personal row ("own 2"): B opens the
 *  rows of V, gives the new rows their homes and waits on the homes write, which the test holds. Meanwhile the server
 *  withdraws V and "own 2" and serves "own" edited, and pull A runs to its end: A drops V's key and installs. Then B's
 *  write is let go and B installs what it opened. The holding of B's write makes the order, not a timer. */
test("an older pull that opened V's rows before a newer pull dropped V's key, finishing last, leaves none of V's items shown, offered or sealed", async () => {
  const { world, acct, w, v } = await sharedWorld();
  const box = world as unknown as Stoppable & Holdable;
  const served = acct as Acct & { rev: number };
  const ownId = acct.items.find((it) => it.vaultId === acct.personalVaultId)!.itemId;
  const own2 = acct.addItem(acct.personalVaultId, login("own 2"));
  const shared2 = acct.addItem(v, login("shared 2"));
  const order: string[] = [];
  let heldHomes: Record<string, string> | null = null;
  let release: () => void = () => {};
  box.idbHold = (db, op, key, value) => {
    if (heldHomes !== null || db !== "andvari-trusted" || op !== "put" || !String(key).includes("itemHomes:")) return null;
    heldHomes = value as Record<string, string>;
    order.push("B opened V's rows and waits on its homes write");
    return new Promise<void>((r) => (release = r));
  };
  try {
    const b = w.alarm("resync");
    await until(() => heldHomes !== null, "B's homes write");
    // A row is given a home only when this browser opens it (homeAndDecrypt, A9), so B has opened V's new row.
    assert.equal(heldHomes![shared2], v, "B opened V's new row before any pull dropped V's key");
    withdraw(acct, v);
    acct.items = acct.items.filter((it) => it.itemId !== own2);
    reseal(served, ownId, login("own edited"));
    await w.alarm("resync");
    await until(async () => (await names(w)).includes("own edited"), "A's install");
    assert.deepEqual(await names(w), ["own edited"], "A dropped V's key and installed its answer while B still waits");
    order.push("A dropped V's key and installed");
    release();
    await b;
    await until(async () => !(await names(w)).includes("own edited"), "B's install");
    order.push("B installed");
  } finally {
    box.idbHold = null;
  }
  assert.deepEqual(order, ["B opened V's rows and waits on its homes write", "A dropped V's key and installed", "B installed"]);
  const shown = await names(w);
  const offered = await matchNames(w);
  const snap = copyOf(box.session);
  box.session.clear();
  for (const [k, x] of snap) box.session.set(k, x);
  const next = await box.start();
  const restored = await names(next);
  assert.deepEqual(shown, ["own", "own 2"], "B installed last (its answer's personal rows, not A's edit), and none of V's items is shown");
  assert.ok(!offered.includes("shared") && !offered.includes("shared 2"), "none of V's items is offered for filling on a page");
  assert.ok(!restored.includes("shared") && !restored.includes("shared 2"), "none of V's items is in the snapshot that a restored worker reads");
});
