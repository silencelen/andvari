// node --test. The real background.ts, driven through its one message listener (testing/bgharness.ts): a loader hook,
// a fake `chrome`, IndexedDB, KDF worker and `fetch`, and fake servers built from the extension's own crypto leaves.
// One test (or a few) per finding of the 2026-11-15 security review, each failing on the code the review read.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import nacl from "tweetnacl";
import { Chain, connect, settle, signedInWorld, World } from "./testing/bgharness.ts";
import { nsKey, originKeyFor, originMatchPattern } from "./serverurl.ts";
import { PIN_KEY } from "./pinstore.ts";

const pinKey = (origin: string) => nsKey(originKeyFor(origin), PIN_KEY);

const SHOP = "https://shop.example";
const PAN = "4242424242424242";

test("harness: a typed address behind the Trust Gate, then a sign-in, opens the personal vault", async () => {
  const { world, server, w } = await signedInWorld();
  const st = await w.popup({ type: "status" });
  assert.equal(st.unlocked, true);
  assert.ok(world.dialed(server.origin).includes("POST /api/v1/auth/login"));
});

// ---- the card update wrote into a shared vault (design §12.2 rule 4) ----

test("a captured card that matches a card in a shared vault never writes into that vault", async () => {
  let shared = "";
  const { world, server, acct, w } = await signedInWorld({
    setup: ({ acct }) => {
      shared = acct.addSharedVault({ decision: "accept" });
      acct.addItem(shared, { type: "card", name: "Team card", card: { number: PAN, expMonth: "01", expYear: "2030", cardholderName: "ALICE A" } }, 2);
      acct.addItem(shared, { type: "login", name: "shop", login: { username: "alice", password: "old", uris: [SHOP] } });
    },
  });
  // The shared vault opened (the account accepted it), so its card is a match the capture can see.
  const cards = await w.popup({ type: "cardItems" });
  assert.equal(cards.items.length, 1, "the shared card is readable");
  world.tabs.set(7, { id: 7, url: `${SHOP}/checkout`, active: true });
  const cap = await w.page({ type: "captureCard", fields: { number: PAN, expMonth: "12", expYear: "2031", cardholderName: "MALLORY M", postalCode: "99999" } }, 7, SHOP);
  assert.equal(cap.ok, true);
  assert.equal(cap.pending.updatesItemId, undefined, "a card the extension may not write is not offered as an update");
  await w.page({ type: "resolvePendingCardSave", action: "save" }, 7, SHOP);
  for (const p of server.pushes) for (const m of p.mutations) assert.notEqual(m.vaultId, shared, "nothing is pushed into the shared vault");
  assert.ok(server.pushes.every((p) => p.mutations.every((m) => m.vaultId === acct.personalVaultId)), "a save lands in the personal vault only");
});

// ---- a card that changes both kind and origin ----

test("accepting a kind change that also moved keeps the pin at its card, and the move is then offered on its own", async () => {
  const { world, chain, server, acct, w } = await signedInWorld();
  const A = server.origin;
  const B = "https://new.smith.example";
  world.serve(B, chain);
  chain.add({ origin: B, kind: "public" });
  await w.alarm("resync");
  const st1 = await w.popup({ type: "status" });
  assert.equal(st1.cardNotice?.kind, "kind", "a card that changes both is a kind change");
  const followed = await w.popup({ type: "followServerChange", hash: chain.newest.hash });
  assert.equal(followed.ok, true);
  const st2 = await w.popup({ type: "status" });
  assert.deepEqual(st2.cardNotice && { kind: st2.cardNotice.kind, from: st2.cardNotice.from, to: st2.cardNotice.to }, { kind: "move", from: A, to: B }, "the move is offered as its own prompt");
  const stored = world.trusted().get(pinKey(A)) as { pin: { origin: string; seq: number; kind: string } };
  assert.equal(stored.pin.origin, A, "the pin stays under its own origin");
  assert.equal(stored.pin.seq, 0);
  assert.equal(stored.pin.kind, "public");
  // Nothing went to the new origin yet, and the old one is still the server until the person follows the move.
  assert.deepEqual(world.dialed(B), world.dialed(B).filter((r) => r === "GET /api/v1/instance"));
  assert.equal((await w.popup({ type: "serverInfo" })).url, A);
  void acct;
});

// ---- a failed read of a trust record taken as a first read ----

/** Fail the first trusted-store `get` of a key containing [part]. */
function failOnce(world: { idbFault: unknown }, part: string): { hits: number } {
  const seen = { hits: 0 };
  world.idbFault = (db: string, op: string, key: unknown) => {
    if (db !== "andvari-trusted" || op !== "get" || typeof key !== "string" || !key.includes(part) || seen.hits > 0) return false;
    seen.hits++;
    return true;
  };
  return seen;
}

const login = (name: string) => ({ type: "login", name, login: { username: name, password: `${name}-pw`, uris: [`https://${name}.example`] } });
const names = (r: { items: { name: string }[] }) => r.items.map((i) => i.name).sort();

test("a high-water mark that cannot be read keeps shared vaults closed and is not written back", async () => {
  let shared = "";
  const { world, server, acct, w } = await signedInWorld({
    setup: ({ server, acct }) => {
      shared = acct.addSharedVault({ decision: "accept" });
      acct.addItem(shared, login("left"));
      acct.addItem(acct.personalVaultId, login("mine"));
      server.servedState.set(acct.userId, acct.stateAt(5, { [shared]: "decline" })); // the account left at seq 5
    },
  });
  assert.deepEqual(names(await w.popup({ type: "allItems" })), ["mine"], "round 1: the left vault is closed");
  const memKey = [...world.trusted().keys()].find((k) => k.includes("accountStateMemory"))!;
  assert.equal((world.trusted().get(memKey) as { highWater: number }).highWater, 5);
  // The server replays the state from before the leave, and one read of the mark fails.
  server.servedState.set(acct.userId, acct.stateAt(3));
  await w.popup({ type: "lock" });
  const fault = failOnce(world, "accountStateMemory");
  assert.equal((await w.popup({ type: "unlock", email: acct.email, password: acct.password })).ok, true);
  assert.equal(fault.hits, 1, "the read failed");
  assert.deepEqual(names(await w.popup({ type: "allItems" })), ["mine"], "an unread mark keeps the shared vault closed");
  assert.equal((world.trusted().get(memKey) as { highWater: number }).highWater, 5, "the mark is not written back from the replay");
  // The next sign-in, with nothing failing, still refuses the replay.
  await w.popup({ type: "lock" });
  assert.equal((await w.popup({ type: "unlock", email: acct.email, password: acct.password })).ok, true);
  assert.deepEqual(names(await w.popup({ type: "allItems" })), ["mine"]);
});

test("item homes that cannot be read admit only the personal vault's rows and are not written back", async () => {
  let shared = "";
  const { world, acct, w } = await signedInWorld({
    setup: ({ acct }) => {
      shared = acct.addSharedVault({ decision: "accept" });
      acct.addItem(shared, login("team"));
      acct.addItem(acct.personalVaultId, login("mine"));
    },
  });
  assert.deepEqual(names(await w.popup({ type: "allItems" })), ["mine", "team"]);
  const homesKey = [...world.trusted().keys()].find((k) => k.includes("itemHomes"))!;
  const before = structuredClone(world.trusted().get(homesKey));
  const fresh = acct.addItem(shared, login("fresh")); // a row this browser has never homed
  await w.popup({ type: "lock" });
  const fault = failOnce(world, "itemHomes");
  assert.equal((await w.popup({ type: "unlock", email: acct.email, password: acct.password })).ok, true);
  assert.equal(fault.hits, 1, "the read failed");
  assert.deepEqual(names(await w.popup({ type: "allItems" })), ["mine"], "no shared row is admitted against homes that could not be read");
  await w.alarm("resync");
  assert.deepEqual(world.trusted().get(homesKey), before, "the record is not written back from what the server served");
  assert.ok(!Object.keys(world.trusted().get(homesKey) as object).includes(fresh));
});

// ---- a followed move carried only the pin ----

test("a followed move carries the namespace's trust records, so a replay from before a leave stays refused at the new origin", async () => {
  let shared = "";
  const { world, chain, server, acct, w } = await signedInWorld({
    setup: ({ server, acct }) => {
      shared = acct.addSharedVault({ decision: "accept" });
      acct.addItem(shared, login("left"));
      acct.addItem(acct.personalVaultId, login("mine"));
      server.servedState.set(acct.userId, acct.stateAt(5, { [shared]: "decline" }));
    },
  });
  const A = server.origin;
  const B = "https://moved.smith.example";
  world.servers.set(B, server); // the same instance, now also answering at its new address
  assert.deepEqual(names(await w.popup({ type: "allItems" })), ["mine"]);
  const oldNs = nsKey(originKeyFor(A), "");
  const oldNames = [...world.trusted().keys()].filter((k) => k.startsWith(oldNs)).map((k) => k.slice(oldNs.length)).sort();
  assert.ok(oldNames.some((n) => n.startsWith("accountStateMemory:")) && oldNames.some((n) => n.startsWith("device:")) && oldNames.some((n) => n.startsWith("itemHomes:")));
  chain.add({ origin: B });
  await w.alarm("resync");
  assert.equal((await w.popup({ type: "status" })).cardNotice?.kind, "move");
  const followed = await w.popup({ type: "followServerChange", hash: chain.newest.hash });
  assert.deepEqual(followed, { ok: true, url: B });
  const newNs = nsKey(originKeyFor(B), "");
  const keys = [...world.trusted().keys()];
  assert.deepEqual(keys.filter((k) => k.startsWith(oldNs)), [], "the old namespace is removed");
  assert.deepEqual(keys.filter((k) => k.startsWith(newNs)).map((k) => k.slice(newNs.length)).sort(), oldNames, "every record moved");
  const mark = world.trusted().get(keys.find((k) => k.startsWith(newNs) && k.includes("accountStateMemory"))!) as { highWater: number };
  assert.equal(mark.highWater, 5, "a move never resets a mark");
  // The replay of the state from before the leave, at the new origin.
  server.servedState.set(acct.userId, acct.stateAt(3));
  assert.equal((await w.popup({ type: "unlock", email: acct.email, password: acct.password })).ok, true);
  assert.deepEqual(names(await w.popup({ type: "allItems" })), ["mine"], "the left vault stays closed");
});

test("a move's target is checked before either pin is touched", async () => {
  const { world, chain, server, w } = await signedInWorld({ signIn: false });
  const A = server.origin;
  const before = structuredClone(world.trusted().get(pinKey(A)));
  // Moves to the placeholder origin, and to an origin this browser may not reach.
  for (const [to, code] of [["https://no-server.invalid", "invalid"], ["https://denied.smith.example", "no_permission"]] as const) {
    world.denied.add(to);
    const c = chain.add({ origin: to });
    await w.popup({ type: "chooseServer", choice: "own", origin: A }); // the refresh that offers the move
    const st = await w.popup({ type: "status" });
    assert.equal(st.cardNotice?.kind, "move", to);
    assert.deepEqual(await w.popup({ type: "followServerChange", hash: c.hash }), { ok: false, code }, to);
    assert.equal((await w.popup({ type: "serverInfo" })).url, A, "the server is unchanged");
    const pinNow = world.trusted().get(pinKey(A)) as { pin: unknown };
    assert.deepEqual(pinNow.pin, (before as { pin: unknown }).pin, "the old origin keeps its pin");
    assert.equal(world.trusted().get(pinKey(to)), undefined, "no pin was written for the target");
    chain.frames.pop();
    chain.cards.pop();
  }
});

// ---- fork handling (and design §4.4 "A fork stops traffic, not reading") ----

const SITE = "https://site.example";

test("a fork found at a refresh stops all traffic but not reading: fill works, nothing is dialed, saves are refused", async () => {
  const { world, server, w } = await signedInWorld({ setup: ({ acct }) => void acct.addItem(acct.personalVaultId, login("site")) });
  const A = server.origin;
  server.chain = new Chain({ origin: A }); // another card 0 at the same address: a fork
  await w.alarm("resync");
  assert.deepEqual((await w.popup({ type: "serverInfo" })).block, { kind: "fork", origin: A });
  const st = await w.popup({ type: "status" });
  assert.equal(st.unlocked, true, "a fork does not lock: what this browser holds stays readable");
  assert.deepEqual(st.cardNotice, { kind: "fork", origin: A }, "the popup's warning, with Forget this server");
  const before = world.log.length;
  const m = await w.page({ type: "matches", host: "site.example" }, 3, SITE);
  assert.equal(m.matches.length, 1, "fill offers still answer");
  const r = await w.page({ type: "reveal", itemId: m.matches[0].itemId, host: "site.example" }, 3, SITE);
  assert.equal(r.secret?.password, "site-pw", "and fills still fill");
  // Saves are refused, with a reason.
  world.tabs.set(3, { id: 3, url: `${SITE}/pay`, active: true });
  await w.page({ type: "captureCard", fields: { number: PAN } }, 3, SITE);
  const saved = await w.page({ type: "resolvePendingCardSave", action: "save" }, 3, SITE);
  assert.equal(saved.code, "server_fork");
  // A quick unlock or a sign-in cannot start; a ping is refused.
  assert.deepEqual(await w.popup({ type: "ping" }), { ok: false, code: "confirm_server" });
  await w.alarm("resync");
  assert.equal(world.log.length, before, "nothing at all is dialed under the fork");
  assert.equal(server.pushes.length, 0);
  // A new worker life: the fork is durable, and the session is restored readable with nothing dialed.
  const w2 = await world.start();
  assert.deepEqual((await w2.popup({ type: "serverInfo" })).block, { kind: "fork", origin: A });
  assert.equal((await w2.page({ type: "matches", host: "site.example" }, 3, SITE)).matches.length, 1);
  assert.equal(world.log.length, before);
});

test("a fork whose durable write failed is still a fork after a worker restart", async () => {
  const { world, server, chain, w } = await signedInWorld();
  const A = server.origin;
  world.idbFault = (db: string, op: string, key: unknown) => db === "andvari-trusted" && op === "put" && typeof key === "string" && key.endsWith(".cardPin");
  server.chain = new Chain({ origin: A });
  await w.alarm("resync");
  await new Promise((r) => setTimeout(r, 1400)); // the routine's retries
  assert.deepEqual((await w.popup({ type: "serverInfo" })).block, { kind: "fork", origin: A });
  assert.equal((world.trusted().get(pinKey(A)) as { fork: boolean }).fork, false, "the write never landed");
  // The server serves the genuine chain again; the worker restarts.
  server.chain = chain;
  world.idbFault = null;
  const w2 = await world.start();
  assert.deepEqual((await w2.popup({ type: "serverInfo" })).block, { kind: "fork", origin: A }, "still a fork");
  await new Promise((r) => setTimeout(r, 50));
  assert.equal((world.trusted().get(pinKey(A)) as { fork: boolean }).fork, true, "and the write was tried again");
  assert.deepEqual(await w2.popup({ type: "unlock", email: "alice@example.com", password: "correct horse" }), { ok: false, code: "confirm_server" });
  // "Forget this server" is the way out, the session's marker included: chosen again, the server stays usable.
  assert.deepEqual(await w2.popup({ type: "forgetServer" }), { ok: true });
  await connect(w2, A);
  const w3 = await world.start();
  assert.equal((await w3.popup({ type: "serverInfo" })).block, null);
});

test("re-choosing the current server when its chain forked stops it at once", async () => {
  const { world, server, w } = await signedInWorld({ signIn: false });
  const A = server.origin;
  server.chain = new Chain({ origin: A });
  assert.deepEqual(await w.popup({ type: "chooseServer", choice: "own", origin: A }), { ok: false, code: "fork" });
  assert.deepEqual((await w.popup({ type: "serverInfo" })).block, { kind: "fork", origin: A });
  const before = world.log.length;
  assert.deepEqual(await w.popup({ type: "ping" }), { ok: false, code: "confirm_server" });
  assert.equal(world.log.length, before, "nothing is dialed");
});

test("under a damaged pin no session is restored, so nothing is filled", async () => {
  const { world, server, w } = await signedInWorld({ setup: ({ acct }) => void acct.addItem(acct.personalVaultId, login("site")) });
  assert.equal((await w.page({ type: "matches", host: "site.example" }, 3, SITE)).matches.length, 1);
  (world.trusted().get(pinKey(server.origin)) as { v: number }).v = 9;
  const w2 = await world.start();
  assert.equal((await w2.popup({ type: "serverInfo" })).block?.kind, "pin_damaged");
  assert.deepEqual(await w2.page({ type: "matches", host: "site.example" }, 3, SITE), { locked: true, matches: [] });
});

// ---- a server switch while the KDF runs ----

test("switching server while the KDF runs sends nothing derived from the password to either origin", async () => {
  const { world, server, acct, w } = await signedInWorld({ signIn: false });
  const B = "https://other.example";
  world.serve(B, new Chain({ origin: B }));
  world.kdfHook = async () => {
    world.kdfHook = null;
    await connect(w, B); // the person connects to another server in Options while the sign-in derives
  };
  const r = await w.popup({ type: "unlock", email: acct.email, password: acct.password });
  assert.equal(r.ok, false);
  assert.deepEqual(world.dialed(B), ["GET /api/v1/instance"], "the other origin got the card fetch only: no login, no authKey");
  assert.ok(!world.dialed(server.origin).includes("POST /api/v1/auth/login"), "and the first origin got no login either");
  assert.ok(world.log.every((l) => !l.body || l.body.authKey === undefined), "no authKey left at all");
});

// ---- design §12.2 rule 7: the extension refuses the operator account ----

test("§12.2 rule 7: a sign-in whose session has the operator role is revoked at once and refused", async () => {
  const { world, server, acct, w } = await signedInWorld({ signIn: false, account: { operator: true } });
  const r = await w.popup({ type: "unlock", email: acct.email, password: acct.password });
  assert.deepEqual(r, { ok: false, code: "operator_account" });
  const after = world.log.filter((l) => l.origin === server.origin).map((l) => `${l.method} ${l.path}`);
  const login = after.indexOf("POST /api/v1/auth/login");
  assert.equal(after[login + 1], "POST /api/v1/auth/logout", "the session is revoked next, before anything else");
  const logout = world.log.find((l) => l.path === "/api/v1/auth/logout")!;
  assert.equal(logout.headers.authorization, `Bearer at-${acct.userId}`, "with the operator session's own token");
  assert.ok(!after.some((x) => x.includes("/sync") || x.includes("/account/")), "nothing of the account is read");
  assert.equal((await w.popup({ type: "status" })).unlocked, false);
});

test("§12.2 rule 7, by the card: a handover after sign-in that names this account the operator signs it out at the next refresh", async () => {
  const { world, chain, server, acct, w } = await signedInWorld();
  chain.add({ operator: acct.userId }); // a handover: this member is now the instance's operator
  const before = world.log.length;
  await w.alarm("resync");
  const st = await w.popup({ type: "status" });
  assert.equal(st.unlocked, false, "signed out at the card refresh, not at the next unlock");
  assert.deepEqual(st.lockNotice, { kind: "operator" }, "and the popup is told why");
  const after = world.log.slice(before).filter((l) => l.origin === server.origin);
  assert.ok(after.some((l) => l.path === "/api/v1/auth/logout" && l.headers.authorization === `Bearer at-${acct.userId}`), "the session is revoked");
  assert.ok(!after.some((l) => l.path.startsWith("/api/v1/sync")), "nothing more of the account is read");
  const w2 = await world.start();
  assert.equal((await w2.popup({ type: "status" })).unlocked, false, "a restart restores nothing");
});

// The window between a handover and the next card refresh is the server's to close. The
// extension's half: a server bell (the socket's "rev" frame) refreshes the card at once, so a server that rings every
// socket when it serves a new card has this browser sign the incoming operator out within the bell's debounce.
test("§12.2 rule 7, by the card: a server bell after a handover signs the account out at once, without waiting for the alarm", async () => {
  const { world, chain, server, acct, w } = await signedInWorld({ setup: ({ server }) => void (server.ticketsOn = true) });
  await settle();
  const sock = world.sockets.at(-1);
  assert.ok(sock, "the unlocked session opened its socket");
  sock.readyState = 1;
  sock.onopen?.();
  sock.onmessage?.({ data: "pong" }); // registered: the catch-up bell runs a resync
  await new Promise((r) => setTimeout(r, 700));
  await settle();
  assert.equal((await w.popup({ type: "status" })).unlocked, true, "nothing yet: the card names a member");
  chain.add({ operator: acct.userId }); // the handover
  sock.onmessage?.({ data: JSON.stringify({ type: "rev" }) });
  await new Promise((r) => setTimeout(r, 700));
  await settle(40);
  const st = await w.popup({ type: "status" });
  assert.equal(st.unlocked, false, "signed out at the bell");
  assert.deepEqual(st.lockNotice, { kind: "operator" });
  assert.ok(world.log.some((l) => l.origin === server.origin && l.path === "/api/v1/auth/logout"), "the session is revoked");
});

test("§12.2 rule 7, by the card: a sign-in whose pin names the account the operator is refused though the role says member", async () => {
  const { world, server, acct, w } = await signedInWorld({ signIn: false, setup: ({ chain, acct }) => chain.add({ operator: acct.userId }) });
  assert.equal(acct.role, "member", "the server's role field has not caught up");
  const r = await w.popup({ type: "unlock", email: acct.email, password: acct.password });
  assert.deepEqual(r, { ok: false, code: "operator_account" });
  const after = world.dialed(server.origin);
  assert.equal(after[after.indexOf("POST /api/v1/auth/login") + 1], "POST /api/v1/auth/logout", "revoked at once");
  assert.ok(!after.some((x) => x.includes("/sync") || x.includes("/account/")), "nothing of the account is read");
});

test("§12.2 rule 7, by the card: a quick unlock after a handover is refused and wipes the quick-unlock record", async () => {
  const { world, chain, server, acct, w } = await signedInWorld();
  const en = await w.popup({ type: "enrollQuickUnlock", pin: "Tq7#kw2pZ" });
  assert.equal(en.ok, true, `enrol: ${JSON.stringify(en)}`);
  await w.popup({ type: "lock" });
  assert.equal((await w.popup({ type: "status" })).quickUnlock.armed, true);
  chain.add({ operator: acct.userId });
  const before = world.log.length;
  const r = await w.popup({ type: "unlockWithPin", pin: "Tq7#kw2pZ" });
  assert.deepEqual(r, { ok: false, code: "operator_account" });
  const st = await w.popup({ type: "status" });
  assert.equal(st.unlocked, false);
  assert.equal(st.quickUnlock.enrolled, false, "the quick-unlock record is gone");
  assert.deepEqual(st.lockNotice, { kind: "operator" });
  const after = world.log.slice(before).filter((l) => l.origin === server.origin).map((l) => l.path);
  assert.ok(!after.includes("/api/v1/auth/refresh"), "no refresh token was spent");
  assert.ok(after.includes("/api/v1/auth/logout"), "the redeemed pair is revoked");
});

test("§12.2 rule 7, by the card: an ordinary card update that keeps another operator signs nobody out", async () => {
  const { chain, w } = await signedInWorld();
  chain.add({ name: "Smith Vault renamed" });
  await w.alarm("resync");
  const st = await w.popup({ type: "status" });
  assert.equal(st.unlocked, true);
  assert.equal(st.lockNotice, null);
});

// ---- the app-interface review's faults, looked for in the extension ----

const until = async (cond: () => boolean, what: string): Promise<void> => {
  for (let i = 0; i < 400 && !cond(); i++) await new Promise((r) => setTimeout(r, 5));
  assert.ok(cond(), what);
};

test("a sign-out overtaken by a server switch sends its pair to neither origin", async () => {
  const { world, server, acct, w } = await signedInWorld({ setup: ({ acct }) => void acct.addItem(acct.personalVaultId, login("site")) });
  const B = "https://other.example";
  world.serve(B, new Chain({ origin: B }));
  const m = await w.page({ type: "matches", host: "site.example" }, 3, SITE);
  await w.page({ type: "reveal", itemId: m.matches[0].itemId, host: "site.example" }, 3, SITE); // a use the lock flushes
  let release = () => {};
  const held = new Promise<void>((r) => (release = r));
  server.override = (method: string, path: string) =>
    method === "GET" && path === "/api/v1/usage" ? held.then(() => new Response(JSON.stringify({ sealedUsage: null, updatedAt: 0 }), { status: 200 })) : null;
  const out = w.popup({ type: "signOut" });
  await until(() => world.dialed(server.origin).includes("GET /api/v1/usage"), "the sign-out's lock is flushing");
  await connect(w, B); // the person connects to another server meanwhile
  release();
  await out;
  await settle();
  const withToken = world.log.filter((l) => l.headers.authorization === `Bearer at-${acct.userId}` || l.body?.refreshToken === `rt-${acct.userId}`);
  assert.ok(withToken.every((l) => l.origin === server.origin), "the pair never reaches the other origin");
  assert.ok(!world.dialed(B).includes("POST /api/v1/auth/logout"), "no logout is sent to it");
});

test("a sign-in left behind by a lock after its login answered installs nothing and ends its session", async () => {
  const { world, server, acct, w } = await signedInWorld({ signIn: false });
  let release = () => {};
  const held = new Promise<void>((r) => (release = r));
  const real = server.handle.bind(server);
  // The sync waits, then gets the server's own answer (the override is called without the headers: keep the token).
  const token = `Bearer at-${acct.userId}`;
  server.override = (method: string, path: string, body: unknown) =>
    method === "GET" && path.startsWith("/api/v1/sync") ? held.then(() => {
      server.override = null;
      return real(method, path, body, { authorization: token });
    }) : null;
  const r = w.popup({ type: "unlock", email: acct.email, password: acct.password });
  await until(() => world.dialed(server.origin).some((x) => x.startsWith("GET /api/v1/sync")), "the sign-in is syncing");
  await w.popup({ type: "lock" }); // the person locks while it waits
  release();
  assert.deepEqual(await r, { ok: false, code: "aborted" });
  await settle();
  assert.equal((await w.popup({ type: "status" })).unlocked, false, "the abandoned sign-in does not complete");
  const logout = world.log.find((l) => l.path === "/api/v1/auth/logout");
  assert.ok(logout, "the session it minted is ended at the server");
  assert.equal(logout!.origin, server.origin);
  assert.equal(logout!.headers.authorization, `Bearer at-${acct.userId}`, "with its own token");
});

test("a sign-in left behind by a switch during its login drops its pair unsent", async () => {
  const { world, server, acct, w } = await signedInWorld({ signIn: false });
  const B = "https://other.example";
  world.serve(B, new Chain({ origin: B }));
  let release = () => {};
  const held = new Promise<void>((r) => (release = r));
  const real = server.handle.bind(server);
  server.override = (method: string, path: string, body: unknown) =>
    method === "POST" && path === "/api/v1/auth/login" ? held.then(() => {
      server.override = null;
      return real(method, path, body);
    }) : null;
  const r = w.popup({ type: "unlock", email: acct.email, password: acct.password });
  await until(() => world.dialed(server.origin).includes("POST /api/v1/auth/login"), "the login is in flight");
  await connect(w, B);
  release();
  assert.deepEqual(await r, { ok: false, code: "aborted" });
  await settle();
  assert.ok(!world.log.some((l) => l.path === "/api/v1/auth/logout"), "no pin in force for the sign-in's origin is current: nothing is sent");
  assert.ok(world.log.filter((l) => l.headers.authorization === `Bearer at-${acct.userId}`).length === 0, "its token reaches no origin");
  assert.equal((await w.popup({ type: "status" })).unlocked, false);
});

test("a session's refresh that finds a newer card it cannot verify tells the popup and keeps the pin", async () => {
  const { world, chain, server, w } = await signedInWorld();
  const before = world.trusted().get(pinKey(server.origin)) as { pin: { seq: number; hash: string } };
  chain.key = nacl.sign.keyPair(); // the next card is signed by a key the pinned card does not name
  chain.add({ name: "Smith Vault, forged" });
  await w.alarm("resync");
  const st = await w.popup({ type: "status" });
  assert.deepEqual(st.cardNotice, { kind: "invalid" }, "the popup is told");
  assert.equal(st.unlocked, true, "not a stop: what the browser holds stays readable");
  const after = world.trusted().get(pinKey(server.origin)) as { pin: { seq: number; hash: string } };
  assert.deepEqual([after.pin.seq, after.pin.hash], [before.pin.seq, before.pin.hash], "the pin stays at the card checked before");
});

test("a fork judged on a pin that was forgotten and made again meanwhile writes nothing", async () => {
  const { world, server, w } = await signedInWorld({ signIn: false });
  const A = server.origin;
  let release = () => {};
  const held = new Promise<void>((r) => (release = r));
  let hold = true;
  const real = server.handle.bind(server);
  server.override = (method: string, path: string, body: unknown) => {
    if (!(hold && method === "GET" && path === "/api/v1/instance")) return null;
    hold = false;
    return held.then(() => real(method, path, body));
  };
  const late = w.popup({ type: "chooseServer", choice: "own", origin: A }); // re-choosing A: its fetch waits
  await until(() => !hold, "the re-choice's fetch is waiting");
  assert.deepEqual(await w.popup({ type: "forgetServer" }), { ok: true });
  server.chain = new Chain({ origin: A }); // the operator reset the identity
  await connect(w, A); // and the person confirmed the Trust Gate again: a new pin on the new chain
  const fresh = world.trusted().get(pinKey(A)) as { pin: { card0Hash: string }; fork: boolean };
  release(); // the old judgement comes back: the new chain against the forgotten pin is a fork
  await late;
  await settle();
  await new Promise((r) => setTimeout(r, 1300)); // past every retry of the fork's write
  const now = world.trusted().get(pinKey(A)) as { pin: { card0Hash: string }; fork: boolean };
  assert.equal(now.fork, false, "the new pin carries no fork mark");
  assert.equal(now.pin.card0Hash, fresh.pin.card0Hash, "and it is still the new chain's pin");
  assert.equal((await w.popup({ type: "serverInfo" })).block, null, "the server is not stopped");
});

// ---- design §4.4: a session the server ends does not delete the device's copy ----

test("§4.4: a refused refresh ends the session but keeps what it holds readable; nothing is sent; signing in again restores it", async () => {
  const { world, server, acct, w } = await signedInWorld({ setup: ({ acct }) => void acct.addItem(acct.personalVaultId, login("site")) });
  const en = await w.popup({ type: "enrollQuickUnlock", pin: "Tq7#kw2pZ" });
  assert.equal(en.ok, true);
  // The server ends the session: every authenticated call is 401, and so is the refresh.
  const dead = () => new Response(JSON.stringify({ error: "unauthorized", message: "refused" }), { status: 401, headers: { "content-type": "application/json" } });
  server.override = (method: string, path: string) =>
    path === "/api/v1/auth/refresh" || path.startsWith("/api/v1/sync") || path.startsWith("/api/v1/account") || path.startsWith("/api/v1/usage") ? dead() : null;
  await w.alarm("resync");
  await settle();
  const st = await w.popup({ type: "status" });
  assert.equal(st.unlocked, true, "the copy is not deleted");
  assert.equal(st.serverEnded, true, "and the popup is told the server ended the session");
  assert.equal(st.quickUnlock.enrolled, false, "the quick-unlock record (it holds a refresh token) is dropped");
  const m = await w.page({ type: "matches", host: "site.example" }, 3, SITE);
  assert.equal(m.matches.length, 1, "fill offers still answer");
  const r = await w.page({ type: "reveal", itemId: m.matches[0].itemId, host: "site.example" }, 3, SITE);
  assert.equal(r.secret?.password, "site-pw", "and fills still fill");
  const before = world.log.length;
  world.tabs.set(3, { id: 3, url: `${SITE}/pay`, active: true });
  await w.page({ type: "captureCard", fields: { number: PAN } }, 3, SITE);
  const saved = await w.page({ type: "resolvePendingCardSave", action: "save" }, 3, SITE);
  assert.equal(saved.code, "server_ended", "nothing is written");
  await w.alarm("resync");
  assert.deepEqual(await w.popup({ type: "enrollQuickUnlock", pin: "Tq7#kw2pZ" }), { ok: false, code: "need_full_unlock" });
  assert.equal(world.log.length, before, "nothing at all is sent while it stands so");
  // A worker restart keeps it: readable, still ended, still silent.
  const w2 = await world.start();
  const st2 = await w2.popup({ type: "status" });
  assert.deepEqual([st2.unlocked, st2.serverEnded], [true, true]);
  assert.equal((await w2.page({ type: "matches", host: "site.example" }, 3, SITE)).matches.length, 1);
  await w2.alarm("resync");
  assert.ok(world.log.slice(before).every((l) => l.path === "/api/v1/instance" || !l.headers.authorization), "no credential is sent after a restart either");
  // Signing in again (after a lock) restores a session that syncs.
  server.override = null;
  await w2.popup({ type: "lock" });
  const again = await w2.popup({ type: "unlock", email: acct.email, password: acct.password });
  assert.equal(again.ok, true);
  const st3 = await w2.popup({ type: "status" });
  assert.deepEqual([st3.unlocked, st3.serverEnded], [true, false]);
});

// ---- design §2.3: the strict emailNorm keys the device record ----

test("§2.3: a device record kept under an address the strict emailNorm refuses is not found, nor rewritten", async () => {
  const { world, server, acct, w } = await signedInWorld({ signIn: false, account: { email: "a@b" } });
  // Written by an older build, whose looser rule took `a@b`.
  const oldKey = nsKey(originKeyFor(server.origin), "device:a@b");
  const old = { deviceSecret: "A".repeat(42) + "A", deviceId: "11111111-1111-4111-8111-111111111111" };
  world.trusted().set(oldKey, old);
  const r = await w.popup({ type: "unlock", email: acct.email, password: acct.password });
  assert.equal(r.ok, true, "the fake server takes the address; the real one refuses it");
  const login = world.log.find((l) => l.path === "/api/v1/auth/login")!;
  assert.equal(login.body.device.deviceId, undefined, "a new device: the old record's row is not named");
  assert.notEqual(login.body.device.deviceSecret, old.deviceSecret, "and its secret is not sent");
  assert.deepEqual(world.trusted().get(oldKey), old, "the old record is left as it was, never written under that key");
  const ns = nsKey(originKeyFor(server.origin), "");
  assert.deepEqual([...world.trusted().keys()].filter((k) => k.startsWith(ns + "device:")), [oldKey], "no record is made for the refused address");
});

// ---- "Remove data for this server" ----

test("Remove data for this server keeps the pin, its fork mark and the high-water mark; the device secret goes", async () => {
  const { world, server, w } = await signedInWorld({
    setup: ({ acct }) => {
      acct.addSharedVault();
      acct.addItem(acct.personalVaultId, login("mine"));
    },
  });
  const A = server.origin;
  const ns = nsKey(originKeyFor(A), "");
  const names = () => [...world.trusted().keys()].filter((k) => k.startsWith(ns)).map((k) => k.slice(ns.length));
  assert.ok(names().some((n) => n.startsWith("device:")));
  server.chain = new Chain({ origin: A });
  await w.alarm("resync"); // a fork: stored with the pin, and the session's marker
  assert.deepEqual(await w.popup({ type: "purgeServerData", origin: A }), { ok: true });
  const kept = names();
  assert.ok(kept.includes("cardPin"), "the pin stays");
  assert.equal((world.trusted().get(pinKey(A)) as { fork: boolean }).fork, true, "with its fork mark");
  assert.ok(kept.some((n) => n.startsWith("accountStateMemory:")), "the high-water mark stays");
  assert.ok(kept.some((n) => n.startsWith("itemHomes:")), "the item homes stay");
  assert.ok(!kept.some((n) => n.startsWith("device:")), "the device secret may go");
  assert.equal(world.session.get(nsKey(originKeyFor(A), "forkSeen")), true, "the session's fork marker stays");
  const w2 = await world.start();
  assert.deepEqual((await w2.popup({ type: "serverInfo" })).block, { kind: "fork", origin: A }, "still stopped after a restart");
});

// ---- one /instance refresh could freeze the worker ----

/** Count Ed25519 verifications (statement.ts signatureValid → tweetnacl) while [f] runs. */
async function verifications(f: () => Promise<unknown>): Promise<number> {
  const real = nacl.sign.detached.verify;
  let n = 0;
  nacl.sign.detached.verify = (m: Uint8Array, s: Uint8Array, k: Uint8Array) => {
    n++;
    return real(m, s, k);
  };
  try {
    await f();
  } finally {
    nacl.sign.detached.verify = real;
  }
  return n;
}

test("a pinned server's chain is verified forward from the pin, not from card 0", async () => {
  const { chain, w } = await signedInWorld({ setup: ({ chain }) => { for (let i = 1; i < 40; i++) chain.add({ name: `Smith Vault ${i}` }); } });
  assert.equal(await verifications(() => w.alarm("resync")), 0, "nothing new since the pin: nothing to verify");
  chain.add({ name: "Smith Vault renamed" });
  assert.equal(await verifications(() => w.alarm("resync")), 1, "one new card: one verification");
  assert.equal(await verifications(() => w.popup({ type: "chooseServer", choice: "own", origin: chain.cards[0].origin })), 0, "re-choosing it verifies forward too");
});

test("a first pin refuses a chain longer than the extension verifies, before verifying anything", async () => {
  const world = new World();
  const origin = "https://long.example";
  const chain = new Chain({ origin });
  for (let i = 1; i <= 64; i++) chain.add({ name: `Long ${i}` });
  world.serve(origin, chain);
  const w = await world.start();
  let r: unknown;
  assert.equal(await verifications(async () => (r = await w.popup({ type: "chooseServer", choice: "own", origin }))), 0);
  assert.deepEqual(r, { ok: false, code: "chain_too_long" });
  chain.frames.pop();
  chain.cards.pop();
  assert.equal((await w.popup({ type: "chooseServer", choice: "own", origin })).ok, true, "64 cards is the most a first pin verifies");
});

// ---- the first-launch wipe ----

test("the first start of this build deletes the old co-key and seal-key databases too", async () => {
  const world = new World();
  world.idb.set("andvari-qu", new Map([["cokey", new Map<string, unknown>([["ns.0123456789abcdef.k_nonexp", "old"]])]]));
  world.idb.set("andvari-session-seal", new Map([["kv", new Map<string, unknown>([["sealKey", { key: "old", epoch: 7 }]])]]));
  world.local.set("serverUrl", "https://old.example");
  world.session.set("session", { v: 1, iv: "x", ct: "y" });
  const w = await world.start();
  await w.popup({ type: "status" });
  assert.equal(world.idb.get("andvari-qu")!.get("cokey")!.size, 0, "the quick-unlock co-key database is emptied");
  const seal = world.idb.get("andvari-session-seal")!.get("kv")!;
  assert.notDeepEqual(seal.get("sealKey"), { key: "old", epoch: 7 }, "the old seal key is gone (the seal made its own after the wipe)");
  assert.equal(world.local.size, 0);
  assert.equal(world.session.get("session"), undefined);
});

test("with no IndexedDB at all, storage.local and storage.session are still cleared", async () => {
  const world = new World();
  world.idbUnavailable = true;
  world.local.set("serverUrl", "https://old.example");
  world.session.set("lockNotice", { kind: "idle", seconds: 60 });
  const w = await world.start();
  assert.equal((await w.popup({ type: "serverInfo" })).block?.kind, "no_store");
  assert.equal(world.local.size, 0);
  assert.equal(world.session.size, 0);
});

// ---- the host permission is asked with the pattern the popup requests ----

test("a server on a non-default port is asked for with a port-less match pattern (as Firefox needs)", async () => {
  const world = new World();
  world.firefoxPatterns = true;
  const origin = "https://vault.smith.example:8443";
  world.serve(origin, new Chain({ origin }));
  const w = await world.start();
  const r = await w.popup({ type: "chooseServer", choice: "own", origin });
  assert.equal(r.ok, true, JSON.stringify(r));
  assert.deepEqual(world.asked, [originMatchPattern(origin)]);
  assert.equal(originMatchPattern(origin), "https://vault.smith.example/*");
});

// ---- spec 03 §0.1 "Field presence": an absent kdfParams is refused, never guessed ----

test("spec 03 §0.1: a prelogin answer without kdfParams is refused as a KDF policy fault, and nothing is derived or sent", async () => {
  const { world, server, acct, w } = await signedInWorld({ signIn: false });
  server.override = (method: string, path: string) =>
    method === "POST" && path === "/api/v1/auth/prelogin" ? new Response(JSON.stringify({ kdfSalt: "AAAAAAAAAAAAAAAAAAAAAA" }), { status: 200 }) : undefined;
  let derived = false;
  world.kdfHook = async () => {
    derived = true;
  };
  assert.deepEqual(await w.popup({ type: "unlock", email: acct.email, password: acct.password }), { ok: false, code: "kdf_policy", error: "KdfPolicyError: server KDF params rejected (kdf_below_floor)" });
  assert.equal(derived, false);
  assert.ok(!world.dialed(server.origin).includes("POST /api/v1/auth/login"));
});

test("a stored pin whose origin is not its namespace's is damaged and blocks the origin", async () => {
  const { world, server } = await signedInWorld({ signIn: false });
  const A = server.origin;
  const rec = world.trusted().get(pinKey(A)) as { pin: { origin: string } };
  rec.pin.origin = "https://elsewhere.example";
  const w2 = await world.start();
  const info = await w2.popup({ type: "serverInfo" });
  assert.deepEqual(info.block, { kind: "pin_damaged", origin: A });
});
