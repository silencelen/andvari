// "Forget the earlier account on this device" in the extension (decided on 2026-11-17): offered only at the refusal of
// another account under a known address, behind the popup's second confirmation. It removes the address's record and
// the earlier account's own records here, keeps the record of that account's identity key and everything of the server,
// and the next sign-in under the address is taken and said once. Driven through the real background.ts.
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { addressRecordName, keyRecordName } from "./accountmemory.ts";
import { rand, signedInWorld } from "./testing/bgharness.ts";

const PIN = "Tq7#kw2pZ";
type W = { trusted(): Map<string, unknown> };
/** Every trusted record as stored, by name. */
const all = (world: W) => Object.fromEntries([...world.trusted()].map(([k, v]) => [k, JSON.stringify(v)]));
const named = (world: W, tail: string) => [...world.trusted().keys()].filter((k) => k.endsWith(tail));
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

/** U signed in (records written, a PIN set up), signed out; the account deleted and made again (V) under the address. */
async function remadeWorld() {
  const t = await signedInWorld({
    setup: ({ server }) => {
      server.override = (method: string, path: string, body: { refreshToken?: string } | undefined) =>
        method === "POST" && path === "/api/v1/auth/refresh" ? json({ accessToken: String(body?.refreshToken).replace(/^rt-/, "at-"), refreshToken: String(body?.refreshToken) }) : null;
    },
  });
  const u = t.acct;
  assert.equal((await t.w.popup({ type: "enrollQuickUnlock", pin: PIN })).ok, true);
  await t.w.popup({ type: "lock" });
  t.server.accounts.length = 0;
  const v = t.server.addAccount({ email: u.email, password: u.password });
  return { ...t, u, v };
}

test("the forgetting removes the address's record and the earlier account's own records, keeps its key record and the server, and is said once", async () => {
  const { world, w, u, v } = await remadeWorld();
  assert.equal((await w.popup({ type: "unlock", email: u.email, password: u.password })).code, "remade_account");
  const before = all(world);
  const keyName = named(world, keyRecordName(u.userId));
  assert.equal(keyName.length, 1);
  assert.equal(named(world, addressRecordName(u.email)).length, 1);
  assert.ok((await w.popup({ type: "status" })).quickUnlock.enrolled, "the PIN is set up for the earlier account");
  const own = Object.keys(before).filter((k) => k.includes(u.userId) && !k.endsWith(keyRecordName(u.userId)));
  assert.ok(own.length > 0, `it had records of its own: ${own.join(", ")}`);
  assert.ok(Object.keys(before).some((k) => k.includes(".device:")), "and a device record under the address");
  assert.deepEqual(await w.popup({ type: "forgetEarlierAccount", email: u.email }), { ok: true });
  const after = all(world);
  // Removed: the address's record, the device record under the address, and everything named by the earlier account's id
  // but its key record; and its quick unlock.
  assert.deepEqual(named(world, addressRecordName(u.email)), [], "the address's record");
  assert.deepEqual(Object.keys(after).filter((k) => k.includes(".device:")), [], "the device record kept under the address");
  assert.deepEqual(Object.keys(after).filter((k) => k.includes(u.userId) && !k.endsWith(keyRecordName(u.userId))), [], "the earlier account's own records");
  assert.equal((await w.popup({ type: "status" })).quickUnlock.enrolled, false, "its quick unlock");
  // Kept: the key record, as it was, and every other record (the server's pin among them).
  assert.equal(after[keyName[0]!], before[keyName[0]!]);
  for (const k of Object.keys(before)) {
    if (k.includes(".device:") || k.endsWith(addressRecordName(u.email)) || (k.includes(u.userId) && !k.endsWith(keyRecordName(u.userId)))) continue;
    assert.ok(k in after, `kept: ${k}`);
  }
  // The address is new to the extension: the new account is taken, and that is said once.
  const r = await w.popup({ type: "unlock", email: v.email, password: v.password });
  assert.deepEqual({ ok: r.ok, notice: r.notice }, { ok: true, notice: "account_remembered" });
  await w.popup({ type: "signOut" });
  const again = await w.popup({ type: "unlock", email: v.email, password: v.password });
  assert.deepEqual({ ok: again.ok, notice: again.notice }, { ok: true, notice: undefined }, "only once");
});

test("the mark that the extension now remembers the new account is kept at rest: a worker stopped before the sign-in still says it, once", async () => {
  const { world, w, u, v } = await remadeWorld();
  assert.equal((await w.popup({ type: "unlock", email: u.email, password: u.password })).code, "remade_account");
  assert.deepEqual(await w.popup({ type: "forgetEarlierAccount", email: u.email }), { ok: true });
  assert.equal(named(world, "accountRemembered:" + u.email.toLowerCase()).length, 1, "kept with the server's records");
  // The browser stops the worker between the forgetting and the new account's first sign-in.
  const w2 = await world.start();
  const r = await w2.popup({ type: "unlock", email: v.email, password: v.password });
  assert.deepEqual({ ok: r.ok, notice: r.notice }, { ok: true, notice: "account_remembered" });
  assert.deepEqual(named(world, "accountRemembered:" + u.email.toLowerCase()), [], "removed once said");
  await w2.popup({ type: "signOut" });
  const w3 = await world.start();
  const again = await w3.popup({ type: "unlock", email: v.email, password: v.password });
  assert.deepEqual({ ok: again.ok, notice: again.notice }, { ok: true, notice: undefined }, "only once");
});

test("where the mark could not be read at the sign-in, the notice is not said a second time at the next", async () => {
  const { world, w, u, v } = await remadeWorld();
  assert.equal((await w.popup({ type: "unlock", email: u.email, password: u.password })).code, "remade_account");
  assert.deepEqual(await w.popup({ type: "forgetEarlierAccount", email: u.email }), { ok: true });
  let once = true;
  world.idbFault = (_db: string, op: string, key: unknown) => {
    if (!once || op !== "get" || !String(key).includes("accountRemembered")) return false;
    once = false;
    return true;
  };
  const r = await w.popup({ type: "unlock", email: v.email, password: v.password });
  assert.deepEqual({ ok: r.ok, notice: r.notice }, { ok: true, notice: "account_remembered" }, "said from memory");
  world.idbFault = null;
  await w.popup({ type: "signOut" });
  const again = await w.popup({ type: "unlock", email: v.email, password: v.password });
  assert.deepEqual({ ok: again.ok, notice: again.notice }, { ok: true, notice: undefined }, "not said a second time");
});

test("\"Forget this server\" removes that mark with the server's records", async () => {
  const { world, w, u } = await remadeWorld();
  assert.equal((await w.popup({ type: "unlock", email: u.email, password: u.password })).code, "remade_account");
  assert.deepEqual(await w.popup({ type: "forgetEarlierAccount", email: u.email }), { ok: true });
  assert.equal(named(world, "accountRemembered:" + u.email.toLowerCase()).length, 1);
  assert.equal((await w.popup({ type: "forgetServer" })).ok, true);
  assert.deepEqual(named(world, "accountRemembered:" + u.email.toLowerCase()), []);
});

test("after it, the earlier account served under another key is the identity fault, with no offer", async () => {
  const { server, w, u, v } = await remadeWorld();
  assert.equal((await w.popup({ type: "unlock", email: u.email, password: u.password })).code, "remade_account");
  assert.deepEqual(await w.popup({ type: "forgetEarlierAccount", email: u.email }), { ok: true });
  assert.equal((await w.popup({ type: "unlock", email: v.email, password: v.password })).ok, true);
  await w.popup({ type: "signOut" });
  // The server serves the earlier account again, under a key of its own making.
  server.accounts.length = 0;
  server.accounts.push(u);
  u.seed = rand(32);
  u.uvk = rand(32);
  assert.equal((await w.popup({ type: "unlock", email: u.email, password: u.password })).code, "identity_mismatch");
  assert.deepEqual(await w.popup({ type: "forgetEarlierAccount", email: u.email }), { ok: false, code: "not_offered" }, "nothing to forget there");
});

test("never offered at the same account under another key, at a quick unlock, or where the records could not be read", async () => {
  const { world, acct, w } = await signedInWorld({
    setup: ({ server }) => {
      server.override = (method: string, path: string, body: { refreshToken?: string } | undefined) =>
        method === "POST" && path === "/api/v1/auth/refresh" ? json({ accessToken: String(body?.refreshToken).replace(/^rt-/, "at-"), refreshToken: String(body?.refreshToken) }) : null;
    },
  });
  assert.equal((await w.popup({ type: "enrollQuickUnlock", pin: PIN })).ok, true);
  await w.popup({ type: "lock" });
  acct.seed = rand(32); // the same account, a seed of the server's under the same vault key
  assert.equal((await w.popup({ type: "unlockWithPin", pin: PIN })).code, "identity_mismatch");
  assert.equal((await w.popup({ type: "forgetEarlierAccount", email: acct.email })).code, "not_offered", "not at a quick unlock");
  assert.equal((await w.popup({ type: "unlock", email: acct.email, password: acct.password })).code, "identity_mismatch");
  assert.equal((await w.popup({ type: "forgetEarlierAccount", email: acct.email })).code, "not_offered", "not for the same account");
  let once = true;
  world.idbFault = (_db: string, op: string, key: unknown) => {
    if (!once || op !== "get" || !String(key).includes("selfIdentity")) return false;
    once = false;
    return true;
  };
  assert.equal((await w.popup({ type: "unlock", email: acct.email, password: acct.password })).code, "memory_unreadable");
  assert.equal((await w.popup({ type: "forgetEarlierAccount", email: acct.email })).code, "not_offered", "not where the cause is not known");
});

test("a read or a removal that fails forgets nothing and is never answered forgotten; a session of that account open refuses it", async () => {
  const { world, server, w, u, v } = await remadeWorld();
  assert.equal((await w.popup({ type: "unlock", email: u.email, password: u.password })).code, "remade_account");
  const before = all(world);
  world.idbFault = (_db: string, op: string, key: unknown) => op === "get" && String(key).includes("selfIdentityByEmail");
  assert.deepEqual(await w.popup({ type: "forgetEarlierAccount", email: u.email }), { ok: false, code: "failed" });
  world.idbFault = (_db: string, op: string) => op === "delete";
  assert.deepEqual(await w.popup({ type: "forgetEarlierAccount", email: u.email }), { ok: false, code: "failed" });
  world.idbFault = null;
  assert.deepEqual(all(world), before, "nothing was forgotten");
  // The earlier account is served again as itself and opened: that later sign-in cleared the offer, and nothing of it is
  // forgotten while its session is open.
  server.accounts.length = 0;
  server.accounts.push(u);
  assert.equal((await w.popup({ type: "unlock", email: u.email, password: u.password })).ok, true);
  assert.equal((await w.popup({ type: "forgetEarlierAccount", email: u.email })).ok, false);
  assert.ok(v.userId !== u.userId);
});

/** Holds the next request to [path] at [server] until the returned release is called; answers it as the server would. */
function holdNext(server: { override: unknown; handle: (...a: unknown[]) => Promise<Response> }, path: string) {
  const before = server.override as ((...a: unknown[]) => unknown) | null;
  let release!: () => void;
  const held = new Promise<void>((r) => (release = r));
  let seen = false;
  let holding = true;
  server.override = (method: string, p: string, body: unknown, headers: unknown) => {
    if (holding && method === "POST" && p === path) {
      holding = false;
      seen = true;
      return held.then(() => server.handle(method, p, body, headers));
    }
    return before?.(method, p, body, headers) ?? null;
  };
  return { release, seen: () => seen };
}
const until = async (done: () => boolean) => {
  for (let i = 0; i < 500 && !done(); i++) await new Promise((r) => setTimeout(r, 10));
};

test("R4: a password sign-in of the earlier account under way: the forgetting leaves it, and nothing is recorded again or said as new", async () => {
  const { world, server, w, u } = await remadeWorld();
  assert.equal((await w.popup({ type: "unlock", email: u.email, password: u.password })).code, "remade_account");
  server.accounts.length = 0;
  server.accounts.push(u); // the server serves the earlier account again
  const login = holdNext(server as never, "/api/v1/auth/login");
  const signing = w.popup({ type: "unlock", email: u.email, password: u.password });
  await until(login.seen);
  const forgot = await w.popup({ type: "forgetEarlierAccount", email: u.email });
  login.release();
  const r = await signing;
  assert.notEqual(forgot.ok, true, "nothing is forgotten under a sign-in on its way");
  assert.notEqual(r.notice, "account_remembered", "the earlier account is never announced as new");
  assert.equal(named(world, addressRecordName(u.email)).length, 1, "the address still names the account it named");
});

test("R5: a PIN unlock of the earlier account under way: the forgetting leaves it, and it never opens over removed records", async () => {
  const { world, server, w, u } = await remadeWorld();
  assert.equal((await w.popup({ type: "unlock", email: u.email, password: u.password })).code, "remade_account");
  server.accounts.length = 0;
  server.accounts.push(u);
  const refresh = holdNext(server as never, "/api/v1/auth/refresh");
  const unlocking = w.popup({ type: "unlockWithPin", pin: PIN });
  await until(refresh.seen);
  const forgot = await w.popup({ type: "forgetEarlierAccount", email: u.email });
  refresh.release();
  const r = await unlocking;
  const records = named(world, addressRecordName(u.email)).length;
  assert.ok(!(forgot.ok === true && r.ok === true), `not both: forgotten ${JSON.stringify(forgot)} and opened ${JSON.stringify(r)}`);
  if (r.ok === true) assert.equal(records, 1, "an account opened keeps its records");
});

test("R9: an offer does not outlive a later refusal of the same account under another key", async () => {
  const { server, w, u } = await remadeWorld();
  assert.equal((await w.popup({ type: "unlock", email: u.email, password: u.password })).code, "remade_account");
  server.accounts.length = 0;
  server.accounts.push(u);
  u.seed = rand(32);
  u.uvk = rand(32);
  assert.equal((await w.popup({ type: "unlock", email: u.email, password: u.password })).code, "identity_mismatch");
  assert.deepEqual(await w.popup({ type: "forgetEarlierAccount", email: u.email }), { ok: false, code: "not_offered" });
});

test("the offer is cleared at a lock and at a quick unlock after it", async () => {
  const { w, u } = await remadeWorld();
  assert.equal((await w.popup({ type: "unlock", email: u.email, password: u.password })).code, "remade_account");
  await w.popup({ type: "lock" });
  assert.deepEqual(await w.popup({ type: "forgetEarlierAccount", email: u.email }), { ok: false, code: "not_offered" }, "after a lock");
  assert.equal((await w.popup({ type: "unlock", email: u.email, password: u.password })).code, "remade_account");
  await w.popup({ type: "unlockWithPin", pin: "000000000" });
  assert.deepEqual(await w.popup({ type: "forgetEarlierAccount", email: u.email }), { ok: false, code: "not_offered" }, "after a quick unlock tried");
});

test("the quick unlock goes before the one removal in the trusted store: a removal that fails leaves every protective record", async () => {
  const { world, w, u } = await remadeWorld();
  assert.equal((await w.popup({ type: "unlock", email: u.email, password: u.password })).code, "remade_account");
  const before = all(world);
  world.idbFault = (db: string, op: string) => db === "andvari-trusted" && op === "delete";
  assert.deepEqual(await w.popup({ type: "forgetEarlierAccount", email: u.email }), { ok: false, code: "failed" });
  world.idbFault = null;
  assert.deepEqual(all(world), before, "every record in the trusted store as it was");
  assert.equal((await w.popup({ type: "status" })).quickUnlock.enrolled, false, "the quick unlock was removed first (the line says it may be gone)");
  assert.deepEqual(await w.popup({ type: "forgetEarlierAccount", email: u.email }), { ok: true }, "a retry finishes it");
});

test("the popup raises the offer at that refusal only, and forgets only at the second step, after the confirmation's text", () => {
  const popup = readFileSync(new URL("./popup.ts", import.meta.url), "utf8");
  assert.equal(popup.match(/offerForgetEarlier\(/g)?.length, 3, "defined once, raised at that refusal on the password step and on the code step");
  assert.equal(popup.match(/if \(r\?\.code === "remade_account"\) offerForgetEarlier\(email\);/g)?.length, 2);
  const click = popup.slice(popup.indexOf('el("forget-earlier").addEventListener("click"'));
  const confirm = click.indexOf("showMsg(\"info\", fillApproved(FORGET_EARLIER_CONFIRM, f.email));");
  const send = click.indexOf('ask({ type: "forgetEarlierAccount", email: f.email })');
  assert.ok(confirm > 0 && send > confirm && click.slice(confirm, send).includes("return;"), "the first click only shows the confirmation");
  assert.ok(read("../popup.html").includes('<button id="forget-earlier" class="link" type="button" hidden></button>'), "hidden until offered");
});

const read = (p: string) => readFileSync(new URL(p, import.meta.url), "utf8");

test("it is not \"Forget this server\": no purge of the server's records, and the records after it are written only where absent", () => {
  const bg = readFileSync(new URL("./background.ts", import.meta.url), "utf8");
  const fn = bg.slice(bg.indexOf("async function forgetEarlierAccount("), bg.indexOf("/** A kept key record as its canonical text"));
  assert.ok(fn.length > 0);
  assert.doesNotMatch(fn, /purgeOriginNamespace|forgetServer\(|removeByPrefix|keyRecordName/);
  assert.doesNotMatch(fn, /setWhereAbsent/);
  assert.equal(fn.match(/trusted\.set\(/g)?.length, 1, "the forgetting writes nothing but the mark that the next sign-in says it");
  assert.ok(fn.includes("await trusted.set({ [rememberNoticeName(n)]: true });"));
  assert.match(bg, /await trusted\.setWhereAbsent\(Object\.fromEntries\(Object\.entries\(records\)/);
});
