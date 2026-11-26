// Which account an address is, and each account's identity key, as the extension knows them at a server (decided on
// 2026-11-17; accountmemory.ts). Before, the extension kept neither: at a fresh sign-in it took the same account under
// another key, and another account under a known address, without a word. Driven through the real background worker
// (testing/bgharness.ts) against a fake server that can delete an account and make it again, or serve it under another key.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { addressNorm, addressRecordName, judgeServed, keyRecordName, readRecord, recordsFor } from "./accountmemory.ts";
import { fillApproved, REMADE_ACCOUNT, unlockErrorCopy, IDENTITY_MISMATCH } from "./errors.ts";
import { isTrustRecord } from "./serverswitch.ts";
import { Account, connect, rand, signedInWorld } from "./testing/bgharness.ts";

const U = "11111111-1111-4111-8111-111111111111";
const V = "22222222-2222-4222-8222-222222222222";
const KEY_U = "a".repeat(43);
const KEY_X = "b".repeat(43);

test("the account after it was deleted and made again under the same address is refused, with both possibilities said", async () => {
  const { server, acct, w } = await signedInWorld();
  await w.popup({ type: "signOut" });
  // The person (or the operator) deletes the account and makes it again: a new id, new keys, the same address.
  server.accounts.length = 0;
  const remade = server.addAccount({ email: acct.email, password: acct.password });
  assert.notEqual(remade.userId, acct.userId);
  const r = await w.popup({ type: "unlock", email: acct.email, password: acct.password });
  assert.deepEqual({ ok: r.ok, code: r.code }, { ok: false, code: "remade_account" });
  assert.equal((await w.popup({ type: "status" })).unlocked ?? false, false, "nothing of the served account is opened");
  assert.equal(unlockErrorCopy("remade_account", acct.email), fillApproved(REMADE_ACCOUNT, acct.email));
  // The records outlive the refusal and a later try: the same answer again.
  const again = await w.popup({ type: "unlock", email: acct.email, password: acct.password });
  assert.equal(again.code, "remade_account");
});

test("the way out there is today, as the refusal says: \"Forget this server\" forgets the earlier account with everything of the server", async () => {
  const { server, acct, w } = await signedInWorld();
  await w.popup({ type: "signOut" });
  server.accounts.length = 0;
  const remade = server.addAccount({ email: acct.email, password: acct.password });
  assert.equal((await w.popup({ type: "unlock", email: acct.email, password: acct.password })).code, "remade_account");
  assert.deepEqual(await w.popup({ type: "forgetServer" }), { ok: true });
  await connect(w, server.origin); // the server is checked again, as at a first connection
  const r = await w.popup({ type: "unlock", email: remade.email, password: remade.password });
  assert.equal(r.ok, true, JSON.stringify(r));
});

test("the same account served under another identity key is the identity fault, with nothing offered", async () => {
  const { acct, w } = await signedInWorld();
  await w.popup({ type: "signOut" });
  // The server now serves the same account id with a key set of its own making (the password known to it).
  acct.seed = rand(32);
  acct.uvk = rand(32);
  const r = await w.popup({ type: "unlock", email: acct.email, password: acct.password });
  assert.deepEqual({ ok: r.ok, code: r.code }, { ok: false, code: "identity_mismatch" });
  assert.equal(unlockErrorCopy("identity_mismatch"), IDENTITY_MISMATCH);
});

test("the account as it was is taken again after a sign-out: the records name it", async () => {
  const { acct, w } = await signedInWorld();
  await w.popup({ type: "signOut" });
  const r = await w.popup({ type: "unlock", email: acct.email, password: acct.password });
  assert.equal(r.ok, true, JSON.stringify(r));
});

test("an extension that never knew the address takes the account it is served", async () => {
  const { server, w } = await signedInWorld({ signIn: false });
  const other: Account = server.addAccount({ email: "bea@example.com", password: "another horse" });
  const r = await w.popup({ type: "unlock", email: other.email, password: other.password });
  assert.equal(r.ok, true, JSON.stringify(r));
});

test("the served account's own key record comes before the question which account the address is", () => {
  // The address names V; the server serves U (known here, under KEY_U) with another key: the identity fault, no offer.
  assert.deepEqual(judgeServed({ boundUserId: V, keyOfServed: KEY_U }, U, KEY_X), { ok: false, code: "identity_mismatch" });
  // U served with its own key while the address names V: the remade-account refusal (both possibilities).
  assert.deepEqual(judgeServed({ boundUserId: V, keyOfServed: KEY_U }, U, KEY_U), { ok: false, code: "remade_account" });
  assert.deepEqual(judgeServed({ boundUserId: U, keyOfServed: KEY_U }, U, KEY_U), { ok: true });
  assert.deepEqual(judgeServed({ boundUserId: null, keyOfServed: null }, U, KEY_X), { ok: true });
  // A record that does not read is never taken as a match.
  assert.deepEqual(judgeServed({ boundUserId: readRecord(42), keyOfServed: null }, U, KEY_U), { ok: false, code: "remade_account" });
  assert.deepEqual(judgeServed({ boundUserId: null, keyOfServed: readRecord({}) }, U, KEY_U), { ok: false, code: "identity_mismatch" });
  assert.equal(readRecord(undefined), null);
  assert.notEqual(readRecord(null), null, "a stored null is a record");
  assert.deepEqual(judgeServed({ boundUserId: null, keyOfServed: readRecord(null) }, U, KEY_U), { ok: false, code: "identity_mismatch" });
});

// ---- A review of the records found two roads past them; each test below failed on the code before the fix ----

const PIN = "Tq7#kw2pZ";
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
/** The fake server has no refresh route of its own: it answers a quick unlock's refresh with the account's usual pair. */
const answerRefresh = ({ server }: { server: { override: unknown } }) => {
  server.override = (method: string, path: string, body: { refreshToken?: string } | undefined) =>
    method === "POST" && path === "/api/v1/auth/refresh" ? json({ accessToken: String(body?.refreshToken).replace(/^rt-/, "at-"), refreshToken: String(body?.refreshToken) }) : null;
};
/** The records this extension keeps of accounts and of this browser's device row, as stored. */
const kept = (world: { trusted(): Map<string, unknown> }) =>
  Object.fromEntries([...world.trusted()].filter(([k]) => /selfIdentity|\.device:/.test(k)).map(([k, v]) => [k, JSON.stringify(v)]));

test("the quick unlock compares the served key with the kept record: the same account under a key the server made is refused there as on the password road", async () => {
  const { world, acct, w } = await signedInWorld({ setup: answerRefresh });
  assert.equal((await w.popup({ type: "enrollQuickUnlock", pin: PIN })).ok, true);
  await w.popup({ type: "lock" });
  const before = kept(world);
  // A server that holds the account's vault key keeps the wrapped key as it is and serves a seed of its own under it.
  acct.seed = rand(32);
  const from = world.log.length;
  const r = await w.popup({ type: "unlockWithPin", pin: PIN });
  assert.deepEqual({ ok: r.ok, code: r.code }, { ok: false, code: "identity_mismatch" });
  assert.equal((await w.popup({ type: "status" })).unlocked ?? false, false, "nothing is opened");
  assert.ok(!world.dialed().slice(from).some((l) => l.startsWith("GET /api/v1/sync")), "nothing is synced");
  assert.deepEqual(kept(world), before, "nothing is written");
  // The password road refuses the very same served key.
  const p = await w.popup({ type: "unlock", email: acct.email, password: acct.password });
  assert.equal(p.code, "identity_mismatch");
});

test("a read of the records that fails refuses the sign-in, and the kept key stays as it was", async () => {
  const { world, acct, w } = await signedInWorld();
  await w.popup({ type: "signOut" });
  const before = kept(world);
  const honest = { seed: acct.seed, uvk: acct.uvk };
  acct.seed = rand(32);
  acct.uvk = rand(32);
  // The store worked at start; it fails on this one read (a transaction that timed out under load).
  let failed = false;
  world.idbFault = (_db: string, op: string, key: unknown) => {
    if (failed || op !== "get" || !String(key).includes("selfIdentity")) return false;
    failed = true;
    return true;
  };
  const r = await w.popup({ type: "unlock", email: acct.email, password: acct.password });
  assert.equal(failed, true);
  assert.deepEqual({ ok: r.ok, code: r.code }, { ok: false, code: "memory_unreadable" });
  assert.equal((await w.popup({ type: "status" })).unlocked ?? false, false);
  assert.deepEqual(kept(world), before, "the kept records are as they were");
  // The read works again: the substitution is the identity fault, and the true account still signs in.
  assert.equal((await w.popup({ type: "unlock", email: acct.email, password: acct.password })).code, "identity_mismatch");
  Object.assign(acct, honest);
  const t = await w.popup({ type: "unlock", email: acct.email, password: acct.password });
  assert.equal(t.ok, true, JSON.stringify(t));
});

test("a sign-in writes a record only where none exists: a key written meanwhile is never overwritten", async () => {
  const { world, server, acct, w } = await signedInWorld({ signIn: false });
  const other = "c".repeat(43);
  let name = "";
  server.override = (_m: string, path: string) => {
    if (path.startsWith("/api/v1/sync") && name === "") {
      // Between the comparison and the write, the record of the account's key appears (another sign-in's write).
      const device = [...world.trusted().keys()].find((k) => k.includes(".device:")) ?? "";
      name = device.slice(0, device.indexOf("device:")) + keyRecordName(acct.userId);
      world.trusted().set(name, other);
    }
    return null;
  };
  const r = await w.popup({ type: "unlock", email: acct.email, password: acct.password });
  assert.equal(r.ok, true, JSON.stringify(r));
  assert.notEqual(name, "");
  assert.equal(world.trusted().get(name), other, "the record kept is not replaced by the served key");
});

test("a sign-in refused for either identity reason ends the session the server gave it, and leaves the device's record as it was", async () => {
  const { world, server, acct, w } = await signedInWorld();
  await w.popup({ type: "signOut" });
  const before = kept(world);
  // Another account under the known address.
  server.accounts.length = 0;
  const remade = server.addAccount({ email: acct.email, password: acct.password });
  let from = world.log.length;
  assert.equal((await w.popup({ type: "unlock", email: acct.email, password: acct.password })).code, "remade_account");
  const ends = (n: number) => world.log.slice(n).filter((l) => l.method === "POST" && l.path === "/api/v1/auth/logout").map((l) => l.headers?.authorization);
  assert.deepEqual(ends(from), [`Bearer at-${remade.userId}`], "the refused session is ended at the server");
  assert.deepEqual(kept(world), before, "nothing was changed: the device's record names the row it named before");
  // The same account under another key.
  server.accounts.length = 0;
  server.accounts.push(acct);
  acct.seed = rand(32);
  acct.uvk = rand(32);
  from = world.log.length;
  assert.equal((await w.popup({ type: "unlock", email: acct.email, password: acct.password })).code, "identity_mismatch");
  assert.deepEqual(ends(from), [`Bearer at-${acct.userId}`]);
  assert.deepEqual(kept(world), before);
});

/** The key record of [userId] as stored, found by its name. */
const keyRecord = (world: { trusted(): Map<string, unknown> }, userId: string) => [...world.trusted()].find(([k]) => k.endsWith(keyRecordName(userId)));

test("the key record keeps the verified key's canonical text, whatever text the server served it in; keys compare as bytes", async () => {
  const { world, server, acct, w } = await signedInWorld({ signIn: false });
  const canonical = acct.accountKeys().identityPub;
  // The first login serves the key padded with spaces (a text that decodes to the same 32 bytes).
  const padded = canonical.slice(0, 10) + " ".repeat(5000) + canonical.slice(10);
  let first = true;
  server.override = (method: string, path: string) => {
    if (!(first && method === "POST" && path === "/api/v1/auth/login")) return null;
    first = false;
    return json({ userId: acct.userId, deviceId: crypto.randomUUID(), accessToken: `at-${acct.userId}`, refreshToken: `rt-${acct.userId}`, accountKeys: { ...acct.accountKeys(), identityPub: padded }, role: "member" });
  };
  const r = await w.popup({ type: "unlock", email: acct.email, password: acct.password });
  assert.equal(r.ok, true, JSON.stringify(r));
  assert.equal(keyRecord(world, acct.userId)?.[1], canonical, "the record is the short canonical text");
  await w.popup({ type: "signOut" });
  const again = await w.popup({ type: "unlock", email: acct.email, password: acct.password });
  assert.equal(again.ok, true, "the same key served plainly is the same key");
});

test("a stored null under a record's name is a record: neither taken as none nor replaced", async () => {
  const { world, acct, w } = await signedInWorld();
  await w.popup({ type: "signOut" });
  const [name] = keyRecord(world, acct.userId)!;
  world.trusted().set(name, null);
  acct.seed = rand(32);
  acct.uvk = rand(32);
  const r = await w.popup({ type: "unlock", email: acct.email, password: acct.password });
  assert.equal(r.code, "identity_mismatch", "a substitution is not taken under a null");
  assert.equal(world.trusted().get(name), null, "and the null is not replaced");
});

test("the device's record is written before the first request after the login: a sign-in failed there names its row next time", async () => {
  const { world, server, acct, w } = await signedInWorld({ signIn: false });
  let failed = false;
  server.override = (_m: string, path: string) => {
    if (failed || !path.startsWith("/api/v1/sync")) return null;
    failed = true;
    return json({ error: "unavailable", message: "busy" }, 503);
  };
  const r = await w.popup({ type: "unlock", email: acct.email, password: acct.password });
  assert.equal(r.ok, false);
  assert.equal((await w.popup({ type: "unlock", email: acct.email, password: acct.password })).ok, true);
  const sent = world.log.filter((l: { path: string }) => l.path === "/api/v1/auth/login").map((l: { body: { device: { deviceId?: string } } }) => l.body.device.deviceId ?? null);
  assert.equal(sent.length, 2);
  assert.equal(sent[0], null, "a first sign-in has no row yet");
  assert.equal(typeof sent[1], "string", "the second names the row the first was given");
});

test("the records: named by the address and by the account's id, kept with the server's pin by \"Remove data for this server\"", () => {
  assert.equal(addressNorm("  Ola@Example.ORG "), "ola@example.org");
  assert.deepEqual(recordsFor("Ola@example.org", U, KEY_U), { [addressRecordName("ola@example.org")]: U, [keyRecordName(U)]: KEY_U });
  assert.equal(isTrustRecord(addressRecordName("ola@example.org")), true);
  assert.equal(isTrustRecord(keyRecordName(U)), true);
});
