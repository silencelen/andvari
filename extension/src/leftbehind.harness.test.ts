// node --test. What the extension leaves in the browser's storage after each way an account's
// session ends here. The real background.ts, driven through testing/bgharness.ts; every key of every area it uses
// (storage.session, storage.local, IndexedDB: the trusted store, the session-seal key, the quick-unlock co-key).
// Each end's whole set of keys is pinned, so a key added later fails here until someone decides whether it stays.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { settle, signedInWorld, type World } from "./testing/bgharness.ts";

const SITE = "https://shop.example";

/** Every key, area-prefixed, with the origin namespace, the email and the user id replaced by placeholders, and a
 *  trailing `!` where the value (not the key) names the email or the user id. */
function dump(world: World, acct: { email: string; userId: string }): string[] {
  const out: string[] = [];
  const norm = (k: string) => k.replace(/ns\.[0-9a-f]{16}\./, "ns.<origin>.").replaceAll(acct.email, "<email>").replaceAll(acct.userId, "<userId>");
  const valueNames = (v: unknown) => {
    let s: string;
    try {
      s = JSON.stringify(v, (_k, x) => (x instanceof Uint8Array ? "" : x)) ?? "";
    } catch {
      s = String(v);
    }
    return s.includes(acct.email) || s.includes(acct.userId) ? " !" : "";
  };
  for (const [k, v] of world.session) out.push(`session:${norm(k)}${valueNames(v)}`);
  for (const [k, v] of world.local) out.push(`local:${norm(k)}${valueNames(v)}`);
  for (const [db, stores] of world.idb as Map<string, Map<string, Map<unknown, unknown>>>) {
    for (const [store, kv] of stores) for (const [k, v] of kv) out.push(`idb:${db}/${store}:${norm(String(k))}${valueNames(v)}`);
  }
  return out.sort();
}

async function enrolledWithAPage() {
  const r = await signedInWorld({ setup: ({ acct }) => void acct.addItem(acct.personalVaultId, { type: "login", name: "shop", login: { username: "alice", password: "pw", uris: [SITE] } }) });
  assert.equal((await r.w.popup({ type: "enrollQuickUnlock", pin: "Tq7#kw2pZ" })).ok, true);
  r.world.tabs.set(4, { id: 4, url: `${SITE}/login`, active: true });
  await r.w.page({ type: "pageInfo" }, 4, SITE);
  return r;
}

/** Kept by every end but "forget this server": the server choice and its pin (trust records, §4.4), the format marker,
 *  this browser's device record for the account (keyed by email; it carries the device id), the account's item homes
 *  and personal-wrap cache (trust records, A8), the remembered email (a convenience, spec 05 A15 (c)), the session-seal
 *  key, and the tab records' page-known facts (a tab's own top origin and form kinds). Also the records of which account
 *  the address is and of that account's identity key (accountmemory.ts, decided on 2026-11-17): they outlive every end
 *  on purpose, and go only with the server. */
const TRUST = [
  "idb:andvari-session-seal/kv:sealKey",
  "idb:andvari-trusted/kv:lastEmail !",
  "idb:andvari-trusted/kv:ns.<origin>.cardPin",
  "idb:andvari-trusted/kv:ns.<origin>.device:<email>",
  "idb:andvari-trusted/kv:ns.<origin>.itemHomes:<userId>",
  "idb:andvari-trusted/kv:ns.<origin>.personalWrap:<userId>",
  "idb:andvari-trusted/kv:ns.<origin>.selfIdentityByEmail:<email> !",
  "idb:andvari-trusted/kv:ns.<origin>.selfIdentityPub:<userId>",
  "idb:andvari-trusted/kv:serverUrl",
  "idb:andvari-trusted/kv:storeFormat",
];
const QUICK = ["idb:andvari-qu/cokey:ns.<origin>.k_nonexp", "session:ns.<origin>.knownLogins", "session:ns.<origin>.quickUnlock"];
const sorted = (xs: string[]) => [...xs].sort();

test("(a) a lock with quick unlock on keeps the quick-unlock record, its co-key and the digest; the copy goes", async () => {
  const { world, acct, w } = await enrolledWithAPage();
  await w.popup({ type: "lock" });
  await settle();
  assert.deepEqual(dump(world, acct), sorted([...TRUST, ...QUICK, "session:tabs"]));
});

test("(a) a lock with quick unlock off keeps only the digest beside the trust records", async () => {
  const { world, acct, w } = await enrolledWithAPage();
  await w.popup({ type: "disableQuickUnlock" });
  await w.popup({ type: "lock" });
  await settle();
  assert.deepEqual(dump(world, acct), sorted([...TRUST, "session:ns.<origin>.knownLogins", "session:tabs"]));
});

test("(b) a sign-out keeps the trust records and nothing of the session or of quick unlock", async () => {
  const { world, acct, w } = await enrolledWithAPage();
  await w.popup({ type: "signOut" });
  await settle();
  assert.deepEqual(dump(world, acct), sorted([...TRUST, "session:tabs"]));
});

test("(c) forget this server removes everything of that server, the remembered email with it: nothing names the account", async () => {
  const { world, acct, w } = await enrolledWithAPage();
  assert.equal((await w.popup({ type: "forgetServer" })).ok, true);
  await settle();
  assert.deepEqual(dump(world, acct), sorted(["idb:andvari-session-seal/kv:sealKey", "idb:andvari-trusted/kv:storeFormat", "session:tabs"]));
  assert.ok(dump(world, acct).every((k) => !k.includes("<email>") && !k.includes("<userId>") && !k.endsWith(" !")), "no key or value names the account");
  assert.equal((await w.popup({ type: "status" })).rememberedEmail, null, "the popup is not handed it either");
});

/** Holds the server's answer to the next login until `release()`; [answer] replaces it when given (a 401 totp_required). */
function holdLogin(server: { override: unknown; handle: (m: string, p: string, b: unknown, h: unknown) => Promise<Response> }, answer?: () => Response) {
  let hit = false;
  let open: () => void = () => {};
  const opened = new Promise<void>((r) => (open = r));
  server.override = (method: string, path: string, body: unknown, headers: unknown) => {
    if (method !== "POST" || path !== "/api/v1/auth/login" || hit) return null;
    hit = true;
    return opened.then(() => {
      if (answer) return answer();
      const o = server.override;
      server.override = null;
      const r = server.handle(method, path, body, headers);
      server.override = o;
      return r;
    });
  };
  return {
    async reached() {
      for (let i = 0; i < 400 && !hit; i++) await new Promise((r) => setTimeout(r, 5));
      assert.ok(hit, "the login is on the wire");
    },
    release: () => open(),
  };
}

for (const [label, answer] of [
  ["an account without two-step sign-in", undefined],
  ["an account with two-step sign-in", () => new Response(JSON.stringify({ error: "totp_required", message: "totp_required" }), { status: 401, headers: { "content-type": "application/json" } })],
] as const) {
  test(`a sign-in answered after "Forget this server" writes nothing that names the account (${label})`, async () => {
    const { world, server, acct, w } = await signedInWorld({ signIn: false });
    const login = holdLogin(server, answer);
    const signingIn = w.popup({ type: "unlock", email: acct.email, password: acct.password });
    await login.reached();
    assert.equal((await w.popup({ type: "forgetServer" })).ok, true);
    login.release();
    assert.deepEqual(await signingIn, { ok: false, code: "aborted" }, "the sign-in gives way to the forget");
    await settle();
    assert.deepEqual(
      dump(world, acct).filter((k) => k.includes("<email>") || k.includes("<userId>") || k.endsWith(" !")),
      [],
      "neither the device record nor the remembered address is back",
    );
    const st = await w.popup({ type: "status" });
    assert.equal(st.rememberedEmail, null);
    assert.equal(st.unlocked, false);
  });
}

test("(e) the server refuses this browser (the account deleted elsewhere): the quick-unlock record and the digest go at once; the copy at the lock", async () => {
  const { world, acct, w, server } = await enrolledWithAPage();
  const dead = () => new Response(JSON.stringify({ error: "unauthorized", message: "refused" }), { status: 401, headers: { "content-type": "application/json" } });
  server.override = (_m: string, path: string) => (path === "/api/v1/auth/refresh" || path.startsWith("/api/v1/sync") || path.startsWith("/api/v1/account") || path.startsWith("/api/v1/usage") ? dead() : null);
  await w.alarm("resync");
  await settle();
  assert.equal((await w.popup({ type: "status" })).serverEnded, true);
  // §4.4: the copy stays readable until the person locks; spec 01 §8.4: the digest goes with the quick-unlock material.
  assert.deepEqual(dump(world, acct), sorted([...TRUST, "session:session", "session:tabs"]));
  await w.popup({ type: "lock" });
  await settle();
  assert.deepEqual(dump(world, acct), sorted([...TRUST, "session:tabs"]));
});
