// node --test. A password sign-in names the session it replaces (spec 03 §2 `replacesRefreshToken`): the refresh token
// of the pair a lock stashed on this server for quick unlock, only for the same account and only from a known device
// row. The real background.ts, driven through testing/bgharness.ts.
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { signedInWorld, type World } from "./testing/bgharness.ts";

const PIN = "Tq7#kw2pZ";

/** The bodies of every login the worker sent, in order. */
function logins(world: World): { email: string; device: { deviceId?: string }; replacesRefreshToken?: string }[] {
  return world.log.filter((l: { method: string; path: string }) => l.method === "POST" && l.path === "/api/v1/auth/login").map((l: { body: never }) => l.body);
}

test("a password sign-in from the locked-armed screen names the session the lock stashed, from the known device row", async () => {
  const { world, w, acct } = await signedInWorld();
  assert.equal(logins(world)[0]!.replacesRefreshToken, undefined, "a first sign-in names nothing");
  assert.equal((await w.popup({ type: "enrollQuickUnlock", pin: PIN })).ok, true);
  await w.popup({ type: "lock" });
  assert.equal((await w.popup({ type: "status" })).quickUnlock.armed, true, "the lock stashed the session's pair");
  // The person types the master password instead of the PIN.
  assert.equal((await w.popup({ type: "unlock", email: acct.email, password: acct.password })).ok, true);
  const second = logins(world)[1]!;
  // On the code before: no name.
  assert.equal(second.replacesRefreshToken, `rt-${acct.userId}`);
  assert.equal(typeof second.device.deviceId, "string", "from the row the first sign-in made");
});

test("nothing is named after a lock that stashed nothing, nor for another account's sign-in", async () => {
  const { world, server, w, acct } = await signedInWorld();
  // A plain lock (no quick unlock): no pair is kept here, so none is named.
  await w.popup({ type: "lock" });
  assert.equal((await w.popup({ type: "unlock", email: acct.email, password: acct.password })).ok, true);
  assert.equal(logins(world)[1]!.replacesRefreshToken, undefined);
  // Locked-armed for alice; bob signs in: alice's session is not his to name.
  const bob = server.addAccount({ email: "bob@example.com", password: "bob horse" });
  assert.equal((await w.popup({ type: "enrollQuickUnlock", pin: PIN })).ok, true);
  await w.popup({ type: "lock" });
  assert.equal((await w.popup({ type: "unlock", email: bob.email, password: bob.password })).ok, true);
  const last = logins(world).at(-1)!;
  assert.equal(last.email, bob.email);
  assert.equal(last.replacesRefreshToken, undefined);
});

test("the second step of a two-step sign-in names what its first step named", () => {
  const bg = readFileSync(new URL("./background.ts", import.meta.url), "utf8");
  assert.ok(bg.includes("pendingTotp = { origin: serverUrl, email, authKey: ak, wrapKey: wk, device, replaces, expiresAt"), "the challenge keeps the name");
  assert.ok(bg.includes("api.login(p.email, toB64(p.authKey), deviceObject(p.device.rec), code, p.replaces)"), "the code's login sends it");
  const api = readFileSync(new URL("./api.ts", import.meta.url), "utf8");
  assert.ok(api.includes("...(replaces && device.deviceId !== undefined ? { replacesRefreshToken: replaces } : {})"), "only from a known row");
});

/** Every request refused for its access token, and every refresh answered by a gateway's page (no answer of the
 *  server's), until the session ends here as not confirmed and its token is kept for the next sign-in's name. */
async function endUnconfirmed(server: { override: unknown }, w: { alarm(n: string): Promise<void>; popup(m: unknown): Promise<any> }) {
  server.override = (_m: string, path: string) =>
    path === "/api/v1/auth/refresh"
      ? new Response("<html>502 Bad Gateway</html>", { status: 502 })
      : path.startsWith("/api/v1/sync")
        ? new Response(JSON.stringify({ error: "unauthorized", message: "expired" }), { status: 401, headers: { "content-type": "application/json" } })
        : null;
  for (let i = 0; i < 6 && (await w.popup({ type: "status" })).serverEndedUnconfirmed !== true; i++) await w.alarm("resync");
  assert.equal((await w.popup({ type: "status" })).serverEndedUnconfirmed, true);
  server.override = null;
}

test("a person's own sign-out removes that account's kept token, and says the end of the session was not confirmed", async () => {
  const { world, server, w, acct } = await signedInWorld();
  await endUnconfirmed(server, w);
  const out = await w.popup({ type: "signOut" });
  assert.deepEqual(out, { ok: true, notice: "session_not_confirmed" });
  assert.equal((await w.popup({ type: "unlock", email: acct.email, password: acct.password })).ok, true);
  assert.equal(logins(world).at(-1)!.replacesRefreshToken, undefined, "nothing of that session stayed to be named");
});

test("another account's sign-in and sign-out leave an account's kept token for that account's next sign-in", async () => {
  const { world, server, w, acct } = await signedInWorld();
  const bob = server.addAccount({ email: "bob@example.com", password: "bob horse" });
  await endUnconfirmed(server, w);
  await w.popup({ type: "lock" });
  assert.equal((await w.popup({ type: "unlock", email: bob.email, password: bob.password })).ok, true);
  assert.deepEqual(await w.popup({ type: "signOut" }), { ok: true }, "bob's sign-out says nothing of alice's session");
  assert.equal((await w.popup({ type: "unlock", email: acct.email, password: acct.password })).ok, true);
  assert.equal(logins(world).at(-1)!.replacesRefreshToken, `rt-${acct.userId}`, "alice's sign-in names her kept token");
});
