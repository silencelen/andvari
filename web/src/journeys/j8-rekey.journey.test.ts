import "fake-indexeddb/auto"; // the browser profile's IndexedDB, where the offline copy lives
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError } from "../api/client";
import { initSodium } from "../crypto/sodium";
import type { AccountKeysV2 } from "../api/wire";
import { adIdkey, adUvk, adVkPersonal } from "../crypto/ad";
import { fromB64, toB64 } from "../crypto/bytes";
import { seal } from "../crypto/envelope";
import { authKey as deriveAuthKey, masterKey, wrapKey } from "../crypto/keys";
import { boxKeypairFromSeed, randomBytes, signKeypairFromSeed } from "../crypto/provider";
import { signGenesis } from "../crypto/trust/genesis";
import { cachedAccountKeys, copyAtUnlock, enterVault, knownIdentity } from "../ui/opensession";
import { cachedPendingWraps } from "../ui/session";
import { openVaultCache } from "../vault/idbcache";
import { unlockSession } from "../vault/onboardflow";
import { changePassword, PROOF_REFUSED, setRequireLink } from "../vault/settingsflow";
import { SERVER_REFUSED_PROOF } from "../ui/copy";
import { passwordChangeText } from "../ui/reauthtext";
import type { SessionKeys } from "../vault/sessionwrap";
import { Browser } from "./browser";
import { journeysUnavailable, type SharePeerProcess, TestInstance } from "./harness";
import { HOOK } from "./wait";

/**
 * Journey 8: the quiet re-key after an unlock (spec 01 §7, "KDF upgrade (F61)"), against the real server. The operator
 * (the engine's own code, AssistPeer.java) raises the policy's password-hashing cost; the next full-password unlock in
 * the browser re-keys with the password it just verified (one `PUT /account/password`), the unlock after it sends no
 * such request, and a second browser profile of the same account is signed out once, by the server's rule for a password
 * change, and signs in again with the same password.
 *
 * The screens' own functions run: signIn (Welcome's sign-in), then enterVault with the password, as useEnter hands it in.
 */
const skip = journeysUnavailable();
if (skip) console.warn(skip);

const EMAIL = "erin@example.org";
const PASSWORD = "correct horse Battery 9 staple";
const OPERATOR_PASSWORD = "operator horse Battery 9 staple";
const DEFAULT = { v: 1, alg: "argon2id13", ops: 3, memBytes: 67_108_864 };

/** A Map-backed Web Storage, for the session record and the identity record enterVault keeps in localStorage. */
function webStorage(): Storage {
  const m = new Map<string, string>();
  return {
    get length() {
      return m.size;
    },
    clear: () => m.clear(),
    getItem: (k: string) => m.get(k) ?? null,
    key: (i: number) => [...m.keys()][i] ?? null,
    removeItem: (k: string) => void m.delete(k),
    setItem: (k: string, v: string) => void m.set(k, v),
  } as Storage;
}

/** Every request the browsers send while [run] runs, as `METHOD /path` (the harness's own requests do not go through fetch). */
async function requestsOf<T>(run: () => Promise<T>): Promise<{ value: T; sent: string[] }> {
  const sent: string[] = [];
  const real = globalThis.fetch;
  const spy = vi.spyOn(globalThis, "fetch").mockImplementation((input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url);
    sent.push(`${(init?.method ?? (input instanceof Request ? input.method : "GET")).toUpperCase()} ${url.pathname}`);
    return real(input, init);
  });
  try {
    return { value: await run(), sent };
  } finally {
    spy.mockRestore();
  }
}

/**
 * A proxy between the browser and the real server that lies about `PUT /account/password` (spec 01 §7, a re-key the
 * server lied about): `never_stored` answers "done" and never forwards it; `stored_refused` forwards it, the server
 * stores it, and the browser is told it was refused. Every request is recorded as in {@link requestsOf}.
 */
async function throughLyingProxy<T>(lie: "never_stored" | "stored_refused", run: () => Promise<T>): Promise<{ value: T; sent: string[]; lied: number }> {
  const sent: string[] = [];
  let lied = 0;
  const real = globalThis.fetch;
  const spy = vi.spyOn(globalThis, "fetch").mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url);
    const method = (init?.method ?? (input instanceof Request ? input.method : "GET")).toUpperCase();
    sent.push(`${method} ${url.pathname}`);
    if (method !== "PUT" || !url.pathname.endsWith("/account/password")) return real(input, init);
    lied++;
    if (lie === "never_stored") return new Response(null, { status: 204 });
    const stored = await real(input, init);
    if (!stored.ok) throw new Error(`the server did not store the change: ${stored.status}`);
    return new Response(JSON.stringify({ error: "reauth_failed", message: "refused" }), { status: 403, headers: { "content-type": "application/json" } });
  });
  try {
    return { value: await run(), sent, lied };
  } finally {
    spy.mockRestore();
  }
}

describe.skipIf(skip !== null)("journey 8: the quiet re-key after a full-password unlock", () => {
  let inst: TestInstance;
  let peer: SharePeerProcess;

  beforeAll(async () => {
    await initSodium();
    vi.stubGlobal("localStorage", webStorage());
    vi.stubGlobal("sessionStorage", webStorage());
    inst = await TestInstance.start({ kind: "public", mode: "open", enrolOperator: false, env: { ANDVARI_SIGNUP_POW_BITS: "10" } });
    peer = await inst.assistPeer("operator@example.org", OPERATOR_PASSWORD);
  }, HOOK.startWithPeer);

  afterAll(async () => {
    vi.unstubAllGlobals();
    await peer?.stop();
    await inst?.stop();
  }, HOOK.stop);

  beforeEach(() => inst.advance(61_000));

  it("the policy is raised; the next unlock re-keys; the unlock after it sends nothing; the other browser is signed out once and signs in again", async () => {
    const openCache = (userId: string) => openVaultCache(userId); // this browser keeps the offline copy
    const home = new Browser(inst, "Firefox at home");
    const signed = await home.signUp(EMAIL, PASSWORD, "Erin");
    expect(signed.session.accountKeys.kdfParams).toEqual(DEFAULT);
    // A sign-up is not an unlock: no password is handed in, nothing is looked at.
    const first = await enterVault(home.ctx, { opened: signed.opened, keys: signed.session.accountKeys, wrap: signed.wrap, email: EMAIL, pin: signed.pin, cardNotice: null, how: null }, openCache);
    expect(first.reKey).toBe("not_counted");
    first.store.close();

    // A second browser profile of the same account.
    const work = new Browser(inst, "Chrome at work");
    const there = await work.signIn(EMAIL, PASSWORD);
    expect(there.kind).toBe("opened");

    // The operator raises the policy's cost (one axis up, inside every bound).
    inst.advance(61_000);
    expect(await peer.cmd("policy 4 67108864")).toEqual({ policy: "done", ops: 4, memBytes: 67_108_864 });
    expect((await home.wire.clientPolicy()).kdfParams).toEqual({ ...DEFAULT, ops: 4 });

    // The next full-password unlock at home re-keys, inline, with the password it just verified.
    const changedBefore = inst.mailCount(EMAIL, "password_changed");
    const again = await home.signIn(EMAIL, PASSWORD);
    if (again.kind !== "opened") throw new Error(again.kind);
    expect(again.session.accountKeys.kdfParams).toEqual(DEFAULT);
    const u1 = await requestsOf(() =>
      enterVault(home.ctx, { opened: again.opened, keys: again.session.accountKeys, wrap: again.wrap, email: EMAIL, pin: again.pin, cardNotice: null, how: null, password: PASSWORD }, openCache),
    );
    expect(u1.value.reKey).toBe("rekeyed");
    expect(u1.sent.filter((r) => r.endsWith("/account/password"))).toEqual(["PUT /api/v1/account/password"]);
    expect(u1.sent).toContain("GET /api/v1/client-policy");
    // No prelogin and no read of the account's keys for the proof: it was made on this device.
    expect(u1.sent.filter((r) => r.includes("prelogin") || r.endsWith("/account/keys"))).toEqual([]);
    const served = await home.wire.accountKeys();
    expect(served.kdfParams).toEqual({ ...DEFAULT, ops: 4 });
    expect(served.kdfSalt).not.toBe(again.session.accountKeys.kdfSalt);
    // The session and the offline copy hold exactly the wrap that was sent.
    expect(u1.value.meta.settings.wrap.current).toMatchObject({ kdfSalt: served.kdfSalt, kdfParams: served.kdfParams, wrappedUvk: served.wrappedUvk });
    expect(await cachedAccountKeys(signed.session.userId, openCache)).toMatchObject({ kdfSalt: served.kdfSalt, kdfParams: served.kdfParams });
    await inst.awaitMail(EMAIL, "password_changed", changedBefore);
    u1.value.store.close();

    // The unlock after it: the cost is the policy's, so nothing is re-keyed and no change is sent.
    inst.advance(61_000);
    const third = await home.signIn(EMAIL, PASSWORD);
    if (third.kind !== "opened") throw new Error(third.kind);
    const u2 = await requestsOf(() =>
      enterVault(home.ctx, { opened: third.opened, keys: third.session.accountKeys, wrap: third.wrap, email: EMAIL, pin: third.pin, cardNotice: null, how: null, password: PASSWORD }, openCache),
    );
    expect(u2.value.reKey).toBe("not_due");
    expect(u2.sent.filter((r) => r.endsWith("/account/password"))).toEqual([]);
    u2.value.store.close();

    // The browser at work was signed out by the change, once; it signs in again with the same password.
    await expect(work.wire.accountKeys()).rejects.toBeInstanceOf(ApiError);
    inst.advance(61_000);
    const back = await work.signIn(EMAIL, PASSWORD);
    if (back.kind !== "opened") throw new Error(back.kind);
    expect(back.session.accountKeys.kdfParams).toEqual({ ...DEFAULT, ops: 4 });
    const u3 = await requestsOf(() =>
      enterVault(work.ctx, { opened: back.opened, keys: back.session.accountKeys, wrap: back.wrap, email: EMAIL, pin: back.pin, cardNotice: null, how: null, password: PASSWORD }, openCache),
    );
    expect(u3.value.reKey).toBe("not_due");
    expect(u3.sent.filter((r) => r.endsWith("/account/password"))).toEqual([]);
    // Home's session was not ended by the work browser's unlock: one sign-out, not a second.
    expect((await home.wire.accountKeys()).kdfSalt).toBe(served.kdfSalt);
    u3.value.store.close();
  }, 600_000);

  it("a re-key the server lied about (a “done” never stored, a refusal of one it stored) is settled at the next unlock, which takes the server's wrap only because it opens to the same account key", async () => {
    const EMAIL2 = "fern@example.org";
    const openCache = (userId: string) => openVaultCache(userId);
    const home = new Browser(inst, "Firefox at home");
    const p0 = (await home.wire.clientPolicy()).kdfParams;
    const signed = await home.signUp(EMAIL2, PASSWORD, "Fern");
    const userId = signed.session.userId;
    const first = await enterVault(home.ctx, { opened: signed.opened, keys: signed.session.accountKeys, wrap: signed.wrap, email: EMAIL2, pin: signed.pin, cardNotice: null, how: null }, openCache);
    first.store.close();
    // The unlock card's own unlock of the session this browser holds, with what this browser knows of the wrap.
    const unlockHere = async () => {
      const copy = await cachedAccountKeys(userId, openCache);
      if (copy === null) throw new Error("no offline copy");
      const pending = await cachedPendingWraps(userId, openCache);
      const { value, sent } = await requestsOf(() =>
        unlockSession({ wire: home.wire, pins: home.pins, origin: home.origin, userId, password: PASSWORD, knownIdentityPub: knownIdentity(EMAIL2)(userId), copy: { kind: "copy", keys: copy, pending } }),
      );
      if (value.kind !== "opened") throw new Error(`the unlock did not open: ${value.kind}`);
      return { r: value, sent };
    };
    const enter = (r: Extract<Awaited<ReturnType<typeof unlockSession>>, { kind: "opened" }>) =>
      enterVault(home.ctx, { opened: r.opened, keys: r.keys, wrap: r.wrap, email: EMAIL2, pin: r.pin, cardNotice: null, how: null, password: PASSWORD }, openCache);

    // 1. The policy is raised; the quiet re-key's change is answered "done" and never reaches the server.
    inst.advance(61_000);
    expect((await peer.cmd(`policy ${p0.ops + 1} ${p0.memBytes}`)).policy).toBe("done");
    const u0 = await unlockHere();
    const lie1 = await throughLyingProxy("never_stored", () => enter(u0.r));
    expect(lie1.lied).toBe(1);
    expect(lie1.value.reKey).toBe("rekeyed"); // what the browser was told
    expect((await home.wire.accountKeys()).kdfParams).toEqual(p0); // what the server holds
    expect((await cachedAccountKeys(userId, openCache))?.kdfParams).toEqual({ ...p0, ops: p0.ops + 1 }); // what the copy holds
    // What the lie does inside this session: its proofs are derived under a salt the server does not hold, and refused;
    // the proof was made here, so the refusal is the server's, never a wrong password.
    expect(await setRequireLink(lie1.value.meta.settings, false, PASSWORD)).toEqual({ kind: "refused", code: PROOF_REFUSED });
    expect(passwordChangeText({ kind: "refused", code: PROOF_REFUSED })).toBe(SERVER_REFUSED_PROOF);
    lie1.value.store.close();

    // The next unlock: the served wrap is neither the copy's nor a pending one; it opens to the same key, so it is taken,
    // with nothing sent but the read of the keys. The re-key then runs for real.
    inst.advance(61_000);
    const u1 = await unlockHere();
    const servedOld = await home.wire.accountKeys();
    expect(u1.r.wrap).toMatchObject({ kdfSalt: servedOld.kdfSalt, kdfParams: p0 });
    expect(u1.sent.filter((r) => !r.endsWith("/account/keys") && !r.includes("/instance"))).toEqual([]);
    const real1 = await requestsOf(() => enter(u1.r));
    expect(real1.value.reKey).toBe("rekeyed");
    expect(real1.sent.filter((r) => r.endsWith("/account/password"))).toEqual(["PUT /api/v1/account/password"]);
    expect((await home.wire.accountKeys()).kdfParams).toEqual({ ...p0, ops: p0.ops + 1 });
    real1.value.store.close();

    // 2. Raised again; this time the server stores the change and the browser is told it was refused.
    inst.advance(61_000);
    expect((await peer.cmd(`policy ${p0.ops + 2} ${p0.memBytes}`)).policy).toBe("done");
    const u2 = await unlockHere();
    const lie2 = await throughLyingProxy("stored_refused", () => enter(u2.r));
    expect(lie2.lied).toBe(1);
    expect(lie2.value.reKey).toBe("failed");
    const servedNew = await home.wire.accountKeys();
    expect(servedNew.kdfParams).toEqual({ ...p0, ops: p0.ops + 2 });
    expect((await cachedAccountKeys(userId, openCache))?.kdfParams).toEqual({ ...p0, ops: p0.ops + 1 });
    expect(await cachedPendingWraps(userId, openCache)).toEqual([]);
    lie2.value.store.close();

    // The next unlock takes the server's new wrap (the same key under it), and nothing is re-keyed or sent.
    const u3 = await unlockHere();
    expect(u3.r.wrap).toMatchObject({ kdfSalt: servedNew.kdfSalt, kdfParams: servedNew.kdfParams });
    const after = await requestsOf(() => enter(u3.r));
    expect(after.value.reKey).toBe("not_due");
    expect(after.sent.filter((r) => r.endsWith("/account/password"))).toEqual([]);
    expect((await cachedAccountKeys(userId, openCache))?.kdfSalt).toBe(servedNew.kdfSalt);
    // And the session's proofs are derived under the server's own salt now: a proof the server checks goes through.
    expect(after.value.meta.settings.wrap.current?.kdfSalt).toBe(servedNew.kdfSalt);
    inst.advance(61_000);
    expect((await setRequireLink(after.value.meta.settings, false, PASSWORD)).kind).toBe("done");
    after.value.store.close();
  }, 600_000);

  it("keys this browser does not know: the copy's own wrap opens the vault from the copy and nothing served is taken; with nothing here to compare, nothing is taken and the sign-in settles it", async () => {
    const EMAIL3 = "gale@example.org";
    const NEW_PASSWORD = "a brand new Password 7 here";
    const openCache = (userId: string) => openVaultCache(userId);
    const home = new Browser(inst, "Firefox at home");
    const signed = await home.signUp(EMAIL3, PASSWORD, "Gale");
    const userId = signed.session.userId;
    const uvk = signed.opened.uvk.slice();
    const first = await enterVault(home.ctx, { opened: signed.opened, keys: signed.session.accountKeys, wrap: signed.wrap, email: EMAIL3, pin: signed.pin, cardNotice: null, how: null }, openCache);
    first.store.close();
    const original = await cachedAccountKeys(userId, openCache);
    if (original === null) throw new Error("no offline copy");
    const unlockHere = async (password: string) =>
      unlockSession({ wire: home.wire, pins: home.pins, origin: home.origin, userId, password, knownIdentityPub: knownIdentity(EMAIL3)(userId), copy: await copyAtUnlock(userId, openCache, () => true) });

    // 1. "Leaves both": a proxy serves a wrap of this account's key under another password. The copy's own wrap opens.
    const elsewhere = await wrapUnder(userId, uvk, "another password entirely 1");
    const lb = await servingKeys(elsewhere, () => unlockHere(PASSWORD));
    expect(lb.value.kind).toBe("opened_from_copy");
    if (lb.value.kind !== "opened_from_copy") throw new Error(lb.value.kind);
    expect(lb.value.cause).toBe("not_open");
    expect(lb.sent.filter((r) => !r.endsWith("/account/keys") && !r.includes("/instance"))).toEqual([]);
    const v = lb.value;
    const opened = await requestsOf(() => enterVault(home.ctx, { opened: v.opened, keys: v.keys, wrap: v.wrap, pendingWraps: v.pending, email: EMAIL3, pin: v.pin, cardNotice: null, how: null, serverKeysNotKnown: true }, openCache));
    expect(opened.value.reKey).toBe("not_counted");
    expect(opened.value.meta.settings.wrap.serverKeysNotKnown).toBe(true);
    expect(opened.sent.filter((r) => r.endsWith("/account/password"))).toEqual([]);
    expect(await cachedAccountKeys(userId, openCache)).toEqual(original); // the copy is left exactly as it was
    opened.value.store.close();

    // 2. This browser's own password change whose write to the copy failed: the server holds the new wrap, the copy the old.
    inst.advance(61_000);
    const back = await unlockHere(PASSWORD);
    if (back.kind !== "opened") throw new Error(back.kind);
    const session = await enterVault(home.ctx, { opened: back.opened, keys: back.keys, wrap: back.wrap, email: EMAIL3, pin: back.pin, cardNotice: null, how: null }, openCache);
    const policyCost = (await home.wire.clientPolicy()).kdfParams;
    expect((await changePassword({ ...session.meta.settings, copy: undefined }, PASSWORD, NEW_PASSWORD, policyCost)).kind).toBe("done");
    session.store.close();
    const stale = await cachedAccountKeys(userId, openCache);
    expect(stale?.kdfSalt).toBe(original.kdfSalt);
    // The new password opens the served wrap and not the copy's: nothing here to compare with, so nothing is taken.
    inst.advance(61_000);
    expect(await unlockHere(NEW_PASSWORD)).toEqual({ kind: "keys_differ", reason: "served_only" });
    expect(await cachedAccountKeys(userId, openCache)).toEqual(stale);
    // The sign-in the unlock card offers settles it: the copy takes the signed-in keys, and the next unlock opens.
    inst.advance(61_000);
    const fresh = await home.signIn(EMAIL3, NEW_PASSWORD);
    if (fresh.kind !== "opened") throw new Error(fresh.kind);
    const entered = await enterVault(home.ctx, { opened: fresh.opened, keys: fresh.session.accountKeys, wrap: fresh.wrap, email: EMAIL3, pin: fresh.pin, cardNotice: null, how: null }, openCache);
    entered.store.close();
    const served = await home.wire.accountKeys();
    expect((await cachedAccountKeys(userId, openCache))?.kdfSalt).toBe(served.kdfSalt);
    expect((await unlockHere(NEW_PASSWORD)).kind).toBe("opened");

    // 3. The server keeps the older password's wrap of the same key and serves it; the older password is typed: not taken.
    const older = await servingKeys({ kdfSalt: original.kdfSalt, kdfParams: original.kdfParams, wrappedUvk: original.wrappedUvk }, () => unlockHere(PASSWORD));
    expect(older.value).toEqual({ kind: "keys_differ", reason: "served_only" });
    expect((await cachedAccountKeys(userId, openCache))?.kdfSalt).toBe(served.kdfSalt);
    // And without the proxy the older password is what it is here now: a wrong password.
    expect((await unlockHere(PASSWORD)).kind).toBe("wrong_password");

    // 4. The sign-in over this copy compares before it writes. A server that kept the older wrap answers the older
    // password's sign-in with it: the same account key, so the copy takes it, and the vault says that it was sealed under
    // another master password and now follows the server's.
    const heldCopy = (id: string) => copyAtUnlock(id, openCache, () => true);
    const realAuth = await authKeyUnder(NEW_PASSWORD, served);
    inst.advance(61_000);
    const kept = await lyingSignIn({ kdfSalt: original.kdfSalt, kdfParams: original.kdfParams, wrappedUvk: original.wrappedUvk }, realAuth, () => home.signIn(EMAIL3, PASSWORD, undefined, heldCopy));
    if (kept.value.kind !== "opened") throw new Error(kept.value.kind);
    expect(kept.value.copySealedElsewhere).toBe(true);
    const k = kept.value;
    const withLine = await enterVault(home.ctx, { opened: k.opened, keys: k.session.accountKeys, wrap: k.wrap, email: EMAIL3, pin: k.pin, cardNotice: null, how: null, copySealedElsewhere: true }, openCache);
    expect(withLine.meta.copySealedElsewhere).toBe(true);
    withLine.store.close();
    const followed = await cachedAccountKeys(userId, openCache);
    expect({ kdfSalt: followed?.kdfSalt, kdfParams: followed?.kdfParams, wrappedUvk: followed?.wrappedUvk }).toEqual({ kdfSalt: original.kdfSalt, kdfParams: original.kdfParams, wrappedUvk: original.wrappedUvk });
    expect(await cachedPendingWraps(userId, openCache)).toEqual([]);

    // The honest road back: the new password, at the real server (changed "on another device" as this copy sees it).
    inst.advance(61_000);
    const honest = await home.signIn(EMAIL3, NEW_PASSWORD, undefined, heldCopy);
    if (honest.kind !== "opened") throw new Error(honest.kind);
    expect(honest.copySealedElsewhere).toBe(true);
    const h = honest;
    const back2 = await enterVault(home.ctx, { opened: h.opened, keys: h.session.accountKeys, wrap: h.wrap, email: EMAIL3, pin: h.pin, cardNotice: null, how: null, copySealedElsewhere: true }, openCache);
    back2.store.close();
    expect((await cachedAccountKeys(userId, openCache))?.kdfSalt).toBe(served.kdfSalt);
    // A next sign-in with the same password: the copy knows it now, so no line.
    inst.advance(61_000);
    const again2 = await home.signIn(EMAIL3, NEW_PASSWORD, undefined, heldCopy);
    expect(again2.kind === "opened" && again2.copySealedElsewhere).toBeUndefined();

    // A server that serves another key for the same address: refused, the copy and its waiting wraps byte for byte as before.
    const waiting = await wrapUnder(userId, uvk, "a change still waiting 3");
    const cache = await openCache(userId);
    await cache.setPendingWraps([waiting]);
    cache.close();
    const beforeKeys = await cachedAccountKeys(userId, openCache);
    const beforePending = await cachedPendingWraps(userId, openCache);
    const other = await anotherKeySet(userId, home.pins.pinFor(home.origin)!.instanceId, NEW_PASSWORD);
    inst.advance(61_000);
    const refused = await lyingSignIn(other, realAuth, () => home.signIn(EMAIL3, NEW_PASSWORD, undefined, heldCopy));
    expect(refused.value).toEqual({ kind: "keys_not_this_account" });
    expect(refused.sent.filter((r) => !r.includes("/instance")).map((r) => r.replace(/ .*\/auth\//, " auth/"))).toEqual(["POST auth/prelogin", "POST auth/login"]);
    expect(await cachedAccountKeys(userId, openCache)).toEqual(beforeKeys);
    expect(await cachedPendingWraps(userId, openCache)).toEqual(beforePending);
  }, 600_000);
});

/** The auth key [password] gives under [keys]' salt and cost: what the real server checks at a login. */
async function authKeyUnder(password: string, keys: Pick<SessionKeys, "kdfSalt" | "kdfParams">): Promise<string> {
  const mk = masterKey(password, fromB64(keys.kdfSalt), keys.kdfParams);
  try {
    const ak = await deriveAuthKey(mk);
    try {
      return toB64(ak);
    } finally {
      ak.fill(0);
    }
  } finally {
    mk.fill(0);
  }
}

/**
 * A server that kept other keys than it holds, at a sign-in: the first exchange names [served]'s salt and cost; the login
 * is passed on to the real server with [realAuth] in place of what the browser derived (the lie accepts that password), and
 * its answer carries [served] (a wrap, or a whole key set) in place of the account's keys.
 */
async function lyingSignIn<T>(served: SessionKeys & Partial<AccountKeysV2>, realAuth: string, run: () => Promise<T>): Promise<{ value: T; sent: string[] }> {
  const sent: string[] = [];
  const real = globalThis.fetch;
  const spy = vi.spyOn(globalThis, "fetch").mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url);
    const method = (init?.method ?? (input instanceof Request ? input.method : "GET")).toUpperCase();
    sent.push(`${method} ${url.pathname}`);
    if (method === "POST" && url.pathname.endsWith("/auth/prelogin")) {
      return new Response(JSON.stringify({ kdfSalt: served.kdfSalt, kdfParams: served.kdfParams }), { status: 200, headers: { "content-type": "application/json" } });
    }
    if (method === "POST" && url.pathname.endsWith("/auth/login")) {
      const body = { ...JSON.parse(String(init?.body)), authKey: realAuth };
      const res = await real(input, { ...init, body: JSON.stringify(body) });
      if (!res.ok) return res;
      const answer = await res.json();
      return new Response(JSON.stringify({ ...answer, accountKeys: { ...answer.accountKeys, ...served } }), { status: 200, headers: { "content-type": "application/json" } });
    }
    return real(input, init);
  });
  try {
    return { value: await run(), sent };
  } finally {
    spy.mockRestore();
  }
}

/** A whole key set of another account key for [userId], as a server could make one (a fresh key, seed and genesis). */
async function anotherKeySet(userId: string, instanceId: string, password: string): Promise<AccountKeysV2> {
  const uvk = randomBytes(32);
  const seed = randomBytes(32);
  const vk = randomBytes(32);
  const identity = boxKeypairFromSeed(seed);
  const signing = signKeypairFromSeed(seed);
  const personalVaultId = "e0000000-0000-4000-8000-000000000001";
  const genesis = signGenesis(signing, { userId, identityKey: toB64(identity.publicKey), instanceId, personalVaultId, createdAt: Date.now() });
  const wrap = await wrapUnder(userId, uvk, password);
  return {
    ...wrap,
    encryptedIdentitySeed: toB64(seal(uvk, seed, adIdkey(userId))),
    identityPub: toB64(identity.publicKey),
    recoveryConfirmed: true,
    personalWrap: { vaultId: personalVaultId, wrappedVk: toB64(seal(uvk, vk, adVkPersonal(personalVaultId, userId))) },
    genesis: toB64(genesis),
  };
}

/** A wrap of [uvk] under [password], a fresh salt and the default cost: what another password's change would seal. */
async function wrapUnder(userId: string, uvk: Uint8Array, password: string): Promise<SessionKeys> {
  const salt = randomBytes(16);
  const mk = masterKey(password, salt, DEFAULT);
  const wk = await wrapKey(mk);
  mk.fill(0);
  try {
    return { kdfSalt: toB64(salt), kdfParams: DEFAULT, wrappedUvk: toB64(seal(wk, uvk, adUvk(userId))) };
  } finally {
    wk.fill(0);
  }
}

/** A proxy that answers `GET /account/keys` with the real server's keys, the wrap part replaced by [wrap]. */
async function servingKeys<T>(wrap: SessionKeys, run: () => Promise<T>): Promise<{ value: T; sent: string[] }> {
  const sent: string[] = [];
  const real = globalThis.fetch;
  const spy = vi.spyOn(globalThis, "fetch").mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url);
    const method = (init?.method ?? (input instanceof Request ? input.method : "GET")).toUpperCase();
    sent.push(`${method} ${url.pathname}`);
    const res = await real(input, init);
    if (method !== "GET" || !url.pathname.endsWith("/account/keys") || !res.ok) return res;
    const body = { ...(await res.json()), kdfSalt: wrap.kdfSalt, kdfParams: wrap.kdfParams, wrappedUvk: wrap.wrappedUvk };
    return new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
  });
  try {
    return { value: await run(), sent };
  } finally {
    spy.mockRestore();
  }
}
