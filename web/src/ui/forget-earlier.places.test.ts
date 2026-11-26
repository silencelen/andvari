import "fake-indexeddb/auto";
import { readFileSync } from "node:fs";
import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { DEVICE_KEY, DeviceIdentity } from "../api/devicesecret";
import { toB64 } from "../crypto/bytes";
import { initSodium } from "../crypto/sodium";
import { kitDisplayForm } from "../crypto/trust/recoverykit";
import { IdentityMismatchError, type Account } from "../vault/account";
import { openVaultCache, readWaiting } from "../vault/idbcache";
import { parseKitInput, verifyKit } from "../vault/kitflow";
import { completeSignup, signIn } from "../vault/onboardflow";
import type { PinStore } from "../vault/pinstore";
import { boundAccountAt, loadSelfIdentityPub, recordSelfIdentityPub } from "../vault/selfidentity";
import { knownIdentity } from "./opensession";
import { browserStorages, KDF, ORIGIN, pinnedStore, RemakeServer } from "./forget-earlier.testkit";
import { clearSession, isAccountScopedKey, saveSession, SESSION_STORAGE_KEY, wipeVaultCache } from "./session";

/**
 * Where this browser refuses because an address is known here under another account or key, and what it keeps under an
 * account's id and under an address (the groundwork of "Forget the earlier account on this device", decided on
 * 2026-11-17). Each test states a fact of the code as it stands.
 */
const EMAIL = "alice@example.com";
const PASSWORD = "alice correct horse 1";
const src = (f: string) => readFileSync(new URL(f, import.meta.url), "utf8");
const asAccount = (pub: Uint8Array) => ({ identityPub: pub }) as unknown as Account;

describe("where the browser refuses an address it knows under another account", () => {
  let st: ReturnType<typeof browserStorages>;
  let pins: PinStore;
  let server: RemakeServer;
  beforeAll(async () => {
    await initSodium();
  });
  beforeEach(async () => {
    st = browserStorages();
    pins = await pinnedStore();
    server = new RemakeServer();
  });
  afterEach(() => st.restore());

  /** The account alice had, signed in here once (its records written as enterVault writes them), then remade at the server. */
  async function knownThenRemade() {
    const first = await server.remake(pins, EMAIL, PASSWORD);
    recordSelfIdentityPub(first.userId, asAccount(first.identityPub), EMAIL);
    const again = await server.remake(pins, EMAIL, PASSWORD);
    return { first, again };
  }

  it("the record: the address is bound to the first account's id and key, a later one is never written over it, and both kinds of fault throw the same type", async () => {
    const { first, again } = await knownThenRemade();
    expect(st.local.map.get("andvari.selfIdentityByEmail.alice@example.com")).toBe(`${first.userId}\n${toB64(first.identityPub)}`);
    expect(st.local.map.get(`andvari.selfIdentityPub.${first.userId}`)).toBe(toB64(first.identityPub));
    recordSelfIdentityPub(again.userId, asAccount(again.identityPub), EMAIL);
    expect(st.local.map.get("andvari.selfIdentityByEmail.alice@example.com")).toBe(`${first.userId}\n${toB64(first.identityPub)}`);
    expect(() => loadSelfIdentityPub(again.userId, EMAIL)).toThrow(IdentityMismatchError);
    // A record that disagrees with itself (the id-keyed pin against the address's record) throws the very same type.
    st.local.map.set(`andvari.selfIdentityPub.${first.userId}`, toB64(again.identityPub));
    expect(() => loadSelfIdentityPub(first.userId, EMAIL)).toThrow(IdentityMismatchError);
  });

  it("a sign-in: the account served under the known address is refused as self_identity_mismatch, after the server took the sign-in", async () => {
    const { again } = await knownThenRemade();
    const r = await signIn({ wire: server, pins, origin: ORIGIN, email: EMAIL, password: PASSWORD, deviceName: "x", session: null, knownIdentityPub: knownIdentity(EMAIL) });
    expect(r).toEqual({ kind: "identity_fault", reason: "self_identity_mismatch", servedUserId: again.userId });
    expect(server.sent).toEqual(["prelogin", "login"]);
  }, 60_000);

  it("an unlock of a kept session: the lookup by the session's own id throws when the address names another account", async () => {
    const { first, again } = await knownThenRemade();
    expect(() => knownIdentity(EMAIL)(again.userId)).toThrow(IdentityMismatchError);
    expect(knownIdentity(EMAIL)(first.userId)).toEqual(first.identityPub);
    const welcome = src("./Welcome.tsx");
    expect(welcome).toContain("known = knownIdentity(session.email)(session.userId);");
    expect(welcome).toContain("known = knownIdentity(held.session.email)(held.session.userId);");
  }, 60_000);

  it("a registration under a known address is refused before anything is derived or sent, on this browser's own record", async () => {
    const { first } = await knownThenRemade();
    server.sent = [];
    const r = await completeSignup({ wire: server, pins, origin: ORIGIN, pin: pins.pinFor(ORIGIN)!, policy: { kdfParams: KDF } as never, email: EMAIL, displayName: "A", password: PASSWORD, signupTicket: "ticket", ageConfirmed: true, deviceName: "x", nowMs: 1763164800000, boundHere: boundAccountAt });
    expect(r).toEqual({ kind: "identity_fault", reason: "self_identity_mismatch" });
    expect(server.sent).toEqual([]);
    expect(st.local.map.get("andvari.selfIdentityByEmail.alice@example.com")!.startsWith(first.userId)).toBe(true);
    expect(src("./Welcome.tsx")).toContain("boundHere: boundAccountAt,");
  }, 60_000);

  it("a recovery with the kit: this browser's own record is a reason of its own, apart from a served key that is not the seed's", async () => {
    const { again } = await knownThenRemade();
    const kit = () => {
      const k = parseKitInput(kitDisplayForm(again.recoverySecret), EMAIL);
      if (k.kind !== "typed") throw new Error("parse");
      return k;
    };
    const other = new Uint8Array(32).fill(7);
    expect(await verifyKit({ wire: server, pins, origin: ORIGIN, input: kit(), knownIdentityPub: () => other })).toEqual({ kind: "identity_fault", reason: "self_identity_mismatch", servedUserId: again.userId });
    expect(await verifyKit({ wire: server, pins, origin: ORIGIN, input: kit(), knownIdentityPub: (u, em) => knownIdentity(em)(u) })).toEqual({ kind: "identity_fault", reason: "self_identity_mismatch", servedUserId: again.userId });
    const a = server.accounts.get(EMAIL)!;
    a.req = { ...a.req, identityPub: toB64(other) };
    expect(await verifyKit({ wire: server, pins, origin: ORIGIN, input: kit(), knownIdentityPub: () => null })).toEqual({ kind: "identity_fault", reason: "identity_pub_mismatch" });
  }, 60_000);

  it("the operator's help and a device link: the web makes no request for help and takes part in no link", () => {
    const wire = src("../api/wireclient.ts");
    expect(wire).not.toContain("/device-links");
    expect(wire).not.toContain('"/links');
    const requests = [...wire.matchAll(/\/recovery\/requests[^"`]*/g)].map((m) => m[0]);
    expect(requests).toEqual(["/recovery/requests/${pathSeg(requestId)}/veto"]);
  });
});

describe("what the browser keeps under an account's id and under an address", () => {
  let st: ReturnType<typeof browserStorages>;
  beforeEach(() => {
    st = browserStorages();
  });
  afterEach(() => st.restore());
  const A = "11111111-1111-4111-8111-111111111111";

  it("a sign-out removes the session and the copy, and keeps the address's record, the id-keyed pin and every key scoped to the id", async () => {
    const kept = [`andvari.cs.${A}.accountState.seq`, `andvari.log2.${A}.pending-index`, `andvari.current.${A}`, `andvari.onetap.${A}`, `andvari.how.${A}`, `andvari.recmirror.${A}`, `andvari.escrowfp.${A}`, `andvari.cacheOptIn.${A}`, `andvari.selfIdentityPub.${A}`];
    for (const k of kept) st.local.setItem(k, "x");
    st.local.setItem("andvari.selfIdentityByEmail.alice@example.com", `${A}\nAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA`);
    new DeviceIdentity().remember(EMAIL, A, "d0000000-0000-4000-8000-000000000001");
    saveSession({ baseUrl: "", userId: A, personalVaultId: "", email: EMAIL, tokens: null });
    const c = await openVaultCache(A);
    c.close();
    // The sign-out's own removals (App.signOut): the session record, then the copy.
    clearSession();
    await wipeVaultCache(A);
    expect(st.local.getItem(SESSION_STORAGE_KEY)).toBeNull();
    expect((await readWaiting(A)).kind).toBe("none");
    for (const k of kept) {
      expect(st.local.getItem(k), k).toBe("x");
      expect(isAccountScopedKey(k, A), k).toBe(true);
    }
    expect(st.local.getItem("andvari.selfIdentityByEmail.alice@example.com")).not.toBeNull();
    expect(isAccountScopedKey("andvari.selfIdentityByEmail.alice@example.com", A)).toBe(false);
    // The device record names the account by its id and by a hash of the address, under one key for the whole browser.
    expect(new DeviceIdentity().userIdFor(EMAIL)).toBe(A);
    expect(st.local.getItem(DEVICE_KEY)).toContain(A);
  });
});
