import "fake-indexeddb/auto";
import { readFileSync } from "node:fs";
import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { randomBytes } from "../crypto/provider";
import { initSodium } from "../crypto/sodium";
import { kitDisplayForm } from "../crypto/trust/recoverykit";
import type { Account } from "../vault/account";
import { SELF_IDENTITY_MISMATCH } from "../vault/accountopen";
import { parseKitInput, verifyKit } from "../vault/kitflow";
import { completeSignup, signIn, unlockSession } from "../vault/onboardflow";
import type { PinStore } from "../vault/pinstore";
import { boundAccountAt, forgettingMarks, recordSelfIdentityPub } from "../vault/selfidentity";
import { earlierOfferFor } from "./ForgetEarlier";
import { browserStorages, KDF, ORIGIN, pinnedStore, RemakeServer } from "./forget-earlier.testkit";
import { knownIdentity } from "./opensession";
import { earlierCopyOf, forgetEarlierAccount, saveSession } from "./session";

/**
 * "Forget the earlier account on this device" is offered only where the account the server serves is ANOTHER account than
 * the one this browser ties the address to. The same account under another identity key is never a remade account (a
 * remade account has a new id), and it is what the address's record exists to stop: the refusal stays the identity
 * fault, with nothing offered, at every place that raises the offer; and a confirmation is not taken where what the
 * offer was made for no longer holds.
 */
const EMAIL = "alice@example.com";
const PASSWORD = "alice correct horse 1";
const src = (f: string) => readFileSync(new URL(f, import.meta.url), "utf8");
const asAccount = (pub: Uint8Array) => ({ identityPub: pub }) as unknown as Account;

describe("the offer needs another account than the remembered one, at every place", () => {
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

  const kitOf = (secret: Uint8Array) => {
    const k = parseKitInput(kitDisplayForm(secret), EMAIL);
    if (k.kind !== "typed") throw new Error("parse");
    return k;
  };
  const signInHere = () => signIn({ wire: server, pins, origin: ORIGIN, email: EMAIL, password: PASSWORD, deviceName: "x", session: null, knownIdentityPub: knownIdentity(EMAIL) });

  /** The check's probe: this browser's record names the very account the server serves, with another identity key. */
  async function sameAccountOtherKey() {
    const served = await server.remake(pins, EMAIL, PASSWORD);
    recordSelfIdentityPub(served.userId, asAccount(randomBytes(32)), EMAIL);
    return served;
  }

  it("the same account under another key: a sign-in, an unlock of the kept session and the kit's check are refused as the identity fault, with no offer", async () => {
    const served = await sameAccountOtherKey();
    // A sign-in.
    const r = await signInHere();
    expect(r).toEqual({ kind: "identity_fault", reason: SELF_IDENTITY_MISMATCH, servedUserId: served.userId });
    if (r.kind !== "identity_fault") return;
    expect(earlierOfferFor(EMAIL, r.reason, r.servedUserId)).toBeNull();
    // An unlock of the kept session of that account: the lookup gives the remembered key (no throw), and the server's key
    // differs from it; the screen's lookup branch, were it reached, passes the session's id, which is the bound one.
    saveSession({ baseUrl: "", userId: served.userId, personalVaultId: "", email: EMAIL, tokens: null });
    const known = knownIdentity(EMAIL)(served.userId);
    expect(known).not.toBeNull();
    const u = await unlockSession({ wire: server, pins, origin: ORIGIN, userId: served.userId, password: PASSWORD, knownIdentityPub: known });
    expect(u.kind === "identity_fault" ? u.reason : u.kind).toBe(SELF_IDENTITY_MISMATCH);
    expect(earlierOfferFor(EMAIL, SELF_IDENTITY_MISMATCH, served.userId)).toBeNull();
    // The kit's check.
    const k = await verifyKit({ wire: server, pins, origin: ORIGIN, input: kitOf(served.recoverySecret), knownIdentityPub: (id, em) => knownIdentity(em)(id) });
    expect(k).toEqual({ kind: "identity_fault", reason: SELF_IDENTITY_MISMATCH, servedUserId: served.userId });
    if (k.kind !== "identity_fault") return;
    expect(earlierOfferFor(EMAIL, k.reason, k.servedUserId)).toBeNull();
    // Nothing was removed or changed on this browser's record by any of them.
    expect(boundAccountAt(EMAIL)).toBe(served.userId);
  }, 120_000);

  it("another account under the address: the offer as before, at the sign-in, the unlock of another account's session, the registration and the kit's check", async () => {
    const first = await server.remake(pins, EMAIL, PASSWORD);
    recordSelfIdentityPub(first.userId, asAccount(first.identityPub), EMAIL);
    const again = await server.remake(pins, EMAIL, PASSWORD);
    const offerOf = (served: string) => ({ email: EMAIL, userId: first.userId, sessionKept: false, served });
    // A sign-in.
    const r = await signInHere();
    expect(r).toEqual({ kind: "identity_fault", reason: SELF_IDENTITY_MISMATCH, servedUserId: again.userId });
    if (r.kind !== "identity_fault") return;
    expect(earlierOfferFor(EMAIL, r.reason, r.servedUserId)).toEqual(offerOf(again.userId));
    // The kit's check.
    const k = await verifyKit({ wire: server, pins, origin: ORIGIN, input: kitOf(again.recoverySecret), knownIdentityPub: (id, em) => knownIdentity(em)(id) });
    expect(k).toEqual({ kind: "identity_fault", reason: SELF_IDENTITY_MISMATCH, servedUserId: again.userId });
    if (k.kind !== "identity_fault") return;
    expect(earlierOfferFor(EMAIL, k.reason, k.servedUserId)).toEqual(offerOf(again.userId));
    // A registration: refused before anything is sent; the account it would make is new, never the remembered one.
    const g = await completeSignup({ wire: server, pins, origin: ORIGIN, pin: pins.pinFor(ORIGIN)!, policy: { kdfParams: KDF } as never, email: EMAIL, displayName: "A", password: PASSWORD, signupTicket: "ticket", ageConfirmed: true, deviceName: "x", nowMs: 1763164800000, boundHere: boundAccountAt });
    expect(g).toEqual({ kind: "identity_fault", reason: SELF_IDENTITY_MISMATCH });
    expect(earlierOfferFor(EMAIL, SELF_IDENTITY_MISMATCH, "new")).toEqual(offerOf("new"));
    // An unlock of the kept session of the new account: the lookup by the session's id throws, and the offer names the
    // earlier account, with the session's account as the one met.
    saveSession({ baseUrl: "", userId: again.userId, personalVaultId: "", email: EMAIL, tokens: null });
    expect(() => knownIdentity(EMAIL)(again.userId)).toThrow();
    expect(earlierOfferFor(EMAIL, SELF_IDENTITY_MISMATCH, again.userId)).toEqual(offerOf(again.userId));
  }, 120_000);

  it("each place passes the account it met: the sign-in's and the kit's from the server's answer, the unlock's kept session, a registration's new one", () => {
    const welcome = src("./Welcome.tsx");
    expect(welcome).toContain("r.servedUserId"); // the sign-in and the kit's check
    expect(welcome).toContain("SELF_IDENTITY_MISMATCH, session.userId)"); // the unlock
    expect(welcome).toContain('r.reason, "new")'); // the registration
    // The unlock's own comparison of the same account's key (after the lookup passed) raises no offer at all.
    const unlock = welcome.slice(welcome.indexOf("function Unlock("), welcome.indexOf("function SignUp("));
    expect(unlock).toMatch(/case "identity_fault":\s*setErr\(IDENTITY_FAULT\);\s*return;/);
  });
});

describe("the second confirmation is not taken where what the offer was made for no longer holds", () => {
  let st: ReturnType<typeof browserStorages>;
  const U = "11111111-1111-4111-8111-111111111111";
  const V = "22222222-2222-4222-8222-222222222222";
  beforeEach(() => {
    st = browserStorages();
  });
  afterEach(() => st.restore());
  const snapshot = () => [...st.local.map.entries()].sort();

  it("the earlier account is the one the server served (an offer for the same account under another key): refused, nothing removed", async () => {
    recordSelfIdentityPub(U, asAccount(randomBytes(32)), EMAIL);
    const before = snapshot();
    expect(await forgetEarlierAccount(EMAIL, U, await earlierCopyOf(U), U)).toEqual({ kind: "no_longer_holds" });
    expect(snapshot()).toEqual(before);
    expect(forgettingMarks()).toEqual([]);
  });

  it("the address is by now tied to the account the server served (another tab forgot the earlier one and took it): refused, nothing removed", async () => {
    recordSelfIdentityPub(U, asAccount(randomBytes(32)), EMAIL);
    const shown = await earlierCopyOf(U);
    // Meanwhile, elsewhere: the earlier account forgotten, and the served account taken under the address.
    st.local.removeItem("andvari.selfIdentityByEmail.alice@example.com");
    recordSelfIdentityPub(V, asAccount(randomBytes(32)), EMAIL);
    const before = snapshot();
    expect(await forgetEarlierAccount(EMAIL, U, shown, V)).toEqual({ kind: "no_longer_holds" });
    expect(snapshot()).toEqual(before);
    expect(boundAccountAt(EMAIL)).toBe(V);
  });

  it("the screen says it and takes the offer away, nothing forgotten", () => {
    const offer = src("./ForgetEarlier.tsx");
    expect(offer).toMatch(/case "no_longer_holds":[\s\S]{0,200}onDone\(fill\(REMADE_ACCOUNT_FORGET_NO_LONGER_HOLDS, offer\.email\)\);/);
  });
});
