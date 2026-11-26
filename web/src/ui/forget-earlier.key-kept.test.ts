import "fake-indexeddb/auto";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { toB64 } from "../crypto/bytes";
import { initSodium } from "../crypto/sodium";
import { kitDisplayForm } from "../crypto/trust/recoverykit";
import type { Account } from "../vault/account";
import { SELF_IDENTITY_MISMATCH } from "../vault/accountopen";
import { parseKitInput, verifyKit } from "../vault/kitflow";
import { signIn } from "../vault/onboardflow";
import type { PinStore } from "../vault/pinstore";
import { boundAccountAt, recordSelfIdentityPub, rememberedNotices } from "../vault/selfidentity";
import { IDENTITY_FAULT } from "./copy";
import { earlierOfferFor, identityRefusal } from "./ForgetEarlier";
import { browserStorages, ORIGIN, pinnedStore, RemakeServer } from "./forget-earlier.testkit";
import { knownIdentity } from "./opensession";
import { earlierCopyOf, forgetEarlierAccount, wipeLocalAccountState } from "./session";

/**
 * The forgetting keeps this browser's record of the earlier account's identity key (its id-keyed pin, public) and nothing
 * else of that account. With it, the earlier account never comes back here under another key, also after a forgetting:
 * a server that shows another account under the address to obtain the forgetting, and then serves the old account with a
 * key of its own, is refused at that second step, with nothing offered. Served again with its own key it is taken as itself.
 *
 * The server below can serve an account under a chosen id with a new key: the registration's first 16 random bytes are
 * its id (registration.ts uuidv4), so they are given for that one call.
 */
const forced = vi.hoisted(() => [] as Uint8Array[]);
vi.mock("../crypto/provider", async (importOriginal) => {
  const real = await importOriginal<typeof import("../crypto/provider")>();
  return { ...real, randomBytes: (n: number) => (n === 16 && forced.length > 0 ? forced.shift()! : real.randomBytes(n)) };
});

const EMAIL = "alice@example.com";
const PASSWORD = "alice correct horse 1";
const idBytes = (uuid: string) => Uint8Array.from(uuid.replace(/-/g, "").match(/../g)!.map((h) => parseInt(h, 16)));
const pinOf = (userId: string) => localStorage.getItem(`andvari.selfIdentityPub.${userId}`);

describe("after a forgetting, the record of the earlier account's key stays", () => {
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

  const signInHere = () => signIn({ wire: server, pins, origin: ORIGIN, email: EMAIL, password: PASSWORD, deviceName: "x", session: null, knownIdentityPub: knownIdentity(EMAIL) });
  /** A sign-in that opens, and the records an opening writes (enterVault: the id-keyed pin and the address's record). */
  async function openedHere(expected: string) {
    const r = await signInHere();
    expect(r.kind).toBe("opened");
    if (r.kind !== "opened") throw new Error("not opened");
    expect(r.session.userId).toBe(expected);
    recordSelfIdentityPub(r.session.userId, { identityPub: r.opened.identity.publicKey } as unknown as Account, EMAIL);
  }
  /** The account under the address is refused on this browser's record; the offer that the screen would draw, or null. */
  async function refusedHere() {
    const r = await signInHere();
    expect(r.kind === "identity_fault" ? r.reason : r.kind).toBe(SELF_IDENTITY_MISMATCH);
    if (r.kind !== "identity_fault") throw new Error("not refused");
    return { served: r.servedUserId, offer: earlierOfferFor(EMAIL, r.reason, r.servedUserId) };
  }
  /** The person forgets the earlier account through the offer: both steps, as the screen takes them. */
  async function forgetThrough(offer: NonNullable<ReturnType<typeof earlierOfferFor>>) {
    expect(await forgetEarlierAccount(offer.email, offer.userId, await earlierCopyOf(offer.userId), offer.served)).toEqual({ kind: "forgotten" });
  }

  /** U opened here; the server then serves another account V under the address; the person forgets U. */
  async function uForgottenForV() {
    const u = await server.remake(pins, EMAIL, PASSWORD);
    const uAtServer = server.accounts.get(EMAIL)!;
    await openedHere(u.userId);
    const v = await server.remake(pins, EMAIL, PASSWORD);
    const vAtServer = server.accounts.get(EMAIL)!;
    const { offer } = await refusedHere();
    expect(offer).toEqual({ email: EMAIL, userId: u.userId, sessionKept: false, served: v.userId });
    await forgetThrough(offer!);
    // The address is new to this browser; the record of U's key is still there, as it was.
    expect(boundAccountAt(EMAIL)).toBeNull();
    expect(pinOf(u.userId)).toBe(toB64(u.identityPub));
    return { u, uAtServer, v, vAtServer };
  }
  /** The server serves the account [userId] again under the address, with a new identity key. */
  async function servedUnderAnotherKey(userId: string) {
    forced.push(idBytes(userId));
    const q = await server.remake(pins, EMAIL, PASSWORD);
    expect(q.userId).toBe(userId);
    return q;
  }

  it("the server then serves U again under another key: refused as the identity fault, with nothing offered, at the sign-in and at the kit's check", async () => {
    const { u } = await uForgottenForV();
    const q = await servedUnderAnotherKey(u.userId);
    expect(toB64(q.identityPub)).not.toBe(toB64(u.identityPub));
    const { served, offer } = await refusedHere();
    expect(served).toBe(u.userId);
    expect(offer).toBeNull();
    const kit = parseKitInput(kitDisplayForm(q.recoverySecret), EMAIL);
    if (kit.kind !== "typed") throw new Error("parse");
    const k = await verifyKit({ wire: server, pins, origin: ORIGIN, input: kit, knownIdentityPub: (id, em) => knownIdentity(em)(id) });
    expect(k).toEqual({ kind: "identity_fault", reason: SELF_IDENTITY_MISMATCH, servedUserId: u.userId });
    if (k.kind !== "identity_fault") return;
    expect(earlierOfferFor(EMAIL, k.reason, k.servedUserId)).toBeNull();
    // Nothing of it was taken: the address names no account, and U's record is the key it had.
    expect(boundAccountAt(EMAIL)).toBeNull();
    expect(pinOf(u.userId)).toBe(toB64(u.identityPub));
  }, 180_000);

  it("the server then serves U again under its own key: taken as U", async () => {
    const { u, uAtServer } = await uForgottenForV();
    server.accounts.set(EMAIL, uAtServer);
    await openedHere(u.userId);
    expect(boundAccountAt(EMAIL)).toBe(u.userId);
  }, 180_000);

  it("V taken, then U served under another key: refused as the identity fault with its plate and nothing offered, at the sign-in and at the kit's check; the address still names V", async () => {
    const { u, v } = await uForgottenForV();
    await openedHere(v.userId);
    const q = await servedUnderAnotherKey(u.userId);
    const r = await signInHere();
    expect(r.kind === "identity_fault" ? r.reason : r.kind).toBe(SELF_IDENTITY_MISMATCH);
    if (r.kind !== "identity_fault") return;
    expect(identityRefusal(EMAIL, r.reason, r.servedUserId)).toEqual({ err: IDENTITY_FAULT, offer: null });
    const kit = parseKitInput(kitDisplayForm(q.recoverySecret), EMAIL);
    if (kit.kind !== "typed") throw new Error("parse");
    const k = await verifyKit({ wire: server, pins, origin: ORIGIN, input: kit, knownIdentityPub: (id, em) => knownIdentity(em)(id) });
    expect(k.kind === "identity_fault" ? k.reason : k.kind).toBe(SELF_IDENTITY_MISMATCH);
    if (k.kind !== "identity_fault") return;
    expect(identityRefusal(EMAIL, k.reason, k.servedUserId)).toEqual({ err: IDENTITY_FAULT, offer: null });
    expect(boundAccountAt(EMAIL)).toBe(v.userId);
    expect(pinOf(u.userId)).toBe(toB64(u.identityPub));
  }, 240_000);

  it("V taken, then V deleted here with the server's confirmation, then U served under another key: refused with its plate and nothing offered; U's key record and the server's pin stay", async () => {
    const { u, v } = await uForgottenForV();
    await openedHere(v.userId);
    const uKeys = () => [...st.local.map.keys()].filter((k) => k.includes(u.userId)).sort();
    const before = uKeys();
    // The deletion the server confirmed, as the app takes it (App's onAccountDeleted: only the deleted account's records).
    await wipeLocalAccountState(v.userId, EMAIL, "confirmed");
    expect(uKeys()).toEqual(before);
    expect(uKeys()).toEqual([`andvari.selfIdentityPub.${u.userId}`]);
    expect(pinOf(u.userId)).toBe(toB64(u.identityPub));
    expect(pinOf(v.userId)).toBeNull();
    expect(boundAccountAt(EMAIL)).toBeNull();
    expect(pins.pinFor(ORIGIN)).not.toBeNull();
    // The server then serves U again, under a key of its own.
    const q = await servedUnderAnotherKey(u.userId);
    const r = await signInHere();
    expect(r).toEqual({ kind: "identity_fault", reason: SELF_IDENTITY_MISMATCH, servedUserId: u.userId });
    if (r.kind !== "identity_fault") return;
    expect(identityRefusal(EMAIL, r.reason, r.servedUserId)).toEqual({ err: IDENTITY_FAULT, offer: null });
    const kit = parseKitInput(kitDisplayForm(q.recoverySecret), EMAIL);
    if (kit.kind !== "typed") throw new Error("parse");
    const k = await verifyKit({ wire: server, pins, origin: ORIGIN, input: kit, knownIdentityPub: (id, em) => knownIdentity(em)(id) });
    expect(k).toEqual({ kind: "identity_fault", reason: SELF_IDENTITY_MISMATCH, servedUserId: u.userId });
    // Nothing of it was taken.
    expect(boundAccountAt(EMAIL)).toBeNull();
    expect(pinOf(u.userId)).toBe(toB64(u.identityPub));
  }, 240_000);

  it("V taken, then U served under its OWN key: the offer to forget V (someone who forgot by mistake finds the way back), at the sign-in and at the kit's check", async () => {
    const { u, uAtServer, v } = await uForgottenForV();
    await openedHere(v.userId);
    server.accounts.set(EMAIL, uAtServer);
    const r = await signInHere();
    expect(r).toEqual({ kind: "identity_fault", reason: SELF_IDENTITY_MISMATCH, servedUserId: u.userId });
    if (r.kind !== "identity_fault") return;
    expect(identityRefusal(EMAIL, r.reason, r.servedUserId)).toEqual({ err: "", offer: { email: EMAIL, userId: v.userId, sessionKept: false, served: u.userId } });
    const kit = parseKitInput(kitDisplayForm(u.recoverySecret), EMAIL);
    if (kit.kind !== "typed") throw new Error("parse");
    const k = await verifyKit({ wire: server, pins, origin: ORIGIN, input: kit, knownIdentityPub: (id, em) => knownIdentity(em)(id) });
    expect(k).toEqual({ kind: "identity_fault", reason: SELF_IDENTITY_MISMATCH, servedUserId: u.userId });
  }, 240_000);

  it("V is taken and recorded once; a third account W is refused with the offer naming V; after V is forgotten both keys' records stay, and U under another key is still refused", async () => {
    const { u, v } = await uForgottenForV();
    await openedHere(v.userId);
    expect(boundAccountAt(EMAIL)).toBe(v.userId);
    expect(rememberedNotices()).toEqual([EMAIL]);
    // A second opening of V writes nothing new and says nothing again.
    await openedHere(v.userId);
    expect(rememberedNotices()).toEqual([EMAIL]);
    expect(st.local.map.get("andvari.selfIdentityByEmail.alice@example.com")).toBe(`${v.userId}\n${toB64(v.identityPub)}`);
    // A third account under the address: refused, with the offer, V now being the earlier account.
    const w = await server.remake(pins, EMAIL, PASSWORD);
    const { offer } = await refusedHere();
    expect(offer).toEqual({ email: EMAIL, userId: v.userId, sessionKept: false, served: w.userId });
    await forgetThrough(offer!);
    expect(pinOf(u.userId)).toBe(toB64(u.identityPub));
    expect(pinOf(v.userId)).toBe(toB64(v.identityPub));
    // U served once more under another key, the address being new again: still refused, with nothing offered.
    await servedUnderAnotherKey(u.userId);
    const again = await refusedHere();
    expect(again).toEqual({ served: u.userId, offer: null });
  }, 240_000);
});
