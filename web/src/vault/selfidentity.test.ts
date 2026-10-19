import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { toB64 } from "../crypto/bytes";
import { randomBytes } from "../crypto/provider";
import { initSodium } from "../crypto/sodium";
import { IdentityMismatchError, type Account } from "./account";
import { bindLegacySelfIdentity, loadSelfIdentityPub, recordSelfIdentityPub } from "./selfidentity";

/**
 * Security review 2026-10, branch A11 (q08), web twin of core SelfIdentityEmailBindingTest: the §2.4 pin was keyed
 * by the server-chosen userId alone, so a server answering the same typed email with a new userId got a pin miss
 * and its identity became the new pin. The pin is now also bound to the email the user typed.
 */
const U1 = "11111111-1111-4111-8111-111111111111";
const FORGED = "99999999-9999-4999-8999-999999999999";

describe("self-identity pin bound to the typed email (A11, q08)", () => {
  const mem = new Map<string, string>();
  let had: PropertyDescriptor | undefined;
  let acct: Account;
  beforeEach(async () => {
    await initSodium();
    mem.clear();
    const shim = { getItem: (k: string) => mem.get(k) ?? null, setItem: (k: string, v: string) => void mem.set(k, v), removeItem: (k: string) => void mem.delete(k), clear: () => mem.clear() };
    had = Object.getOwnPropertyDescriptor(globalThis, "localStorage");
    Object.defineProperty(globalThis, "localStorage", { value: shim, configurable: true });
    acct = { identityPub: randomBytes(32) } as unknown as Account;
  });
  afterEach(() => {
    if (had) Object.defineProperty(globalThis, "localStorage", had);
    else delete (globalThis as { localStorage?: unknown }).localStorage;
  });

  it("a new userId for the same email is a security fault, not a fresh pin", () => {
    expect(loadSelfIdentityPub(U1, "ann@example.com")).toBeNull();
    recordSelfIdentityPub(U1, acct, "ann@example.com");
    expect(() => loadSelfIdentityPub(FORGED, " Ann@Example.com")).toThrow(IdentityMismatchError);
    expect(loadSelfIdentityPub(U1, "ann@example.com")).toEqual(acct.identityPub);
    expect(loadSelfIdentityPub(FORGED, "bob@example.com")).toBeNull(); // another email is independent
  });

  it("a pre-A11 userId-keyed pin is bound to the saved session's email and kept", () => {
    mem.set(`andvari.selfIdentityPub.${U1}`, toB64(acct.identityPub));
    mem.set("andvari.session", JSON.stringify({ baseUrl: "", userId: U1, email: "ann@example.com", personalVaultId: "", isAdmin: false, tokens: null }));
    bindLegacySelfIdentity();
    mem.delete("andvari.session"); // a revocation then signs the browser out
    expect(() => loadSelfIdentityPub(FORGED, "ann@example.com")).toThrow(IdentityMismatchError);
    expect(loadSelfIdentityPub(U1, "ann@example.com")).toEqual(acct.identityPub);
    expect(mem.get(`andvari.selfIdentityPub.${U1}`)).toBe(toB64(acct.identityPub));
  });

  it("the legacy pin is bound lazily on the next read while the session exists", () => {
    mem.set(`andvari.selfIdentityPub.${U1}`, toB64(acct.identityPub));
    mem.set("andvari.session", JSON.stringify({ baseUrl: "", userId: U1, email: "ann@example.com", personalVaultId: "", isAdmin: false, tokens: null }));
    expect(() => loadSelfIdentityPub(FORGED, "ann@example.com")).toThrow(IdentityMismatchError);
  });

  it("a corrupt binding reads as absent", () => {
    mem.set("andvari.selfIdentityByEmail.ann@example.com", "garbage");
    expect(loadSelfIdentityPub(FORGED, "ann@example.com")).toBeNull();
  });
});
