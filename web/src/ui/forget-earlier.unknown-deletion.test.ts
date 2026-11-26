import "fake-indexeddb/auto";
import { readFileSync } from "node:fs";
import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { randomBytes } from "../crypto/provider";
import { initSodium } from "../crypto/sodium";
import type { Account } from "../vault/account";
import { openVaultCache, readWaiting } from "../vault/idbcache";
import { boundAccountAt, recordSelfIdentityPub } from "../vault/selfidentity";
import { browserStorages } from "./forget-earlier.testkit";
import { wipeLocalAccountState } from "./session";

/**
 * "Forget" after a deletion whose outcome is not known (the session ended while the request was in flight) leaves this
 * browser's records of which account the address is and of that account's identity key, as a sign-out does: the account
 * may still exist, and a server can produce that outcome by ending the session during the request. Only a deletion the
 * server confirmed removes them. Everything else of the account goes as before.
 */
const EMAIL = "alice@example.com";
const A = "11111111-1111-4111-8111-111111111111";
const src = (f: string) => readFileSync(new URL(f, import.meta.url), "utf8");

describe("forgetting an account after a deletion whose outcome is not known", () => {
  let st: ReturnType<typeof browserStorages>;
  beforeAll(async () => {
    await initSodium();
  });
  beforeEach(async () => {
    st = browserStorages();
    recordSelfIdentityPub(A, { identityPub: randomBytes(32) } as unknown as Account, EMAIL);
    st.local.setItem(`andvari.current.${A}`, "x");
    (await openVaultCache(A)).close();
  });
  afterEach(() => {
    st.restore();
    indexedDB.deleteDatabase(`andvari-vault-${A}`);
  });

  it("not confirmed: the address's record and the key's record stay; the rest of the account goes", async () => {
    const pin = st.local.getItem(`andvari.selfIdentityPub.${A}`);
    await wipeLocalAccountState(A, EMAIL, "unconfirmed");
    expect(boundAccountAt(EMAIL)).toBe(A);
    expect(st.local.getItem(`andvari.selfIdentityPub.${A}`)).toBe(pin);
    expect(st.local.getItem(`andvari.current.${A}`)).toBeNull();
    expect((await readWaiting(A)).kind).toBe("none");
  });

  it("confirmed by the server: both go, as before", async () => {
    await wipeLocalAccountState(A, EMAIL);
    expect(boundAccountAt(EMAIL)).toBeNull();
    expect(st.local.getItem(`andvari.selfIdentityPub.${A}`)).toBeNull();
  });

  it("the app passes how the deletion ended", () => {
    expect(src("./App.tsx")).toContain('void wipeLocalAccountState(userId, email, end === "confirmed" ? "confirmed" : "unconfirmed");');
  });
});
