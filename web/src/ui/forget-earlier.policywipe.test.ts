import "fake-indexeddb/auto";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import type { Mutation } from "../api/types";
import { randomBytes } from "../crypto/provider";
import { initSodium } from "../crypto/sodium";
import type { Account } from "../vault/account";
import { openVaultCache, readWaiting } from "../vault/idbcache";
import { keepPolicyWipeNotice, ORG_CACHE_OFF_KEY, POLICY_WIPE_NOTICE_KEY, retryHeldPolicyWipes, takePolicyWipeNotice } from "../vault/policywipe";
import { recordSelfIdentityPub } from "../vault/selfidentity";
import { browserStorages } from "./forget-earlier.testkit";
import { earlierCopyOf, forgetEarlierAccount } from "./session";

/**
 * The notice of a server's policy wipe that stays after a forgetting (a word owed to the person about changes that were
 * lost) no longer carries the earlier account's id at rest: it is kept under a key of its own, as said-able. And a wipe
 * the policy still owed for that account's copy (its notice not yet "gone") does nothing more for an account this browser
 * forgot: no record naming the account is written again, no copy is made, and the notice is said once, whatever the policy.
 */
const EMAIL = "alice@example.com";
const A = "11111111-1111-4111-8111-111111111111";
const B = "22222222-2222-4222-8222-222222222222";
const mut = (id: string): Mutation => ({ mutationId: id, op: "put", itemId: `item-${id}`, vaultId: "v1", baseItemRev: 0 });
const NOTICE = { server: "Family", unsent: 2, unsure: 1 };

describe("the policy wipe's notice and a forgetting", () => {
  let st: ReturnType<typeof browserStorages>;
  beforeAll(async () => {
    await initSodium();
  });
  beforeEach(async () => {
    st = browserStorages();
    vi.stubGlobal("fetch", vi.fn(() => Promise.reject(new Error("nothing may be sent"))));
    recordSelfIdentityPub(A, { identityPub: randomBytes(32) } as unknown as Account, EMAIL);
    const c = await openVaultCache(A);
    await c.enqueue(mut("1"));
    c.close();
  });
  afterEach(() => {
    vi.unstubAllGlobals();
    st.restore();
    indexedDB.deleteDatabase(`andvari-vault-${A}`);
  });

  const keysNamingA = () => [...st.local.map.keys()].filter((k) => k.includes(A) && k !== `andvari.selfIdentityPub.${A}`);
  const forgetA = async () => expect(await forgetEarlierAccount(EMAIL, A, await earlierCopyOf(A), B)).toEqual({ kind: "forgotten" });

  it("a notice to be said (its copy gone): after the forgetting it holds no id, and it is said once", async () => {
    keepPolicyWipeNotice(A, NOTICE, true);
    await forgetA();
    expect(st.local.getItem(POLICY_WIPE_NOTICE_KEY)).not.toContain(A);
    expect(takePolicyWipeNotice()).toEqual(NOTICE);
    expect(takePolicyWipeNotice()).toBeNull();
  });

  it("a wipe still owed (not gone), the policy still forbidding: after the forgetting no id at rest; the held wipes' retry writes nothing naming the account and makes no copy; the notice is said once", async () => {
    st.local.setItem(ORG_CACHE_OFF_KEY, "1");
    keepPolicyWipeNotice(A, NOTICE, false);
    await forgetA();
    expect(st.local.getItem(POLICY_WIPE_NOTICE_KEY)).not.toContain(A);
    await retryHeldPolicyWipes();
    expect(keysNamingA()).toEqual([]);
    expect((await readWaiting(A)).kind).toBe("none");
    expect(takePolicyWipeNotice()).toEqual(NOTICE);
    expect(takePolicyWipeNotice()).toBeNull();
  });

  it("a wipe still owed, the policy since allowing the copy: the notice of what was lost is not dropped unsaid, because the forgetting removed the copy", async () => {
    keepPolicyWipeNotice(A, NOTICE, false);
    await forgetA();
    await retryHeldPolicyWipes();
    expect(keysNamingA()).toEqual([]);
    expect(takePolicyWipeNotice()).toEqual(NOTICE);
  });
});
