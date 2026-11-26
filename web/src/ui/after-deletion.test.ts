import "fake-indexeddb/auto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { DeviceIdentity } from "../api/devicesecret";
import { randomBytes } from "../crypto/provider";
import { initSodium } from "../crypto/sodium";
import type { Account } from "../vault/account";
import { openVaultCache } from "../vault/idbcache";
import { keepPolicyWipeNotice, markCopyBeingRemoved, takePolicyWipeNotice } from "../vault/policywipe";
import { boundAccountAt, recordSelfIdentityPub, rememberNextAt } from "../vault/selfidentity";
import { ACCOUNT_DELETED_NOTICE, DELETION_MOST_LIKELY_DONE } from "./account-delete";
import { browserStorages } from "./forget-earlier.testkit";
import { WIPE_OWED_PREFIX, wipeLocalAccountState } from "./session";

/**
 * What the web app keeps of an account after its deletion, and what it says (the deletion the server confirmed; the
 * person's "Forget" after a deletion whose answer was lost). The records are put in place as the app writes them while
 * the account is used here; the deletion's own step is the app's (App's onAccountDeleted).
 */
const EMAIL = "dora@example.org";
const V = "33333333-3333-4333-8333-333333333333";
const OTHER = "44444444-4444-4444-8444-444444444444";
const DEVICE = "55555555-5555-4555-8555-555555555555";

describe("after an account's deletion", () => {
  let st: ReturnType<typeof browserStorages>;
  beforeAll(async () => {
    await initSodium();
  });
  beforeEach(async () => {
    st = browserStorages();
    // The account, used here: its session, its records by id, its key and the address's record, the device row, a copy.
    localStorage.setItem("andvari.session", JSON.stringify({ userId: V, email: EMAIL }));
    for (const k of [`andvari.as2.${V}.sealed`, `andvari.as2.${V}.seen`, `andvari.how.${V}`, `andvari.autoLockSeconds.${V}`]) localStorage.setItem(k, "x");
    recordSelfIdentityPub(V, { identityPub: randomBytes(32) } as unknown as Account, EMAIL);
    new DeviceIdentity().remember(EMAIL, V, DEVICE);
    const c = await openVaultCache(V);
    c.close();
    // Device-wide records that can name it: a policy's wipe owed and its notice kept, a copy being removed.
    localStorage.setItem(WIPE_OWED_PREFIX + V, "1");
    markCopyBeingRemoved(V);
    keepPolicyWipeNotice(V, { server: "Family", unsent: 2, unsure: 0 }, false);
    // Another account's settings, to show what is not the deleted account's.
    localStorage.setItem(`andvari.autoLockSeconds.${OTHER}`, "300");
    localStorage.setItem("andvari.theme", "dark");
  });
  afterEach(() => {
    st.restore();
    indexedDB.deleteDatabase(`andvari-vault-${V}`);
  });

  /** Every record in either store whose key or value names the account's id or its address. */
  const naming = () =>
    [...st.local.map.entries(), ...st.tab.map.entries()]
      .filter(([k, v]) => k.includes(V) || v.includes(V) || k.includes(EMAIL) || v.includes(EMAIL))
      .map(([k]) => k)
      .sort();

  it("the server confirmed it: nothing here names the account or its address afterwards, as its notice says", async () => {
    expect(naming().length).toBeGreaterThan(5);
    await wipeLocalAccountState(V, EMAIL, "confirmed");
    expect(naming()).toEqual([]);
    expect((await indexedDB.databases()).map((d) => d.name)).not.toContain(`andvari-vault-${V}`);
    // What is not the account's stays: another account's setting, the browser's own.
    expect(localStorage.getItem(`andvari.autoLockSeconds.${OTHER}`)).toBe("300");
    expect(localStorage.getItem("andvari.theme")).toBe("dark");
    // The word owed about the changes a policy's wipe lost stays, said once, without the account's id.
    expect(takePolicyWipeNotice()).toEqual({ server: "Family", unsent: 2, unsure: 0 });
    expect(takePolicyWipeNotice()).toBeNull();
    // The notice the app shows then says exactly that.
    expect(ACCOUNT_DELETED_NOTICE).toContain("this browser kept nothing of it");
  });

  it("the server confirmed it after a forgetting whose next account was still to be taken: the address's waiting notice goes too", async () => {
    rememberNextAt("later@example.org");
    rememberNextAt(EMAIL);
    await wipeLocalAccountState(V, EMAIL, "confirmed");
    expect(naming()).toEqual([]);
  });

  it("its answer was lost and the person chose Forget: the address's record and the account's key stay, and the card's line does not say that everything goes", async () => {
    await wipeLocalAccountState(V, EMAIL, "unconfirmed");
    expect(boundAccountAt(EMAIL)).toBe(V);
    expect(naming()).toEqual([`andvari.selfIdentityByEmail.${EMAIL}`, `andvari.selfIdentityPub.${V}`]);
    // The card offers that Forget: its line must not promise "everything else it kept for it", which is not so.
    expect(DELETION_MOST_LIKELY_DONE).not.toContain("everything else it kept for it");
    // And the card's own description says what the Forget keeps.
    const card = readFileSync(fileURLToPath(new URL("./DeleteAccount.tsx", import.meta.url)), "utf8");
    expect(card).not.toContain("forgetting also drops the userId-scoped state and the\n * spec 01 §5 self-identity records");
  });
});
