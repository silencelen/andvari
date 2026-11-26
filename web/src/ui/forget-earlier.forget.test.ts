import "fake-indexeddb/auto";
import { readdirSync, readFileSync } from "node:fs";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { DEVICE_KEY, DeviceIdentity } from "../api/devicesecret";
import type { Mutation } from "../api/types";
import { initSodium } from "../crypto/sodium";
import { randomBytes } from "../crypto/provider";
import type { Account } from "../vault/account";
import { openVaultCache, readWaiting } from "../vault/idbcache";
import { boundAccountAt, FORGETTING_KEY, forgettingMarks, recordSelfIdentityPub } from "../vault/selfidentity";
import { confirmationTakenBackBy } from "./ForgetEarlier";
import { browserStorages } from "./forget-earlier.testkit";
import { earlierCopyOf, forgetEarlierAccount, saveSession, SESSION_STORAGE_KEY, settleForgettings, TAB_TOKENS_KEY } from "./session";

/**
 * The forgetting itself (decided on 2026-11-17): it removes the record that ties the address to the earlier account, that
 * account's copy, and everything kept under its id at this origin, by what each key is keyed with; it leaves other
 * accounts and everything known of the server; it sends nothing; a forgetting that was begun is finished.
 */
const EMAIL = "alice@example.com";
const A = "11111111-1111-4111-8111-111111111111";
const B = "22222222-2222-4222-8222-222222222222";
const ORIGIN_PIN = "andvari.pin2.https://vault.example.org";
const mut = (id: string): Mutation => ({ mutationId: id, op: "put", itemId: `item-${id}`, vaultId: "v1", baseItemRev: 0 });
const kinds = (u: string) => [
  `andvari.cs.${u}.accountState.seq`,
  `andvari.cs.${u}.personalWrap`,
  `andvari.log2.${u}.pending-index`,
  `andvari.log2.${u}.33333333-3333-4333-8333-333333333333.state`,
  `andvari.as2.${u}.recovery`,
  `andvari.recmirror.${u}`,
  `andvari.escrowfp.${u}`,
  `andvari.current.${u}`,
  `andvari.onetap.${u}`,
  `andvari.how.${u}`,
  `andvari.cacheOptIn.${u}`,
  `andvari.autoLockSeconds.${u}`,
  `andvari.lastExportAt.${u}`,
  // A kind no code writes today: the walk goes by what a key is keyed with, so a kind added later goes too.
  `andvari.someLaterKind.${u}.part`,
];

describe("the forgetting of the earlier account", () => {
  let st: ReturnType<typeof browserStorages>;
  let fetched: ReturnType<typeof vi.fn>;
  beforeAll(async () => {
    await initSodium();
  });
  beforeEach(async () => {
    st = browserStorages();
    fetched = vi.fn(() => Promise.reject(new Error("nothing may be sent")));
    vi.stubGlobal("fetch", fetched);
    recordSelfIdentityPub(A, { identityPub: randomBytes(32) } as unknown as Account, EMAIL);
    recordSelfIdentityPub(B, { identityPub: randomBytes(32) } as unknown as Account, "bob@example.com");
    for (const k of [...kinds(A), ...kinds(B)]) st.local.setItem(k, "x");
    st.local.setItem(ORIGIN_PIN, "the server's pin");
    st.local.setItem("andvari.theme", "dark");
    st.local.setItem("andvari.policyWipeNotice", JSON.stringify({ [A]: { server: "Family", unsent: 1 } }));
    new DeviceIdentity().remember(EMAIL, A, "d0000000-0000-4000-8000-00000000000a");
    new DeviceIdentity().remember("bob@example.com", B, "d0000000-0000-4000-8000-00000000000b");
    st.tab.setItem(TAB_TOKENS_KEY, JSON.stringify({ tabId: "t", userId: A, tokens: { accessToken: "a", refreshToken: "r" } }));
    for (const u of [A, B]) {
      const c = await openVaultCache(u);
      await c.enqueue(mut(`${u}-1`));
      await c.enqueue(mut(`${u}-2`));
      c.close();
    }
  });
  afterEach(async () => {
    vi.unstubAllGlobals();
    st.restore();
    for (const u of [A, B]) indexedDB.deleteDatabase(`andvari-vault-${u}`);
  });

  const snapshot = () => new Map(st.local.map);
  const diff = (before: Map<string, string>) => ({
    removed: [...before.keys()].filter((k) => !st.local.map.has(k)).sort(),
    added: [...st.local.map.keys()].filter((k) => !before.has(k)).sort(),
    changed: [...before.keys()].filter((k) => st.local.map.has(k) && st.local.map.get(k) !== before.get(k)).sort(),
  });

  it("removes exactly the earlier account's records and copy, leaves the server's and other accounts', and sends nothing", async () => {
    const shown = await earlierCopyOf(A);
    expect(shown).toEqual({ kept: true, unsent: 2, held: 0 });
    const before = snapshot();
    expect(await forgetEarlierAccount(EMAIL, A, shown, B)).toEqual({ kind: "forgotten" });
    const d = diff(before);
    // Everything of A goes but the record of its identity key, which stays as it was.
    expect(d.removed).toEqual(["andvari.selfIdentityByEmail.alice@example.com", ...kinds(A)].sort());
    expect(st.local.getItem(`andvari.selfIdentityPub.${A}`)).toBe(before.get(`andvari.selfIdentityPub.${A}`));
    expect(d.added).toEqual(["andvari.rememberNext"]); // the address only: the next account under it is said once
    expect(d.changed).toEqual([DEVICE_KEY]); // A's row and its address hash went; the secret and B's row stay
    expect(new DeviceIdentity().userIdFor(EMAIL)).toBeNull();
    expect(new DeviceIdentity().userIdFor("bob@example.com")).toBe(B);
    expect((await readWaiting(A)).kind).toBe("none");
    expect((await readWaiting(B)).kind).toBe("read");
    expect(st.local.getItem(ORIGIN_PIN)).toBe("the server's pin");
    expect(boundAccountAt("bob@example.com")).toBe(B);
    expect(st.tab.getItem(TAB_TOKENS_KEY)).toBeNull(); // this tab's slot named the earlier account
    expect(forgettingMarks()).toEqual([]);
    expect(fetched).not.toHaveBeenCalled();
  });

  it("a count that changed since the confirmation was shown removes nothing and answers with what holds now", async () => {
    const before = snapshot();
    expect(await forgetEarlierAccount(EMAIL, A, { kept: true, unsent: 1, held: 0 }, B)).toEqual({ kind: "not_confirmed", copy: { kept: true, unsent: 2, held: 0 } });
    expect(diff(before)).toEqual({ removed: [], added: [], changed: [] });
    expect((await readWaiting(A)).kind).toBe("read");
  });

  it("another tab open on the earlier account: its session is kept here, so nothing is removed and its sign-out comes first", async () => {
    saveSession({ baseUrl: "", userId: A, personalVaultId: "", email: EMAIL, tokens: null });
    const before = snapshot();
    expect(await forgetEarlierAccount(EMAIL, A, await earlierCopyOf(A), B)).toEqual({ kind: "account_open" });
    expect(diff(before)).toEqual({ removed: [], added: [], changed: [] });
    expect((await readWaiting(A)).kind).toBe("read");
  });

  it("another tab's change of the session, the address's record, a forgetting's mark or the earlier account's records takes the confirmation back", () => {
    const offer = { email: EMAIL, userId: A };
    for (const k of [null, SESSION_STORAGE_KEY, "andvari.selfIdentityByEmail.alice@example.com", FORGETTING_KEY, `andvari.cs.${A}.accountState.seq`, `andvari.wipeOwed.${A}`]) expect(confirmationTakenBackBy(k, offer), String(k)).toBe(true);
    for (const k of [`andvari.cs.${B}.accountState.seq`, "andvari.selfIdentityByEmail.bob@example.com", "andvari.theme", ORIGIN_PIN]) expect(confirmationTakenBackBy(k, offer), k).toBe(false);
  });

  it("a forgetting that throws part-way keeps its mark, and the next click finishes it and answers forgotten, never nothing to forget", async () => {
    const shown = await earlierCopyOf(A);
    const real = st.local.removeItem.bind(st.local);
    let fail = true;
    st.local.removeItem = (k: string) => {
      if (fail && k === `andvari.log2.${A}.pending-index`) {
        fail = false;
        throw new Error("store failed");
      }
      real(k);
    };
    await expect(forgetEarlierAccount(EMAIL, A, shown, B)).rejects.toThrow("store failed");
    expect(boundAccountAt(EMAIL)).toBeNull(); // the first removal was made
    expect(forgettingMarks()).toEqual([{ email: EMAIL, userId: A }]);
    expect(st.local.getItem(`andvari.log2.${A}.pending-index`)).toBe("x");
    expect(await forgetEarlierAccount(EMAIL, A, shown, B)).toEqual({ kind: "forgotten" });
    expect([...st.local.map.keys()].filter((k) => k.includes(A))).toEqual([`andvari.selfIdentityPub.${A}`]);
    expect((await readWaiting(A)).kind).toBe("none");
    expect(forgettingMarks()).toEqual([]);
    // Once finished, a further click has nothing to forget.
    expect(await forgetEarlierAccount(EMAIL, A, shown, B)).toEqual({ kind: "nothing_to_forget" });
  });

  it("a forgetting stopped part-way is finished at the next start", async () => {
    const shown = await earlierCopyOf(A);
    const real = st.local.removeItem.bind(st.local);
    st.local.removeItem = (k: string) => {
      if (k === `andvari.current.${A}`) throw new Error("store failed");
      real(k);
    };
    await expect(forgetEarlierAccount(EMAIL, A, shown, B)).rejects.toThrow("store failed");
    st.local.removeItem = real;
    await settleForgettings();
    expect([...st.local.map.keys()].filter((k) => k.includes(A))).toEqual([`andvari.selfIdentityPub.${A}`]);
    expect((await readWaiting(A)).kind).toBe("none");
    expect(forgettingMarks()).toEqual([]);
    expect(boundAccountAt("bob@example.com")).toBe(B);
  });

  it("at a start, a mark whose first removal was never made, or whose account was signed in to here since, is dropped with nothing removed", async () => {
    st.local.setItem(FORGETTING_KEY, JSON.stringify([{ email: EMAIL, userId: A }]));
    let before = snapshot();
    await settleForgettings();
    expect(diff(before)).toEqual({ removed: [FORGETTING_KEY], added: [], changed: [] });
    // The address's record went, and the earlier account's session is kept here again: nothing of it is removed.
    st.local.removeItem("andvari.selfIdentityByEmail.alice@example.com");
    st.local.removeItem(`andvari.selfIdentityPub.${A}`);
    saveSession({ baseUrl: "", userId: A, personalVaultId: "", email: EMAIL, tokens: null });
    st.local.setItem(FORGETTING_KEY, JSON.stringify([{ email: EMAIL, userId: A }]));
    before = snapshot();
    await settleForgettings();
    expect(diff(before)).toEqual({ removed: [FORGETTING_KEY], added: [], changed: [] });
    expect((await readWaiting(A)).kind).toBe("read");
  });

  it("a mark that cannot be written stops the forgetting before anything is removed", async () => {
    const shown = await earlierCopyOf(A);
    const real = st.local.setItem.bind(st.local);
    st.local.setItem = (k: string, v: string) => {
      if (k === FORGETTING_KEY) throw new Error("quota");
      real(k, v);
    };
    const before = snapshot();
    await expect(forgetEarlierAccount(EMAIL, A, shown, B)).rejects.toThrow("quota");
    expect(diff(before)).toEqual({ removed: [], added: [], changed: [] });
  });

  it("with no record and no mark there is nothing to forget, and nothing is removed", async () => {
    st.local.removeItem("andvari.selfIdentityByEmail.alice@example.com");
    const before = snapshot();
    expect(await forgetEarlierAccount(EMAIL, A, { kept: true, unsent: 2, held: 0 }, B)).toEqual({ kind: "nothing_to_forget" });
    expect(diff(before)).toEqual({ removed: [], added: [], changed: [] });
  });
});

describe("only the person's click on the second confirmation forgets", () => {
  const dir = new URL(".", import.meta.url);
  const source = (rel: string) => readFileSync(new URL(rel, dir), "utf8");
  const sources = (sub: string) =>
    readdirSync(new URL(sub, dir))
      .filter((f) => /\.tsx?$/.test(f) && !/\.test\.ts$|\.testkit\.ts$/.test(f))
      .map((f) => [`${sub}${f}`, source(`${sub}${f}`)] as const);

  it("forgetEarlierAccount is called once, by the second confirmation's button, with the confirmation on show; settleForgettings only at a start", () => {
    const all = [...sources("./"), ...sources("../vault/"), ...sources("../api/")];
    const callers = all.filter(([, s]) => /\bforgetEarlierAccount\(/.test(s)).map(([f]) => f);
    expect(callers.sort()).toEqual(["./ForgetEarlier.tsx", "./session.ts"]);
    const offer = source("./ForgetEarlier.tsx");
    expect(offer.match(/forgetEarlierAccount\(/g)).toHaveLength(1);
    expect(offer).toContain("const r = await forgetEarlierAccount(offer.email, offer.userId, shown, offer.served);");
    expect(offer.match(/void confirm\(/g)).toHaveLength(1);
    expect(offer).toContain("onClick={() => void confirm(copy)}>{REMADE_ACCOUNT_CONFIRM_FORGET}</button>");
    // A failure is said and the step stays: no retry in the catch.
    expect(offer).toMatch(/\} catch \{\s*setLine\(REMADE_ACCOUNT_FORGET_FAILED\);\s*\}/);
    const settlers = all.filter(([, s]) => /\bsettleForgettings\(/.test(s)).map(([f]) => f);
    expect(settlers.sort()).toEqual(["./App.tsx", "./session.ts"]);
    expect(source("./App.tsx")).toContain("void settleForgettings().catch(() => {});");
  });
});
