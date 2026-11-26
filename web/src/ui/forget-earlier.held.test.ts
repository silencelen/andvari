import "fake-indexeddb/auto";
import { readFileSync } from "node:fs";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import type { Mutation } from "../api/types";
import { initSodium } from "../crypto/sodium";
import type { Account } from "../vault/account";
import { openVaultCache } from "../vault/idbcache";
import { recordSelfIdentityPub } from "../vault/selfidentity";
import {
  fill,
  REMADE_ACCOUNT_CONFIRM,
  REMADE_ACCOUNT_CONFIRM_ALWAYS,
  REMADE_ACCOUNT_CONFIRM_COPY_ALL_SENT,
  REMADE_ACCOUNT_CONFIRM_COPY_CANNOT_TELL,
  REMADE_ACCOUNT_CONFIRM_COPY_ONE_UNSENT,
  REMADE_ACCOUNT_CONFIRM_COPY_UNSENT,
  REMADE_ACCOUNT_CONFIRM_HELD_CANNOT_TELL,
  REMADE_ACCOUNT_CONFIRM_HELD_ONE_UNSENT,
  REMADE_ACCOUNT_CONFIRM_HELD_UNSENT,
} from "./copy";
import { confirmLines } from "./ForgetEarlier";
import { browserStorages } from "./forget-earlier.testkit";
import { earlierCopyOf, forgetEarlierAccount, heldSharedChanges } from "./session";

/**
 * Changes to shared vaults that the earlier account signed in this browser and that are held, not known to be stored
 * (kept by the shared-vault code at rest, outside the copy, and kept across a sign-out), go with the forgetting: the
 * second confirmation counts them, or says that it cannot tell; never "every change was sent" over a held one, and never
 * silence where one is held.
 */
const EMAIL = "alice@example.com";
const A = "11111111-1111-4111-8111-111111111111";
const B = "22222222-2222-4222-8222-222222222222";
const V1 = "33333333-3333-4333-8333-333333333333";
const V2 = "44444444-4444-4444-8444-444444444444";
const mut = (id: string): Mutation => ({ mutationId: id, op: "put", itemId: `item-${id}`, vaultId: "v1", baseItemRev: 0 });
const src = (f: string) => readFileSync(new URL(f, import.meta.url), "utf8");

describe("held changes to shared vaults in the second confirmation", () => {
  let st: ReturnType<typeof browserStorages>;
  beforeAll(async () => {
    await initSodium();
  });
  beforeEach(() => {
    st = browserStorages();
    vi.stubGlobal("fetch", vi.fn(() => Promise.reject(new Error("nothing may be sent"))));
    recordSelfIdentityPub(A, { identityPub: new Uint8Array(32).fill(1) } as unknown as Account, EMAIL);
  });
  afterEach(() => {
    vi.unstubAllGlobals();
    st.restore();
    indexedDB.deleteDatabase(`andvari-vault-${A}`);
  });

  /** A held record as the shared-vault code keeps it (logstore.ts savePending): one per vault, and the vault in the index. */
  const hold = (vaultId: string, known: { acked?: true; notStored?: true } = {}) => {
    st.local.setItem(`andvari.log2.${A}.${vaultId}.pending`, JSON.stringify({ vaultId, frame: "AAAA", heldAt: 1, ...known }));
    const index = new Set((st.local.getItem(`andvari.log2.${A}.pending-index`) ?? "").split(",").filter((x) => x !== ""));
    index.add(vaultId);
    st.local.setItem(`andvari.log2.${A}.pending-index`, [...index].sort().join(","));
  };
  const lineOf = async () => confirmLines(EMAIL, await earlierCopyOf(A));

  it("with no copy kept: the held changes the server said it did not store are counted in a line of their own", async () => {
    hold(V1, { notStored: true });
    expect(await earlierCopyOf(A)).toEqual({ kept: false, unsent: 0, held: 1 });
    expect(await lineOf()).toEqual([fill(REMADE_ACCOUNT_CONFIRM, EMAIL), REMADE_ACCOUNT_CONFIRM_HELD_ONE_UNSENT, REMADE_ACCOUNT_CONFIRM_ALWAYS]);
    hold(V2, { notStored: true });
    expect((await lineOf())[1]).toBe(fill(REMADE_ACCOUNT_CONFIRM_HELD_UNSENT, EMAIL, "2"));
  });

  it("with no copy kept: a held change that may have reached the server (its answer lost) makes the line say it cannot tell", async () => {
    hold(V1, { notStored: true });
    hold(V2);
    expect(heldSharedChanges(A)).toBeNull();
    expect((await lineOf())[1]).toBe(REMADE_ACCOUNT_CONFIRM_HELD_CANNOT_TELL);
  });

  it("a change kept at rest for a frozen vault is not counted: the freeze dropped it, and it is never sent", async () => {
    hold(V1, { notStored: true });
    hold(V2);
    st.local.setItem(`andvari.log2.${A}.${V2}.flag`, "frozen:2");
    expect(heldSharedChanges(A)).toBe(1);
    st.local.setItem(`andvari.log2.${A}.${V1}.flag`, "frozen:5");
    expect(heldSharedChanges(A)).toBe(0);
    expect(await lineOf()).toEqual([fill(REMADE_ACCOUNT_CONFIRM, EMAIL), REMADE_ACCOUNT_CONFIRM_ALWAYS]);
  });

  it("with an empty copy kept: never 'every change was sent' over a held change", async () => {
    (await openVaultCache(A)).close();
    expect((await lineOf())[1]).toBe(REMADE_ACCOUNT_CONFIRM_COPY_ALL_SENT); // nothing held: as before
    hold(V1);
    expect((await lineOf())[1]).toBe(REMADE_ACCOUNT_CONFIRM_COPY_CANNOT_TELL);
    st.local.setItem(`andvari.log2.${A}.${V1}.pending`, JSON.stringify({ vaultId: V1, frame: "AAAA", notStored: true }));
    expect((await lineOf())[1]).toBe(REMADE_ACCOUNT_CONFIRM_COPY_ONE_UNSENT);
  });

  it("with a copy that waits to send: its count and the held changes together", async () => {
    const c = await openVaultCache(A);
    await c.enqueue(mut("1"));
    await c.enqueue(mut("2"));
    c.close();
    hold(V1, { notStored: true });
    hold(V2, { notStored: true });
    expect(await earlierCopyOf(A)).toEqual({ kept: true, unsent: 2, held: 2 });
    expect((await lineOf())[1]).toBe(fill(REMADE_ACCOUNT_CONFIRM_COPY_UNSENT, EMAIL, "4"));
  });

  it("a change the server's answer said it stored is not counted; an index naming no record holds nothing; a record that cannot be read cannot be told", async () => {
    hold(V1, { acked: true });
    st.local.setItem(`andvari.log2.${A}.pending-index`, `${V1},${V2}`);
    expect(heldSharedChanges(A)).toBe(0);
    expect(await lineOf()).toEqual([fill(REMADE_ACCOUNT_CONFIRM, EMAIL), REMADE_ACCOUNT_CONFIRM_ALWAYS]);
    st.local.setItem(`andvari.log2.${A}.${V2}.pending`, "{not json");
    expect(heldSharedChanges(A)).toBeNull();
    // Another account's held change is never this account's.
    st.local.removeItem(`andvari.log2.${A}.${V2}.pending`);
    st.local.setItem(`andvari.log2.${B}.${V2}.pending`, JSON.stringify({ vaultId: V2, frame: "AAAA" }));
    expect(heldSharedChanges(A)).toBe(0);
  });

  it("a held change that appeared after the confirmation was shown: nothing removed, the confirmation shown again with it; then the forgetting removes them with their index", async () => {
    const shown = await earlierCopyOf(A);
    hold(V1, { notStored: true });
    expect(await forgetEarlierAccount(EMAIL, A, shown, B)).toEqual({ kind: "not_confirmed", copy: { kept: false, unsent: 0, held: 1 } });
    expect(st.local.getItem(`andvari.log2.${A}.${V1}.pending`)).not.toBeNull();
    expect(await forgetEarlierAccount(EMAIL, A, await earlierCopyOf(A), B)).toEqual({ kind: "forgotten" });
    expect(st.local.getItem(`andvari.log2.${A}.${V1}.pending`)).toBeNull();
    expect(st.local.getItem(`andvari.log2.${A}.pending-index`)).toBeNull();
  });

  it("the records are read as the shared-vault code writes them", () => {
    const logs = src("../vault/logstore.ts");
    expect(logs).toContain("return `andvari.log2.${this.me}.${vaultId}.${part}`;");
    expect(logs).toContain('this.storage.set(this.k(vaultId, "pending"), JSON.stringify(p));');
    expect(logs).toContain("return `andvari.log2.${this.me}.pending-index`;");
    expect(logs).toContain("readonly acked?: true;");
    expect(logs).toContain("readonly notStored?: true;");
    expect(logs).toContain("readonly frame: string;");
  });
});
