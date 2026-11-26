import "fake-indexeddb/auto";
import { beforeAll, describe, expect, it } from "vitest";
import type { ApiClient } from "../api/client";
import { memoryStorage } from "../api/devicesecret";
import type { AccountKeysV2 } from "../api/wire";
import { fromB64Canonical } from "../crypto/trust/grammar";
import { verifyCardChain } from "../crypto/trust/instancecard";
import { vector } from "../crypto/trust/vectors";
import { initSodium } from "../crypto/sodium";
import { Account } from "./account";
import { memoryClientState } from "./accountstatesync";
import { openVaultCache } from "./idbcache";
import { openFromCopy } from "./onboardflow";
import { PinStore } from "./pinstore";
import { buildRegistration } from "./registration";
import { type ItemWire, ReadOnlyCopyError, VaultStore } from "./store";

const rec = vector("recovery.json");
const CARDS = rec.cardChains["rotated-once"].frames as string[];
const KDF = { v: 1, alg: "argon2id13", ops: 3, memBytes: 67_108_864 } as const;
const PASSWORD = "correct horse battery";

/** An account registered against a pinned origin, its keys as the server would serve them, and the pin store. */
async function registered() {
  const origin = verifyCardChain(CARDS.map((f) => fromB64Canonical(f)!)).cards[0]!.fields.origin;
  const storage = memoryStorage();
  const pins = new PinStore(storage, async () => ({ cards: CARDS, rotations: [] }), null);
  const g = await pins.begin(origin);
  if (g.kind !== "needs_trust_gate") throw new Error(g.kind);
  pins.confirmTrustGate(g.ticket);
  const pin = pins.pinFor(origin)!;
  const reg = await buildRegistration({
    email: "alice@example.com", displayName: "Alice", password: PASSWORD, kdfParams: KDF, signupTicket: "t", pin, ageConfirmed: true,
    device: { platform: "web", name: "x", deviceSecret: "A".repeat(43) }, nowMs: 1_763_164_800_000,
  });
  const r = reg.request;
  const keys: AccountKeysV2 = { kdfSalt: r.kdfSalt, kdfParams: r.kdfParams, wrappedUvk: r.wrappedUvk, encryptedIdentitySeed: r.encryptedIdentitySeed, identityPub: r.identityPub, recoveryConfirmed: true, personalWrap: r.personalWrap, genesis: r.genesis };
  return { origin, pins, pin, userId: reg.userId, keys, storage };
}

describe("the offline copy (spec 02 §8, design §4.4)", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("the cache keeps the post-cut-over keys with their genesis; a copy without one never displaces it", async () => {
    const { keys } = await registered();
    const c = await openVaultCache("copy-user");
    expect(await c.setAccountKeysV2(keys)).toBe(true);
    expect(await c.setAccountKeysV2({ ...keys, genesis: null })).toBe(false);
    expect(await c.setAccountKeysV2({ ...keys, kdfParams: { ...KDF, memBytes: 1024 } })).toBe(false);
    expect(await c.accountKeysV2()).toEqual(keys);
    await c.clearAccountKeys();
    expect(await c.accountKeysV2()).toBeNull();
    c.close();
  }, 120_000);

  it("opens offline with openAccount's checks, and under a forked pin too; nothing is fetched", async () => {
    const { origin, pins, userId, keys } = await registered();
    const opened = await openFromCopy({ keys, pins, origin, userId, password: PASSWORD, knownIdentityPub: null });
    expect(opened.kind).toBe("opened");
    expect((await openFromCopy({ keys, pins, origin, userId, password: "not it", knownIdentityPub: null })).kind).toBe("wrong_password");
    expect((await openFromCopy({ keys: null, pins, origin, userId, password: PASSWORD, knownIdentityPub: null })).kind).toBe("no_copy");
    // The genesis is checked: the copy of another account does not open as this one.
    const other = await registered();
    expect((await openFromCopy({ keys: other.keys, pins, origin, userId, password: PASSWORD, knownIdentityPub: null })).kind).not.toBe("opened");
    // A forked pin stops traffic, not reading.
    const forked = { state: () => ({ kind: "forked", pin: pins.pinFor(origin)! }) } as unknown as PinStore;
    expect((await openFromCopy({ keys, pins: forked, origin, userId, password: PASSWORD, knownIdentityPub: null })).kind).toBe("opened");
    // A damaged pin checks nothing, so it opens nothing.
    const damaged = { state: () => ({ kind: "damaged" }) } as unknown as PinStore;
    expect((await openFromCopy({ keys, pins: damaged, origin, userId, password: PASSWORD, knownIdentityPub: null })).kind).toBe("no_copy");
  }, 240_000);

  it("a copy read under a fork sends nothing, accepts nothing and writes nothing", async () => {
    const { origin, pins, userId, keys } = await registered();
    const o = await openFromCopy({ keys, pins, origin, userId, password: PASSWORD, knownIdentityPub: null });
    if (o.kind !== "opened") throw new Error(o.kind);
    const calls: string[] = [];
    const spy = new Proxy({}, { get: (_t, p) => async () => { calls.push(String(p)); throw new Error("sent"); } });
    const store = new VaultStore(spy as ApiClient, Account.fromOpened(o.opened, keys), undefined, memoryClientState(), spy as ItemWire);
    store.freezeAsReadOnlyCopy();
    expect(store.isReadOnlyCopy()).toBe(true);
    await store.sync();
    await expect(store.save(null, { type: "note", name: "n" })).rejects.toBeInstanceOf(ReadOnlyCopyError);
    await expect(store.remove("x")).rejects.toBeInstanceOf(ReadOnlyCopyError);
    await expect(store.importDocs([{ itemId: "i", doc: { type: "note", name: "n" } }])).rejects.toBeInstanceOf(ReadOnlyCopyError);
    await expect(store.leaveSharedVault("v")).rejects.toBeInstanceOf(Error);
    await expect(store.listDeleted()).rejects.toBeInstanceOf(ReadOnlyCopyError);
    expect(calls).toEqual([]);
  }, 120_000);
});
