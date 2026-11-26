import "fake-indexeddb/auto";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import type { AccountKeys } from "../api/types";
import { boxKeypairFromSeed, randomBytes, signKeypairFromSeed } from "../crypto/provider";
import { initSodium } from "../crypto/sodium";
import { Account } from "../vault/account";
import { openVaultCache } from "../vault/idbcache";
import type { SettingsSession } from "../vault/settingsflow";
import { READ_ONLY_COPY_REFUSED, ReadOnlyCopyError } from "../vault/store";
import { KIT_ROTATE_SESSION_ENDED, KIT_ROTATE_TITLE, KIT_ROTATE_WRONG_PASSWORD } from "./copy";
import { RotateKitCard } from "./KitCard";
import { kitRotateText } from "./reauthtext";
import { cachedPendingWraps, keepPendingWraps, rekeyCachedAccountKeys, setOfflineCopyEnabled } from "./session";

const here = (p: string) => fileURLToPath(new URL(p, import.meta.url));
const spanBetween = (s: string, from: string, to: string): string => s.slice(s.indexOf(from), s.indexOf(to, s.indexOf(from)));
const UID = "user-kit-password";

function fakeStorage(): Storage {
  const m = new Map<string, string>();
  return {
    get length() {
      return m.size;
    },
    clear: () => m.clear(),
    getItem: (k: string) => m.get(k) ?? null,
    key: (i: number) => [...m.keys()][i] ?? null,
    removeItem: (k: string) => void m.delete(k),
    setItem: (k: string, v: string) => void m.set(k, v),
  } as Storage;
}

const KDF = { v: 1, alg: "argon2id13", ops: 2, memBytes: 67_108_864 } as const;

describe("Settings: the kit card and the password change's own keys", () => {
  beforeAll(async () => {
    await initSodium();
  });
  beforeEach(() => {
    vi.stubGlobal("localStorage", fakeStorage());
  });
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("the kit card asks for the password and rotates through the one re-authentication path", () => {
    const pin = { origin: "https://vault.example", name: "", card0Hash: "a".repeat(64) };
    const settings = { pins: { pinFor: () => pin }, origin: pin.origin, account: "me@example.org" } as unknown as SettingsSession;
    const html = renderToStaticMarkup(createElement(RotateKitCard, { settings }));
    expect(html).toContain(KIT_ROTATE_TITLE);
    expect(html).toContain("Make a new recovery kit");
    expect(html).toContain('type="password"');
    // No pin, no kit: the kit names the pinned instance.
    expect(renderToStaticMarkup(createElement(RotateKitCard, { settings: { ...settings, pins: { pinFor: () => null } } as unknown as SettingsSession }))).toBe("");
    // The card is on Settings, beside the other settingsflow cards; KitGate lives with the card, not in Welcome.
    const settingsTsx = readFileSync(here("./Settings.tsx"), "utf8");
    expect(settingsTsx).toContain("<RotateKitCard settings={settings} />");
    const kitTsx = readFileSync(here("./KitCard.tsx"), "utf8");
    expect(kitTsx).toContain("rotateKitFor(settings, password)");
    expect(readFileSync(here("./Welcome.tsx"), "utf8")).not.toContain("function KitGate(");
    expect(kitRotateText({ kind: "wrong_password" })).toBe(KIT_ROTATE_WRONG_PASSWORD);
  });

  it("the sentences the design gives no wording for are defined in copy.ts under their mark (a placeholder or approved wording)", () => {
    // The kit-rotation refusals come from copy.ts, each under its own mark; reauthtext.ts holds no sentence of its own.
    expect(kitRotateText({ kind: "wrong_password" })).toBe(KIT_ROTATE_WRONG_PASSWORD);
    expect(kitRotateText({ kind: "session_ended" })).toBe(KIT_ROTATE_SESSION_ENDED);
    const copyTs = readFileSync(here("./copy.ts"), "utf8");
    for (const name of ["KIT_ROTATE_WRONG_PASSWORD", "KIT_ROTATE_SESSION_ENDED", "KIT_ROTATE_UNKNOWN"]) {
      expect(copyTs).toMatch(new RegExp(`/\\*\\* (?:PLACEHOLDER|Approved wording \\(decided on [0-9-]+\\)): [^\\n]*\\*/\\nexport const ${name} = `));
    }
    const kitText = spanBetween(readFileSync(here("./reauthtext.ts"), "utf8"), "export function kitRotateText(", "\n}\n");
    expect(kitText).not.toMatch(/return "/);
    // The read-only copy's refusal (vault/store.ts) is marked the same way, and is what the error says.
    const storeTs = readFileSync(here("../vault/store.ts"), "utf8");
    expect(storeTs).toMatch(/\/\*\*\n \* (?:PLACEHOLDER |Approved wording \(decided on [0-9-]+\): )[^]*?\*\/\nexport const READ_ONLY_COPY_REFUSED = /);
    expect(new ReadOnlyCopyError().message).toBe(READ_ONLY_COPY_REFUSED);
  });

  it("a password change rekeys the offline copy from the change's own keys, without a fetch", async () => {
    await setOfflineCopyEnabled(UID, true);
    const before: AccountKeys = { kdfSalt: "b2xk", kdfParams: KDF, wrappedUvk: "b2xkLXdyYXA", encryptedIdentitySeed: "c2VlZA", identityPub: "cHVi", escrowFingerprint: "" };
    let cache = await openVaultCache(UID);
    await cache.setAccountKeys(before);
    cache.close();
    await rekeyCachedAccountKeys(UID, { kdfSalt: "bmV3", kdfParams: KDF, wrappedUvk: "bmV3LXdyYXA" });
    cache = await openVaultCache(UID);
    const after = await cache.accountKeys();
    cache.close();
    expect(after).toMatchObject({ kdfSalt: "bmV3", wrappedUvk: "bmV3LXdyYXA", encryptedIdentitySeed: "c2VlZA", identityPub: "cHVi" });
  });

  it("the pending wraps are kept beside the copy, settled by the re-key, and a failed write says failed", async () => {
    await setOfflineCopyEnabled(UID, true);
    const before: AccountKeys = { kdfSalt: "b2xk", kdfParams: KDF, wrappedUvk: "b2xkLXdyYXA", encryptedIdentitySeed: "c2VlZA", identityPub: "cHVi", escrowFingerprint: "" };
    const cache = await openVaultCache(UID);
    await cache.setAccountKeys(before);
    cache.close();
    // A kept wrap outside the KDF fence reads as none (the floor is checked where it is read, as for the copy's keys).
    expect(await keepPendingWraps(UID, [{ kdfSalt: "d2Vhaw", kdfParams: { ...KDF, ops: 1 }, wrappedUvk: "d2Vhaw" }])).toBe("written");
    expect(await cachedPendingWraps(UID)).toEqual([]);
    const FENCED = { ...KDF, ops: 3 };
    const p1 = { kdfSalt: "cDE", kdfParams: FENCED, wrappedUvk: "cDEtd3JhcA" };
    const p2 = { kdfSalt: "cDI", kdfParams: FENCED, wrappedUvk: "cDItd3JhcA" };
    expect(await keepPendingWraps(UID, [p1, p2])).toBe("written");
    expect(await cachedPendingWraps(UID)).toEqual([p1, p2]);
    expect(await keepPendingWraps(UID, [p1])).toBe("written");
    expect(await cachedPendingWraps(UID)).toEqual([p1]);
    expect(await rekeyCachedAccountKeys(UID, p1, [])).toBe("written");
    expect(await cachedPendingWraps(UID)).toEqual([]);
    // With the copy off there is nothing to keep, and nothing is said to have failed.
    await setOfflineCopyEnabled(UID, false);
    expect(await keepPendingWraps(UID, [p2])).toBe("none");
    expect(await rekeyCachedAccountKeys(UID, p2)).toBe("none");
    // A cache that refuses the write: never swallowed.
    const refusing = async () => {
      const c = await openVaultCache(`${UID}-refusing`);
      await c.setAccountKeys(before);
      return Object.assign(Object.create(c) as typeof c, { setAccountKeys: async () => false, setAccountKeysV2: async () => false, setPendingWraps: async () => false, close: () => c.close() });
    };
    expect(await rekeyCachedAccountKeys(UID, p1, [], refusing)).toBe("failed");
    expect(await keepPendingWraps(UID, [p1], refusing)).toBe("failed");
    expect(await rekeyCachedAccountKeys(UID, p1, [], async () => { throw new Error("IndexedDB is gone"); })).toBe("failed");
  });

  it("the session's wrap follows the change, so a later in-session proof runs under the new password's wrap", () => {
    const seed = randomBytes(32);
    const old = { kdfSalt: "b2xk", kdfParams: KDF, wrappedUvk: "b2xkLXdyYXA" };
    const next = { kdfSalt: "bmV3", kdfParams: KDF, wrappedUvk: "bmV3LXdyYXA" };
    const a = Account.fromOpened({ userId: UID, uvk: randomBytes(32), identity: boxKeypairFromSeed(seed), signing: signKeypairFromSeed(seed), genesis: null as never, personalVaultId: null, personalVk: null }, old);
    expect(a.sessionWrap.current).toEqual(old);
    a.sessionWrap.beginChange(next);
    expect(a.sessionWrap.pending).toEqual(next);
    a.sessionWrap.changeMade(next);
    expect(a.sessionWrap.current).toEqual(next);
    expect(a.sessionWrap.pending).toBeNull();
  });
});
