import "fake-indexeddb/auto";
import { IDBFactory as FakeIDBFactory } from "fake-indexeddb";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { AccountKeys, KdfParams } from "../api/types";
import { AUTO_LOCK_MAX_SECONDS, CLIPBOARD_CLEAR_MAX_SECONDS } from "../api/types";
import { openVaultCache, vaultDbName } from "../vault/idbcache";
import { clampAutoLockSeconds, clampClipboardClearSeconds } from "./policyclamp";
import {
  applyOrgOfflineCachePolicy,
  setOfflineCopyEnabled,
  shouldOfferCacheNudge,
  webCacheEnabled,
} from "./session";
import { resolveAutoLockSeconds } from "./useAutoLock";

/**
 * POLICY-MONOTONICITY suite (design 2026-07-15-multi-tenant-endpoints §2.3 + §5.4): the
 * `ClientPolicy` object arrives from an UNAUTHENTICATED endpoint on an untrusted server, so every
 * client-floor field must be structurally incapable of relaxing the client — *a hostile server may
 * always make the client safer, never laxer*. Pinned here, in one place, so a refactor that lets
 * any lax direction through trips a named monotonicity test:
 *
 *  - `offlineCacheAllowed=true` alone NEVER enables the durable cache (necessary, not sufficient —
 *    per-device consent §5.4.1 is the other half), on any origin;
 *  - `offlineCacheAllowed=false` ALWAYS wipes + pins, beating every device-level consent;
 *  - oversized/zero/garbage timers clamp into their windows (B1-1) — a server can neither disable
 *    auto-lock nor pin the clipboard;
 *  - the B2-11 nudge never advertises what policy forbids.
 */

const g = globalThis as { indexedDB?: IDBFactory; window?: { location: { origin: string } } };

const UID = "user-mono";
const OPT_IN = `andvari.cacheOptIn.${UID}`;

const ORIGINS = [
  "https://andvari.example.net", // the old "private ⇒ trusted" shapes…
  "http://192.168.1.9",
  "http://localhost:5173",
  "https://andvari.monahanhosting.com", // …and the public/reference shape: all identical now
  "https://self-hosted.example.org",
];

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

const kdf = (): KdfParams => ({ v: 1, alg: "argon2id13", ops: 3, memBytes: 67_108_864 });
const keys = (): AccountKeys => ({
  kdfSalt: "c2FsdA",
  kdfParams: kdf(),
  wrappedUvk: "wrap",
  encryptedIdentitySeed: "seed",
  identityPub: "pub",
  escrowFingerprint: "fp",
});

async function seedCache(userId = UID): Promise<void> {
  const cache = await openVaultCache(userId);
  await cache.setAccountKeys(keys());
  cache.close();
}

async function dbExists(userId: string): Promise<boolean> {
  const list = await (g.indexedDB as unknown as { databases: () => Promise<{ name?: string }[]> }).databases();
  return list.some((d) => d.name === vaultDbName(userId));
}

beforeEach(() => {
  g.indexedDB = new FakeIDBFactory() as unknown as IDBFactory;
  vi.stubGlobal("localStorage", fakeStorage());
});

afterEach(() => {
  vi.unstubAllGlobals();
  delete g.window;
});

describe("offlineCacheAllowed=true is NECESSARY, never SUFFICIENT (§2.3 tighten-only, §5.4.1 consent)", () => {
  it("a hostile 'allowed: true' alone never enables the durable cache — no consent, no cache, on ANY origin", async () => {
    for (const origin of ORIGINS) {
      g.window = { location: { origin } };
      await applyOrgOfflineCachePolicy(true, UID); // the most generous thing a server can declare
      expect(webCacheEnabled(UID), origin).toBe(false); // …moves nothing without the device's own opt-in
      expect(await dbExists(UID)).toBe(false); // and creates nothing
    }
  });

  it("'allowed: true' + this user's consent is the ONLY enabling conjunction", async () => {
    await applyOrgOfflineCachePolicy(true, UID);
    localStorage.setItem(OPT_IN, "1");
    expect(webCacheEnabled(UID)).toBe(true);
  });

  it("the gate is origin-independent — identical answer under every origin stub (no hostname sniffing left)", () => {
    localStorage.setItem(OPT_IN, "1");
    const answers = ORIGINS.map((origin) => {
      g.window = { location: { origin } };
      return webCacheEnabled(UID);
    });
    expect(answers).toEqual(ORIGINS.map(() => true));
  });
});

describe("offlineCacheAllowed=false ALWAYS wipes its own namespace + pins (§2.3 CLIENT-FLOOR row)", () => {
  it("wipes the standing cache and closes the gate — beating an explicit per-device opt-in", async () => {
    localStorage.setItem(OPT_IN, "1"); // fully consented device
    await seedCache();
    expect(await dbExists(UID)).toBe(true);

    await applyOrgOfflineCachePolicy(false, UID);

    expect(await dbExists(UID)).toBe(false); // the wipe is unconditional (server-initiated, §E.4)
    expect(webCacheEnabled(UID)).toBe(false); // consent notwithstanding
  });

  it("the false-pin outlives the fetch: user consent gestures cannot reopen the gate while pinned", async () => {
    await applyOrgOfflineCachePolicy(false, UID);
    await setOfflineCopyEnabled(UID, true); // the user flips the toggle ON anyway
    expect(webCacheEnabled(UID)).toBe(false); // org pin still wins (§E.4 precedence)
  });

  it("flapping true→false→true never leaves the cache enabled without consent", async () => {
    await applyOrgOfflineCachePolicy(true, UID);
    await applyOrgOfflineCachePolicy(false, UID);
    await applyOrgOfflineCachePolicy(true, UID); // a hostile server toggling its declaration
    expect(webCacheEnabled(UID)).toBe(false); // still needs the device's own opt-in
  });
});

describe("B2-11 nudge monotonicity — never advertises what policy forbids", () => {
  it("no nudge while the org pin is down, even on a never-asked device", async () => {
    await applyOrgOfflineCachePolicy(false, null);
    expect(shouldOfferCacheNudge(UID)).toBe(false);
  });

  it("the nudge is exactly the unanswered-consent state: allowed + no markers", async () => {
    await applyOrgOfflineCachePolicy(true, null);
    expect(shouldOfferCacheNudge(UID)).toBe(true);
    localStorage.setItem(OPT_IN, "1"); // answered yes
    expect(shouldOfferCacheNudge(UID)).toBe(false);
  });
});

describe("timer clamps (§2.3, B1-1) — a server can neither disable auto-lock nor pin the clipboard", () => {
  it("clampAutoLockSeconds: 0/absent/garbage/oversized all land at the ceiling; in-range passes", () => {
    // "never lock" lies → the ceiling (never 0/disabled):
    expect(clampAutoLockSeconds(0)).toBe(AUTO_LOCK_MAX_SECONDS);
    expect(clampAutoLockSeconds(-5)).toBe(AUTO_LOCK_MAX_SECONDS);
    expect(clampAutoLockSeconds(undefined)).toBe(AUTO_LOCK_MAX_SECONDS);
    expect(clampAutoLockSeconds(null)).toBe(AUTO_LOCK_MAX_SECONDS);
    expect(clampAutoLockSeconds(Number.NaN)).toBe(AUTO_LOCK_MAX_SECONDS);
    expect(clampAutoLockSeconds(Number.POSITIVE_INFINITY)).toBe(AUTO_LOCK_MAX_SECONDS);
    // oversized → clamped DOWN:
    expect(clampAutoLockSeconds(86_400)).toBe(AUTO_LOCK_MAX_SECONDS);
    expect(clampAutoLockSeconds(AUTO_LOCK_MAX_SECONDS + 1)).toBe(AUTO_LOCK_MAX_SECONDS);
    // in-range (safer-than-ceiling) passes through — the server may tighten, never loosen:
    expect(clampAutoLockSeconds(300)).toBe(300);
    expect(clampAutoLockSeconds(1)).toBe(1);
    expect(clampAutoLockSeconds(AUTO_LOCK_MAX_SECONDS)).toBe(AUTO_LOCK_MAX_SECONDS);
  });

  it("clampClipboardClearSeconds: [1, ceiling] — garbage wipes FAST, oversized clamps down", () => {
    expect(clampClipboardClearSeconds(0)).toBe(1);
    expect(clampClipboardClearSeconds(-10)).toBe(1);
    expect(clampClipboardClearSeconds(Number.NaN)).toBe(1);
    expect(clampClipboardClearSeconds(undefined)).toBe(1);
    expect(clampClipboardClearSeconds(3_600)).toBe(CLIPBOARD_CLEAR_MAX_SECONDS); // "pin the clipboard for an hour" → 300 s
    expect(clampClipboardClearSeconds(Number.POSITIVE_INFINITY)).toBe(1); // non-finite is garbage, not "huge"
    expect(clampClipboardClearSeconds(30)).toBe(30); // the wire default passes untouched
    expect(clampClipboardClearSeconds(CLIPBOARD_CLEAR_MAX_SECONDS)).toBe(CLIPBOARD_CLEAR_MAX_SECONDS);
  });

  it("resolveAutoLockSeconds end-to-end: no server input — fetched, persisted, or missing — yields a disabled lock", () => {
    expect(resolveAutoLockSeconds(0, null).seconds).toBe(AUTO_LOCK_MAX_SECONDS); // declared "never lock"
    expect(resolveAutoLockSeconds(86_400, null).seconds).toBe(AUTO_LOCK_MAX_SECONDS); // declared huge
    expect(resolveAutoLockSeconds(null, 0).seconds).toBe(AUTO_LOCK_MAX_SECONDS); // stale pre-clamp persisted 0
    expect(resolveAutoLockSeconds(null, null).seconds).toBe(AUTO_LOCK_MAX_SECONDS); // policy route 404s — still locked
    // …and every resolved value is in (0, ceiling]:
    for (const fetched of [0, 1, 60, 300, 900, 901, 86_400, -1, Number.NaN]) {
      const { seconds } = resolveAutoLockSeconds(fetched, null);
      expect(seconds).toBeGreaterThan(0);
      expect(seconds).toBeLessThanOrEqual(AUTO_LOCK_MAX_SECONDS);
    }
  });
});
