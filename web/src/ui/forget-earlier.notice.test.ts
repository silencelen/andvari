import "fake-indexeddb/auto";
import { readFileSync } from "node:fs";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { randomBytes } from "../crypto/provider";
import { initSodium } from "../crypto/sodium";
import type { Account } from "../vault/account";
import { forgettingMarks, recordSelfIdentityPub, rememberedNotices } from "../vault/selfidentity";
import { browserStorages } from "./forget-earlier.testkit";
import { earlierCopyOf, forgetEarlierAccount, settleForgettings } from "./session";

/**
 * The notice "this browser now remembers the new account" after a forgetting: said once also where the forgetting was
 * stopped part-way and finished only after the next account under the address was taken, and drawn in a tab that is
 * already open when another tab raises it.
 */
const EMAIL = "alice@example.com";
const A = "11111111-1111-4111-8111-111111111111";
const B = "22222222-2222-4222-8222-222222222222";
const asAccount = () => ({ identityPub: randomBytes(32) }) as unknown as Account;

describe("the notice after a forgetting", () => {
  let st: ReturnType<typeof browserStorages>;
  beforeAll(async () => {
    await initSodium();
  });
  beforeEach(() => {
    st = browserStorages();
    vi.stubGlobal("fetch", vi.fn(() => Promise.reject(new Error("nothing may be sent"))));
    recordSelfIdentityPub(A, asAccount(), EMAIL);
    st.local.setItem(`andvari.current.${A}`, "x");
  });
  afterEach(() => {
    vi.unstubAllGlobals();
    st.restore();
  });

  it("a forgetting stopped after its first removal, the next account taken, then the forgetting finished: the notice is said once, nothing left waiting", async () => {
    const shown = await earlierCopyOf(A);
    const real = st.local.removeItem.bind(st.local);
    st.local.removeItem = (k: string) => {
      if (k === `andvari.current.${A}`) throw new Error("store failed");
      real(k);
    };
    await expect(forgetEarlierAccount(EMAIL, A, shown, B)).rejects.toThrow("store failed");
    st.local.removeItem = real;
    // The next account under the address is taken before the forgetting is finished: its record is written.
    recordSelfIdentityPub(B, asAccount(), EMAIL);
    expect(rememberedNotices()).toEqual([]);
    await settleForgettings();
    expect(forgettingMarks()).toEqual([]);
    expect(rememberedNotices()).toEqual([EMAIL]);
    expect(st.local.getItem("andvari.rememberNext")).toBeNull();
  });

  it("an open tab redraws the notices when another tab raises or dismisses one", () => {
    const app = readFileSync(new URL("./App.tsx", import.meta.url), "utf8");
    expect(app).toMatch(/if \(e\.key === null \|\| e\.key === REMEMBERED_NOTICES_KEY\) setRemembered\(rememberedNotices\(\)\);/);
    expect(app).toContain('window.addEventListener("storage", onNoticesChanged);');
  });
});
