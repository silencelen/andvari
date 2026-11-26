import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { initSodium } from "../crypto/sodium";
import type { Account } from "../vault/account";
import { signIn } from "../vault/onboardflow";
import { deleteAccount } from "../vault/settingsflow";
import { SessionWrap } from "../vault/sessionwrap";
import { boundAccountAt, dismissRemembered, recordSelfIdentityPub, rememberedNotices } from "../vault/selfidentity";
import { confirmLines, earlierOfferFor } from "../ui/ForgetEarlier";
import { mapStorage } from "../ui/forget-earlier.testkit";
import { type TabLocks, useTabLocks, webLockRegistry } from "../ui/weblocks.testkit";
import { knownIdentity } from "../ui/opensession";
import { earlierCopyOf, forgetEarlierAccount, wipeLocalAccountState } from "../ui/session";
import { Browser } from "./browser";
import { journeysUnavailable, TestInstance } from "./harness";
import { HOOK } from "./wait";

/**
 * Journey 21: "Forget the earlier account on this device" (decided on 2026-11-17) over the real server. An account is
 * made in one browser, and a second browser signs in to it. The account is deleted from the first browser and made again
 * there under the same address. The second browser, which still knows the earlier account under the address, is refused
 * with both possibilities and the offer; it forgets behind both steps, signs in to the new account, and is told once that
 * it now remembers the new account.
 *
 * Each browser's own storage (localStorage, sessionStorage) is put in place while that browser acts, as each tab has its
 * own profile. The flows are the ones the screens call; the two buttons are the person's clicks, which this harness has
 * no page to make: the first step is the offer the refusal raises, the second is what its confirmation says, counted then,
 * and the forgetting is called with exactly that.
 */
const skip = journeysUnavailable();
if (skip) console.warn(skip);

const EMAIL = "remade@example.org";
const P1 = "first correct Horse 4 battery";
const P2 = "second correct Horse 5 staple";

type Profile = { local: Storage; tab: Storage; locks: TabLocks };
const profile = (): Profile => ({ local: mapStorage(), tab: mapStorage(), locks: webLockRegistry().tab() });
async function as<T>(p: Profile, run: () => Promise<T>): Promise<T> {
  const g = globalThis as Record<string, unknown>;
  const had = { local: Object.getOwnPropertyDescriptor(g, "localStorage"), tab: Object.getOwnPropertyDescriptor(g, "sessionStorage") };
  Object.defineProperty(g, "localStorage", { value: p.local, configurable: true });
  Object.defineProperty(g, "sessionStorage", { value: p.tab, configurable: true });
  const unlock = useTabLocks(p.locks);
  try {
    return await run();
  } finally {
    unlock();
    if (had.local) Object.defineProperty(g, "localStorage", had.local);
    else delete g.localStorage;
    if (had.tab) Object.defineProperty(g, "sessionStorage", had.tab);
    else delete g.sessionStorage;
  }
}
const asAccount = (pub: Uint8Array) => ({ identityPub: pub }) as unknown as Account;

describe.skipIf(skip !== null)("journey 21: a browser that knew an account deleted elsewhere and made again forgets it and takes the new one", () => {
  let inst: TestInstance;

  beforeAll(async () => {
    await initSodium();
    inst = await TestInstance.start({ kind: "private", mode: "open" });
  }, HOOK.start);

  afterAll(async () => {
    await inst?.stop();
  }, HOOK.stop);

  it("refused with both possibilities, forgotten behind both steps, signed in to the new account, told once", async () => {
    const one = profile();
    const two = profile();
    const first = new Browser(inst, "Firefox on Linux");
    const second = new Browser(inst, "Chrome on Windows");

    // The account is made in the first browser, which keeps its record as the app does when the vault opens.
    const made = await as(one, async () => {
      const s = await first.signUp(EMAIL, P1);
      recordSelfIdentityPub(s.opened.userId, asAccount(s.opened.identity.publicKey), EMAIL);
      return s;
    });
    const earlier = made.opened.userId;

    // The second browser signs in to it: its record now ties the address to that account.
    await as(two, async () => {
      await second.settle();
      const r = await signIn({ wire: second.wire, pins: second.pins, origin: second.origin, email: EMAIL, password: P1, deviceName: second.deviceName, session: null, knownIdentityPub: knownIdentity(EMAIL) });
      expect(r.kind).toBe("opened");
      if (r.kind !== "opened") return;
      recordSelfIdentityPub(r.session.userId, asAccount(r.opened.identity.publicKey), EMAIL);
      await second.signOut();
      expect(boundAccountAt(EMAIL)).toBe(earlier);
    });

    // The first browser deletes the account, forgets it as the app does after a confirmed deletion, and makes it again.
    const remade = await as(one, async () => {
      const done = await deleteAccount(first.settings(made.opened, EMAIL, new SessionWrap(made.wrap)), { typedEmail: EMAIL, password: P1, verifiedState: () => null, nowMs: inst.now() });
      expect(done.kind).toBe("deleted");
      await wipeLocalAccountState(earlier, EMAIL);
      expect(boundAccountAt(EMAIL)).toBeNull();
      const again = await new Browser(inst, "Firefox on Linux", first.storage).signUp(EMAIL, P2);
      expect(again.opened.userId).not.toBe(earlier);
      return again;
    });

    await as(two, async () => {
      // Refused on this browser's own record, with the offer naming the earlier account.
      const refused = await signIn({ wire: second.wire, pins: second.pins, origin: second.origin, email: EMAIL, password: P2, deviceName: second.deviceName, session: null, knownIdentityPub: knownIdentity(EMAIL) });
      expect(refused).toEqual({ kind: "identity_fault", reason: "self_identity_mismatch", servedUserId: remade.opened.userId });
      await second.signOut(); // the screens end the session the refused sign-in was given (abandonSignIn)
      const offer = refused.kind === "identity_fault" ? earlierOfferFor(EMAIL, refused.reason, refused.servedUserId) : null;
      expect(offer).toEqual({ email: EMAIL, userId: earlier, sessionKept: false, served: remade.opened.userId });
      if (offer === null) return;
      // The second step, as its confirmation says it: no copy is kept here (a browser without the offline copy).
      const shown = await earlierCopyOf(offer.userId);
      expect(shown).toEqual({ kept: false, unsent: 0, held: 0 });
      expect(confirmLines(offer.email, shown)).toHaveLength(2);
      // Nothing is sent by the forgetting itself.
      const fetchSpy = vi.spyOn(globalThis, "fetch");
      try {
        expect(await forgetEarlierAccount(offer.email, offer.userId, shown, offer.served)).toEqual({ kind: "forgotten" });
        expect(fetchSpy).not.toHaveBeenCalled();
      } finally {
        fetchSpy.mockRestore();
      }
      expect(boundAccountAt(EMAIL)).toBeNull();
      expect(rememberedNotices()).toEqual([]);

      // The address is new to this browser: the sign-in opens the new account, and the notice is raised once.
      const back = await signIn({ wire: second.wire, pins: second.pins, origin: second.origin, email: EMAIL, password: P2, deviceName: second.deviceName, session: null, knownIdentityPub: knownIdentity(EMAIL) });
      expect(back.kind).toBe("opened");
      if (back.kind !== "opened") return;
      expect(back.session.userId).toBe(remade.opened.userId);
      recordSelfIdentityPub(back.session.userId, asAccount(back.opened.identity.publicKey), EMAIL);
      expect(boundAccountAt(EMAIL)).toBe(remade.opened.userId);
      expect(rememberedNotices()).toEqual([EMAIL]);
      dismissRemembered(EMAIL);
      expect(rememberedNotices()).toEqual([]);
      await second.signOut();
    });
  }, 480_000);
});
