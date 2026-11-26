import "fake-indexeddb/auto";
import { readFileSync } from "node:fs";
import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { initSodium } from "../crypto/sodium";
import { kitDisplayForm } from "../crypto/trust/recoverykit";
import type { Account } from "../vault/account";
import { parseKitInput, verifyKit } from "../vault/kitflow";
import { completeSignup, signIn } from "../vault/onboardflow";
import type { PinStore } from "../vault/pinstore";
import { boundAccountAt, dismissRemembered, recordSelfIdentityPub, rememberedNotices } from "../vault/selfidentity";
import { browserStorages, KDF, ORIGIN, pinnedStore, RemakeServer } from "./forget-earlier.testkit";
import { knownIdentity } from "./opensession";
import { earlierCopyOf, forgetEarlierAccount, saveSession, wipeLocalAccountState } from "./session";

/**
 * After the forgetting (decided on 2026-11-17): the next sign-in, registration or recovery under the address is taken as
 * in a browser that never knew it, and the person is told once that this browser now remembers the new account, by a
 * notice kept until dismissed, also across a reload, a lock and a closed tab in between.
 */
const EMAIL = "alice@example.com";
const PASSWORD = "alice correct horse 1";
const src = (f: string) => readFileSync(new URL(f, import.meta.url), "utf8");
const asAccount = (pub: Uint8Array) => ({ identityPub: pub }) as unknown as Account;

describe("after the forgetting", () => {
  let st: ReturnType<typeof browserStorages>;
  let pins: PinStore;
  let server: RemakeServer;
  beforeAll(async () => {
    await initSodium();
  });
  beforeEach(async () => {
    st = browserStorages();
    pins = await pinnedStore();
    server = new RemakeServer();
  });
  afterEach(() => st.restore());

  async function forgottenAfterRemake() {
    const first = await server.remake(pins, EMAIL, PASSWORD);
    recordSelfIdentityPub(first.userId, asAccount(first.identityPub), EMAIL);
    const again = await server.remake(pins, EMAIL, PASSWORD);
    const refused = await signIn({ wire: server, pins, origin: ORIGIN, email: EMAIL, password: PASSWORD, deviceName: "x", session: null, knownIdentityPub: knownIdentity(EMAIL) });
    expect(refused.kind).toBe("identity_fault");
    expect(await forgetEarlierAccount(EMAIL, first.userId, await earlierCopyOf(first.userId), again.userId)).toEqual({ kind: "forgotten" });
    return { first, again };
  }

  it("the next sign-in is taken as on a browser that never knew the address, and the notice is raised when its account is kept, once", async () => {
    const { again } = await forgottenAfterRemake();
    expect(rememberedNotices()).toEqual([]); // nothing to say until the next account is taken
    const r = await signIn({ wire: server, pins, origin: ORIGIN, email: EMAIL, password: PASSWORD, deviceName: "x", session: null, knownIdentityPub: knownIdentity(EMAIL) });
    expect(r.kind).toBe("opened");
    if (r.kind !== "opened") return;
    expect(r.session.userId).toBe(again.userId);
    // enterVault keeps the session and records the account (opensession.ts): the address now names the new account.
    recordSelfIdentityPub(r.session.userId, asAccount(r.opened.identity.publicKey), EMAIL);
    expect(boundAccountAt(EMAIL)).toBe(again.userId);
    expect(rememberedNotices()).toEqual([EMAIL]);
    // Kept at rest until dismissed (a reload reads it again), and never raised again for this forgetting.
    expect(JSON.parse(st.local.getItem("andvari.rememberedNew")!)).toEqual([EMAIL]);
    dismissRemembered(EMAIL);
    expect(rememberedNotices()).toEqual([]);
    expect(st.local.getItem("andvari.rememberNext")).toBeNull();
  }, 120_000);

  it("the mark for the notice outlives what happens before the next sign-in: it is at rest from the forgetting on", async () => {
    await forgottenAfterRemake();
    expect(JSON.parse(st.local.getItem("andvari.rememberNext")!)).toEqual([EMAIL]);
    // A lock or a closed tab keeps localStorage as it is; a sign-out of another account does not touch it either.
    saveSession({ baseUrl: "", userId: "33333333-3333-4333-8333-333333333333", personalVaultId: "", email: "bob@example.com", tokens: null });
    expect(JSON.parse(st.local.getItem("andvari.rememberNext")!)).toEqual([EMAIL]);
  }, 120_000);

  it("the next registration under the address is made, and the next recovery with the kit is taken", async () => {
    const { again } = await forgottenAfterRemake();
    const kit = parseKitInput(kitDisplayForm(again.recoverySecret), EMAIL);
    if (kit.kind !== "typed") throw new Error("parse");
    expect((await verifyKit({ wire: server, pins, origin: ORIGIN, input: kit, knownIdentityPub: (u, em) => knownIdentity(em)(u) })).kind).toBe("verified");
    const r = await completeSignup({ wire: server, pins, origin: ORIGIN, pin: pins.pinFor(ORIGIN)!, policy: { kdfParams: KDF } as never, email: EMAIL, displayName: "A", password: PASSWORD, signupTicket: "ticket", ageConfirmed: true, deviceName: "x", nowMs: 1763164800000, boundHere: boundAccountAt });
    expect(r.kind).toBe("registered");
  }, 120_000);

  it("the notice goes with an account's deletion under the address", async () => {
    const { again } = await forgottenAfterRemake();
    recordSelfIdentityPub(again.userId, asAccount(again.identityPub), EMAIL);
    expect(rememberedNotices()).toEqual([EMAIL]);
    await wipeLocalAccountState(again.userId, EMAIL);
    expect(rememberedNotices()).toEqual([]);
  }, 120_000);

  it("the notice is drawn above every screen with its dismiss, and refreshed when a session is kept", () => {
    const app = src("./App.tsx");
    expect(app).toContain("const [remembered, setRemembered] = useState<string[]>(() => rememberedNotices());");
    expect(app).toContain("<span>{fill(REMADE_ACCOUNT_REMEMBERED, e)}</span>");
    expect(app).toMatch(/dismissRemembered\(e\);\s*setRemembered\(rememberedNotices\(\)\);/);
    const unlocked = app.slice(app.indexOf("const onUnlocked = "), app.indexOf("const onUnlocked = ") + 1500);
    expect(unlocked).toContain("setRemembered(rememberedNotices());");
  });

  it("after forgotten the sign-in stands at its password step: a refusal never keeps the two-step code's field", () => {
    const welcome = src("./Welcome.tsx");
    const signIn = welcome.slice(welcome.indexOf("function SignIn("), welcome.indexOf("function Unlock("));
    // Only the server's ask for the code keeps the password; every other answer, the identity fault included, empties the
    // password and the code and takes the code's field away, so "try again" starts at the password.
    expect(signIn.match(/keepPassword = true;/g)).toHaveLength(1);
    expect(signIn).toMatch(/case "totp_required":\s*keepPassword = true;/);
    expect(signIn).toMatch(/if \(!keepPassword\) \{\s*setPassword\(""\);\s*setTotp\(""\);\s*setNeedTotp\(false\);/);
  });
});
