import { createElement } from "react";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiClient } from "../api/client";
import { memoryStorage } from "../api/devicesecret";
import type { WireApi } from "../api/wireclient";
import { initSodium } from "../crypto/sodium";
import { signIn } from "../vault/onboardflow";
import type { PinStore } from "../vault/pinstore";
import { SIGN_IN } from "./copy";
import { buttonNamed, click, closePage, draw, type Drawn, openPage, pressEnter, type } from "./dom.testkit";
import { browserStorages, ORIGIN, pinnedStore } from "./forget-earlier.testkit";
import { FreshStart } from "./Welcome";

vi.mock("../vault/onboardflow", async (real) => ({ ...(await real<typeof import("../vault/onboardflow")>()), signIn: vi.fn() }));

/**
 * The sign-in form's record (tabsession.ts signInForm) lives as long as its form stays drawn: between two submits of one
 * form React keeps the same form, so the second submit names the session the first one found to replace, although the
 * first submit's start of the sign-in has bound this tab's client to a placeholder by then (a form made afresh would find
 * nothing to name). Drawn, with the person's own acts: the screen's Sign in, typing, Enter, a refusal, typing, Enter.
 */
const EMAIL = "alice@example.com";
const A = "11111111-1111-4111-8111-111111111111";

describe("the sign-in form keeps its record between two submits of one form, drawn", () => {
  let st: ReturnType<typeof browserStorages>;
  let drawn: Drawn | null = null;
  beforeAll(async () => {
    await initSodium();
    openPage();
  });
  afterAll(async () => {
    await closePage();
  });
  beforeEach(() => {
    st = browserStorages();
    vi.stubGlobal(
      "fetch",
      vi.fn(() => Promise.reject(new Error("nothing may be sent"))),
    );
  });
  afterEach(async () => {
    await drawn?.unmount();
    drawn = null;
    vi.unstubAllGlobals();
    vi.mocked(signIn).mockReset();
    st.restore();
  });

  it("a wrong password, then a second submit of the same form: both name this tab's session of A", async () => {
    const pins = await pinnedStore();
    const pin = pins.pinFor(ORIGIN);
    if (pin === null) throw new Error("no pin");
    // This tab holds A's pair (no offline copy: the pair is the tab's own), as after a lock that kept it or a session in use.
    const client = new ApiClient(ORIGIN, { accessToken: "at-A", refreshToken: "rt-A" });
    client.boundUserId = A;
    const ctx = { client, wire: {} as WireApi, pins: pins as PinStore, origin: ORIGIN, storage: memoryStorage() };
    vi.mocked(signIn).mockResolvedValue({ kind: "invalid_credentials" } as Awaited<ReturnType<typeof signIn>>);
    drawn = await draw(
      createElement(FreshStart, { ctx, policy: null, policyError: false, onRetryPolicy: async () => {}, mode: { fresh: true }, onReady: () => {}, onForget: () => {}, pin, cardNotice: null }),
    );
    const page = drawn.page;
    await click(buttonNamed(page, SIGN_IN));
    const email = page.querySelector("input[type=email]") as HTMLInputElement;
    const password = page.querySelector("input[type=password]") as HTMLInputElement;
    await type(email, EMAIL);
    await type(password, "a wrong password");
    await pressEnter(password);
    expect(signIn).toHaveBeenCalledTimes(1);
    expect(page.textContent).toContain("Wrong email or master password.");
    // The same form, still drawn: the password field was emptied by the refusal; the person types it again and submits.
    expect(page.querySelector("input[type=password]")).toBe(password);
    expect(password.value).toBe("");
    expect(client.boundUserId).not.toBe(A); // the first submit's start bound the client to its placeholder
    await type(password, "the right password");
    await pressEnter(password);
    expect(signIn).toHaveBeenCalledTimes(2);
    const named = vi.mocked(signIn).mock.calls.map((c) => c[0].replaces);
    expect(named).toEqual([
      { userId: A, refreshToken: "rt-A" },
      { userId: A, refreshToken: "rt-A" },
    ]);
  });
});
