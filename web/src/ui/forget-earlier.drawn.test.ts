import "fake-indexeddb/auto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { createElement } from "react";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiClient } from "../api/client";
import { memoryStorage } from "../api/devicesecret";
import type { Mutation } from "../api/types";
import type { WireApi } from "../api/wireclient";
import { randomBytes } from "../crypto/provider";
import { initSodium } from "../crypto/sodium";
import type { Account } from "../vault/account";
import { SELF_IDENTITY_MISMATCH } from "../vault/accountopen";
import { openVaultCache, readWaiting } from "../vault/idbcache";
import { signIn } from "../vault/onboardflow";
import type { PinStore } from "../vault/pinstore";
import { boundAccountAt, recordSelfIdentityPub } from "../vault/selfidentity";
import { GATE_CANCEL, IDENTITY_FAULT, REMADE_ACCOUNT_CONFIRM_FORGET, REMADE_ACCOUNT_CONFIRM_TITLE, REMADE_ACCOUNT_FORGET, REMADE_ACCOUNT_FORGOTTEN, REMADE_ACCOUNT_TITLE, SIGN_IN } from "./copy";
import { buttonNamed, buttonsNamed, click, closePage, draw, type Drawn, focused, openPage, pressEnter, settle, type } from "./dom.testkit";
import { EarlierAccountOffer } from "./ForgetEarlier";
import { browserStorages, ORIGIN, pinnedStore } from "./forget-earlier.testkit";
import { FreshStart } from "./Welcome";

vi.mock("../vault/onboardflow", async (real) => ({ ...(await real<typeof import("../vault/onboardflow")>()), signIn: vi.fn() }));

/**
 * The two steps of "Forget the earlier account on this device", drawn: the offer stands under the sign-in's refusal with
 * no plate above it; neither of its buttons is a default or a submit button, and none has the focus; the Enter key never
 * passes the second step (only the person's click on its button forgets); in the sign-in form above it, Enter submits that
 * form, as it should, and the second step goes with the new try.
 */
const EMAIL = "alice@example.com";
const A = "11111111-1111-4111-8111-111111111111";
const B = "22222222-2222-4222-8222-222222222222";
const mut = (id: string): Mutation => ({ mutationId: id, op: "put", itemId: `item-${id}`, vaultId: "v1", baseItemRev: 0 });

describe("the offer to forget the earlier account, drawn", () => {
  let st: ReturnType<typeof browserStorages>;
  let drawn: Drawn | null = null;
  beforeAll(async () => {
    await initSodium();
    openPage();
  });
  afterAll(async () => {
    await closePage();
  });
  beforeEach(async () => {
    st = browserStorages();
    vi.stubGlobal(
      "fetch",
      vi.fn(() => Promise.reject(new Error("nothing may be sent"))),
    );
    recordSelfIdentityPub(A, { identityPub: randomBytes(32) } as unknown as Account, EMAIL);
    const c = await openVaultCache(A);
    await c.enqueue(mut("a-1"));
    c.close();
  });
  afterEach(async () => {
    await drawn?.unmount();
    drawn = null;
    vi.unstubAllGlobals();
    vi.mocked(signIn).mockReset();
    st.restore();
    indexedDB.deleteDatabase(`andvari-vault-${A}`);
  });

  /** Neither button is the default (a submit button), none is focused, and the offer is in no form. */
  const noDefault = (page: HTMLElement, names: string[]) => {
    for (const n of names) {
      const b = buttonNamed(page, n);
      expect(b.type, n).toBe("button");
      expect(b.closest("form"), n).toBeNull();
      // React's autoFocus focuses the element as it is drawn (no attribute is written): the focus is what tells.
      expect(focused(), n).not.toBe(b);
    }
  };

  it("two steps: neither is passed by Enter, neither button is a default, and only the click on the second forgets", async () => {
    const onDone = vi.fn();
    drawn = await draw(createElement(EarlierAccountOffer, { offer: { email: EMAIL, userId: A, sessionKept: false, served: B }, server: "Family", onKeep: () => {}, onDone }));
    const page = drawn.page;
    expect(page.textContent).toContain(REMADE_ACCOUNT_TITLE);
    expect(page.textContent).not.toContain(IDENTITY_FAULT);
    noDefault(page, [REMADE_ACCOUNT_FORGET, GATE_CANCEL]);
    // Enter on the page and on the offer itself shows nothing further.
    await pressEnter();
    await pressEnter(page.querySelector("[role=group]") as Element);
    expect(page.textContent).not.toContain(REMADE_ACCOUNT_CONFIRM_TITLE);
    // The first click shows the second step, counted then.
    await click(buttonNamed(page, REMADE_ACCOUNT_FORGET));
    expect(page.textContent).toContain(REMADE_ACCOUNT_CONFIRM_TITLE);
    noDefault(page, [REMADE_ACCOUNT_CONFIRM_FORGET, GATE_CANCEL]);
    expect(buttonsNamed(page, REMADE_ACCOUNT_FORGET)).toEqual([]);
    // Enter, wherever the focus is now, never passes it: nothing is forgotten.
    await pressEnter();
    await pressEnter(page.querySelector("[role=group]") as Element);
    expect(onDone).not.toHaveBeenCalled();
    expect(boundAccountAt(EMAIL)).toBe(A);
    expect((await readWaiting(A)).kind).toBe("read");
    // The person's click forgets.
    await click(buttonNamed(page, REMADE_ACCOUNT_CONFIRM_FORGET));
    await settle();
    expect(onDone).toHaveBeenCalledWith(REMADE_ACCOUNT_FORGOTTEN.replace("{0}", EMAIL));
    expect(boundAccountAt(EMAIL)).toBeNull();
  });

  it("at both steps the two buttons share their row equally, so a wrapped label does not make one the larger (seen in a real browser at phone width)", async () => {
    drawn = await draw(createElement(EarlierAccountOffer, { offer: { email: EMAIL, userId: A, sessionKept: false, served: B }, server: "Family", onKeep: () => {}, onDone: () => {} }));
    const page = drawn.page;
    const evenRow = (names: string[]) => {
      const rows = names.map((n) => buttonNamed(page, n).parentElement);
      expect(rows[0], names[0]).toBe(rows[1]);
      expect(rows[0]?.classList.contains("row") && rows[0]?.classList.contains("even"), names[0]).toBe(true);
    };
    evenRow([REMADE_ACCOUNT_FORGET, GATE_CANCEL]);
    await click(buttonNamed(page, REMADE_ACCOUNT_FORGET));
    expect(page.textContent).toContain(REMADE_ACCOUNT_CONFIRM_TITLE);
    evenRow([REMADE_ACCOUNT_CONFIRM_FORGET, GATE_CANCEL]);
    // The rule that makes them equal: the same height (stretched) and the same share of the row's width.
    const css = readFileSync(fileURLToPath(new URL("./styles.css", import.meta.url)), "utf8").replace(/\s+/g, " ");
    expect(css).toContain(".row.even { align-items: stretch; }");
    expect(css).toContain(".row.even > button { flex: 1 1 0; min-width: 0; }");
  });

  it("under the sign-in's refusal: the offer with no plate above it; Enter in the form above submits that form, and the second step goes with the new try", async () => {
    const pins = await pinnedStore();
    const pin = pins.pinFor(ORIGIN);
    if (pin === null) throw new Error("no pin");
    const ctx = { client: new ApiClient(ORIGIN), wire: {} as WireApi, pins: pins as PinStore, origin: ORIGIN, storage: memoryStorage() };
    vi.mocked(signIn).mockResolvedValue({ kind: "identity_fault", reason: SELF_IDENTITY_MISMATCH, servedUserId: B } as Awaited<ReturnType<typeof signIn>>);
    drawn = await draw(
      createElement(FreshStart, { ctx, policy: null, policyError: false, onRetryPolicy: async () => {}, mode: { fresh: true }, onReady: () => {}, onForget: () => {}, pin, cardNotice: null }),
    );
    const page = drawn.page;
    await click(buttonNamed(page, SIGN_IN));
    const [email, password] = [page.querySelector("input[type=email]"), page.querySelector("input[type=password]")] as HTMLInputElement[];
    await type(email as HTMLInputElement, EMAIL);
    await type(password as HTMLInputElement, "the earlier password");
    await pressEnter(password);
    expect(signIn).toHaveBeenCalledTimes(1);
    // The refusal: the offer's own lines, and no plate (the identity fault's line) anywhere above or beside it.
    expect(page.textContent).toContain(REMADE_ACCOUNT_TITLE);
    expect(page.textContent).not.toContain(IDENTITY_FAULT);
    expect(page.querySelector(".msg.err, [class*=err]")?.textContent ?? "").not.toContain(IDENTITY_FAULT);
    noDefault(page, [REMADE_ACCOUNT_FORGET]);
    // The form's own default is its Sign in button, and the offer is outside the form.
    expect(page.querySelector("form button[type=submit], form button:not([type])")?.textContent).toBe(SIGN_IN);
    await click(buttonNamed(page, REMADE_ACCOUNT_FORGET));
    expect(page.textContent).toContain(REMADE_ACCOUNT_CONFIRM_TITLE);
    noDefault(page, [REMADE_ACCOUNT_CONFIRM_FORGET]);
    // Enter in the password field submits the sign-in form (a new try), never the second step.
    await type(password as HTMLInputElement, "the earlier password");
    await pressEnter(password);
    expect(signIn).toHaveBeenCalledTimes(2);
    expect(page.textContent).not.toContain(REMADE_ACCOUNT_CONFIRM_TITLE);
    expect(page.textContent).toContain(REMADE_ACCOUNT_TITLE); // the same refusal raised the offer again, at its first step
    expect(boundAccountAt(EMAIL)).toBe(A);
    expect((await readWaiting(A)).kind).toBe("read");
  });
});
