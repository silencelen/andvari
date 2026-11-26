import "fake-indexeddb/auto";
import { readFileSync } from "node:fs";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { toB64 } from "../crypto/bytes";
import { randomBytes } from "../crypto/provider";
import { initSodium } from "../crypto/sodium";
import type { Account } from "../vault/account";
import { IDENTITY_PUB_MISMATCH, NO_GENESIS, SEED_UNOPENABLE, SELF_IDENTITY_MISMATCH, UVK_DAMAGED } from "../vault/accountopen";
import type { Mutation } from "../api/types";
import { openVaultCache } from "../vault/idbcache";
import { signIn } from "../vault/onboardflow";
import type { PinStore } from "../vault/pinstore";
import { recordSelfIdentityPub } from "../vault/selfidentity";
import {
  fill,
  GATE_CANCEL,
  REMADE_ACCOUNT_CONFIRM,
  REMADE_ACCOUNT_CONFIRM_ALWAYS,
  REMADE_ACCOUNT_CONFIRM_COPY_ALL_SENT,
  REMADE_ACCOUNT_CONFIRM_COPY_CANNOT_TELL,
  REMADE_ACCOUNT_CONFIRM_COPY_ONE_UNSENT,
  REMADE_ACCOUNT_CONFIRM_COPY_UNSENT,
  REMADE_ACCOUNT_FORGET,
  REMADE_ACCOUNT_FORGET_ACCOUNT_OPEN,
  REMADE_ACCOUNT_HOW_TO_TELL,
  REMADE_ACCOUNT_IF_REMADE,
  REMADE_ACCOUNT_IF_SERVER,
  REMADE_ACCOUNT_REFUSAL,
  REMADE_ACCOUNT_TITLE,
} from "./copy";
import { confirmLines, EarlierAccountOffer, earlierOfferFor } from "./ForgetEarlier";
import { browserStorages, ORIGIN, pinnedStore, RemakeServer } from "./forget-earlier.testkit";
import { knownIdentity } from "./opensession";
import { earlierCopyOf, saveSession, unsentChangeCount } from "./session";

/**
 * The refusal says both possibilities and offers "Forget the earlier account on this device" (decided on 2026-11-17),
 * only where the refusal is this browser's own record of the address. Lines are named by their exported names.
 */
const EMAIL = "alice@example.com";
const A = "11111111-1111-4111-8111-111111111111";
const B = "22222222-2222-4222-8222-222222222222";
const src = (f: string) => readFileSync(new URL(f, import.meta.url), "utf8");
const mut = (id: string): Mutation => ({ mutationId: id, op: "put", itemId: `item-${id}`, vaultId: "v1", baseItemRev: 0 });
const esc = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#x27;");

describe("the offer: only on this browser's own record of the address", () => {
  let st: ReturnType<typeof browserStorages>;
  beforeAll(async () => {
    await initSodium();
  });
  beforeEach(() => {
    st = browserStorages();
  });
  afterEach(() => st.restore());
  const bind = (userId: string, pub = randomBytes(32)) => {
    recordSelfIdentityPub(userId, { identityPub: pub } as unknown as Account, EMAIL);
    return pub;
  };

  it("is made for self_identity_mismatch where the address's record names an account, and for nothing else", () => {
    bind(A);
    expect(earlierOfferFor(" Alice@Example.com ", SELF_IDENTITY_MISMATCH, B)).toEqual({ email: EMAIL, userId: A, sessionKept: false, served: B });
    expect(earlierOfferFor(EMAIL, SELF_IDENTITY_MISMATCH, "new")).toEqual({ email: EMAIL, userId: A, sessionKept: false, served: "new" }); // a registration
    for (const other of [IDENTITY_PUB_MISMATCH, NO_GENESIS, SEED_UNOPENABLE, UVK_DAMAGED, "uvk_unopenable", "bad_frame", "identity_mismatch", "genesis_bad_signature"]) {
      expect(earlierOfferFor(EMAIL, other, B), other).toBeNull();
    }
    expect(earlierOfferFor("bob@example.com", SELF_IDENTITY_MISMATCH, B)).toBeNull(); // no record names that address
    expect(earlierOfferFor("not an address", SELF_IDENTITY_MISMATCH, B)).toBeNull();
    expect(earlierOfferFor(EMAIL, SELF_IDENTITY_MISMATCH, undefined)).toBeNull(); // the account met is not known
  });

  it("is not made for the same account under another identity key: never a remade account, and what the record exists to stop", () => {
    bind(A);
    expect(earlierOfferFor(EMAIL, SELF_IDENTITY_MISMATCH, A)).toBeNull();
  });

  it("is not made where the browser's two records disagree (a record that disagrees with itself)", () => {
    bind(A);
    st.local.setItem(`andvari.selfIdentityPub.${A}`, toB64(randomBytes(32)));
    expect(earlierOfferFor(EMAIL, SELF_IDENTITY_MISMATCH, B)).toBeNull();
  });

  it("names the earlier account as kept where the browser keeps that account's session, so that its sign-out comes first", () => {
    bind(A);
    saveSession({ baseUrl: "", userId: A, personalVaultId: "", email: EMAIL, tokens: null });
    expect(earlierOfferFor(EMAIL, SELF_IDENTITY_MISMATCH, B)?.sessionKept).toBe(true);
    saveSession({ baseUrl: "", userId: B, personalVaultId: "", email: EMAIL, tokens: null });
    expect(earlierOfferFor(EMAIL, SELF_IDENTITY_MISMATCH, B)?.sessionKept).toBe(false);
  });

  it("a sign-in that meets the remembered account under another identity key is refused with no offer", async () => {
    const pins: PinStore = await pinnedStore();
    const server = new RemakeServer();
    const first = await server.remake(pins, EMAIL, "pw one two three");
    // This browser remembers the same account with another key (the server swapped the account's identity seed).
    recordSelfIdentityPub(first.userId, { identityPub: randomBytes(32) } as unknown as Account, EMAIL);
    const r = await signIn({ wire: server, pins, origin: ORIGIN, email: EMAIL, password: "pw one two three", deviceName: "x", session: null, knownIdentityPub: knownIdentity(EMAIL) });
    expect(r).toEqual({ kind: "identity_fault", reason: SELF_IDENTITY_MISMATCH, servedUserId: first.userId });
    if (r.kind !== "identity_fault") return;
    expect(earlierOfferFor(EMAIL, r.reason, r.servedUserId)).toBeNull();
  }, 60_000);

  it("a sign-in to the account made again under the address is refused with the offer naming the earlier account", async () => {
    const pins: PinStore = await pinnedStore();
    const server = new RemakeServer();
    const first = await server.remake(pins, EMAIL, "pw one two three");
    recordSelfIdentityPub(first.userId, { identityPub: first.identityPub } as unknown as Account, EMAIL);
    await server.remake(pins, EMAIL, "pw one two three");
    const r = await signIn({ wire: server, pins, origin: ORIGIN, email: EMAIL, password: "pw one two three", deviceName: "x", session: null, knownIdentityPub: knownIdentity(EMAIL) });
    expect(r.kind).toBe("identity_fault");
    if (r.kind !== "identity_fault") return;
    expect(earlierOfferFor(EMAIL, r.reason, r.servedUserId)).toEqual({ email: EMAIL, userId: first.userId, sessionKept: false, served: r.servedUserId });
  }, 60_000);

  it("is raised at the sign-in, the unlock (for another account than the session's only), the registration and the kit check, and nowhere else", () => {
    const welcome = src("./Welcome.tsx");
    expect(welcome.match(/earlierOfferFor\(/g)).toHaveLength(1);
    expect(welcome.match(/identityRefusal\(/g)).toHaveLength(3);
    expect(welcome).toContain("const f = identityRefusal(email, r.reason, r.servedUserId);"); // the sign-in
    expect(welcome).toContain('const o = earlierOfferFor(email, r.reason, "new");'); // the registration, refused before anything is sent
    expect(welcome).toContain("const f = identityRefusal(step.email, r.reason, r.servedUserId);"); // the kit check
    expect(welcome).toContain("const f = identityRefusal(session.email, SELF_IDENTITY_MISMATCH, session.userId);"); // the unlock
    // Drawn only from that state, and outside every form: Enter in a form's field never reaches it.
    expect(welcome.match(/<EarlierAccountOffer /g)).toHaveLength(4);
    expect(welcome.match(/<\/form>\s*\{earlier && <EarlierAccountOffer /g)).toHaveLength(4);
  });
});

describe("what the offer says", () => {
  let st: ReturnType<typeof browserStorages>;
  beforeEach(() => {
    st = browserStorages();
  });
  afterEach(() => st.restore());

  it("the refusal, the two possibilities each in a sentence of its own, how to tell, then the button and Cancel alike", () => {
    const html = renderToStaticMarkup(createElement(EarlierAccountOffer, { offer: { email: EMAIL, userId: A, sessionKept: false, served: B }, server: "Family", onKeep: () => {}, onDone: () => {} }));
    const order = [REMADE_ACCOUNT_TITLE, fill(REMADE_ACCOUNT_REFUSAL, EMAIL, "Family"), REMADE_ACCOUNT_IF_REMADE, REMADE_ACCOUNT_IF_SERVER, REMADE_ACCOUNT_HOW_TO_TELL, REMADE_ACCOUNT_FORGET, GATE_CANCEL].map((l) => html.indexOf(esc(l)));
    expect(order.every((i) => i > -1)).toBe(true);
    expect([...order].sort((a, b) => a - b)).toEqual(order);
    expect(html).toContain(`<p>${esc(REMADE_ACCOUNT_IF_REMADE)}</p><p>${esc(REMADE_ACCOUNT_IF_SERVER)}</p>`);
    const buttons = [...html.matchAll(/<button([^>]*)>([^<]*)<\/button>/g)];
    expect(buttons.map((b) => b[2])).toEqual([esc(REMADE_ACCOUNT_FORGET), esc(GATE_CANCEL)]);
    for (const [, attrs] of buttons) {
      expect(attrs).toContain('type="button"');
      expect(attrs).toContain('class="secondary"');
      expect(attrs).not.toMatch(/autofocus|primary/i);
    }
  });

  it("where the browser keeps the earlier account's session: the same refusal and possibilities, no button, and its sign-out first", () => {
    const html = renderToStaticMarkup(createElement(EarlierAccountOffer, { offer: { email: EMAIL, userId: A, sessionKept: true, served: B }, server: "Family", onKeep: () => {}, onDone: () => {} }));
    expect(html).toContain(esc(REMADE_ACCOUNT_IF_REMADE));
    expect(html).toContain(esc(REMADE_ACCOUNT_IF_SERVER));
    expect(html).toContain(esc(REMADE_ACCOUNT_FORGET_ACCOUNT_OPEN));
    expect(html).not.toContain("<button");
  });

  it("the second confirmation: what goes, the copy with its count where one is kept, and always that it cannot be undone", () => {
    expect(confirmLines(EMAIL, { kept: false, unsent: 0, held: 0 })).toEqual([fill(REMADE_ACCOUNT_CONFIRM, EMAIL), REMADE_ACCOUNT_CONFIRM_ALWAYS]);
    expect(confirmLines(EMAIL, { kept: true, unsent: null, held: 0 })[1]).toBe(REMADE_ACCOUNT_CONFIRM_COPY_CANNOT_TELL);
    expect(confirmLines(EMAIL, { kept: true, unsent: 0, held: 0 })[1]).toBe(REMADE_ACCOUNT_CONFIRM_COPY_ALL_SENT);
    expect(confirmLines(EMAIL, { kept: true, unsent: 1, held: 0 })[1]).toBe(REMADE_ACCOUNT_CONFIRM_COPY_ONE_UNSENT);
    expect(confirmLines(EMAIL, { kept: true, unsent: 3, held: 0 })).toEqual([fill(REMADE_ACCOUNT_CONFIRM, EMAIL), fill(REMADE_ACCOUNT_CONFIRM_COPY_UNSENT, EMAIL, "3"), REMADE_ACCOUNT_CONFIRM_ALWAYS]);
  });

  it("the copy is counted as a sign-out counts it: none, a copy with what waits in it, and a copy that cannot be read", async () => {
    expect(await earlierCopyOf(A)).toEqual({ kept: false, unsent: 0, held: 0 });
    const c = await openVaultCache(A);
    await c.enqueue(mut("1"));
    await c.enqueue(mut("2"));
    c.close();
    expect(await earlierCopyOf(A)).toEqual({ kept: true, unsent: 2, held: 0 });
    expect((await earlierCopyOf(A)).unsent).toBe(await unsentChangeCount(A));
    // A copy whose owner record is not this account cannot be read: kept, and "cannot tell".
    const d = await openVaultCache(B);
    d.close();
    const req = indexedDB.open(`andvari-vault-${B}`);
    await new Promise<void>((resolve, reject) => {
      req.onsuccess = () => {
        const db = req.result;
        const tx = db.transaction("kv", "readwrite");
        tx.objectStore("kv").put({ key: "userId", value: A });
        tx.oncomplete = () => {
          db.close();
          resolve();
        };
        tx.onerror = () => reject(tx.error);
      };
      req.onerror = () => reject(req.error);
    });
    expect(await earlierCopyOf(B)).toEqual({ kept: true, unsent: null, held: 0 });
  });
});
