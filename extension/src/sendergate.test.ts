// node --test. Security review 2026-10, branch A14 (F3, F4, F11): the service worker answered
// popup-only messages from content scripts. `cardItems` listed every card (merchant-named items,
// masked last-4) to any frame; `enrollQuickUnlock` let a page-side context replace the user's PIN
// and later redeem it with `unlockWithPin`; `unlock` / `unlockTotp` signed the extension into an
// account the page chose (login CSRF: the user's next saves land in that account). The scattered
// per-handler checks are kept; the fix is ONE structural gate in dispatch: a message type content
// scripts do not send needs an extension-page sender, judged by `sender.url` — never by
// `sender.tab === undefined`, which is false for the options page (a real tab) and the biometric
// connector window.
//
// The leaf (sendergate.ts) is chrome-free; the wiring pins at the bottom hold background.ts to it
// (background.ts is not node-importable).
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { CONTENT_SENT, EXTENSION_ONLY, SENDER_CLASS, senderGate, senderMaySend } from "./sendergate.ts";

/** The answer a refused message gets, or the PASS marker when the gate lets it through. */
const PASS = Symbol("pass");
function answerFor(type: string, sender: { url?: string }, base: string): unknown {
  const v = senderGate(type, sender, base);
  return v.refused ? v.answer : PASS;
}

const CHROME_BASE = "chrome-extension://abcdefghijklmnopabcdefghijklmnop/";
const FIREFOX_BASE = "moz-extension://6b3f2c1e-0d4a-4e8b-9c7d-1a2b3c4d5e6f/";

/** What a content script's message carries: the WEB page's URL, a tab, a frame, the page origin. */
const contentSender = { url: "https://bank.example/login", tab: { id: 7 }, frameId: 0, origin: "https://bank.example" };

/** Independent oracle: each extension-page-only type's refusal, written out by hand. Every one is
 *  that message's existing refusal or empty shape — never a throw, never data. */
const EXPECTED_REFUSAL: Record<string, unknown> = {
  status: {
    unlocked: false,
    count: 0,
    email: null,
    mustChangePassword: false,
    lockNotice: null,
    quickUnlock: { enrolled: false, armed: false, attemptsRemaining: 0, offerDismissed: false, kind: null },
    totpPending: null,
    personalChange: false,
    personalChangeText: null,
    personalProposal: false,
    waitingGrants: 0,
    wrongVault: 0,
    rememberedEmail: null,
  },
  personalAcceptChange: { ok: false, code: "not_allowed" },
  personalDescribeChange: { ok: false, code: "not_allowed" },
  unlock: { ok: false, code: "aborted" },
  unlockTotp: { ok: false, code: "aborted" },
  cancelTotp: { ok: false },
  lock: { ok: false },
  signOut: { ok: false },
  unlockWithPin: { ok: false, code: "aborted" },
  enrollQuickUnlock: { ok: false, code: "need_full_unlock" },
  unlockWithBio: { ok: false, code: "aborted" },
  enrollQuickUnlockBio: { ok: false, code: "need_full_unlock" },
  disableQuickUnlock: { ok: false },
  dismissQuickUnlockOffer: { ok: false },
  purgeServerData: { ok: false },
  ping: { ok: false },
  allItems: { locked: true, items: [] },
  reuseNotice: null,
  cardItems: { locked: true, items: [] },
  fillFromPopup: { ok: false, code: "not_allowed", error: "not allowed from a page" },
  revealCardField: { ok: false, error: "not allowed from a page" },
  linkUri: { ok: false, error: "not allowed from a page" },
  totp: { ok: false },
  setTotp: { ok: false, code: "not_allowed", error: "popup only" },
  updateStatus: { current: "", latest: null, chromeUrl: null, firefoxUrl: null, quietReason: null },
  cardFillOffers: { fillable: false, origin: null, crossOriginFormsOnly: false },
  fillCardFromPopup: { ok: false, code: "not_allowed", error: "not allowed from a page" },
  serverInfo: { url: "", legacy: null, trustedStore: false },
  setServerUrl: { ok: false, code: "not_allowed" },
  forgetLegacyServer: { ok: false },
};

test("every extension-page-only type is refused from a content script, with its own refusal shape", () => {
  assert.deepEqual([...EXTENSION_ONLY].sort(), Object.keys(EXPECTED_REFUSAL).sort(), "the oracle covers exactly the gated set");
  for (const type of EXTENSION_ONLY) {
    for (const base of [CHROME_BASE, FIREFOX_BASE]) {
      const r = answerFor(type, contentSender, base);
      assert.notEqual(r, PASS, `${type} must be refused from a content script`);
      assert.deepEqual(r, EXPECTED_REFUSAL[type], `${type}: the refusal is that message's own empty shape`);
      assert.equal(senderMaySend(type, contentSender, base), false, type);
    }
  }
});

test("the gated set includes every session, quick-unlock and card-inventory message", () => {
  for (const type of [
    "unlock", "unlockTotp", "cancelTotp", "unlockWithPin", "enrollQuickUnlock", "unlockWithBio",
    "enrollQuickUnlockBio", "disableQuickUnlock", "dismissQuickUnlockOffer", "lock", "signOut", "cardItems",
    // No content script asks for status, so its email never reaches a page frame.
    "status",
  ]) {
    assert.equal(SENDER_CLASS[type as keyof typeof SENDER_CLASS], "extension", `${type} must be extension-page-only`);
  }
});

// A15: the server choice used to be written to chrome.storage.local by the options page and adopted by the worker
// through storage.onChanged, so a content script that wrote that key repointed the extension past this gate. The
// worker now takes the choice only as a message, and only from our own pages.
test("A15: setServerUrl (and the server-info pair) are extension-page-only — a content script is refused", () => {
  for (const type of ["setServerUrl", "serverInfo", "forgetLegacyServer"]) {
    assert.equal(SENDER_CLASS[type as keyof typeof SENDER_CLASS], "extension", `${type} must be extension-page-only`);
    for (const base of [CHROME_BASE, FIREFOX_BASE]) assert.equal(senderMaySend(type, contentSender, base), false, type);
  }
  assert.deepEqual(answerFor("setServerUrl", contentSender, CHROME_BASE), { ok: false, code: "not_allowed" });
  assert.deepEqual(answerFor("setServerUrl", contentSender, FIREFOX_BASE), { ok: false, code: "not_allowed" });
  // Even a content script inside a frame of our own vault origin, or claiming an extension-looking origin, is a page.
  for (const sender of [
    { url: "https://andvari.monahanhosting.com/#/options", tab: { id: 3 } },
    { url: `https://x.example/${CHROME_BASE}options.html`, tab: { id: 3 } },
  ]) {
    assert.deepEqual(answerFor("setServerUrl", sender, CHROME_BASE), { ok: false, code: "not_allowed" }, sender.url);
  }
  assert.equal(answerFor("setServerUrl", { url: `${CHROME_BASE}options.html`, tab: { id: 12 } }, CHROME_BASE), PASS, "the options tab passes");
});

test("a sender with no url, another extension's url or a look-alike prefix is not an extension page", () => {
  const notOurs = [
    {},
    { url: undefined, tab: { id: 1 } },
    { url: "" },
    { url: "chrome-extension://otherextensionidotherextensionid/popup.html" },
    { url: CHROME_BASE.slice(0, -1) + "x/popup.html" }, // same id plus one character
    { url: "https://abcdefghijklmnopabcdefghijklmnop/popup.html" },
    { url: "about:blank" },
  ];
  for (const sender of notOurs) {
    assert.notEqual(answerFor("unlock", sender, CHROME_BASE), PASS, JSON.stringify(sender));
    assert.notEqual(answerFor("cardItems", sender, CHROME_BASE), PASS, JSON.stringify(sender));
  }
});

test("our own pages pass for every type: the popup, the options page (a real tab) and the connector window", () => {
  const pages = [
    { url: `${CHROME_BASE}popup.html` },
    { url: `${CHROME_BASE}options.html`, tab: { id: 12 } }, // options_ui open_in_tab: sender.tab is SET
    { url: `${CHROME_BASE}connector.html`, tab: { id: 13 } }, // windows.create({type:"popup"}) is a tab too
  ];
  for (const sender of pages) {
    for (const type of Object.keys(SENDER_CLASS)) {
      assert.equal(answerFor(type, sender, CHROME_BASE), PASS, `${type} from ${sender.url}`);
      assert.equal(senderMaySend(type, sender, CHROME_BASE), true);
    }
  }
});

test("Firefox: a moz-extension:// page passes the same check, and a page script still does not", () => {
  for (const type of Object.keys(SENDER_CLASS)) {
    assert.equal(answerFor(type, { url: `${FIREFOX_BASE}popup.html` }, FIREFOX_BASE), PASS, type);
  }
  assert.notEqual(answerFor("enrollQuickUnlock", contentSender, FIREFOX_BASE), PASS);
  // A Chrome page URL is not this Firefox extension's page, and vice versa.
  assert.notEqual(answerFor("unlock", { url: `${CHROME_BASE}popup.html` }, FIREFOX_BASE), PASS);
  assert.notEqual(answerFor("unlock", { url: `${FIREFOX_BASE}popup.html` }, CHROME_BASE), PASS);
});

test("the types content scripts send still pass from a content script", () => {
  for (const type of CONTENT_SENT) assert.equal(answerFor(type, contentSender, CHROME_BASE), PASS, type);
});

test("an unknown type is refused from a content script; a malformed extension base fails closed", () => {
  assert.deepEqual(answerFor("toString", contentSender, CHROME_BASE), { ok: false });
  assert.deepEqual(answerFor("noSuchMessage", contentSender, CHROME_BASE), { ok: false });
  for (const base of ["", "/", "https://example.org/", "chrome-extension://", "chrome-extension://abc"]) {
    assert.notEqual(answerFor("unlock", { url: `${base}popup.html` }, base), PASS, `base ${JSON.stringify(base)}`);
    assert.notEqual(answerFor("unlock", { url: "https://example.org/x" }, base), PASS);
  }
});

test("each refusal is a fresh object, so nothing a caller does to one answer leaks into the next", () => {
  const a = answerFor("cardItems", contentSender, CHROME_BASE) as { items: unknown[] };
  a.items.push("poison");
  assert.deepEqual(answerFor("cardItems", contentSender, CHROME_BASE), { locked: true, items: [] });
});

// ---- classification is complete and derived from the code, not from memory ----

const src = (f: string) => readFileSync(new URL(`./${f}`, import.meta.url), "utf-8");

test("every message type in messages.ts is classified as content-sent or extension-page-only", () => {
  const msgs = src("messages.ts");
  const start = msgs.indexOf("export type Req =");
  const end = msgs.indexOf("export type Res<", start);
  assert.ok(start > -1 && end > start, "the Req union is where it was");
  const declared = new Set([...msgs.slice(start, end).matchAll(/\|\s*\{\s*type:\s*"([A-Za-z]+)"/g)].map((m) => m[1]!));
  assert.ok(declared.size >= 40, `parsed ${declared.size} Req types — did the union's shape change?`);
  const classified = new Set(Object.keys(SENDER_CLASS));
  for (const t of declared) assert.ok(classified.has(t), `messages.ts declares "${t}" but sendergate.ts does not classify it`);
  for (const t of classified) assert.ok(declared.has(t), `sendergate.ts classifies "${t}", which messages.ts no longer declares`);
});

test("the content-sent set is exactly what content.ts and the modules it imports send", () => {
  // The content bundle's import closure, read from source (type-only imports included: harmless).
  const seen = new Set<string>();
  const queue = ["content.ts"];
  while (queue.length > 0) {
    const f = queue.pop()!;
    if (seen.has(f)) continue;
    seen.add(f);
    for (const m of src(f).matchAll(/from\s+"\.\/([^"]+)"/g)) queue.push(m[1]!.endsWith(".ts") ? m[1]! : `${m[1]}.ts`);
  }
  assert.ok(seen.has("content-ui.ts") && seen.has("detect.ts") && seen.has("cardfill.ts"), "the closure reached the content modules");
  const sent = new Set<string>();
  for (const f of seen) {
    for (const m of src(f).matchAll(/\b(?:safeSend|send|sendMessage)\(\s*\{\s*type:\s*"([A-Za-z]+)"/g)) sent.add(m[1]!);
  }
  assert.ok(sent.size >= 15, `found only ${sent.size} content sends — did the send helper move?`);
  assert.deepEqual([...sent].sort(), [...CONTENT_SENT].sort(), "classify a new content-side send, and gate a type content no longer sends");
});

// ---- wiring: background.ts runs the gate before any handler ----

const bg = src("background.ts");

test("dispatch runs the sender gate first, against this extension's own base URL", () => {
  const head = bg.slice(bg.indexOf("async function dispatch("), bg.indexOf("switch (msg.type) {", bg.indexOf("async function dispatch(")));
  assert.ok(head.length > 0, "dispatch is where it was");
  assert.ok(head.includes("const gate = senderGate(msg.type, sender, EXTENSION_BASE);"), "the gate is the first statement");
  assert.ok(head.includes("if (gate.refused) return gate.answer;"));
  assert.match(bg, /const EXTENSION_BASE = chrome\.runtime\.getURL\(""\);/);
  assert.match(bg, /import \{ senderGate, senderMaySend \} from "\.\/sendergate";/);
});

test("a refused message is not user activity: it never re-arms the idle lock", () => {
  const handle = bg.slice(bg.indexOf("async function handle("), bg.indexOf("async function dispatch("));
  assert.ok(handle.includes("senderMaySend(msg.type, sender, EXTENSION_BASE)"), "armAutoLock is gated on an allowed sender");
});
