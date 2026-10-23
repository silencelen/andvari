/**
 * Security review 2026-10, branch A14 (F3, F4, F11): the service worker's ONE sender gate.
 *
 * `runtime.onMessage` hears every context of this extension: our own pages (popup, options,
 * biometric connector) AND every content script, i.e. every web page's frame. Content scripts send
 * a known, small set of messages. Everything else in the protocol is meant for our pages only, but
 * that rule lived in per-handler checks, and some handlers had none: `cardItems` listed every card
 * to any frame, `enrollQuickUnlock` let a page-side context replace the user's PIN (and later redeem
 * it with `unlockWithPin`), and `unlock` / `unlockTotp` could sign the extension into an account the
 * page chose, after which the user's saves went to that account.
 *
 * The rule here: a type in [CONTENT_SENT] passes from any sender (its handler keeps its own
 * checks, e.g. `reveal`'s host gate). Every other type needs an EXTENSION-PAGE sender, judged by
 * `sender.url` starting with `chrome.runtime.getURL("")` — `chrome-extension://<id>/` on Chrome,
 * `moz-extension://<uuid>/` on Firefox. The browser sets `sender.url` from the frame's committed
 * URL; a content script's is the web page's. NOT `sender.tab === undefined`: the options page
 * (options_ui open_in_tab) and the connector window (windows.create type "popup") both have a tab.
 *
 * The per-handler checks (`allItems`, `reveal`, `totp`, `purgeServerData`, …) stay as they are;
 * this is an extra layer in front of them and only ever narrows who may send what.
 *
 * Chrome-free on purpose: background.ts is not node-importable, so the decision is tested here and
 * the call sites are pinned from sendergate.test.ts.
 */
import type { Req, Res } from "./messages";

type ReqType = Req["type"];
export type SenderClass = "content" | "extension";

/**
 * Every message type, classified. "content" = content.ts (the only content-side module that sends;
 * sendergate.test.ts re-derives the set from its import closure) sends it. "extension" = only our
 * own pages may. `satisfies Record<ReqType, …>` makes `tsc` refuse a new Req type that is not
 * listed here, and the test refuses one at `npm test` time too.
 */
export const SENDER_CLASS = {
  // ---- sent by content scripts ----
  matches: "content",
  reveal: "content",
  generate: "content",
  passwordReuse: "content",
  capturedCredential: "content",
  pendingSave: "content",
  resolvePendingSave: "content",
  openPopupForSave: "content",
  openPopupForSearch: "content",
  pageInfo: "content",
  scheduleClipboardClear: "content",
  cardFormInfo: "content",
  cardChipOffer: "content",
  openPopupForCards: "content",
  captureCard: "content",
  resolvePendingCardSave: "content",
  revealCardForFill: "content",
  // ---- our extension pages only ----
  status: "extension",
  personalAcceptChange: "extension",
  personalDescribeChange: "extension",
  unlock: "extension",
  unlockTotp: "extension",
  cancelTotp: "extension",
  lock: "extension",
  signOut: "extension",
  unlockWithPin: "extension",
  enrollQuickUnlock: "extension",
  unlockWithBio: "extension",
  enrollQuickUnlockBio: "extension",
  disableQuickUnlock: "extension",
  dismissQuickUnlockOffer: "extension",
  purgeServerData: "extension",
  ping: "extension",
  allItems: "extension",
  reuseNotice: "extension",
  cardItems: "extension",
  fillFromPopup: "extension",
  revealCardField: "extension",
  // A page-side caller could once link only its own host; content.ts no longer sends this at all.
  linkUri: "extension",
  totp: "extension",
  setTotp: "extension",
  updateStatus: "extension",
  cardFillOffers: "extension",
  fillCardFromPopup: "extension",
  // A15: the server choice is a message now, not a storage write a content script could also make.
  serverInfo: "extension",
  setServerUrl: "extension",
  forgetLegacyServer: "extension",
} as const satisfies Record<ReqType, SenderClass>;

type ExtensionOnly = { [K in ReqType]: (typeof SENDER_CLASS)[K] extends "extension" ? K : never }[ReqType];

/**
 * What an extension-page-only message answers any other sender: that message's existing refusal
 * or empty shape, checked against its own `Res<…>` by the mapped type. Nothing here carries data —
 * no lock state, no email, no counts — and the handler never runs, so no state changes (a refused
 * `unlockTotp` leaves the pending challenge alone; a refused `lock` locks nothing).
 */
const REFUSALS: { [K in ExtensionOnly]: Res<K> } = {
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
  // "aborted" is the protocol's benign no-op code (the popup just re-renders); a page gets no hint.
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
  serverInfo: { url: "", trustedStore: false, block: null },
  setServerUrl: { ok: false, code: "not_allowed" },
  forgetLegacyServer: { ok: false },
};

/** The two halves of [SENDER_CLASS], for the tests and for readers. */
export const CONTENT_SENT: readonly ReqType[] = (Object.keys(SENDER_CLASS) as ReqType[]).filter((t) => SENDER_CLASS[t] === "content");
export const EXTENSION_ONLY: readonly ReqType[] = (Object.keys(SENDER_CLASS) as ReqType[]).filter((t) => SENDER_CLASS[t] === "extension");

/** `chrome.runtime.getURL("")` has exactly this shape on both engines. Anything else (an empty
 *  string would make every URL "start with" it) fails closed. */
const EXTENSION_BASE_RE = /^[a-z][a-z0-9+.-]*-extension:\/\/[^/?#]+\/$/;

/** True when [sender] is one of THIS extension's pages (popup, options, connector, offscreen). */
export function isExtensionPageSender(sender: { url?: string }, extensionBase: string): boolean {
  if (!EXTENSION_BASE_RE.test(extensionBase)) return false;
  return typeof sender.url === "string" && sender.url.startsWith(extensionBase);
}

/** Whether [type] may come from [sender] at all (the gate's verdict, without the refusal). */
export function senderMaySend(type: string, sender: { url?: string }, extensionBase: string): boolean {
  if (isExtensionPageSender(sender, extensionBase)) return true;
  return Object.hasOwn(SENDER_CLASS, type) && SENDER_CLASS[type as ReqType] === "content";
}

/** The gate's verdict: let the message through, or answer it with [answer] instead (a refusal can
 *  itself be `null` — `reuseNotice`'s empty answer — hence the explicit flag). */
export type GateVerdict = { refused: false } | { refused: true; answer: unknown };

/**
 * The gate. Refused ⇒ the answer to send instead of running the handler: the type's own refusal
 * shape (a fresh copy), or `{ok:false}` for a type that is not in the protocol at all.
 */
export function senderGate(type: string, sender: { url?: string }, extensionBase: string): GateVerdict {
  if (senderMaySend(type, sender, extensionBase)) return { refused: false };
  if (Object.hasOwn(REFUSALS, type)) return { refused: true, answer: structuredClone(REFUSALS[type as ExtensionOnly]) };
  return { refused: true, answer: { ok: false } };
}
