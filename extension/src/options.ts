/**
 * Options page (design 2026-07-15-multi-tenant-endpoints §5.1) — the extension's endpoint switcher.
 * Shows the raw current origin, takes a new server address, renders the anti-phishing Trust Gate
 * (§4.3), and on the gate's "Connect" click — the user gesture — requests BOTH host-permission grants
 * (per-origin fetch + broad autofill) and commits the switch (grantflow.ts, flag D2). The actual
 * origin-clean switch (token drop, api/WS/namespace/autofill rebuild) happens in the service worker,
 * on this page's `setServerUrl` message (security review 2026-10, A15: the worker keeps the choice in
 * its own store, which neither this page nor any web page writes); this page only validates, gates,
 * grants, and asks.
 *
 * External module only (MV3 CSP forbids inline). No key material ever reaches here.
 */
import { BROAD_ORIGIN_PATTERN, requestServerGrants } from "./grantflow";
import { drawWordmarks } from "./brand";
import { clearLiveMsg, messageBlocks, renderBlocks, setLiveMsg, setLiveMsgBlocks } from "./livemsg";
import { send, type Res } from "./messages";
import { canonicalizeServerUrl, ORIGIN_REFUSED, originMatchPattern } from "./serverurl";
import { readThemePref, setThemePref, type ThemePref } from "./theme";
import { originBreakPieces, trustGateView } from "./trustgate";
import { CARD_RECORD_DAMAGED_TITLE, cardRecordDamagedCopy, chooseServerCopy, chooseServerMessage, SERVER_FORK } from "./errors";
import { PUBLIC_INSTANCE } from "./publicinstance";
import * as T from "./copy";
import { fillApproved } from "./errors";
import { COUNT_UNKNOWN, forgetUnsavedLine, unsavedArmStep } from "./unsavedarm";

const el = <T extends HTMLElement = HTMLElement>(id: string): T => {
  const e = document.getElementById(id);
  if (!e) throw new Error(`#${id} missing`);
  return e as T;
};

const originNow = el("origin-now");
const input = el<HTMLInputElement>("server-input");
const continueBtn = el<HTMLButtonElement>("continue");
const gate = el("trust-gate");
const gateHeading = el("gate-heading");
const gateOrigin = el("gate-origin");
const gateBody = el("gate-body");
const gatePunycode = el("gate-punycode");
const gateHttp = el("gate-http");
const gateCancel = el<HTMLButtonElement>("gate-cancel");
const gateConnect = el<HTMLButtonElement>("gate-connect");
const serverMsg = el("server-msg");
const purgeBtn = el<HTMLButtonElement>("purge");
const purgeMsg = el("purge-msg");
const autofillStatus = el("autofill-status");
const gateCard = el("gate-card");
const gateOperator = el("gate-operator");
const serverStop = el("server-stop");
const serverStopBody = el("server-stop-body");
const serverStopHeading = el("server-stop-h");
const serverForget = el<HTMLButtonElement>("server-forget");
const serverForgetNote = el("server-forget-note");
const storeNote = el("store-note");
const themeChoices = el("theme-choices");

/** The verified card the Trust Gate is offering — set at Continue (after the worker checked the chain), read at
 *  Connect, which names it by its hash. */
let pendingCanonical: string | null = null;
let pendingHash: string | null = null;

/** a11y 2a (livemsg.ts owns the rule): this wrote text into a HIDDEN region and unhid it after —
 *  the inverted order, so the first outcome an SR user got here ("Connected to …", the
 *  declined-grant explanation) was a static read nothing announced. The role stays "status" for
 *  every kind, matching what options.html declares statically on #server-msg/#purge-msg: this page
 *  has no modal flow an assertive interrupt would serve, and the popup's alert/status split is
 *  about its unlock errors. */
function setMsg(node: HTMLElement, kind: "ok" | "err" | "info", text: string): void {
  setLiveMsg(node, `msg ${kind}`, "status", text);
}
function clearMsg(node: HTMLElement): void {
  clearLiveMsg(node);
}

/** A15: what the worker dials, whether a choice can be kept here, and (A15 review F1) a block while no server is
 *  dialed. Null when the worker does not answer (S3: never read as the default — nothing is shown as connected). */
async function serverInfoNow(): Promise<Res<"serverInfo"> | null> {
  try {
    const r = await send({ type: "serverInfo" });
    if (r && typeof r.url === "string") return r; // "" = no server chosen
  } catch {
    /* the worker did not answer */
  }
  return null;
}


/** Read + render the current configured origin (raw, exactly as it will be dialed), or why there is none. */
async function renderCurrent(): Promise<void> {
  const info = await serverInfoNow();
  const block = info?.block ?? null;
  if (info === null) originNow.textContent = T.OPTIONS_SERVER_NOT_ANSWERING;
  else if (block?.kind === "unsettled") originNow.textContent = T.OPTIONS_SERVER_UNSETTLED;
  else if (block?.kind === "no_server" || block?.kind === "no_store" || info.url === "") originNow.textContent = T.OPTIONS_NO_SERVER_YET;
  else originNow.textContent = info.url;
  // A fork or a damaged record stops everything (§4.4); "Forget this server" is the only way on.
  const stop = block?.kind === "fork" || block?.kind === "pin_damaged" ? block : null;
  serverStop.hidden = stop === null;
  // Entry 12: a damaged record has its approved title, and its two paragraphs stay two (each set as text).
  serverStopHeading.textContent = stop?.kind === "pin_damaged" ? CARD_RECORD_DAMAGED_TITLE : T.SERVER_CANT_BE_USED;
  if (stop?.kind === "pin_damaged") renderBlocks(serverStopBody, messageBlocks(null, cardRecordDamagedCopy(stop.origin)));
  else serverStopBody.textContent = stop?.kind === "fork" ? `${stop.origin} — ${SERVER_FORK}` : "";
  // No extension store here (Firefox "Never remember history"): say so before the person tries to connect.
  storeNote.hidden = info === null || info.trustedStore;
  // Rendered run 2026-11-16: with no server chosen there is no "server shown above" to remove data for.
  const danger = purgeBtn.closest("section");
  if (danger) danger.hidden = info === null || info.url === "";
}

/** Card autofill Tier 1 §10: the honest injection state — held broad grant = autofill can inject;
 *  missing (or an unreadable permissions API) reads as OFF, never a false "on" (the grantflow
 *  fail-safe direction: dormant is honest, "on" while injecting nowhere is the F3 bug itself). */
async function renderAutofillStatus(): Promise<void> {
  let held = false;
  try {
    held = await chrome.permissions.contains({ origins: [BROAD_ORIGIN_PATTERN] });
  } catch {
    /* permissions API unavailable — report off */
  }
  autofillStatus.textContent = held ? T.AUTOFILL_INJECTION_ON : T.AUTOFILL_INJECTION_OFF;
}

function hideGate(): void {
  // a11y-webext--7: both exits (Cancel, and a successful Connect) hid this container while one of
  // its own buttons held focus, so focus fell to <body> — on the most consequential decision the
  // page offers, leaving a keyboard user to Tab in from the top and an SR user with no place. Put
  // it back on the address field the gate was opened from, whenever focus is actually inside the
  // gate (never yank it from wherever else the user has since gone). Same fix shape as the
  // popup's named "a11y 4a" relock bug.
  if (gate.contains(document.activeElement)) input.focus();
  gate.hidden = true;
  pendingCanonical = null;
  pendingHash = null;
}

/** Whether the broad (autofill) grant landed at the last Continue — reported after Connect. */
let autofillGranted = false;

/**
 * Continue → validate the address against the §2.2 grammar, request the host grants (the gesture: requestServerGrants
 * is the FIRST async call, so permissions.request still sees it), then ask the worker to fetch and verify the server's
 * identity card (design 2026-11-15 §4.4) and render the Trust Gate with its card line. Nothing is kept until Connect.
 */
async function openGate(): Promise<void> {
  clearMsg(serverMsg);
  const canonical = canonicalizeServerUrl(input.value);
  if (canonical === null) {
    hideGate();
    setMsg(serverMsg, "err", ORIGIN_REFUSED);
    return;
  }
  continueBtn.disabled = true;
  try {
    const decision = await requestServerGrants(originMatchPattern(canonical));
    if (!decision.commit) {
      hideGate();
      setMsg(serverMsg, "info", T.ACCESS_DECLINED);
      return;
    }
    autofillGranted = decision.autofill;
    const r = await send({ type: "chooseServer", choice: "own", origin: canonical });
    if (!r?.ok) {
      hideGate();
      // Entry 8 names both addresses, from the worker's answer (the card's from the chain it verified), with its title.
      const m = chooseServerMessage(r, PUBLIC_INSTANCE.origin);
      setLiveMsgBlocks(serverMsg, "msg err", "status", m.title, m.body);
      return;
    }
    if (!r.gate) {
      // A server this browser already pinned (or the public instance): no gate, the worker switched to it.
      hideGate();
      input.value = r.url ?? canonical;
      await renderCurrent();
      setMsg(serverMsg, "ok", fillApproved(T.CONNECTED_TO, r.url ?? canonical));
      return;
    }
    pendingCanonical = r.gate.origin;
    pendingHash = r.gate.hash;
    const view = trustGateView(r.gate.origin, r.gate);
    gateHeading.textContent = view.heading;
    // Text nodes with a <wbr> between the origin's own pieces: the same characters, broken only at its punctuation.
    gateOrigin.replaceChildren(...originBreakPieces(view.origin).flatMap((p, i) => (i === 0 ? [p] : [document.createElement("wbr"), p])));
    gateCard.textContent = view.cardLine;
    gateOperator.textContent = view.operatorLine;
    gateOperator.hidden = view.operatorLine === "";
    gateBody.textContent = view.body;
    gatePunycode.textContent = view.punycodeCaution ?? "";
    gatePunycode.hidden = view.punycodeCaution === null;
    gateHttp.textContent = view.httpCaution ?? "";
    gateHttp.hidden = view.httpCaution === null;
    gate.hidden = false;
    gateCancel.focus(); // Cancel is the default focus (never Connect)
  } catch {
    hideGate();
    setMsg(serverMsg, "err", chooseServerCopy(undefined));
  } finally {
    continueBtn.disabled = false;
    void renderAutofillStatus();
  }
}

/** Connect → keep the card the gate showed (the worker pins it and switches). */
async function connect(): Promise<void> {
  const canonical = pendingCanonical;
  const hash = pendingHash;
  if (canonical === null || hash === null) return;
  gateConnect.disabled = true;
  try {
    const r = await send({ type: "confirmServer", origin: canonical, hash });
    if (!r?.ok) {
      setMsg(serverMsg, "err", chooseServerCopy(r?.code));
      return;
    }
    hideGate();
    input.value = canonical;
    await renderCurrent();
    setMsg(
      serverMsg,
      "ok",
      autofillGranted
        ? fillApproved(T.CONNECTED_TO, canonical)
        : fillApproved(T.CONNECTED_TO_AUTOFILL_OFF, canonical),
    );
  } catch {
    setMsg(serverMsg, "err", chooseServerCopy(undefined));
  } finally {
    gateConnect.disabled = false;
  }
}

/** Danger zone: purge THIS browser's stored data for the current origin (§4.2/B2-7 — the only
 *  destructive path). Two-click confirm so it can't fire by accident. */
let purgeArmed = false;
async function purge(): Promise<void> {
  clearMsg(purgeMsg);
  const info = await serverInfoNow();
  if (info === null) {
    setMsg(purgeMsg, "err", T.PURGE_NOT_ANSWERING);
    return;
  }
  const current = info.url;
  if (!purgeArmed) {
    purgeArmed = true;
    purgeBtn.textContent = fillApproved(T.PURGE_CONFIRM, current);
    // The pin and what andvari checks the server against stay.
    setMsg(purgeMsg, "info", T.PURGE_NOTE);
    return;
  }
  purgeArmed = false;
  purgeBtn.textContent = T.PURGE_BUTTON;
  try {
    const r = await send({ type: "purgeServerData", origin: current });
    if (r?.ok) setMsg(purgeMsg, "ok", fillApproved(T.PURGE_DONE, current));
    else setMsg(purgeMsg, "err", T.PURGE_FAILED);
  } catch {
    setMsg(purgeMsg, "err", T.PURGE_FAILED);
  }
}

/** H134 Appearance row (theme.ts). The document is already stamped by theme-boot.js before first
 *  paint; this only reflects the stored pick into the button group and re-stamps on a click, so the
 *  change is instant on this page and lands for the popup the next time it opens. aria-pressed is
 *  the single source of the selected state — the CSS keys on it, so what a screen reader announces
 *  and what the eye sees cannot drift apart. */
function renderTheme(pref: ThemePref): void {
  for (const b of themeChoices.querySelectorAll<HTMLButtonElement>("button[data-theme-pref]")) {
    b.setAttribute("aria-pressed", String(b.dataset.themePref === pref));
  }
}
themeChoices.addEventListener("click", (e) => {
  const btn = (e.target as HTMLElement | null)?.closest<HTMLButtonElement>("button[data-theme-pref]");
  const pref = btn?.dataset.themePref;
  if (pref !== "auto" && pref !== "light" && pref !== "dark") return;
  setThemePref(pref);
  renderTheme(pref);
});

continueBtn.addEventListener("click", () => void openGate());
// §12.3 "Forget this server": the way out of a fork or a damaged record. Design §4.4 (decided on 2026-11-17): it deletes
// the logins and cards this browser captured on pages and has not saved, so with any waiting, or when the worker does not
// answer the count, the first click says how many (or that andvari cannot tell) and the second forgets.
let forgetArmed: number | null = null;
async function capturesNow(): Promise<number> {
  try {
    const s = await send({ type: "status" });
    return typeof s?.unsavedCaptures === "number" ? s.unsavedCaptures : COUNT_UNKNOWN;
  } catch {
    return COUNT_UNKNOWN;
  }
}
function disarmForget(): void {
  forgetArmed = null;
  serverForget.textContent = T.FORGET_THIS_SERVER;
  serverForgetNote.hidden = true;
  serverForgetNote.textContent = "";
}
serverForget.addEventListener("click", () => {
  void (async () => {
    const now = await capturesNow();
    const step = unsavedArmStep(forgetArmed, now, false);
    if (!step.act) {
      forgetArmed = step.armed;
      serverForget.textContent = T.FORGET_CONFIRM;
      serverForgetNote.textContent = forgetUnsavedLine(now) ?? "";
      serverForgetNote.hidden = serverForgetNote.textContent === "";
      return;
    }
    disarmForget();
    try {
      await send({ type: "forgetServer" });
    } catch {
      /* the worker did not answer — the notice simply stays */
    }
    if (serverStop.contains(document.activeElement)) input.focus();
    await renderCurrent();
  })();
});
// As the purge's confirm: leaving the button cancels a half-armed Forget.
serverForget.addEventListener("blur", () => {
  if (forgetArmed !== null) disarmForget();
});
input.addEventListener("keydown", (e) => {
  if (e.key === "Enter") {
    e.preventDefault();
    void openGate();
  }
});
gateCancel.addEventListener("click", () => {
  hideGate();
  clearMsg(serverMsg);
});
gateConnect.addEventListener("click", () => void connect());
purgeBtn.addEventListener("click", () => void purge());
// Re-arm guard: any other interaction cancels a half-armed purge confirm.
purgeBtn.addEventListener("blur", () => {
  if (purgeArmed) {
    purgeArmed = false;
    purgeBtn.textContent = T.PURGE_BUTTON;
  }
});

renderTheme(readThemePref());
drawWordmarks(document); // the drawn name in the header (brand.ts)
void renderCurrent();
void renderAutofillStatus();
