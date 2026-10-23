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
import { clearLiveMsg, setLiveMsg } from "./livemsg";
import { send, type Res } from "./messages";
import { canonicalizeServerUrl, DEFAULT_SERVER_URL, originMatchPattern } from "./serverurl";
import { readThemePref, setThemePref, type ThemePref } from "./theme";
import { trustGateView } from "./trustgate";

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
const legacyNote = el("legacy-note");
const legacyOrigin = el("legacy-origin");
const legacyReview = el<HTMLButtonElement>("legacy-review");
const legacyForget = el<HTMLButtonElement>("legacy-forget");
const storeNote = el("store-note");
const themeChoices = el("theme-choices");

/** The canonical origin the Trust Gate is currently offering — set at Continue, read at Connect. The
 *  Connect handler MUST compute its permission pattern from this WITHOUT an intervening await, so the
 *  user gesture is still live when requestServerGrants calls permissions.request. */
let pendingCanonical: string | null = null;

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

/** A15: what the worker dials, a pre-A15 choice awaiting re-confirmation, and whether a choice can be kept here. A
 *  worker that does not answer reads as the default (the fail-safe getServerUrl always had). */
async function serverInfoNow(): Promise<Res<"serverInfo">> {
  try {
    const r = await send({ type: "serverInfo" });
    if (r && typeof r.url === "string" && r.url) return r;
  } catch {
    /* the worker did not answer */
  }
  return { url: DEFAULT_SERVER_URL, legacy: null, trustedStore: true };
}

/** The pre-A15 server the notice offers for review, or null. Display only: the ONLY way to adopt it is the Trust Gate. */
let legacyCandidate: string | null = null;

/** Read + render the current configured origin (raw, exactly as it will be dialed). */
async function renderCurrent(): Promise<void> {
  const info = await serverInfoNow();
  originNow.textContent = info.url;
  if (!input.value.trim()) input.value = info.url; // prefill so a Firefox first-run just Continues → Connects
  // A15: a server chosen before the update is shown, never reconnected: it sat in storage a web page could write.
  legacyCandidate = info.legacy;
  legacyOrigin.textContent = info.legacy ?? "";
  legacyNote.hidden = info.legacy === null;
  // A15: no extension store here (Firefox "Never remember history"): say so before the user tries to connect.
  storeNote.hidden = info.trustedStore;
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
  autofillStatus.textContent = `Autofill injection: ${held ? "on" : "off"} (all-sites permission)`;
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
}

/** Continue → validate the address and render the Trust Gate for it (never auto-connect). */
function openGate(): void {
  clearMsg(serverMsg);
  const canonical = canonicalizeServerUrl(input.value);
  if (canonical === null) {
    hideGate();
    setMsg(serverMsg, "err", "Enter a full server address, e.g. https://andvari.example.com (scheme + host only).");
    return;
  }
  pendingCanonical = canonical;
  const view = trustGateView(canonical);
  gateHeading.textContent = view.heading;
  gateOrigin.textContent = view.origin;
  gateBody.textContent = view.body;
  gatePunycode.textContent = view.punycodeCaution ?? "";
  gatePunycode.hidden = view.punycodeCaution === null;
  gateHttp.textContent = view.httpCaution ?? "";
  gateHttp.hidden = view.httpCaution === null;
  gate.hidden = false;
  gateCancel.focus(); // Cancel is the default focus (§4.3 — never Connect)
}

/** Connect → the grant gesture. Requests the per-origin fetch grant + the broad autofill grant in one
 *  gesture, then commits per grantflow's decision. requestServerGrants MUST be the first async call so
 *  permissions.request still sees the gesture (no await before it). */
async function connect(): Promise<void> {
  const canonical = pendingCanonical;
  if (canonical === null) return;
  gateConnect.disabled = true;
  try {
    const decision = await requestServerGrants(originMatchPattern(canonical));
    if (!decision.commit) {
      if (decision.reason === "invalid-origin") {
        setMsg(serverMsg, "err", "This browser can't be granted access to that address (an IPv6-literal host). Use a hostname or an https origin.");
      } else {
        setMsg(serverMsg, "info", "Browser access to that server was declined — nothing changed. You stay connected to the current server.");
      }
      return;
    }
    // A15: the worker canonicalizes, keeps the choice in its own store and runs the origin-clean switch before it
    // answers. A choice it cannot keep (no extension store in this browser mode) changes nothing.
    const r = await send({ type: "setServerUrl", url: canonical });
    if (!r?.ok) {
      setMsg(serverMsg, "err", r?.code === "storage" ? STORE_UNAVAILABLE : "Couldn't switch servers. Nothing changed — try again.");
      return;
    }
    hideGate();
    input.value = canonical;
    await renderCurrent();
    if (decision.autofill) {
      setMsg(serverMsg, "ok", `Connected to ${canonical}. Sign in from the toolbar popup.`);
    } else {
      // Broad grant declined → the switch still committed; autofill is dormant until it's granted.
      setMsg(
        serverMsg,
        "ok",
        `Connected to ${canonical}. Autofill on other sites stays off until you allow andvari to access web pages — reopen Options and Connect again to enable it. Sign in from the toolbar popup.`,
      );
    }
  } catch {
    setMsg(serverMsg, "err", "Couldn't switch servers. Nothing changed — try again.");
  } finally {
    gateConnect.disabled = false;
    void renderAutofillStatus(); // the Connect gesture is where the broad grant can land — re-read it
  }
}

const STORE_UNAVAILABLE =
  "This browser gives andvari no storage of its own in this mode (Firefox does this when it never remembers history), so it can't keep a server choice. Nothing changed.";

/** Danger zone: purge THIS browser's stored data for the current origin (§4.2/B2-7 — the only
 *  destructive path). Two-click confirm so it can't fire by accident. */
let purgeArmed = false;
async function purge(): Promise<void> {
  clearMsg(purgeMsg);
  const current = (await serverInfoNow()).url;
  if (!purgeArmed) {
    purgeArmed = true;
    purgeBtn.textContent = `Remove all data for ${current}? Click again to confirm`;
    setMsg(purgeMsg, "info", "This removes only this browser's PIN / quick-unlock and cached state for that server. Your vault on the server is untouched.");
    return;
  }
  purgeArmed = false;
  purgeBtn.textContent = "Remove data for this server…";
  try {
    const r = await send({ type: "purgeServerData", origin: current });
    if (r?.ok) setMsg(purgeMsg, "ok", `Removed this browser's stored data for ${current}.`);
    else setMsg(purgeMsg, "err", "Couldn't remove the stored data.");
  } catch {
    setMsg(purgeMsg, "err", "Couldn't remove the stored data.");
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

continueBtn.addEventListener("click", openGate);
// A15: "Review this address" opens the ordinary Trust Gate for the pre-update choice — Connect stays the only commit.
legacyReview.addEventListener("click", () => {
  if (legacyCandidate === null) return;
  input.value = legacyCandidate;
  openGate();
});
legacyForget.addEventListener("click", () => {
  void (async () => {
    try {
      await send({ type: "forgetLegacyServer" });
    } catch {
      /* the worker did not answer — the notice simply stays */
    }
    if (legacyNote.contains(document.activeElement)) input.focus();
    await renderCurrent();
  })();
});
input.addEventListener("keydown", (e) => {
  if (e.key === "Enter") {
    e.preventDefault();
    openGate();
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
    purgeBtn.textContent = "Remove data for this server…";
  }
});

renderTheme(readThemePref());
void renderCurrent();
void renderAutofillStatus();
