/**
 * Options page (design 2026-07-15-multi-tenant-endpoints §5.1) — the extension's endpoint switcher.
 * Shows the raw current origin, takes a new server address, renders the anti-phishing Trust Gate
 * (§4.3), and on the gate's "Connect" click — the user gesture — requests BOTH host-permission grants
 * (per-origin fetch + broad autofill) and commits the switch (grantflow.ts, flag D2). The actual
 * origin-clean switch (token drop, api/WS/namespace/autofill rebuild) happens in the service worker,
 * which reacts to the storage.local write; this page only validates, gates, grants, and persists.
 *
 * External module only (MV3 CSP forbids inline). No key material ever reaches here.
 */
import { requestServerGrants } from "./grantflow";
import { send } from "./messages";
import { canonicalizeServerUrl, getServerUrl, originMatchPattern, setServerUrl } from "./serverurl";
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

/** The canonical origin the Trust Gate is currently offering — set at Continue, read at Connect. The
 *  Connect handler MUST compute its permission pattern from this WITHOUT an intervening await, so the
 *  user gesture is still live when requestServerGrants calls permissions.request. */
let pendingCanonical: string | null = null;

function setMsg(node: HTMLElement, kind: "ok" | "err" | "info", text: string): void {
  node.className = `msg ${kind}`;
  node.textContent = text;
  node.hidden = false;
}
function clearMsg(node: HTMLElement): void {
  node.hidden = true;
  node.textContent = "";
}

/** Read + render the current configured origin (raw, exactly as it will be dialed). */
async function renderCurrent(): Promise<void> {
  const current = await getServerUrl();
  originNow.textContent = current;
  if (!input.value.trim()) input.value = current; // prefill so a Firefox first-run just Continues → Connects
}

function hideGate(): void {
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
    await setServerUrl(canonical); // persists → the service worker performs the origin-clean switch
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
  }
}

/** Danger zone: purge THIS browser's stored data for the current origin (§4.2/B2-7 — the only
 *  destructive path). Two-click confirm so it can't fire by accident. */
let purgeArmed = false;
async function purge(): Promise<void> {
  clearMsg(purgeMsg);
  const current = await getServerUrl();
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

continueBtn.addEventListener("click", openGate);
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

void renderCurrent();
