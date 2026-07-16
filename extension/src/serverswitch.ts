// Runtime (value) imports carry the .ts extension so this leaf resolves under `node --test`
// (serverswitch.test.ts imports it); esbuild + tsc (allowImportingTsExtensions) accept the suffix.
import { canonicalizeServerUrl, originKeyFor } from "./serverurl.ts";

/**
 * Chrome-free seams for the two origin-lifecycle paths in background.ts, extracted so `node --test`
 * drives the REAL enforcement instead of a hand-rolled mirror (the repo's leaf-module discipline —
 * serverurl.ts / locksequence.ts / quickunlock.ts):
 *   - applyServerSwitch: the §4.1 origin-clean server switch (token-clear-on-switch, breaker B1-5).
 *   - purgeServerDataFor: the §4.2 "remove data for this server" handler core (popup-only guard).
 * background.ts wires the chrome-coupled dependencies (doLock, makeApi, storage, purgeOriginNamespace)
 * into these; the security-critical ORDER + guards live HERE, so removing one breaks this module's test.
 */

/** The minimal api surface applyServerSwitch's test needs to prove no Authorization crosses a switch. */
export interface SwitchApi {
  getTokens(): { access: string | null; refresh: string | null };
}

/** Chrome-coupled dependencies of a server switch, injected by background.applyServerChange. */
export interface ServerSwitchDeps<A extends SwitchApi> {
  /** The freshly-persisted target origin (background: getServerUrl()). */
  nextUrl: string;
  /** The origin currently in effect (background: serverUrl). */
  currentUrl: string;
  /** Is a vault session live right now? (background: session !== null). */
  hasSession: boolean;
  /** Invalidate any in-flight quick-unlock redeem — it belongs to the old origin (background: redeemGen++). */
  bumpRedeemGen(): void;
  /** Lock under the OLD origin (background: doLock("manual")). MUST run before the api swaps so an
   *  armed lock stashes the live token pair into the OLD origin's namespace (§4.1, PRESERVED per B2-7). */
  lock(): Promise<void>;
  /** Construct a BRAND-NEW api for [url] (background: makeApi) — a fresh instance holds no tokens. */
  makeApi(url: string): A;
  /** Install the new api as the live one (background: `api = <new>`). */
  installApi(api: A): void;
  /** Adopt the new origin + its namespace key (background: serverUrl / currentOriginKey). */
  setOrigin(url: string): void;
  /** Recompute the dynamic autofill exclusions for the new origin (background: registerAutofillScripts). */
  registerAutofill(): Promise<void>;
}

/**
 * Apply a persisted serverUrl change (§4.1 origin-clean rules). ORDER is the whole enforcement:
 *  1. no-op when the origin did not actually change;
 *  2. bump the redeem generation (an in-flight PIN redeem belongs to the old origin — it self-discards
 *     via background's owns() guard);
 *  3. lock under the OLD origin FIRST — the armed branch stashes the live token pair into the OLD
 *     namespace (an A→B→A round trip keeps A's PIN, B2-7);
 *  4. adopt the new origin, then swap in a BRAND-NEW api for it. AndvariApi has no baseUrl setter, so a
 *     fresh instance is the ONLY way to point at a new origin, and it carries NO tokens: no Authorization
 *     header can cross the change (breaker B1-5);
 *  5. recompute the autofill exclusions for the new origin.
 */
export async function applyServerSwitch<A extends SwitchApi>(deps: ServerSwitchDeps<A>): Promise<void> {
  if (deps.nextUrl === deps.currentUrl) return;
  deps.bumpRedeemGen();
  if (deps.hasSession) await deps.lock(); // still under the OLD originKey — the stash lands in the old namespace
  deps.setOrigin(deps.nextUrl);
  deps.installApi(deps.makeApi(deps.nextUrl)); // FRESH instance — no token crosses the origin change
  await deps.registerAutofill();
}

/**
 * The purgeServerData message handler core (§4.2 — the ONLY destructive per-origin path: the options
 * page's explicit "Remove data for this server"). POPUP/options ONLY: a sender WITH a tab is a content
 * script ⇒ refused (parity with revealCardField / fillCardFromPopup). It is not page-reachable today (no
 * externally_connectable, no content→SW relay), but this arbitrary-origin wipe of a quick-unlock record
 * must never gain a page route if a content-script relay is ever added. Then canonicalize (a non-origin
 * string ⇒ no key ⇒ no-op) and hand the derived originKey to [purge]. Returns the handler's { ok }.
 */
export async function purgeServerDataFor(
  origin: string,
  senderHasTab: boolean,
  purge: (originKey: string) => Promise<void>,
): Promise<{ ok: boolean }> {
  if (senderHasTab) return { ok: false }; // page/content sender — refuse before any wipe (defense-in-depth)
  const canonical = canonicalizeServerUrl(origin);
  if (canonical) await purge(originKeyFor(canonical));
  return { ok: canonical !== null };
}
