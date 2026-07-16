/**
 * Options-page host-permission grant flow (design 2026-07-15-multi-tenant-endpoints §5.1, flag D2).
 *
 * Switching the extension to a self-host server needs TWO grants, both requested in the SAME user
 * gesture (the Trust Gate's "Connect" click):
 *   (a) the PER-ORIGIN grant (`<origin>/*`) — WITHOUT it the CORS-less `fetch` of api.ts to the
 *       configured server is blocked, so nothing works;
 *   (b) the BROAD grant (the all-hosts `https` host pattern) — WITHOUT it the dynamic autofill
 *       content script (registered for all http/https pages) is injected nowhere, so autofill stays
 *       dormant even though the switch "worked". A per-origin grant alone leaves autofill off (§5.1).
 *
 * Degrade rules (binding): a dismissed BROAD grant must NOT fail the whole switch — the server change
 * still commits, autofill just stays off with an honest note until the user grants it later (the
 * background `permissions.onAdded` reconcile then lights it up). A dismissed PER-ORIGIN grant ⇒ NO
 * change at all (a switch we can't fetch against is worse than staying put).
 *
 * LEAF module (serverurl.ts / updateverify.ts discipline): no chrome import, no chrome types. The
 * permissions surface is resolved structurally from globalThis (or injected by tests), so `node
 * --test` loads it directly and pins the decision table.
 */

/** The broad optional host permission the dynamic autofill script needs to inject on arbitrary pages
 *  (design §5.1 manifest model). An all-hosts `http` pattern is deliberately NOT requested — the
 *  manifest's `optional_host_permissions` only allows `http://localhost`/`127.0.0.1`, so autofill on
 *  plain-http pages is out of scope by construction; https covers the real web. */
export const BROAD_ORIGIN_PATTERN = "https://*/*";

export interface GrantDecision {
  /** Commit the server switch (persist the new origin)? False ⇒ leave everything on the old server. */
  commit: boolean;
  /** Will autofill be able to inject on arbitrary pages after this? True iff the broad grant is held. */
  autofill: boolean;
  /** Which branch fired — drives the options-page status copy and pins the test. */
  reason: "granted" | "autofill-declined" | "declined" | "invalid-origin";
}

/**
 * Pure decision from the two granted-state booleans (read back via `permissions.contains`, the source
 * of truth — never the combined request's all-or-nothing boolean). Structurally incapable of failing
 * the switch on a broad-only decline, and structurally incapable of committing without the per-origin
 * fetch grant.
 */
export function decideGrant(perOriginGranted: boolean, broadGranted: boolean): GrantDecision {
  if (!perOriginGranted) return { commit: false, autofill: false, reason: "declined" };
  if (!broadGranted) return { commit: true, autofill: false, reason: "autofill-declined" };
  return { commit: true, autofill: true, reason: "granted" };
}

/** The minimal chrome.permissions surface used here — structural, so this leaf carries no chrome
 *  types and tests inject a plain object. Both methods resolve to booleans (MV3 promise form). */
export interface PermissionsSurface {
  request(perms: { origins: string[] }): Promise<boolean>;
  contains(perms: { origins: string[] }): Promise<boolean>;
}

function chromePermissions(): PermissionsSurface | null {
  const g = globalThis as { chrome?: { permissions?: PermissionsSurface } };
  return g.chrome?.permissions ?? null;
}

async function containsSafe(perms: PermissionsSurface, pattern: string): Promise<boolean> {
  try {
    return await perms.contains({ origins: [pattern] });
  } catch {
    return false; // an unreadable permission is treated as NOT held — fail safe (no accidental commit)
  }
}

/**
 * Run the grant flow for a switch to [originPattern] (the port-dropped `<scheme>://<host>/*` pattern
 * from serverurl.originMatchPattern — null for an unexpressible host, e.g. an IPv6 literal). MUST be
 * called synchronously from within the Connect user gesture.
 *
 * Both grants ride ONE `permissions.request` — Chrome forbids a second `request` after an `await`
 * breaks the gesture, so a combined `{origins:[originPattern, BROAD]}` is the only correct shape for
 * "same gesture". The combined boolean is then IGNORED: the granted STATE is read back per-pattern via
 * `contains`, which is what lets a broad-only decline degrade (commit + autofill off) while a
 * per-origin decline leaves everything unchanged.
 */
export async function requestServerGrants(
  originPattern: string | null,
  perms: PermissionsSurface | null = chromePermissions(),
): Promise<GrantDecision> {
  if (originPattern === null) return { commit: false, autofill: false, reason: "invalid-origin" };
  if (perms === null) return { commit: false, autofill: false, reason: "declined" }; // no permissions API → cannot grant
  try {
    await perms.request({ origins: [originPattern, BROAD_ORIGIN_PATTERN] });
  } catch {
    // request threw (LAN-http origin outside optional_host_permissions, or no gesture) — fall through
    // to the contains readback: the per-origin will read false and the switch stays put (declined).
  }
  const perOriginGranted = await containsSafe(perms, originPattern);
  const broadGranted = await containsSafe(perms, BROAD_ORIGIN_PATTERN);
  return decideGrant(perOriginGranted, broadGranted);
}

/**
 * Firefox first-run routing (design §5.1): host permissions are optional-by-default on Firefox MV3,
 * so a fresh install has NO grant for the configured origin and every fetch fails as "unreachable".
 * The popup detects the missing grant and routes to the (mandatory-there) options page, whose Connect
 * gesture is the only place a `permissions.request` can run. `null` = undetectable (permissions API
 * absent) ⇒ never route: a false alarm that trapped every user in options would be worse than the
 * (Chrome-default) case where the grant already exists. */
export function shouldRouteToOptions(originGranted: boolean | null): boolean {
  return originGranted === false;
}
