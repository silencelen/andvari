import type { BuildTarget } from "./buildtarget.ts";
import { canonicalizeServerUrl } from "./serverurl.ts";

/**
 * Safari on iOS: the extension uses the andvari app's server. The app writes the origin it chose (after its own Trust
 * Gate) to the App Group it shares with this extension, and the extension's native handler
 * (app-ios/AndvariSafari/SafariWebExtensionHandler.swift) answers `{type:"appServer"}` with it. The worker asks when
 * it starts and whenever the popup opens. When the app has a server and the extension uses another, the worker adopts
 * the app's through the same commit the options page's Connect uses (the trusted store, then the origin-clean switch,
 * §4.1), with no second Trust Gate: the person confirmed this origin in the app.
 *
 * LEAF module: no chrome import, so `node --test` loads it directly. The worker passes the native-message call in.
 */

/** The one native message the extension sends. */
export const APP_SERVER_REQUEST = { type: "appServer" } as const;

/** How long the worker waits for the app's handler. It reads one value from the App Group, so this is generous. */
export const APP_SERVER_TIMEOUT_MS = 3_000;

/** What the app said: its origin (canonical), that it has none yet, or nothing usable (not Safari, no handler, no answer). */
export type AppServerAnswer = { kind: "set"; url: string } | { kind: "none" } | { kind: "unavailable" };

/**
 * Read the handler's reply: `{ok: true, type: "appServer", url: <origin> | null}`. Only an explicit null means "no
 * server"; a missing key, a non-string or a value that is not a plain http(s) origin is no answer at all, so a malformed
 * reply never moves the extension anywhere.
 */
export function parseAppServerReply(reply: unknown): AppServerAnswer {
  if (typeof reply !== "object" || reply === null) return { kind: "unavailable" };
  const r = reply as { ok?: unknown; type?: unknown; url?: unknown };
  if (r.ok !== true || r.type !== "appServer") return { kind: "unavailable" };
  if (r.url === null) return { kind: "none" };
  if (typeof r.url !== "string") return { kind: "unavailable" };
  const canonical = canonicalizeServerUrl(r.url);
  return canonical === null ? { kind: "unavailable" } : { kind: "set", url: canonical };
}

/** Ask the app, bounded by [timeoutMs]. Never throws: a refusal, a throw or silence is "unavailable". */
export async function askAppServer(
  sendNative: (msg: typeof APP_SERVER_REQUEST) => Promise<unknown>,
  timeoutMs: number = APP_SERVER_TIMEOUT_MS,
): Promise<AppServerAnswer> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const silence = new Promise<undefined>((resolve) => {
      timer = setTimeout(() => resolve(undefined), timeoutMs);
    });
    return parseAppServerReply(await Promise.race([sendNative(APP_SERVER_REQUEST), silence]));
  } catch {
    return { kind: "unavailable" };
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

/**
 * The origin the extension should adopt, or null to change nothing: only in the Safari build, only when the app has a
 * server, and only when it differs from [current], the origin the worker dials now (null while a block stands, so the
 * app's confirmed choice also settles a pending one).
 */
export function appServerToAdopt(answer: AppServerAnswer, current: string | null, target: BuildTarget): string | null {
  if (target !== "safari" || answer.kind !== "set") return null;
  return answer.url === current ? null : answer.url;
}
