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

/** How the native call itself ended, for the popup's Details (no debugger attaches to Safari on a phone). */
export type NativeCall = "resolved" | "rejected" | "timeout";

/** One ask: the answer, how the call ended, and the error text when it was rejected. Nothing here is secret. */
export type AppServerAsk = { answer: AppServerAnswer; call: NativeCall; error: string | null };

const SILENCE = Symbol("silence");

/** Ask the app, bounded by [timeoutMs]. Never throws: a refusal, a throw or silence is "unavailable", and says which. */
export async function askAppServerDetailed(
  sendNative: (msg: typeof APP_SERVER_REQUEST) => Promise<unknown>,
  timeoutMs: number = APP_SERVER_TIMEOUT_MS,
): Promise<AppServerAsk> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const silence = new Promise<typeof SILENCE>((resolve) => {
      timer = setTimeout(() => resolve(SILENCE), timeoutMs);
    });
    const reply = await Promise.race([sendNative(APP_SERVER_REQUEST), silence]);
    if (reply === SILENCE) return { answer: { kind: "unavailable" }, call: "timeout", error: null };
    return { answer: parseAppServerReply(reply), call: "resolved", error: null };
  } catch (e) {
    const text = e instanceof Error ? `${e.name}: ${e.message}` : String(e);
    return { answer: { kind: "unavailable" }, call: "rejected", error: text.slice(0, 200) };
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

/** [askAppServerDetailed], the answer only. */
export async function askAppServer(
  sendNative: (msg: typeof APP_SERVER_REQUEST) => Promise<unknown>,
  timeoutMs: number = APP_SERVER_TIMEOUT_MS,
): Promise<AppServerAnswer> {
  return (await askAppServerDetailed(sendNative, timeoutMs)).answer;
}

type NativeRuntime = { runtime?: { sendNativeMessage?: (app: string, msg: unknown, cb?: (reply: unknown) => void) => unknown; lastError?: { message?: string } | null } };

/**
 * The native-message call for this engine. Safari documents `browser.runtime.sendNativeMessage` (a promise; the
 * application id is ignored), so `browser` is used when it exists. The `chrome` namespace is the fallback, in its
 * callback form: its promise form is not something Safari promises to settle.
 */
export function nativeSender(
  scope: { browser?: NativeRuntime; chrome?: NativeRuntime },
  application: string,
): (msg: typeof APP_SERVER_REQUEST) => Promise<unknown> {
  return (msg) => {
    const viaBrowser = scope.browser?.runtime;
    if (viaBrowser && typeof viaBrowser.sendNativeMessage === "function") {
      return Promise.resolve(viaBrowser.sendNativeMessage(application, msg));
    }
    const viaChrome = scope.chrome?.runtime;
    if (viaChrome && typeof viaChrome.sendNativeMessage === "function") {
      return new Promise((resolve, reject) => {
        viaChrome.sendNativeMessage!(application, msg, (reply) => {
          const err = viaChrome.lastError;
          if (err) reject(new Error(err.message ?? "native message failed"));
          else resolve(reply);
        });
      });
    }
    return Promise.reject(new Error("runtime.sendNativeMessage is not available"));
  };
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
