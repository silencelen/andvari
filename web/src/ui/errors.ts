import { ApiError } from "../api/client";

/**
 * A transport-level failure: the fetch rejected before any HTTP response arrived
 * (off VPN, server restarting, DNS down). Distinct from an {@link ApiError}, which
 * means the server *did* respond — so callers can tell "can't reach the server" apart
 * from "the server said no" and never blame the user's password for a network blip.
 */
export class NetworkError extends Error {
  constructor(cause?: unknown) {
    super("network unreachable");
    this.name = "NetworkError";
    if (cause !== undefined) (this as { cause?: unknown }).cause = cause;
  }
}

/**
 * Await a fetch/API call, re-tagging a transport failure as {@link NetworkError} while
 * letting everything else pass through unchanged. Only a fetch() rejection — which the
 * platform surfaces as a TypeError — counts as transport; a SyntaxError from parsing a
 * garbage 200 body, a decode failure, or an {@link ApiError} all mean the server (or
 * something claiming to be it) DID answer, and must not be blamed on the network. Wrap
 * only the network steps of a flow; leave crypto steps (e.g. Account.unlock) un-wrapped
 * so a throw from them is unambiguously "wrong password", not "server down".
 */
export async function net<T>(p: Promise<T>): Promise<T> {
  try {
    return await p;
  } catch (e) {
    if (e instanceof TypeError) throw new NetworkError(e);
    throw e;
  }
}

/** The one canonical "can't reach the server" sentence, reused across auth surfaces. */
export const UNREACHABLE = "Can't reach the andvari server — check your connection (and your VPN, if your server is private), then try again.";

/** Policy/settings fetch failed — deliberately neutral between "unreachable" and "server
 *  errored", because the caller can't always tell and must not send users VPN-debugging
 *  when the server merely answered 500. */
export const POLICY_UNAVAILABLE = "Couldn't load the server's settings — it may be briefly unavailable. Try again in a moment.";

/** TWIN of extension/src/errors.ts CLIPBOARD_FAILED (and desktop Ui.kt CLIPBOARD_COPY_FAILED):
 *  a clipboard write refused by the platform (document not focused, permissions-policy) — the
 *  canon sentence, never the raw rejection text (pinned byte-equal by clipboard.test.ts). */
export const CLIPBOARD_FAILED = "Couldn't copy to the clipboard — try again.";

/** Audit F05: the AUTO-CLEAR was refused (the same "document is not focused" condition, hit at
 *  wipe time because copy → alt-tab → paste is the dominant flow). The secret is still on the
 *  clipboard, so every surface that promised "clears in Ns" must retract that promise instead of
 *  leaving it standing. A retry is armed for the next time this tab is focused (clipboard.ts). */
export const CLIPBOARD_NOT_CLEARED =
  "Still on your clipboard — this browser wouldn't let andvari clear it. Copy something harmless to replace it.";

/** The short form of {@link CLIPBOARD_NOT_CLEARED} for the in-label copy pill, which has room
 *  for "copied ✓ · clears in 30s" and no more. */
export const CLIPBOARD_NOT_CLEARED_SHORT = "still on your clipboard — clear it manually";
