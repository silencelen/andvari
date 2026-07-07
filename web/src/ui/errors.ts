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
export const UNREACHABLE = "Can't reach the andvari server — check you're on the home network or VPN, then try again.";

/** Policy/settings fetch failed — deliberately neutral between "unreachable" and "server
 *  errored", because the caller can't always tell and must not send users VPN-debugging
 *  when the server merely answered 500. */
export const POLICY_UNAVAILABLE = "Couldn't load the server's settings — it may be briefly unavailable. Try again in a moment.";
