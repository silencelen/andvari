/// <reference lib="webworker" />
import { initSodium } from "../crypto/sodium";
import { powSearch } from "../crypto/trust/signup";
import { solvePow } from "./registration";

/**
 * The sign-up proof of work off the main thread (design §7.5: "clients compute it in a background thread
 * with a progress note"). Message in: {email, utcDate, powBits}. Messages out: {progress: tried} while it
 * runs, then {date, nonce}, or {error}. The email is the address the person typed; nothing secret is here.
 */
const ctx = self as unknown as DedicatedWorkerGlobalScope;

ctx.onmessage = (e: MessageEvent<{ email: string; utcDate: string; powBits: number }>) => {
  const { email, utcDate, powBits } = e.data;
  initSodium()
    .then(() => solvePow(powBits, utcDate, (from, tries) => powSearch(email, utcDate, powBits, from, tries), (tried) => ctx.postMessage({ progress: tried })))
    .then((r) => ctx.postMessage(r))
    .catch((err: unknown) => ctx.postMessage({ error: err instanceof Error ? err.message : "pow failed" }));
};
