import { emailNorm } from "../crypto/trust/grammar";
import { powSearch } from "../crypto/trust/signup";
import { solvePow, utcDate } from "./registration";

/**
 * Runs the sign-up proof of work for [email] (its `emailNorm`, as the server hashes it) in a Web Worker,
 * reporting how many nonces were tried. Where no Worker exists (tests, an old browser) it runs in slices on
 * this thread, yielding between them. Answers the `pow` field of `POST /signup/start`.
 */
export function runPow(email: string, powBits: number, nowMs: number, onProgress: (tried: number) => void = () => {}, signal?: AbortSignal): Promise<{ date: string; nonce: number }> {
  const norm = emailNorm(email);
  if (norm === null) return Promise.reject(new Error("invalid_email"));
  const date = utcDate(nowMs);
  if (powBits <= 0) return Promise.resolve({ date, nonce: 0 });
  if (typeof Worker === "undefined") return solvePow(powBits, date, (from, tries) => powSearch(norm, date, powBits, from, tries), onProgress, signal);
  return new Promise((resolve, reject) => {
    const w = new Worker(new URL("./powworker.ts", import.meta.url), { type: "module" });
    const stop = () => {
      w.terminate();
      reject(new DOMException("aborted", "AbortError"));
    };
    signal?.addEventListener("abort", stop, { once: true });
    w.onmessage = (e: MessageEvent<{ progress?: number; date?: string; nonce?: number; error?: string }>) => {
      const m = e.data;
      if (typeof m.progress === "number") return onProgress(m.progress);
      w.terminate();
      signal?.removeEventListener("abort", stop);
      if (typeof m.nonce === "number" && typeof m.date === "string") resolve({ date: m.date, nonce: m.nonce });
      else reject(new Error(m.error ?? "pow failed"));
    };
    w.onerror = () => {
      w.terminate();
      reject(new Error("pow worker failed"));
    };
    w.postMessage({ email: norm, utcDate: date, powBits });
  });
}
