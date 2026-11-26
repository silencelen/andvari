/**
 * What a pure verifier of this directory returns (design 2026-11-15 §18.2, the crypto and statement verifiers): the checked value,
 * or exactly one NAMED verdict. No verifier here throws on untrusted input, reads a clock, or does any
 * I/O. A thrown `CryptoError` always means the CALLER asked a builder to sign something outside the
 * grammar. Twin of core `Checked`.
 */
export type Checked<T, V extends string> =
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly verdict: V };

export const ok = <T>(value: T): { readonly ok: true; readonly value: T } => ({ ok: true, value });
export const refused = <V extends string>(verdict: V): { readonly ok: false; readonly verdict: V } => ({ ok: false, verdict });

/** The verdict string of a result: `ok`, or the refusing verdict. */
export const verdictOf = (r: Checked<unknown, string>): string => (r.ok ? "ok" : r.verdict);
