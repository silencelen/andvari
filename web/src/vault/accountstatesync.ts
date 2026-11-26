/**
 * Small per-account client state that survives a reload (security review 2026-10, root cause A, A5), kept under
 * `andvari.cs.<userId>.` in this browser's storage. Values are public counters or sealed blobs; nothing here is
 * plaintext.
 *
 * The old account-state sync that lived in this file (AccountStateSync, this browser's merged copy of the
 * old account-state document) is gone. The account state is the session's AccountStateStore (accountdocstore.ts,
 * design §5.4); ownership, offers and handovers are the verified vault logs' (design §3.3). A source pin
 * (store.n2.test.ts) keeps it from coming back.
 */
export interface ClientStateStore {
  get(key: string): string | null;
  set(key: string, value: string | null): void;
}

/** localStorage-backed store keyed by userId; falls back to memory where storage is unavailable. */
export function localClientState(userId: string): ClientStateStore {
  const mem = new Map<string, string>();
  const k = (key: string) => `andvari.cs.${userId}.${key}`;
  const ls = (): Storage | null => {
    try {
      return typeof localStorage !== "undefined" ? localStorage : null;
    } catch {
      return null;
    }
  };
  return {
    get(key) {
      try {
        const v = ls()?.getItem(k(key));
        if (v != null) return v;
      } catch {
        /* storage blocked: memory only */
      }
      return mem.get(key) ?? null;
    },
    set(key, value) {
      if (value === null) mem.delete(key);
      else mem.set(key, value);
      try {
        if (value === null) ls()?.removeItem(k(key));
        else ls()?.setItem(k(key), value);
      } catch {
        /* storage blocked: memory only */
      }
    },
  };
}

export function memoryClientState(): ClientStateStore {
  const mem = new Map<string, string>();
  return {
    get: (key) => mem.get(key) ?? null,
    set: (key, value) => {
      if (value === null) mem.delete(key);
      else mem.set(key, value);
    },
  };
}
