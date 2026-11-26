/**
 * Web Locks as a browser grants them across its tabs, for tests (Node has no `navigator.locks`): one registry per
 * browser, one lock manager per tab. Shared and exclusive modes, `ifAvailable`, `signal`, requests granted in the order
 * asked (a shared request waits behind an exclusive one asked before it), a lock held until its callback's promise
 * settles, and a tab whose document ends (closed or crashed) losing every lock it held or asked for, as a browser does.
 */
type Mode = "shared" | "exclusive";
type Ask = { name: string; mode: Mode; tab: number; grant: () => void; drop: () => void };
type Held = { name: string; mode: Mode; tab: number; let: () => void };

export type TabLocks = {
  request(name: string, a: unknown, b?: unknown): Promise<unknown>;
  /** The tab's document ends (closed, or its process crashed): its locks go without its callbacks settling. */
  end(): void;
};

export function webLockRegistry(): { tab(): TabLocks; holders(name: string): number } {
  const held: Held[] = [];
  const queue: Ask[] = [];
  let tabs = 0;
  const fits = (name: string, mode: Mode, before: Ask[]): boolean => {
    const hs = held.filter((h) => h.name === name);
    const qs = before.filter((q) => q.name === name);
    if (mode === "exclusive") return hs.length === 0 && qs.length === 0;
    return hs.every((h) => h.mode === "shared") && qs.every((q) => q.mode === "shared");
  };
  const pump = (): void => {
    for (let i = 0; i < queue.length; i++) {
      const q = queue[i] as Ask;
      if (fits(q.name, q.mode, queue.slice(0, i))) {
        queue.splice(i, 1);
        q.grant();
        i = -1;
      }
    }
  };
  return {
    holders: (name) => held.filter((h) => h.name === name).length,
    tab(): TabLocks {
      const me = ++tabs;
      let ended = false;
      return {
        request(name, a, b) {
          const opts = (typeof a === "function" ? {} : (a ?? {})) as { mode?: Mode; ifAvailable?: boolean; signal?: AbortSignal };
          const fn = (typeof a === "function" ? a : b) as (lock: unknown) => unknown;
          const mode: Mode = opts.mode ?? "exclusive";
          if (ended) return new Promise(() => {});
          return new Promise((resolve, reject) => {
            const run = (): void => {
              const h: Held = { name, mode, tab: me, let: () => {} };
              let gone = false;
              const letGo = (): void => {
                if (gone) return;
                gone = true;
                held.splice(held.indexOf(h), 1);
                pump();
              };
              h.let = letGo;
              held.push(h);
              Promise.resolve()
                .then(() => fn({ name, mode }))
                .then(
                  (v) => {
                    letGo();
                    resolve(v);
                  },
                  (e) => {
                    letGo();
                    reject(e);
                  },
                );
            };
            if (opts.ifAvailable) {
              if (fits(name, mode, queue)) run();
              else Promise.resolve().then(() => fn(null)).then(resolve, reject);
              return;
            }
            const ask: Ask = { name, mode, tab: me, grant: run, drop: () => {} };
            if (opts.signal) {
              if (opts.signal.aborted) {
                reject(opts.signal.reason);
                return;
              }
              opts.signal.addEventListener("abort", () => {
                const i = queue.indexOf(ask);
                if (i < 0) return;
                queue.splice(i, 1);
                reject(opts.signal?.reason);
              });
            }
            queue.push(ask);
            pump();
          });
        },
        end() {
          ended = true;
          for (let i = queue.length - 1; i >= 0; i--) if (queue[i]?.tab === me) queue.splice(i, 1);
          for (const h of held.filter((x) => x.tab === me)) h.let();
          pump();
        },
      };
    },
  };
}

/** Puts [locks] in place as this document's `navigator.locks`; returns the way back. */
export function useTabLocks(locks: TabLocks | undefined): () => void {
  const nav = globalThis.navigator as unknown as Record<string, unknown>;
  const had = Object.getOwnPropertyDescriptor(nav, "locks");
  if (locks === undefined) delete nav.locks;
  else Object.defineProperty(nav, "locks", { value: locks, configurable: true });
  return () => {
    if (had) Object.defineProperty(nav, "locks", had);
    else delete nav.locks;
  };
}
