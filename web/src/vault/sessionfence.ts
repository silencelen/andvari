/**
 * One way to end a session's work at a lock or a sign-out.
 *
 * The tab has one transport, and its bearer is read when a request is made. Without a fence, work the session had
 * started (a save, the rest of an import, an upload, a password change, a kit rotation, the usage ledger) went on after
 * a lock, and after a sign-out and a sign-in as another account a late request of the old session could carry the new
 * account's bearer (the worst case: the old account state, sealed under the old account's key, written into the new
 * account's slot). Every transport a session uses is wrapped here; {@link SessionFence.close} makes every later call of
 * the session refuse with {@link SessionClosedError} before anything is sent. A call already on its way finishes (its
 * bearer was read when it was made, and the transport retries it only for the account it was made for).
 *
 * Nothing is wiped here: no key array is zero-filled at a lock (the Account and its store are left to the collector).
 *
 * What the person is told: when the fence closes on work still on its way, or a call of the session is refused after
 * it closed, [onInterrupted] runs once, and the unlock card says that a change may not have reached the server.
 * `quiet` transports neither count nor tell. The usage ledger is not behind the fence but {@link boundTo} its account.
 */

export class SessionClosedError extends Error {
  constructor() {
    super("session_closed");
    this.name = "SessionClosedError";
  }
}

/**
 * [target] with every method call refused while [ok] says no. For the usage ledger, whose last flush runs as the vault
 * unmounts at a lock: it may still land for the same account (the tokens a lock keeps are that account's), never once
 * the tab's transport is bound to another account or to none.
 */
export function boundTo<T extends object>(target: T, ok: () => boolean): T {
  return new Proxy(target, {
    get: (t, key) => {
      const v: unknown = Reflect.get(t, key, t);
      if (typeof v !== "function") return v;
      return (...args: unknown[]) => {
        if (!ok()) throw new SessionClosedError();
        return (v as (...a: unknown[]) => unknown).apply(t, args);
      };
    },
  });
}

export class SessionFence {
  private closed = false;
  private inFlight = 0;
  private told = false;

  /** Told once, as the class comment says. The app sets it when the session opens. */
  onInterrupted: () => void = () => {};

  get isClosed(): boolean {
    return this.closed;
  }

  /** Ends the session's work: every later call through a wrapped transport refuses. Idempotent. */
  close(): void {
    if (this.closed) return;
    this.closed = true;
    if (this.inFlight > 0) this.tell();
  }

  private tell(): void {
    if (this.told) return;
    this.told = true;
    this.onInterrupted();
  }

  /** [target] with every method call refused once the fence is closed. Properties read through unchanged. */
  wrap<T extends object>(target: T, opts: { quiet?: boolean } = {}): T {
    const quiet = opts.quiet === true;
    return new Proxy(target, {
      get: (t, key) => {
        const v: unknown = Reflect.get(t, key, t);
        if (typeof v !== "function") return v;
        return (...args: unknown[]) => {
          if (this.closed) {
            if (!quiet) this.tell();
            throw new SessionClosedError();
          }
          const out: unknown = (v as (...a: unknown[]) => unknown).apply(t, args);
          if (quiet || !(out instanceof Promise)) return out;
          this.inFlight++;
          return out.finally(() => {
            this.inFlight--;
          });
        };
      },
    });
  }
}
