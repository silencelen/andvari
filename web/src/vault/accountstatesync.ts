import { ApiError, type ApiClient } from "../api/client";
import type { Account } from "./account";
import {
  ACCOUNT_STATE_SEALED_MAX,
  type AccountStateDoc,
  AccountStateError,
  type Contact,
  emptyAccountState,
  mergeAccountState,
  sameAccountStateContent,
  withContact,
  withoutContact,
} from "./accountstate";

/**
 * Small per-account client state that must survive a reload (security review 2026-10, root cause A, A5):
 * the account-state high-water seq, this browser's own SEALED copy of the account state, and the personal
 * vault id last used here. Values are public counters or UVK-sealed blobs; nothing here is plaintext.
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

export type AccountStateAnomaly = "rollback" | "unreadable" | null;

/**
 * Client half of `/account/state` — twin of core `AccountStateSync.kt`. Read, open, merge with this
 * browser's sealed copy under its high-water seq, write back when anything differs. A substituted blob
 * does not open (anomaly "unreadable", local wins); a served seq below the high-water mark, or a withheld
 * blob after one was seen, is a "rollback" (local wins). Pins are added ONLY through {@link pin} with a
 * contact built by contacts.ts from a human comparison.
 */
export class AccountStateSync {
  doc: AccountStateDoc;
  anomaly: AccountStateAnomaly = null;
  readOnly = false;
  private serverSeq = 0;

  constructor(
    private readonly api: ApiClient,
    private readonly account: Account,
    private readonly local: ClientStateStore,
    private readonly clock: () => number = () => Date.now(),
  ) {
    this.doc = this.loadLocal() ?? emptyAccountState(account.userId);
  }

  private highWater(): number {
    const v = Number(this.local.get("acctstate.hw") ?? "0");
    return Number.isSafeInteger(v) && v > 0 ? v : 0;
  }

  private loadLocal(): AccountStateDoc | null {
    const sealed = this.local.get("acctstate.copy");
    if (!sealed) return null;
    try {
      return this.account.openAccountState(sealed);
    } catch {
      return null;
    }
  }

  contacts(): Contact[] {
    return this.doc.contacts;
  }

  async refresh(): Promise<AccountStateDoc> {
    for (let attempt = 0; attempt < 3; attempt++) {
      const resp = await this.api.accountState();
      this.serverSeq = resp.seq;
      let served: AccountStateDoc | null = null;
      let unreadable = false;
      if (resp.sealedState) {
        try {
          served = this.account.openAccountState(resp.sealedState);
        } catch (e) {
          if (e instanceof AccountStateError) {
            // Opens under our UVK but is not a v1 document: a newer client wrote it. Never overwrite.
            this.readOnly = true;
            this.anomaly = null;
            return this.doc;
          }
          unreadable = true;
        }
      }
      const localDoc = this.loadLocal() ?? (this.doc.seq > 0 || this.doc.contacts.length > 0 ? this.doc : null);
      const merged = mergeAccountState(this.account.userId, localDoc, served, this.highWater());
      this.anomaly = unreadable ? "unreadable" : merged.rollback ? "rollback" : null;
      const needsWrite = unreadable || merged.rollback || (served === null && localDoc !== null) || !sameAccountStateContent(merged.doc, served);
      if (!needsWrite || this.readOnly) {
        this.adopt(merged.doc, resp.sealedState);
        return this.doc;
      }
      if (served === null && localDoc === null && merged.doc.contacts.length === 0 && Object.keys(merged.doc.consumedNonces).length === 0 && merged.doc.orgRecoveryFp === null) {
        this.doc = merged.doc; // nothing to say yet: no empty blob just to have one
        return this.doc;
      }
      if (await this.write(merged.doc)) return this.doc;
    }
    return this.doc;
  }

  private async write(next: AccountStateDoc): Promise<boolean> {
    const bumped = { ...next, seq: Math.max(next.seq, this.highWater(), this.doc.seq) + 1 };
    const sealed = this.account.sealAccountState(bumped);
    if (sealed.length > ACCOUNT_STATE_SEALED_MAX) throw new Error("account state is too large");
    try {
      const r = await this.api.putAccountState(sealed, this.serverSeq);
      this.serverSeq = r.seq;
      this.adopt(bumped, sealed);
      return true;
    } catch (e) {
      if (e instanceof ApiError && e.status === 409) return false;
      throw e;
    }
  }

  private adopt(next: AccountStateDoc, sealed: string | null) {
    this.doc = next;
    if (next.seq > this.highWater()) this.local.set("acctstate.hw", String(next.seq));
    let copy = sealed;
    if (!copy) {
      try {
        copy = this.account.sealAccountState(next);
      } catch {
        copy = null;
      }
    }
    if (copy) this.local.set("acctstate.copy", copy);
  }

  /** Pin a contact built by contacts.ts from a HUMAN comparison. Never this account itself. */
  async pin(contact: Contact): Promise<void> {
    if (contact.userId === this.account.userId) throw new Error("cannot pin yourself");
    if (this.readOnly) throw new Error("account state was written by a newer client");
    await this.refresh().catch(() => {});
    for (let i = 0; i < 3; i++) {
      if (await this.write(withContact(this.doc, contact))) return;
      await this.refresh();
    }
    throw new Error("account state kept changing; try again");
  }

  async unpin(userId: string): Promise<void> {
    if (this.readOnly) throw new Error("account state was written by a newer client");
    await this.refresh().catch(() => {});
    for (let i = 0; i < 3; i++) {
      if (await this.write(withoutContact(this.doc, userId, this.clock()))) return;
      await this.refresh();
    }
    throw new Error("account state kept changing; try again");
  }
}
