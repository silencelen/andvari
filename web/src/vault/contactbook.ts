import type { KeyValue } from "../api/devicesecret";
import { toHexLower } from "../crypto/bytes";
import { sha256Sync } from "../crypto/provider";
import { decodeName, fromB64Exact, isHex64, isUuid } from "../crypto/trust/grammar";
import { type ContactRecord, removeContact } from "./accountdoc";
import type { AccountStateStore } from "./accountdocstore";

/**
 * When a contact counts on this browser (design §6.9, §8.5). A contact record syncs to every device in the
 * UVK-sealed account state, but any holder of the UVK can write one (a page from a dishonest server included,
 * T-R6), so a record alone makes nothing current. On the web a contact becomes CURRENT only by the person's own
 * act in this browser:
 *
 * - (c) they confirmed it here: "New person from your *device*: *label*. Use on this device?", one tap each;
 * - (d) they confirmed the one-tap list "People you've connected with", shown once to a browser that signed in
 *   with only the password (every web session that did not create the account).
 *
 * The web never processes or answers a link and is never linked (§13), so (a) and (b) do not exist here, and the web
 * creates no contact. Only a current contact makes a grant adoptable (§3.6), is offered when adding a member to a
 * vault this account owns (§13), and gets its label shown (§3.9).
 *
 * This browser keeps `pins.confirmed = {userId, keyHash}` in its device storage, keyed by the hex SHA-256 of the
 * contact's raw key, so a record for one key never makes another key current. A list that does not decode reads as
 * empty: nothing is current until confirmed again (fail closed). Behaviour twin of core `ContactCurrency` and
 * `AccountContactBook`.
 */
export type Currency = "confirmed" | "one_tap";

/** How this browser's session for the account came to be (§8.5): only a browser that registered the account skips the one-tap list. */
export type SessionHow = "registered" | "password" | "recovered";

interface Stored {
  userId: string;
  keyHash: string;
  how: Currency;
}

/** The lowercase hex SHA-256 of a `b64_32` key; null when it is not one. */
export function keyHash(identityPubB64: string): string | null {
  const key = fromB64Exact(identityPubB64, 32);
  return key === null ? null : toHexLower(sha256Sync(key));
}

export class ContactCurrency {
  private readonly key: string;
  private readonly oneTapKey: string;
  private readonly howKey: string;

  constructor(
    private readonly storage: KeyValue,
    userId: string,
  ) {
    this.key = `andvari.current.${userId}`;
    this.oneTapKey = `andvari.onetap.${userId}`;
    this.howKey = `andvari.how.${userId}`;
  }

  private all(): Stored[] {
    const text = this.storage.get(this.key);
    if (text === null) return [];
    try {
      const rows = JSON.parse(text) as unknown;
      if (!Array.isArray(rows)) return [];
      const out: Stored[] = [];
      for (const r of rows as Partial<Stored>[]) {
        // One malformed row empties the list: a record this browser cannot read vouches for nothing.
        if (r === null || typeof r !== "object" || typeof r.userId !== "string" || !isUuid(r.userId) || typeof r.keyHash !== "string" || !isHex64(r.keyHash)) return [];
        if (r.how !== "confirmed" && r.how !== "one_tap") return [];
        out.push({ userId: r.userId, keyHash: r.keyHash, how: r.how });
      }
      return out;
    } catch {
      return [];
    }
  }

  private write(rows: Stored[]): void {
    if (rows.length === 0) this.storage.remove(this.key);
    else this.storage.set(this.key, JSON.stringify(rows));
  }

  /** How [userId] under exactly [identityPubB64] is current here, or null when it is not. */
  currency(userId: string, identityPubB64: string): Currency | null {
    const h = keyHash(identityPubB64);
    if (h === null) return null;
    return this.all().find((s) => s.userId === userId && s.keyHash === h)?.how ?? null;
  }

  /** Makes [userId] under [identityPubB64] current here, replacing any record for another key of that user. */
  mark(userId: string, identityPubB64: string, how: Currency): boolean {
    const h = keyHash(identityPubB64);
    if (h === null || !isUuid(userId)) return false;
    this.write([...this.all().filter((s) => s.userId !== userId), { userId, keyHash: h, how }]);
    return true;
  }

  drop(userId: string): void {
    this.write(this.all().filter((s) => s.userId !== userId));
  }

  oneTapShown(): boolean {
    return this.storage.get(this.oneTapKey) === "1";
  }

  setOneTapShown(): void {
    this.storage.set(this.oneTapKey, "1");
  }

  /** Recorded when the session is made (register, sign-in, kit recovery); kept across reloads of that session. */
  setSessionHow(how: SessionHow): void {
    this.storage.set(this.howKey, how);
  }

  /** A browser with no record of how its session came to be reads as password-only: the list is only a prompt. */
  sessionHow(): SessionHow {
    const h = this.storage.get(this.howKey);
    return h === "registered" || h === "recovered" ? h : "password";
  }
}

/** One contact as this browser sees it. `labelText` is the decoded name, to render as plain text only. */
export interface ContactEntry {
  readonly record: ContactRecord;
  readonly current: Currency | null;
  readonly labelText: string;
}

/** A contact made on another device and not yet current here. Carries the record the person was shown. */
export interface ContactPrompt {
  readonly record: ContactRecord;
  readonly labelText: string;
}

export class ContactBook {
  constructor(
    private readonly account: Pick<AccountStateStore, "local" | "update">,
    readonly currency: ContactCurrency,
    private readonly clock: () => number = Date.now,
  ) {}

  private records(): ContactRecord[] {
    return [...this.account.local().contacts.values()].sort((a, b) => (a.userId < b.userId ? -1 : a.userId > b.userId ? 1 : 0));
  }

  private entry(r: ContactRecord): ContactEntry {
    return { record: r, current: this.currency.currency(r.userId, r.identityPub), labelText: decodeName(r.label) ?? "" };
  }

  list(): ContactEntry[] {
    return this.records().map((r) => this.entry(r));
  }

  /** The contact for [userId] whose key is exactly [identityPub] and is current here: the only source of a label. */
  currentFor(userId: string, identityPub: string): ContactEntry | null {
    const r = this.account.local().contacts.get(userId);
    if (!r || r.identityPub !== identityPub) return null;
    const e = this.entry(r);
    return e.current === null ? null : e;
  }

  /** The current contact for [userId], whatever its key: what an `add` of that person would use. */
  current(userId: string): ContactEntry | null {
    const r = this.account.local().contacts.get(userId);
    return r ? this.currentFor(userId, r.identityPub) : null;
  }

  /** True while the one-tap list is still to be shown: a browser that did not create the account, once (§8.5). */
  oneTapListDue(): boolean {
    return this.currency.sessionHow() !== "registered" && !this.currency.oneTapShown();
  }

  /**
   * Contacts made elsewhere that wait for one tap each (§6.9 (c)). While the one-tap list is due they are shown
   * there instead, all at once, so this is empty until that list was answered.
   */
  prompts(): ContactPrompt[] {
    if (this.oneTapListDue()) return [];
    return this.records()
      .filter((r) => this.currency.currency(r.userId, r.identityPub) === null)
      .map((r) => ({ record: r, labelText: decodeName(r.label) ?? "" }));
  }

  /** The person confirmed [prompt] here. Refused when the record changed since it was shown (another key). */
  confirmHere(prompt: ContactPrompt): boolean {
    const now = this.account.local().contacts.get(prompt.record.userId);
    if (!now || now.identityPub !== prompt.record.identityPub) return false;
    return this.currency.mark(now.userId, now.identityPub, "confirmed");
  }

  /** The person confirmed the one-tap list with [userIds] ticked; the rest stay not current. Shown once. */
  confirmOneTap(userIds: ReadonlySet<string>): boolean {
    if (!this.oneTapListDue()) return false;
    const contacts = this.account.local().contacts;
    for (const id of userIds) {
      const r = contacts.get(id);
      if (r && this.currency.currency(r.userId, r.identityPub) === null) this.currency.mark(r.userId, r.identityPub, "one_tap");
    }
    this.currency.setOneTapShown();
    return true;
  }

  /** Removes a contact: a tombstone stamped later than the pin (§5.4), then this browser's own record of it. */
  async remove(userId: string): Promise<boolean> {
    const w = await this.account.update((doc) => removeContact(doc, userId, this.clock()));
    const ok = w.kind === "written" || w.kind === "unchanged";
    if (ok) this.currency.drop(userId);
    return ok;
  }
}
