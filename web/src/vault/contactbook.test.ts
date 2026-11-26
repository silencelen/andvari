import { beforeAll, describe, expect, it } from "vitest";
import { memoryStorage } from "../api/devicesecret";
import { initSodium } from "../crypto/sodium";
import { type AccountDocument, type ContactRecord, EMPTY_DOCUMENT } from "./accountdoc";
import { ContactBook, ContactCurrency, keyHash } from "./contactbook";

/**
 * Contact currency on the web (design §6.9, §8.5): a record in account state makes nothing current; only this
 * browser's own confirmation does, bound to the exact key.
 */
const ME = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const BOB = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const CAT = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
const KEY1 = "dmn5TI1-jtERdRVMZoWG5QFr3LXPGreVJcHDayMnGio";
const KEY2 = "3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08";

const contact = (userId: string, identityPub: string, label = "Qm9i"): ContactRecord => ({
  userId, identityPub, label, method: "link", verifiedAt: 100, compared: true, madeOn: "d0000000-0000-4000-8000-000000000001", extra: new Map(),
});

class State {
  doc: AccountDocument;
  constructor(...contacts: ContactRecord[]) {
    this.doc = { ...EMPTY_DOCUMENT, contacts: new Map(contacts.map((c) => [c.userId, c])) };
  }
  local() {
    return this.doc;
  }
  async update(change: (d: AccountDocument) => AccountDocument) {
    this.doc = change(this.doc);
    return { kind: "written" as const, document: this.doc };
  }
}

describe("contact currency on the web", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("a synced contact is not current until the person confirms it here, and only under that key", () => {
    const state = new State(contact(BOB, KEY1));
    const storage = memoryStorage();
    const currency = new ContactCurrency(storage, ME);
    currency.setSessionHow("registered");
    const book = new ContactBook(state, currency);
    expect(book.currentFor(BOB, KEY1)).toBeNull();
    expect(book.current(BOB)).toBeNull();
    const [prompt] = book.prompts();
    expect(prompt!.labelText).toBe("Bob");
    expect(book.confirmHere(prompt!)).toBe(true);
    expect(book.currentFor(BOB, KEY1)).toMatchObject({ current: "confirmed", labelText: "Bob" });
    // The same user under another key is not current, and neither is another user under this key.
    expect(book.currentFor(BOB, KEY2)).toBeNull();
    expect(currency.currency(CAT, KEY1)).toBeNull();
    // The account state now names another key for Bob (a write by any UVK holder): nothing is current.
    state.doc = { ...state.doc, contacts: new Map([[BOB, contact(BOB, KEY2)]]) };
    expect(book.current(BOB)).toBeNull();
    expect(book.prompts().map((p) => p.record.identityPub)).toEqual([KEY2]);
  });

  it("a prompt whose record changed since it was shown confirms nothing", () => {
    const state = new State(contact(BOB, KEY1));
    const currency = new ContactCurrency(memoryStorage(), ME);
    currency.setSessionHow("registered");
    const book = new ContactBook(state, currency);
    const [prompt] = book.prompts();
    state.doc = { ...state.doc, contacts: new Map([[BOB, contact(BOB, KEY2)]]) };
    expect(book.confirmHere(prompt!)).toBe(false);
    expect(book.current(BOB)).toBeNull();
  });

  it("a browser that signed in with the password shows the one-tap list once; only ticked people become current", () => {
    const state = new State(contact(BOB, KEY1), contact(CAT, KEY2, "Q2F0"));
    const currency = new ContactCurrency(memoryStorage(), ME);
    const book = new ContactBook(state, currency);
    // No record of how the session came to be reads as password-only.
    expect(book.oneTapListDue()).toBe(true);
    expect(book.prompts()).toEqual([]);
    expect(book.confirmOneTap(new Set([BOB, "dddddddd-dddd-4ddd-8ddd-dddddddddddd"]))).toBe(true);
    expect(book.current(BOB)?.current).toBe("one_tap");
    expect(book.current(CAT)).toBeNull();
    expect(book.oneTapListDue()).toBe(false);
    expect(book.confirmOneTap(new Set([CAT]))).toBe(false);
    // The person left unticked now waits for a tap of their own.
    expect(book.prompts().map((p) => p.record.userId)).toEqual([CAT]);
  });

  it("a browser that created the account has no one-tap list", () => {
    const currency = new ContactCurrency(memoryStorage(), ME);
    currency.setSessionHow("registered");
    expect(new ContactBook(new State(contact(BOB, KEY1)), currency).oneTapListDue()).toBe(false);
    currency.setSessionHow("recovered");
    expect(new ContactBook(new State(contact(BOB, KEY1)), currency).oneTapListDue()).toBe(true);
  });

  it("a record list that does not decode vouches for nothing", () => {
    const storage = memoryStorage();
    const currency = new ContactCurrency(storage, ME);
    currency.mark(BOB, KEY1, "confirmed");
    expect(currency.currency(BOB, KEY1)).toBe("confirmed");
    storage.set(`andvari.current.${ME}`, JSON.stringify([{ userId: BOB, keyHash: keyHash(KEY1), how: "link" }]));
    expect(currency.currency(BOB, KEY1)).toBeNull();
    storage.set(`andvari.current.${ME}`, "{not json");
    expect(currency.currency(BOB, KEY1)).toBeNull();
    expect(currency.mark(BOB, "not a key", "confirmed")).toBe(false);
  });

  it("removing a contact tombstones it past the pin and forgets this browser's confirmation", async () => {
    const state = new State(contact(BOB, KEY1));
    const currency = new ContactCurrency(memoryStorage(), ME);
    currency.setSessionHow("registered");
    const book = new ContactBook(state, currency, () => 50);
    book.confirmHere(book.prompts()[0]!);
    expect(await book.remove(BOB)).toBe(true);
    expect(state.doc.contacts.has(BOB)).toBe(false);
    expect(state.doc.contactTombstones.get(BOB)).toBe(101);
    expect(currency.currency(BOB, KEY1)).toBeNull();
  });
});
