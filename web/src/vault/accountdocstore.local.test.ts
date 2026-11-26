import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { memoryStorage } from "../api/devicesecret";
import type { AccountStateResponseV2 } from "../api/wire";
import { adAccountState } from "../crypto/ad";
import { toB64, utf8 } from "../crypto/bytes";
import { seal } from "../crypto/envelope";
import { randomBytes } from "../crypto/provider";
import { initSodium } from "../crypto/sodium";
import { type AccountDocument, EMPTY_DOCUMENT, encodeDocument, withVaultHead } from "./accountdoc";
import { AccountStateStore, type AccountStateWire } from "./accountdocstore";

/**
 * The account's stored document as `AccountStateStore.local()` hands it out: the sealed text is read from storage at
 * every asking, and opened only when it is not the exact text this store last opened. Another tab's write is another
 * text and is opened at the next asking; a text that does not open is never kept; and what one store opened stays with
 * that store and its key, so a session made after a lock or a sign-out opens the text for itself.
 */

const USER = "11111111-1111-4111-8111-111111111111";
const VAULT = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const GENESIS = "cd".repeat(32);

/** Every opening of a sealed account document, under any key: each call of `open` with the account state's AD. */
const counted = vi.hoisted(() => ({ ad: null as string | null, opened: 0 }));
vi.mock("../crypto/envelope", async (importOriginal) => {
  const real = await importOriginal<typeof import("../crypto/envelope")>();
  return {
    ...real,
    open: (key: Uint8Array, blob: Uint8Array, ad: Uint8Array) => {
      if (counted.ad !== null && toB64(ad) === counted.ad) counted.opened++;
      return real.open(key, blob, ad);
    },
  };
});

/** `local()` never reaches the server: a wire that is asked anything fails the test. */
const noWire: AccountStateWire = {
  accountState: (): Promise<AccountStateResponseV2> => {
    throw new Error("local() asked the server");
  },
  putAccountState: (): Promise<AccountStateResponseV2> => {
    throw new Error("local() wrote to the server");
  },
};

const sealedKey = `andvari.as2.${USER}.sealed`;
const hwKey = `andvari.as2.${USER}.hw`;
const sealFor = (uvk: Uint8Array, doc: AccountDocument): string => toB64(seal(uvk, utf8(encodeDocument(USER, doc)), adAccountState(USER)));
const text = (doc: AccountDocument): string => encodeDocument(USER, doc);
/** A document at in-blob [seq] that records [VAULT] at place 3 with [hash]. */
const docWith = (seq: number, hash: string): AccountDocument => ({ ...withVaultHead(EMPTY_DOCUMENT, VAULT, GENESIS, 3, hash), seq });

/** [n] askings of [store]'s `local()`: what each handed out (as its encoded text), and how many openings they made. */
function ask(store: AccountStateStore, n: number): { texts: string[]; opened: number } {
  const before = counted.opened;
  const texts: string[] = [];
  for (let i = 0; i < n; i++) texts.push(text(store.local()));
  return { texts, opened: counted.opened - before };
}

describe("the account's stored document, as local() hands it out", () => {
  let uvk: Uint8Array;
  beforeAll(async () => {
    await initSodium();
    uvk = randomBytes(32);
    counted.ad = toB64(adAccountState(USER));
  });
  beforeEach(() => {
    counted.opened = 0;
  });

  it("a row of askings while the stored text stays the same opens it once, and each hands out the stored document", () => {
    const storage = memoryStorage();
    const a = docWith(1, "aa".repeat(32));
    storage.set(sealedKey, sealFor(uvk, a));
    const store = new AccountStateStore(USER, uvk, noWire, storage);
    const r = ask(store, 6);
    expect(r.texts).toEqual(Array(6).fill(text(a)));
    expect(r.opened).toBe(1);
  });

  it("another tab's write is opened at the next asking, once, and its document is what comes out: also a text of the same length and the same in-blob seq", () => {
    const storage = memoryStorage();
    const a = docWith(1, "aa".repeat(32));
    storage.set(sealedKey, sealFor(uvk, a));
    // The high-water mark as the store keeps it beside its copy: the in-blob seq of the document kept.
    storage.set(hwKey, "1");
    const store = new AccountStateStore(USER, uvk, noWire, storage);
    expect(ask(store, 3)).toEqual({ texts: Array(3).fill(text(a)), opened: 1 });
    // Another tab writes a document of the same in-blob seq whose sealed text has the same length.
    const b = docWith(1, "bb".repeat(32));
    const sealedB = sealFor(uvk, b);
    expect(sealedB.length).toBe(storage.get(sealedKey)!.length);
    expect(sealedB).not.toBe(storage.get(sealedKey));
    storage.set(sealedKey, sealedB);
    expect(ask(store, 3)).toEqual({ texts: Array(3).fill(text(b)), opened: 1 });
    // And then a later document, as a write that advances the in-blob seq leaves it.
    const c = docWith(2, "cc".repeat(32));
    storage.set(sealedKey, sealFor(uvk, c));
    expect(ask(store, 3)).toEqual({ texts: Array(3).fill(text(c)), opened: 1 });
    // The same document sealed again (another nonce) is another text: it is opened again.
    storage.set(sealedKey, sealFor(uvk, c));
    expect(ask(store, 3)).toEqual({ texts: Array(3).fill(text(c)), opened: 1 });
  });

  it("the stored text removed, and then the very same text put back: the empty document in between, and the text opened again", () => {
    const storage = memoryStorage();
    const a = docWith(1, "aa".repeat(32));
    const sealedA = sealFor(uvk, a);
    storage.set(sealedKey, sealedA);
    const store = new AccountStateStore(USER, uvk, noWire, storage);
    expect(ask(store, 3)).toEqual({ texts: Array(3).fill(text(a)), opened: 1 });
    // A forgetting removes the copy; nothing of the document opened from it comes out then.
    storage.remove(sealedKey);
    expect(ask(store, 3)).toEqual({ texts: Array(3).fill(text(EMPTY_DOCUMENT)), opened: 0 });
    // The same text written again (as a copy put back from elsewhere) is opened again, once.
    storage.set(sealedKey, sealedA);
    expect(ask(store, 3)).toEqual({ texts: Array(3).fill(text(a)), opened: 1 });
  });

  it("a text that does not open is never kept: the empty document comes out at each asking, each asking tries it again, and a good text afterwards is opened", () => {
    const storage = memoryStorage();
    const store = new AccountStateStore(USER, uvk, noWire, storage);
    const a = docWith(1, "aa".repeat(32));
    // [opened]: the openings four askings make. A text that is not base64 is refused before it reaches the opening.
    const bad: [string, string, number][] = [
      ["a text sealed under another key", sealFor(randomBytes(32), a), 4],
      ["a text that is not a sealed document", "%% not a sealed document %%", 0],
    ];
    for (const [what, t, opened] of bad) {
      storage.set(sealedKey, t);
      const r = ask(store, 4);
      expect(r.texts, what).toEqual(Array(4).fill(text(EMPTY_DOCUMENT)));
      expect(r.opened, what).toBe(opened);
    }
    // A good text after the bad ones: opened once, and its document comes out.
    storage.set(sealedKey, sealFor(uvk, a));
    expect(ask(store, 4)).toEqual({ texts: Array(4).fill(text(a)), opened: 1 });
    // A text that does not open after the good one: the good one's document does not come out for it.
    storage.set(sealedKey, sealFor(randomBytes(32), a));
    expect(ask(store, 4)).toEqual({ texts: Array(4).fill(text(EMPTY_DOCUMENT)), opened: 4 });
  });

  it("after a lock and a new unlock nothing of the earlier session's document comes out: the new session opens the text itself, and a session under another key gets the empty document", () => {
    const storage = memoryStorage();
    const a = docWith(1, "aa".repeat(32));
    storage.set(sealedKey, sealFor(uvk, a));
    const before = new AccountStateStore(USER, uvk, noWire, storage);
    expect(ask(before, 3)).toEqual({ texts: Array(3).fill(text(a)), opened: 1 });
    const kept = before.local();
    // A lock or a sign-out ends the session, and the store goes with it; the next unlock makes a store of its own.
    const after = new AccountStateStore(USER, uvk, noWire, storage);
    expect(ask(after, 3)).toEqual({ texts: Array(3).fill(text(a)), opened: 1 });
    expect(after.local()).not.toBe(kept);
    // A session under another key over the same storage: the text does not open for it, and nothing of the earlier
    // session's document comes out.
    const other = new AccountStateStore(USER, randomBytes(32), noWire, storage);
    expect(ask(other, 3)).toEqual({ texts: Array(3).fill(text(EMPTY_DOCUMENT)), opened: 3 });
  });
});
