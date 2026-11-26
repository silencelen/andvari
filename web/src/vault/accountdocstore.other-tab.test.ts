import { beforeAll, describe, expect, it } from "vitest";
import { type KeyValue, memoryStorage } from "../api/devicesecret";
import type { AccountStateResponseV2 } from "../api/wire";
import { adAccountState } from "../crypto/ad";
import { toB64, utf8 } from "../crypto/bytes";
import { seal } from "../crypto/envelope";
import { randomBytes } from "../crypto/provider";
import { initSodium } from "../crypto/sodium";
import { type AccountDocument, EMPTY_DOCUMENT, encodeDocument, withVaultHead } from "./accountdoc";
import { AccountStateStore, type AccountStateWire } from "./accountdocstore";

/**
 * Another tab of the same profile writes the account's sealed copy while this store holds a document of its own: a
 * document it read that the storage did not keep, or a read that is still out. Either way the store goes on with both:
 * it never answers the other tab's text alone, and it never writes its older copy over that text.
 */

const USER = "11111111-1111-4111-8111-111111111111";
const VAULT = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const OTHER = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const GENESIS = "cd".repeat(32);
const sealedKey = `andvari.as2.${USER}.sealed`;

/** A document at in-blob [seq] holding a record for each [vault, place, hash]. */
const docOf = (seq: number, records: [string, number, string][]): AccountDocument => {
  let d: AccountDocument = EMPTY_DOCUMENT;
  for (const [v, at, h] of records) d = withVaultHead(d, v, GENESIS, at, h);
  return { ...d, seq };
};
const sealFor = (uvk: Uint8Array, d: AccountDocument): string => toB64(seal(uvk, utf8(encodeDocument(USER, d)), adAccountState(USER)));

/** A wire that answers every read with [answer] (after [during], when given) and is never asked to write. */
function wireAnswering(answer: () => AccountStateResponseV2, during?: () => void): AccountStateWire {
  return {
    accountState: async (): Promise<AccountStateResponseV2> => {
      const a = answer();
      during?.();
      return a;
    },
    putAccountState: (): Promise<AccountStateResponseV2> => {
      throw new Error("nothing is written to the server here");
    },
  };
}

/** What a store of its own, made over [storage] now, reads from the copy at rest alone (no network). */
const atRest = (uvk: Uint8Array, storage: KeyValue): AccountDocument =>
  new AccountStateStore(USER, uvk, wireAnswering(() => ({ sealedState: null, seq: 0 })), storage).local();

describe("the account's document beside another tab's write", () => {
  let uvk: Uint8Array;
  beforeAll(async () => {
    await initSodium();
    uvk = randomBytes(32);
  });

  it("a later text of another tab is merged with the document whose copy the storage did not keep, and is not answered alone", async () => {
    const raw = memoryStorage();
    raw.set(sealedKey, sealFor(uvk, docOf(1, [[VAULT, 3, "aa".repeat(32)]])));
    // This store's writes of the sealed copy are dropped (a full storage refuses the large write); every other write
    // lands, and another tab's writes go to the storage itself.
    const dropping: KeyValue = {
      get: (k) => raw.get(k),
      set: (k, v) => (k === sealedKey ? undefined : raw.set(k, v)),
      remove: (k) => raw.remove(k),
    };
    const served = docOf(2, [[VAULT, 5, "bb".repeat(32)]]);
    const store = new AccountStateStore(USER, uvk, wireAnswering(() => ({ sealedState: sealFor(uvk, served), seq: 7 })), dropping);
    const r = await store.read();
    expect(r.kind).toBe("ok");
    expect(r.document.vaults.get(VAULT)?.seq).toBe(5);
    // The storage did drop the write: the copy at rest still records place 3, and this store answers place 5.
    expect(atRest(uvk, raw).vaults.get(VAULT)?.seq).toBe(3);
    expect(store.local().vaults.get(VAULT)?.seq).toBe(5);

    // Another tab writes a later text: it records a vault of its own, and still place 3 for VAULT.
    const otherTab = sealFor(uvk, docOf(3, [[VAULT, 3, "aa".repeat(32)], [OTHER, 1, "cc".repeat(32)]]));
    raw.set(sealedKey, otherTab);
    // That text is at rest, and what is at rest alone holds the lower record for VAULT.
    expect(raw.get(sealedKey)).toBe(otherTab);
    const rest = atRest(uvk, raw);
    expect(rest.vaults.get(OTHER)?.seq).toBe(1);
    expect(rest.vaults.get(VAULT)?.seq).toBe(3);

    // This store holds both: the new text's record, and the higher record it read.
    const now = store.local();
    expect(now.vaults.get(OTHER)?.seq).toBe(1);
    expect(now.vaults.get(VAULT)?.seq).toBe(5);
    expect(store.local().vaults.get(VAULT)?.seq).toBe(5);
  });

  it("read() takes the local copy after the server's answer: a record another tab stored while the read was out stays in the copy", async () => {
    const storage = memoryStorage();
    storage.set(sealedKey, sealFor(uvk, docOf(1, [[VAULT, 3, "aa".repeat(32)]])));
    // The server's state from before the other tab's write, which reaches it only later: no record for OTHER.
    const older = docOf(1, [[VAULT, 4, "dd".repeat(32)]]);
    const otherTab = sealFor(uvk, docOf(2, [[VAULT, 3, "aa".repeat(32)], [OTHER, 1, "cc".repeat(32)]]));
    let wroteDuringRead = false;
    const store = new AccountStateStore(
      USER,
      uvk,
      wireAnswering(
        () => ({ sealedState: sealFor(uvk, older), seq: 7 }),
        () => {
          // Another tab writes the account's copy while this read is out.
          storage.set(sealedKey, otherTab);
          wroteDuringRead = true;
        },
      ),
      storage,
    );
    // Before the read, this store's copy holds no record for OTHER, and the answer will hold none either.
    expect(store.local().vaults.get(OTHER)).toBeUndefined();
    expect(older.vaults.get(OTHER)).toBeUndefined();

    const r = await store.read();
    // The other tab's text was at rest before the answer came in.
    expect(wroteDuringRead).toBe(true);
    expect(r.kind).toBe("ok");
    // The read merged the other tab's record with the served one, and wrote the two together.
    expect(r.document.vaults.get(OTHER)?.seq).toBe(1);
    expect(r.document.vaults.get(VAULT)?.seq).toBe(4);
    const rest = atRest(uvk, storage);
    expect(rest.vaults.get(OTHER)?.seq).toBe(1);
    expect(rest.vaults.get(VAULT)?.seq).toBe(4);
  });
});
