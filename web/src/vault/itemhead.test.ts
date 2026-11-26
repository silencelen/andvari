import { beforeAll, describe, expect, it } from "vitest";
import type { ItemDoc, WireItem } from "../api/types";
import { boxKeypairFromSeed, randomBytes, signKeypairFromSeed } from "../crypto/provider";
import { initSodium } from "../crypto/sodium";
import { Account } from "./account";
import { itemLogHead, stampLogHead } from "./itemhead";

const H = "a".repeat(64);
const PV = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
const V = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
const ITEM = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";

function account(): Account {
  const seed = randomBytes(32);
  return Account.fromOpened(
    { userId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", uvk: randomBytes(32), identity: boxKeypairFromSeed(seed), signing: signKeypairFromSeed(seed), genesis: null as never, personalVaultId: PV, personalVk: randomBytes(32) },
    null,
  );
}

const doc = (extra: Record<string, unknown> = {}): ItemDoc => ({ type: "login", name: "x", login: { username: "u", password: "p" }, ...extra }) as unknown as ItemDoc;

function opened(a: Account, vaultId: string, up: { formatVersion: number; blob: string }): ItemDoc {
  return a.decryptItem({ itemId: ITEM, vaultId, rev: 1, updatedAt: 1, deleted: false, formatVersion: up.formatVersion, blob: up.blob } as unknown as WireItem);
}

describe("item log heads (spec 02 §3 logHead, design §3.9)", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("reads only a non-negative integer seq and a 64-hex hash", () => {
    expect(itemLogHead(doc({ logHead: { seq: 4, hash: H } }))).toEqual({ seq: 4, hash: H });
    expect(itemLogHead(doc())).toBeNull();
    for (const bad of [{ seq: -1, hash: H }, { seq: 1.5, hash: H }, { seq: "4", hash: H }, { seq: 4, hash: "A".repeat(64) }, { seq: 4, hash: "ab" }, [4, H], null]) {
      expect(itemLogHead(doc({ logHead: bad }))).toBeNull();
    }
  });

  it("stamping replaces or removes the head and keeps every other field, known or not", () => {
    const d = doc({ logHead: { seq: 1, hash: H }, futureField: { keep: true } });
    const s = stampLogHead(d, { seq: 9, hash: "b".repeat(64) }) as unknown as Record<string, unknown>;
    expect(s.logHead).toEqual({ seq: 9, hash: "b".repeat(64) });
    expect(s.futureField).toEqual({ keep: true });
    const none = stampLogHead(d, null) as unknown as Record<string, unknown>;
    expect("logHead" in none).toBe(false);
    expect(none.futureField).toEqual({ keep: true });
  });

  it("a write to a log-governed vault carries its verified head; the personal vault's carries none", () => {
    const a = account();
    a.logKeyRing().set(V, randomBytes(32));
    a.attachLogRoles((id) => (id === V ? "writer" : null), (id) => id === V);
    let head: { seq: number; hash: string } | null = { seq: 7, hash: H };
    a.attachLogHeads((id) => (id === V ? head : null));
    const shared = opened(a, V, a.sealItem({ kind: "chosen", vaultId: V }, ITEM, doc({ logHead: { seq: 99, hash: "c".repeat(64) } })));
    expect(itemLogHead(shared)).toEqual({ seq: 7, hash: H });
    // A log that is not verified now gives no head: the write carries none rather than a stale one.
    head = null;
    expect(itemLogHead(opened(a, V, a.sealItem({ kind: "chosen", vaultId: V }, ITEM, doc({ logHead: { seq: 7, hash: H } }))))).toBeNull();
    // A copy into the personal vault drops the head it brought from the shared vault.
    const personal = opened(a, PV, a.sealItem({ kind: "chosen", vaultId: PV }, ITEM, doc({ logHead: { seq: 7, hash: H } })));
    expect(itemLogHead(personal)).toBeNull();
  });
});
