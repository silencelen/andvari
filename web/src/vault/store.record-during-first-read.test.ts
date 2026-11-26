// A browser that has verified nothing of a shared vault yet reads its log for the first time, and while that read is out
// the account's record of the vault lands in the profile's storage, as another tab's write of the account state puts it
// there. The record read again after the fetch counts as known on such a browser too: a record above the served head
// leaves the vault withheld at the served head, and a record that names another entry at a place the served log holds
// freezes it there; in neither case is the record replaced, and nothing is sent. Driven through the real VaultStore,
// SharedLogSession, VaultLogStore and account-state store against the shared fake server.
import "fake-indexeddb/auto";
import { beforeAll, describe, expect, it } from "vitest";
import { memoryStorage } from "../api/devicesecret";
import { adAccountState } from "../crypto/ad";
import { toB64, utf8 } from "../crypto/bytes";
import { seal } from "../crypto/envelope";
import { initSodium } from "../crypto/sodium";
import { VAULT_KEY_NOT_VERIFIED } from "../ui/copy";
import { VaultKeyNotVerifiedError } from "./account";
import { encodeDocument, withVaultHead } from "./accountdoc";
import { BOB, browser, type Browser, family, freshDb, listed, type Profile } from "./fakesyncserver.testkit";

/** The hash another device of the account recorded at a place where the served log holds another entry, or none. */
const OTHER_HASH = "ab".repeat(32);

const sealedKey = `andvari.as2.${BOB}.sealed`;
const newProfile = (bob: Browser): Profile => ({ storage: memoryStorage(), personalVaultId: bob.profile.personalVaultId, personalVk: bob.profile.personalVk.slice() });

/**
 * Alice owns "Family" with "bank"; bob is a writer who accepted, and his account records the vault ([rec0]). [entries]:
 * alice changes bob's role that many times after it, ending at writer. Then a browser of bob's with a profile of its own,
 * before its first sync: it holds the account's document as read at its start and nothing of the vault's log.
 */
async function freshBrowser(entries: number) {
  freshDb();
  const f = await family();
  const rec0 = f.bob.shared.accountState.local().vaults.get(f.old)!;
  expect(rec0).toBeDefined();
  for (let i = 0; i < entries; i++) await f.alice.store.setMemberRole(f.old, BOB, i === entries - 1 ? "writer" : "reader");
  const fresh = await browser(f.server, f.bob.person, f.bob.contacts, { again: newProfile(f.bob), sync: false });
  expect(fresh.shared.logs.verifiedState(f.old)).toBeNull();
  expect(fresh.shared.logs.hashes(f.old).size).toBe(0);
  expect(fresh.shared.accountState.local().vaults.get(f.old)).toMatchObject({ seq: rec0.seq, hash: rec0.hash });
  return { ...f, rec0, fresh };
}
type Fresh = Awaited<ReturnType<typeof freshBrowser>>;

/**
 * [f]'s fresh browser syncs; at the moment the first page of the vault's log is asked for, another tab of the same profile
 * writes the account state with the vault's record at [seq] with [hash]: the server stores it and the profile's storage
 * holds it. Answers the server's counter of the account state after that write.
 */
async function firstReadAcross(f: Fresh, seq: number, hash: string): Promise<number> {
  const st = f.fresh.profile.storage;
  const doc = f.fresh.shared.accountState.local();
  const next = { ...withVaultHead(doc, f.old, f.rec0.genesisHash, seq, hash), seq: doc.seq + 1 };
  const text = toB64(seal(f.bob.person.uvk, utf8(encodeDocument(BOB, next)), adAccountState(BOB)));
  let landed = -1;
  f.server.onLogPage = (v) => {
    if (landed >= 0 || v !== f.old) return;
    landed = f.server.states.get(BOB)!.seq + 1;
    f.server.states.set(BOB, { sealed: text, seq: landed });
    st.set(sealedKey, text);
  };
  await f.fresh.store.sync();
  f.server.onLogPage = null;
  expect(landed).toBeGreaterThan(0);
  return landed;
}

/** [f]'s fresh browser does not write to the vault, and a save of "bank" there is refused and sends nothing. */
async function nothingWritten(f: Fresh): Promise<void> {
  expect(f.fresh.store.mayWrite(f.old)).toBe(false);
  expect(f.fresh.shared.logs.writeAllowed(f.old)).toBe(false);
  const bank = f.fresh.store.list().find((i) => i.vaultId === f.old && i.doc.name === "bank")!;
  const before = f.server.writes.length;
  const answer = await f.fresh.store.save(bank.itemId, { ...bank.doc, name: "bank-new" }, [], undefined, f.old).then(
    (v) => ({ ok: v }),
    (e: unknown) => e,
  );
  await f.fresh.store.sync();
  expect(answer).toBeInstanceOf(VaultKeyNotVerifiedError);
  expect((answer as Error).message).toBe(VAULT_KEY_NOT_VERIFIED);
  expect(f.server.writes.slice(before)).toEqual([]);
}

describe("a record that lands during a fresh browser's first read of a shared vault's log", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("a record above the served head: withheld at the served head, not writable, the record kept as it landed, and nothing sent", async () => {
    const f = await freshBrowser(0);
    const head = f.server.head(f.old).seq;
    const recordSeq = head + 1;
    const writes = f.server.writes.length;
    const counter = await firstReadAcross(f, recordSeq, OTHER_HASH);
    expect(f.fresh.shared.logs.verifiedState(f.old)!.head.seq).toBe(head);
    expect(f.fresh.shared.logs.status(f.old)).toMatchObject({ kind: "withheld", servedSeq: head });
    expect(f.fresh.shared.accountState.local().vaults.get(f.old)).toMatchObject({ seq: recordSeq, hash: OTHER_HASH });
    expect(f.server.states.get(BOB)!.seq).toBe(counter);
    expect(f.server.writes.slice(writes).filter((w) => w.endsWith(`:${f.old}`))).toEqual([]);
    expect(listed(f.fresh.store, f.old)).toBe(true);
    await nothingWritten(f);
    expect(f.fresh.shared.logs.status(f.old)).toMatchObject({ kind: "withheld", servedSeq: head });
    expect(f.server.states.get(BOB)!.seq).toBe(counter);
  });

  it("a record that names another entry at a place the served log holds and goes on beyond: frozen there, not writable, the record kept as it landed, and nothing sent", async () => {
    const f = await freshBrowser(2);
    const head = f.server.head(f.old).seq;
    const recordSeq = f.rec0.seq + 1;
    expect(head).toBe(recordSeq + 1);
    const writes = f.server.writes.length;
    const counter = await firstReadAcross(f, recordSeq, OTHER_HASH);
    expect(f.fresh.shared.logs.status(f.old)).toMatchObject({ kind: "frozen", atSeq: recordSeq });
    expect(f.fresh.shared.accountState.local().vaults.get(f.old)).toMatchObject({ seq: recordSeq, hash: OTHER_HASH });
    expect(f.server.states.get(BOB)!.seq).toBe(counter);
    expect(f.server.writes.slice(writes).filter((w) => w.endsWith(`:${f.old}`))).toEqual([]);
    expect(listed(f.fresh.store, f.old)).toBe(true);
    await nothingWritten(f);
    expect(f.fresh.shared.logs.status(f.old)).toMatchObject({ kind: "frozen", atSeq: recordSeq });
    expect(f.server.states.get(BOB)!.seq).toBe(counter);
  });
});
