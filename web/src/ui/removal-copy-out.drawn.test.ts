// A copy (or a move) of an item out of a shared vault waits for the item's files to be uploaded into the target before it
// puts the item there. After those waits the store asks whether the SOURCE vault's key still works: a removal carried out
// while a file uploads puts no item into the target. What stays in the target is the file already uploaded, which no item
// names.
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { initSodium } from "../crypto/sodium";
import { listed } from "../vault/fakesyncserver.testkit";
import { closePage } from "./dom.testkit";
import { held, opened, removeBob, tabBCarriesItOut, wireOf } from "./removal.testkit";

beforeAll(async () => {
  await initSodium();
});
afterAll(async () => {
  await closePage();
});

/** Holds bob's next upload (after the server took it) until the returned gate opens; says when it has been taken. */
function holdUpload(f: Awaited<ReturnType<typeof opened>>) {
  const w = wireOf(f.bob);
  const real = w.uploadAttachment!;
  const g = held();
  let taken: () => void = () => {};
  const uploaded = new Promise<void>((r) => (taken = r));
  w.uploadAttachment = (async (...a: never[]) => {
    const r = await (real as unknown as (...x: never[]) => Promise<unknown>)(...a);
    taken();
    await g.wait; // the timing only: the upload's answer comes after the removal was carried out
    return r;
  }) as never;
  return { open: g.open, uploaded };
}

/** What the server holds in bob's own vault: items, and files. */
const inOwn = (f: Awaited<ReturnType<typeof opened>>) => {
  const own = f.bob.account.personalVaultId;
  return { items: [...f.server.items.values()].filter((i) => i.vaultId === own).length, files: [...f.server.attachments.values()].filter((a) => a.vaultId === own).length };
};

describe("a copy out of a shared vault across a removal", () => {
  it("a copy to Personal of an item with no file: a removal another tab carries out while the copy's change is made puts no item into the own vault", async () => {
    const f = await opened({ draw: false });
    const bank = f.bob.store.list().find((i) => i.doc.name === "bank")!;
    expect(bank.vaultId).toBe(f.old);
    // A wrapper around the store's real function that names the copy's change, acting at its start: tab B of bob's
    // browser profile carries the removal out there.
    const store = f.bob.store as unknown as { gestureMutationId: (gestureId: string, leg: string) => Promise<string> };
    const real = store.gestureMutationId.bind(f.bob.store);
    let carriedOut = false;
    store.gestureMutationId = async (gestureId: string, leg: string) => {
      if (leg === "copy" && !carriedOut) {
        carriedOut = true;
        await removeBob(f.alice, f.old);
        await tabBCarriesItOut(f);
      }
      return real(gestureId, leg);
    };
    const g = f.bob.store.newMoveGesture(bank.itemId, f.bob.account.personalVaultId, false);
    const outcome = await f.bob.store.runGesture(g).then(
      () => "copied",
      (e: unknown) => (e instanceof Error ? e.constructor.name : "refused"),
    );
    expect({ carriedOut, listedHere: listed(f.bob.store, f.old), outcome, inOwn: inOwn(f) }).toEqual({
      carriedOut: true,
      listedHere: false,
      outcome: "VaultKeyNotVerifiedError",
      inOwn: { items: 0, files: 0 },
    });
  });

  it("a copy to Personal of a shared item whose file uploads while the removal is carried out puts no item into the own vault", async () => {
    const f = await opened({ attachment: true, draw: false });
    const up = holdUpload(f);
    const g = f.bob.store.newMoveGesture(f.gate.itemId, f.bob.account.personalVaultId, false);
    const run = f.bob.store.runGesture(g).then(
      () => "copied",
      (e: unknown) => (e instanceof Error ? e.constructor.name : "refused"),
    );
    await up.uploaded;
    await removeBob(f.alice, f.old);
    await f.bob.store.sync();
    expect(listed(f.bob.store, f.old)).toBe(false);
    up.open();
    expect({ outcome: await run, inOwn: inOwn(f) }).toEqual({ outcome: "VaultKeyNotVerifiedError", inOwn: { items: 0, files: 1 } });
  });

  it("copy all to Personal: an item whose file uploads while the removal is carried out is not put into the own vault", async () => {
    const f = await opened({ attachment: true, draw: false });
    const up = holdUpload(f);
    const run = f.bob.store.copyAllToPersonal(f.old).then(
      () => "copied",
      (e: unknown) => (e instanceof Error ? e.constructor.name : "refused"),
    );
    await up.uploaded;
    await removeBob(f.alice, f.old);
    await f.bob.store.sync();
    expect(listed(f.bob.store, f.old)).toBe(false);
    up.open();
    const outcome = await run;
    // "bank" (no file) was copied before the removal; the gate, whose file was uploading, was not.
    await f.bob.store.sync();
    const own = f.bob.store.list().filter((i) => i.vaultId === f.bob.account.personalVaultId).map((i) => i.doc.name);
    expect({ outcome, inOwn: inOwn(f), own }).toEqual({ outcome: "VaultKeyNotVerifiedError", inOwn: { items: 1, files: 1 }, own: ["bank"] });
  });
});
