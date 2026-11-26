// A file of an item is handed out only while the item's vault is still one this browser may read: the store asks again
// after the download's answer came, before it opens the file, so a removal carried out while the answer was on its way
// writes no file (whoever asked for it: the item view, or a backup's attachment fetch).
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { initSodium } from "../crypto/sodium";
import { listed } from "../vault/fakesyncserver.testkit";
import { ITEM_CLOSED } from "./copy";
import { buttonNamed, click, closePage, settle } from "./dom.testkit";
import { closedLines, filesWritten, GATE, held, leftIn, opened, openItem, removeBob, wireOf } from "./removal.testkit";

beforeAll(async () => {
  await initSodium();
});
afterAll(async () => {
  await closePage();
});

describe("a download across a removal", () => {
  it("a download answered after the removal was carried out writes no file", async () => {
    const f = await opened({ attachment: true });
    const w = wireOf(f.bob);
    const realDownload = w.downloadAttachment!;
    const g = held();
    w.downloadAttachment = (async (id: string) => {
      const bytes = await (realDownload as unknown as (i: string) => Promise<Uint8Array>)(id);
      await g.wait; // the timing only: the server's answer arrives after it served the removal
      return bytes;
    }) as never;
    await openItem(f.screen, GATE.name);
    expect(f.screen.text()).toContain("gate-plan.pdf");
    const written = await filesWritten(f.screen, async () => {
      await click(buttonNamed(f.screen.page, "Download"));
      await removeBob(f.alice, f.old);
      await f.screen.bell();
      expect({ listed: listed(f.bob.store, f.old), handedOut: f.bob.store.get(f.gate.itemId) !== undefined, fieldsLeft: leftIn(f.screen), lines: closedLines(f.screen) }).toEqual({
        listed: false,
        handedOut: false,
        fieldsLeft: [],
        lines: [ITEM_CLOSED],
      });
      g.open();
      await settle(20);
    });
    expect({ files: written.length, content: await Promise.all(written.map((b) => b.text())) }).toEqual({ files: 0, content: [] });
    await f.screen.unmount();
  });

  it("the store refuses to open the file once the vault's key no longer works, whoever called it", async () => {
    const f = await opened({ attachment: true, draw: false });
    const w = wireOf(f.bob);
    const realDownload = w.downloadAttachment!;
    const g = held();
    w.downloadAttachment = (async (id: string) => {
      const bytes = await (realDownload as unknown as (i: string) => Promise<Uint8Array>)(id);
      await g.wait; // the timing only
      return bytes;
    }) as never;
    const ref = f.gate.doc.attachments![0]!;
    const asked = f.bob.store.downloadAttachment(f.gate, ref).then(
      () => "opened",
      (e: unknown) => (e instanceof Error ? e.constructor.name : "refused"),
    );
    await removeBob(f.alice, f.old);
    await f.bob.store.sync();
    expect(listed(f.bob.store, f.old)).toBe(false);
    g.open();
    expect(await asked).toBe("VaultKeyNotVerifiedError");
  });
});
