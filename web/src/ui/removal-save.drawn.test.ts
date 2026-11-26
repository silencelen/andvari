// The line the vault screen shows when the item being edited went with a removal, where Save had been pressed: a save
// the server answered as applied is not called "not saved", and a save still waiting for its answer is said to be
// unknown, not lost.
import { act } from "react";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { initSodium } from "../crypto/sodium";
import { listed } from "../vault/fakesyncserver.testkit";
import { ITEM_CLOSED, ITEM_CLOSED_EDITING_NOT_KEPT, ITEM_CLOSED_EDITING_SENT } from "./copy";
import { buttonNamed, click, closePage, settle, type } from "./dom.testkit";
import { editorInput, GATE, held, opened, openItem, removeBob, tabBCarriesItOut, winOf, wireOf } from "./removal.testkit";

beforeAll(async () => {
  await initSodium();
});
afterAll(async () => {
  await closePage();
});

const TYPED = "typed and saved before the removal";

/** Bob edits the gate's notes and presses Save; the server takes the push, and its answer is held until [g] opens. */
async function savePressedAnswerHeld() {
  const f = await opened();
  await openItem(f.screen, GATE.name);
  await click(buttonNamed(f.screen.page, "Edit"));
  await type(editorInput(f.screen, "Notes"), TYPED);
  const w = wireOf(f.bob);
  const realPush = w.pushMutations!;
  const g = held();
  let pushed = 0;
  w.pushMutations = (async (m: never) => {
    const r = await (realPush as unknown as (x: never) => Promise<unknown>)(m); // the server takes it: bob is still a member
    pushed++;
    await g.wait; // the timing only: the answer comes later
    return r;
  }) as never;
  await click(buttonNamed(f.screen.page, "Save"));
  await settle(10);
  expect(pushed).toBe(1);
  return { f, g };
}

/** The lines the screen shows about the item it closed. */
const linesShown = (f: Awaited<ReturnType<typeof opened>>) => [ITEM_CLOSED, ITEM_CLOSED_EDITING_NOT_KEPT, ITEM_CLOSED_EDITING_SENT].filter((l) => f.screen.text().includes(l));

describe("the line after Save, when the item went with a removal", () => {
  it("a save the server took, answered after the removal: the line does not say it was not saved", async () => {
    const { f, g } = await savePressedAnswerHeld();
    await removeBob(f.alice, f.old);
    await f.screen.bell(); // this tab's sync waits behind the push
    g.open();
    await settle(30);
    await f.screen.bell().catch(() => {});
    expect(listed(f.bob.store, f.old)).toBe(false);
    await f.alice.store.sync();
    expect({ lines: linesShown(f), vaultHolds: f.alice.store.get(f.gate.itemId)?.doc.notes }).toEqual({
      lines: [ITEM_CLOSED],
      vaultHolds: TYPED,
    });
    await f.screen.unmount();
  });

  it("a save the server took, the removal made with no bell and no storage event before the answer: the line is the plain closing line", async () => {
    const { f, g } = await savePressedAnswerHeld();
    await removeBob(f.alice, f.old); // nothing tells this tab: no bell, no event; the save's own reconcile finds the removal
    g.open();
    await settle(40);
    expect({ listed: listed(f.bob.store, f.old), lines: linesShown(f), editorOpen: f.screen.page.querySelector("form.sheet") !== null }).toEqual({
      listed: false,
      lines: [ITEM_CLOSED],
      editorOpen: false,
    });
    await f.screen.unmount();
  });

  it("a save sent with no answer before the removal was carried out: the line says it may or may not have reached the vault", async () => {
    const { f, g } = await savePressedAnswerHeld();
    await removeBob(f.alice, f.old);
    await tabBCarriesItOut(f); // another tab carries the removal out while this tab's save waits for its answer
    // The browser tells this tab of tab B's write with a `storage` event (happy-dom has no second tab to fire it).
    const win = winOf(f.screen);
    await act(async () => {
      win.dispatchEvent(new win.Event("storage"));
    });
    await settle(10);
    expect({ editorOpen: f.screen.page.querySelector("form.sheet") !== null, lines: linesShown(f) }).toEqual({ editorOpen: false, lines: [ITEM_CLOSED_EDITING_SENT] });
    // The answer comes (the server took the change): the outcome is no longer unknown, and the line says only that the
    // item was closed.
    g.open();
    await settle(30);
    expect(linesShown(f)).toEqual([ITEM_CLOSED]);
    await f.screen.unmount();
  });
});
