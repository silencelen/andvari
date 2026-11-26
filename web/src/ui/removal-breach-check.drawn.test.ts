// The breach check of an item's password sends a prefix of the password's digest. It asks the open item's guard again
// after the digest and before the request: a removal carried out while the digest ran sends nothing.
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { initSodium } from "../crypto/sodium";
import { listed } from "../vault/fakesyncserver.testkit";
import { buttonNamed, click, closePage, settle } from "./dom.testkit";
import { GATE, opened, openItem, removeBob } from "./removal.testkit";

/** What runs at the start of the next digest (the real digest runs right after it). */
const atDigest: { next: (() => Promise<void>) | null } = { next: null };
vi.mock("../crypto/hibp", async (importOriginal) => {
  const orig = await importOriginal<typeof import("../crypto/hibp")>();
  return {
    ...orig,
    hibpSha1UpperHex: async (...args: Parameters<typeof orig.hibpSha1UpperHex>) => {
      const h = atDigest.next;
      atDigest.next = null;
      if (h) await h(); // a wrapper around the real digest, acting at its start
      return orig.hibpSha1UpperHex(...args);
    },
  };
});

beforeAll(async () => {
  await initSodium();
});
afterAll(async () => {
  await closePage();
});

describe("the breach check across a removal", () => {
  it("control: with no removal, the check asks for one range", async () => {
    const f = await opened();
    await openItem(f.screen, GATE.name);
    await click(buttonNamed(f.screen.page, "Check breach exposure"));
    await settle(10);
    expect(f.screen.ranges).toHaveLength(1);
    await f.screen.unmount();
  });

  it("a removal carried out during the breach check's digest: no range request leaves", async () => {
    const f = await opened();
    await openItem(f.screen, GATE.name);
    atDigest.next = async () => {
      await removeBob(f.alice, f.old);
      await f.bob.store.sync();
    };
    await click(buttonNamed(f.screen.page, "Check breach exposure"));
    await settle(20);
    expect({ listed: listed(f.bob.store, f.old), ranges: f.screen.ranges }).toEqual({ listed: false, ranges: [] });
    await f.screen.unmount();
  });
});
