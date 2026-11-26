import { describe, expect, it } from "vitest";
import type { LifecycleNotice } from "../vault/store";
import { fill, ITEM_BROUGHT_BACK, ITEM_BROUGHT_BACK_MANY, ITEM_BROUGHT_BACK_UNNAMED } from "./copy";
import { noticeBody } from "./Vault";

/**
 * The notice that a change of this browser brought back an item deleted elsewhere (spec 03 §5): one change has a line of
 * its own whether or not this browser can name the item, and only two or more are counted.
 */
const notice = (parkedCount: number, itemName?: string): LifecycleNotice =>
  ({ id: "n", vaultId: "v", vaultName: "Family", kind: "item-brought-back", parkedCount, ...(itemName !== undefined ? { itemName } : {}) }) as LifecycleNotice;

describe("a change that brought back an item deleted elsewhere", () => {
  it("one change whose item cannot be named has its own line, never '1 of your changes'", () => {
    // On the code before: fill(ITEM_BROUGHT_BACK_MANY, "1", "Family"), "1 of your changes ... brought back items".
    expect(noticeBody(notice(1)).body).toBe(fill(ITEM_BROUGHT_BACK_UNNAMED, "Family"));
    expect(noticeBody(notice(1)).body).not.toBe(fill(ITEM_BROUGHT_BACK_MANY, "1", "Family"));
  });

  it("one change whose item is named, and two or more changes, keep their lines", () => {
    expect(noticeBody(notice(1, "router")).body).toBe(fill(ITEM_BROUGHT_BACK, "router", "Family"));
    expect(noticeBody(notice(2)).body).toBe(fill(ITEM_BROUGHT_BACK_MANY, "2", "Family"));
    expect(noticeBody(notice(2)).warn).toBe(false);
  });
});
