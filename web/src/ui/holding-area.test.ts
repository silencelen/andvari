import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import type { VaultStore } from "../vault/store";
import { REMOVE_FROM_THIS_DEVICE } from "./copy";
import { fmtDay } from "./format";
import { RecentlyRemoved } from "./Sharing";
import { noticeBody } from "./Vault";

/**
 * Design §3.8, spec 02 §10.6: what the holding area tells the person names the day the copy leaves this device (30 days
 * from the verification), never the vault's purge time; and every held copy offers "Remove from this device".
 */

const DAY = 86_400_000;
const V = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";

function storeWith(h: { reason: string; verified: boolean; purgeAt?: number; expungeAt: number }): VaultStore {
  return {
    heldVaults: () => [{ vaultId: V, name: "Family", itemCount: 0, canCopyOut: false, ...h }],
  } as unknown as VaultStore;
}

describe("the holding area's words", () => {
  const purgeAt = Date.UTC(2026, 10, 20, 12);
  const expungeAt = Date.UTC(2026, 11, 13, 12);

  it("a deleted vault's line names the day its copy leaves, not the purge", () => {
    const html = renderToStaticMarkup(createElement(RecentlyRemoved, { store: storeWith({ reason: "deleted", verified: true, purgeAt, expungeAt }), hide: [] }));
    expect(html).toContain(`kept sealed until ${fmtDay(expungeAt)}`);
    expect(html).not.toContain(fmtDay(purgeAt));
    expect(html).toContain(REMOVE_FROM_THIS_DEVICE);
  });

  it("the notice after a verified delete names the same day", () => {
    const { body } = noticeBody({ id: "n", vaultId: V, vaultName: "Family", kind: "deleted", purgeAt, keptUntil: expungeAt });
    expect(body).toContain(fmtDay(expungeAt));
    expect(body).not.toContain(fmtDay(purgeAt));
  });

  it("every other reason's line names its own day too", () => {
    for (const reason of ["left", "removed"]) {
      const html = renderToStaticMarkup(createElement(RecentlyRemoved, { store: storeWith({ reason, verified: true, expungeAt: expungeAt + DAY }), hide: [] }));
      expect(html).toContain(fmtDay(expungeAt + DAY));
    }
  });
});
