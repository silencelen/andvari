import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import type { MovePlan, VaultInfo, VaultStore } from "../vault/store";
import { MOVE_REMOVING } from "./copy";
import { MoveEverythingPanel } from "./Sharing";

/**
 * "Move everything to a new vault", opened from removing someone: the line MOVE_REMOVING names the person being
 * removed and the vault they are removed from. Its entry numbers the vault {0} and the person {1}; the panel once gave
 * them the other way round, so the vault's name stood where the person's belongs and the person's inside the quotation
 * marks. Rendered with a vault and a person whose names cannot be confused; the line's other words are not pinned.
 */
const VAULT = "Garden Club Shared";
const PERSON = "Priya Raman";

function storeFor(plan: MovePlan): VaultStore {
  return {
    movePlan: () => plan,
    moveDeleteWaiting: () => false,
  } as unknown as VaultStore;
}

function render(removing: string | null): string {
  const vault: VaultInfo = { vaultId: "v-1", type: "shared", name: VAULT, role: "owner" };
  const plan: MovePlan = { vaultId: "v-1", sourceStays: false, members: [], itemCount: 3, uncopyable: 0, resume: null };
  return renderToStaticMarkup(
    createElement(MoveEverythingPanel, {
      vault,
      store: storeFor(plan),
      serverNames: new Map(),
      removing,
      removingName: removing === null ? "" : PERSON,
      onClose: () => undefined,
      onMoved: () => undefined,
    }),
  );
}

/** The paragraphs of [html] that are not in [without]: the lines the removal adds to the panel. */
function addedParagraphs(html: string, without: string): string[] {
  const paras = (s: string) => [...s.matchAll(/<p[^>]*>([\s\S]*?)<\/p>/g)].map((m) => m[1]!);
  const before = new Set(paras(without));
  return paras(html).filter((p) => !before.has(p));
}

describe("the move panel opened from removing someone", () => {
  it("MOVE_REMOVING puts the vault inside the quotation marks and names the person outside them", () => {
    const added = addedParagraphs(render("u-priya"), render(null));
    expect(added).toHaveLength(1);
    const line = added[0]!;
    expect(line).toContain(`“${VAULT}”`);
    expect(line).not.toContain(`“${PERSON}”`);
    expect(line.replace(`“${VAULT}”`, "")).toContain(PERSON);
    expect(line).not.toContain("{0}");
    expect(line).not.toContain("{1}");
  });

  it("the line is the entry's own: its words around the two names are MOVE_REMOVING's", () => {
    const line = addedParagraphs(render("u-priya"), render(null))[0]!;
    const words = MOVE_REMOVING.split(/\{\d+\}/).filter((w) => w.trim() !== "");
    for (const w of words) expect(line).toContain(w.replace(/'/g, "&#x27;"));
  });
});
