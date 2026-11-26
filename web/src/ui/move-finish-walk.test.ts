import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { MOVE_DISCARDED, MOVE_DISCARDED_SAME_NAME, MOVE_DONE, MOVE_DONE_ALONE, fill, withoutLastSentence } from "./copy";
import { moveResultText } from "./Sharing";
import type { MoveResult } from "../vault/store";

/**
 * Faults a walk in a real browser found in a move whose old vault's deletion waits, its "Finish the move", and the
 * password change whose answer was lost (headless Chrome against a test server, the other member through the engine's
 * own code). Each is pinned here; the walk itself lives outside the repository.
 */
const here = (p: string) => fileURLToPath(new URL(p, import.meta.url));
const read = (p: string) => readFileSync(here(p), "utf8");

const result = (over: Partial<MoveResult>): MoveResult => ({
  newVaultId: "v-new",
  name: "Trip 2",
  copied: 1,
  oldDeleted: { purgeAt: Date.UTC(2026, 10, 23, 12) },
  oldKept: null,
  notAdded: [],
  added: 0,
  uncopyable: 0,
  changed: 0,
  discarded: null,
  ...over,
});

describe("what a finished move says", () => {
  it("asks no one to accept the new vault when the move added nobody (the other member had left)", () => {
    const alone = moveResultText(result({ added: 0 }), "Trip");
    const withPeople = moveResultText(result({ added: 1 }), "Trip");
    // MOVE_DONE_ALONE is MOVE_DONE less its last sentence (the one that asks the people added), whatever the words are.
    expect(MOVE_DONE_ALONE).toBe(withoutLastSentence(MOVE_DONE));
    expect(alone).toBe(withoutLastSentence(withPeople));
    expect(withPeople.startsWith(fill(MOVE_DONE, "Trip 2", "Trip").split("{2}")[0] ?? "")).toBe(true);
    expect(alone.startsWith(fill(MOVE_DONE_ALONE, "Trip 2", "Trip").split("{2}")[0] ?? "")).toBe(true);
    expect(alone).not.toContain("{");
  });

  it("withoutLastSentence drops exactly the last sentence and refuses a single one", () => {
    expect(withoutLastSentence("One. Two (three). Four “x”.")).toBe("One. Two (three).");
    expect(withoutLastSentence("Is it “A.” Yes.")).toBe("Is it “A.”");
    expect(withoutLastSentence("Done! Next?  Last.")).toBe("Done! Next?");
    expect(() => withoutLastSentence("Only one sentence.")).toThrow();
    expect(() => withoutLastSentence("v1.2 is out")).toThrow();
  });

  it("does not say “everything is in Trip 2” and “Trip 2 was deleted” about two vaults of one name", () => {
    const same = moveResultText(result({ discarded: { vaultId: "v-half", name: "Trip 2", deleted: true } }), "Trip");
    expect(same).toContain("so that one was deleted and this move made a new “Trip 2”.");
    expect(same).not.toContain("made a fresh one");
    expect(MOVE_DISCARDED_SAME_NAME).toContain("{0}");
    // A different name keeps the earlier sentence.
    expect(moveResultText(result({ name: "Trip fresh", discarded: { vaultId: "v-half", name: "Trip 2", deleted: true } }), "Trip")).toContain(MOVE_DISCARDED.replace("{0}", "Trip 2"));
  });

  it("the store says how many people the move added, on both of its endings", () => {
    const src = read("../vault/store.ts");
    expect(src).toMatch(/readonly added: number;/);
    expect(src).toContain("added: heldRun.added.size,");
    expect(src).toContain("added: run.added.size,");
  });
});

describe("the old vault's panel while its deletion waits, on a phone", () => {
  it("lets its sentence take a line of its own instead of a column of one or two words beside the button", () => {
    const src = read("./Sharing.tsx");
    const at = src.indexOf("fill(MOVE_WAITING_PANEL");
    const row = src.slice(src.lastIndexOf("<div", at), at);
    expect(row).toContain('flexWrap: "wrap"');
    expect(row).toMatch(/<span style=\{\{ flex: "1 1 16em" \}\}>/);
  });
});

describe("the move's panel after its deletion was held", () => {
  it("does not also say the move stopped after copying some items, and its button says “Finish the move”", () => {
    const src = read("./Sharing.tsx");
    const panel = src.slice(src.indexOf("function MoveEverythingPanel"), src.indexOf("function useServerNames"));
    expect(panel).toContain("const deleteWaiting = store.moveDeleteWaiting(vault.vaultId);");
    expect(panel).toMatch(/\{plan\.resume !== null && !deleteWaiting && <div className="msg info"[^\n]*MOVE_RESUME/);
    expect(panel).toContain("onClick={go}>{deleteWaiting ? MOVE_FINISH : MOVE_EVERYTHING}</button>");
  });
});

describe("“Finish the move” by keyboard", () => {
  const src = read("./Sharing.tsx");
  const body = src.slice(src.indexOf("export function UnfinishedMoves"), src.indexOf("function MoveEverythingPanel"));

  it("moves the focus to the note's OK once the move ends, instead of dropping it to the page's start", () => {
    expect(body).toContain("ref={okRef}");
    expect(body).toMatch(/if \(said !== null && focusNote\.current\) okRef\.current\?\.focus\(\);/);
    expect(body.match(/focusNote\.current = true;/g)?.length).toBe(2);
  });

  it("closes the note with Escape as with OK, and leaves the focus on the main region", () => {
    expect(body).toMatch(/if \(e\.key === "Escape"\) \{ e\.stopPropagation\(\); closeNote\(\); \}/);
    expect(body).toContain("onClick={closeNote}");
    expect(body).toContain('document.getElementById("main-content")?.focus()');
    expect(read("./Vault.tsx")).toContain('const MAIN_ID = "main-content";');
  });

  it("the old vault's panel: Enter on its “Finish the move” puts the focus in the move's panel, Escape closes it and gives the focus back", () => {
    const panel = src.slice(src.indexOf("function MoveEverythingPanel"), src.indexOf("function useServerNames"));
    expect(panel).toMatch(/if \(at === null \|\| at === document\.body\) panelRef\.current\?\.focus\(\);/);
    expect(panel).toMatch(/ref=\{panelRef\}\s*tabIndex=\{-1\}/);
    expect(panel).toMatch(/if \(e\.key === "Escape" && !busy\) \{\s*e\.stopPropagation\(\);\s*onClose\(\);/);
    // The panel takes the focus as a whole, never on its primary button.
    expect(panel).not.toMatch(/autoFocus/);
    const owner = src.slice(src.indexOf("const [moving, setMoving]"), src.indexOf("function MoveEverythingPanel"));
    expect(owner).toMatch(/if \(moving === undefined && refocusOpener\.current\) moveOpener\.current\?\.focus\(\);/);
    expect(owner).toMatch(/onClose=\{\(\) => \{\s*refocusOpener\.current = true;\s*setMoving\(undefined\);/);
    expect(owner).toContain("ref={moveOpener} disabled={busy || store.movePlan(vault.vaultId) === null} onClick={() => setMoving({ removing: null })}>{MOVE_FINISH}");
    expect(owner).toContain("ref={moveOpener} disabled={busy} onClick={() => setMoving({ removing: null })}>{MOVE_EVERYTHING}");
  });

  it("never takes the focus by itself: nothing in the banner is focused on mount", () => {
    expect(body).not.toMatch(/autoFocus/);
  });
});

describe("a password change whose answer was lost", () => {
  it("leaves no new password typed in the form, ready to be sent again", () => {
    const src = read("./Settings.tsx");
    const card = src.slice(src.indexOf("function PasswordCard"), src.indexOf("return (", src.indexOf("function PasswordCard")));
    expect(card).toMatch(/if \(r\.kind === "unknown"\) \{\s*setNext\(""\);\s*setConfirm\(""\);/);
    const caught = card.slice(card.indexOf("} catch (e) {"));
    expect(caught).toMatch(/setCurrent\(""\);\s*setNext\(""\);\s*setConfirm\(""\);/);
  });
});
