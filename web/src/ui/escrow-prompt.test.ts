import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { SessionWrap } from "../vault/sessionwrap";
import { escrowQuestionOffered } from "./EscrowPrompt";
import { ESCROW_KEEP, ESCROW_LATER, ESCROW_NOT_NOW, ESCROW_TURN_OFF, ESCROW_UNSIGNED_BODY, ESCROW_UNSIGNED_KEEP, ESCROW_UNSIGNED_OFF } from "./copy";

const here = (p: string) => fileURLToPath(new URL(p, import.meta.url));
const design = readFileSync(here("../../../docs/design/2026-11-15-onboarding-trust.md"), "utf8");
const prompt = readFileSync(here("./EscrowPrompt.tsx"), "utf8");

/** Design §4.5 at unlock (the flow itself is graded in vault/settingsflow.test.ts). */
describe("the escrow prompt at unlock", () => {
  it("uses the design's own words for both prompts and their buttons", () => {
    expect(design).toContain("Keep that?\" with [Not now]");
    for (const b of [ESCROW_NOT_NOW, ESCROW_KEEP, ESCROW_TURN_OFF, ESCROW_UNSIGNED_OFF, ESCROW_UNSIGNED_KEEP, ESCROW_LATER]) expect(design).toContain(`[${b}]`.replace("[Turn off operator recovery]", "[ Turn off operator recovery ]").replace("[Keep it with the new key]", "[ Keep it with the new key ]").replace("[Later]", "[ Later ]"));
    expect(design).toContain(ESCROW_UNSIGNED_BODY);
  });

  it("empties its password field after any ending: a refusal, the back-off, a thrown failure, the unsigned-change turn", () => {
    const answer = prompt.slice(prompt.indexOf("const answer = async"), prompt.indexOf("const name = decodeName("));
    const fin = answer.slice(answer.lastIndexOf("} finally {"));
    expect(fin).toMatch(/setPassword\(""\);/);
    // Every early return sits inside the try, so the finally runs for it.
    const tryBody = answer.slice(answer.indexOf("try {"), answer.lastIndexOf("} finally {"));
    expect((answer.match(/return /g) ?? []).length).toBe((tryBody.match(/return /g) ?? []).length);
  });

  it("defaults to the safe answer: Not now for 'Keep that?', Turn off for the unsigned change", () => {
    const ask = prompt.slice(prompt.lastIndexOf(") : ("));
    expect(ask.indexOf('className="primary"')).toBeLessThan(ask.indexOf("ESCROW_NOT_NOW"));
    expect(ask.indexOf("ESCROW_NOT_NOW")).toBeLessThan(ask.indexOf("ESCROW_KEEP"));
    const unsigned = prompt.slice(prompt.indexOf("{unsigned ? (\n          <>\n            <button"));
    expect(unsigned.indexOf('className="primary"')).toBeLessThan(unsigned.indexOf("ESCROW_UNSIGNED_OFF"));
    // Both changes go through the one password path; nothing in the prompt seals on its own.
    expect(prompt).toContain("setRecoveryPosture(");
    expect(prompt).not.toContain("sealUvkV2");
    // Run at unlock, but never on a copy read under a forked pin (§4.4: nothing is sent).
    const vault = readFileSync(here("./Vault.tsx"), "utf8");
    // Nor on the offline copy opened while the server is out of reach: the re-seal waits until a sync reaches it.
    expect(vault).toContain("<EscrowPrompt settings={readOnlyCopy || fromCopy ? undefined : settings} shared={store.sharedLogs()} />");
    expect(vault).toContain("const readOnlyCopy = readOnlyProp || store.isReadOnlyCopy();");
  });

  it("spec 01 §7: the question is not offered while the session knows the server's keys are not this browser's; the silent re-seal still runs", () => {
    const marked = new SessionWrap(null);
    marked.markServerKeysNotKnown();
    expect(escrowQuestionOffered({ wrap: marked })).toBe(false);
    expect(escrowQuestionOffered({ wrap: new SessionWrap(null) })).toBe(true);
    // Read both where the answer is taken and where the prompt is drawn; the re-seal's own path is unchanged.
    expect(prompt).toMatch(/if \(r\.kind === "ask"\) \{\s*if \(escrowQuestionOffered\(settings\)\) setPrompt\(r\.decision\);/);
    expect(prompt).toContain("if (prompt === null || !escrowQuestionOffered(settings)) {");
    expect(prompt).toContain("void escrowAtUnlock(settings, shared.accountState, storage, Date.now())");
  });
});
