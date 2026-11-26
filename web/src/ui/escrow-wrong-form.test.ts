import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { ApiError } from "../api/client";
import { ESCROW_WRONG_FORM, refusalOf } from "../vault/settingsflow";
import { ESCROW_WRONG_FORM_TEXT } from "./copy";
import { passwordChangeText } from "./reauthtext";
import { refusalText } from "./Welcome";

/**
 * The server stores only the one form of recovery copy for an account's address and refuses any other with
 * `400 escrow_wrong_form`, at registration, at `PUT /account/recovery` and at `PUT /escrow/self`. This web client seals
 * that form; the code still has its own sentence at all three, and never appears raw.
 */
const here = dirname(fileURLToPath(import.meta.url));
const wrongForm = new ApiError(400, ESCROW_WRONG_FORM, "the server's own words");

describe("escrow_wrong_form has a sentence of its own wherever a recovery copy is sent", () => {
  it("at sign-up (registration)", () => {
    expect(refusalText(wrongForm)).toBe(ESCROW_WRONG_FORM_TEXT);
  });

  it("at the recovery settings and the answer at unlock (PUT /account/recovery)", () => {
    const r = refusalOf(wrongForm);
    expect(r).toEqual({ kind: "refused", code: ESCROW_WRONG_FORM });
    expect(passwordChangeText(r as never)).toBe(ESCROW_WRONG_FORM_TEXT);
  });

  it("at the silent re-seal after a signed rotation (PUT /escrow/self): the prompt says it instead of keeping quiet", () => {
    const prompt = readFileSync(join(here, "EscrowPrompt.tsx"), "utf8");
    expect(prompt).toContain('else if (r.kind === "unavailable" && r.reason === ESCROW_WRONG_FORM) setSealErr(ESCROW_WRONG_FORM_TEXT);');
    expect(prompt).toContain("{sealErr && <div");
    const flow = readFileSync(join(here, "../vault/settingsflow.ts"), "utf8");
    expect(flow).toContain('return { kind: "unavailable", reason: e instanceof ApiError ? e.code : "unreachable" };');
  });

  it("the sentence is marked (a placeholder or approved wording) and names neither the code nor the server's words", () => {
    expect(ESCROW_WRONG_FORM_TEXT).not.toContain(ESCROW_WRONG_FORM);
    expect(ESCROW_WRONG_FORM_TEXT).not.toContain("the server's own words");
    const copy = readFileSync(join(here, "copy.ts"), "utf8");
    const at = copy.indexOf("export const ESCROW_WRONG_FORM_TEXT");
    const mark = Math.max(copy.lastIndexOf("PLACEHOLDER", at), copy.lastIndexOf("Approved wording", at));
    expect(mark).toBeGreaterThan(copy.lastIndexOf("export const", at - 1));
  });
});
