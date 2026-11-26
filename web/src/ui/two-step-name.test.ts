import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { TOTP_ENROLL_FIRST } from "./account-delete";
import { deleteErrorText } from "./account-delete";
import { ApiError } from "../api/client";

/**
 * One name for one thing: the design and the wording approved on 2026-11-17 say "two-step sign-in". The two-step card
 * and the account deletion say that, through their keys, and no sentence a person reads there says "two-factor" or
 * "second factor" any more.
 */
const here = dirname(fileURLToPath(import.meta.url));
const src = (f: string) => readFileSync(join(here, f), "utf8");
/** [s] without its comments (block, JSX and line comments). */
const code = (s: string) => s.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:"'`])\/\/.*$/gm, "$1");

describe("two-step sign-in, by that name", () => {
  it("the two-step card's heading, status, required line, QR label, secret line and button are its keys", () => {
    const card = src("Settings.tsx").slice(src("Settings.tsx").indexOf("function TotpCard("), src("Settings.tsx").indexOf("function PasswordCard("));
    for (const k of ["setErr(TWO_STEP_CHECK_FAILED)", "setMsg(TWO_STEP_TURNED_ON)", "<h2>{TWO_STEP_TITLE}</h2>", "{TWO_STEP_REQUIRED_HERE}", "ariaLabel={TWO_STEP_QR_LABEL}", "{fill(TWO_STEP_SECRET_CLEARS, String(clipClear))}", ": TWO_STEP_TURN_ON}"]) {
      expect(card, k).toContain(k);
    }
  });

  it("account deletion refused until two-step sign-in is on reads its key", () => {
    expect(deleteErrorText(new ApiError(403, "totp_enrollment_required", "x"))).toBe(TOTP_ENROLL_FIRST);
  });

  it("the import report's group of logins whose code secret differs reads its key", () => {
    // Through its tense: the finished screen reads IMPORT_TOTP_DIFFERS, the preview its own key (ui/wrongstate.test.ts).
    expect(src("Vault.tsx")).toContain("{bucket(report.totpDiffers, importTotpDiffersText(preview))}");
    expect(src("Vault.tsx")).toContain("return preview ? IMPORT_TOTP_DIFFERS_PREVIEW : IMPORT_TOTP_DIFFERS;");
  });

  it("no sentence in Settings or the account deletion says two-factor or second factor", () => {
    for (const f of ["Settings.tsx", "account-delete.ts"]) expect(code(src(f)), f).not.toMatch(/two-factor|second factor|\b2FA\b/i);
  });
});
