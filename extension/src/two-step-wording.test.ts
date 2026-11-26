// node --test (see version.test.ts). One name for one thing: the design and the wording approved on 2026-11-17 say
// "two-step sign-in"; the extension's sentences say that, and no sentence a person reads says "two-factor" or "2FA".
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { ADD_TOTP_LABEL, TOTP_COPIED_TOAST, TOTP_SHOWN_TOAST } from "./copy.ts";
import { TOTP_ENROLL_REQUIRED, unlockErrorCopy } from "./errors.ts";

const read = (f: string): string => readFileSync(new URL(f, import.meta.url), "utf-8");

/** Every string literal in [src] (quoted or template), comments left out. */
function literals(src: string): string[] {
  const noComments = src.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:"'`])\/\/.*$/gm, "$1");
  return [...noComments.matchAll(/"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*'|`(?:[^`\\]|\\.)*`/g)].map((m) => m[0]);
}

test("the four lines the wording page names are the extension's named lines, shown where they belong", () => {
  // Named by their constants (the wording page's NW1): the owner's words go into them by a tool.
  assert.equal(unlockErrorCopy("totp_enroll_required"), TOTP_ENROLL_REQUIRED);
  const content = read("./content.ts");
  assert.match(content, /const TOTP_COPIED_TOAST = T\.TOTP_COPIED_TOAST;/);
  assert.match(content, /const TOTP_SHOWN_TOAST = T\.TOTP_SHOWN_TOAST;/);
  assert.match(content, /showToast\(TOTP_COPIED_TOAST\);/);
  assert.match(content, /showToast\(`\$\{TOTP_SHOWN_TOAST\} \$\{code\}`, true\);/);
  const popup = read("./popup.ts");
  assert.match(popup, /const ADD_TOTP_LABEL = T\.ADD_TOTP_LABEL;/);
  assert.match(popup, /actBtn\(T\.BTN_ADD, ADD_TOTP_LABEL, /);
  for (const s of [TOTP_COPIED_TOAST, TOTP_SHOWN_TOAST, ADD_TOTP_LABEL, TOTP_ENROLL_REQUIRED]) assert.ok(s.length > 0);
});

test("no sentence in errors, copy, content or popup says two-factor or 2FA", () => {
  for (const f of ["./errors.ts", "./copy.ts", "./content.ts", "./popup.ts"]) {
    const hits = literals(read(f)).filter((s) => /two-factor|\b2FA\b/i.test(s));
    assert.deepEqual(hits, [], f);
  }
});
