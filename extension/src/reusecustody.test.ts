// node --test. Security review 2026-10 (root cause E, two MEDIUM findings): the signup reuse alert
// was a page-drivable vault-wide password-membership oracle.
//
// (1) The typed-by-user mark was per FIELD: any trusted keystroke armed it, and the value asked
//     about was whatever `.value` held at focusout — so a page swapped a guess in after each real
//     keystroke (`field.value = guess; field.blur()`) and got one membership query per keypress.
//     The mark is now per VALUE (ReuseCustody): only a value the user's own keystrokes produced,
//     edit by edit from an empty field, can be asked about.
// (2) The answer was a toast drawn in the page, which the page read back by hit-testing. The answer
//     now goes to extension-owned UI only (the toolbar badge + the popup) — the wiring pins below.
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { ReuseCustody } from "./reusealert.ts";

/** A field as the content script sees it: the live value and the caret/selection. */
class Field {
  value = "";
  selStart: number | null = 0;
  selEnd: number | null = 0;
}

/** One real keystroke as the browser delivers it: trusted keydown (our capture listener runs), the
 *  browser's own edit, then the trusted input event. `pageAtKeydown` runs between our keydown
 *  listener and the browser's edit — exactly where a page's own keydown handler sits. */
function keystroke(c: ReuseCustody<Field>, f: Field, key: string, pageAtKeydown?: (f: Field) => void): void {
  c.keydown(f, { value: f.value, selStart: f.selStart, selEnd: f.selEnd, key });
  pageAtKeydown?.(f);
  let inputType: string;
  let data: string | null = null;
  const s = f.selStart ?? f.value.length;
  const e = f.selEnd ?? f.value.length;
  if (key === "Backspace") {
    inputType = "deleteContentBackward";
    f.value = s !== e ? f.value.slice(0, s) + f.value.slice(e) : f.value.slice(0, Math.max(0, s - 1)) + f.value.slice(s);
    f.selStart = f.selEnd = s !== e ? s : Math.max(0, s - 1);
  } else {
    inputType = "insertText";
    data = key;
    f.value = f.value.slice(0, s) + key + f.value.slice(e);
    f.selStart = f.selEnd = s + key.length;
  }
  c.input(f, f.value, inputType, data);
}

function type(c: ReuseCustody<Field>, f: Field, text: string): void {
  for (const ch of text) keystroke(c, f, ch);
}

test("a value the user typed is askable — and only that exact value", () => {
  const c = new ReuseCustody<Field>();
  const f = new Field();
  type(c, f, "hunter22");
  assert.equal(c.askable(f, "hunter22"), true);
  assert.equal(c.askable(f, "password1"), false);
  keystroke(c, f, "Backspace");
  assert.equal(c.askable(f, "hunter2"), true, "a real Backspace keeps custody");
});

test("THE ORACLE: a guess swapped in after a real keystroke is never askable", () => {
  const c = new ReuseCustody<Field>();
  const f = new Field();
  const guesses = ["123456", "password", "qwerty12", "letmein1"];
  // On each real keystroke the page sets `.value` to its next guess and drives focusout.
  for (const [i, ch] of [..."abcd"].entries()) {
    keystroke(c, f, ch);
    f.value = guesses[i]!;
    assert.equal(c.askable(f, f.value), false, `guess ${i} must not be askable`);
  }
});

test("a value the page rewrites DURING the keystroke loses custody (prefix pre-seed)", () => {
  const c = new ReuseCustody<Field>();
  const f = new Field();
  type(c, f, "ab");
  // The page knows e.key: it pre-seeds a guess minus its last char so the user's key completes it.
  keystroke(c, f, "1", (fld) => {
    fld.value = "password";
    fld.selStart = fld.selEnd = fld.value.length;
  });
  assert.equal(f.value, "password1");
  assert.equal(c.askable(f, "password1"), false);
  // …and custody stays lost while the field holds a script-written value, however long the user types.
  type(c, f, "xyz");
  assert.equal(c.askable(f, f.value), false);
});

test("a page edit that no trusted keystroke announced (execCommand / drop / script) loses custody", () => {
  const c = new ReuseCustody<Field>();
  const f = new Field();
  type(c, f, "abcd");
  f.value = "abcdpassword";
  c.input(f, f.value, "insertText", "password"); // a trusted input with no keydown behind it
  assert.equal(c.askable(f, f.value), false);
});

test("an insert that is not the key the user pressed loses custody", () => {
  const c = new ReuseCustody<Field>();
  const f = new Field();
  c.keydown(f, { value: "", selStart: 0, selEnd: 0, key: "a" });
  f.value = "password"; // the page's handler cancelled the keystroke and inserted its own text
  c.input(f, f.value, "insertText", "password");
  assert.equal(c.askable(f, "password"), false);
});

test("custody recovers from an empty field, and resets on our own fill", () => {
  const c = new ReuseCustody<Field>();
  const f = new Field();
  f.value = "prefilled";
  f.selStart = f.selEnd = f.value.length;
  type(c, f, "x");
  assert.equal(c.askable(f, f.value), false, "a script-filled start never gains custody");
  f.selStart = 0; // select-all, then Backspace — the user cleared the field themselves
  keystroke(c, f, "Backspace");
  type(c, f, "fresh123");
  assert.equal(c.askable(f, "fresh123"), true);
  c.reset(f);
  assert.equal(c.askable(f, "fresh123"), false);
});

test("the oracle gives the same (no) answer whatever the page swaps in", () => {
  // Same user keystrokes, three page behaviours: none, swap-after, swap-during. Only the value
  // the user produced is ever askable, so a swap cannot move the answer.
  const run = (page: "none" | "after" | "during"): boolean[] => {
    const c = new ReuseCustody<Field>();
    const f = new Field();
    const out: boolean[] = [];
    for (const ch of "s3cr3t!x") {
      keystroke(c, f, ch, page === "during" ? (fld) => { fld.value = "guess"; fld.selStart = fld.selEnd = 5; } : undefined);
      if (page === "after") f.value = "guess" + ch;
      out.push(c.askable(f, "guess" + ch));
    }
    return out;
  };
  const none = run("none");
  assert.deepEqual(run("after"), none);
  assert.deepEqual(run("during"), none);
  assert.ok(none.every((x) => x === false));
});

// ---- wiring: the answer never reaches the page ----

const src = (f: string) => readFileSync(new URL(`./${f}`, import.meta.url), "utf-8");
const ct = src("content.ts");
const bg = src("background.ts");
const msgs = src("messages.ts");
const popup = src("popup.ts");

function spanOf(s: string, from: string, to: string): string {
  const a = s.indexOf(from);
  assert.ok(a > -1, `span start missing: ${from}`);
  const b = s.indexOf(to, a);
  assert.ok(b > a, `span end missing or out of order: ${to}`);
  return s.slice(a, b);
}

test("content asks only with per-value custody and draws nothing in the page", () => {
  const ask = spanOf(ct, "async function checkPasswordReuse(", "// ---- capture engine ----");
  assert.ok(ask.includes("reuseCustody.askable(input, value)"), "the ask is gated on the value's custody");
  assert.ok(!ask.includes("showToast"), "no in-page toast: its presence was the page-readable answer");
  assert.ok(!ask.includes("reuseWarning("), "content never even sees a count to render");
  assert.ok(!ct.includes("reuseTyped"), "the per-field mark is gone");
});

test("the SW keeps the count: the page-facing answer carries none, the popup reads it", () => {
  assert.match(msgs, /T extends "passwordReuse"\s*\?\s*\{ ok: boolean \}/, "the passwordReuse answer carries no count");
  const h = spanOf(bg, 'case "passwordReuse": {', 'case "reuseNotice": {');
  const answers = h.match(/return \{[^}]*\} satisfies Res<"passwordReuse">/g) ?? [];
  assert.ok(answers.length >= 4, "every refusal and the hit answer the same bare shape");
  for (const a of answers) assert.match(a, /^return \{ ok: (true|false) \} satisfies/, `no count may ride the answer: ${a}`);
  assert.ok(h.includes("reuseNotices.set("), "a hit is recorded SW-side");
  const n = spanOf(bg, 'case "reuseNotice": {', "}\n    case");
  assert.ok(n.includes("if (sender.tab !== undefined)"), "only the popup (no tab) may read the notice");
  assert.ok(popup.includes('ask({ type: "reuseNotice" })'), "the popup renders it");
});
