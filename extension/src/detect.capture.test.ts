// node --test. Pins H04 (2026-09-13 audit): which password field the capture engine reads. The DOM
// builders (buildLoginForm) can't run here, so the choice is a pure function over the password
// fields in document order — the same factoring detect.cards.test.ts uses for the card verdicts.
//
// Both change-password shapes used to capture the CURRENT password: the 2a rule then matched the
// stored item and drew no banner, so a site-side password change (or a generated password that
// existed only in the page) was silently lost.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { chooseCapturePassword } from "./detect.ts";

// Fields are stand-ins: only identity matters, and document order is the array order.
const current = { name: "current" };
const fresh = { name: "new" };
const confirm = { name: "confirm" };

test("plain sign-in: one password field — capture == fill target", () => {
  assert.equal(chooseCapturePassword([current], [], current), current);
});

test("hinted change-password (current-password + new-password + confirm): capture the NEW field, fill stays current", () => {
  // detect: flagged = [new, confirm] ⇒ newPasswords; primary = the unflagged current field.
  assert.equal(chooseCapturePassword([current, fresh, confirm], [fresh, confirm], current), fresh);
});

test("hinted change-password with a lone new-password field: capture it", () => {
  assert.equal(chooseCapturePassword([current, fresh], [fresh], current), fresh);
});

test("hintless change-password (three unflagged passwords): capture the SECOND (current, new, confirm)", () => {
  // detect: no hints ⇒ newPasswords = [], isSignup false, primary = passwords[0] (the fill target).
  // Verifier correction on H04: this shape must not depend on the new-password hint.
  assert.equal(chooseCapturePassword([current, fresh, confirm], [], current), fresh);
});

test("classic signup pair (two unflagged passwords): capture the first — it is the new password", () => {
  // detect: isSignup ⇒ newPasswords = both; primary = passwords[0].
  assert.equal(chooseCapturePassword([fresh, confirm], [fresh, confirm], fresh), fresh);
});

test("the capture choice never returns a field outside the form's own passwords", () => {
  for (const [pw, nw, fill] of [
    [[current], [], current],
    [[current, fresh, confirm], [fresh, confirm], current],
    [[current, fresh, confirm], [], current],
    [[fresh, confirm], [fresh, confirm], fresh],
  ] as const) {
    assert.ok(pw.includes(chooseCapturePassword(pw, nw, fill)));
  }
});
