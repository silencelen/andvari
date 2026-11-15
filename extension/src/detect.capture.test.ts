// node --test. Pins H04 (2026-09-13 audit): which password field the capture engine reads. The DOM
// builders (buildLoginForm) can't run here, so the choice is a pure function over the password
// fields in document order — the same factoring detect.cards.test.ts uses for the card verdicts.
//
// Both change-password shapes used to capture the CURRENT password: the 2a rule then matched the
// stored item and drew no banner, so a site-side password change (or a generated password that
// existed only in the page) was silently lost.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { chooseCapturePassword, chooseEnteredCapture } from "./detect.ts";

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

// ---- what the person entered comes first (0.30.0 release check) ----
//
// chooseEnteredCapture: a field that received trusted input, or that andvari filled or generated into at the person's
// request, is read before one that did not. A honeypot trap is never entered; one drawn under another field passes the
// detection rules, and two of them beside the real password read as the three-field change-password shape.
const trap = { name: "trap" };
const trap2 = { name: "trap2" };
const real = { name: "real" };
const only = (...fields: object[]) => (f: object): boolean => fields.includes(f);
const nobody = (): boolean => false;

test("entered: nothing entered leaves every shape's pick as it was", () => {
  for (const [pw, nw, fill] of [
    [[current], [], current],
    [[current, fresh, confirm], [fresh, confirm], current],
    [[current, fresh, confirm], [], current],
    [[fresh, confirm], [fresh, confirm], fresh],
    [[real, trap, trap2], [], real],
  ] as const) {
    assert.equal(chooseEnteredCapture(pw, nw, fill, nobody), chooseCapturePassword(pw, nw, fill));
  }
});

test("entered: two traps beside the real password no longer make the capture read a trap", () => {
  // The filltest honeypot page as a browser's detection sees it: the real password, then two covered traps.
  assert.equal(chooseCapturePassword([real, trap, trap2], [], real), trap, "the pick without what was entered");
  assert.equal(chooseEnteredCapture([real, trap, trap2], [], real, only(real)), real);
  // A trap before the real password (two unflagged passwords read as the signup pair; the fill target is the trap).
  assert.equal(chooseEnteredCapture([trap, real], [trap, real], trap, only(real)), real);
  // And a trap inside a change of password the person typed out.
  assert.equal(chooseEnteredCapture([current, trap, fresh, confirm], [], current, only(current, fresh, confirm)), fresh);
});

test("entered: a change of password keeps its pick once the new password is typed", () => {
  // Hintless: while only the current password is typed the capture holds it; the new one replaces it as it is typed.
  assert.equal(chooseEnteredCapture([current, fresh, confirm], [], current, only(current)), current);
  assert.equal(chooseEnteredCapture([current, fresh, confirm], [], current, only(current, fresh)), fresh);
  assert.equal(chooseEnteredCapture([current, fresh, confirm], [], current, only(current, fresh, confirm)), fresh);
  // Hinted: the new-password field, as before.
  assert.equal(chooseEnteredCapture([current, fresh, confirm], [fresh, confirm], current, only(current, fresh, confirm)), fresh);
  // A generated password lands in both new fields, which andvari records as entered.
  assert.equal(chooseEnteredCapture([current, fresh, confirm], [fresh, confirm], current, only(fresh, confirm)), fresh);
});

test("entered: a field the person entered is never passed over for one they did not", () => {
  const shapes = [
    [[current], [], current],
    [[current, fresh, confirm], [fresh, confirm], current],
    [[current, fresh, confirm], [], current],
    [[fresh, confirm], [fresh, confirm], fresh],
    [[real, trap, trap2], [], real],
    [[trap, real], [trap, real], trap],
  ] as const;
  for (const [pw, nw, fill] of shapes) {
    for (let mask = 1; mask < 1 << pw.length; mask++) {
      const typed = pw.filter((_, i) => mask & (1 << i));
      const got = chooseEnteredCapture(pw, nw, fill, only(...typed));
      assert.ok(typed.includes(got), `${pw.map((f) => f.name).join(",")} typed ${typed.map((f) => f.name).join(",")}: ${got.name}`);
    }
  }
});

