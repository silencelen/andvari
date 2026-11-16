// node --test. The filltest site's honeypot page (login/honeypot.html), whose form extension/test-pages/login-honeypot.html
// carries as the site serves it: seven username and password traps around a real username and password, each hidden a
// different way. The 0.30.0 release check ran detection over it in Chrome: the save capture read a trap, in 0.29.1 the
// "visibility hidden" one and since then the "1 by 1 px" one. That page's own input rule is more specific than the trap
// classes, so the "1 by 1 px" and "clipped" traps are drawn full width, about 20 px high, one under the next trap: they pass
// the detection rules (only the fill-time hit test sees them covered), and three password fields read as the change-password
// shape, whose capture is the SECOND field. The capture now reads the field the person entered (chooseEnteredCapture).
//
// No layout here: what a browser's detection keeps of the page is the measured list below (headless Chrome, 1280 x 900, this
// file and the site's page alike), and the worst case, every password field of the page, is checked beside it.
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { chooseCapturePassword, chooseEnteredCapture } from "./detect.ts";

const html = readFileSync(new URL("../test-pages/login-honeypot.html", import.meta.url), "utf-8");
const form = html.slice(html.indexOf("<form"), html.indexOf("</form>"));
const attr = (tag: string, name: string): string | null => tag.match(new RegExp(`\\s${name}="([^"]*)"`))?.[1] ?? null;
const inputs = [...form.matchAll(/<input\b[^>]*>/g)].map((m) => ({ id: attr(m[0], "id")!, type: attr(m[0], "type") ?? "text", trap: attr(m[0], "data-trap") === "1" }));
const passwordIds = inputs.filter((i) => i.type === "password").map((i) => i.id);

/** The password fields detection keeps of the page in Chrome: hp4 is visibility:hidden; hp5 and hp6 measure 446 x 20 px. */
const DETECTED = ["real-pass", "hp5", "hp6"];

/** newPasswords as detect.ts builds them for unflagged fields: two are the signup pair (both), three or more none. */
const newPasswordsOf = (passwords: readonly string[]): string[] => (passwords.length === 2 ? [...passwords] : []);

test("the fixture is the honeypot page: two real fields and seven traps, each hidden a different way", () => {
  assert.deepEqual(inputs.filter((i) => !i.trap).map((i) => i.id), ["real-user", "real-pass"]);
  assert.deepEqual(inputs.filter((i) => i.trap).map((i) => i.id), ["hp1", "hp2", "hp3", "hp4", "hp5", "hp6", "hp7"]);
  assert.deepEqual(passwordIds, ["real-pass", "hp4", "hp5", "hp6"]);
  for (const trick of ["trap-display-none", "trap-offscreen", "trap-opacity", "trap-visibility", "trap-tiny", "trap-clip", "trap-covered"]) {
    assert.ok(form.includes(`class="${trick}`), trick);
  }
  // Every trap is kept from people the ways a honeypot is: out of the tab order, and out of the accessibility tree.
  for (const tag of form.match(/<input\b[^>]*data-trap="1"[^>]*>/g) ?? []) assert.match(tag, /tabindex="-1"/, tag);
  assert.equal((form.match(/aria-hidden="true"/g) ?? []).length, 7);
  // The specificity that lets two of the traps pass the detection rules is the page's own, and stays in the fixture.
  assert.match(html, /input\[type=text\], input\[type=password\] \{[^}]*width: 100%/);
  assert.match(html, /\.trap-tiny \{ position: absolute; width: 1px; height: 1px;/);
});

test("before: three password fields made the capture read the second, a trap", () => {
  assert.deepEqual(DETECTED.filter((id) => !passwordIds.includes(id)), [], "the measured list is the page's own fields");
  assert.equal(chooseCapturePassword(DETECTED, newPasswordsOf(DETECTED), "real-pass"), "hp5");
});

test("the capture reads the password the person typed, whichever traps pass the visibility rules", () => {
  const typed = (id: string): boolean => id === "real-pass";
  for (const detected of [DETECTED, passwordIds, ["real-pass", "hp5"], ["real-pass", "hp6"], ["real-pass"]]) {
    assert.equal(chooseEnteredCapture(detected, newPasswordsOf(detected), "real-pass", typed), "real-pass", detected.join(","));
  }
  // Traps ahead of the real field (so the fill target is a trap, as two unflagged fields read as a signup pair) too.
  assert.equal(chooseEnteredCapture(["hp5", "real-pass"], ["hp5", "real-pass"], "hp5", typed), "real-pass");
  // An andvari fill of the real field is entered as well: the capture reads it, not a trap.
  assert.equal(chooseEnteredCapture(DETECTED, [], "real-pass", (id) => id === "real-pass"), "real-pass");
});

test("with nothing entered detection's pick stands: an empty trap, so nothing is offered for saving", () => {
  // A person who typed nothing has nothing to save; the trap is empty, and captureNow sends no empty password.
  assert.equal(chooseEnteredCapture(DETECTED, [], "real-pass", () => false), "hp5");
  assert.match(readFileSync(new URL("./content.ts", import.meta.url), "utf-8"), /if \(f\.kind === "username-step" \? username === "" : password === ""\) return;/);
});

// The content script is wiring around the pure choice: these pin that the capture goes through it, and what counts as entered.
const ct = readFileSync(new URL("./content.ts", import.meta.url), "utf-8");
const span = (from: string, to: string): string => {
  const a = ct.indexOf(from);
  const b = ct.indexOf(to, a + from.length);
  assert.ok(a >= 0 && b > a, `${from} … ${to}`);
  return ct.slice(a, b);
};

test("content.ts: every snapshot reads the field the person entered, chosen afresh at each read", () => {
  const update = span("function updateSnapshot(f: LoginForm): void {", "\n}\n");
  assert.match(update, /const p = captureField\(f\)\?\.value \?\? "";/);
  assert.doesNotMatch(update, /f\.capturePassword\?\.value/, "never detection's pick alone");
  const choose = span("function captureField(f: LoginForm): HTMLInputElement | null {", "\n}\n");
  assert.match(choose, /return chooseEnteredCapture\(f\.passwords, f\.newPasswords, f\.password, \(el\) => entered\.has\(el\)\);/);
  // Every password field of the form belongs to it, so a keystroke in any of them snapshots.
  assert.match(span("function formFor(input: HTMLInputElement): LoginForm | null {", "\n}\n"), /f\.passwords\.includes\(input\)/);
});

test("content.ts: entered means trusted input, or an andvari fill or generated password the person asked for", () => {
  assert.match(ct, /const entered = new WeakSet<HTMLInputElement>\(\);/);
  // The trusted input listener records the field before the snapshot reads it; a page's scripted events are not trusted.
  assert.match(ct, /if \(!e\.isTrusted \|\| !\(t instanceof HTMLInputElement\)\) return;\s*entered\.add\(t\);[^\n]*\n\s*const f = formFor\(t\);\s*if \(f\) updateSnapshot\(f\);/);
  assert.match(span("function fillForm(", "\n}\n"), /setValue\(live\.password, s\.password\);\s*entered\.add\(live\.password\);/);
  assert.match(span("async function useStrongPassword(", "\n}\n"), /setValue\(t, r\.password\);\s*entered\.add\(t\);/);
  // Exactly those three places: nothing else marks a field entered.
  assert.equal((ct.match(/entered\.add\(/g) ?? []).length, 3);
});
