// node --test. What the first rendered run of the popup (headless Chrome, 2026-11-16) found wrong, pinned so it does not
// come back. The run itself lives outside the repository (it drives the release build with a stand-in worker).
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const read = (p: string) => readFileSync(fileURLToPath(new URL(p, import.meta.url)), "utf-8");
const css = read("../popup.css");
const popup = read("./popup.ts");

test("the popup is one column capped at Chrome's 600px, and only the vault gives up height", () => {
  // A card notice above the 400px vault pushed the message, Lock and Sign out out of the popup.
  assert.ok(css.includes("body:has(> .pop-head) { display: flex; flex-direction: column; max-height: 600px; }"));
  assert.ok(css.includes("body:has(> .pop-head) > * { flex: none; }"));
  assert.ok(css.includes("body:has(> .pop-head) > .unlocked { flex: 0 1 auto; min-height: 110px; }"));
  // A long message under the sign-in form takes the decorative hero's room.
  assert.ok(css.includes("body:has(#msg:not([hidden])) #locked .hero { display: none; }"));
  // Scoped to the popup: the options page and the connector window share this file.
  assert.ok(read("../popup.html").includes('<header class="pop-head">'));
  assert.ok(!read("../options.html").includes("pop-head") && !read("../connector.html").includes("pop-head"));
});

test("the password label is never uppercased: it names an email and an origin", () => {
  assert.ok(css.includes("#password-label { text-transform: none;"));
});

test("the first popup preselects neither choice, and its two buttons do not touch", () => {
  assert.ok(!popup.includes("pub.focus()"));
  assert.ok(popup.includes("if (document.activeElement === pub) pub.blur();"));
  assert.ok(css.includes(".confirm-server .primary + .primary { margin-top: 8px; }"));
});

test("the unlocked view's quick-unlock offer and enroll form keep the popup's side margins", () => {
  assert.ok(css.includes("#unlocked > .qu-offer { margin: 10px 16px 2px; }"));
  assert.ok(css.includes("#unlocked > #qu-enroll { margin: 4px 16px 0; }"));
});

test("rendered: at a phone's width the server address takes the whole row, so its placeholder is not cut", () => {
  const opts = read("../options.html");
  const media = opts.slice(opts.indexOf("@media (max-width: 480px) {"));
  assert.ok(media.length > 0 && opts.includes("@media (max-width: 480px) {"));
  assert.ok(/^@media \(max-width: 480px\) \{\s*\.row \{\s*flex-direction: column;\s*align-items: stretch;\s*\}\s*\.row button \{\s*width: 100%;\s*\}/.test(media));
});

test("rendered: in the two stops Forget this server is a whole-width plain button, not focused at open", () => {
  const html = read("../popup.html");
  assert.ok(html.includes('<button id="confirm-server-not-mine" class="ghost confirm-server-forget" type="button">Forget this server</button>'));
  assert.ok(css.includes(".confirm-server .confirm-server-forget { width: 100%;"));
  const stop = popup.slice(popup.indexOf('if (block.kind === "fork" || block.kind === "pin_damaged") {'), popup.indexOf("// `no_server`: the first popup"));
  assert.ok(stop.includes("notMine.hidden = false;") && !stop.includes("notMine.focus()"), "Enter does not forget the server");
});

test("rendered: no ruled strip above the quick-unlock PIN when a message takes the hero's room", () => {
  assert.ok(css.includes("body:has(#msg:not([hidden])) #locked .qu-block { margin-top: 0; padding-top: 0; border-top: 0; }"));
});

test("the quick-unlock offer does not promise to skip a one-time code an account may not have", () => {
  const html = read("../popup.html");
  const offer = html.slice(html.indexOf('<div id="qu-offer"'), html.indexOf('<div class="qu-acts">', html.indexOf('<div id="qu-offer"')));
  // What this is about: the old promise is gone. The offer's own words are not pinned here (they await the owner's).
  assert.ok(!offer.includes("<em>and</em> your one-time code"));
});

test("a quick unlock that opened the vault but could not update its record says so, after the vault is shown", () => {
  const line = 'if (r.notice === "quick_unlock_not_updated") showMsg("info", QUICK_UNLOCK_NOT_UPDATED);';
  for (const lane of ["async function quUnlock(", "async function quBioUnlock("]) {
    const fn = popup.slice(popup.indexOf(lane), popup.indexOf("\n}\n", popup.indexOf(lane)));
    assert.ok(fn.indexOf("await refresh();") > 0 && fn.indexOf(line) > fn.indexOf("await refresh();"), lane);
  }
});

test("a password or one-time-code sign-in that opened the vault says what it could not do, after the vault is shown", () => {
  for (const lane of ["async function unlock(", "async function verifyTotp("]) {
    const fn = popup.slice(popup.indexOf(lane), popup.indexOf("\n}\n", popup.indexOf(lane)));
    assert.ok(fn.indexOf("await refresh();") > 0 && fn.indexOf("showSignInNotice(r.notice);") > fn.indexOf("await refresh();"), lane);
  }
  assert.ok(popup.includes('if (notice === "session_not_saved") showMsg("info", SESSION_NOT_SAVED);'));
});

test("a session the server ended offers no quick unlock (the worker refuses to enroll one)", () => {
  const at = popup.indexOf("showMsg(\"info\", s.serverEndedUnconfirmed ? sessionNotConfirmedNotice(unsaved) : serverEndedNotice(unsaved));");
  assert.ok(at > 0);
  const block = popup.slice(at, at + 400);
  for (const id of ["qu-offer", "qu-enroll", "qu-settings"]) assert.ok(block.includes(`el("${id}").hidden = true;`), id);
});

test("an alarm the browser refused is one line beside the open vault, and none while locked", () => {
  assert.ok(read("../popup.html").includes('<div id="timer-notice" class="must-change-strip grants-waiting" role="status" hidden></div>'));
  assert.ok(popup.includes('const timerLine = s.unlocked ? timerNoticeLine(s.timerNotice) : "";'));
  assert.ok(popup.includes('el("timer-notice").hidden = timerLine === "";'));
});
