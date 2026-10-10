// In-page surface WIRING pins (security review 2026-10, root cause B). Source-text assertions:
// content-ui.ts touches `document` and cannot run under node, so the guard itself is behaviour-
// tested in visibilityguard.test.ts and THIS file pins that every activation path consults it —
// a leaf test stays green when its call site is deleted.
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const cu = readFileSync(new URL("./content-ui.ts", import.meta.url), "utf-8");

function spanOf(src: string, from: string, to: string): string {
  const a = src.indexOf(from);
  assert.ok(a > -1, `span start missing: ${from}`);
  const b = src.indexOf(to, a);
  assert.ok(b > a, `span end missing or out of order: ${to}`);
  return src.slice(a, b);
}

/** Code lines only — the rationale comments are free to name what they forbid. */
function code(s: string): string {
  return s
    .split("\n")
    .filter((l) => !l.trim().startsWith("//") && !l.trim().startsWith("*"))
    .join("\n");
}

test("row activation (pointer and AT click) is refused unless the dropdown is provably visible", () => {
  const bind = code(spanOf(cu, "function bindRowActivation(", "function matchRow("));
  const trusted = bind.indexOf("if (!e.isTrusted) return;");
  const gate = bind.indexOf("if (!activationAllowed(dropdownEl)) return;");
  const act = bind.indexOf("act();");
  assert.ok(trusted > -1 && gate > trusted && act > gate, "isTrusted, then the visibility gate, then the action");
});

test("keyboard Enter on a highlighted row goes through the same gate", () => {
  const keys = code(spanOf(cu, 'else if (e.key === "Enter")', 'else if (e.key === "Tab")'));
  const gate = keys.indexOf("if (!activationAllowed(dropdownEl)) return;");
  const act = keys.indexOf("listRows[activeIdx]?.act();");
  assert.ok(gate > -1 && act > gate, "Enter must be gated before the row runs");
});

test("the banner's primary action and the chip are gated; the dismissals are not", () => {
  const offer = code(spanOf(cu, "function offerBanner(", "export function showSaveBanner("));
  const primary = spanOf(offer, 'primary.addEventListener("click"', 'ghost.addEventListener("click"');
  assert.ok(primary.indexOf("if (!activationAllowed(bar)) return;") > primary.indexOf("if (!e.isTrusted) return;"));
  const ghost = offer.slice(offer.indexOf('ghost.addEventListener("click"'));
  assert.ok(!ghost.includes("activationAllowed"), "declining is always safe — never gate the way out");
  const chip = code(spanOf(cu, "export function showCardChip(", "export function repositionCardChip("));
  assert.ok(chip.includes("if (!activationAllowed(chip)) return;"));
  const chord = code(spanOf(cu, "a11y-webext--12: the chip's keyboard activation", "if (!dropdownEl) return; // a lone chip"));
  assert.ok(chord.includes("activationAllowed(chipEl)"), "the chip's keyboard chord is gated too");
});

test("every surface is watched when it mounts and forgotten when it goes", () => {
  assert.ok(code(spanOf(cu, "export function openDropdown(", "export function closeDropdown(")).includes("guard().watch(box);"));
  assert.ok(code(spanOf(cu, "export function closeDropdown(", "function bannerShell(")).includes("guard().forget("));
  assert.ok(code(spanOf(cu, "function bannerShell(", "function closeBanner(")).includes("guard().watch(bar);"));
  assert.ok(code(spanOf(cu, "function closeBanner(", "let bannerDecline")).includes("guard().forget(which);"));
  assert.ok(code(spanOf(cu, "export function showCardChip(", "export function repositionCardChip(")).includes("guard().watch(chip);"));
  assert.ok(code(spanOf(cu, "export function closeCardChip(", "/** [K8] every close that ORIGINATES")).includes("guard().forget("));
});

test("the dropdown is ONE fixed size in every state — its height no longer encodes lock state or match count", () => {
  const rule = UI_RULE(".list {");
  assert.match(rule, /\bheight:\s*\d+px/, "the list region must declare a fixed height");
  assert.doesNotMatch(rule, /max-height/, "a max-height lets the box shrink to its content again");
  assert.match(rule, /overflow-y:\s*auto/, "more rows scroll inside the fixed box");
  // The search box used to grow the dropdown inside the page; cross-site search now lives in the
  // popup (the search-all row hands off to it), so the in-page surface has no second layout.
  assert.ok(!cu.includes("function renderSearch("), "the in-page search layout is gone");
});

function UI_RULE(selector: string): string {
  const css = spanOf(cu, "const UI_CSS = `", "`;");
  const at = css.indexOf("\n" + selector);
  assert.ok(at > -1, `rule missing: ${selector}`);
  return css.slice(at, css.indexOf("}", at));
}
