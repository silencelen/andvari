// node --test. What the first rendered run of the options page (headless Chrome, 2026-11-16) found wrong, pinned.
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const read = (p: string) => readFileSync(fileURLToPath(new URL(p, import.meta.url)), "utf-8");

test("the line after the Trust Gate or the stop does not sit on its border", () => {
  assert.match(read("../options.html"), /\.trust-gate \{\s*margin-bottom: 12px;\s*\}/);
});

test("phone width: the Trust Gate's origin breaks only at its own punctuation, and shows exactly the origin", async () => {
  const { originBreakPieces } = await import("./trustgate.ts");
  for (const o of ["https://vault.smith.example", "https://my-vault.example.co.uk:8443", "http://localhost:8080", "https://xn--vlt-0na.example"]) {
    const pieces = originBreakPieces(o);
    assert.equal(pieces.join(""), o, "the pieces are the origin, character for character");
    assert.ok(pieces.slice(1).every((p, i) => (i === 0 ? true : /^[.:-]/.test(p))), `breaks only before . - : (${pieces.join("|")})`);
  }
  assert.deepEqual(originBreakPieces("https://vault.smith.example"), ["https://", "vault", ".smith", ".example"]);
  const ts = read("./options.ts");
  assert.ok(ts.includes('gateOrigin.replaceChildren(...originBreakPieces(view.origin).flatMap((p, i) => (i === 0 ? [p] : [document.createElement("wbr"), p])));'));
  assert.ok(!ts.includes("gateOrigin.textContent ="), "no second writer of the shown origin");
  const html = read("../options.html");
  const gate = html.slice(html.indexOf(".gate-origin {"), html.indexOf("}", html.indexOf(".gate-origin {")));
  assert.ok(gate.includes("overflow-wrap: break-word;") && !gate.includes("anywhere"), "no break inside a label while a <wbr> fits");
});

test("phone width: the injection line keeps its distance from the address row and the message above it", () => {
  assert.match(read("../options.html"), /#autofill-status \{\s*margin-top: 14px;\s*\}/);
});

test("with no server chosen, the page offers no removal of a server's data", () => {
  const src = read("./options.ts");
  assert.ok(src.includes('const danger = purgeBtn.closest("section");'));
  assert.ok(src.includes('if (danger) danger.hidden = info === null || info.url === "";'));
  assert.ok(read("../options.html").includes('<section class="section danger-zone" aria-labelledby="danger-h">'));
});
