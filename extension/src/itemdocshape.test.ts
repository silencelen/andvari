// Security review 2026-10 (root cause D): the extension's run of the shared decrypted-document
// shape vectors, plus the wiring pin that the service worker actually applies the check at its one
// decrypt site. A co-member's `{"name": null}` or bare `null` doc used to throw in byName() on
// every status/matches/allItems dispatch and break the extension for every vault until removed.
// Same verdicts as web vault/itemdoc-shape.test.ts and core ItemDocShapeVectorTest.
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { itemDocProblem } from "./itemdocshape.ts";

const vectorsDir = fileURLToPath(new URL("../../spec/test-vectors/", import.meta.url));
const v = JSON.parse(readFileSync(vectorsDir + "itemdoc-validate.json", "utf-8"));

test("itemdoc-validate.json — every item case reaches the vector's verdict", () => {
  for (const c of v.items) {
    const problem = itemDocProblem(JSON.parse(c.docJson));
    assert.equal(problem === null, c.valid, `${c.name}: ${problem}`);
  }
});

test("decryptItem quarantines a failing doc instead of admitting it", () => {
  // A9: the per-row open lives in decryptItem (homeAndDecrypt and decryptItems both route through it).
  const bg = readFileSync(new URL("./background.ts", import.meta.url), "utf-8");
  const a = bg.indexOf("function decryptItem(");
  assert.ok(a > -1, "decryptItem missing");
  const body = bg.slice(a, bg.indexOf("\n}\n", a));
  assert.match(body, /if \(itemDocProblem\(doc\) !== null\) return null;/);
  // …and the check runs BEFORE the row is returned, so nothing unchecked ever reaches session.items.
  assert.ok(body.indexOf("itemDocProblem(doc)") < body.indexOf("return { itemId"), "check must precede the return");
  const all = bg.slice(bg.indexOf("function decryptItems("), bg.indexOf("\n}\n", bg.indexOf("function decryptItems(")));
  assert.match(all, /decryptItem\(it, vaultKeys\)/, "decryptItems routes through decryptItem");
});
