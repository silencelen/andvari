// node --test. A line of the extension's copy whose words are word for word what the released extension shows counts as
// approved, as the current app's own words (decided on 2026-11-17), and is marked "Approved wording (the released
// extension's own words)". testing/released-wording.json lists those lines with their words, as a script wrote it from
// the released sources. This fails when a line so marked no longer has the words listed for it (a later change of such a
// sentence makes it a new one: it goes back to being a placeholder, knowingly) and when the list and the marks disagree.
import { strict as assert } from "node:assert";
import { readdirSync, readFileSync } from "node:fs";
import { test } from "node:test";
import ts from "typescript";

const dir = new URL("./", import.meta.url);
const read = (f: string): string => readFileSync(new URL(f, dir), "utf-8");
const SOURCES = readdirSync(dir).filter((f) => f.endsWith(".ts") && !f.endsWith(".test.ts") && f !== "pslData.ts").sort();
const MARK = "Approved wording (the released extension's own words)";
const listed = (JSON.parse(read("testing/released-wording.json")) as { lines: Record<string, { file: string; text: string }> }).lines;

/** Every `export const NAME = "..."` whose doc comment carries [MARK]: name → its file and words. */
function marked(): Map<string, { file: string; text: string }> {
  const out = new Map<string, { file: string; text: string }>();
  for (const file of SOURCES) {
    const text = read(file);
    const sf = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true);
    for (const stmt of sf.statements) {
      if (!ts.isVariableStatement(stmt) || !stmt.modifiers?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword)) continue;
      const lead = text.slice(stmt.getFullStart(), stmt.getStart(sf));
      const at = lead.lastIndexOf("/**");
      const end = at < 0 ? -1 : lead.indexOf("*/", at);
      if (end < 0 || lead.slice(end + 2).trim() !== "" || !lead.slice(at, end).includes(MARK)) continue;
      for (const d of stmt.declarationList.declarations) {
        if (ts.isIdentifier(d.name) && d.initializer && ts.isStringLiteral(d.initializer)) out.set(d.name.text, { file, text: d.initializer.text });
      }
    }
  }
  return out;
}

/** The marked lines whose words or file differ from [list], or which it does not hold. */
function changedAgainst(list: Record<string, { file: string; text: string }>, now: Map<string, { file: string; text: string }>): string[] {
  const changed: string[] = [];
  for (const [name, line] of now) {
    const was = list[name];
    if (was === undefined) changed.push(`${name} (${line.file}): marked, but not on the list`);
    else if (was.text !== line.text || was.file !== line.file) changed.push(`${name} (${line.file}): ${JSON.stringify(was.text)} is now ${JSON.stringify(line.text)}`);
  }
  return changed;
}

test("each line marked as the released extension's own words still has the words the list holds for it", () => {
  assert.deepEqual(changedAgainst(listed, marked()), [], "a changed sentence is a new one: mark it PLACEHOLDER again and take it off testing/released-wording.json");
});

test("every line on the list is still marked so (a line turned back into a placeholder leaves the list too)", () => {
  const now = marked();
  assert.deepEqual(Object.keys(listed).filter((n) => !now.has(n)), []);
  assert.ok(Object.keys(listed).length > 200, `the released extension's lines, found ${Object.keys(listed).length}`);
});

test("the check itself sees a changed sentence and a marked line the list does not hold", () => {
  const name = Object.keys(listed)[0]!;
  const now = marked();
  const changedWords = { ...listed, [name]: { ...listed[name]!, text: `${listed[name]!.text} (as the release had it)` } };
  assert.equal(changedAgainst(changedWords, now).length, 1);
  const { [name]: _dropped, ...without } = listed;
  assert.deepEqual(changedAgainst(without, now), [`${name} (${listed[name]!.file}): marked, but not on the list`]);
});
