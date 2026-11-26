// node --test (see version.test.ts). Every sentence a person reads in the extension is an exported, named constant
// with its own doc comment marked as the web marks its copy: `PLACEHOLDER` (the words await the owner's) or `Approved
// wording`. The wording tool places the owner's words by the constant's name and only into a marked constant, so a
// sentence anywhere else is one the tool cannot reach. This walks every source file and fails on such a sentence.
import { strict as assert } from "node:assert";
import { readdirSync, readFileSync } from "node:fs";
import { test } from "node:test";
import ts from "typescript";

const dir = new URL("./", import.meta.url);
const read = (f: string): string => readFileSync(new URL(f, dir), "utf-8");
/** The sources a build ships (tests, the test helpers and the generated suffix list aside). */
const SOURCES = readdirSync(dir).filter((f) => f.endsWith(".ts") && !f.endsWith(".test.ts") && f !== "pslData.ts").sort();

/** Words a person reads: two words in a row, or one capitalised word standing alone ("Cancel", "Unlocking…"). */
const WORDS = /[A-Za-z’']{2,} [A-Za-z’']{2,}/;
const ONE_WORD = /^[A-Z][a-z’']+[.!?…]?$/;

/** Names, not wording: a platform's own name for its unlock, and the card brands and payment providers. */
const PROPER_NAMES = new Set(["Touch ID", "Windows Hello", "Face ID", "Visa", "Mastercard", "Amex", "Discover"]);
/** The Safari popup's support report (its labels are for whoever reads the report, in English on every device). */
const REPORT_FUNCTIONS = new Set(["fillServerDetails", "backgroundBootLines"]);
/** Fields that carry a debug detail or data across the message seam; surfaces never render them (errors.ts header). */
const DATA_FIELDS = new Set(["error", "detail", "reason", "provider", "source", "readError", "message", "justification", "pageOrigin"]);
/** Modules whose strings are reasons a check returns to its caller, a build gate's message, or configuration: never
 *  rendered (a surface shows its own line for each code). */
const INTERNAL_FILES = new Set(["api.ts", "crypto.ts", "itemdocshape.ts", "servedblob.ts", "trustedkv.ts", "releasegate.ts", "publicinstance.ts", "publicinstance.testserver.ts"]);
/** DOM properties and attributes whose strings are not read as words. */
const NOT_WORDS_TARGETS = new Set(["className", "rel", "cssText"]);

/** Exported strings that are not lines of copy: the worker's fixed debug detail for a build without card fill, and the
 *  device name this extension records on the server (data, which other devices show as the device's name). */
const NOT_COPY = new Set(["CARD_FILL_OFF", "DEVICE_NAME"]);

const PLACEHOLDER_MARK = /^\s*(?:\/\*\*|\*)\s*PLACEHOLDER\b/m;
const APPROVED_MARK = /Approved wording/;

/** The doc comment directly above [stmt] (nothing but white space between), or null. */
function docAbove(sf: ts.SourceFile, stmt: ts.Node): string | null {
  const lead = sf.text.slice(stmt.getFullStart(), stmt.getStart(sf));
  const at = lead.lastIndexOf("/**");
  if (at < 0) return null;
  const end = lead.indexOf("*/", at);
  if (end < 0 || lead.slice(end + 2).trim() !== "") return null;
  return lead.slice(at, end + 2);
}

interface Line {
  file: string;
  name: string;
  text: string;
  doc: string | null;
}

/** Every `export const NAME = "..."` of the sources, with its doc comment. */
function copyLines(): Line[] {
  const out: Line[] = [];
  for (const file of SOURCES) {
    const sf = ts.createSourceFile(file, read(file), ts.ScriptTarget.Latest, true);
    for (const stmt of sf.statements) {
      if (!ts.isVariableStatement(stmt) || !stmt.modifiers?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword)) continue;
      for (const d of stmt.declarationList.declarations) {
        if (ts.isIdentifier(d.name) && /^[A-Z][A-Z0-9_]*$/.test(d.name.text) && d.initializer && ts.isStringLiteral(d.initializer)) {
          out.push({ file, name: d.name.text, text: d.initializer.text, doc: docAbove(sf, stmt) });
        }
      }
    }
  }
  return out;
}

function isExportedCopyInitializer(node: ts.Node): boolean {
  const d = node.parent;
  if (!d || !ts.isVariableDeclaration(d) || d.initializer !== node || !ts.isStringLiteral(node)) return false;
  const stmt = d.parent?.parent;
  return !!stmt && ts.isVariableStatement(stmt) && !!stmt.modifiers?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword) && ts.isIdentifier(d.name) && /^[A-Z][A-Z0-9_]*$/.test(d.name.text);
}

/** Why a string at [node] is not a sentence a person reads, or null when it is one. */
function exempt(node: ts.Node): string | null {
  if (INTERNAL_FILES.has(node.getSourceFile().fileName)) return "a reason a check gives its caller";
  for (let n: ts.Node | undefined = node.parent; n; n = n.parent) {
    if ((ts.isFunctionDeclaration(n) || ts.isFunctionExpression(n)) && n.name && REPORT_FUNCTIONS.has(n.name.text)) return "the support report";
    if (ts.isBinaryExpression(n) && n.operatorToken.kind === ts.SyntaxKind.EqualsToken && /Diag\b/.test(n.left.getText())) return "the support report";
    if (ts.isCallExpression(n) && ts.isIdentifier(n.expression) && n.expression.text === "adoptAppAnswer") return "the support report";
  }
  for (let n: ts.Node | undefined = node.parent; n; n = n.parent) {
    if (ts.isCallExpression(n) && /^console\./.test(n.expression.getText())) return "a console message";
    if (ts.isNewExpression(n) && /Error$/.test(n.expression.getText())) return "a fault's message";
    if (ts.isCallExpression(n) && n.expression.kind === ts.SyntaxKind.SuperKeyword) return "a fault's message";
    if (ts.isThrowStatement(n)) return "a fault's message";
    if (ts.isPropertyAssignment(n) && ts.isIdentifier(n.name) && DATA_FIELDS.has(n.name.text)) return "a debug detail or data field";
    if (ts.isStatement(n) || ts.isVariableDeclaration(n)) break;
  }
  const p = node.parent;
  if (ts.isImportDeclaration(p) || ts.isExportDeclaration(p) || ts.isLiteralTypeNode(p) || ts.isCaseClause(p)) return "code";
  if (ts.isPropertyAssignment(p) && p.name === node) return "a key";
  if (ts.isBinaryExpression(p) && [ts.SyntaxKind.EqualsEqualsEqualsToken, ts.SyntaxKind.ExclamationEqualsEqualsToken].includes(p.operatorToken.kind)) return "a comparison";
  if (ts.isBinaryExpression(p) && p.operatorToken.kind === ts.SyntaxKind.EqualsToken && ts.isPropertyAccessExpression(p.left) && NOT_WORDS_TARGETS.has(p.left.name.text)) return "a class or style";
  if (ts.isConditionalExpression(p) && ts.isBinaryExpression(p.parent) && ts.isPropertyAccessExpression(p.parent.left) && NOT_WORDS_TARGETS.has(p.parent.left.name.text)) return "a class or style";
  const arg = ts.isConditionalExpression(p) ? p : node;
  const call = arg.parent;
  if (call && ts.isCallExpression(call) && /(^|\.)span$/.test(call.expression.getText()) && call.arguments[0] === arg) return "a class or style";
  if (call && ts.isCallExpression(call) && /^setLiveMsg(Blocks)?$/.test(call.expression.getText()) && call.arguments[1] === arg) return "a class or style";
  return null;
}

/** Each string in the sources that reads as words and is not a marked copy constant: "file:line text". */
function strays(): string[] {
  const out: string[] = [];
  for (const file of SOURCES) {
    const sf = ts.createSourceFile(file, read(file), ts.ScriptTarget.Latest, true);
    const visit = (node: ts.Node): void => {
      let s: string | null = null;
      if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) s = node.text;
      else if (ts.isTemplateExpression(node)) s = node.head.text + node.templateSpans.map((x) => ` ${x.literal.text}`).join("");
      if (s !== null && (WORDS.test(s) || ONE_WORD.test(s.trim())) && !PROPER_NAMES.has(s) && !/[{};]\s*$|^\s*[:.#@]/.test(s.trim()) && !isExportedCopyInitializer(node) && exempt(node) === null) {
        out.push(`${file}:${sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1} ${s.slice(0, 90)}`);
      }
      ts.forEachChild(node, visit);
    };
    visit(sf);
  }
  return out;
}

test("no sentence a person reads is outside an exported, named line of copy", () => {
  assert.deepEqual(strays(), []);
});

test("every line of copy carries its own doc comment with the web's placeholder or approved mark", () => {
  const lines = copyLines().filter((l) => !NOT_COPY.has(l.name) && (l.file === "copy.ts" || l.file === "errors.ts" || l.file === "trustgate.ts" || WORDS.test(l.text) || ONE_WORD.test(l.text)));
  assert.ok(lines.length > 300, `the extension's lines of copy, found ${lines.length}`);
  const unmarked = lines.filter((l) => l.doc === null || !(PLACEHOLDER_MARK.test(l.doc) || APPROVED_MARK.test(l.doc))).map((l) => `${l.file} ${l.name}`);
  assert.deepEqual(unmarked, []);
});

test("a line's name is the extension's only line of that name, so the tool places it in one place", () => {
  const seen = new Map<string, string>();
  const twice: string[] = [];
  for (const l of copyLines()) {
    if (seen.has(l.name)) twice.push(`${l.name}: ${seen.get(l.name)} and ${l.file}`);
    seen.set(l.name, l.file);
  }
  assert.deepEqual(twice, []);
});

test("the four lines the wording page names first are lines the tool can place", () => {
  const byName = new Map(copyLines().map((l) => [l.name, l]));
  for (const k of ["TOTP_COPIED_TOAST", "TOTP_SHOWN_TOAST", "ADD_TOTP_LABEL", "TOTP_ENROLL_REQUIRED"]) {
    const l = byName.get(k);
    assert.ok(l, `${k} is an exported line`);
    assert.ok(l!.doc !== null && (PLACEHOLDER_MARK.test(l!.doc) || APPROVED_MARK.test(l!.doc)), `${k} is marked`);
  }
});

test("the walk sees an inline sentence, a template one and an unmarked line (its own checks work)", () => {
  // A probe source the same rules read: one stray of each kind must be found, and the marked line and the exempt ones not.
  const probe = [
    "/** PLACEHOLDER: a line. */",
    'export const GOOD = "A line the tool can place.";',
    'el.textContent = "Inline words a person reads";',
    "el.title = `Templated words ${x} here`;",
    'throw new Error("a fault message nobody reads");',
    'el.className = "row action";',
  ].join("\n");
  const sf = ts.createSourceFile("probe.ts", probe, ts.ScriptTarget.Latest, true);
  const found: string[] = [];
  const visit = (node: ts.Node): void => {
    let s: string | null = null;
    if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) s = node.text;
    else if (ts.isTemplateExpression(node)) s = node.head.text;
    if (s !== null && WORDS.test(s) && !isExportedCopyInitializer(node) && exempt(node) === null) found.push(s);
    ts.forEachChild(node, visit);
  };
  visit(sf);
  assert.deepEqual(found, ["Inline words a person reads", "Templated words "]);
});
