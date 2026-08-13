// node --test (see version.test.ts). Gates the DELIBERATE duplication in errors.ts: the seam
// code unions (UnlockCode/SaveErrorCode/… — the pinned E1 contract) are re-declared there rather
// than imported, so that file stays dependency-free and the copy pins run standalone. errors.ts
// records the invariant in prose ("must stay literal-identical to messages.ts"); prose does not
// fail a gate, so this test is the enforcement: every union declared in BOTH files must match
// member-for-member, in order. Without it a one-sided edit forks the twins silently.
//
// The unions are type-level and fully erased at runtime, so there is nothing to import — both
// files are read as SOURCE TEXT and parsed here (the contrast.test.ts idiom: parse the artifact,
// don't trust a hand-kept list).
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

/**
 * Comments out, strings intact. This is the whole reason the test is not a one-line regex:
 * messages.ts hangs a trailing `// …` off individual FillFailCode/UnlockCode members, so a
 * naive `/type X =([^/]*)/` truncates the union at its first comment and compares two
 * one-member lists — a FALSE PASS, which is worse than no gate at all. Quote handling is
 * needed because comment markers can legitimately appear inside the copy strings.
 */
function stripComments(src: string): string {
  let out = "";
  let i = 0;
  while (i < src.length) {
    const c = src[i];
    const d = src[i + 1];
    if (c === "/" && d === "/") {
      while (i < src.length && src[i] !== "\n") i++;
      out += "\n"; // keep the line break: members are newline-separated
      continue;
    }
    if (c === "/" && d === "*") {
      i += 2;
      while (i < src.length && !(src[i] === "*" && src[i + 1] === "/")) i++;
      i += 2;
      out += " ";
      continue;
    }
    if (c === '"' || c === "'" || c === "`") {
      out += c;
      i++;
      while (i < src.length) {
        const ch = src[i];
        out += ch;
        i++;
        if (ch === "\\") {
          if (i < src.length) out += src[i++];
          continue;
        }
        if (ch === c) break;
      }
      continue;
    }
    out += c;
    i++;
  }
  return out;
}

/** The declaration body from `start` to its terminating `;`, brace/bracket/paren-aware so an
 *  object-shaped union (messages.ts `Req`) is read whole and then rejected, never truncated
 *  into something that happens to look like a string union. */
function readBody(code: string, start: number): string | null {
  let depth = 0;
  for (let i = start; i < code.length; i++) {
    const c = code[i];
    if (c === "{" || c === "[" || c === "(") depth++;
    else if (c === "}" || c === "]" || c === ")") depth--;
    else if (c === ";" && depth === 0) return code.slice(start, i);
  }
  return null;
}

/** Ordered members of a pure string-literal union, or null for any other declaration shape.
 *  Strict by design: anything the parser cannot read cleanly drops out of the comparison set,
 *  and the coverage assertion below turns that into a loud failure. */
function unionMembers(body: string): string[] | null {
  const trimmed = body.trim().replace(/^\|/, "");
  if (trimmed === "") return null;
  const members: string[] = [];
  for (const part of trimmed.split("|")) {
    const m = /^"([^"\\]*)"$/.exec(part.trim());
    if (!m) return null;
    members.push(m[1]);
  }
  return members;
}

/** name → ordered members, for every string-literal union declared at top level in `src`. */
function parseStringUnions(src: string, label: string): Map<string, string[]> {
  const code = stripComments(src);
  const decl = /(?:^|[\n;}])\s*(?:export\s+)?type\s+([A-Za-z_$][\w$]*)\s*=/g;
  const out = new Map<string, string[]>();
  for (let m = decl.exec(code); m !== null; m = decl.exec(code)) {
    const body = readBody(code, decl.lastIndex);
    if (body === null) continue;
    const members = unionMembers(body);
    if (members === null) continue;
    assert.equal(out.has(m[1]), false, `${label}: duplicate type ${m[1]}`);
    out.set(m[1], members);
  }
  return out;
}

const read = (rel: string) => readFileSync(fileURLToPath(new URL(rel, import.meta.url)), "utf-8");
const seam = parseStringUnions(read("./messages.ts"), "messages.ts");
const copy = parseStringUnions(read("./errors.ts"), "errors.ts");

// The twins as of 0.19.0 — the E1 seam codes (UnlockCode/SaveErrorCode/FillFailCode), the
// quick-unlock lane (spec 01 §8.4) and its biometric sibling (0.17.0), and the TOTP-add lane
// (design 2026-08-12). Adding a twin to errors.ts extends this automatically; this list only
// guarantees none can go MISSING.
const SHARED = [
  "UnlockCode",
  "SaveErrorCode",
  "TotpAddCode",
  "FillFailCode",
  "PinUnlockCode",
  "PinWeakReason",
  "EnrollCode",
  "BioUnlockCode",
  "EnrollBioCode",
];

test("the parser reads whole unions, past trailing comments and line breaks", () => {
  // FillFailCode is the trap case: every member in messages.ts carries a `// …` gloss, and the
  // union spans six lines. A truncating parser reports 1 member here and then "passes" forever.
  assert.deepEqual(seam.get("FillFailCode"), ["locked", "not_allowed", "no_form", "no_fields", "no_secret", "unreachable"]);
  assert.equal(seam.get("UnlockCode")?.length, 13); // multi-line + commented
  assert.deepEqual(seam.get("SaveErrorCode"), ["locked", "conflict", "failed"]); // single-line
  // Object-shaped unions (Req/TabMsg) and generic conditionals (Res) are not string unions and
  // must not leak into the comparison set as truncated garbage.
  assert.equal(seam.has("Req"), false);
  assert.equal(seam.has("Res"), false);
});

test("errors.ts declares the seam twins it says it declares", () => {
  const missing = SHARED.filter((n) => !copy.has(n) || !seam.has(n));
  assert.deepEqual(missing, [], `twin unions not parsed from both files: ${missing.join(", ")}`);
});

test("every union declared in both files is literal-identical, in order", () => {
  const shared = [...copy.keys()].filter((n) => seam.has(n)).sort();
  // Non-empty and at least the known twins: a rename (or a parse regression) must fail here
  // rather than quietly compare an empty set.
  assert.ok(shared.length > 0);
  for (const name of [...SHARED].sort()) assert.ok(shared.includes(name), `${name} dropped out of the shared set`);
  for (const name of shared) {
    // Order matters as much as membership: these are read side by side when the copy ladders
    // are reviewed, and a reordered twin is the first sign of a one-sided edit.
    assert.deepEqual(copy.get(name), seam.get(name), `${name} has forked between errors.ts and messages.ts`);
  }
});
