import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import { fromB64, utf8 } from "../crypto/bytes";
import { initSodium } from "../crypto/sodium";
import { ImportError, parseCsvImport, planImport } from "./csv";

/**
 * Consumes spec/test-vectors/import.json — the SAME file the Kotlin ImportVectorsTest
 * checks — so both impls parse browser CSVs byte-identically. Keep the two in lockstep.
 */

const vectorsDir = fileURLToPath(new URL("../../../spec/test-vectors/", import.meta.url));

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function load(name: string): any {
  return JSON.parse(readFileSync(vectorsDir + name, "utf-8"));
}

beforeAll(async () => {
  await initSodium(); // fromB64 (base64url) needs libsodium ready
});

describe("import.json — files", () => {
  const v = load("import.json");
  for (const c of v.files) {
    it(c.name, () => {
      const parsed = parseCsvImport(fromB64(c.contentB64));
      const exp = c.expect;
      expect(parsed.format).toBe(exp.format);

      expect(parsed.rows.length).toBe(exp.rows.length);
      for (let idx = 0; idx < exp.rows.length; idx++) {
        const er = exp.rows[idx];
        const r = parsed.rows[idx]!;
        expect(r.name).toBe(er.name);
        expect(r.url).toBe(er.url);
        expect(r.username).toBe(er.username);
        expect(r.password).toBe(er.password);
        expect(r.notes).toBe(er.notes);
        if ("timePasswordChangedMs" in er) expect(r.timePasswordChangedMs).toBe(er.timePasswordChangedMs);
      }

      expect(parsed.errors.length).toBe(exp.errors.length);
      for (let idx = 0; idx < exp.errors.length; idx++) {
        const ee = exp.errors[idx];
        const e = parsed.errors[idx]!;
        expect(e.line).toBe(ee.line);
        expect(e.code).toBe(ee.code);
      }

      let seq = 0;
      const plan = planImport(parsed, () => `id-${seq++}`);
      expect(plan.items.length).toBe(exp.docs.length);
      for (let idx = 0; idx < exp.docs.length; idx++) {
        const ed = exp.docs[idx];
        const doc = plan.items[idx]!.doc;
        expect(doc.name).toBe(ed.name);
        expect(doc.login?.username ?? "").toBe(ed.username);
        expect(doc.login?.password ?? "").toBe(ed.password);
        expect(doc.login?.uris?.[0] ?? "").toBe(ed.uri);
        expect(doc.notes ?? "").toBe(ed.notes);
      }
      expect(plan.report.imported).toBe(exp.report.imported);
      expect(plan.report.skippedEmpty).toBe(exp.report.skippedEmpty);
      expect(plan.report.collapsed).toBe(exp.report.collapsed);
      expect(plan.report.flagged).toEqual(exp.report.flagged);
    });
  }
});

describe("import.json — reject", () => {
  const v = load("import.json");
  for (const r of v.reject) {
    it(r.name, () => {
      const bytes: Uint8Array =
        "contentB64" in r
          ? fromB64(r.contentB64)
          : utf8(r.construct.header + "\n" + (r.construct.row + "\n").repeat(r.construct.count));
      let caught: unknown;
      try {
        parseCsvImport(bytes);
      } catch (e) {
        caught = e;
      }
      expect(caught).toBeInstanceOf(ImportError);
      expect((caught as ImportError).code).toBe(r.reason);
    });
  }
});

describe("planImport idempotency contract", () => {
  it("mints itemIds once and reuses them across a re-plan of the same parsed input", () => {
    // Two separate plans of the same Parsed get independent id streams (re-parsing =
    // new plan = duplicates), but a single plan's itemIds are stable to reuse on retry.
    const parsed = parseCsvImport(
      utf8("name,url,username,password,note\nA,https://a.test,u,p,\nB,https://b.test,u2,p2,\n"),
    );
    let seq = 0;
    const plan = planImport(parsed, () => `stable-${seq++}`);
    expect(plan.items.map((i) => i.itemId)).toEqual(["stable-0", "stable-1"]);
  });
});
