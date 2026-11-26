import { appendFileSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

/** Test support: the conformance vectors of the onboarding and trust design (spec/test-vectors, §17). */
const vectorsDir = fileURLToPath(new URL("../../../../spec/test-vectors/", import.meta.url));

// The vector files are plain JSON written by the independent oracle; rows are read by name in each test.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function vector(name: string): any {
  return JSON.parse(readFileSync(vectorsDir + name, "utf-8"));
}

/**
 * Grades every row of one section, in file order. The count comes from the file, never from the test:
 * a section that is missing or empty is a harness fault, and the tally proves no row was passed over.
 * The tally it records (see [tally]) is the per-section count a conformance sweep reports.
 */
export function gradeEvery<T>(label: string, rows: readonly T[] | undefined, grade: (row: T, index: number) => void): number {
  if (!Array.isArray(rows) || rows.length === 0) throw new Error(`${label}: the section is missing or empty`);
  let graded = 0;
  rows.forEach((row, i) => {
    grade(row, i);
    graded++;
  });
  if (graded !== rows.length) throw new Error(`${label}: graded ${graded} of ${rows.length} rows`);
  tally(label, graded, rows.length);
  return graded;
}

/** Async twin of [gradeEvery], for verifiers that await. */
export async function gradeEveryAsync<T>(label: string, rows: readonly T[] | undefined, grade: (row: T, index: number) => Promise<void>): Promise<number> {
  if (!Array.isArray(rows) || rows.length === 0) throw new Error(`${label}: the section is missing or empty`);
  let graded = 0;
  for (const [i, row] of rows.entries()) {
    await grade(row, i);
    graded++;
  }
  if (graded !== rows.length) throw new Error(`${label}: graded ${graded} of ${rows.length} rows`);
  tally(label, graded, rows.length);
  return graded;
}

/** With ANDVARI_GRADED_LOG set, each graded section appends `<label> <graded>/<rows>` to that file. */
function tally(label: string, graded: number, rows: number): void {
  const log = process.env.ANDVARI_GRADED_LOG;
  if (log) appendFileSync(log, `${label} ${graded}/${rows}\n`);
}

/**
 * The file's top-level keys are exactly the ones this suite reads (or names as not its own). A section
 * the oracle adds later then fails here instead of going ungraded.
 */
export function expectSections(file: unknown, known: readonly string[]): void {
  const keys = Object.keys(file as Record<string, unknown>).sort();
  const want = [...known].sort();
  if (JSON.stringify(keys) !== JSON.stringify(want)) {
    throw new Error(`the file's sections are ${keys.join(", ")}; this suite knows ${want.join(", ")}`);
  }
}

export function hexBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  return out;
}
