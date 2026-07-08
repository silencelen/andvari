import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

/**
 * ENFORCES the README's provenance table (review finding test-adequacy-2: a documented
 * tamper check nobody runs isn't a tamper check). Any byte change to the vendored
 * encoder — malicious or accidental — fails the suite until the README table is
 * consciously re-pinned alongside it.
 */
const PINS: Record<string, string> = {
  "qrcode.js": "18ae399f81182bc9de916e9c77b195df20cc58d6f2d55a62b085a299f1bf1780",
  "qrcode.esm.js": "35e88c0dac5c3546c16ec4be3ff5a2e82653b91080ac20e0dbb1a35a18fbe3fa",
};

const here = (name: string) => fileURLToPath(new URL(`./${name}`, import.meta.url));

describe("vendored qrcode-generator integrity (README pins)", () => {
  for (const [name, sha] of Object.entries(PINS)) {
    it(`${name} matches its pinned sha256`, () => {
      const actual = createHash("sha256").update(readFileSync(here(name))).digest("hex");
      expect(actual).toBe(sha);
    });
  }

  it("qrcode.esm.js is exactly qrcode.js + the marked ESM epilogue (mechanical derivation)", () => {
    const pristine = readFileSync(here("qrcode.js"), "utf8");
    const esm = readFileSync(here("qrcode.esm.js"), "utf8");
    expect(esm.startsWith(pristine)).toBe(true);
    const epilogue = esm.slice(pristine.length);
    expect(epilogue).toContain("export default qrcode");
    expect(epilogue.split("\n").length).toBeLessThanOrEqual(8); // a shim, not a fork
  });
});
