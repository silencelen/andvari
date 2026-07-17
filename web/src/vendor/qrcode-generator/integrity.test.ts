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
  "qrcode.esm.js": "d23117de09bde2305e034cd55c19e2e259f6ea6fd9bc27a89deb538ce197ce30",
};

const here = (name: string) => fileURLToPath(new URL(`./${name}`, import.meta.url));

describe("vendored qrcode-generator integrity (README pins)", () => {
  for (const [name, sha] of Object.entries(PINS)) {
    it(`${name} matches its pinned sha256`, () => {
      const actual = createHash("sha256").update(readFileSync(here(name))).digest("hex");
      expect(actual).toBe(sha);
    });
  }

  it("qrcode.esm.js is exactly qrcode.js − the UMD CJS branch + the marked ESM epilogue", () => {
    // The documented 2-part mechanical derivation (README "Files"): the UMD footer's
    // CommonJS branch is removed (vitest 3's module runner provides interop
    // `exports`/`module` globals, so upstream's `module.exports = factory()` fired and
    // collided with the read-only ESM namespace), then the ESM epilogue is appended.
    const pristine = readFileSync(here("qrcode.js"), "utf8");
    const esm = readFileSync(here("qrcode.esm.js"), "utf8");
    const CJS_BRANCH = " else if (typeof exports === 'object') {\n      module.exports = factory();\n  }";
    expect(pristine).toContain(CJS_BRANCH); // upstream still carries it — else re-derive
    const derived = pristine.replace(CJS_BRANCH, "");
    expect(esm.startsWith(derived)).toBe(true); // exactly the one documented removal
    const epilogue = esm.slice(derived.length);
    expect(epilogue).toContain("export default qrcode");
    expect(epilogue.split("\n").length).toBeLessThanOrEqual(10); // a shim, not a fork
  });
});
