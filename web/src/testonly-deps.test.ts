import { existsSync, readFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

/**
 * The library that draws pages inside the tests (decided on 2026-11-19: for the tests only, pinned by version and
 * checksum) never reaches what the web app ships. What ships is what the build bundles: the module the page loads
 * (index.html) and every module it reaches through an import or a worker's URL. Not one of them may import the library
 * or a package it brought, and none of them is a test or a test kit.
 */
const web = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const TEST_ONLY = ["happy-dom", "ws", "entities", "whatwg-mimetype", "buffer-image-size", "@types/ws", "@types/whatwg-mimetype"];

/** Every module the build reaches from the page's own script, and every bare package each of them names. */
function shipped(): { files: string[]; packages: Set<string> } {
  const html = readFileSync(join(web, "index.html"), "utf8");
  const entries = [...html.matchAll(/<script[^>]*type="module"[^>]*src="\/([^"]+)"/g)].map((m) => join(web, m[1] as string));
  const seen = new Set<string>();
  const packages = new Set<string>();
  const todo = [...entries];
  while (todo.length > 0) {
    const file = todo.pop() as string;
    if (seen.has(file)) continue;
    seen.add(file);
    const src = readFileSync(file, "utf8");
    const specs = [
      ...[...src.matchAll(/\b(?:import|export)\s[^;]*?\sfrom\s+["']([^"']+)["']/g)].map((m) => m[1] as string),
      ...[...src.matchAll(/\bimport\s+["']([^"']+)["']/g)].map((m) => m[1] as string),
      ...[...src.matchAll(/\bimport\(\s*["']([^"']+)["']\s*\)/g)].map((m) => m[1] as string),
      ...[...src.matchAll(/new URL\(\s*["']([^"']+)["']\s*,\s*import\.meta\.url\s*\)/g)].map((m) => m[1] as string),
    ];
    for (const s of specs) {
      if (!s.startsWith(".")) {
        packages.add(s.startsWith("@") ? s.split("/").slice(0, 2).join("/") : (s.split("/")[0] as string));
        continue;
      }
      const base = resolve(dirname(file), s);
      const hit = [base, `${base}.ts`, `${base}.tsx`, join(base, "index.ts"), join(base, "index.tsx")].find((p) => existsSync(p) && /\.tsx?$/.test(p));
      if (hit) todo.push(hit);
    }
  }
  return { files: [...seen].map((f) => relative(web, f)).sort(), packages };
}

describe("the test-only page library is never shipped", () => {
  it("no module the build reaches imports it or a package it brought, and none of them is a test", () => {
    const { files, packages } = shipped();
    // The walk reaches the app (a guard that it walked at all): the page's script, the app, the proof-of-work worker.
    expect(files).toEqual(expect.arrayContaining(["src/main.tsx", "src/ui/App.tsx", "src/vault/powworker.ts"]));
    for (const p of TEST_ONLY) expect(packages.has(p), p).toBe(false);
    expect(files.filter((f) => /\.test\.tsx?$|\.testkit\.tsx?$|^src\/journeys\/|^src\/e2e\//.test(f))).toEqual([]);
  });

  it("it is a development dependency only, at one exact version, and the lock file holds a checksum for it and each package it brought", () => {
    const pkg = JSON.parse(readFileSync(join(web, "package.json"), "utf8")) as { dependencies: Record<string, string>; devDependencies: Record<string, string> };
    expect(pkg.dependencies["happy-dom"]).toBeUndefined();
    expect(pkg.devDependencies["happy-dom"]).toMatch(/^\d+\.\d+\.\d+$/);
    const lock = JSON.parse(readFileSync(join(web, "package-lock.json"), "utf8")) as { packages: Record<string, { version?: string; dev?: boolean; integrity?: string; hasInstallScript?: boolean }> };
    for (const p of TEST_ONLY.filter((x) => x !== "@types/node")) {
      const e = lock.packages[`node_modules/${p}`];
      expect(e, p).toBeDefined();
      expect(e?.dev, p).toBe(true);
      expect(e?.integrity, p).toMatch(/^sha512-/);
      expect(e?.hasInstallScript, p).toBeUndefined();
    }
    expect(lock.packages["node_modules/happy-dom"]?.version).toBe(pkg.devDependencies["happy-dom"]);
  });
});
