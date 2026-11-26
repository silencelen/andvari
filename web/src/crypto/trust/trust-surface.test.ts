import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

/**
 * Design 2026-11-15 §2.1: "There is still no 'sign any statement' API on an account. Each flow owns its
 * own builder." `signFrame` signs arbitrary statement bytes under any purpose, so it must stay inside
 * `crypto/trust/`, where each purpose's builder calls it after encoding its own template. This scan
 * pins that no other file of the web client imports it.
 */
const srcDir = fileURLToPath(new URL("../../", import.meta.url));
const trustDir = join(srcDir, "crypto", "trust");

function sources(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) return name === "node_modules" ? [] : sources(path);
    return /\.(ts|tsx)$/.test(name) ? [path] : [];
  });
}

describe("the trust module's signing surface", () => {
  it("signFrame is used only inside crypto/trust", () => {
    const offenders = sources(srcDir)
      .filter((path) => !path.startsWith(trustDir))
      .filter((path) => /\bsignFrame\b/.test(readFileSync(path, "utf-8")));
    expect(offenders).toEqual([]);
  });
});
