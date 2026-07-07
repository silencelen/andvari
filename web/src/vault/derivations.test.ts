import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import { initSodium } from "../crypto/sodium";
import { estimateStrength } from "../ui/strength";
import { conflictCopyId } from "./store";

/**
 * Consumes spec/test-vectors/{strength,conflictcopy}.json — the SAME files the Kotlin
 * suite checks. The strength score gates the spec 07 §2.3 backup-passphrase floor, and
 * the conflict-copy id must match core byte-for-byte or concurrent materializers double
 * every conflict copy across the fleet.
 */
const vectorsDir = fileURLToPath(new URL("../../../spec/test-vectors/", import.meta.url));
const load = (name: string) => JSON.parse(readFileSync(vectorsDir + name, "utf-8"));

beforeAll(async () => {
  await initSodium();
});

describe("strength vectors", () => {
  it("scores match core", () => {
    for (const c of load("strength.json").cases as { password: string; utf16Length: number; score: number }[]) {
      expect(c.password.length, `UTF-16 length of '${c.password}'`).toBe(c.utf16Length);
      expect(estimateStrength(c.password), `score of '${c.password}'`).toBe(c.score);
    }
  });
});

describe("conflict-copy-id vectors", () => {
  it("ids match core", async () => {
    for (const c of load("conflictcopy.json").cases as { itemId: string; rev: number; copyId: string }[]) {
      expect(await conflictCopyId(c.itemId, c.rev), `copyId of (${c.itemId}, ${c.rev})`).toBe(c.copyId);
    }
  });
});
