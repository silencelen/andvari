import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { ApiClient } from "./client";

/**
 * Assisted recovery (spec 04 §7): the legacy `adminRecovery(bundleText)` call, which POSTed a
 * recovery-cli bundle to `/admin/recovery` and had no screen, is removed. The web has no operator console (the server
 * refuses its operator sessions), and the answer now travels as a token that only the desktop console and
 * `andvari-cli operator fulfil` read. Nothing here may come back without a screen and the token reader.
 */
describe("the legacy recovery-bundle upload is gone", () => {
  it("ApiClient has no adminRecovery, and its source posts nothing to /admin/recovery", () => {
    expect((ApiClient.prototype as unknown as Record<string, unknown>).adminRecovery).toBeUndefined();
    const src = readFileSync(fileURLToPath(new URL("./client.ts", import.meta.url)), "utf8");
    expect(src).not.toMatch(/admin\/recovery["`]/);
    expect(src).not.toContain("PreSerializedJson");
  });
});
