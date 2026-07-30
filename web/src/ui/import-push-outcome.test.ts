import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { ApiError } from "../api/client";
import { KdfPolicyError, WEAK_KDF_MESSAGE } from "../crypto/keys";
import { NetworkError } from "./errors";
import { importPushOutcome } from "./Vault";

/**
 * ux-error--1 (polish audit 2026-07-27): every import PUSH failure collapsed into ONE retryable
 * sentence ("press Retry to import the rest"), so a permission refusal or a weakened-KDF block
 * replayed the same doomed push forever under copy that promised it would finish. The panel now
 * asks [importPushOutcome] whether the failure is terminal, and only a transient one keeps the
 * Retry button (the natives' twin split is pinned by desktop ImportPushOutcomeTest / android
 * PureGatesTest). Pure function + real sources, no rendering — the offlineCopyModel idiom.
 */

const here = (p: string) => fileURLToPath(new URL(p, import.meta.url));
const householdKt = readFileSync(
  here("../../../core/src/commonMain/kotlin/io/silencelen/andvari/core/client/HouseholdCopy.kt"),
  "utf8",
);
/** The curated sentence on HouseholdCopy's `e.status == <status>` row (vault-copy.test.ts's helper). */
function canonStatusRow(status: number): string {
  const m = householdKt.match(new RegExp(`e\\.status == ${status} -> "([^"]+)"`));
  expect(m, `HouseholdCopy's ${status} row moved — update the pin`).not.toBeNull();
  return m![1]!;
}

describe("import push outcome — terminal vs transient", () => {
  it("a transport blip keeps the Retry affordance and its no-duplicates promise", () => {
    const o = importPushOutcome(new NetworkError());
    expect(o.fatal).toBe(false);
    expect(o.message).toContain("press Retry");
  });

  it("a rate limit and a 5xx stay retryable — the server's own copy says to try again", () => {
    for (const e of [new ApiError(429, "rate_limited", "slow down"), new ApiError(503, "unavailable", "restarting")]) {
      expect(importPushOutcome(e).fatal, `${e.status} should stay retryable`).toBe(false);
    }
  });

  it("an unclassified throw stays retryable (the idempotent replay converges)", () => {
    expect(importPushOutcome(new Error("boom")).fatal).toBe(false);
  });

  it("a 403 is TERMINAL and shows the canon 403 sentence, not a retry promise", () => {
    const o = importPushOutcome(new ApiError(403, "forbidden", "forbidden"));
    expect(o.fatal).toBe(true);
    expect(o.message).toBe(canonStatusRow(403)); // byte-twin of the natives' HouseholdCopy row
    expect(o.message).not.toContain("Retry");
  });

  it("a 413 is TERMINAL and shows the canon 413 sentence", () => {
    const o = importPushOutcome(new ApiError(413, "too_large", "quota"));
    expect(o.fatal).toBe(true);
    expect(o.message).toBe(canonStatusRow(413));
  });

  it("a weakened-KDF push is TERMINAL and keeps the security warning (H1, spec 05 T1)", () => {
    const o = importPushOutcome(new KdfPolicyError("kdf_below_floor", { v: 19, alg: "argon2id", ops: 1, memBytes: 1024 }));
    expect(o.fatal).toBe(true);
    expect(o.message).toBe(WEAK_KDF_MESSAGE);
    expect(o.message).not.toContain("Retry");
  });

  it("never surfaces the server's raw message", () => {
    const raw = "SQLITE_CONSTRAINT: UNIQUE constraint failed: mutations.id";
    for (const status of [400, 403, 413, 500]) {
      expect(importPushOutcome(new ApiError(status, "err", raw)).message).not.toContain("SQLITE");
    }
  });
});

describe("the Retry button is gated on the outcome, not merely on there being an error", () => {
  const vaultTsx = readFileSync(here("./Vault.tsx"), "utf8");

  it("Vault.tsx renders the exit — never Retry — for a fatal push failure", () => {
    // The audited defect was structural: `importErr ? <Retry> : <Import N>` had no terminal arm,
    // so ANY push failure lit the Retry button. The fatal arm must come FIRST.
    const fatalArm = vaultTsx.indexOf("{importErr && importFatal ? (");
    const retryArm = vaultTsx.indexOf(") : importErr ? (");
    expect(fatalArm, "the terminal arm is gone — a refusal would light Retry again").toBeGreaterThan(-1);
    expect(retryArm).toBeGreaterThan(fatalArm);
    // …and the terminal arm's button is the exit (onDone, so landed rows show), not a retry.
    expect(vaultTsx.slice(fatalArm, retryArm)).toContain("onClick={onDone}");
    expect(vaultTsx.slice(fatalArm, retryArm)).not.toContain("runImport");
  });
});
