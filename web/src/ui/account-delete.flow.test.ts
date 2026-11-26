import { describe, expect, it } from "vitest";
import { UNREACHABLE } from "./errors";
import { afterOutcome, cardOutcomeOf, DELETE_FUTURE_HEAD, initialFlow, previewOfV2, settledOutcome } from "./account-delete";

/** The Delete account card on the post-cut-over flow: settingsflow's outcomes as the card's (design §3.11, spec 03 §13). */
describe("cardOutcomeOf", () => {
  it("only `deleted` is a deletion, `unknown` stays ambiguous, an unread preview was never sent", () => {
    expect(cardOutcomeOf({ kind: "deleted", deletedAt: 5 })).toEqual({ kind: "deleted", deletedAt: 5 });
    expect(settledOutcome(cardOutcomeOf({ kind: "unknown", error: new Error("x") }))).toBe("unknown");
    expect(cardOutcomeOf({ kind: "unreachable" })).toEqual({ kind: "error", message: UNREACHABLE, unanswered: true });
    expect(settledOutcome(cardOutcomeOf({ kind: "unreachable" }))).toBe("unsent");
    expect(cardOutcomeOf({ kind: "session_ended" })).toEqual({ kind: "session_gone" });
  });

  it("a code the preview did not know about turns the code field on; a future head says so", () => {
    expect(afterOutcome(initialFlow(), cardOutcomeOf({ kind: "totp_needed" })).totpRequired).toBe(true);
    expect(afterOutcome(initialFlow(), cardOutcomeOf({ kind: "future_head" })).err).toBe(DELETE_FUTURE_HEAD);
    expect(cardOutcomeOf({ kind: "blocked", blockers: [{ kind: "shared_vault", vaultId: null, others: 2 }] })).toEqual({ kind: "blocked", blockers: [{ kind: "shared_vault", vaultId: null, others: 2 }] });
  });

  it("the post-cut-over preview renders as the card's preview", () => {
    expect(previewOfV2({ blockers: [], deletedVaults: ["a"], leftVaults: ["b"], memberships: [{ vaultId: "b", head: { seq: 1, hash: "h", at: 1 } }], totpRequired: true })).toEqual({ blockers: [], deletedVaults: ["a"], leftVaults: ["b"], totpRequired: true });
  });
});
