import { describe, expect, it } from "vitest";
import { fill, KEPT_CHANGES_ONE, SESSION_NOT_CONFIRMED, UNSENT_LOST_NOT_CONFIRMED, UNSENT_LOST_NOT_CONFIRMED_ONE } from "./copy";
import { heldEndNotice, keptChangesLine, lostChangesLine, sessionEndLine } from "./sessionend";

/** The lines App puts around the end of a session this browser could not confirm (App signOut and endByServer). */
describe("the lines around a session this browser could not confirm", () => {
  it("unsent changes lost with it are counted in a line of their own, never as a session that expired", () => {
    const expired = lostChangesLine("expired", undefined, 3);
    const unconfirmed = lostChangesLine("unconfirmed", undefined, 3);
    expect(unconfirmed).toBe(fill(UNSENT_LOST_NOT_CONFIRMED, "3"));
    expect(unconfirmed).not.toBe(expired);
    expect(lostChangesLine("unconfirmed", SESSION_NOT_CONFIRMED, 2)).toBe(`${SESSION_NOT_CONFIRMED} ${fill(UNSENT_LOST_NOT_CONFIRMED, "2")}`);
    expect(lostChangesLine("unconfirmed", SESSION_NOT_CONFIRMED, 0)).toBe(SESSION_NOT_CONFIRMED);
    // One change has a line of its own (never "1 changes").
    expect(lostChangesLine("unconfirmed", undefined, 1)).toBe(UNSENT_LOST_NOT_CONFIRMED_ONE);
    expect(lostChangesLine("unconfirmed", SESSION_NOT_CONFIRMED, 1)).toBe(`${SESSION_NOT_CONFIRMED} ${UNSENT_LOST_NOT_CONFIRMED_ONE}`);
    expect(lostChangesLine("user", undefined, 4), "the person's own sign-out asked before, with its count").toBeUndefined();
  });

  it("the notice over the card of a held session does not say the browser's own end a second time", () => {
    expect(heldEndNotice("unconfirmed", undefined, sessionEndLine("unconfirmed"), keptChangesLine(1))).toBe(KEPT_CHANGES_ONE);
    expect(heldEndNotice("unconfirmed", undefined, sessionEndLine("unconfirmed"), undefined)).toBe("");
    expect(heldEndNotice("expired", undefined, sessionEndLine("expired"), undefined)).toBe(sessionEndLine("expired"));
  });
});
