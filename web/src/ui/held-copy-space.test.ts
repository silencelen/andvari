import { describe, expect, it } from "vitest";
import { ApiError } from "../api/client";
import { HELD_COPY_OUT_OF_SPACE, OWNER_OUT_OF_SPACE, OWNER_OUT_OF_SPACE_YOURS } from "./copy";
import { heldCopyErrorText } from "./Sharing";

/**
 * The wording check of 17 November: copying a held vault's items into the personal vault when the account is out of
 * space said "This vault's owner is out of space… You own this vault", beside a vault that may be someone else's. The
 * copy lands in the person's own vault, so the line is about their account, in a key of its own.
 */
describe("a copy out of a held vault refused for space", () => {
  it("says the person's account is out of space, never the vault owner's line", () => {
    const text = heldCopyErrorText(new ApiError(413, "quota_exceeded", "x"));
    expect(text).toBe(HELD_COPY_OUT_OF_SPACE);
    expect(text).not.toContain(OWNER_OUT_OF_SPACE);
    expect(text).not.toContain(OWNER_OUT_OF_SPACE_YOURS);
  });
});
