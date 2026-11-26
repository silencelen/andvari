import { describe, expect, it } from "vitest";
import { ApiError } from "../api/client";
import { refusalText } from "./Welcome";

/** Spec 01 §5.5's stricter address grammar: the server's `invalid_email` and the local refusal read the same. */
describe("refusalText and invalid_email", () => {
  it("the server's refusal and the local grammar's refusal are the same sentence, never a device problem", () => {
    const served = refusalText(new ApiError(400, "invalid_email", "invalid email"));
    expect(served).toBe("That doesn't look like an email address.");
    expect(refusalText(new Error("invalid_email"))).toBe(served);
  });
});
