import { describe, expect, it } from "vitest";
import { revokeConfirmText } from "./AccountDevices";
import { DEVICES_REVOKE_CONFIRM, fill } from "./copy";

/**
 * The wording check of 17 November: the removal's confirmation was filled with `.replace("{name}")` while the wording
 * page's line has `{0}`, so the approved line, once placed, would have shown its slot unfilled. It is filled with the
 * common fill now, whatever the words in the key.
 */
describe("the device removal's confirmation", () => {
  it("is filled through the common fill, and its slot is {0}", () => {
    expect(revokeConfirmText("Kitchen laptop")).toBe(fill(DEVICES_REVOKE_CONFIRM, "Kitchen laptop"));
    expect(revokeConfirmText("Kitchen laptop")).toContain("Kitchen laptop");
    expect(revokeConfirmText("Kitchen laptop")).not.toMatch(/\{[a-z0-9]+\}/);
    expect(DEVICES_REVOKE_CONFIRM).not.toContain("{name}");
  });
});
