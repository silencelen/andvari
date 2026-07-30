import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

/**
 * ux-copy--5 (polish audit 2026-07-27): the invite-QR panel still instructed the retired topology —
 * scan it "while on the same network as this page's address", and "for a phone that isn't on the
 * tailnet yet, mint from the LAN address instead". The enroll link embeds `location.origin` verbatim
 * (§3), so the true constraint is about that ADDRESS being reachable by the invitee's device, not
 * about any network the admin happens to be on. Pinned as source text the vault-copy.test.ts way:
 * the retired wording can't come back, and the security warning that shares the sentence — anyone
 * who photographs the QR can redeem it until it expires, unrevokable — can't be swept away with it.
 */

const adminTsx = readFileSync(fileURLToPath(new URL("./Admin.tsx", import.meta.url)), "utf8");

describe("Admin.tsx invite-QR copy", () => {
  it("presumes no network — the constraint is reaching this page's address", () => {
    expect(adminTsx).toContain(
      "it points at this page's address, so mint it from an address the invitee's device can reach",
    );
  });

  it("carries none of the retired-topology wording", () => {
    for (const retired of ["same network", "tailnet", "Tailscale", "LAN address"]) {
      expect(adminTsx, `retired-topology copy must never return: ${retired}`).not.toContain(retired);
    }
  });

  it("keeps the unrevokable-QR security warning", () => {
    expect(adminTsx).toContain(
      "Anyone who photographs this can use it until it expires — it can't be revoked",
    );
  });
});
