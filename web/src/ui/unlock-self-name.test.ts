import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

/**
 * Design §4.5: the server's display name is marked "(as the server names itself)" for a pin made at the Trust Gate (a
 * typed address). The sign-in and unlock cards' "Master password for … on …" line named the server without the mark
 * (the walk's unlock cards, D and E parts). Both labels now use shownName, which adds it for exactly those pins.
 */
const welcome = readFileSync(fileURLToPath(new URL("./Welcome.tsx", import.meta.url)), "utf8");

describe("the password label names the server as §4.5 says", () => {
  it("both MASTER_PASSWORD_FOR labels take the name from shownName(pin)", () => {
    const labels = [...welcome.matchAll(/fill\(MASTER_PASSWORD_FOR, [^}]*\)(?=\} prompt)/g)].map((m) => m[0]);
    expect(labels).toEqual(["fill(MASTER_PASSWORD_FOR, shownEmail, shownName(pin), origin)", "fill(MASTER_PASSWORD_FOR, session.email, shownName(pin), origin)"]);
    const shown = welcome.slice(welcome.indexOf("export function shownName("), welcome.indexOf("export function shownName(") + 250);
    expect(shown).toContain('return pin.root === "trust_gate" ? `${name} ${AS_THE_SERVER_NAMES_ITSELF}` : name;');
  });
});
