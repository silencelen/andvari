import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

/**
 * Faults the 2026-11-16 walk of sharing between two people in a real browser found (bob in headless Chrome, alice
 * through the engine's own code, against a private test server), each pinned where a source can hold it. The walk
 * itself lives outside the repository.
 */
const here = (p: string) => fileURLToPath(new URL(p, import.meta.url));
const read = (p: string) => readFileSync(here(p), "utf8");
const css = read("./styles.css");

describe("on a phone the Sharing screen keeps names readable and controls on the screen", () => {
  it("a vault's row keeps room for its name and wraps its tag and button", () => {
    // At 390 px "Family" read "F…": the name had about 25 px beside the role tag and Settings.
    expect(css).toMatch(/\.item\.static\s*\{[^}]*flex-wrap:\s*wrap/);
    expect(css).toMatch(/\.item\.static \.body\s*\{[^}]*min-width:\s*8em/);
  });

  it("the transfer row wraps instead of pushing its button off the card", () => {
    const src = read("./Sharing.tsx");
    const at = src.indexOf('aria-label="Make someone else the owner"');
    expect(src.slice(src.lastIndexOf("<div", at), at)).toContain('flexWrap: "wrap"');
  });
});

describe("removing a member (§3.13)", () => {
  it("the confirmation says what removal does not do, in the design's own words", async () => {
    const { REMOVE_MEMBER_DOES_NOT } = await import("./copy");
    const design = readFileSync(here("../../../docs/design/2026-11-15-onboarding-trust.md"), "utf8");
    expect(design).toContain(`> ${REMOVE_MEMBER_DOES_NOT}`);
    const src = read("./Sharing.tsx");
    const branch = src.slice(src.indexOf("removing === r.userId ? ("), src.indexOf("Confirm remove"));
    expect(branch).toContain("{REMOVE_MEMBER_DOES_NOT}");
    expect(src).not.toContain("the vault key is not rotated");
  });

  it("while removing, the member's name has a line of its own (a phone showed \"A..\" beside the two buttons)", () => {
    const src = read("./Sharing.tsx");
    const row = src.slice(src.indexOf('<div className="attach-row" key={r.userId}'), src.indexOf("Confirm remove"));
    expect(row).toMatch(/className="attach-name" style=\{removing === r\.userId \? \{ flexBasis: "100%" \}/);
  });
});

describe("leaving a vault", () => {
  it("the confirmation's paragraph reads left to right, not right-aligned", () => {
    const src = read("./Sharing.tsx");
    const at = src.indexOf("You'll lose access on all your devices");
    expect(src.slice(src.lastIndexOf("<span", at), at)).not.toContain('textAlign: "right"');
  });
});

describe("the ownership offer as its target sees it", () => {
  const src = read("./Sharing.tsx");
  const card = src.slice(src.indexOf("function IncomingTransferCard"), src.indexOf("// ---- recently deleted"));

  it("says until when the offer can be accepted, and its words live in copy.ts", () => {
    expect(card).toContain("fill(OFFER_IN_UNTIL, fmtDay(offer.expiresAt))");
    for (const k of ["OFFER_IN_TITLE", "OFFER_IN_BODY", "OFFER_IN_ACCEPT", "OFFER_IN_DECLINE"]) expect(card).toContain(k);
    expect(card).not.toMatch(/>Decline<|"Become the owner"/);
  });

  it("no card in the UI carries a coloured bar down its left edge (the owner's design rule)", () => {
    const bars = readdirSync(here(".")).filter((n) => n.endsWith(".tsx") && /borderLeft/.test(read(`./${n}`)));
    expect(bars).toEqual([]);
  });
});

describe("Settings carries no card of the old way of checking people (design §6.9, §13)", () => {
  it("no Identity code to read out and no list of household members verified by typed code, QR or enrolment", () => {
    const settings = read("./Settings.tsx");
    const household = read("./Household.tsx");
    for (const gone of ["IdentityCard", "HouseholdCard", "Identity code", "read this out"]) expect(settings).not.toContain(gone);
    for (const gone of ["export function HouseholdCard", "<h2>Household members", "METHOD_LABEL", "unpin("]) expect(household).not.toContain(gone);
  });
});

describe("a list that asks the person to tick or pick someone names them", () => {
  it("a tick box or a choice button is as wide as itself, not as wide as a text field", () => {
    // The global `input { width: 100% }` made the one-tap list's box a line of its own and squeezed the
    // add-a-contact list's name to nothing.
    expect(css).toMatch(/input\[type="checkbox"\],\s*input\[type="radio"\]\s*\{[^}]*width:\s*auto/);
  });

  it("every label around a tick box or a choice button is a row with sentence-case text", () => {
    const bad: string[] = [];
    for (const f of readdirSync(here(".")).filter((n) => n.endsWith(".tsx"))) {
      const src = read(`./${f}`);
      for (const m of src.matchAll(/<label\b([^>]*)>/g)) {
        const inner = src.slice(m.index! + m[0].length, src.indexOf("</label>", m.index));
        if (!/type="(checkbox|radio)"/.test(inner)) continue;
        // The global `label` rule is the 12 px upper-case caption; these classes give the row and the sentence back.
        if (!/className="[^"]*\b(check|inline-check|attach-row|member-line)\b/.test(m[1]!)) bad.push(`${f}:${src.slice(0, m.index).split("\n").length}`);
      }
    }
    expect(bad).toEqual([]);
    expect(css).toMatch(/label\.attach-row\s*\{[^}]*text-transform:\s*none/);
    expect(css).toMatch(/label\.member-line\s*\{[^}]*text-transform:\s*none/);
  });
});
