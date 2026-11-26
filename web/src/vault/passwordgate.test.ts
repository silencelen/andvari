import { describe, expect, it } from "vitest";
import { vector } from "../crypto/trust/vectors";
import { decide, type GatePurpose, isPasswordPin, PasswordRuleError, requireProceed } from "./passwordgate";

/**
 * The web's password rule against spec/test-vectors/passwordgate.json. The web has four purposes: sign-in from
 * its first screen, creating an account there, re-authentication inside a session, and recovering its own
 * account with the kit from "Forgot your master password?" (§13). It has two entry screens (the first screen,
 * `server_choice`, and the kit recovery screen) and takes no link payload, so it grades exactly:
 *
 * - sign-in and register rows that start on `server_choice` with no payload;
 * - re-authentication rows (`entry: null`);
 * - kit recovery rows that start on `kit_recovery_screen` with a kit.
 *
 * and of those only the rows whose pins a browser can hold, the baked instance's and the Trust Gate's (design §17).
 * Every other row is a device-link or assisted-recovery row, starts on a screen the web does not have (an invite,
 * an app link, the device-link screen), or holds a pin a browser never holds (kit, setup, link offer, enrol); the
 * count is pinned so a new row of the web's own kind cannot go ungraded.
 */
const file = vector("passwordgate.json");
const WEB: readonly GatePurpose[] = ["sign_in", "register", "reauth", "kit_recovery"];

interface Row {
  name: string;
  purpose: string;
  entry: string | null;
  payload: string | null;
  origin: string;
  account: string | null;
  pins: { origin: string; root: string; account?: string; blocked?: boolean }[];
  session: { origin: string; account: string } | null;
  expect: { decision: string };
}

const rows = file.rows as Row[];
/** The roots of the pins a browser can hold (design §4.4, §17): the baked instance and the Trust Gate's. */
const BROWSER_ROOTS = new Set(["baked", "trust_gate"]);
/** A row of the web's purposes that starts on an entry the web has (no app link, no scan, no device-link screen). */
const isWebEntryRow = (r: Row) => {
  if (r.purpose === "kit_recovery") return r.entry === "kit_recovery_screen" && r.payload === "kit";
  return (WEB as string[]).includes(r.purpose) && (r.entry === "server_choice" || r.entry === null) && r.payload === null;
};
/** Design §17: the web grades the rows of its four purposes whose pins a browser can hold and whose entry it has. */
const isWebRow = (r: Row) => isWebEntryRow(r) && r.pins.every((p) => BROWSER_ROOTS.has(p.root));
const GRADED = 13;

describe("passwordgate.json (the web's rows)", () => {
  it("grades every row of the web's purposes, entries and browser-held pins", () => {
    const graded = rows.filter(isWebRow);
    expect(graded.length).toBe(GRADED);
    expect(graded.filter((r) => r.purpose === "kit_recovery").length).toBe(3);
    expect(graded.filter((r) => r.purpose === "reauth").length).toBe(4);
    for (const r of graded) {
      const d = decide({
        purpose: r.purpose as GatePurpose,
        origin: r.origin,
        account: r.account,
        pins: r.pins.map((p) => ({ origin: p.origin, root: p.root as never, account: p.account ?? null, blocked: p.blocked ?? false })),
        session: r.session,
      });
      expect(d, r.name).toBe(r.expect.decision);
    }
  });

  it("the rows it leaves out are not the web's", () => {
    const left = rows.filter((r) => !isWebRow(r));
    for (const r of left) {
      if (isWebEntryRow(r)) {
        // The web's own entry, but a pin a browser never holds (kit, setup, link offer, enrol).
        expect(r.pins.some((p) => !BROWSER_ROOTS.has(p.root)), r.name).toBe(true);
        continue;
      }
      if (r.purpose === "kit_recovery") {
        // A kit shown anywhere but the kit recovery screen starts nothing: the web's only kit field is that screen.
        expect(r.entry, r.name).not.toBe("kit_recovery_screen");
        expect(r.expect.decision, r.name).toBe("refuse_entry");
      } else if ((WEB as string[]).includes(r.purpose)) {
        // A sign-in or register row started on an invite, app-link, kit or device-link screen.
        expect(r.entry === "server_choice" || r.entry === null, r.name).toBe(false);
      } else expect(["device_link", "assisted_recovery"], r.name).toContain(r.purpose);
    }
    expect(left.length + GRADED).toBe(rows.length);
  });

  it("a kit pin counts for recovering the kit's own account and for nothing else", () => {
    const pin = { origin: "https://a.example", root: "kit" as const, account: "a@b.c" };
    expect(isPasswordPin(pin, "kit_recovery", "a@b.c")).toBe(true);
    expect(isPasswordPin(pin, "kit_recovery", "x@b.c")).toBe(false);
    expect(isPasswordPin(pin, "sign_in", "a@b.c")).toBe(false);
    // The pin store's records carry no account, so a kit or setup record never passes on its own.
    expect(isPasswordPin({ origin: "https://a.example", root: "kit" }, "kit_recovery", "a@b.c")).toBe(false);
    expect(isPasswordPin({ origin: "https://a.example", root: "setup" }, "kit_recovery", "a@b.c")).toBe(false);
  });

  it("requireProceed throws a typed refusal that carries no secret", () => {
    expect(() => requireProceed({ purpose: "sign_in", origin: "https://a.example", account: "a@b.c", pins: [], session: null })).toThrow(PasswordRuleError);
    expect(() =>
      requireProceed({ purpose: "sign_in", origin: "https://a.example", account: "a@b.c", pins: [{ origin: "https://a.example", root: "trust_gate" }], session: null }),
    ).not.toThrow();
  });
});
