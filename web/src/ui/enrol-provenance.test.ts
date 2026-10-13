import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { IN_PERSON_CODE_WARNING } from "../enroll/enrollcheck";

/**
 * Security review 2026-10, root cause A, branch A5c (API review #4): the web enrol page has ONE intake, a
 * navigated link, and a QR scanned with the phone's camera app is a navigation too, indistinguishable from
 * an emailed link. The in-person code is an unkeyed hash of that link, so the server that composed it can
 * email "the code" as well. The pin of the admin (`ifp`/`iu`) therefore rests on two human acts the form
 * must collect and the state layer must re-check: the code typed from the admin's screen, and the member's
 * first-person statement that they are reading that screen right now, under the stop warning. These pins
 * are source-scans of the form (Welcome renders window.location + module singletons and cannot mount in
 * the node env; house pattern: enroll-errors.test.ts / master-breach-no-relay.test.ts).
 */
const src = (p: string) => readFileSync(fileURLToPath(new URL(p, import.meta.url)), "utf8");
const welcome = src("./Welcome.tsx");
const admin = src("./Admin.tsx");
/** Comment-stripped, so a rule written in prose cannot satisfy a pin about the code. */
const welcomeCode = welcome
  .replace(/\/\*[\s\S]*?\*\//g, "")
  .split("\n")
  .map((l) => l.replace(/^\s*\/\/.*$/, ""))
  .join("\n");

describe("web enrolment — the admin pin needs in-person evidence, never a navigated link's code alone (A5c)", () => {
  it("the waived posture no longer offers the code as an 'optional' identity check with no warning", () => {
    expect(welcome).not.toContain("optional: lets this app verify your admin's identity now");
  });

  it("the stop warning is rendered wherever the in-person code is typed, in every posture", () => {
    expect(welcomeCode).toContain("{IN_PERSON_CODE_WARNING}");
    expect(IN_PERSON_CODE_WARNING).toContain("Never use a code from an email or message.");
  });

  it("the pin is decided from the raw evidence (typed code + first-person affirmation), not a boolean", () => {
    // The evidence object is built from the human's two acts: the affirmation is the posture's own
    // first-person tick (required-affirm) or the waived posture's "I'm with my admin right now".
    expect(welcomeCode).toMatch(/inPersonAffirmed:\s*posture === "required-affirm" \? affirmConfirmed : inPersonAffirmed/);
    // ...and both the escrow seal's in-person verdict and the admin pin take that evidence, never `true`.
    expect(welcomeCode).toMatch(/await enrolInPerson\(linkPayload, inPersonEvidence\)/);
    expect(welcomeCode).toMatch(/pinFromEnrolLink\(linkPayload, inPersonEvidence,/);
    expect(welcomeCode).not.toMatch(/pinFromEnrolLink\([^)]*\btrue\b/);
  });

  it("in the waived posture the code field sits behind the in-person affirmation; otherwise verification is PENDING, not an error", () => {
    expect(welcome).toContain("I'm with my admin");
    expect(welcome).toContain(ADMIN_PIN_PENDING);
    // The pending state is informational copy, never the error channel.
    expect(welcomeCode).not.toMatch(/setErr\([^)]*Verify a household member/);
  });

  it("the end screen reports the pending verification when no pin was made", () => {
    expect(welcomeCode).toMatch(/showIdentity\.adminPinned\s*\?[\s\S]*?:\s*<Msg kind="info">\{ADMIN_PIN_PENDING\}<\/Msg>/);
  });

  it("the admin's screen tells the admin never to send the code by email or message", () => {
    expect(admin).toContain("Never send it by email or message");
  });
});

/** The pending sentence, pinned verbatim so the two renderings (form + end screen) cannot drift apart. */
const ADMIN_PIN_PENDING = "Your admin isn't verified on this account yet. You can verify them any time under Settings → Verify a household member.";
