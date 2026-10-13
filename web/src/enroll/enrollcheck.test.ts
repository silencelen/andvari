import { describe, expect, it } from "vitest";
import { initSodium } from "../crypto/sodium";
import { enrolInPerson, enrollCheckCode, IN_PERSON_CODE_WARNING } from "./enrollcheck";
import type { EnrollPayload } from "./enrolllink";

/**
 * Security review 2026-10, root cause A, branch A5c (API review #4): the in-person code is an unkeyed hash
 * of the link's own `rfp|ifp|iu`, so whoever composed the link can also compute it. A hostile server that
 * emails a navigated /enroll link can email "the code" beside it. Nothing the invitee's client can verify is
 * beyond the server's reach (the client's only inputs are the link and what the server serves), so the
 * anchor is necessarily the HUMAN's comparison, and the verdict is pinned here: the code typed from the
 * admin's screen AND the human's first-person statement that they are reading that screen right now. A
 * navigated link plus a correct code, on its own, is pending verification, never a pin.
 */
const payload: EnrollPayload = {
  v: 1,
  o: "https://vault.example",
  t: "tok",
  e: "m@example.org",
  ifp: "14f1bf4220e132f3aa00bb11cc22dd33ee44ff5566778899aabbccddeeff0011",
  iu: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
};

describe("enrolInPerson — the in-person verdict for a navigated enrol link (A5c)", () => {
  it("a navigated link plus a correct code is NOT in-person evidence on its own", async () => {
    await initSodium();
    const code = (await enrollCheckCode(payload))!;
    expect(await enrolInPerson(payload, { typedCode: code, inPersonAffirmed: false })).toBe(false);
  });

  it("the genuine in-person path: the code read off the admin's screen plus the first-person affirmation", async () => {
    await initSodium();
    const code = (await enrollCheckCode(payload))!;
    expect(await enrolInPerson(payload, { typedCode: code, inPersonAffirmed: true })).toBe(true);
    // Separators a human types are tolerated, as everywhere a 32-hex short form is typed.
    expect(await enrolInPerson(payload, { typedCode: code.replace(/(.{4})/g, "$1 ").toUpperCase(), inPersonAffirmed: true })).toBe(true);
  });

  it("an affirmation without the code, or with a prefix of it, is not in-person evidence either", async () => {
    await initSodium();
    const code = (await enrollCheckCode(payload))!;
    expect(await enrolInPerson(payload, { typedCode: "", inPersonAffirmed: true })).toBe(false);
    expect(await enrolInPerson(payload, { typedCode: code.slice(0, 16), inPersonAffirmed: true })).toBe(false);
    expect(await enrolInPerson(payload, { typedCode: "f".repeat(32), inPersonAffirmed: true })).toBe(false);
    // A link with no in-person fields has no code and can never be in-person evidence.
    expect(await enrolInPerson({ v: 1, o: payload.o, t: "t", e: "e" }, { typedCode: "", inPersonAffirmed: true })).toBe(false);
  });

  it("the stop warning is the exact sentence the review asked for, shown wherever the code is typed", () => {
    expect(IN_PERSON_CODE_WARNING).toBe(
      "Only type a code you are reading from your admin's screen right now. Never use a code from an email or message.",
    );
  });
});
