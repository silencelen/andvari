import { beforeAll, describe, expect, it } from "vitest";
import { fromB64, toB64 } from "../bytes";
import { initSodium } from "../sodium";
import {
  composeKitQr, confirmGroups, confirmMatches, isValidGroupChoice, kitDisplayForm, kitGroups, MAX_KIT_QR_LENGTH, parseKitQr, parseTypedSecret,
} from "./recoverykit";
import { expectSections, gradeEvery, vector } from "./vectors";

/**
 * The recovery kit of design 2026-11-15 §10, graded off the SAME `recoverykit.json` core's
 * `RecoveryKitVectorTest` consumes: grouping, the typed secret (space, CR and LF ignored, nothing else),
 * the three-group confirmation, and the kit QR's compose and total parse. A text that does not parse
 * is `bad_kit` (§2.4 "Small cases"): `qr.parse` rows name that verdict, and it is graded exactly.
 */
const v = vector("recoverykit.json");

beforeAll(async () => {
  await initSodium();
});

describe("recoverykit.json", () => {
  it("the file has the sections this suite grades, and no other", () => {
    expectSections(v, ["_about", "grouping", "typedSecret", "confirm", "groupChoice", "qr"]);
    expectSections(v.qr, ["maxLength", "compose", "parse"]);
  });

  it("grouping: eleven groups and the display form", () => {
    gradeEvery("recoverykit.grouping", v.grouping, (r: any) => {
      const secret = fromB64(r.secretB64);
      expect(kitGroups(secret), r.why).toEqual(r.groups);
      expect(kitDisplayForm(secret), r.why).toBe(r.display);
    });
  });

  it("typedSecret: space, CR and LF are ignored and nothing else", () => {
    gradeEvery("recoverykit.typedSecret", v.typedSecret, (r: any) => {
      const result = parseTypedSecret(r.input);
      expect(result.ok, r.why).toBe(r.expect.valid);
      if (result.ok) expect(toB64(result.value), r.why).toBe(r.expect.secretB64);
      else expect(result.verdict, r.why).toBe("bad_kit");
    });
  });

  it("confirm: exact and case-sensitive once space, CR and LF are ignored, in the order asked", () => {
    gradeEvery("recoverykit.confirm", v.confirm, (r: any) => {
      expect(confirmMatches(fromB64(r.secretB64), r.groups, r.typed), r.why).toBe(r.expect.matches);
    });
  });

  it("groupChoice: three distinct numbers in 1..11", () => {
    gradeEvery("recoverykit.groupChoice", v.groupChoice, (r: any) => {
      expect(isValidGroupChoice(r.groups), r.why).toBe(r.valid);
    });
    for (let i = 0; i < 50; i++) expect(isValidGroupChoice(confirmGroups())).toBe(true);
  });

  it("qr.compose: andvari-kit:2:<O>:<C>:<E>:<S>", () => {
    expect(v.qr.maxLength).toBe(MAX_KIT_QR_LENGTH);
    gradeEvery("recoverykit.qr.compose", v.qr.compose, (r: any) => {
      expect(composeKitQr(r.origin, r.card0Hash, r.email, fromB64(r.secretB64)), r.why).toBe(r.text);
    });
    const r = v.qr.compose[0];
    expect(() => composeKitQr("http://192.168.1.10", r.card0Hash, r.email, fromB64(r.secretB64))).toThrow();
    expect(() => composeKitQr(r.origin, r.card0Hash, "Alice@example.com", fromB64(r.secretB64))).toThrow();
  });

  it("qr.parse: total and canonical; anything else is bad_kit", () => {
    gradeEvery("recoverykit.qr.parse", v.qr.parse, (r: any) => {
      expect(r.expect.verdict === "ok", `${r.why}: expect.valid says what expect.verdict says`).toBe(r.expect.valid);
      const result = parseKitQr(r.input);
      expect(result.ok ? "ok" : result.verdict, r.why).toBe(r.expect.verdict);
      if (result.ok) {
        expect([result.value.origin, result.value.card0Hash, result.value.emailNorm, toB64(result.value.secret)], r.why).toEqual([
          r.expect.origin, r.expect.card0Hash, r.expect.email, r.expect.secretB64,
        ]);
      }
    });
  });

  it("qr.parse: the cap counts after the white space is stripped, and non-ASCII bytes inside O or E are refused before any decoding", () => {
    const text: string = v.qr.compose[0].text;
    expect(parseKitQr(text + " ".repeat(MAX_KIT_QR_LENGTH)).ok).toBe(true);
    // A byte-order mark in front of the origin: a default TextDecoder would strip it and accept the origin.
    const bomOrigin = toB64(Uint8Array.from([0xef, 0xbb, 0xbf, ...new TextEncoder().encode("https://vault.example.org")]));
    expect(parseKitQr(text.replace("aHR0cHM6Ly92YXVsdC5leGFtcGxlLm9yZw", bomOrigin)).ok).toBe(false);
  });
});
