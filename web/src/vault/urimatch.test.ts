import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { pslResolve, PSL_SNAPSHOT_HASH } from "./psl";
import { PSL_RULES_JOINED } from "./pslData";
import { classify, matches, normalizeHost, parseSavedUri, RESOLVE_UNKNOWN, type FieldKind } from "./urimatch";

// Consumes the SAME spec/test-vectors/urimatch.json the Kotlin UriMatchVectorTest checks.
const vectorsDir = fileURLToPath(new URL("../../../spec/test-vectors/", import.meta.url));
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const v: any = JSON.parse(readFileSync(vectorsDir + "urimatch.json", "utf-8"));
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const v2: any = JSON.parse(readFileSync(vectorsDir + "urimatch-etld1.json", "utf-8"));
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const v3: any = JSON.parse(readFileSync(vectorsDir + "urimatch-idna.json", "utf-8"));

describe("urimatch.json — matching (byte-frozen originals)", () => {
  it("matches per the label-boundary rule — with the REAL resolver (frozen outcomes must hold under eTLD+1)", () => {
    for (const c of v.match) {
      const saved = parseSavedUri(c.savedUri);
      const actual = saved !== null && matches(saved, { webHost: c.webHost ?? null, packageName: c.packageName }, pslResolve);
      expect(actual, `${c.savedUri} @ ${c.webHost}/${c.packageName}`).toBe(c.expected);
    }
  });

  it("matches per the label-boundary rule — with RESOLVE_UNKNOWN (pre-amendment semantics preserved)", () => {
    for (const c of v.match) {
      const saved = parseSavedUri(c.savedUri);
      const actual = saved !== null && matches(saved, { webHost: c.webHost ?? null, packageName: c.packageName }, RESOLVE_UNKNOWN);
      expect(actual, `${c.savedUri} @ ${c.webHost}/${c.packageName}`).toBe(c.expected);
    }
  });
});

describe("urimatch-etld1.json — eTLD+1 / PSL (design 2026-07-10 A1-A12)", () => {
  it("A6: the snapshot hash matches the RUNTIME rule string (not constant-vs-constant)", () => {
    expect(PSL_SNAPSHOT_HASH).toBe(v2.snapshotHash);
    const runtime = createHash("sha256").update(PSL_RULES_JOINED, "ascii").digest("hex");
    expect(runtime, "sha256 of the loaded joined rule string").toBe(v2.snapshotHash);
  });

  it("resolves registrable/public-suffix/unknown per the shared vectors", () => {
    for (const c of v2.registrable) {
      const r = pslResolve(c.host);
      expect(r.kind, `resolve(${c.host}).kind`).toBe(c.kind);
      if (c.kind === "registrable") {
        expect(r.kind === "registrable" && r.domain, `resolve(${c.host}).domain`).toBe(c.domain);
      }
    }
  });

  it("matches per the amended rules (R-SUFFIX-BARE, R-EQ, R-OLD)", () => {
    for (const c of v2.match) {
      const saved = parseSavedUri(c.savedUri);
      const actual = saved !== null && matches(saved, { webHost: c.webHost ?? null, packageName: c.packageName }, pslResolve);
      expect(actual, `${c.savedUri} @ ${c.webHost}`).toBe(c.expected);
    }
  });
});

describe("urimatch-idna.json — A-label canonicalization (H22, 2026-09-13)", () => {
  // The `normalize` section pins normalizeHost's OUTPUT bytes, not just a match outcome: three
  // engines sharing one buggy encoder would still agree on saved == page, so the A-label itself
  // (from an independent WHATWG oracle) is the contract. Core UriMatchIdnaVectorTest parity.
  it("normalizeHost yields the browser's A-label, and is idempotent over it", () => {
    for (const c of v3.normalize) {
      const actual = normalizeHost(c.input);
      expect(actual, `normalizeHost(${c.input})`).toBe(c.expected);
      if (actual !== null) expect(normalizeHost(actual), `idempotent over ${c.input}`).toBe(actual);
    }
  });

  it("a Unicode saved host matches the punycode page host (and vice versa) — real resolver", () => {
    for (const c of v3.match) {
      const saved = parseSavedUri(c.savedUri);
      const actual = saved !== null && matches(saved, { webHost: c.webHost ?? null, packageName: c.packageName }, pslResolve);
      expect(actual, `${c.savedUri} @ ${c.webHost}`).toBe(c.expected);
    }
  });
});

describe("urimatch.json — classification", () => {
  it("classifies fields per priority", () => {
    for (const c of v.classify) {
      const actual: FieldKind = classify({
        hints: c.hints,
        inputTypeClass: c.inputTypeClass,
        inputTypeVariation: c.inputTypeVariation,
        htmlType: c.htmlType ?? null,
        htmlNameOrId: c.htmlNameOrId ?? null,
      });
      expect(actual, JSON.stringify(c)).toBe(c.expected);
    }
  });
});

// H65 (2026-09-13 audit, spec 02 §3.1 amendment). The shared classify vectors grade the
// one-time-code override itself in all three engines; these pin the parts that CANNOT live in a
// card-free shared section, because core answers them with a CARD kind the 3-kind engines have
// no word for.
//
// R37 — which of these is a revert detector, stated honestly, because the previous sentence
// claimed all of them were: the shared classify vectors plus the mid-token and 2FA blocks below
// go red if the override is reverted, widened or reordered. The masked-CVV block does NOT and
// must not: with the override reverted, `case "password": return "password"` answers those four
// assertions correctly by accident. That block is a NON-regression pin — it guards against the
// carve-out being WIDENED away or lost, and it must stay green with or without the override.
describe("H65 — the one-time-code override's edges (3-kind engine)", () => {
  it("leaves a masked CVV on `password` so detect.ts's form-level demoteCsc can still reach it", () => {
    // Core returns CC_CSC here (its step-2 CSC demotion runs BEFORE the override). This engine has
    // no card verdict, so it must keep today's `password` instead: dropping these to `none` would
    // delete the field from the extension's collect() and silently break masked-CVV card fill.
    expect(classify({ htmlType: "password", htmlNameOrId: "securityCode" })).toBe("password");
    expect(classify({ htmlType: "password", htmlNameOrId: "security_code" })).toBe("password");
    expect(classify({ htmlType: "password", htmlNameOrId: "cvv_code" })).toBe("password");
    expect(classify({ htmlType: "password", htmlNameOrId: "card_verification_code" })).toBe("password");
  });

  it("R35: camelCase CSC spellings too — core tokenizes on the case boundary, so this must as well", () => {
    // The regression this exists to prevent: the carve-out was tested against the LOWER-CASED
    // name, which destroys the very boundary core's tokenizer splits on. `cardSecurityCode` —
    // the ordinary JS/React spelling — therefore found no separator, failed the carve-out, and
    // was demoted to "none" by its `code` token while core returned CC_CSC for the same field.
    // On the extension that means collect() drops the field and masked-CVV fill silently breaks.
    for (const name of ["cardSecurityCode", "cvvCode", "cvcCode", "cardVerificationCode", "creditCardSecurityCode", "CVVCode"]) {
      expect(classify({ htmlType: "password", htmlNameOrId: name }), name).toBe("password");
    }
  });

  it("refuses the carve-out mid-token, exactly as core's whole-token-run CSC matcher does", () => {
    expect(classify({ htmlType: "password", htmlNameOrId: "cscode" })).toBe("none");
    expect(classify({ htmlType: "password", htmlNameOrId: "mysecuritycode" })).toBe("none");
    expect(classify({ htmlType: "password", htmlNameOrId: "cvvcode" })).toBe("none");
  });

  it("does not widen NAME_NEGATIVE: the two-factor names are password-override-only", () => {
    // Folding "2fa"/"mfa" into NAME_NEGATIVE would flip these frozen USERNAME verdicts.
    expect(classify({ htmlType: "email", htmlNameOrId: "2fa_recovery_email" })).toBe("username");
    expect(classify({ htmlType: "text", htmlNameOrId: "mfa_username" })).toBe("username");
    expect(classify({ htmlType: "password", htmlNameOrId: "mfa" })).toBe("none");
  });
});
