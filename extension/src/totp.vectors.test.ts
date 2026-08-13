// The extension's OWN execution of the shared TOTP vectors (node --test) — closing the totp.ts
// header claim "all impls run spec/test-vectors/totp.json", which was false while this port was the
// pre-0.8.0 divergent copy (exttech-2). Plus the parse-level determinism pins the vectors don't
// cover, each asserting the WEB/core outcome (the 2026-07-09 fixes backported here). The
// fileURLToPath pattern mirrors urimatch.vectors.test.ts:14.
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { base32Decode, isValidTotp, normalizeTotp, parseOtpauthUri, totpCode, type TotpAlgorithm } from "./totp.ts";

const vectorsDir = fileURLToPath(new URL("../../spec/test-vectors/", import.meta.url));
const vectors = JSON.parse(readFileSync(vectorsDir + "totp.json", "utf-8")) as {
  cases: { secretBase32: string; algorithm: string; digits: number; period: number; timeSec: number; expected: string }[];
};

test("totp.json shared vectors compute identically (RFC 6238; SHA1/256/512, 6/8 digits, 30/60 s)", () => {
  for (const c of vectors.cases) {
    const code = totpCode(
      {
        secret: base32Decode(c.secretBase32),
        algorithm: c.algorithm as TotpAlgorithm,
        digits: c.digits,
        periodSeconds: c.period,
        label: "",
        issuer: "",
      },
      c.timeSec,
    );
    assert.equal(code, c.expected, `${c.algorithm} d${c.digits} p${c.period} @ ${c.timeSec}`);
  }
});

// A valid base32 secret to hang the parse-level pins off (from the totp.json URI vectors).
const SECRET = "JBSWY3DPEHPK3PXP";

test("parse-level determinism pins (assert the web/core outcome)", () => {
  // Lenient label decode: a Latin-1 %E9 escape must ACCEPT (was fatal:true — a twin divergence).
  assert.doesNotThrow(() => parseOtpauthUri(`otpauth://totp/Caf%E9?secret=${SECRET}`), "Latin-1 %E9 label must parse leniently");

  // Strict percent hex: "%1G" is not valid hex → reject on EVERY client (parseInt would take 0x01).
  assert.throws(() => parseOtpauthUri(`otpauth://totp/%1G?secret=${SECRET}`), "%1G is not valid percent-hex");

  // Full-string int parse: "8x" is junk → the default 6, never parseInt's partial 8.
  assert.equal(parseOtpauthUri(`otpauth://totp/x?secret=${SECRET}&digits=8x`).digits, 6, "digits=8x -> 6");
  // A well-formed digits=8 still parses to 8 (sanity — the strict parser didn't over-reject).
  assert.equal(parseOtpauthUri(`otpauth://totp/x?secret=${SECRET}&digits=8`).digits, 8, "digits=8 -> 8");
  // An explicit out-of-range value parses, then range-throws.
  assert.throws(() => parseOtpauthUri(`otpauth://totp/x?secret=${SECRET}&digits=0`), "digits=0 is out of range");

  // Same for period: junk -> default 30, explicit 0 -> range throw.
  assert.equal(parseOtpauthUri(`otpauth://totp/x?secret=${SECRET}&period=30x`).periodSeconds, 30, "period=30x -> 30");
  assert.throws(() => parseOtpauthUri(`otpauth://totp/x?secret=${SECRET}&period=0`), "period=0 is out of range");

  // Empty / all-padding secret -> empty HMAC key -> reject (A5 reject-don't-corrupt).
  assert.throws(() => parseOtpauthUri("otpauth://totp/x?secret="), "empty secret rejected");
  assert.throws(() => parseOtpauthUri("otpauth://totp/x?secret=="), "all-padding secret decodes empty -> rejected");

  // Unicode whitespace INSIDE the secret is NOT ignored (only the pinned ASCII set is) -> invalid
  // base32 char -> throw. U+FEFF (BOM) and U+00A0 (NBSP) are exactly where a `\s`-based decoder
  // diverged across twins (JS `\s` strips U+FEFF; the JVM keeps it). Escapes kept explicit.
  assert.throws(() => parseOtpauthUri("otpauth://totp/x?secret=JBSW\uFEFFY3DP"), "U+FEFF in secret rejected");
  assert.throws(() => parseOtpauthUri("otpauth://totp/x?secret=JBSW\u00A0Y3DP"), "NBSP in secret rejected");
});

// TOTP-add lane (2026-08-12): the write-path twins — normalizeTotp + isValidTotp mirror
// web/src/crypto/totp.ts + Vault.tsx isValidTotp (the same pins vectors.test.ts holds there).
test("normalizeTotp wraps a bare base32 secret into a live otpauth URI (web twin)", () => {
  const bare = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"; // RFC 6238 SHA1 seed, no otpauth wrapper
  assert.throws(() => parseOtpauthUri(bare), "a bare secret alone must not parse");
  const cfg = parseOtpauthUri(normalizeTotp(bare));
  assert.equal(cfg.algorithm, "SHA1"); // otpauth defaults applied by the wrapper
  assert.equal(cfg.digits, 6);
  assert.equal(cfg.periodSeconds, 30);
  // …and it renders the SAME live code the explicit otpauth URI would.
  assert.equal(totpCode(cfg, 59), totpCode(parseOtpauthUri(`otpauth://totp/x?secret=${bare}`), 59));
});

test("normalizeTotp: URI passthrough, ASCII-whitespace strip, case preserved, junk unchanged", () => {
  const uri = `otpauth://totp/x?secret=${SECRET}`;
  assert.equal(normalizeTotp(uri), uri, "an otpauth URI passes through unchanged");
  // The pinned ASCII strip set (space \t \n \f \r — the exact chars core Totp.normalizeTotp
  // strips): a secret pasted with the enrollment page's display grouping still wraps.
  assert.equal(normalizeTotp("jbsw y3dp\tehpk\n3pxp\r"), "otpauth://totp/andvari?secret=jbswy3dpehpk3pxp", "grouped paste wraps with ORIGINAL case preserved");
  assert.equal(normalizeTotp("not base32!"), "notbase32!", "junk returns whitespace-stripped, unchanged otherwise");
  assert.equal(normalizeTotp("   "), "", "all-whitespace collapses to empty");
});

test("isValidTotp is the write gate: accepts only what parseOtpauthUri accepts (web twin)", () => {
  assert.equal(isValidTotp(normalizeTotp(SECRET)), true);
  assert.equal(isValidTotp(normalizeTotp(`otpauth://totp/x?secret=${SECRET}`)), true);
  assert.equal(isValidTotp(normalizeTotp("not base32!")), false, "junk normalizes unchanged and must refuse");
  assert.equal(isValidTotp(""), false, "empty is not a valid config");
  assert.equal(isValidTotp(normalizeTotp(`otpauth://totp/x?secret=${SECRET}&digits=0`)), false, "out-of-range digits refuse at the gate");
});
