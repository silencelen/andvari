import { describe, expect, it } from "vitest";
import { verdictOf } from "./checked";
import { parseHostOffer, withinJsonDepth } from "./codec";

/**
 * Design 2026-11-15 §2.4 "Host JSON offer" (VR-15): "printable ASCII and a JSON object with a string
 * `purpose`, else `non_canonical`; a `purpose` other than `setup-offer` and `enrol-offer` is
 * `unknown_format`". These rows pin the edge between the two verdicts. Core grades the SAME list
 * (`HostOfferRecognitionTest`), where the platform parser is too generous to be asked.
 */
const verdict = (text: string): string => verdictOf(parseHostOffer(new TextEncoder().encode(text)));

describe("host offer recognition", () => {
  it("is the same on every engine", () => {
    const deep = "[".repeat(33) + "]".repeat(33);
    const atTheBound = "[".repeat(31) + "]".repeat(31); // 32 containers open with the object around it
    const rows: [string, string][] = [
      ['{"purpose":"other"}', "unknown_format"],
      [' {"purpose":"other"}', "unknown_format"], // white space is still JSON; the purpose decides
      ['{"purpose":"other","x":1e5}', "unknown_format"],
      ['{"purpose":"oth\\u0065r"}', "unknown_format"],
      ['{"__proto__":{"purpose":"x"},"purpose":"other"}', "unknown_format"],
      [`{"purpose":"other","x":${atTheBound}}`, "unknown_format"],
      ['{"purpose":"other","x":abc}', "non_canonical"], // not JSON: a bare token
      ['{"purpose":"other","x":NaN}', "non_canonical"],
      ['{"purpose":"other","x":01}', "non_canonical"],
      ['{"purpose":"other","x":1.}', "non_canonical"],
      ['{"purpose":"other","x":-}', "non_canonical"],
      ['{"purpose":"other",}', "non_canonical"],
      ['{"purpose":"other"}x', "non_canonical"],
      ["{\"purpose\":\"other\",\"x\":'y'}", "non_canonical"],
      [`{"purpose":"other","x":${deep}}`, "non_canonical"], // deeper than this module reads
      ['{"purpose":1}', "non_canonical"],
      ['{"purpose":null}', "non_canonical"],
      ['{"v":2}', "non_canonical"],
      ['{"__proto__":{"purpose":"setup-offer"}}', "non_canonical"],
      ['[{"purpose":"setup-offer"}]', "non_canonical"],
      ['"setup-offer"', "non_canonical"],
      // A key twice at the top level is non_canonical whichever value comes last.
      ['{"purpose":"zzz","purpose":"setup-offer"}', "non_canonical"],
      ['{"purpose":"setup-offer","purpose":"zzz"}', "non_canonical"],
      ['{"purpose":"other","purpose":"other"}', "non_canonical"],
      ['{"purpose":"other","x":1,"x":2}', "non_canonical"],
      ['{"purpose":"other","\\u0078":1,"x":2}', "non_canonical"], // the same key, once escaped
      ['{"purpose":"other","x":{"a":1,"a":2}}', "unknown_format"], // only the top level is judged here
      ['{"purpose":"setup-off\\u0065r"}', "non_canonical"], // a host offer by its purpose, never canonical with an escape
      ['{"purpose":"setup-offer"}', "non_canonical"],
      ["", "non_canonical"],
    ];
    for (const [text, expected] of rows) expect(verdict(text), text).toBe(expected);
  });

  it("the nesting bound counts open containers, not brackets inside strings", () => {
    expect(withinJsonDepth("[".repeat(32) + "]".repeat(32))).toBe(true);
    expect(withinJsonDepth("[".repeat(33) + "]".repeat(33))).toBe(false);
    expect(withinJsonDepth(`"${"[".repeat(100)}"`)).toBe(true);
    expect(withinJsonDepth(`"\\"${"[".repeat(100)}"`)).toBe(true);
  });
});
