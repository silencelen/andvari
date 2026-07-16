// Trust-gate copy + render-rule tests (node --test). Security-critical: this PINS the anti-phishing
// copy (design §4.3) so a wording drift breaks the build, and proves the IDN/plain-http cautions fire
// exactly when they should and never otherwise.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import {
  hasPunycodeLabel,
  isPlainHttp,
  TRUST_GATE_BODY,
  TRUST_GATE_HEADING,
  TRUST_GATE_HTTP_CAUTION,
  TRUST_GATE_PUNYCODE_CAUTION,
  trustGateView,
} from "./trustgate.ts";

test("copy is pinned verbatim to design §4.3 baseline", () => {
  assert.equal(TRUST_GATE_HEADING, "Connect to a different server?");
  assert.equal(
    TRUST_GATE_BODY,
    "This server will store your encrypted vault and see your account activity (email, sign-ins, item counts). Only continue if you trust it.",
  );
  assert.equal(
    TRUST_GATE_PUNYCODE_CAUTION,
    "This address uses international characters, shown here in their punycode (xn--) form. Make sure it is exactly the server you intend.",
  );
  assert.equal(TRUST_GATE_HTTP_CAUTION, "This is a plain http:// address — traffic to it is not encrypted in transit.");
});

test("hasPunycodeLabel — true only for a host carrying an xn-- label", () => {
  assert.equal(hasPunycodeLabel("https://xn--e1afmkfd.xn--p1ai"), true); // пример.рф canonicalized
  assert.equal(hasPunycodeLabel("https://xn--80ak6aa92e.com"), true); // apple homograph
  assert.equal(hasPunycodeLabel("https://example.org"), false);
  assert.equal(hasPunycodeLabel("https://self.example:8443"), false);
  assert.equal(hasPunycodeLabel("http://192.168.2.122:8080"), false);
});

test("isPlainHttp — true only for an http:// origin", () => {
  assert.equal(isPlainHttp("http://localhost:8443"), true);
  assert.equal(isPlainHttp("http://192.168.2.122:8080"), true);
  assert.equal(isPlainHttp("https://example.org"), false);
});

test("trustGateView — plain https origin: raw origin shown, no cautions", () => {
  const v = trustGateView("https://andvari.example.com");
  assert.equal(v.origin, "https://andvari.example.com"); // the RAW origin — never a display name
  assert.equal(v.heading, TRUST_GATE_HEADING);
  assert.equal(v.body, TRUST_GATE_BODY);
  assert.equal(v.punycodeCaution, null);
  assert.equal(v.httpCaution, null);
});

test("trustGateView — IDN origin raises the punycode caution", () => {
  const v = trustGateView("https://xn--e1afmkfd.xn--p1ai");
  assert.equal(v.origin, "https://xn--e1afmkfd.xn--p1ai");
  assert.equal(v.punycodeCaution, TRUST_GATE_PUNYCODE_CAUTION);
  assert.equal(v.httpCaution, null);
});

test("trustGateView — plain-http origin raises the http caution", () => {
  const v = trustGateView("http://192.168.2.122:8080");
  assert.equal(v.httpCaution, TRUST_GATE_HTTP_CAUTION);
  assert.equal(v.punycodeCaution, null);
});

test("trustGateView — an IDN over http raises BOTH cautions", () => {
  const v = trustGateView("http://xn--e1afmkfd.xn--p1ai");
  assert.equal(v.punycodeCaution, TRUST_GATE_PUNYCODE_CAUTION);
  assert.equal(v.httpCaution, TRUST_GATE_HTTP_CAUTION);
});
