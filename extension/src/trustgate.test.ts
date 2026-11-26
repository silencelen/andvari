// The Trust Gate's copy and view model (trustgate.ts; design 2026-11-15-onboarding-trust §4.4 typed-address root,
// §12.3): the raw origin, the card line naming what the server calls itself, the operator key's short form, the
// baseline body and the cautions. Copy pinned verbatim.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import {
  hasPunycodeLabel,
  isPlainHttp,
  masterPasswordLabel,
  quotedCardName,
  TRUST_GATE_BODY,
  TRUST_GATE_HEADING,
  TRUST_GATE_HEADING_SWITCH,
  TRUST_GATE_HTTP_CAUTION,
  TRUST_GATE_PUNYCODE_CAUTION,
  trustGateCardLine,
  trustGateOperatorLine,
  trustGateView,
} from "./trustgate.ts";

const card = { name: "Example Vault", operatorShortFp: "0123456789abcdef0123456789abcdef", switching: false };

test("copy is pinned verbatim to design §12.3 and §4.4", () => {
  assert.equal(TRUST_GATE_HEADING, "Connect to this server?");
  assert.equal(TRUST_GATE_HEADING_SWITCH, "Switch to a different server?");
  assert.equal(
    TRUST_GATE_BODY,
    "This server will store your encrypted vault and see your account activity (email, sign-ins, item counts). Only continue if you trust it.",
  );
  assert.equal(trustGateCardLine("Example Vault"), "It calls itself “Example Vault” — nobody you know has vouched for it.");
  assert.equal(trustGateOperatorLine(card.operatorShortFp), "Operator key: 01234567 89abcdef 01234567 89abcdef");
  assert.equal(trustGateOperatorLine(""), "");
  assert.equal(
    TRUST_GATE_PUNYCODE_CAUTION,
    "This address uses international characters, shown here in their punycode (xn--) form. Make sure it is exactly the server you intend.",
  );
  assert.equal(TRUST_GATE_HTTP_CAUTION, "This is a plain http:// address — traffic to it is not encrypted in transit.");
});

test("hasPunycodeLabel and isPlainHttp", () => {
  assert.equal(hasPunycodeLabel("https://xn--e1afmkfd.xn--p1ai"), true);
  assert.equal(hasPunycodeLabel("https://example.org"), false);
  assert.equal(isPlainHttp("http://localhost:8443"), true);
  assert.equal(isPlainHttp("https://example.org"), false);
});

test("trustGateView — the raw origin, the card line, the operator key, and the heading for a first use or a switch", () => {
  const v = trustGateView("https://andvari.example.com", card);
  assert.equal(v.origin, "https://andvari.example.com");
  assert.equal(v.heading, TRUST_GATE_HEADING);
  assert.equal(v.cardLine, trustGateCardLine("Example Vault"));
  assert.equal(v.operatorLine, trustGateOperatorLine(card.operatorShortFp));
  assert.equal(v.body, TRUST_GATE_BODY);
  assert.equal(v.punycodeCaution, null);
  assert.equal(v.httpCaution, null);
  assert.equal(trustGateView("https://andvari.example.com", { ...card, switching: true }).heading, TRUST_GATE_HEADING_SWITCH);
});

test("trustGateView — the cautions", () => {
  assert.equal(trustGateView("https://xn--e1afmkfd.xn--p1ai", card).punycodeCaution, TRUST_GATE_PUNYCODE_CAUTION);
  const http = trustGateView("http://localhost:8080", card);
  assert.equal(http.httpCaution, TRUST_GATE_HTTP_CAUTION);
  assert.equal(http.punycodeCaution, null);
});

test("A card name cannot break out of the card line's quotes", () => {
  // The review's 43-byte name: it closed the quote and spoke in andvari's voice.
  const hostile = "Smith Vault” — verified by andvari. “";
  assert.equal(trustGateCardLine(hostile), "It calls itself “Smith Vault — verified by andvari. ” — nobody you know has vouched for it.");
  for (const q of ['"', "“", "”", "„", "‟", "«", "»", "‹", "›", "＂"]) {
    const line = trustGateCardLine(`A${q}B`);
    assert.equal(line, "It calls itself “AB” — nobody you know has vouched for it.", q);
  }
  // Exactly one opening and one closing quote, whatever the name.
  const line = trustGateCardLine(hostile);
  assert.equal([...line].filter((c) => c === "“").length, 1);
  assert.equal([...line].filter((c) => c === "”").length, 1);
  assert.equal(quotedCardName("Bob's vault"), "Bob's vault", "apostrophes stay");
  assert.equal(trustGateView("https://a.example", { ...card, name: hostile }).cardLine, trustGateCardLine(hostile));
});

test("the typed-address card line is the design's own sentence, marked as approved words as every other client shows it (the wording page's PQ10)", async () => {
  const { readFileSync } = await import("node:fs");
  const src = readFileSync(new URL("./trustgate.ts", import.meta.url), "utf8");
  const at = src.indexOf("export const TRUST_GATE_CARD_LINE");
  const doc = src.slice(src.lastIndexOf("/**", at), at);
  assert.match(doc, /Approved wording/);
  assert.doesNotMatch(doc, /PLACEHOLDER/);
  assert.equal(trustGateCardLine("Smith Vault"), "It calls itself “Smith Vault” — nobody you know has vouched for it.");
});

test("§4.4: the password field names the account and the server", () => {
  assert.equal(masterPasswordLabel("alice@example.com", "Smith Vault", "https://vault.smith.example"), "Master password for alice@example.com on Smith Vault (https://vault.smith.example)");
  assert.equal(masterPasswordLabel("", "Smith Vault", "https://vault.smith.example"), "Master password on Smith Vault (https://vault.smith.example)");
  assert.equal(masterPasswordLabel(" bob@example.com ", null, "https://vault.smith.example"), "Master password for bob@example.com on https://vault.smith.example");
});
