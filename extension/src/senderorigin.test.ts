// node --test. Security review 2026-10 (root cause E): capture and match decisions bind to the
// BROWSER-SET `sender.origin`, never to a host or URL the page's content script reports.
//
// `capturedCredential` derived its host from the `location.href` the content script sent, so an
// opaque-origin (sandboxed) frame whose URL sits on the target site was credited as that site and
// could mint a pending UPDATE of the user's login there. `matches` and `pageInfo` likewise took the
// frame's own word for which host to match. The leaf below is the one spelling of "who is asking";
// the wiring pins at the bottom hold background.ts to it (it is not node-importable).
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { captureBinding, originHost, requestHost } from "./senderorigin.ts";

test("a capture is bound to sender.origin — a spoofed page URL cannot name the site", () => {
  // The frame is really evil.example; its content script would have reported https://bank.example/login.
  const spoofedPageUrl = "https://bank.example/login";
  const bound = captureBinding("https://evil.example");
  assert.deepEqual(bound, { host: "evil.example", uri: "https://evil.example" });
  assert.notEqual(bound?.host, originHost(spoofedPageUrl));
});

test("an opaque, empty or missing origin binds nothing (fail closed)", () => {
  for (const o of ["null", "", undefined, 42, "not a url"]) assert.equal(captureBinding(o), null, String(o));
  for (const o of ["null", "", undefined]) assert.equal(originHost(o), null, String(o));
});

test("the stored uri keeps the origin's own scheme and port (H124), from the browser, not the page", () => {
  assert.deepEqual(captureBinding("http://localhost:8080"), { host: "localhost", uri: "http://localhost:8080" });
  assert.deepEqual(captureBinding("https://www.Example.com"), { host: "example.com", uri: "https://example.com" });
});

test("a tab sender's match host is its origin's; only the popup (no tab) names a host itself", () => {
  assert.equal(requestHost(true, "https://evil.example", "bank.example"), "evil.example");
  assert.equal(requestHost(true, "null", "bank.example"), null);
  assert.equal(requestHost(false, undefined, "bank.example"), "bank.example");
});

// ---- wiring: every capture / match decision in the SW goes through the leaf ----

const bg = readFileSync(new URL("./background.ts", import.meta.url), "utf-8");
const ct = readFileSync(new URL("./content.ts", import.meta.url), "utf-8");
const msgs = readFileSync(new URL("./messages.ts", import.meta.url), "utf-8");

function spanOf(src: string, from: string, to: string): string {
  const a = src.indexOf(from);
  assert.ok(a > -1, `span start missing: ${from}`);
  const b = src.indexOf(to, a);
  assert.ok(b > a, `span end missing or out of order: ${to}`);
  return src.slice(a, b);
}

test("capturedCredential takes its host and uri from sender.origin, and the page sends no URL", () => {
  const cap = spanOf(bg, "async function capturedCredential(", "async function resolvePendingSave(");
  assert.ok(cap.includes("captureBinding(sender.origin)"), "the capture is bound by the browser-set origin");
  assert.ok(!cap.includes("msg.url"), "no page-supplied URL may reach the capture");
  assert.match(msgs, /\{ type: "capturedCredential"; username: string; password: string \}/, "the message carries no url");
  assert.ok(!/type: "capturedCredential", url:/.test(ct), "content sends no location.href");
});

test("matches and pageInfo match the sender's origin host, not the frame's claim", () => {
  const m = spanOf(bg, 'case "matches": {', 'case "allItems": {');
  assert.ok(m.includes("requestHost(sender.tab !== undefined, sender.origin, msg.host)"), "matches binds to sender.origin");
  const p = spanOf(bg, 'case "pageInfo": {', "const tabId = sender.tab?.id;");
  assert.ok(p.includes("requestHost(sender.tab !== undefined, sender.origin, msg.host)"), "pageInfo binds to sender.origin");
  assert.ok(!/matchesFor\(msg\.host\)/.test(bg), "no handler matches on a page-supplied host");
});
