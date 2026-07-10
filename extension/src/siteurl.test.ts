// node --test (see version.test.ts). Pins the exec-vector guard: a saved uri may be hostile,
// and the popup detail view turns uris into clickable links — only http/https may become one.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { displaySite, safeSiteUrl } from "./siteurl.ts";

test("plain and scheme-bearing http(s) uris become absolute https/http URLs", () => {
  assert.equal(safeSiteUrl("example.com"), "https://example.com/");
  assert.equal(safeSiteUrl("example.com/login"), "https://example.com/login");
  assert.equal(safeSiteUrl("https://x.example.com/a?b=1"), "https://x.example.com/a?b=1");
  assert.equal(safeSiteUrl("http://10.0.0.1:8080/panel"), "http://10.0.0.1:8080/panel");
  assert.equal(safeSiteUrl("  Example.COM  "), "https://example.com/"); // trim + host lowercased by URL
});

test("non-http(s) schemes NEVER become a link (exec/exfil guard)", () => {
  assert.equal(safeSiteUrl("javascript:alert(1)"), null); // no // → https-prefixed → unparseable host
  assert.equal(safeSiteUrl("javascript://%0aalert(1)"), null); // real scheme, rejected by protocol
  assert.equal(safeSiteUrl("data:text/html,<script>x</script>"), null);
  assert.equal(safeSiteUrl("file:///etc/passwd"), null);
  assert.equal(safeSiteUrl("chrome://settings"), null);
  assert.equal(safeSiteUrl("vbscript:msgbox(1)"), null);
  assert.equal(safeSiteUrl(""), null);
  assert.equal(safeSiteUrl("   "), null);
  assert.equal(safeSiteUrl("//evil.example"), null); // protocol-relative → empty host → null
});

test("displaySite is host-first, drops the query, truncates, and never throws on junk", () => {
  assert.equal(displaySite("https://example.com/login?token=secret"), "example.com/login");
  assert.equal(displaySite("example.com"), "example.com");
  assert.equal(displaySite("javascript:alert(1)"), "javascript:alert(1)"); // inert text, not a link
  const long = "https://example.com/" + "a".repeat(80);
  assert.ok(displaySite(long).length <= 44);
  assert.ok(displaySite(long).endsWith("…"));
});
