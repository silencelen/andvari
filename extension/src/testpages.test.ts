// node --test. The card test pages (extension/test-pages/) come from review rounds 5 to 10: a skimmer's fields over,
// under or beside a payment provider's frame, hidden by a trick (an invisible overlay, blending, covers the hit test
// cannot see, a frame with no src that a form posts into or a script navigates, a frame in a closed shadow root or in a
// srcdoc frame), and first-party forms beside frames and marks. Since the owner's decision of 2026-11-14 they all come
// to one answer, for one reason: their fields are the page's own, in documents of the page's origin (or of no origin:
// srcdoc, about:blank), and a card goes only into a payment provider's card document (cardrelease.ts). This pins that
// each page says so, carries the trick it was built for, and that no page's own document is a provider's.
import { strict as assert } from "node:assert";
import { readdirSync, readFileSync } from "node:fs";
import { test } from "node:test";
import { cardProviderOf, isCardProviderOrigin } from "./cardproviders.ts";
import { frameOriginOf } from "./cardrelease.ts";

const dir = new URL("../test-pages/", import.meta.url);
const page = (name: string): string => readFileSync(new URL(name, dir), "utf-8");
const frames = (html: string): string[] => [...html.matchAll(/<iframe[^>]*\ssrc="([^"]+)"/g)].map((m) => m[1]!);
const PAGES = readdirSync(dir).filter((n) => n.startsWith("card-") && n.endsWith(".html")).sort();

test("every card test page says nothing is filled into it, and why", () => {
  assert.ok(PAGES.length >= 18, `${PAGES.length} pages`);
  for (const name of PAGES) {
    assert.match(page(name), /<p class="rule"><strong>Card fill since 2026-11-14:<\/strong> nothing is filled into this page\./, name);
    // Card fields of its own, or in a same-origin frame of another test page (the rotated one frames a first-party form).
    const own = /autocomplete="cc-|name="card|name="cvc|name="cc/.test(page(name)) || frames(page(name)).some((src) => PAGES.includes(src));
    assert.ok(own, `${name}: the page has card fields of its own`);
  }
});

test("the pages' own documents are never a provider's: wherever they are served, and their srcdoc and blank frames", () => {
  for (const served of ["https://site.andvari-uitest.test:8443", "http://localhost:8000", "http://127.0.0.1:8080", "file:///tmp/test-pages"]) {
    assert.ok(!isCardProviderOrigin(frameOriginOf({ url: `${served}/card-overlay.html` })), served);
  }
  for (const url of ["about:srcdoc", "about:blank", "javascript:void(0)", "data:text/html,<input>"]) assert.equal(frameOriginOf({ url }), null, url);
  assert.equal(frameOriginOf({ origin: "null", url: "https://js.stripe.com/x" }), null, "a sandboxed frame has no origin, whatever its URL");
});

test("the provider frames the attack pages show are providers' (by their src), and hold none of the page's fields", () => {
  for (const [name, provider] of [
    ["card-overlay.html", "Stripe"],
    ["card-blend.html", "Braintree"],
    ["card-shadow-cover.html", "Adyen"],
    ["card-hidden-provider-frame.html", "Stripe"],
  ] as const) {
    const srcs = frames(page(name));
    assert.ok(srcs.some((src) => cardProviderOf(src)?.provider === provider), `${name}: ${provider}`);
  }
  // The skimmer's inputs sit in the page's own document, beside or over those frames: a press on them is a press in
  // the page, which never chooses a card field.
  assert.match(page("card-overlay.html"), /<iframe title="card number" src="https:\/\/js\.stripe\.com\/[^"]*"><\/iframe><input name="cardnumber" autocomplete="cc-number"/);
});

test("each page carries the trick it is named for", () => {
  const overlay = page("card-overlay.html");
  assert.match(overlay, /color: transparent; caret-color: transparent; border: 0;\s*background: transparent linear-gradient\(transparent, transparent\);/);
  assert.match(page("card-blend.html"), /mix-blend-mode: lighten;/);
  const firstParty = page("card-blend-first-party.html");
  assert.deepEqual(frames(firstParty), []);
  assert.match(firstParty, /\.blended \{ mix-blend-mode: lighten;/);
  const shadow = page("card-shadow-cover.html");
  assert.match(shadow, /pointer-events: none; box-shadow: 0 0 0 400px #fff;/);
  assert.match(shadow, /\.veil::after \{ content: ""; position: absolute;/);
  const hosted = page("card-accept-hosted.html");
  assert.match(hosted, /<form id="token" method="post" action="https:\/\/test\.authorize\.net\/payment\/payment" target="hosted">/, "a form posted into the frame");
  assert.match(hosted, /<iframe name="hosted" title="payment form"><\/iframe>/, "which has no src");
  assert.match(page("card-location-replace.html"), /f\.contentWindow\.location\.replace\(f\.dataset\.to\)/);
  assert.match(page("card-closed-root.html"), /this\.attachShadow\(\{ mode: "closed" \}\)/);
  assert.match(page("card-srcdoc-nested.html"), /<iframe title="card number" srcdoc="[^"]*<iframe src='https:\/\/checkoutshopper-live\.adyen\.com\//, "a provider frame inside a srcdoc frame");
  assert.match(page("card-rotated-frame.html"), /\.turn \{ transform: rotate\(180deg\); \}/);
  assert.match(page("card-hidden-provider-frame.html"), /\.stash \{ position: absolute; left: -9999px; width: 0; height: 0; border: 0; \}/);
  assert.match(page("card-first-party-beside-frames.html"), /<iframe class="stripe-controller" name="__privateStripeController1"/);
  assert.deepEqual(frames(page("card-pm-inline-menu.html")), ["chrome-extension://abcdefghijklmnopabcdefghijklmnop/menu.html"], "another password manager's own page");
  assert.match(page("card-fixed-widgets.html"), /\.chat \{ position: fixed;/);
  assert.match(page("card-narrow-cvc-icon.html"), /\.narrow \{ width: 96px; \}/);
});
