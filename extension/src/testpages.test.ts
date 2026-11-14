// node --test. The round-7 H1 and round-8 H test pages (extension/test-pages/) each put a payment provider's frame on
// the page with a skimmer's fields over or under it, hidden by a trick: an invisible overlay, blending, covers the hit
// test cannot see, a frame with no src (a form posted into it, or a script navigating it), a frame inside a closed
// shadow root or inside a srcdoc frame. The frames rule refuses them all by where the frames are, whatever their src;
// the provider list only names the provider in the explainer. One page is a first-party form beside frames that are
// not against it, which must fill. This pins that the pages say what they test, so a device check exercises the right
// thing.
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { paymentProviderCardFrame, paymentProviderHost } from "./paymentproviders.ts";

const page = (name: string): string => readFileSync(new URL(`../test-pages/${name}`, import.meta.url), "utf-8");
const frames = (html: string): string[] => [...html.matchAll(/<iframe[^>]*\ssrc="([^"]+)"/g)].map((m) => m[1]!);

test("the round-7 attack pages' frames are ones the explainer names", () => {
  for (const [name, host] of [
    ["card-overlay.html", "js.stripe.com"],
    ["card-blend.html", "assets.braintreegateway.com"],
    ["card-shadow-cover.html", "checkoutshopper-live.adyen.com"],
  ] as const) {
    const hosts = frames(page(name)).map(paymentProviderHost);
    assert.ok(hosts.includes(host), `${name}: ${host}`);
  }
});

test("each page carries the trick it is named for", () => {
  const overlay = page("card-overlay.html");
  assert.match(overlay, /color: transparent; caret-color: transparent; border: 0;\s*background: transparent linear-gradient\(transparent, transparent\);/);
  assert.match(page("card-blend.html"), /mix-blend-mode: lighten;/);
  // The first-party variant has no provider frame: its defence is the choice and the fill rules ("blended").
  const firstParty = page("card-blend-first-party.html");
  assert.deepEqual(frames(firstParty), []);
  assert.match(firstParty, /\.blended \{ mix-blend-mode: lighten;/);
  const shadow = page("card-shadow-cover.html");
  assert.match(shadow, /pointer-events: none; box-shadow: 0 0 0 400px #fff;/);
  assert.match(shadow, /\.veil::after \{ content: ""; position: absolute;/);
});

test("round-8 H: frames that name no provider in a src, and frames this script may not see inside", () => {
  const hosted = page("card-accept-hosted.html");
  assert.match(hosted, /<form id="token" method="post" action="https:\/\/test\.authorize\.net\/payment\/payment" target="hosted">/, "a form posted into the frame");
  assert.match(hosted, /<iframe name="hosted" title="payment form"><\/iframe>/, "which has no src");
  assert.deepEqual(frames(hosted), []);
  const replaced = page("card-location-replace.html");
  assert.match(replaced, /f\.contentWindow\.location\.replace\(f\.dataset\.to\)/);
  assert.deepEqual(frames(replaced), [], "no src attribute names the provider");
  const closed = page("card-closed-root.html");
  assert.match(closed, /this\.attachShadow\(\{ mode: "closed" \}\)/);
  assert.match(closed, /const frame = document\.createElement\("iframe"\);/);
  const nested = page("card-srcdoc-nested.html");
  assert.match(nested, /<iframe title="card number" srcdoc="[^"]*<iframe src='https:\/\/checkoutshopper-live\.adyen\.com\//, "a provider frame inside a srcdoc frame");
  assert.equal(paymentProviderHost("https://checkoutshopper-live.adyen.com/checkoutshopper/securedfields/test/card.html"), "checkoutshopper-live.adyen.com", "which the explainer can name");
  // Every attack page lays the skimmer's own fields over its frames, nothing of their own showing.
  for (const name of ["card-accept-hosted.html", "card-location-replace.html", "card-closed-root.html", "card-srcdoc-nested.html"]) {
    assert.match(page(name), /color: transparent; caret-color: transparent; border: 0; background: transparent;/, name);
  }
});

test("round-8 M: a first-party form beside a PayPal button and Stripe.js's hidden controller frame is filled", () => {
  const html = page("card-first-party-beside-frames.html");
  assert.match(html, /<iframe class="stripe-controller" name="__privateStripeController1"/);
  assert.match(html, /visibility: hidden !important;\s*position: fixed !important; height: 1px !important;/, "one pixel high, hidden, across the top");
  assert.match(html, /<div class="paypal"><iframe title="PayPal" src="https:\/\/www\.paypal\.com\/smart\/buttons/, "a PayPal button frame below the form");
  assert.ok(html.indexOf('<form id="checkout"') < html.indexOf('<div class="paypal">') && html.indexOf("</form>") < html.indexOf('<div class="paypal">'), "outside the form, after it");
  assert.ok(!html.includes("color: transparent"), "the page's own fields, shown");
});

test("the threat model's case c: a provider's hidden card-entry frame beside a first-party form stops the fill", () => {
  const html = page("card-hidden-provider-frame.html");
  const srcs = frames(html);
  assert.equal(srcs.length, 1);
  assert.equal(paymentProviderCardFrame(srcs[0]!), "js.stripe.com", "a card-entry frame by host and path");
  assert.match(html, /\.stash \{ position: absolute; left: -9999px; width: 0; height: 0; border: 0; \}/, "zero-size and off screen");
  assert.ok(!html.includes("color: transparent"), "the page's own form is shown: only case c stops it");
});

test("the threat model's case a: a card form in a frame that cannot be mapped (rotated) is not filled", () => {
  const html = page("card-rotated-frame.html");
  assert.match(html, /\.turn \{ transform: rotate\(180deg\); \}/);
  assert.match(html, /<div class="turn"><iframe title="checkout" src="card-first-party-beside-frames\.html"><\/iframe><\/div>/, "a same-origin frame, so the content script runs in it");
});

test("round-9 false positives: frames and marks the page shows beside or over a first-party form, which must fill", () => {
  const menu = page("card-pm-inline-menu.html");
  assert.deepEqual(frames(menu), ["chrome-extension://abcdefghijklmnopabcdefghijklmnop/menu.html"], "another password manager's own page");
  const fixed = page("card-fixed-widgets.html");
  assert.match(fixed, /\.badge \{ position: fixed;/);
  assert.match(fixed, /\.chat \{ position: fixed;/);
  for (const src of frames(fixed)) assert.equal(paymentProviderCardFrame(src), null, src);
  assert.match(fixed, /const gap = \(exp\.right \+ cvc\.left\) \/ 2;/, "between the two fields, over neither");
  const icons = page("card-narrow-cvc-icon.html");
  assert.match(icons, /\.field label \{ position: absolute; left: 6px; top: 2px; padding: 0 4px; font-size: 11px; background: #fff;/, "a floated label on an opaque chip");
  assert.match(icons, /\.narrow img, \.narrow svg \{ position: absolute; right: 4px; top: 6px; width: 30px; height: 30px; \}/, "a brand mark in the narrow field");
  assert.match(icons, /\.narrow \{ width: 96px; \}/);
  const beside = page("card-first-party-beside-frames.html");
  for (const src of frames(beside)) assert.equal(paymentProviderCardFrame(src), null, `${src}: a button or controller frame is not card entry`);
});
