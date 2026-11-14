// node --test. The card-entry origins andvari fills a card into (owner decision 2026-11-14, round-11 review): exact https
// origins, each with its source, no wildcards; nothing that only serves buttons, controllers, fraud checks or 3-D
// Secure, nothing that is also a whole web app or takes a site owner's scripts, no vault whose owner decides where the
// raw card goes; and the UI-test origin only in the UI-test build.
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { CARD_PROVIDER_ORIGINS, cardProviderOf, isCardProviderOrigin } from "./cardproviders.ts";

test("every entry is an https origin with a source, listed once", () => {
  const seen = new Set<string>();
  for (const p of CARD_PROVIDER_ORIGINS) {
    assert.match(p.origin, /^https:\/\/[a-z0-9-]+(\.[a-z0-9-]+)+$/, p.origin);
    assert.match(p.source, /^https:\/\//, `${p.origin}: a source`);
    assert.ok(p.provider.length > 0);
    assert.ok(!seen.has(p.origin), `${p.origin} listed twice`);
    seen.add(p.origin);
  }
  for (const name of ["Stripe", "Braintree", "Adyen", "Checkout.com", "Square", "Worldpay", "Cybersource", "Authorize.net", "Recurly"]) {
    assert.ok(CARD_PROVIDER_ORIGINS.some((p) => p.provider === name), `${name} is listed`);
  }
  // Round-11 review: a host that is also a whole web app (PayPal, NMI's merchant portal), pages a site owner can add
  // scripts to (Chargebee's hosted pages), a vault whose owner decides where the raw card goes (VGS, Spreedly), and a
  // host no provider page documents (Shopify) are not card-entry origins here.
  for (const name of ["PayPal", "NMI", "Chargebee", "VGS", "Spreedly", "Shopify"]) {
    assert.ok(!CARD_PROVIDER_ORIGINS.some((p) => p.provider === name), `${name} is not listed`);
  }
});

test("the owner's named origins are card-entry origins, exactly", () => {
  for (const o of ["https://js.stripe.com", "https://checkout.stripe.com", "https://assets.braintreegateway.com", "https://checkoutshopper-live.adyen.com", "https://js.checkout.com", "https://web.squarecdn.com", "https://flex.cybersource.com", "https://accept.authorize.net", "https://api.recurly.com"]) {
    assert.ok(isCardProviderOrigin(o), o);
  }
  for (const o of ["https://www.paypal.com", "https://secure.nmi.com", "https://js.verygoodvault.com", "https://core.spreedly.com", "https://js.chargebee.com", "https://acme.chargebee.com", "https://checkout.pci.shopifyinc.com"]) {
    assert.ok(!isCardProviderOrigin(o), o);
  }
  assert.equal(cardProviderOf("https://js.stripe.com/v3/elements-inner-card-0123.html")?.provider, "Stripe", "a URL is read for its origin");
  assert.equal(cardProviderOf("https://JS.Stripe.com")?.provider, "Stripe", "the host's case is the browser's");
});

test("nothing else is: another host of the provider, a parent domain, plain http, another port, an opaque origin", () => {
  for (const o of [
    "https://stripe.com",
    "https://m.stripe.network",
    "https://hooks.stripe.com",
    "https://evil.js.stripe.com",
    "https://js.stripe.com.evil.example",
    "http://js.stripe.com",
    "https://js.stripe.com:8443",
    "https://braintreegateway.com",
    "https://adyen.com",
    "https://paypal.com",
    "https://pay.google.com",
    "https://shop.example",
    "null",
    "",
    "not a url",
  ]) {
    assert.ok(!isCardProviderOrigin(o), o);
  }
  assert.ok(!isCardProviderOrigin(null));
  assert.ok(!isCardProviderOrigin(undefined));
});

test("no wildcards: every entry is one host, matched exactly", () => {
  assert.ok(CARD_PROVIDER_ORIGINS.every((p) => !p.origin.includes("*")));
  assert.ok(!isCardProviderOrigin("https://a.js.stripe.com"));
  assert.ok(!isCardProviderOrigin("https://js.stripe.com:444"));
});

test("the UI-test provider is only in the UI-test build", () => {
  assert.ok(!isCardProviderOrigin("https://pay.andvari-uitest.test:8443"), "not in the unbundled source");
  const source = readFileSync(new URL("./cardproviders.ts", import.meta.url), "utf-8");
  assert.ok(!source.includes("andvari-uitest.test"), "the source names no test origin: build.mjs defines it for the UI-test variant only");
  const build = readFileSync(new URL("../build.mjs", import.meta.url), "utf-8");
  assert.match(build, /__ANDVARI_UITEST_PROVIDER__/);
  assert.match(build, /https:\/\/pay\.andvari-uitest\.test:8443/);
});
