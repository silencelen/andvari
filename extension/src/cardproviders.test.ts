// node --test. The card-entry origins andvari fills a card into (owner decision 2026-11-14): exact https origins, each
// with its source; a wildcard only where the provider documents one, matching one label; nothing that only serves
// buttons, controllers, fraud checks or 3-D Secure; and the UI-test origin only in the UI-test build.
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { CARD_PROVIDER_ORIGINS, cardProviderOf, isCardProviderOrigin } from "./cardproviders.ts";

test("every entry is an https origin with a source, listed once", () => {
  const seen = new Set<string>();
  for (const p of CARD_PROVIDER_ORIGINS) {
    assert.match(p.origin, /^https:\/\/(\*\.)?[a-z0-9-]+(\.[a-z0-9-]+)+$/, p.origin);
    assert.match(p.source, /^https:\/\//, `${p.origin}: a source`);
    assert.ok(p.provider.length > 0);
    assert.ok(!seen.has(p.origin), `${p.origin} listed twice`);
    seen.add(p.origin);
  }
  for (const name of ["Stripe", "Braintree", "Adyen", "Checkout.com", "Square", "PayPal", "Worldpay", "Cybersource", "NMI", "VGS", "Spreedly", "Authorize.net", "Recurly", "Chargebee", "Shopify"]) {
    assert.ok(CARD_PROVIDER_ORIGINS.some((p) => p.provider === name), `${name} is listed`);
  }
});

test("the owner's named origins are card-entry origins, exactly", () => {
  for (const o of ["https://js.stripe.com", "https://checkout.stripe.com", "https://assets.braintreegateway.com", "https://checkoutshopper-live.adyen.com", "https://js.checkout.com", "https://web.squarecdn.com", "https://www.paypal.com", "https://flex.cybersource.com", "https://secure.nmi.com", "https://js.verygoodvault.com", "https://core.spreedly.com", "https://accept.authorize.net", "https://api.recurly.com", "https://js.chargebee.com", "https://checkout.pci.shopifyinc.com"]) {
    assert.ok(isCardProviderOrigin(o), o);
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

test("a documented wildcard matches one label under its domain, on the default port only", () => {
  assert.ok(CARD_PROVIDER_ORIGINS.filter((p) => p.origin.includes("*")).every((p) => p.provider === "Chargebee"), "Chargebee's hosted pages only");
  assert.ok(isCardProviderOrigin("https://acme.chargebee.com"));
  assert.ok(isCardProviderOrigin("https://acme-test.chargebee.com"));
  assert.ok(!isCardProviderOrigin("https://a.b.chargebee.com"), "one label");
  assert.ok(!isCardProviderOrigin("https://chargebee.com"));
  assert.ok(!isCardProviderOrigin("https://acme.chargebee.com:444"));
  assert.ok(!isCardProviderOrigin("https://acme.chargebee.com.evil.example"));
});

test("the UI-test provider is only in the UI-test build", () => {
  assert.ok(!isCardProviderOrigin("https://pay.andvari-uitest.test:8443"), "not in the unbundled source");
  const source = readFileSync(new URL("./cardproviders.ts", import.meta.url), "utf-8");
  assert.ok(!source.includes("andvari-uitest.test"), "the source names no test origin: build.mjs defines it for the UI-test variant only");
  const build = readFileSync(new URL("../build.mjs", import.meta.url), "utf-8");
  assert.match(build, /__ANDVARI_UITEST_PROVIDER__/);
  assert.match(build, /https:\/\/pay\.andvari-uitest\.test:8443/);
});
