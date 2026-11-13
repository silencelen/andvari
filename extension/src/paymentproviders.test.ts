// node --test. Round-7 review H1, the structural defence: a payment provider's frame on a page means the card fields
// are the provider's, and andvari fills no card into the page's own documents.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { PAYMENT_PROVIDER_FRAMES, paymentProviderHost } from "./paymentproviders.ts";

test("a provider's frame is recognised by the host it is served from, a subdomain included", () => {
  assert.equal(paymentProviderHost("https://js.stripe.com/v3/elements-inner-card-1234.html#x"), "js.stripe.com");
  assert.equal(paymentProviderHost("https://assets.braintreegateway.com/web/3.97.0/html/hosted-fields-frame.min.html"), "assets.braintreegateway.com");
  assert.equal(paymentProviderHost("https://checkoutshopper-live-us.adyen.com/checkoutshopper/securedfields/x"), "checkoutshopper-live-us.adyen.com");
  assert.equal(paymentProviderHost("https://checkout.shopifycs.com/number?identifier=1"), "checkout.shopifycs.com");
  assert.equal(paymentProviderHost("https://checkout.pci.shopifyinc.com/build/abc/number-ltr.html"), "checkout.pci.shopifyinc.com");
  assert.equal(paymentProviderHost("https://web.squarecdn.com/1.0/card.html"), "web.squarecdn.com");
  assert.equal(paymentProviderHost("https://access.worldpay.com/access-checkout/v2.5.0/?x"), "access.worldpay.com");
  assert.equal(paymentProviderHost("https://api.eu.recurly.com/js/v1/field.html#config=x"), "api.eu.recurly.com");
  assert.equal(paymentProviderHost("https://JS.Stripe.com/v3/"), "js.stripe.com", "hosts are case-insensitive");
});

test("anything else is not a provider's frame: another host that only looks like one, plain http, a relative src", () => {
  assert.equal(paymentProviderHost("https://js.stripe.com.evil.example/x"), null);
  assert.equal(paymentProviderHost("https://evilstripe.com/x"), null);
  assert.equal(paymentProviderHost("https://stripe.com/"), null, "only the frames' host, not the marketing site");
  assert.equal(paymentProviderHost("http://js.stripe.com/v3/"), null);
  assert.equal(paymentProviderHost("/v3/elements"), null);
  assert.equal(paymentProviderHost("about:blank"), null);
  assert.equal(paymentProviderHost(""), null);
});

test("every listed host is a bare hostname with a documented source", () => {
  assert.ok(PAYMENT_PROVIDER_FRAMES.length >= 14);
  assert.ok(!PAYMENT_PROVIDER_FRAMES.some((p) => p.host === "shopifyinc.com" || p.host === "stripe.com"), "not a provider's whole domain where only its frames' host is documented");
  for (const p of PAYMENT_PROVIDER_FRAMES) {
    assert.match(p.host, /^[a-z0-9-]+(\.[a-z0-9-]+)+$/, p.host);
    assert.match(p.source, /^https:\/\//, `${p.provider}: a source`);
    assert.ok(p.provider.length > 0);
  }
  for (const name of ["Stripe", "Braintree", "PayPal", "Adyen", "Checkout.com", "Square", "Worldpay", "Authorize.net", "Recurly", "Chargebee", "Shopify"]) {
    assert.ok(PAYMENT_PROVIDER_FRAMES.some((p) => p.provider === name), name);
  }
});
