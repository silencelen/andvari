// node --test. The card-entry origins andvari fills a card into (owner decision 2026-11-14, round-11 review): exact https
// origins, each with its source, no wildcards; nothing that only serves buttons, controllers, fraud checks or 3-D
// Secure, nothing that is also a whole web app or takes a site owner's scripts, no vault whose owner decides where the
// raw card goes; and the UI-test origin only in the UI-test build.
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { CARD_PROVIDER_ORIGINS, CARD_PROVIDER_TEST_ORIGINS, cardProviderOf, isCardEntryDocument, isCardProviderOrigin } from "./cardproviders.ts";

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

test("a release build lists no provider's sandbox or test host (round-12 review); the debug and UI-test builds do", () => {
  const test = ["https://sandbox.web.squarecdn.com", "https://checkout-web-components.sandbox.checkout.com", "https://jstest.authorize.net", "https://test.authorize.net", "https://testflex.cybersource.com", "https://request.eprotect.vantivprelive.com", "https://request.eprotect.vantivpostlive.com", "https://checkoutshopper-test.adyen.com", "https://try.access.worldpay.com"];
  for (const o of test) {
    assert.ok(CARD_PROVIDER_TEST_ORIGINS.some((p) => p.origin === o), `${o} is a test host`);
    assert.ok(!CARD_PROVIDER_ORIGINS.some((p) => p.origin === o), `${o} is not a production host`);
    assert.ok(!isCardProviderOrigin(o), `${o}: not without the build's define (as in a release build)`);
  }
  const build = readFileSync(new URL("../build.mjs", import.meta.url), "utf-8");
  assert.match(build, /__ANDVARI_PROVIDER_TEST_HOSTS__: JSON\.stringify\(!release \|\| uitest\)/);
  assert.match(build, /a release build must not list a payment provider's test host/);
});

test("where a provider serves several kinds of element, only its card-entry documents are card frames (round-12 review)", () => {
  const stripe = "https://js.stripe.com";
  assert.ok(isCardEntryDocument(stripe, "/v3/elements-inner-card-6f1c2a9b0e.html"), "the Card Element family");
  assert.ok(isCardEntryDocument(stripe, "/v3/elements-inner-payment-0b4f.html"), "the Payment Element");
  for (const path of ["/v3/elements-inner-address-6f1c2a9b0e.html", "/v3/elements-inner-link-authentication-1a.html", "/v3/elements-inner-express-checkout-2b.html", "/v3/controller-3c.html", "/v3/elements-inner-autocomplete-4d.html", "/v3/elements-inner-card.html", "/v3/elements-inner-card-6f1c.html/x"]) {
    assert.ok(!isCardEntryDocument(stripe, path), path);
  }
  // A provider with one kind of element: every document of the origin.
  assert.ok(isCardEntryDocument("https://assets.braintreegateway.com", "/web/3.111.0/html/hosted-fields-frame.min.html"));
  assert.ok(isCardEntryDocument("https://checkout.stripe.com", "/c/pay/cs_live_x"));
  assert.ok(!isCardEntryDocument("https://shop.example", "/v3/elements-inner-card-6f1c.html"), "never another origin");
});
