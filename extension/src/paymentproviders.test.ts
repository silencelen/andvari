// node --test. The card-fill threat model's case c: a payment provider's card-entry frame on a page means the card is
// the provider's to take, and andvari fills no card into the page's own documents there. The provider's other frames
// (buttons, wallets, controller, fraud, 3-D Secure) beside a first-party form must not stop a fill.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { CARD_ENTRY_FRAMES, PAYMENT_PROVIDER_FRAMES, paymentProviderCardFrame, paymentProviderHost } from "./paymentproviders.ts";

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

const H32 = "0123456789abcdef0123456789abcdef";
const H40 = "0123456789abcdef0123456789abcdef01234567";

test("card-entry frames are recognised by host, whole path and, where the path is shared, the field they hold", () => {
  const card = [
    [`https://js.stripe.com/v3/elements-inner-card-${H32}.html#componentName=cardNumber`, "js.stripe.com"],
    [`https://js.stripe.com/v3/elements-inner-card-${H40}.html`, "js.stripe.com"],
    [`https://js.stripe.com/v3/elements-inner-payment-${H32}.html`, "js.stripe.com"],
    [`https://js.stripe.com/v3/elements-inner-payment-af-control-${H32}.html`, "js.stripe.com"],
    [`https://js.stripe.com/v3/embedded-checkout-inner-${H32}.html`, "js.stripe.com"],
    [`https://js.stripe.com/v3/card-details-recollection-modal-${H32}.html`, "js.stripe.com"],
    ["https://assets.braintreegateway.com/web/3.148.0/html/hosted-fields-frame.min.html#abc", "assets.braintreegateway.com"],
    ["https://checkoutshopper-live-us.adyen.com/checkoutshopper/securedfields/live_KEY/5.1.0/securedFields.html?type=card&d=aHR0cHM6", "checkoutshopper-live-us.adyen.com"],
    ["https://checkoutshopper-test.adyen.com/checkoutshopper/securedfields/test_KEY/6.48.1/securedFields.html?type=cardCompat", "checkoutshopper-test.adyen.com"],
    ["https://js.checkout.com/framesv2/?v=2.69.1&publicKey=pk", "js.checkout.com"],
    ["https://js.checkout.com/framesv2/?v=2.69.1&publicKey=pk&element=card-number", "js.checkout.com"],
    ["https://checkout-web-components.checkout.com/pages/1.236.0/index.html?pageName=card-cvv", "checkout-web-components.checkout.com"],
    [`https://checkout-web-components.checkout.com/pages/1.236.0/index.html#${btoa(JSON.stringify({ pageName: "card-number" }))}`, "checkout-web-components.checkout.com"],
    ["https://sandbox.web.squarecdn.com/1.87.2/single-card-element-iframe.html", "sandbox.web.squarecdn.com"],
    ["https://www.paypal.com/smart/card-field?type=number&sessionID=x", "www.paypal.com"],
    ["https://www.sandbox.paypal.com/web-sdk/v6/card-fields-content", "www.sandbox.paypal.com"],
    ["https://request.eprotect.vantivcnp.com/eProtect/eProtect.html?type=eProtect&paypageid=x", "request.eprotect.vantivcnp.com"],
    [`https://flex.cybersource.com/microform/bundle/v2.12.1/iframe.html?keyId=k#${encodeURIComponent(JSON.stringify({ fieldType: "securityCode" }))}`, "flex.cybersource.com"],
    ["https://testflex.cybersource.com/cybersource/assets/microform/0.11.4/iframe.html", "testflex.cybersource.com"],
    ["https://secure.nmi.com/token/inline.php?tokenizationKey=k&elementId=ccnumber", "secure.nmi.com"],
    ["https://secure.example-gateway.com/token/inline.php?elementId=cvv", "secure.example-gateway.com"],
    ["https://secure.nmi.com/token/lightbox.php?paymentType=cc", "secure.nmi.com"],
    ["https://js.verygoodvault.com/vgs-collect/3.2.2/lib/index.html#name=n&type=card-number", "js.verygoodvault.com"],
    ["https://core.spreedly.com/v1/embedded/number-frame-1.193.html", "core.spreedly.com"],
    ["https://js.authorize.net/v3/acceptMain/acceptMain.html#{}", "js.authorize.net"],
    ["https://accept.authorize.net/payment/payment", "accept.authorize.net"],
    [`https://api.recurly.com/js/v1/field.html#config=${encodeURIComponent(JSON.stringify({ type: "number" }))}`, "api.recurly.com"],
    ["https://js.chargebee.com/assets/cbjs-2026.11.12/v2/component.html?site=s&env=prod#shop.example", "js.chargebee.com"],
    ["https://acme.chargebee.com/hosted_pages/checkout?id=1", "acme.chargebee.com"],
    ["https://checkout.pci.shopifyinc.com/build/a8e4a94/number-ltr.html?identifier=1", "checkout.pci.shopifyinc.com"],
    ["https://checkout.shopifycs.com/verification_value?identifier=1", "checkout.shopifycs.com"],
  ] as const;
  for (const [url, host] of card) assert.equal(paymentProviderCardFrame(url), host, url);
  // Flow in hash mode can carry the field in the frame's name instead.
  assert.equal(paymentProviderCardFrame("https://checkout-web-components.checkout.com/pages/1.236.0/index.html#garbled", "card-number__x1"), "checkout-web-components.checkout.com");
});

test("a provider's buttons, wallets, controller, fraud and 3-D Secure frames are not card entry", () => {
  const notCard = [
    `https://js.stripe.com/v3/controller-${H32}.html`,
    `https://js.stripe.com/v3/controller-with-preconnect-${H32}.html`,
    `https://js.stripe.com/v3/m-outer-${H32}.html`,
    `https://js.stripe.com/v3/elements-inner-payment-request-${H32}.html`,
    `https://js.stripe.com/v3/elements-inner-payment-method-messaging-${H32}.html`,
    `https://js.stripe.com/v3/elements-inner-express-checkout-${H32}.html`,
    `https://js.stripe.com/v3/elements-inner-link-${H32}.html`,
    `https://js.stripe.com/v3/three-ds-2-challenge-${H32}.html`,
    `https://js.stripe.com/v3/elements-inner-address-${H32}.html`,
    "https://js.stripe.com/v3/elements-inner-card-0123.html",
    "https://assets.braintreegateway.com/web/3.148.0/html/dispatch-frame.min.html",
    "https://assets.braintreegateway.com/web/3.148.0/html/three-d-secure-bank-frame.min.html",
    "https://checkoutshopper-live.adyen.com/checkoutshopper/securedfields/live_KEY/5.1.0/securedFields.html?type=giftcard",
    "https://checkoutshopper-live.adyen.com/checkoutshopper/assets/html/live_KEY/dfp.1.0.0.html",
    "https://js.checkout.com/framesv2/?v=2.69.1&publicKey=pk&element=controller",
    "https://checkout-web-components.checkout.com/pages/1.236.0/index.html?pageName=card-controller",
    "https://checkout-web-components.checkout.com/pages/1.236.0/fingerprint.html",
    "https://web.squarecdn.com/1.87.2/main-iframe.html",
    "https://web.squarecdn.com/1.87.2/gift-card-element-iframe.html",
    "https://www.paypal.com/smart/buttons?style.layout=horizontal",
    "https://www.paypal.com/smart/menu",
    "https://www.paypal.com/credit-presentment/smart/message",
    "https://www.paypal.com/web-sdk/v6/bridge",
    `https://flex.cybersource.com/microform/bundle/v2/iframe.html#${encodeURIComponent(JSON.stringify({ fieldType: "routingNumber" }))}`,
    "https://secure.nmi.com/token/inline.php?elementId=checkaccount",
    "https://secure.nmi.com/token/lightbox.php?paymentType=ck",
    "https://secure.nmi.com/token/google_pay_field.php",
    "https://js.verygoodvault.com/vgs-collect/3.2.2/lib/index.html#type=ssn",
    "https://core.spreedly.com/v1/embedded/fraud-frame-1.193.html",
    `https://api.recurly.com/js/v1/field.html#config=${encodeURIComponent(JSON.stringify({ type: "text" }))}`,
    "https://api.recurly.com/js/v1/three_d_secure/start",
    "https://js.chargebee.com/assets/cbjs-2026.11.12/v2/master.html",
    "https://js.chargebee.com/components/v1/payment/button.html",
    "https://www.google.com/recaptcha/api2/anchor?ar=1",
    "https://widget.intercom.io/widget/test",
    "chrome-extension://abcdefghijklmnop/menu.html",
    "http://secure.nmi.com/token/inline.php?elementId=ccnumber",
    "https://js.stripe.com.evil.example/v3/elements-inner-card-" + H32 + ".html",
    "",
    "/v3/elements-inner-card-" + H32 + ".html",
  ];
  for (const url of notCard) assert.equal(paymentProviderCardFrame(url), null, url);
});

test("every card-entry pattern names its provider and a source, and covers the providers the threat model lists", () => {
  for (const f of CARD_ENTRY_FRAMES) {
    assert.match(f.source, /^https:\/\//, `${f.provider}: a source`);
    assert.ok(f.anyHost === true || f.hosts.length > 0 || (f.domains ?? []).length > 0, `${f.provider}: hosts`);
    assert.ok(f.path.source.startsWith("^"), `${f.provider}: the whole path`);
  }
  for (const name of ["Stripe", "Braintree", "Adyen", "Checkout.com", "Square", "PayPal", "Worldpay", "Cybersource", "NMI", "VGS", "Spreedly", "Authorize.net", "Recurly", "Chargebee", "Shopify"]) {
    assert.ok(CARD_ENTRY_FRAMES.some((f) => f.provider === name), name);
  }
});
