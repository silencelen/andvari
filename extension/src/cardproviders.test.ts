// node --test. The card-entry origins andvari fills a card into (owner decision 2026-11-14, round-11 review): exact https
// origins, each with its source, no wildcards; nothing that only serves buttons, controllers, fraud checks or 3-D
// Secure, nothing that is also a whole web app or takes a site owner's scripts, no vault whose owner decides where the
// raw card goes; and the UI-test origin only in the UI-test build.
import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { CARD_PROVIDER_ORIGINS, CARD_PROVIDER_TEST_ORIGINS, cardProviderOf, isCardEntryDocument, isCardProviderOrigin, providerAccountOf } from "./cardproviders.ts";

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
  // Round-13 review: a build is a release build unless DEBUG=1 says otherwise, and only DEBUG=1 or UITEST=1 lists them.
  assert.match(build, /const debug = process\.env\.DEBUG === "1";\s*const release = !debug;/);
  assert.ok(!/process\.env\.RELEASE/.test(build), "RELEASE=1 is no longer what makes a release build");
  assert.match(build, /__ANDVARI_PROVIDER_TEST_HOSTS__: JSON\.stringify\(debug \|\| uitest\)/);
  assert.match(build, /if \(!debug && !uitest\) \{/);
  assert.match(build, /a release build must not list a payment provider's test host/);
});

test("an iOS Release build, and the unsigned app CI builds, refuse every test host, not only the UI-test domain (round-13 review)", () => {
  const script = fileURLToPath(new URL("../../app-ios/scripts/check-no-test-hosts.sh", import.meta.url));
  const dir = mkdtempSync(join(tmpdir(), "andvari-test-hosts-"));
  try {
    writeFileSync(join(dir, "background.js"), 'const providers = ["https://js.stripe.com", "https://assets.braintreegateway.com"];');
    assert.equal(spawnSync("bash", [script, dir], { encoding: "utf-8" }).status, 0, "a bundle naming production hosts only passes");
    const hosts = ["pay.andvari-uitest.test:8443", ...CARD_PROVIDER_TEST_ORIGINS.map((p) => new URL(p.origin).host)];
    assert.ok(hosts.length >= 10);
    for (const host of hosts) {
      writeFileSync(join(dir, "content.js"), `const x = "https://${host}";`);
      const r = spawnSync("bash", [script, dir], { encoding: "utf-8" });
      assert.equal(r.status, 1, `${host} must fail the check`);
      assert.match(r.stdout, /only the UI-test and DEBUG=1 builds may list/);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
  // The Safari target's build phase for any Release build (what an archive is), and the unsigned app's CI check.
  const project = readFileSync(new URL("../../app-ios/project.yml", import.meta.url), "utf-8");
  assert.match(project, /if \[ "\$\{CONFIGURATION\}" = "Release" \]; then\s*"\$\{SRCROOT\}\/scripts\/check-no-test-hosts\.sh" "\$\{TARGET_BUILD_DIR\}\/\$\{WRAPPER_NAME\}" \|\| \{/);
  const unsigned = readFileSync(new URL("../../.github/workflows/ios-unsigned.yml", import.meta.url), "utf-8");
  assert.match(unsigned, /\n\s*app-ios\/scripts\/check-no-test-hosts\.sh "\$APP\/PlugIns\/AndvariSafari\.appex"\n/);
  // The script reads the hosts from the source, so a test host added there is refused too.
  const sh = readFileSync(script, "utf-8");
  assert.match(sh, /\/\^export const CARD_PROVIDER_TEST_ORIGINS\//);
  assert.match(sh, /for h in andvari-uitest \$hosts; do/);
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

test("Stripe's card documents include the Payment Element's autofill control and the card details re-collection modal (round-13 review)", () => {
  const stripe = "https://js.stripe.com";
  assert.ok(isCardEntryDocument(stripe, "/v3/elements-inner-payment-af-control-3f9a0c1d.html"));
  assert.ok(isCardEntryDocument(stripe, "/v3/card-details-recollection-modal-8be24f.html"));
  for (const path of ["/v3/elements-inner-payment-af-control.html", "/v3/elements-inner-af-control-3f9a.html", "/v3/card-details-recollection-modal.html", "/v3/card-details-recollection-modal-xyz.html", "/v3/card-details-recollection-modal-8be2.html/x", "/v2/card-details-recollection-modal-8be2.html", "/v3/card-details-recollection-8be2.html"]) {
    assert.ok(!isCardEntryDocument(stripe, path), path);
  }
  const source = readFileSync(new URL("./cardproviders.ts", import.meta.url), "utf-8");
  assert.match(source, /these come from Stripe\.js's own bundle\s*\/\/ \(js\.stripe\.com\/v3\/, fetched 2026-11-14\), not from documentation/, "where the names come from");
});

test("the merchant account a provider's card document names in its own URL (round-13 review)", () => {
  const card = "https://js.stripe.com/v3/elements-inner-card-0a1b2c.html";
  assert.equal(providerAccountOf(`${card}#wait=false&apiKey=pk_live_51AbCdEfGh&stripeAccount=acct_1XyZw&locale=en`), "stripe:pk_live_51AbCdEfGh/acct_1XyZw");
  assert.equal(providerAccountOf(`${card}#apiKey=pk_test_51AbCdEfGh`), "stripe:pk_test_51AbCdEfGh");
  assert.equal(providerAccountOf(`${card}#apiKey=pk_live_51AbCdEfGh&stripeAccount=acct_<b>`), "stripe:pk_live_51AbCdEfGh", "a connected account that is no id is left out");
  assert.notEqual(providerAccountOf(`${card}#apiKey=pk_live_AAAAAAAAAA`), providerAccountOf(`${card}#apiKey=pk_live_BBBBBBBBBB`), "two shops' keys: two accounts");
  for (const href of [
    `${card}#apiKey=sk_live_AAAAAAAAAA`, // not a publishable key
    `${card}?apiKey=pk_live_AAAAAAAAAA`, // not where Stripe.js puts it
    `${card}#apiKey=pk_live_AAAA%3Cscript%3E`,
    `${card}#apiKey=pk_live_AAA`,
    card,
    "https://shop.example/pay#apiKey=pk_live_AAAAAAAAAA", // not a provider's document
    "https://js.stripe.com.evil.example/v3/x.html#apiKey=pk_live_AAAAAAAAAA",
    "not a url",
  ]) {
    assert.equal(providerAccountOf(href), null, href);
  }
  assert.equal(providerAccountOf("https://checkoutshopper-live.adyen.com/checkoutshopper/securedfields/live_ABCDEFGH12345678/5.66.1/securedFields.html?type=card&d=x"), "adyen:live_ABCDEFGH12345678");
  assert.equal(providerAccountOf("https://checkoutshopper-live-us.adyen.com/checkoutshopper/securedfields/live_ABCDEFGH12345678/5.66.1/securedFields.html"), "adyen:live_ABCDEFGH12345678");
  assert.equal(providerAccountOf("https://checkoutshopper-live.adyen.com/checkoutshopper/securedfields/../5.66.1/securedFields.html"), null);
  assert.equal(providerAccountOf("https://js.checkout.com/framesv2/2.69.1/card-frame.html?publicKey=pk_sbox_abcdefgh1234&localization=EN-GB"), "checkout:pk_sbox_abcdefgh1234");
  assert.equal(providerAccountOf("https://js.checkout.com/framesv2/2.69.1/card-frame.html#publicKey=pk_sbox_abcdefgh1234"), null);
  // Recurly: the public key inside the JSON of the fragment (recurly.js builds `field.html#config=<json>`).
  const recurlyField = (config: unknown): string => `https://api.recurly.com/js/v1/field.html#config=${encodeURIComponent(JSON.stringify(config))}`;
  assert.equal(providerAccountOf(recurlyField({ type: "number", elementId: "x", recurly: { publicKey: "ewr1-AbCdEfGhIjKlMn", api: "https://api.recurly.com/js/v1" } })), "recurly:ewr1-AbCdEfGhIjKlMn");
  assert.equal(providerAccountOf(recurlyField({ type: "number", recurly: { publicKey: "ewr1-AbCdEfGhIjKlMn" } }).replace("api.recurly.com", "api.eu.recurly.com")), "recurly:ewr1-AbCdEfGhIjKlMn");
  assert.equal(providerAccountOf(recurlyField({ type: "number", recurly: { api: "https://api.recurly.com/js/v1" } })), null, "no key");
  assert.equal(providerAccountOf(recurlyField({ type: "number", recurly: { publicKey: "ewr1 <b>" } })), null, "not a key");
  assert.equal(providerAccountOf("https://api.recurly.com/js/v1/field.html#config=%7Bnot%20json"), null);
  assert.equal(providerAccountOf(`https://api.recurly.com/js/v1/field.html#config=${"x".repeat(17_000)}`), null, "a fragment past 16 KiB is not read");
  // Worldpay eProtect: the Pay Page ID in the path (or the query of eProtect.html); Access Checkout: the checkout ID.
  assert.equal(providerAccountOf("https://request.eprotect.vantivcnp.com/eProtect/eProtect_a2y4o6m8k0_shopstyle_api2.html"), "eprotect:a2y4o6m8k0");
  assert.equal(providerAccountOf("https://request.eprotect.vantivcnp.com/eProtect/eProtect_a2y4o6m8k0_shopstyle_api2_enhancedUx_2.html"), "eprotect:a2y4o6m8k0");
  assert.equal(providerAccountOf("https://request.eprotect.vantivcnp.com/eProtect/eProtect.html?type=eProtect&paypageid=a2y4o6m8k0&style=s"), "eprotect:a2y4o6m8k0");
  assert.equal(providerAccountOf("https://request.eprotect.vantivcnp.com/eProtect/other.html?paypageid=a2y4o6m8k0"), null);
  assert.equal(providerAccountOf("https://access.worldpay.com/access-checkout/v2.5.0/?type=pan&mode=default&id=0d5a3e57-91a3-4b5f-a7a1-1c2a5d6b7e8f"), "wpaccess:0d5a3e57-91a3-4b5f-a7a1-1c2a5d6b7e8f");
  assert.equal(providerAccountOf("https://access.worldpay.com/other/?id=0d5a3e57-91a3-4b5f"), null);
  // Cybersource: the capture context's key id, one Microform's own.
  assert.equal(providerAccountOf('https://flex.cybersource.com/microform/bundle/v2.0.2/iframe.html?keyId=08rK0LjHvbx0Z5HuuxIz#{"microformId":"m"}'), "cybersource:08rK0LjHvbx0Z5HuuxIz");
  assert.equal(providerAccountOf("https://flex.cybersource.com/microform/bundle/v2.0.2/iframe.html"), null);
  // Providers whose frame URL names no account: their frames group by origin and chain alone.
  assert.equal(providerAccountOf("https://assets.braintreegateway.com/web/3.111.0/html/hosted-fields-frame.min.html#abc"), null);
  assert.equal(providerAccountOf("https://web.squarecdn.com/1.70.0/main-iframe.html"), null);
  assert.equal(providerAccountOf('https://js.authorize.net/v3/acceptMain/acceptMain.html#%7B%22verifyOrigin%22%3A%22AcceptUI%22%7D'), null);
  assert.equal(providerAccountOf("https://accept.authorize.net/payment/payment"), null);
  // Each tag is one the worker keeps (background.ts accountOf: a lowercase tag, a colon, a bounded token).
  for (const v of ["recurly:ewr1-AbCdEfGhIjKlMn", "eprotect:a2y4o6m8k0", "wpaccess:0d5a3e57-91a3-4b5f-a7a1-1c2a5d6b7e8f", "cybersource:08rK0LjHvbx0Z5HuuxIz", "stripe:pk_live_51AbCdEfGh/acct_1XyZw", "adyen:live_ABCDEFGH12345678", "checkout:pk_sbox_abcdefgh1234"]) {
    assert.match(v, /^[a-z]+:[A-Za-z0-9_/-]+$/, v);
  }
  // The test hosts are named nowhere outside their list and its comment (a release build must name none of them).
  const source = readFileSync(new URL("./cardproviders.ts", import.meta.url), "utf-8");
  const list = source.indexOf("export const CARD_PROVIDER_TEST_ORIGINS");
  const outsideList = source.slice(0, source.lastIndexOf("/**", list)) + source.slice(source.indexOf("];", list));
  for (const p of CARD_PROVIDER_TEST_ORIGINS) assert.ok(!outsideList.includes(new URL(p.origin).host), `${p.origin} is named outside the test list`);
  // What the content script sends is what the worker keeps (background.ts accountOf): one token, bounded.
  const bg = readFileSync(new URL("./background.ts", import.meta.url), "utf-8");
  assert.match(bg, /return typeof v === "string" && v\.length <= 300 && \/\^\[a-z\]\+:\[A-Za-z0-9_\/-\]\+\$\/\.test\(v\) \? v : null;/);
});
