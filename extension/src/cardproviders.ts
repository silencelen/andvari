/**
 * Where andvari fills a card (owner decision 2026-11-14; the card-fill threat model, docs/design/2026-11-09-ios-app.md,
 * "Card fill threat model"): only into a document whose origin, as the browser reports it for that frame, is one of
 * these payment providers' card-entry origins, or into a top-level page on one (a hosted checkout). Every other
 * document, a shop's own top frame and its same-origin frames included, never receives card data.
 *
 * Exact origins. A wildcard stands only where the provider documents a subdomain per merchant (Chargebee's hosted
 * pages), and matches one label. Origins that serve only buttons, wallets, controllers, fraud checks or 3-D Secure are
 * not here (Stripe's m.stripe.network and hooks.stripe.com, Google Pay, Apple Pay). PayPal serves its buttons and its
 * card fields from one host, which is listed for the card fields. Each entry names where the origin is documented
 * (checked 2026-11-14).
 *
 * LEAF module: no chrome import, so node --test loads it directly.
 */
declare const __ANDVARI_UITEST_PROVIDER__: string | undefined;

export interface CardProviderOrigin {
  provider: string;
  /** `https://host`, exactly; or `https://*.domain`, one label under it, where the provider documents that. */
  origin: string;
  /** Where the origin is documented: the provider's guidance on where its card fields are served from. */
  source: string;
}

export const CARD_PROVIDER_ORIGINS: readonly CardProviderOrigin[] = [
  // Elements, the Payment Element and Embedded Checkout frames; Checkout's hosted page.
  { provider: "Stripe", origin: "https://js.stripe.com", source: "https://docs.stripe.com/security/guide#content-security-policy" },
  { provider: "Stripe", origin: "https://checkout.stripe.com", source: "https://docs.stripe.com/security/guide#content-security-policy" },
  // Hosted Fields (and the Drop-in's card form): one frame per field, sandbox and production alike.
  { provider: "Braintree", origin: "https://assets.braintreegateway.com", source: "https://braintree.github.io/braintree-web/current/" },
  // Secured Fields: one frame per field, from the region's checkoutshopper host.
  ...[
    "checkoutshopper-test",
    "checkoutshopper-live",
    "checkoutshopper-live-us",
    "checkoutshopper-live-au",
    "checkoutshopper-live-apse",
    "checkoutshopper-live-in",
    "checkoutshopper-live-nea",
  ].map((h) => ({ provider: "Adyen", origin: `https://${h}.adyen.com`, source: "https://github.com/Adyen/adyen-web/blob/main/packages/lib/src/core/Environment/constants.ts" })),
  // Frames (one frame, or one per field) and Flow's card components.
  { provider: "Checkout.com", origin: "https://js.checkout.com", source: "https://www.checkout.com/docs/payments/accept-payments/accept-a-payment-on-your-website/frames-reference" },
  { provider: "Checkout.com", origin: "https://checkout-web-components.checkout.com", source: "https://www.checkout.com/docs/payments/accept-payments/accept-a-payment-on-your-website/flow-library-reference" },
  { provider: "Checkout.com", origin: "https://checkout-web-components.sandbox.checkout.com", source: "https://www.checkout.com/docs/payments/accept-payments/accept-a-payment-on-your-website/flow-library-reference" },
  // The Web Payments SDK's card frame.
  { provider: "Square", origin: "https://web.squarecdn.com", source: "https://developer.squareup.com/docs/web-payments/content-security-policy" },
  { provider: "Square", origin: "https://sandbox.web.squarecdn.com", source: "https://developer.squareup.com/docs/web-payments/content-security-policy" },
  // Card Fields (JS SDK v5 and v6).
  { provider: "PayPal", origin: "https://www.paypal.com", source: "https://developer.paypal.com/sdk/js/csp/" },
  { provider: "PayPal", origin: "https://www.sandbox.paypal.com", source: "https://developer.paypal.com/sdk/js/csp/" },
  // eProtect (number, expiry and code in one frame) and Access Checkout.
  { provider: "Worldpay", origin: "https://request.eprotect.vantivcnp.com", source: "https://request.eprotect.vantivcnp.com/eProtect/js/eProtect-iframe-client.min.js" },
  { provider: "Worldpay", origin: "https://request.eprotect.vantivprelive.com", source: "https://request.eprotect.vantivcnp.com/eProtect/js/eProtect-iframe-client.min.js" },
  { provider: "Worldpay", origin: "https://request.eprotect.vantivpostlive.com", source: "https://request.eprotect.vantivcnp.com/eProtect/js/eProtect-iframe-client.min.js" },
  { provider: "Worldpay", origin: "https://access.worldpay.com", source: "https://developer.worldpay.com/products/access/checkout/web" },
  { provider: "Worldpay", origin: "https://try.access.worldpay.com", source: "https://developer.worldpay.com/products/access/checkout/web" },
  // Flex Microform: number and security code frames.
  { provider: "Cybersource", origin: "https://flex.cybersource.com", source: "https://developer.cybersource.com/docs/cybs/en-us/digital-accept-flex/developer/all/rest/digital-accept/microform-integ-v2.html" },
  { provider: "Cybersource", origin: "https://testflex.cybersource.com", source: "https://developer.cybersource.com/docs/cybs/en-us/digital-accept-flex/developer/all/rest/digital-accept/microform-integ-v2.html" },
  // Collect.js on NMI's own gateway hosts (a white-label gateway's host is its own, and is not listed).
  { provider: "NMI", origin: "https://secure.nmi.com", source: "https://secure.nmi.com/token/Collect.js" },
  { provider: "NMI", origin: "https://secure.networkmerchants.com", source: "https://secure.nmi.com/token/Collect.js" },
  // Collect.js: one frame per field.
  { provider: "VGS", origin: "https://js.verygoodvault.com", source: "https://www.verygoodsecurity.com/docs/vgs-collect/js/integration" },
  { provider: "VGS", origin: "https://js3.verygoodvault.com", source: "https://js.verygoodvault.com/vgs-collect/3.2.2/vgs-collect.js" },
  // iFrame: the number and code frames.
  { provider: "Spreedly", origin: "https://core.spreedly.com", source: "https://docs.spreedly.com/reference/iframe/v1/" },
  // Accept Hosted (the payment form, in a frame or as the page) and Accept UI's lightbox. Accept.js has no frame: its
  // fields are the shop's own, and are not filled.
  { provider: "Authorize.net", origin: "https://accept.authorize.net", source: "https://developer.authorize.net/api/reference/features/accept-hosted.html" },
  { provider: "Authorize.net", origin: "https://test.authorize.net", source: "https://developer.authorize.net/api/reference/features/accept-hosted.html" },
  { provider: "Authorize.net", origin: "https://js.authorize.net", source: "https://developer.authorize.net/api/reference/features/acceptjs.html" },
  { provider: "Authorize.net", origin: "https://jstest.authorize.net", source: "https://developer.authorize.net/api/reference/features/acceptjs.html" },
  // Elements and hosted fields.
  { provider: "Recurly", origin: "https://api.recurly.com", source: "https://recurly.com/developers/reference/recurly-js/" },
  { provider: "Recurly", origin: "https://api.eu.recurly.com", source: "https://github.com/recurly/recurly-js/blob/master/lib/recurly/hosted-field.js" },
  // Components, and the hosted pages each site gets on a subdomain of its own (documented as https://<site>.chargebee.com).
  { provider: "Chargebee", origin: "https://js.chargebee.com", source: "https://www.chargebee.com/checkout-portal-docs/components-fields-integrations.html" },
  { provider: "Chargebee", origin: "https://*.chargebee.com", source: "https://www.chargebee.com/docs/billing/2.0/kb/billing/content-security-policy-for-loading-the-checkout-page" },
  // Checkout's card fields, one frame per field (no official page names the host; checkout.shopifycs.com is the earlier one).
  { provider: "Shopify", origin: "https://checkout.pci.shopifyinc.com", source: "https://shopify.dev/changelog" },
  { provider: "Shopify", origin: "https://checkout.shopifycs.com", source: "https://shopify.dev/changelog" },
];

/**
 * The UI-test variant of the Safari build only (build.mjs `UITEST=1`): the test site's stand-in provider, so a fill can
 * be tested in the simulator. Every other build defines nothing here, and the release Safari build is checked not to
 * contain it.
 */
const TEST_PROVIDERS: readonly CardProviderOrigin[] =
  typeof __ANDVARI_UITEST_PROVIDER__ === "string" && __ANDVARI_UITEST_PROVIDER__ !== ""
    ? [{ provider: "andvari UI test", origin: __ANDVARI_UITEST_PROVIDER__, source: "app-ios/uitest/README.md" }]
    : [];

const ALL: readonly CardProviderOrigin[] = [...CARD_PROVIDER_ORIGINS, ...TEST_PROVIDERS];

/** The origin of [value] as a browser writes it (`https://host` or `https://host:port`), or null for anything but an
 *  https URL or origin. */
function normalized(value: string): string | null {
  try {
    const u = new URL(value);
    return u.protocol === "https:" && u.hostname !== "" ? u.origin : null;
  } catch {
    return null;
  }
}

function matches(entry: string, origin: string): boolean {
  const star = /^https:\/\/\*\.([a-z0-9.-]+)$/.exec(entry);
  if (star === null) return entry === origin;
  const host = new URL(origin).host;
  const domain = star[1]!;
  return host.endsWith("." + domain) && /^[a-z0-9-]+$/.test(host.slice(0, -(domain.length + 1)));
}

/** The listed provider whose card-entry origin [origin] is, or null: any other origin, an opaque one, or not https. */
export function cardProviderOf(origin: string | null | undefined): CardProviderOrigin | null {
  if (typeof origin !== "string" || origin === "" || origin === "null") return null;
  const o = normalized(origin);
  if (o === null) return null;
  return ALL.find((p) => matches(p.origin, o)) ?? null;
}

/** Whether a document of [origin] may receive card data. */
export function isCardProviderOrigin(origin: string | null | undefined): boolean {
  return cardProviderOf(origin) !== null;
}
