/**
 * Where andvari fills a card (owner decision 2026-11-14; the card-fill threat model, docs/design/2026-11-09-ios-app.md,
 * "Card fill threat model"): only into a document whose origin, as the browser reports it for that frame, is one of
 * these payment providers' card-entry origins, or into a top-level page on one (a hosted checkout). Every other
 * document, a shop's own top frame and its same-origin frames included, never receives card data.
 *
 * Exact origins, no wildcards, each a host that serves the provider's own card-entry pages and nothing a merchant or
 * anyone else can put a script into. Not here (round-11 review): origins that serve only buttons, wallets,
 * controllers, fraud checks or 3-D Secure (Stripe's m.stripe.network and hooks.stripe.com, Google Pay, Apple Pay);
 * hosts that are also a whole web app (PayPal's card fields come from www.paypal.com, NMI's Collect.js from the same
 * host as its merchant portal); pages a site owner can add scripts to (Chargebee's hosted pages, *.chargebee.com);
 * vaults whose owner decides where the raw card goes (VGS, Spreedly: an attacker's own vault would get a readable
 * number); and hosts no provider page documents (Shopify's checkout card fields). Each entry names where the origin is
 * documented (checked 2026-11-14).
 *
 * LEAF module: no chrome import, so node --test loads it directly.
 */
declare const __ANDVARI_UITEST_PROVIDER__: string | undefined;

export interface CardProviderOrigin {
  provider: string;
  /** `https://host`, exactly (`https://host:port` for the UI-test build's stand-in only). */
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
  // eProtect (number, expiry and code in one frame) and Access Checkout.
  { provider: "Worldpay", origin: "https://request.eprotect.vantivcnp.com", source: "https://request.eprotect.vantivcnp.com/eProtect/js/eProtect-iframe-client.min.js" },
  { provider: "Worldpay", origin: "https://request.eprotect.vantivprelive.com", source: "https://request.eprotect.vantivcnp.com/eProtect/js/eProtect-iframe-client.min.js" },
  { provider: "Worldpay", origin: "https://request.eprotect.vantivpostlive.com", source: "https://request.eprotect.vantivcnp.com/eProtect/js/eProtect-iframe-client.min.js" },
  { provider: "Worldpay", origin: "https://access.worldpay.com", source: "https://developer.worldpay.com/products/access/checkout/web" },
  { provider: "Worldpay", origin: "https://try.access.worldpay.com", source: "https://developer.worldpay.com/products/access/checkout/web" },
  // Flex Microform: number and security code frames.
  { provider: "Cybersource", origin: "https://flex.cybersource.com", source: "https://developer.cybersource.com/docs/cybs/en-us/digital-accept-flex/developer/all/rest/digital-accept/microform-integ-v2.html" },
  { provider: "Cybersource", origin: "https://testflex.cybersource.com", source: "https://developer.cybersource.com/docs/cybs/en-us/digital-accept-flex/developer/all/rest/digital-accept/microform-integ-v2.html" },
  // Accept Hosted (the payment form, in a frame or as the page) and Accept UI's lightbox. Accept.js has no frame: its
  // fields are the shop's own, and are not filled.
  { provider: "Authorize.net", origin: "https://accept.authorize.net", source: "https://developer.authorize.net/api/reference/features/accept-hosted.html" },
  { provider: "Authorize.net", origin: "https://test.authorize.net", source: "https://developer.authorize.net/api/reference/features/accept-hosted.html" },
  { provider: "Authorize.net", origin: "https://js.authorize.net", source: "https://developer.authorize.net/api/reference/features/acceptjs.html" },
  { provider: "Authorize.net", origin: "https://jstest.authorize.net", source: "https://developer.authorize.net/api/reference/features/acceptjs.html" },
  // Elements and hosted fields.
  { provider: "Recurly", origin: "https://api.recurly.com", source: "https://recurly.com/developers/reference/recurly-js/" },
  { provider: "Recurly", origin: "https://api.eu.recurly.com", source: "https://github.com/recurly/recurly-js/blob/master/lib/recurly/hosted-field.js" },
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

/** The listed provider whose card-entry origin [origin] is, or null: any other origin, an opaque one, or not https. */
export function cardProviderOf(origin: string | null | undefined): CardProviderOrigin | null {
  if (typeof origin !== "string" || origin === "" || origin === "null") return null;
  const o = normalized(origin);
  if (o === null) return null;
  return ALL.find((p) => p.origin === o) ?? null;
}

/** Whether a document of [origin] may receive card data. */
export function isCardProviderOrigin(origin: string | null | undefined): boolean {
  return cardProviderOf(origin) !== null;
}
