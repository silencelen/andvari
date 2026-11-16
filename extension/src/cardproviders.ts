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
 * documented (checked 2026-11-14). A release build lists the production hosts only: the sandbox and test hosts are in
 * the debug and UI-test builds (round-12 review). Where a provider serves several kinds of element from one origin, only
 * its card-entry documents count, by their own path ([isCardEntryDocument]).
 *
 * LEAF module: no chrome import, so node --test loads it directly.
 */
declare const __ANDVARI_UITEST_PROVIDER__: string | undefined;
declare const __ANDVARI_PROVIDER_TEST_HOSTS__: boolean | undefined;

export interface CardProviderOrigin {
  provider: string;
  /** `https://host`, exactly (`https://host:port` for the UI-test build's stand-in only). */
  origin: string;
  /** Where the origin is documented: the provider's guidance on where its card fields are served from. */
  source: string;
  /**
   * Where the provider serves several kinds of element from this origin (round-12 review: Stripe's Address Element is
   * no card frame, and its postal code is a shipping one): the paths of its card-entry documents, as the document's own
   * `location.pathname`. A document of this origin on any other path is no card document. Absent: every document of
   * the origin is one.
   */
  cardPaths?: readonly RegExp[];
}

export const CARD_PROVIDER_ORIGINS: readonly CardProviderOrigin[] = [
  // The Card Element family (card, cardNumber, cardExpiry, cardCvc) and the Payment Element, with the Payment
  // Element's autofill control and the card details re-collection modal. Not the Address, Link, Express Checkout or
  // controller frames of the same origin. Stripe documents no frame names: these come from Stripe.js's own bundle
  // (js.stripe.com/v3/, fetched 2026-11-14), not from documentation: elements-inner-card-<hash>.html,
  // elements-inner-payment-<hash>.html, elements-inner-payment-af-control-<hash>.html and
  // card-details-recollection-modal-<hash>.html.
  {
    provider: "Stripe",
    origin: "https://js.stripe.com",
    source: "https://docs.stripe.com/security/guide#content-security-policy",
    cardPaths: [
      /^\/v3\/elements-inner-(card|payment|payment-af-control)-[0-9a-f]+\.html$/,
      /^\/v3\/card-details-recollection-modal-[0-9a-f]+\.html$/,
    ],
  },
  // Checkout's hosted page.
  { provider: "Stripe", origin: "https://checkout.stripe.com", source: "https://docs.stripe.com/security/guide#content-security-policy" },
  // Hosted Fields (and the Drop-in's card form): one frame per field, sandbox and production alike.
  { provider: "Braintree", origin: "https://assets.braintreegateway.com", source: "https://braintree.github.io/braintree-web/current/" },
  // Secured Fields: one frame per field, from the region's live checkoutshopper host.
  ...["checkoutshopper-live", "checkoutshopper-live-us", "checkoutshopper-live-au", "checkoutshopper-live-apse", "checkoutshopper-live-in", "checkoutshopper-live-nea"].map(
    (h): CardProviderOrigin => ({ provider: "Adyen", origin: `https://${h}.adyen.com`, source: "https://github.com/Adyen/adyen-web/blob/main/packages/lib/src/core/Environment/constants.ts" }),
  ),
  // Frames (one frame, or one per field) and Flow's card components.
  { provider: "Checkout.com", origin: "https://js.checkout.com", source: "https://www.checkout.com/docs/payments/accept-payments/accept-a-payment-on-your-website/frames-reference" },
  { provider: "Checkout.com", origin: "https://checkout-web-components.checkout.com", source: "https://www.checkout.com/docs/payments/accept-payments/accept-a-payment-on-your-website/flow-library-reference" },
  // The Web Payments SDK's card frame.
  { provider: "Square", origin: "https://web.squarecdn.com", source: "https://developer.squareup.com/docs/web-payments/content-security-policy" },
  // eProtect (number, expiry and code in one frame) and Access Checkout.
  { provider: "Worldpay", origin: "https://request.eprotect.vantivcnp.com", source: "https://request.eprotect.vantivcnp.com/eProtect/js/eProtect-iframe-client.min.js" },
  { provider: "Worldpay", origin: "https://access.worldpay.com", source: "https://developer.worldpay.com/products/access/checkout/web" },
  // Flex Microform: number and security code frames.
  { provider: "Cybersource", origin: "https://flex.cybersource.com", source: "https://developer.cybersource.com/docs/cybs/en-us/digital-accept-flex/developer/all/rest/digital-accept/microform-integ-v2.html" },
  // Accept Hosted (the payment form, in a frame or as the page) and Accept UI's lightbox. Accept.js has no frame: its
  // fields are the shop's own, and are not filled.
  { provider: "Authorize.net", origin: "https://accept.authorize.net", source: "https://developer.authorize.net/api/reference/features/accept-hosted.html" },
  { provider: "Authorize.net", origin: "https://js.authorize.net", source: "https://developer.authorize.net/api/reference/features/acceptjs.html" },
  // Elements and hosted fields.
  { provider: "Recurly", origin: "https://api.recurly.com", source: "https://recurly.com/developers/reference/recurly-js/" },
  { provider: "Recurly", origin: "https://api.eu.recurly.com", source: "https://github.com/recurly/recurly-js/blob/master/lib/recurly/hosted-field.js" },
];

/**
 * The providers' sandbox and test hosts (round-12 review). Only the debug and UI-test builds list them (build.mjs
 * defines `__ANDVARI_PROVIDER_TEST_HOSTS__`); a release build fails if any is left in it. test.authorize.net in
 * particular is the whole sandbox gateway, with hosted forms a merchant writes.
 */
export const CARD_PROVIDER_TEST_ORIGINS: readonly CardProviderOrigin[] = [
  { provider: "Adyen", origin: "https://checkoutshopper-test.adyen.com", source: "https://github.com/Adyen/adyen-web/blob/main/packages/lib/src/core/Environment/constants.ts" },
  { provider: "Checkout.com", origin: "https://checkout-web-components.sandbox.checkout.com", source: "https://www.checkout.com/docs/payments/accept-payments/accept-a-payment-on-your-website/flow-library-reference" },
  { provider: "Square", origin: "https://sandbox.web.squarecdn.com", source: "https://developer.squareup.com/docs/web-payments/content-security-policy" },
  { provider: "Worldpay", origin: "https://request.eprotect.vantivprelive.com", source: "https://request.eprotect.vantivcnp.com/eProtect/js/eProtect-iframe-client.min.js" },
  { provider: "Worldpay", origin: "https://request.eprotect.vantivpostlive.com", source: "https://request.eprotect.vantivcnp.com/eProtect/js/eProtect-iframe-client.min.js" },
  { provider: "Worldpay", origin: "https://try.access.worldpay.com", source: "https://developer.worldpay.com/products/access/checkout/web" },
  { provider: "Cybersource", origin: "https://testflex.cybersource.com", source: "https://developer.cybersource.com/docs/cybs/en-us/digital-accept-flex/developer/all/rest/digital-accept/microform-integ-v2.html" },
  { provider: "Authorize.net", origin: "https://test.authorize.net", source: "https://developer.authorize.net/api/reference/features/accept-hosted.html" },
  { provider: "Authorize.net", origin: "https://jstest.authorize.net", source: "https://developer.authorize.net/api/reference/features/acceptjs.html" },
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

const ALL: readonly CardProviderOrigin[] = [
  ...CARD_PROVIDER_ORIGINS,
  ...(typeof __ANDVARI_PROVIDER_TEST_HOSTS__ === "boolean" && __ANDVARI_PROVIDER_TEST_HOSTS__ ? CARD_PROVIDER_TEST_ORIGINS : []),
  ...TEST_PROVIDERS,
];

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

/**
 * Whether the document at [origin] and [pathname] (its own `location.pathname`, read inside it) is a card-entry document:
 * a listed provider's origin, and, where the provider serves several kinds of element there, one of its card-entry
 * paths ([CardProviderOrigin.cardPaths]).
 */
export function isCardEntryDocument(origin: string | null | undefined, pathname: string): boolean {
  const p = cardProviderOf(origin);
  if (p === null) return false;
  return p.cardPaths === undefined || p.cardPaths.some((re) => re.test(pathname));
}

/**
 * The merchant account a provider's card document works for, where its own URL names one (round-13 review): two card
 * documents of one provider that name two accounts are two payment forms, never one fill. Read by the content script
 * inside the provider's document, from that document's own URL as it loaded. The page that made the frame wrote that
 * URL, so this is the page's word: two different accounts can only keep two forms apart (a refusal), and the same
 * account named twice proves nothing. Null where the URL names none.
 *
 * Read from each provider's own client bundle, 2026-11-14, not from documentation:
 * - Stripe: the publishable key (`apiKey`, pk_live_ or pk_test_) and the connected account (`stripeAccount`) in the
 *   fragment Stripe.js gives each Elements frame (js.stripe.com/v3/).
 * - Adyen: the client key in the Secured Fields path, `/checkoutshopper/securedfields/<clientKey>/<version>/...`
 *   (adyen-web 5.66.1).
 * - Checkout.com Frames: the public key in the query, `?publicKey=pk_...` (framesv2.min.js 2.69.1). Flow's card field
 *   frames carry none (its key goes to its controller frame).
 * - Recurly: the public key in the JSON of the fragment, `#config=<json>`, at `recurly.publicKey` (recurly.js v4).
 * - Worldpay eProtect: the Pay Page ID in the path, `/eProtect/eProtect_<paypageId>_<style>_api2.html` (or in the
 *   `paypageid` query of eProtect.html) (eProtect-iframe-client.min.js).
 * - Worldpay Access Checkout: the checkout ID in the `id` query (access-checkout-web 2.5.0).
 * - Cybersource Flex Microform: the capture context's key id in the `keyId` query (flex-microform 2.0.2): one
 *   Microform's own, narrower than an account, so two Microforms are two forms even for one merchant.
 * - None: Braintree (the fragment names a channel, the settings arrive by message), Square, and Authorize.net (Accept
 *   Hosted is loaded by a form post; Accept UI's frame is told only the page's origin).
 * The providers' test hosts are not named here, since a release build must name none: their frames, which only the
 * debug and UI-test builds list, are grouped by origin and chain alone (Adyen's, matched by a pattern, are read like its
 * live ones).
 */
export function providerAccountOf(href: string): string | null {
  let u: URL;
  try {
    u = new URL(href);
  } catch {
    return null;
  }
  const safe = (v: unknown, re: RegExp): string | null => (typeof v === "string" && re.test(v) ? v : null);
  const tagged = (tag: string, v: string | null): string | null => (v === null ? null : `${tag}:${v}`);
  if (u.origin === "https://js.stripe.com") {
    const params = new URLSearchParams(u.hash.replace(/^#/, ""));
    const key = safe(params.get("apiKey") ?? params.get("key"), /^pk_(live|test)_[A-Za-z0-9]{8,200}$/);
    if (key === null) return null;
    const account = safe(params.get("stripeAccount"), /^acct_[A-Za-z0-9]{4,64}$/);
    return account === null ? `stripe:${key}` : `stripe:${key}/${account}`;
  }
  if (/^https:\/\/checkoutshopper-[a-z0-9-]+\.adyen\.com$/.test(u.origin)) {
    const m = /^\/checkoutshopper\/securedfields\/([^/]+)\//.exec(u.pathname);
    return tagged("adyen", safe(m?.[1], /^(live|test)_[A-Za-z0-9]{8,200}$/));
  }
  if (u.origin === "https://js.checkout.com") {
    return tagged("checkout", safe(u.searchParams.get("publicKey"), /^pk_[A-Za-z0-9_-]{8,200}$/));
  }
  if (u.origin === "https://api.recurly.com" || u.origin === "https://api.eu.recurly.com") {
    if (u.hash.length > 16_384) return null;
    const config = new URLSearchParams(u.hash.replace(/^#/, "")).get("config");
    if (config === null) return null;
    let parsed: unknown;
    try {
      parsed = JSON.parse(config);
    } catch {
      return null;
    }
    const recurly = typeof parsed === "object" && parsed !== null ? (parsed as { recurly?: unknown }).recurly : undefined;
    const key = typeof recurly === "object" && recurly !== null ? (recurly as { publicKey?: unknown }).publicKey : undefined;
    return tagged("recurly", safe(key, /^[A-Za-z0-9][A-Za-z0-9_-]{7,199}$/));
  }
  if (u.origin === "https://request.eprotect.vantivcnp.com") {
    const m = /^\/eProtect\/eProtect_([A-Za-z0-9]+)_/.exec(u.pathname);
    const id = m?.[1] ?? (u.pathname === "/eProtect/eProtect.html" ? u.searchParams.get("paypageid") : null);
    return tagged("eprotect", safe(id, /^[A-Za-z0-9]{4,64}$/));
  }
  if (u.origin === "https://access.worldpay.com" && u.pathname.startsWith("/access-checkout/")) {
    return tagged("wpaccess", safe(u.searchParams.get("id"), /^[A-Za-z0-9-]{8,100}$/));
  }
  if (u.origin === "https://flex.cybersource.com" && u.pathname.startsWith("/microform/")) {
    return tagged("cybersource", safe(u.searchParams.get("keyId"), /^[A-Za-z0-9_-]{2,300}$/));
  }
  return null;
}
