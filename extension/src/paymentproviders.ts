/**
 * Payment providers that take the card in a frame of their own (hosted fields), for the card-fill threat model
 * (docs/design/2026-11-09-ios-app.md, "Card fill threat model"). [PAYMENT_PROVIDER_FRAMES] lists the hosts their frames
 * come from: it names a provider in the explainer and decides nothing. [CARD_ENTRY_FRAMES] lists, by host and path (and
 * a query or fragment value where the path alone does not tell), the frames that hold card entry: one of them anywhere
 * on a page is case c, and no card is filled into the page's own documents there. A provider's buttons, wallets,
 * controller, fraud and 3-D Secure frames do not match, so they never stop a fill beside a first-party form. Each
 * entry names where its URL comes from (checked against the providers' SDKs, 2026-11-13).
 *
 * Hosts are matched exactly or as a parent domain (`host` or `*.host`). Matching more than a provider serves (a whole
 * domain) only ever refuses a fill. Each entry names where the host is documented.
 */
export interface PaymentProviderFrame {
  provider: string;
  /** A host, matched exactly or as a parent domain. */
  host: string;
  /** Where the host is documented: the provider's guidance on where its frames are served from. */
  source: string;
}

export const PAYMENT_PROVIDER_FRAMES: readonly PaymentProviderFrame[] = [
  // frame-src https://js.stripe.com https://*.js.stripe.com
  { provider: "Stripe", host: "js.stripe.com", source: "https://docs.stripe.com/security/guide#content-security-policy" },
  // CSP table: frame-src and child-src assets.braintreegateway.com (sandbox and production)
  { provider: "Braintree", host: "assets.braintreegateway.com", source: "https://braintree.github.io/braintree-web/current/" },
  // CardFields, JS SDK v5: frame-src *.paypal.com *.paypalobjects.com *.venmo.com
  { provider: "PayPal", host: "paypal.com", source: "https://developer.paypal.com/sdk/js/csp/" },
  { provider: "PayPal", host: "paypalobjects.com", source: "https://developer.paypal.com/sdk/js/csp/" },
  { provider: "PayPal", host: "venmo.com", source: "https://developer.paypal.com/sdk/js/csp/" },
  // Secured Fields frames: checkoutshopper-test / -live / -live-us / -live-au / -live-apse / -live-in / -live-nea .adyen.com.
  // Adyen's CSP page says only "frame-src: *"; the hosts are in its own web library.
  { provider: "Adyen", host: "adyen.com", source: "https://github.com/Adyen/adyen-web/blob/main/packages/lib/src/core/Environment/constants.ts" },
  // frame-src https://*.checkout.com (Frames loads its frames from js.checkout.com)
  { provider: "Checkout.com", host: "checkout.com", source: "https://www.checkout.com/docs/payments/accept-payments/upgrade-to-flow-from-frames/upgrade-from-frames-for-web" },
  // frame-src https://web.squarecdn.com (sandbox: sandbox.web.squarecdn.com)
  { provider: "Square", host: "squarecdn.com", source: "https://developer.squareup.com/docs/web-payments/content-security-policy" },
  // Access Checkout: access.worldpay.com, try.access.worldpay.com; hosted payment pages: payments.worldpay.com
  { provider: "Worldpay", host: "worldpay.com", source: "https://docs.worldpay.com/access/products/hosted-payment-pages/iframe" },
  // Accept Hosted: accept.authorize.net (sandbox test.authorize.net); the AcceptUI lightbox: js.authorize.net
  { provider: "Authorize.net", host: "authorize.net", source: "https://developer.authorize.net/api/reference/features/accept-hosted.html" },
  // Hosted fields: api.recurly.com, api.eu.recurly.com (named in recurly-js, not in the docs)
  { provider: "Recurly", host: "recurly.com", source: "https://github.com/recurly/recurly-js/blob/master/lib/recurly/hosted-field.js" },
  // frame-src https://<site>.chargebee.com/ (components load from js.chargebee.com)
  { provider: "Chargebee", host: "chargebee.com", source: "https://www.chargebee.com/docs/billing/2.0/kb/billing/content-security-policy-for-loading-the-checkout-page" },
  // Card fields at checkout. No official source names the host; checkout.pci.shopifyinc.com is the current one by
  // third-party accounts, checkout.shopifycs.com the earlier one. Matching more than Shopify serves only refuses a fill.
  { provider: "Shopify", host: "pci.shopifyinc.com", source: "https://shopify.dev/changelog" },
  { provider: "Shopify", host: "shopifycs.com", source: "https://shopify.dev/changelog" },
  // Round-9 additions, card-entry frames found in the providers' SDKs (CARD_ENTRY_FRAMES below).
  { provider: "Cybersource", host: "cybersource.com", source: "https://flex.cybersource.com/microform/bundle/v2/flex-microform.min.js" },
  { provider: "NMI", host: "nmi.com", source: "https://secure.nmi.com/token/Collect.js" },
  { provider: "NMI", host: "networkmerchants.com", source: "https://secure.nmi.com/token/Collect.js" },
  { provider: "VGS", host: "verygoodvault.com", source: "https://js.verygoodvault.com/vgs-collect/3.2.2/vgs-collect.js" },
  { provider: "Spreedly", host: "spreedly.com", source: "https://core.spreedly.com/iframe/iframe-v1.min.js" },
  { provider: "Worldpay", host: "vantivcnp.com", source: "https://request.eprotect.vantivcnp.com/eProtect/js/eProtect-iframe-client.min.js" },
  { provider: "Worldpay", host: "vantivprelive.com", source: "https://request.eprotect.vantivcnp.com/eProtect/js/eProtect-iframe-client.min.js" },
  { provider: "Worldpay", host: "vantivpostlive.com", source: "https://request.eprotect.vantivcnp.com/eProtect/js/eProtect-iframe-client.min.js" },
];

/** The host of [url] when it is a listed provider's (matched as [PaymentProviderFrame.host] says), or null for any
 *  other URL, a relative one, or anything but https. */
export function paymentProviderHost(url: string): string | null {
  let host: string;
  try {
    const u = new URL(url);
    if (u.protocol !== "https:") return null;
    host = u.hostname.toLowerCase();
  } catch {
    return null;
  }
  return PAYMENT_PROVIDER_FRAMES.some((p) => host === p.host || host.endsWith("." + p.host)) ? host : null;
}

/**
 * A frame that holds card entry: its hosts, its whole pathname, and where needed a test of its query or fragment (or
 * its frame's name) that tells card entry from the provider's other frames on the same path.
 */
export interface CardEntryFrame {
  provider: string;
  /** Hosts matched exactly; [anyHost]: the path is matched on any https host (white-label gateways). */
  hosts: readonly string[];
  /** Also any subdomain of these. */
  domains?: readonly string[];
  anyHost?: boolean;
  /** The URL's whole pathname. */
  path: RegExp;
  /** For a path shared with frames that are not card entry: whether this one is. Undecidable counts as card entry. */
  card?: (u: URL, frameName: string | null) => boolean;
  source: string;
}

const HEX = "(?:[0-9a-f]{32}|[0-9a-f]{40})";
const VER = "v?\\d+(?:\\.\\d+)*";

/** The JSON a fragment carries (`#<json>`, URL-encoded or not), or null. */
function fragmentJson(u: URL): Record<string, unknown> | null {
  const raw = u.hash.replace(/^#/, "");
  for (const text of [raw, safeDecode(raw)]) {
    if (text === null) continue;
    try {
      const v: unknown = JSON.parse(text);
      if (v !== null && typeof v === "object") return v as Record<string, unknown>;
    } catch {
      /* not JSON */
    }
  }
  return null;
}

function safeDecode(s: string): string | null {
  try {
    return decodeURIComponent(s);
  } catch {
    return null;
  }
}

/** A field or page name the provider puts in the query, else in its fragment's JSON (plain or base64), else null. */
function named(u: URL, key: string): string | null {
  const q = u.searchParams.get(key);
  if (q !== null) return q;
  const json = fragmentJson(u);
  if (json !== null && typeof json[key] === "string") return json[key] as string;
  const raw = u.hash.replace(/^#/, "");
  try {
    const decoded: unknown = JSON.parse(atob(safeDecode(raw) ?? raw));
    if (decoded !== null && typeof decoded === "object" && typeof (decoded as Record<string, unknown>)[key] === "string") return (decoded as Record<string, string>)[key]!;
  } catch {
    /* not base64 JSON */
  }
  return null;
}

/** [name] is one of [card], or cannot be told (counted as card entry: a fill there only ever refuses). */
const oneOf = (name: string | null, card: readonly string[]): boolean => name === null || card.includes(name);

export const CARD_ENTRY_FRAMES: readonly CardEntryFrame[] = [
  // Stripe.js v3 builds each frame's URL from a fixed list of names (the frame-type switch): the Card Element (card,
  // cardNumber, cardExpiry, cardCvc, postalCode), the Payment Element, Embedded Checkout and the card-details
  // recollection lightbox. Not: payment-request, express-checkout, link, controller, metrics, 3DS, messaging, address.
  { provider: "Stripe", hosts: ["js.stripe.com"], domains: ["js.stripe.com"], path: new RegExp(`^/v3/elements-inner-card-${HEX}\\.html$`), source: "https://js.stripe.com/v3/" },
  { provider: "Stripe", hosts: ["js.stripe.com"], domains: ["js.stripe.com"], path: new RegExp(`^/v3/elements-inner-payment(?:-af-control)?-${HEX}\\.html$`), source: "https://js.stripe.com/v3/" },
  // Built from the Payment Element's options; what it holds is not documented, so it is counted as card entry.
  { provider: "Stripe", hosts: ["js.stripe.com"], domains: ["js.stripe.com"], path: new RegExp(`^/v3/elements-inner-habanero-${HEX}\\.html$`), source: "https://js.stripe.com/v3/" },
  { provider: "Stripe", hosts: ["js.stripe.com"], domains: ["js.stripe.com"], path: new RegExp(`^/v3/(?:guacamole-)?embedded-checkout-inner-${HEX}\\.html$`), source: "https://js.stripe.com/v3/fingerprinted/js/embedded-checkout-outer-1013a4c3147d55bf24d35f59d3f4ee0a.js" },
  { provider: "Stripe", hosts: ["js.stripe.com"], domains: ["js.stripe.com"], path: new RegExp(`^/v3/card-details-recollection-modal-${HEX}\\.html$`), source: "https://js.stripe.com/v3/" },
  // Hosted Fields (also the Drop-in's card form): one frame per field. Not: dispatch, PayPal, Venmo, 3DS frames.
  { provider: "Braintree", hosts: ["assets.braintreegateway.com"], path: new RegExp(`^/web/${VER}/html/hosted-fields-frame(?:\\.min)?\\.html$`), source: "https://js.braintreegateway.com/web/3.148.0/js/hosted-fields.js" },
  // Secured fields: number, expiry and CVC, type=card (cardCompat on test). Not: type=giftcard; dfp and 3DS frames.
  {
    provider: "Adyen",
    hosts: ["checkoutshopper-test.adyen.com", "checkoutshopper-live.adyen.com", "checkoutshopper-live-us.adyen.com", "checkoutshopper-live-au.adyen.com", "checkoutshopper-live-apse.adyen.com", "checkoutshopper-live-in.adyen.com", "checkoutshopper-live-nea.adyen.com"],
    path: new RegExp(`^/checkoutshopper/securedfields/[^/]+/${VER}/securedFields\\.html$`),
    card: (u) => oneOf(u.searchParams.get("type"), ["card", "cardCompat"]),
    source: "https://github.com/Adyen/adyen-web/blob/main/packages/lib/src/components/internal/SecuredFields/lib/CSF/extensions/handleConfig.ts",
  },
  // Frames v2: one frame (no element) or one per field. Not: element=controller.
  { provider: "Checkout.com", hosts: ["js.checkout.com"], path: /^\/framesv2\/?$/, card: (u) => u.searchParams.get("element") !== "controller", source: "https://cdn.checkout.com/js/framesv2.min.js" },
  // Flow: pageName in the query, or in a base64 JSON fragment, or the frame's name `<pageName>__<id>`. Not: card-controller,
  // prefetcher, authentication; fingerprint.html.
  {
    provider: "Checkout.com",
    hosts: ["checkout-web-components.checkout.com", "checkout-web-components.sandbox.checkout.com"],
    path: new RegExp(`^/pages/${VER}/index\\.html$`),
    card: (u, frameName) => oneOf(named(u, "pageName") ?? frameName?.split("__")[0] ?? null, ["card-number", "card-expiry-date", "card-cvv", "cardholder-name", "card-cvv-standalone"]),
    source: "https://checkout-web-components.checkout.com/index.js",
  },
  // Web Payments SDK: the card's one frame. Not: main-iframe, gift card, ACH.
  { provider: "Square", hosts: ["web.squarecdn.com", "sandbox.web.squarecdn.com"], path: /^\/[^/]+\/single-card-element-iframe\.html$/, source: "https://web.squarecdn.com/v1/square.js" },
  // Card Fields (JS SDK v5 card-field and the card form's card-fields; v6 in open shadow roots). Not: smart/buttons, menu,
  // modal, Pay Later messages, wallet, altpayfields.
  { provider: "PayPal", hosts: ["www.paypal.com", "www.sandbox.paypal.com"], path: /^\/smart\/card-fields?$/, source: "https://github.com/paypal/paypal-checkout-components/blob/main/src/zoid/card-fields/component.jsx" },
  { provider: "PayPal", hosts: ["www.paypal.com", "www.sandbox.paypal.com"], path: /^\/web-sdk\/v6\/(?:card-fields-content|card-form-content)$/, source: "https://docs.paypal.ai/payments/methods/cards/js-sdk-v6-card-fields-one-time" },
  // eProtect: number, expiry and CVV in one frame.
  { provider: "Worldpay", hosts: ["request.eprotect.vantivcnp.com", "request.eprotect.vantivprelive.com", "request.eprotect.vantivpostlive.com"], path: /^\/eProtect\/eProtect(?:_[^/]*)?\.html$/, source: "https://request.eprotect.vantivcnp.com/eProtect/js/eProtect-iframe-client.min.js" },
  // Flex Microform v2: number and security code (fieldType in the fragment's JSON). Not: eCheck fields. And legacy 0.11.
  {
    provider: "Cybersource",
    hosts: ["flex.cybersource.com", "testflex.cybersource.com"],
    path: new RegExp(`^/microform/bundle/${VER}/iframe\\.html$`),
    card: (u) => oneOf(named(u, "fieldType"), ["number", "securityCode"]),
    source: "https://developer.cybersource.com/docs/cybs/en-us/digital-accept-flex/developer/all/rest/digital-accept/microform-integ-v2.html",
  },
  { provider: "Cybersource", hosts: ["flex.cybersource.com", "testflex.cybersource.com"], path: /^\/cybersource\/assets\/microform\/0\.11(?:\.\d+)*\/iframe\.html$/, source: "https://flex.cybersource.com/cybersource/assets/microform/0.11/flex-microform.min.js" },
  // Collect.js, inline (elementId) and lightbox (paymentType=cc), on NMI's hosts and any white-label gateway's: the
  // path is NMI's own. Not: check fields, ACH lightbox, Google Pay field.
  { provider: "NMI", hosts: [], anyHost: true, path: /^\/token\/inline\.php$/, card: (u) => oneOf(u.searchParams.get("elementId"), ["ccnumber", "ccexp", "cvv"]), source: "https://secure.nmi.com/token/Collect.js" },
  { provider: "NMI", hosts: [], anyHost: true, path: /^\/token\/lightbox\.php$/, card: (u) => u.searchParams.get("paymentType") !== "ck", source: "https://docs.nmi.com/docs/light-box-integration" },
  // Collect.js: card number, security code and expiry (type in the fragment). Not: other field types.
  {
    provider: "VGS",
    hosts: ["js.verygoodvault.com", "js3.verygoodvault.com"],
    path: /^\/vgs-collect\/[^/]+\/lib\/[^/]+\.html$/,
    card: (u) => {
      const t = /type["']?\s*[:=]\s*["']?([a-z-]+)/i.exec(safeDecode(u.hash) ?? u.hash)?.[1] ?? null;
      return oneOf(t, ["card-number", "card-security-code", "card-expiration-date"]);
    },
    source: "https://js.verygoodvault.com/vgs-collect/3.2.2/vgs-collect.js",
  },
  // iFrame: number and CVV. Not: the fraud frame.
  { provider: "Spreedly", hosts: ["core.spreedly.com"], path: /^\/v1\/embedded\/(?:number|cvv)-frame-[^/]*\.html$/, source: "https://core.spreedly.com/iframe/iframe-v1.min.js" },
  // Accept UI's lightbox (created hidden at load). Accept Hosted and Accept Customer are posted into a frame by a form:
  // matched by the form's action (content.ts providerCardFramesHere). Accept.js has no frame: its fields are the page's.
  { provider: "Authorize.net", hosts: ["js.authorize.net", "jstest.authorize.net"], path: /^\/v3\/acceptMain\/acceptMain\.html$/, source: "https://js.authorize.net/v3/AcceptUI.js" },
  { provider: "Authorize.net", hosts: ["accept.authorize.net", "test.authorize.net"], path: /^\/(?:payment\/payment|customer\/(?:manage|addPayment|editPayment))$/, source: "https://developer.authorize.net/api/reference/features/accept-hosted.html" },
  // Elements and hosted fields (type in #config). Not: relay, three_d_secure.
  {
    provider: "Recurly",
    hosts: ["api.recurly.com", "api.eu.recurly.com"],
    path: /^\/js\/v1\/(?:field|field-canary)\.html$/,
    card: (u) => {
      const config = /(?:^|&)config=([^&]*)/.exec(u.hash.replace(/^#/, ""))?.[1];
      let type: string | null = null;
      try {
        const parsed: unknown = config === undefined ? null : JSON.parse(safeDecode(config) ?? config);
        if (parsed !== null && typeof parsed === "object" && typeof (parsed as Record<string, unknown>).type === "string") type = (parsed as Record<string, string>).type!;
      } catch {
        type = null;
      }
      return oneOf(type, ["card", "number", "month", "year", "cvv"]);
    },
    source: "https://github.com/recurly/recurly-js/blob/master/lib/recurly/hosted-field.js",
  },
  // Components: the card component; Payment Components (card among others); a hosted checkout page in a frame. Not:
  // master and loader frames, the payment button and dialog.
  { provider: "Chargebee", hosts: ["js.chargebee.com"], path: /^\/assets\/cbjs-[^/]+\/v2\/component\.html$/, source: "https://js.chargebee.com/v2/chargebee.js" },
  { provider: "Chargebee", hosts: ["js.chargebee.com"], path: /^\/components\/v1\/payment\/component\.html$/, source: "https://js.chargebee.com/v2/chargebee.js" },
  { provider: "Chargebee", hosts: [], domains: ["chargebee.com"], path: /^\/hosted_pages\/checkout/, source: "https://js.chargebee.com/v2/chargebee.js" },
  // Card fields at checkout, one frame per field (seen live, not documented), and the earlier host.
  { provider: "Shopify", hosts: ["checkout.pci.shopifyinc.com"], path: /^\/build\/[^/]+\/(?:number|name|expiry|verification_value|issue_date|issue_number)-(?:ltr|rtl)\.html$/, source: "https://checkout.pci.shopifyinc.com/build/a8e4a94/number-ltr.html" },
  { provider: "Shopify", hosts: ["checkout.pci.shopifyinc.com", "checkout.shopifycs.com"], path: /^\/(?:number|name|expiry|verification_value)$/, source: "https://shopify.dev/changelog" },
];

/**
 * The host of [url] when it is a provider's card-entry frame ([CARD_ENTRY_FRAMES]; [frameName]: the frame element's
 * name, which some providers put the field in), or null: any other frame, plain http, or what is not a URL.
 */
export function paymentProviderCardFrame(url: string, frameName: string | null = null): string | null {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    return null;
  }
  if (u.protocol !== "https:") return null;
  const host = u.hostname.toLowerCase();
  for (const f of CARD_ENTRY_FRAMES) {
    const hostOk = f.anyHost === true || f.hosts.includes(host) || (f.domains ?? []).some((d) => host === d || host.endsWith("." + d));
    if (!hostOk || !f.path.test(u.pathname)) continue;
    if (f.card !== undefined && !f.card(u, frameName)) continue;
    return host;
  }
  return null;
}
