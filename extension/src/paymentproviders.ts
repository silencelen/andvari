/**
 * Payment providers that take the card in a frame of their own (hosted fields). Round-7 review H1: where a tab embeds
 * one of these frames, or has card fields in any cross-origin frame, the card fields are not the page's own, and a
 * field the page shows over or beside them may be a skimmer's overlay that a script owning the page draws to look like
 * them (no visibility rule can tell the two apart). andvari then fills no card into the tab's top frame or any
 * same-origin frame, and the popup names the provider's host and offers to copy from the app instead. The frame's own
 * src is checked, not only its report: on Safari the content script may not run in the provider's frame without the
 * per-site permission.
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
