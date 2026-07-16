/**
 * Anti-phishing Trust Gate copy + render rules (design 2026-07-15-multi-tenant-endpoints §4.3),
 * rendered in the options page before EVERY server switch. Security-critical + copy-pinned: the
 * only identity the user is ever shown is the RAW origin the client will connect to — never a
 * server-supplied display name (an `instanceName` arrives only AFTER connecting, and an attacker's
 * branding must never render as verified). This module owns the exact strings so trustgate.test.ts
 * pins them and a wording drift breaks the test before it ships.
 *
 * LEAF module (no chrome import): the host parse uses WHATWG `URL` (present in the SW, the options
 * page, and node), so `node --test` loads it directly. Extension enrollment is a non-goal (design
 * §4.4), so there is NO enrollment-variant copy here — the ext gate is always the baseline (manual
 * repoint) case.
 */

/** Heading + body pinned verbatim from design §4.3 baseline copy. The `{origin}` sits BETWEEN them,
 *  rendered monospaced + visually dominant by the options page (never concatenated into a sentence,
 *  so a hostile host string can't smuggle punctuation into readable prose). */
export const TRUST_GATE_HEADING = "Connect to a different server?";
export const TRUST_GATE_BODY =
  "This server will store your encrypted vault and see your account activity (email, sign-ins, item counts). Only continue if you trust it.";

/** IDN defense (§4.3): a host with any punycode (`xn--`) label is shown in that ASCII form with this
 *  caution, so a look-alike Unicode homograph can't masquerade as a familiar host. */
export const TRUST_GATE_PUNYCODE_CAUTION =
  "This address uses international characters, shown here in their punycode (xn--) form. Make sure it is exactly the server you intend.";

/** Plain-http caution (§4.3): traffic to an `http://` origin (a LAN self-host) is not encrypted. */
export const TRUST_GATE_HTTP_CAUTION =
  "This is a plain http:// address — traffic to it is not encrypted in transit.";

/** True iff any label of the origin's host is a punycode (`xn--`) label — i.e. the host was an IDN
 *  that WHATWG URL canonicalization (serverurl.canonicalizeServerUrl) rendered to ASCII. */
export function hasPunycodeLabel(canonicalOrigin: string): boolean {
  let host: string;
  try {
    host = new URL(canonicalOrigin).hostname;
  } catch {
    return false;
  }
  return host.split(".").some((label) => label.startsWith("xn--"));
}

/** True for a plain-http origin (canonical origins are lowercase, so a prefix test is exact). */
export function isPlainHttp(canonicalOrigin: string): boolean {
  return canonicalOrigin.startsWith("http://");
}

export interface TrustGateView {
  /** The raw origin, shown monospaced + dominant — the ONLY identity rendered (§4.3). */
  origin: string;
  heading: string;
  body: string;
  /** The IDN caution to show, or null when the host is all-ASCII. */
  punycodeCaution: string | null;
  /** The plain-http caution to show, or null for an https origin. */
  httpCaution: string | null;
}

/** Assemble the gate's view model for a CANONICAL origin (serverurl.canonicalizeServerUrl output).
 *  Caller renders `origin` monospaced/dominant, the two cautions only when non-null. */
export function trustGateView(canonicalOrigin: string): TrustGateView {
  return {
    origin: canonicalOrigin,
    heading: TRUST_GATE_HEADING,
    body: TRUST_GATE_BODY,
    punycodeCaution: hasPunycodeLabel(canonicalOrigin) ? TRUST_GATE_PUNYCODE_CAUTION : null,
    httpCaution: isPlainHttp(canonicalOrigin) ? TRUST_GATE_HTTP_CAUTION : null,
  };
}
