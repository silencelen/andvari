/**
 * Anti-phishing Trust Gate copy + render rules (design 2026-11-15-onboarding-trust §4.4 typed-address root, §12.3;
 * design 2026-07-15-multi-tenant-endpoints §4.3), rendered in the options page before a typed server is pinned.
 * Security-critical + copy-pinned: the identity the person is shown is the RAW origin the client will connect to, then
 * the card line naming what the server calls itself — always beside its origin, never as a verified identity (T-R8) —
 * and the operator key's 32-hex short form for anyone who wants to check. This module owns the exact strings so
 * trustgate.test.ts pins them and a wording drift breaks the test before it ships.
 *
 * LEAF module (no chrome import): the host parse uses WHATWG `URL`, so `node --test` loads it directly.
 */

/** Approved wording (the design's own words, §12.3): the title at first use. */
export const TRUST_GATE_HEADING = "Connect to this server?";
/** Approved wording (decided on 2026-11-17): the title when a server is already set. */
export const TRUST_GATE_HEADING_SWITCH = "Switch to a different server?";
/** Approved wording (the design's own words, §12.3): what the server will see. */
export const TRUST_GATE_BODY =
  "This server will store your encrypted vault and see your account activity (email, sign-ins, item counts). Only continue if you trust it.";

/** Double quotation marks in every form a name could use to close the sentence's own quotes and start one of its own. */
const QUOTE_MARKS = /["«»“”„‟‹›⹂〝〞〟＂]/g;

/**
 * A card's name as it may sit inside the quotes of a sentence. The name is data the
 * server chose (§2.2 `name`, up to 64 bytes), so the quotation marks that could close the sentence's quotes are
 * removed: "Smith Vault” — verified by andvari. “" can no longer end the quote and speak in andvari's voice. Apostrophes
 * stay (a name like "Bob's vault" is common, and the sentence uses no single quotes).
 */
export function quotedCardName(name: string): string {
  return name.replace(QUOTE_MARKS, "");
}

/**
 * Approved wording (the design's own words, §4.4, as every other client shows them; the wording page's PQ10): the
 * typed-address card line, with a full stop; {0} the card's name. Its words do not change; only its mark did.
 */
export const TRUST_GATE_CARD_LINE = "It calls itself “{0}” — nobody you know has vouched for it.";

/** Approved wording (the design's own words, §4.4): the password label; {0} the email, {1} the server. */
export const MASTER_PASSWORD_FOR_ON = "Master password for {0} on {1}";
/** Approved wording (decided on 2026-11-17): the password label while no email is typed yet; {0} the server. */
export const MASTER_PASSWORD_ON = "Master password on {0}";

/** Approved wording (decided on 2026-11-17): the operator key's short form, for anyone who wants to check it; {0} the key in groups of eight. */
export const OPERATOR_KEY_LINE = "Operator key: {0}";

/** `{0}`, `{1}`, … in [template] replaced by [values] in one pass (errors.ts fillApproved's twin; this module is a leaf). */
function fill(template: string, ...values: string[]): string {
  return template.replace(/\{(\d+)\}/g, (slot, n: string) => (Number(n) < values.length ? values[Number(n)]! : slot));
}

/** §4.4: the typed-address card line. The name is the card's, shown as plain text; the origin sits apart, dominant. */
export function trustGateCardLine(name: string): string {
  return fill(TRUST_GATE_CARD_LINE, quotedCardName(name));
}

/**
 * §4.4: "Every screen that asks for an existing account's master password names the account and the instance: Master
 * password for *email* on *name* (*origin*)." The popup's password label. The name is shown beside its origin (T-R8);
 * with no email typed yet the account part is left out, and with no card name the origin alone names the server.
 */
export function masterPasswordLabel(email: string, name: string | null, origin: string): string {
  const server = name === null || name === "" ? origin : `${name} (${origin})`;
  return email.trim() === "" ? fill(MASTER_PASSWORD_ON, server) : fill(MASTER_PASSWORD_FOR_ON, email.trim(), server);
}

/** §4.4: the operator key's short form, for anyone who wants to check it with the operator. */
export function trustGateOperatorLine(shortFp: string): string {
  return shortFp === "" ? "" : fill(OPERATOR_KEY_LINE, shortFp.replace(/(.{8})(?=.)/g, "$1 "));
}

/** Approved wording (the released extension's own words): IDN defense, a host with any punycode (`xn--`) label is shown in that ASCII form with this caution, so a
 *  look-alike Unicode homograph can't masquerade as a familiar host. */
export const TRUST_GATE_PUNYCODE_CAUTION =
  "This address uses international characters, shown here in their punycode (xn--) form. Make sure it is exactly the server you intend.";

/** Approved wording (the released extension's own words): the plain-http caution; the grammar allows it only for localhost and 127.0.0.1 (development), which is not encrypted. */
export const TRUST_GATE_HTTP_CAUTION =
  "This is a plain http:// address — traffic to it is not encrypted in transit.";

/** True iff any label of the origin's host is a punycode (`xn--`) label. */
export function hasPunycodeLabel(canonicalOrigin: string): boolean {
  let host: string;
  try {
    host = new URL(canonicalOrigin).hostname;
  } catch {
    return false;
  }
  return host.split(".").some((label) => label.startsWith("xn--"));
}

/** The origin cut into the pieces a line may break between, so that on a narrow screen it wraps after `://` and before
 *  a `.`, `-` or `:` of its own, never inside a label (seen rendered at phone width: the gate showed
 *  "https://vault.smith.exampl" over "e", which is harder to check letter by letter). Joined, the pieces are the origin
 *  exactly; the page puts a `<wbr>` between them, which adds no character to what is shown or copied. */
export function originBreakPieces(origin: string): string[] {
  const out: string[] = [];
  const scheme = origin.indexOf("://");
  let rest = origin;
  if (scheme >= 0) {
    out.push(origin.slice(0, scheme + 3));
    rest = origin.slice(scheme + 3);
  }
  for (const piece of rest.split(/(?=[.:-])/)) if (piece !== "") out.push(piece);
  return out;
}

/** True for a plain-http origin (canonical origins are lowercase, so a prefix test is exact). */
export function isPlainHttp(canonicalOrigin: string): boolean {
  return canonicalOrigin.startsWith("http://");
}

export interface TrustGateView {
  /** The raw origin, shown monospaced + dominant. */
  origin: string;
  heading: string;
  /** The card line ("It calls itself …"). */
  cardLine: string;
  /** The operator key's short form line ("" when it could not be computed). */
  operatorLine: string;
  body: string;
  punycodeCaution: string | null;
  httpCaution: string | null;
}

/** Assemble the gate's view model for a CANONICAL origin and the card the worker verified there. */
export function trustGateView(canonicalOrigin: string, card: { name: string; operatorShortFp: string; switching: boolean }): TrustGateView {
  return {
    origin: canonicalOrigin,
    heading: card.switching ? TRUST_GATE_HEADING_SWITCH : TRUST_GATE_HEADING,
    cardLine: trustGateCardLine(card.name),
    operatorLine: trustGateOperatorLine(card.operatorShortFp),
    body: TRUST_GATE_BODY,
    punycodeCaution: hasPunycodeLabel(canonicalOrigin) ? TRUST_GATE_PUNYCODE_CAUTION : null,
    httpCaution: isPlainHttp(canonicalOrigin) ? TRUST_GATE_HTTP_CAUTION : null,
  };
}
