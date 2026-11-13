/**
 * Pure field-detection engine — no chrome.*, no side effects. Classification defers to the
 * canonical, vector-tested classify() in urimatch.ts (verbatim port of web/src/vault/urimatch.ts);
 * this module only adapts DOM inputs (and, Tier 1, card-only selects) into FieldSignals and
 * groups them into fillable login forms.
 *
 * Scans are visible-fields-only: hidden inputs are where sites stash tokens and where phishing
 * kits hide credential sinks — and a multi-step page's not-yet-shown password field must NOT
 * collapse step 1 into a normal login form.
 */
// Explicit .ts so the node --test runner (detect.cards.test.ts) can resolve this transitively —
// esbuild (bundle) + tsc (allowImportingTsExtensions) accept it too; node ESM needs the extension.
import { TABLES, fold } from "./cardfill.ts"; // no runtime cycle: cardfill's detect import is type-only
import { classify, type FieldKind, type FieldSignal } from "./urimatch.ts";

/** A scope that can own a login form: the <form>, a nearest-common container, or the scan root. */
export type Scope = Element | Document | ShadowRoot;

/** What a Field may be backed by (Tier 1, design 2026-07-23-card-autofill-tier1 §1): selects
 *  join the pool for the select-meaningful CARD kinds only. LoginForm's slots stay
 *  HTMLInputElement — selects are hard-set kind:"none"/textLike:false at collect(), so they can
 *  never reach a login slot; every narrowing back to HTMLInputElement is an `instanceof` guard,
 *  and `as HTMLInputElement` casts are FORBIDDEN here ([T15] — a cast would compile a select
 *  into content.ts's setValue, which throws). */
export type FillableControl = HTMLInputElement | HTMLSelectElement;

export interface LoginForm {
  /** "username-step": a lone username field + submit control, no password (multi-step step 1). */
  kind: "login" | "username-step";
  form: HTMLFormElement | null;
  /** form ?? nearest common container of the grouped fields (scan root for stray singles). */
  container: Scope;
  username: HTMLInputElement | null;
  password: HTMLInputElement | null;
  /** Generator fill targets: every new-password field (primary + confirm). Empty when !isSignup. */
  newPasswords: HTMLInputElement[];
  /** H04 (2026-09-13 audit): the field whose value the CAPTURE engine records as "the password"
   *  — distinct from `password`, which is the FILL target. On a change-password form the fill
   *  target is the current-password field (that is what a login fill must write), but the value
   *  worth saving is the NEW one; reading `password` for capture saved the OLD password (or, with
   *  the generator, nothing the vault ever learned — the generated value went only into
   *  newPasswords). Chosen by chooseCapturePassword; null only on a username-step form. */
  capturePassword: HTMLInputElement | null;
  isSignup: boolean;
  /** CVV-negative rule (cards design 2026-07-09): true when the form's LONE password-typed
   *  field is name/id-token-matched cvv|cvc|csc — a checkout CVV box, not a login password.
   *  The capture engine must not offer save/update for it (an "update" would overwrite the
   *  stored merchant password with a CVV). Since the 2026-07-27 fix for the owner-reported
   *  checkout failure, the FILL surfaces consult it too: content.ts maybeOpen cedes a
   *  suppressSave form's card fields to the C1 chip, and the popup-driven fill skips
   *  suppressSave forms — core demotes the CVV field-locally BEFORE the password rule, so the
   *  old "fill/dropdown behavior is deliberately unchanged" stance was a parity gap, not a rule. */
  suppressSave: boolean;
}

/** autocomplete tokens whose canonical hint name differs even after classify()'s own [-_] strip. */
const AUTOCOMPLETE_HINT_MAP: Record<string, string> = {
  "one-time-code": "otpcode",
  "cc-number": "cardnumber",
  "cc-csc": "creditcardsecuritycode",
};

/** Mirrors urimatch's NAME_NEGATIVE (not exported there) — gates the username-fallback pool. */
const NAME_NEGATIVE_RX = /search|otp|captcha|code|query|phone/;

/** CVV keywords for the save-suppression / CSC-demotion rule — FULL core `CSC_DEMOTION` parity
 *  (FieldClassifier.kt), whole-token-run matched, never substring. `securitycode` +
 *  `cardverification` graduated in with S3 (design 2026-07-10-extension-card-fill [A7]): the
 *  shipped 0.13.0 set (cvv/cvc/csc) was narrower than core, so a checkout `securityCode` password
 *  slipped the save-suppression and could overwrite a stored merchant password with a CVV. */
const CVV_TOKENS = ["cvv", "cvc", "csc", "securitycode", "cardverification"];

/** Card field kinds the in-page card-fill path (S3) recognises — the extension's projection of
 *  core `FieldKind`'s CC_* set. Reported to the SW as METADATA ONLY (never values, design [A2])
 *  and index the fill executor's per-field value setter. */
export type CardFieldKind = "cardnumber" | "cardexpiry" | "cardexpmonth" | "cardexpyear" | "cardname" | "cardcvv" | "cardtype" | "cardpostal";

/** Card autocomplete hints (normalized: lowercase, [-_] stripped) → kind — mirrors core
 *  `FieldClassifier.CARD_HINTS`. fieldSignalOf already maps cc-number→cardnumber and
 *  cc-csc→creditcardsecuritycode via AUTOCOMPLETE_HINT_MAP; re-normalizing here is idempotent. */
const CARD_HINTS: Record<string, CardFieldKind> = {
  cardnumber: "cardnumber",
  creditcardnumber: "cardnumber",
  ccnumber: "cardnumber",
  creditcardsecuritycode: "cardcvv",
  cccsc: "cardcvv",
  creditcardexpirationmonth: "cardexpmonth",
  ccexpmonth: "cardexpmonth",
  creditcardexpirationyear: "cardexpyear",
  ccexpyear: "cardexpyear",
  creditcardexpirationdate: "cardexpiry",
  ccexp: "cardexpiry",
  ccname: "cardname",
  cctype: "cardtype",
};

/** cardfill.json keyword-group kind spellings (engine-neutral autocomplete tokens) → this
 *  module's kinds — total over the compiled-in TABLES.keywords copy (vector-deep-equalled). */
const VECTOR_CARD_KIND: Record<string, CardFieldKind> = {
  "cc-number": "cardnumber",
  "cc-exp-month": "cardexpmonth",
  "cc-exp-year": "cardexpyear",
  "cc-exp": "cardexpiry",
  "cc-csc": "cardcvv",
  "cc-name": "cardname",
  "cc-type": "cardtype",
  "cc-postal": "cardpostal", // G3 [X3-A4c]
};

/** [X3-A4b] one of the four silent-gap sites adding CC_POSTAL breaks NO compile check on: the
 *  cardfill.json `keywords` groups drive `CARD_NAME_KINDS` by a per-group `kind` lookup, and a
 *  `VECTOR_CARD_KIND[g.kind]!` non-null assertion would SILENTLY map a future unmapped vector kind
 *  to `undefined`. Throw at MODULE INIT instead so a keyword group whose kind this module has no
 *  CardFieldKind for reds loudly the moment detect.ts loads (any suite importing it). */
function vectorCardKind(kind: string): CardFieldKind {
  const k = VECTOR_CARD_KIND[kind];
  if (k === undefined) throw new Error(`detect.ts: cardfill.json keyword group kind '${kind}' has no CardFieldKind mapping`);
  return k;
}

/** Card name/id/label token runs (whole-token-run matched) → kind — the SINGLE normative
 *  in-bundle copy is cardfill.ts `TABLES.keywords` ([U8]: ordered groups, deep-equalled against
 *  cardfill.json; core asserts SEQUENCE equality against the same section). Group ORDER is
 *  load-bearing: exp-month/-year before the generic exp group ("expirymonth" would also
 *  whole-run-match the exp group's "expiry"), and the trailing bare-`creditcard` group ([U1])
 *  fires only when no specific kind matched. */
const CARD_NAME_KINDS: [readonly string[], CardFieldKind][] = TABLES.keywords.map((g) => [g.keywords, vectorCardKind(g.kind)]); // [X3-A4b] THROWS on an unmapped vector kind

/** HTML types the card NAME-keyword fallback may fire from (core `CARD_FALLBACK_HTML_TYPES`
 *  parity): the keyword is the card signal, never numeric-ness; a password type is NEVER
 *  name-classified as a card field here — only the form-level CSC demotion may relabel it. */
const CARD_FALLBACK_HTML_TYPES = new Set(["", "text", "tel", "number"]);

/** name/id/label → lowercase ASCII tokens: split on non-alphanumerics, camelCase boundaries, and
 *  letter↔digit boundaries ("cardVerificationValue" → [card,verification,value]; "cvv2" →
 *  [cvv,2] — checkout CVVs are routinely named cvv2/cvc2, Visa's own branding). PARITY since
 *  Tier 2 ([U9]/§1.4): core FieldClassifier.tokens() carries the same digit boundary at its two
 *  card call sites (step-2 CSC demotion + step-4 card keywords/gift guard; legacyClassify stays
 *  substring-based, untouched), so trailing-digit names ("cardNumber2", multi-card field arrays)
 *  now classify on BOTH engines — pinned by the flipped cardform.json alignment case. One
 *  recorded residual seam: an anchorless lone `cvv2` password still diverges (core demotes
 *  field-locally, the extension only form-level) — parity claims must not cover it. Feeds card
 *  CLASSIFICATION (labels per source string, [U5]), the [T10] gift guard, and the CVV
 *  save-suppression rule. */
function tokens(raw: string): string[] {
  const out: string[] = [];
  let sb = "";
  const flush = () => {
    if (sb !== "") {
      out.push(sb.toLowerCase());
      sb = "";
    }
  };
  for (let i = 0; i < raw.length; i++) {
    const c = raw.charAt(i);
    const isDigit = c >= "0" && c <= "9";
    const isUpper = c >= "A" && c <= "Z";
    if (!isDigit && !isUpper && !(c >= "a" && c <= "z")) {
      flush(); // separator (incl. non-ASCII — fine for a suppression heuristic)
      continue;
    }
    if (sb !== "") {
      const p = raw.charAt(i - 1); // sb non-empty ⇒ raw[i-1] was appended (separators flush)
      const pDigit = p >= "0" && p <= "9";
      const nextLower = i + 1 < raw.length && raw.charAt(i + 1) >= "a" && raw.charAt(i + 1) <= "z";
      if (isUpper && (pDigit || (p >= "a" && p <= "z") || (p >= "A" && p <= "Z" && nextLower))) flush();
      else if (isDigit !== pDigit) flush(); // letter↔digit boundary (see doc comment)
    }
    sb += c;
  }
  flush();
  return out;
}

/** WHOLE-TOKEN-RUN match (core FieldClassifier.tokenMatch parity): kw matches iff it EQUALS
 *  the concatenation of a contiguous run of whole tokens — it can neither start nor end
 *  mid-token ("cvc" never matches cv_code or mycvv; "cvv" DOES match cvv2's [cvv,2] run head). */
function tokenMatch(toks: string[], kw: string): boolean {
  for (let i = 0; i < toks.length; i++) {
    let acc = "";
    for (let j = i; j < toks.length; j++) {
      acc += toks[j]!;
      if (acc.length > kw.length) break;
      if (acc.length === kw.length) {
        if (acc === kw) return true;
        break;
      }
    }
  }
  return false;
}

/** True when a field's name/id reads as a card security code — exported for the cross-suite
 *  pin test (web/src/extension-pins.test.ts). Pure string → verdict, no DOM. */
export function isCvvNameOrId(nameOrId: string): boolean {
  const toks = tokens(nameOrId);
  return CVV_TOKENS.some((kw) => tokenMatch(toks, kw));
}

/** Gift/loyalty negative guard (§3/F13, [T10]): a name/id-token cardnumber verdict is SUPPRESSED
 *  when the SAME string's tokens also read gift-ish — a gift-card PAN must never anchor a card
 *  form. Suppress-only and anchor-only: other card kinds pass untouched (a "giftCardExpiry"
 *  stays cardexpiry — harmless without an anchor). The autocomplete-hint path is deliberately
 *  NOT guarded (an explicit cc-number hint is the site's own claim — Chromium parity). */
// i18n number tokens ride with i18n suppressors (§1.3): "numeroCarteCadeau" must not anchor.
const GIFT_SUPPRESS_TOKENS = ["gift", "egift", "voucher", "loyalty", "coupon", "cadeau", "geschenk", "regalo"];

/** [X3-A1](i) shipping-suppressor tokens (whole-token-run matched, [T10]/gift-guard shape): a
 *  cardpostal verdict whose producing string ALSO reads shipping/delivery is suppressed — billing
 *  zip must never fill/overwrite a shipping zip on a mixed single-form checkout ("shippingPostalCode"
 *  → cardpostal + "shipping" run → suppressed). Suppress-only + postal-only: other kinds pass. */
const SHIP_SUPPRESS_TOKENS = ["ship", "shipping", "delivery", "deliver", "recipient", "lieferung", "liefer", "livraison", "envio", "spedizione"];

/** A per-string token verdict. Beyond the card kinds, two TERMINAL suppression sentinels — distinct
 *  from null (no verdict at all) because suppression is terminal for the string, so the §8 htmlId
 *  retry / label pass must not resurrect the kind off a cleaner-looking source: "gift" (a suppressed
 *  cardnumber, [T10]) and "shipsuppress" (a suppressed cardpostal, [X3-A1](i)). */
type CardTokenVerdict = CardFieldKind | "gift" | "shipsuppress" | null;

/** One name/id string → card verdict via the token runs. See CardTokenVerdict for the sentinels. */
function cardKindFromTokens(raw: string): CardTokenVerdict {
  // [W4] ASCII-fold at THIS chokepoint (not inside tokens(), which also feeds isCvvNameOrId →
  // suppressSave, a login-capture verdict that MUST stay byte-identical): "Prüfnummer" → folded
  // "pruefnummer" → tokens → the shipped cc-csc keyword matches (raw tokens() splits at ü and never
  // does). Covers classifyCardField name+id, classifyCardSelect, cardKindFromLabels, classifyCardRadio.
  const toks = tokens(fold(raw));
  for (const [kws, kind] of CARD_NAME_KINDS) {
    if (kws.some((kw) => tokenMatch(toks, kw))) {
      if (kind === "cardnumber" && GIFT_SUPPRESS_TOKENS.some((kw) => tokenMatch(toks, kw))) return "gift";
      if (kind === "cardpostal" && SHIP_SUPPRESS_TOKENS.some((kw) => tokenMatch(toks, kw))) return "shipsuppress"; // [X3-A1](i)
      return kind;
    }
  }
  return null;
}

/** A token verdict that is a real card kind (neither null nor a suppression sentinel). */
function isSuppressSentinel(k: CardTokenVerdict): k is "gift" | "shipsuppress" {
  return k === "gift" || k === "shipsuppress";
}

/** [U6] label-source bounds: a string longer than 60 chars or 8 tokens is IGNORED — help-sentence
 *  labels over-match ("…cannot be combined with card number payments"). */
const LABEL_MAX_CHARS = 60;
const LABEL_MAX_TOKENS = 8;

/** [U5] label source strings, classified PER-STRING: per-string tokenization, per-string verdict,
 *  per-string [T10] gift guard — a token run must NEVER span a source boundary (aria-label
 *  "Rewards card" + placeholder "Number of points" would otherwise fabricate a `cardnumber` run),
 *  so concatenation is forbidden. The first verdict is TERMINAL, gift included — same rule as the
 *  name→id retry: a string that positively identified a gift-card number must not be out-voted by
 *  a later, cleaner-looking source. */
function cardKindFromLabels(labels: readonly string[] | undefined): CardFieldKind | null {
  if (!labels) return null;
  for (const s of labels) {
    // [U6] budget on the FOLDED tokenization — the same stream the verdict runs on (the fold is
    // char→string within a token, so counts can't diverge today; keeping one stream makes that
    // an invariant instead of a coincidence).
    if (s.length > LABEL_MAX_CHARS || tokens(fold(s)).length > LABEL_MAX_TOKENS) continue; // [U6] ignored, not a verdict
    const k = cardKindFromTokens(s);
    if (k !== null) return isSuppressSentinel(k) ? null : k;
  }
  return null;
}

/** Per-field card classification — pure (FieldSignal → kind), no DOM. Fires ONLY in the
 *  `classify() == none` gap (design [A8], core `FieldClassifier` step-4 parity): every field the
 *  login classifier decided keeps its verdict, so a card kind can never outrank USERNAME/PASSWORD
 *  and login verdicts on card-free forms stay bit-identical. Autocomplete card hints win first
 *  (a masked cc-csc password is a NEGATIVE login hint → lands in the gap here); then name/id token
 *  runs, but only for card-fallback HTML types (never a password type — the CSC demotion below is
 *  the only path that relabels a password). §8/F5: the token pass runs over htmlNameOrId first and
 *  RETRIES over htmlId only when the name produced NO card verdict (a suppressed gift verdict IS a
 *  verdict); the gift guard evaluates against whichever string produced the verdict ([T10]).
 *  §1.1/[U5]: label SOURCE STRINGS (collect() builds the ordered list — aria-label · el.labels ·
 *  aria-labelledby targets · placeholder) are the WEAKEST signal, consulted last and only when
 *  neither name nor id produced any verdict; same fallback-HTML-type gate as the name pass (a
 *  password type is never label-classified either). */
export function classifyCardField(sig: FieldSignal, htmlId?: string | null, labels?: readonly string[]): CardFieldKind | null {
  if (classify(sig) !== "none") return null;
  const hints = (sig.hints ?? []).map((h) => h.toLowerCase().replace(/[_-]/g, ""));
  for (const h of hints) {
    const k = CARD_HINTS[h];
    if (k) return k;
  }
  if (!CARD_FALLBACK_HTML_TYPES.has((sig.htmlType ?? "").toLowerCase())) return null;
  const byName = cardKindFromTokens(sig.htmlNameOrId ?? "");
  if (isSuppressSentinel(byName)) return null; // gift / shipsuppress are TERMINAL (no id/label retry)
  if (byName) return byName;
  const byId = htmlId ? cardKindFromTokens(htmlId) : null;
  if (byId !== null) return isSuppressSentinel(byId) ? null : byId;
  return cardKindFromLabels(labels);
}

/** The card kinds a <select> can meaningfully be (§1): one row of an enumerable set. A PAN/CVV/
 *  cardholder name is free text — a select claiming one is decoration or garbage, so any other
 *  card verdict returns null here (never remapped, never anchoring — §0: a <select> can never
 *  anchor nor be a PAN/CVV/name field). */
const SELECT_CARD_KINDS: ReadonlySet<CardFieldKind> = new Set(["cardexpmonth", "cardexpyear", "cardexpiry", "cardtype"]);

/** Per-select card classification — autocomplete hints first (same normalized CARD_HINTS map),
 *  then name/id token runs (§8 order, gift guard per-string), then label source strings ([U5]
 *  parity with the input path — weakest, last, per-string). Deliberately NO
 *  CARD_FALLBACK_HTML_TYPES check (that's input vocabulary) and NO classify() gap-gate: a select
 *  is definitionally not a login credential, so the login engine is never consulted. */
export function classifyCardSelect(nameOrId: string | null, htmlId: string | null, hints: readonly string[], labels?: readonly string[]): CardFieldKind | null {
  const restricted = (k: CardTokenVerdict): CardFieldKind | null =>
    k !== null && !isSuppressSentinel(k) && SELECT_CARD_KINDS.has(k) ? k : null;
  for (const h of hints) {
    const k = CARD_HINTS[h.toLowerCase().replace(/[_-]/g, "")];
    if (k) return restricted(k);
  }
  const byName = cardKindFromTokens(nameOrId ?? "");
  if (byName !== null) return restricted(byName); // any card verdict (even a restricted-away one) stops the retries
  const byId = htmlId ? cardKindFromTokens(htmlId) : null;
  if (byId !== null) return restricted(byId);
  return restricted(cardKindFromLabels(labels));
}

/** [W8] V3 radio card-type classifier — a cardtype-ONLY restriction (TIGHTER than SELECT_CARD_KINDS:
 *  a cardMonth/expiryYear radio must NOT classify), so only a brand radio group is ever collected.
 *  Same name/id/label/hint order + per-string gift guard as classifyCardSelect, but NEVER the login
 *  classify() — a `name=rememberLogin` radio must be inert (none), never poison the login pool. Any
 *  non-cardtype card verdict on name still stops the id/label retries (kind-restricted-away → null).*/
export function classifyCardRadio(nameOrId: string | null, htmlId: string | null, hints: readonly string[], labels?: readonly string[]): CardFieldKind | null {
  const restricted = (k: CardTokenVerdict): CardFieldKind | null => (k === "cardtype" ? "cardtype" : null);
  for (const h of hints) {
    const k = CARD_HINTS[h.toLowerCase().replace(/[_-]/g, "")];
    if (k) return restricted(k);
  }
  const byName = cardKindFromTokens(nameOrId ?? "");
  if (byName !== null) return restricted(byName);
  const byId = htmlId ? cardKindFromTokens(htmlId) : null;
  if (byId !== null) return restricted(byId);
  return restricted(cardKindFromLabels(labels));
}

/** Form-level CSC demotion — pure (kind + type + name/id → kind). A password-typed field named
 *  like a security code, sitting ON a card form (a cardnumber anchor is present — the caller only
 *  invokes this then), IS the CVV: name-based parity with core `CardForm.refine`'s cluster
 *  demotion. This keeps login verdicts bit-identical (it never runs on a card-free form) while
 *  letting the fill executor reach a masked CVV box. §8/F29: name and id are checked
 *  INDEPENDENTLY — the shipped single `name || id` let `name="field_7" id="cardCvc"` slip the
 *  demotion; suppression-side widening is fail-safe. */
export function demoteCsc(kind: CardFieldKind | null, htmlType: string, name: string, id: string): CardFieldKind | null {
  if (!kind && htmlType.toLowerCase() === "password" && (isCvvNameOrId(name) || isCvvNameOrId(id))) return "cardcvv";
  return kind;
}

const SUBMIT_TEXT_RX = /sign.?in|log.?in|continue|next|submit|anmelden|einloggen/i;

/** input types that never hold a fillable credential — a "show password" checkbox or a "Login"
 *  submit whose name/id contains pass/login would otherwise classify() as password/username. */
const NON_FILLABLE_TYPES = new Set([
  "checkbox", "radio", "submit", "button", "reset", "image", "file", "hidden", "color", "range",
]);

/** Ancestor levels a formless field may climb looking for siblings / a submit control before it
 *  is treated as standalone — keeps a real widget's fields together without reaching unrelated
 *  widgets near <body>. */
const FORMLESS_SCOPE_DEPTH = 6;

/** DOM input/select → FieldSignal. autocomplete tokens pass through as hints — classify()
 *  lowercases and strips [-_], so "current-password"/"new-password" land on the canonical hint
 *  sets; the map above covers the three whose Android-hint spelling differs. Selects ride the
 *  same shape: `htmlType` = el.type ("select-one") — never login-classified (collect() hard-sets
 *  their kind), but the card path reads hints/name off the identical signal. */
export function fieldSignalOf(input: FillableControl): FieldSignal & { isNewPassword: boolean } {
  const tokens = (input.getAttribute("autocomplete") ?? "")
    .trim()
    .toLowerCase()
    .split(/\s+/)
    .filter((t) => t !== "" && t !== "on" && t !== "off");
  return {
    hints: tokens.map((t) => AUTOCOMPLETE_HINT_MAP[t] ?? t),
    htmlType: input.type,
    htmlNameOrId: input.name || input.id || null,
    isNewPassword: tokens.includes("new-password"),
  };
}

/** Submit-shaped control: button[type=submit]/input[type=submit|image], or a button/link/
 *  role=button whose text reads like a login action. textContent ≈ visible text here —
 *  innerText forces layout and this must stay cheap enough to run per click. */
export function isSubmitLike(el: Element): boolean {
  if (el instanceof HTMLInputElement)
    return el.type === "submit" || el.type === "image" || (el.type === "button" && SUBMIT_TEXT_RX.test(el.value));
  if (el instanceof HTMLButtonElement) return el.type === "submit" || SUBMIT_TEXT_RX.test(el.textContent ?? "");
  if (el instanceof HTMLAnchorElement || el.getAttribute("role") === "button")
    return SUBMIT_TEXT_RX.test(el.textContent ?? "");
  return false;
}

interface Field {
  input: FillableControl;
  kind: FieldKind;
  isNewPassword: boolean;
  /** Username-fallback eligibility: unclassified text/email with no negative name signal. */
  textLike: boolean;
  /** Per-field card kind (pre-demotion, S3) — null on non-card fields. Only ever non-null in the
   *  `classify() == none` gap, so adding it never perturbs login grouping on card-free forms. */
  cardKind: CardFieldKind | null;
}

/** [T15] the ONE narrowing shape back to input-backed fields — an `instanceof` type guard, never
 *  a cast. Selects are hard-set kind:"none"/textLike:false at collect(), so every password/
 *  username/textLike discharge below is runtime-guaranteed to pass this guard. */
interface InputField extends Field {
  input: HTMLInputElement;
}
function isInputField(f: Field): f is InputField {
  return f.input instanceof HTMLInputElement;
}

/** offsetParent is null for position:fixed elements even when visible — hence the rects check. */
function isRendered(el: HTMLElement): boolean {
  return el.offsetParent !== null || el.getClientRects().length > 0;
}

/**
 * A field the page renders but the person cannot see is not one this extension fills (round-5 review C1). Detection
 * collects only fields that pass the page-time rules ([visibilityOf] at [MIN_OPACITY_DETECT]; a select or radio drawn
 * through a proxy is excused the opacity, size and hit rules; "off the page" means outside both the page and the
 * field's scrolling container, so a fixed login modal inside a smaller scroller is on the page). A card fill holds each
 * field to the full rules ([probeVisibility] with `fill`). Shared by login and card detection on every target.
 *
 * Round-7 review: rules like these cannot win against a script that owns the top frame, which controls rendering. The
 * structural defence is elsewhere (paymentproviders.ts: no card fill into a page whose card fields are a provider's
 * frames); these rules are defence in depth for first-party card forms.
 */
function isVisible(el: HTMLElement): boolean {
  return isRendered(el) && visibilityOf(probeVisibility(el, { onScreen: false, hitTest: false }), proxiedAtDetection(el)) === "ok";
}

/**
 * At detection: a control pages routinely draw through a proxy (a select under a custom dropdown, a radio under a
 * styled label) is collected, though its own box may be transparent, tiny or covered while it is the one the page
 * reads. Only the rules a proxy cannot excuse apply to it (not hidden, not off the page).
 */
export function proxiedAtDetection(el: Element): boolean {
  return el instanceof HTMLSelectElement || (el instanceof HTMLInputElement && el.type === "radio");
}

/**
 * At fill time (round-7 review, regression 2): only what a proxy routinely draws and what carries no number or code
 * may be filled while its own box cannot be seen: a radio (the brand), and a select for the expiry month or year or
 * the brand, in the chosen field's form. The chosen field itself is never excused: it gets every rule.
 */
export function proxiedAtFill(el: Element, kind: CardFieldKind): boolean {
  if (el instanceof HTMLInputElement && el.type === "radio") return true;
  return el instanceof HTMLSelectElement && (kind === "cardexpmonth" || kind === "cardexpyear" || kind === "cardtype");
}

/** One element's computed styles that decide whether it, and what it holds, can be seen. */
export interface StyleFacts {
  display: string;
  visibility: string;
  opacity: string;
  /** `filter` (fill-time read; absent at detection). */
  filter?: string;
  /** The first of `mask-image`, `-webkit-mask-image`, `-webkit-mask-box-image` that is not "none" (fill-time read). */
  mask?: string;
  /** The box the mask is laid over (this element's), in viewport coordinates, when there is a mask. */
  maskBox?: Box;
  /** `mix-blend-mode` (fill-time read). */
  blend?: string;
}

/** How a field draws what is typed into it: its text colours, background and font size. */
export interface InkFacts {
  color: string;
  /** `-webkit-text-fill-color`, which paints the text over `color` where it is set. */
  textFill: string;
  background: string;
  backgroundImage: string;
  fontSize: string;
}

export interface Box {
  left: number;
  top: number;
  width: number;
  height: number;
}

/** What decides whether a field is one a person can see. Gathered from the DOM by [probeVisibility]. */
export interface VisibilityFacts {
  /** The field's styles, then each ancestor's (across shadow hosts), innermost first. */
  chain: ReadonlyArray<StyleFacts>;
  /** How the field draws its text; null when not read (detection). */
  ink: InkFacts | null;
  /** The field's box, in viewport coordinates. */
  rect: Box;
  /** Where the field may lie and be on the page, in viewport coordinates: the page's extent and, when it has one, its
   *  nearest scrolling container's content (round-6 review M2). Outside all of them is off the page. */
  extents: ReadonlyArray<Box>;
  /** The viewport, when the field must be on screen now; null otherwise. */
  viewport: { width: number; height: number } | null;
  /** Whether something paints over the field at one of its sample points ("other"), the field is what shows at all of
   *  them ("self"), or it was not tested (null: off screen, or the caller did not ask). */
  hit: "self" | "other" | null;
}

/** Why a field is not visible, or "ok". */
export type VisibilityVerdict = "ok" | "hidden" | "transparent" | "filtered" | "clipped" | "blended" | "unreadable" | "tiny" | "offpage" | "offscreen" | "covered";

/** The smallest box, in CSS pixels, a field a person can use is drawn in. */
export const MIN_FIELD_PX = 8;
/** The smallest text, in CSS pixels, a person can read what was filled in. */
export const MIN_FONT_PX = 6;
/** Below this combined opacity (every ancestor's, any filter's and any mask's) a field a card is filled into is too faint. */
export const MIN_OPACITY = 0.9;
/** What detection collects at all: anything fainter is not a field (the fill holds each field to [MIN_OPACITY]). */
export const MIN_OPACITY_DETECT = 0.1;
/** Text fainter than this does not show what was filled in (round-7 review). */
export const MIN_TEXT_ALPHA = 0.5;

/** PURE: an amount of a filter function or a colour alpha ("0.5", "50%"); NaN when it is neither. */
function amount(v: string): number {
  const t = v.trim();
  if (t === "") return Number.NaN;
  const pct = /^(-?[0-9]*\.?[0-9]+(?:e-?[0-9]+)?)%$/i.exec(t);
  if (pct) return Number(pct[1]) / 100;
  return /^-?[0-9]*\.?[0-9]+(?:e-?[0-9]+)?$/i.test(t) ? Number(t) : Number.NaN;
}

/** PURE: the top-level functions of a CSS value list ("a(1) b(rgb(0, 0, 0) 2px)" → [["a","1"],["b","rgb(0, 0, 0) 2px"]]); null when it does not parse. */
function cssFunctions(value: string): [string, string][] | null {
  const out: [string, string][] = [];
  let i = 0;
  const s = value.trim();
  while (i < s.length) {
    while (i < s.length && s[i] === " ") i++;
    if (i >= s.length) break;
    const open = s.indexOf("(", i);
    if (open < 0) return null;
    const name = s.slice(i, open).trim().toLowerCase();
    if (!/^[a-z-]+$/.test(name)) return null;
    let depth = 0;
    let j = open;
    for (; j < s.length; j++) {
      if (s[j] === "(") depth++;
      else if (s[j] === ")" && --depth === 0) break;
    }
    if (depth !== 0) return null;
    out.push([name, s.slice(open + 1, j).trim()]);
    i = j + 1;
  }
  return out;
}

/** PURE: [s] split at its top-level commas (not those inside parentheses). */
function topLevelCommas(s: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let from = 0;
  for (let i = 0; i < s.length; i++) {
    if (s[i] === "(") depth++;
    else if (s[i] === ")") depth--;
    else if (s[i] === "," && depth === 0) {
      parts.push(s.slice(from, i).trim());
      from = i + 1;
    }
  }
  parts.push(s.slice(from).trim());
  return parts;
}

/**
 * PURE: what a computed `filter` does to the field: the opacity it multiplies in (`opacity()`), or null when it hides
 * or garbles what it filters (a blur, a brightness or contrast that washes text out, a half invert, an SVG filter) or
 * cannot be read. Hue, saturation, sepia, greyscale and shadows leave the text readable.
 */
export function filterOpacity(filter: string | undefined): number | null {
  if (filter === undefined) return 1;
  const f = filter.trim();
  if (f === "" || f === "none") return 1;
  const fns = cssFunctions(f);
  if (fns === null || fns.length === 0) return null;
  let factor = 1;
  for (const [name, arg] of fns) {
    const a = amount(arg);
    switch (name) {
      case "opacity":
        if (!Number.isFinite(a)) return null;
        factor *= Math.min(1, Math.max(0, a));
        break;
      case "blur": {
        const px = /^([0-9]*\.?[0-9]+)px$/.exec(arg.trim());
        const r = arg.trim() === "0" ? 0 : px ? Number(px[1]) : Number.NaN;
        if (!(r <= 1)) return null;
        break;
      }
      case "brightness":
        if (!(a >= 0.5 && a <= 2)) return null;
        break;
      case "contrast":
        if (!(a >= 0.5)) return null;
        break;
      case "invert":
        if (!Number.isFinite(a) || (a > 0.3 && a < 0.7)) return null;
        break;
      case "grayscale":
      case "sepia":
      case "saturate":
      case "hue-rotate":
      case "drop-shadow":
        break;
      default:
        return null; // url(), or a function this does not know: no proof the field can be seen
    }
  }
  return factor;
}

/** PURE: a computed colour's alpha: 0 for "transparent", the "/ a" or rgba() alpha where there is one, else 1. */
export function colorAlpha(color: string): number {
  const c = color.trim().toLowerCase();
  if (c === "transparent") return 0;
  const slash = /\/\s*([0-9.]+%?)\s*\)$/.exec(c);
  if (slash) {
    const a = amount(slash[1]!);
    return Number.isFinite(a) ? Math.min(1, Math.max(0, a)) : 1;
  }
  const rgba = /^rgba\(\s*[^,]+,[^,]+,[^,]+,\s*([0-9.]+%?)\s*\)$/.exec(c);
  if (rgba) {
    const a = amount(rgba[1]!);
    return Number.isFinite(a) ? Math.min(1, Math.max(0, a)) : 1;
  }
  return 1;
}

/** PURE: an rgb()/rgba() colour's channels, or null for any other form. */
function rgbOf(color: string): [number, number, number] | null {
  const m = /^rgba?\(\s*([0-9.]+)\s*,\s*([0-9.]+)\s*,\s*([0-9.]+)/.exec(color.trim().toLowerCase());
  return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : null;
}

/** PURE: the colour at the start of a gradient colour stop ("rgba(0, 0, 0, 0) 40%" → "rgba(0, 0, 0, 0)"). */
function stopColour(stop: string): { color: string; positions: string[] } {
  const s = stop.trim();
  let depth = 0;
  let end = s.length;
  for (let i = 0; i < s.length; i++) {
    if (s[i] === "(") depth++;
    else if (s[i] === ")") depth--;
    else if (s[i] === " " && depth === 0) {
      end = i;
      break;
    }
  }
  return { color: s.slice(0, end), positions: s.slice(end).trim().split(/\s+/).filter((p) => p !== "") };
}

/**
 * PURE (round-7 review, regression 3): how opaque a computed mask leaves the point ([x], [y], viewport coordinates)
 * of the element it masks, whose box is [box]: 1 for none; for one linear gradient, its alpha there, so a fade at the
 * edge of a scrolling panel leaves a field in its opaque part visible; null when it cannot be told (an image, several
 * layers, a corner direction, another gradient), which the rules take as hiding.
 */
export function maskAlphaAt(mask: string | undefined, box: Box, x: number, y: number): number | null {
  if (mask === undefined) return 1;
  const m = mask.trim();
  if (m === "" || m === "none") return 1;
  const fns = cssFunctions(m);
  if (fns === null || fns.length !== 1 || fns[0]![0] !== "linear-gradient") return null;
  const args = topLevelCommas(fns[0]![1]);
  let angle = 180; // "to bottom", the default
  const first = args[0]!.trim().toLowerCase();
  const sides: Record<string, number> = { "to top": 0, "to right": 90, "to bottom": 180, "to left": 270 };
  if (first.startsWith("to ")) {
    if (!(first in sides)) return null; // a corner: not told
    angle = sides[first]!;
    args.shift();
  } else {
    const a = /^(-?[0-9]*\.?[0-9]+)(deg|rad|turn|grad)$/.exec(first);
    if (a) {
      const v = Number(a[1]);
      angle = a[2] === "deg" ? v : a[2] === "rad" ? (v * 180) / Math.PI : a[2] === "turn" ? v * 360 : v * 0.9;
      args.shift();
    }
  }
  if (args.length < 2 || !(box.width > 0 && box.height > 0)) return null;
  const rad = (angle * Math.PI) / 180;
  const dx = Math.sin(rad);
  const dy = -Math.cos(rad);
  const length = Math.abs(box.width * dx) + Math.abs(box.height * dy);
  if (!(length > 0)) return null;
  const t = ((x - (box.left + box.width / 2)) * dx + (y - (box.top + box.height / 2)) * dy) / length + 0.5;
  // Stops: alpha and position (a fraction of the gradient line); missing positions are spread evenly between known ones.
  const stops: { alpha: number; at: number | null }[] = [];
  for (const raw of args) {
    const { color, positions } = stopColour(raw);
    const alpha = colorAlpha(color);
    if (positions.length === 0) stops.push({ alpha, at: null });
    for (const p of positions) {
      const pct = /^(-?[0-9]*\.?[0-9]+)%$/.exec(p);
      const px = /^(-?[0-9]*\.?[0-9]+)px$/.exec(p);
      if (!pct && !px) return null;
      stops.push({ alpha, at: pct ? Number(pct[1]) / 100 : Number(px![1]) / length });
    }
  }
  if (stops[0]!.at === null) stops[0]!.at = 0;
  if (stops[stops.length - 1]!.at === null) stops[stops.length - 1]!.at = 1;
  for (let i = 1; i < stops.length; i++) {
    if (stops[i]!.at !== null) {
      stops[i]!.at = Math.max(stops[i]!.at!, stops[i - 1]!.at ?? 0);
      continue;
    }
    let j = i;
    while (stops[j]!.at === null) j++;
    const from = stops[i - 1]!.at!;
    const to = stops[j]!.at!;
    for (let k = i; k < j; k++) stops[k]!.at = from + ((to - from) * (k - i + 1)) / (j - i + 1);
  }
  if (t <= stops[0]!.at!) return stops[0]!.alpha;
  for (let i = 1; i < stops.length; i++) {
    const a = stops[i - 1]!;
    const b = stops[i]!;
    if (t <= b.at!) return b.at! === a.at! ? b.alpha : a.alpha + ((b.alpha - a.alpha) * (t - a.at!)) / (b.at! - a.at!);
  }
  return stops[stops.length - 1]!.alpha;
}

/** PURE: whether what is typed into a field would show: text at least half opaque (round-7 review), not the
 *  background's own colour, and big enough to read. */
function inkVerdict(ink: InkFacts): VisibilityVerdict {
  const text = Math.min(colorAlpha(ink.color), colorAlpha(ink.textFill));
  if (text < MIN_TEXT_ALPHA) return "unreadable";
  const image = ink.backgroundImage.trim() !== "" && ink.backgroundImage.trim() !== "none";
  const fg = rgbOf(ink.textFill.trim() === "" ? ink.color : ink.textFill);
  const bg = rgbOf(ink.background);
  if (!image && fg !== null && bg !== null && text >= 0.9 && colorAlpha(ink.background) >= 0.9 && fg.every((v, i) => Math.abs(v - bg[i]!) <= 8)) return "unreadable";
  const size = /^([0-9]*\.?[0-9]+)px$/.exec(ink.fontSize.trim());
  if (!size || Number(size[1]) < MIN_FONT_PX) return "unreadable";
  return "ok";
}

/**
 * PURE: the visibility rules, over facts the DOM gave ([probeVisibility]). Fails closed on anything unreadable.
 * [proxied]: a control a page draws through a proxy ([proxiedAtDetection], [proxiedAtFill]) is not held to the
 * opacity, filter, mask, blend, ink, size and hit rules. [minOpacity]: [MIN_OPACITY] for a fill, [MIN_OPACITY_DETECT]
 * for what detection collects. A clip (clip-path, the legacy clip, an overflow) is not judged from its value: what it
 * removes is not hit-testable, so the sample points the hit test looks at catch it where it hides the field.
 */
export function visibilityOf(f: VisibilityFacts, proxied = false, minOpacity = MIN_OPACITY_DETECT): VisibilityVerdict {
  if (f.chain.length === 0) return "hidden";
  if (f.chain.some((s) => s.display === "none")) return "hidden";
  const own = f.chain[0]!;
  if (own.visibility === "hidden" || own.visibility === "collapse") return "hidden";
  const { left, top, width, height } = f.rect;
  if (!proxied) {
    let opacity = 1;
    const cx = left + width / 2;
    const cy = top + height / 2;
    for (const s of f.chain) {
      const o = Number.parseFloat(s.opacity);
      opacity *= Number.isFinite(o) ? Math.min(1, Math.max(0, o)) : 0; // an unreadable value is no proof of visibility
      const filtered = filterOpacity(s.filter);
      if (filtered === null) return "filtered";
      opacity *= filtered;
      if (s.blend !== undefined && s.blend.trim() !== "" && s.blend.trim() !== "normal") return "blended";
      if (s.mask !== undefined && s.mask.trim() !== "" && s.mask.trim() !== "none") {
        const masked = s.maskBox === undefined ? null : maskAlphaAt(s.mask, s.maskBox, cx, cy);
        if (masked === null) return "clipped";
        opacity *= Math.min(1, Math.max(0, masked));
      }
    }
    if (opacity < minOpacity) return "transparent";
    if (f.ink !== null) {
      const ink = inkVerdict(f.ink);
      if (ink !== "ok") return ink;
    }
    if (!(width >= MIN_FIELD_PX && height >= MIN_FIELD_PX)) return "tiny";
  }
  const inside = (e: Box): boolean => !(left + width <= e.left || top + height <= e.top || left >= e.left + e.width || top >= e.top + e.height);
  if (f.extents.length === 0 || !f.extents.some(inside)) return "offpage";
  if (f.viewport !== null) {
    const cx = left + width / 2;
    const cy = top + height / 2;
    if (cx < 0 || cy < 0 || cx >= f.viewport.width || cy >= f.viewport.height) return "offscreen";
  }
  if (!proxied && f.hit === "other") return "covered";
  return "ok";
}

/** How far up the tree [probeVisibility] reads styles: enough for any real form, bounded for a hostile one. */
const MAX_STYLE_DEPTH = 64;

/** [el]'s parent, across a shadow boundary to its host. By shape, not instanceof: [el] may be another frame's (realm's). */
function parentAcross(el: Element): Element | null {
  return el.parentElement ?? (el.getRootNode() as Partial<ShadowRoot>).host ?? null;
}

function scrolls(overflow: string): boolean {
  return overflow === "auto" || overflow === "scroll" || overflow === "overlay";
}

/** Where [el] may lie and be on the page, in viewport coordinates: the page's extent, and its nearest scrolling container's content. */
function extentsOf(el: HTMLElement, view: Window): Box[] {
  const de = el.ownerDocument.documentElement;
  const vw = view.innerWidth;
  const vh = view.innerHeight;
  const page: Box = { left: -view.scrollX, top: -view.scrollY, width: Math.max(de?.scrollWidth ?? 0, vw), height: Math.max(de?.scrollHeight ?? 0, vh) };
  let node = parentAcross(el);
  for (let depth = 0; node !== null && node !== de && node !== el.ownerDocument.body && depth < MAX_STYLE_DEPTH; depth++) {
    const cs = view.getComputedStyle(node);
    if ((scrolls(cs.overflowX) && node.scrollWidth > node.clientWidth) || (scrolls(cs.overflowY) && node.scrollHeight > node.clientHeight)) {
      const r = node.getBoundingClientRect();
      return [page, { left: r.left + node.clientLeft - node.scrollLeft, top: r.top + node.clientTop - node.scrollTop, width: node.scrollWidth, height: node.scrollHeight }];
    }
    node = parentAcross(node);
  }
  return [page];
}

/** What an element paints over whatever lies under it. Gathered by [paintFactsOf]. */
export interface PaintFacts {
  /** Its opacity times every ancestor's. */
  opacity: number;
  background: string;
  backgroundImage: string;
  /** `backdrop-filter`, which blurs or tints what is under it. */
  backdrop: string;
  /** An image, video, canvas, frame, embedded object or SVG: it paints its content. */
  replaced: boolean;
  /** Its ::before and ::after, when they are generated: what they paint, their own opacity, and their size ("auto" or px). */
  pseudo: ReadonlyArray<{ background: string; backgroundImage: string; opacity?: string; width?: string; height?: string }>;
}

/** How opaque an element over a field must be to hide it. */
export const COVER_ALPHA = 0.5;

/** PURE: whether an element painted over a field hides it: an opaque enough background, image, backdrop filter, or
 *  replaced content. One that paints nothing there (a transparent overlay) does not; a pseudo-element counts only at
 *  its own opacity and size (round-7 review, regression 5: a filled text field's invisible ripple is no cover). */
export function paintsOver(p: PaintFacts): boolean {
  const image = (v: string): boolean => v.trim() !== "" && v.trim() !== "none";
  if (!(p.opacity >= COVER_ALPHA)) return false;
  if (p.replaced || image(p.backgroundImage) || image(p.backdrop)) return true;
  if (colorAlpha(p.background) * p.opacity >= COVER_ALPHA) return true;
  const sized = (v: string | undefined): boolean => {
    if (v === undefined || v.trim() === "" || v.trim() === "auto") return true;
    const px = /^([0-9]*\.?[0-9]+)px$/.exec(v.trim());
    return px === null || Number(px[1]) >= MIN_FIELD_PX;
  };
  return p.pseudo.some((ps) => {
    const o = ps.opacity === undefined ? 1 : Number.parseFloat(ps.opacity);
    const alpha = (Number.isFinite(o) ? Math.min(1, Math.max(0, o)) : 1) * p.opacity;
    if (!(alpha >= COVER_ALPHA) || !sized(ps.width) || !sized(ps.height)) return false;
    return image(ps.backgroundImage) || colorAlpha(ps.background) * alpha >= COVER_ALPHA;
  });
}

const REPLACED = new Set(["IMG", "VIDEO", "CANVAS", "IFRAME", "FRAME", "EMBED", "OBJECT", "PICTURE"]);
const FRAMES = new Set(["IFRAME", "FRAME", "EMBED", "OBJECT"]);

function paintFactsOf(at: Element): PaintFacts {
  const view = at.ownerDocument.defaultView!;
  const cs = view.getComputedStyle(at);
  let opacity = 1;
  let node: Element | null = at;
  for (let depth = 0; node !== null && depth < MAX_STYLE_DEPTH; depth++) {
    const o = Number.parseFloat(view.getComputedStyle(node).opacity);
    opacity *= Number.isFinite(o) ? Math.min(1, Math.max(0, o)) : 1;
    node = parentAcross(node);
  }
  const pseudo = ["::before", "::after"]
    .map((p) => view.getComputedStyle(at, p))
    .filter((ps) => ps.content !== "none" && ps.content !== "normal" && ps.content !== "")
    .map((ps) => ({ background: ps.backgroundColor, backgroundImage: ps.backgroundImage, opacity: ps.opacity, width: ps.width, height: ps.height }));
  return {
    opacity,
    background: cs.backgroundColor,
    backgroundImage: cs.backgroundImage,
    backdrop: cs.getPropertyValue("backdrop-filter") || cs.getPropertyValue("-webkit-backdrop-filter") || "none",
    replaced: REPLACED.has(at.tagName.toUpperCase()) || at.namespaceURI === "http://www.w3.org/2000/svg",
    pseudo,
  };
}

const CONTROLS = "input:not([type=hidden]), select, textarea, button";

/**
 * The field's own wrapper: the outermost of its nearest few ancestors that holds no other form control. Its label,
 * floating label and adornments live there and are part of the field (round-7 review, regressions 4 and 6).
 */
export function fieldWrapperOf(el: Element): Element | null {
  let wrapper: Element | null = null;
  let node = parentAcross(el);
  const body = el.ownerDocument.body;
  for (let depth = 0; node !== null && node !== body && depth < 4; depth++) {
    if (node.querySelectorAll(CONTROLS).length !== 1) break;
    wrapper = node;
    node = parentAcross(node);
  }
  return wrapper;
}

/**
 * Whether [at] is part of field [el]'s own presentation rather than something over it: one of its labels, or something
 * inside its wrapper ([fieldWrapperOf]) that holds no control or frame and does not contain the field (a floating
 * label, a brand icon, an adornment).
 */
export function isFieldPart(el: Element, at: Element): boolean {
  const labels = el instanceof HTMLInputElement || el instanceof HTMLSelectElement ? [...(el.labels ?? [])] : [];
  if (labels.some((l) => l === at || l.contains(at))) return true;
  const wrapper = fieldWrapperOf(el);
  if (wrapper === null || !wrapper.contains(at) || at.contains(el)) return false;
  if (FRAMES.has(at.tagName.toUpperCase()) || at.querySelector(`${CONTROLS}, iframe, frame, embed, object`) !== null) return false;
  return true;
}

/** Where [rect] is looked at: its centre, and halfway from it to each side (round-7 review, regression 7). */
export function samplePoints(rect: Box): { x: number; y: number }[] {
  const cx = rect.left + rect.width / 2;
  const cy = rect.top + rect.height / 2;
  return [
    { x: cx, y: cy },
    { x: rect.left + rect.width / 4, y: cy },
    { x: rect.left + (rect.width * 3) / 4, y: cy },
    { x: cx, y: rect.top + rect.height / 4 },
    { x: cx, y: rect.top + (rect.height * 3) / 4 },
  ];
}

/**
 * What shows at each of [points] (viewport coordinates of [el]'s document): "self" when, at every one, the topmost
 * element that paints anything ([paintsOver]) is [el], inside it, or part of it ([isFieldPart]); "other" otherwise,
 * including where [el] is not there at all (clipped, or under something). Elements [ignore] names (this extension's
 * own UI) are looked through. A cover that lets the pointer through (pointer-events: none) is not seen: that is the
 * limit of these rules, and why they are defence in depth only.
 */
export function whatShowsAt(el: Element, points: readonly { x: number; y: number }[], ignore: (e: Element) => boolean = () => false): "self" | "other" {
  const root = el.getRootNode() as Document | ShadowRoot;
  const doc = el.ownerDocument;
  for (const { x, y } of points) {
    const list = typeof root.elementsFromPoint === "function" ? root.elementsFromPoint(x, y) : doc.elementsFromPoint(x, y);
    let found = false;
    for (const at of list) {
      if (at === el || el.contains(at)) {
        found = true;
        break;
      }
      if (ignore(at) || isFieldPart(el, at)) continue;
      if (paintsOver(paintFactsOf(at))) return "other";
    }
    if (!found) return "other";
  }
  return "self";
}

/**
 * The [VisibilityFacts] for [el], from the live DOM. [onScreen]: the field must be on screen now. [hitTest]: what shows
 * at its sample points ([samplePoints], [whatShowsAt]) that are on screen, the centre at least. [fill]: read the
 * fill-time styles too (filter, mask, blend, ink).
 */
export function probeVisibility(el: HTMLElement, opts: { onScreen: boolean; hitTest: boolean; fill?: boolean; ignore?: (e: Element) => boolean }): VisibilityFacts {
  const doc = el.ownerDocument;
  const view = doc.defaultView ?? window;
  const chain: StyleFacts[] = [];
  let node: Element | null = el;
  for (let depth = 0; node !== null && depth < MAX_STYLE_DEPTH; depth++) {
    const cs = view.getComputedStyle(node);
    const facts: StyleFacts = { display: cs.display, visibility: cs.visibility, opacity: cs.opacity };
    if (opts.fill === true) {
      facts.filter = cs.filter;
      facts.mask = [cs.getPropertyValue("mask-image"), cs.getPropertyValue("-webkit-mask-image"), cs.getPropertyValue("-webkit-mask-box-image")].find((m) => m.trim() !== "" && m.trim() !== "none") ?? "none";
      if (facts.mask !== "none") {
        const b = node.getBoundingClientRect();
        facts.maskBox = { left: b.left, top: b.top, width: b.width, height: b.height };
      }
      facts.blend = cs.getPropertyValue("mix-blend-mode") || "normal";
    }
    chain.push(facts);
    node = parentAcross(node);
  }
  let ink: InkFacts | null = null;
  if (opts.fill === true) {
    const cs = view.getComputedStyle(el);
    ink = { color: cs.color, textFill: cs.getPropertyValue("-webkit-text-fill-color") || cs.color, background: cs.backgroundColor, backgroundImage: cs.backgroundImage, fontSize: cs.fontSize };
  }
  const r = el.getBoundingClientRect();
  const rect = { left: r.left, top: r.top, width: r.width, height: r.height };
  const vw = view.innerWidth;
  const vh = view.innerHeight;
  let hit: "self" | "other" | null = null;
  const cx = r.left + r.width / 2;
  const cy = r.top + r.height / 2;
  if (opts.hitTest && cx >= 0 && cy >= 0 && cx < vw && cy < vh) {
    hit = whatShowsAt(el, samplePoints(rect).filter((p) => p.x >= 0 && p.y >= 0 && p.x < vw && p.y < vh), opts.ignore);
  }
  return { chain, ink, rect, extents: extentsOf(el, view), viewport: opts.onScreen ? { width: vw, height: vh } : null, hit };
}

/** Where [el] sits in its scrolling container's content (or the page's): unmoved by scrolling, moved by a relayout. */
export function contentPositionOf(el: HTMLElement): Box {
  const view = el.ownerDocument.defaultView ?? window;
  const r = el.getBoundingClientRect();
  const extents = extentsOf(el, view);
  const e = extents[extents.length - 1]!;
  return { left: r.left - e.left, top: r.top - e.top, width: r.width, height: r.height };
}

/** [U6] per-sweep-generation label cache: extraction costs textContent walks and a form-sized
 *  wrapping label must not re-pay them per field per tick. content.ts bumps the generation on
 *  childList-bearing mutation ticks (the ticks that can change label structure, same cadence as
 *  the shadow-root sweep [U16]); attribute-only ticks reuse. Staleness is bounded at one
 *  childList tick, never invalidated mid-sweep. */
let labelGeneration = 0;
const labelCache = new WeakMap<FillableControl, { gen: number; sources: string[] }>();
export function bumpLabelGeneration(): void {
  labelGeneration++;
}

/** [U7] the ORDERED label source list for one control — each entry stays a SEPARATE string
 *  ([U5]: classification never concatenates across sources): `aria-label` attr · `el.labels`
 *  texts (native <label for>/wrapping resolution, root-scoped — never document.querySelector,
 *  which is wrong under shadow scoping and id escaping) · each `aria-labelledby` id resolved via
 *  `getRootNode().getElementById` (one string per target, listed order) · placeholder (inputs
 *  only; selects have none). Bounds ([U6]) live in the classifier, not here — the cache stores
 *  raw sources. Exported for the pure suite's cache/order pins (structural: runs on stubs). */
export function labelSourcesOf(el: FillableControl): string[] {
  const hit = labelCache.get(el);
  if (hit && hit.gen === labelGeneration) return hit.sources;
  const sources: string[] = [];
  const aria = el.getAttribute("aria-label");
  if (aria) sources.push(aria);
  if (el.labels) for (const l of el.labels) sources.push(l.textContent ?? "");
  const by = el.getAttribute("aria-labelledby");
  if (by) {
    const root = el.getRootNode() as Document | ShadowRoot;
    for (const id of by.split(/\s+/)) {
      if (id === "") continue;
      const t = typeof root.getElementById === "function" ? root.getElementById(id) : null;
      if (t) sources.push(t.textContent ?? "");
    }
  }
  if (el instanceof HTMLInputElement && el.placeholder) sources.push(el.placeholder);
  labelCache.set(el, { gen: labelGeneration, sources });
  return sources;
}

function collect(root: Document | ShadowRoot): Field[] {
  const out: Field[] = [];
  for (const el of root.querySelectorAll("input, select")) {
    if (el instanceof HTMLInputElement) {
      if (el.disabled || el.readOnly || !isVisible(el)) continue;
      // [W8] dedicated radio arm BEFORE the NON_FILLABLE_TYPES skip: a radio is collected ONLY as a
      // cardtype (classifyCardRadio is cardtype-only + never the login classify()), hard-set kind
      // "none"/textLike false so it stays login-inert ([W7] keeps it out of the login cluster pool).
      if (el.type === "radio") {
        const sig = fieldSignalOf(el);
        const cardKind = classifyCardRadio(sig.htmlNameOrId ?? null, el.id, sig.hints ?? [], labelSourcesOf(el));
        if (cardKind !== null) out.push({ input: el, kind: "none", isNewPassword: false, textLike: false, cardKind });
        continue;
      }
      if (NON_FILLABLE_TYPES.has(el.type)) continue; // never fill a checkbox/submit, whatever its name
      const sig = fieldSignalOf(el);
      const kind = classify(sig);
      const t = el.type;
      const textLike =
        kind === "none" &&
        (t === "text" || t === "email") &&
        !NAME_NEGATIVE_RX.test((el.name || el.id).toLowerCase());
      // §8: id rides alongside for the token retry; [U5]/[U7]: label sources are the weakest,
      // gap-only signal — extraction is skipped outright for login-claimed fields.
      const cardKind = classifyCardField(sig, el.id, kind === "none" ? labelSourcesOf(el) : undefined);
      if (kind !== "none" || textLike || cardKind !== null)
        out.push({ input: el, kind, isNewPassword: sig.isNewPassword, textLike, cardKind });
    } else if (el instanceof HTMLSelectElement) {
      // readOnly stays input-gated (selects have no readOnly); only select-one qualifies — a
      // multi-select cannot hold ONE expiry/type. Selects NEVER enter the login pool: kind is
      // hard-set "none"/textLike false and classify() is not consulted (§1) — a card-less select
      // contributes nothing, so it isn't collected at all.
      if (el.disabled || !isVisible(el) || el.type !== "select-one") continue;
      const sig = fieldSignalOf(el);
      const cardKind = classifyCardSelect(sig.htmlNameOrId ?? null, el.id, sig.hints ?? [], labelSourcesOf(el));
      if (cardKind !== null) out.push({ input: el, kind: "none", isNewPassword: false, textLike: false, cardKind });
    }
  }
  return out;
}

function hasSubmitControl(scope: Scope): boolean {
  const sel = 'button, input[type="submit"], input[type="image"], input[type="button"], a, [role="button"]';
  for (const el of scope.querySelectorAll(sel)) if (isSubmitLike(el)) return true;
  return false;
}

/** Submit-like control within a BOUNDED ancestor scope of a formless field — never the whole
 *  document. Without the bound, a stray newsletter/coupon email field borrows any "Log in" /
 *  "Continue" / "Next" control elsewhere on the page and masquerades as a login step. */
function hasNearbySubmit(el: Element): boolean {
  let node: Element | null = el.parentElement;
  for (let depth = 0; node && depth < FORMLESS_SCOPE_DEPTH; depth++, node = node.parentElement) {
    if (hasSubmitControl(node)) return true;
  }
  return false;
}

/** Split formless fields into clusters: for each password, its group is the nearest ancestor
 *  that also contains another candidate field (two side-by-side login widgets stay separate).
 *  [T1]/[W7] the clustering is LOGIN-INERT-CONTROL-BLIND: the per-password early-stop counts only
 *  LOGIN-ELIGIBLE Fields (input-backed AND (kind !== "none" || textLike)), NOT `instanceof
 *  HTMLInputElement` — a cardtype RADIO is an input but login-inert (excluded by its TYPE), and a
 *  select is input-inert; both must ride as the remainder or a formless expiry-<select>/brand-radio
 *  row beside a password CVV would satisfy the early-stop a level too low and split the PAN off the
 *  cluster (killing the shipped CVV fill + demotion). Every OTHER card-classified input (tel/number
 *  PANs, negative-name CVVs) stays IN the pool — the shipped clustering depends on it. After the groups form, each login-inert Field
 *  attaches to the FIRST group whose container contains it (document order), else it rides the root
 *  leftover group. Leftover password-less fields form one root-scoped group (username-step
 *  candidate). Exported for the pure suite ([T1] §11): the algorithm is structural (parentElement
 *  climbs + contains) and runs against node stubs — no live DOM. */
export function formlessGroups(loose: Field[], root: Document | ShadowRoot): { container: Scope; fields: Field[] }[] {
  // Review-fold (Tier 3): the inert remainder is selects + cardtype radios; G3 [X3-A3] ADDS
  // cardpostal INPUTS to it (login-inert — a billing zip is never needed for PAN-CVV cohesion,
  // and keeping it out of the clustering pool is what makes a card-free username+password+postal
  // page group login-bit-identically before/after G3: the postal cannot drive a password's
  // early-stop; it attaches post-formation by container like a select/radio). A bare
  // (kind!=="none" || textLike) predicate silently demoted tel/number-typed card INPUTS too —
  // collect() admits them via cardKind alone (textLike needs type text/email) — splitting the
  // shipped password-CVV↔PAN clustering on formless checkouts (no demotion, no CVV fill, and
  // the [A7] save-suppression lost its anchor). Non-radio, non-postal card inputs must cluster
  // exactly as they did under the old instanceof partition. (A billing zip named non-negatively is
  // textLike regardless — that path is unchanged; only cardKind-ONLY postals, e.g. `postal_code`,
  // become inert, and those were never collected pre-G3.)
  const loginEligible = (f: Field): boolean =>
    f.input instanceof HTMLInputElement &&
    (f.kind !== "none" || f.textLike || (f.cardKind !== null && f.cardKind !== "cardpostal" && f.input.type !== "radio"));
  const inputs = loose.filter(loginEligible);
  const inert = loose.filter((f) => !loginEligible(f));
  const remaining = new Set(inputs);
  const groups: { container: Scope; fields: Field[] }[] = [];
  for (const f of inputs) {
    if (f.kind !== "password" || !remaining.has(f)) continue;
    let group: { container: Scope; fields: Field[] } | null = null;
    // Bounded climb: a real login widget keeps username+password within a few levels. Climbing
    // to <body> would swallow unrelated widgets' fields into one bogus form (breaking both).
    let depth = 0;
    for (let node = f.input.parentElement; node && depth < FORMLESS_SCOPE_DEPTH; node = node.parentElement, depth++) {
      const n = node;
      const contained = [...remaining].filter((x) => n.contains(x.input));
      if (contained.length > 1) {
        group = { container: n, fields: contained };
        break;
      }
    }
    if (!group) group = { container: f.input.parentElement ?? root, fields: [f] };
    for (const x of group.fields) remaining.delete(x);
    groups.push(group);
  }
  const leftover = [...remaining];
  for (const s of inert) {
    const g = groups.find((x) => x.container.contains(s.input));
    if (g) g.fields.push(s);
    else leftover.push(s);
  }
  if (leftover.length > 0) groups.push({ container: root, fields: leftover });
  return groups;
}

function buildLoginForm(form: HTMLFormElement | null, container: Scope, fields: Field[]): LoginForm | null {
  // Login slots take input-backed fields only ([T15] instanceof narrowing) — runtime-redundant
  // (selects are always kind "none"/!textLike) but it is what makes the slot types honest.
  const passwords = fields.filter(isInputField).filter((f) => f.kind === "password");
  // [A7] formKind gate: ANY form carrying a detected card-NUMBER field is a card form and is
  // excluded from the login capture/save path — an "update" here would overwrite a stored merchant
  // password with a PAN/CVV. This is the general fix; the lone-CVV rule below is the narrower one.
  const isCardForm = fields.some((f) => f.cardKind === "cardnumber");

  if (passwords.length === 0) {
    // Multi-step step 1: exactly one CLASSIFIED username (fallback pool doesn't qualify)
    // plus a way to advance — otherwise it's just a stray text field.
    const users = fields.filter(isInputField).filter((f) => f.kind === "username");
    if (users.length !== 1) return null;
    // A real form scopes its own submit; a formless single needs one NEARBY (bounded), not
    // anywhere in the document — otherwise a lone newsletter email reads as a login step.
    const advances = form ? hasSubmitControl(form) : hasNearbySubmit(users[0]!.input);
    if (!advances) return null;
    return {
      kind: "username-step",
      form,
      container,
      username: users[0]!.input,
      password: null,
      newPasswords: [],
      capturePassword: null,
      isSignup: false,
      suppressSave: isCardForm,
    };
  }

  const flagged = passwords.filter((p) => p.isNewPassword);
  // Two unflagged passwords = the classic signup password+confirm pair; three or more
  // without autocomplete is a change-password form — its FIRST field is current-password,
  // which is exactly what a login fill should target, so it stays kind "login", not signup.
  const isSignup = flagged.length > 0 || passwords.length === 2;
  const newPasswords =
    flagged.length > 0 ? flagged.map((p) => p.input) : isSignup ? passwords.map((p) => p.input) : [];
  const primary = passwords.find((p) => !p.isNewPassword) ?? passwords[0]!;
  const capturePassword = chooseCapturePassword(passwords.map((p) => p.input), newPasswords, primary.input);

  // Username = nearest classified-username above the primary password, per-group; fall back
  // to the nearest non-negative text/email above (today's heuristic) when nothing classifies.
  const pIdx = fields.indexOf(primary);
  let username: HTMLInputElement | null = null;
  for (let i = pIdx - 1; i >= 0; i--) {
    const c = fields[i]!;
    if (c.kind === "username" && isInputField(c)) {
      username = c.input;
      break;
    }
  }
  if (!username) {
    for (let i = pIdx - 1; i >= 0; i--) {
      const c = fields[i]!;
      if (c.textLike && isInputField(c)) {
        username = c.input;
        break;
      }
    }
  }

  // CVV-negative rule: only a genuinely password-TYPED input qualifies (a text field that
  // classify()'d password off a name keyword can't be a CVV box), and only when it is the
  // form's ONLY password field — a real username+password+cvv checkout keeps its banner path
  // (not lone), and a login form named normally is untouched. [A7] a card form (cardnumber
  // anchor present) also suppresses, regardless of the password count. §8/F29: name and id are
  // checked INDEPENDENTLY (the shipped `name || id` let a garbage name shadow a CVV id;
  // suppression-side widening is fail-safe).
  const suppressSave =
    isCardForm ||
    (passwords.length === 1 &&
      primary.input.type === "password" &&
      (isCvvNameOrId(primary.input.name) || isCvvNameOrId(primary.input.id)));

  return { kind: "login", form, container, username, password: primary.input, newPasswords, capturePassword, isSignup, suppressSave };
}

/**
 * H04 (2026-09-13 audit): which password field the capture engine should read as "the password
 * being set". Pure over the form's password fields in document order so node --test can pin
 * every shape (detect.capture.test.ts) — the DOM builders above only ever pass through it.
 *
 *  - any NEW-password field (autocomplete=new-password, or the two-unflagged signup pair) → the
 *    FIRST of them: that is the value the user is choosing, and the value the generator wrote;
 *  - three or more password fields with NO hint at all → the SECOND: this is the change-password
 *    shape detect recognises for fill (current, new, confirm — current first, which is why fill
 *    keeps targeting passwords[0]); the value worth saving is the new one, never the current;
 *  - otherwise → the fill target itself (a plain sign-in: one password, and it is the password).
 *
 * Both fixed shapes previously captured the CURRENT password: the 2a rule then saw "same
 * password as stored" and drew no banner at all, so a site-side password change (or a generated
 * password the vault never learned) was silently lost — the user's next hypothesis was "I forgot
 * my password". The fill target is deliberately NOT changed here: `password` stays the field a
 * login fill writes into.
 */
export function chooseCapturePassword<T>(passwords: readonly T[], newPasswords: readonly T[], fillTarget: T): T {
  if (newPasswords.length > 0) return newPasswords[0]!;
  if (passwords.length >= 3) return passwords[1]!;
  return fillTarget;
}

interface FieldGroup {
  form: HTMLFormElement | null;
  container: Scope;
  fields: Field[];
}

/** The one field-grouping pass (document order: formed groups first, then formless clusters),
 *  shared by the login and card builders so they see IDENTICAL grouping. Does not descend into
 *  shadow roots — callers pass each root they care about. */
function groupFields(root: Document | ShadowRoot): FieldGroup[] {
  const fields = collect(root);
  const byForm = new Map<HTMLFormElement | null, Field[]>();
  for (const f of fields) {
    const list = byForm.get(f.input.form);
    if (list) list.push(f);
    else byForm.set(f.input.form, [f]);
  }
  const out: FieldGroup[] = [];
  for (const [form, group] of byForm) {
    if (form === null) continue;
    out.push({ form, container: form, fields: group });
  }
  const loose = byForm.get(null);
  if (loose) {
    for (const g of formlessGroups(loose, root)) out.push({ form: null, container: g.container, fields: g.fields });
  }
  return out;
}

/** All fillable login forms under `root`, document order. */
export function findLoginForms(root: Document | ShadowRoot): LoginForm[] {
  const out: LoginForm[] = [];
  for (const g of groupFields(root)) {
    const built = buildLoginForm(g.form, g.container, g.fields);
    if (built) out.push(built);
  }
  return out;
}

/** A same-page card form: a field group with a detected card-NUMBER anchor. `fields` carries the
 *  index-aligned card kinds + their inputs (CSC demotion applied) for the S3 fill executor. */
export interface CardFormFieldRef {
  kind: CardFieldKind;
  input: FillableControl;
  /** V3 [W12]: for a cardtype RADIO ref, the group's members — same `name`, THIS form's own
   *  collected cardtype refs only ([W10]: never a document-wide `name` re-query). N members collapse
   *  to ONE ref (this one; `input` is the group representative), so the executor builds synthetic
   *  options [{value, text: adjacent label}] from `group` and fills the group ONCE (radioIndexFor +
   *  `.checked`), filled LAST ([W11]). Absent for inputs and selects. */
  group?: HTMLInputElement[];
}
export interface CardForm {
  form: HTMLFormElement | null;
  container: Scope;
  fields: CardFormFieldRef[];
}

function buildCardForm(form: HTMLFormElement | null, container: Scope, fields: Field[]): CardForm | null {
  if (!fields.some((f) => f.cardKind === "cardnumber")) return null; // a card form REQUIRES the PAN anchor
  const refs: CardFormFieldRef[] = [];
  // [W12] same-name cardtype radios collapse to ONE ref within THIS form ([W10] never document-wide):
  // the first member owns the ref (+ a growing `group` array of members); later members fold in.
  const radioGroups = new Map<string, HTMLInputElement[]>();
  for (const f of fields) {
    const kind = demoteCsc(f.cardKind, f.input.type, f.input.name, f.input.id);
    if (!kind) continue;
    if (f.input instanceof HTMLInputElement && f.input.type === "radio") {
      const name = f.input.name;
      const existing = name !== "" ? radioGroups.get(name) : undefined;
      if (existing) {
        existing.push(f.input); // folds into the representative's `group` (same array reference)
        continue;
      }
      const members = [f.input];
      if (name !== "") radioGroups.set(name, members);
      refs.push({ kind, input: f.input, group: members });
      continue;
    }
    refs.push({ kind, input: f.input });
  }
  // [X3-A1](ii) fail-closed on ambiguity: if MORE than one field on THIS anchored form survives as
  // cardpostal (the [X3-A1](i) shipping-suppressor already dropped shipping zips per-string, so a
  // billing+shipping mix leaves ONE), declare/fill NONE — never guess which billing zip is the card's.
  // Dropping the refs here removes cardpostal from the form's kind-signature too, so the SW's frozen
  // grant.kinds ([U15]) never carries it and revealCardForFill composes no postalCode ([X3-A4d]).
  // The count predicate is the SHARED `postalIsAmbiguous` (also driven by the pure test) — this DOM
  // path can't run under node --test, so the exported predicate is what carries direct coverage.
  const finalRefs = postalIsAmbiguous(refs.map((r) => r.kind)) ? refs.filter((r) => r.kind !== "cardpostal") : refs;
  return { form, container, fields: finalRefs };
}

/** [X3-A1](ii): >1 surviving cardpostal on one anchored form is ambiguous → the caller drops ALL
 *  cardpostal (fail-closed, never guess the card's billing zip among several). Exported so
 *  buildCardForm and the pure suite share ONE count predicate rather than a hand-mirror. */
export function postalIsAmbiguous(kinds: readonly (CardFieldKind | null)[]): boolean {
  return kinds.filter((k) => k === "cardpostal").length > 1;
}

/** All same-page card forms under `root`, document order — same grouping as findLoginForms so the
 *  two views never disagree on which fields belong to which form. */
export function findCardForms(root: Document | ShadowRoot): CardForm[] {
  const out: CardForm[] = [];
  for (const g of groupFields(root)) {
    const built = buildCardForm(g.form, g.container, g.fields);
    if (built) out.push(built);
  }
  return out;
}
