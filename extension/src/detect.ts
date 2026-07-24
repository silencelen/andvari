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
  isSignup: boolean;
  /** CVV-negative rule (cards design 2026-07-09): true when the form's LONE password-typed
   *  field is name/id-token-matched cvv|cvc|csc — a checkout CVV box, not a login password.
   *  The capture engine must not offer save/update for it (an "update" would overwrite the
   *  stored merchant password with a CVV). Fill/dropdown behavior is deliberately unchanged. */
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
export type CardFieldKind = "cardnumber" | "cardexpiry" | "cardexpmonth" | "cardexpyear" | "cardname" | "cardcvv" | "cardtype";

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
};

/** Card name/id/label token runs (whole-token-run matched) → kind — the SINGLE normative
 *  in-bundle copy is cardfill.ts `TABLES.keywords` ([U8]: ordered groups, deep-equalled against
 *  cardfill.json; core asserts SEQUENCE equality against the same section). Group ORDER is
 *  load-bearing: exp-month/-year before the generic exp group ("expirymonth" would also
 *  whole-run-match the exp group's "expiry"), and the trailing bare-`creditcard` group ([U1])
 *  fires only when no specific kind matched. */
const CARD_NAME_KINDS: [readonly string[], CardFieldKind][] = TABLES.keywords.map((g) => [g.keywords, VECTOR_CARD_KIND[g.kind]!]);

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

/** One name/id string → card verdict via the token runs. "gift" = a cardnumber verdict was
 *  produced AND suppressed — distinct from null (no verdict at all) because suppression is
 *  TERMINAL for the field: the string positively identified a gift-card number, so the §8 htmlId
 *  retry must not resurrect it off a cleaner-looking id. */
function cardKindFromTokens(raw: string): CardFieldKind | "gift" | null {
  // [W4] ASCII-fold at THIS chokepoint (not inside tokens(), which also feeds isCvvNameOrId →
  // suppressSave, a login-capture verdict that MUST stay byte-identical): "Prüfnummer" → folded
  // "pruefnummer" → tokens → the shipped cc-csc keyword matches (raw tokens() splits at ü and never
  // does). Covers classifyCardField name+id, classifyCardSelect, cardKindFromLabels, classifyCardRadio.
  const toks = tokens(fold(raw));
  for (const [kws, kind] of CARD_NAME_KINDS) {
    if (kws.some((kw) => tokenMatch(toks, kw))) {
      if (kind === "cardnumber" && GIFT_SUPPRESS_TOKENS.some((kw) => tokenMatch(toks, kw))) return "gift";
      return kind;
    }
  }
  return null;
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
    if (k !== null) return k === "gift" ? null : k;
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
  if (byName === "gift") return null;
  if (byName) return byName;
  const byId = htmlId ? cardKindFromTokens(htmlId) : null;
  if (byId !== null) return byId === "gift" ? null : byId;
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
  const restricted = (k: CardFieldKind | "gift" | null): CardFieldKind | null =>
    k !== null && k !== "gift" && SELECT_CARD_KINDS.has(k) ? k : null;
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
  const restricted = (k: CardFieldKind | "gift" | null): CardFieldKind | null => (k === "cardtype" ? "cardtype" : null);
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
function isVisible(el: HTMLElement): boolean {
  return el.offsetParent !== null || el.getClientRects().length > 0;
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
  // Review-fold (Tier 3): the inert remainder is EXACTLY selects + cardtype radios. A bare
  // (kind!=="none" || textLike) predicate silently demoted tel/number-typed card INPUTS too —
  // collect() admits them via cardKind alone (textLike needs type text/email) — splitting the
  // shipped password-CVV↔PAN clustering on formless checkouts (no demotion, no CVV fill, and
  // the [A7] save-suppression lost its anchor). Non-radio card inputs must cluster exactly as
  // they did under the old instanceof partition.
  const loginEligible = (f: Field): boolean =>
    f.input instanceof HTMLInputElement && (f.kind !== "none" || f.textLike || (f.cardKind !== null && f.input.type !== "radio"));
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

  return { kind: "login", form, container, username, password: primary.input, newPasswords, isSignup, suppressSave };
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
  return { form, container, fields: refs };
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
