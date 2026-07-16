/**
 * Pure field-detection engine — no chrome.*, no side effects. Classification defers to the
 * canonical, vector-tested classify() in urimatch.ts (verbatim port of web/src/vault/urimatch.ts);
 * this module only adapts DOM inputs into FieldSignals and groups them into fillable login forms.
 *
 * Scans are visible-fields-only: hidden inputs are where sites stash tokens and where phishing
 * kits hide credential sinks — and a multi-step page's not-yet-shown password field must NOT
 * collapse step 1 into a normal login form.
 */
// Explicit .ts so the node --test runner (detect.cards.test.ts) can resolve this transitively —
// esbuild (bundle) + tsc (allowImportingTsExtensions) accept it too; node ESM needs the extension.
import { classify, type FieldKind, type FieldSignal } from "./urimatch.ts";

/** A scope that can own a login form: the <form>, a nearest-common container, or the scan root. */
export type Scope = Element | Document | ShadowRoot;

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
export type CardFieldKind = "cardnumber" | "cardexpiry" | "cardexpmonth" | "cardexpyear" | "cardname" | "cardcvv";

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
};

/** Card name/id token runs (whole-token-run matched) → kind — mirrors core
 *  `FieldClassifier.CARD_NAME_KINDS`. Group ORDER matters: exp-month/-year before the generic
 *  exp group ("expmonth" would also whole-run-match a bare "exp" group member). "pan" is
 *  deliberately absent (hazard exceeds value); no bare "exp". */
const CARD_NAME_KINDS: [readonly string[], CardFieldKind][] = [
  [["cardnumber", "ccnumber", "ccnum", "cardno", "cardnum"], "cardnumber"],
  [["expmonth", "expmm", "expirationmonth"], "cardexpmonth"],
  [["expyear", "expyy", "expirationyear"], "cardexpyear"],
  [["expiry", "expdate", "ccexp", "expiration", "expirationdate"], "cardexpiry"],
  [["cvv", "cvc", "csc", "securitycode"], "cardcvv"],
  [["cardholder", "nameoncard", "ccname"], "cardname"],
];

/** HTML types the card NAME-keyword fallback may fire from (core `CARD_FALLBACK_HTML_TYPES`
 *  parity): the keyword is the card signal, never numeric-ness; a password type is NEVER
 *  name-classified as a card field here — only the form-level CSC demotion may relabel it. */
const CARD_FALLBACK_HTML_TYPES = new Set(["", "text", "tel", "number"]);

/** name/id → lowercase ASCII tokens: split on non-alphanumerics, camelCase boundaries, and
 *  letter↔digit boundaries ("cardVerificationValue" → [card,verification,value]; "cvv2" →
 *  [cvv,2]). The digit boundary is one deliberate widening over core FieldClassifier.tokens()
 *  (which keeps digits glued to letters): checkout CVVs are routinely named cvv2/cvc2 (Visa's
 *  own branding), and this feeds a SUPPRESSION rule only — it can mute a save banner, never
 *  classify a fill target — so widening is fail-safe. */
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

/** Per-field card classification — pure (FieldSignal → kind), no DOM. Fires ONLY in the
 *  `classify() == none` gap (design [A8], core `FieldClassifier` step-4 parity): every field the
 *  login classifier decided keeps its verdict, so a card kind can never outrank USERNAME/PASSWORD
 *  and login verdicts on card-free forms stay bit-identical. Autocomplete card hints win first
 *  (a masked cc-csc password is a NEGATIVE login hint → lands in the gap here); then name/id token
 *  runs, but only for card-fallback HTML types (never a password type — the CSC demotion below is
 *  the only path that relabels a password). */
export function classifyCardField(sig: FieldSignal): CardFieldKind | null {
  if (classify(sig) !== "none") return null;
  const hints = (sig.hints ?? []).map((h) => h.toLowerCase().replace(/[_-]/g, ""));
  for (const h of hints) {
    const k = CARD_HINTS[h];
    if (k) return k;
  }
  if (!CARD_FALLBACK_HTML_TYPES.has((sig.htmlType ?? "").toLowerCase())) return null;
  const toks = tokens(sig.htmlNameOrId ?? "");
  for (const [kws, kind] of CARD_NAME_KINDS) if (kws.some((kw) => tokenMatch(toks, kw))) return kind;
  return null;
}

/** Form-level CSC demotion — pure (kind + type + name → kind). A password-typed field named like a
 *  security code, sitting ON a card form (a cardnumber anchor is present — the caller only invokes
 *  this then), IS the CVV: name-based parity with core `CardForm.refine`'s cluster demotion. This
 *  keeps login verdicts bit-identical (it never runs on a card-free form) while letting the fill
 *  executor reach a masked CVV box. */
export function demoteCsc(kind: CardFieldKind | null, htmlType: string, nameOrId: string): CardFieldKind | null {
  if (!kind && htmlType.toLowerCase() === "password" && isCvvNameOrId(nameOrId)) return "cardcvv";
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

/** DOM input → FieldSignal. autocomplete tokens pass through as hints — classify() lowercases
 *  and strips [-_], so "current-password"/"new-password" land on the canonical hint sets;
 *  the map above covers the three whose Android-hint spelling differs. */
export function fieldSignalOf(input: HTMLInputElement): FieldSignal & { isNewPassword: boolean } {
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
  input: HTMLInputElement;
  kind: FieldKind;
  isNewPassword: boolean;
  /** Username-fallback eligibility: unclassified text/email with no negative name signal. */
  textLike: boolean;
  /** Per-field card kind (pre-demotion, S3) — null on non-card fields. Only ever non-null in the
   *  `classify() == none` gap, so adding it never perturbs login grouping on card-free forms. */
  cardKind: CardFieldKind | null;
}

/** offsetParent is null for position:fixed elements even when visible — hence the rects check. */
function isVisible(el: HTMLElement): boolean {
  return el.offsetParent !== null || el.getClientRects().length > 0;
}

function collect(root: Document | ShadowRoot): Field[] {
  const out: Field[] = [];
  for (const input of root.querySelectorAll("input")) {
    if (input.disabled || input.readOnly || !isVisible(input)) continue;
    if (NON_FILLABLE_TYPES.has(input.type)) continue; // never fill a checkbox/submit, whatever its name
    const sig = fieldSignalOf(input);
    const kind = classify(sig);
    const t = input.type;
    const textLike =
      kind === "none" &&
      (t === "text" || t === "email") &&
      !NAME_NEGATIVE_RX.test((input.name || input.id).toLowerCase());
    const cardKind = classifyCardField(sig);
    if (kind !== "none" || textLike || cardKind !== null)
      out.push({ input, kind, isNewPassword: sig.isNewPassword, textLike, cardKind });
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
 *  Leftover password-less fields form one root-scoped group (username-step candidate). */
function formlessGroups(loose: Field[], root: Document | ShadowRoot): { container: Scope; fields: Field[] }[] {
  const remaining = new Set(loose);
  const groups: { container: Scope; fields: Field[] }[] = [];
  for (const f of loose) {
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
  if (remaining.size > 0) groups.push({ container: root, fields: [...remaining] });
  return groups;
}

function buildLoginForm(form: HTMLFormElement | null, container: Scope, fields: Field[]): LoginForm | null {
  const passwords = fields.filter((f) => f.kind === "password");
  // [A7] formKind gate: ANY form carrying a detected card-NUMBER field is a card form and is
  // excluded from the login capture/save path — an "update" here would overwrite a stored merchant
  // password with a PAN/CVV. This is the general fix; the lone-CVV rule below is the narrower one.
  const isCardForm = fields.some((f) => f.cardKind === "cardnumber");

  if (passwords.length === 0) {
    // Multi-step step 1: exactly one CLASSIFIED username (fallback pool doesn't qualify)
    // plus a way to advance — otherwise it's just a stray text field.
    const users = fields.filter((f) => f.kind === "username");
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
    if (fields[i]!.kind === "username") {
      username = fields[i]!.input;
      break;
    }
  }
  if (!username) {
    for (let i = pIdx - 1; i >= 0; i--) {
      if (fields[i]!.textLike) {
        username = fields[i]!.input;
        break;
      }
    }
  }

  // CVV-negative rule: only a genuinely password-TYPED input qualifies (a text field that
  // classify()'d password off a name keyword can't be a CVV box), and only when it is the
  // form's ONLY password field — a real username+password+cvv checkout keeps its banner path
  // (not lone), and a login form named normally is untouched. [A7] a card form (cardnumber
  // anchor present) also suppresses, regardless of the password count.
  const suppressSave =
    isCardForm ||
    (passwords.length === 1 && primary.input.type === "password" && isCvvNameOrId(primary.input.name || primary.input.id));

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
  input: HTMLInputElement;
}
export interface CardForm {
  form: HTMLFormElement | null;
  container: Scope;
  fields: CardFormFieldRef[];
}

function buildCardForm(form: HTMLFormElement | null, container: Scope, fields: Field[]): CardForm | null {
  if (!fields.some((f) => f.cardKind === "cardnumber")) return null; // a card form REQUIRES the PAN anchor
  const refs: CardFormFieldRef[] = [];
  for (const f of fields) {
    const kind = demoteCsc(f.cardKind, f.input.type, f.input.name || f.input.id);
    if (kind) refs.push({ kind, input: f.input });
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
