/**
 * Pure field-detection engine — no chrome.*, no side effects. Classification defers to the
 * canonical, vector-tested classify() in urimatch.ts (verbatim port of web/src/vault/urimatch.ts);
 * this module only adapts DOM inputs into FieldSignals and groups them into fillable login forms.
 *
 * Scans are visible-fields-only: hidden inputs are where sites stash tokens and where phishing
 * kits hide credential sinks — and a multi-step page's not-yet-shown password field must NOT
 * collapse step 1 into a normal login form.
 */
import { classify, type FieldKind, type FieldSignal } from "./urimatch";

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

/** CVV keywords for the save-suppression rule — the tight core of the core classifier's
 *  CSC_DEMOTION set (FieldClassifier.kt), whole-token-run matched, never substring. */
const CVV_TOKENS = ["cvv", "cvc", "csc"];

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
    if (kind !== "none" || textLike) out.push({ input, kind, isNewPassword: sig.isNewPassword, textLike });
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
      suppressSave: false,
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
  // (not lone), and a login form named normally is untouched.
  const suppressSave =
    passwords.length === 1 && primary.input.type === "password" && isCvvNameOrId(primary.input.name || primary.input.id);

  return { kind: "login", form, container, username, password: primary.input, newPasswords, isSignup, suppressSave };
}

/** All fillable login forms under `root`, document order: formed groups first, then formless
 *  clusters. Does not descend into shadow roots — callers pass each root they care about. */
export function findLoginForms(root: Document | ShadowRoot): LoginForm[] {
  const fields = collect(root);
  const byForm = new Map<HTMLFormElement | null, Field[]>();
  for (const f of fields) {
    const list = byForm.get(f.input.form);
    if (list) list.push(f);
    else byForm.set(f.input.form, [f]);
  }

  const out: LoginForm[] = [];
  for (const [form, group] of byForm) {
    if (form === null) continue;
    const built = buildLoginForm(form, form, group);
    if (built) out.push(built);
  }
  const loose = byForm.get(null);
  if (loose) {
    for (const g of formlessGroups(loose, root)) {
      const built = buildLoginForm(null, g.container, g.fields);
      if (built) out.push(built);
    }
  }
  return out;
}
