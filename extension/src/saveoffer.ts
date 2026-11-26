import * as T from "./copy.ts";
import type { PendingSave } from "./messages";

/**
 * The save/update banner's words (security review 2026-10, branch A11, q14). Pure and DOM-free so it is node-testable;
 * content-ui.ts renders the parts. The banner always names the DESTINATION vault (the name decrypted under a key this
 * browser holds, never a server label), and an Update into a vault other than the in-force personal vault says so in
 * words: whoever else holds that vault can read the new password.
 */
export interface OfferPart {
  text: string;
  hl: boolean;
}

/** Design 2026-11-15 §12.2 rule 4: the extension writes only to the personal vault, so a changed password for a
 *  login in a shared vault is not an Update offer: it is this notice, and its one button only closes the banner. */
export function sharedLoginNotice(p: PendingSave): boolean {
  return p.updatesItemId !== null && p.vaultShared !== false;
}

/**
 * [template]'s words as parts, each `{n}` slot a highlighted part holding `values[n]` (as text, never markup). A slot
 * with quotation marks around it in the template ("“{1}”") takes them into the highlight. Empty text parts are left
 * out, so a line's parts read exactly as the line.
 */
export function slotParts(template: string, ...values: string[]): OfferPart[] {
  const parts: OfferPart[] = [];
  const re = /“?\{(\d+)\}”?/g;
  let at = 0;
  for (const m of template.matchAll(re)) {
    const i = m.index ?? 0;
    if (i > at) parts.push({ text: template.slice(at, i), hl: false });
    const v = values[Number(m[1])] ?? m[0];
    const open = m[0].startsWith("“") ? "“" : "";
    const close = m[0].endsWith("”") ? "”" : "";
    parts.push({ text: `${open}${v}${close}`, hl: true });
    at = i + m[0].length;
  }
  if (at < template.length) parts.push({ text: template.slice(at), hl: false });
  return parts;
}

export function saveOfferCopy(p: PendingSave): { parts: OfferPart[]; primary: string } {
  const named = p.vaultName ?? null;
  if (sharedLoginNotice(p)) return { parts: slotParts(T.SHARED_LOGIN_NOTICE, named ?? T.A_SHARED_VAULT), primary: T.OK };
  if (p.updatesItemId) {
    // The existing item's username too: auto-saved items are named after the host, so the name alone can't
    // distinguish a password change from a wrong-account merge (2b guard).
    const item = p.updatesItemName ?? T.THIS_LOGIN;
    const user = p.updatesItemUsername || null;
    const parts =
      user !== null && named
        ? slotParts(T.UPDATE_PASSWORD_OFFER_USER_IN, item, user, named)
        : user !== null
          ? slotParts(T.UPDATE_PASSWORD_OFFER_USER, item, user)
          : named
            ? slotParts(T.UPDATE_PASSWORD_OFFER_IN, item, named)
            : slotParts(T.UPDATE_PASSWORD_OFFER, item);
    return { parts, primary: T.UPDATE };
  }
  return { parts: named ? slotParts(T.SAVE_LOGIN_OFFER_IN, p.host, named) : slotParts(T.SAVE_LOGIN_OFFER, p.host), primary: T.SAVE };
}
