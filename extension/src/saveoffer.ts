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

export function saveOfferCopy(p: PendingSave): { parts: OfferPart[]; primary: string } {
  const parts: OfferPart[] = [];
  const t = (text: string) => parts.push({ text, hl: false });
  const h = (text: string) => parts.push({ text, hl: true });
  const named = p.vaultName ?? null;
  if (p.updatesItemId) {
    // The existing item's username too: auto-saved items are named after the host, so the name alone can't
    // distinguish a password change from a wrong-account merge (2b guard).
    t("Update the password for ");
    h(p.updatesItemName ?? "this login");
    if (p.updatesItemUsername) {
      t(" (");
      h(p.updatesItemUsername);
      t(")");
    }
    // A pending persisted by an older worker carries no flag: an update into an unnamed vault reads as shared.
    if (p.vaultShared !== false) {
      if (named) {
        t(" in the shared vault ");
        h(`“${named}”`);
      } else t(" in a shared vault");
      t("? Everyone who holds that vault can read it.");
      return { parts, primary: named ? `Update in ${named}` : "Update shared" };
    }
    if (named) {
      t(" in ");
      h(`“${named}”`);
    }
    t("?");
    return { parts, primary: "Update" };
  }
  t("Save this login for ");
  h(p.host);
  if (named) {
    t(" to ");
    h(`“${named}”`);
    t("?");
  } else t(" to andvari?");
  return { parts, primary: "Save" };
}
