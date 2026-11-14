/**
 * The card-release rule (owner decision 2026-11-14; docs/design/2026-11-09-ios-app.md, "Card fill threat model"):
 * which documents may receive card data, which choice a fill goes from, and which frames a fill reaches when a provider
 * puts each card field in a frame of its own.
 *
 * Every input is a fact the browser reports: each frame's origin from its own messages (`sender.origin`, else the origin
 * of `sender.url`), its frameId, and the origins of the documents it is nested in (`location.ancestorOrigins`, as the
 * content script running in that frame reads it; the page around it cannot change that list). Nothing a page writes
 * into its own DOM (a frame's src, a form's action, where a frame sits) is an input, so nothing a page does there can
 * change the answer.
 *
 * LEAF module (no chrome import): background.ts feeds it, node --test pins it (cardrelease.test.ts).
 */
import { isCardProviderOrigin } from "./cardproviders.ts";
import type { CardFieldKind } from "./detect.ts";
import { webOriginOfUrl } from "./senderorigin.ts";

/**
 * The origin the browser reports for the frame a message came from: `sender.origin` when the engine sets one (an opaque
 * "null", a sandboxed document's, is no origin), else the origin of the frame's own `sender.url` (Safari does not
 * promise `origin`). Null for anything but an http(s) document.
 */
export function frameOriginOf(sender: { origin?: unknown; url?: unknown }): string | null {
  if (sender.origin !== undefined) {
    return typeof sender.origin === "string" && sender.origin !== "" && sender.origin !== "null" ? sender.origin : null;
  }
  return webOriginOfUrl(sender.url);
}

/** What a frame reported about its card forms, with the browser-reported origin it reported from. */
export interface CardFrameRecord {
  origin: string;
  /** Each card form's field kinds, in document order. */
  forms: CardFieldKind[][];
  /** The index in [forms] of the form holding the field the person chose in this frame, or null. */
  anchor?: number | null;
  /** When this worker heard of that choice (ms). */
  anchorAt?: number;
  /**
   * The origins of the documents this frame is nested in, nearest first (`location.ancestorOrigins`, read by the content
   * script in this frame; empty for a top-level page). Null where the browser has no such list (Firefox): such a frame
   * has no split-field siblings, and a fill reaches it alone.
   */
  ancestors?: readonly string[] | null;
}

/** How long a choice stands: a fill long after it is a new decision, and asks for a new press. */
export const CHOICE_TTL_MS = 10 * 60 * 1000;

/** Whether the frame a record came from may receive card data: a provider's document with a card form. */
export function mayReceiveCard(r: CardFrameRecord | undefined): r is CardFrameRecord {
  return r !== undefined && isCardProviderOrigin(r.origin) && Array.isArray(r.forms) && r.forms.length > 0;
}

/** The frames of a tab that may receive card data, by frameId. */
export function providerCardFrames(records: Readonly<Record<string, CardFrameRecord>>): { frameId: number; origin: string }[] {
  return Object.entries(records)
    .filter(([, r]) => mayReceiveCard(r))
    .map(([fid, r]) => ({ frameId: Number(fid), origin: r.origin }));
}

/** Whether the tab has card forms only in documents that may not receive card data (a shop's own form). */
export function pageCardFormsOnly(records: Readonly<Record<string, CardFrameRecord>>): boolean {
  const all = Object.values(records).filter((r) => Array.isArray(r.forms) && r.forms.length > 0);
  return all.length > 0 && !all.some((r) => isCardProviderOrigin(r.origin));
}

export interface ChosenCardFrame {
  frameId: number;
  origin: string;
  /** The kinds of the form holding the chosen field. */
  kinds: CardFieldKind[];
}

/**
 * The frame where the person chose a card field last, in a provider's document, with the form holding it; null when no
 * provider frame holds a choice made within [CHOICE_TTL_MS]. A choice in any other document is never one.
 */
export function chosenCardFrame(records: Readonly<Record<string, CardFrameRecord>>, now: number): ChosenCardFrame | null {
  let best: (ChosenCardFrame & { at: number }) | null = null;
  for (const [fid, r] of Object.entries(records)) {
    if (!mayReceiveCard(r)) continue;
    const a = r.anchor;
    const at = r.anchorAt;
    if (typeof a !== "number" || !Number.isInteger(a) || a < 0 || a >= r.forms.length || typeof at !== "number") continue;
    if (now - at > CHOICE_TTL_MS || at - now > 60_000) continue;
    const kinds = r.forms[a]!;
    if (!Array.isArray(kinds) || kinds.length === 0) continue;
    if (best === null || at > best.at) best = { frameId: Number(fid), origin: r.origin, kinds, at };
  }
  return best === null ? null : { frameId: best.frameId, origin: best.origin, kinds: best.kinds };
}

export interface CardFillTarget extends ChosenCardFrame {
  /** The frame the person chose in; the others are its split-field siblings. */
  chosen: boolean;
}

/** Whether two frames are nested in the same chain of documents, by origin: both lists known and equal. */
function sameAncestors(a: readonly string[] | null | undefined, b: readonly string[] | null | undefined): boolean {
  if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) return false;
  return a.every((o, i) => o === b[i]);
}

/** What one fill does: the frames it reaches, or why it reaches none. */
export type CardFillPlan =
  | { ok: true; targets: CardFillTarget[] }
  /** Two of the frames the fill would reach take the same card detail (a frame the page added beside the provider's):
   *  nothing is filled, since nothing tells which of them is the provider's own. */
  | { ok: false; reason: "duplicate_kind"; kinds: CardFieldKind[] };

/**
 * The frames one fill reaches. The chosen frame, with the form holding the chosen field. And, for a provider that puts
 * each field in a frame of its own (Braintree, Adyen, Checkout.com, Cybersource, VGS and others), every other frame of
 * the tab with the same browser-reported origin and the same chain of ancestor origins that holds one card form: each
 * receives its own form's kinds, and nothing else. A frame nested elsewhere (inside an ad, or one level deeper) never
 * does, whatever its origin; where the browser gives no ancestor list (Firefox) the chosen frame is filled alone, one
 * field per Fill. Exactly one frame may take each kind: when two would (an extra frame the page put beside the
 * provider's, even one of the same provider), the whole fill is refused.
 */
export function cardFillPlan(records: Readonly<Record<string, CardFrameRecord>>, chosen: ChosenCardFrame): CardFillPlan {
  const targets: CardFillTarget[] = [{ ...chosen, chosen: true }];
  const chain = records[chosen.frameId]?.ancestors;
  if (Array.isArray(chain)) {
    for (const [fid, r] of Object.entries(records)) {
      const frameId = Number(fid);
      if (frameId === chosen.frameId || !mayReceiveCard(r) || r.origin !== chosen.origin || !sameAncestors(r.ancestors, chain)) continue;
      if (r.forms.length !== 1) continue;
      const kinds = r.forms[0]!;
      if (!Array.isArray(kinds) || kinds.length === 0) continue;
      targets.push({ frameId, origin: r.origin, kinds, chosen: false });
    }
  }
  const taken = new Set<CardFieldKind>();
  const twice = new Set<CardFieldKind>();
  for (const t of targets) {
    for (const k of new Set(t.kinds)) {
      if (taken.has(k)) twice.add(k);
      taken.add(k);
    }
  }
  if (twice.size > 0) return { ok: false, reason: "duplicate_kind", kinds: [...twice] };
  return { ok: true, targets };
}

/** A card grant: what one frame may redeem once, for one fill. */
export interface CardGrant {
  itemId: string;
  frameId: number;
  origin: string;
  kinds: CardFieldKind[];
  sig: string;
  expiresMs: number;
}

/**
 * Whether [sender] may redeem [grant] for [itemId] now: the frame the grant was minted for, still at the provider origin
 * it was minted for (as the browser reports it now), before the grant expires. Each frame redeems its own grant; none
 * redeems another's.
 */
export function mayRedeem(grant: CardGrant | undefined, itemId: string, sender: { frameId?: unknown; origin?: unknown; url?: unknown }, now: number): grant is CardGrant {
  if (grant === undefined || grant.itemId !== itemId || grant.expiresMs <= now) return false;
  if (typeof sender.frameId !== "number" || sender.frameId !== grant.frameId) return false;
  const origin = frameOriginOf(sender);
  return origin !== null && origin === grant.origin && isCardProviderOrigin(origin);
}
