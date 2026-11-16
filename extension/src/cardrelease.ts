/**
 * The card-release rule (owner decision 2026-11-14, round-11 review; docs/design/2026-11-09-ios-app.md, "Card fill
 * threat model"): which documents may receive card data, and which of them one fill reaches.
 *
 * A card goes only into a payment provider's card document, and only into a frame where the person chose a card field
 * themselves: the newest choice, and with it only the quick taps of the same split card form (same provider origin,
 * same chain of documents, each within 30 s of the next; round-12 review). No frame is ever filled because of where it
 * sits. No fill happens while the person's choices sit in more than one payment form (round-13 review: another
 * provider origin, another chain of documents, or another merchant account), nor while more than one provider card
 * frame in the tab asks for the same card detail (an invisible frame over the real one, or an extra one beside it),
 * nor while a provider frame the page shows has not reported.
 *
 * Every input is a fact the browser reports, or a report of the content script running in that provider's own frame:
 * each frame's origin from its own messages (`sender.origin`; the origin of `sender.url` for the top frame only), its
 * frameId, its ancestor origins (or, on Firefox, its parent's frameId), the merchant account its own URL names, whether
 * it is collapsed, the card forms it holds and the field the person chose in it. The shop's page's own word (the
 * provider srcs its top frame shows) can only refuse a fill, never release one.
 *
 * LEAF module (no chrome import): background.ts feeds it, node --test pins it (cardrelease.test.ts).
 */
import { isCardProviderOrigin } from "./cardproviders.ts";
import type { CardFieldKind } from "./detect.ts";
import { webOriginOfUrl } from "./senderorigin.ts";

/**
 * The origin the browser reports for the frame a message came from: `sender.origin` when the engine sets one (an opaque
 * "null", a sandboxed document's, is no origin). Without it, the origin of the frame's own `sender.url`, for the top
 * frame only (Safari does not promise `origin`): a sandboxed sub-frame keeps its URL but has no origin (round-12
 * review), so a sub-frame with no `sender.origin` has none. Null for anything but an http(s) document.
 */
export function frameOriginOf(sender: { origin?: unknown; url?: unknown; frameId?: unknown }): string | null {
  if (sender.origin !== undefined) {
    return typeof sender.origin === "string" && sender.origin !== "" && sender.origin !== "null" ? sender.origin : null;
  }
  return sender.frameId === 0 ? webOriginOfUrl(sender.url) : null;
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
   * script in this frame); null where the browser has no such list (Firefox).
   */
  ancestors?: readonly string[] | null;
  /**
   * Firefox, which lists no ancestors: the frameId of this frame's parent, as the browser gives it to the content script
   * in this frame (`runtime.getFrameId(window.parent)`); null where it could not say.
   */
  parent?: number | null;
  /** The merchant account the frame's own URL names (cardproviders.ts providerAccountOf); null where it names none. */
  account?: string | null;
  /**
   * False while the frame is collapsed: it has never shown in the top-level viewport with a size, or it has no size now
   * ([frameCounts]; its content script asks). A frame scrolled out of view after it showed keeps counting.
   */
  shown?: boolean;
}

/**
 * Whether a provider's card frame counts (round-13 review, rule 5): once it has shown in the top-level viewport with a
 * size, it keeps counting wherever the page is scrolled, until it has no size (or is removed, which ends its script).
 * Before it has shown it is collapsed: a second payment method's frame, or a stored card's, kept out of sight.
 */
export function frameCounts(everShown: boolean, width: number, height: number): boolean {
  return everShown && width > 0 && height > 0;
}

/** How long a choice stands (round-12 review: 2 minutes): a fill later than that is a new decision, and asks for a new press. */
export const CHOICE_TTL_MS = 2 * 60 * 1000;

/** How far apart two choices of one fill may be (round-12 review): a split card form is a chain of quick taps. */
export const CHOICE_CHAIN_MS = 30 * 1000;

/**
 * Whether the frame a record came from may receive card data: a provider's card document with a card form, not
 * collapsed (round-12 review: a frame of zero size, or nowhere in the viewport, neither counts nor can be chosen).
 */
export function mayReceiveCard(r: CardFrameRecord | undefined): r is CardFrameRecord {
  return r !== undefined && isCardProviderOrigin(r.origin) && Array.isArray(r.forms) && r.forms.length > 0 && r.shown !== false;
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
  /** The frame's ancestor origins, nearest first, where the browser lists them (the popup names those below the top). */
  ancestors?: readonly string[] | null;
}

/** The live choice a record holds, or null: an index into its forms, made within [CHOICE_TTL_MS]. */
function liveChoice(r: CardFrameRecord, now: number): CardFieldKind[] | null {
  const a = r.anchor;
  const at = r.anchorAt;
  if (typeof a !== "number" || !Number.isInteger(a) || a < 0 || a >= r.forms.length || typeof at !== "number") return null;
  if (now - at > CHOICE_TTL_MS || at - now > 60_000) return null;
  const kinds = r.forms[a]!;
  return Array.isArray(kinds) && kinds.length > 0 ? kinds : null;
}

/**
 * The payment form a provider frame belongs to (round-13 review): its provider origin, its chain of documents (its
 * ancestor origins, or on Firefox its parent frame) and the merchant account its URL names. [chainKnown] is false
 * where the browser said neither ancestors nor parent: then nothing tells two such frames' forms apart.
 */
export function formGroupOf(r: CardFrameRecord): { key: string; chainKnown: boolean } {
  const chain = Array.isArray(r.ancestors) ? `a:${JSON.stringify(r.ancestors)}` : typeof r.parent === "number" ? `p:${r.parent}` : null;
  return { key: `${r.origin}|${chain ?? "?"}|${r.account ?? ""}`, chainKnown: chain !== null };
}

type LiveChoice = ChosenCardFrame & { at: number; group: string; chainKnown: boolean };

/** The live choices of a tab's provider card frames, newest first. */
function liveChoices(records: Readonly<Record<string, CardFrameRecord>>, now: number): LiveChoice[] {
  const live: LiveChoice[] = [];
  for (const [fid, r] of Object.entries(records)) {
    if (!mayReceiveCard(r)) continue;
    const kinds = liveChoice(r, now);
    if (kinds === null) continue;
    const g = formGroupOf(r);
    live.push({ frameId: Number(fid), origin: r.origin, kinds, at: r.anchorAt!, ancestors: r.ancestors ?? null, group: g.key, chainKnown: g.chainKnown });
  }
  return live.sort((x, y) => y.at - x.at || x.frameId - y.frameId);
}

/**
 * Whether the person's live choices sit in more than one payment form (round-13 review): another provider origin,
 * another chain of documents, or another merchant account. A choice is never let go for being older or for being in
 * the other form: the person says which form they meant by tapping it again (after Start over). Where the browser says
 * no chain for a frame, choices in two frames are taken as two forms.
 */
export function choicesSpanForms(records: Readonly<Record<string, CardFrameRecord>>, now: number): boolean {
  const live = liveChoices(records, now);
  if (live.length < 2) return false;
  if (live.some((c) => !c.chainKnown)) return true;
  return new Set(live.map((c) => c.group)).size > 1;
}

/**
 * The provider frames one fill reaches, newest first (round-12 review), when the person's choices sit in one payment
 * form ([choicesSpanForms]; none otherwise): the frame of the newest choice, and with it the choices made within
 * [CHOICE_CHAIN_MS] of the next newer choice kept, the quick taps of one split card form. A choice that covers a kind a
 * newer one covers is dropped. A choice made in any other document is never one.
 */
export function chosenCardFrames(records: Readonly<Record<string, CardFrameRecord>>, now: number): ChosenCardFrame[] {
  if (choicesSpanForms(records, now)) return [];
  const live = liveChoices(records, now);
  const newest = live[0];
  if (newest === undefined) return [];
  const covered = new Set<CardFieldKind>(newest.kinds);
  const kept = [newest];
  for (const c of live.slice(1)) {
    if (c.group !== newest.group) continue; // never: one form only, above
    if (kept[kept.length - 1]!.at - c.at > CHOICE_CHAIN_MS) break; // older still: every one after is further back
    if (c.kinds.some((k) => covered.has(k))) continue;
    for (const k of c.kinds) covered.add(k);
    kept.push(c);
  }
  return kept.map(({ frameId, origin, kinds, ancestors }) => ({ frameId, origin, kinds, ancestors }));
}

/** The newest live choice, or null (the popup names its frame's origin). */
export function chosenCardFrame(records: Readonly<Record<string, CardFrameRecord>>, now: number): ChosenCardFrame | null {
  return chosenCardFrames(records, now)[0] ?? null;
}

/**
 * The frames whose choice a new choice in [frameId] of [kinds] replaces: every other frame of the same payment form
 * ([formGroupOf]) with a choice whose form covers any of the same kinds. The worker clears them, and tells each frame to
 * let its choice go. A choice in another form is left standing (round-13 review): the fill then refuses until the person
 * starts over, rather than the newest tap deciding which form gets the card.
 */
export function supersededChoices(records: Readonly<Record<string, CardFrameRecord>>, frameId: number, kinds: readonly CardFieldKind[], now: number): number[] {
  const mine = new Set(kinds);
  const self = records[String(frameId)];
  if (self === undefined) return [];
  const group = formGroupOf(self).key;
  return Object.entries(records)
    .filter(([fid, r]) => Number(fid) !== frameId && formGroupOf(r).key === group && (liveChoice(r, now)?.some((k) => mine.has(k)) ?? false))
    .map(([fid]) => Number(fid));
}

/** The frames of a tab holding a choice: what "Start over" lets go (round-13 review). */
export function framesWithChoices(records: Readonly<Record<string, CardFrameRecord>>): number[] {
  return Object.entries(records)
    .filter(([, r]) => typeof r.anchor === "number")
    .map(([fid]) => Number(fid));
}

/**
 * The card kinds more than one provider card frame of the tab offers (any origin, any parent), as the content script in
 * each of those frames reports its card forms. While there is any, nothing is filled: nothing tells which of two frames
 * asking for the same detail is the box the person meant, and an invisible frame laid over the real one, or an extra
 * one beside it, is exactly that.
 */
export function kindsOfferedTwice(records: Readonly<Record<string, CardFrameRecord>>): CardFieldKind[] {
  const seen = new Set<CardFieldKind>();
  const twice = new Set<CardFieldKind>();
  for (const r of Object.values(records)) {
    if (!mayReceiveCard(r)) continue;
    const offered = new Set(r.forms.flat());
    for (const k of offered) {
      if (seen.has(k)) twice.add(k);
      seen.add(k);
    }
  }
  return [...twice].sort();
}

/** What one fill does: the frames it reaches, or why it reaches none. */
export type CardFillPlan =
  | { ok: true; targets: ChosenCardFrame[] }
  | { ok: false; reason: "unreported"; origin: string }
  | { ok: false; reason: "duplicate_kind"; kinds: CardFieldKind[] }
  | { ok: false; reason: "mixed_forms" }
  | { ok: false; reason: "no_choice" };

/**
 * The frames one fill reaches ([chosenCardFrames]), each with the form holding its chosen field. None while a provider
 * frame the page shows has not reported ([unreported]: its origin, from the page's own srcs, which can only refuse,
 * never release; round-12 review), so that a card kind it might offer cannot be counted; none while any card kind is
 * offered by more than one provider card frame ([kindsOfferedTwice]); and none while the person's choices sit in more
 * than one payment form ([choicesSpanForms], round-13 review).
 */
export function cardFillPlan(records: Readonly<Record<string, CardFrameRecord>>, now: number, unreported: string | null = null): CardFillPlan {
  if (unreported !== null) return { ok: false, reason: "unreported", origin: unreported };
  const twice = kindsOfferedTwice(records);
  if (twice.length > 0) return { ok: false, reason: "duplicate_kind", kinds: twice };
  if (choicesSpanForms(records, now)) return { ok: false, reason: "mixed_forms" };
  const targets = chosenCardFrames(records, now);
  return targets.length > 0 ? { ok: true, targets } : { ok: false, reason: "no_choice" };
}

/**
 * Where a fill goes, in words (round-13 review): each target's provider host, with the documents it sits in below the
 * top one ("js.stripe.com inside rewards.example"), so a provider frame inside another site's widget says so. Ancestors
 * are nearest first; the last is the top document, which the popup does not repeat.
 */
export function fillDestination(frames: readonly { origin: string; ancestors?: readonly string[] | null }[]): string {
  const hostOf = (o: string): string => {
    try {
      return new URL(o).host;
    } catch {
      return o;
    }
  };
  const parts = frames.map((f) => [hostOf(f.origin), ...(Array.isArray(f.ancestors) ? f.ancestors.slice(0, -1) : []).map(hostOf)].join(" inside "));
  return [...new Set(parts)].join(", ");
}

/** Whether [shown] (what the popup showed, as it sends it back) names exactly the frames, origins and card details of
 *  [targets]. */
export function sameFrames(shown: unknown, targets: readonly { frameId: number; origin: string; kinds: readonly CardFieldKind[] }[]): boolean {
  if (!Array.isArray(shown) || shown.length !== targets.length) return false;
  const key = (frameId: number, origin: string, kinds: readonly unknown[]): string => `${frameId}|${origin}|${[...new Set(kinds.map(String))].sort().join(",")}`;
  const keys = new Set<string>();
  for (const f of shown) {
    if (typeof f !== "object" || f === null) return false;
    const { frameId, origin, kinds } = f as { frameId?: unknown; origin?: unknown; kinds?: unknown };
    if (typeof frameId !== "number" || typeof origin !== "string" || !Array.isArray(kinds)) return false;
    keys.add(key(frameId, origin, kinds));
  }
  return keys.size === targets.length && targets.every((t) => keys.has(key(t.frameId, t.origin, t.kinds)));
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
