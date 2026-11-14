/**
 * The card-release rule (owner decision 2026-11-14, round-11 review; docs/design/2026-11-09-ios-app.md, "Card fill
 * threat model"): which documents may receive card data, and which of them one fill reaches.
 *
 * A card goes only into a payment provider's card document, and only into a frame where the person chose a card field
 * themselves: the newest choice, and with it only the quick taps of the same split card form (same provider origin,
 * same chain of documents, each within 30 s of the next; round-12 review). No frame is ever filled because of where it
 * sits. No fill happens while more than one provider card frame in the tab asks for the same card detail (an invisible
 * frame over the real one, or an extra one beside it), nor while a provider frame the page shows has not reported.
 *
 * Every input is a fact the browser reports, or a report of the content script running in that provider's own frame:
 * each frame's origin from its own messages (`sender.origin`; the origin of `sender.url` for the top frame only), its
 * frameId, its ancestor origins and whether it is collapsed, the card forms it holds and the field the person chose in
 * it. The shop's page's own word (the provider srcs its top frame shows) can only refuse a fill, never release one.
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
  /** False while the frame is collapsed: zero size, or nowhere in the top-level viewport (its content script asks). */
  shown?: boolean;
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

/** Whether two frames sit in the same chain of documents: the same ancestor origins, where the browser lists them. */
function sameAncestors(a: readonly string[] | null | undefined, b: readonly string[] | null | undefined): boolean {
  const listed = (x: readonly string[] | null | undefined): x is readonly string[] => Array.isArray(x);
  if (!listed(a) && !listed(b)) return true; // the browser lists none (Firefox): nothing to compare
  if (!listed(a) || !listed(b) || a.length !== b.length) return false;
  return a.every((o, i) => o === b[i]);
}

/**
 * The provider frames one fill reaches, newest first (round-12 review): the frame of the person's newest choice, and
 * with it only the choices that are of the same provider origin, sit in the same chain of documents (the same
 * `location.ancestorOrigins`, where the browser lists them), and were made within [CHOICE_CHAIN_MS] of the next newer
 * choice kept: the quick taps of one split card form. Any other choice (a field typed into for something else, a frame
 * of another widget) is dropped, and a choice that covers a kind a newer one covers is too. A choice made in any other
 * document is never one.
 */
export function chosenCardFrames(records: Readonly<Record<string, CardFrameRecord>>, now: number): ChosenCardFrame[] {
  const live: (ChosenCardFrame & { at: number; ancestors: readonly string[] | null | undefined })[] = [];
  for (const [fid, r] of Object.entries(records)) {
    if (!mayReceiveCard(r)) continue;
    const kinds = liveChoice(r, now);
    if (kinds !== null) live.push({ frameId: Number(fid), origin: r.origin, kinds, at: r.anchorAt!, ancestors: r.ancestors });
  }
  live.sort((x, y) => y.at - x.at || x.frameId - y.frameId);
  const newest = live[0];
  if (newest === undefined) return [];
  const covered = new Set<CardFieldKind>(newest.kinds);
  const kept = [newest];
  for (const c of live.slice(1)) {
    if (c.origin !== newest.origin || !sameAncestors(c.ancestors, newest.ancestors)) continue;
    if (kept[kept.length - 1]!.at - c.at > CHOICE_CHAIN_MS) break; // older still: every one after is further back
    if (c.kinds.some((k) => covered.has(k))) continue;
    for (const k of c.kinds) covered.add(k);
    kept.push(c);
  }
  return kept.map(({ frameId, origin, kinds }) => ({ frameId, origin, kinds }));
}

/** The newest live choice, or null (the popup names its frame's origin). */
export function chosenCardFrame(records: Readonly<Record<string, CardFrameRecord>>, now: number): ChosenCardFrame | null {
  return chosenCardFrames(records, now)[0] ?? null;
}

/**
 * The frames whose choice a new choice in [frameId] of [kinds] replaces: every other frame of the tab with a choice
 * whose form covers any of the same kinds. The worker clears them, and tells each frame to let its choice go.
 */
export function supersededChoices(records: Readonly<Record<string, CardFrameRecord>>, frameId: number, kinds: readonly CardFieldKind[], now: number): number[] {
  const mine = new Set(kinds);
  return Object.entries(records)
    .filter(([fid, r]) => Number(fid) !== frameId && (liveChoice(r, now)?.some((k) => mine.has(k)) ?? false))
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
  | { ok: false; reason: "no_choice" };

/**
 * The frames one fill reaches ([chosenCardFrames]), each with the form holding its chosen field. None while a provider
 * frame the page shows has not reported ([unreported]: its origin, from the page's own srcs, which can only refuse,
 * never release; round-12 review), so that a card kind it might offer cannot be counted; and none while any card kind is
 * offered by more than one provider card frame ([kindsOfferedTwice]).
 */
export function cardFillPlan(records: Readonly<Record<string, CardFrameRecord>>, now: number, unreported: string | null = null): CardFillPlan {
  if (unreported !== null) return { ok: false, reason: "unreported", origin: unreported };
  const twice = kindsOfferedTwice(records);
  if (twice.length > 0) return { ok: false, reason: "duplicate_kind", kinds: twice };
  const targets = chosenCardFrames(records, now);
  return targets.length > 0 ? { ok: true, targets } : { ok: false, reason: "no_choice" };
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
