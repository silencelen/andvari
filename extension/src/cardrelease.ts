/**
 * The card-release rule (owner decision 2026-11-14, round-11 review; docs/design/2026-11-09-ios-app.md, "Card fill
 * threat model"): which documents may receive card data, and which of them one fill reaches.
 *
 * A card goes only into a payment provider's card document, and only into a frame where the person chose a card field
 * themselves (a provider that puts each field in a frame of its own is filled by choosing each field, then pressing
 * Fill once). No frame is ever filled because of where it sits. And no fill happens while more than one provider card
 * frame in the tab asks for the same card detail: an invisible frame over the real one, or an extra one beside it,
 * turns the fill into a refusal.
 *
 * Every input is a fact the browser reports, or a report of the content script running in that provider's own frame:
 * each frame's origin from its own messages (`sender.origin`, else the origin of `sender.url`), its frameId, the card
 * forms it holds and the field the person chose in it. Nothing the shop's page writes into its own DOM is an input.
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
 * Every provider frame holding a live choice of the person's, with the form holding the chosen field, newest first. A
 * choice made in any other document is never one. Of two choices covering the same kind, the newer stands (the
 * worker also clears the older one when the newer is made: [supersededChoices]).
 */
export function chosenCardFrames(records: Readonly<Record<string, CardFrameRecord>>, now: number): ChosenCardFrame[] {
  const live: (ChosenCardFrame & { at: number })[] = [];
  for (const [fid, r] of Object.entries(records)) {
    if (!mayReceiveCard(r)) continue;
    const kinds = liveChoice(r, now);
    if (kinds !== null) live.push({ frameId: Number(fid), origin: r.origin, kinds, at: r.anchorAt! });
  }
  live.sort((x, y) => y.at - x.at || x.frameId - y.frameId);
  const covered = new Set<CardFieldKind>();
  const out: ChosenCardFrame[] = [];
  for (const c of live) {
    if (c.kinds.some((k) => covered.has(k))) continue;
    for (const k of c.kinds) covered.add(k);
    out.push({ frameId: c.frameId, origin: c.origin, kinds: c.kinds });
  }
  return out;
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
  | { ok: false; reason: "duplicate_kind"; kinds: CardFieldKind[] }
  | { ok: false; reason: "no_choice" };

/**
 * The frames one fill reaches: every provider frame where the person chose a card field (one tap in a single-frame card
 * element; one in each frame of a split one), each with the form holding its chosen field. None while any card kind is
 * offered by more than one provider card frame ([kindsOfferedTwice]).
 */
export function cardFillPlan(records: Readonly<Record<string, CardFrameRecord>>, now: number): CardFillPlan {
  const twice = kindsOfferedTwice(records);
  if (twice.length > 0) return { ok: false, reason: "duplicate_kind", kinds: twice };
  const targets = chosenCardFrames(records, now);
  return targets.length > 0 ? { ok: true, targets } : { ok: false, reason: "no_choice" };
}

/** Whether [shown] (what the popup showed, as it sends it back) names exactly the frames and origins of [targets]. */
export function sameFrames(shown: unknown, targets: readonly { frameId: number; origin: string }[]): boolean {
  if (!Array.isArray(shown) || shown.length !== targets.length) return false;
  const keys = new Set<string>();
  for (const f of shown) {
    if (typeof f !== "object" || f === null) return false;
    const { frameId, origin } = f as { frameId?: unknown; origin?: unknown };
    if (typeof frameId !== "number" || typeof origin !== "string") return false;
    keys.add(`${frameId}|${origin}`);
  }
  return keys.size === targets.length && targets.every((t) => keys.has(`${t.frameId}|${t.origin}`));
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
