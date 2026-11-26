import { changeOf, comparePinned, pinRecordOf, type Card, type ForwardResult, type PinnedResult, type PinRecord } from "./instancecard.ts";
import { isBakedInstance } from "./publicinstance.ts";
import { isHex64, isOrigin, isUuid, nameText } from "./statement.ts";

/**
 * The extension's card pin, one record per origin namespace, and the pin-store rules of design
 * 2026-11-15-onboarding-trust §4.4 as pure transitions. The record outlives sign-out and lives in the trusted store.
 *
 * - A root never replaces an existing pin: choosing a server that already has a pin refreshes that pin (the served
 *   chain is compared with it), it never makes a first pin over it.
 * - A fork is durable: stored with the pin, it survives restarts, and while it is set the extension refreshes nothing
 *   from that origin, sends nothing derived from the password, and every flow stops. The only way on is
 *   "Forget this server".
 * - A record that fails to decode is `damaged` and blocks the origin. It is never read as "no pin".
 * - A move or a `kind` change prompts (`pending`): until the person confirms, the old pin, and with it the old
 *   origin and `kind`, stays in use. A card that changes both is a `kind` change; accepting it records the `kind` and
 *   keeps the pin at its card, and the move is then a prompt of its own.
 * - A pin is only ever stored under its own origin; one that reads back under another is `damaged`.
 * - The baked public instance is never followed through a move or a `kind` change (`changed`): the extension keeps
 *   its pin and says "This server says it changed. Update andvari." (T-R7, T2-R-j).
 * - A move never replaces a pin that already exists for the new origin (`pin_conflict`, checked by the caller, which
 *   holds the store).
 *
 * Both extension roots, the baked instance and the Trust Gate's typed address, are password pins (§4.4).
 * LEAF module: no chrome.
 */

export interface StoredPin {
  readonly v: 1;
  readonly root: "baked" | "typed";
  readonly pin: PinRecord;
  readonly fork: boolean;
  readonly changed: boolean;
  readonly pending: { readonly change: "move" | "kind"; readonly card: PinRecord } | null;
}

export type PinRead = { kind: "none" } | { kind: "damaged" } | { kind: "pin"; stored: StoredPin };

/** The trusted-store key of the pin, under the origin's namespace. */
export const PIN_KEY = "cardPin";

const isObj = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);
const isInt = (v: unknown): v is number => typeof v === "number" && Number.isInteger(v) && v >= 0 && v < 2 ** 53;

function pinRecord(v: unknown): PinRecord | null {
  if (!isObj(v)) return null;
  const keys = ["instanceId", "card0Hash", "seq", "hash", "origin", "name", "kind", "operator", "operatorSignKey", "recoveryFp"];
  if (Object.keys(v).length !== keys.length || !keys.every((k) => k in v)) return null;
  const ok =
    typeof v.instanceId === "string" && isUuid(v.instanceId) &&
    typeof v.card0Hash === "string" && isHex64(v.card0Hash) &&
    isInt(v.seq) &&
    typeof v.hash === "string" && isHex64(v.hash) &&
    typeof v.origin === "string" && isOrigin(v.origin) &&
    typeof v.name === "string" && nameText(v.name) !== null &&
    (v.kind === "public" || v.kind === "private") &&
    typeof v.operator === "string" && isUuid(v.operator) &&
    typeof v.operatorSignKey === "string" && v.operatorSignKey.length === 43 &&
    typeof v.recoveryFp === "string" && (v.recoveryFp === "none" || isHex64(v.recoveryFp));
  return ok ? (v as unknown as PinRecord) : null;
}

/**
 * Read the pin stored under [origin]'s namespace: absent is `none`; anything that is not exactly a pin record is
 * `damaged`, and so is a pin whose own `origin` is not [origin] (§4.4: a client never stores such a record, so one that
 * reads back that way was not written by these rules, and dialing [origin] under it would trust another address's card).
 */
export function decodeStoredPin(raw: unknown, origin: string): PinRead {
  if (raw === undefined) return { kind: "none" };
  if (!isObj(raw) || raw.v !== 1 || (raw.root !== "baked" && raw.root !== "typed") || typeof raw.fork !== "boolean" || typeof raw.changed !== "boolean") {
    return { kind: "damaged" };
  }
  const pin = pinRecord(raw.pin);
  if (pin === null || pin.origin !== origin) return { kind: "damaged" };
  let pending: StoredPin["pending"] = null;
  if (raw.pending !== null) {
    const p = raw.pending;
    const card = isObj(p) ? pinRecord(p.card) : null;
    if (!isObj(p) || (p.change !== "move" && p.change !== "kind") || card === null) return { kind: "damaged" };
    pending = { change: p.change, card };
  }
  return { kind: "pin", stored: { v: 1, root: raw.root, pin, fork: raw.fork, changed: raw.changed, pending } };
}

/** A first pin, as stored. */
export function newStoredPin(root: "baked" | "typed", pin: PinRecord): StoredPin {
  return { v: 1, root, pin, fork: false, changed: false, pending: null };
}

export type RefreshVerdict = "ok" | "withheld" | "fork" | "changed" | "pending";

/**
 * A verified served chain against the stored pin (§4.4, "On every policy probe or sync"). A stored fork stays a fork
 * and nothing is read from the chain. Otherwise: `fork` (stored, durable); `withheld` (nothing changes: the newer
 * pinned card is kept); or the newest card: no move or `kind` change advances the pin (a rename, a handover, a
 * recovery-key rotation); a move or `kind` change of the baked instance is `changed` (never followed); of any other
 * instance it is `pending` until the person confirms.
 */
export function refreshPin(stored: StoredPin, cards: readonly Card[]): { stored: StoredPin; verdict: RefreshVerdict } {
  if (stored.fork) return { stored, verdict: "fork" };
  return judgeServed(stored, comparePinned(cards, stored.pin));
}

/**
 * [refreshPin] over a chain verified forward from the pin (instancecard.ts verifyForward):
 * the same transitions. A served chain whose newest card is the pinned one changes nothing but clears a stale prompt.
 */
export function refreshPinForward(stored: StoredPin, served: Extract<ForwardResult, { ok: true }>): { stored: StoredPin; verdict: RefreshVerdict } {
  if (stored.fork) return { stored, verdict: "fork" };
  if (served.verdict === "ok" && served.newest === null) return { stored: { ...stored, changed: false, pending: null }, verdict: "ok" };
  return judgeServed(stored, served.verdict === "ok" ? { verdict: "ok", newest: served.newest! } : { verdict: served.verdict });
}

function judgeServed(stored: StoredPin, cmp: PinnedResult): { stored: StoredPin; verdict: RefreshVerdict } {
  if (cmp.verdict === "fork") return { stored: { ...stored, fork: true, pending: null }, verdict: "fork" };
  if (cmp.verdict === "withheld") return { stored, verdict: "withheld" };
  const change = changeOf(stored.pin, cmp.newest);
  if (change === "none") {
    return { stored: { ...stored, pin: pinRecordOf(cmp.newest, stored.pin.card0Hash), changed: false, pending: null }, verdict: "ok" };
  }
  if (isBakedInstance(stored.pin)) return { stored: { ...stored, changed: true, pending: null }, verdict: "changed" };
  return { stored: { ...stored, pending: { change, card: pinRecordOf(cmp.newest, stored.pin.card0Hash) } }, verdict: "pending" };
}

/**
 * The person confirmed a pending `kind` change (§4.4). When the newest card keeps the pin's origin, the pin takes it.
 * When it also moved, the pin records only the accepted `kind` and stays at its card, under its own origin: the move is
 * then offered by the next refresh as a prompt of its own, and only following that advances the pin (CardTrust.kt
 * acceptKindChange). Null when no `kind` change is pending.
 */
export function confirmKindChange(stored: StoredPin): StoredPin | null {
  if (stored.fork || stored.pending?.change !== "kind") return null;
  const card = stored.pending.card;
  if (card.origin === stored.pin.origin) return { ...stored, pin: card, pending: null };
  return { ...stored, pin: { ...stored.pin, kind: card.kind }, pending: null };
}

/** The person confirmed a pending move: the pin for the new origin (the caller refuses it when one exists there). */
export function confirmMove(stored: StoredPin): { origin: string; stored: StoredPin } | null {
  if (stored.fork || stored.pending?.change !== "move") return null;
  const card = stored.pending.card;
  return { origin: card.origin, stored: { ...stored, pin: card, pending: null } };
}
