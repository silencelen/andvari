import type { KeyValue } from "../api/devicesecret";
import type { InstanceResponse } from "../api/wire";
import { toHexLower } from "../crypto/bytes";
import { shortForm } from "../crypto/fingerprint";
import { sha256Sync } from "../crypto/provider";
import { compareCardPin } from "../crypto/trust/checkpoints";
import { fromB64Canonical, isB64_32, isHex64, isHex64n, isName, isOrigin, isUuid } from "../crypto/trust/grammar";
import {
  type CardPinRecord,
  checkBakedRoot,
  checkTypedRoot,
  type InstanceKind,
  operatorIdentityKey,
  pinRecordOf,
  type VerifiedCard,
  verifyCardChain,
} from "../crypto/trust/instancecard";
import type { BakedInstance } from "./publicinstance";

/**
 * The web client's pinned instance card (design §4.4), in this browser's storage, under the pin-store rules:
 *
 * - a pin is made only from a card chain the twin verified from card 0, anchored by the baked
 *   `card0Hash` (the public instance) or by the person's Trust Gate confirmation of exactly the chain shown;
 *   nothing served as JSON (the policy's `instanceName` or `canonicalOrigin`) ever becomes a pin;
 * - the dialed origin must be the newest card's origin (`origin_mismatch`);
 * - a root never replaces an existing pin: under a pin, the served chain is judged against it first and
 *   anything but ok stops;
 * - a fork is durable and blocks every flow until the person forgets the server;
 * - a record that fails to decode is `damaged` and blocks, never read as "no pin".
 *
 * The web dials one origin, the one that served it, and has no server choice (§12.2). It makes only the two
 * roots that need no link: `baked` and `trust_gate`. It cannot follow a move (another origin serves its own
 * web client), so a move is reported for the person to open the new address, and the pin stays.
 */

export type PinRoot = "baked" | "kit" | "setup" | "trust_gate" | "link_offer" | "enrol";

/** §4.4's record plus how the first pin was made. `name` is the card's `name` text (base64url); render it decoded, as plain text, beside the origin. */
export interface WebPin extends CardPinRecord {
  readonly root: PinRoot;
}

export type PinState =
  | { readonly kind: "none" }
  | { readonly kind: "pinned"; readonly pin: WebPin }
  /** A fork was seen: durable, the origin is stopped until "Forget this server". */
  | { readonly kind: "forked"; readonly pin: WebPin }
  /** The stored record does not decode: the origin is blocked. */
  | { readonly kind: "damaged" };

export type CardStatus =
  | { readonly kind: "ok"; readonly pin: WebPin }
  | { readonly kind: "fork"; readonly pinned: WebPin }
  /** The chain ends below the pin (or is empty): keep the pin, say "older version", retry on the next probe. */
  | { readonly kind: "withheld"; readonly pinned: WebPin }
  /** The newest card moved the origin. The web keeps its pin and tells the person where the server went. */
  | { readonly kind: "moved"; readonly pinned: WebPin; readonly newest: WebPin }
  /** The newest card changed `kind`: never followed silently. `mustUpdate` for the baked instance (no gate). */
  | { readonly kind: "kind_changed"; readonly pinned: WebPin; readonly newest: WebPin; readonly mustUpdate: boolean }
  /**
   * Under a pin in force, the served chain failed verification (core `InstanceCardState.NotVerified`, approved entry
   * 11): the pin stays exactly as it was and nothing stops; `verdict` names the failure, for logs only, never shown.
   */
  | { readonly kind: "not_verified"; readonly pinned: WebPin; readonly verdict: string }
  /** The origin is blocked or has no pin, or a prompt is stale: `verdict` names why; the pin stays. */
  | { readonly kind: "refused"; readonly verdict: string }
  /** The chain could not be fetched; the error is carried, the pin stays. */
  | { readonly kind: "unreachable"; readonly error: unknown };

/** Proof that the Trust Gate was shown for one exact chain: confirming it pins exactly that chain. */
export interface TrustGateTicket {
  readonly origin: string;
  readonly candidate: WebPin;
}

export type FirstPin =
  | { readonly kind: "pinned"; readonly pin: WebPin }
  /** Show the Trust Gate: the origin, the name "(as the server names itself)" and the operator key's 32-hex short form. */
  | { readonly kind: "needs_trust_gate"; readonly origin: string; readonly name: string; readonly operatorShortFp: string; readonly ticket: TrustGateTicket }
  /**
   * The served chain failed, or an anchor did not match (`withheld`, `origin_mismatch`, `card0_mismatch`, a card verdict).
   * For `origin_mismatch`, [cardOrigin] is the origin the newest card names (approved entry 8 shows it beside the dialed one).
   */
  | { readonly kind: "refused"; readonly verdict: string; readonly cardOrigin?: string }
  /** Under an existing pin the chain moved or changed kind: handled as that first. */
  | { readonly kind: "pin_changed"; readonly status: CardStatus }
  /** The origin is blocked: forked, or a damaged record. */
  | { readonly kind: "blocked"; readonly state: PinState }
  /** The call would swap the chain an existing pin holds. */
  | { readonly kind: "pin_conflict"; readonly pinned: WebPin }
  | { readonly kind: "unreachable"; readonly error: unknown };

const KEY_PREFIX = "andvari.pin2.";
const ROOTS: readonly PinRoot[] = ["baked", "kit", "setup", "trust_gate", "link_offer", "enrol"];

/** How much a root lets a pin do; a first-pin call on an existing pin may only raise it (core CardChainRules.rank). */
export function rank(root: PinRoot): number {
  switch (root) {
    case "baked":
    case "trust_gate":
      return 4;
    case "setup":
    case "kit":
      return 3;
    case "link_offer":
      return 2;
    case "enrol":
      return 1;
  }
}

function decodePin(origin: string, text: string): PinState {
  try {
    const o = JSON.parse(text) as Record<string, unknown>;
    const s = (k: string): string => {
      const v = o[k];
      if (typeof v !== "string") throw new Error(k);
      return v;
    };
    const seq = o.seq;
    if (typeof seq !== "number" || !Number.isSafeInteger(seq) || seq < 0) throw new Error("seq");
    const root = s("root") as PinRoot;
    const kind = s("kind");
    const pin: WebPin = {
      instanceId: s("instanceId"),
      card0Hash: s("card0Hash"),
      seq,
      hash: s("hash"),
      origin: s("origin"),
      name: s("name"),
      kind: kind as InstanceKind,
      operator: s("operator"),
      operatorSignKey: s("operatorSignKey"),
      recoveryFp: s("recoveryFp"),
      root,
    };
    const valid =
      ROOTS.includes(root) &&
      (kind === "public" || kind === "private") &&
      isUuid(pin.instanceId) &&
      isHex64(pin.card0Hash) &&
      isHex64(pin.hash) &&
      isOrigin(pin.origin) &&
      pin.origin === origin &&
      isName(pin.name) &&
      isUuid(pin.operator) &&
      isB64_32(pin.operatorSignKey) &&
      isHex64n(pin.recoveryFp) &&
      (o.forked === undefined || typeof o.forked === "boolean");
    if (!valid) return { kind: "damaged" };
    return o.forked === true ? { kind: "forked", pin } : { kind: "pinned", pin };
  } catch {
    return { kind: "damaged" };
  }
}

/** Judge a verified chain (card 0 first) against [pin] (§4.4; core CardChainRules.judge). */
export function judgeChain(pin: WebPin, cards: readonly VerifiedCard[], baked: BakedInstance | null): CardStatus {
  const verdict = compareCardPin(pin.card0Hash, { seq: pin.seq, hash: pin.hash }, cards.map((c) => c.hash));
  if (verdict === "withheld") return { kind: "withheld", pinned: pin };
  if (verdict === "fork") return { kind: "fork", pinned: pin };
  if (cards[0]!.fields.instanceId !== pin.instanceId) return { kind: "fork", pinned: pin };
  const newest: WebPin = { ...pinRecordOf(cards[cards.length - 1]!), root: pin.root, card0Hash: pin.card0Hash };
  const isBaked = baked !== null && (pin.card0Hash === baked.card0Hash || pin.origin === baked.origin);
  // A card that changes both origin and kind is a kind change, never a move alone.
  if (newest.kind !== pin.kind) return { kind: "kind_changed", pinned: pin, newest, mustUpdate: isBaked };
  if (newest.origin !== pin.origin) return { kind: "moved", pinned: pin, newest };
  return { kind: "ok", pin: newest };
}

/**
 * Design §12.2 rule 7 and §13: the web must not hold the operator account. True when the verified card [pin] names
 * [userId] as its `operator` (a handover can make a member the operator); the session is then signed out with the
 * operator sentence. Needs no signal from the server, so it also covers the unlock of a held session.
 */
export function cardNamesOperator(pin: CardPinRecord | null, userId: string): boolean {
  return pin !== null && pin.operator === userId;
}

/**
 * Design §4.4 "a fork stops traffic, not reading": why nothing may be sent to an origin in this pin state (`forked`, or
 * `damaged`: a record that does not decode checks nothing), or null when traffic may flow.
 */
export function pinStopsTraffic(state: PinState): "forked" | "damaged" | null {
  return state.kind === "forked" || state.kind === "damaged" ? state.kind : null;
}

/** The operator key's 32-hex short identity fingerprint, over its X25519 image (§4.1), for the Trust Gate. */
export function operatorShortFp(operatorSignKey: string): string {
  const x = operatorIdentityKey(operatorSignKey);
  return x === null ? "" : shortForm(toHexLower(sha256Sync(x)));
}

/** A first pin refused with [verdict]; an `origin_mismatch` carries the origin the newest card names (approved entry 8). */
function refusedFirst(verdict: string, cards: readonly VerifiedCard[]): FirstPin {
  const newest = cards[cards.length - 1];
  return verdict === "origin_mismatch" && newest !== undefined ? { kind: "refused", verdict, cardOrigin: newest.fields.origin } : { kind: "refused", verdict };
}

type Fetched ={ kind: "cards"; cards: readonly VerifiedCard[] } | { kind: "refused"; verdict: string } | { kind: "unreachable"; error: unknown };

export class PinStore {
  constructor(
    private readonly storage: KeyValue,
    /** `GET /instance` of the origin this browser dials: the origin that served it. */
    private readonly fetchInstance: (origin: string) => Promise<InstanceResponse>,
    private readonly baked: BakedInstance | null,
  ) {}

  /** True when [origin] is the baked public instance's origin (a store build's constants; none while they are placeholders). */
  isBaked(origin: string): boolean {
    return this.baked !== null && origin === this.baked.origin;
  }

  state(origin: string): PinState {
    const text = this.storage.get(KEY_PREFIX + origin);
    return text === null ? { kind: "none" } : decodePin(origin, text);
  }

  /** The pin in force for [origin]; null when none, forked or damaged. */
  pinFor(origin: string): WebPin | null {
    const s = this.state(origin);
    return s.kind === "pinned" ? s.pin : null;
  }

  private put(pin: WebPin, forked = false): void {
    this.storage.set(KEY_PREFIX + pin.origin, JSON.stringify({ ...pin, forked }));
    if (!forked) for (const fn of [...this.pinned]) fn(pin);
    else this.reportStopped(pin.origin);
  }

  private readonly pinned = new Set<(pin: WebPin) => void>();
  private readonly stopped = new Set<(origin: string) => void>();

  private reportStopped(origin: string): void {
    for (const fn of [...this.stopped]) fn(origin);
  }

  /**
   * Called when this store marks an origin forked, and whenever a refresh finds its record forked or damaged (design
   * §4.4: the session stops its traffic and freezes as the read-only copy). Returns the unsubscribe.
   */
  onStopped(fn: (origin: string) => void): () => void {
    this.stopped.add(fn);
    return () => {
      this.stopped.delete(fn);
    };
  }

  /**
   * Called with every newly verified pin this store records (a refresh that advanced or re-confirmed it, a first pin,
   * an accepted kind change). The session uses it for design §12.2 rule 7: a card naming the signed-in account as
   * `operator` signs it out. Returns the unsubscribe.
   */
  onPinned(fn: (pin: WebPin) => void): () => void {
    this.pinned.add(fn);
    return () => {
      this.pinned.delete(fn);
    };
  }

  /** "Forget this server" (§12.3): removes the pin and its fork or damage mark. The caller wipes the namespace's data. */
  forget(origin: string): void {
    this.storage.remove(KEY_PREFIX + origin);
  }

  private async fetch(origin: string): Promise<Fetched> {
    let resp: InstanceResponse;
    try {
      resp = await this.fetchInstance(origin);
    } catch (error) {
      return { kind: "unreachable", error };
    }
    if (resp.cards.length === 0) return { kind: "refused", verdict: "withheld" };
    const frames: Uint8Array[] = [];
    for (const c of resp.cards) {
      const f = fromB64Canonical(c);
      if (f === null) return { kind: "refused", verdict: "bad_frame" };
      frames.push(f);
    }
    // A client never passes an expected instanceId: those are pin verdicts, checked after the chain (§2.4).
    const r = verifyCardChain(frames);
    if (r.verdict !== null) return { kind: "refused", verdict: r.verdict };
    return { kind: "cards", cards: r.cards };
  }

  /** Fetch the chain and verify it against the pin (§4.4: every policy probe or sync). A fork is marked durably; an ok chain advances the pin. */
  async refresh(origin: string): Promise<CardStatus> {
    const st = this.state(origin);
    if (st.kind === "none") return { kind: "refused", verdict: "no_pin" };
    if (st.kind === "damaged") {
      this.reportStopped(origin);
      return { kind: "refused", verdict: "damaged" };
    }
    if (st.kind === "forked") {
      this.reportStopped(origin);
      return { kind: "fork", pinned: st.pin };
    }
    const f = await this.fetch(origin);
    if (f.kind === "unreachable") return { kind: "unreachable", error: f.error };
    // A served chain that does not verify changes nothing: the pin stays, nothing is followed and nothing stops (core
    // EngineInstance maps `CardStatus.Refused` to `NotVerified`; approved entry 11).
    if (f.kind === "refused") return f.verdict === "withheld" ? { kind: "withheld", pinned: st.pin } : { kind: "not_verified", pinned: st.pin, verdict: f.verdict };
    const status = judgeChain(st.pin, f.cards, this.baked);
    if (status.kind === "fork") this.put(st.pin, true);
    if (status.kind === "ok") this.put(status.pin);
    return status;
  }

  /**
   * The first pin of the origin this browser dials (§4.4): the baked root for the public instance's origin, the
   * Trust Gate for any other. Under an existing pin the chain is judged against it first and nothing is swapped.
   */
  async begin(origin: string): Promise<FirstPin> {
    const st = this.state(origin);
    if (st.kind === "damaged" || st.kind === "forked") return { kind: "blocked", state: st };
    const f = await this.fetch(origin);
    if (f.kind === "unreachable") return { kind: "unreachable", error: f.error };
    if (f.kind === "refused") return { kind: "refused", verdict: f.verdict };
    const cards = f.cards;
    if (st.kind === "pinned") {
      const j = judgeChain(st.pin, cards, this.baked);
      if (j.kind === "fork") {
        this.put(st.pin, true);
        return { kind: "blocked", state: this.state(origin) };
      }
      if (j.kind === "withheld") return { kind: "refused", verdict: "withheld" };
      if (j.kind !== "ok") return { kind: "pin_changed", status: j };
      this.put(j.pin);
      return { kind: "pinned", pin: j.pin };
    }
    const baked = this.baked;
    if (baked !== null && origin === baked.origin) {
      const v = checkBakedRoot(cards, origin, baked.card0Hash, baked.instanceId);
      if (v !== null) return refusedFirst(v, cards);
      const newest = cards[cards.length - 1]!;
      // A move or a kind change of the baked instance is never followed: it ships as an update.
      if (newest.fields.origin !== baked.origin || newest.fields.kind !== baked.kind) return { kind: "refused", verdict: "update_required" };
      const pin: WebPin = { ...pinRecordOf(newest), root: "baked" };
      this.put(pin);
      return { kind: "pinned", pin };
    }
    const v = checkTypedRoot(cards, origin);
    if (v !== null) return refusedFirst(v, cards);
    const candidate: WebPin = { ...pinRecordOf(cards[cards.length - 1]!), root: "trust_gate" };
    return {
      kind: "needs_trust_gate",
      origin,
      name: candidate.name,
      operatorShortFp: operatorShortFp(candidate.operatorSignKey),
      ticket: Object.freeze({ origin, candidate }),
    };
  }

  /** The person confirmed the Trust Gate: pins exactly the chain the ticket showed, never over another chain. */
  confirmTrustGate(ticket: TrustGateTicket): FirstPin {
    const c = ticket.candidate;
    const st = this.state(ticket.origin);
    if (st.kind === "damaged" || st.kind === "forked") return { kind: "blocked", state: st };
    if (c.origin !== ticket.origin) return { kind: "refused", verdict: "origin_mismatch", cardOrigin: c.origin };
    if (st.kind === "none") {
      this.put(c);
      return { kind: "pinned", pin: c };
    }
    const existing = st.pin;
    if (existing.card0Hash !== c.card0Hash || existing.instanceId !== c.instanceId || existing.seq > c.seq) return { kind: "pin_conflict", pinned: existing };
    if (existing.seq === c.seq && existing.hash !== c.hash) return { kind: "pin_conflict", pinned: existing };
    if (rank(c.root) <= rank(existing.root)) return { kind: "pinned", pin: existing };
    this.put(c);
    return { kind: "pinned", pin: c };
  }

  /**
   * The person confirmed a `kind` change through the Trust Gate (§4.4, §12.3). The served chain is judged again
   * rather than trusting the prompt; the baked instance's kind change is never followed. A change that also
   * moved is accepted on this origin only (the web cannot follow the move).
   */
  async acceptKindChange(origin: string, shown: { newestHash: string }): Promise<CardStatus> {
    const st = this.state(origin);
    if (st.kind !== "pinned") return this.refresh(origin);
    const f = await this.fetch(origin);
    if (f.kind === "unreachable") return { kind: "unreachable", error: f.error };
    if (f.kind === "refused") return f.verdict === "withheld" ? { kind: "withheld", pinned: st.pin } : { kind: "not_verified", pinned: st.pin, verdict: f.verdict };
    const now = judgeChain(st.pin, f.cards, this.baked);
    if (now.kind !== "kind_changed") return now;
    if (now.mustUpdate) return now;
    if (now.newest.hash !== shown.newestHash) return { kind: "refused", verdict: "stale_prompt" };
    const pin = now.newest.origin === origin ? now.newest : { ...st.pin, kind: now.newest.kind };
    this.put(pin);
    return { kind: "ok", pin };
  }
}
