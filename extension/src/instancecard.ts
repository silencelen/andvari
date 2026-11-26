import { b64Strict, frameHash, parseFrame, PURPOSE_CODES, signatureValid, signerIs, ZERO_HASH, type ParseVerdict } from "./statement.ts";

/**
 * The instance card in the extension (design 2026-11-15-onboarding-trust §4.1, §4.2, §4.4, §12.2 rule 3):
 * the chain verified with signers compared byte for byte against `operatorSignKey`, the served chain
 * compared with a pinned card, and the first pin from the two roots the extension has, the baked public
 * instance and the typed address behind the Trust Gate. Pure functions over frames; the pin store and the
 * network live elsewhere (pinstore.ts, background.ts). Graded by `instancecard.json`.
 *
 * The extension makes no `operator_key_mismatch` check (VR-11): only an operator's own devices can, and
 * the extension has no Montgomery map to make it.
 */

const CARD_CODE = PURPOSE_CODES["instance-card"]!;

/** A verified card: its hash and its statement's fields. */
export interface Card {
  readonly hash: string;
  readonly instanceId: string;
  readonly seq: number;
  readonly prev: string;
  readonly origin: string;
  readonly name: string;
  readonly kind: "public" | "private";
  readonly operator: string;
  readonly operatorSignKey: string;
  readonly recoveryFp: string;
  readonly issuedAt: number;
}

/** The pin record of §4.4. */
export interface PinRecord {
  readonly instanceId: string;
  readonly card0Hash: string;
  readonly seq: number;
  readonly hash: string;
  readonly origin: string;
  readonly name: string;
  readonly kind: "public" | "private";
  readonly operator: string;
  readonly operatorSignKey: string;
  readonly recoveryFp: string;
}

export type ChainVerdict = ParseVerdict | "instance_mismatch" | "bad_seq" | "bad_prev" | "not_authorized" | "bad_signature";

export type ChainResult = { ok: true; cards: readonly Card[] } | { ok: false; verdict: ChainVerdict; at: number };

/**
 * Verify a served chain from card 0 (§4.2, VR-10). Per card, in order: the parse verdicts;
 * `instance_mismatch` (another `instanceId` than card 0's); `bad_seq`; `bad_prev`; `not_authorized` (the
 * signer is not byte-equal to the previous card's `operatorSignKey`, or card 0's own); `bad_signature`.
 * Cards have no `precondition`. The first failure stops the walk; `at` is the index of the failing card.
 */
export function verifyChain(frames: readonly Uint8Array[]): ChainResult {
  const cards: Card[] = [];
  for (let i = 0; i < frames.length; i++) {
    const frame = frames[i]!;
    const parsed = parseFrame(frame, "instance-card");
    if (!parsed.ok) return { ok: false, verdict: parsed.verdict, at: i };
    const v = parsed.value.values;
    const card: Card = {
      hash: frameHash(frame),
      instanceId: v.instanceId as string,
      seq: v.seq as number,
      prev: v.prev as string,
      origin: v.origin as string,
      name: v.name as string,
      kind: v.kind as "public" | "private",
      operator: v.operator as string,
      operatorSignKey: v.operatorSignKey as string,
      recoveryFp: v.recoveryFp as string,
      issuedAt: v.issuedAt as number,
    };
    const previous = i === 0 ? null : cards[i - 1]!;
    if (previous !== null && card.instanceId !== cards[0]!.instanceId) return { ok: false, verdict: "instance_mismatch", at: i };
    if (card.seq !== i) return { ok: false, verdict: "bad_seq", at: i };
    if (card.prev !== (previous === null ? ZERO_HASH : previous.hash)) return { ok: false, verdict: "bad_prev", at: i };
    const mustSign = b64Strict(previous === null ? card.operatorSignKey : previous.operatorSignKey);
    if (mustSign === null || !signerIs(parsed.value.signerPub, mustSign)) return { ok: false, verdict: "not_authorized", at: i };
    if (!signatureValid(CARD_CODE, parsed.value.signerPub, parsed.value.signature, parsed.value.statement)) {
      return { ok: false, verdict: "bad_signature", at: i };
    }
    cards.push(card);
  }
  return { ok: true, cards };
}

/**
 * The longest chain the extension verifies for a FIRST pin. Verifying is synchronous and
 * costs about 20 ms a card in the service worker's pure-JS Ed25519 (measured: 64 cards 1.25 s, 811 cards 16.5 s on the
 * review host), while the 512 KiB body cap admits about 790 cards of ~665 bytes each, a 16-to-19-second freeze of every
 * fill and message from any typed address before the Trust Gate. A chain gains one card per rename, handover, move or
 * recovery-key rotation, so 64 cards is decades of an operator's changes, verified in about a second. A longer chain is
 * refused as `chain_too_long` before anything is verified. A device that already holds a pin verifies only the cards
 * after it (verifyForward), whose number only the operator's key can grow, and stops at the first one that fails.
 */
export const MAX_FIRST_PIN_CARDS = 64;

/**
 * A served chain against a pinned card, verified FORWARD from the pin (design §4.4 "verifies forward from the pinned
 * card"): the prefix is compared by hash only (card 0 against `card0Hash`, the card at the pinned
 * `seq` against the pinned hash: the chain's `prev` links commit to everything between), so nothing before the pin is
 * parsed or verified again. Then each newer card is verified as [verifyChain] would, from the pinned card. The pinned
 * verdicts come first, in [comparePinned]'s order: `withheld` (empty, or ending below the pin), `fork` (another card 0,
 * or another card at the pinned `seq`). `newest` is null when the pinned card is the newest served.
 */
export type ForwardResult =
  | { ok: true; verdict: "withheld" | "fork" }
  | { ok: true; verdict: "ok"; newest: Card | null }
  | { ok: false; verdict: ChainVerdict; at: number };

export function verifyForward(frames: readonly Uint8Array[], pin: Pick<PinRecord, "card0Hash" | "seq" | "hash" | "instanceId" | "operatorSignKey">): ForwardResult {
  if (frames.length === 0) return { ok: true, verdict: "withheld" };
  if (frameHash(frames[0]!) !== pin.card0Hash) return { ok: true, verdict: "fork" };
  if (frames.length - 1 < pin.seq) return { ok: true, verdict: "withheld" };
  if (frameHash(frames[pin.seq]!) !== pin.hash) return { ok: true, verdict: "fork" };
  let previous = { hash: pin.hash, operatorSignKey: pin.operatorSignKey };
  let newest: Card | null = null;
  for (let i = pin.seq + 1; i < frames.length; i++) {
    const frame = frames[i]!;
    const parsed = parseFrame(frame, "instance-card");
    if (!parsed.ok) return { ok: false, verdict: parsed.verdict, at: i };
    const v = parsed.value.values;
    const card: Card = {
      hash: frameHash(frame),
      instanceId: v.instanceId as string,
      seq: v.seq as number,
      prev: v.prev as string,
      origin: v.origin as string,
      name: v.name as string,
      kind: v.kind as "public" | "private",
      operator: v.operator as string,
      operatorSignKey: v.operatorSignKey as string,
      recoveryFp: v.recoveryFp as string,
      issuedAt: v.issuedAt as number,
    };
    if (card.instanceId !== pin.instanceId) return { ok: false, verdict: "instance_mismatch", at: i };
    if (card.seq !== i) return { ok: false, verdict: "bad_seq", at: i };
    if (card.prev !== previous.hash) return { ok: false, verdict: "bad_prev", at: i };
    const mustSign = b64Strict(previous.operatorSignKey);
    if (mustSign === null || !signerIs(parsed.value.signerPub, mustSign)) return { ok: false, verdict: "not_authorized", at: i };
    if (!signatureValid(CARD_CODE, parsed.value.signerPub, parsed.value.signature, parsed.value.statement)) return { ok: false, verdict: "bad_signature", at: i };
    previous = card;
    newest = card;
  }
  return { ok: true, verdict: "ok", newest };
}

/** The pin record for card `card` of a chain whose card 0 hashes to `card0Hash`. */
export function pinRecordOf(card: Card, card0Hash: string): PinRecord {
  return {
    instanceId: card.instanceId,
    card0Hash,
    seq: card.seq,
    hash: card.hash,
    origin: card.origin,
    name: card.name,
    kind: card.kind,
    operator: card.operator,
    operatorSignKey: card.operatorSignKey,
    recoveryFp: card.recoveryFp,
  };
}

/** The part of a pin a served chain is compared against. */
export interface PinHead {
  readonly card0Hash: string;
  readonly seq: number;
  readonly hash: string;
}

export type PinnedResult = { verdict: "ok"; newest: Card } | { verdict: "withheld" } | { verdict: "fork" };

/**
 * A verified chain against a pinned card (§4.4, VR-17): `withheld` for an empty chain; `fork` when card 0
 * does not hash to the pin's `card0Hash`, however short the chain; `withheld` when the same chain ends
 * below the pinned `seq` (a state, not a stop); `fork` when another hash stands at the pinned `seq`;
 * otherwise `ok` with the newest verified card.
 */
export function comparePinned(cards: readonly Card[], pin: PinHead): PinnedResult {
  if (cards.length === 0) return { verdict: "withheld" };
  if (cards[0]!.hash !== pin.card0Hash) return { verdict: "fork" };
  if (cards.length - 1 < pin.seq) return { verdict: "withheld" };
  if (cards[pin.seq]!.hash !== pin.hash) return { verdict: "fork" };
  return { verdict: "ok", newest: cards[cards.length - 1]! };
}

/** The extension's two first-pin roots (§4.4, §12.2 rule 3). */
export type Root = { root: "baked"; instanceId: string; card0Hash: string } | { root: "typed" };

export type FirstPinVerdict = "withheld" | "origin_mismatch" | "card0_mismatch" | "instance_mismatch";

/** `origin_mismatch` carries the origin the newest verified card names (`cardOrigin`), for the refusal's wording. */
export type FirstPinResult =
  | { verdict: "ok"; pin: PinRecord }
  | { verdict: "origin_mismatch"; cardOrigin: string }
  | { verdict: Exclude<FirstPinVerdict, "origin_mismatch"> };

/**
 * The first pin for `dialedOrigin` on a device that holds none for it (§4.4, §2.4 pinning row), from a
 * verified chain: `withheld` for an empty chain (every root); `origin_mismatch` first of the mismatches,
 * when the newest card's origin is not the dialed one (a first pin never follows a card to another
 * address); then, for the baked root, `card0_mismatch` and `instance_mismatch`. The newest verified card
 * is pinned. A typed address is trust on first use: the caller shows the Trust Gate before keeping it.
 */
export function firstPin(cards: readonly Card[], root: Root, dialedOrigin: string): FirstPinResult {
  if (cards.length === 0) return { verdict: "withheld" };
  const newest = cards[cards.length - 1]!;
  if (newest.origin !== dialedOrigin) return { verdict: "origin_mismatch", cardOrigin: newest.origin };
  const card0 = cards[0]!;
  if (root.root === "baked") {
    if (card0.hash !== root.card0Hash) return { verdict: "card0_mismatch" };
    if (card0.instanceId !== root.instanceId) return { verdict: "instance_mismatch" };
  }
  return { verdict: "ok", pin: pinRecordOf(newest, card0.hash) };
}

/**
 * What a verified card newer than the pin asks of the person (§4.4): `none` (a rename, a handover, a
 * recovery-key rotation, or no change: the pin advances), `move` (another origin) or `kind` (another
 * `kind`; a card that changes both origin and kind is a `kind` change, never a move alone).
 */
export function changeOf(pin: PinRecord, newest: Card): "none" | "move" | "kind" {
  if (newest.kind !== pin.kind) return "kind";
  if (newest.origin !== pin.origin) return "move";
  return "none";
}
