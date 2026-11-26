import { ctEquals, toHexLower } from "../bytes";
import { ed25519PkToCurve25519, sha256Sync } from "../provider";
import { type Checked, ok, refused } from "./checked";
import { compareCardPin } from "./checkpoints";
import { parseFrame } from "./codec";
import { type FrameParts, frameHash, type FrameVerdict, signatureValid, signerIs } from "./frame";
import { decodeName, fromB64Exact, isHex64, NONE, ZERO_HASH } from "./grammar";

/**
 * The instance card (design 2026-11-15 §4): template (§4.1), chain (§4.2) and the pin checks of §4.4,
 * with names and order from §2.4 ("Card chain", VR-10; "Pinning", VR-12). Twin of core `InstanceCard`,
 * written on its own and graded off the same `instancecard.json`.
 *
 * VERIFY ONLY. §13: the web client never signs an instance card, so this file has no builder.
 * Which root may make a first pin, and what a pin allows (the password rule), is not decided here.
 */

export type InstanceKind = "public" | "private";

/**
 * One card as its statement says it (§4.1). `name` is the DECODED display name (render it only as plain
 * text, always with `origin` beside it, T-R8); `nameB64` is the statement's `name` text. `recoveryFp` is
 * null for the statement's `none`. Ids, keys and hashes are the canonical statement text.
 */
export interface CardFields {
  readonly instanceId: string;
  readonly seq: number;
  readonly prev: string;
  readonly origin: string;
  readonly name: string;
  readonly nameB64: string;
  readonly kind: InstanceKind;
  readonly operator: string;
  /** The operator account's Ed25519 joint key, `b64_32` text. It must sign the NEXT card. */
  readonly operatorSignKey: string;
  readonly recoveryFp: string | null;
  readonly issuedAt: number;
}

/**
 * A position in a card chain: what the NEXT card must chain from (§4.2), and the five values of a
 * device's pin that verifying forward needs (§4.4). `card0Hash` is `H(card 0)` of that chain: it tells a
 * NEW chain under the same `instanceId` (an operator reset, §4.6) from the same chain served short.
 */
export interface CardHead {
  readonly instanceId: string;
  readonly card0Hash: string;
  readonly seq: number;
  readonly hash: string;
  readonly operatorSignKey: string;
}

/** A card that passed the strict parse only: NOT authenticated and not placed in a chain. */
export interface UnverifiedCard {
  readonly fields: CardFields;
  readonly hash: string;
  readonly parts: FrameParts;
}

declare const verifiedCard: unique symbol;

/**
 * A card {@link verifyCard} accepted as the next card after the head it was given. `hash` is `H(frame)`,
 * `card0Hash` the hash of its chain's card 0 (its own when it is card 0). The brand means it came from
 * this file's verifier, and the value is frozen at every level (`frame` reads as a fresh copy).
 */
export interface VerifiedCard {
  readonly [verifiedCard]: true;
  readonly fields: CardFields;
  readonly hash: string;
  readonly card0Hash: string;
  readonly frame: Uint8Array;
}

/** §2.4 "Card chain" (VR-10), in check order: the vault log's verdicts without `precondition`, `instance_mismatch` in `wrong_vault`'s place. */
export type CardVerdict =
  | FrameVerdict
  | "instance_mismatch"
  | "bad_seq"
  | "bad_prev"
  | "not_authorized"
  | "bad_signature"
  | "operator_key_mismatch";

/**
 * §2.4 "Pinning" (VR-12), in check order. Expectations from OUTSIDE the chain (baked, kit, offer, pin):
 * checked after the chain verified, never passed into the chain verifier. `withheld` is a state, not a stop.
 */
export type PinVerdict = "origin_mismatch" | "card0_mismatch" | "instance_mismatch" | "card_not_in_chain" | "fork" | "withheld";

/**
 * The **Ed25519 signing key** a verifier TRUSTS for an operator account (§4.1, VR-11), 32 bytes, or null
 * when it holds none. An operator's own device answers for its own `userId` only, with the Ed25519 key
 * it derives from its own identity seed (`signKeypairFromSeed(seed).publicKey`). Every other client
 * passes nothing.
 *
 * It is NEVER the X25519 identity key: {@link verifyCard} compares these bytes with the card's
 * `operatorSignKey`, so an X25519 key handed here refuses every card (`operator_key_mismatch`).
 */
export type OperatorKeys = (userId: string) => Uint8Array | null;

export interface CardVerifyOptions {
  /** ONLY THE SERVER passes this (its own instance id). A baked, kit, offer or pinned id is a pin verdict, checked after the chain. */
  readonly expectedInstanceId?: string;
  readonly operatorKeys?: OperatorKeys;
}

/** The head a verified card gives: what the next card chains from, and what a device pins. */
export const headOf = (card: VerifiedCard): CardHead => ({
  instanceId: card.fields.instanceId, card0Hash: card.card0Hash, seq: card.fields.seq, hash: card.hash,
  operatorSignKey: card.fields.operatorSignKey,
});

/** §4.4's pin record for a verified card, in its stored (statement text) form: `name` as `name` text, `recoveryFp` as `none`. */
export interface CardPinRecord {
  readonly instanceId: string;
  readonly card0Hash: string;
  readonly seq: number;
  readonly hash: string;
  readonly origin: string;
  readonly name: string;
  readonly kind: InstanceKind;
  readonly operator: string;
  readonly operatorSignKey: string;
  readonly recoveryFp: string;
}

export const pinRecordOf = (card: VerifiedCard): CardPinRecord => {
  const f = card.fields;
  return {
    instanceId: f.instanceId, card0Hash: card.card0Hash, seq: f.seq, hash: card.hash, origin: f.origin, name: f.nameB64,
    kind: f.kind, operator: f.operator, operatorSignKey: f.operatorSignKey, recoveryFp: f.recoveryFp ?? NONE,
  };
};

/** The §2 parse of one card and nothing more: the frame, purpose 0x04 and the strict canonical parse. A card has no template rule of its own. */
export function parseCard(frame: Uint8Array): Checked<UnverifiedCard, CardVerdict> {
  const parsed = parseFrame(frame, "instance-card");
  if (!parsed.ok) return parsed;
  const raw = parsed.value.raw;
  // The codec proved every value in its grammar; the decode below cannot fail.
  const name = decodeName(raw.name!);
  if (name === null) return refused("non_canonical");
  const fields: CardFields = {
    instanceId: raw.instanceId!, seq: Number(raw.seq), prev: raw.prev!, origin: raw.origin!, name, nameB64: raw.name!,
    kind: raw.kind as InstanceKind, operator: raw.operator!, operatorSignKey: raw.operatorSignKey!,
    recoveryFp: raw.recoveryFp === NONE ? null : raw.recoveryFp!, issuedAt: Number(raw.issuedAt),
  };
  return ok({ fields, hash: frameHash(frame), parts: parsed.value.parts });
}

/**
 * Verify ONE card as the next card after `prior` (null: it must be card 0). §4.2 in §2.4's order; the
 * first failure is the verdict:
 *
 * 1. the parse verdicts ({@link parseCard});
 * 2. `instance_mismatch`: not `prior`'s `instanceId` (card 0's of the same chain), or not the server's own;
 * 3. `bad_seq`: not 0 for card 0, not `prior.seq + 1` otherwise;
 * 4. `bad_prev`: not 64 zeros for card 0, not `prior.hash` otherwise;
 * 5. `not_authorized`: `signerPub` is not BYTE-EQUAL to `prior.operatorSignKey` (card 0: its own);
 * 6. `bad_signature`;
 * 7. `operator_key_mismatch`, only when `operatorKeys` holds a key for the card's `operator`:
 *    `operatorSignKey` is not BYTE-EQUAL to that Ed25519 key (§4.1, VR-11). The comparison is on the
 *    Ed25519 key itself, never through its X25519 image: a key and its negation have the same image,
 *    the key's holder can sign under either, and a card naming the negation would pass an image check
 *    and then lock the real key out of every later card.
 */
export function verifyCard(prior: CardHead | null, frame: Uint8Array, options: CardVerifyOptions = {}): Checked<VerifiedCard, CardVerdict> {
  const parsed = parseCard(frame);
  if (!parsed.ok) return parsed;
  const { fields: f, hash, parts } = parsed.value;
  if (prior !== null && f.instanceId !== prior.instanceId) return refused("instance_mismatch");
  if (options.expectedInstanceId !== undefined && f.instanceId !== options.expectedInstanceId) return refused("instance_mismatch");
  if (f.seq !== (prior === null ? 0 : prior.seq + 1)) return refused("bad_seq");
  if (f.prev !== (prior === null ? ZERO_HASH : prior.hash)) return refused("bad_prev");
  const signerKey = fromB64Exact(prior === null ? f.operatorSignKey : prior.operatorSignKey, 32);
  if (signerKey === null || !signerIs(parts, signerKey)) return refused("not_authorized");
  if (!signatureValid(parts)) return refused("bad_signature");
  const trusted = options.operatorKeys?.(f.operator) ?? null;
  if (trusted !== null) {
    const named = fromB64Exact(f.operatorSignKey, 32);
    if (named === null || trusted.length !== 32 || !ctEquals(named, trusted)) return refused("operator_key_mismatch");
  }
  // Frozen all the way down: the fields object too, and the frame is handed out as a copy each time, since
  // the bytes of a typed array cannot be frozen. A verified card cannot be changed after the fact.
  const bytes = frame.slice();
  return ok(Object.freeze({
    fields: Object.freeze(f), hash, card0Hash: prior === null ? hash : prior.card0Hash,
    get frame(): Uint8Array {
      return bytes.slice();
    },
  }) as VerifiedCard);
}

/**
 * The result of {@link verifyCardChain}: `cards` verified, in order; when a frame failed, `failedAt` is
 * its index in the input and `verdict` why, and nothing after it was looked at. Both null when every
 * frame verified.
 */
export interface CardChainResult {
  readonly cards: readonly VerifiedCard[];
  readonly failedAt: number | null;
  readonly verdict: CardVerdict | null;
}

/** Verify `frames` in order after `from` (null: the first must be card 0, as `GET /instance` serves card 0 first). Stops at the first failure. */
export function verifyCardChain(frames: readonly Uint8Array[], from: CardHead | null = null, options: CardVerifyOptions = {}): CardChainResult {
  let head = from;
  const cards: VerifiedCard[] = [];
  for (let i = 0; i < frames.length; i++) {
    const card = verifyCard(head, frames[i]!, options);
    if (!card.ok) return { cards, failedAt: i, verdict: card.verdict };
    cards.push(card.value);
    head = headOf(card.value);
  }
  return { cards, failedAt: null, verdict: null };
}

const newestOf = (chain: readonly VerifiedCard[]): VerifiedCard | null => chain[chain.length - 1] ?? null;

/**
 * §2.4 "Pinning", the FIRST of the mismatches for every root that makes a first pin: the newest verified
 * card of `chain` (verified from card 0) does not name `dialedOrigin` (`origin_mismatch`). Null when it
 * does, and for an empty chain (every root answers `withheld` for that). It holds after a move too: the
 * old address of a moved instance is `origin_mismatch`. NOT run under an existing pin, where a changed
 * origin is a move ({@link followPin}).
 */
export function checkDialedOrigin(chain: readonly VerifiedCard[], dialedOrigin: string): PinVerdict | null {
  const newest = newestOf(chain);
  return newest !== null && newest.fields.origin !== dialedOrigin ? "origin_mismatch" : null;
}

/** The BAKED root (§4.4): `withheld`; `origin_mismatch`; `card0_mismatch` (also when the `instanceId` differs too); `instance_mismatch`. Null: pin the newest card. */
export function checkBakedRoot(chain: readonly VerifiedCard[], dialedOrigin: string, card0Hash: string, instanceId: string): PinVerdict | null {
  const first = chain[0];
  if (first === undefined) return "withheld";
  const origin = checkDialedOrigin(chain, dialedOrigin);
  if (origin !== null) return origin;
  if (first.card0Hash !== card0Hash) return "card0_mismatch";
  return first.fields.instanceId !== instanceId ? "instance_mismatch" : null;
}

/** The KIT root (§4.4, §10; the CLI's `--trust-card` too): `withheld`; `origin_mismatch`; `card0_mismatch`. Null: pin the newest card. */
export function checkKitRoot(chain: readonly VerifiedCard[], dialedOrigin: string, card0Hash: string): PinVerdict | null {
  const first = chain[0];
  if (first === undefined) return "withheld";
  const origin = checkDialedOrigin(chain, dialedOrigin);
  if (origin !== null) return origin;
  return first.card0Hash !== card0Hash ? "card0_mismatch" : null;
}

/**
 * The LINK-OFFER root (§4.4): `withheld` for no card served; `origin_mismatch`; `card_not_in_chain` (no
 * card has `H = offer.cardHash`); `instance_mismatch` (that card is under another `instanceId` than the
 * offer's). Null: pin the NEWEST card, not the one the offer names. Kept for parity with core and the
 * vectors: §13 forbids the web client to open links, so no web flow calls it.
 */
export function checkOfferRoot(chain: readonly VerifiedCard[], dialedOrigin: string, cardHash: string, instanceId: string): PinVerdict | null {
  if (chain.length === 0) return "withheld";
  const origin = checkDialedOrigin(chain, dialedOrigin);
  if (origin !== null) return origin;
  const card = chain.find((c) => c.hash === cardHash);
  if (card === undefined) return "card_not_in_chain";
  return card.fields.instanceId !== instanceId ? "instance_mismatch" : null;
}

/** The TYPED-ADDRESS root (§4.4, trust on first use behind the Trust Gate): `withheld`; `origin_mismatch`. Null: the gate may be shown, and Connect pins the newest card. */
export function checkTypedRoot(chain: readonly VerifiedCard[], dialedOrigin: string): PinVerdict | null {
  if (chain.length === 0) return "withheld";
  return checkDialedOrigin(chain, dialedOrigin);
}

/**
 * What a served chain means for a device that pins a card. `pin` is null when the served chain holds
 * the pinned hash at the pinned `seq`; otherwise it is `fork` or `withheld` and `newer` is empty. With
 * the pin contained, `newer` are the cards after it that verified, oldest first; when one did not,
 * `verdict` says why and `newer` stops before it (the device may advance to the last of `newer`).
 */
export interface CardFollow {
  readonly pin: "fork" | "withheld" | null;
  readonly newer: readonly VerifiedCard[];
  readonly verdict: CardVerdict | null;
}

/**
 * §4.4 "On every policy probe or sync": judge the chain a server SERVED (card 0 first) against the
 * pinned card, then verify forward from the pin.
 *
 * - no card served: `withheld`;
 * - card 0 of the served chain does not hash to `pin.card0Hash`: `fork`, HOWEVER SHORT the chain is;
 * - the same chain with fewer than `pin.seq + 1` cards: `withheld`;
 * - another hash at `pin.seq`: `fork`;
 * - otherwise the cards after the pin are verified from it. The pinned hash fixes every earlier card
 *   through `prev`, so nothing below the pin is verified again.
 */
export function followPin(pin: CardHead, served: readonly Uint8Array[], operatorKeys?: OperatorKeys): CardFollow {
  const verdict = compareCardPin(pin.card0Hash, { seq: pin.seq, hash: pin.hash }, served.map(frameHash));
  if (verdict !== "ok") return { pin: verdict, newer: [], verdict: null };
  const result = verifyCardChain(served.slice(pin.seq + 1), pin, operatorKeys === undefined ? {} : { operatorKeys });
  return { pin: null, newer: result.cards, verdict: result.verdict };
}

/**
 * The X25519 image of a card's `operatorSignKey` (§4.1): the operator account's `identityPub`, over which
 * the operator's short fingerprint is SHOWN. Null when the key has none. For display only: two Ed25519
 * keys (a key and its negation) have the same image, so it never decides whose key a card names.
 */
export function operatorIdentityKey(operatorSignKey: string): Uint8Array | null {
  const ed25519 = fromB64Exact(operatorSignKey, 32);
  if (ed25519 === null) return null;
  try {
    return ed25519PkToCurve25519(ed25519);
  } catch {
    return null;
  }
}

/** §4.5 condition 3: `recoveryPub` hashes to `recoveryFp` at full length (`hexLower(SHA-256(key))`). False for `none`. */
export function recoveryKeyMatches(recoveryFp: string | null, recoveryPub: Uint8Array): boolean {
  return recoveryFp !== null && isHex64(recoveryFp) && recoveryPub.length === 32 && toHexLower(sha256Sync(recoveryPub)) === recoveryFp;
}
