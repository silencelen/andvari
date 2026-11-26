import { ctEquals, toB64, toHexLower, utf8 } from "../bytes";
import { adIdkey } from "../ad";
import { openKey } from "../envelope";
import { boxKeypairFromSeed, type KeyPairBytes, sealOpen, sha256Sync } from "../provider";
import { type Checked, ok, refused } from "./checked";
import { encodeStatement, parseFrame, type ParsedFrame, secretOf } from "./codec";
import { type FrameParts, frameHash, type FrameVerdict, signatureValid, signerImage, signerMapsTo, signFrame, wipeFrameParts } from "./frame";
import { decodeEmail, emailNorm, fromB64Canonical, isHex64 } from "./grammar";
import { CryptoError } from "../sodium";
import type { VerifiedCard } from "./instancecard";

/**
 * The recovery statements (design 2026-11-15 §4.5 and §9.3): recovery-key rotation (purpose 0x08) with
 * its chains and the first-consent walk, operator-assisted recovery (0x09) with the request code, and
 * the veto (0x0A). Names and orders from §2.4 ("Rotation", "Veto", "Assisted recovery", the
 * signer-binding table and "Small cases"). Twin of core `Recovery`, graded off the same `recovery.json`.
 *
 * No rotation or assisted-recovery builder lives here: both are signed only by the offline recovery
 * seed in `recovery-cli`. The web builds a veto only.
 *
 * Signer binding for 0x08 and 0x09 (§2.3, T-B4, T-B5): the recovery-key signing key is
 * `crypto_sign_seed_keypair(recovery seed)`, so `ed25519_pk_to_curve25519(signerPub)` IS the recovery
 * public key and its SHA-256 is the fingerprint a card's `recoveryFp` carries. These helpers are handed
 * that fingerprint, and "the signer maps to the key the fingerprint names" is checked as "the signer's
 * X25519 image hashes to the fingerprint": no served recovery key is needed or trusted for it.
 */

export type RecoveryVerdict =
  | "unopenable"
  | FrameVerdict
  | "fp_mismatch"
  | "signer_not_pinned_key"
  | "bad_signature"
  | "instance_mismatch"
  | "user_mismatch"
  | "request_mismatch"
  | "identity_mismatch";

/** True when the frame's signer is the recovery key whose fingerprint is `fp` (`hexLower(SHA-256(x25519 image))`). */
function signerHasFingerprint(parts: FrameParts, fp: string | null): boolean {
  if (fp === null || !isHex64(fp)) return false;
  const image = signerImage(parts);
  return image !== null && toHexLower(sha256Sync(image)) === fp;
}

// ---- 0x08 rotation (§4.5) --------------------------------------------------------------------------

/** `{"v":2,"purpose":"recovery-rotation","instanceId":<uuid>,"fromFp":<hex64>,"toFp":<hex64>,"issuedAt":<ms>}` */
export interface RotationFields {
  readonly instanceId: string;
  readonly fromFp: string;
  readonly toFp: string;
  readonly issuedAt: number;
}

declare const verifiedRotation: unique symbol;

/** A rotation that passed {@link verifyRotation}. `hash` is `H(frame)`. */
export interface VerifiedRotation {
  readonly [verifiedRotation]: true;
  readonly fields: RotationFields;
  readonly hash: string;
}

const rotationFields = (raw: ParsedFrame["raw"]): RotationFields => ({
  instanceId: raw.instanceId!, fromFp: raw.fromFp!, toFp: raw.toFp!, issuedAt: Number(raw.issuedAt),
});

/**
 * One rotation against the verifier's CURRENT fingerprint `currentFp` (its consent, the card's
 * `recoveryFp`, the fingerprint of the account's current escrow, or the previous link's `toFp`), on
 * instance `instanceId`. In §2.4's order; the first failure is the verdict:
 *
 * 1. the parse verdicts (purpose 0x08; a `none` fingerprint is `non_canonical`: both are hex64);
 * 2. `fp_mismatch`: `fromFp` is not `currentFp`. Right after the parse: it decides WHICH key must sign;
 * 3. `signer_not_pinned_key`: the signer is not the recovery key `currentFp` names;
 * 4. `bad_signature`;
 * 5. `instance_mismatch`: made for another instance (one that shares the recovery seed moves nothing here).
 */
export function verifyRotation(frame: Uint8Array, instanceId: string, currentFp: string): Checked<VerifiedRotation, RecoveryVerdict> {
  const parsed = parseFrame(frame, "recovery-rotation");
  if (!parsed.ok) return parsed;
  const { raw, parts } = parsed.value;
  if (raw.fromFp !== currentFp) return refused("fp_mismatch");
  if (!signerHasFingerprint(parts, currentFp)) return refused("signer_not_pinned_key");
  if (!signatureValid(parts)) return refused("bad_signature");
  if (raw.instanceId !== instanceId) return refused("instance_mismatch");
  return ok(Object.freeze({ fields: Object.freeze(rotationFields(raw)), hash: frameHash(frame) }) as VerifiedRotation);
}

/**
 * The result of {@link verifyRotationChain}: `reached` is the fingerprint the verified links lead to.
 * When a link failed, `failedAt` is its index and `verdict` why. When every link verified but the
 * chain does not end at the expected fingerprint, `verdict` is `fp_mismatch` and `failedAt` null.
 * `verdict` null: the chain holds.
 */
export interface RotationChainResult {
  readonly reached: string;
  readonly failedAt: number | null;
  readonly verdict: RecoveryVerdict | null;
}

/**
 * A chain of rotations, oldest first, as `PUT /escrow/self {rotations}` carries it (§4.5, FI-R1):
 * every link verifies in order, the first against `fromFp` (the fingerprint of the account's current
 * escrow) and each next against the previous `toFp`, and the last `toFp` is `toFp`, the fingerprint
 * the new escrow is sealed to. An empty chain holds only when `fromFp` is already `toFp`.
 */
export function verifyRotationChain(frames: readonly Uint8Array[], instanceId: string, fromFp: string, toFp: string): RotationChainResult {
  let reached = fromFp;
  for (let i = 0; i < frames.length; i++) {
    const link = verifyRotation(frames[i]!, instanceId, reached);
    if (!link.ok) return { reached, failedAt: i, verdict: link.verdict };
    reached = link.value.fields.toFp;
  }
  return { reached, failedAt: null, verdict: reached === toFp ? null : "fp_mismatch" };
}

/**
 * §4.5 condition 2: `toFp` "equals the consented `fp`, or follows from it by a chain of valid rotation
 * statements". True when `fromFp` is `toFp`, or when the served `rotations` (in any order; ones that do
 * not verify are ignored) link `fromFp` to `toFp`, each link verified against the fingerprint reached.
 */
export function rotationsLink(rotations: readonly Uint8Array[], instanceId: string, fromFp: string, toFp: string): boolean {
  return fromFp === toFp || new ServedRotations(rotations, instanceId).links(fromFp, toFp);
}

/**
 * The served rotations that lead from `fromFp` (the fingerprint of the account's current escrow) to `toFp`, oldest
 * first, each verified against the fingerprint reached: what `PUT /escrow/self {rotations}` carries (§4.5, FI-R1).
 * Empty when `fromFp` is `toFp`; null when no chain of valid rotations leads there.
 */
export function rotationChain(rotations: readonly Uint8Array[], instanceId: string, fromFp: string, toFp: string): Uint8Array[] | null {
  return new ServedRotations(rotations, instanceId).chain(fromFp, toFp);
}

/**
 * The rotations a server served for one instance, searched from a fingerprint the caller already holds
 * (core's `ServedRotations`).
 *
 * Each frame is parsed ONCE and filed under the `fromFp` it CLAIMS. That is only an index: nothing in it
 * is trusted. A statement counts as a step out of a fingerprint only once that fingerprint has been
 * reached, and then only when {@link verifyRotation} accepts it for a verifier standing there: signed by
 * the recovery key that fingerprint names, for this instance. So the work is bounded by what was served:
 * one parse per frame, and at most one verification per frame, whatever the number of fingerprints
 * reached. (Trying every frame against every fingerprint reached, as this did, is their product.)
 */
class ServedRotations {
  private readonly claiming = new Map<string, Uint8Array[]>();
  private readonly verified = new Map<string, readonly { readonly toFp: string; readonly frame: Uint8Array }[]>();

  constructor(rotations: readonly Uint8Array[], private readonly instanceId: string) {
    for (const frame of rotations) {
      const parsed = parseFrame(frame, "recovery-rotation");
      if (!parsed.ok) continue;
      const claimed = parsed.value.raw.fromFp!;
      const filed = this.claiming.get(claimed);
      if (filed === undefined) this.claiming.set(claimed, [frame]);
      else filed.push(frame);
    }
  }

  /** The fingerprints one verified step away from `fp`, in served order. Verified on first use and kept. */
  private stepsFrom(fp: string): readonly { readonly toFp: string; readonly frame: Uint8Array }[] {
    let steps = this.verified.get(fp);
    if (steps === undefined) {
      const found: { toFp: string; frame: Uint8Array }[] = [];
      for (const frame of this.claiming.get(fp) ?? []) {
        const link = verifyRotation(frame, this.instanceId, fp);
        if (link.ok) found.push({ toFp: link.value.fields.toFp, frame });
      }
      steps = found;
      this.verified.set(fp, steps);
    }
    return steps;
  }

  /** True when verified steps lead from `fromFp` to `toFp`. A rotation back to an earlier key is a step like any other; the search keeps what it has reached, so it ends. */
  links(fromFp: string, toFp: string): boolean {
    return this.chain(fromFp, toFp) !== null;
  }

  /** The verified frames of a shortest path from `fromFp` to `toFp`, oldest first; empty when they are equal; null when none. */
  chain(fromFp: string, toFp: string): Uint8Array[] | null {
    if (fromFp === toFp) return [];
    const via = new Map<string, { readonly from: string; readonly frame: Uint8Array }>();
    const reached = new Set<string>([fromFp]);
    const queue = [fromFp];
    for (let at = 0; at < queue.length; at++) {
      const here = queue[at]!;
      for (const step of this.stepsFrom(here)) {
        if (reached.has(step.toFp)) continue;
        reached.add(step.toFp);
        via.set(step.toFp, { from: here, frame: step.frame });
        if (step.toFp === toFp) {
          const out: Uint8Array[] = [];
          for (let fp = toFp; fp !== fromFp; ) {
            const v = via.get(fp)!;
            out.push(v.frame);
            fp = v.from;
          }
          return out.reverse();
        }
        queue.push(step.toFp);
      }
    }
    return null;
  }
}

/** A change of `recoveryFp` between card `seq − 1` and card `seq` (null: `none`). */
export interface FpChange {
  readonly seq: number;
  readonly fromFp: string | null;
  readonly toFp: string | null;
}

/**
 * The first-consent walk (§4.5, FS-R2, FC-2): when a person turns operator recovery on, the client walks
 * the served chain FROM CARD 0 to the newest card, whatever its pin root. `cards` is that chain,
 * verified from card 0. Returned: every change of `recoveryFp` the served `rotations` do NOT cover, in
 * chain order. A change is covered when the rotations link the old value to the new one
 * ({@link rotationsLink}, verified for the chain's instance); a change from or to `none` never is,
 * because a rotation names two keys. A non-empty result shows the unsigned-change warning and
 * preselects "Only me".
 */
export function unsignedChanges(cards: readonly VerifiedCard[], rotations: readonly Uint8Array[]): FpChange[] {
  const out: FpChange[] = [];
  // One index for the whole walk: a statement is parsed and verified once, however many changes ask for it.
  let served: ServedRotations | null = null;
  for (let i = 1; i < cards.length; i++) {
    const from = cards[i - 1]!.fields.recoveryFp;
    const to = cards[i]!.fields.recoveryFp;
    if (from === to) continue;
    let covered = false;
    if (from !== null && to !== null) {
      served ??= new ServedRotations(rotations, cards[0]!.fields.instanceId);
      covered = served.links(from, to);
    }
    if (!covered) out.push({ seq: cards[i]!.fields.seq, fromFp: from, toFp: to });
  }
  return out;
}

// ---- 0x09 assisted recovery (§9.3) -----------------------------------------------------------------

const REQUEST_CODE_DOMAIN = "andvari/v2|recovery-request|code|";

/** §2.3: `hexLower(SHA-256("andvari/v2|recovery-request|code|" + b64url(rPub)))[0..24]`, 96 bits the person reads to the operator. */
export function requestCode(rPub: Uint8Array): string {
  return toHexLower(sha256Sync(utf8(REQUEST_CODE_DOMAIN + toB64(rPub)))).slice(0, 24);
}

/** The display form of a request code: six groups of four, separated by single spaces. */
export const groupedRequestCode = (code: string): string => code.match(/.{1,4}/g)?.join(" ") ?? "";

/** What the requesting device knows of its own request (§9.3 step 1). */
export interface AssistedRequest {
  /** The pinned card's `instanceId`. */
  readonly instanceId: string;
  /** This device's userId, or null on a fresh install that holds none: the comparison is then skipped (§2.4 "Small cases"). */
  readonly userId: string | null;
  readonly requestId: string;
  /** The one-time request key pair `(rPub, rSec)`. */
  readonly rPub: Uint8Array;
  readonly rSec: Uint8Array;
}

/** What the poll serves once `ready`, besides the seal (§9.3 step 4). */
export interface ServedIdentity {
  /** `Envelope(UVK, seed, "andvari/v1|idkey|{userId}")`. */
  readonly encryptedIdentitySeed: Uint8Array;
  readonly identityPub: Uint8Array;
}

/** A payload that passed every check of {@link openAssistedRecovery}. The UVK is the caller's to wipe once re-wrapped. */
export interface OpenedAssistedRecovery {
  readonly userId: string;
  readonly uvk: Uint8Array;
  readonly issuedAt: number;
}

/**
 * The requesting device's checks once the poll answers `ready` (§9.3 step 4), in §2.4's order; the
 * first failure is the verdict:
 *
 * 1. `unopenable`: the seal does not open with the request key pair;
 * 2. the parse verdicts (purpose 0x09);
 * 3. `signer_not_pinned_key`: the signer is not the recovery key the PINNED card's `recoveryFp` names
 *    (null for `none`: nothing can pass); `bad_signature`. A server holding no recovery key fails here;
 * 4. `request_mismatch`: `instanceId`, `requestId`, `requestKey` (b64url of `rPub`), and `userId`
 *    when the device holds one;
 * 5. `identity_mismatch`: the served seed does not open under the delivered UVK with the statement's
 *    `userId` in its AD, or its X25519 key is not the served `identityPub` (R27).
 *
 * Passing this does not tie the account to the address typed: the app shows the delivered account ID
 * for the person to check before any new password is set (§9.3 step 4).
 *
 * The opened frame, its parts, the identity seed and every copy of the UVK this function makes are
 * wiped before it returns, except the `uvk` it hands back. One copy is out of its reach: libsodium's,
 * inside its WebAssembly memory, which it frees without wiping.
 */
export function openAssistedRecovery(
  request: AssistedRequest,
  sealed: Uint8Array,
  pinnedRecoveryFp: string | null,
  served: ServedIdentity,
): Checked<OpenedAssistedRecovery, RecoveryVerdict> {
  let frame: Uint8Array;
  try {
    frame = sealOpen(request.rPub, request.rSec, sealed);
  } catch {
    return refused("unopenable");
  }
  // The frame holds the account's UVK in the clear. Whatever the outcome, the frame, its split parts and
  // (unless it is handed to the caller) the decoded key are wiped before this returns.
  let parsed: ParsedFrame | null = null;
  let uvk: Uint8Array | null = null;
  let handedOver = false;
  try {
    const p = parseFrame(frame, "assisted-recovery");
    if (!p.ok) return p;
    parsed = p.value;
    const { raw, parts } = parsed;
    if (!signerHasFingerprint(parts, pinnedRecoveryFp)) return refused("signer_not_pinned_key");
    if (!signatureValid(parts)) return refused("bad_signature");
    if (raw.instanceId !== request.instanceId || raw.requestId !== request.requestId || raw.requestKey !== toB64(request.rPub)) {
      return refused("request_mismatch");
    }
    if (request.userId !== null && raw.userId !== request.userId) return refused("request_mismatch");

    uvk = secretOf(parsed, "uvk"); // straight from the statement bytes: the key is never a string
    let seed: Uint8Array;
    try {
      seed = openKey(uvk, served.encryptedIdentitySeed, adIdkey(raw.userId!), "the identity seed");
    } catch {
      return refused("identity_mismatch");
    }
    let same = false;
    try {
      if (seed.length === 32 && served.identityPub.length === 32) {
        const derived = boxKeypairFromSeed(seed);
        derived.privateKey.fill(0);
        same = ctEquals(derived.publicKey, served.identityPub);
      }
    } finally {
      seed.fill(0);
    }
    if (!same) return refused("identity_mismatch");
    handedOver = true;
    return ok({ userId: raw.userId!, uvk, issuedAt: Number(raw.issuedAt) });
  } finally {
    frame.fill(0);
    if (parsed !== null) wipeFrameParts(parsed.parts);
    if (uvk !== null && !handedOver) uvk.fill(0);
  }
}

// ---- 0x09 version 3: the answer that names the address and carries the commit value -----------------
//
// NOT DEAD CODE. No screen of the web asks the operator for help: the person's assisted flow (asking, polling, opening
// the answer, the commit) lives in the apps, and no route of it has a caller in this bundle (api/wire.ts). These are the
// web twins of core `AssistedRecovery.openV3` and `AssistedRecovery.commitHash` (spec 04 §7 steps 3 to 5),
// kept so that the web crypto stays graded against the same vectors as every other engine
// (`spec/test-vectors/recovery-v3.json`, recovery-v3.vectors.test.ts) and is ready the day the web carries the flow.

/** A version-3 answer that passed every check of {@link openAssistedRecoveryV3}. The caller wipes `uvk` and `commit`. */
export interface OpenedAssistedRecoveryV3 extends OpenedAssistedRecovery {
  /** The `emailNorm` the answer names: the address the person typed when asking. */
  readonly email: string;
  /** The 32-byte commit value the device presents at the commit (spec 03 §18.5). */
  readonly commit: Uint8Array;
}

const COMMIT_DOMAIN = "andvari/v2|recovery-request|commit|";

/**
 * The commit hash (spec 04 §7 step 3, spec 01 §5.5): `hexLower(SHA-256("andvari/v2|recovery-request|commit|" +
 * b64url(commit)))`. The tool prints it in the answer token, the upload carries it, and the server compares a presented
 * commit value's hash with it. Twin of core `AssistedRecovery.commitHash`.
 */
export function commitHash(commit: Uint8Array): string {
  if (commit.length !== 32) throw new CryptoError("the commit value is 32 bytes");
  return toHexLower(sha256Sync(utf8(COMMIT_DOMAIN + toB64(commit))));
}

/**
 * The requesting device's checks on a VERSION-3 answer (spec 04 §7 step 4), the only form a device accepts, in
 * {@link openAssistedRecovery}'s order; the first failure is the verdict:
 * 1. `unopenable`;
 * 2. the 0x09 frame and strict parse under the version-3 template only (`bad_frame`, `unknown_format`, `non_canonical`,
 *    `bad_statement`: a statement canonical under the old version-2 template is `bad_statement`, whatever its `v`);
 * 3. `signer_not_pinned_key`, `bad_signature`;
 * 4. `request_mismatch`: `instanceId`, `requestId`, `requestKey`, `userId` when the device holds one, and `email`
 *    decoding to exactly `emailNorm(typedEmail)`, the address the person typed when asking, on a fresh install too (a
 *    typed address with no `emailNorm` matches nothing);
 * 5. `identity_mismatch`.
 *
 * Twin of core `AssistedRecovery.openV3`. The frame, its parts and every copy of the key and the commit value this
 * function makes are wiped before it returns, except the two it hands back.
 */
export function openAssistedRecoveryV3(
  request: AssistedRequest,
  typedEmail: string,
  sealed: Uint8Array,
  pinnedRecoveryFp: string | null,
  served: ServedIdentity,
): Checked<OpenedAssistedRecoveryV3, RecoveryVerdict> {
  let frame: Uint8Array;
  try {
    frame = sealOpen(request.rPub, request.rSec, sealed);
  } catch {
    return refused("unopenable");
  }
  let parsed: ParsedFrame | null = null;
  let uvk: Uint8Array | null = null;
  let commit: Uint8Array | null = null;
  let handedOver = false;
  try {
    const p = parseFrame(frame, "assisted-recovery", 3);
    if (!p.ok) return p;
    parsed = p.value;
    const { raw, parts } = parsed;
    if (!signerHasFingerprint(parts, pinnedRecoveryFp)) return refused("signer_not_pinned_key");
    if (!signatureValid(parts)) return refused("bad_signature");
    if (raw.instanceId !== request.instanceId || raw.requestId !== request.requestId || raw.requestKey !== toB64(request.rPub)) {
      return refused("request_mismatch");
    }
    if (request.userId !== null && raw.userId !== request.userId) return refused("request_mismatch");
    // The address the answer restores is the one the person asked with, with or without a held account.
    const named = decodeEmail(raw.email!)?.email ?? null;
    const asked = emailNorm(typedEmail);
    if (named === null || asked === null || named !== asked) return refused("request_mismatch");
    commit = fromB64Canonical(raw.commit!);
    if (commit === null || commit.length !== 32) return refused("non_canonical");

    uvk = secretOf(parsed, "uvk");
    if (!identityHolds(uvk, raw.userId!, served)) return refused("identity_mismatch");
    handedOver = true;
    return ok({ userId: raw.userId!, uvk, issuedAt: Number(raw.issuedAt), email: named, commit });
  } finally {
    frame.fill(0);
    if (parsed !== null) wipeFrameParts(parsed.parts);
    if (!handedOver) {
      uvk?.fill(0);
      commit?.fill(0);
    }
  }
}

/** §9.3 step 4's last check (R27): the served seed opens under [uvk] with [userId] in its AD, to the served `identityPub`. */
function identityHolds(uvk: Uint8Array, userId: string, served: ServedIdentity): boolean {
  let seed: Uint8Array;
  try {
    seed = openKey(uvk, served.encryptedIdentitySeed, adIdkey(userId), "the identity seed");
  } catch {
    return false;
  }
  try {
    if (seed.length !== 32 || served.identityPub.length !== 32) return false;
    const derived = boxKeypairFromSeed(seed);
    derived.privateKey.fill(0);
    return ctEquals(derived.publicKey, served.identityPub);
  } finally {
    seed.fill(0);
  }
}

// ---- 0x0A veto (§9.3 step 2) -----------------------------------------------------------------------

/** `{"v":2,"purpose":"recovery-veto","requestId":<b64_16>,"userId":<uuid>,"issuedAt":<ms>}` */
export interface VetoFields {
  readonly requestId: string;
  readonly userId: string;
  readonly issuedAt: number;
}

/** Encode and sign a veto with `signer`, the account's joint Ed25519 key, for `POST /recovery/requests/{id}/veto`. Throws `CryptoError` outside the grammar. */
export function signVeto(signer: KeyPairBytes, veto: VetoFields): Uint8Array {
  const statement = encodeStatement("recovery-veto", { requestId: veto.requestId, userId: veto.userId, issuedAt: String(veto.issuedAt) });
  return signFrame(signer, "recovery-veto", statement);
}

/**
 * The checks on a posted veto (the server's, §9.3 step 2), in §2.4's order: the parse verdicts;
 * `signer_not_pinned_key` (the signer does not map to `identityPub`, the account's stored identity
 * key); `bad_signature`; `user_mismatch` (`userId` is not the session's); `request_mismatch` (not the
 * path's `requestId`).
 */
export function verifyVeto(frame: Uint8Array, identityPub: Uint8Array, userId: string, requestId: string): Checked<VetoFields, RecoveryVerdict> {
  const parsed = parseFrame(frame, "recovery-veto");
  if (!parsed.ok) return parsed;
  const { raw, parts } = parsed.value;
  if (!signerMapsTo(parts, identityPub)) return refused("signer_not_pinned_key");
  if (!signatureValid(parts)) return refused("bad_signature");
  if (raw.userId !== userId) return refused("user_mismatch");
  if (raw.requestId !== requestId) return refused("request_mismatch");
  return ok({ requestId: raw.requestId!, userId: raw.userId!, issuedAt: Number(raw.issuedAt) });
}
