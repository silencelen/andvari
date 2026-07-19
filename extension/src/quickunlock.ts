// Runtime (value) imports carry the .ts extension so quickunlock.ts resolves under `node --test`
// (its test imports it); esbuild + tsc (allowImportingTsExtensions) accept the suffix for the bundle.
import { adQuickUnlock, adQuickUnlockBio, deriveKBio, fromB64, open, seal, toB64, type KdfParams } from "./crypto.ts";

/**
 * Extension quick-unlock Tier B (spec 01 §8.4; design 2026-07-13-platform-fit §1) — a PIN-wrapped,
 * session-scoped UVK that turns the 15-min idle relock's full online sign-in + ~6 s Argon2id into
 * PIN + ~1 s. This module is the chrome-free, node-testable ENGINE: every storage / IndexedDB /
 * Argon2id / clock dependency is injected (background.ts wires the real ones), so the two mandatory
 * breaker passes' crypto and lifecycle invariants can be exercised under plain `node --test`.
 *
 * The load-bearing weakening vs a naïve PIN-only wrap (breaker A1): the UVK is DOUBLE-wrapped —
 *   ct = AEAD(K_pin, AEAD(K_nonexp, UVK))
 * where K_nonexp is a NON-EXTRACTABLE WebCrypto AES-GCM key living in IndexedDB (injected here as
 * a CryptoKey). A PIN-only wrap is offline-crackable (a 6-digit PIN is GPU-minutes, not years) and
 * is REJECTED. The co-key never leaves the browser and only unwraps this session-scoped blob, so it
 * is not a standalone durable vault opener; it MUST be wiped on every blob-wipe (see `wipe`). Both
 * AEAD layers bind `adQuickUnlock(userId)` (breaker A6 crypto side).
 *
 * The engine never persists the UVK (breaker B1 — background keeps it in SW memory for the unlocked
 * lifetime only), never touches the wire (spec 01 §8 invariant), and fails CLOSED everywhere a read
 * could throw. The record lives under a DISTINCT storage.session key that `ensureLoaded` must NOT
 * hydrate `session` from (breaker B3) — `session` stays null while locked-armed, so every `!session`
 * gate keeps reporting fully locked.
 */

// ---- PIN KDF fence (breaker A8) — a DEDICATED assertion, NOT crypto.ts assertServerKdfParams
// (whose FLOOR is the 64 MiB MASTER-password floor). pinParams live in the attacker-writable blob,
// so they need a floor AND a ceiling: a planted 4 GiB would OOM the service worker; a sub-floor set
// would be offline-crackable. Sub-range / non-finite / omitted → corrupt → wipe (never derive).
export const PIN_KDF_MIN_MEM_BYTES = 33_554_432; // 32 MiB — the honest quick-unlock floor (design §1)
export const PIN_KDF_MIN_OPS = 2;
export const PIN_KDF_MAX_MEM_BYTES = 1_073_741_824; // 1 GiB
export const PIN_KDF_MAX_OPS = 10;

/** Distinct signal — the blob's pinParams are out of the honest range (planted / corrupt). */
export class PinKdfPolicyError extends Error {
  // Explicit field (not a TS parameter property): the extension test runner is node
  // --experimental-strip-types (strip-only), which rejects the `constructor(readonly x)` shorthand.
  readonly reason: "pin_kdf_below_floor" | "pin_kdf_above_ceiling";
  constructor(reason: "pin_kdf_below_floor" | "pin_kdf_above_ceiling") {
    super(`quick-unlock PIN KDF params rejected (${reason})`);
    this.name = "PinKdfPolicyError";
    this.reason = reason;
  }
}

/** Reject blob-supplied PIN KDF params outside the honest range BEFORE any argon2id derives under
 *  them (breaker A8). Inclusive bounds. Non-numeric / omitted fields slip past a bare `<`/`>`, so
 *  reject them explicitly (mirrors crypto.ts assertServerKdfParams' JS-bypass guard). */
export function assertPinKdfParams(p: KdfParams): void {
  if (p.v !== 1 || p.alg !== "argon2id13") throw new PinKdfPolicyError("pin_kdf_below_floor");
  if (typeof p.ops !== "number" || !Number.isFinite(p.ops) || typeof p.memBytes !== "number" || !Number.isFinite(p.memBytes))
    throw new PinKdfPolicyError("pin_kdf_below_floor");
  if (p.memBytes < PIN_KDF_MIN_MEM_BYTES || p.ops < PIN_KDF_MIN_OPS) throw new PinKdfPolicyError("pin_kdf_below_floor");
  if (p.memBytes > PIN_KDF_MAX_MEM_BYTES || p.ops > PIN_KDF_MAX_OPS) throw new PinKdfPolicyError("pin_kdf_above_ceiling");
}

// ---- PIN entropy floor (breaker A2 ⊕ B8) — enforcement, NOT copy-only. There is no hardware gate
// under MV3, so Argon2id over the PIN is the only defense against a stolen blob; the entropy floor
// is the other. A 6-digit all-numeric PIN (~10^6) is GPU-minutes and is REJECTED.
export const PIN_MIN_LENGTH = 6;
export const PIN_ALL_DIGIT_MIN_LENGTH = 10;
export type PinWeakReason = "too_short" | "digits_need_length" | "trivial";

// Canonical weak sequences — a PIN that is a whole contiguous slice of one of these (or its reverse),
// case-insensitively, is trivial. "1234567890" is listed explicitly because the 9→0 wrap makes it NOT
// a slice of "0123456789" yet it is the single most common numeric PIN humans pick.
const WEAK_SEQUENCES = ["1234567890", "0123456789", "abcdefghijklmnopqrstuvwxyz"];

/** True for a low-entropy PIN a length/digit rule alone would still admit: ≤2 distinct characters
 *  (all-identical, or a period-2 alternation like "121212"), an EXACT repeated block of any period
 *  ("12341234", "abcabc"), or a whole-PIN slice of a canonical ascending/descending sequence. */
function isTrivialPin(pin: string): boolean {
  const cp = [...pin].map((c) => c.charCodeAt(0));
  if (new Set(cp).size <= 2) return true; // ≤2 distinct chars (subsumes all-identical + period-2 repeats)
  // an exact repeated block: pin === block.repeat(n) for some period p ≤ len/2 (review F1: period-k repeats)
  for (let p = 1; p <= pin.length >> 1; p++) {
    if (pin.length % p === 0 && pin.slice(0, p).repeat(pin.length / p) === pin) return true;
  }
  const low = pin.toLowerCase();
  for (const seq of WEAK_SEQUENCES) {
    const rev = [...seq].reverse().join("");
    if (seq.includes(low) || rev.includes(low)) return true; // ascending or descending run
  }
  return false;
}

/** Entropy floor: ≥6 chars; all-digit PINs need ≥10 digits (a 6-8 char PIN must carry ≥1 non-digit);
 *  trivial sequences/repeats blocked. Returns a reason so the popup can render a specific nudge. */
export function validatePin(pin: string): { ok: true } | { ok: false; reason: PinWeakReason } {
  if (pin.length < PIN_MIN_LENGTH) return { ok: false, reason: "too_short" };
  if (/^\d+$/.test(pin) && pin.length < PIN_ALL_DIGIT_MIN_LENGTH) return { ok: false, reason: "digits_need_length" };
  if (isTrivialPin(pin)) return { ok: false, reason: "trivial" };
  return { ok: true };
}

// ---- double-wrap seal/open (breaker A1) ----
const INNER_IV_BYTES = 12; // AES-GCM IV
const AES_TAG_BYTES = 16;

// crypto.subtle's BufferSource type rejects a Uint8Array whose backing buffer is ArrayBufferLike
// (the SharedArrayBuffer union) — noble's `open()` output and TextEncoder AAD are typed that way.
// These are all ≤60-byte views, so a fresh ArrayBuffer-backed copy is free and sidesteps the union.
const ab = (u: Uint8Array): Uint8Array<ArrayBuffer> => {
  const c = new Uint8Array(u.length);
  c.set(u);
  return c;
};

/** ct = AEAD(K_pin, AEAD(K_nonexp, UVK)). Inner = WebCrypto AES-GCM under the non-extractable co-key
 *  (IV prepended to its ciphertext); outer = the existing XChaCha20-Poly1305 envelope under K_pin.
 *  Both layers AAD-bound to `adQuickUnlock(userId)`. Returns the outer envelope base64url. */
export async function sealDoubleWrap(kPin: Uint8Array, kNonExp: CryptoKey, uvk: Uint8Array, userId: string, aad: Uint8Array = adQuickUnlock(userId)): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(INNER_IV_BYTES));
  const innerCt = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: ab(aad) }, kNonExp, ab(uvk)));
  const innerBlob = new Uint8Array(INNER_IV_BYTES + innerCt.length);
  innerBlob.set(iv, 0);
  innerBlob.set(innerCt, INNER_IV_BYTES);
  return toB64(seal(kPin, innerBlob, aad)); // outer envelope carries its own 24-byte nonce inline
}

/** Reverse of sealDoubleWrap. Throws on wrong PIN / tampered outer (open) OR a wrong/absent co-key
 *  / tampered inner (subtle.decrypt) — indistinguishable by design, so there is NO partial-correctness
 *  oracle (breaker A1/A2 fail-closed table row). */
export async function openDoubleWrap(kPin: Uint8Array, kNonExp: CryptoKey, ct: string, userId: string, aad: Uint8Array = adQuickUnlock(userId)): Promise<Uint8Array> {
  const innerBlob = open(kPin, fromB64(ct), aad); // outer AEAD — throws on wrong PIN / tamper / unknown version
  if (innerBlob.length < INNER_IV_BYTES + AES_TAG_BYTES) throw new Error("quick-unlock inner blob too short");
  const iv = innerBlob.subarray(0, INNER_IV_BYTES);
  const innerCt = innerBlob.subarray(INNER_IV_BYTES);
  return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: ab(iv), additionalData: ab(aad) }, kNonExp, ab(innerCt)));
}

// ---- record shape (storage.session, DISTINCT key) ----

/** The PIN-wrapped-UVK blob. `ct` is the double wrap; `lastFullUnlockAt` is COPIED from the surviving
 *  full-password unlock at enroll (breaker A4) — never minted `now` from a QUICK session. */
/** PIN-wrapped-UVK blob (the original v:1 shape). `kind` is absent on pre-0.17.0 records and reads as
 *  "pin"; new PIN enrolls write it explicitly. */
export interface QuBlobPin {
  v: 1;
  kind?: "pin";
  salt: string; // base64url, 16 bytes — Argon2id(PIN) salt
  kdfParams: KdfParams;
  ct: string; // base64url — AEAD(K_pin, AEAD(K_nonexp, UVK))
  createdAt: number;
  lastFullUnlockAt: number;
}
/** Biometric-wrapped-UVK blob (0.17.0). The outer key K_bio = HKDF(WebAuthn-PRF secret) is NEVER
 *  stored — only the credential id + PRF salt needed to re-derive it via the platform authenticator
 *  (gated by OS user-verification). No KDF params: the PRF output is full entropy, so the
 *  assertPinKdfParams floor/ceiling fence is pin-only. AAD = adQuickUnlockBio (review amendment 2). */
export interface QuBlobBio {
  v: 1;
  kind: "biometric";
  credentialId: string; // base64url WebAuthn rawId
  prfSalt: string; // base64url, 32 bytes
  ct: string; // base64url — AEAD(K_bio, AEAD(K_nonexp, UVK))
  createdAt: number;
  lastFullUnlockAt: number;
}
export type QuBlob = QuBlobPin | QuBlobBio;
export type BlobKind = "pin" | "biometric";

/** Validate + narrow a stored blob's method (review amendment 1). Absent `kind` ⇒ "pin" (v:1 compat).
 *  Returns null when the narrowed shape is missing a required field — the caller treats null as
 *  corrupt → wipe. MUST run BEFORE any reserve-decrement so a kind-stripped bio blob (which narrows to
 *  "pin" and would hit assertPinKdfParams(undefined) → uncaught TypeError, escaping doUnlockWithPin's
 *  un-try'd beginRedeem) can never leave the blob un-wiped. */
export function validBlobKind(blob: QuBlob | null | undefined): BlobKind | null {
  if (!blob || typeof blob !== "object") return null;
  const b = blob as unknown as Record<string, unknown>;
  const kind: BlobKind = b.kind === "biometric" ? "biometric" : "pin";
  if (kind === "pin") {
    return typeof b.salt === "string" && !!b.kdfParams && typeof b.kdfParams === "object" && typeof b.ct === "string" ? "pin" : null;
  }
  return typeof b.credentialId === "string" && typeof b.prfSalt === "string" && typeof b.ct === "string" ? "biometric" : null;
}

/** The whole quick-unlock compartment. Present whenever ARMED (unlocked-armed OR locked-armed).
 *  `lockedTokens` is the locked-but-authenticated token stash — set ONLY at lock (doLock armed
 *  branch), null while unlocked-armed (tokens live in the full SessionSnapshot then) and after any
 *  wipe. `userId` gives the per-userId binding erase story (breaker A6). */
export interface QuRecord {
  v: 1;
  userId: string;
  email: string;
  blob: QuBlob;
  attemptsRemaining: number; // starts MAX_PIN_ATTEMPTS; attacker-resettable — see spec 05 A7-extension
  autoLockSeconds: number;
  lockedTokens: { access: string; refresh: string | null } | null;
}

export const MAX_PIN_ATTEMPTS = 5;
/** The Android durable-blob 30-day periodic-full rule collapses to min(browser session, 24 h) here:
 *  storage.session cannot outlive the browser, and the extension has no re-key path (spec 01 §8.4). */
export const QU_MAX_AGE_MS = 24 * 60 * 60 * 1000;

// ---- injected dependencies ----

/** The DISTINCT storage.session record slot (breaker B3). `remove` MUST delete the key directly
 *  (breaker A7/A10/B7 — never via a persistSession that early-returns when session===null). */
export interface QuStore {
  read(): Promise<QuRecord | null>;
  write(rec: QuRecord): Promise<void>;
  remove(): Promise<void>;
}

/** The non-extractable AES-GCM co-key in IndexedDB (breaker A1). `generate` mints a FRESH key
 *  (per enroll) and persists it; `delete` is called on EVERY blob-wipe. */
export interface QuCoKey {
  generate(): Promise<CryptoKey>;
  get(): Promise<CryptoKey | null>;
  delete(): Promise<void>;
}

/** The WebAuthn ceremony seam (0.17.0) — injected so quickunlock.ts stays chrome/WebAuthn-free and
 *  node-testable. The real impl runs `navigator.credentials.create/get` in the connector window and
 *  brokers the result to the SW; a throw (NotAllowedError = cancel/timeout/deleted credential) surfaces
 *  as `bio_cancelled` with the record left UNTOUCHED. `enroll` returns prfEnabled=false on a platform
 *  without PRF (→ bio_unsupported). `evalPrf` returns the 32-byte PRF secret. */
export interface QuBiometric {
  enroll(prfSalt: Uint8Array): Promise<{ credentialId: string; prfEnabled: boolean }>;
  evalPrf(credentialId: string, prfSalt: Uint8Array): Promise<Uint8Array>;
}

export interface QuDeps {
  store: QuStore;
  coKey: QuCoKey;
  /** Argon2id(PIN) via the SW's kdf worker (background.deriveMasterKeyAsync). */
  deriveKPin(pin: string, params: KdfParams, salt: Uint8Array): Promise<Uint8Array>;
  /** WebAuthn-PRF ceremony broker (0.17.0). Absent → the biometric method is unavailable (PIN only). */
  biometric?: QuBiometric;
  /** One-shot enroll bench → the strongest floored params under ~1 s on this machine (breaker B8). */
  benchPinParams(): Promise<KdfParams>;
  now(): number;
  randomBytes(n: number): Uint8Array;
}

// ---- result unions ----

export interface EnrollArgs {
  uvk: Uint8Array;
  userId: string;
  email: string;
  pin: string;
  /** COPIED from the live session's surviving full-password stamp — never `now()` (breaker A4). */
  lastFullUnlockAt: number;
  autoLockSeconds: number;
}
export type EnrollResult = { ok: true } | { ok: false; code: "weak_pin"; reason: PinWeakReason };
/** enrollBio outcome. `bio_unsupported` = no platform authenticator / no PRF (prfEnabled false or a
 *  non-32-byte secret); `bio_cancelled` = the ceremony threw (user cancel / timeout / no gesture). In
 *  BOTH failure cases NOTHING is wiped (amendment 3 — the ceremony runs before any wipe). */
export type EnrollBioResult = { ok: true } | { ok: false; code: "bio_unsupported" | "bio_cancelled" };

/** doLock armed-branch verdict. `not-enrolled` → the caller stays byte-identical to today's full
 *  erase; `declined` (ineligible record OR a read that threw — fail-closed) → full erase + wipe. */
export type ArmResult = "armed" | "not-enrolled" | "declined";

export type BeginRedeemOk = { ok: true; uvk: Uint8Array; userId: string; email: string; tokens: { access: string; refresh: string | null }; blob: QuBlob; autoLockSeconds: number };
export type BeginRedeem =
  | BeginRedeemOk
  | { ok: false; code: "not_armed" | "expired" | "exhausted" | "corrupt" }
  | { ok: false; code: "wrong_pin"; attemptsRemaining: number };
/** Biometric redeem outcome — no `wrong_pin`/`exhausted` (no attempt budget); adds `bio_cancelled`
 *  (the ceremony threw, record kept). Distinct from BeginRedeem so the PIN mapper never sees bio codes. */
export type BeginRedeemBio =
  | BeginRedeemOk
  | { ok: false; code: "not_armed" | "expired" | "corrupt" | "bio_cancelled" };

export interface QuStatus {
  enrolled: boolean;
  /** Redeemable-right-now: locked-armed, tokens stashed, fresh, attempts left. Drives the popup's
   *  PIN field vs master-password field on the LOCKED screen. */
  armed: boolean;
  attemptsRemaining: number;
  /** Which method is enrolled (0.17.0) — drives the PIN field vs the "Unlock with Windows Hello /
   *  Touch ID" button on the locked screen. null when nothing is enrolled. */
  kind: BlobKind | null;
}

/**
 * The quick-unlock engine. background.ts owns the single-flight + owns()-generation guard around
 * `beginRedeem` (breaker A5⊕B4) and does the server dance between beginRedeem and completeRedeem;
 * this class owns the crypto + record lifecycle.
 */
export class QuickUnlock {
  private readonly deps: QuDeps;
  constructor(deps: QuDeps) {
    this.deps = deps;
  }

  /** The window guard, evaluated on Date.now() with fail-closed-on-future-stamp (design §1). The
   *  spec 01 §8.1 cross-boot server-anchor machinery is deliberately NOT needed — a reboot kills the
   *  browser kills the storage.session record. */
  isStampFresh(lastFullUnlockAt: number): boolean {
    const now = this.deps.now();
    if (typeof lastFullUnlockAt !== "number" || !Number.isFinite(lastFullUnlockAt)) return false;
    if (lastFullUnlockAt > now) return false; // future stamp → fail closed
    return now - lastFullUnlockAt <= QU_MAX_AGE_MS;
  }

  /** FULL wipe (breaker A1/A3/A7/B7): remove the record slot directly AND delete the co-key. Every
   *  wipe-class event (exhausted attempts, revocation, sign-out, disable, stale/foreign UVK,
   *  corrupt params, account switch) routes here. Idempotent — safe when nothing exists. */
  async wipe(): Promise<void> {
    await this.deps.store.remove();
    await this.deps.coKey.delete();
  }

  /** Account switch (breaker A6): a full unlock as a DIFFERENT user strands the prior opener — wipe
   *  it. The AAD already blocks cross-account crypto use; this is the explicit erase story. */
  async reconcileUser(userId: string): Promise<void> {
    try {
      const rec = await this.deps.store.read();
      if (rec && rec.userId !== userId) await this.wipe();
    } catch {
      /* a read that throws — a fresh full unlock re-enrolls from scratch anyway */
    }
  }

  /** A successful full-PASSWORD unlock (breaker A6 + A11 + the fail-closed "a full unlock re-stamps"
   *  rule): wipe a different-user blob (account switch), and for a surviving same-user blob RE-STAMP
   *  the 24 h window to `at` (the fresh full-password time — the ONLY place besides enroll that moves
   *  the stamp, and never from a QUICK session) and refresh the attempt budget to full. */
  async onFullUnlock(userId: string, at: number): Promise<void> {
    await this.reconcileUser(userId);
    try {
      const rec = await this.deps.store.read();
      if (rec && rec.userId === userId) {
        rec.blob.lastFullUnlockAt = at;
        rec.attemptsRemaining = MAX_PIN_ATTEMPTS;
        await this.deps.store.write(rec);
      }
    } catch {
      /* a read/write that throws — the blob simply keeps its prior stamp/counter (fail-safe) */
    }
  }

  async status(): Promise<QuStatus> {
    try {
      const rec = await this.deps.store.read();
      if (!rec) return { enrolled: false, armed: false, attemptsRemaining: 0, kind: null };
      const kind = validBlobKind(rec.blob); // a corrupt/missing blob → null → the popup shows the master form
      const armed = kind !== null && rec.lockedTokens !== null && rec.attemptsRemaining > 0 && this.isStampFresh(rec.blob.lastFullUnlockAt);
      return { enrolled: kind !== null, armed, attemptsRemaining: rec.attemptsRemaining, kind };
    } catch {
      return { enrolled: false, armed: false, attemptsRemaining: 0, kind: null };
    }
  }

  /** Enroll (breaker A1/A2/A4/A8). Caller has already gated: session unlocked, uvk in memory
   *  (breaker B1), mustChangePassword===false (§8.1-A5). Wipes any prior blob + co-key FIRST, then
   *  mints a FRESH co-key so the new blob is bound to fresh key material. */
  async enroll(args: EnrollArgs): Promise<EnrollResult> {
    const pv = validatePin(args.pin);
    if (!pv.ok) return { ok: false, code: "weak_pin", reason: pv.reason };
    const kdfParams = await this.deps.benchPinParams();
    assertPinKdfParams(kdfParams); // never persist sub-floor/above-ceiling params (breaker A8)
    await this.wipe(); // #11: wipe prior blob + co-key before re-enroll
    const kNonExp = await this.deps.coKey.generate();
    const salt = this.deps.randomBytes(16);
    const kPin = await this.deps.deriveKPin(args.pin, kdfParams, salt);
    const ct = await sealDoubleWrap(kPin, kNonExp, args.uvk, args.userId);
    const blob: QuBlobPin = { v: 1, kind: "pin", salt: toB64(salt), kdfParams, ct, createdAt: this.deps.now(), lastFullUnlockAt: args.lastFullUnlockAt };
    await this.deps.store.write({
      v: 1,
      userId: args.userId,
      email: args.email,
      blob,
      attemptsRemaining: MAX_PIN_ATTEMPTS,
      autoLockSeconds: args.autoLockSeconds,
      lockedTokens: null,
    });
    return { ok: true };
  }

  /** Enroll the BIOMETRIC method (0.17.0). Same caller gates as enroll() (unlocked, uvk in memory,
   *  !mustChangePassword). Amendment 3: the WebAuthn ceremonies run BEFORE wipe() — a cancelled/failed
   *  prompt (the likeliest failure) must never leave the prior quick-unlock wiped with no replacement.
   *  Only once the PRF secret is in hand do we wipe + mint a fresh co-key + seal, all-or-nothing. */
  async enrollBio(args: Omit<EnrollArgs, "pin">): Promise<EnrollBioResult> {
    const bio = this.deps.biometric;
    if (!bio) return { ok: false, code: "bio_unsupported" };
    const prfSalt = this.deps.randomBytes(32);
    let credentialId: string;
    let secret: Uint8Array;
    try {
      const c = await bio.enroll(prfSalt);
      if (!c.prfEnabled) return { ok: false, code: "bio_unsupported" }; // platform without PRF — nothing written
      credentialId = c.credentialId;
      secret = await bio.evalPrf(credentialId, prfSalt);
    } catch {
      return { ok: false, code: "bio_cancelled" }; // NotAllowedError etc. — prior record UNTOUCHED
    }
    if (secret.length !== 32) {
      secret.fill(0);
      return { ok: false, code: "bio_unsupported" };
    }
    const kBio = deriveKBio(secret, args.userId);
    secret.fill(0); // zeroize the raw PRF secret the moment K_bio is derived
    await this.wipe(); // commit point — from here it's all-or-nothing on a fresh co-key
    const kNonExp = await this.deps.coKey.generate();
    const ct = await sealDoubleWrap(kBio, kNonExp, args.uvk, args.userId, adQuickUnlockBio(args.userId));
    kBio.fill(0);
    const blob: QuBlobBio = { v: 1, kind: "biometric", credentialId, prfSalt: toB64(prfSalt), ct, createdAt: this.deps.now(), lastFullUnlockAt: args.lastFullUnlockAt };
    await this.deps.store.write({
      v: 1,
      userId: args.userId,
      email: args.email,
      blob,
      attemptsRemaining: MAX_PIN_ATTEMPTS, // inert for bio (never decremented) — see beginRedeemBio
      autoLockSeconds: args.autoLockSeconds,
      lockedTokens: null,
    });
    return { ok: true };
  }

  /** Biometric redeem — the counterpart of beginRedeem for a `kind:'biometric'` armed record. NO
   *  reserve-then-attempt: the blob is not offline-crackable (K_bio is a full-entropy hardware secret
   *  released only after OS user-verification, with the OS's own anti-hammering), so the attempt
   *  counter is never decremented. A ceremony throw = `bio_cancelled` (record UNTOUCHED, retry allowed).
   *  A post-PRF AEAD-open failure is deterministic corruption → wipe (a wrong K_bio can only mean a
   *  tampered blob, since the PRF re-derives identically). */
  async beginRedeemBio(): Promise<BeginRedeemBio> {
    const bio = this.deps.biometric;
    if (!bio) return { ok: false, code: "not_armed" };
    let rec: QuRecord | null;
    try {
      rec = await this.deps.store.read();
    } catch {
      return { ok: false, code: "not_armed" };
    }
    if (!rec || rec.lockedTokens === null) return { ok: false, code: "not_armed" };
    if (validBlobKind(rec.blob) !== "biometric") {
      await this.wipe(); // wrong-kind / corrupt / missing shape → wipe (amendment 1)
      return { ok: false, code: "corrupt" };
    }
    const bioBlob = rec.blob as QuBlobBio;
    if (!this.isStampFresh(bioBlob.lastFullUnlockAt)) return { ok: false, code: "expired" };
    let secret: Uint8Array;
    try {
      secret = await bio.evalPrf(bioBlob.credentialId, fromB64(bioBlob.prfSalt));
    } catch {
      return { ok: false, code: "bio_cancelled" }; // cancel / timeout / deleted credential — record kept
    }
    const kBio = deriveKBio(secret, rec.userId);
    secret.fill(0);
    const kNonExp = await this.deps.coKey.get();
    if (!kNonExp) {
      kBio.fill(0);
      await this.wipe(); // co-key gone but blob survived → orphaned → wipe
      return { ok: false, code: "corrupt" };
    }
    let uvk: Uint8Array;
    try {
      uvk = await openDoubleWrap(kBio, kNonExp, bioBlob.ct, rec.userId, adQuickUnlockBio(rec.userId));
    } catch {
      kBio.fill(0);
      await this.wipe(); // PRF verified but the AEAD failed → tampered blob → wipe (deterministic corruption)
      return { ok: false, code: "corrupt" };
    }
    kBio.fill(0);
    return { ok: true, uvk, userId: rec.userId, email: rec.email, tokens: rec.lockedTokens, blob: bioBlob, autoLockSeconds: rec.autoLockSeconds };
  }

  /** doLock armed branch (breaker B3): stash the live token pair so a locked-but-authenticated PIN
   *  redeem is possible, and report whether the caller should KEEP the slim snapshot or full-erase.
   *  Fails CLOSED to `declined` on any throw. Refuses to arm an ineligible (exhausted / stale) blob
   *  so tokens are never retained past the min(session, 24 h) window. */
  async arm(tokens: { access: string; refresh: string | null }): Promise<ArmResult> {
    let rec: QuRecord | null;
    try {
      rec = await this.deps.store.read();
    } catch {
      return "declined"; // fail-closed → caller full-erases + wipes
    }
    if (!rec) return "not-enrolled";
    // !rec.blob: a malformed record → decline (the caller full-erases + wipes). Guard the deref so a
    // blob-less record can never THROW out of arm() past doLock's [SKEY,TKEY] erase (review F1).
    if (validBlobKind(rec.blob) === null || rec.attemptsRemaining <= 0 || !this.isStampFresh(rec.blob.lastFullUnlockAt)) return "declined";
    rec.lockedTokens = { access: tokens.access, refresh: tokens.refresh };
    try {
      await this.deps.store.write(rec);
    } catch {
      return "declined";
    }
    return "armed";
  }

  /**
   * Reserve-then-attempt (breaker A5⊕B4). RESERVE the attempt (decrement + persist) BEFORE the AEAD
   * attempt so an SW eviction / racing popup between the decrement and the open can never gift a free
   * guess. On a verified crypto success returns the UVK + stashed tokens for the caller's forced-refresh
   * server dance; the counter is reset only by `completeRedeem` (after a verified full server success).
   */
  async beginRedeem(pin: string): Promise<BeginRedeem> {
    let rec: QuRecord | null;
    try {
      rec = await this.deps.store.read();
    } catch {
      return { ok: false, code: "not_armed" };
    }
    if (!rec || rec.lockedTokens === null) return { ok: false, code: "not_armed" };
    // Amendment 1: validate + require the PIN kind BEFORE the reserve-decrement. A missing blob, a
    // bio blob mis-routed here, or a kind-stripped blob → corrupt → wipe (never deref bad shapes /
    // decrement for a blob we can't open with a PIN).
    if (validBlobKind(rec.blob) !== "pin") {
      await this.wipe();
      return { ok: false, code: "corrupt" };
    }
    const pinBlob = rec.blob as QuBlobPin;
    // 24 h / future-stamp gate — blob KEPT (a fresh full unlock re-stamps). Not a guessing oracle,
    // so it is safe to evaluate before the reservation.
    if (!this.isStampFresh(pinBlob.lastFullUnlockAt)) return { ok: false, code: "expired" };
    if (rec.attemptsRemaining <= 0) {
      await this.wipe();
      return { ok: false, code: "exhausted" };
    }
    // RESERVE before the crackable operation. Persist the decrement first (mirrors api.ts consume-before-POST).
    const remaining = rec.attemptsRemaining - 1;
    rec.attemptsRemaining = remaining;
    await this.deps.store.write(rec);

    let kPin: Uint8Array;
    try {
      assertPinKdfParams(pinBlob.kdfParams); // A8 — sub-range params are corrupt, never derived under
      kPin = await this.deps.deriveKPin(pin, pinBlob.kdfParams, fromB64(pinBlob.salt));
    } catch (e) {
      if (e instanceof PinKdfPolicyError) {
        await this.wipe(); // planted/corrupt params → wipe (not a "wrong PIN")
        return { ok: false, code: "corrupt" };
      }
      throw e;
    }
    const kNonExp = await this.deps.coKey.get();
    if (!kNonExp) {
      await this.wipe(); // co-key gone but blob somehow survived → orphaned → wipe
      return { ok: false, code: "corrupt" };
    }
    let uvk: Uint8Array;
    try {
      uvk = await openDoubleWrap(kPin, kNonExp, pinBlob.ct, rec.userId);
    } catch {
      // Wrong PIN / tampered / unknown version / wrong co-key — indistinguishable, no oracle.
      if (remaining <= 0) {
        await this.wipe();
        return { ok: false, code: "exhausted" };
      }
      return { ok: false, code: "wrong_pin", attemptsRemaining: remaining };
    }
    // A verified open PROVES PIN knowledge, so the brute-force budget resets to full HERE — the
    // correct PIN never burns attempts even if the subsequent server dance (forced refresh / sync)
    // fails transiently. A concurrent wipe/lock is handled by the caller's owns() guard.
    rec.attemptsRemaining = MAX_PIN_ATTEMPTS;
    await this.deps.store.write(rec);
    return { ok: true, uvk, userId: rec.userId, email: rec.email, tokens: rec.lockedTokens, blob: rec.blob, autoLockSeconds: rec.autoLockSeconds };
  }

  /** During the redeem's forced-refresh, the caller routes onTokensChanged here so the consumed /
   *  rotated token pair is persisted to the locked-token stash BEFORE the POST (breaker A5, AM1
   *  parity) — a mid-refresh SW death then never resurrects a spent refresh token. */
  async setLockedTokens(tokens: { access: string | null; refresh: string | null }): Promise<void> {
    let rec: QuRecord | null;
    try {
      rec = await this.deps.store.read();
    } catch {
      return;
    }
    if (!rec) return;
    rec.lockedTokens = tokens.access ? { access: tokens.access, refresh: tokens.refresh } : null;
    await this.deps.store.write(rec);
  }

  /** After a verified full server success: clear the locked-token stash (the rotated pair now lives
   *  in the full SessionSnapshot) and refresh autoLockSeconds; keep the blob so the next lock re-arms.
   *  The counter was already reset to full by beginRedeem's verified open. */
  async completeRedeem(autoLockSeconds: number): Promise<void> {
    const rec = await this.deps.store.read();
    if (!rec) return; // wiped by a concurrent event — caller's owns() guard already discarded the redeem
    rec.attemptsRemaining = MAX_PIN_ATTEMPTS;
    rec.lockedTokens = null;
    rec.autoLockSeconds = autoLockSeconds;
    await this.deps.store.write(rec);
  }
}
