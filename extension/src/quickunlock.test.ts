// node --test (see version.test.ts). The extension quick-unlock Tier B engine (spec 01 §8.4) — the
// crypto + lifecycle invariants both mandatory breaker passes demanded. Chrome-free: every dep is
// injected, so the double-wrap, the reserve-before-attempt counter, the fail-closed wipes, and the
// pinParams fence all run under plain type-stripped node. WebCrypto (crypto.subtle) + the co-key are
// REAL here (node ships webcrypto); only storage / the Argon2id worker / the clock are faked.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { sha256 } from "@noble/hashes/sha2.js";
import { adQuickUnlock, open, type KdfParams } from "./crypto.ts";
import {
  assertPinKdfParams,
  MAX_PIN_ATTEMPTS,
  openDoubleWrap,
  PinKdfPolicyError,
  PIN_KDF_MAX_MEM_BYTES,
  PIN_KDF_MAX_OPS,
  PIN_KDF_MIN_MEM_BYTES,
  PIN_KDF_MIN_OPS,
  QuickUnlock,
  QU_MAX_AGE_MS,
  sealDoubleWrap,
  validatePin,
  type QuCoKey,
  type QuDeps,
  type QuRecord,
  type QuStore,
} from "./quickunlock.ts";

const utf8 = (s: string) => new TextEncoder().encode(s);
const PIN_PARAMS: KdfParams = { v: 1, alg: "argon2id13", ops: 2, memBytes: PIN_KDF_MIN_MEM_BYTES };
const UVK = new Uint8Array(32).map((_, i) => i + 1); // a recognizable 32-byte UVK

/** A deterministic stand-in for the Argon2id worker: K_pin = SHA-256(pin). Deterministic per PIN
 *  (so a correct PIN round-trips, a wrong PIN yields a different key ⇒ the AEAD fails), and fast. */
function fakeDerive(pin: string): Promise<Uint8Array> {
  return Promise.resolve(sha256(utf8(pin)));
}

function fakeStore() {
  let rec: QuRecord | null = null;
  const state = { writes: 0, removes: 0, throwOnRead: false };
  const store: QuStore = {
    read: async () => {
      if (state.throwOnRead) throw new Error("storage.session unavailable");
      return rec ? (structuredClone(rec) as QuRecord) : null;
    },
    write: async (r) => {
      rec = structuredClone(r) as QuRecord;
      state.writes++;
    },
    remove: async () => {
      rec = null;
      state.removes++;
    },
  };
  return { store, state, peek: () => rec };
}

function fakeCoKey() {
  let key: CryptoKey | null = null;
  const state = { generated: 0, deleted: 0 };
  const coKey: QuCoKey = {
    generate: async () => {
      key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
      state.generated++;
      return key;
    },
    get: async () => key,
    delete: async () => {
      key = null;
      state.deleted++;
    },
  };
  return { coKey, state, present: () => key !== null };
}

function makeEngine(over: Partial<QuDeps> = {}) {
  const s = fakeStore();
  const c = fakeCoKey();
  const clock = { now: 1_000_000_000_000 };
  const deps: QuDeps = {
    store: s.store,
    coKey: c.coKey,
    deriveKPin: (pin) => fakeDerive(pin),
    benchPinParams: async () => PIN_PARAMS,
    now: () => clock.now,
    randomBytes: (n) => crypto.getRandomValues(new Uint8Array(n)),
    ...over,
  };
  return { qu: new QuickUnlock(deps), s, c, clock, deps };
}

const enrollArgs = (over: Partial<Parameters<QuickUnlock["enroll"]>[0]> = {}) => ({
  uvk: UVK,
  userId: "user-A",
  email: "a@example.com",
  pin: "correct horse",
  lastFullUnlockAt: 1_000_000_000_000,
  autoLockSeconds: 900,
  ...over,
});

// ---------------------------------------------------------------- assertPinKdfParams (breaker A8)

test("assertPinKdfParams: at-floor and mid-range pass", () => {
  assert.doesNotThrow(() => assertPinKdfParams({ v: 1, alg: "argon2id13", ops: PIN_KDF_MIN_OPS, memBytes: PIN_KDF_MIN_MEM_BYTES }));
  assert.doesNotThrow(() => assertPinKdfParams({ v: 1, alg: "argon2id13", ops: 3, memBytes: 67_108_864 }));
});

test("assertPinKdfParams: below floor rejected (NOT the 64 MiB master floor — 32 MiB passes here)", () => {
  // The key distinction from assertServerKdfParams: 32 MiB is BELOW the master floor but AT the PIN
  // floor, so it must pass here and fail there. Guards against reusing the wrong assertion.
  assert.throws(
    () => assertPinKdfParams({ v: 1, alg: "argon2id13", ops: 1, memBytes: PIN_KDF_MIN_MEM_BYTES }),
    (e: unknown) => e instanceof PinKdfPolicyError && e.reason === "pin_kdf_below_floor",
  );
  assert.throws(
    () => assertPinKdfParams({ v: 1, alg: "argon2id13", ops: 2, memBytes: 16_777_216 }),
    (e: unknown) => e instanceof PinKdfPolicyError && e.reason === "pin_kdf_below_floor",
  );
});

test("assertPinKdfParams: above ceiling rejected (a planted 4 GiB would OOM the SW)", () => {
  assert.throws(
    () => assertPinKdfParams({ v: 1, alg: "argon2id13", ops: 3, memBytes: 4_294_967_296 }),
    (e: unknown) => e instanceof PinKdfPolicyError && e.reason === "pin_kdf_above_ceiling",
  );
  assert.throws(
    () => assertPinKdfParams({ v: 1, alg: "argon2id13", ops: PIN_KDF_MAX_OPS + 1, memBytes: PIN_KDF_MAX_MEM_BYTES }),
    (e: unknown) => e instanceof PinKdfPolicyError && e.reason === "pin_kdf_above_ceiling",
  );
});

test("assertPinKdfParams: omitted / non-finite ops or memBytes rejected (JS bypass guard)", () => {
  assert.throws(() => assertPinKdfParams({ v: 1, alg: "argon2id13" } as never), (e: unknown) => e instanceof PinKdfPolicyError);
  assert.throws(
    () => assertPinKdfParams({ v: 1, alg: "argon2id13", ops: NaN, memBytes: PIN_KDF_MIN_MEM_BYTES }),
    (e: unknown) => e instanceof PinKdfPolicyError,
  );
});

// ---------------------------------------------------------------- validatePin (breaker A2⊕B8)

test("validatePin: too short is rejected", () => {
  assert.deepEqual(validatePin("ab1"), { ok: false, reason: "too_short" });
  assert.deepEqual(validatePin("aB3x9"), { ok: false, reason: "too_short" });
});

test("validatePin: all-digit PINs need ≥10 digits (the numeric floor trips before the triviality check)", () => {
  assert.deepEqual(validatePin("482913"), { ok: false, reason: "digits_need_length" }); // 6-digit numeric — the classic weak PIN
  assert.deepEqual(validatePin("48291736"), { ok: false, reason: "digits_need_length" }); // 8 digits still too short
  assert.deepEqual(validatePin("111111"), { ok: false, reason: "digits_need_length" }); // a short numeric repeat trips the floor first
  assert.deepEqual(validatePin("4829173605"), { ok: true }); // 10 non-trivial digits OK
});

test("validatePin: a 6-8 char PIN with ≥1 non-digit is accepted", () => {
  assert.deepEqual(validatePin("48b913"), { ok: true }); // one letter lifts it out of the numeric floor
  assert.deepEqual(validatePin("hunter2"), { ok: true });
});

test("validatePin: trivial sequences and repeats are blocked (past the numeric floor)", () => {
  assert.deepEqual(validatePin("aaaaaa"), { ok: false, reason: "trivial" }); // letter repeat
  assert.deepEqual(validatePin("abcdef"), { ok: false, reason: "trivial" }); // ascending letter run
  assert.deepEqual(validatePin("fedcba"), { ok: false, reason: "trivial" }); // descending letter run
  assert.deepEqual(validatePin("1234567890"), { ok: false, reason: "trivial" }); // a 10-digit run is still trivial
  assert.deepEqual(validatePin("aaaaaaaaaa"), { ok: false, reason: "trivial" }); // a long repeat is still trivial
  // review F1 — period-k repeats a length/digit rule alone would otherwise admit:
  assert.deepEqual(validatePin("1212121212"), { ok: false, reason: "trivial" }); // 2 distinct digits, period-2
  assert.deepEqual(validatePin("6969696969"), { ok: false, reason: "trivial" }); // 2 distinct digits
  assert.deepEqual(validatePin("123412341234"), { ok: false, reason: "trivial" }); // exact period-4 digit block
  assert.deepEqual(validatePin("1234512345"), { ok: false, reason: "trivial" }); // exact period-5 digit block
  assert.deepEqual(validatePin("abcabc"), { ok: false, reason: "trivial" }); // exact period-3 letter block
  assert.deepEqual(validatePin("ababab"), { ok: false, reason: "trivial" }); // 2 distinct letters
  // and a genuinely strong PIN still passes (guards against an over-eager triviality rule):
  assert.deepEqual(validatePin("4829173605"), { ok: true });
  assert.deepEqual(validatePin("g7k2mq"), { ok: true });
});

// ---------------------------------------------------------------- double wrap (breaker A1, A6)

test("double-wrap round-trips through both layers (K_pin ⊕ non-extractable co-key)", async () => {
  const kNonExp = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  const kPin = sha256(utf8("a strong pin"));
  const ct = await sealDoubleWrap(kPin, kNonExp, UVK, "user-A");
  const back = await openDoubleWrap(kPin, kNonExp, ct, "user-A");
  assert.deepEqual([...back], [...UVK]);
});

test("wrong PIN, wrong co-key, and wrong userId all fail with no oracle (breaker A1/A6)", async () => {
  const kNonExp = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  const other = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  const ct = await sealDoubleWrap(sha256(utf8("real pin")), kNonExp, UVK, "user-A");
  await assert.rejects(openDoubleWrap(sha256(utf8("wrong pin")), kNonExp, ct, "user-A")); // wrong PIN → outer AEAD fails
  await assert.rejects(openDoubleWrap(sha256(utf8("real pin")), other, ct, "user-A")); // wrong co-key → inner AEAD fails
  await assert.rejects(openDoubleWrap(sha256(utf8("real pin")), kNonExp, ct, "user-B")); // wrong userId → AAD mismatch
});

test("a PIN-only wrap cannot open the double blob — the co-key is load-bearing (breaker A1)", async () => {
  // Prove the outer XChaCha layer alone does NOT yield the UVK: opening with just K_pin returns the
  // INNER ciphertext (iv‖aes-gcm), never the 32-byte UVK. An attacker who cracks the PIN still faces
  // the non-extractable co-key.
  const kNonExp = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  const kPin = sha256(utf8("crackable pin"));
  const ct = await sealDoubleWrap(kPin, kNonExp, UVK, "user-A");
  const innerBlob = open(kPin, (await import("./crypto.ts")).fromB64(ct), adQuickUnlock("user-A"));
  assert.notDeepEqual([...innerBlob], [...UVK]);
  assert.equal(innerBlob.length, 12 + 32 + 16); // iv(12) ‖ aes-gcm ct+tag(48) — NOT the bare UVK
});

// ---------------------------------------------------------------- enroll → redeem round trip

test("enroll then beginRedeem with the correct PIN recovers the UVK + stashed tokens", async () => {
  const { qu, s } = makeEngine();
  assert.deepEqual(await qu.enroll(enrollArgs()), { ok: true });
  // Arm (simulate doLock stashing tokens):
  assert.equal(await qu.arm({ access: "acc-1", refresh: "ref-1" }), "armed");
  const r = await qu.beginRedeem("correct horse");
  assert.ok(r.ok);
  if (r.ok) {
    assert.deepEqual([...r.uvk], [...UVK]);
    assert.deepEqual(r.tokens, { access: "acc-1", refresh: "ref-1" });
    assert.equal(r.userId, "user-A");
  }
  // A verified success resets the counter to 5 and clears the token stash (completeRedeem):
  await qu.completeRedeem(900);
  const rec = s.peek()!;
  assert.equal(rec.attemptsRemaining, MAX_PIN_ATTEMPTS);
  assert.equal(rec.lockedTokens, null);
  assert.ok(rec.blob, "the blob survives so the next lock re-arms");
});

test("enroll refuses a weak PIN and writes NOTHING", async () => {
  const { qu, s, c } = makeEngine();
  assert.deepEqual(await qu.enroll(enrollArgs({ pin: "abcdef" })), { ok: false, code: "weak_pin", reason: "trivial" });
  assert.equal(s.peek(), null);
  assert.equal(c.state.generated, 0, "no co-key minted for a rejected enroll");
});

// ------------------------------------------------ attempt reservation + no-oracle (breaker A5⊕B4)

test("a wrong PIN decrements the persisted counter and returns a generic wrong_pin", async () => {
  const { qu, s } = makeEngine();
  await qu.enroll(enrollArgs());
  await qu.arm({ access: "a", refresh: "r" });
  const r1 = await qu.beginRedeem("nope nope");
  assert.deepEqual(r1, { ok: false, code: "wrong_pin", attemptsRemaining: 4 });
  assert.equal(s.peek()!.attemptsRemaining, 4, "the decrement is persisted");
  const r2 = await qu.beginRedeem("still wrong");
  assert.deepEqual(r2, { ok: false, code: "wrong_pin", attemptsRemaining: 3 });
});

test("the attempt is RESERVED before the AEAD attempt — an eviction mid-derive cannot gift a guess", async () => {
  // deriveKPin throws (simulating SW death / worker failure between the reservation and the open) —
  // but ONLY during the redeem (enroll needs a working derive to seal). The counter must already be
  // decremented + persisted at derive time, so the freed attempt is NOT recovered.
  const ctl = { throwDerive: false, observed: -1 };
  let store: ReturnType<typeof fakeStore>;
  const { qu, s } = makeEngine({
    deriveKPin: (pin) => {
      if (ctl.throwDerive) {
        ctl.observed = store.peek()?.attemptsRemaining ?? -99; // what the store holds at derive time
        return Promise.reject(new Error("worker died"));
      }
      return fakeDerive(pin);
    },
  });
  store = s;
  await qu.enroll(enrollArgs());
  await qu.arm({ access: "a", refresh: "r" });
  ctl.throwDerive = true;
  await assert.rejects(qu.beginRedeem("some pin"));
  assert.equal(ctl.observed, 4, "the decrement was persisted BEFORE the derive/open ran");
  assert.equal(s.peek()!.attemptsRemaining, 4, "and it stays spent after the throw");
});

test("exhausting all 5 attempts wipes the blob AND the co-key (zero residue)", async () => {
  const { qu, s, c } = makeEngine();
  await qu.enroll(enrollArgs());
  await qu.arm({ access: "a", refresh: "r" });
  for (let i = 0; i < MAX_PIN_ATTEMPTS - 1; i++) assert.equal((await qu.beginRedeem("wrong")).ok, false);
  assert.equal(s.peek()!.attemptsRemaining, 1);
  const last = await qu.beginRedeem("wrong");
  assert.deepEqual(last, { ok: false, code: "exhausted" });
  assert.equal(s.peek(), null, "record removed");
  assert.equal(c.present(), false, "co-key deleted");
  assert.ok(c.state.deleted >= 1);
});

test("a correct PIN on the LAST attempt still succeeds (reservation reaches 0, open verifies)", async () => {
  const { qu } = makeEngine();
  await qu.enroll(enrollArgs());
  await qu.arm({ access: "a", refresh: "r" });
  for (let i = 0; i < MAX_PIN_ATTEMPTS - 1; i++) await qu.beginRedeem("wrong");
  const r = await qu.beginRedeem("correct horse");
  assert.ok(r.ok, "the last reserved attempt, when correct, unlocks");
});

test("a verified open resets the brute-force budget immediately (a correct PIN never burns attempts)", async () => {
  const { qu, s } = makeEngine();
  await qu.enroll(enrollArgs());
  await qu.arm({ access: "a", refresh: "r" });
  await qu.beginRedeem("wrong 1");
  await qu.beginRedeem("wrong 2");
  assert.equal(s.peek()!.attemptsRemaining, 3, "two wrong attempts spent");
  const r = await qu.beginRedeem("correct horse");
  assert.ok(r.ok);
  assert.equal(s.peek()!.attemptsRemaining, MAX_PIN_ATTEMPTS, "the verified open reset the budget to full");
});

// ---------------------------------------------------------------- wipe leaves zero residue

test("wipe removes the record slot directly AND deletes the co-key", async () => {
  const { qu, s, c } = makeEngine();
  await qu.enroll(enrollArgs());
  assert.ok(s.peek());
  assert.ok(c.present());
  await qu.wipe();
  assert.equal(s.peek(), null);
  assert.equal(c.present(), false);
  assert.ok(s.state.removes >= 1, "storage.session.remove was called directly, not via a persist");
});

// ---------------------------------------------------------------- stamp freshness (24 h rule)

test("beginRedeem past 24 h since the full unlock requires the master password, blob KEPT", async () => {
  const { qu, s, clock } = makeEngine();
  await qu.enroll(enrollArgs({ lastFullUnlockAt: clock.now }));
  await qu.arm({ access: "a", refresh: "r" });
  clock.now += QU_MAX_AGE_MS + 1; // just past the window
  assert.deepEqual(await qu.beginRedeem("correct horse"), { ok: false, code: "expired" });
  assert.ok(s.peek(), "the blob is retained — a fresh full unlock re-stamps");
});

test("a future lastFullUnlockAt stamp fails closed at both arm() and beginRedeem() (clock tamper)", async () => {
  const { qu, s, clock } = makeEngine();
  await qu.enroll(enrollArgs({ lastFullUnlockAt: clock.now }));
  // arm() refuses a future-stamped blob outright — tokens are never even retained.
  const rec0 = s.peek()!;
  rec0.blob.lastFullUnlockAt = clock.now + 60_000;
  await s.store.write(rec0);
  assert.equal(await qu.arm({ access: "a", refresh: "r" }), "declined");
  // And if a blob is somehow armed then its stamp is pushed to the future, beginRedeem fails closed.
  rec0.blob.lastFullUnlockAt = clock.now;
  rec0.lockedTokens = { access: "a", refresh: "r" };
  await s.store.write(rec0);
  const armed = s.peek()!;
  armed.blob.lastFullUnlockAt = clock.now + 60_000;
  await s.store.write(armed);
  assert.deepEqual(await qu.beginRedeem("correct horse"), { ok: false, code: "expired" });
});

// ---------------------------------------------------------------- arm() verdicts (breaker B3)

test("arm returns not-enrolled when there is no blob (caller stays byte-identical)", async () => {
  const { qu } = makeEngine();
  assert.equal(await qu.arm({ access: "a", refresh: "r" }), "not-enrolled");
});

test("arm declines an exhausted or stale blob, and FAILS CLOSED (declined) when the read throws", async () => {
  const { qu, s } = makeEngine();
  await qu.enroll(enrollArgs());
  // exhaust:
  const rec = s.peek()!;
  rec.attemptsRemaining = 0;
  await s.store.write(rec);
  assert.equal(await qu.arm({ access: "a", refresh: "r" }), "declined");
  // read throws → fail closed:
  s.state.throwOnRead = true;
  assert.equal(await qu.arm({ access: "a", refresh: "r" }), "declined");
});

test("arm on a fresh enrolled blob stashes the tokens and reports armed", async () => {
  const { qu, s } = makeEngine();
  await qu.enroll(enrollArgs());
  assert.equal(await qu.arm({ access: "acc", refresh: null }), "armed");
  assert.deepEqual(s.peek()!.lockedTokens, { access: "acc", refresh: null });
});

// ---------------------------------------------------------------- per-userId reconcile (breaker A6)

test("reconcileUser wipes a blob owned by a different user (account switch)", async () => {
  const { qu, s, c } = makeEngine();
  await qu.enroll(enrollArgs({ userId: "user-A" }));
  await qu.reconcileUser("user-A"); // same user → kept
  assert.ok(s.peek());
  await qu.reconcileUser("user-B"); // different user → wiped
  assert.equal(s.peek(), null);
  assert.equal(c.present(), false);
});

test("onFullUnlock re-stamps the same-user window + refreshes the budget, and wipes a different user", async () => {
  const { qu, s, c, clock } = makeEngine();
  await qu.enroll(enrollArgs({ userId: "user-A", lastFullUnlockAt: clock.now }));
  await qu.arm({ access: "a", refresh: "r" });
  await qu.beginRedeem("wrong"); // spend an attempt → 4
  assert.equal(s.peek()!.attemptsRemaining, 4);
  // A same-user full unlock 20 h later re-stamps the window and resets the counter:
  clock.now += 20 * 60 * 60 * 1000;
  await qu.onFullUnlock("user-A", clock.now);
  assert.equal(s.peek()!.blob.lastFullUnlockAt, clock.now, "the 24 h window re-stamped to the fresh full unlock");
  assert.equal(s.peek()!.attemptsRemaining, MAX_PIN_ATTEMPTS, "budget refreshed by the master-password proof");
  // Now redeem is fresh again even though enroll was >24 h before this moment:
  clock.now += 60_000;
  const r = await qu.beginRedeem("correct horse");
  assert.ok(r.ok, "the re-stamp kept quick unlock alive past the original enroll window");
  // A different-user full unlock wipes it (account switch):
  await qu.onFullUnlock("user-B", clock.now);
  assert.equal(s.peek(), null);
  assert.equal(c.present(), false);
});

// ---------------------------------------------------------------- corrupt-params + missing co-key → wipe

test("a blob carrying sub-floor pinParams is treated as corrupt → wiped, never derived under", async () => {
  const { qu, s, c } = makeEngine();
  await qu.enroll(enrollArgs());
  await qu.arm({ access: "a", refresh: "r" });
  const rec = s.peek()!;
  rec.blob.kdfParams = { v: 1, alg: "argon2id13", ops: 1, memBytes: 1024 }; // planted weak params
  await s.store.write(rec);
  assert.deepEqual(await qu.beginRedeem("correct horse"), { ok: false, code: "corrupt" });
  assert.equal(s.peek(), null, "corrupt blob wiped");
  assert.equal(c.present(), false);
});

test("beginRedeem returns not_armed when the token stash is absent (unlocked-armed / never locked)", async () => {
  const { qu } = makeEngine();
  await qu.enroll(enrollArgs()); // enrolled but NOT armed (lockedTokens === null)
  assert.deepEqual(await qu.beginRedeem("correct horse"), { ok: false, code: "not_armed" });
});

test("a redeem whose co-key vanished is corrupt → wiped (orphaned blob)", async () => {
  const { qu, s, c } = makeEngine();
  await qu.enroll(enrollArgs());
  await qu.arm({ access: "a", refresh: "r" });
  await c.coKey.delete(); // co-key gone but the record somehow survived
  assert.deepEqual(await qu.beginRedeem("correct horse"), { ok: false, code: "corrupt" });
  assert.equal(s.peek(), null);
});

// ---------------------------------------------------------------- status (drives the popup)

test("status reflects enrolled / armed / attempts across the lifecycle", async () => {
  const { qu } = makeEngine();
  assert.deepEqual(await qu.status(), { enrolled: false, armed: false, attemptsRemaining: 0, kind: null });
  await qu.enroll(enrollArgs());
  assert.deepEqual(await qu.status(), { enrolled: true, armed: false, attemptsRemaining: 5, kind: "pin" }); // unlocked-armed: not redeemable yet
  await qu.arm({ access: "a", refresh: "r" });
  assert.deepEqual(await qu.status(), { enrolled: true, armed: true, attemptsRemaining: 5, kind: "pin" }); // locked-armed: redeemable
});

// ---------------------------------------------------------------- biometric method (0.17.0)

// A deterministic PRF stand-in: evalPrf(credId, salt) = SHA-256(credId ‖ salt) — stable per (cred,salt)
// like the real WebAuthn PRF, so the redeem re-derives the same K_bio and the AEAD opens.
function fakeBiometric(over: Partial<{ prfEnabled: boolean; enrollThrows: boolean; evalThrows: boolean }> = {}) {
  const state = { enrolls: 0, evals: 0, prfEnabled: true, enrollThrows: false, evalThrows: false, ...over };
  const bio = {
    enroll: async (_salt: Uint8Array) => {
      state.enrolls++;
      if (state.enrollThrows) throw new Error("NotAllowedError");
      return { credentialId: "cred-1", prfEnabled: state.prfEnabled };
    },
    evalPrf: async (credentialId: string, salt: Uint8Array) => {
      state.evals++;
      if (state.evalThrows) throw new Error("NotAllowedError");
      return sha256(new Uint8Array([...new TextEncoder().encode(credentialId), ...salt]));
    },
  };
  return { bio, state };
}
const bioArgs = () => ({ uvk: UVK, userId: "user-A", email: "a@example.com", lastFullUnlockAt: 1_000_000_000_000, autoLockSeconds: 900 });

test("bio: enrollBio → arm → beginRedeemBio round-trips the UVK, and the attempt counter never moves", async () => {
  const { bio } = fakeBiometric();
  const { qu, s } = makeEngine({ biometric: bio });
  assert.deepEqual(await qu.enrollBio(bioArgs()), { ok: true });
  assert.equal((await qu.status()).kind, "biometric");
  await qu.arm({ access: "a", refresh: "r" });
  for (let i = 0; i < 3; i++) {
    const r = await qu.beginRedeemBio();
    assert.ok(r.ok, `redeem ${i}`);
    if (r.ok) assert.deepEqual(r.uvk, UVK);
    assert.equal(s.peek()!.attemptsRemaining, 5, "bio redeem never decrements the counter");
  }
});

test("bio: a cancelled ceremony (evalPrf throws) → bio_cancelled, record UNTOUCHED, a later retry works", async () => {
  const fb = fakeBiometric();
  const { qu, s } = makeEngine({ biometric: fb.bio });
  await qu.enrollBio(bioArgs());
  await qu.arm({ access: "a", refresh: "r" });
  fb.state.evalThrows = true;
  assert.deepEqual(await qu.beginRedeemBio(), { ok: false, code: "bio_cancelled" });
  assert.ok(s.peek(), "record kept after a cancel");
  assert.notEqual(s.peek()!.lockedTokens, null, "still armed after a cancel");
  fb.state.evalThrows = false;
  assert.ok((await qu.beginRedeemBio()).ok, "retry succeeds");
});

test("bio: enrollBio amendment 3 — a ceremony failure leaves the PRIOR record intact (ceremonies BEFORE wipe)", async () => {
  const fb = fakeBiometric({ evalThrows: true });
  const { qu, s, c } = makeEngine({ biometric: fb.bio });
  await qu.enroll(enrollArgs()); // an existing PIN quick-unlock
  const before = s.peek();
  assert.deepEqual(await qu.enrollBio(bioArgs()), { ok: false, code: "bio_cancelled" });
  assert.equal((s.peek() as QuRecord).blob.ct, (before as QuRecord).blob.ct, "prior PIN blob untouched");
  assert.equal((await qu.status()).kind, "pin", "still the PIN method");
  assert.ok(c.present(), "prior co-key not wiped by a failed bio enroll");
});

test("bio: enrollBio on a platform without PRF → bio_unsupported, nothing written", async () => {
  const { bio } = fakeBiometric({ prfEnabled: false });
  const { qu, s } = makeEngine({ biometric: bio });
  assert.deepEqual(await qu.enrollBio(bioArgs()), { ok: false, code: "bio_unsupported" });
  assert.equal(s.peek(), null);
});

test("bio: no biometric dep → enrollBio bio_unsupported, beginRedeemBio not_armed", async () => {
  const { qu } = makeEngine(); // no biometric injected
  assert.deepEqual(await qu.enrollBio(bioArgs()), { ok: false, code: "bio_unsupported" });
  assert.deepEqual(await qu.beginRedeemBio(), { ok: false, code: "not_armed" });
});

test("amendment 1: a bio blob routed to the PIN lane → corrupt + WIPED (no uncaught assertPinKdfParams throw)", async () => {
  const { bio } = fakeBiometric();
  const { qu, s } = makeEngine({ biometric: bio });
  await qu.enrollBio(bioArgs());
  await qu.arm({ access: "a", refresh: "r" });
  assert.deepEqual(await qu.beginRedeem("any pin"), { ok: false, code: "corrupt" });
  assert.equal(s.peek(), null, "wiped");
});

test("amendment 1: a kind-STRIPPED bio blob (narrows to pin, no salt/kdfParams) → corrupt + wiped, no throw", async () => {
  const { bio } = fakeBiometric();
  const { qu, s } = makeEngine({ biometric: bio });
  await qu.enrollBio(bioArgs());
  await qu.arm({ access: "a", refresh: "r" });
  delete (s.peek()!.blob as { kind?: string }).kind; // the storage-writer A8 attacker strips the discriminant
  assert.deepEqual(await qu.beginRedeem("any pin"), { ok: false, code: "corrupt" });
  assert.equal(s.peek(), null, "wiped, not an uncaught TypeError");
});

test("cross-kind: a PIN blob relabelled kind:'biometric' can't be opened by beginRedeemBio → corrupt + wiped", async () => {
  const { bio } = fakeBiometric();
  const { qu, s } = makeEngine({ biometric: bio });
  await qu.enroll(enrollArgs());
  await qu.arm({ access: "a", refresh: "r" });
  const b = s.peek()!.blob as Record<string, unknown>; // transplant the discriminant + fake bio fields
  b.kind = "biometric";
  b.credentialId = "cred-1";
  b.prfSalt = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; // 32 b64url bytes
  assert.deepEqual(await qu.beginRedeemBio(), { ok: false, code: "corrupt" });
  assert.equal(s.peek(), null, "the transplant fails-closed to corrupt+wipe (wrong key + bio AAD)");
});
