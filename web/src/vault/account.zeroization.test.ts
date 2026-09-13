import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import type { AccountKeys, RecoveryVerifyResponse } from "../api/types";
import { adIdkey, adRecovery, adUvk } from "../crypto/ad";
import type { KdfParams } from "../crypto/keys";
import { initSodium } from "../crypto/sodium";
import { Account } from "./account";

/**
 * Audit H80 (spec 01 §2 "Zeroization", the web twin of core AccountZeroizationTest): MK, authKey,
 * wrapKey and the identity seed are dead the moment their consumers return, and Account `fill(0)`s
 * them. Zeroization of a LOCAL is invisible from outside — so this suite wraps the primitive layer
 * (`../crypto/provider`, the one module keys.ts, envelope.ts and member-recovery.ts all reach the
 * cipher through) with a transparent recorder that keeps the LIVE array references as they pass:
 * the MK is argon2id's own output array, the wrapKey is the `key` handed to the UVK-envelope
 * seal/open, the identity seed is boxKeypairFromSeed's input, the recovered UVK is the recovery
 * envelope open's output. Each is captured with a snapshot of its bytes at that moment, and the
 * test asserts afterwards that the live array is all zeros while the snapshot proves it once was
 * not. The UVK the returned Account keeps for the session is asserted NOT wiped, so the wipe is
 * proven targeted rather than blanket.
 */

interface Seen {
  live: Uint8Array;
  at: Uint8Array;
}

// vi.mock factories are hoisted above the imports, so the recorder they write into must be too.
const rec = vi.hoisted(() => ({
  argon: [] as { live: Uint8Array; at: Uint8Array }[], // MK outputs
  seeds: [] as { live: Uint8Array; at: Uint8Array }[], // identity seeds (keypair input)
  aeadKeys: [] as { ad: Uint8Array; seen: { live: Uint8Array; at: Uint8Array } }[], // (ad, key) per seal/open
  opened: [] as { ad: Uint8Array; seen: { live: Uint8Array; at: Uint8Array } }[], // (ad, plaintext) per open
  reset() {
    this.argon.length = 0;
    this.seeds.length = 0;
    this.aeadKeys.length = 0;
    this.opened.length = 0;
  },
}));

vi.mock("../crypto/provider", async (importOriginal) => {
  const real = await importOriginal<typeof import("../crypto/provider")>();
  const seen = (a: Uint8Array) => ({ live: a, at: a.slice() });
  return {
    ...real,
    argon2id: (...args: Parameters<typeof real.argon2id>) => {
      const out = real.argon2id(...args);
      rec.argon.push(seen(out));
      return out;
    },
    boxKeypairFromSeed: (seed: Uint8Array) => {
      rec.seeds.push(seen(seed));
      return real.boxKeypairFromSeed(seed);
    },
    aeadEncrypt: (key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array, ad: Uint8Array) => {
      rec.aeadKeys.push({ ad: ad.slice(), seen: seen(key) });
      return real.aeadEncrypt(key, nonce, plaintext, ad);
    },
    aeadDecrypt: (key: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array, ad: Uint8Array) => {
      rec.aeadKeys.push({ ad: ad.slice(), seen: seen(key) });
      const out = real.aeadDecrypt(key, nonce, ciphertext, ad);
      rec.opened.push({ ad: ad.slice(), seen: seen(out) });
      return out;
    },
  };
});

const same = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);
const single = <T>(xs: T[], what: string): T => {
  if (xs.length !== 1) throw new Error(`expected exactly one ${what}, saw ${xs.length}`);
  return xs[0] as T;
};
const keyFor = (ad: Uint8Array): Seen => single(rec.aeadKeys.filter((k) => same(k.ad, ad)), `AEAD key for that AD`).seen;
const openedFor = (ad: Uint8Array): Seen => single(rec.opened.filter((k) => same(k.ad, ad)), `AEAD open for that AD`).seen;

function assertWiped(s: Seen, what: string) {
  expect(s.at.some((b) => b !== 0), `${what} was already all-zero when captured — nothing to prove`).toBe(true);
  expect(s.live.every((b) => b === 0), `${what} was not zeroed after use`).toBe(true);
}

function assertKept(s: Seen, what: string) {
  expect(same(s.live, s.at), `${what} must survive — the session owns it`).toBe(true);
  expect(s.live.every((b) => b === 0), `${what} is unexpectedly zero`).toBe(false);
}

const KDF: KdfParams = { v: 1, alg: "argon2id13", ops: 1, memBytes: 8192 }; // test-speed argon2id
const PASSWORD = "correct horse battery staple";

type Enrolled = Awaited<ReturnType<typeof Account.enroll>>;
const enroll = () => Account.enroll({ inviteToken: "inv", email: "a@x.com", displayName: "a", password: PASSWORD, kdfParams: KDF });
const keysOf = (r: Enrolled): AccountKeys => ({
  kdfSalt: r.request.kdfSalt,
  kdfParams: r.request.kdfParams,
  wrappedUvk: r.request.wrappedUvk,
  encryptedIdentitySeed: r.request.encryptedIdentitySeed,
  identityPub: r.request.identityPub,
  escrowFingerprint: "",
});

describe("Account zeroization (audit H80, spec 01 §2)", () => {
  beforeAll(async () => {
    await initSodium();
  });
  beforeEach(() => rec.reset());

  it("enroll wipes the MK, wrapKey and identity seed and keeps the UVK", async () => {
    const r = await enroll();
    const userId = r.request.userId;
    expect(rec.argon.length, "enroll derives exactly one MK").toBe(1);
    assertWiped(single(rec.argon, "MK"), "MK");
    assertWiped(keyFor(adUvk(userId)), "wrapKey (the UVK-envelope key)");
    assertWiped(single(rec.seeds, "identity seed"), "identity seed");
    // The UVK is the key that sealed the identity seed — the Account owns it; NOT wiped.
    assertKept(keyFor(adIdkey(userId)), "UVK");
  });

  it("unlock wipes the MK, wrapKey and identity seed and keeps the UVK", async () => {
    const r = await enroll();
    rec.reset();
    await Account.unlock(r.request.userId, PASSWORD, keysOf(r));
    expect(rec.argon.length, "unlock derives exactly one MK").toBe(1);
    assertWiped(single(rec.argon, "MK"), "MK");
    assertWiped(keyFor(adUvk(r.request.userId)), "wrapKey");
    assertWiped(single(rec.seeds, "identity seed"), "identity seed");
    // The UVK came out of the wrappedUvk open and now belongs to the Account — kept.
    assertKept(openedFor(adUvk(r.request.userId)), "UVK");
  });

  it("a wrong password still wipes the MK and wrapKey", async () => {
    const r = await enroll();
    rec.reset();
    await expect(Account.unlock(r.request.userId, "not the password", keysOf(r))).rejects.toThrow(/wrong master password/);
    assertWiped(single(rec.argon, "MK (failed unlock)"), "MK (failed unlock)");
    assertWiped(keyFor(adUvk(r.request.userId)), "wrapKey (failed unlock)");
  });

  it("deriveAuthKey wipes the MK and still returns the intact credential", async () => {
    const r = await enroll();
    rec.reset();
    const b64 = await Account.deriveAuthKey(PASSWORD, r.request.kdfSalt, r.request.kdfParams);
    expect(b64).toBe(r.request.authKey); // the encoded credential is intact…
    assertWiped(single(rec.argon, "MK"), "MK"); // …and the MK that produced it is gone.
  });

  it("buildPasswordChange wipes the new MK and wrapKey and keeps the session's UVK", async () => {
    const r = await enroll();
    rec.reset();
    const change = await r.account.buildPasswordChange("a brand new master password", KDF);
    expect(change.newWrappedUvk.length).toBeGreaterThan(0);
    assertWiped(single(rec.argon, "new MK"), "new MK");
    assertWiped(keyFor(adUvk(r.request.userId)), "new wrapKey");
    // The change re-wraps the SAME UVK the session goes on using — it must still unlock items.
    await expect(Account.unlock(r.request.userId, "a brand new master password", { ...keysOf(r), kdfSalt: change.newKdfSalt, kdfParams: change.newKdfParams, wrappedUvk: change.newWrappedUvk })).resolves.toBeInstanceOf(Account);
  });

  it("recover wipes the new MK, new wrapKey, identity seed AND the recovered UVK", async () => {
    const r = await enroll();
    const userId = r.request.userId;
    const verify: RecoveryVerifyResponse = {
      userId,
      recoveryTicket: "opaque-ticket",
      recoveryWrappedUvk: r.request.memberRecovery.recoveryWrappedUvk,
      encryptedIdentitySeed: r.request.encryptedIdentitySeed,
      identityPub: r.request.identityPub,
    };
    rec.reset();
    const commit = await Account.recover({ recoverySecret: r.recoverySecret, verify, newPassword: "a brand new master password", newKdfParams: KDF });
    expect(commit.newWrappedUvk.length).toBeGreaterThan(0); // the body is built before anything is wiped
    expect(rec.argon.length, "recover derives exactly one (new) MK").toBe(1);
    assertWiped(single(rec.argon, "new MK"), "new MK");
    assertWiped(keyFor(adUvk(userId)), "new wrapKey");
    assertWiped(single(rec.seeds, "identity seed"), "identity seed (hard-fail probe)");
    // recover() returns a commit body, not a session: the recovered UVK is dead too.
    assertWiped(openedFor(adRecovery(userId)), "recovered UVK");
  });
});
