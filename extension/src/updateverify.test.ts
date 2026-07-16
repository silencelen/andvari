// Runs under Node's built-in runner (node --test); type-stripped natively (Node 22.18+).
// Excluded from tsc (tsconfig `exclude`) because it imports node:test, which the extension's
// chrome-only lib set does not type. `npm test` in extension/ runs this.
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import nacl from "tweetnacl";
import {
  evaluateSignedManifest,
  PINNED_UPDATE_KEYS,
  TEST_PUBKEY,
  updatesEnabled,
  UPDATE_MAX_SIGNED_AGE_MS,
  verifyManifest,
} from "./updateverify.ts";

// base64url (extension wire encoding) — mirrors crypto.ts toB64, kept local so this test carries
// no crypto import beyond tweetnacl.
const toB64 = (u: Uint8Array): string => {
  let s = "";
  for (const b of u) s += String.fromCharCode(b);
  return Buffer.from(s, "binary").toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};

// A locally-minted signer standing in for the owner's workstation key. verify tests pin its pubkey.
const kp = nacl.sign.keyPair();
const PINNED_LOCAL = [toB64(kp.publicKey)];
const sign = (raw: Uint8Array): string => toB64(nacl.sign.detached(raw, kp.secretKey));
const bytes = (o: unknown): Uint8Array => new TextEncoder().encode(JSON.stringify(o));

const freshManifest = (over: Record<string, unknown> = {}) => ({
  seq: 42,
  signedAt: new Date().toISOString(),
  browserExtension: { version: "9.9.9", chromeUrl: "/downloads/ext-chrome.zip", firefoxUrl: "/downloads/ext-firefox.zip" },
  ...over,
});

test("PINNED_UPDATE_KEYS + TEST_PUBKEY are byte-single-sourced to core UpdateVerify.kt (§M-D7)", () => {
  const kt = readFileSync(
    fileURLToPath(new URL("../../core/src/commonMain/kotlin/io/silencelen/andvari/core/client/UpdateVerify.kt", import.meta.url)),
    "utf-8",
  );
  // TEST_PUBKEY sentinel parity.
  const ktTest = /TEST_PUBKEY\s*=\s*"([^"]+)"/.exec(kt);
  assert.ok(ktTest, "core TEST_PUBKEY literal not found");
  assert.equal(TEST_PUBKEY, ktTest[1], "extension TEST_PUBKEY must equal the Kotlin sentinel");
  // PINNED set parity — every entry inside the Kotlin listOf(...) must appear here, in order.
  // Entries are either base64url string LITERALS (an armed build) or the bare TEST_PUBKEY symbol
  // (the UN-ARMED shipped default since the 2026-07-15 multi-tenant pivot, design §9) — the symbol
  // maps to the sentinel value already proven byte-equal above, so the lock stays meaningful:
  // both sides pin the exact same sentinel.
  const ktPinnedBlock = /val PINNED[^=]*=\s*listOf\(([^)]*)\)/.exec(kt);
  assert.ok(ktPinnedBlock, "core PINNED listOf(...) not found");
  const ktKeys = [...ktPinnedBlock[1].matchAll(/"([^"]+)"|(\bTEST_PUBKEY\b)/g)].map((m) => m[1] ?? TEST_PUBKEY);
  assert.ok(ktKeys.length > 0, "core PINNED must pin at least one entry (sentinel or real)");
  assert.deepEqual([...PINNED_UPDATE_KEYS], ktKeys, "extension pinned key SET must byte-equal Kotlin UpdateVerify.PINNED");
});

test("updatesEnabled — sentinel-only is disabled, a real key enables (§M-D3)", () => {
  assert.equal(updatesEnabled([TEST_PUBKEY]), false);
  assert.equal(updatesEnabled(PINNED_LOCAL), true);
  // Shipped default is UN-ARMED (placeholder-pinned) for the multi-tenant pivot (design 2026-07-15
  // §9) — fail-closed-quiet: the SW never fetches the manifest, /downloads stays plain pull.
  assert.equal(updatesEnabled(), false);
});

test("verifyManifest — a valid detached sig over the EXACT bytes verifies", () => {
  const raw = bytes(freshManifest());
  assert.equal(verifyManifest(raw, nacl.sign.detached(raw, kp.secretKey), PINNED_LOCAL), true);
});

test("verifyManifest — tampered bytes are rejected (§M-D6)", () => {
  const raw = bytes(freshManifest());
  const sig = nacl.sign.detached(raw, kp.secretKey);
  const tampered = raw.slice();
  tampered[5] ^= 0x01;
  assert.equal(verifyManifest(tampered, sig, PINNED_LOCAL), false);
});

test("verifyManifest — wrong-size sig/pubkey fail closed (never throw)", () => {
  const raw = bytes(freshManifest());
  assert.equal(verifyManifest(raw, new Uint8Array(63), PINNED_LOCAL), false); // short sig
  assert.equal(verifyManifest(raw, nacl.sign.detached(raw, kp.secretKey), [toB64(new Uint8Array(31))]), false); // short key
  assert.equal(verifyManifest(raw, nacl.sign.detached(raw, kp.secretKey), [TEST_PUBKEY]), false); // §M-D3 disabled
});

test("evaluateSignedManifest — valid sig accepted, fields surfaced", () => {
  const m = freshManifest();
  const raw = bytes(m);
  const d = evaluateSignedManifest(raw, sign(raw), { pinned: PINNED_LOCAL, lastAcceptedSeq: 0, now: Date.now() });
  assert.equal(d.kind, "accepted");
  if (d.kind === "accepted") {
    assert.equal(d.seq, 42);
    assert.equal((d.ext as { version?: unknown }).version, "9.9.9");
  }
});

test("evaluateSignedManifest — missing .sig fails closed QUIET (unverified)", () => {
  const raw = bytes(freshManifest());
  const d = evaluateSignedManifest(raw, null, { pinned: PINNED_LOCAL, lastAcceptedSeq: 0, now: Date.now() });
  assert.deepEqual(d, { kind: "quiet", reason: "unverified" });
});

test("evaluateSignedManifest — a sig from a NON-pinned key fails closed", () => {
  const other = nacl.sign.keyPair();
  const raw = bytes(freshManifest());
  const sig = toB64(nacl.sign.detached(raw, other.secretKey));
  const d = evaluateSignedManifest(raw, sig, { pinned: PINNED_LOCAL, lastAcceptedSeq: 0, now: Date.now() });
  assert.deepEqual(d, { kind: "quiet", reason: "unverified" });
});

test("evaluateSignedManifest — a validly-signed body is NOT parsed until verify passes", () => {
  // Sign body A, then present body B (different bytes) with A's sig → the B parse must never run.
  const rawA = bytes(freshManifest({ seq: 100 }));
  const sigA = sign(rawA);
  const rawB = bytes(freshManifest({ seq: 101 }));
  const d = evaluateSignedManifest(rawB, sigA, { pinned: PINNED_LOCAL, lastAcceptedSeq: 0, now: Date.now() });
  assert.deepEqual(d, { kind: "quiet", reason: "unverified" });
});

test("evaluateSignedManifest — seq regression rejected (§B anti-rollback)", () => {
  const older = freshManifest({ seq: 41 }); // a validly-signed OLD manifest replayed
  const raw = bytes(older);
  const d = evaluateSignedManifest(raw, sign(raw), { pinned: PINNED_LOCAL, lastAcceptedSeq: 42, now: Date.now() });
  assert.deepEqual(d, { kind: "quiet", reason: "seq_regression" });
});

test("evaluateSignedManifest — equal seq is benign (no NEW offer, quiet)", () => {
  const same = freshManifest({ seq: 42 });
  const raw = bytes(same);
  const d = evaluateSignedManifest(raw, sign(raw), { pinned: PINNED_LOCAL, lastAcceptedSeq: 42, now: Date.now() });
  assert.deepEqual(d, { kind: "quiet", reason: "seq_regression" });
});

test("evaluateSignedManifest — a signedAt older than the window is quiet-stale (§M-D4b)", () => {
  const stale = freshManifest({ signedAt: new Date(Date.now() - UPDATE_MAX_SIGNED_AGE_MS - 60_000).toISOString() });
  const raw = bytes(stale);
  const d = evaluateSignedManifest(raw, sign(raw), { pinned: PINNED_LOCAL, lastAcceptedSeq: 0, now: Date.now() });
  assert.deepEqual(d, { kind: "quiet", reason: "stale" });
});

test("evaluateSignedManifest — a non-integer seq is malformed (post-verify parse guard)", () => {
  const bad = freshManifest({ seq: "42" });
  const raw = bytes(bad);
  const d = evaluateSignedManifest(raw, sign(raw), { pinned: PINNED_LOCAL, lastAcceptedSeq: 0, now: Date.now() });
  assert.deepEqual(d, { kind: "quiet", reason: "malformed" });
});
