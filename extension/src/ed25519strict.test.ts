// Hostile signatures the extension's verifier must refuse the way libsodium (the Kotlin and web engines) does, though
// tweetnacl 1.0.3 alone accepts them (statement.ts signatureValid): a non-reduced S (S + L), small-order public keys
// (the identity point forges for anyone; the all-zero key), small-order or non-canonical R. And a negated key -A,
// which is a legitimate key of its own: byte comparison of signer keys keeps it apart from A.
// The Edwards arithmetic here (BigInt, affine) exists only to construct inputs and to check the blocklist.
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import nacl from "tweetnacl";
import { sha512 } from "@noble/hashes/sha2.js";
import { b64Encode, b64Strict, MAGIC, pointAcceptable, scalarReduced, signatureValid, signedMessage, SMALL_ORDER_Y } from "./statement.ts";
import { verifyChain } from "./instancecard.ts";
import { ownKeysFromSeed, verifyGenesis } from "./genesis.ts";

const P = 2n ** 255n - 19n;
const L = 2n ** 252n + 27742317777372353535851937790883648493n;
const mod = (a: bigint, m = P) => ((a % m) + m) % m;
function pow(b: bigint, e: bigint, m = P): bigint {
  let r = 1n;
  b = mod(b, m);
  for (; e > 0n; e >>= 1n, b = (b * b) % m) if (e & 1n) r = (r * b) % m;
  return r;
}
const inv = (a: bigint) => pow(a, P - 2n);
const D = mod(-121665n * inv(121666n));
const SQRT_M1 = pow(2n, (P - 1n) / 4n);
type Pt = [bigint, bigint];
const ID: Pt = [0n, 1n];
function add([x1, y1]: Pt, [x2, y2]: Pt): Pt {
  const t = mod(D * x1 * x2 * y1 * y2);
  return [mod((x1 * y2 + y1 * x2) * inv(1n + t)), mod((y1 * y2 + x1 * x2) * inv(1n - t))];
}
function mul(k: bigint, p: Pt): Pt {
  let r = ID;
  for (let q = p; k > 0n; k >>= 1n, q = add(q, q)) if (k & 1n) r = add(r, q);
  return r;
}
const le = (b: Uint8Array) => b.reduceRight((n, x) => (n << 8n) | BigInt(x), 0n);
function toLe(n: bigint): Uint8Array {
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++, n >>= 8n) out[i] = Number(n & 0xffn);
  return out;
}
function decode(enc: Uint8Array): Pt | null {
  const y = le(enc) & ((1n << 255n) - 1n);
  if (y >= P) return null;
  const x2 = mod((y * y - 1n) * inv(D * y * y + 1n));
  let x = pow(x2, (P + 3n) / 8n);
  if (mod(x * x) !== x2) x = mod(x * SQRT_M1);
  if (mod(x * x) !== x2) return null;
  const sign = BigInt(enc[31]! >> 7);
  if (x === 0n && sign === 1n) return null;
  if ((x & 1n) !== sign) x = P - x;
  return [x, y];
}
const encode = ([x, y]: Pt) => {
  const e = toLe(y);
  e[31]! |= Number(x & 1n) << 7;
  return e;
};
const B = decode(Uint8Array.from({ length: 32 }, (_, i) => (i === 0 ? 0x58 : 0x66)))!;

const vectorsDir = fileURLToPath(new URL("../../spec/test-vectors/", import.meta.url));
const ic = JSON.parse(readFileSync(vectorsDir + "instancecard.json", "utf-8"));
const ag = JSON.parse(readFileSync(vectorsDir + "accountgenesis.json", "utf-8"));
const bytes = (s: string) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
const frameOf = (code: number, signer: Uint8Array, sig: Uint8Array, statement: Uint8Array) => Uint8Array.from([...MAGIC, code, ...signer, ...sig, ...statement]);
const card0Text = ic.chains[0].cards[0].statementUtf8 as string;
const withSignKey = (keyB64: string) => new TextEncoder().encode(card0Text.replace(/"operatorSignKey":"[^"]*"/, `"operatorSignKey":"${keyB64}"`));

test("the small-order blocklist is exactly the points of order dividing 8, plus the non-canonical 0 and 1", () => {
  for (const y of SMALL_ORDER_Y.filter((v) => v < P)) {
    for (const sign of [0, 1]) {
      const e = toLe(y);
      e[31]! |= sign << 7;
      const pt = decode(e);
      if (pt === null) continue; // x = 0 with the sign bit set
      const eight = mul(8n, pt);
      assert.deepEqual(eight, ID, `y=${y} has order dividing 8`);
      assert.equal(pointAcceptable(e), false);
    }
  }
  // An ordinary key passes.
  assert.equal(pointAcceptable(ownKeysFromSeed(new Uint8Array(32).fill(7)).signPub), true);
  // A non-canonical y (p + 2: canonical form 2) is refused.
  assert.equal(pointAcceptable(toLe(P + 2n)), false);
});

test("S + L: tweetnacl accepts the second encoding of a valid card signature; the extension refuses it (bad_signature)", () => {
  const cards = ic.chains[0].cards.slice(0, 2).map((c: { frameB64: string }) => bytes(c.frameB64));
  const forged = Uint8Array.from(cards[1]!);
  const s = le(forged.subarray(69, 101));
  forged.set(toLe(s + L), 69);
  const signer = forged.subarray(5, 37);
  const stmt = forged.subarray(101);
  assert.equal(nacl.sign.detached.verify(signedMessage(4, signer, stmt), forged.subarray(37, 101), signer), true, "tweetnacl alone accepts S + L");
  assert.equal(scalarReduced(forged.subarray(69, 101)), false);
  assert.equal(signatureValid(4, signer, forged.subarray(37, 101), stmt), false);
  const r = verifyChain([cards[0]!, forged]);
  assert.ok(!r.ok);
  assert.equal(r.verdict, "bad_signature");
  assert.equal(r.at, 1);
});

test("S + L on the account genesis: bad_signature", () => {
  const row = ag.rows.find((x: { name: string }) => x.name === "valid");
  const g = Uint8Array.from(bytes(row.genesisB64));
  g.set(toLe(le(g.subarray(69, 101)) + L), 69);
  const own = ownKeysFromSeed(b64Strict(ag.account.seedB64)!);
  const got = verifyGenesis(g, { own, sessionUserId: row.sessionUserId, pinnedInstanceId: row.pinnedInstanceId, servedPersonalVaultId: null });
  assert.deepEqual(got, { ok: false, verdict: "bad_signature" });
});

test("the identity point as signer: tweetnacl verifies a forgery anyone can make; the extension refuses it", () => {
  const identity = encode(ID);
  const stmt = withSignKey(b64Encode(identity));
  // [S]B = R + [h]·identity = R, so S = 1 and R = B verify for every message.
  const sig = Uint8Array.from([...encode(B), ...toLe(1n)]);
  assert.equal(nacl.sign.detached.verify(signedMessage(4, identity, stmt), sig, identity), true, "tweetnacl alone accepts the forgery");
  assert.equal(signatureValid(4, identity, sig, stmt), false);
  // A card 0 that names the identity point as its own key: the signer binds (bytes equal), the signature is refused.
  const r = verifyChain([frameOf(4, identity, sig, stmt)]);
  assert.ok(!r.ok);
  assert.equal(r.verdict, "bad_signature");
  // As a genesis signer it can never be the extension's own key.
  const row = ag.rows.find((x: { name: string }) => x.name === "valid");
  const g = Uint8Array.from(bytes(row.genesisB64));
  g.set(identity, 5);
  g.set(sig, 37);
  const own = ownKeysFromSeed(b64Strict(ag.account.seedB64)!);
  assert.deepEqual(verifyGenesis(g, { own, sessionUserId: row.sessionUserId, pinnedInstanceId: row.pinnedInstanceId, servedPersonalVaultId: null }), { ok: false, verdict: "signer_not_pinned_key" });
});

test("the all-zero key (a point of order 4) as a card's own key and signer: bad_signature", () => {
  const zero = new Uint8Array(32);
  const stmt = withSignKey(b64Encode(zero));
  const sig = Uint8Array.from([...encode(B), ...toLe(1n)]);
  assert.equal(pointAcceptable(zero), false);
  const r = verifyChain([frameOf(4, zero, sig, stmt)]);
  assert.ok(!r.ok);
  assert.equal(r.verdict, "bad_signature");
});

test("a small-order R is refused even under an ordinary key", () => {
  const card = bytes(ic.chains[0].cards[0].frameB64);
  const bad = Uint8Array.from(card);
  bad.set(encode(ID), 37);
  assert.equal(signatureValid(4, bad.subarray(5, 37), bad.subarray(37, 101), bad.subarray(101)), false);
});

test("a negated key -A is a key of its own: a card 0 self-signed under -A verifies; A cannot sign after it", () => {
  const seed = b64Strict(ic.keys.operator.seedB64)!;
  const h = sha512(seed);
  const a = le(Uint8Array.from(h.subarray(0, 32), (x, i) => (i === 0 ? x & 248 : i === 31 ? (x & 127) | 64 : x)));
  const A = mul(a, B);
  assert.equal(b64Encode(encode(A)), ic.keys.operator.signPubB64, "the operator's Ed25519 key");
  const negA = encode([mod(-A[0]), A[1]]);
  assert.notDeepEqual(negA, encode(A));
  const stmt = withSignKey(b64Encode(negA));
  const msg = signedMessage(4, negA, stmt);
  const r = mod(le(sha512(Uint8Array.from([...h.subarray(32), ...msg]))), L);
  const R = encode(mul(r, B));
  const k = mod(le(sha512(Uint8Array.from([...R, ...negA, ...msg]))), L);
  const S = mod(r + k * (L - mod(a, L)), L);
  const sig = Uint8Array.from([...R, ...toLe(S)]);
  assert.equal(signatureValid(4, negA, sig, stmt), true, "a valid signature under -A");
  const card0 = frameOf(4, negA, sig, stmt);
  const ok = verifyChain([card0]);
  assert.ok(ok.ok, "card 0 under -A verifies: its signer is byte-equal to the key it names");
  // The genuine card 1 of the vectors, signed by A, cannot follow a card 0 that names -A (and its prev differs too).
  const card1 = bytes(ic.chains[0].cards[1].frameB64);
  const after = verifyChain([card0, card1]);
  assert.ok(!after.ok);
  assert.equal(after.verdict, "bad_prev"); // prev names the vectors' card 0, not this one: the earlier verdict wins
});
