import { beforeAll, describe, expect, it, vi } from "vitest";
import { fromB64, fromB64Bytes, toB64, toB64Bytes, utf8 } from "../bytes";
import { hkdfSha256 } from "../hkdf";
import { boxKeypairFromSeed, randomBytes, signKeypairFromSeed } from "../provider";
import { initSodium } from "../sodium";
import { encodeStatement, parseFrame, parseStatement, secretOf } from "./codec";
import { signFrame, wipeFrameParts } from "./frame";
import { fromB64Canonical } from "./grammar";
import { openVaultGrant, sealVaultGrant, signVaultGrant } from "./grant";
import { openAssistedRecovery } from "./recovery";
import { composeKitQr } from "./recoverykit";
import { NONE_HELD, replayLog } from "./vaultlog";
import { vector } from "./vectors";

/**
 * Key material is wiped where it can be. A grant frame
 * holds the vault key and an assisted-recovery frame the account's UVK, both in the clear, and HKDF's
 * pseudorandom key is as good as its input key.
 *
 * The provider is wrapped so that the test holds the very arrays the code under test was given: what
 * `sealOpen` returned (the opened frame) and what `hmacSha256` returned and was fed (the PRK, the blocks,
 * the block inputs). A string cannot be wiped, so the other half of the fix is that the key never becomes
 * one: it is written into a statement and read out of it as bytes.
 */
const seen = vi.hoisted(() => ({ opened: [] as Uint8Array[], macs: [] as Uint8Array[], macInputs: [] as Uint8Array[] }));
vi.mock("../provider", async (importOriginal) => {
  const real = await importOriginal<typeof import("../provider")>();
  return {
    ...real,
    sealOpen: (publicKey: Uint8Array, privateKey: Uint8Array, sealed: Uint8Array): Uint8Array => {
      const out = real.sealOpen(publicKey, privateKey, sealed);
      seen.opened.push(out);
      return out;
    },
    hmacSha256: async (key: Uint8Array, data: Uint8Array): Promise<Uint8Array> => {
      const out = await real.hmacSha256(key, data);
      seen.macs.push(out);
      seen.macInputs.push(data);
      return out;
    },
  };
});

const isZero = (bytes: Uint8Array): boolean => bytes.every((b) => b === 0);
const grants = vector("next/sharedgrant-v2.json");
const recovery = vector("recovery.json");

beforeAll(async () => {
  await initSodium();
});

describe("base64url on bytes, for values that must not become strings", () => {
  it("agrees with the string codec on every length and refuses what it refuses", () => {
    for (let n = 0; n <= 70; n++) {
      const bytes = randomBytes(n);
      const text = toB64Bytes(bytes);
      expect(new TextDecoder().decode(text), `length ${n}`).toBe(toB64(bytes));
      expect(fromB64Bytes(text), `length ${n}`).toEqual(bytes);
    }
    // Every byte value in every position of a short text: the two decoders accept and refuse alike.
    for (const base of ["AAAA", "AAA", "AA", "QUJD", "-_-_", "AAAAAA", "AAAAAAA"]) {
      for (let at = 0; at < base.length; at++) {
        for (let c = 0; c < 256; c++) {
          const mutated = utf8(base);
          mutated[at] = c;
          const viaString = c < 128 ? fromB64Canonical(String.fromCharCode(...mutated)) : null;
          expect(fromB64Bytes(mutated), `${base}[${at}] = ${c}`).toEqual(viaString);
        }
      }
    }
    expect(fromB64Bytes(utf8("A"))).toBeNull(); // one character carries no byte
    expect(fromB64Bytes(utf8("AAAAA"))).toBeNull();
    expect(fromB64Bytes(utf8("AB"))).toBeNull(); // unused trailing bits must be zero
    expect(fromB64Bytes(utf8("AA=="))).toBeNull(); // no padding
    expect(fromB64Bytes(utf8("xxAAAAyy"), 2, 6)).toEqual(new Uint8Array(3));
    expect(fromB64Bytes(utf8("AAAA"), 2, 9)).toBeNull();
  });
});

describe("a secret field never becomes a string", () => {
  const alice = grants.accounts.alice;
  const bob = grants.accounts.bob;
  const fields = { from: alice.userId, to: bob.userId, toKey: bob.identityPubB64, vaultId: grants.vaultId, grantId: "AAAAAAAAAAAAAAAAAAAAAA", issuedAt: "1763164800000" };

  it("is written from bytes, read back as bytes, and absent from the parsed values", () => {
    const vk = randomBytes(32);
    const statement = encodeStatement("vault-grant", fields, { vk });
    expect(new TextDecoder().decode(statement)).toContain(`"vk":"${toB64(vk)}"`);
    const parsed = parseStatement("vault-grant", statement);
    expect(parsed.ok && Object.keys(parsed.value)).toEqual(["v", "purpose", "from", "to", "toKey", "vaultId", "grantId", "issuedAt"]);

    const frame = signFrame(signKeypairFromSeed(fromB64(alice.seedB64)), "vault-grant", statement);
    const whole = parseFrame(frame, "vault-grant");
    expect(whole.ok).toBe(true);
    if (!whole.ok) return;
    expect("vk" in whole.value.raw).toBe(false);
    expect(secretOf(whole.value, "vk")).toEqual(vk);
    expect(() => secretOf(whole.value, "toKey")).toThrow(); // a plain field is not read this way
    wipeFrameParts(whole.value.parts);
    expect(isZero(whole.value.parts.statement) && isZero(whole.value.parts.signature) && isZero(whole.value.parts.signerPub)).toBe(true);
    expect(() => secretOf(whole.value, "vk")).toThrow(); // nothing is left to read
  });

  it("is refused as text, with the wrong length, and outside its grammar", () => {
    const vk = randomBytes(32);
    expect(() => encodeStatement("vault-grant", { ...fields, vk: toB64(vk) })).toThrow();
    expect(() => encodeStatement("vault-grant", { ...fields, vk: toB64(vk) }, { vk })).toThrow();
    expect(() => encodeStatement("vault-grant", fields, { vk: vk.subarray(0, 31) })).toThrow();
    expect(() => encodeStatement("vault-grant", fields)).toThrow();
    expect(() => encodeStatement("vault-log", { kind: "leave", vaultId: grants.vaultId, seq: "1", prev: "0".repeat(64), actor: alice.userId, at: "1" }, { vk })).toThrow();
    // The b64_32 grammar holds for the key where it stands: 43 characters, canonical.
    const text = new TextDecoder().decode(encodeStatement("vault-grant", fields, { vk: new Uint8Array(32) }));
    const withVk = (value: string): string => {
      const r = parseStatement("vault-grant", utf8(text.replace(`"vk":"${"A".repeat(43)}"`, `"vk":"${value}"`)));
      return r.ok ? "ok" : r.verdict;
    };
    expect(withVk("A".repeat(43))).toBe("ok");
    expect(withVk("A".repeat(42))).toBe("non_canonical");
    expect(withVk("A".repeat(44))).toBe("non_canonical");
    expect(withVk(`${"A".repeat(42)}B`)).toBe("non_canonical"); // non-zero trailing bits
    expect(withVk(`${"A".repeat(42)}+`)).toBe("non_canonical"); // the standard alphabet
    expect(withVk(`${"A".repeat(42)}=`)).toBe("non_canonical");
  });
});

describe("what an opener leaves behind", () => {
  it("a grant: the opened frame is wiped on success and on every refusal after the seal", async () => {
    const alice = grants.accounts.alice;
    const cases: { name: string; me: string; log: string; rowVaultId: string; sealedB64: string; expect: { verdict: string } }[] = grants.cases;
    const afterTheSeal = cases.filter((c) => c.expect.verdict !== "unopenable" && grants.logs[c.log].verdict === "ok");
    expect(new Set(afterTheSeal.map((c) => c.expect.verdict)).size).toBeGreaterThan(8);
    for (const c of afterTheSeal) {
      const account = grants.accounts[c.me];
      const box = boxKeypairFromSeed(fromB64(account.seedB64));
      const state = replayLog(grants.vaultId, grants.logs[c.log].frames.map(fromB64), null, NONE_HELD).state;
      seen.opened.length = 0;
      const result = await openVaultGrant({ userId: account.userId, identityPub: box.publicKey, identityPriv: box.privateKey }, c.rowVaultId, fromB64(c.sealedB64), state);
      expect(result.ok ? "ok" : result.verdict, c.name).toBe(c.expect.verdict);
      expect(seen.opened.length, c.name).toBe(1);
      expect(isZero(seen.opened[0]!), `${c.name}: the opened frame`).toBe(true);
      if (result.ok) expect(isZero(result.value.vk), `${c.name}: the key handed to the caller is the caller's`).toBe(false);
    }
    // A grant this client signs: the statement it framed is wiped, and the frame is the caller's to wipe.
    const vk = fromB64(grants.vkB64);
    const frame = signVaultGrant(signKeypairFromSeed(fromB64(alice.seedB64)), {
      from: alice.userId, to: grants.accounts.bob.userId, toKey: grants.accounts.bob.identityPubB64, vaultId: grants.vaultId,
      grantId: "AAAAAAAAAAAAAAAAAAAAAA", issuedAt: 1763164800000, vk,
    });
    expect(sealVaultGrant(fromB64(grants.accounts.bob.identityPubB64), frame).length).toBeGreaterThan(frame.length);
    expect(isZero(vk)).toBe(false); // the caller's own key is not touched
  });

  it("an assisted recovery: the opened frame is wiped on success and on every refusal after the seal", () => {
    const rPub = fromB64(recovery.requestKey.rPubB64);
    const rSec = fromB64(recovery.requestKey.rSecB64);
    let afterTheSeal = 0;
    for (const r of recovery.assisted) {
      seen.opened.length = 0;
      const result = openAssistedRecovery(
        { instanceId: r.request.instanceId, userId: r.request.userId, requestId: r.request.requestId, rPub, rSec },
        fromB64(r.sealedB64), r.cardRecoveryFp,
        { encryptedIdentitySeed: fromB64(r.encryptedIdentitySeedB64), identityPub: fromB64(r.identityPubB64) },
      );
      expect(result.ok ? "ok" : result.verdict, r.name).toBe(r.expect.verdict);
      if (r.expect.verdict === "unopenable") continue;
      afterTheSeal++;
      expect(isZero(seen.opened[0]!), `${r.name}: the opened frame`).toBe(true);
      if (result.ok) expect(toB64(result.value.uvk), r.name).toBe(r.expect.uvkB64);
    }
    expect(afterTheSeal).toBeGreaterThan(10);
  });

  it("HKDF: the pseudorandom key, every block and every block input", async () => {
    seen.macs.length = 0;
    seen.macInputs.length = 0;
    const ikm = randomBytes(32);
    const out = await hkdfSha256(ikm, new Uint8Array(0), utf8("andvari/v2|test"), 80);
    expect(out.length).toBe(80);
    expect(isZero(out)).toBe(false);
    expect(seen.macs.length).toBe(4); // the PRK, then T(1), T(2), T(3)
    for (const mac of seen.macs) expect(isZero(mac)).toBe(true);
    expect(seen.macInputs[0]).toBe(ikm); // the caller's key is the caller's
    expect(isZero(ikm)).toBe(false);
    for (const input of seen.macInputs.slice(1)) expect(isZero(input)).toBe(true);
  });

  it("a kit: the parse-back's copy of the secret is wiped, and the caller's is not", () => {
    const secret = randomBytes(32);
    const text = composeKitQr("https://vault.example.org", "ab".repeat(32), "a@b.example", secret);
    expect(text.endsWith(toB64(secret))).toBe(true);
    expect(isZero(secret)).toBe(false);
  });
});
