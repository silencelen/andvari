import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import type { AccountKeys, WireGrant } from "../api/types";
import { adIdkey, adUvk, adVk } from "../crypto/ad";
import { fromB64, toB64, toHexLower } from "../crypto/bytes";
import { open, seal } from "../crypto/envelope";
import { fingerprint } from "../crypto/escrow";
import { masterKey, wrapKey, type KdfParams } from "../crypto/keys";
import { boxKeypairFromSeed, randomBytes, sealTo, sha256Sync, signKeypairFromSeed } from "../crypto/provider";
import { sealSharedGrant } from "../crypto/sharedgrant";
import { buildGrantFrame } from "../crypto/signedgrant";
import { initSodium } from "../crypto/sodium";
import { Account } from "./account";

/**
 * Consumes spec/test-vectors/keyprecedence.json (security review 2026-10, root cause A §3.1 as it stands after A6/A7;
 * branch A1b) — web twin of core `KeyPrecedenceVectorTest`, the SAME file. Every row is built into real crypto and run
 * through the functions production calls: `Account.addGrant` for the precedence and `Account.sealItem` for
 * INV-WRITE-KEY.
 */

const KDF: KdfParams = { v: 1, alg: "argon2id13", ops: 1, memBytes: 8192 };
const vectors = JSON.parse(readFileSync(fileURLToPath(new URL("../../../spec/test-vectors/keyprecedence.json", import.meta.url)), "utf8")) as {
  cases: {
    name: string;
    vault: "shared" | "personal";
    held: { vouch?: "A" | "B"; kind?: "frozen" | "confirmed"; heldTag?: "A" | "B" } | null;
    rows: { role: string; wrappedVk: string | null; sealedVk: string | null; signedGrant: { by: string; vk: "A" | "B" } | null }[];
    expect: { key: string | null; source: string | null; vkMismatch: boolean; keyUnreadable: boolean; pending: boolean; anomaly: string | null; legacyReadOnly: boolean; writable: boolean };
  }[];
};

interface Enrolled {
  userId: string;
  password: string;
  keys: AccountKeys;
  identityPub: string;
  personalVaultId: string;
  personalWrappedVk: string;
}

async function enroll(tag: string): Promise<Enrolled> {
  const email = `${tag}-${Math.random().toString(16).slice(2)}@example.com`;
  const recovery = boxKeypairFromSeed(randomBytes(32));
  const password = `pw ${email}`;
  const { request } = await Account.enroll({ inviteToken: "t", email, displayName: email, password, kdfParams: KDF, recoveryPublicKey: recovery.publicKey, recoveryFingerprint: await fingerprint(recovery.publicKey) });
  return {
    userId: request.userId,
    password,
    keys: {
      kdfSalt: request.kdfSalt, kdfParams: request.kdfParams, wrappedUvk: request.wrappedUvk, encryptedIdentitySeed: request.encryptedIdentitySeed,
      identityPub: request.identityPub, escrowFingerprint: request.escrow!.fingerprint, personalWrap: request.personalWrap,
    },
    identityPub: request.identityPub,
    personalVaultId: request.personalVault.vaultId,
    personalWrappedVk: request.personalVault.wrappedVk,
  };
}

async function uvkOf(e: Enrolled): Promise<Uint8Array> {
  return open(await wrapKey(masterKey(e.password, fromB64(e.keys.kdfSalt), e.keys.kdfParams)), fromB64(e.keys.wrappedUvk), adUvk(e.userId));
}

const tag = (k: Uint8Array): string => toHexLower(sha256Sync(k));

function tamper(b64: string): string {
  const raw = fromB64(b64);
  raw[raw.length - 1] = raw[raw.length - 1]! ^ 0x01;
  return toB64(raw);
}

const SOURCE: Record<string, string> = { "personal-wrap": "personal_wrap", "uvk-wrap": "uvk_wrap", "signed-grant": "signed_grant", "legacy-seal": "legacy_seal" };

describe("keyprecedence.json — the §3.1 table on the web engine", () => {
  let owner: Enrolled, member: Enrolled, stranger: Enrolled;
  let ownerSeed: Uint8Array, strangerSeed: Uint8Array, uvkM: Uint8Array;
  beforeAll(async () => {
    await initSodium();
    owner = await enroll("kp-owner");
    member = await enroll("kp-member");
    stranger = await enroll("kp-stranger");
    ownerSeed = open(await uvkOf(owner), fromB64(owner.keys.encryptedIdentitySeed), adIdkey(owner.userId));
    strangerSeed = open(await uvkOf(stranger), fromB64(stranger.keys.encryptedIdentitySeed), adIdkey(stranger.userId));
    uvkM = await uvkOf(member);
  });

  it("is populated", () => {
    expect(vectors.cases.length).toBeGreaterThanOrEqual(20);
  });

  for (const c of vectors.cases) {
    it(c.name, async () => {
      const personal = c.vault === "personal";
      const device = await Account.unlock(member.userId, member.password, member.keys);
      const vaultId = personal ? member.personalVaultId : device.newItemId();
      const keyA = personal ? open(uvkM, fromB64(member.personalWrappedVk), adVk(vaultId, member.userId)) : randomBytes(32);
      const keyB = randomBytes(32);
      const key = (s: string): Uint8Array => (s === "A" ? keyA : s === "B" ? keyB : (() => { throw new Error(`unknown key ${s}`); })());
      device.grantPins = (uid) => (uid === owner.userId ? { identityPub: fromB64(owner.identityPub), current: true } : null);
      if (c.held?.vouch) device.authorizeLegacyKey(vaultId, tag(key(c.held.vouch)), c.held.kind ?? "confirmed");
      if (c.held?.heldTag) device.rememberHeldKey(vaultId, tag(key(c.held.heldTag)));
      c.rows.forEach((row, i) => {
        const wrappedVk = row.wrappedVk === null ? ""
          : row.wrappedVk === "damaged" ? tamper(toB64(seal(uvkM, keyA, adVk(vaultId, member.userId))))
          : toB64(seal(uvkM, key(row.wrappedVk), adVk(vaultId, member.userId)));
        const sealedVk = row.sealedVk === null ? null
          : row.sealedVk === "foreign" ? toB64(sealSharedGrant(boxKeypairFromSeed(randomBytes(32)).publicKey, vaultId, keyA))
          : toB64(sealSharedGrant(fromB64(member.identityPub), vaultId, key(row.sealedVk)));
        let signedGrant: string | null = null;
        if (row.signedGrant) {
          const [seed, from] = row.signedGrant.by === "owner" ? [ownerSeed, owner.userId]
            : row.signedGrant.by === "unpinned" ? [strangerSeed, stranger.userId]
            : [randomBytes(32), owner.userId];
          const frame = buildGrantFrame(signKeypairFromSeed(seed), {
            purpose: "vault-grant", from, to: member.userId, toKey: fromB64(member.identityPub), vaultId,
            grantId: randomBytes(16), issuedAt: 1_791_590_400_000, vk: key(row.signedGrant.vk),
          });
          signedGrant = toB64(sealTo(fromB64(member.identityPub), frame));
        }
        const grant: WireGrant = { vaultId, userId: member.userId, role: row.role, wrappedVk, rev: 3 + i, sealedVk, signedGrant };
        try {
          device.addGrant(grant);
        } catch {
          /* the verdict is read off the account below */
        }
      });
      const held = device.hasVault(vaultId) ? device.legacyKeyTag(vaultId) : null;
      const gotKey = held === null ? null : held === tag(keyA) ? "A" : held === tag(keyB) ? "B" : "?";
      const src = device.hasVault(vaultId) ? device.keySource(vaultId) : null;
      let writable = true;
      try {
        device.sealItem({ kind: "chosen", vaultId }, device.newItemId(), { type: "login", name: "probe" });
      } catch {
        writable = false;
      }
      expect({
        key: gotKey,
        source: src === null ? null : SOURCE[src]!,
        vkMismatch: device.vkMismatch(vaultId),
        keyUnreadable: device.keyUnreadable(vaultId),
        pending: device.pendingGrants().some((p) => p.vaultId === vaultId),
        anomaly: device.grantAnomalies().get(vaultId) ?? null,
        legacyReadOnly: device.isLegacyReadOnly(vaultId),
        writable,
      }).toEqual(c.expect);
    });
  }
});
