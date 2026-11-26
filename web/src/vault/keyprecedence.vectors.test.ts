import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import type { AccountKeys, WireGrant } from "../api/types";
import { adItem, adUvk, adVk } from "../crypto/ad";
import { fromB64, toB64 } from "../crypto/bytes";
import { open, seal } from "../crypto/envelope";
import { fingerprint } from "../crypto/escrow";
import { masterKey, wrapKey, type KdfParams } from "../crypto/keys";
import { boxKeypairFromSeed, randomBytes } from "../crypto/provider";
import { initSodium } from "../crypto/sodium";
import { Account } from "./account";

/**
 * Consumes spec/test-vectors/keyprecedence.json (security review 2026-10, root cause A §3.1), the SAME file core
 * `KeyPrecedenceVectorTest` grades. Under the signed vault log (design 2026-11-15) the web takes a key from a grant
 * row for one vault only: its personal vault, whose row carries this account's own UVK wrap, opened only to compare
 * with the key the personal wrap gave at unlock (`Account.addGrant`). A row is graded through `Account.addGrant` and
 * `Account.sealItem`, the functions production calls, unless one of these makes it a row the web no longer grades:
 *
 * - `vouch`: the row starts from a §8.2 vouch or an A7 held-key tag (design §15 deletes held-key memory and vouches);
 * - `legacy`: a row carries a v1 `sealedVk` (§15 deletes the v1 seal, canonical-key precedence rule 3; the wire has no
 *   such field any more);
 * - `pinned_grant`: a row carries a v2 grant verified against a contact pin (§3.12 deletes automatic adoption from
 *   pinned senders and pending invitations; a grant is decided against its log, next/sharedgrant-v2.json);
 * - `shared`: a shared vault's key comes only from its verified log (§3.6), never from a grant row; the web's own-wrap
 *   rule for it is the genesis-bound one wrapad.json `adopt` grades (adoption.test.ts).
 *
 * Every other row is a kept row and is graded; there is no skip list to fall out of date. Today every row of the
 * file is one of the four, so the web-local rows below exercise the same grader on the personal vault's own row.
 */

const KDF: KdfParams = { v: 1, alg: "argon2id13", ops: 1, memBytes: 8192 };

type Row = { role: string; wrappedVk: string | null; sealedVk: string | null; signedGrant: { by: string; vk: "A" | "B" } | null };
type Expect = { key: string | null; source: string | null; vkMismatch: boolean; keyUnreadable: boolean; pending: boolean; anomaly: string | null; legacyReadOnly: boolean; writable: boolean };
interface Case {
  name: string;
  vault: "shared" | "personal";
  held: { vouch?: "A" | "B"; kind?: "frozen" | "confirmed"; heldTag?: "A" | "B" } | null;
  rows: Row[];
  expect: Expect;
}

const vectors = JSON.parse(readFileSync(fileURLToPath(new URL("../../../spec/test-vectors/keyprecedence.json", import.meta.url)), "utf8")) as { cases: Case[] };

type Retired = "vouch" | "legacy" | "pinned_grant" | "shared";

/** Why the web no longer grades `c`, or null when it is a kept row (and is graded). First reason wins. */
function retiredBecause(c: Case): Retired | null {
  if (c.held !== null) return "vouch";
  if (c.rows.some((r) => r.sealedVk !== null)) return "legacy";
  if (c.rows.some((r) => r.signedGrant !== null)) return "pinned_grant";
  if (c.vault !== "personal") return "shared";
  return null;
}

interface Enrolled {
  userId: string;
  password: string;
  keys: AccountKeys;
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
    personalVaultId: request.personalVault.vaultId,
    personalWrappedVk: request.personalVault.wrappedVk,
  };
}

async function uvkOf(e: Enrolled): Promise<Uint8Array> {
  return open(await wrapKey(masterKey(e.password, fromB64(e.keys.kdfSalt), e.keys.kdfParams)), fromB64(e.keys.wrappedUvk), adUvk(e.userId));
}

function tamper(b64: string): string {
  const raw = fromB64(b64);
  raw[raw.length - 1] = raw[raw.length - 1]! ^ 0x01;
  return toB64(raw);
}

function opensWith(key: Uint8Array, vaultId: string, itemId: string, fv: number, blob: string): boolean {
  try {
    open(key, fromB64(blob), adItem(vaultId, itemId, fv));
    return true;
  } catch {
    return false;
  }
}

/** Grade a kept row: the personal vault, unlocked from its personal wrap (key A), then the rows through addGrant. */
async function grade(member: Enrolled, uvkM: Uint8Array, c: Case): Promise<Expect> {
  const device = await Account.unlock(member.userId, member.password, member.keys);
  const vaultId = member.personalVaultId;
  const keyA = open(uvkM, fromB64(member.personalWrappedVk), adVk(vaultId, member.userId));
  const keyB = randomBytes(32);
  const key = (s: string): Uint8Array => (s === "A" ? keyA : s === "B" ? keyB : (() => { throw new Error(`unknown key ${s}`); })());
  c.rows.forEach((row, i) => {
    const wrappedVk = row.wrappedVk === null ? ""
      : row.wrappedVk === "damaged" ? tamper(toB64(seal(uvkM, keyA, adVk(vaultId, member.userId))))
      : toB64(seal(uvkM, key(row.wrappedVk), adVk(vaultId, member.userId)));
    const grant: WireGrant = { vaultId, userId: member.userId, role: row.role, wrappedVk, rev: 3 + i };
    try {
      device.addGrant(grant);
    } catch {
      /* the verdict is read off the account below */
    }
  });
  let writable = true;
  let gotKey: string | null = null;
  try {
    const itemId = device.newItemId();
    const up = device.sealItem({ kind: "chosen", vaultId }, itemId, { type: "login", name: "probe" });
    gotKey = opensWith(keyA, vaultId, itemId, up.formatVersion, up.blob) ? "A" : opensWith(keyB, vaultId, itemId, up.formatVersion, up.blob) ? "B" : "?";
  } catch {
    writable = false;
  }
  if (!writable && device.hasVault(vaultId)) gotKey = "?"; // held but not sealable: no state the web has, so it fails the row
  const own = device.hasVault(vaultId) && device.keyFromOwnUvkWrap(vaultId);
  return {
    key: gotKey,
    source: !device.hasVault(vaultId) ? null : vaultId === device.personalVaultId && own ? "personal_wrap" : "?",
    vkMismatch: device.vkMismatch(vaultId),
    // The web has no unreadable-key, pending-invitation, grant-anomaly or legacy-read-only state any more: a kept row
    // that expected one fails here.
    keyUnreadable: false,
    pending: false,
    anomaly: null,
    legacyReadOnly: false,
    writable,
  };
}

/** Web-local rows in the vector file's own symbols: the personal vault's row, which is what the web still grades. */
const LOCAL: Case[] = [
  {
    name: "web: the personal row with our own wrap of the personal key changes nothing",
    vault: "personal", held: null, rows: [{ role: "owner", wrappedVk: "A", sealedVk: null, signedGrant: null }],
    expect: { key: "A", source: "personal_wrap", vkMismatch: false, keyUnreadable: false, pending: false, anomaly: null, legacyReadOnly: false, writable: true },
  },
  {
    name: "web: the personal row with our own wrap of ANOTHER key is a mismatch; the personal key stands",
    vault: "personal", held: null, rows: [{ role: "owner", wrappedVk: "B", sealedVk: null, signedGrant: null }],
    expect: { key: "A", source: "personal_wrap", vkMismatch: true, keyUnreadable: false, pending: false, anomaly: null, legacyReadOnly: false, writable: true },
  },
  {
    name: "web: a damaged wrap on the personal row changes nothing; the personal key stands",
    vault: "personal", held: null, rows: [{ role: "owner", wrappedVk: "damaged", sealedVk: null, signedGrant: null }],
    expect: { key: "A", source: "personal_wrap", vkMismatch: false, keyUnreadable: false, pending: false, anomaly: null, legacyReadOnly: false, writable: true },
  },
  {
    name: "web: a warm re-delivery of another key's wrap cannot change the personal key",
    vault: "personal", held: null,
    rows: [{ role: "owner", wrappedVk: "A", sealedVk: null, signedGrant: null }, { role: "owner", wrappedVk: "B", sealedVk: null, signedGrant: null }],
    expect: { key: "A", source: "personal_wrap", vkMismatch: true, keyUnreadable: false, pending: false, anomaly: null, legacyReadOnly: false, writable: true },
  },
];

describe("keyprecedence.json — the §3.1 table on the web engine", () => {
  let member: Enrolled;
  let uvkM: Uint8Array;
  beforeAll(async () => {
    await initSodium();
    member = await enroll("kp-member");
    uvkM = await uvkOf(member);
  });

  it("is populated, and a kept row expects nothing the grader does not read", () => {
    expect(vectors.cases.length).toBeGreaterThan(0);
    const graded = ["anomaly", "key", "keyUnreadable", "legacyReadOnly", "pending", "source", "vkMismatch", "writable"];
    for (const c of [...vectors.cases, ...LOCAL]) {
      if (retiredBecause(c) === null) expect(Object.keys(c.expect).sort(), c.name).toEqual(graded);
    }
  });

  for (const c of vectors.cases) {
    const why = retiredBecause(c);
    if (why === null) {
      it(c.name, async () => {
        expect(await grade(member, uvkM, c)).toEqual(c.expect);
      });
    }
  }

  for (const c of LOCAL) {
    it(c.name, async () => {
      expect(retiredBecause(c)).toBeNull();
      expect(await grade(member, uvkM, c)).toEqual(c.expect);
    });
  }
});
