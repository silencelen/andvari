import { beforeAll, describe, expect, it } from "vitest";
import type { ApiClient } from "../api/client";
import type { SyncResponse } from "../api/types";
import { toB64 } from "../crypto/bytes";
import { fingerprint } from "../crypto/escrow";
import { groupedShort } from "../crypto/fingerprint";
import type { KdfParams } from "../crypto/keys";
import { boxKeypairFromSeed, randomBytes } from "../crypto/provider";
import { identityFingerprint } from "../crypto/sharedgrant";
import { initSodium } from "../crypto/sodium";
import { enrollCheckCode, enrollCheckCodeMatches } from "../enroll/enrollcheck";
import type { EnrollPayload } from "../enroll/enrolllink";
import { Account } from "./account";
import { emptyAccountState, withContact } from "./accountstate";
import { memoryClientState } from "./accountstatesync";
import { composeIdentityQr, IDENTITY_QR_PREFIX, parseIdentityQr, pinFromEnrolLink, pinFromQr, pinFromTyped, pinState } from "./contacts";
import { VaultStore } from "./store";

/**
 * Security review 2026-10, root cause A §4.2 / §7.2 (branch A5) — web twin of core ContactPinTest. A contact
 * is pinned ONLY from a human verification; a key the server served is never pinned on its own.
 */

const BEA = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const KDF: KdfParams = { v: 1, alg: "argon2id13", ops: 1, memBytes: 8192 };

describe("contact pins come only from a human", () => {
  let bea: ReturnType<typeof boxKeypairFromSeed>;
  let mallory: ReturnType<typeof boxKeypairFromSeed>;
  let beaFp: string;
  beforeAll(async () => {
    await initSodium();
    bea = boxKeypairFromSeed(new Uint8Array(32).fill(5));
    mallory = boxKeypairFromSeed(new Uint8Array(32).fill(6));
    beaFp = await identityFingerprint(bea.publicKey);
  });
  const served = () => ({ userId: BEA, identityPub: toB64(bea.publicKey) });
  const substituted = () => ({ userId: BEA, identityPub: toB64(mallory.publicKey) });

  it("typed: exactly 32 hex from a human, against the served key", async () => {
    expect(await pinFromTyped(groupedShort(beaFp), served(), "Bea", 1)).not.toBeNull();
    expect(await pinFromTyped(beaFp, served(), "Bea", 1)).toBeNull(); // a full 64-hex value is a machine value
    expect(await pinFromTyped(beaFp.slice(0, 16), served(), "Bea", 1)).toBeNull();
    expect(await pinFromTyped(beaFp.slice(0, 32), substituted(), "Bea", 1)).toBeNull(); // the server swapped the key
  });

  it("QR: full-length compare only", async () => {
    const qr = await composeIdentityQr(BEA, bea.publicKey);
    expect((await pinFromQr(qr, served(), "Bea", 1))?.method).toBe("qr");
    expect(await pinFromQr(qr, substituted(), "Bea", 1)).toBeNull();
    expect(await pinFromQr(`${IDENTITY_QR_PREFIX}${BEA}:${beaFp.slice(0, 32)}`, served(), "Bea", 1)).toBeNull();
    expect(parseIdentityQr(qr.toUpperCase())).toBeNull();
  });

  it("enrolment: only under the typed in-person code AND the in-person affirmation, never a server-chosen key", async () => {
    const p: EnrollPayload = { v: 1, o: "https://vault.example", t: "t", e: "e", ifp: beaFp, iu: BEA };
    const code = (await enrollCheckCode(p))!;
    // A5c (security review 2026-10, API review #4): the code is an unkeyed hash of the link itself, so whoever
    // composed the link (the server emails invites) can hand the invitee "the code" through the same channel.
    // A navigated link plus a correct code is NOT in-person evidence on its own; the human's first-person
    // in-person affirmation is required too, and this layer re-checks the code from the raw typed entry.
    expect(await pinFromEnrolLink(p, { typedCode: code, inPersonAffirmed: false }, served(), "Admin", 1)).toBeNull(); // navigated link + correct code, no affirmation
    expect(await pinFromEnrolLink(p, { typedCode: "", inPersonAffirmed: true }, served(), "Admin", 1)).toBeNull(); // affirmation without the code
    expect(await pinFromEnrolLink(p, { typedCode: code.slice(0, 16), inPersonAffirmed: true }, served(), "Admin", 1)).toBeNull(); // a prefix is not the code
    expect((await pinFromEnrolLink(p, { typedCode: code, inPersonAffirmed: true }, served(), "Admin", 1))?.method).toBe("enrol"); // the genuine in-person path
    expect(await pinFromEnrolLink(p, { typedCode: code, inPersonAffirmed: true }, substituted(), "Admin", 1)).toBeNull();
    const forged: EnrollPayload = { ...p, ifp: await identityFingerprint(mallory.publicKey) };
    expect(await enrollCheckCodeMatches(forged, code)).toBe(false); // a server-composed link fails the admin's on-screen code
    expect(await pinFromEnrolLink(forged, { typedCode: code, inPersonAffirmed: true }, served(), "Admin", 1)).toBeNull();
  });

  it("pinState detects a key change", () => {
    const doc = withContact(emptyAccountState("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"), { userId: BEA, identityPub: served().identityPub, label: "Bea", verifiedAt: 1, method: "typed" });
    expect(pinState(doc, served())).toBe("pinned-match");
    expect(pinState(doc, substituted())).toBe("pinned-mismatch");
    expect(pinState(doc, { userId: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", identityPub: served().identityPub })).toBe("unpinned");
  });

  it("a sync that delivers a member grant pins nothing (its only account-state write is the A1b member provenance)", async () => {
    const rk = boxKeypairFromSeed(randomBytes(32));
    const fp = await fingerprint(rk.publicKey);
    const victim = (await Account.enroll({ inviteToken: "t", email: "v@example.com", displayName: "v", password: "pw pw pw pw", kdfParams: KDF, recoveryPublicKey: rk.publicKey, recoveryFingerprint: fp })).account;
    const owner = (await Account.enroll({ inviteToken: "t", email: "o@example.com", displayName: "o", password: "pw pw pw pw", kdfParams: KDF, recoveryPublicKey: rk.publicKey, recoveryFingerprint: fp })).account;
    const shared = owner.buildCreateSharedVault("Household");
    const writes: string[] = [];
    const feed: SyncResponse = {
      rev: 9,
      full: true,
      vaults: [{ vaultId: shared.vaultId, type: "shared", rev: 3, metaBlob: shared.request.metaBlob, createdAt: 0 }],
      grants: [{ vaultId: shared.vaultId, userId: victim.userId, role: "writer", wrappedVk: "", rev: 3, sealedVk: owner.wrapVkForMember(victim.identityPub, shared.vaultId) }],
      items: [],
      removedGrants: [],
    };
    const api = {
      sync: async () => feed,
      push: async () => ({ rev: 1, results: [] }),
      putPersonalWrap: async () => {},
      accountState: async () => ({ sealedState: null, seq: 0 }),
      putAccountState: async (s: string) => {
        writes.push(s);
        return { sealedState: s, seq: 1 };
      },
    } as unknown as ApiClient;
    const store = new VaultStore(api, victim, undefined, memoryClientState());
    await store.sync();
    expect(victim.hasVault(shared.vaultId)).toBe(true);
    expect(store.accountState.contacts()).toHaveLength(0);
    // The only writes a sync makes on its own are the A1b (LOW-R) member-provenance record and, on the registering
    // device, the A9 personal-vault designation: never a contact.
    for (const w of writes) expect(victim.openAccountState(w).contacts).toHaveLength(0);
    const last = victim.openAccountState(writes[writes.length - 1]!);
    expect(Object.keys(last.memberReceived)).toEqual([shared.vaultId]);
    expect(last.personal?.vaultId).toBe(victim.personalVaultId);
  });
});
