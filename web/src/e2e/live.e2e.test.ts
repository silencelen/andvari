import "fake-indexeddb/auto";
import { IDBFactory as FakeIDBFactory } from "fake-indexeddb";
import { readFileSync, writeFileSync } from "node:fs";
import { beforeAll, describe, expect, it } from "vitest";
import { ApiClient } from "../api/client";
import type { WireItem } from "../api/types";
import { fromB64, toB64 } from "../crypto/bytes";
import { assertServerKdfParams } from "../crypto/keys";
import { randomBytes } from "../crypto/provider";
import { initSodium } from "../crypto/sodium";
import { Account, deviceName } from "../vault/account";
import { shortIdentityFingerprint } from "../crypto/sharedgrant";
import { NullCache, openVaultCache, vaultDbName } from "../vault/idbcache";
import { VaultStore } from "../vault/store";

/**
 * Live end-to-end against a running andvari server (the real shadowJar), reusing the
 * actual web client code paths (Account crypto, VaultStore sync, ApiClient + real
 * WebSocket). Orchestrated by scripts/e2e.sh, which starts/kills the server and runs
 * this in two phases across a SIGKILL to prove crash-durable idempotency.
 *
 * Skipped entirely unless ANDVARI_E2E (base URL) is set.
 */
const BASE = process.env.ANDVARI_E2E;
const PHASE = process.env.ANDVARI_E2E_PHASE ?? "a";
const STATE = process.env.ANDVARI_E2E_STATE ?? "/tmp/andvari-e2e-state.json";
const BOOTSTRAP = process.env.ANDVARI_E2E_BOOTSTRAP ?? "";

interface State {
  email: string;
  password: string;
  userId: string;
  personalVaultId: string;
  tokens: { accessToken: string; refreshToken: string };
  item1Id: string;
  item1MutationId: string;
}

// ---- PHASE C (offline durable cache) raw-IndexedDB inspection/tamper helpers ----
// The cache APIs (idbcache.ts / store.ts) are FROZEN; these read/tamper the DB out of
// band to prove at-rest ciphertext-only, the §B.4 coherence discard, etc.

const idbFactory = (): IDBFactory => (globalThis as { indexedDB?: IDBFactory }).indexedDB!;

function rawReq<T>(r: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });
}

/** Open an EXISTING cache DB at its current version (no schema change / upgrade). */
function rawOpenExisting(name: string): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const r = idbFactory().open(name);
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });
}

/** True iff `sentinel` appears in `s` either RAW or after a base64url decode — ciphertext
 *  decodes to random bytes, so a cleartext leak would surface as ASCII in one of the two. */
function stringHasSentinel(s: string, sentinel: string): boolean {
  if (s.includes(sentinel)) return true;
  if (s.length < 8 || !/^[A-Za-z0-9_-]+$/.test(s)) return false;
  let bytes: Uint8Array;
  try {
    bytes = fromB64(s);
  } catch {
    return false;
  }
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return bin.includes(sentinel);
}

/** Recursively hunt the sentinel through every value — strings (raw + base64-decoded),
 *  byte blobs, arrays, and object properties. Returns a path hint on a hit, else null. */
function deepFindSentinel(v: unknown, sentinel: string, path: string): string | null {
  if (typeof v === "string") return stringHasSentinel(v, sentinel) ? `${path} (string)` : null;
  if (v instanceof Uint8Array || v instanceof ArrayBuffer) {
    const bytes = v instanceof ArrayBuffer ? new Uint8Array(v) : v;
    let bin = "";
    for (const b of bytes) bin += String.fromCharCode(b);
    return bin.includes(sentinel) ? `${path} (bytes)` : null;
  }
  if (Array.isArray(v)) {
    for (let i = 0; i < v.length; i++) {
      const hit = deepFindSentinel(v[i], sentinel, `${path}[${i}]`);
      if (hit) return hit;
    }
    return null;
  }
  if (v && typeof v === "object") {
    for (const k of Object.keys(v)) {
      const hit = deepFindSentinel((v as Record<string, unknown>)[k], sentinel, `${path}.${k}`);
      if (hit) return hit;
    }
    return null;
  }
  return null;
}

/** Enumerate EVERY record + key of EVERY object store and scan for the sentinel (A2 tripwire). */
async function scanCacheForSentinel(dbName: string, sentinel: string): Promise<string | null> {
  const db = await rawOpenExisting(dbName);
  try {
    for (const storeName of Array.from(db.objectStoreNames)) {
      const store = db.transaction(storeName, "readonly").objectStore(storeName);
      const values = await rawReq(store.getAll());
      const keys = await rawReq(store.getAllKeys());
      const vHit = deepFindSentinel(values, sentinel, `${storeName}.value`);
      if (vHit) return vHit;
      const kHit = deepFindSentinel(keys as unknown[], sentinel, `${storeName}.key`);
      if (kHit) return kHit;
    }
    return null;
  } finally {
    db.close();
  }
}

/** Tear the cache out-of-band between sessions (the drill-3 corruption): wipe the grants
 *  store's contents (the design's example), inject a residue row that never came from the
 *  server, and tamper kv:userId so the §B.4 (i) open-time coherence check discards it whole. */
async function tearCache(dbName: string, poison: WireItem): Promise<void> {
  const db = await rawOpenExisting(dbName);
  try {
    const tx = db.transaction(["grants", "items", "kv"], "readwrite");
    tx.objectStore("grants").clear();
    tx.objectStore("items").put(poison);
    tx.objectStore("kv").put({ key: "userId", value: "MALLORY-torn-tamper" });
    await new Promise<void>((resolve, reject) => {
      tx.oncomplete = () => resolve();
      tx.onabort = () => reject(tx.error);
    });
  } finally {
    db.close();
  }
}

describe.skipIf(!BASE)("live server e2e", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("phase A: enroll, push, second client sees it over WebSocket < 2s", async () => {
    if (PHASE !== "a") return;
    const policyResp = await fetch(`${BASE}/api/v1/client-policy`);
    const policy = await policyResp.json();
    const recoveryPub = fromB64((await (await fetch(`${BASE}/api/v1/recovery-pubkey`)).text()).trim());

    const email = "e2e-admin@monahanhosting.com";
    const password = "correct horse battery staple e2e";
    const clientA = new ApiClient(BASE!);
    const { request, account } = await Account.enroll({
      inviteToken: BOOTSTRAP,
      email,
      displayName: "E2E Admin",
      password,
      kdfParams: policy.kdfParams,
      recoveryPublicKey: recoveryPub,
      recoveryFingerprint: policy.recoveryFingerprint,
    });
    const session = await clientA.register(request);
    clientA.setTokens({ accessToken: session.accessToken, refreshToken: session.refreshToken });
    const storeA = new VaultStore(clientA, account);
    await storeA.sync();

    // Second client (same account, fresh device) with a real WebSocket dirty-bell.
    const clientB = new ApiClient(BASE!);
    const pre = await clientB.prelogin(email);
    const authKey = await Account.deriveAuthKey(password, pre.kdfSalt, pre.kdfParams);
    const sessionB = await clientB.login(email, authKey, "e2e-client-b");
    const accountB = await Account.unlock(sessionB.userId, password, sessionB.accountKeys);
    const storeB = new VaultStore(clientB, accountB);
    await storeB.sync();

    let bellRev = 0;
    let wsOpen = false;
    const closeWs = clientB.events((rev) => { bellRev = rev; }, () => {}, () => { wsOpen = true; });
    // The ticket mint adds a REST round-trip before the upgrade — await the actual
    // socket-open signal (a push that beats registration rings no bell; the notifier
    // has no replay), instead of a blind settle window.
    const openDeadline = Date.now() + 5000;
    while (!wsOpen && Date.now() < openDeadline) await new Promise((r) => setTimeout(r, 25));
    expect(wsOpen, "client B's WebSocket opened (ticket mint + upgrade)").toBe(true);

    // A pushes an item.
    const item1Id = account.newItemId();
    const m1 = storeA.putMutation(item1Id, account.personalVaultId, { type: "login", name: "GitHub", login: { username: "jacob", password: "s3cret-e2e" } }, 0);
    await clientA.push([m1]);

    // B should get a bell, then pull + decrypt the item, within 2s.
    const deadline = Date.now() + 2000;
    while (bellRev === 0 && Date.now() < deadline) await new Promise((r) => setTimeout(r, 50));
    expect(bellRev, "client B received a WebSocket rev bell").toBeGreaterThan(0);

    await storeB.sync();
    const seen = storeB.list().find((i) => i.itemId === item1Id);
    expect(seen, "client B decrypted A's item").toBeDefined();
    expect(seen!.doc.login?.password).toBe("s3cret-e2e");
    closeWs();

    // Attachment E2E (P4): A saves an item with an encrypted attachment; B syncs,
    // downloads, and decrypts it byte-for-byte.
    const attData = randomBytes(100_000); // crosses the 64 KiB chunk boundary
    const attRef = { id: crypto.randomUUID(), name: "e2e-blob.bin", size: attData.length, fileKey: toB64(randomBytes(32)) };
    await storeA.save(null, { type: "note", name: "with attachment", attachments: [attRef] }, [{ id: attRef.id, data: attData }]);
    await storeB.sync();
    const withAtt = storeB.list().find((i) => i.doc.name === "with attachment");
    expect(withAtt, "client B sees the attachment item").toBeDefined();
    expect(withAtt!.doc.attachments?.[0]?.id).toBe(attRef.id);
    const refB = withAtt!.doc.attachments![0]!;
    const roundtripped = await storeB.downloadAttachment(withAtt!, refB);
    expect(roundtripped.length, "attachment decrypts to the original size").toBe(attData.length);
    expect(Buffer.from(roundtripped).equals(Buffer.from(attData)), "attachment bytes survive the roundtrip").toBe(true);

    // Invite flow (P4): the admin generates an invite; a BRAND-NEW user registers with
    // it (needs the invite once), then that user's SECOND device only needs email+password.
    const inviteEmail = `e2e-invitee-${Date.now()}@monahanhosting.com`;
    const invite = await clientA.adminInvite(inviteEmail, false);
    expect(invite.inviteToken, "admin got a one-time invite token").toBeTruthy();
    expect(invite.email).toBe(inviteEmail);

    const inviteePw = "invitee master password e2e";
    const clientC = new ApiClient(BASE!);
    const enrolled = await Account.enroll({
      inviteToken: invite.inviteToken,
      email: inviteEmail,
      displayName: "E2E Invitee",
      password: inviteePw,
      kdfParams: policy.kdfParams,
      recoveryPublicKey: recoveryPub,
      recoveryFingerprint: policy.recoveryFingerprint,
    });
    const sessionC = await clientC.register(enrolled.request);
    expect(sessionC.userId, "invitee enrolled a fresh account").toBeTruthy();
    expect(sessionC.isAdmin, "invitee is NOT an admin").toBe(false);

    // Reusing the same invite must fail (one-time).
    const clientDup = new ApiClient(BASE!);
    const dup = await Account.enroll({
      inviteToken: invite.inviteToken, email: inviteEmail, displayName: "dup", password: "x",
      kdfParams: policy.kdfParams, recoveryPublicKey: recoveryPub, recoveryFingerprint: policy.recoveryFingerprint,
    });
    let inviteReused = false;
    try { await clientDup.register(dup.request); } catch { inviteReused = true; }
    expect(inviteReused, "a consumed invite cannot be reused").toBe(true);

    // The invitee's SECOND device: email + password only, no invite. Vault syncs.
    const clientC2 = new ApiClient(BASE!);
    const preC = await clientC2.prelogin(inviteEmail);
    const authKeyC = await Account.deriveAuthKey(inviteePw, preC.kdfSalt, preC.kdfParams);
    const sessionC2 = await clientC2.login(inviteEmail, authKeyC, "invitee-device-2");
    expect(sessionC2.userId, "invitee's 2nd device signs in with just email+password").toBe(sessionC.userId);
    const accountC2 = await Account.unlock(sessionC2.userId, inviteePw, sessionC2.accountKeys);
    const storeC2 = new VaultStore(clientC2, accountC2);
    await storeC2.sync(); // proves the fresh device can pull + decrypt its own (empty) vault

    // Family sharing (P5) over the real routes + WebSocket: admin A creates a shared vault,
    // adds invitee C as writer after the out-of-band fingerprint check, C's dirty-bell fires,
    // C decrypts A's shared item; A removes C; C's next sync purges the vault.
    const share = account.buildCreateSharedVault("Family");
    await clientA.createVault(share.request);
    await storeA.sync();
    await storeA.save(null, { type: "login", name: "shared-wifi", login: { username: "home", password: "sh4red" } }, [], undefined, share.vaultId);

    const lookedUp = await clientA.lookupUser(inviteEmail);
    expect(lookedUp.userId).toBe(sessionC.userId);
    // The fingerprint the owner verifies must equal what the member's own client shows.
    expect(await accountC2.identityFingerprintShort()).toBe(await shortIdentityFingerprint(fromB64(lookedUp.identityPub)));
    const sealedVk = account.wrapVkForMember(fromB64(lookedUp.identityPub), share.vaultId);
    await clientA.addVaultMember(share.vaultId, { userId: sessionC.userId, role: "writer", sealedVk });

    let shareBell = 0;
    let cOpen = false;
    const closeC = clientC2.events((rev) => { shareBell = rev; }, () => {}, () => { cOpen = true; });
    const openBy = Date.now() + 5000;
    while (!cOpen && Date.now() < openBy) await new Promise((r) => setTimeout(r, 25));
    // A already added C above; a fresh push rings C's bell within 2 s.
    await storeA.save(null, { type: "note", name: "shared-note" }, [], undefined, share.vaultId);
    const shareDeadline = Date.now() + 2000;
    while (shareBell === 0 && Date.now() < shareDeadline) await new Promise((r) => setTimeout(r, 50));
    expect(shareBell, "invitee got a WebSocket bell for the shared vault").toBeGreaterThan(0);
    closeC();

    await storeC2.sync();
    expect(storeC2.list().some((i) => i.doc.name === "shared-wifi"), "invitee decrypted the owner's shared item").toBe(true);
    expect(accountC2.roleFor(share.vaultId), "invitee holds the writer role").toBe("writer");

    await clientA.removeVaultMember(share.vaultId, sessionC.userId);
    await storeC2.sync();
    expect(storeC2.list().some((i) => i.vaultId === share.vaultId), "removed member's shared items are purged").toBe(false);
    expect(accountC2.roleFor(share.vaultId), "removed member lost the vault key/role").toBeNull();

    // Cards (0.7.0): a card seals at formatVersion 2 — the one plaintext signal the ZK
    // server holds — and the server's monotonic-fv guard refuses a forged downgrade put
    // (the 0.2.x card-strip rewrite pattern) with the card left intact.
    await storeA.save(null, { type: "card", name: "e2e Visa", card: { number: "4242424242424242", expMonth: "12", expYear: "2030", brand: "visa" } });
    const cardItem = storeA.list().find((i) => i.doc.name === "e2e Visa");
    expect(cardItem, "card item saved + applied locally").toBeDefined();
    const cardRow = (await clientA.sync(0)).items.find((i) => i.itemId === cardItem!.itemId);
    expect(cardRow?.formatVersion, "server row stores the card at formatVersion 2").toBe(2);

    // Forged downgrade: the SAME blob re-declared fv1 against the current rev. The server
    // never opens blobs — the guard compares the integers — so this is exactly the write
    // a card-stripping legacy client would emit.
    const forged = await clientA.push([
      {
        mutationId: crypto.randomUUID(),
        op: "put",
        itemId: cardRow!.itemId,
        vaultId: cardRow!.vaultId,
        baseItemRev: cardRow!.rev,
        item: { formatVersion: 1, attachmentIds: [], blob: cardRow!.blob! },
      },
    ]);
    expect(forged.results[0]?.status, "the fv downgrade is refused, not applied/conflicted").toBe("denied");

    await storeA.sync();
    const cardAfter = storeA.get(cardItem!.itemId);
    expect(cardAfter?.doc.card?.number, "the card still decrypts with its number intact").toBe("4242424242424242");
    const rowAfter = (await clientA.sync(0)).items.find((i) => i.itemId === cardItem!.itemId);
    expect(rowAfter?.formatVersion, "the row is still fv2 after the refused write").toBe(2);
    expect(rowAfter?.rev, "the refused write did not bump the item rev").toBe(cardRow!.rev);

    const state: State = {
      email, password, userId: session.userId, personalVaultId: account.personalVaultId,
      tokens: { accessToken: session.accessToken, refreshToken: session.refreshToken },
      item1Id, item1MutationId: m1.mutationId,
    };
    writeFileSync(STATE, JSON.stringify(state));
  }, 30_000); // several real argon2id (64 MiB) derivations — well past vitest's 5 s default

  it("phase B: after SIGKILL+restart, re-pushing the same mutationId is idempotent", async () => {
    if (PHASE !== "b") return;
    const state: State = JSON.parse(readFileSync(STATE, "utf-8"));
    const client = new ApiClient(BASE!, state.tokens);

    // Server crashed mid-flight; client retries the SAME mutationId. Must not duplicate.
    await initSodium();
    const keys = await client.accountKeys();
    const account = await Account.unlock(state.userId, state.password, keys);
    const store = new VaultStore(client, account);
    await store.sync();

    // Re-encrypt the same item under the same itemId + mutationId and re-push.
    // Idempotency contract (spec 03 §5): the server replays the ORIGINAL result
    // verbatim — same status + same newItemRev — and does NOT create a second item.
    const retry = store.putMutation(state.item1Id, account.personalVaultId, { type: "login", name: "GitHub", login: { username: "jacob", password: "s3cret-e2e" } }, 0);
    retry.mutationId = state.item1MutationId; // the crash-retry uses the ORIGINAL id
    const resp = await client.push([retry]);
    expect(resp.results[0]?.status, "replay returns the original 'applied' result, not a re-execution").toBe("applied");

    await store.sync();
    const gh = store.list().filter((i) => i.doc.name === "GitHub");
    expect(gh.length, "exactly one GitHub item survived the crash — no duplicate from the retry").toBe(1);

    // And normal operation continues post-restart.
    await store.save(null, { type: "note", name: "post-crash note", notes: "still works" });
    await store.sync();
    expect(store.list().some((i) => i.doc.name === "post-crash note")).toBe(true);
  });

  it("phase C: offline durable cache — A2 tripwire, offline unlock, torn-cache resync, queued-save flush", async () => {
    if (PHASE !== "c") return;
    await initSodium();
    const state: State = JSON.parse(readFileSync(STATE, "utf-8"));
    const userId = state.userId;
    // A fixed distinctive literal (Math.random/Date are unavailable in some contexts) that
    // rides an item's plaintext name AND password — the cleartext canary the A2 scan hunts.
    const A2_SENTINEL = "A2-SENTINEL-7f3c9e1b2d4a4c5e-cleartext-canary";
    const DEAD_BASE = "http://127.0.0.1:1"; // closed loopback port ⇒ immediate ECONNREFUSED (transport error)

    // Fresh fake-indexeddb factory so no cross-run IDB residue bleeds into these drills.
    (globalThis as { indexedDB?: IDBFactory }).indexedDB = new FakeIDBFactory() as unknown as IDBFactory;

    // A live client + an account unlocked from the SERVER's accountKeys (models the S3 online
    // unlock that then caches the keys). Reuses the STATE user, surviving the phase-A SIGKILL.
    const live = new ApiClient(BASE!, state.tokens);
    const serverKeys = await live.accountKeys();
    const account = await Account.unlock(userId, state.password, serverKeys);

    // ---- seed a sentinel item on the SERVER (idempotent within a run) ----
    {
      const seedCache = await openVaultCache(userId);
      const seedStore = new VaultStore(live, account, seedCache);
      await seedStore.hydrate();
      await seedStore.sync();
      if (!seedStore.list().some((i) => i.doc.name.includes(A2_SENTINEL))) {
        await seedStore.save(null, {
          type: "login",
          name: `A2 tripwire ${A2_SENTINEL}`,
          login: { username: "canary", password: A2_SENTINEL },
        });
        await seedStore.sync();
      }
      await seedCache.wipe(); // drop the DB so drill 1 repopulates a FRESH cache purely by pull
    }

    // ======================================================================
    // DRILL 1 — A2 ciphertext-only tripwire (THE load-bearing test). Pull the
    // sentinel item into a fresh cache via the real VaultStore, then scan every
    // stored value: the sentinel MUST be absent at rest yet present decrypted.
    // ======================================================================
    const scanCache = await openVaultCache(userId);
    const scanStore = new VaultStore(live, account, scanCache);
    await scanStore.hydrate();
    await scanStore.sync(); // pure pull → ciphertext envelopes/grants/vaults into scanCache
    await scanCache.setAccountKeys(serverKeys); // model the S3 cache-refresh (drill 2 reads it back)

    const decrypted = scanStore.list().find((i) => i.doc.name.includes(A2_SENTINEL));
    expect(decrypted, "A2: the sentinel item decrypts in memory after the pull").toBeDefined();
    const sentinelItemId = decrypted!.itemId;
    // NON-VACUOUS: the sentinel really is present in the DECRYPTED in-memory item (name + password),
    // so the ABSENT-at-rest assertion below is proving something real round-tripped the cache.
    expect(
      JSON.stringify(decrypted!.doc).includes(A2_SENTINEL),
      "A2 PRESENT: sentinel IS in the decrypted in-memory item",
    ).toBe(true);
    expect(decrypted!.doc.login?.password, "A2 PRESENT: the decrypted password is the sentinel").toBe(A2_SENTINEL);
    // ABSENT: no stored value in ANY object store carries the sentinel in cleartext (raw or base64).
    const atRestHit = await scanCacheForSentinel(vaultDbName(userId), A2_SENTINEL);
    expect(
      atRestHit,
      `A2 ABSENT: sentinel must NOT appear in any stored cache value (hit at: ${atRestHit})`,
    ).toBeNull();

    // ======================================================================
    // DRILL 2 — offline hydrate + unlock round-trip. Build an account ONLY from the
    // CACHED keys + password, hydrate ONLY from the cache, server unreachable.
    // ======================================================================
    scanCache.close();
    const deadClient = new ApiClient(DEAD_BASE, state.tokens);
    const offlineCache = await openVaultCache(userId); // the SAME populated DB, reopened cold
    const cachedKeys = await offlineCache.accountKeys();
    expect(cachedKeys, "offline unlock: accountKeys served from the cache with NO server call").not.toBeNull();
    assertServerKdfParams(cachedKeys!.kdfParams); // C3 floor at cache-read (the unlock seam's gate)
    const offlineAccount = await Account.unlock(userId, state.password, cachedKeys!); // pure crypto — offline unlock
    const offlineStore = new VaultStore(deadClient, offlineAccount, offlineCache);
    await offlineStore.hydrate(); // rebuilds the working set from the cache; makes NO server call
    const offlineItem = offlineStore.list().find((i) => i.itemId === sentinelItemId);
    expect(offlineItem, "offline: the item is listable from the cache with the server unreachable").toBeDefined();
    expect(offlineItem!.doc.login?.password, "offline: it decrypts via the cached grant + envelope alone").toBe(A2_SENTINEL);
    // Prove the server is genuinely unreachable — the cache ALONE served the unlock.
    let offlineSyncThrew = false;
    try {
      await offlineStore.sync();
    } catch {
      offlineSyncThrew = true;
    }
    expect(offlineSyncThrew, "offline: a real sync() against the dead client fails (no successful server call)").toBe(true);
    offlineCache.close();

    // ======================================================================
    // DRILL 3 — torn-cache resync convergence. Corrupt the cache between sessions,
    // reopen against the LIVE server, and assert the coherence path DISCARDS the torn
    // cache and resyncs from 0 to a byte-identical item set (no partial-trust residue).
    // ======================================================================
    const goldCache = await openVaultCache(userId);
    const goldStore = new VaultStore(live, account, goldCache);
    await goldStore.hydrate();
    await goldStore.sync();
    const snapshot = (s: VaultStore): string =>
      JSON.stringify(
        s
          .list()
          .map((i) => ({ itemId: i.itemId, vaultId: i.vaultId, doc: i.doc }))
          .sort((a, b) => a.itemId.localeCompare(b.itemId)),
      );
    const golden = snapshot(goldStore);
    expect(goldStore.list().length, "pre-tear: the cache serves a non-empty item set").toBeGreaterThan(0);
    goldCache.close();

    const poison: WireItem = {
      itemId: "TORN-POISON-never-from-server",
      vaultId: "v-torn",
      rev: 1,
      createdAt: 0,
      updatedAt: 0,
      deleted: false,
      conflict: false,
      formatVersion: 1,
      attachmentIds: [],
      blob: "torn-not-real-ciphertext",
    };
    await tearCache(vaultDbName(userId), poison);

    const healedCache = await openVaultCache(userId); // §B.4 (i): foreign kv:userId ⇒ discard EVERY store
    const healedStore = new VaultStore(live, account, healedCache);
    await healedStore.hydrate(); // cold — the torn cache was discarded whole
    await healedStore.sync(); // resync from 0 against the live server
    expect(snapshot(healedStore), "torn-cache heal: the resynced item set is byte-identical to pre-tear").toBe(golden);
    expect(
      healedStore.list().some((i) => i.itemId.startsWith("TORN-POISON")),
      "torn-cache heal: the injected residue row was discarded, never partially trusted",
    ).toBe(false);
    expect(healedStore.list().length, "torn-cache heal: grants were re-fetched so items decrypt again").toBeGreaterThan(0);
    healedCache.close();

    // ======================================================================
    // DRILL 4 — offline queued save → reconnect flush (persist-gated, breaker #1).
    // The node env lacks navigator.storage.persisted; stub it to report GRANTED, else skip.
    // ======================================================================
    let drill4 = "skipped(no-persist-stub)";
    let persistStubbed = false;
    try {
      Object.defineProperty(globalThis, "navigator", {
        configurable: true,
        value: { userAgent: "node-e2e", storage: { persisted: async () => true, estimate: async () => ({ usage: 0, quota: 1e9 }) } },
      });
      persistStubbed = (await navigator.storage.persisted()) === true;
    } catch (e) {
      console.warn(`phase C drill 4: could not stub navigator.storage.persisted — skipping (${(e as Error).message})`);
    }
    if (persistStubbed) {
      const q4Client = new ApiClient(BASE!, state.tokens);
      const q4Cache = await openVaultCache(userId);
      const q4Store = new VaultStore(q4Client, account, q4Cache);
      await q4Store.hydrate();
      await q4Store.sync();

      // Go offline (flip the client's baseUrl to the dead port) and save — persistence granted
      // ⇒ success-as-QUEUED, not push-or-throw.
      q4Client.baseUrl = DEAD_BASE;
      const noteName = `offline-queued-${A2_SENTINEL}-note`;
      await q4Store.save(null, { type: "note", name: noteName, notes: "written while offline" });
      const pendingRows = await q4Cache.pending();
      expect(pendingRows.length, "offline save: exactly one durable queue row").toBe(1);
      const queuedMutation = pendingRows[0]!; // stable mutationId — captured before the flush
      expect(await q4Store.queuedMutationCount(), "offline save: one unsynced mutation").toBe(1);
      const optimistic = q4Store.list().find((i) => i.doc.name === noteName);
      expect(optimistic, "offline save: the item renders optimistically").toBeDefined();
      expect(q4Store.hasPendingSync(optimistic!.itemId), "offline save: carries a pending-sync mark").toBe(true);

      // Reconnect + flush — the queued mutation drains with its STABLE mutationId.
      q4Client.baseUrl = BASE!;
      await q4Store.sync();
      expect(await q4Store.queuedMutationCount(), "reconnect flush: the queue drained").toBe(0);
      expect(q4Store.hasPendingSync(optimistic!.itemId), "reconnect flush: no longer pending sync").toBe(false);

      // SAME mutationId is idempotent: re-pushing converges — the original result replays, no dup.
      const replay = await live.push([queuedMutation]);
      expect(["applied", "duplicate"].includes(replay.results[0]?.status ?? ""), "reconnect flush: replayed mutationId is idempotent").toBe(true);
      const verifyStore = new VaultStore(live, account, new NullCache());
      await verifyStore.sync();
      expect(verifyStore.list().filter((i) => i.doc.name === noteName).length, "reconnect flush: server converged on exactly ONE item").toBe(1);
      q4Cache.close();
      drill4 = "ran(queued→flushed idempotent)";
    }

    // ======================================================================
    // DRILL 5 — wipe/close mid-queue must REFUSE-NOT-DEGRADE, never silent-success
    // (CR-01, the compliance high). With the durable-queue path ARMED (persistence
    // granted), force-close the live cache mid-session (models a sibling-tab wipe /
    // browser-forced close: durable lingers true, every write no-ops §D.2a). A save()
    // while ONLINE must do the REAL send (verifiable enqueue reports the row did not
    // land → demote → direct flushChunk); it must never report success for a write that
    // was neither pushed nor durably queued.
    // ======================================================================
    let drill5 = "skipped(no-persist-stub)";
    if (persistStubbed) {
      const q5Client = new ApiClient(BASE!, state.tokens);
      const q5Cache = await openVaultCache(userId);
      const q5Store = new VaultStore(q5Client, account, q5Cache);
      await q5Store.hydrate();
      await q5Store.sync();

      // Force-close the live handle mid-session — the CR-01 black-hole precondition.
      q5Cache.close();

      const bhName = `forceclose-online-${A2_SENTINEL}-note`;
      // MUST resolve by doing the real send (never throw here — we are online), and MUST NOT
      // silently swallow: a fresh store syncing from the server must SEE the item.
      await q5Store.save(null, { type: "note", name: bhName, notes: "written after a mid-session cache close" });
      expect(q5Store.cacheDurable, "force-close: the store demoted the dead cache to NullCache").toBe(false);

      const verify5 = new VaultStore(live, account, new NullCache());
      await verify5.sync();
      expect(
        verify5.list().filter((i) => i.doc.name === bhName).length,
        "force-close mid-queue online: the save did the REAL send — never a silent black hole (CR-01)",
      ).toBe(1);
      drill5 = "ran(forceclose→real-send,no-blackhole)";
    }

    // Loud, grep-able completion marker for the harness log (proves the drills executed).
    console.log(`PHASE-C-DRILLS-COMPLETE a2=absent+present offlineUnlock=ok tornResync=byte-identical queuedFlush=${drill4} forceCloseRefuse=${drill5}`);
  }, 120_000);
});
