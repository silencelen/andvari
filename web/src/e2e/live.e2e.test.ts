import { readFileSync, writeFileSync } from "node:fs";
import { beforeAll, describe, expect, it } from "vitest";
import { ApiClient } from "../api/client";
import { fromB64, toB64 } from "../crypto/bytes";
import { randomBytes } from "../crypto/provider";
import { initSodium } from "../crypto/sodium";
import { Account, deviceName } from "../vault/account";
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
    const closeWs = clientB.events((rev) => { bellRev = rev; }, () => {});
    await new Promise((r) => setTimeout(r, 300)); // let the socket connect

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

    const state: State = {
      email, password, userId: session.userId, personalVaultId: account.personalVaultId,
      tokens: { accessToken: session.accessToken, refreshToken: session.refreshToken },
      item1Id, item1MutationId: m1.mutationId,
    };
    writeFileSync(STATE, JSON.stringify(state));
  });

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
});
