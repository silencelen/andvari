import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import type { ApiClient } from "./api/client";
import type { ItemDoc, Mutation, MutationResult, PushResponse, SyncResponse, WireGrant, WireItem, WireVault } from "./api/types";
import { fingerprint } from "./crypto/escrow";
import type { KdfParams } from "./crypto/keys";
import { acceptProof, acceptProofFromHash, deleteProof, offerProof, removeProof, restoreProof, verifyProof } from "./crypto/lifecycleproof";
import { boxKeypairFromSeed, randomBytes } from "./crypto/provider";
import { initSodium } from "./crypto/sodium";
import { Account } from "./vault/account";
import { VaultStore } from "./vault/store";

/**
 * Audit 2026-09-13 H41: regression pins for the 0.26.2 (2026-08-30 audit) web + shared-crypto
 * fixes that shipped with no test. Of the ~57 fixes in that release only nine touched a suite,
 * and the untested ones included security controls — a fix nothing pins is a fix nothing keeps.
 * Each block below names its G-row and FAILS if that fix is reverted.
 *
 * Behavioural where a seam exists (G51 on the lifecycle-proof twin, G02 on the real VaultStore
 * against a fake ApiClient — the store.lifecycle.test.ts drive pattern); source pins in the
 * house token-lockstep idiom where the fix lives inside a component closure the node env cannot
 * render (G15, G22, G26, G27, G34, G57, G65).
 */

const here = (p: string) => fileURLToPath(new URL(p, import.meta.url));
const healthTsx = readFileSync(here("./ui/Health.tsx"), "utf8");
const vaultTsx = readFileSync(here("./ui/Vault.tsx"), "utf8");
const unlockTs = readFileSync(here("./ui/unlock.ts"), "utf8");
const stalenessTsx = readFileSync(here("./ui/Staleness.tsx"), "utf8");

/** Source between two markers, both asserted present and in order — a renamed anchor must fail
 *  loudly rather than silently empty the span (an empty span makes every `contains` vacuous). */
function spanOf(src: string, from: string, to: string): string {
  const a = src.indexOf(from);
  expect(a, `span start missing: ${from}`).toBeGreaterThan(-1);
  const b = src.indexOf(to, a + from.length);
  expect(b, `span end missing/out of order: ${to}`).toBeGreaterThan(a);
  return src.slice(a, b);
}

// ---------------------------------------------------------------------------------------------
// G51 — LifecycleProof separator guard (web twin of core's requireDomainSafe)
// ---------------------------------------------------------------------------------------------

describe("G51 — every lifecycle-proof mint refuses a '|' in a server-supplied component", () => {
  // Sodium is initialised in beforeAll; the key is minted from it lazily (a describe-time
  // randomBytes would run before the init).
  let key: Uint8Array;
  beforeAll(async () => {
    await initSodium();
    key = randomBytes(32);
  });

  const vaultId = "55555555-5555-4555-8555-555555555555";
  const id = "66666666-6666-4666-8666-666666666666";
  const userId = "44444444-4444-4444-8444-444444444444";
  const wrapHash = "00ff".repeat(16);
  const bad = "a|b";
  // deleteProof & co. throw SYNCHRONOUSLY before minting (the guard runs ahead of the async
  // mac) — `.then(f)` folds either a sync throw or a rejection into one rejected promise, so a
  // future refactor to `async` keeps this pin valid.
  const refuses = (f: () => Promise<string>) => expect(Promise.resolve().then(f)).rejects.toThrow("must not contain '|'");

  it("delete / restore guard vaultId and deleteId", async () => {
    await refuses(() => deleteProof(key, bad, id));
    await refuses(() => deleteProof(key, vaultId, bad));
    await refuses(() => restoreProof(key, bad, id));
    await refuses(() => restoreProof(key, vaultId, bad));
  });

  it("offer guards vaultId, offerId and toUserId", async () => {
    await refuses(() => offerProof(key, bad, id, userId, 1, 1));
    await refuses(() => offerProof(key, vaultId, bad, userId, 1, 1));
    await refuses(() => offerProof(key, vaultId, id, bad, 1, 1));
  });

  it("acceptProofFromHash guards vaultId, offerId, newOwnerUserId AND the server-relayed wrapHash", async () => {
    await refuses(() => acceptProofFromHash(key, bad, id, userId, 1, wrapHash));
    await refuses(() => acceptProofFromHash(key, vaultId, bad, userId, 1, wrapHash));
    await refuses(() => acceptProofFromHash(key, vaultId, id, bad, 1, wrapHash));
    await refuses(() => acceptProofFromHash(key, vaultId, id, userId, 1, bad));
  });

  it("remove guards vaultId, targetUserId and nonce", async () => {
    await refuses(() => removeProof(key, bad, userId, id));
    await refuses(() => removeProof(key, vaultId, bad, id));
    await refuses(() => removeProof(key, vaultId, userId, bad));
  });

  it("both halves of the aliasing pair refuse — the guard picks no winner", async () => {
    await refuses(() => deleteProof(key, "a|b", "c"));
    await refuses(() => deleteProof(key, "a", "b|c"));
  });

  it("honest ids still mint, and accept() hashes the wrap so a bar inside it is not a boundary", async () => {
    const p = await deleteProof(key, vaultId, id);
    expect(verifyProof(p, await deleteProof(key, vaultId, id))).toBe(true);
    const a = await acceptProof(key, vaultId, id, userId, 1, "wrap|with|bars");
    expect(a).toBe(await acceptProof(key, vaultId, id, userId, 1, "wrap|with|bars"));
  });
});

// ---------------------------------------------------------------------------------------------
// G02 — a stale suppressDrop entry must never let a LATER genuine removal bypass holding
// ---------------------------------------------------------------------------------------------

const KDF: KdfParams = { v: 1, alg: "argon2id13", ops: 1, memBytes: 8192 };
const DOC: ItemDoc = { type: "login", name: "Shared login", login: { username: "fam", password: "hunter2" } };
const emptySync = (rev: number): SyncResponse => ({ rev, full: false, vaults: [], grants: [], items: [], removedGrants: [] });

/** The minimum ApiClient surface the leave/delete → reconcile → re-grant → revoke drive touches. */
class FakeApi {
  queue: SyncResponse[] = [];
  rev = 1;
  /** Throw on the NEXT sync only — the action's own reconcile pull fails, later pulls succeed. */
  failNextSync = false;

  async sync(_since: number): Promise<SyncResponse> {
    if (this.failNextSync) {
      this.failNextSync = false;
      throw new Error("transport down");
    }
    const resp = this.queue.shift() ?? emptySync(this.rev);
    this.rev = Math.max(this.rev, resp.rev);
    return resp;
  }
  async push(mutations: Mutation[]): Promise<PushResponse> {
    const results: MutationResult[] = mutations.map((m) => ({ mutationId: m.mutationId, status: "applied", newItemRev: 1 }));
    return { rev: ++this.rev, results };
  }
  async deleteVault(_id: string, _body: unknown) {
    return { rev: ++this.rev, purgeAt: Date.now() + 7 * 86_400_000 };
  }
  async leaveVault(_id: string) {
    return { rev: ++this.rev };
  }
  asClient(): ApiClient {
    return this as unknown as ApiClient;
  }
}

async function enroll(email: string): Promise<Account> {
  const recovery = boxKeypairFromSeed(randomBytes(32));
  const { account } = await Account.enroll({
    inviteToken: "test-invite",
    email,
    displayName: email,
    password: `pw ${email}`,
    kdfParams: KDF,
    recoveryPublicKey: recovery.publicKey,
    recoveryFingerprint: await fingerprint(recovery.publicKey),
  });
  return account;
}

interface Seed {
  member: Account;
  store: VaultStore;
  api: FakeApi;
  vaultId: string;
  itemId: string;
  vault: WireVault;
  grant: WireGrant;
  item: WireItem;
}

/** A member holding a shared vault (owner-created, VK sealed to the member) at cursor 5. */
async function seededMember(): Promise<Seed> {
  const owner = await enroll("owner@example.com");
  const member = await enroll("member@example.com");
  const { request, vaultId } = owner.buildCreateSharedVault("Family");
  const sealedVk = owner.wrapVkForMember(member.identityPub, vaultId);
  const itemId = owner.newItemId();
  const vault: WireVault = { vaultId, type: "shared", rev: 2, metaBlob: request.metaBlob, createdAt: 0 };
  const grant: WireGrant = { vaultId, userId: member.userId, role: "writer", wrappedVk: "", rev: 3, sealedVk };
  const item: WireItem = {
    itemId,
    vaultId,
    rev: 4,
    createdAt: 0,
    updatedAt: 0,
    deleted: false,
    conflict: false,
    formatVersion: 1,
    attachmentIds: [],
    blob: owner.encryptItem(vaultId, itemId, DOC).blob,
  };
  const api = new FakeApi();
  const store = new VaultStore(api.asClient(), member);
  api.queue.push({ rev: 5, full: true, vaults: [vault], grants: [grant], items: [item], removedGrants: [] });
  await store.sync();
  return { member, store, api, vaultId, itemId, vault, grant, item };
}

/** After the self-initiated action's reconcile FAILED (hard-drop path), the vault is re-granted
 *  and then GENUINELY revoked with no proof. Pre-G02 the suppressDrop entry from the failed
 *  reconcile was still standing, so the later revocation read as self-initiated and hard-dropped
 *  silently — no anomaly notice, nothing in holding. */
async function regrantThenBareRevoke(s: Seed): Promise<void> {
  expect(s.member.hasVault(s.vaultId), "the failed reconcile hard-drops the vault this device left").toBe(false);
  s.api.queue.push({
    rev: 8, full: false, vaults: [{ ...s.vault, rev: 8 }], grants: [{ ...s.grant, rev: 8 }], items: [{ ...s.item, rev: 8 }], removedGrants: [],
  });
  await s.store.sync();
  expect(s.store.get(s.itemId), "re-granted: the vault is live again").toBeDefined();

  s.api.queue.push({ rev: 9, full: false, vaults: [], grants: [], items: [], removedGrants: [s.vaultId], removedGrantsInfo: [] });
  await s.store.sync();
  // The genuine, unproven removal lands in HOLDING with an anomaly — never a clean drop.
  // (`some`, not `find`: the re-grant above legitimately minted an "added" notice first.)
  expect(s.store.notices().some((x) => x.vaultId === s.vaultId && x.kind === "anomaly"), "an anomaly notice").toBe(true);
  expect(s.store.heldVaults().find((h) => h.vaultId === s.vaultId), "parked in holding").toBeDefined();
}

describe("G02 — the self-initiated marker never outlives the action's own reconcile", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("leaveSharedVault: a failed reconcile does not leave a marker that swallows a later genuine revocation", async () => {
    const s = await seededMember();
    s.api.failNextSync = true;
    await s.store.leaveSharedVault(s.vaultId);
    await regrantThenBareRevoke(s);
  });

  it("deleteSharedVault: same rule on the delete leg", async () => {
    const s = await seededMember();
    s.api.failNextSync = true;
    await s.store.deleteSharedVault(s.vaultId);
    await regrantThenBareRevoke(s);
  });

  it("control: a self-initiated leave whose reconcile SUCCEEDS still drops cleanly with no banner", async () => {
    const s = await seededMember();
    s.api.queue.push({ rev: 8, full: false, vaults: [], grants: [], items: [], removedGrants: [s.vaultId], removedGrantsInfo: [{ vaultId: s.vaultId, reason: "left" }] });
    await s.store.leaveSharedVault(s.vaultId);
    expect(s.member.hasVault(s.vaultId)).toBe(false);
    expect(s.store.notices()).toHaveLength(0);
    expect(s.store.heldVaults()).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------------------------
// Source pins — fixes inside component closures the node env cannot render
// ---------------------------------------------------------------------------------------------

describe("G15 — the Duplicates 'open site' href goes through safeSiteHref, never an inline regex", () => {
  it("Health.tsx imports the helper and the differs-cluster link uses it", () => {
    expect(healthTsx).toContain('import { safeSiteHref } from "./safeurl";');
    const dupes = spanOf(healthTsx, "function Duplicates(", "\nfunction ");
    expect(dupes).toContain("const href = safeSiteHref(m.firstUri);");
    expect(dupes).toContain('<a className="link" href={href} target="_blank" rel="noreferrer">');
    // The pre-fix shape: a scheme test that lets javascript:/data: through in a SHARED vault,
    // where the uri was authored by another member.
    expect(dupes).not.toContain("/^https?:\\/\\//i.test(m.firstUri)");
    expect(dupes).not.toContain("href={m.firstUri}");
    expect(dupes).not.toContain("`https://${m.firstUri}`");
  });
});

describe("G22 — Trash Restore/Delete-forever are reader-gated and a 403 is a permission sentence", () => {
  const trash = spanOf(vaultTsx, "function TrashView(", "\nfunction ");

  it("the Vault shell hands TrashView the account's role lookup", () => {
    expect(vaultTsx).toContain("<TrashView store={store} roleFor={(vaultId) => account.roleFor(vaultId)} onRestored={refresh} />");
  });

  it("a reader-role tombstone renders view-only with NO Restore / Delete forever controls", () => {
    expect(trash).toContain('const readOnly = roleFor(d.vaultId) === "reader";');
    expect(trash).toContain('{readOnly && " · view only"}');
    // The action block is gated as a whole — both the purge confirm arm and the two buttons.
    const row = spanOf(trash, 'const readOnly = roleFor(d.vaultId) === "reader";', "</div>\n          );");
    expect(row).toContain("{!readOnly &&");
    expect(row.indexOf("{!readOnly &&")).toBeLessThan(row.indexOf("onClick={() => restore(d)}"));
    expect(row.indexOf("{!readOnly &&")).toBeLessThan(row.indexOf("onClick={() => purge(d.itemId)}"));
  });

  it("both failure arms map the server's 403 (no_grant) to the honest permission sentence, never 'try again'", () => {
    const purge = spanOf(trash, "const purge = async (itemId: string) => {", "const restore = async (");
    expect(purge).toContain("e instanceof ApiError && e.status === 403");
    expect(purge).toContain("You don't have permission to delete items from this vault — your access may have been changed to view-only. Nothing was removed.");
    const restore = spanOf(trash, "const restore = async (", "return (");
    expect(restore).toContain("e instanceof ApiError && e.status === 403");
    expect(restore).toContain("You don't have permission to restore items into this vault — your access may have been changed to view-only. Nothing was changed.");
  });
});

describe("G65 — an unclassifiable failure in the online-unlock sync tail is DEVICE_PROBLEM, never WRONG_PASSWORD", () => {
  it("the fallthrough after the 401 / network / ApiError rungs names the device, not the password", () => {
    // Account.unlock has already SUCCEEDED by this point — the password is cryptographically
    // proven right, so the last rung of this ladder can never be a typo verdict.
    const tail = spanOf(unlockTs, "await net(store.sync());", 'return { kind: "error", message: DEVICE_PROBLEM };');
    expect(tail).toContain('if (e instanceof ApiError && e.status === 401) return { kind: "expired" };');
    expect(tail).toContain('if (e instanceof NetworkError) return { kind: "error", message: UNREACHABLE };');
    expect(tail).toContain('if (e instanceof ApiError) return { kind: "error", message: SERVER_PROBLEM };');
    // Nothing between the last classified rung and the fallthrough may re-introduce the lie.
    const afterServerRung = tail.slice(tail.indexOf("message: SERVER_PROBLEM };"));
    expect(afterServerRung).not.toContain("message: WRONG_PASSWORD");
    expect(afterServerRung).not.toContain("return {");
  });
});

describe("G26 — breach-scan completion is announced, not implied by a label flip", () => {
  it("Health.tsx mints the finished sentence and feeds a persistent Announcer", () => {
    expect(healthTsx).toContain("`Breach scan finished — ${found} login${found === 1 ? \"\" : \"s\"} found in known breaches.`");
    // The sentence is the value handed to the state the Announcer reads, not a stray literal.
    expect(spanOf(healthTsx, "setScanMsg(\n", ");")).toContain("Breach scan finished");
    expect(healthTsx).toContain("<Announcer text={scanMsg} />");
  });
});

describe("G27 / G57 / G34 — the staleness tab's offer names its item, the action column is named, the explainer tells the truth", () => {
  it("the 'marked as gone' offer names the login (the run card has already advanced past it)", () => {
    expect(stalenessTsx).toContain("const offerSentence = offerName ? `“${offerName}” is marked as gone. Remove it from the vault?` : \"\";");
    expect(stalenessTsx).toContain("<span>{offerSentence}</span>");
    expect(stalenessTsx).not.toContain("<span>Marked as gone. Remove it from the vault?</span>");
    // …and the same sentence rides the persistent live region, so AT hears it.
    expect(stalenessTsx).toContain("offerSentence ? offerSentence :");
  });

  it("the action column carries a name for AT and the explainer says the ledger is cross-device", () => {
    expect(stalenessTsx).toContain('<th><span className="visually-hidden">Actions</span></th>');
    expect(stalenessTsx).not.toContain("<th></th>");
    expect(stalenessTsx).toContain("“Last used” syncs across your devices");
    expect(stalenessTsx).not.toContain("comes from this app on this device only");
  });
});
