import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import type { ApiClient } from "./api/client";
import type { ItemDoc, Mutation, MutationResult, PushResponse, SyncResponse, WireItem, WireVault } from "./api/types";
import { randomBytes } from "./crypto/provider";
import { initSodium } from "./crypto/sodium";
import type { Account } from "./vault/account";
import { memoryClientState } from "./vault/accountstatesync";
import { FakeSharedLogs, sharedVaultFixture, testAccount } from "./vault/fakesharedlogs.testkit";
import { NullCache } from "./vault/idbcache";
import { type ItemWire, VaultStore } from "./vault/store";

/**
 * Audit 2026-09-13 H41: regression pins for the 0.26.2 (2026-08-30 audit) web + shared-crypto
 * fixes that shipped with no test. Of the ~57 fixes in that release only nine touched a suite,
 * and the untested ones included security controls — a fix nothing pins is a fix nothing keeps.
 * Each block below names its G-row and FAILS if that fix is reverted.
 *
 * Behavioural where a seam exists (G02 on the real VaultStore; G51's lifecycle-proof pins went with the proofs,
 * design §15's web row;
 * against a fake ApiClient — the store.lifecycle.test.ts drive pattern); source pins in the
 * house token-lockstep idiom where the fix lives inside a component closure the node env cannot
 * render (G15, G22, G26, G27, G34, G57, G65).
 */

const here = (p: string) => fileURLToPath(new URL(p, import.meta.url));
const healthTsx = readFileSync(here("./ui/Health.tsx"), "utf8");
const vaultTsx = readFileSync(here("./ui/Vault.tsx"), "utf8");
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
// G02 — a stale suppressDrop entry must never let a LATER genuine removal bypass holding
// ---------------------------------------------------------------------------------------------

const DOC: ItemDoc = { type: "login", name: "Shared login", login: { username: "fam", password: "hunter2" } };
const emptySync = (rev: number): SyncResponse => ({ rev, full: false, vaults: [], grants: [], items: [], removedGrants: [] });

/** The item routes the leave/delete → reconcile → re-share → removal drive touches. */
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
  async pushMutations(mutations: Mutation[]): Promise<PushResponse> {
    const results: MutationResult[] = mutations.map((m) => ({ mutationId: m.mutationId, status: "applied", newItemRev: 1 }));
    return { rev: ++this.rev, results };
  }
  asWire(): ItemWire {
    return this as unknown as ItemWire;
  }
}

interface Seed {
  member: Account;
  store: VaultStore;
  api: FakeApi;
  logs: FakeSharedLogs;
  vaultId: string;
  vk: Uint8Array;
  itemId: string;
  vault: WireVault;
  item: WireItem;
}

/** A member holding a shared vault (writer, by its verified log) at cursor 5. */
async function seededMember(): Promise<Seed> {
  const member = testAccount("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "cccccccc-cccc-4ccc-8ccc-cccccccccccc");
  const fx = sharedVaultFixture("Family");
  const item = fx.item(DOC, 4);
  const api = new FakeApi();
  const store = new VaultStore({} as ApiClient, member, new NullCache(), memoryClientState(), api.asWire());
  const logs = new FakeSharedLogs(member).attachTo(store);
  logs.share(fx.vaultId, fx.vk, "writer");
  api.queue.push({ rev: 5, full: true, vaults: [fx.vault], grants: [], items: [item], removedGrants: [] });
  await store.sync();
  expect(store.get(item.itemId)?.doc).toEqual(DOC);
  return { member, store, api, logs, vaultId: fx.vaultId, vk: fx.vk, itemId: item.itemId, vault: fx.vault, item };
}

/** After the self-initiated action's reconcile FAILED, the vault is shared again and then removed with a log that
 *  does not explain it. Pre-G02 the suppressDrop entry from the failed reconcile was still standing, so the later
 *  removal read as self-initiated and hard-dropped silently: no anomaly notice, nothing in holding. */
async function reshareThenUnexplainedRemoval(s: Seed): Promise<void> {
  // The failed reconcile left the vault as it was: the log action is committed, a later sync trues up.
  s.logs.share(s.vaultId, s.vk, "writer");
  s.member.logKeyRing().delete(s.vaultId);
  s.api.queue.push({ rev: 8, full: false, vaults: [{ ...s.vault, rev: 8 }], grants: [], items: [{ ...s.item, rev: 8 }], removedGrants: [] });
  await s.store.sync();
  expect(s.store.get(s.itemId), "shared again: the vault is live").toBeDefined();

  s.logs.fail(s.vaultId);
  s.api.queue.push({ rev: 9, full: false, vaults: [], grants: [], items: [], removedGrants: [s.vaultId], removedGrantsInfo: [] });
  await s.store.sync();
  // The removal the log does not explain lands in HOLDING with an anomaly — never a clean drop.
  expect(s.store.notices().some((x) => x.vaultId === s.vaultId && x.kind === "anomaly"), "an anomaly notice").toBe(true);
  expect(s.store.heldVaults().find((h) => h.vaultId === s.vaultId), "parked in holding").toBeDefined();
}

// Log-governed (design §3.7, §3.11): the rule lives in VaultStore.dropAfterOwnLogAction (suppressDrop cleared in a
// finally). The vault logs are FakeSharedLogs (vault/fakesharedlogs.testkit.ts): the test says what the verified log says.
describe("G02 — the self-initiated marker never outlives the action's own reconcile", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("leaveSharedVault: a failed reconcile does not leave a marker that swallows a later unexplained removal", async () => {
    const s = await seededMember();
    s.api.failNextSync = true;
    await s.store.leaveSharedVault(s.vaultId);
    expect(s.logs.appended.map((a) => a.action.kind)).toEqual(["leave"]);
    await reshareThenUnexplainedRemoval(s);
  });

  it("deleteSharedVault: same rule on the delete leg", async () => {
    const s = await seededMember();
    s.logs.share(s.vaultId, s.vk, "owner");
    s.api.failNextSync = true;
    await s.store.deleteSharedVault(s.vaultId);
    expect(s.logs.appended.map((a) => a.action.kind)).toEqual(["delete"]);
    await reshareThenUnexplainedRemoval(s);
  });

  it("control: a self-initiated leave whose reconcile succeeds still drops cleanly with no banner", async () => {
    const s = await seededMember();
    s.api.queue.push({ rev: 8, full: false, vaults: [], grants: [], items: [], removedGrants: [s.vaultId], removedGrantsInfo: [{ vaultId: s.vaultId, reason: "left" }] });
    await s.store.leaveSharedVault(s.vaultId);
    expect(s.member.hasVault(s.vaultId)).toBe(false);
    expect(s.store.get(s.itemId)).toBeUndefined();
    expect(s.store.notices()).toHaveLength(0);
    expect(s.store.heldVaults()).toHaveLength(0);
  });

  it("control: the same removal without the device's own action is an anomaly in holding", async () => {
    const s = await seededMember();
    s.logs.fail(s.vaultId);
    s.api.queue.push({ rev: 8, full: false, vaults: [], grants: [], items: [], removedGrants: [s.vaultId], removedGrantsInfo: [] });
    await s.store.sync();
    expect(s.store.notices().some((x) => x.vaultId === s.vaultId && x.kind === "anomaly")).toBe(true);
    expect(s.store.heldVaults().find((h) => h.vaultId === s.vaultId)).toBeDefined();
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
    // The reader gate, (design §3.13 as decided on 2026-11-17) a vault whose move's deletion waits, and (decided on
    // 23 November 2026) a shared vault whose log is frozen or withheld here.
    expect(trash).toContain('const readOnly = roleFor(d.vaultId) === "reader" || store.moveDeleteWaiting(d.vaultId) || !store.mayWrite(d.vaultId);');
    expect(trash).toContain('{readOnly && " · view only"}');
    // The action block is gated as a whole — both the purge confirm arm and the two buttons.
    const row = spanOf(trash, 'const readOnly = roleFor(d.vaultId) === "reader" || store.moveDeleteWaiting(d.vaultId) || !store.mayWrite(d.vaultId);', "</div>\n          );");
    expect(row).toContain("{!readOnly &&");
    expect(row.indexOf("{!readOnly &&")).toBeLessThan(row.indexOf("onClick={() => restore(d)}"));
    expect(row.indexOf("{!readOnly &&")).toBeLessThan(row.indexOf("onClick={() => purge(d.itemId, d.vaultId)}"));
  });

  it("both failure arms map the server's 403 (no_grant) to the honest permission sentence, never 'try again'", () => {
    const purge = spanOf(trash, "const purge = async (itemId: string, vaultId: string) => {", "const restore = async (");
    expect(purge).toContain("e instanceof ApiError && e.status === 403");
    expect(purge).toContain("You don't have permission to delete items from this vault — your access may have been changed to view-only. Nothing was removed.");
    const restore = spanOf(trash, "const restore = async (", "return (");
    expect(restore).toContain("e instanceof ApiError && e.status === 403");
    expect(restore).toContain("You don't have permission to restore items into this vault — your access may have been changed to view-only. Nothing was changed.");
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
