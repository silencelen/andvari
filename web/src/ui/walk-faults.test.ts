import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import type { ApiClient } from "../api/client";
import type { SyncResponse } from "../api/types";
import { Account } from "../vault/account";
import { memoryClientState } from "../vault/accountstatesync";
import { NullCache } from "../vault/idbcache";
import { type ItemWire, type VaultInfo, VaultStore } from "../vault/store";
import { CREATE_ACCOUNT_HERE, fill, MOVE_UNFINISHED, MOVE_WAITING_LOCKED, OFFLINE_COPY_OFFER, OFFLINE_OPENED, SIGN_IN } from "./copy";
import { MemberPanel, UnfinishedMoves } from "./Sharing";
import { Vault } from "./Vault";
import { vaultLabel, vaultLabels } from "./vaultlabel";
import { FreshStart } from "./Welcome";

/**
 * What the 2026-11-16 browser walk listed and did not fix: (a) a vault opened from the offline copy says so and offers
 * nothing that needs the server as though it would work; (b) the one-time question says when the copy is made; (c) a
 * profile the server signed out offers "Sign in" first; (d) the old vault's panel while a move's deletion waits offers
 * none of the actions its log refuses, and says why; (e) two vaults of one name are told apart by when each was made.
 */
const here = dirname(fileURLToPath(import.meta.url));
const src = (f: string) => readFileSync(join(here, f), "utf8");
const V = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
const NEW = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";
const OWNER = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const BOB = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

function plainStore(): { account: Account; store: VaultStore } {
  const account = Account.fromOpened(
    { userId: OWNER, uvk: new Uint8Array(32).fill(1), identity: { publicKey: new Uint8Array(32), privateKey: new Uint8Array(32) }, signing: { publicKey: new Uint8Array(32), privateKey: new Uint8Array(64) }, genesis: null as never, personalVaultId: null, personalVk: null } as never,
    null,
  );
  const wire = { sync: async () => ({ rev: 1, full: true, vaults: [], grants: [], items: [], removedGrants: [] }) as unknown as SyncResponse } as unknown as ItemWire;
  return { account, store: new VaultStore({} as ApiClient, account, new NullCache(), memoryClientState(), wire) };
}

function renderVault(openedFromCopy: boolean): string {
  const { account, store } = plainStore();
  const client = { events: () => () => {} } as unknown as ApiClient;
  return renderToStaticMarkup(
    createElement(Vault, {
      account, store, client, usageWire: {} as never, email: "alice@example.org", policy: null, isAdmin: false, openedFromCopy,
      mustChangePassword: false, offlineRecoveryReminder: false, onLock: () => {}, onRevoked: () => {},
    }),
  );
}

const unescape = (s: string) => s.replace(/&#x27;/g, "'").replace(/&quot;/g, '"').replace(/&amp;/g, "&");

describe("(a) a vault opened from the offline copy", () => {
  it("says so in a line above every view, and says nothing of it when opened online", () => {
    expect(unescape(renderVault(true))).toContain(OFFLINE_OPENED);
    expect(unescape(renderVault(false))).not.toContain(OFFLINE_OPENED);
  });

  it("the unlock's mode reaches the vault, and the line stays until a pull reaches the server", () => {
    expect(src("./opensession.ts")).toContain("openedFrom: mode, ");
    expect(src("./App.tsx")).toContain('openedFromCopy={phase.meta.openedFrom === "offline"}');
    const vault = src("./Vault.tsx");
    expect(vault).toContain("if (store.lastSyncAt !== copySyncedAt.current) setFromCopy(false);");
    // What needs the server waits: shares to accept, a move to finish, the recovery copy's re-seal; the retry says what it is.
    expect(vault).toContain("{!fromCopy && <SharedPrompts");
    expect(vault).toContain("{!readOnlyCopy && !fromCopy && <UnfinishedMoves");
    expect(vault).toContain("<EscrowPrompt settings={readOnlyCopy || fromCopy ? undefined : settings}");
    expect(vault).toContain('fromCopy ? OFFLINE_TRY_SERVER : "Sync now"');
  });
});

describe("(b) the one-time question about the offline copy", () => {
  it("says the copy is made at the next unlock or sign-in (making it at once would need keys this page no longer holds)", () => {
    expect(OFFLINE_COPY_OFFER).toContain("It is made the next time you unlock or sign in here");
  });
});

describe("(c) a profile the server signed out", () => {
  const pin = { name: "", origin: "https://vault.example.org", root: "baked", instanceId: "i" } as never;
  const render = (knownEmail?: string) =>
    renderToStaticMarkup(
      createElement(FreshStart, {
        ctx: {} as never, policy: { signup: { mode: "open", full: false } } as never, policyError: false, onRetryPolicy: async () => {}, mode: { fresh: true } as never,
        onReady: () => {}, onForget: () => {}, pin, cardNotice: null, ...(knownEmail ? { knownEmail } : {}),
      }),
    );

  it("knowing its account, offers “Sign in” first, as the primary", () => {
    const html = render("alice@example.org");
    expect(html.indexOf(SIGN_IN)).toBeGreaterThan(-1);
    expect(html.indexOf(SIGN_IN)).toBeLessThan(html.indexOf(CREATE_ACCOUNT_HERE));
    expect(html).toMatch(new RegExp(`<button class="primary"[^>]*>${SIGN_IN}</button>`));
    expect(html).toMatch(new RegExp(`<button class="secondary"[^>]*>${CREATE_ACCOUNT_HERE}</button>`));
  });

  it("a fresh profile keeps the design's order", () => {
    const html = render();
    expect(html.indexOf(CREATE_ACCOUNT_HERE)).toBeLessThan(html.indexOf(SIGN_IN));
  });

  it("App hands the ended session's address to the first screen only for a session the server ended", () => {
    const app = src("./App.tsx");
    expect(app).toContain('const knownEmail = kind === "user" ? undefined : loadSession()?.email || undefined;');
    expect(app).toContain("knownEmail={phase.kind === \"welcome\" ? phase.knownEmail : undefined}");
  });
});

describe("(d) the old vault's panel while a move's deletion waits", () => {
  const vault: VaultInfo = { vaultId: V, type: "shared", name: "Bob's", role: "owner", createdAt: 1 };
  function panel(waiting: boolean): string {
    const store = new Proxy(
      {
        moveDeleteWaiting: () => waiting,
        memberRoster: () => ({ rows: [{ userId: OWNER, role: "owner", label: "me", self: true }, { userId: BOB, role: "writer", label: "Bob", self: false }], mayBeIncomplete: false, stale: false, verified: true }),
        movePlan: () => ({ resume: { name: "Bob's 2", newVaultId: NEW, copied: 2 }, members: [], sourceStays: false }),
        vaults: () => [vault, { vaultId: NEW, type: "shared", name: "Bob's 2", role: "owner", createdAt: 2 }],
        sharedLogs: () => null,
        pendingTransferFor: () => null,
      } as Record<string, unknown>,
      { get: (t, k) => (k in t ? t[k as string] : () => []) },
    ) as unknown as VaultStore;
    return unescape(
      renderToStaticMarkup(
        createElement(MemberPanel, {
          vault, store, client: { listVaultMembers: async () => [] } as never, onChanged: () => {}, onBackup: () => {}, copying: null, setCopying: () => {}, copiedNote: "", setCopiedNote: () => {}, onDeletedNote: () => {}, onMovedNote: () => {},
        }),
      ),
    );
  }

  it("offers none of the actions its log refuses, says why in one line, and keeps “Finish the move”", () => {
    const html = panel(true);
    expect(html).toContain(fill(MOVE_WAITING_LOCKED, "Bob's"));
    for (const gone of [">Rename<", ">Remove<", "<select", "Delete vault", "Offer ownership"]) expect(html, gone).not.toContain(gone);
    expect(html).toContain("Finish the move");
  });

  it("without a waiting deletion the owner's controls are there as before", () => {
    const html = panel(false);
    expect(html).not.toContain(fill(MOVE_WAITING_LOCKED, "Bob's"));
    for (const there of [">Rename<", ">Remove<", "<select", "Delete vault"]) expect(html, there).toContain(there);
  });
});

describe("(e) two vaults of one name", () => {
  const a = { vaultId: V, name: "Trip 2", createdAt: Date.UTC(2026, 10, 16, 20, 5) };
  const b = { vaultId: NEW, name: "Trip 2", createdAt: Date.UTC(2026, 10, 16, 21, 31) };
  const c = { vaultId: BOB, name: "Family", createdAt: 3 };

  it("each says when it was made; a name no other vault bears is shown as it is", () => {
    const labels = vaultLabels([a, b, c]);
    expect(labels.get(V)).toMatch(/^Trip 2 \(made .+\)$/);
    expect(labels.get(NEW)).toMatch(/^Trip 2 \(made .+\)$/);
    expect(labels.get(V)).not.toBe(labels.get(NEW));
    expect(labels.get(BOB)).toBe("Family");
    expect(vaultLabel(a, [a, c])).toBe("Trip 2");
  });

  it("the move's sentences name them so", () => {
    const store = {
      unfinishedMoves: () => [{ vaultId: V, name: "Trip 2", newVaultId: NEW, newName: "Trip 2", added: [] }],
      vaults: () => [a, b, c],
    } as unknown as VaultStore;
    const html = unescape(renderToStaticMarkup(createElement(UnfinishedMoves, { store, onChanged: () => {} })));
    const labels = vaultLabels([a, b, c]);
    expect(html).toContain(fill(MOVE_UNFINISHED, labels.get(V)!, labels.get(NEW)!));
  });

  it("the lists and pickers that name vaults use the labels", () => {
    // The Sharing list says it on the row's second line (a phone cut the longer name short, the walk found).
    expect(src("./Sharing.tsx")).toContain('{vaultLabel(v, vaults) !== v.name ? ` · ${fill(SAME_NAME_MADE_LINE, madeWhen(v.createdAt))}` : ""}');
    const vault = src("./Vault.tsx");
    expect(vault).toContain("const vaultLabelById = useMemo(() => vaultLabels(vaultsInfo), [vaultsInfo]);");
    expect(vault).toContain("{vaultLabelById.get(v.vaultId) ?? v.name}</option>");
    // An item row's tag keeps the plain name: the label pushed the item's own name out of the row on a phone.
    expect(vault).toContain("const vaultNameById = useMemo(() => new Map(vaultsInfo.map((v) => [v.vaultId, v.name])), [vaultsInfo]);");
    expect(vault.match(/vaultLabel\(v, (targets|vaultChoices)\)/g)).toHaveLength(3);
  });
});
