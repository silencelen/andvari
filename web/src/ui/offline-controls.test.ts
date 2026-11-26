import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import type { ApiClient } from "../api/client";
import type { VaultInfo, VaultStore } from "../vault/store";
import { Account } from "../vault/account";
import { OFFLINE_SETTINGS_WAIT, OFFLINE_SHARING_WAIT, ROLE_LOCKED_NOW, TWO_STEP_TITLE } from "./copy";
import { Settings } from "./Settings";
import { MemberPanel, Sharing } from "./Sharing";

/**
 * While the vault is opened from this browser's offline copy, Sharing and Settings do not offer what needs the server
 * as though it would work: it is disabled, under one line that says why (as the vault view has it). On the panel of a
 * vault whose deletion waits, each member's role carries a mark that it cannot be changed now.
 */
const here = dirname(fileURLToPath(import.meta.url));
const src = (f: string) => readFileSync(join(here, f), "utf8");
const OWNER = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const BOB = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const V = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
const unescape = (s: string) => s.replace(/&#x27;/g, "'").replace(/&quot;/g, '"').replace(/&amp;/g, "&");
const DISABLED = '<fieldset class="needs-server" disabled="">';

const account = Account.fromOpened(
  { userId: OWNER, uvk: new Uint8Array(32).fill(1), identity: { publicKey: new Uint8Array(32), privateKey: new Uint8Array(32) }, signing: { publicKey: new Uint8Array(32), privateKey: new Uint8Array(64) }, genesis: null as never, personalVaultId: null, personalVk: null } as never,
  null,
);
const shared: VaultInfo = { vaultId: V, type: "shared", name: "Family", role: "owner", createdAt: 1 };

/** A store that answers what these views read; anything else answers an empty list. */
const store = (over: Record<string, unknown> = {}) =>
  new Proxy(
    { vaults: () => [shared], incomingTransfers: () => [], sharedLogs: () => null, quota: () => null, lastSyncAt: 0, cacheDurable: false, cacheDemoted: false, queuedMutationCount: () => 0, ...over } as Record<string, unknown>,
    { get: (t, k) => (k in t ? t[k as string] : () => []) },
  ) as unknown as VaultStore;

/** The parts of [html] inside a disabled needs-server fieldset. */
function disabledParts(html: string): string[] {
  const out: string[] = [];
  let i = html.indexOf(DISABLED);
  while (i >= 0) {
    const end = html.indexOf("</fieldset>", i);
    out.push(html.slice(i, end));
    i = html.indexOf(DISABLED, end);
  }
  return out;
}

describe("Settings while the vault is the offline copy", () => {
  const settings = { wire: {}, pins: { pinFor: () => null }, origin: "https://vault.example.org", account: "alice@example.org", opened: {}, wrap: {} } as never;
  const render = (offline: boolean) =>
    unescape(
      renderToStaticMarkup(
        createElement(Settings, {
          client: {} as ApiClient, account, store: store(), policy: null, onPasswordChanged: () => {}, settings, offline,
          email: "alice@example.org", onAccountDeleted: () => {}, onBackup: () => {}, onCsv: () => {},
        }),
      ),
    );

  it("shows the cards that need the server disabled, under one line that says why", () => {
    const html = render(true);
    expect(html).toContain(OFFLINE_SETTINGS_WAIT);
    const off = disabledParts(html).join("\n");
    for (const card of [TWO_STEP_TITLE, "Change master password", "Delete account"]) expect(off, card).toContain(card);
    // What works here without the server stays offered: the backup and the appearance (and the offline copy's own card,
    // which this store-less render does not draw).
    expect(src("./Settings.tsx")).toMatch(/<OfflineCopyCard store=\{store\} userId=\{account.userId\} \/>\s*\{offline && <div className="msg info"/);
    for (const card of ["<h2>Backups</h2>", "<h2>Appearance</h2>"]) {
      expect(html, card).toContain(card);
      expect(off, card).not.toContain(card);
    }
    // The line stands above the first disabled card.
    expect(html.indexOf(OFFLINE_SETTINGS_WAIT)).toBeLessThan(html.indexOf(DISABLED));
    // The walk found the two-factor card asking the server anyway ("Couldn't check … reload", and "Loading…" for
    // good) and the devices card saying it could not load them: offline they ask nothing and wait for nothing.
    expect(html).not.toContain("Loading…");
    expect(src("./Settings.tsx")).toContain("if (offline) return;\n    client.totpStatus()");
    expect(src("./AccountDevices.tsx")).toContain("if (!offline) void load();");
  });

  it("the vault-wide line leaves Sharing and Settings to their own", () => {
    expect(src("./Vault.tsx")).toContain('{fromCopy && !readOnlyCopy && view !== "sharing" && view !== "settings" && (');
  });

  it("online, nothing is disabled and the line is not there", () => {
    const html = render(false);
    expect(html).not.toContain(OFFLINE_SETTINGS_WAIT);
    expect(html).not.toContain(DISABLED);
    expect(html).toContain(TWO_STEP_TITLE);
    expect(html).toContain("Loading…");
  });
});

describe("Sharing while the vault is the offline copy", () => {
  const render = (offline: boolean) =>
    unescape(
      renderToStaticMarkup(
        createElement(Sharing, { account, store: store(), client: {} as ApiClient, onSynced: () => {}, onBackup: () => {}, settingsVaultId: null, onOpenSettings: () => {}, onCloseSettings: () => {}, offline }),
      ),
    );

  it("says why in one line, and making a vault is disabled; the list stays readable", () => {
    const html = render(true);
    expect(html).toContain(OFFLINE_SHARING_WAIT);
    const off = disabledParts(html).join("\n");
    expect(off).toContain(">Create</button>");
    expect(html).toContain('<div class="name">Family</div>');
    expect(off).not.toContain('<div class="name">Family</div>');
  });

  it("online, nothing is disabled and the line is not there", () => {
    const html = render(false);
    expect(html).not.toContain(OFFLINE_SHARING_WAIT);
    expect(html).not.toContain(DISABLED);
  });

  it("the vault view hands its offline state to both, and the vault's own settings layer is disabled too", () => {
    const vault = src("./Vault.tsx");
    expect(vault.match(/offline=\{fromCopy && !readOnlyCopy\}/g)).toHaveLength(2);
    const sharing = src("./Sharing.tsx");
    for (const part of ['needsServer("incoming"', 'needsServer("layer"', 'needsServer("new"', 'needsServer("deleted"']) expect(sharing, part).toContain(part);
    // This browser's held copies stay offered: "Remove from this device" sends nothing.
    expect(sharing).toContain("<RecentlyRemoved store={store} hide={restorableIds} />");
  });
});

describe("the panel of a vault whose deletion waits", () => {
  it("marks each member's role as one that cannot be changed now", () => {
    const s = store({
      moveDeleteWaiting: () => true,
      memberRoster: () => ({ rows: [{ userId: OWNER, role: "owner", label: "me", self: true }, { userId: BOB, role: "writer", label: "Bob", self: false }], mayBeIncomplete: false, stale: false, verified: true }),
      movePlan: () => null,
      pendingTransferFor: () => null,
    });
    const html = unescape(
      renderToStaticMarkup(
        createElement(MemberPanel, {
          vault: shared, store: s, client: { listVaultMembers: async () => [] } as never, onChanged: () => {}, onBackup: () => {}, copying: null, setCopying: () => {}, copiedNote: "", setCopiedNote: () => {}, onDeletedNote: () => {}, onMovedNote: () => {},
        }),
      ),
    );
    expect(html).toContain(`<span class="tag role-locked" title="${ROLE_LOCKED_NOW}">`);
    expect(html).toContain(`writer<span class="visually-hidden">, ${ROLE_LOCKED_NOW}</span>`);
    // The owner's own tag is the plain one: an owner's role is never changed on this panel.
    expect(html).toContain('<span class="tag">owner</span>');
  });
});
