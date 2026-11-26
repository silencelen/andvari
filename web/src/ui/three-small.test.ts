import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { ApiClient } from "../api/client";
import type { SyncResponse } from "../api/types";
import { Account } from "../vault/account";
import { memoryClientState } from "../vault/accountstatesync";
import { NullCache } from "../vault/idbcache";
import { SessionWrap } from "../vault/sessionwrap";
import type { SettingsSession } from "../vault/settingsflow";
import { type ItemWire, VaultStore } from "../vault/store";
import { COPY_FOLLOWS_SERVER } from "./copy";
import { Vault } from "./Vault";

/**
 * Two small faults found by looking at the screens: after a refusal at the unlock or the sign-in, the typed master
 * password stayed in its field; and the line that says this browser's copy was sealed under another master password
 * showed above every view for the whole session instead of above the view the vault opened on, once (Settings
 * included, which is where a sign-in lands when Settings was open before).
 */
const here = dirname(fileURLToPath(import.meta.url));
const src = (f: string) => readFileSync(join(here, f), "utf8");
const OWNER = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const unescape = (s: string) => s.replace(/&#x27;/g, "'").replace(/&quot;/g, '"').replace(/&amp;/g, "&");

function renderVault(hash: string, copySealedElsewhere: boolean): string {
  vi.stubGlobal("window", { location: { hash } });
  const account = Account.fromOpened(
    { userId: OWNER, uvk: new Uint8Array(32).fill(1), identity: { publicKey: new Uint8Array(32), privateKey: new Uint8Array(32) }, signing: { publicKey: new Uint8Array(32), privateKey: new Uint8Array(64) }, genesis: null as never, personalVaultId: null, personalVk: null } as never,
    null,
  );
  const wire = { sync: async () => ({ rev: 1, full: true, vaults: [], grants: [], items: [], removedGrants: [] }) as unknown as SyncResponse } as unknown as ItemWire;
  const store = new VaultStore({} as ApiClient, account, new NullCache(), memoryClientState(), wire);
  const settings = { wrap: new SessionWrap(null) } as unknown as SettingsSession;
  const client = { events: () => () => {} } as unknown as ApiClient;
  return unescape(
    renderToStaticMarkup(
      createElement(Vault, {
        account, store, client, settings, usageWire: {} as never, email: "alice@example.org", policy: null, isAdmin: false,
        mustChangePassword: false, offlineRecoveryReminder: false, onLock: () => {}, onRevoked: () => {}, copySealedElsewhere,
      }),
    ),
  );
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("the copy sealed under another master password: one line above the view the vault opens on", () => {
  it("shows once above the vault list, and once above Settings when the vault opens there", () => {
    for (const hash of ["", "#settings", "#sharing"]) {
      const html = renderVault(hash, true);
      expect(html.split(COPY_FOLLOWS_SERVER).length, hash || "(home)").toBe(2);
    }
    expect(renderVault("#settings", false)).not.toContain(COPY_FOLLOWS_SERVER);
  });

  it("leaving that view ends it for the session: it is tied to the view it opened on, not shown above every view", () => {
    const vault = src("Vault.tsx");
    expect(vault).toContain("const [copyLineView, setCopyLineView] = useState<View | null>(() => (copySealedElsewhere ? view : null));");
    expect(vault).toMatch(/useEffect\(\(\) => \{\s*if \(copyLineView !== null && view !== copyLineView\) setCopyLineView\(null\);\s*\}, \[view, copyLineView\]\);/);
    expect(vault).toContain("{copyLineView !== null && copyLineView === view && (");
    expect(vault).not.toContain("{copySealedElsewhere && (");
  });
});

describe("after a refusal at the unlock or the sign-in the typed password does not stay in its field", () => {
  const welcome = src("Welcome.tsx");
  const fn = (name: string) => welcome.slice(welcome.indexOf(`function ${name}(`), welcome.indexOf("\n}\n", welcome.indexOf(`function ${name}(`)));

  it("the sign-in empties it after every answer but the server's ask for the two-step code, which leaves the code step too", () => {
    const signIn = fn("SignIn");
    expect(signIn).toContain("let keepPassword = false;");
    expect(signIn.match(/keepPassword = true;/g)).toHaveLength(1);
    expect(signIn).toMatch(/case "totp_required":\s*keepPassword = true;\s*setNeedTotp\(true\);\s*return;/);
    expect(signIn).toMatch(/\} finally \{\s*setBusy\(false\);\s*if \(!keepPassword\) \{\s*setPassword\(""\);\s*setTotp\(""\);\s*setNeedTotp\(false\);\s*\}/);
  });

  it("the unlock card and the read-only open of the kept copy empty it after every answer", () => {
    expect(fn("Unlock")).toMatch(/\} finally \{\s*setBusy\(false\);[^}]*setPassword\(""\);\s*\}/);
    expect(fn("HeldCopyUnlock")).toMatch(/\} finally \{\s*setBusy\(false\);\s*setPassword\(""\);/);
  });
});
