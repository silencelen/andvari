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
import { SessionWrap } from "../vault/sessionwrap";
import type { SettingsSession } from "../vault/settingsflow";
import { type ItemWire, VaultStore } from "../vault/store";
import { KdfPolicyError, WEAK_KDF_MESSAGE } from "../crypto/keys";
import { deleteErrorText } from "./account-delete";
import { CHANGE_NOT_STORED, CHANGE_NOT_STORED_UNDATED, COPY_FOLLOWS_SERVER, fill, KDF_NOT_USABLE, kdfRefusalText, OFFLINE_COPY_UNREADABLE, SERVER_KEYS_NOT_KNOWN_OPENED, SERVER_KEYS_NOT_KNOWN_SETTINGS, WRONG_PASSWORD_KDF_NOT_USABLE } from "./copy";
import { fmtDayYear } from "./format";
import { passwordChangeText } from "./reauthtext";
import { Settings } from "./Settings";
import { Vault } from "./Vault";
import { OfflineCopyUnlockLine, refusalText, unlockCopyStamp, unlockRefusalText } from "./Welcome";

/**
 * Spec 01 §7 on the screens: a vault opened from the copy while the server serves keys this browser does not know says
 * so in a line above every view, for the whole session; the unlock card opens it that way with no password handed on;
 * and when nothing here opens to compare with, the card takes nothing and offers a sign-in.
 */
const here = dirname(fileURLToPath(import.meta.url));
const src = (f: string) => readFileSync(join(here, f), "utf8");
const OWNER = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const unescape = (s: string) => s.replace(/&#x27;/g, "'").replace(/&quot;/g, '"').replace(/&amp;/g, "&");

function renderVault(marked: boolean, copySealedElsewhere = false): string {
  const account = Account.fromOpened(
    { userId: OWNER, uvk: new Uint8Array(32).fill(1), identity: { publicKey: new Uint8Array(32), privateKey: new Uint8Array(32) }, signing: { publicKey: new Uint8Array(32), privateKey: new Uint8Array(64) }, genesis: null as never, personalVaultId: null, personalVk: null } as never,
    null,
  );
  const wire = { sync: async () => ({ rev: 1, full: true, vaults: [], grants: [], items: [], removedGrants: [] }) as unknown as SyncResponse } as unknown as ItemWire;
  const store = new VaultStore({} as ApiClient, account, new NullCache(), memoryClientState(), wire);
  const wrap = new SessionWrap(null);
  if (marked) wrap.markServerKeysNotKnown();
  const settings = { wrap } as unknown as SettingsSession;
  const client = { events: () => () => {} } as unknown as ApiClient;
  return renderToStaticMarkup(
    createElement(Vault, {
      account, store, client, settings, usageWire: {} as never, email: "alice@example.org", policy: null, isAdmin: false,
      mustChangePassword: false, offlineRecoveryReminder: false, onLock: () => {}, onRevoked: () => {}, copySealedElsewhere,
    }),
  );
}

describe("keys on the server this browser does not know (spec 01 §7)", () => {
  it("the vault says so in one line while the session is marked, and not otherwise", () => {
    expect(unescape(renderVault(true))).toContain(SERVER_KEYS_NOT_KNOWN_OPENED);
    expect(unescape(renderVault(false))).not.toContain(SERVER_KEYS_NOT_KNOWN_OPENED);
    // Above every view: the line is not inside a view's own branch; it keeps the content column's width and gutter.
    expect(src("Vault.tsx")).toContain("{settings?.wrap.serverKeysNotKnown === true && (");
    expect(unescape(renderVault(true))).toContain('class="msg err top-prompt"');
  });

  it("the unlock card reads what this browser holds to compare with, opens “leaves both” from the copy with the session marked and no password handed on, and offers a sign-in when nothing is taken", () => {
    const w = src("Welcome.tsx");
    expect(w).toContain("copy: await copyAtUnlock(session.userId)");
    expect(w).toContain('await enter({ opened: r.opened, keys: r.keys, wrap: r.wrap, pending: r.pending, email: session.email, pin: r.pin, cardNotice: r.notice, serverKeysNotKnown: true, flow });');
    expect(w).toMatch(/case "keys_differ":[\s\S]{0,200}setNotKnown\(true\);\s*return;/);
    expect(w).toContain('<button type="button" className="ghost" style={{ width: "100%", marginBottom: 16 }} onClick={() => setSignInInstead(true)}>{SIGN_IN}</button>');
    expect(w).toContain("if (!session.tokens || signInInstead) {");
    // A cost outside the fence is the server's, said as that.
    expect(w).toMatch(/case "kdf_refused":\s*setErr\(KDF_NOT_USABLE\);/);
  });

  it("a served cost that is not whole reads as the server's fault on every screen that shows a refused cost, never as a wrong password", () => {
    const e = new KdfPolicyError("kdf_not_whole", { v: 1, alg: "argon2id13", ops: 3, memBytes: 67_109_376 });
    expect(refusalText(e)).toBe(KDF_NOT_USABLE);
    expect(deleteErrorText(e)).toBe(KDF_NOT_USABLE);
    expect(passwordChangeText({ kind: "refused", code: "kdf_not_whole" })).toBe(KDF_NOT_USABLE);
    expect(kdfRefusalText(e)).toBe(KDF_NOT_USABLE);
    // Below the floor and above the ceiling keep the approved weakened-settings sentence.
    expect(kdfRefusalText(new KdfPolicyError("kdf_below_floor", { v: 1, alg: "argon2id13", ops: 1, memBytes: 8192 }))).toBe(WEAK_KDF_MESSAGE);
    for (const f of ["App.tsx", "Settings.tsx", "Vault.tsx", "account-delete.ts", "Welcome.tsx"]) expect(src(f), f).not.toMatch(/KdfPolicyError\)? \?? ?(return )?\{? ?(message: )?WEAK_KDF_MESSAGE/);
  });

  it("Settings, while marked: every card that asks for the master password is shown unavailable under one line that says why, instead of offered and then refused", () => {
    const html = (marked: boolean) => {
      const wrap = new SessionWrap(null);
      if (marked) wrap.markServerKeysNotKnown();
      const settings = { wire: {}, pins: { pinFor: () => null }, origin: "https://vault.example.org", account: "alice@example.org", opened: {}, wrap } as unknown as SettingsSession;
      const store = new Proxy({ vaults: () => [], incomingTransfers: () => [], sharedLogs: () => null, quota: () => null, lastSyncAt: 0, cacheDurable: false, cacheDemoted: false, queuedMutationCount: () => 0 } as Record<string, unknown>, { get: (t, k) => (k in t ? t[k as string] : () => []) }) as unknown as VaultStore;
      const account = Account.fromOpened(
        { userId: OWNER, uvk: new Uint8Array(32).fill(1), identity: { publicKey: new Uint8Array(32), privateKey: new Uint8Array(32) }, signing: { publicKey: new Uint8Array(32), privateKey: new Uint8Array(64) }, genesis: null as never, personalVaultId: null, personalVk: null } as never,
        null,
      );
      return unescape(renderToStaticMarkup(createElement(Settings, { client: {} as ApiClient, account, store, policy: null, onPasswordChanged: () => {}, settings, email: "alice@example.org", onAccountDeleted: () => {}, onBackup: () => {}, onCsv: () => {} })));
    };
    const on = html(true);
    const DISABLED = '<fieldset class="needs-server" disabled="">';
    expect(on).toContain(SERVER_KEYS_NOT_KNOWN_SETTINGS);
    expect(on.indexOf(SERVER_KEYS_NOT_KNOWN_SETTINGS)).toBeLessThan(on.indexOf(DISABLED));
    const off = on.split(DISABLED).slice(1).map((p) => p.slice(0, p.indexOf("</fieldset>"))).join("\n");
    for (const card of ["Change master password", "Delete account"]) expect(off, card).toContain(card);
    // The backup and the appearance ask for no password and stay offered.
    for (const card of ["<h2>Backups</h2>", "<h2>Appearance</h2>"]) expect(off, card).not.toContain(card);
    const plain = html(false);
    expect(plain).not.toContain(SERVER_KEYS_NOT_KNOWN_SETTINGS);
    expect(plain).not.toContain(DISABLED);
  });

  it("the unlock card never says “last synced” over a copy this browser cannot read, and never makes a copy to find out", async () => {
    const read = (kind: string) => async () => ({ kind });
    expect(await unlockCopyStamp(OWNER, async () => ({ lastSyncAt: 5 }), read("unreadable"))).toEqual({ lastSyncAt: 5, unreadable: true });
    expect(await unlockCopyStamp(OWNER, async () => ({ lastSyncAt: 5 }), async () => Promise.reject(new Error("idb")))).toEqual({ lastSyncAt: 5, unreadable: true });
    expect(await unlockCopyStamp(OWNER, async () => ({ lastSyncAt: 5 }), read("copy"))).toEqual({ lastSyncAt: 5 });
    let opened = false;
    expect(await unlockCopyStamp(OWNER, async () => null, async () => { opened = true; return { kind: "none" }; })).toBeNull();
    expect(opened, "no database: nothing is opened (opening would make one)").toBe(false);
    const line = (stamp: Parameters<typeof OfflineCopyUnlockLine>[0]["stamp"]) => unescape(renderToStaticMarkup(createElement(OfflineCopyUnlockLine, { stamp })));
    expect(line({ lastSyncAt: 5, unreadable: true })).toContain(OFFLINE_COPY_UNREADABLE);
    expect(line({ lastSyncAt: 5, unreadable: true })).not.toContain("last synced");
    expect(line({ lastSyncAt: 5 })).toContain("last synced");
    expect(src("Welcome.tsx")).toContain("void unlockCopyStamp(session.userId).then(");
  });

  it("the line above the views of a vault opened offline keeps the content column's width and gutter, as the keys-not-known line does", () => {
    expect(src("Vault.tsx")).toContain('<div className="msg info top-prompt" style={{ display: "block" }} role="status">{OFFLINE_OPENED}</div>');
  });

  it("a sign-in over this browser's copy: compared before anything is written; another key ends the session with its own sentence; a copy sealed under another password is said in one line above every view, for the session", () => {
    const w = src("Welcome.tsx");
    expect(w).toContain("heldCopy: (userId) => copyAtUnlock(userId),");
    expect(w).toMatch(/case "keys_not_this_account":[\s\S]{0,200}void abandonSignIn\(ctx\.client, flow\);\s*setErr\(SIGN_IN_KEYS_NOT_THIS_ACCOUNT\);\s*return;/);
    // The flag rides to enterVault on both ways in (straight in, and through the kit gate's capture).
    expect(w).toContain("await enter({ opened: r.opened, keys, wrap: r.wrap, email, pin: r.pin, cardNotice: r.notice, password, copySealedElsewhere, flow });");
    expect(w).toContain("setCapture({ opened: r.opened, keys, wrap: r.wrap, email, pin: r.pin, cardNotice: r.notice, kit, password, copySealedElsewhere, flow });");
    expect(src("App.tsx")).toContain("copySealedElsewhere={phase.meta.copySealedElsewhere === true}");
    const html = (flag: boolean) => unescape(renderVault(false, flag));
    expect(html(true)).toContain(COPY_FOLLOWS_SERVER);
    expect(html(true).split(COPY_FOLLOWS_SERVER).length).toBe(2); // one line
    expect(html(false)).not.toContain(COPY_FOLLOWS_SERVER);
    expect(src("Vault.tsx")).toContain('<div className="msg info top-prompt" style={{ display: "block" }} role="status">{COPY_FOLLOWS_SERVER}</div>');
  });

  it("the unlock card's two sentences that say two things: a wrong password with a cost outside the fence, and the new password of a change that never reached the server (with its day)", () => {
    expect(unlockRefusalText({ kind: "wrong_password_kdf_refused" })).toBe(WRONG_PASSWORD_KDF_NOT_USABLE);
    expect(unlockRefusalText({ kind: "wrong_password_kdf_refused" })).not.toBe(KDF_NOT_USABLE);
    const at = 1763251200000;
    expect(unlockRefusalText({ kind: "change_not_stored", at })).toBe(fill(CHANGE_NOT_STORED, fmtDayYear(at)));
    expect(unlockRefusalText({ kind: "change_not_stored", at: null })).toBe(CHANGE_NOT_STORED_UNDATED);
    expect(src("Welcome.tsx")).toMatch(/case "wrong_password_kdf_refused":\s*case "change_not_stored":\s*setErr\(unlockRefusalText\(r\)\);\s*return;/);
  });

  it("enterVault: a marked session writes nothing to the copy, keeps its pending wraps, and runs no re-key", () => {
    const o = src("opensession.ts");
    expect(o).toMatch(/if \(notKnown\) \{\s*account\.sessionWrap\.markServerKeysNotKnown\(\);\s*if \(params\.pendingWraps !== undefined\) account\.sessionWrap\.adoptPending\(params\.pendingWraps\);\s*\} else if \(mode === "online"\) \{/);
  });
});
