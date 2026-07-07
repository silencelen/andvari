import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { ApiClient, ApiError, type SessionEndKind } from "../api/client";
import type { AttachmentRef, ClientPolicy, ItemDoc } from "../api/types";
import { toB64 } from "../crypto/bytes";
import { generatePassword } from "../crypto/generator";
import { hibpCountInRange, hibpPrefix, hibpSha1UpperHex } from "../crypto/hibp";
import { randomBytes } from "../crypto/provider";
import { base32Decode, parseOtpauthUri, totpCode, totpSecondsRemaining } from "../crypto/totp";
import type { Account } from "../vault/account";
import type { PendingUpload, VaultInfo, VaultItem, VaultStore } from "../vault/store";
import { ImportError, type ImportFormat, type ImportPlan, parseCsvImport, planImport } from "../import/csv";
import { isExportOriginAllowed } from "../export/plan";
import { Admin } from "./Admin";
import { ExportPanel, type ExportMode } from "./ExportPanel";
import { humanSize } from "./format";
import { Health } from "./Health";
import { Settings } from "./Settings";
import { Sharing } from "./Sharing";
import { estimateStrength } from "./strength";

type View = "vault" | "sharing" | "health" | "settings" | "admin";

interface Props {
  account: Account;
  store: VaultStore;
  client: ApiClient;
  policy: ClientPolicy | null;
  isAdmin: boolean;
  mustChangePassword: boolean;
  /** F26: locks — keeps the persisted session; the user gets the Unlock card. */
  onLock: () => void;
  /** F26: the session died server-side — full sign-out, not a lock. `kind` says
   *  whether it was an explicit revocation or plain expiry (the copy differs). */
  onRevoked: (kind: SessionEndKind) => void;
}

export function Vault({ account, store, client, policy, isAdmin, mustChangePassword, onLock, onRevoked }: Props) {
  const [view, setView] = useState<View>("vault");
  const [items, setItems] = useState<VaultItem[]>(store.list());
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<string | null>(null);
  const [editing, setEditing] = useState<ItemDoc | null>(null);
  const [importOpen, setImportOpen] = useState(false);
  const [exportMode, setExportMode] = useState<ExportMode | null>(null);
  const [mustChange, setMustChange] = useState(mustChangePassword);
  // Connectivity, split in two so F29's fallback poll has an honest gate:
  //  - wsUp: the dirty-bell socket state (onOpen/onDown from ApiClient.events);
  //  - syncOk: whether the LAST sync attempt landed (marked PENDING at socket open
  //    until the catch-up pull succeeds — green never sits over missed bells).
  // The dot shows their conjunction. Both start optimistic (green) so a healthy unlock
  // never flashes grey; a *sustained* WS drop turns it grey (onDown is debounced ~2.5s).
  const [wsUp, setWsUp] = useState(true);
  const [syncOk, setSyncOk] = useState(true);
  const online = wsUp && syncOk;
  const degraded = !wsUp || !syncOk;
  // Manual "Sync now" (F29): disabled while a click-driven sync is in flight.
  const [syncBusy, setSyncBusy] = useState(false);
  // Type-to-search on unlock is a desktop convenience; autofocusing on touch pops the
  // keyboard over the vault on every open, so gate it to fine (mouse/trackpad) pointers.
  const finePointer = useMemo(
    () => typeof window !== "undefined" && !!window.matchMedia && window.matchMedia("(pointer: fine)").matches,
    [],
  );

  // spec 07 (SHOULD): sessions arriving via the break-glass PUBLIC origin hide both
  // export entry points (T6/T11 posture — don't advertise bulk extraction on the
  // least-trusted surface). The client is served same-origin by the server, so the
  // page origin IS the server origin; see isExportOriginAllowed for the honest-cheap
  // tailnet/LAN/localhost check.
  const exportAllowed = useMemo(
    () => typeof window !== "undefined" && isExportOriginAllowed(window.location.origin),
    [],
  );

  const refresh = () => setItems(store.list());

  // One sync path for the dirty-bell, every (re)open, the F29 offline poll, and the
  // manual "Sync now" button. It never throws (the WS callbacks run un-awaited inside
  // ApiClient.events), and it marks the sync healthy only AFTER a successful pull — so
  // the dot never shows "Connected" over data we failed to fetch. A SyncIntegrityError
  // (store's F31 rollback guard) lands in the same catch: state was kept, dot goes grey.
  const syncNow = useCallback(async () => {
    try {
      await store.sync();
      setItems(store.list());
      setSyncOk(true);
    } catch {
      setSyncOk(false);
    }
  }, [store]);

  // WS dirty-bell → pull. The bell auto-reconnects (client.ts: backoff + fresh ticket per
  // attempt) and onOpen fires on EVERY (re)open, so the sync there catches both the mint
  // round-trip window and any bells missed while the socket was down (no replay server-side).
  // The returned close fn is the effect cleanup — no socket leaks across lock/unlock cycles.
  useEffect(() => {
    const close = client.events(
      () => void syncNow(), // dirty bell
      (kind) => onRevoked(kind), // session died server-side — full sign-out (F26)
      () => {
        setWsUp(true);
        // PENDING until the catch-up pull lands: bells missed while the socket was
        // down aren't caught yet, so the dot must not go green on open alone.
        setSyncOk(false);
        void syncNow();
      },
      () => setWsUp(false), // sustained drop (debounced)
    );
    return close;
  }, [client, syncNow, onRevoked]);

  // F29: with the socket down (WS-stripping proxy, blocked ticket mint) the bell can't
  // ring — and a bell-pull that FAILED with the socket healthy would otherwise never
  // retry. While either is unhealthy, poll over plain HTTP: first tick ~5 s after the
  // socket drops (a normal reconnect blip usually beats it) or ~10 s after a failed
  // sync, then every 60 s. Gating on the combined `degraded` keeps the chain
  // undisturbed across failures (a fail flips no state, so the cadence stays 60 s);
  // it stops the moment both are healthy again (effect cleanup). Timeouts are
  // chained, not an interval, so a slow sync never overlaps the next tick.
  useEffect(() => {
    if (!degraded) return;
    let cancelled = false;
    let timer: number | undefined;
    const tick = async () => {
      await syncNow();
      if (!cancelled) timer = window.setTimeout(() => void tick(), 60_000);
    };
    timer = window.setTimeout(() => void tick(), wsUp ? 10_000 : 5_000);
    return () => {
      cancelled = true;
      if (timer !== undefined) window.clearTimeout(timer);
    };
    // wsUp only picks the first delay — re-arming on its change would reset the chain.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [degraded, syncNow]);

  const manualSync = async () => {
    setSyncBusy(true);
    try {
      await syncNow();
    } finally {
      setSyncBusy(false);
    }
  };

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return items;
    return items.filter((it) => it.doc.name.toLowerCase().includes(q) || (it.doc.login?.username ?? "").toLowerCase().includes(q) || (it.doc.login?.uris?.[0] ?? "").toLowerCase().includes(q));
  }, [items, query]);

  // Vault metadata for badges + the new-item picker (recomputed whenever items refresh).
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const vaultsInfo = useMemo(() => store.vaults(), [store, items]);
  const vaultNameById = useMemo(() => new Map(vaultsInfo.map((v) => [v.vaultId, v.name])), [vaultsInfo]);
  // New items may target the personal vault or any shared vault we can write to.
  const newItemVaultChoices = useMemo(
    () => vaultsInfo.filter((v) => v.type === "personal" || v.role === "owner" || v.role === "writer"),
    [vaultsInfo],
  );
  const hasWritableShared = newItemVaultChoices.some((v) => v.type !== "personal");

  const startNew = (type: "login" | "note") => {
    setSelected(null);
    setImportOpen(false);
    setExportMode(null);
    setEditing(type === "login" ? { type, name: "", login: { username: "", password: "", uris: [""] } } : { type, name: "", notes: "" });
  };

  const openItem = (it: VaultItem) => {
    setSelected(it.itemId);
    setImportOpen(false);
    setExportMode(null);
    setEditing(null);
  };

  const save = async (doc: ItemDoc, newFiles: PendingUpload[], onProgress?: (done: number, total: number) => void, vaultId?: string) => {
    await store.save(selected, doc, newFiles, onProgress, vaultId);
    refresh();
    setEditing(null);
    setSelected(null);
  };

  const remove = async (itemId: string) => {
    await store.remove(itemId);
    refresh();
    setSelected(null);
  };

  const goToItem = (itemId: string) => {
    setView("vault");
    setEditing(null);
    setImportOpen(false);
    setExportMode(null);
    setSelected(itemId);
  };

  const navBtn = (v: View, label: string) => (
    <button className={`navbtn ${view === v ? "active" : ""}`} onClick={() => { setView(v); setEditing(null); setImportOpen(false); setExportMode(null); setSelected(null); }}>{label}</button>
  );

  const current = selected ? store.get(selected) : null;

  return (
    <div>
      <div className="appbar">
        <div className="row">
          <span className="brand"><span className="a-mark">and</span>vari</span>
          <nav className="nav">
            {navBtn("vault", "Vault")}
            {navBtn("sharing", "Sharing")}
            {navBtn("health", "Health")}
            {navBtn("settings", "Settings")}
            {isAdmin && navBtn("admin", "Admin")}
          </nav>
        </div>
        <div className="row">
          <span
            className="muted"
            title={
              online
                ? "Connected"
                : wsUp
                  ? "Last sync failed — will retry"
                  : "Live updates down — checking for changes every 60 s"
            }
          >
            <span className={`dot ${online ? "on" : "off"}`} />
            <span className="userid">{account.userId.slice(0, 8)}</span>
          </span>
          {/* F29: while degraded, let the user pull over plain HTTP right now instead
              of waiting out the poll window. */}
          {!online && (
            <button className="ghost" disabled={syncBusy} onClick={() => void manualSync()}>
              {syncBusy ? "Syncing…" : "Sync now"}
            </button>
          )}
          <button className="ghost" onClick={onLock}>Lock</button>
        </div>
      </div>

      {mustChange && (
        <div className="banner">
          <span>Recovery sign-in — set a new master password now.</span>
          <button className="link" onClick={() => { setView("settings"); setEditing(null); setSelected(null); }}>Go to Settings →</button>
        </div>
      )}

      <div className="wrap">
        {view === "health" ? (
          <Health store={store} client={client} onOpenItem={goToItem} />
        ) : view === "sharing" ? (
          <Sharing account={account} store={store} client={client} onSynced={refresh} />
        ) : view === "settings" ? (
          <Settings client={client} account={account} policy={policy} onPasswordChanged={() => setMustChange(false)} />
        ) : view === "admin" && isAdmin ? (
          <Admin client={client} />
        ) : exportMode ? (
          <ExportPanel
            mode={exportMode}
            account={account}
            store={store}
            policy={policy}
            onClose={() => { setExportMode(null); refresh(); }}
          />
        ) : importOpen ? (
          <ImportPanel
            store={store}
            onClose={() => setImportOpen(false)}
            onDone={() => { setImportOpen(false); refresh(); }}
          />
        ) : editing ? (
          <Editor
            initial={editing}
            policy={policy}
            vaultChoices={selected === null && hasWritableShared ? newItemVaultChoices : undefined}
            onSave={save}
            onCancel={() => setEditing(null)}
          />
        ) : current ? (
          <Detail
            item={current}
            client={client}
            store={store}
            policy={policy}
            readOnly={account.roleFor(current.vaultId) === "reader"}
            vaultName={current.vaultId !== account.personalVaultId ? vaultNameById.get(current.vaultId) : undefined}
            onEdit={() => setEditing(current.doc)}
            onDelete={() => remove(current.itemId)}
            onBack={() => setSelected(null)}
          />
        ) : (
          <>
            <div className="toolbar">
              <input placeholder="Search vault…" value={query} onChange={(e) => setQuery(e.target.value)} autoFocus={finePointer} />
              <button className="ghost" onClick={() => startNew("login")}>+ Login</button>
              <button className="ghost" onClick={() => startNew("note")}>+ Note</button>
              <button className="ghost" onClick={() => { setSelected(null); setEditing(null); setExportMode(null); setImportOpen(true); }}>Import CSV</button>
              {/* Hidden on the public break-glass origin (spec 07 — see exportAllowed). The two
                  export destinations live under one menu so the toolbar can't crush the search box. */}
              {exportAllowed && (
                <ExportMenu
                  onBackup={() => { setSelected(null); setEditing(null); setImportOpen(false); setExportMode("backup"); }}
                  onCsv={() => { setSelected(null); setEditing(null); setImportOpen(false); setExportMode("csv"); }}
                />
              )}
            </div>
            {filtered.length === 0 ? (
              <div className="empty">
                <div className="sigil">ᛝ</div>
                <p>{items.length === 0 ? "Your hoard is empty. Add your first secret." : "Nothing matches that search."}</p>
              </div>
            ) : (
              <div className="list">
                {filtered.map((it) => (
                  <button className="item" key={it.itemId} onClick={() => openItem(it)}>
                    <span className="glyph">{(it.doc.name || "?").charAt(0).toUpperCase()}</span>
                    <span className="body">
                      <div className="name">{it.doc.name || "(untitled)"}</div>
                      <div className="sub">{it.doc.type === "login" ? it.doc.login?.username || it.doc.login?.uris?.[0] || "login" : "secure note"}</div>
                    </span>
                    {it.vaultId !== account.personalVaultId && (
                      <span className="tag" style={{ color: "var(--gold)" }}>{vaultNameById.get(it.vaultId) ?? "shared"}</span>
                    )}
                    <span className="tag">{it.doc.type}</span>
                  </button>
                ))}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}

/** Toolbar "Export ▾" disclosure — folds the two export destinations under one
 *  button (they were the widest toolbar items and crushed the search box in 0.4.0).
 *  Closes on outside-click, Escape, or scroll; supports arrow-key menu navigation;
 *  flips its horizontal anchor so it never renders off the viewport edge on a phone. */
function ExportMenu({ onBackup, onCsv }: { onBackup: () => void; onCsv: () => void }) {
  const [open, setOpen] = useState(false);
  const wrapRef = useRef<HTMLDivElement | null>(null);
  const btnRef = useRef<HTMLButtonElement | null>(null);
  const menuRef = useRef<HTMLDivElement | null>(null);
  const itemRefs = useRef<(HTMLButtonElement | null)[]>([]);

  const close = (returnFocus: boolean) => {
    setOpen(false);
    if (returnFocus) btnRef.current?.focus();
  };

  const toggle = () => setOpen((o) => !o);

  // Clamp the (possibly wider-than-button) menu into the viewport regardless of where the
  // wrapped toolbar put the trigger — the long "Export…" label makes it ~315px, which
  // overflows a phone if simply anchored to one side. Runs pre-paint so there's no flicker.
  useLayoutEffect(() => {
    const m = menuRef.current;
    if (!open || !m) return;
    m.style.transform = "";
    const r = m.getBoundingClientRect();
    let shift = 0;
    if (r.right > window.innerWidth - 8) shift = window.innerWidth - 8 - r.right;
    if (r.left + shift < 8) shift = 8 - r.left;
    if (shift) m.style.transform = `translateX(${Math.round(shift)}px)`;
  }, [open]);

  // Focus the first item when the menu opens (keyboard menu semantics).
  useEffect(() => {
    if (open) itemRefs.current[0]?.focus();
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => { if (wrapRef.current && !wrapRef.current.contains(e.target as Node)) setOpen(false); };
    const onScroll = () => setOpen(false);
    document.addEventListener("mousedown", onDoc);
    // Scroll (esp. touch) would otherwise slide the open menu over the sticky appbar.
    window.addEventListener("scroll", onScroll, true);
    return () => { document.removeEventListener("mousedown", onDoc); window.removeEventListener("scroll", onScroll, true); };
  }, [open]);

  const onMenuKey = (e: React.KeyboardEvent) => {
    const items = itemRefs.current.filter(Boolean) as HTMLButtonElement[];
    const idx = items.indexOf(document.activeElement as HTMLButtonElement);
    if (e.key === "Escape") { e.preventDefault(); close(true); }
    else if (e.key === "ArrowDown") { e.preventDefault(); items[(idx + 1 + items.length) % items.length]?.focus(); }
    else if (e.key === "ArrowUp") { e.preventDefault(); items[(idx - 1 + items.length) % items.length]?.focus(); }
  };

  const choose = (fn: () => void) => { close(false); fn(); };

  return (
    <div className="menu-wrap" ref={wrapRef}>
      <button ref={btnRef} type="button" className="ghost" aria-haspopup="menu" aria-expanded={open} onClick={toggle}>Export ▾</button>
      {open && (
        <div ref={menuRef} className="menu" role="menu" onKeyDown={onMenuKey}>
          <button ref={(el) => { itemRefs.current[0] = el; }} type="button" role="menuitem" onClick={() => choose(onBackup)}>Back up vault…</button>
          <button ref={(el) => { itemRefs.current[1] = el; }} type="button" role="menuitem" onClick={() => choose(onCsv)}>Export for another password manager…</button>
        </div>
      )}
    </div>
  );
}

// ---- copy with auto-clear ----
function useCopy(clearSeconds: number) {
  const [flash, setFlash] = useState<string | null>(null);
  const timer = useRef<number | null>(null);
  const copy = async (label: string, value: string) => {
    await navigator.clipboard.writeText(value);
    setFlash(label);
    if (timer.current) window.clearTimeout(timer.current);
    window.setTimeout(() => setFlash((f) => (f === label ? null : f)), 1200);
    // Auto-clear the clipboard after the policy window (best-effort).
    window.setTimeout(() => navigator.clipboard.writeText("").catch(() => {}), Math.max(1, clearSeconds) * 1000);
  };
  return { flash, copy };
}

function Detail({ item, client, store, policy, readOnly, vaultName, onEdit, onDelete, onBack }: { item: VaultItem; client: ApiClient; store: VaultStore; policy: ClientPolicy | null; readOnly: boolean; vaultName?: string; onEdit: () => void; onDelete: () => Promise<void>; onBack: () => void }) {
  const { flash, copy } = useCopy(policy?.clipboardClearSeconds ?? 30);
  const [deleting, setDeleting] = useState(false);
  const [delBusy, setDelBusy] = useState(false);
  const [delErr, setDelErr] = useState("");
  const doc = item.doc;

  // Mirror the Editor's save path: await the delete, and on failure keep the confirm open
  // with a message instead of silently closing it while the item still exists everywhere.
  // store.remove only throws when the delete did NOT commit (a post-commit reconcile
  // failure is swallowed there), so "nothing was removed" is truthful in every branch —
  // but a 403 is a permissions problem, not a connectivity one, and must say so.
  const confirmDelete = async () => {
    setDelErr("");
    setDelBusy(true);
    try {
      await onDelete(); // resolves → parent unmounts this Detail; no need to reset busy
    } catch (e) {
      setDelErr(
        e instanceof ApiError && e.status === 403
          ? `You don't have permission to delete “${doc.name}” — your access to this vault may have been changed to view-only. Nothing was removed.`
          : e instanceof ApiError
            ? `The server refused to delete “${doc.name}” — nothing was removed. Try again in a moment.`
            : `Couldn't reach the server to delete “${doc.name}” — nothing was removed. Try again when you're connected.`,
      );
      setDelBusy(false);
    }
  };
  return (
    <div className="sheet">
      <button className="link" onClick={onBack}>← back to vault</button>
      <h2 style={{ marginTop: 12 }}>{doc.name}</h2>
      <div className="muted" style={{ marginBottom: 18 }}>
        {doc.type === "login" ? "Login" : "Secure note"}
        {vaultName && <> · in “{vaultName}”</>}
        {readOnly && <> · view only</>}
      </div>

      {doc.type === "login" && doc.login && (
        <>
          {doc.login.username && (
            <div className="field">
              <label>Username</label>
              <div className="secret-row">
                <input readOnly value={doc.login.username} className="mono" />
                <button className="ghost" onClick={() => copy("username", doc.login!.username!)}>Copy</button>
              </div>
            </div>
          )}
          {doc.login.password && (
            <div className="field">
              <label>Password {flash === "password" && <span className="copy-flash">copied ✓</span>}</label>
              <div className="secret-row">
                <PasswordField value={doc.login.password} />
                <button className="ghost" onClick={() => copy("password", doc.login!.password!)}>Copy</button>
              </div>
            </div>
          )}
          {doc.login.totp && <TotpView uri={doc.login.totp} onCopy={(code) => copy("code", code)} />}
          {doc.login.uris?.[0] && (
            <div className="field">
              <label>Website</label>
              <input readOnly value={doc.login.uris[0]} />
            </div>
          )}
          {doc.login.password && <HealthLine password={doc.login.password} client={client} />}
        </>
      )}

      {doc.notes && (
        <div className="field">
          <label>Notes</label>
          <textarea readOnly rows={5} value={doc.notes} />
        </div>
      )}

      {(doc.attachments?.length ?? 0) > 0 && <AttachmentList item={item} store={store} />}

      {/* A reader-role member cannot edit/delete/attach — the push would be denied. */}
      {!readOnly && (
        <>
          {delErr && <div className="msg err" style={{ marginTop: 18 }}>{delErr}</div>}
          <div className="actions">
            {deleting ? (
              <>
                <span className="muted">Delete “{doc.name}” from every device?</span>
                <div className="spacer" />
                <button className="ghost" disabled={delBusy} onClick={confirmDelete} style={{ color: "var(--danger)" }}>{delBusy ? "Deleting…" : "Confirm delete"}</button>
                <button className="ghost" disabled={delBusy} onClick={() => { setDeleting(false); setDelErr(""); }}>Keep</button>
              </>
            ) : (
              <>
                <button className="primary" onClick={onEdit}>Edit</button>
                <div className="spacer" />
                <button className="ghost" onClick={() => setDeleting(true)} style={{ color: "var(--danger)" }}>Delete</button>
              </>
            )}
          </div>
        </>
      )}
    </div>
  );
}

/** Detail-view attachments: download → decrypt → hand the browser a one-shot object URL. */
function AttachmentList({ item, store }: { item: VaultItem; store: VaultStore }) {
  const [busyId, setBusyId] = useState<string | null>(null);
  const [err, setErr] = useState("");

  const download = async (ref: AttachmentRef) => {
    setErr("");
    setBusyId(ref.id);
    try {
      const plain = await store.downloadAttachment(item, ref);
      const url = URL.createObjectURL(new Blob([plain as BlobPart], { type: "application/octet-stream" }));
      const a = document.createElement("a");
      a.href = url;
      a.download = ref.name || "attachment";
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch {
      setErr(`Could not download “${ref.name}” — the blob is missing or failed to decrypt.`);
    } finally {
      setBusyId(null);
    }
  };

  return (
    <div className="field">
      <label>Attachments</label>
      {err && <div className="msg err">{err}</div>}
      <div className="attach-list">
        {item.doc.attachments!.map((ref) => (
          <div className="attach-row" key={ref.id}>
            <span className="attach-name">{ref.name}</span>
            <span className="muted">{humanSize(ref.size)}</span>
            <button type="button" className="ghost" disabled={busyId === ref.id} onClick={() => download(ref)}>
              {busyId === ref.id ? "Opening…" : "Download"}
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}

function PasswordField({ value }: { value: string }) {
  const [show, setShow] = useState(false);
  return (
    <>
      <input readOnly className="mono" type={show ? "text" : "password"} value={value} />
      <button className="ghost" onClick={() => setShow((s) => !s)}>{show ? "Hide" : "Show"}</button>
    </>
  );
}

function TotpView({ uri, onCopy }: { uri: string; onCopy: (code: string) => void }) {
  const [code, setCode] = useState("······");
  const [remaining, setRemaining] = useState(30);
  const [period, setPeriod] = useState(30);
  useEffect(() => {
    let cfg;
    try {
      cfg = parseOtpauthUri(uri);
    } catch {
      setCode("invalid");
      return;
    }
    setPeriod(cfg.periodSeconds);
    const tick = async () => {
      const now = Math.floor(Date.now() / 1000);
      setCode(await totpCode(cfg!, now));
      setRemaining(totpSecondsRemaining(cfg!, now));
    };
    tick();
    const id = window.setInterval(tick, 1000);
    return () => window.clearInterval(id);
  }, [uri]);
  return (
    <div className="field">
      <label>One-time code</label>
      <div className="totp-wrap">
        <button className="totp link" onClick={() => onCopy(code.replace(/\s/g, ""))} title="copy">{code.replace(/(\d{3})(\d{3})/, "$1 $2")}</button>
        <div className="ring" style={{ ["--p" as string]: String((remaining / period) * 100) }} title={`${remaining}s`} />
      </div>
    </div>
  );
}

function HealthLine({ password, client }: { password: string; client: ApiClient }) {
  const [status, setStatus] = useState<string>("");
  const check = async () => {
    setStatus("checking…");
    try {
      const hash = await hibpSha1UpperHex(password);
      const body = await client.hibpRange(hibpPrefix(hash));
      const count = hibpCountInRange(body, hash);
      setStatus(count > 0 ? `⚠ found in ${count.toLocaleString()} breaches — change it` : "✓ not in any known breach");
    } catch {
      setStatus("breach check unavailable");
    }
  };
  return (
    <div style={{ marginTop: 4 }}>
      <button className="link" onClick={check}>Check breach exposure</button>
      {status && <span className="muted" style={{ marginLeft: 10, color: status.startsWith("⚠") ? "var(--danger)" : "var(--ink-dim)" }}>{status}</span>}
    </div>
  );
}

function Editor({ initial, policy, vaultChoices, onSave, onCancel }: { initial: ItemDoc; policy: ClientPolicy | null; vaultChoices?: VaultInfo[]; onSave: (d: ItemDoc, files: PendingUpload[], onProgress?: (done: number, total: number) => void, vaultId?: string) => Promise<void>; onCancel: () => void }) {
  const [doc, setDoc] = useState<ItemDoc>(structuredClone(initial));
  // New items only: which vault to create in (existing items never move vaults).
  const [vaultId, setVaultId] = useState<string | undefined>(vaultChoices?.[0]?.vaultId);
  const [pending, setPending] = useState<PendingUpload[]>([]);
  const [progress, setProgress] = useState<{ done: number; total: number } | null>(null);
  const [fileErr, setFileErr] = useState("");
  const [saveErr, setSaveErr] = useState("");
  const [busy, setBusy] = useState(false);
  const fileInput = useRef<HTMLInputElement | null>(null);
  const isLogin = doc.type === "login";
  const login = doc.login ?? {};

  const setLogin = (patch: Partial<NonNullable<ItemDoc["login"]>>) => setDoc({ ...doc, login: { ...login, ...patch } });

  const gen = () => setLogin({ password: generatePassword() });

  const maxBytes = policy?.attachmentMaxBytes ?? 25 * 1024 * 1024;

  const addFiles = async (files: FileList | null) => {
    if (!files || files.length === 0) return;
    setFileErr("");
    const errors: string[] = [];
    const newRefs: AttachmentRef[] = [];
    const newPending: PendingUpload[] = [];
    for (const file of Array.from(files)) {
      if (file.size === 0) {
        errors.push(`“${file.name}” is empty — empty files can't be attached.`);
        continue;
      }
      if (file.size > maxBytes) {
        errors.push(`“${file.name}” is ${humanSize(file.size)} — over the ${humanSize(maxBytes)} limit.`);
        continue;
      }
      const data = new Uint8Array(await file.arrayBuffer());
      const ref: AttachmentRef = { id: crypto.randomUUID(), name: file.name, size: file.size, fileKey: toB64(randomBytes(32)) };
      newRefs.push(ref);
      newPending.push({ id: ref.id, data });
    }
    if (newRefs.length > 0) {
      setDoc((d) => ({ ...d, attachments: [...(d.attachments ?? []), ...newRefs] }));
      setPending((p) => [...p, ...newPending]);
    }
    if (errors.length > 0) setFileErr(errors.join(" "));
    if (fileInput.current) fileInput.current.value = "";
  };

  const removeAttachment = (id: string) => {
    // Dropping the doc entry is enough — server-side GC reaps the orphaned blob.
    setDoc((d) => ({ ...d, attachments: (d.attachments ?? []).filter((a) => a.id !== id) }));
    setPending((p) => p.filter((f) => f.id !== id));
  };

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    // TOTP normalizes ONCE here (never per keystroke); un-decodable text blocks the save.
    let toSave = doc;
    if (isLogin) {
      const rawTotp = (login.totp ?? "").trim();
      if (rawTotp) {
        const totp = normalizeTotp(rawTotp);
        if (!isValidTotp(totp)) {
          setSaveErr("TOTP secret isn't valid base32 or an otpauth:// link");
          return;
        }
        toSave = { ...doc, login: { ...login, totp } };
      } else if (login.totp) {
        // Field is blank or whitespace-only — persist it as absent, never a " " string the
        // Detail view would treat as truthy and render as a broken TOTP row.
        toSave = { ...doc, login: { ...login, totp: undefined } };
      }
    }
    setBusy(true);
    setSaveErr("");
    setProgress(null);
    try {
      await onSave(toSave, pending, (done, total) => setProgress({ done, total }), vaultId);
    } catch (err) {
      setSaveErr(err instanceof ApiError && err.status === 413 ? `Save rejected: ${err.message || "attachment quota exceeded"}.` : "Save failed — nothing was changed.");
    } finally {
      setBusy(false);
      setProgress(null);
    }
  };

  const attachments = doc.attachments ?? [];
  const pendingIds = new Set(pending.map((p) => p.id));

  return (
    <form className="sheet" onSubmit={submit}>
      <button type="button" className="link" onClick={onCancel}>← cancel</button>
      <h2 style={{ marginTop: 12 }}>{initial.name ? "Edit" : isLogin ? "New login" : "New note"}</h2>
      {vaultChoices && vaultChoices.length > 1 && (
        <div className="field">
          <label>Vault</label>
          <select value={vaultId} onChange={(e) => setVaultId(e.target.value)}>
            {vaultChoices.map((v) => (
              <option key={v.vaultId} value={v.vaultId}>
                {v.name}{v.type === "personal" ? "" : " (shared)"}
              </option>
            ))}
          </select>
        </div>
      )}
      <div className="field">
        <label>Name</label>
        <input autoFocus value={doc.name} onChange={(e) => setDoc({ ...doc, name: e.target.value })} />
      </div>
      {isLogin && (
        <>
          <div className="field">
            <label>Username</label>
            <input className="mono" value={login.username ?? ""} onChange={(e) => setLogin({ username: e.target.value })} />
          </div>
          <div className="field">
            <label>Password</label>
            <div className="secret-row">
              <input className="mono" value={login.password ?? ""} onChange={(e) => setLogin({ password: e.target.value })} />
              <button type="button" className="ghost" onClick={gen}>Generate</button>
            </div>
            {login.password && <StrengthBar password={login.password} />}
          </div>
          <div className="field">
            <label>Website</label>
            {/* Edits uris[0] only; the tail (extra URIs written by other clients) is preserved. */}
            <input value={login.uris?.[0] ?? ""} onChange={(e) => setLogin({ uris: e.target.value ? [e.target.value, ...(login.uris ?? []).slice(1)] : (login.uris ?? []).slice(1) })} placeholder="https://" />
          </div>
          <div className="field">
            <label>TOTP secret (otpauth:// URI or base32)</label>
            {/* RAW text while typing — normalizing per keystroke rewrote the field to an
                otpauth:// URI on the first character. Normalized once, in submit. */}
            <input className="mono" value={login.totp ?? ""} onChange={(e) => setLogin({ totp: e.target.value })} placeholder="optional" />
          </div>
        </>
      )}
      <div className="field">
        <label>Notes</label>
        <textarea rows={isLogin ? 3 : 6} value={doc.notes ?? ""} onChange={(e) => setDoc({ ...doc, notes: e.target.value })} />
      </div>

      <div className="field">
        <label>Attachments</label>
        {fileErr && <div className="msg err">{fileErr}</div>}
        {attachments.length > 0 && (
          <div className="attach-list">
            {attachments.map((ref) => (
              <div className="attach-row" key={ref.id}>
                <span className="attach-name">{ref.name}</span>
                <span className="muted">{humanSize(ref.size)}{pendingIds.has(ref.id) ? " · new" : ""}</span>
                <button type="button" className="ghost" onClick={() => removeAttachment(ref.id)} style={{ color: "var(--danger)" }}>Remove</button>
              </div>
            ))}
          </div>
        )}
        <input ref={fileInput} type="file" multiple style={{ display: "none" }} onChange={(e) => addFiles(e.target.files)} />
        <button type="button" className="ghost" onClick={() => fileInput.current?.click()}>+ Attach files</button>
        <span className="muted" style={{ marginLeft: 10 }}>encrypted on this device · up to {humanSize(maxBytes)} each</span>
      </div>

      {saveErr && <div className="msg err">{saveErr}</div>}
      <div className="actions">
        <button className="primary" disabled={busy || !doc.name}>
          {busy ? (progress && progress.total > 0 ? `Sealing… ${Math.min(progress.done + 1, progress.total)}/${progress.total}` : "Sealing…") : "Save"}
        </button>
        <button type="button" className="ghost" onClick={onCancel}>Cancel</button>
      </div>
    </form>
  );
}

function StrengthBar({ password }: { password: string }) {
  const score = estimateStrength(password);
  const colors = ["var(--danger)", "var(--danger)", "var(--gold)", "var(--ok)", "var(--ok)"];
  return (
    <div className="strength">
      <span style={{ width: `${(score + 1) * 20}%`, background: colors[score] }} />
    </div>
  );
}

/** Accept either a full otpauth URI or a bare base32 secret (wrap the latter). */
function normalizeTotp(input: string): string {
  const t = input.trim();
  if (!t) return "";
  if (t.toLowerCase().startsWith("otpauth://")) return t;
  try {
    base32Decode(t);
    return `otpauth://totp/andvari?secret=${t.replace(/\s/g, "")}`;
  } catch {
    return t;
  }
}

/** True when [normalizeTotp]'s output is a parseable otpauth URI — the save-time gate
 *  (the Detail view would otherwise render the stored value as "invalid" forever). */
function isValidTotp(normalized: string): boolean {
  try {
    parseOtpauthUri(normalized);
    return true;
  } catch {
    return false;
  }
}

// ---- CSV import (spec 06) ----

function friendlyParseError(e: unknown): string {
  if (e instanceof ImportError) {
    switch (e.code) {
      case "too_large":
        return "That file is larger than 10 MiB — far bigger than any real browser password export. Double-check you picked the right file.";
      case "too_many_rows":
        return "That file has more than 10,000 logins. Split it into smaller files and import them one at a time.";
      case "unrecognized_header":
        return "This doesn’t look like a Chrome, Edge, or Firefox password export. In your browser’s password manager choose “Export passwords” and import the CSV it saves.";
      default:
        return `That file could not be read (${e.code}).`;
    }
  }
  return "That file could not be read. Make sure it’s the CSV your browser exported.";
}

function problemLabel(code: string): string {
  switch (code) {
    case "wrong_field_count":
      return "Wrong number of columns";
    case "bad_quote":
      return "Malformed quoting";
    default:
      return "Couldn't read this row";
  }
}

const FORMAT_LABEL: Record<ImportFormat, string> = { chrome: "Chrome / Edge", firefox: "Firefox" };

/**
 * Import a browser CSV export entirely on this device (spec 06): parse + plan locally,
 * preview, then encrypt-and-push. The file never leaves the browser. The plan's itemIds
 * are minted once, so a mid-import failure is fixed with Retry (idempotent replay of the
 * SAME plan) rather than re-parsing — re-parsing would mint new ids and duplicate.
 */
function ImportPanel({ store, onClose, onDone }: { store: VaultStore; onClose: () => void; onDone: () => void }) {
  const fileInput = useRef<HTMLInputElement | null>(null);
  const [fileName, setFileName] = useState("");
  const [format, setFormat] = useState<ImportFormat | null>(null);
  const [plan, setPlan] = useState<ImportPlan | null>(null);
  const [parseErr, setParseErr] = useState("");
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState<{ done: number; total: number } | null>(null);
  const [importErr, setImportErr] = useState("");
  const [finished, setFinished] = useState(false);

  const reset = () => {
    setPlan(null);
    setFormat(null);
    setParseErr("");
    setImportErr("");
    setFinished(false);
    setProgress(null);
  };

  const onFile = async (files: FileList | null) => {
    if (!files || files.length === 0) return;
    const file = files[0]!;
    reset();
    setFileName(file.name);
    try {
      const bytes = new Uint8Array(await file.arrayBuffer());
      const parsed = parseCsvImport(bytes);
      setFormat(parsed.format);
      setPlan(planImport(parsed, () => crypto.randomUUID())); // ids minted ONCE, reused on retry
    } catch (e) {
      setParseErr(friendlyParseError(e));
    } finally {
      if (fileInput.current) fileInput.current.value = "";
    }
  };

  const runImport = async () => {
    if (!plan) return;
    setBusy(true);
    setImportErr("");
    setProgress({ done: 0, total: plan.items.length });
    try {
      // Reuse plan.items on every attempt: each carries its own itemId, used as the push
      // mutationId → the server dedupes an already-applied put, so Retry never duplicates.
      await store.importDocs(plan.items, (done, total) => setProgress({ done, total }));
      setFinished(true);
    } catch {
      setImportErr(
        "The import was interrupted before it finished. Everything that already landed is safe in your vault — press Retry to import the rest (it won’t create duplicates).",
      );
    } finally {
      setBusy(false);
    }
  };

  const report = plan?.report;
  const nothingToImport = plan !== null && plan.items.length === 0;

  return (
    <div className="sheet">
      <button type="button" className="link" onClick={onClose}>← back to vault</button>
      <h2 style={{ marginTop: 12 }}>Import from browser CSV</h2>
      <div className="muted" style={{ marginBottom: 18 }}>Chrome, Edge, or Firefox exported passwords · everything stays on this device</div>

      {/* Always-visible plaintext caution. */}
      <div className="msg info" style={{ display: "block" }}>
        <strong>⚠ This file holds every password in plaintext.</strong> Nothing about it is
        uploaded — parsing happens here in your browser and each login is encrypted before it
        is saved. After importing, delete the CSV and empty your trash. Importing the same file
        again creates duplicate copies.
      </div>

      <input
        ref={fileInput}
        type="file"
        accept=".csv,text/csv,text/plain"
        style={{ display: "none" }}
        onChange={(e) => onFile(e.target.files)}
      />

      {finished ? (
        <>
          <div className="tiles" style={{ marginTop: 4 }}>
            <div className="tile"><div className="tile-value tone-good">{report?.imported ?? 0}</div><div className="tile-label">Imported</div></div>
            {(report?.collapsed ?? 0) > 0 && <div className="tile"><div className="tile-value">{report!.collapsed}</div><div className="tile-label">Merged</div></div>}
            {(report?.flagged.length ?? 0) > 0 && <div className="tile"><div className="tile-value tone-mid">{report!.flagged.length}</div><div className="tile-label">Renamed</div></div>}
            {(report?.skippedEmpty ?? 0) > 0 && <div className="tile"><div className="tile-value">{report!.skippedEmpty}</div><div className="tile-label">Skipped</div></div>}
            {(report?.errors.length ?? 0) > 0 && <div className="tile"><div className="tile-value tone-bad">{report!.errors.length}</div><div className="tile-label">Errors</div></div>}
          </div>
          <div className="msg info" style={{ display: "block" }}>
            Added {report?.imported ?? 0} {(report?.imported ?? 0) === 1 ? "login" : "logins"} to your personal vault.
            Now delete <strong>{fileName || "the CSV file"}</strong> and empty your trash.
          </div>
          <div className="actions">
            <button type="button" className="primary" onClick={onDone}>Done</button>
          </div>
        </>
      ) : plan ? (
        <>
          <div className="muted" style={{ marginBottom: 12 }}>
            {fileName && <>“{fileName}” · </>}detected {format ? FORMAT_LABEL[format] : "browser"} export
          </div>
          <div className="tiles" style={{ marginTop: 4 }}>
            <div className="tile"><div className="tile-value tone-good">{report!.imported}</div><div className="tile-label">To import</div></div>
            <div className="tile"><div className="tile-value">{report!.collapsed}</div><div className="tile-label">Merged (dupes)</div></div>
            <div className="tile"><div className="tile-value tone-mid">{report!.flagged.length}</div><div className="tile-label">Renamed</div></div>
            <div className="tile"><div className="tile-value">{report!.skippedEmpty}</div><div className="tile-label">Skipped (empty)</div></div>
          </div>

          {report!.flagged.length > 0 && (
            <div className="msg info" style={{ display: "block" }}>
              Same site with different passwords — imported separately and renamed for you to review:{" "}
              {report!.flagged.join(", ")}.
            </div>
          )}

          {report!.errors.length > 0 && (
            <div className="field">
              <label>Rows skipped ({report!.errors.length})</label>
              <div className="table-scroll">
                <table className="table">
                  <thead><tr><th>Line</th><th>Problem</th></tr></thead>
                  <tbody>
                    {report!.errors.map((err, idx) => (
                      <tr key={`${err.line}-${idx}`}><td className="mono">{err.line}</td><td>{problemLabel(err.code)}</td></tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {nothingToImport && <div className="msg info" style={{ display: "block" }}>Nothing to import from this file.</div>}
          {importErr && <div className="msg err">{importErr}</div>}

          {busy && progress && (
            <div className="field" style={{ marginTop: 16 }}>
              <label>Importing… {Math.min(progress.done, progress.total)} / {progress.total}</label>
              <div className="strength" style={{ height: 6 }}>
                <span style={{ width: `${progress.total > 0 ? (progress.done / progress.total) * 100 : 0}%`, background: "var(--gold)" }} />
              </div>
            </div>
          )}

          <div className="actions">
            {importErr ? (
              <button type="button" className="primary" disabled={busy} onClick={runImport}>{busy ? "Retrying…" : "Retry"}</button>
            ) : (
              <button type="button" className="primary" disabled={busy || nothingToImport} onClick={runImport}>
                {busy ? "Importing…" : `Import ${report!.imported} ${report!.imported === 1 ? "login" : "logins"}`}
              </button>
            )}
            <div className="spacer" />
            <button type="button" className="ghost" disabled={busy} onClick={() => { reset(); setFileName(""); }}>Choose a different file</button>
          </div>
        </>
      ) : (
        <>
          {parseErr && <div className="msg err">{parseErr}</div>}
          <div className="actions">
            <button type="button" className="primary" onClick={() => fileInput.current?.click()}>Choose CSV file…</button>
            <div className="spacer" />
            <button type="button" className="ghost" onClick={onClose}>Cancel</button>
          </div>
        </>
      )}
    </div>
  );
}
