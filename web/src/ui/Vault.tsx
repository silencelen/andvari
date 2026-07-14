import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState, type ReactElement } from "react";
import { ApiClient, ApiError, type SessionEndKind } from "../api/client";
import type { AttachmentRef, ClientPolicy, ItemDoc } from "../api/types";
import { toB64 } from "../crypto/bytes";
import { shortFormMatches } from "../crypto/escrow";
import { generatePassword } from "../crypto/generator";
import { hibpCountInRange, hibpPrefix, hibpSha1UpperHex } from "../crypto/hibp";
import { randomBytes } from "../crypto/provider";
import { normalizeTotp, parseOtpauthUri, totpCode, totpSecondsRemaining } from "../crypto/totp";
import type { Account } from "../vault/account";
import { CARD_CREATE_ENABLED, brand, brandLabel, cardSubtitle, digitsOnly, expiryLabel, groupNumber, isExpired, luhnValid, padMonth, yearTo4 } from "../vault/card";
import {
  CopyDeniedError,
  ItemChangedError,
  type LifecycleNotice,
  type MoveGesture,
  type PendingUpload,
  type VaultInfo,
  type VaultItem,
  type VaultStore,
} from "../vault/store";
import { ImportError, type ImportFormat, type ImportPlan, type ImportReport, type Parsed, type ParsedRow, parseCsvImport, planImport, rowOrdinalsByLine } from "../import/csv";
import { isExportOriginAllowed } from "../export/plan";
import { Admin } from "./Admin";
import { ExportPanel, type ExportMode } from "./ExportPanel";
import { Field } from "./Field";
import { humanSize } from "./format";
import { Announcer, Msg } from "./Msg";
import { Health } from "./Health";
import { Settings } from "./Settings";
import { Sharing } from "./Sharing";
import { EmptySigil } from "./Sigil";
import { estimateStrength } from "./strength";
import { windowRange, type WindowRange } from "./virtual";

type View = "vault" | "sharing" | "health" | "settings" | "admin" | "trash";

/**
 * F76: make hardware/gesture Back step through the vault's open UI layers instead of leaving
 * the SPA — leaving drops the in-memory keys and costs a full argon2 unlock. While any layer
 * is open ([deep]) we keep ONE sentinel history entry armed; a real Back pops it, we close the
 * topmost layer ([closeTop]) and re-arm. When the last layer is closed via an in-app control
 * we consume the sentinel with a self-initiated back() (flagged so the handler ignores it), so
 * no dangling entry lingers. A lock/sign-out unmounts Vault → the effect cleanup drops the
 * listener; a stray sentinel is harmless (same-URL pushState, consumed by the next Back).
 */
function useBackGuard(deep: boolean, closeTop: () => void) {
  const armed = useRef(false);
  const selfPop = useRef(false);
  const deepRef = useRef(deep);
  const closeRef = useRef(closeTop);
  deepRef.current = deep;
  closeRef.current = closeTop;

  useEffect(() => {
    if (typeof window === "undefined") return;
    const onPop = () => {
      if (selfPop.current) {
        selfPop.current = false;
        armed.current = false;
        return;
      }
      if (deepRef.current) {
        closeRef.current(); // close exactly one layer
        window.history.pushState({ andvariBack: true }, ""); // re-arm — the browser consumed our sentinel
      } else {
        armed.current = false; // nothing open — let the pop stand (navigate away)
      }
    };
    window.addEventListener("popstate", onPop);
    return () => {
      window.removeEventListener("popstate", onPop);
      // Lock / sign-out can unmount us with a layer still open (deep→shallow never fires, so
      // effect-2's self-pop never runs). Consume the armed sentinel here or it lingers as the
      // current history top and — across repeated lock cycles — accumulates, each stray
      // silently eating a later Back press. The listener is already detached, so this same-URL
      // pop is invisible. (A mid-layer browser RELOAD can't be reconciled — no cleanup runs —
      // but a reload already dropped the keys, so F76's "don't waste an unlock" point is moot.)
      if (armed.current) window.history.back();
    };
  }, []);

  useEffect(() => {
    if (typeof window === "undefined") return;
    if (deep && !armed.current) {
      window.history.pushState({ andvariBack: true }, "");
      armed.current = true;
    } else if (!deep && armed.current) {
      selfPop.current = true; // a layer closed via an in-app control — reclaim our sentinel
      window.history.back();
    }
  }, [deep]);
}

interface Props {
  account: Account;
  store: VaultStore;
  client: ApiClient;
  /** F80: the signed-in email for the appbar — a raw userId prefix reads as debug
   *  output. Empty when the persisted session predates the field (fallback below). */
  email: string;
  policy: ClientPolicy | null;
  isAdmin: boolean;
  mustChangePassword: boolean;
  /** F57: this account's escrow is sealed to a superseded recovery key — offer a re-seal. */
  escrowStale: boolean;
  /** F57: the CURRENT org recovery fingerprint (re-seal target + short-form verify anchor). */
  escrowFingerprint: string;
  /** F26: locks — keeps the persisted session; the user gets the Unlock card. */
  onLock: () => void;
  /** F26: the session died server-side — full sign-out, not a lock. `kind` says
   *  whether it was an explicit revocation or plain expiry (the copy differs). */
  onRevoked: (kind: SessionEndKind) => void;
}

export function Vault({ account, store, client, email, policy, isAdmin, mustChangePassword, escrowStale, escrowFingerprint, onLock, onRevoked }: Props) {
  const [view, setView] = useState<View>("vault");
  const [items, setItems] = useState<VaultItem[]>(store.list());
  // Lifecycle notices (spec 03 §11) — the banner reflects the store's list after every sync.
  const [notices, setNotices] = useState<LifecycleNotice[]>(store.notices());
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<string | null>(null);
  const [editing, setEditing] = useState<ItemDoc | null>(null);
  const [importOpen, setImportOpen] = useState(false);
  const [exportMode, setExportMode] = useState<ExportMode | null>(null);
  // DN-1 (A1): the Sharing view's per-vault settings layer. The id lives HERE — not in
  // Sharing — so the ONE back guard below can close it as the topmost layer (a second
  // useBackGuard anywhere under Vault is forbidden: double-popstate would make one Back
  // close two layers). null = Sharing shows the vaults list.
  const [sharingSettingsVaultId, setSharingSettingsVaultId] = useState<string | null>(null);
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
  // a11yweb-04/AM-3: one connectivity string — the tooltip AND the visually-hidden text
  // twin in the appbar read from it, so a screen reader hears the state flip.
  const connStatus = online
    ? "Connected"
    : wsUp
      ? "Last sync failed — will retry"
      : "Live updates down — checking for changes every 60 s";
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

  // F76: any open layer makes Back close it instead of leaving the vault. Topmost-first order
  // mirrors how the layers stack (editor/import/export over a view; detail over the list).
  const deep = view !== "vault" || selected !== null || editing !== null || importOpen || exportMode !== null;
  const closeTop = useCallback(() => {
    if (editing) return setEditing(null);
    if (importOpen) return setImportOpen(false);
    if (exportMode) return setExportMode(null);
    if (selected) return setSelected(null);
    // DN-1 (A1): the sharing settings layer closes before the view falls back — one Back
    // steps settings → vaults list, the next leaves Sharing. `deep` needs no change
    // (view !== "vault" already holds while Sharing is open).
    if (view === "sharing" && sharingSettingsVaultId) return setSharingSettingsVaultId(null);
    if (view !== "vault") return setView("vault");
  }, [editing, importOpen, exportMode, selected, view, sharingSettingsVaultId]);
  useBackGuard(deep, closeTop);

  const refresh = () => {
    setItems(store.list());
    setNotices(store.notices());
  };

  const dismissNotice = (id: string) => {
    store.dismissNotice(id);
    setNotices(store.notices());
  };

  // One sync path for the dirty-bell, every (re)open, the F29 offline poll, and the
  // manual "Sync now" button. It never throws (the WS callbacks run un-awaited inside
  // ApiClient.events), and it marks the sync healthy only AFTER a successful pull — so
  // the dot never shows "Connected" over data we failed to fetch. A SyncIntegrityError
  // (store's F31 rollback guard) lands in the same catch: state was kept, dot goes grey.
  const syncNow = useCallback(async () => {
    try {
      await store.sync();
      setItems(store.list());
      setNotices(store.notices());
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
    // F79: search name + username + EVERY uri (not just the first) + notes + a card's
    // brand/••last4 identity — so a login found only by its 2nd website, a secure note found
    // by its body, and a card found by "visa" all match. Secrets (passwords/PANs/CVVs) are
    // never search keys.
    return items.filter((it) => {
      const d = it.doc;
      if (d.name.toLowerCase().includes(q)) return true;
      if ((d.notes ?? "").toLowerCase().includes(q)) return true;
      if (d.type === "login" && d.login) {
        if ((d.login.username ?? "").toLowerCase().includes(q)) return true;
        if ((d.login.uris ?? []).some((u) => u.toLowerCase().includes(q))) return true;
      }
      if (d.type === "card") return cardSubtitle(d).toLowerCase().includes(q);
      return false;
    });
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

  // fv fail-close surface (design 2026-07-09): items sealed by a NEWER client sit in the
  // store's undecryptable set instead of degrading — surface a count so "invisible" reads
  // as "stored safely, pending an app update", for this fv bump and every future one.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const needsUpdate = useMemo(() => store.needsUpdateCount(), [store, items]);

  const startNew = (type: "login" | "note" | "card") => {
    setSelected(null);
    setImportOpen(false);
    setExportMode(null);
    setEditing(
      type === "login"
        ? { type, name: "", login: { username: "", password: "", uris: [""] } }
        : type === "card"
          ? { type, name: "", card: {} }
          : { type, name: "", notes: "" },
    );
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
    // a11yweb-05: aria-current marks the active view for AT (the .active class is visual only).
    <button className={`navbtn ${view === v ? "active" : ""}`} aria-current={view === v ? "page" : undefined} onClick={() => { setView(v); setEditing(null); setImportOpen(false); setExportMode(null); setSelected(null); setSharingSettingsVaultId(null); }}>{label}</button>
  );

  const current = selected ? store.get(selected) : null;

  // One row for BOTH list paths — the virtualizer below is a slicing layer over
  // this exact element, not a second row implementation (F56).
  const renderRow = (it: VaultItem) => (
    <button className="item" key={it.itemId} onClick={() => openItem(it)}>
      <span className="glyph">{(it.doc.name || "?").charAt(0).toUpperCase()}</span>
      <span className="body">
        <div className="name">{it.doc.name || "(untitled)"}</div>
        <div className="sub">{it.doc.type === "login" ? it.doc.login?.username || it.doc.login?.uris?.[0] || "login" : it.doc.type === "card" ? cardSubtitle(it.doc) : "secure note"}</div>
      </span>
      {it.vaultId !== account.personalVaultId && (
        <span className="tag" style={{ color: "var(--gold-text)" }}>{vaultNameById.get(it.vaultId) ?? "shared"}</span>
      )}
      <span className="tag">{it.doc.type}</span>
    </button>
  );

  return (
    <div>
      <div className="appbar">
        <div className="row">
          <span className="brand"><span className="a-mark">and</span>vari</span>
          <nav className="nav">
            {navBtn("vault", "Vault")}
            {navBtn("sharing", "Sharing")}
            {/* IA P1/DN-2: Health and Trash left the nav — they're toolbar icons on the vault
                view (occasional tools, not top-level places). Nav is now the 3-4 real places. */}
            {navBtn("settings", "Settings")}
            {isAdmin && navBtn("admin", "Admin")}
          </nav>
        </div>
        <div className="row">
          <span className="muted who" title={connStatus}>
            <span className={`dot ${online ? "on" : "off"}`} aria-hidden="true" />
            <span className="userid">{email || account.userId.slice(0, 8)}</span>
            {/* AM-3: a visually-hidden role=status TWIN inside .who. Its textContent mutates
                on the connectivity flip → announced; the email in .userid stays intact (an
                aria-label on .who would clobber it AND, as an attribute change, never announce). */}
            <span className="visually-hidden" role="status">{connStatus}</span>
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

      {escrowStale && escrowFingerprint && <ReSealBanner account={account} client={client} escrowFingerprint={escrowFingerprint} />}

      <NoticesBanner notices={notices} onDismiss={dismissNotice} />

      {/* Calm, no-shame copy (the newer client is someone else's device, not an error), and
          deliberately non-dismissable — it clears itself once the items decrypt post-update
          (the mustChange banner idiom, not the dismissable notices one). */}
      {needsUpdate > 0 && (
        <div className="banner">
          <span>
            {needsUpdate === 1
              ? "1 item in your vaults was saved with a newer version of andvari — it’s stored safely and will appear here once this app is updated."
              : `${needsUpdate} items in your vaults were saved with a newer version of andvari — they’re stored safely and will appear here once this app is updated.`}
          </span>
        </div>
      )}

      <div className="wrap">
        {view === "health" ? (
          <Health store={store} client={client} onOpenItem={goToItem} />
        ) : view === "trash" ? (
          <TrashView store={store} onRestored={refresh} />
        ) : view === "sharing" ? (
          <Sharing
            account={account}
            store={store}
            client={client}
            onSynced={refresh}
            /* A8: "Back up first" leaves Sharing — the settings id clears with the other
               layer state, so the round-trip lands back on the vaults LIST. */
            onBackup={() => { setView("vault"); setSelected(null); setEditing(null); setImportOpen(false); setSharingSettingsVaultId(null); setExportMode("backup"); }}
            settingsVaultId={sharingSettingsVaultId}
            onOpenSettings={setSharingSettingsVaultId}
            onCloseSettings={() => setSharingSettingsVaultId(null)}
          />
        ) : view === "settings" ? (
          <Settings
            client={client}
            account={account}
            policy={policy}
            onPasswordChanged={() => setMustChange(false)}
            /* IA P3: backing up from Settings flips to the vault view first so the ExportPanel
               layer renders (the view axis wins over exportMode in this switch), mirroring
               Sharing's "Back up first". Undefined on the public origin → the buttons hide. */
            onBackup={exportAllowed ? () => { setView("vault"); setSelected(null); setEditing(null); setImportOpen(false); setSharingSettingsVaultId(null); setExportMode("backup"); } : undefined}
            onCsv={exportAllowed ? () => { setView("vault"); setSelected(null); setEditing(null); setImportOpen(false); setSharingSettingsVaultId(null); setExportMode("csv"); } : undefined}
          />
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
            moveTargets={newItemVaultChoices.filter((v) => v.vaultId !== current.vaultId)}
            onEdit={() => setEditing(current.doc)}
            onDelete={() => remove(current.itemId)}
            onMoved={() => { refresh(); setSelected(null); }}
            onBack={() => setSelected(null)}
          />
        ) : (
          <>
            <div className="toolbar">
              <input aria-label="Search vault" placeholder="Search vault…" value={query} onChange={(e) => setQuery(e.target.value)} autoFocus={finePointer} />
              <button className="ghost" onClick={() => startNew("login")}>+ Login</button>
              <button className="ghost" onClick={() => startNew("note")}>+ Note</button>
              {/* Dark until the Option A gate clears (0.2.x MSI retired) — see CARD_CREATE_ENABLED.
                  Everything downstream (row/detail/editor for EXISTING cards) renders regardless. */}
              {CARD_CREATE_ENABLED && <button className="ghost" onClick={() => startNew("card")}>+ Card</button>}
              <button className="ghost" onClick={() => { setSelected(null); setEditing(null); setExportMode(null); setImportOpen(true); }}>Import</button>
              {/* Hidden on the public break-glass origin (spec 07 — see exportAllowed). The two
                  export destinations live under one menu so the toolbar can't crush the search box. */}
              {exportAllowed && (
                <ExportMenu
                  onBackup={() => { setSelected(null); setEditing(null); setImportOpen(false); setExportMode("backup"); }}
                  onCsv={() => { setSelected(null); setEditing(null); setImportOpen(false); setExportMode("csv"); }}
                />
              )}
              {/* IA P1: Health — an occasional tool, moved off the nav to a toolbar icon.
                  (The toolbar only shows on the vault view, so these icons only ever navigate
                  AWAY — there's no active state to reflect.) */}
              <button
                type="button"
                className="ghost"
                aria-label="Vault health"
                title="Vault health"
                onClick={() => { setEditing(null); setImportOpen(false); setExportMode(null); setSelected(null); setSharingSettingsVaultId(null); setView("health"); }}
              >
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" style={{ verticalAlign: "-2px" }}>
                  <path d="M22 12h-4l-3 9L9 3l-3 9H2" />
                </svg>
              </button>
              {/* DN-2: the Trash entry point — a small icon here instead of a main-nav item.
                  Mirrors navBtn's layer-clearing so it behaves like navigation, not a layer. */}
              <button
                type="button"
                className="ghost"
                aria-label="Trash"
                title="Trash"
                onClick={() => { setEditing(null); setImportOpen(false); setExportMode(null); setSelected(null); setSharingSettingsVaultId(null); setView("trash"); }}
              >
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" style={{ verticalAlign: "-2px" }}>
                  <path d="M3 6h18" /><path d="M8 6V4a1 1 0 0 1 1-1h6a1 1 0 0 1 1 1v2" /><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6" /><path d="M10 11v6M14 11v6" />
                </svg>
              </button>
            </div>
            {filtered.length === 0 ? (
              <div className="empty">
                <div className="sigil"><EmptySigil /></div>
                <p>{items.length === 0 ? "Your hoard is empty. Add your first secret." : "Nothing matches that search."}</p>
              </div>
            ) : filtered.length > VIRTUAL_THRESHOLD ? (
              <VirtualList items={filtered} renderRow={renderRow} />
            ) : (
              <div className="list vault-list">{filtered.map(renderRow)}</div>
            )}
          </>
        )}
      </div>
    </div>
  );
}

// F56 vault-list windowing geometry. ROW_H/LIST_GAP mirror styles.css
// (.vault-list .item height / .list gap) — the three must move together.
const ROW_H = 72;
const LIST_GAP = 8;
const STRIDE = ROW_H + LIST_GAP;
const OVERSCAN = 8;
/** Perf addendum 2026-07-09: below ~500 rows the plain render wins on simplicity. */
const VIRTUAL_THRESHOLD = 500;

/**
 * F56: fixed-stride window over the vault list, engaged only past VIRTUAL_THRESHOLD.
 * The PAGE stays the scroller (no inner scrollbar, so the two render paths feel
 * identical); the visible slice derives from the host's viewport offset, recomputed
 * on scroll/resize behind one rAF. Keyboard focus needs no special casing in the
 * Tab direction: focusing a row near the window's edge makes the browser scroll it
 * into view, that scroll lands here, and the slice follows (overscan keeps the next
 * rows mounted for Tab). Accepted tradeoff (react-window has it too): a focused row
 * wheel-scrolled PAST the overscan unmounts and focus falls to body — restoring it
 * would yank the scroll back, which is worse; the plain ≤500 path keeps it mounted.
 *
 * The measuring effect is a LAYOUT effect: the initial state assumes scrollTop 0, and
 * a mount while scrolled deep (filter cleared) or a shrink via the background sync's
 * post-paint render would otherwise paint one stale/blank frame before correcting.
 */
function VirtualList({ items, renderRow }: { items: VaultItem[]; renderRow: (it: VaultItem) => ReactElement }) {
  const hostRef = useRef<HTMLDivElement | null>(null);
  const [range, setRange] = useState<WindowRange>(() => windowRange(0, window.innerHeight, STRIDE, OVERSCAN, items.length));

  useLayoutEffect(() => {
    let frame = 0;
    const update = () => {
      frame = 0;
      const host = hostRef.current;
      if (!host) return;
      // The host's viewport offset IS the list-relative scrollTop, negated.
      const next = windowRange(-host.getBoundingClientRect().top, window.innerHeight, STRIDE, OVERSCAN, items.length);
      setRange((r) => (next.start === r.start && next.end === r.end ? r : next));
    };
    const schedule = () => {
      if (!frame) frame = window.requestAnimationFrame(update);
    };
    update();
    // Capture-phase: scroll doesn't bubble, so any non-document ancestor scroller
    // would otherwise be invisible here.
    window.addEventListener("scroll", schedule, true);
    window.addEventListener("resize", schedule);
    return () => {
      window.removeEventListener("scroll", schedule, true);
      window.removeEventListener("resize", schedule);
      if (frame) window.cancelAnimationFrame(frame);
    };
  }, [items.length]);

  return (
    // The spacer holds the full scroll height (last row carries no trailing gap);
    // the absolutely-placed slice sits exactly where its rows would have laid out.
    <div ref={hostRef} style={{ position: "relative", height: items.length * STRIDE - LIST_GAP }}>
      <div className="list vault-list" style={{ position: "absolute", top: range.start * STRIDE, left: 0, right: 0 }}>
        {items.slice(range.start, range.end).map(renderRow)}
      </div>
    </div>
  );
}

/** "July 14"-style day (spec 03 §11 copy). Falls back gracefully for a missing time. */
export function fmtDay(ms?: number): string {
  if (!ms) return "soon";
  return new Date(ms).toLocaleDateString(undefined, { month: "long", day: "numeric" });
}

function noticeBody(n: LifecycleNotice): { body: string; warn: boolean } {
  const name = n.vaultName || "a vault";
  switch (n.kind) {
    case "deleted":
      return {
        warn: false,
        body:
          `“${name}” was deleted by its owner. Its items were moved off this device` +
          (n.purgeAt ? ` (kept sealed until ${fmtDay(n.purgeAt)}, then removed).` : ".") +
          (n.parkedCount ? ` ${n.parkedCount} of your edits hadn’t synced — they’ll be recovered if the vault is restored this week.` : ""),
      };
    case "removed":
      return { warn: false, body: `Your access to “${name}” was removed.` };
    case "left":
      return { warn: false, body: `You left “${name}”.` };
    case "restored":
      return { warn: false, body: `“${name}” was restored.` };
    case "added":
      return { warn: false, body: `You were added to “${name}”.` };
    case "transfer-complete":
      return { warn: false, body: n.becameMine ? `You are now the owner of “${name}”.` : `“${name}” now has a new owner.` };
    case "transfer-anomaly":
      return {
        warn: true,
        body:
          `The server says “${name}” changed owners, but this couldn’t be verified with the vault’s own key. ` +
          `If nobody in your household did this, tell your admin — the server may be misbehaving.`,
      };
    case "anomaly":
      return {
        warn: true,
        body:
          `The server says you lost access to “${name}”, but this couldn’t be verified as a real owner action. ` +
          `A sealed copy of its data is kept on this device for 30 days (Sharing → the trash icon). ` +
          `If nobody in your household did this, tell your admin — the server may be misbehaving.`,
      };
  }
}

/**
 * F57: after a recovery-key re-ceremony an account's escrow is sealed to the DEAD key (spec 04
 * §4). This prompt re-seals the UVK to the CURRENT recovery key — but ONLY after the user
 * confirms the new fingerprint against their PRINTED recovery sheet (short-form). resealEscrowFor
 * then binds the server-fetched pubkey to that verified fingerprint and refuses on mismatch, so a
 * hostile server cannot redirect the escrow to an attacker key. Non-blocking: "Later" just leaves
 * it for the next unlock (escrowStale persists server-side until the re-seal lands).
 */
function ReSealBanner({ account, client, escrowFingerprint }: { account: Account; client: ApiClient; escrowFingerprint: string }) {
  const [open, setOpen] = useState(false);
  const [entry, setEntry] = useState("");
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);
  const [err, setErr] = useState("");
  const shortOk = shortFormMatches(entry, escrowFingerprint);

  const reseal = async () => {
    setBusy(true);
    setErr("");
    try {
      const pub = await client.recoveryPubkey();
      const { sealed, fingerprint } = await account.resealEscrowFor(pub, escrowFingerprint);
      await client.putEscrow(sealed, fingerprint);
      setDone(true);
    } catch (e) {
      setErr(e instanceof Error ? e.message : "re-seal failed — try again, or contact your admin");
    } finally {
      setBusy(false);
    }
  };

  if (done) {
    return <div className="banner"><span>Account re-protected — your recovery is up to date. ✓</span></div>;
  }
  if (!open) {
    return (
      <div className="banner">
        <span>Your household's recovery key changed — re-protect this account so it stays recoverable.</span>
        <button className="link" onClick={() => setOpen(true)}>Re-protect →</button>
      </div>
    );
  }
  return (
    <div className="banner">
      <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem", width: "100%" }}>
        <span className="muted">
          Confirm the NEW recovery fingerprint from your printed recovery sheet, then re-protect. Your master
          key never leaves this device except sealed to the recovery key you verify below.
        </span>
        <label>Type the FIRST 16 characters of the fingerprint on your printed recovery sheet</label>
        <input
          value={entry}
          onChange={(e) => setEntry(e.target.value)}
          placeholder="from the sheet, not this screen"
          autoComplete="off"
          spellCheck={false}
        />
        {!shortOk && entry && (
          <span style={{ color: "var(--danger)" }}>
            doesn't match this server's recovery key — if you copied the sheet correctly, STOP and contact your admin
          </span>
        )}
        {shortOk && <span className="muted">matches — {escrowFingerprint.replace(/(.{4})/g, "$1 ").trim()}</span>}
        {err && <span style={{ color: "var(--danger)" }}>{err}</span>}
        <div style={{ display: "flex", gap: "0.5rem" }}>
          <button className="primary" disabled={!shortOk || busy} onClick={reseal}>{busy ? "Re-protecting…" : "Re-protect account"}</button>
          <button className="ghost" disabled={busy} onClick={() => setOpen(false)}>Later</button>
        </div>
      </div>
    </div>
  );
}

/** The lifecycle notices banner (spec 03 §11): attributed only when the proof verified; the
 *  anomaly warning renders in the danger tone. Each notice is individually dismissable. */
function NoticesBanner({ notices, onDismiss }: { notices: LifecycleNotice[]; onDismiss: (id: string) => void }) {
  if (notices.length === 0) return null;
  return (
    <div className="wrap" style={{ paddingBottom: 0 }}>
      {notices.map((n) => {
        const { body, warn } = noticeBody(n);
        return (
          <div key={n.id} className={`msg ${warn ? "err" : "info"}`} role={warn ? "alert" : undefined} style={{ display: "flex", alignItems: "flex-start", gap: 12 }}>
            <span style={{ flex: 1 }}>{body}</span>
            <button type="button" className="link" onClick={() => onDismiss(n.id)}>Dismiss</button>
          </div>
        );
      })}
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
    // a11yweb-08: Tab closes the menu (no preventDefault, no focus return) so focus proceeds
    // out per the WAI-ARIA menu-button pattern instead of stranding an open menu behind it.
    else if (e.key === "Tab") setOpen(false);
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

function Detail({ item, client, store, policy, readOnly, vaultName, moveTargets, onEdit, onDelete, onMoved, onBack }: { item: VaultItem; client: ApiClient; store: VaultStore; policy: ClientPolicy | null; readOnly: boolean; vaultName?: string; moveTargets: VaultInfo[]; onEdit: () => void; onDelete: () => Promise<void>; onMoved: () => void; onBack: () => void }) {
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
      {/* BL-1: copy confirmation is polite async info — the visible .copy-flash span mounts
          already-populated (silent), so announce it off this persistent region, named by
          which field was copied ("password copied", "code copied", …). */}
      <Announcer text={flash ? `${flash} copied` : ""} />
      <button className="link" onClick={onBack}>← back to vault</button>
      <h2 style={{ marginTop: 12 }}>{doc.name}</h2>
      <div className="muted" style={{ marginBottom: 18 }}>
        {/* Cards identify themselves by brand + ••last4 (design contract) — the one line
            that lets the user pick the right card without revealing the full PAN. */}
        {doc.type === "login" ? "Login" : doc.type === "card" ? (doc.card?.number ? cardSubtitle(doc) : "Card") : "Secure note"}
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
            <Field label="Website">
              <input readOnly value={doc.login.uris[0]} />
            </Field>
          )}
          {doc.login.password && <HealthLine password={doc.login.password} client={client} />}
        </>
      )}

      {doc.type === "card" && doc.card && (
        <>
          {doc.card.cardholderName && (
            <div className="field">
              <label>Cardholder</label>
              <div className="secret-row">
                <input readOnly value={doc.card.cardholderName} />
                <button className="ghost" onClick={() => copy("cardholder", doc.card!.cardholderName!)}>Copy</button>
              </div>
            </div>
          )}
          {doc.card.number && (
            <div className="field">
              <label>Card number {flash === "card number" && <span className="copy-flash">copied ✓</span>}</label>
              {/* Reveal shows the grouped form; Copy hands checkout forms the bare digits. */}
              <div className="secret-row">
                <PasswordField value={groupNumber(doc.card.number)} />
                <button className="ghost" onClick={() => copy("card number", doc.card!.number!)}>Copy</button>
              </div>
            </div>
          )}
          {expiryLabel(doc.card) !== null && (
            <div className="field">
              <label>Expiry</label>
              <div className="secret-row" style={{ alignItems: "center" }}>
                <input readOnly className="mono" value={expiryLabel(doc.card)!} />
                {isExpired(doc.card.expMonth, doc.card.expYear) && <span className="tag expired">expired</span>}
              </div>
            </div>
          )}
          {doc.card.securityCode && (
            <div className="field">
              <label>Security code {flash === "security code" && <span className="copy-flash">copied ✓</span>}</label>
              <div className="secret-row">
                <PasswordField value={doc.card.securityCode} />
                <button className="ghost" onClick={() => copy("security code", doc.card!.securityCode!)}>Copy</button>
              </div>
            </div>
          )}
        </>
      )}

      {doc.notes && (
        <Field label="Notes">
          <textarea readOnly rows={5} value={doc.notes} />
        </Field>
      )}

      {(doc.attachments?.length ?? 0) > 0 && <AttachmentList item={item} store={store} />}

      <ItemHistory item={item} store={store} readOnly={readOnly} onRestored={onBack} />

      {/* A reader-role member cannot edit/delete/attach — the push would be denied. */}
      {!readOnly && (
        <>
          {delErr && <div className="msg err" role="alert" style={{ marginTop: 18 }}>{delErr}</div>}
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
          {!deleting && moveTargets.length > 0 && <MoveCopyControl item={item} store={store} targets={moveTargets} onMoved={onMoved} />}
        </>
      )}
    </div>
  );
}

/**
 * Item undelete (feature): "Recently deleted" — the tombstoned items the user can still recover.
 * Each is named from its last archived version (a tombstone's own blob is null); Restore re-creates
 * it live via the dedicated server route (clean un-tombstone, no spurious conflict copy). Honest:
 * retention is unbounded today (F49), so this holds everything ever deleted within reach.
 */
function TrashView({ store, onRestored }: { store: VaultStore; onRestored: () => void }) {
  const [items, setItems] = useState<{ itemId: string; vaultId: string; deletedAt: number; doc: ItemDoc | null }[] | null>(null);
  const [err, setErr] = useState("");
  const [restoringId, setRestoringId] = useState<string | null>(null);
  const [purgingId, setPurgingId] = useState<string | null>(null);
  const [confirmPurgeId, setConfirmPurgeId] = useState<string | null>(null);

  const load = useCallback(async () => {
    setErr("");
    try {
      setItems(await store.deletedItems());
    } catch (e) {
      setErr(e instanceof ApiError ? "Couldn't load deleted items from the server." : "Couldn't reach the server for deleted items.");
    }
  }, [store]);

  useEffect(() => { void load(); }, [load]);

  const purge = async (itemId: string) => {
    setPurgingId(itemId);
    setErr("");
    try {
      await store.purgeDeleted(itemId);
    } catch {
      setErr("Couldn't delete it permanently — try again.");
    } finally {
      setPurgingId(null);
      setConfirmPurgeId(null);
      await load();
    }
  };

  const restore = async (d: { itemId: string; vaultId: string; doc: ItemDoc | null }) => {
    if (!d.doc) return; // nothing readable to restore
    setRestoringId(d.itemId);
    setErr("");
    try {
      await store.restoreDeleted(d.itemId, d.vaultId, d.doc);
      onRestored(); // re-sync so the item reappears in the vault
    } catch {
      setErr("Restore failed — try again.");
    } finally {
      setRestoringId(null);
      await load(); // always re-list: the restored item drops out (and a lost-response success reconciles)
    }
  };

  return (
    <div className="sheet">
      <h2>Trash</h2>
      <div className="muted" style={{ marginBottom: 18 }}>
        Deleted items you can still restore — kept for 30 days, then removed automatically. Restoring
        brings an item back to its vault on every device; “Delete forever” removes it now.
      </div>
      {err && <Msg kind="err">{err}</Msg>}
      {items === null ? (
        <div className="muted">Loading…</div>
      ) : items.length === 0 ? (
        <div className="muted">Nothing here — deleted items you can recover will show up in this list.</div>
      ) : (
        items.map((d) => (
          <div key={d.itemId} className="secret-row" style={{ alignItems: "center", marginTop: 8 }}>
            <span style={{ flex: 1 }}>
              {d.doc ? d.doc.name : <span className="muted">(unrecoverable — no readable version)</span>}
              <span className="muted mono" style={{ marginLeft: 8 }}>deleted {new Date(d.deletedAt).toISOString().slice(0, 10)}</span>
            </span>
            {confirmPurgeId === d.itemId ? (
              <>
                <span className="muted">Delete forever?</span>
                <button className="ghost" style={{ color: "var(--danger)" }} disabled={purgingId !== null} onClick={() => purge(d.itemId)}>
                  {purgingId === d.itemId ? "Deleting…" : "Confirm"}
                </button>
                <button className="ghost" disabled={purgingId !== null} onClick={() => setConfirmPurgeId(null)}>Keep</button>
              </>
            ) : (
              <>
                <button className="ghost" disabled={!d.doc || restoringId !== null || purgingId !== null} onClick={() => restore(d)}>
                  {restoringId === d.itemId ? "Restoring…" : "Restore"}
                </button>
                <button className="ghost" style={{ color: "var(--danger)" }} disabled={restoringId !== null || purgingId !== null} onClick={() => setConfirmPurgeId(d.itemId)}>
                  Delete forever
                </button>
              </>
            )}
          </div>
        ))
      )}
    </div>
  );
}

/**
 * Item history & restore (feature: "the fat-finger seatbelt"). Fetches the archived versions the
 * server already keeps (up to the last 10), decrypts each under the held VK, and offers per-version
 * password reveal + "Restore" (a plain put over the live item). Readers can view but not restore.
 * Honest bound: "up to the last 10 saves" — never "nothing is ever lost" (spec 02 §7).
 */
function ItemHistory({ item, store, readOnly, onRestored }: { item: VaultItem; store: VaultStore; readOnly: boolean; onRestored: () => void }) {
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [versions, setVersions] = useState<{ rev: number; archivedAt: number; doc: ItemDoc }[] | null>(null);
  const [err, setErr] = useState("");
  const [restoringRev, setRestoringRev] = useState<number | null>(null);

  const load = async () => {
    setOpen(true);
    if (versions !== null || loading) return;
    setLoading(true);
    setErr("");
    try {
      setVersions(await store.itemVersions(item.itemId, item.vaultId));
    } catch (e) {
      setErr(e instanceof ApiError ? "Couldn't load history from the server." : "Couldn't reach the server for history.");
    } finally {
      setLoading(false);
    }
  };

  const restore = async (v: { rev: number; doc: ItemDoc }) => {
    setRestoringRev(v.rev);
    setErr("");
    try {
      await store.save(item.itemId, v.doc); // an ordinary put over the live item
      onRestored(); // back to the vault; the live item now holds the restored version
    } catch {
      setErr("Restore failed — nothing changed. Try again.");
      setRestoringRev(null);
    }
  };

  if (!open) {
    return <button className="link" style={{ marginTop: 12 }} onClick={load}>Version history</button>;
  }
  return (
    <div className="field" style={{ marginTop: 18 }}>
      <label>Version history <span className="muted">· up to the last 10 saves</span></label>
      {loading && <div className="muted">Loading…</div>}
      {err && <Msg kind="err">{err}</Msg>}
      {versions?.length === 0 && <div className="muted">No earlier versions yet — history starts from the next change.</div>}
      {versions?.map((v) => (
        <div key={v.rev} className="secret-row" style={{ alignItems: "center", marginTop: 6 }}>
          <span className="muted mono" style={{ minWidth: 92 }}>{new Date(v.archivedAt).toISOString().slice(0, 10)}</span>
          {v.doc.type === "login" && v.doc.login?.password ? (
            <PasswordField value={v.doc.login.password} />
          ) : (
            <span className="muted" style={{ flex: 1 }}>{v.doc.type === "login" ? "(no password in this version)" : v.doc.type === "card" ? cardSubtitle(v.doc) : "note"}</span>
          )}
          {!readOnly && (
            <button className="ghost" disabled={restoringRev !== null} onClick={() => restore(v)}>
              {restoringRev === v.rev ? "Restoring…" : "Restore"}
            </button>
          )}
        </div>
      ))}
      <button className="link" style={{ marginTop: 8 }} onClick={() => setOpen(false)}>Hide history</button>
    </div>
  );
}

/**
 * F19 (design §8): move or copy this item into another vault. Runs the store's copy-leg-first
 * gesture; a transient failure keeps the SAME gesture so Retry converges (never duplicates); a
 * denied copy or a changed source aborts with an honest message (source untouched).
 */
function MoveCopyControl({ item, store, targets, onMoved }: { item: VaultItem; store: VaultStore; targets: VaultInfo[]; onMoved: () => void }) {
  const [mode, setMode] = useState<"move" | "copy" | null>(null);
  const [target, setTarget] = useState(targets[0]?.vaultId ?? "");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [progress, setProgress] = useState<{ done: number; total: number } | null>(null);
  const gestureRef = useRef<MoveGesture | null>(null);

  const resetGesture = () => { gestureRef.current = null; };

  const run = async () => {
    if (!mode || !target) return;
    setBusy(true);
    setErr("");
    setProgress(null);
    try {
      const g = gestureRef.current ?? store.newMoveGesture(item.itemId, target, mode === "move");
      gestureRef.current = g; // reused verbatim on retry (server dedup converges)
      await store.runGesture(g, (done, total) => setProgress({ done, total }));
      resetGesture();
      onMoved();
    } catch (e) {
      if (e instanceof CopyDeniedError) {
        resetGesture();
        setErr("You don’t have permission to add items to that vault — nothing was moved.");
      } else if (e instanceof ItemChangedError) {
        resetGesture();
        setErr("This item changed while moving — go back, review it, and try again.");
      } else if (e instanceof ApiError && e.status === 403) {
        resetGesture();
        setErr(e.message);
      } else {
        // Transient — keep the gesture so Retry replays the same ids (no duplicate).
        setErr("That didn’t finish. Press Retry — it won’t create a duplicate.");
      }
    } finally {
      setBusy(false);
      setProgress(null);
    }
  };

  if (!mode) {
    return (
      <div className="actions" style={{ marginTop: 6 }}>
        <button type="button" className="ghost" onClick={() => { setMode("move"); resetGesture(); }}>Move to vault…</button>
        <button type="button" className="ghost" onClick={() => { setMode("copy"); resetGesture(); }}>Copy to vault…</button>
      </div>
    );
  }

  return (
    <div className="field" style={{ marginTop: 12 }}>
      <label>{mode === "move" ? "Move to another vault" : "Copy to another vault"}</label>
      {err && <Msg kind="err">{err}</Msg>}
      {mode === "move" && (
        <p className="muted" style={{ marginTop: 0 }}>
          Members of “{store.vaults().find((v) => v.vaultId === item.vaultId)?.name ?? "this vault"}” may still have copies from before the move.
        </p>
      )}
      <div className="secret-row">
        <select value={target} aria-label={mode === "move" ? "Move to another vault" : "Copy to another vault"} onChange={(e) => { setTarget(e.target.value); resetGesture(); }} disabled={busy} style={{ width: "auto" }}>
          {targets.map((v) => (
            <option key={v.vaultId} value={v.vaultId}>{v.name}{v.type === "personal" ? "" : " (shared)"}</option>
          ))}
        </select>
        <button type="button" className="primary" disabled={busy || !target} onClick={run}>
          {busy ? (progress && progress.total > 0 ? `Copying… ${progress.done}/${progress.total}` : "Working…") : err ? "Retry" : mode === "move" ? "Move" : "Copy"}
        </button>
        <button type="button" className="ghost" disabled={busy} onClick={() => { setMode(null); setErr(""); resetGesture(); }}>Cancel</button>
      </div>
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
      {err && <Msg kind="err">{err}</Msg>}
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

/** Editable sibling of PasswordField — masked by default with a reveal toggle. The editor
 *  CVV renders through this (design: SecretField); login passwords keep the plain editor
 *  idiom (generate-and-glance), a deliberate difference, not an oversight. */
function SecretInput({ value, onChange, ariaLabel }: { value: string; onChange: (v: string) => void; ariaLabel?: string }) {
  const [show, setShow] = useState(false);
  return (
    <div className="secret-row">
      {/* BL-2: this custom input never gets Field's injected id, so name it here. */}
      <input className="mono" type={show ? "text" : "password"} inputMode="numeric" autoComplete="off" aria-label={ariaLabel} value={value} onChange={(e) => onChange(e.target.value)} />
      <button type="button" className="ghost" aria-label={show ? "Hide value" : "Show value"} onClick={() => setShow((s) => !s)}>{show ? "Hide" : "Show"}</button>
    </div>
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
        {/* a11yweb-09: name the copy affordance + speak the code (the visible digits are the
            control's text but "123456, button" gives no hint it copies). */}
        <button className="totp link" aria-label={`One-time code ${code.replace(/\s/g, "")} — copy`} onClick={() => onCopy(code.replace(/\s/g, ""))} title="copy">{code.replace(/(\d{3})(\d{3})/, "$1 $2")}</button>
        {/* aria-hidden: the ring updates every second — it must NOT be a live region. */}
        <div className="ring" aria-hidden="true" style={{ ["--p" as string]: String((remaining / period) * 100) }} title={`${remaining}s`} />
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

const MONTH_CHOICES = ["01", "02", "03", "04", "05", "06", "07", "08", "09", "10", "11", "12"];

/** Expiry-year picker: a rolling 16-year window, PLUS any stored out-of-window values
 *  (verbatim, prepended) — editing an old card must never silently change its year. */
function expiryYearChoices(stored: (string | undefined)[]): string[] {
  const first = new Date().getFullYear();
  const ys = Array.from({ length: 16 }, (_, i) => String(first + i));
  for (const y of stored) if (y && !ys.includes(y)) ys.unshift(y);
  return ys;
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
  // F78: the editor password is masked by default (reveal toggle), and Generate over an
  // EXISTING password asks first — a mistyped-then-generated field silently losing what the
  // user typed was the reported footgun.
  const [showPw, setShowPw] = useState(false);
  const [confirmGen, setConfirmGen] = useState(false);
  const fileInput = useRef<HTMLInputElement | null>(null);
  const isLogin = doc.type === "login";
  const login = doc.login ?? {};
  const isCard = doc.type === "card";
  const card = doc.card ?? {};

  const setLogin = (patch: Partial<NonNullable<ItemDoc["login"]>>) => setDoc({ ...doc, login: { ...login, ...patch } });
  const setCard = (patch: Partial<NonNullable<ItemDoc["card"]>>) => setDoc({ ...doc, card: { ...card, ...patch } });

  // Generate: an empty field fills immediately; a non-empty one arms an inline confirm
  // (house style — no native dialogs) so a real password is never clobbered by a stray tap.
  // Either way the new password is revealed, so the user sees what will be saved.
  const gen = () => {
    if ((login.password ?? "").length > 0 && !confirmGen) {
      setConfirmGen(true);
      return;
    }
    setLogin({ password: generatePassword() });
    setShowPw(true);
    setConfirmGen(false);
  };

  // Live editor signals off the typed number: decisive-prefix brand badge, and a Luhn check
  // that WARNS once a plausible PAN length is present — never blocks Save (store-what-the-
  // user-typed beats rejecting an odd-but-real number).
  const cardDigits = digitsOnly(card.number ?? "");
  const cardBrand = brandLabel(brand(cardDigits));
  const luhnWarn = cardDigits.length >= 12 && !luhnValid(cardDigits);
  // Injects the doc's stored years from `initial` so an old card's value stays offered for
  // the whole edit session — editing must never silently change it.
  const yearChoices = expiryYearChoices([card.expYear, initial.card?.expYear]);

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
    } else if (isCard) {
      // Cards normalize ONCE here too — spread-only (account.ts contract), so unknown keys
      // inside `card` survive the rewrite. brand is ALWAYS recomputed from the number
      // (display-only; a user-authored or stale brand must never persist). digits-only
      // strips separators AND stray non-digits from a hand-typed number; a card whose
      // every field normalizes to absent is a legal empty shell.
      toSave = {
        ...doc,
        card: {
          ...card,
          cardholderName: (card.cardholderName ?? "").trim() || undefined,
          number: cardDigits || undefined,
          expMonth: padMonth(card.expMonth ?? "") ?? undefined,
          expYear: yearTo4(card.expYear ?? "") ?? undefined,
          securityCode: digitsOnly(card.securityCode ?? "") || undefined,
          brand: brand(cardDigits) ?? undefined,
        },
      };
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
      <h2 style={{ marginTop: 12 }}>{initial.name ? "Edit" : isLogin ? "New login" : isCard ? "New card" : "New note"}</h2>
      {vaultChoices && vaultChoices.length > 1 && (
        <Field label="Vault">
          <select value={vaultId} onChange={(e) => setVaultId(e.target.value)}>
            {vaultChoices.map((v) => (
              <option key={v.vaultId} value={v.vaultId}>
                {v.name}{v.type === "personal" ? "" : " (shared)"}
              </option>
            ))}
          </select>
        </Field>
      )}
      <Field label="Name">
        <input autoFocus value={doc.name} onChange={(e) => setDoc({ ...doc, name: e.target.value })} />
      </Field>
      {isLogin && (
        <>
          <Field label="Username">
            <input className="mono" value={login.username ?? ""} onChange={(e) => setLogin({ username: e.target.value })} />
          </Field>
          <div className="field">
            {/* BL-2: multi-child block (secret-row + confirm + StrengthBar) — Field can't wrap
                it, so name the inner <input> directly. */}
            <label>Password</label>
            <div className="secret-row">
              {/* Masked by default (F78); typing stays possible — a password field the user
                  can't read is the login-editor's one blind spot the reveal toggle fixes. */}
              <input className="mono" aria-label="Password" type={showPw ? "text" : "password"} value={login.password ?? ""} onChange={(e) => { setLogin({ password: e.target.value }); setConfirmGen(false); }} />
              <button type="button" className="ghost" aria-label={showPw ? "Hide password" : "Show password"} onClick={() => setShowPw((s) => !s)}>{showPw ? "Hide" : "Show"}</button>
              <button type="button" className="ghost" onClick={gen}>{confirmGen ? "Replace?" : "Generate"}</button>
            </div>
            {confirmGen && <span className="muted" style={{ color: "var(--gold-text)" }}>this replaces the current password — tap “Replace?” to confirm, or edit the field to cancel</span>}
            {login.password && <StrengthBar password={login.password} />}
          </div>
          <Field label="Website">
            {/* Edits uris[0] only; the tail (extra URIs written by other clients) is preserved. */}
            <input value={login.uris?.[0] ?? ""} onChange={(e) => setLogin({ uris: e.target.value ? [e.target.value, ...(login.uris ?? []).slice(1)] : (login.uris ?? []).slice(1) })} placeholder="https://" />
          </Field>
          <Field label="TOTP secret (otpauth:// URI or base32)">
            {/* RAW text while typing — normalizing per keystroke rewrote the field to an
                otpauth:// URI on the first character. Normalized once, in submit. */}
            <input className="mono" value={login.totp ?? ""} onChange={(e) => setLogin({ totp: e.target.value })} placeholder="optional" />
          </Field>
        </>
      )}
      {isCard && (
        <>
          <Field label="Cardholder name">
            <input value={card.cardholderName ?? ""} onChange={(e) => setCard({ cardholderName: e.target.value })} />
          </Field>
          <Field
            label={<>Card number {cardBrand && <span className="tag brand">{cardBrand}</span>}</>}
            hint={
              luhnWarn ? (
                <div className="muted" style={{ marginTop: 6, color: "var(--gold-text)" }}>
                  this number doesn’t pass the usual check — you can still save it
                </div>
              ) : undefined
            }
          >
            {/* RAW text while typing (separators and all) — digits-only ONCE, in submit (the
                TOTP idiom). The badge + Luhn line read the live digits; warn, never block. */}
            <input className="mono" inputMode="numeric" autoComplete="off" value={card.number ?? ""} onChange={(e) => setCard({ number: e.target.value })} />
          </Field>
          <div className="field">
            <label>Expiry</label>
            {/* Both selects offer an empty choice — every card field is optional. The month
                VALUE renders through padMonth so a foreign-written "1" displays as "01".
                BL-2: two selects under one label — name each directly. */}
            <div className="row">
              <select value={padMonth(card.expMonth ?? "") ?? ""} aria-label="Expiry month" onChange={(e) => setCard({ expMonth: e.target.value })} style={{ width: "auto" }}>
                <option value="">month</option>
                {MONTH_CHOICES.map((m) => (
                  <option key={m} value={m}>{m}</option>
                ))}
              </select>
              <select value={card.expYear ?? ""} aria-label="Expiry year" onChange={(e) => setCard({ expYear: e.target.value })} style={{ width: "auto" }}>
                <option value="">year</option>
                {yearChoices.map((y) => (
                  <option key={y} value={y}>{y}</option>
                ))}
              </select>
            </div>
          </div>
          <div className="field">
            <label>Security code <span className="muted">· optional — stored encrypted like everything else</span></label>
            {/* Masked-with-reveal (unlike the login password's plain editor field): a CVV is
                glanceable-short and worth shielding from shoulders by default. Digits-only
                is applied once, at submit, beside the other card normalizations. */}
            <SecretInput ariaLabel="Security code" value={card.securityCode ?? ""} onChange={(v) => setCard({ securityCode: v })} />
          </div>
        </>
      )}
      <Field label="Notes">
        <textarea rows={isLogin || isCard ? 3 : 6} value={doc.notes ?? ""} onChange={(e) => setDoc({ ...doc, notes: e.target.value })} />
      </Field>

      <div className="field">
        <label>Attachments</label>
        {fileErr && <Msg kind="err">{fileErr}</Msg>}
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

      {saveErr && <Msg kind="err">{saveErr}</Msg>}
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

/** True when the SHARED normalizeTotp's output (crypto/totp.ts — A5: one normalize for
 *  editors and CSV adapters alike) is a parseable otpauth URI — the save-time gate
 *  (the Detail view would otherwise render the stored value as "invalid" forever). */
function isValidTotp(normalized: string): boolean {
  try {
    parseOtpauthUri(normalized);
    return true;
  } catch {
    return false;
  }
}

// ---- CSV import (spec 06 + design 2026-07-11 universal importer) ----

/** The per-source "How do I export from…?" help table — the ONE surviving per-source
 *  surface of the universal importer (design 2026-07-11). Content-aligned twin of core
 *  ImportHelp (the usual non-KMP mirror — keep the two in lockstep). Steps are best-effort
 *  export navigation docs (current as of 2026-07), NOT contracts — parsing never consults
 *  them; header detection is authoritative (csv.ts). */
interface ImportSource {
  label: string;
  steps: string[];
  note?: string;
}

const IMPORT_SOURCES: ImportSource[] = [
  {
    label: "Chrome",
    steps: [
      "Open chrome://password-manager/settings (Menu ⋮ → Passwords and autofill → Google Password Manager → Settings).",
      "Under “Export passwords”, choose Download file.",
      "Confirm with your device sign-in and save the CSV.",
    ],
  },
  {
    label: "Edge",
    steps: [
      "Open edge://wallet/passwords.",
      "Click ⋯ (More options) → Export passwords.",
      "Confirm with your device sign-in and save the CSV.",
    ],
  },
  {
    label: "Brave",
    steps: [
      "Open brave://password-manager/settings.",
      "Under “Export passwords”, choose Download file.",
      "Confirm with your device sign-in and save the CSV.",
    ],
  },
  {
    label: "Opera",
    steps: [
      "Open opera://settings/passwords.",
      "Next to “Saved Passwords”, click ⋮ → Export passwords.",
      "Confirm with your device sign-in and save the CSV.",
    ],
  },
  {
    label: "Firefox",
    steps: [
      "Open about:logins (Menu ☰ → Passwords).",
      "Click ⋯ (top right) → Export passwords…",
      "Confirm with your device sign-in and save the CSV.",
    ],
  },
  {
    label: "Bitwarden",
    steps: [
      "In the Bitwarden web vault or desktop app: Tools → Export vault.",
      "File format: .csv (not .json).",
      "Confirm with your master password and save the file.",
    ],
  },
  {
    label: "1Password",
    steps: [
      "In the 1Password desktop app (version 8 or newer): File → Export → your account.",
      "Choose the CSV format, confirm with your account password, and save the file.",
    ],
    note: "1Password 7 and older export a different CSV shape — update to 1Password 8 or newer, or route through Bitwarden/another CSV export as an intermediate.",
  },
  {
    // A10: pin the FILE-DOWNLOAD export path — the in-browser-tab route HTML-mangles values.
    label: "LastPass",
    steps: [
      "Sign in to your vault at lastpass.com.",
      "Open Advanced Options in the left menu → Export.",
      "Confirm with your master password — LastPass downloads a lastpass_export.csv file.",
    ],
    note: "Use that downloaded file directly. Don’t copy CSV text out of a browser tab into a file — that route mangles characters like “&”.",
  },
];

function friendlyParseError(e: unknown): string {
  if (e instanceof ImportError) {
    switch (e.code) {
      case "too_large":
        return "That file is larger than 10 MiB — far bigger than any real password export. Double-check you picked the right file.";
      case "too_many_rows":
        return "That file has more than 10,000 rows. Split it into smaller files and import them one at a time.";
      case "unrecognized_header":
        // Universal copy (design 2026-07-11): no pick exists to key a bespoke hint on,
        // so the old 1Password-specific hint folds into the one message.
        return "This file isn't a recognized password export. Make sure you exported a CSV (not JSON or a zip) — and if it came from 1Password, that you're on 1Password 8 or newer.";
      default:
        return `That file could not be read (${e.code}).`;
    }
  }
  return "That file could not be read. Make sure it's the CSV your password manager exported.";
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

const FORMAT_LABEL: Record<ImportFormat, string> = {
  chrome: "Chrome/Edge (Chromium)",
  firefox: "Firefox",
  bitwarden: "Bitwarden",
  "1password": "1Password",
  lastpass: "LastPass",
};

/** A10 heuristic: multiple values carrying HTML entities smell like a copy-paste-from-a-
 *  browser-tab export (the classic LastPass trap). Hint ONLY — never auto-decode. */
const HTML_MANGLE = /&(amp|lt|gt|quot|#\d+);/;
function looksHtmlMangled(rows: ParsedRow[]): boolean {
  let hits = 0;
  for (const r of rows) {
    for (const v of [r.name, r.url, r.username, r.password, r.notes, r.totp ?? ""]) {
      if (HTML_MANGLE.test(v)) {
        hits++;
        if (hits >= 2) return true;
      }
    }
  }
  return false;
}

/** House idiom for the report's name lists: inline when short, summarized + expandable
 *  when long — every bucket stays enumerated BY NAME (A9), never reduced to a count. */
function NameList({ names }: { names: string[] }) {
  const [expanded, setExpanded] = useState(false);
  const LIMIT = 8;
  if (names.length <= LIMIT) return <>{names.join(", ")}</>;
  if (expanded) {
    return (
      <>
        {names.join(", ")}{" "}
        <button type="button" className="link" onClick={() => setExpanded(false)}>show fewer</button>
      </>
    );
  }
  return (
    <>
      {names.slice(0, LIMIT).join(", ")}{" "}
      <button type="button" className="link" onClick={() => setExpanded(true)}>…and {names.length - LIMIT} more</button>
    </>
  );
}

/** Every report bucket, enumerated by name — rendered on the preview AND the finished
 *  screen so nothing about what the plan did is a surprise afterwards. */
function ReportBuckets({ report }: { report: ImportReport }) {
  const bucket = (names: string[], intro: string) =>
    names.length > 0 ? (
      <div className="msg info" style={{ display: "block" }}>
        {intro} <NameList names={names} />.
      </div>
    ) : null;
  return (
    <>
      {bucket(report.alreadyInVault, "Already in your vault — skipped:")}
      {bucket(report.passwordDiffers, "Same site and username as your vault, but a different password — imported separately (renamed) so you can review which one is current:")}
      {bucket(report.totpDiffers, "Same login as your vault, but a different 2FA secret — imported separately (renamed) for review:")}
      {bucket(report.flagged, "Renamed so every item keeps a distinct name:")}
      {bucket(report.archivedSkipped, "Archived in the export — not imported:")}
      {bucket(report.unknownTypeSkipped, "Item types andvari can't import yet — skipped:")}
      {bucket(report.totpUnsupported, "One-time-code secrets in a format andvari can't verify — kept as text in each item's notes:")}
      {bucket(report.noteItems, "Secure notes imported:")}
    </>
  );
}

function ReportTiles({ report, done }: { report: ImportReport; done: boolean }) {
  return (
    <div className="tiles" style={{ marginTop: 4 }}>
      <div className="tile"><div className="tile-value tone-good">{report.imported}</div><div className="tile-label">{done ? "Imported" : "To import"}</div></div>
      {report.alreadyInVault.length > 0 && <div className="tile"><div className="tile-value">{report.alreadyInVault.length}</div><div className="tile-label">Already in vault</div></div>}
      {report.collapsed > 0 && <div className="tile"><div className="tile-value">{report.collapsed}</div><div className="tile-label">Merged (dupes)</div></div>}
      {report.flagged.length > 0 && <div className="tile"><div className="tile-value tone-mid">{report.flagged.length}</div><div className="tile-label">Renamed</div></div>}
      {report.skippedEmpty > 0 && <div className="tile"><div className="tile-value">{report.skippedEmpty}</div><div className="tile-label">Skipped (empty)</div></div>}
      {report.errors.length > 0 && <div className="tile"><div className="tile-value tone-bad">{report.errors.length}</div><div className="tile-label">Rows with problems</div></div>}
    </div>
  );
}

/**
 * Universal import (design 2026-07-11): one screen — "Choose file…" straight to the picker
 * (header detection decides the format; no source pick exists) → vault-aware plan preview →
 * encrypt-and-push. Everything happens on this device; the file
 * never leaves the browser. The plan's itemIds are minted once, so a mid-import failure is
 * fixed with Retry (idempotent replay of the SAME plan — each itemId doubles as the push
 * mutationId) rather than re-parsing; re-parsing mints new ids and would duplicate.
 * The plan compares against the DESTINATION vault (store.importProjections(vaultId), A8/S2 —
 * default personal, switchable to any writable shared vault): items already there are
 * skipped — including rows a previous import renamed to "name (k)" (rule 1 also
 * matches through the stripped base name). One exception keeps this short of a blanket
 * "re-import is safe": a row whose totp value doesn't parse is unmatchable by design (A7,
 * fp = null) and re-imports as a renamed copy — the preview shows it before anything lands.
 * S2 invariant: `planned` pairs each plan with the vault whose projections produced it, and
 * the commit reads THAT vault — never the picker — so plan and importDocs cannot disagree.
 */
function ImportPanel({ store, onClose, onDone }: { store: VaultStore; onClose: () => void; onDone: () => void }) {
  const fileInput = useRef<HTMLInputElement | null>(null);
  /** The "How do I export from…?" help block — collapsed by default (design 2026-07-11). */
  const [helpOpen, setHelpOpen] = useState(false);
  const [fileName, setFileName] = useState("");
  const [format, setFormat] = useState<ImportFormat | null>(null);
  const [planned, setPlanned] = useState<{ plan: ImportPlan; vault: VaultInfo } | null>(null);
  /** The parse, retained so a destination change can re-plan without re-reading the file. */
  const [parsed, setParsed] = useState<Parsed | null>(null);
  /** physical line → 1-based data-row ordinal, so errors render "row N (file line M)" (A9). */
  const [rowNoByLine, setRowNoByLine] = useState<Map<number, number>>(new Map());
  const [mangled, setMangled] = useState(false);
  const [parseErr, setParseErr] = useState("");
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState<{ done: number; total: number } | null>(null);
  const [importErr, setImportErr] = useState("");
  /** S2: a non-locking notice for a failed destination PICK (vault vanished mid-sync) —
   *  deliberately not importErr, which would flip importLocked and freeze the very picker
   *  the user needs to choose again with. */
  const [pickErr, setPickErr] = useState("");
  const [finished, setFinished] = useState(false);

  // F18 idiom (mirrors newItemVaultChoices): personal + shared vaults we can WRITE to —
  // readers never appear. Computed per render, not memoized: the first sync can finish
  // while this panel is open and newly-held vaults must surface without a remount.
  const vaultChoices = store.vaults().filter((v) => v.type === "personal" || v.role === "owner" || v.role === "writer");

  const reset = () => {
    setPlanned(null);
    setParsed(null);
    setFormat(null);
    setRowNoByLine(new Map());
    setMangled(false);
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
      // A8: the plan needs the vault's projections — REFUSE honestly when this device has
      // never completed a sync, rather than silently planning against an empty vault
      // (which would quietly re-import everything as new). The personal-vault lookup shares
      // the gate: post-sync it always exists, pre-sync store.vaults() may be empty.
      const personal = vaultChoices.find((v) => v.type === "personal");
      if (store.lastSyncAt === null || !personal) {
        setParseErr(
          "Your vault hasn't finished its first sync on this device, so the import can't check what you already have. Wait for the sync (or press Sync now in the top bar), then pick the file again.",
        );
        return;
      }
      const bytes = new Uint8Array(await file.arrayBuffer());
      const p = parseCsvImport(bytes);
      setFormat(p.format);
      setParsed(p);
      setRowNoByLine(rowOrdinalsByLine(bytes));
      setMangled(looksHtmlMangled(p.rows)); // A10 — hint only, never auto-decode
      // ids minted ONCE here, reused verbatim on Retry. Every fresh parse plans against
      // the DEFAULT destination — personal (S2 picker contract).
      setPlanned({ plan: planImport(p, store.importProjections(personal.vaultId), () => crypto.randomUUID()), vault: personal });
    } catch (e) {
      setParseErr(friendlyParseError(e));
    } finally {
      if (fileInput.current) fileInput.current.value = "";
    }
  };

  // Locked once an import attempt starts: re-planning after a partial import would mint new
  // ids (breaking Retry's idempotent replay) and strand already-landed rows in the old vault.
  const importLocked = busy || finished || importErr !== "";

  const changeDestination = (vaultId: string) => {
    const vault = vaultChoices.find((v) => v.vaultId === vaultId);
    if (!vault || !parsed || importLocked) return;
    // A sync-time removal can race the click (the option came from a render-closure
    // snapshot) — never re-plan against a vault we no longer hold: its projections read
    // empty and every row plans as "to import" (native importSetVault parity).
    if (!store.vaults().some((v) => v.vaultId === vault.vaultId)) {
      setPickErr("That vault isn't available any more — it may have been removed. Pick another destination.");
      return;
    }
    setPickErr("");
    // A plan is only valid against the vault whose projections it compared (the F75 dedupe
    // verdicts differ per vault) — so re-plan from the retained parse. planImport is
    // synchronous and plan+vault land in ONE state commit, so Confirm can never fire against
    // a stale pairing; fresh ids are safe here — nothing has been pushed yet (importLocked).
    setPlanned({ plan: planImport(parsed, store.importProjections(vault.vaultId), () => crypto.randomUUID()), vault });
  };

  const runImport = async () => {
    if (!planned) return;
    setBusy(true);
    setImportErr("");
    setProgress({ done: 0, total: planned.plan.items.length });
    try {
      // Reuse plan.items on every attempt: each carries its own itemId, used as the push
      // mutationId → the server dedupes an already-applied put, so Retry never duplicates.
      // Destination = the vault CAPTURED with the plan (S2 invariant), never the picker.
      await store.importDocs(planned.plan.items, (done, total) => setProgress({ done, total }), planned.vault.vaultId);
      setFinished(true);
    } catch {
      setImportErr(
        "The import was interrupted before it finished. Everything that already landed is safe in your vault — press Retry to import the rest (it won’t create duplicates).",
      );
    } finally {
      setBusy(false);
    }
  };

  const report = planned?.plan.report ?? null;
  const nothingToImport = planned !== null && planned.plan.items.length === 0;
  // Destination shown in the plan summary + final report — "your personal vault" keeps the
  // pre-S2 copy for the default; a shared vault is named so the reader knows who sees it.
  const destLabel = planned ? (planned.vault.type === "personal" ? "your personal vault" : `“${planned.vault.name}” (shared)`) : "";

  return (
    <div className="sheet">
      {/* a11yweb-02/BL-1: announce the import lifecycle START + COMPLETE only (never the
          per-row progress label — that would be screen-reader spam). Persistent region so
          the completion, which swaps in the report branch, is not silently mounted. */}
      <Announcer
        text={
          finished && report
            ? `Import complete. Added ${report.imported} ${report.imported === 1 ? "item" : "items"} to ${destLabel}.`
            : busy && planned
              ? `Importing ${planned.plan.items.length} ${planned.plan.items.length === 1 ? "item" : "items"}…`
              : ""
        }
      />
      <button type="button" className="link" onClick={onClose}>← back to vault</button>
      <h2 style={{ marginTop: 12 }}>Import passwords (CSV)</h2>
      <div className="muted" style={{ marginBottom: 18 }}>from a browser or another password manager · everything stays on this device</div>

      {/* Always-visible plaintext caution. */}
      <div className="msg info" style={{ display: "block" }}>
        <strong>⚠ An exported CSV holds every password in plaintext.</strong> Nothing about it
        is uploaded — parsing happens here in your browser and each item is encrypted before it
        is saved. Items already in your vault are skipped — the preview shows exactly what will
        be imported. When you're done, delete the CSV and empty your trash.
      </div>

      <input
        ref={fileInput}
        type="file"
        accept=".csv,text/csv,text/plain"
        style={{ display: "none" }}
        onChange={(e) => onFile(e.target.files)}
      />

      {finished && report ? (
        <>
          <ReportTiles report={report} done />
          <ReportBuckets report={report} />
          <div className="msg info" style={{ display: "block" }}>
            Added {report.imported} {report.imported === 1 ? "item" : "items"} to {destLabel}.
            Now delete <strong>{fileName || "the CSV file"}</strong> and empty your trash.
          </div>
          <div className="actions">
            <button type="button" className="primary" onClick={onDone}>Done</button>
          </div>
        </>
      ) : planned && report ? (
        <>
          <div className="muted" style={{ marginBottom: 12 }}>
            {fileName && <>“{fileName}” · </>}detected {format ? FORMAT_LABEL[format] : "password"} export · into {destLabel}
          </div>

          {pickErr && <div className="muted" style={{ marginBottom: 8 }}>{pickErr}</div>}
          {/* S2: destination picker (F18 idiom — rendered only when there is a real choice).
              Changing it re-plans against that vault's projections (changeDestination). */}
          {vaultChoices.length > 1 && (
            <Field label="Import into">
              <select value={planned.vault.vaultId} disabled={importLocked} onChange={(e) => changeDestination(e.target.value)}>
                {vaultChoices.map((v) => (
                  <option key={v.vaultId} value={v.vaultId}>
                    {v.name}{v.type === "personal" ? "" : " (shared)"}
                  </option>
                ))}
              </select>
            </Field>
          )}

          {/* A10: the copy-paste-from-a-browser-tab trap (classic LastPass). Hint only. */}
          {mangled && (
            <div className="msg info" style={{ display: "block" }}>
              Several values in this file look HTML-mangled {"— “&” written as “&amp;”, for example —"}
              which happens when CSV text is copied out of a browser tab instead of downloaded.
              Nothing was decoded automatically; for a clean import, re-export via Advanced Options → Export
              so a real file downloads.
            </div>
          )}

          <ReportTiles report={report} done={false} />
          <ReportBuckets report={report} />

          {report.errors.length > 0 && (
            <div className="field">
              <label>Rows skipped ({report.errors.length})</label>
              <div className="table-scroll">
                <table className="table">
                  <thead><tr><th>Row</th><th>Problem</th></tr></thead>
                  <tbody>
                    {/* Capped: a mass-mangled file yields up to 9,999 error rows — that many
                        <tr>s is real DOM/jank cost for zero review value. */}
                    {report.errors.slice(0, 100).map((err, idx) => (
                      <tr key={`${err.line}-${idx}`}>
                        <td className="mono">row {rowNoByLine.get(err.line) ?? "?"} (file line {err.line})</td>
                        <td>{problemLabel(err.code)}</td>
                      </tr>
                    ))}
                    {report.errors.length > 100 && (
                      <tr><td colSpan={2}>…and {report.errors.length - 100} more rows not shown — fix the export and re-select the file.</td></tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {nothingToImport && <div className="msg info" style={{ display: "block" }}>Nothing new to import from this file.</div>}
          {importErr && <Msg kind="err">{importErr}</Msg>}

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
                {busy ? "Importing…" : `Import ${report.imported} ${report.imported === 1 ? "item" : "items"}`}
              </button>
            )}
            <div className="spacer" />
            {/* Locked in the PARTIAL state (importErr): reset() would wipe the plan's idempotent
                ids and a re-pick re-plans against personal by default — the exact cross-vault
                duplicate path importLocked exists to close. After a CLEAN finish it's fine
                (rows landed + synced; the next plan dedupes them). */}
            <button type="button" className="ghost" disabled={busy || importErr !== ""} onClick={() => { reset(); setFileName(""); }}>Choose a different file</button>
          </div>
        </>
      ) : (
        <>
          {/* The universal screen (design 2026-07-11): no source pick — the file decides. */}
          <div className="muted" style={{ marginBottom: 12 }}>
            Works with password exports from Chrome, Edge, Brave, Opera, Firefox, Bitwarden,
            1Password 8 or newer, LastPass, and Safari — the file itself decides how it's read.
          </div>
          {/* A-webError: this branch is parseErr's ONLY render site — a bad file must
              visibly fail right here, next to the picker button. */}
          {parseErr && <Msg kind="err">{parseErr}</Msg>}
          <div className="actions">
            <button type="button" className="primary" onClick={() => fileInput.current?.click()}>Choose file…</button>
            <div className="spacer" />
            <button type="button" className="ghost" onClick={onClose}>Cancel</button>
          </div>
          <div className="field" style={{ marginTop: 18 }}>
            <button type="button" className="link" aria-expanded={helpOpen} onClick={() => setHelpOpen((o) => !o)}>
              How do I export from…? {helpOpen ? "▴" : "▾"}
            </button>
            {helpOpen &&
              IMPORT_SOURCES.map((s) => (
                <div key={s.label} style={{ marginTop: 12 }}>
                  <label>{s.label}</label>
                  <ol className="steps">
                    {s.steps.map((step, i) => (
                      <li key={i}>{step}</li>
                    ))}
                  </ol>
                  {s.note && <div className="muted">{s.note}</div>}
                </div>
              ))}
          </div>
        </>
      )}
    </div>
  );
}
