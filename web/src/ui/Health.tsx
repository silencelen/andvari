import { useCallback, useMemo, useState } from "react";
import { ApiClient } from "../api/client";
import { hibpCountInRange, hibpPrefix, hibpSha1UpperHex } from "../crypto/hibp";
import type { VaultItem, VaultStore } from "../vault/store";
import { duplicateClusters, planDismiss, planKeep, type DuplicateCluster, type RoleFor } from "./duplicates";
import { Announcer, Msg } from "./Msg";
import { Staleness } from "./Staleness";
import { stalenessRows, stalenessSummary } from "./staleness";
import { EmptySigil } from "./Sigil";
import { STRENGTH_LABELS, estimateStrength } from "./strength";
import { ViewHeader } from "./ViewHeader";

interface Props {
  /** Vault's live items state (refreshed after every sync/pull) — NOT a store snapshot. */
  items: VaultItem[];
  client: ApiClient;
  /** CR-08: keys the in-session breach cache per-account so a shared browser never cross-contaminates. */
  userId: string;
  onOpenItem: (itemId: string) => void;
  /** Duplicate merge (2026-08-12): the guided merge writes through the store… */
  store: VaultStore;
  /** …and this is Vault's refresh() — re-derives `items` after the merge lands (TrashView's
   *  onRestored convention), which is what makes the merged cluster disappear from the list. */
  onChanged: () => void;
  /** The server-declared clipboard window, passed to the verification run's copy buttons. The
   *  CLAMP lives in useCopy (§2.3 B1-1), so an out-of-range policy value cannot pin a secret. */
  clipboardClearSeconds?: number;
  /** Usage lookup (spec 02 §8.2); absent renders "—", which is NOT "never used". */
  lastUsedAt?: (itemId: string) => number | undefined;
  /** Report that the user actually used a login (a copied password, a site opened to sign in). */
  onUsed?: (itemId: string) => void;
}

interface Row {
  itemId: string;
  name: string;
  password: string;
  strength: number;
  reused: number; // other items sharing this password
  hasTotp: boolean;
}

/** bug-web--1: rows derive from Vault's `items` prop, whose identity changes on every applied
 *  sync — the old `store` prop never changed identity, so a memo keyed on it computed once per
 *  mount and the WS dirty-bell's live updates froze the whole view until a navigate-away.
 *  Exported pure so health-rows.test.ts pins the strength/reuse/TOTP derivation. */
export function healthRows(items: VaultItem[]): Row[] {
  const logins = items.filter((it) => it.doc.type === "login" && it.doc.login?.password);
  const byPassword = new Map<string, number>();
  for (const it of logins) {
    const pw = it.doc.login!.password!;
    byPassword.set(pw, (byPassword.get(pw) ?? 0) + 1);
  }
  return logins.map((it) => {
    const pw = it.doc.login!.password!;
    return {
      itemId: it.itemId,
      name: it.doc.name || "(untitled)",
      password: pw,
      strength: estimateStrength(pw),
      reused: (byPassword.get(pw) ?? 1) - 1,
      hasTotp: !!it.doc.login!.totp,
    };
  });
}

/** Owner dev-note 2026-08-18: the duplicate checker grew past a screenful and buried the per-item
 *  table below it, so the view is split in two — the tiles stay as the always-visible summary and
 *  everything below them belongs to one switchable half (Admin's tabs idiom). */
type HealthTab = "passwords" | "duplicates" | "staleness";

/** Vault-wide password health: strength, reuse, duplicates, and (on demand) HIBP breach exposure. */
export function Health({ items, client, userId, onOpenItem, store, onChanged, clipboardClearSeconds, lastUsedAt, onUsed }: Props) {
  const [tab, setTab] = useState<HealthTab>("passwords");
  const rows = useMemo<Row[]>(() => healthRows(items), [items]);
  // audit F03: duplicates cluster ACROSS vaults (the app mints cross-vault twins itself), so the
  // checker needs vault identity — names for the row badges and the confirm sentence, and the
  // role that decides whether a merge may write at all. Same source as Vault's row badge
  // (store.vaults()), recomputed with `items` per that view's memo idiom.
  // bug-web--1 (kept): keyed on `items` ONLY — the store's identity never changes for the mount,
  // so listing it would be the identity-stable dependency that froze this view once already.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const vaultsInfo = useMemo(() => store.vaults(), [items]);
  const vaultNameById = useMemo(() => new Map(vaultsInfo.map((v) => [v.vaultId, v.name])), [vaultsInfo]);
  const roleFor = useCallback(
    (vaultId: string) => vaultsInfo.find((v) => v.vaultId === vaultId)?.role ?? null,
    [vaultsInfo],
  );
  const dupes = useMemo<DuplicateCluster[]>(() => duplicateClusters(items, roleFor), [items, roleFor]);
  // Tiles derive from the SAME rows the Staleness tab shows (snoozed excluded, as there), so a
  // tile can never disagree with the list under it.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const staleRows = useMemo(() => stalenessRows(items, { lastUsedAt }), [items, lastUsedAt]);
  const staleSummary = stalenessSummary(staleRows);

  // itemId → breach count, filled by a scan and cached ON-DEVICE (by itemId — never the plaintext
  // password, which is only the scan's lookup key) so it survives navigating away from Health.
  // Loaded from the cache on mount → the button reads "Rescan" and the column shows last results.
  const [breachByItem, setBreachByItem] = useState<Map<string, number> | null>(() => loadBreachCache(userId));
  const [scanning, setScanning] = useState(false);
  const [progress, setProgress] = useState({ done: 0, total: 0 });
  const [scanErr, setScanErr] = useState("");

  const scan = async () => {
    setScanning(true);
    setScanErr("");
    try {
      // k-anonymity (spec 03 §8): hash every UNIQUE password, fetch each 5-hex
      // prefix range once, then map suffix counts back — sequential, gentle on the relay.
      const unique = [...new Set(rows.map((r) => r.password))];
      const hashes = new Map<string, string>(); // password → sha1 upper hex
      for (const pw of unique) hashes.set(pw, await hibpSha1UpperHex(pw));
      const byPrefix = new Map<string, string[]>(); // prefix → passwords
      for (const [pw, hash] of hashes) {
        const p = hibpPrefix(hash);
        byPrefix.set(p, [...(byPrefix.get(p) ?? []), pw]);
      }
      setProgress({ done: 0, total: byPrefix.size });
      const result = new Map<string, number>();
      let done = 0;
      for (const [prefix, passwords] of byPrefix) {
        const body = await client.hibpRange(prefix);
        for (const pw of passwords) result.set(pw, hibpCountInRange(body, hashes.get(pw)!));
        setProgress({ done: ++done, total: byPrefix.size });
      }
      // Persist + display keyed by itemId — never the plaintext password (the scan's lookup key).
      const byItem = new Map(rows.map((r) => [r.itemId, result.get(r.password) ?? 0]));
      setBreachByItem(byItem);
      saveBreachCache(userId, byItem);
    } catch {
      setScanErr("Breach scan failed — the HIBP relay is unavailable. Partial results were discarded.");
    } finally {
      setScanning(false);
    }
  };

  const weak = rows.filter((r) => r.strength <= 1).length;
  const reused = rows.filter((r) => r.reused > 0).length;
  const breached = breachByItem ? rows.filter((r) => (breachByItem.get(r.itemId) ?? 0) > 0).length : null;
  // Highest breach count first (owner ask), then alphabetical; unscanned/no-breach items tie at 0.
  const sorted = useMemo(() => {
    const n = (id: string) => breachByItem?.get(id) ?? 0;
    return [...rows].sort((a, b) => n(b.itemId) - n(a.itemId) || a.name.localeCompare(b.name));
  }, [rows, breachByItem]);

  return (
    <div>
      <ViewHeader
        title="Vault health"
        actions={
          <button className="ghost" onClick={scan} disabled={scanning || rows.length === 0}>
            {scanning ? `Scanning… ${progress.done}/${progress.total}` : breachByItem ? "Rescan for breaches" : "Scan for breaches"}
          </button>
        }
      />
      {scanErr && <Msg kind="err">{scanErr}</Msg>}

      <div className="tiles">
        <Tile label="Logins" value={String(rows.length)} />
        <Tile label="Weak" value={String(weak)} tone={weak > 0 ? "bad" : "good"} />
        <Tile label="Reused" value={String(reused)} tone={reused > 0 ? "bad" : "good"} />
        <Tile label="Breached" value={breached === null ? "—" : String(breached)} tone={breached === null ? undefined : breached > 0 ? "bad" : "good"} hint={breached === null ? "run a scan" : undefined} />
        {/* Active clusters only — an acknowledged "not duplicates" must not keep the tile red. */}
        <Tile label="Duplicates" value={String(dupes.filter((d) => !d.dismissed).length)} tone={dupes.some((d) => !d.dismissed) ? "bad" : "good"} />
        <Tile label="Unchecked" value={String(staleSummary.unchecked)} tone={staleSummary.unchecked > 0 ? "bad" : "good"} />
        <Tile label="Failing" value={String(staleSummary.failing)} tone={staleSummary.failing > 0 ? "bad" : "good"} />
      </div>

      <div className="tabs" role="group" aria-label="Health view">
        <button type="button" className={tab === "passwords" ? "active" : ""} aria-pressed={tab === "passwords"} onClick={() => setTab("passwords")}>
          Passwords
        </button>
        <button type="button" className={tab === "duplicates" ? "active" : ""} aria-pressed={tab === "duplicates"} onClick={() => setTab("duplicates")}>
          Duplicates
        </button>
        <button type="button" className={tab === "staleness" ? "active" : ""} aria-pressed={tab === "staleness"} onClick={() => setTab("staleness")}>
          Staleness
        </button>
      </div>

      {tab === "staleness" ? (
        <Staleness
          items={items}
          roleFor={roleFor}
          store={store}
          onOpenItem={onOpenItem}
          onChanged={onChanged}
          clearSeconds={clipboardClearSeconds ?? 30}
          lastUsedAt={lastUsedAt}
          onUsed={onUsed}
        />
      ) : tab === "duplicates" ? (
        dupes.length > 0 ? (
          <Duplicates clusters={dupes} items={items} roleFor={roleFor} store={store} vaultNameById={vaultNameById} onOpenItem={onOpenItem} onChanged={onChanged} />
        ) : (
          <div className="empty">
            <div className="sigil"><EmptySigil /></div>
            <p>No duplicate entries — every account is saved exactly once.</p>
          </div>
        )
      ) : rows.length === 0 ? (
        <div className="empty">
          <div className="sigil"><EmptySigil /></div>
          <p>No logins with passwords yet — nothing to assess.</p>
        </div>
      ) : (
        <div className="table-scroll">
          <table className="table">
            <thead>
              <tr>
                <th>Item</th>
                <th>Strength</th>
                <th>Reused</th>
                <th>TOTP</th>
                <th>Breaches</th>
              </tr>
            </thead>
            <tbody>
              {sorted.map((r) => {
                const count = breachByItem?.get(r.itemId);
                return (
                  // F80: the whole row stays a click target for pointer users.
                  // a11y-webext--2: the keyboard/AT affordance is the real <button> in the
                  // first cell, NOT role="button" + aria-label on the <tr>. That pair replaced
                  // the row role (orphaning every <td>) and, being Children-Presentational,
                  // reduced the row to "Open <name>, button" — hiding the strength/reuse/TOTP/
                  // breach payload this whole view exists to convey. Row semantics restored;
                  // .rowlink:focus-within keeps the visual (styles.css).
                  <tr key={r.itemId} className="rowlink" onClick={() => onOpenItem(r.itemId)}>
                    <td>
                      <button type="button" className="link" onClick={(e) => { e.stopPropagation(); onOpenItem(r.itemId); }}>
                        {r.name}
                      </button>
                    </td>
                    <td><StrengthTag score={r.strength} /></td>
                    <td>{r.reused > 0 ? <span className="tone-bad">{r.reused} other{r.reused > 1 ? "s" : ""}</span> : <span className="muted">no</span>}</td>
                    <td>{r.hasTotp ? "yes" : <span className="muted">no</span>}</td>
                    <td>
                      {breachByItem === null ? (
                        <span className="muted">—</span>
                      ) : count && count > 0 ? (
                        <span className="tone-bad">{count.toLocaleString()}</span>
                      ) : (
                        <span className="tone-good">none</span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// In-session breach cache — itemId → count only (no password material). CR-08 (compliance
// 2026-07-15): this used to persist to a GLOBAL localStorage key ("andvari:breach-cache:v1"),
// where a map derived from decrypted passwords (a >10M count fingerprints a top-100 password)
// survived sign-out/revocation, landed on the public break-glass origin, and cross-contaminated
// accounts on a shared browser — a client-at-rest artifact outside the spec 02 §5 table and every
// WC-13 wipe gate. Fix: keep it in MEMORY only, keyed PER-ACCOUNT, matching the wipe table —
// retained across a lock and Health unmount/remount (module scope survives a phase change), GONE
// on sign-out (clearBreachCache, called from App.signOut, the one wipe choke point) and on reload.
// Nothing is written at rest, so there is no residue, no public-origin leak, and no gate to bypass.
const breachCacheByUser = new Map<string, Map<string, number>>();
/** CR-08: the retired global localStorage key. Proactively purged (below) so the pre-fix at-rest
 *  residue — item count + a password-popularity fingerprint on the public break-glass origin — is
 *  removed from devices that ran the old build, not merely left un-updated. */
const LEGACY_BREACH_CACHE_KEY = "andvari:breach-cache:v1";
function purgeLegacyBreachResidue(): void {
  try {
    localStorage.removeItem(LEGACY_BREACH_CACHE_KEY);
  } catch {
    /* storage unreachable (privacy mode / non-window) — nothing to purge */
  }
}
function loadBreachCache(userId: string): Map<string, number> | null {
  purgeLegacyBreachResidue(); // opening Health scrubs any old at-rest map first
  const m = breachCacheByUser.get(userId);
  return m ? new Map(m) : null; // a copy — callers own their snapshot; never share the stored ref
}
function saveBreachCache(userId: string, byItem: Map<string, number>): void {
  breachCacheByUser.set(userId, new Map(byItem));
}
/** CR-08 / WC-13 §E.4: drop every account's in-memory breach map. Called from App.signOut (the
 *  declared wipe choke point) so the map is GONE on sign-out / revocation / definitive-401 — never
 *  outliving the session the way the old localStorage key did. A lock does NOT call this (retained). */
export function clearBreachCache(): void {
  breachCacheByUser.clear();
  purgeLegacyBreachResidue(); // and scrub the legacy at-rest residue at the wipe choke point
}

/** The duplicate-entry checker (owner-requested 2026-08-12; clustering + the merge PLAN live in
 *  duplicates.ts — this renders and writes, nothing more). Exact clusters may offer a guided
 *  merge: save the composed survivor doc, then remove the losers — removal is the ordinary
 *  delete, so the copies land in Deleted items (30-day Trash) rather than oblivion, and the
 *  confirm line says so. The confirm is the purge idiom (two-step, per-cluster). "differs"
 *  clusters (same account, diverging passwords — one is stale) are report-only BY DESIGN: only
 *  the human knows which password the site currently accepts.
 *
 *  audit F03: every member row names its VAULT (the gold tag Vault's list rows already use) and
 *  the confirm names both the vault kept and the vault emptied — a merge moves real items out of
 *  a real place, and this screen used to name neither. Cross-vault and view-only clusters carry
 *  a refusal from planMerge instead of a Merge button. */
function Duplicates({ clusters, items, roleFor, store, vaultNameById, onOpenItem, onChanged }: { clusters: DuplicateCluster[]; items: VaultItem[]; roleFor: RoleFor; store: VaultStore; vaultNameById: Map<string, string>; onOpenItem: (itemId: string) => void; onChanged: () => void }) {
  const [confirmId, setConfirmId] = useState<string | null>(null); // survivorId of the open confirm
  const [mergingId, setMergingId] = useState<string | null>(null);
  // The differs-resolution confirm: which cluster (by signature) and which member the user
  // picked as survivor. One at a time, the merge-confirm idiom.
  const [keepConfirm, setKeepConfirm] = useState<{ sig: string; keepId: string } | null>(null);
  const [msg, setMsg] = useState<{ kind: "err" | "info"; text: string } | null>(null);

  const active = clusters.filter((c) => !c.dismissed);
  const dismissed = clusters.filter((c) => c.dismissed);

  // Refusal-preview at the first click (retiredAt 0 — the probe never writes), so a cluster
  // that can't be cleaned up says why IMMEDIATELY instead of after a confirm.
  const startKeep = (c: DuplicateCluster, keepId: string) => {
    const probe = planKeep(items, c.members.map((m) => m.itemId), keepId, roleFor, 0);
    if (!probe.keep) {
      setMsg({ kind: "err", text: probe.keepRefusal ?? "This cluster can't be cleaned up automatically." });
      return;
    }
    setMsg(null);
    setKeepConfirm({ sig: c.signature, keepId });
  };

  const runKeep = async (c: DuplicateCluster, keepId: string) => {
    if (mergingId !== null) return;
    const { keep, keepRefusal } = planKeep(items, c.members.map((m) => m.itemId), keepId, roleFor, Date.now());
    if (!keep) {
      setMsg({ kind: "err", text: keepRefusal ?? "This cluster can't be cleaned up automatically." });
      setKeepConfirm(null);
      return;
    }
    setMergingId(keepId);
    setMsg(null);
    try {
      // Survivor first (the runMerge rule): nothing is deleted before the history landed.
      await store.save(keep.survivorId, keep.doc);
      for (const id of keep.loserIds) await store.remove(id);
      const n = keep.loserIds.length;
      setMsg({
        kind: "info",
        text: `Kept one copy — ${n === 1 ? "the other copy" : `${n} other copies`} moved to Deleted items (kept 30 days); the passwords they carried stay in the kept item's password history.`,
      });
    } catch {
      setMsg({ kind: "err", text: "The clean-up didn't finish — any removed copy is in Deleted items. Check the cluster and try again." });
    } finally {
      setMergingId(null);
      setKeepConfirm(null);
      onChanged();
    }
  };

  // restore=false stamps the acknowledgment; restore=true clears it. Single click both ways —
  // nothing is destroyed, and each direction is the other's undo.
  const runDismiss = async (c: DuplicateCluster, restore: boolean) => {
    if (mergingId !== null) return;
    const { writes, dismissRefusal } = planDismiss(items, c.members.map((m) => m.itemId), restore ? "" : c.signature, roleFor);
    if (!writes) {
      setMsg({ kind: "err", text: dismissRefusal ?? "These copies can't be updated." });
      return;
    }
    setMergingId(c.signature);
    setMsg(null);
    try {
      for (const w of writes) await store.save(w.itemId, w.doc);
      setMsg(
        restore
          ? { kind: "info", text: "Back on the list." }
          : { kind: "info", text: "Marked as not duplicates — this group stays quiet unless its copies change." },
      );
    } catch {
      setMsg({ kind: "err", text: "Couldn't update every copy — the group may reappear until a retry lands. Try again." });
    } finally {
      setMergingId(null);
      onChanged();
    }
  };

  const runMerge = async (c: DuplicateCluster) => {
    const plan = c.merge;
    if (!plan || mergingId !== null) return;
    setMergingId(plan.survivorId);
    setMsg(null);
    try {
      // Survivor first: if anything fails, no copy has been deleted before the union landed.
      await store.save(plan.survivorId, plan.doc);
      for (const id of plan.loserIds) await store.remove(id);
      const n = plan.loserIds.length;
      setMsg({ kind: "info", text: `Merged — ${n === 1 ? "the duplicate copy" : `${n} duplicate copies`} moved to Deleted items (kept 30 days).` });
    } catch {
      // Partial outcomes are honest ones: whatever was removed is in Deleted items, and the
      // re-derive below shows exactly what is still duplicated.
      setMsg({ kind: "err", text: "The merge didn't finish — any removed copy is in Deleted items. Check the cluster and try again." });
    } finally {
      setMergingId(null);
      setConfirmId(null);
      onChanged();
    }
  };

  return (
    <div className="dupes">
      <h3 className="dupes-title">Duplicate entries</h3>
      <div className="muted" style={{ marginBottom: 10 }}>
        The same account saved more than once — usually a save that landed while the vault was locked, or an import.
        Merging keeps one copy (its saved sites combined) and moves the rest to Deleted items, where they stay restorable for 30 days.
        {" "}Copies sitting in different vaults are listed but never merged — removing one would take it away from everyone who shares that vault.
        {" "}When passwords differ, test by signing in (“open site”), then “Keep this one” — the passwords it replaces stay in the kept item's password history.
        {" "}And a group that's correct as it stands — two services on one host, a deliberate cross-vault twin — can be marked “not duplicates” and stops nagging.
      </div>
      {msg && <Msg kind={msg.kind}>{msg.text}</Msg>}
      {/* BL-1 (audit F12): the merge outcome is ASYNC info — the cluster and its Merge button
          unmount as it lands, and a `.msg info` mounting already-populated is not announced
          (Msg.tsx). Unconditional persistent region, per that contract; failures already speak
          for themselves through role="alert". */}
      <Announcer text={msg && msg.kind === "info" ? msg.text : ""} />
      {active.map((c) => {
        const survivor = c.merge ? c.members.find((m) => m.itemId === c.merge!.survivorId) : undefined;
        const survivorName = survivor?.name ?? "";
        // The vault kept and the vault(s) emptied. planMerge refuses cross-vault clusters, so
        // these are the same place today — naming both is what makes that visible, and keeps
        // the sentence honest if the refusal is ever relaxed.
        const vaultLabel = (vaultId: string) => vaultNameById.get(vaultId) ?? "shared";
        const survivorVault = survivor ? vaultLabel(survivor.vaultId) : "";
        const loserVaults = c.merge
          ? [...new Set(c.merge.loserIds.map((id) => vaultLabel(c.members.find((m) => m.itemId === id)?.vaultId ?? "")))].join(" · ")
          : "";
        return (
          <div className="dupe" key={c.members[0]!.itemId}>
            <div className="dupe-head">
              <span className="dupe-site">{c.sites.join(" · ")}</span>
              {c.kind === "exact" ? (
                <span className="muted">identical copies</span>
              ) : (
                <span className="tone-mid">passwords differ — one is likely stale; the newest is listed first</span>
              )}
            </div>
            {c.members.map((m) => (
              <div className="dupe-member" key={m.itemId}>
                <button type="button" className="link" onClick={() => onOpenItem(m.itemId)}>
                  {m.name}
                </button>
                {/* The vault tag Vault's list rows carry (audit F03) — on EVERY row here,
                    personal included: which vault a copy is in is the one thing that decides
                    whether removing it touches anybody else. */}
                <span className="tag" style={{ color: "var(--gold-text)" }}>{vaultLabel(m.vaultId)}</span>
                <span className="muted">
                  {m.username.trim() || "(no username)"} · updated {new Date(m.updatedAt).toLocaleDateString()}
                  {m.hasTotp ? " · has a one-time code" : ""}
                </span>
                {/* The honest password test (owner decision 2026-08-18): open the site and sign
                    in — the client never probes a site with candidate credentials itself. */}
                {c.kind === "differs" && m.firstUri && (
                  <a className="link" href={/^https?:\/\//i.test(m.firstUri) ? m.firstUri : `https://${m.firstUri}`} target="_blank" rel="noreferrer">
                    open site
                  </a>
                )}
                {c.kind === "differs" && (
                  <button type="button" className="ghost" onClick={() => startKeep(c, m.itemId)} disabled={mergingId !== null}>
                    Keep this one…
                  </button>
                )}
              </div>
            ))}
            {c.kind === "differs" && keepConfirm && keepConfirm.sig === c.signature && (
              <div className="dupe-actions">
                <span className="muted">
                  Keep “{c.members.find((m) => m.itemId === keepConfirm.keepId)?.name ?? ""}” and move{" "}
                  {c.members.length === 2 ? "the other copy" : `the ${c.members.length - 1} other copies`} to Deleted items (kept 30 days)?
                  The passwords they carry stay in the kept item's password history.
                </span>
                <button type="button" className="ghost" onClick={() => void runKeep(c, keepConfirm.keepId)} disabled={mergingId !== null}>
                  {mergingId === keepConfirm.keepId ? "Keeping…" : "Keep"}
                </button>
                <button type="button" className="ghost" onClick={() => setKeepConfirm(null)} disabled={mergingId !== null}>
                  Cancel
                </button>
              </div>
            )}
            {c.kind === "exact" &&
              (c.merge ? (
                confirmId === c.merge.survivorId ? (
                  <div className="dupe-actions">
                    <span className="muted">
                      Keep “{survivorName}” in “{survivorVault}” and move {c.merge.loserIds.length === 1 ? "the other copy" : `the ${c.merge.loserIds.length} other copies`} in “{loserVaults}” to Deleted items (kept 30 days)?
                    </span>
                    <button type="button" className="ghost" onClick={() => void runMerge(c)} disabled={mergingId !== null}>
                      {mergingId === c.merge.survivorId ? "Merging…" : "Merge"}
                    </button>
                    <button type="button" className="ghost" onClick={() => setConfirmId(null)} disabled={mergingId !== null}>
                      Cancel
                    </button>
                  </div>
                ) : (
                  <div className="dupe-actions">
                    <button type="button" className="ghost" onClick={() => setConfirmId(c.merge!.survivorId)}>
                      Merge…
                    </button>
                  </div>
                )
              ) : (
                <div className="dupe-actions">
                  <span className="muted">{c.mergeRefusal}</span>
                </div>
              ))}
            <div className="dupe-actions">
              <button type="button" className="ghost" onClick={() => void runDismiss(c, false)} disabled={mergingId !== null}>
                {c.members.length === 2 ? "Not duplicates — keep both" : "Not duplicates — keep all"}
              </button>
            </div>
          </div>
        );
      })}
      {dismissed.length > 0 && (
        <>
          <h3 className="dupes-title" style={{ marginTop: 14 }}>Marked not duplicates</h3>
          {dismissed.map((c) => (
            <div className="dupe dupe-dismissed" key={c.signature}>
              <span className="dupe-site">{c.sites.join(" · ")}</span>
              <span className="muted">
                {c.members.length} copies · {c.members[0]!.username.trim() || "(no username)"}
              </span>
              <button type="button" className="ghost" onClick={() => void runDismiss(c, true)} disabled={mergingId !== null}>
                Restore
              </button>
            </div>
          ))}
        </>
      )}
    </div>
  );
}

function Tile({ label, value, tone, hint }: { label: string; value: string; tone?: "good" | "bad"; hint?: string }) {
  return (
    <div className="tile">
      <div className={`tile-value ${tone === "bad" ? "tone-bad" : tone === "good" ? "tone-good" : ""}`}>{value}</div>
      <div className="tile-label">{label}{hint ? <span className="muted"> · {hint}</span> : null}</div>
    </div>
  );
}

function StrengthTag({ score }: { score: number }) {
  const cls = score <= 1 ? "tone-bad" : score === 2 ? "tone-mid" : "tone-good";
  return <span className={cls}>{STRENGTH_LABELS[score] ?? "?"}</span>;
}
