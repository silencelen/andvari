import { useEffect, useMemo, useState } from "react";
import type { ClientPolicy, KdfParams as WireKdfParams } from "../api/types";
import { concat, toB64, utf8 } from "../crypto/bytes";
import { DEFAULT_KDF_PARAMS, type KdfParams } from "../crypto/keys";
import { randomBytes } from "../crypto/provider";
import {
  type AttachmentSection,
  type BackupAttachmentEntry,
  type BackupPayload,
  MAX_KDF_MEM_BYTES,
  MAX_KDF_OPS,
  buildBackup,
  csvWarnings,
  openBackup,
  writeCsv,
} from "../export/export";
import {
  buildPreflight,
  exportFilename,
  orderForExport,
  planAttachments,
  writeLastExportAt,
} from "../export/plan";
import type { Account } from "../vault/account";
import type { VaultStore } from "../vault/store";
import { fmtDate, humanSize } from "./format";
import { estimateStrength } from "./strength";

export type ExportMode = "backup" | "csv";

interface Props {
  mode: ExportMode;
  account: Account;
  store: VaultStore;
  policy: ClientPolicy | null;
  onClose: () => void;
}

// libsodium crypto_pwhash minima — mirrors export.ts's private MIN_KDF_* (argon2id
// cannot even run below these; not a policy floor).
const MIN_KDF_OPS = 1;
const MIN_KDF_MEM_BYTES = 8 * 1024;

/**
 * spec 07 §2.3 pins backup derivation to "spec 01 §1 params" — the LIVE org policy's
 * kdfParams when known, NOT the compiled default (a raised org KDF cost must harden
 * backups too). Policy params are accepted only inside the §2.2 open() window —
 * ceilings memBytes ≤ 256 MiB / opsLimit ≤ 16 AND the libsodium minima — so the file
 * we produce is always one our own openBackup (and argon2id itself) accepts; anything
 * outside, a foreign alg/v, or an absent policy falls back to DEFAULT_KDF_PARAMS.
 * Mirrors AndvariViewModel/DesktopState's ceiling-or-default guard (web additionally
 * closes the bottom of the window: wire params here are structurally unvalidated).
 * Exported for tests.
 */
export function backupKdfParams(policy: { kdfParams: WireKdfParams } | null): KdfParams {
  const p = policy?.kdfParams;
  const usable =
    p !== undefined &&
    p.v === 1 &&
    p.alg === "argon2id13" &&
    p.ops >= MIN_KDF_OPS &&
    p.ops <= MAX_KDF_OPS &&
    p.memBytes >= MIN_KDF_MEM_BYTES &&
    p.memBytes <= MAX_KDF_MEM_BYTES;
  return usable ? p : DEFAULT_KDF_PARAMS;
}

/**
 * Export panel (spec 07) — both artifacts are built 100% client-side:
 * - "backup": the encrypted `.andvari` container (§2) — sync first, moment-of-truth
 *   preflight, passphrase with a strength floor, optional attachments under the 64 MiB
 *   cap, verify-before-success, then a Blob download.
 * - "csv": the plaintext migration escape hatch (§1) — by-name loss enumeration and a
 *   plaintext warning gate before the download button enables.
 */
export function ExportPanel({ mode, account, store, policy, onClose }: Props) {
  // spec 07: clients MUST sync before snapshotting; offline → proceed with a visible
  // "vault as of last sync <time>" banner (store.lastSyncAt).
  const [syncDone, setSyncDone] = useState(false);
  const [syncFailed, setSyncFailed] = useState(false);
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        await store.sync();
      } catch {
        if (!cancelled) setSyncFailed(true);
      } finally {
        if (!cancelled) setSyncDone(true);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [store]);

  // Advisory identity fingerprint for the §2.4 payload (restore preview).
  const [fingerprint, setFingerprint] = useState("");
  useEffect(() => {
    account.identityFingerprintShort().then(setFingerprint).catch(() => {});
  }, [account]);

  // Per-vault opt-out (shared vaults only; the personal vault always exports).
  const [excluded, setExcluded] = useState<Set<string>>(new Set());
  const [includeAttachments, setIncludeAttachments] = useState(false);

  // Recompute the preview whenever the sync lands or toggles change.
  const allVaults = useMemo(() => (syncDone ? store.vaults() : []), [store, syncDone]);
  const allItems = useMemo(() => (syncDone ? store.list() : []), [store, syncDone]);
  const preflight = useMemo(() => buildPreflight(allVaults, allItems), [allVaults, allItems]);
  const includedVaults = useMemo(
    () => allVaults.filter((v) => v.type === "personal" || !excluded.has(v.vaultId)),
    [allVaults, excluded],
  );
  const orderedItems = useMemo(() => orderForExport(allItems, includedVaults), [allItems, includedVaults]);
  const attachmentPlan = useMemo(() => planAttachments(orderedItems), [orderedItems]);

  const toggleVault = (vaultId: string) =>
    setExcluded((old) => {
      const next = new Set(old);
      if (next.has(vaultId)) next.delete(vaultId);
      else next.add(vaultId);
      return next;
    });

  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState("");
  const [err, setErr] = useState("");
  const [done, setDone] = useState<{ filename: string; overCap: string[]; fetchFailed: string[] } | null>(null);

  // ---- backup passphrase (spec 07 §2.3) ----
  const [pw, setPw] = useState("");
  const [confirm, setConfirm] = useState("");
  const strength = estimateStrength(pw);
  const nonAscii = /[^\x20-\x7e]/.test(pw);
  const passOk = pw.length > 0 && strength >= 3 && pw === confirm;

  const runBackup = async () => {
    setBusy(true);
    setErr("");
    try {
      keepAutoLockAlive();
      // 1. Fetch + section attachments one at a time (opt-in; §2.5). A fetch failure
      //    is retried once, then skipped BY NAME — never silently, never fatal.
      const fetchFailed: string[] = [];
      const sections: AttachmentSection[] = [];
      const manifest: BackupAttachmentEntry[] = [];
      if (includeAttachments) {
        for (const { item, ref } of attachmentPlan.included) {
          setProgress(`Fetching attachment “${ref.name}”…`);
          keepAutoLockAlive();
          let data: Uint8Array | null = null;
          try {
            data = await store.downloadAttachment(item, ref);
          } catch {
            try {
              data = await store.downloadAttachment(item, ref); // retry once
            } catch {
              fetchFailed.push(ref.name);
            }
          }
          if (!data) continue;
          const fileKey = randomBytes(32); // FRESH key for this file's own section
          manifest.push({
            section: manifest.length + 1,
            attachmentId: ref.id,
            itemId: item.itemId,
            name: ref.name,
            size: data.length,
            fileKey: toB64(fileKey),
          });
          const plain = data;
          sections.push({ fileKey, plaintext: () => plain });
        }
      }

      // 2. §2.4 payload. `undecryptable` = the store's retained sync-time failures
      //    (VK held, decrypt failed — newer formatVersion or corrupt blob), minus any
      //    vault the user deselected above (the Kotlin call sites apply the same
      //    filter) — enumerated so a restore can see what the backup is missing,
      //    never silently omitted. Everything in `items` decrypted as formatVersion 1.
      const payload: BackupPayload = {
        v: 1,
        exportedAt: Date.now(),
        origin: typeof window !== "undefined" ? window.location.origin : "",
        userId: account.userId,
        identityFingerprint: fingerprint,
        vaults: includedVaults.map((v) => ({ vaultId: v.vaultId, type: v.type, name: v.name, role: v.role ?? "" })),
        items: orderedItems.map((it) => ({
          itemId: it.itemId,
          vaultId: it.vaultId,
          formatVersion: 1,
          updatedAt: it.updatedAt,
          doc: it.doc,
        })),
        attachments: manifest,
        skipped: {
          undecryptable: store.undecryptable().filter((u) => !excluded.has(u.vaultId)),
          attachmentsOverCap: includeAttachments ? attachmentPlan.overCap : [],
          attachmentFetchFailed: fetchFailed,
        },
      };

      // 3. Build (spec 01 §1 production KDF params — the live policy's, window-checked
      //    by backupKdfParams — fresh salt + fileId).
      setProgress("Sealing backup…");
      keepAutoLockAlive();
      const parts = await buildBackup(pw, crypto.randomUUID(), randomBytes(16), backupKdfParams(policy), payload, sections);
      const bytes = concat(...parts);

      // 4. Verify BEFORE declaring success (§2.6): re-open the exact output bytes and
      //    check every attachment section's final tag, single pass.
      setProgress("Verifying…");
      keepAutoLockAlive();
      const opened = await openBackup(pw, bytes);
      for (const entry of opened.payload.attachments) opened.readAttachment(entry).fill(0);

      // 5. Only now hand the file to the browser (a lock anywhere above aborts with
      //    no partial file — nothing has left memory yet).
      const filename = exportFilename("backup");
      downloadBlob([bytes as BlobPart], "application/octet-stream", filename);
      writeLastExportAt(account.userId, Date.now());
      setDone({ filename, overCap: includeAttachments ? attachmentPlan.overCap : [], fetchFailed });
      setPw("");
      setConfirm("");
    } catch {
      setErr("Backup failed — no file was saved. Nothing about your vault changed; try again.");
    } finally {
      setBusy(false);
      setProgress("");
    }
  };

  // ---- CSV (spec 07 §1) ----
  const warnings = useMemo(() => csvWarnings(orderedItems.map((it) => it.doc)), [orderedItems]);
  const [plaintextAck, setPlaintextAck] = useState(false);
  const loginCount = orderedItems.filter((it) => it.doc.type === "login").length;

  const runCsv = () => {
    setErr("");
    try {
      keepAutoLockAlive();
      const csv = writeCsv(orderedItems.map((it) => it.doc));
      const filename = exportFilename("csv");
      // UTF-8, no BOM (spec 07 §1) — encode explicitly rather than trusting Blob string handling.
      downloadBlob([utf8(csv) as BlobPart], "text/csv", filename);
      writeLastExportAt(account.userId, Date.now());
      setDone({ filename, overCap: [], fetchFailed: [] });
    } catch {
      setErr("Export failed — no file was saved.");
    }
  };

  const title = mode === "backup" ? "Back up vault" : "Export for another password manager";

  return (
    <div className="sheet">
      <button type="button" className="link" onClick={onClose} disabled={busy}>← back to vault</button>
      <h2 style={{ marginTop: 12 }}>{title}</h2>
      <div className="muted" style={{ marginBottom: 18 }}>
        {mode === "backup"
          ? "An encrypted file holding every item you can read · built entirely on this device"
          : "A plaintext CSV other password managers can import · built entirely on this device"}
      </div>

      {!syncDone ? (
        <p className="muted">syncing your vault…</p>
      ) : done ? (
        <>
          <div className="msg info" style={{ display: "block" }}>
            {mode === "backup" ? (
              <>
                <strong>Backup saved as “{done.filename}”.</strong> It opens only with the passphrase
                you just chose — if you later change your master password, this file still uses
                today's passphrase. Store it somewhere safe (and separate from the passphrase).
              </>
            ) : (
              <>
                <strong>Exported “{done.filename}”.</strong> That file holds every password in
                plaintext — after the other password manager imports it, delete it and empty
                your trash.
              </>
            )}
          </div>
          {done.overCap.length > 0 && (
            <div className="msg info" style={{ display: "block" }}>
              Skipped (over the {humanSize(64 * 1024 * 1024)} attachment cap): {done.overCap.join(", ")}.
            </div>
          )}
          {done.fetchFailed.length > 0 && (
            <div className="msg err" style={{ display: "block" }}>
              Could not fetch (skipped after a retry): {done.fetchFailed.join(", ")}. The items
              themselves are in the backup; only these attachment files are missing.
            </div>
          )}
          <div className="actions">
            <button type="button" className="primary" onClick={onClose}>Done</button>
          </div>
        </>
      ) : (
        <>
          {syncFailed && (
            <div className="msg info" style={{ display: "block" }}>
              You appear to be offline — this file will reflect your vault as of the last sync
              ({store.lastSyncAt ? fmtDate(store.lastSyncAt) : "unknown"}).
            </div>
          )}

          {/* Moment-of-truth preflight: per-vault counts, shared vaults on by default. */}
          <div className="field">
            <label>What gets exported</label>
            {preflight.map((v) => (
              <div className="attach-row" key={v.vaultId}>
                {v.type === "personal" ? (
                  <span className="attach-name">{v.name}</span>
                ) : (
                  <label className="attach-name" style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    <input type="checkbox" checked={!excluded.has(v.vaultId)} onChange={() => toggleVault(v.vaultId)} disabled={busy} />
                    {v.name} <span className="muted">(shared)</span>
                  </label>
                )}
                <span className="muted">{v.itemCount} {v.itemCount === 1 ? "item" : "items"}</span>
              </div>
            ))}
            {preflight.some((v) => v.type !== "personal") && (
              <p className="muted" style={{ marginBottom: 0 }}>
                Exporting is private — other members and the server are not notified.
              </p>
            )}
          </div>

          {mode === "backup" ? (
            <>
              <div className="field">
                <label style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <input type="checkbox" checked={includeAttachments} onChange={(e) => setIncludeAttachments(e.target.checked)} disabled={busy} />
                  Include attachment files ({attachmentPlan.included.length}, {humanSize(attachmentPlan.totalBytes)})
                </label>
                {includeAttachments && attachmentPlan.overCap.length > 0 && (
                  <p className="muted" style={{ marginBottom: 0 }}>
                    Over the {humanSize(64 * 1024 * 1024)} total cap, skipped: {attachmentPlan.overCap.join(", ")}.
                  </p>
                )}
              </div>

              <div className="field">
                <label>Backup passphrase</label>
                <input type="password" className="mono" autoComplete="new-password" value={pw} onChange={(e) => setPw(e.target.value)} disabled={busy} />
                {pw && <StrengthBar password={pw} />}
                {pw && strength < 3 && <span className="muted" style={{ color: "var(--danger)" }}>too weak — this passphrase is all that protects the file</span>}
                {nonAscii && (
                  <span className="muted">
                    Contains non-ASCII characters — they are taken exactly as typed, so make sure you
                    can retype them on a future keyboard.
                  </span>
                )}
              </div>
              <div className="field">
                <label>Confirm passphrase</label>
                <input type="password" className="mono" autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} disabled={busy} />
                {confirm && confirm !== pw && <span className="muted" style={{ color: "var(--danger)" }}>passphrases don't match</span>}
              </div>
              <p className="muted">
                Tip: your master password is a fine choice — the backup is then exactly as protected
                as your vault. A different passphrase belongs on your printed recovery sheet.
              </p>

              {err && <div className="msg err">{err}</div>}
              {busy && progress && <p className="muted">{progress}</p>}
              <div className="actions">
                <button type="button" className="primary" disabled={busy || !passOk} onClick={runBackup}>
                  {busy ? "Working…" : "Create encrypted backup"}
                </button>
                <div className="spacer" />
                <button type="button" className="ghost" onClick={onClose} disabled={busy}>Cancel</button>
              </div>
            </>
          ) : (
            <>
              {/* §1 loss enumeration — by item NAME, never by count. */}
              {warnings.noteItems.length > 0 && (
                <div className="msg info" style={{ display: "block" }}>
                  Secure notes are not part of the CSV format and will be left out: {warnings.noteItems.join(", ")}.
                </div>
              )}
              {warnings.withAttachments.length > 0 && (
                <div className="msg info" style={{ display: "block" }}>
                  Attachments cannot be represented in a CSV — these items export without their files: {warnings.withAttachments.join(", ")}.
                </div>
              )}
              {warnings.extraUris.length > 0 && (
                <div className="msg info" style={{ display: "block" }}>
                  Only the first website is kept — extra websites are dropped from: {warnings.extraUris.join(", ")}.
                </div>
              )}
              {warnings.emptyUsernameAndPassword.length > 0 && (
                <div className="msg info" style={{ display: "block" }}>
                  These have no username or password — they are written, but most importers (including
                  andvari's) skip them: {warnings.emptyUsernameAndPassword.join(", ")}.
                </div>
              )}
              <div className="msg info" style={{ display: "block" }}>
                Re-importing this file later collapses exact duplicates into one login.
              </div>

              {/* The spec 06 plaintext warning gates the download button. */}
              <div className="msg info" style={{ display: "block" }}>
                <strong>⚠ This file will hold every password in plaintext.</strong> Nothing about it
                is uploaded — it is written here in your browser. Import it into the other password
                manager right away, then delete it and empty your trash.
              </div>
              <div className="field">
                <label style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <input type="checkbox" checked={plaintextAck} onChange={(e) => setPlaintextAck(e.target.checked)} />
                  I understand this file is unencrypted
                </label>
              </div>

              {err && <div className="msg err">{err}</div>}
              <div className="actions">
                <button type="button" className="primary" disabled={!plaintextAck || loginCount === 0} onClick={runCsv}>
                  Download {loginCount} {loginCount === 1 ? "login" : "logins"} as CSV
                </button>
                <div className="spacer" />
                <button type="button" className="ghost" onClick={onClose}>Cancel</button>
              </div>
            </>
          )}
        </>
      )}
    </div>
  );
}

/**
 * Export must count as user activity for the spec 01 §8 auto-lock (spec 07 §2.6).
 * useAutoLock exposes no imperative handle — its ONLY activity signal is a
 * capture-phase pointerdown/keydown/touchstart listener on window — so the hands-off
 * phases here (Argon2id, attachment fetches, verify) dispatch a synthetic pointerdown
 * through that same listener (script-created events are untrusted, isTrusted=false,
 * but DOM listeners still run). Independently, the flow is abort-safe: everything is
 * assembled in memory and the Blob download is the LAST step, so a lock mid-export
 * unmounts the panel and leaves no partial file (§2.6's other allowed behavior).
 */
function keepAutoLockAlive(): void {
  if (typeof window !== "undefined") window.dispatchEvent(new Event("pointerdown"));
}

/** One-shot object-URL download — the AttachmentList pattern. */
function downloadBlob(parts: BlobPart[], type: string, filename: string): void {
  const url = URL.createObjectURL(new Blob(parts, { type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/** Mirror of Vault.tsx's StrengthBar (kept local — importing it back from Vault.tsx
 *  would create a Vault ⇄ ExportPanel import cycle). */
function StrengthBar({ password }: { password: string }) {
  const score = estimateStrength(password);
  const colors = ["var(--danger)", "var(--danger)", "var(--gold)", "var(--ok)", "var(--ok)"];
  return (
    <div className="strength">
      <span style={{ width: `${(score + 1) * 20}%`, background: colors[score] }} />
    </div>
  );
}
