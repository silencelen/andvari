import { useMemo, useState } from "react";
import type { VaultItem, VaultStore } from "../vault/store";
import { fmtDay } from "./format";
import { CLIPBOARD_FAILED, CLIPBOARD_NOT_CLEARED } from "./errors";
import { Announcer, Msg } from "./Msg";
import { useCopy } from "./usecopy";
import { safeSiteHref } from "./safeurl";
import { EmptySigil } from "./Sigil";
import { type RoleFor, SNOOZE_MS, type StalenessRow, planCheck, planUnsnooze, stalenessRows } from "./staleness";

/**
 * The Staleness half of Vault health (owner-requested 2026-08-22; design
 * 2026-08-22-login-health-staleness-verification). Renders and writes ONLY — every ranking,
 * bucket and composed doc is decided in the pure staleness.ts, the duplicates.ts arrangement.
 *
 * THE VERIFICATION RUN IS SEMI-AUTOMATIC BY DOCTRINE, not by omission. The rule was already
 * settled for the duplicate checker's differs flow (duplicates.ts:55) and this generalizes it:
 * *the only honest password test is the human logging in; the client must never probe a site
 * with candidate credentials itself.* So this view opens a tab and gets out of the way. It does
 * not submit the form, does not fetch the site to guess whether it is alive, and does not read
 * the page to infer whether the sign-in worked — that last one would need a content script on
 * arbitrary pages, a permission and threat escalation bought for a guess. The human asserts; we
 * record.
 *
 * The extension "assist" needs no plumbing and none is invented here: opening the site in a tab
 * is enough, because an installed extension offers its ordinary autofill on arrival. There is
 * deliberately no web-to-extension channel (the extension is a separate client with its own
 * storage, and injecting into the vault origin is fail-closed forbidden — background.ts).
 */

interface Props {
  items: VaultItem[];
  roleFor: RoleFor;
  store: VaultStore;
  onOpenItem: (itemId: string) => void;
  /** Vault's refresh() — re-derives `items` so a recorded verdict leaves the list immediately. */
  onChanged: () => void;
  /** The clipboard auto-clear window; the shared useCopy hook owns the clamp and the timer, so
   *  this view cannot invent its own copy policy. */
  clearSeconds: number;
  /** Usage lookup (spec 02 §8.2). Absent = no recorded use, which renders "—" and NEVER
   *  "never used" — a distinction the whole ledger design turns on. */
  lastUsedAt?: (itemId: string) => number | undefined;
  /** Report a real use. Copying the password and opening the site to sign in are both genuine
   *  uses; merely LOOKING at the staleness row is not, so the table itself records nothing. */
  onUsed?: (itemId: string) => void;
}

/** The four verdicts, with the sentence each one is really making. Order = the order a user
 *  scans them in: the good outcome first, then progressively worse. */
const VERDICTS: { result: string; label: string; hint: string }[] = [
  { result: "ok", label: "Signed in", hint: "The saved password worked." },
  { result: "bad", label: "Wrong password", hint: "It was refused — the saved one is out of date." },
  { result: "gone", label: "Account is gone", hint: "The account or the whole service no longer exists." },
  { result: "blocked", label: "Couldn't complete", hint: "MFA, a lockout or a captcha stopped the test." },
];

/** "3 months ago" at day resolution — enough for a staleness column, and it never implies a
 *  precision the underlying client clock does not have. */
function ago(ms: number | undefined, now: number): string {
  if (ms === undefined) return "—";
  const days = Math.max(0, Math.floor((now - ms) / 86_400_000));
  if (days === 0) return "today";
  if (days === 1) return "yesterday";
  if (days < 60) return `${days} days ago`;
  const months = Math.floor(days / 30);
  return months < 24 ? `${months} months ago` : `${Math.floor(days / 365)} years ago`;
}

function CheckCell({ row, now }: { row: StalenessRow; now: number }) {
  if (!row.check) return <span className="muted">never</span>;
  const v = VERDICTS.find((x) => x.result === row.check!.result);
  // spec 02 §3: the vocabulary is OPEN — an unrecognized verdict from a newer client reads as
  // "checked", never as a failure and never as a crash.
  const label = v ? v.label : "checked";
  const tone = row.check.result === "ok" ? "tone-good" : v ? "tone-bad" : "muted";
  return (
    <span>
      <span className={tone}>{label}</span> <span className="muted">· {ago(row.checkedAt, now)}</span>
    </span>
  );
}

export function Staleness({ items, roleFor, store, onOpenItem, onChanged, clearSeconds, lastUsedAt, onUsed }: Props) {
  const { flash, copyErr, wipeStuck, copy } = useCopy(clearSeconds);
  const [showSnoozed, setShowSnoozed] = useState(false);
  const [msg, setMsg] = useState<{ kind: "err" | "info"; text: string } | null>(null);
  const [busy, setBusy] = useState(false);
  // The run is SESSION-SCOPED and never persisted — the owner's 2026-08-18 rule that sort/filter
  // state must not be "helpfully" remembered applies to wizard position too.
  const [run, setRun] = useState<{ queue: string[]; index: number } | null>(null);
  // "Account is gone" records the verdict and then OFFERS a delete. Never automatic: a deletion
  // the user did not ask for is the one outcome this whole view exists to avoid.
  const [offerDelete, setOfferDelete] = useState<string | null>(null);

  const now = Date.now();
  // bug-web--1: keyed on `items` (whose identity changes on every applied sync), never on
  // `store` (whose identity never changes for the mount, and which froze this view once before).
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const rows = useMemo<StalenessRow[]>(
    () => stalenessRows(items, { lastUsedAt, includeSnoozed: showSnoozed, now }),
    [items, showSnoozed, lastUsedAt],
  );

  const current = run ? items.find((it) => it.itemId === run.queue[run.index]) : undefined;
  const currentRow = current ? rows.find((r) => r.itemId === current.itemId) : undefined;

  const advance = () =>
    setRun((r) => {
      if (!r) return null;
      const next = r.index + 1;
      if (next >= r.queue.length) {
        setMsg({ kind: "info", text: "Run finished — every login in the list has been looked at." });
        return null;
      }
      return { ...r, index: next };
    });

  const startRun = (queue: string[]) => {
    if (queue.length === 0) return;
    setMsg(null);
    setOfferDelete(null);
    setRun({ queue, index: 0 });
  };

  const record = async (itemId: string, result: string, snoozeMs?: number) => {
    if (busy) return;
    const plan = planCheck(items, itemId, result, Date.now(), roleFor, snoozeMs);
    if (!plan.write) {
      setMsg({ kind: "err", text: plan.refusal ?? "That check couldn't be recorded." });
      return;
    }
    setBusy(true);
    setMsg(null);
    try {
      await store.save(plan.write.itemId, plan.write.doc);
      if (result === "gone") setOfferDelete(itemId);
      else setOfferDelete(null);
      advance();
    } catch {
      // Offline writes queue, so the honest failure here is "it didn't land", not "it was lost".
      setMsg({ kind: "err", text: "That check didn't save — nothing was changed. Try again." });
    } finally {
      setBusy(false);
      onChanged();
    }
  };

  const unsnooze = async (itemId: string) => {
    const plan = planUnsnooze(items, itemId, roleFor);
    if (plan.refusal) {
      setMsg({ kind: "err", text: plan.refusal });
      return;
    }
    if (!plan.write) return;
    setBusy(true);
    try {
      await store.save(plan.write.itemId, plan.write.doc);
      setMsg({ kind: "info", text: "Back on the list." });
    } catch {
      setMsg({ kind: "err", text: "Couldn't clear the snooze — try again." });
    } finally {
      setBusy(false);
      onChanged();
    }
  };

  const removeGone = async (itemId: string) => {
    setBusy(true);
    try {
      await store.remove(itemId);
      setMsg({ kind: "info", text: "Moved to Deleted items — it stays restorable there for 30 days." });
      setOfferDelete(null);
    } catch {
      setMsg({ kind: "err", text: "Couldn't delete that item — try again." });
    } finally {
      setBusy(false);
      onChanged();
    }
  };

  const unchecked = rows.filter((r) => r.bucket === "never").map((r) => r.itemId);

  if (rows.length === 0 && !showSnoozed) {
    return (
      <div className="empty">
        <div className="sigil"><EmptySigil /></div>
        <p>No logins to rank yet — staleness needs saved logins.</p>
      </div>
    );
  }

  return (
    <div className="stale">
      <h3 className="dupes-title">Oldest and least-checked logins</h3>
      <div className="muted" style={{ marginBottom: 10 }}>
        Ranked worst first: logins whose last check FAILED, then ones never checked at all (oldest change first),
        then whichever has gone longest since a human confirmed it.
        {" "}“Last changed” is exactly that — any edit bumps it, so it is not the age of the password.
        {" "}“Last used here” comes from this app on this device only; a fill on your phone will not show up.
        {" "}Checking is deliberately manual: andvari opens the site and you sign in — it never tries the password for you.
      </div>

      {msg && <Msg kind={msg.kind}>{msg.text}</Msg>}
      {copyErr && <Msg kind="err">{CLIPBOARD_FAILED}</Msg>}
      {wipeStuck && <Msg kind="err">{CLIPBOARD_NOT_CLEARED}</Msg>}
      {/* BL-1: copy confirmation and run outcomes are polite async info — one persistent live
          region, matching Detail's contract (a .msg mounting already-populated is not announced). */}
      <Announcer
        text={wipeStuck ? CLIPBOARD_NOT_CLEARED : copyErr ? CLIPBOARD_FAILED : flash ? `${flash} copied` : msg && msg.kind === "info" ? msg.text : ""}
      />

      {offerDelete && (
        <div className="confirm-row">
          <span>Marked as gone. Remove it from the vault?</span>
          <button type="button" className="danger" disabled={busy} onClick={() => void removeGone(offerDelete)}>
            Move to Deleted items
          </button>
          <button type="button" className="ghost" onClick={() => setOfferDelete(null)}>Keep it</button>
        </div>
      )}

      {current && currentRow ? (
        <div className="run-card">
          <div className="run-head">
            <strong>{currentRow.name}</strong>
            <span className="muted"> · {run!.index + 1} of {run!.queue.length}</span>
          </div>
          <div className="muted" style={{ marginBottom: 8 }}>
            Open the site, sign in yourself, then come back and say what happened.
          </div>
          <div className="run-actions">
            {currentRow.username && (
              <button type="button" className="ghost" onClick={() => copy("username", currentRow.username)}>
                Copy username
              </button>
            )}
            {current.doc.login?.password && (
              <button type="button" className="ghost" onClick={() => { onUsed?.(current.itemId); copy("password", current.doc.login!.password!); }}>
                Copy password
              </button>
            )}
            {flash && (
              <span className="copy-flash">{wipeStuck ? "still on your clipboard" : `${flash} copied ✓ · clears in ${clearSeconds}s`}</span>
            )}
            {/* safeSiteHref, not an inline regex: in a SHARED vault this uri was authored by
                another member, which is what makes a javascript: value a real vector. */}
            {(() => {
              const href = safeSiteHref(currentRow.firstUri);
              return href ? (
                <a className="link" href={href} target="_blank" rel="noreferrer" onClick={() => onUsed?.(current.itemId)}>open site ↗</a>
              ) : (
                <span className="muted">no saved site to open</span>
              );
            })()}
          </div>
          <div className="run-verdicts">
            {VERDICTS.map((v) => (
              <button
                key={v.result}
                type="button"
                disabled={busy}
                title={v.hint}
                onClick={() => void record(current.itemId, v.result, v.result === "blocked" ? SNOOZE_MS : undefined)}
              >
                {v.label}
              </button>
            ))}
            {/* Skip writes NOTHING — an unanswered item must not become a recorded verdict. */}
            <button type="button" className="ghost" disabled={busy} onClick={advance}>Skip</button>
            <button type="button" className="ghost" disabled={busy} onClick={() => setRun(null)}>Stop</button>
          </div>
          <div className="muted" style={{ marginTop: 6 }}>
            “Couldn't complete” also quiets this login for 30 days.
          </div>
        </div>
      ) : (
        <div className="run-actions" style={{ marginBottom: 10 }}>
          <button type="button" className="ghost" disabled={unchecked.length === 0} onClick={() => startRun(unchecked)}>
            Check the {unchecked.length} never-checked
          </button>
          <button type="button" className="ghost" disabled={rows.length === 0} onClick={() => startRun(rows.map((r) => r.itemId))}>
            Check everything, worst first
          </button>
          <label className="inline-check">
            <input type="checkbox" checked={showSnoozed} onChange={(e) => setShowSnoozed(e.target.checked)} />
            Show snoozed
          </label>
        </div>
      )}

      <div className="table-scroll">
        <table className="table">
          <thead>
            <tr>
              <th>Item</th>
              <th>Last used here</th>
              <th>Last changed</th>
              <th>Last checked</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.itemId} className="rowlink" onClick={() => onOpenItem(r.itemId)}>
                <td>
                  <button type="button" className="link" onClick={(e) => { e.stopPropagation(); onOpenItem(r.itemId); }}>
                    {r.name}
                  </button>
                  {r.snoozed && <span className="muted"> · snoozed</span>}
                </td>
                <td>{r.lastUsedAt === undefined ? <span className="muted">—</span> : ago(r.lastUsedAt, now)}</td>
                <td title={fmtDay(r.updatedAt)}>{ago(r.updatedAt, now)}</td>
                <td><CheckCell row={r} now={now} /></td>
                <td>
                  {r.snoozed ? (
                    <button type="button" className="ghost" disabled={busy} onClick={(e) => { e.stopPropagation(); void unsnooze(r.itemId); }}>
                      Unsnooze
                    </button>
                  ) : (
                    <button type="button" className="ghost" disabled={busy} onClick={(e) => { e.stopPropagation(); startRun([r.itemId]); }}>
                      Check
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
