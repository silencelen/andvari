import { useEffect, useMemo, useRef, useState } from "react";
import type { VaultItem, VaultStore } from "../vault/store";
import { ago, fmtDay } from "./format";
import { CLIPBOARD_FAILED, CLIPBOARD_NOT_CLEARED } from "./errors";
import { Announcer, Msg } from "./Msg";
import { useCopy } from "./usecopy";
import { safeSiteHref } from "./safeurl";
import { Empty } from "./Empty";
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
  /** Jump to an item. `generate` (H117) additionally opens its editor with a freshly generated
   *  password — the design §4 "bad → offers: … generate a new password" leg. */
  onOpenItem: (itemId: string, opts?: { generate?: boolean }) => void;
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

/** H30: the sentence the run feeds its live region on every advance — the login's name AND its
 *  position, because the verdict buttons keep their DOM place across record() → advance(), so a
 *  screen-reader user whose focus never moved would otherwise answer for a login they were never
 *  told about. Exported pure so staleness-run-a11y.test.ts pins the shape. */
export function runPositionSentence(name: string, index: number, total: number): string {
  return `Now checking ${name} · ${index + 1} of ${total}`;
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
  // H117: "Wrong password" records the verdict and then OFFERS the two follow-ups the design's §4
  // table has promised since the feature was ratified — open the item, or open it with a new
  // password generated. Neither is automatic and neither writes: a client that changed a password
  // on its own would be changing it on ANDVARI only, while the site still holds the old one.
  const [offerBad, setOfferBad] = useState<string | null>(null);

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

  // H30 (audit 2026-09-13): the run used to advance SILENTLY. Two things made it so: nothing in the
  // Announcer chain changed on an advance (setMsg(null) blanks it), and focus stayed on the verdict
  // button just pressed while React swapped the heading to the next login — or, on start, the
  // run-actions buttons were unmounted wholesale under the focused element and focus fell to
  // <body>. So a screen-reader user recorded "Signed in" against logins they could not see. Fix,
  // both legs: (1) a DEDICATED persistent live region carries the name + position sentence, and
  // its text changes on every index change (the persistent-node mutation is what a polite region
  // actually announces — Msg.tsx); it is separate from the outcome Announcer so a copy flash or a
  // delete offer never masks the position. (2) the run head is a focus target (tabIndex -1) and
  // takes focus whenever the run starts or advances, so the swap that unmounts the start buttons
  // lands focus ON the card, and each verdict lands it on the next login's name.
  const runNotice = current && currentRow && run ? runPositionSentence(currentRow.name, run.index, run.queue.length) : "";
  const runHeadRef = useRef<HTMLDivElement>(null);
  const runKey = run ? `${run.index}/${run.queue.join(",")}` : null;
  useEffect(() => {
    if (runKey !== null) runHeadRef.current?.focus();
  }, [runKey]);

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
    setOfferBad(null);
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
      // One offer at a time: each verdict's follow-up replaces the previous one, so the card
      // never stacks two "what now?" rows for two different logins.
      setOfferDelete(result === "gone" ? itemId : null);
      setOfferBad(result === "bad" ? itemId : null);
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

  // G27: by the time the offer renders, the run card has already advanced to the NEXT login, so
  // the sentence must NAME the item — a bare "it" points at whatever is now on screen. The same
  // sentence feeds the persistent Announcer below (a conditionally-mounted row is silent to AT).
  const nameOf = (itemId: string | null) =>
    itemId ? items.find((it) => it.itemId === itemId)?.doc.name || "(untitled)" : null;
  const offerName = nameOf(offerDelete);
  const offerSentence = offerName ? `“${offerName}” is marked as gone. Remove it from the vault?` : "";
  // H117: the same G27 rule for the bad-password offer — by the time it renders the card has
  // advanced to the NEXT login, so the sentence must NAME the item it is about.
  const badName = nameOf(offerBad);
  const badSentence = badName ? `“${badName}” is marked as having the wrong password. Change it?` : "";

  if (rows.length === 0 && !showSnoozed) {
    // Two states land here and need different sentences: zero saved logins, or every login
    // snoozed — which only happens via the failing "Couldn't complete" verdict, the opposite of
    // "nothing to worry about". The Show-snoozed toggle stays mounted in the all-snoozed state:
    // Unsnooze lives on rows, so unmounting the toggle here left snoozed logins unreachable for
    // up to 30 days.
    const snoozedCount = stalenessRows(items, { lastUsedAt, includeSnoozed: true, now }).length;
    return (
      <Empty>
        {snoozedCount > 0 ? (
          <>
            {/* H123: ONE sentence with the Android twin (HealthScreen.kt's all-snoozed Empty),
                pinned in staleness-empty-state-copy.test.ts. G31 fixed this empty state on both
                clients in the same remediation and each lane wrote its own wording from the
                feature description rather than from a pinned string — the exact drift the
                predecessor audit named. The phone's sentence wins because it NAMES the control
                the user has to operate ("Show snoozed", the label on the checkbox directly
                below) instead of the vaguer "show them". */}
            <p>Every login is snoozed right now — Show snoozed to see them or bring one back early.</p>
            <label className="inline-check">
              <input type="checkbox" checked={showSnoozed} onChange={(e) => setShowSnoozed(e.target.checked)} />
              Show snoozed
            </label>
          </>
        ) : (
          <p>No logins to rank yet — staleness needs saved logins.</p>
        )}
      </Empty>
    );
  }

  return (
    <div className="stale">
      <h3 className="dupes-title">Oldest and least-checked logins</h3>
      <div className="muted" style={{ marginBottom: 10 }}>
        Ranked worst first: logins whose last check FAILED, then ones never checked at all (oldest change first),
        then whichever has gone longest since a human confirmed it.
        {" "}“Last changed” is exactly that — any edit bumps it, so it is not the age of the password.
        {" "}“Last used” syncs across your devices — a password copied on the phone or filled by the browser extension counts here too. The one gap: a fill by the phone's autofill service can't be recorded.
        {" "}Checking is deliberately manual: andvari opens the site and you sign in — it never tries the password for you.
      </div>

      {msg && <Msg kind={msg.kind}>{msg.text}</Msg>}
      {copyErr && <Msg kind="err">{CLIPBOARD_FAILED}</Msg>}
      {wipeStuck && <Msg kind="err">{CLIPBOARD_NOT_CLEARED}</Msg>}
      {/* BL-1: copy confirmation, run outcomes and the delete offer are polite async info — one
          persistent live region, matching Detail's contract (a .msg mounting already-populated is
          not announced). */}
      <Announcer
        text={wipeStuck ? CLIPBOARD_NOT_CLEARED : copyErr ? CLIPBOARD_FAILED : flash ? `${flash} copied` : offerSentence ? offerSentence : badSentence ? badSentence : msg && msg.kind === "info" ? msg.text : ""}
      />
      {/* H30: the run's position, on its own persistent region (see the note at runNotice). */}
      <Announcer text={runNotice} />

      {offerDelete && (
        <div className="confirm-row">
          <span>{offerSentence}</span>
          {/* H50: the house destructive idiom (Vault's Confirm delete / Delete forever, Sharing's
              Delete vault) — a ghost in the danger ink. This carried a bare `danger` class name, a class
              defined nowhere, so the one destructive control in the row fell through to the UA's
              grey system button with no red tone, no theme, and no focus-ring parity. */}
          <button type="button" className="ghost" style={{ color: "var(--danger)" }} disabled={busy} onClick={() => void removeGone(offerDelete)}>
            Move to Deleted items
          </button>
          <button type="button" className="ghost" onClick={() => setOfferDelete(null)}>Keep it</button>
        </div>
      )}

      {/* H117: the post-"Wrong password" offers the design's §4 verdict table promises. Until now
          the four verdicts each claimed "a different next action" and only `gone` and `blocked`
          had one, so a user who told andvari the saved password was refused was moved straight on
          to the next login with no path to the item they had just found broken. Same shape as the
          gone offer beside it (a .confirm-row naming the item), same doctrine as the rest of this
          view: the client opens things and gets out of the way — it never changes a password on
          the site, and it never saves one here without a Save. */}
      {offerBad && (
        <div className="confirm-row">
          <span>{badSentence}</span>
          <button type="button" className="ghost" disabled={busy} onClick={() => onOpenItem(offerBad)}>
            Open the item
          </button>
          <button type="button" className="ghost" disabled={busy} onClick={() => onOpenItem(offerBad, { generate: true })}>
            Generate a new password
          </button>
          <button type="button" className="ghost" onClick={() => setOfferBad(null)}>Not now</button>
        </div>
      )}

      {current && currentRow ? (
        <div className="run-card">
          <div className="run-head" ref={runHeadRef} tabIndex={-1}>
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
                className="ghost"
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
              <th>Last used</th>
              <th>Last changed</th>
              <th>Last checked</th>
              {/* G57: named for AT — the sibling Health table names every column. */}
              <th><span className="visually-hidden">Actions</span></th>
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
