import { useState } from "react";
import type { ContactPrompt } from "../vault/contactbook";
import type { Adoption } from "../vault/logstore";
import type { SharedAsk, SharedLogSession } from "../vault/sharedlogs";
import {
  CONTACT_PROMPT,
  CONTACT_PROMPT_YES,
  ONE_TAP_BODY,
  ONE_TAP_CONFIRM,
  ONE_TAP_LATER,
  ONE_TAP_TITLE,
  SHARE_ACCEPT,
  SHARE_ASK,
  SHARE_ASK_WAITING,
  SHARE_ASK_WAITING_ONE,
  SHARE_CONNECT_FIRST,
  SHARE_CONNECT_FIRST_UNNAMED,
  SHARE_DECLINE,
  SHARE_ANSWER_UNKNOWN,
  SHARE_DECLINE_FROZEN_REFUSED,
  SHARE_DECLINE_FROZEN_STORED,
  SHARE_DECLINE_FROZEN_UNKNOWN,
  SHARE_DECLINE_NOT_STORED,
  SHARE_DECLINE_WAITING,
  SHARE_NOT_RECORDED,
  fill,
} from "./copy";
import { Announcer } from "./Msg";

/**
 * The line after the person answered an incoming share, or null when nothing is to be said: "wasn't saved, nothing
 * changed" only when the write to the account state was refused or never sent; "can't tell" when it went out and its
 * outcome cannot be told (it may be saved, and the vault is then adopted at the next sync).
 */
export function shareAnswerText(a: Adoption): string | null {
  // A decline is recorded either way; only a leave the server did not store is said, except on a vault frozen here,
  // where what the browser knows of the leave is said in each case (it can no longer read it back).
  if (a.kind === "declined") {
    if (a.frozen !== undefined) return a.frozen === "stored" ? SHARE_DECLINE_FROZEN_STORED : a.frozen === "refused" ? SHARE_DECLINE_FROZEN_REFUSED : SHARE_DECLINE_FROZEN_UNKNOWN;
    return a.leave === "waiting" ? SHARE_DECLINE_WAITING : a.leave === "not_stored" ? SHARE_DECLINE_NOT_STORED : null;
  }
  if (a.kind !== "not_recorded") return null;
  return a.reason === "unknown" ? SHARE_ANSWER_UNKNOWN : SHARE_NOT_RECORDED;
}

/**
 * What a shared vault and its contacts ask of the person on this browser (design §3.6, §6.9, §8.5), above the
 * vault list: the one-tap contact list (once, on a browser that did not create the account), a contact made on
 * another device, and the acceptance prompt of a share. Every name shown is plain text from the log store or the
 * contact book: a label only for a contact current here, a vault name only after §3.6 (a) to (c) passed.
 *
 * [onChanged] runs a sync after an answer: a contact made current may turn a "connect first" share into an ask.
 */
export function SharedPrompts({ shared, onChanged }: { shared: SharedLogSession | null; onChanged: () => void }) {
  const [, setTick] = useState(0);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  // §8.5 [Later]: the one-tap list steps aside for this page; it is still due, so it comes back on the next visit.
  const [oneTapLater, setOneTapLater] = useState(false);
  if (shared === null) return null;
  const rerender = () => setTick((t) => t + 1);

  const answer = async (ask: SharedAsk, accept: boolean) => {
    setBusy(true);
    setErr("");
    try {
      const a = await shared.answer(ask, accept);
      const line = shareAnswerText(a);
      if (line !== null) setErr(line);
      onChanged();
    } catch {
      // Thrown somewhere between the fresh read and the write's answer: whether the answer was saved cannot be told.
      setErr(SHARE_ANSWER_UNKNOWN);
    } finally {
      setBusy(false);
      rerender();
    }
  };

  const oneTapDue = shared.contacts.oneTapListDue();
  const listed = oneTapDue && !oneTapLater ? shared.contacts.list().filter((c) => c.current === null) : [];
  const prompts = shared.contacts.prompts();
  const asks = shared.pendingAsks();
  // §3.6: one line per such vault, naming the sender as the server reports it (the vault's name is not shown).
  const connectFirstLines = shared.undecided().flatMap((id) => {
    const o = shared.outcome(id);
    return o?.kind === "connect_first" ? [o.serverName ? fill(SHARE_CONNECT_FIRST, o.serverName) : SHARE_CONNECT_FIRST_UNNAMED] : [];
  });
  const connectFirst = connectFirstLines.length > 0;
  const askText = (a: SharedAsk) => SHARE_ASK.replace("{name}", a.ownerLabel).replace("{vault}", a.vaultName);
  // The live region stays mounted (Msg.tsx): a prompt that appears after a sync is announced.
  const announce = asks[0] ? askText(asks[0]) : listed.length > 0 ? ONE_TAP_TITLE : connectFirst && !oneTapDue ? connectFirstLines[0]! : "";
  if (listed.length === 0 && prompts.length === 0 && asks.length === 0 && !connectFirst && err === "") return <Announcer text="" />;

  return (
    <div className="wrap" style={{ paddingBottom: 0 }}>
      <Announcer text={announce} />
      {listed.length > 0 && (
        <OneTapList
          entries={listed.map((c) => ({ userId: c.record.userId, label: c.labelText }))}
          onConfirm={(ids) => {
            shared.contacts.confirmOneTap(ids);
            rerender();
            onChanged();
          }}
          onLater={() => setOneTapLater(true)}
        />
      )}
      {prompts.map((p) => (
        <ContactPromptRow
          key={p.record.userId}
          prompt={p}
          onYes={() => {
            shared.contacts.confirmHere(p);
            rerender();
            onChanged();
          }}
        />
      ))}
      {asks.map((a) => (
        <div key={a.vaultId} className="msg info" style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <span style={{ flex: 1 }}>{askText(a)}{a.waiting > 0 && <> {a.waiting === 1 ? fill(SHARE_ASK_WAITING_ONE, a.vaultName) : fill(SHARE_ASK_WAITING, String(a.waiting), a.vaultName)}</>}</span>
          <button type="button" className="ghost" disabled={busy} onClick={() => void answer(a, true)}>{SHARE_ACCEPT}</button>
          <button type="button" className="link" disabled={busy} onClick={() => void answer(a, false)}>{SHARE_DECLINE}</button>
        </div>
      ))}
      {connectFirst && !oneTapDue && connectFirstLines.map((line, i) => <div key={i} className="msg info">{line}</div>)}
      {err !== "" && <div className="msg err" role="alert">{err}</div>}
    </div>
  );
}

function OneTapList({ entries, onConfirm, onLater }: { entries: { userId: string; label: string }[]; onConfirm: (ids: ReadonlySet<string>) => void; onLater: () => void }) {
  // §8.5: "[list with checkboxes, all ticked]": the person unticks anyone they don't recognise.
  const [ticked, setTicked] = useState<ReadonlySet<string>>(() => new Set(entries.map((e) => e.userId)));
  const toggle = (id: string) => {
    const next = new Set(ticked);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    setTicked(next);
  };
  return (
    <div className="msg info" role="group" aria-label={ONE_TAP_TITLE}>
      <strong>{ONE_TAP_TITLE}</strong>
      <p>{ONE_TAP_BODY}</p>
      {entries.map((e) => (
        <label key={e.userId} className="check" style={{ marginBottom: 8 }}>
          <input type="checkbox" checked={ticked.has(e.userId)} onChange={() => toggle(e.userId)} /> {e.label}
        </label>
      ))}
      <button type="button" className="ghost" onClick={() => onConfirm(ticked)}>{ONE_TAP_CONFIRM}</button>{" "}
      <button type="button" className="link" onClick={onLater}>{ONE_TAP_LATER}</button>
    </div>
  );
}

function ContactPromptRow({ prompt, onYes }: { prompt: ContactPrompt; onYes: () => void }) {
  return (
    <div className="msg info" style={{ display: "flex", alignItems: "center", gap: 12 }}>
      <span style={{ flex: 1 }}>{CONTACT_PROMPT.replace("{name}", prompt.labelText)}</span>
      <button type="button" className="ghost" onClick={onYes}>{CONTACT_PROMPT_YES}</button>
    </div>
  );
}
