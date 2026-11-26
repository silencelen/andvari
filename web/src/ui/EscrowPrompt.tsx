import { useEffect, useState } from "react";
import { browserStorage, type KeyValue } from "../api/devicesecret";
import { decodeName } from "../crypto/trust/grammar";
import { ESCROW_WRONG_FORM, type EscrowDecision, escrowAtUnlock, keepOperatorRecovery, type SettingsSession, setRecoveryPosture } from "../vault/settingsflow";
import type { SharedLogSession } from "../vault/sharedlogs";
import { Busy } from "./Busy";
import {
  ESCROW_KEEP,
  ESCROW_KEEP_QUESTION,
  ESCROW_LATER,
  ESCROW_NOT_NOW,
  ESCROW_SAVED,
  ESCROW_TURN_OFF,
  ESCROW_UNSIGNED_BODY,
  ESCROW_UNSIGNED_KEEP,
  ESCROW_UNSIGNED_OFF,
  ESCROW_UNSIGNED_TITLE,
  ESCROW_WRONG_FORM_TEXT,
  fill,
  POSTURE_UNAVAILABLE,
} from "./copy";
import { Field } from "./Field";
import { Announcer, Msg } from "./Msg";
import { passwordChangeText } from "./reauthtext";

type Prompt = Extract<EscrowDecision, { kind: "ask" | "unsigned_change" }>;

/**
 * Design §4.5 at unlock: the silent re-seal after a signed rotation (only with this browser's own mirror), or the
 * person's answer. "Keep that?" defaults to [Not now] (nothing sealed; it asks again at the next unlock); the
 * unsigned-change warning defaults to turning operator recovery off. Keep and turn off both need the master password
 * and go through `PUT /account/recovery` (setRecoveryPosture), which sets the mirror. Runs once per unlock.
 */
/**
 * Whether the question (either prompt: both ask for the master password) may be put in this session. Not while the
 * session knows the server's keys are not this browser's (spec 01 §7, "leaves both"): the proof would be refused, as in
 * Settings, so it is not offered; it is asked again at a later unlock. The silent re-seal asks for nothing and still runs.
 */
export function escrowQuestionOffered(settings: Pick<SettingsSession, "wrap">): boolean {
  return settings.wrap.serverKeysNotKnown !== true;
}

export function EscrowPrompt({ settings, shared, storage = browserStorage }: { settings: SettingsSession | undefined; shared: SharedLogSession | null; storage?: KeyValue }) {
  const [prompt, setPrompt] = useState<Prompt | null>(null);
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [msg, setMsg] = useState("");
  const [sealErr, setSealErr] = useState("");

  useEffect(() => {
    if (!settings || shared === null) return;
    let live = true;
    void escrowAtUnlock(settings, shared.accountState, storage, Date.now()).then(
      (r) => {
        if (!live) return;
        if (r.kind === "ask") {
          if (escrowQuestionOffered(settings)) setPrompt(r.decision);
        }
        // The silent re-seal was refused as a form the server no longer stores: said, never kept quiet or shown raw.
        else if (r.kind === "unavailable" && r.reason === ESCROW_WRONG_FORM) setSealErr(ESCROW_WRONG_FORM_TEXT);
      },
      () => {},
    );
    return () => { live = false; };
  }, [settings, shared, storage]);

  if (!settings || shared === null) return null;
  if (prompt === null || !escrowQuestionOffered(settings)) {
    return (
      <>
        <Announcer text={msg} />
        {sealErr && <div className="msg err top-prompt" style={{ display: "block" }} role="alert">{sealErr}</div>}
      </>
    );
  }

  const answer = async (keep: boolean) => {
    setBusy(true);
    setErr("");
    try {
      if (!keep) {
        const r = await setRecoveryPosture(settings, shared.accountState, storage, { posture: "private" }, password, Date.now());
        if (r.kind !== "done") return setErr(passwordChangeText(r));
      } else {
        // Spec 01 §7: the password is proven on this device before the offer is read again; a wrong one sends nothing.
        const r = await keepOperatorRecovery(settings, shared.accountState, storage, password, prompt.kind === "unsigned_change", Date.now());
        if (r.kind === "unavailable") return setErr(POSTURE_UNAVAILABLE);
        if (r.kind === "unsigned_change") {
          // The walk from card 0 found an unsigned change: keeping is the takeover warning's choice, never this one's.
          setPrompt({ kind: "unsigned_change", name: prompt.name, origin: prompt.origin, fromFp: r.change.fromFp ?? "", toFp: r.change.toFp ?? "" });
          return;
        }
        if (r.kind !== "done") return setErr(passwordChangeText(r));
      }
      setPrompt(null);
      setMsg(ESCROW_SAVED);
    } finally {
      // Every ending empties the field, a refusal (the back-off's included), a thrown failure and the unsigned-change
      // turn too, as every other password field of the web does: a typed password never waits on screen for a retry.
      setPassword("");
      setBusy(false);
    }
  };

  const name = decodeName(prompt.name) ?? "";
  const unsigned = prompt.kind === "unsigned_change";
  return (
    <div className={`msg ${unsigned ? "err" : "info"} top-prompt`} style={{ display: "block" }} role="alert">
      {unsigned ? (
        <>
          <strong>{fill(ESCROW_UNSIGNED_TITLE, name, prompt.origin)}</strong>
          <p>{ESCROW_UNSIGNED_BODY}</p>
        </>
      ) : (
        <strong>{fill(ESCROW_KEEP_QUESTION, name, prompt.origin)}</strong>
      )}
      {err && <Msg kind="err">{err}</Msg>}
      <Field label="Master password">
        <input type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} disabled={busy} />
      </Field>
      <div className="actions">
        {unsigned ? (
          <>
            <button type="button" className="primary" disabled={busy || !password} onClick={() => void answer(false)}>{busy ? <Busy>Saving…</Busy> : ESCROW_UNSIGNED_OFF}</button>
            <button type="button" className="ghost" disabled={busy || !password} onClick={() => void answer(true)}>{ESCROW_UNSIGNED_KEEP}</button>
            <button type="button" className="ghost" disabled={busy} onClick={() => setPrompt(null)}>{ESCROW_LATER}</button>
          </>
        ) : (
          <>
            <button type="button" className="primary" disabled={busy} onClick={() => setPrompt(null)}>{ESCROW_NOT_NOW}</button>
            <button type="button" className="ghost" disabled={busy || !password} onClick={() => void answer(true)}>{busy ? <Busy>Saving…</Busy> : ESCROW_KEEP}</button>
            <button type="button" className="ghost" disabled={busy || !password} onClick={() => void answer(false)}>{ESCROW_TURN_OFF}</button>
          </>
        )}
      </div>
    </div>
  );
}
