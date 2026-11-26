import { useEffect, useState } from "react";
import { browserStorage, type KeyValue } from "../api/devicesecret";
import { readMirror } from "../vault/recoverymirror";
import { type OperatorOffer, operatorOffer, type PostureChoice, type SettingsSession, setRecoveryPosture } from "../vault/settingsflow";
import type { SharedLogSession } from "../vault/sharedlogs";
import { Busy } from "./Busy";
import { POSTURE_SAVED, POSTURE_TITLE, POSTURE_UNAVAILABLE } from "./copy";
import { Field } from "./Field";
import { Announcer, Msg } from "./Msg";
import { ONLY_ME, RecoveryChoice, type RecoveryChoiceValue, recoveryChoiceReady } from "./RecoveryChoice";
import { passwordChangeText } from "./reauthtext";

/**
 * Settings → who can restore this account (design §7.7, §4.5), on a private instance whose pinned card offers
 * operator recovery. The offer is made fresh when the card opens (the card chain is fetched and walked again); the
 * choice, its box and any unsigned-change keep are §7.7's RecoveryChoice; saving asks the master password and
 * writes the choice to the account state and this browser's mirror with the escrow change (setRecoveryPosture).
 * Without an offer the card says nothing is offered here and changes nothing.
 */
export function RecoveryPostureCard({ settings, shared, storage = browserStorage }: { settings: SettingsSession; shared: SharedLogSession; storage?: KeyValue }) {
  const [offer, setOffer] = useState<OperatorOffer | null | "loading" | "none">("loading");
  const [value, setValue] = useState<RecoveryChoiceValue>(() => (readMirror(storage, settings.opened.userId)?.posture === "operator" ? { ...ONLY_ME, posture: "operator" } : ONLY_ME));
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [msg, setMsg] = useState("");

  useEffect(() => {
    let live = true;
    void operatorOffer(settings).then(
      (r) => live && setOffer(r.kind === "offer" ? r.offer : r.reason === "not_offered" ? null : "none"),
      () => live && setOffer("none"),
    );
    return () => {
      live = false;
    };
  }, [settings]);

  if (offer === null) return null; // not a private instance offering operator recovery: nothing to choose
  if (offer === "loading") return <div className="sheet"><h2>{POSTURE_TITLE}</h2><p className="muted"><Busy>Checking…</Busy></p></div>;
  if (offer === "none") return <div className="sheet"><h2>{POSTURE_TITLE}</h2><Msg kind="err">{POSTURE_UNAVAILABLE}</Msg></div>;

  const save = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr("");
    setMsg("");
    const choice: PostureChoice = value.posture === "private" ? { posture: "private" } : { posture: "operator", offer, understood: value.understood, keepDespiteUnsignedChange: value.keepNewKey };
    try {
      const r = await setRecoveryPosture(settings, shared.accountState, storage, choice, password, Date.now());
      if (r.kind === "done") setMsg(POSTURE_SAVED);
      else setErr(passwordChangeText(r));
    } catch (e2) {
      setErr(passwordChangeText({ kind: "unknown", error: e2 }));
    } finally {
      setPassword("");
      setBusy(false);
    }
  };

  return (
    <form className="sheet" onSubmit={save}>
      <h2>{POSTURE_TITLE}</h2>
      {err && <Msg kind="err">{err}</Msg>}
      {msg && <Msg kind="info">{msg}</Msg>}
      <Announcer text={err || msg} />
      <RecoveryChoice offer={offer} value={value} onChange={setValue} />
      <Field label="Master password">
        <input type="password" autoComplete="current-password" value={password} disabled={busy} onChange={(e) => setPassword(e.target.value)} />
      </Field>
      <div className="actions">
        <button className="primary" disabled={busy || password.length === 0 || !recoveryChoiceReady(value, offer)}>{busy ? <Busy>Saving…</Busy> : "Save"}</button>
      </div>
    </form>
  );
}
