import { useCallback, useEffect, useState } from "react";
import type { DeviceRow } from "../api/wire";
import { PASSWORD_CHANGE_UNCONFIRMED, PROOF_REFUSED, type Reauthed, revokeDevice, SERVER_KEYS_NOT_KNOWN, type SettingsSession } from "../vault/settingsflow";
import { Busy } from "./Busy";
import {
  PASSWORD_CHANGE_NOT_CONFIRMED,
  SERVER_REFUSED_PROOF,
  DEVICES_CURRENT,
  DEVICES_HOW,
  DEVICES_HOW_OTHER,
  DEVICES_LAST_SEEN,
  DEVICES_PLATFORM,
  DEVICES_PLATFORM_OTHER,
  DEVICES_REMOVED_TAG,
  DEVICES_REVOKE,
  DEVICES_REVOKE_KEEPS_COPY,
  DEVICES_REVOKE_CONFIRM,
  DEVICES_REVOKED,
  DEVICES_TITLE,
  DEVICES_UNAVAILABLE,
  DEVICES_RELOAD_FAILED,
  DEVICES_UNKNOWN,
  DEVICES_WRONG_PASSWORD,
  fill,
  SERVER_KEYS_NOT_KNOWN_REFUSED,
  SIGNIN_BACKOFF,
} from "./copy";
import { Field } from "./Field";
import { fmtDate } from "./format";
import { Announcer, Msg } from "./Msg";

/** The sentence for a revoke's outcome; null for `done`. */
/** The removal's confirmation, naming the device: filled with the common fill (the page's line has `{0}`). */
export function revokeConfirmText(deviceName: string): string {
  return fill(DEVICES_REVOKE_CONFIRM, deviceName);
}

export function revokeOutcomeText(r: Reauthed<void>): string | null {
  switch (r.kind) {
    case "done":
      return null;
    case "wrong_password":
      return DEVICES_WRONG_PASSWORD;
    case "rate_limited":
      return SIGNIN_BACKOFF;
    case "unknown":
      return DEVICES_UNKNOWN;
    case "refused":
      // Spec 01 §7: a proof refused while the session is marked as holding keys the server does not.
      // A proof refused otherwise was made here all the same: never a wrong password.
      // A password change has no answer and the server's keys could not be read: nothing was sent.
      if (r.code === PASSWORD_CHANGE_UNCONFIRMED) return PASSWORD_CHANGE_NOT_CONFIRMED;
      return r.code === SERVER_KEYS_NOT_KNOWN ? SERVER_KEYS_NOT_KNOWN_REFUSED : r.code === PROOF_REFUSED ? SERVER_REFUSED_PROOF : DEVICES_UNAVAILABLE;
    default:
      return DEVICES_UNAVAILABLE;
  }
}

/** How a device joined, its platform and when it was last seen, as words (never the wire's raw `how` or `platform`). */
export function deviceLine(d: Pick<DeviceRow, "how" | "platform" | "lastSeenAt">): string {
  const parts = [DEVICES_HOW[d.how] ?? DEVICES_HOW_OTHER, DEVICES_PLATFORM[d.platform] ?? DEVICES_PLATFORM_OTHER];
  if (d.lastSeenAt !== null) parts.push(fill(DEVICES_LAST_SEEN, fmtDate(d.lastSeenAt)));
  return parts.join(" · ");
}

/**
 * What the card says when the device list could not be loaded: on opening, the approved line; right after a revoke the
 * server confirmed, the revoke's own line and that the list couldn't be loaded again ("nothing changed" would be untrue).
 */
export function deviceListFailedText(afterRevoke: boolean): string {
  return afterRevoke ? `${DEVICES_REVOKED} ${DEVICES_RELOAD_FAILED}` : DEVICES_UNAVAILABLE;
}

/**
 * The account's own devices (design §8.6, spec 03 §16.7), on vault/settingsflow.ts: each one's name as plain text,
 * how it joined and when it was last seen; another device is revoked with the master password (re-authenticated
 * through the password rule). This browser is marked and cannot revoke itself here (signing out does that).
 */
export function AccountDevicesCard({ settings, offline = false }: { settings: SettingsSession; offline?: boolean }) {
  const [rows, setRows] = useState<DeviceRow[] | null>(null);
  const [err, setErr] = useState("");
  const [info, setInfo] = useState("");
  const [revoking, setRevoking] = useState<string | null>(null);
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);

  // [afterRevoke]: the reload right after a revoke the server confirmed. Its failure is not the revoke's: the device
  // WAS signed out, so the screen (and what a screen reader hears) says that and that only the list failed.
  const load = useCallback(async (afterRevoke = false) => {
    try {
      setRows(await settings.wire.devices());
    } catch {
      const t = deviceListFailedText(afterRevoke);
      if (afterRevoke) setInfo(t);
      else setErr(t);
    }
  }, [settings]);
  // On the offline copy the server can't be reached: the list is not asked for (Settings says why in its own line).
  useEffect(() => {
    if (!offline) void load();
  }, [load, offline]);

  const revoke = async (e: React.FormEvent) => {
    e.preventDefault();
    if (revoking === null) return;
    setBusy(true);
    setErr("");
    setInfo("");
    try {
      const r = await revokeDevice(settings, revoking, password);
      const text = revokeOutcomeText(r);
      if (text === null) {
        setInfo(DEVICES_REVOKED);
        setRevoking(null);
        await load(true);
      } else setErr(text);
    } finally {
      setPassword("");
      setBusy(false);
    }
  };

  return (
    // A settings sheet like its neighbours (it was the narrow sign-in `.card`), one row per device: its name, then how
    // it joined, its platform and when it was last seen in words rather than the wire's raw values.
    <section className="sheet">
      <h2>{DEVICES_TITLE}</h2>
      <p className="muted">{DEVICES_REVOKE_KEEPS_COPY}</p>
      <Announcer text={err || info} />
      {err && <Msg kind="err">{err}</Msg>}
      {info && <Msg kind="info">{info}</Msg>}
      {rows === null && !err && !offline && <Busy>Loading…</Busy>}
      {rows !== null && (
        <ul className="device-list">
          {rows.map((d) => (
            <li key={d.deviceId}>
              <div>
                <strong>{d.name}</strong>
                {d.current && <span className="tag">{DEVICES_CURRENT}</span>}
                {!d.current && !d.live && <span className="tag">{DEVICES_REMOVED_TAG}</span>}
                <div className="muted">{deviceLine(d)}</div>
              </div>
              {!d.current && d.live && (
                <button type="button" className="ghost" disabled={busy} onClick={() => setRevoking(d.deviceId)}>
                  {DEVICES_REVOKE}
                </button>
              )}
            </li>
          ))}
        </ul>
      )}
      {revoking !== null && (
        <form onSubmit={revoke}>
          <p>{revokeConfirmText(rows?.find((d) => d.deviceId === revoking)?.name ?? "")}</p>
          <Field label="Master password">
            <input type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} />
          </Field>
          <button className="primary" disabled={busy || password === ""}>{busy ? <Busy>{DEVICES_REVOKE}</Busy> : DEVICES_REVOKE}</button>{" "}
          <button type="button" className="link" onClick={() => setRevoking(null)}>Cancel</button>
        </form>
      )}
    </section>
  );
}
