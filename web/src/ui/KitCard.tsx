import { useMemo, useState } from "react";
import { composeKitQr, CONFIRM_GROUPS, confirmGroups, confirmMatches, kitGroups } from "../crypto/trust/recoverykit";
import { decodeName } from "../crypto/trust/grammar";
import { qrModules } from "../vendor/qrcode-generator";
import type { WebPin } from "../vault/pinstore";
import { accountId, type OpenedAccount } from "../vault/accountopen";
import { confirmKit, type FreshKit, type KitWire } from "../vault/kitflow";
import { rotateKitFor, type SettingsSession } from "../vault/settingsflow";
import { Busy } from "./Busy";
import {
  fill,
  KIT_ACCOUNT_ID,
  KIT_HOW_TO_RECOVER,
  KIT_IDLE_WARNING,
  KIT_KEEP_PRIVATE,
  KIT_REPLACED,
  KIT_ROTATE_BODY,
  KIT_ROTATE_DONE,
  KIT_ROTATE_TITLE,
  KIT_SHOWN_AGAIN,
  KIT_TITLE,
  KIT_TYPE_GROUPS,
} from "./copy";
import { kitRotateText } from "./reauthtext";
import { Field } from "./Field";
import { Announcer, Msg } from "./Msg";
import { QrSvg } from "./QrSvg";
import { useAutoLock } from "./useAutoLock";

/** The kit's reveal and confirm screens hold a secret outside the vault: an idle cap bounds them (the old CR-02 rule). */
export const KIT_IDLE_SECONDS = 300;
/** §10: after this many failed confirmations the kit is shown again. */
export const KIT_MAX_TRIES = 3;

/** The instance as the kit and every recovery screen name it: the card's name and its origin (§4.4, §10). */
export function instanceLabel(pin: WebPin): { name: string; origin: string } {
  return { name: decodeName(pin.name) ?? "", origin: pin.origin };
}

/**
 * The kit (design §10): shown, then typed back as three groups chosen by CSPRNG, before the vault opens. There is
 * no Copy button on either screen. The kit document is this card, printed from the browser: nothing is uploaded.
 */
export function KitCard({
  secret,
  email,
  pin,
  accountId,
  nowMs,
  onConfirmed,
  onTimeout,
}: {
  secret: Uint8Array;
  email: string;
  pin: WebPin;
  accountId: string;
  nowMs: number;
  onConfirmed: () => void;
  onTimeout: () => void;
}) {
  const [step, setStep] = useState<"show" | "confirm">("show");
  const [notice, setNotice] = useState("");
  const [tries, setTries] = useState(0);
  const [choice, setChoice] = useState<number[]>(() => confirmGroups());
  const [typed, setTyped] = useState<string[]>(() => Array(CONFIRM_GROUPS).fill(""));
  // The idle limit warns before it acts, as the vault's lock does: the kit is never taken off the screen unannounced.
  const idleWarning = useAutoLock(KIT_IDLE_SECONDS, onTimeout);
  const warning = <KitIdleWarning active={idleWarning} />;
  const groups = useMemo(() => kitGroups(secret), [secret]);
  const qr = useMemo(() => {
    try {
      return qrModules(composeKitQr(pin.origin, pin.card0Hash, email, secret), "M");
    } catch {
      return null;
    }
  }, [pin, email, secret]);
  const { name, origin } = instanceLabel(pin);

  if (step === "confirm") {
    const submit = (e: React.FormEvent) => {
      e.preventDefault();
      if (confirmMatches(secret, choice, typed)) {
        onConfirmed();
        return;
      }
      const n = tries + 1;
      setTyped(Array(CONFIRM_GROUPS).fill(""));
      if (n >= KIT_MAX_TRIES) {
        setTries(0);
        setChoice(confirmGroups());
        setNotice(KIT_SHOWN_AGAIN);
        setStep("show");
        return;
      }
      setTries(n);
    };
    return (
      <form onSubmit={submit} autoComplete="off">
        {warning}
        <p>{fill(KIT_TYPE_GROUPS, ...choice.map(String))}</p>
        {tries > 0 && <Msg kind="err">{`${KIT_MAX_TRIES - tries} ${KIT_MAX_TRIES - tries === 1 ? "try" : "tries"} left.`}</Msg>}
        {choice.map((g, i) => (
          <Field key={g} label={`Group ${g}`}>
            <input
              value={typed[i]}
              autoFocus={i === 0}
              spellCheck={false}
              autoCapitalize="off"
              onChange={(e) => setTyped((t) => t.map((x, j) => (j === i ? e.target.value : x)))}
            />
          </Field>
        ))}
        <button className="primary" disabled={typed.some((t) => t.trim() === "")}>Confirm</button>
        <button type="button" className="link" onClick={() => setStep("show")}>Show the kit again</button>
      </form>
    );
  }

  return (
    <div className="kit">
      {warning}
      <Announcer text={notice} />
      {notice && <Msg kind="info">{notice}</Msg>}
      {/* The kit document is meant to be printed: `.print-keep` keeps it (and its QR) visible on paper. */}
      <section className="kit-document print-keep" aria-label={KIT_TITLE}>
        <h2>{KIT_TITLE}</h2>
        <p><strong>{KIT_KEEP_PRIVATE}</strong></p>
        <p>
          {email}
          <br />
          {name} ({origin})
          <br />
          {new Date(nowMs).toISOString().slice(0, 10)}
        </p>
        <p className="kit-secret mono" style={{ fontSize: "1.25em", wordSpacing: "0.4em" }}>
          {groups.map((g, i) => (
            <span key={i}>{g}{i < groups.length - 1 ? " " : ""}</span>
          ))}
        </p>
        {qr && <QrSvg modules={qr} ariaLabel={KIT_TITLE} />}
        <p>{fill(KIT_ACCOUNT_ID, accountId)}</p>
        <p className="muted">{KIT_HOW_TO_RECOVER}</p>
      </section>
      <button type="button" className="secondary" onClick={() => window.print()}>Print</button>
      <button type="button" className="primary" onClick={() => { setNotice(""); setStep("confirm"); }}>I've saved it</button>
    </div>
  );
}

/** The idle limit's warning on a kit screen: always mounted for the screen reader, shown while [active]. */
export function KitIdleWarning({ active }: { active: boolean }) {
  return (
    <>
      <Announcer text={active ? KIT_IDLE_WARNING : ""} />
      {active && <Msg kind="info">{KIT_IDLE_WARNING}</Msg>}
    </>
  );
}

/**
 * A kit the server holds after a write this browser then refused: a registration or a kit recovery the server stored,
 * whose answer did not pass this browser's checks. No session is kept, so nothing is confirmed at the server; but the
 * person needs this kit not to be locked out (after a recovery the old kit no longer works), so it is shown with the
 * refusal [line] before anything is wiped, saved and typed back as at any kit, and its secret is wiped only on the way
 * out: typed back, or the idle cap after it was on screen (warned before it acts). [onSeen] then says the line that
 * stays: [line] after the kit was typed back, [gone] after the idle limit took it off the screen ([line] tells the person
 * to keep a kit that is then no longer shown; [gone] says it was taken away and what the next sign-in offers).
 */
export function StoredKitCard({ line, gone, kit, email, pin, accountId: id, onSeen }: { line: string; gone: string; kit: FreshKit; email: string; pin: WebPin; accountId: string; onSeen: (stays: string) => void }) {
  const done = (stays: string) => () => {
    kit.secret.fill(0);
    onSeen(stays);
  };
  return (
    <>
      <Msg kind="err">{line}</Msg>
      <KitCard secret={kit.secret} email={email} pin={pin} accountId={id} nowMs={Date.now()} onConfirmed={done(line)} onTimeout={done(gone)} />
    </>
  );
}

/**
 * Shows [kit] and waits for its confirmation (§10) before [onDone]. `409 recovery_piece_stale` (another device
 * replaced it) rotates a fresh one through [rotate]; any other failure is shown with a retry, never swallowed.
 * [describe] words a failure. The secret is wiped on each way out (confirmed, replaced, timed out), not in an effect
 * cleanup: StrictMode's rehearsal unmount would wipe a kit still on screen.
 */
export function KitGate({ wire, kit, email, pin, opened, rotate, describe, onDone, onTimeout }: {
  wire: KitWire;
  kit: FreshKit;
  email: string;
  pin: WebPin;
  opened: OpenedAccount;
  rotate: () => Promise<FreshKit>;
  describe: (e: unknown) => string;
  onDone: () => void;
  onTimeout: () => void;
}) {
  const [current, setCurrent] = useState(kit);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const [confirmed, setConfirmed] = useState(false);
  const send = async () => {
    setBusy(true);
    setErr("");
    try {
      const r = await confirmKit(wire, current.pieceId);
      if (r.kind === "confirmed") {
        current.secret.fill(0);
        onDone();
        return;
      }
      if (r.kind === "stale") {
        setConfirmed(false);
        setErr(KIT_REPLACED);
        try {
          const next = await rotate();
          current.secret.fill(0);
          setCurrent(next);
        } catch (e) {
          setErr(describe(e));
        }
        return;
      }
      setErr(describe(r.error));
    } finally {
      setBusy(false);
    }
  };
  if (confirmed) {
    return (
      <div>
        {err && <Msg kind="err">{err}</Msg>}
        <button className="primary" disabled={busy} onClick={() => void send()}>{busy ? <Busy>Saving…</Busy> : "Try again"}</button>
      </div>
    );
  }
  return (
    <>
      {err && <Msg kind="info">{err}</Msg>}
      <KitCard
        key={current.pieceId ?? "kit"}
        secret={current.secret}
        email={email}
        pin={pin}
        accountId={accountId(opened.identity.publicKey)}
        nowMs={Date.now()}
        onConfirmed={() => {
          setConfirmed(true);
          void send();
        }}
        onTimeout={() => {
          current.secret.fill(0);
          onTimeout();
        }}
      />
    </>
  );
}

/**
 * Settings, "Make a new recovery kit" (design §10, §13; spec 03 §12): the master password goes through the one
 * re-authentication path ({@link rotateKitFor}: the password rule, then the local proof), the new piece replaces the
 * old one on the server, and the new kit is shown and typed back through {@link KitGate}. A replaced piece rotates
 * again, with the password the person typed (kept only while the kit is on screen).
 */
export function RotateKitCard({ settings }: { settings: SettingsSession }) {
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [done, setDone] = useState(false);
  const [kit, setKit] = useState<FreshKit | null>(null);
  const pin = settings.pins.pinFor(settings.origin);

  const rotate = async (): Promise<FreshKit> => {
    const r = await rotateKitFor(settings, password);
    if (r.kind === "done") return r.value;
    throw new KitRotateRefused(kitRotateText(r));
  };
  const start = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr("");
    setDone(false);
    try {
      setKit(await rotate());
    } catch (x) {
      setErr(x instanceof KitRotateRefused ? x.message : kitRotateText({ kind: "unknown", error: x }));
      setPassword("");
    } finally {
      setBusy(false);
    }
  };
  const close = (confirmed: boolean) => {
    setKit(null);
    setPassword("");
    setDone(confirmed);
  };

  if (pin === null) return null;
  return (
    <div className="sheet">
      <h2>{KIT_ROTATE_TITLE}</h2>
      <Announcer text={done ? KIT_ROTATE_DONE : ""} />
      {done && <Msg kind="info">{KIT_ROTATE_DONE}</Msg>}
      {kit !== null ? (
        <KitGate
          wire={settings.wire}
          kit={kit}
          email={settings.account}
          pin={pin}
          opened={settings.opened}
          rotate={rotate}
          describe={(x) => (x instanceof KitRotateRefused ? x.message : kitRotateText({ kind: "unknown", error: x }))}
          onDone={() => close(true)}
          onTimeout={() => close(false)}
        />
      ) : (
        <form onSubmit={start}>
          <p className="muted" style={{ marginTop: 0 }}>{KIT_ROTATE_BODY}</p>
          {err && <Msg kind="err">{err}</Msg>}
          <Field label="Master password">
            <input type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} disabled={busy} />
          </Field>
          <button className="primary" disabled={busy || !password}>{busy ? <Busy>Checking…</Busy> : "Make a new recovery kit"}</button>
        </form>
      )}
    </div>
  );
}

class KitRotateRefused extends Error {}
