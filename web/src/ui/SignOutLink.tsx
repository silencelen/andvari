import { useState } from "react";
import { unsentLine } from "./copy";
import { Announcer, Msg } from "./Msg";
import { offlineCopyStamp, unsentChangeCount } from "./session";

/**
 * H135: the sign-out confirm, in the house's INLINE two-step idiom.
 *
 * Signing out of the web app is destructive in a way its label ("Sign out / use a different
 * account") does not look: it clears the session, revokes the device server-side, and
 * deleteDatabase's this account's offline copy — so on a device that is offline, or whose server
 * is down, the member cannot open their vault again at all until connectivity returns, and any
 * queued offline edits are gone with it. F07 gated that behind `window.confirm`. Every other
 * destructive path in this app — delete item, delete forever, restore-over, discard changes, leave
 * vault, remove member, delete vault, disable user, merge duplicates — arms an inline confirm
 * instead, and the Editor's own comment states the rule: "house style — no native dialogs". The
 * extension popup already converted its sign-out to exactly this idiom (popup.ts, ux-parity--1).
 *
 * Why the idiom is better here and not merely prettier: `window.confirm` is the only unthemed,
 * un-styleable, tab-blocking surface left in the product, it cannot reach the persistent
 * Announcer a screen-reader user is listening to (BL-1), and on a phone the OS sheet lands on
 * top of the treasury look at precisely the "you will lose unsynced changes" moment.
 *
 * The gate: the count and the durable-copy probe are read at CLICK time (never a mount-time
 * snapshot — another tab may have queued edits since), and a device with neither queued work nor
 * a durable copy still signs out on one click, because there is nothing to lose. Design §4.4
 * (decided on 2026-11-17): the confirmation says how many changes made here were not sent, or
 * that this browser cannot tell (a count that failed is never said as none), and how to try
 * sending them first; the second click counts again, and a count that moved since the first
 * arms the confirmation again with the new number instead of signing out.
 */

/** The natives' verbatim sentence (desktop Ui.kt / Android MainActivity) — all three clients say
 *  the same thing about the same wipe. The line about unsent changes follows it when there are any. */
export const SIGN_OUT_QUESTION =
  "Sign out of this device? This removes the vault copy and any unsynced changes from this device. You'll need your master password — and a connection to your server — to sign back in.";

/** What an armed confirmation says, and the count it was armed on (null: this browser cannot tell). */
export type UnsentAsk = { readonly text: string; readonly unsent: number | null };

/**
 * One click of a two-step act guarded by unsent changes: [armed] is what the first click showed (null: not armed),
 * [next] what holds now (null: nothing is at stake, so the act needs no confirmation). The act happens only when
 * nothing is at stake, or on a second click over the same count.
 */
export function unsentArmStep(armed: UnsentAsk | null, next: UnsentAsk | null): { act: boolean; armed: UnsentAsk | null } {
  if (next === null) return { act: true, armed: null };
  if (armed !== null && armed.unsent === next.unsent && armed.text === next.text) return { act: true, armed: null };
  return { act: false, armed: next };
}

/**
 * The confirm this sign-out needs, or `null` when it needs none. Exported pure (with the probes injectable) so the gate
 * is unit-pinned without a DOM — the repo's node-env test posture. [sendFirst]: the line that says how to try sending
 * unsent changes first from where the person is (shown only when there are any, or this browser cannot tell).
 */
export async function signOutAsk(
  userId: string | null,
  probes?: {
    unsent?: (userId: string) => Promise<number | null>;
    durable?: (userId: string) => Promise<boolean>;
  },
  sendFirst?: string,
): Promise<UnsentAsk | null> {
  if (!userId) return null; // no session to lose anything from
  const unsentProbe = probes?.unsent ?? unsentChangeCount;
  const durableProbe = probes?.durable ?? (async (u: string) => (await offlineCopyStamp(u)) !== null);
  let unsent: number | null;
  try {
    unsent = await unsentProbe(userId);
  } catch {
    unsent = null; // unknown ⇒ ask, and say that this browser cannot tell
  }
  let durable = false;
  let durableFailed = false;
  try {
    durable = await durableProbe(userId);
  } catch {
    durableFailed = true;
  }
  if (unsent === 0 && !durable && !durableFailed) return null;
  const line = unsentLine(unsent);
  const text = [SIGN_OUT_QUESTION, line, line !== undefined ? sendFirst : undefined].filter(Boolean).join(" ");
  return { text, unsent };
}

/** The confirm sentence alone ({@link signOutAsk}'s text), or `null` when the sign-out needs none. */
export async function signOutQuestion(userId: string | null, probes?: Parameters<typeof signOutAsk>[1], sendFirst?: string): Promise<string | null> {
  return (await signOutAsk(userId, probes, sendFirst))?.text ?? null;
}

/** The armed label — the popup's wording, so the two browser surfaces read identically. */
export const SIGN_OUT_ARMED_LABEL = "Sign out? Click again to confirm";
export const SIGN_OUT_LABEL = "Sign out / use a different account";

/**
 * A two-step act guarded by unsent changes: [probe] says what is at stake at each click (null: nothing), [act] runs on
 * the click that {@link unsentArmStep} lets through.
 */
export function useUnsentArm(probe: () => Promise<UnsentAsk | null>, act: () => void) {
  const [armed, setArmed] = useState<UnsentAsk | null>(null);
  const [busy, setBusy] = useState(false);
  const click = async () => {
    setBusy(true);
    try {
      const step = unsentArmStep(armed, await probe());
      setArmed(step.armed);
      if (step.act) act();
    } finally {
      setBusy(false);
    }
  };
  return { armed, busy, click, cancel: () => setArmed(null) };
}

/**
 * The Unlock card's and the recovery-capture gate's escape hatch. `userId` is the account whose
 * queue and offline copy the wipe would take (null = nothing persisted yet, so no confirm).
 * `sendFirst`: how to try sending unsent changes first from this card.
 */
export function SignOutLink({ userId, onSignOut, sendFirst }: { userId: string | null; onSignOut: () => void; sendFirst?: string }) {
  const { armed, busy, click, cancel } = useUnsentArm(() => signOutAsk(userId, undefined, sendFirst), onSignOut);
  const question = armed?.text ?? null;

  return (
    <div style={{ textAlign: "center", marginTop: 16 }}>
      {question && <Msg kind="info">{question}</Msg>}
      {/* BL-1: the consequence is async info landing in a conditionally-mounted box, which a
          polite region entering the tree already-populated never announces — so it rides this
          persistent Announcer, mounted empty from first paint. */}
      <Announcer text={question ?? ""} />
      <button type="button" className="link" disabled={busy} onClick={() => void click()}>
        {question ? SIGN_OUT_ARMED_LABEL : SIGN_OUT_LABEL}
      </button>
      {question && (
        <>
          {" "}
          <button type="button" className="link" onClick={cancel}>
            Stay signed in
          </button>
        </>
      )}
    </div>
  );
}
