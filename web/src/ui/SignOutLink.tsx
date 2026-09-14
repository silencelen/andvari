import { useState } from "react";
import { Announcer, Msg } from "./Msg";
import { offlineCopyStamp, pendingSyncCount } from "./session";

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
 * The gate itself is unchanged in substance: the count and the durable-copy probe are read at
 * CLICK time (never a mount-time snapshot — another tab may have queued edits since), and a
 * device with neither queued work nor a durable copy still signs out on one click, because there
 * is nothing to lose. A FAILED probe arms the confirm rather than skipping it: not knowing
 * whether there is unsynced work is a reason to ask, not a reason to wipe.
 */

/** The natives' verbatim sentence (desktop Ui.kt / Android MainActivity) — all three clients say
 *  the same thing about the same wipe. The unsynced count is appended when there is one. */
export const SIGN_OUT_QUESTION =
  "Sign out of this device? This removes the vault copy and any unsynced changes from this device. You'll need your master password — and a connection to your server — to sign back in.";

/**
 * The confirm sentence this sign-out needs, or `null` when it needs none. Exported pure (with the
 * probes injectable) so the gate is unit-pinned without a DOM — the repo's node-env test posture.
 */
export async function signOutQuestion(
  userId: string | null,
  probes?: {
    queued?: (userId: string) => Promise<number>;
    durable?: (userId: string) => Promise<boolean>;
  },
): Promise<string | null> {
  if (!userId) return null; // no session to lose anything from
  const queuedProbe = probes?.queued ?? pendingSyncCount;
  const durableProbe = probes?.durable ?? (async (u: string) => (await offlineCopyStamp(u)) !== null);
  let unsynced = 0;
  let durable = false;
  let probeFailed = false;
  try {
    unsynced = await queuedProbe(userId);
  } catch {
    probeFailed = true; // unknown ⇒ ask (see the header note)
  }
  try {
    durable = await durableProbe(userId);
  } catch {
    probeFailed = true;
  }
  if (unsynced === 0 && !durable && !probeFailed) return null;
  return unsynced > 0
    ? `${SIGN_OUT_QUESTION} ${unsynced} unsynced ${unsynced === 1 ? "change" : "changes"} will be permanently lost.`
    : SIGN_OUT_QUESTION;
}

/** The armed label — the popup's wording, so the two browser surfaces read identically. */
export const SIGN_OUT_ARMED_LABEL = "Sign out? Click again to confirm";
export const SIGN_OUT_LABEL = "Sign out / use a different account";

/**
 * The Unlock card's and the recovery-capture gate's escape hatch. `userId` is the account whose
 * queue and offline copy the wipe would take (null = nothing persisted yet, so no confirm).
 */
export function SignOutLink({ userId, onSignOut }: { userId: string | null; onSignOut: () => void }) {
  const [question, setQuestion] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const click = async () => {
    if (question) {
      // Armed: this is the second, deliberate click.
      setQuestion(null);
      onSignOut();
      return;
    }
    setBusy(true);
    try {
      const q = await signOutQuestion(userId);
      if (q) setQuestion(q);
      else onSignOut(); // nothing to lose — one click, as before
    } finally {
      setBusy(false);
    }
  };

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
          <button type="button" className="link" onClick={() => setQuestion(null)}>
            Stay signed in
          </button>
        </>
      )}
    </div>
  );
}
