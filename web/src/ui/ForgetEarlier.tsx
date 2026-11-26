import { useEffect, useState } from "react";
import { emailNorm } from "../crypto/trust/grammar";
import { SELF_IDENTITY_MISMATCH } from "../vault/accountopen";
import { earlierAccountAt, FORGETTING_KEY } from "../vault/selfidentity";
import {
  fill,
  GATE_CANCEL,
  IDENTITY_FAULT,
  REMADE_ACCOUNT_CONFIRM,
  REMADE_ACCOUNT_CONFIRM_ALWAYS,
  REMADE_ACCOUNT_CONFIRM_COPY_ALL_SENT,
  REMADE_ACCOUNT_CONFIRM_COPY_CANNOT_TELL,
  REMADE_ACCOUNT_CONFIRM_COPY_ONE_UNSENT,
  REMADE_ACCOUNT_CONFIRM_COPY_UNSENT,
  REMADE_ACCOUNT_CONFIRM_FORGET,
  REMADE_ACCOUNT_CONFIRM_HELD_CANNOT_TELL,
  REMADE_ACCOUNT_CONFIRM_HELD_ONE_UNSENT,
  REMADE_ACCOUNT_CONFIRM_HELD_UNSENT,
  REMADE_ACCOUNT_CONFIRM_TITLE,
  REMADE_ACCOUNT_FORGET,
  REMADE_ACCOUNT_FORGET_ACCOUNT_OPEN,
  REMADE_ACCOUNT_FORGET_CANNOT_TELL_OPEN,
  REMADE_ACCOUNT_FORGET_FAILED,
  REMADE_ACCOUNT_FORGET_NO_LONGER_HOLDS,
  REMADE_ACCOUNT_FORGET_NOT_CONFIRMED,
  REMADE_ACCOUNT_FORGOTTEN,
  REMADE_ACCOUNT_NOTHING_TO_FORGET,
  REMADE_ACCOUNT_HOW_TO_TELL,
  REMADE_ACCOUNT_IF_REMADE,
  REMADE_ACCOUNT_IF_SERVER,
  REMADE_ACCOUNT_REFUSAL,
  REMADE_ACCOUNT_TITLE,
} from "./copy";
import { Announcer, Msg } from "./Msg";
import { earlierCopyOf, type EarlierCopy, forgetEarlierAccount, isAccountScopedKey, loadSession, SESSION_STORAGE_KEY } from "./session";

/**
 * "Forget the earlier account on this device" (decided on 2026-11-17): offered under a refusal whose cause is this
 * browser's own record of the address, the identity fault `self_identity_mismatch`, and only where that record names an
 * account and agrees with itself. Never under any other fault (a damaged key, the server's card, a served key that is not
 * the seed's, a record that disagrees with itself). Built only from a refused flow's own result: no server answer, timer,
 * link or setting makes one.
 */
export interface EarlierOffer {
  /** The address, as the shared grammar normalises it. */
  readonly email: string;
  /** The earlier account this browser binds the address to. */
  readonly userId: string;
  /**
   * The earlier account is the session this browser keeps (open or locked, in this tab or another): nothing is offered,
   * and the refusal says to sign out of it first (its sign-out counts the changes not sent), as the shared code answers
   * ACCOUNT_OPEN for an account open or kept on the device.
   */
  readonly sessionKept: boolean;
  /**
   * The account the refused flow met: the id the server answered for (a sign-in, the kit's check), the kept session's id
   * (an unlock), or `new` (a registration). Never the earlier account: the second confirmation refuses to be taken where
   * the address is by then tied to this account, or where it is the earlier one.
   */
  readonly served: string;
}

/**
 * The offer for a flow under [email] refused for [reason], or null where the refusal is anything but this browser's record.
 * [served] is the account the refused flow met: the id the server answered for, or `new` for a registration (an account
 * made here, never the remembered one). The offer is made only where it is another account than the remembered one: the
 * same account under another identity key is never a remade account (a new account has a new id), and it is exactly what
 * the record exists to stop (a recovery that swapped the identity seed), so nothing is offered for it. Without a served
 * id (null) nothing is offered either.
 */
export function earlierOfferFor(email: string, reason: string, served: string | "new" | null | undefined): EarlierOffer | null {
  if (reason !== SELF_IDENTITY_MISMATCH || served == null) return null;
  const n = emailNorm(email);
  if (n === null) return null;
  const userId = earlierAccountAt(n);
  if (userId === null || userId === served) return null;
  return { email: n, userId, sessionKept: loadSession()?.userId === userId, served };
}

/**
 * What a sign-in, an unlock of a kept session or the kit's check shows for an identity fault: where the offer is made, the
 * offer alone, whose own lines say the refusal and both possibilities (the plate that says not to enter the password again
 * and to contact the person who runs the server takes one side of the two, so it does not stand above the offer, as at
 * the registration); where nothing is offered (the same account under another key, any other fault), that plate as before.
 */
export function identityRefusal(email: string, reason: string, served: string | "new" | null | undefined): { readonly err: string; readonly offer: EarlierOffer | null } {
  const offer = earlierOfferFor(email, reason, served);
  return { err: offer === null ? IDENTITY_FAULT : "", offer };
}

/**
 * Whether another tab's change of storage key [key] takes the second confirmation back: the whole store cleared, the kept
 * session, the address's record, a forgetting begun, or any record of the earlier account itself (that account being
 * written to elsewhere). What the person confirmed is then not certain to be what holds.
 */
export function confirmationTakenBackBy(key: string | null, offer: Pick<EarlierOffer, "email" | "userId">): boolean {
  if (key === null) return true;
  return key === SESSION_STORAGE_KEY || key === FORGETTING_KEY || key === `andvari.selfIdentityByEmail.${offer.email}` || isAccountScopedKey(key, offer.userId);
}

/**
 * The second confirmation's lines, in order: what goes; the copy, where one is kept, with its count; always. The changes
 * to shared vaults the earlier account signed here and that are held go with it too: where a copy is kept they are counted
 * into its line (never "every change was sent" over a held one), and where none is kept they have a line of their own;
 * where it cannot be told whether any of them arrived, the line says it cannot tell.
 */
export function confirmLines(email: string, copy: EarlierCopy): string[] {
  const held = copy.held;
  const n = copy.unsent === null || held === null ? null : copy.unsent + held;
  const copyLine = copy.kept
    ? n === null
      ? REMADE_ACCOUNT_CONFIRM_COPY_CANNOT_TELL
      : n === 0
        ? REMADE_ACCOUNT_CONFIRM_COPY_ALL_SENT
        : n === 1
          ? REMADE_ACCOUNT_CONFIRM_COPY_ONE_UNSENT
          : fill(REMADE_ACCOUNT_CONFIRM_COPY_UNSENT, email, String(n))
    : held === 0
      ? null
      : held === null
        ? REMADE_ACCOUNT_CONFIRM_HELD_CANNOT_TELL
        : held === 1
          ? REMADE_ACCOUNT_CONFIRM_HELD_ONE_UNSENT
          : fill(REMADE_ACCOUNT_CONFIRM_HELD_UNSENT, email, String(held));
  return [fill(REMADE_ACCOUNT_CONFIRM, email), ...(copyLine === null ? [] : [copyLine]), REMADE_ACCOUNT_CONFIRM_ALWAYS];
}

/**
 * The offer under a refused flow's line: the refusal, the two possibilities each as a sentence of its own and neither
 * preferred, how to tell, then the button and Cancel, alike in weight, neither the default, neither focused, neither a
 * submit button (Enter in the flow's form never reaches them). The first button shows the second confirmation, counted
 * at that moment; nothing is forgotten by it.
 */
export function EarlierAccountOffer({ offer, server, onKeep, onDone }: { offer: EarlierOffer; server: string; onKeep: () => void; onDone: (line: string) => void }) {
  // Non-null while the second confirmation is on show: what it says, as counted when it was asked for.
  const [copy, setCopy] = useState<EarlierCopy | null>(null);
  const [busy, setBusy] = useState(false);
  // The line of the last answer that leaves the offer on show (an account kept here, a changed count, a failure).
  const [line, setLine] = useState("");
  // A lock (here or in another tab), and another tab's change of the records this confirmation is about, take it back;
  // a reload or a change of screen drops it with this component.
  useEffect(() => {
    const back = () => setCopy(null);
    const onStorage = (e: StorageEvent) => {
      if (confirmationTakenBackBy(e.key, offer)) back();
    };
    window.addEventListener("storage", onStorage);
    const ch = typeof BroadcastChannel !== "undefined" ? new BroadcastChannel("andvari-lock") : null;
    if (ch) ch.onmessage = back;
    return () => {
      window.removeEventListener("storage", onStorage);
      ch?.close();
    };
  }, [offer]);
  const ask = async () => {
    setBusy(true);
    setLine("");
    try {
      setCopy(await earlierCopyOf(offer.userId));
    } finally {
      setBusy(false);
    }
  };
  // Only from the person's click on the second confirmation's button, with what that confirmation says. Never tried
  // again by itself: a forgetting that throws leaves this step on show for the person's next click, which finishes it.
  const confirm = async (shown: EarlierCopy) => {
    setBusy(true);
    setLine("");
    try {
      const r = await forgetEarlierAccount(offer.email, offer.userId, shown, offer.served);
      switch (r.kind) {
        case "forgotten":
          onDone(fill(REMADE_ACCOUNT_FORGOTTEN, offer.email));
          return;
        case "nothing_to_forget":
          onDone(fill(REMADE_ACCOUNT_NOTHING_TO_FORGET, offer.email));
          return;
        case "no_longer_holds":
          // The offer itself no longer holds: it is taken away with the confirmation, and nothing was removed.
          onDone(fill(REMADE_ACCOUNT_FORGET_NO_LONGER_HOLDS, offer.email));
          return;
        case "account_open":
          setCopy(null);
          setLine(REMADE_ACCOUNT_FORGET_ACCOUNT_OPEN);
          return;
        case "open_cannot_tell":
          setCopy(null);
          setLine(REMADE_ACCOUNT_FORGET_CANNOT_TELL_OPEN);
          return;
        case "not_confirmed":
          setCopy(r.copy);
          setLine(REMADE_ACCOUNT_FORGET_NOT_CONFIRMED);
          return;
      }
    } catch {
      setLine(REMADE_ACCOUNT_FORGET_FAILED);
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="stack" role="group" aria-label={REMADE_ACCOUNT_TITLE}>
      {/* The second step lands after an awaited count: said to a screen reader as it appears. */}
      <Announcer text={line || (copy !== null ? REMADE_ACCOUNT_CONFIRM_TITLE : offer.sessionKept ? REMADE_ACCOUNT_FORGET_ACCOUNT_OPEN : "")} />
      <strong>{REMADE_ACCOUNT_TITLE}</strong>
      <p>{fill(REMADE_ACCOUNT_REFUSAL, offer.email, server)}</p>
      <p>{REMADE_ACCOUNT_IF_REMADE}</p>
      <p>{REMADE_ACCOUNT_IF_SERVER}</p>
      <p>{REMADE_ACCOUNT_HOW_TO_TELL}</p>
      {offer.sessionKept ? (
        <Msg kind="info">{REMADE_ACCOUNT_FORGET_ACCOUNT_OPEN}</Msg>
      ) : copy === null ? (
        <>
          {line && <Msg kind="info">{line}</Msg>}
          <div className="row even">
            <button type="button" className="secondary" disabled={busy} onClick={() => void ask()}>{REMADE_ACCOUNT_FORGET}</button>
            <button type="button" className="secondary" disabled={busy} onClick={onKeep}>{GATE_CANCEL}</button>
          </div>
        </>
      ) : (
        <>
          <strong>{REMADE_ACCOUNT_CONFIRM_TITLE}</strong>
          {confirmLines(offer.email, copy).map((l) => (
            <p key={l}>{l}</p>
          ))}
          {line && <Msg kind={line === REMADE_ACCOUNT_FORGET_FAILED ? "err" : "info"}>{line}</Msg>}
          <div className="row even">
            <button type="button" className="secondary" disabled={busy} onClick={() => void confirm(copy)}>{REMADE_ACCOUNT_CONFIRM_FORGET}</button>
            <button type="button" className="secondary" disabled={busy} onClick={() => setCopy(null)}>{GATE_CANCEL}</button>
          </div>
        </>
      )}
    </div>
  );
}
