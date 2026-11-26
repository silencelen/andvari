package io.silencelen.andvari.app.trust

import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.remember
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppSnapshot
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.IntentResult
import io.silencelen.andvari.core.app.KeptStops
import io.silencelen.andvari.core.app.KitRecoverResult
import io.silencelen.andvari.core.app.KitScanResult
import io.silencelen.andvari.core.app.LinkDeviceEnd
import io.silencelen.andvari.core.app.LinkPasswordResult
import io.silencelen.andvari.core.app.MasterPasswordPrompt
import io.silencelen.andvari.core.app.ReplacePasswordResult
import io.silencelen.andvari.core.app.SignInAnswer
import io.silencelen.andvari.core.app.SignUpStartResult

// A second account while one its server signed out is kept on this phone (l2b-14 item 1, AppSnapshot.keptSignedOut).
// Sign-in, its code step, registration, a device-link pickup and a kit recovery can answer ANOTHER_ACCOUNT_KEPT; the
// screen then names the kept account and offers to sign it out, behind a warning that says what goes and that it
// cannot be undone. AppApi.signOut does it in the journey, and the app is back at the first screen.

/** What an ANOTHER_ACCOUNT_KEPT answer means for the person. */
internal enum class KeptRefusal {
    /** Sign out of the kept account first, then try again. */
    SIGN_OUT_FIRST,

    /** A kit recovery's commit went through: the new master password is in force; sign out of the kept account, then sign in with it. */
    PASSWORD_IN_FORCE,
}

/** Which kept-account refusal [r] is; null for every other answer. */
internal fun keptRefusal(r: IntentResult?): KeptRefusal? = when (r) {
    SignInAnswer.ANOTHER_ACCOUNT_KEPT,
    // The sign-up's first step refuses already (design point 6), with the same offer.
    SignUpStartResult.ANOTHER_ACCOUNT_KEPT,
    CreateAccountResult.ANOTHER_ACCOUNT_KEPT,
    LinkPasswordResult.ANOTHER_ACCOUNT_KEPT,
    KitRecoverResult.ANOTHER_ACCOUNT_KEPT,
    -> KeptRefusal.SIGN_OUT_FIRST
    ReplacePasswordResult.ANOTHER_ACCOUNT_KEPT -> KeptRefusal.PASSWORD_IN_FORCE
    else -> null
}

/** The account, its server's name and its address, in that order; empty when core named none. */
private fun keptValues(kept: MasterPasswordPrompt?): Array<String> =
    if (kept == null) emptyArray() else arrayOf(kept.email.orEmpty(), kept.instance.name, kept.instance.origin)

/** What the screen says for a kept-account refusal, naming the kept account; null for every other answer. */
internal fun keptAccountWords(r: IntentResult?, kept: MasterPasswordPrompt?, notConfirmed: Boolean = false): UiText? = when (keptRefusal(r)) {
    // [notConfirmed] ([AppSnapshot.keptSignedOutNotConfirmed]): the kept session ended because this phone could not
    // confirm it with its server, never "its server signed it out".
    KeptRefusal.SIGN_OUT_FIRST -> UiText.ph(if (notConfirmed) Placeholder.KEPT_ACCOUNT_SIGN_OUT_FIRST_NOT_CONFIRMED else Placeholder.KEPT_ACCOUNT_SIGN_OUT_FIRST, *keptValues(kept))
    KeptRefusal.PASSWORD_IN_FORCE -> UiText.ph(if (notConfirmed) Placeholder.KEPT_ACCOUNT_PASSWORD_IN_FORCE_NOT_CONFIRMED else Placeholder.KEPT_ACCOUNT_PASSWORD_IN_FORCE, *keptValues(kept))
    null -> null
}

/** The warning before the kept account is signed out: what is deleted from this phone, and that it cannot be undone. */
internal fun keptSignOutWarning(kept: MasterPasswordPrompt): UiText =
    UiText.ph(Placeholder.KEPT_ACCOUNT_SIGN_OUT_WARNING, *keptValues(kept))

/**
 * Whether [s] offers to sign the kept account out after [result], while the account is kept: a kept-account refusal.
 * Where this phone's own copy of the same account stands in the way, the offer is that copy's removal instead
 * ([WayOut.COPY_REMOVAL]).
 */
internal fun offersKeptSignOut(s: AppSnapshot, result: IntentResult?): Boolean =
    wayOutFor(result) == WayOut.KEPT_SIGN_OUT && s.keptSignedOut != null

/** The way out a stop names, offered under its sentence ([WayOutOffer]). */
internal enum class WayOut {
    /** Another account is kept here: sign it out (its count first), then try again. */
    KEPT_SIGN_OUT,

    /** This phone's own copy of the account stands in the way (damaged, or its keys are not the server's): remove it, its count first. */
    COPY_REMOVAL,

    /** This phone holds its server's operator account: remove it from this phone (never a sign-out). */
    HELD_OPERATOR_REMOVAL,
}

/**
 * The way out of the stop [r] is, as the shared code names it ([KeptStops.wayOut]: one cause, one way out), or null
 * where it has none to offer here: an answer that names another account than the kept one, and the identity fault, are
 * told to whoever runs the server, never met with a sign-out.
 */
internal fun wayOutFor(r: IntentResult?): WayOut? = r?.let { wayOutOf(KeptStops.wayOut(it)) }

/** The way out of a device link that ended for one of this phone's own reasons ([KeptStops.linkWayOut]). */
internal fun wayOutFor(end: LinkDeviceEnd): WayOut? = wayOutOf(KeptStops.linkWayOut(end))

/**
 * The results that move the person to another screen than the one they were asked on (check A17, property 5): a
 * recovery's commit or a registration that the server took while this phone refused the session (to the new kit), and a
 * recovery stopped before its commit (back to where the kit is handed in, or to the request's screen). They are said
 * where the person lands ([TrustModel]).
 */
internal fun movesWithPerson(r: IntentResult): Boolean = when (r) {
    ReplacePasswordResult.ANOTHER_ACCOUNT_KEPT,
    ReplacePasswordResult.IDENTITY_FAULT_COMMITTED,
    ReplacePasswordResult.SERVER_KEYS_NOT_KNOWN_HERE_COMMITTED,
    ReplacePasswordResult.COMMITTED_NOT_KEPT,
    ReplacePasswordResult.OPERATOR_ACCOUNT_HELD_COMMITTED,
    ReplacePasswordResult.KEPT_COPY_DAMAGED_COMMITTED,
    ReplacePasswordResult.SERVER_KEYS_NOT_KNOWN_HERE,
    ReplacePasswordResult.ANOTHER_ACCOUNT_KEPT_NOT_COMMITTED,
    ReplacePasswordResult.IDENTITY_FAULT,
    ReplacePasswordResult.OPERATOR_ACCOUNT_HELD,
    ReplacePasswordResult.KEPT_COPY_DAMAGED,
    ReplacePasswordResult.NOT_THE_KEPT_ACCOUNT,
    // A commit the server took whose answer did not open the account here: the journey is back at the first screen.
    ReplacePasswordResult.COMMITTED_NOT_OPENED,
    // A commit after the operator's help that the request can no longer finish (it ran out of time or was used, or
    // whoever runs the server ended it): nothing was committed and the journey is back at the first screen.
    ReplacePasswordResult.REQUEST_ENDED,
    // A request cancelled before its mailed code (from the account's side or by whoever runs the server): it is forgotten
    // here and the journey is back at the first screen, which says so.
    io.silencelen.andvari.core.app.CodeResult.REQUEST_CANCELLED,
    // A device link's claim refused as one of too many requests: nothing is claimed and the journey is back where a link
    // is handed in, which says the wait (asked on the server's check, it was never seen there).
    io.silencelen.andvari.core.app.ServerResult.RATE_LIMITED,
    CreateAccountResult.ACCOUNT_MADE_NOT_KEPT,
    CreateAccountResult.ACCOUNT_MADE_IDENTITY_FAULT,
    CreateAccountResult.ACCOUNT_MADE_OPERATOR_ACCOUNT_HELD,
    CreateAccountResult.IDENTITY_FAULT,
    KitRecoverResult.SERVER_KEYS_NOT_KNOWN_HERE,
    KitRecoverResult.ANOTHER_ACCOUNT_KEPT,
    KitRecoverResult.IDENTITY_FAULT,
    KitRecoverResult.OPERATOR_ACCOUNT_HELD,
    KitRecoverResult.KEPT_COPY_DAMAGED,
    -> true
    else -> false
}

/** Why the request's screen stops, in place of its stage's line, and the way out it offers ([OperatorHelpScreen]). */
internal class OperatorHelpStop(val line: CopyKey, val way: WayOut?)

/**
 * The request's own stop, if the operator's answer cannot be used on this phone now; null while the request goes on.
 * Its way out is the screen's own ([EntryScreen.OperatorHelp.wayOut]): none for an answer naming another account than
 * the kept one, nor for the identity fault (told to whoever runs the server).
 */
internal fun operatorHelpStop(screen: EntryScreen.OperatorHelp): OperatorHelpStop? =
    (screen.operatorAccountHeld ?: screen.keptCopyDamaged ?: screen.anotherAccountKept ?: screen.keysNotKnownHere
        ?: screen.notTheKeptAccount ?: screen.identityFault)?.let { OperatorHelpStop(it, wayOutOf(screen.wayOut)) }

/** Whether [s] can offer the removal of the held operator account from where it is: the journey, not the kit nor the first screen (whose card has it). */
internal fun offersHeldRemoval(s: AppSnapshot): Boolean =
    s.phase == AppPhase.ENTRY && s.entry !is EntryScreen.Kit && s.entry !is EntryScreen.FirstRun

/**
 * Under a stop, its way out: the kept account's sign-out, the removal of this phone's copy (both with their count
 * first, behind the confirmation), or the removal of the held operator account (on the first screen, behind its own
 * confirmation). Nothing is offered while the kit is on show: the kit is typed back first.
 */
@Composable
internal fun WayOutOffer(model: TrustModel, s: AppSnapshot, way: WayOut?) {
    if (s.entry is EntryScreen.Kit) return
    when (way) {
        WayOut.KEPT_SIGN_OUT -> s.keptSignedOut?.let { KeptAccountSignOut(model, s, it) }
        WayOut.COPY_REMOVAL -> s.keptSignedOut?.let { KeptAccountSignOut(model, s, it, removal = true) }
        WayOut.HELD_OPERATOR_REMOVAL -> if (offersHeldRemoval(s)) {
            Second(UiText.ph(Placeholder.OPERATOR_HELD_REMOVE), enabled = !s.busy) { model.askRemoveHeldOperator() }
        }
        null -> Unit
    }
}

/** The shared code's one way out for a cause ([io.silencelen.andvari.core.app.KeptStops]), as this app offers it. */
internal fun wayOutOf(kept: io.silencelen.andvari.core.app.KeptWayOut?): WayOut? = when (kept) {
    io.silencelen.andvari.core.app.KeptWayOut.SIGN_OUT_KEPT_ACCOUNT -> WayOut.KEPT_SIGN_OUT
    io.silencelen.andvari.core.app.KeptWayOut.REMOVE_THIS_COPY -> WayOut.COPY_REMOVAL
    io.silencelen.andvari.core.app.KeptWayOut.REMOVE_HELD_OPERATOR_ACCOUNT -> WayOut.HELD_OPERATOR_REMOVAL
    null -> null
}

/**
 * The way out this screen offers under a wiped kit's notice: the shared code's ([io.silencelen.andvari.core.app.KitWipedNotice.wayOut]),
 * unless the screen already offers the same under a result it says ([saidResult]), so it is never offered twice.
 */
internal fun kitWipedWayOut(notice: io.silencelen.andvari.core.app.KitWipedNotice, saidResult: IntentResult?, s: AppSnapshot): WayOut? =
    wayOutOf(notice.wayOut)?.takeIf { it != wayOutFor(saidResult) && namedKeptStands(notice, s) }

/**
 * A way out that signs the kept account OUT stands on the screen on show: the notice that a kit was wiped names it
 * ([io.silencelen.andvari.core.app.KeptWayOut.SIGN_OUT_KEPT_ACCOUNT]) for the kept session that is still here. Then a
 * line about that session's end must not tell the person to sign in again.
 */
internal fun signOutWayOutStands(s: AppSnapshot): Boolean =
    s.kitWiped?.let { it.wayOut == io.silencelen.andvari.core.app.KeptWayOut.SIGN_OUT_KEPT_ACCOUNT && namedKeptStands(it, s) } == true

/**
 * The kept session the notice named is still the one kept here: the mark it named
 * ([io.silencelen.andvari.core.app.KitWipedNotice.namedKept]) equals the kept session's mark now (the first screen's
 * [AppSnapshot.keptSignedOut], or the lock screen's prompt), and neither is empty. Compared for equality only; never
 * shown, logged or kept. A notice that names no kept session offers no way out that acts on one.
 */
internal fun namedKeptStands(notice: io.silencelen.andvari.core.app.KitWipedNotice, s: AppSnapshot): Boolean {
    val named = notice.namedKept?.takeIf { it.isNotEmpty() } ?: return false
    val now = (s.keptSignedOut ?: s.locked?.prompt)?.keptMark?.takeIf { it.isNotEmpty() } ?: return false
    return named == now
}

/**
 * Under a notice that a kit was wiped and that names what stands in the way here, the first screen offers that way out,
 * with no sign-in tried first: the kept account's sign-out or this phone's copy's removal (each with its count first and
 * its confirmations, [KeptAccountSignOut]); the operator's account held here is removed from the first screen's own card
 * ([HeldOperatorCard]), with its confirmation. The notice itself carries only its Close.
 */
@Composable
internal fun KitWipedWayOut(model: TrustModel, s: AppSnapshot, notice: io.silencelen.andvari.core.app.KitWipedNotice) {
    when (kitWipedWayOut(notice, model.saidOn(s)?.result, s)) {
        WayOut.KEPT_SIGN_OUT -> s.keptSignedOut?.let { KeptAccountSignOut(model, s, it) }
        WayOut.COPY_REMOVAL -> s.keptSignedOut?.let { KeptAccountSignOut(model, s, it, removal = true) }
        WayOut.HELD_OPERATOR_REMOVAL, null -> Unit
    }
}

/** The warning before this phone's copy is removed: what is deleted, and that it cannot be undone. */
internal fun copyRemovalWarning(kept: MasterPasswordPrompt): UiText =
    UiText.ph(Placeholder.COPY_REMOVE_WARNING, *keptValues(kept))

/**
 * Under a kept-account refusal: "Sign out of that account", which asks first. The confirm is [AppApi.signOut], which
 * in the journey signs the kept account out and deletes its copy; the app is then at the first screen. Its copy is
 * not open, so this phone cannot count what was not sent: the confirmation says so and asks twice ([SignOutAsk]).
 * [removal]: the same act where this phone's own copy is what stands in the way, named as its removal.
 */
@Composable
internal fun KeptAccountSignOut(model: TrustModel, s: AppSnapshot, kept: MasterPasswordPrompt, removal: Boolean = false) {
    val drawn = LocalDrawnAsk.current
    val ask = drawn ?: remember(model, kept) { model.signOutAsk() }
    val label = UiText.ph(if (removal) Placeholder.COPY_REMOVE else Placeholder.KEPT_ACCOUNT_SIGN_OUT)
    Second(label, enabled = !s.busy) { ask.open() }
    LaunchedEffect(s) { ask.refresh() }
    SignOutConfirm(ask, s, label, warning = if (removal) copyRemovalWarning(kept) else keptSignOutWarning(kept), dismiss = UiText.of(CopyKey.CANCEL))
}
