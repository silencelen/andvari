package io.silencelen.andvari.desktop.trust

import androidx.compose.foundation.layout.Column
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import io.silencelen.andvari.core.app.AppSnapshot
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.IntentResult
import io.silencelen.andvari.core.app.KeptStops
import io.silencelen.andvari.core.app.KeptWayOut
import io.silencelen.andvari.core.app.KitRecoverResult
import io.silencelen.andvari.core.app.KitScanResult
import io.silencelen.andvari.core.app.LinkPasswordResult
import io.silencelen.andvari.core.app.MasterPasswordPrompt
import io.silencelen.andvari.core.app.ReplacePasswordResult
import io.silencelen.andvari.core.app.SignInAnswer
import io.silencelen.andvari.core.app.SignUpStartResult

// A second account while a server-ended one is kept (the app interface's option A): this computer keeps an account its
// server signed out ([AppSnapshot.keptSignedOut]), and any other account is refused until that one is signed out. Sign-in,
// its code step, registration, a device link's password and a kit recovery can each answer ANOTHER_ACCOUNT_KEPT; every
// one of those screens shows what was said through [SaidHere], which shows this refusal instead of the bare result.
//
// The session keeper's other reasons are each said as what they are, with their own way out (the check of
// 2026-11-17): a damaged copy of the kept account is removed (its sign-out, which counts what was not sent first); an
// operator's account held here is removed from this computer, never signed out; an answer that names another account
// than the one kept offers nothing.

/**
 * The answers that mean "another account is kept here": nothing was sent (or, after a kit's commit, the new password is
 * in force). Sign-up's first step answers it too, before any address or code is sent. The recovery that
 * stopped before its commit, the kit handed in for another account, and the registration whose account was made and not
 * kept here say the same, each with its own sentence.
 */
internal fun isAnotherAccountKept(r: IntentResult?): Boolean =
    r === SignInAnswer.ANOTHER_ACCOUNT_KEPT || r === SignUpStartResult.ANOTHER_ACCOUNT_KEPT || r === CreateAccountResult.ANOTHER_ACCOUNT_KEPT ||
        r === LinkPasswordResult.ANOTHER_ACCOUNT_KEPT || r === KitRecoverResult.ANOTHER_ACCOUNT_KEPT ||
        r === ReplacePasswordResult.ANOTHER_ACCOUNT_KEPT || r === ReplacePasswordResult.ANOTHER_ACCOUNT_KEPT_NOT_COMMITTED ||
        r === KitScanResult.ANOTHER_ACCOUNT_KEPT || r === CreateAccountResult.ACCOUNT_MADE_NOT_KEPT

/** The answers that mean "this computer's copy of the kept account is damaged": its way out is to remove that copy. */
internal fun isKeptCopyDamaged(r: IntentResult?): Boolean =
    r === SignInAnswer.KEPT_COPY_DAMAGED || r === KitRecoverResult.KEPT_COPY_DAMAGED || r === ReplacePasswordResult.KEPT_COPY_DAMAGED ||
        r === ReplacePasswordResult.KEPT_COPY_DAMAGED_COMMITTED || r === LinkPasswordResult.KEPT_COPY_DAMAGED

/**
 * Every answer that is the session keeper's own refusal, or a recovery committed whose session this computer then
 * refused. Such an answer is said where the person is when it comes (the shared code may have moved them: back to where
 * a kit is handed in, or on to the new kit), never only on the screen it was asked on.
 */
internal fun isKeeperAnswer(r: IntentResult?): Boolean =
    isAnotherAccountKept(r) || isKeptCopyDamaged(r) || r in KEEPER_ANSWERS

private val KEEPER_ANSWERS: Set<IntentResult> = setOf(
    SignInAnswer.OPERATOR_ACCOUNT_HELD, SignInAnswer.SERVER_KEYS_NOT_KNOWN_HERE, SignInAnswer.IDENTITY_FAULT,
    SignUpStartResult.OPERATOR_ACCOUNT_HELD, CreateAccountResult.OPERATOR_ACCOUNT_HELD, CreateAccountResult.IDENTITY_FAULT,
    KitScanResult.OPERATOR_ACCOUNT_HELD,
    KitRecoverResult.OPERATOR_ACCOUNT_HELD, KitRecoverResult.IDENTITY_FAULT, KitRecoverResult.SERVER_KEYS_NOT_KNOWN_HERE,
    LinkPasswordResult.OPERATOR_ACCOUNT_HELD, LinkPasswordResult.IDENTITY_FAULT, LinkPasswordResult.SERVER_KEYS_NOT_KNOWN_HERE,
    LinkPasswordResult.ANOTHER_SESSION_KEPT,
    ReplacePasswordResult.OPERATOR_ACCOUNT_HELD, ReplacePasswordResult.IDENTITY_FAULT, ReplacePasswordResult.SERVER_KEYS_NOT_KNOWN_HERE,
    ReplacePasswordResult.NOT_THE_KEPT_ACCOUNT,
    ReplacePasswordResult.IDENTITY_FAULT_COMMITTED, ReplacePasswordResult.SERVER_KEYS_NOT_KNOWN_HERE_COMMITTED,
    ReplacePasswordResult.COMMITTED_NOT_KEPT, ReplacePasswordResult.OPERATOR_ACCOUNT_HELD_COMMITTED,
    // A commit that happened and could not be opened here: the journey is back at the first screen, which says it.
    ReplacePasswordResult.COMMITTED_NOT_OPENED,
    // A registration the server took, whose session a fault of the account's identity refused here: with its kit.
    CreateAccountResult.ACCOUNT_MADE_IDENTITY_FAULT,
)

/**
 * What the screen says on that refusal: the kept account named whole (address, server, origin: §4.4), that it must be
 * signed out first, then the result's own sentence where it says what happened: nothing was committed (a recovery stopped
 * before its commit, a kit for another account), or a recovery's commit went through and the new master password is set
 * (the shared code's sentence for it). Null for any other result, or when no account is kept any more (the result's own
 * words are shown then).
 */
internal fun keptAccountLines(result: IntentResult?, s: AppSnapshot): List<UiText>? {
    if (!isAnotherAccountKept(result)) return null
    if (s.keptSignedOut == null) return null
    val lines = keptAccountNamed(s).toMutableList()
    if (result === ReplacePasswordResult.ANOTHER_ACCOUNT_KEPT || result === ReplacePasswordResult.ANOTHER_ACCOUNT_KEPT_NOT_COMMITTED ||
        result === KitScanResult.ANOTHER_ACCOUNT_KEPT
    ) {
        result.sentence?.let { lines += UiText.of(it) }
    }
    return lines
}

/**
 * [text] is the line the shared code says for [result] once the kit that came with it was typed back
 * ([KeptStops.lineWithoutKit]), in place of the result's own sentence (which tells the person to save that kit).
 */
internal fun saysWhyWithoutKit(result: IntentResult, text: UiText?): Boolean {
    val why = KeptStops.lineWithoutKit(result) ?: return false
    return text != null && text.shown() == UiText.of(why).shown()
}

internal fun keptAccountLine(kept: MasterPasswordPrompt): UiText =
    UiText.phWith(
        Placeholder.KEPT_ACCOUNT_SIGN_OUT_FIRST,
        kept.email?.let(::said) ?: Slot(UiText.ph(Placeholder.KEPT_ACCOUNT_UNNAMED).shown(), named = false),
        said(kept.instance.name), said(kept.instance.origin),
    )

/**
 * The kept account of [s] named above a refusal's way out: [keptAccountLine], which says its server signed it out; or,
 * where this computer could not confirm that session with its server ([AppSnapshot.keptSignedOutNotConfirmed]), the
 * account named without that claim, then the shared code's line for that end beside a sign-out
 * ([AppSnapshot.keptSignedOutSignOutFirstLine]); its line for that end elsewhere ([AppSnapshot.keptSignedOutLine]) tells
 * the person to sign in again, the opposite of signing that account out first, so it is not drawn here. Empty where no
 * account is kept.
 */
internal fun keptAccountNamed(s: AppSnapshot): List<UiText> {
    val kept = s.keptSignedOut ?: return emptyList()
    if (!s.keptSignedOutNotConfirmed) return listOf(keptAccountLine(kept))
    val named = UiText.phWith(
        Placeholder.KEPT_ACCOUNT_NOT_CONFIRMED_SIGN_OUT_FIRST,
        kept.email?.let(::said) ?: Slot(UiText.ph(Placeholder.KEPT_ACCOUNT_UNNAMED).shown(), named = false),
        said(kept.instance.name), said(kept.instance.origin),
    )
    // The shared code's line for that end where the person is told to sign that account out first, which never says "sign
    // in again" (its other line for that end, SESSION_NOT_CONFIRMED, does, and is not drawn here): as handed, after the name.
    return listOfNotNull(named, s.keptSignedOutSignOutFirstLine?.let { UiText.of(it) })
}

/**
 * The way out of a refusal, as a screen offers it.
 * - [SignOutKept]: another account is kept; its sign-out, behind the usual warning.
 * - [RemoveDamagedCopy]: the kept copy is damaged; its removal, which is that account's sign-out (it says first how many
 *   changes were not sent, or that it cannot tell), behind the same warning.
 * Null where the refusal has no way out on this computer (an operator's account held here, which the desktop never
 * holds and never signs out; an answer that names another account; a refusal with no kept account to act on).
 */
internal sealed class WayOut(val lines: List<UiText>, val kept: MasterPasswordPrompt) {
    class SignOutKept(lines: List<UiText>, kept: MasterPasswordPrompt) : WayOut(lines, kept)
    class RemoveDamagedCopy(lines: List<UiText>, kept: MasterPasswordPrompt) : WayOut(lines, kept)

    /** The button that opens the warning. */
    val button: UiText get() = if (this is RemoveDamagedCopy) UiText.ph(Placeholder.KEPT_COPY_REMOVE) else UiText.ph(Placeholder.SIGN_OUT)
}

/**
 * The shared code's one way out for one cause ([act]: [KeptStops.wayOut], [KeptStops.linkWayOut], a screen's or a
 * notice's own `wayOut`) as this computer offers it, with [lines] above its button: the kept account's sign-out, or the
 * removal of this computer's own copy, each behind the usual count and confirmations. The held operator account's
 * removal is offered by the first screen itself ([EntryScreen.FirstRun.heldAsOperator]), the only screen that carries
 * it: nothing here. Null too where no account is kept to act on.
 */
internal fun wayOutFor(act: KeptWayOut?, lines: List<UiText>, s: AppSnapshot): WayOut? {
    val kept = s.keptSignedOut ?: return null
    return when (act) {
        KeptWayOut.SIGN_OUT_KEPT_ACCOUNT -> WayOut.SignOutKept(lines, kept)
        KeptWayOut.REMOVE_THIS_COPY -> WayOut.RemoveDamagedCopy(lines, kept)
        KeptWayOut.REMOVE_HELD_OPERATOR_ACCOUNT, null -> null
    }
}

/**
 * [WayOut] for [result] (its words [text]) on the snapshot [s]: the shared code's act for it ([KeptStops.wayOut]). On the
 * first screen after the kit that came with [result] was typed back, [text] is the shared code's line for that
 * ([saysWhyWithoutKit]): it is said with the kept account named, never the result's own sentence beside it.
 */
internal fun wayOutOf(result: IntentResult?, text: UiText?, s: AppSnapshot): WayOut? {
    val act = result?.let(KeptStops::wayOut) ?: return null
    if (s.keptSignedOut == null) return null
    val said = text ?: result.sentence?.let { UiText.of(it) }
    val lines = when {
        act != KeptWayOut.SIGN_OUT_KEPT_ACCOUNT -> listOfNotNull(said)
        saysWhyWithoutKit(result, text) -> keptAccountNamed(s) + listOfNotNull(said)
        else -> keptAccountLines(result, s) ?: (keptAccountNamed(s) + listOfNotNull(said))
    }
    return wayOutFor(act, lines, s)
}

/**
 * The way out under the notice that a kit was wiped ([io.silencelen.andvari.core.app.KitWipedNotice]): the shared
 * code's act for what stands in the way here ([io.silencelen.andvari.core.app.KitWipedNotice.wayOut], [act]), where this
 * computer can act on it: the kept account's sign-out, behind its usual count and confirmations, on the screen without a
 * sign-in tried first. Null for no act (an identity fault), for the held operator account (the first screen itself
 * offers its removal, [EntryScreen.FirstRun.heldAsOperator]) and where no account is kept to act on ([kept] null). The
 * notice names why already, so the way out adds only the kept account's own line.
 *
 * Offered only while what the notice named still stands: the kept session it named when the kit was wiped
 * ([io.silencelen.andvari.core.app.KitWipedNotice.namedKept]) is the very one kept now, its mark equal to the kept
 * account's ([MasterPasswordPrompt.keptMark]) and neither empty. A session taken since (another account, or the same
 * account taken again) has another mark, so nothing is offered for it. The marks are compared for equality only, never
 * shown, logged or kept. With the mark, the removal of a damaged copy is offered under the notice again.
 */
internal fun kitWipedWayOut(act: KeptWayOut?, kept: MasterPasswordPrompt?, namedKept: String?, lines: List<UiText>): WayOut? {
    if (act == null || kept == null || namedKept.isNullOrEmpty() || kept.keptMark.isEmpty() || kept.keptMark != namedKept) return null
    return when (act) {
        KeptWayOut.SIGN_OUT_KEPT_ACCOUNT -> WayOut.SignOutKept(lines, kept)
        KeptWayOut.REMOVE_THIS_COPY -> WayOut.RemoveDamagedCopy(emptyList(), kept)
        // The held operator account: the first screen under the notice offers its removal itself.
        KeptWayOut.REMOVE_HELD_OPERATOR_ACCOUNT -> null
    }
}

/** [kitWipedWayOut] for the notice on show in [s], on the journey's screens other than a kit's. */
internal fun kitWipedWayOut(s: AppSnapshot): WayOut? {
    if (s.phase != io.silencelen.andvari.core.app.AppPhase.ENTRY || s.entry is EntryScreen.Kit) return null
    val notice = s.kitWiped ?: return null
    return kitWipedWayOut(notice.wayOut, s.keptSignedOut, notice.namedKept, keptAccountNamed(s))
}

/** A device link that ended over something kept here offers the shared code's way out ([KeptStops.linkWayOut]) on the screen that says so. */
internal fun linkEndWayOut(screen: EntryScreen.LinkDeviceEnded, s: AppSnapshot): WayOut? {
    val act = KeptStops.linkWayOut(screen.outcome)
    val lines = if (act == KeptWayOut.SIGN_OUT_KEPT_ACCOUNT) keptAccountNamed(s) else emptyList()
    return wayOutFor(act, lines, s)
}

/**
 * The refusal, in place: its lines, then the way out ("Sign out" of the kept account, or "Remove" its damaged copy)
 * behind the app's usual warning ([SignOutQuestion]), which here also says that its copy on this computer goes. Signing
 * out returns to the first screen ([io.silencelen.andvari.core.app.AppApi.signOut] in the journey). [offered] false
 * shows the lines only: a kit on show that this computer did not keep would go with the sign-out unsaid, so the way out
 * is offered on the first screen once the kit was typed back.
 */
@Composable
internal fun KeptAccountRefusal(model: TrustModel, s: AppSnapshot, way: WayOut, offered: Boolean = true) {
    for (line in way.lines) Say(line, color = MaterialTheme.colorScheme.error)
    // A kit this computer did not keep is on show: the way out waits for the first screen.
    if (!offered) return
    var asking by remember { mutableStateOf(false) }
    Second(way.button, enabled = !s.busy) { asking = true }
    if (asking) SignOutQuestion(model, way.kept, s) { asking = false }
}

/**
 * The app's usual sign-out warning ([SignOutButton]'s question), as the current app's "Sign out of this device?"
 * window. For a kept account it names that account and says that its copy here is deleted with it, changes not yet
 * sent included (§4.4: only the person's sign-out deletes it). It reads the shared code's check as it opens
 * ([SignOutAsk]): with changes waiting, or while this computer cannot tell, it says so, offers to send them first
 * where that can be done, and "Sign out" opens the second confirmation, which alone signs out.
 */
@Composable
internal fun SignOutQuestion(model: TrustModel, kept: MasterPasswordPrompt?, s: AppSnapshot, close: () -> Unit) {
    val ask = remember { SignOutAsk(model, SignOutAct.SignOut, close) }
    // The page changed under the open confirmation (a lock, a sync, the server's end): the check is read again.
    LaunchedEffect(s) { ask.reread() }
    if (ask.second) return SecondConfirmation(ask, s, close)
    val unsent = ask.line != null || ask.said != null
    val restoring = unfinishedRestore(model)
    AlertDialog(
        onDismissRequest = close,
        title = { Say(Placeholder.SIGN_OUT_CONFIRM) },
        text = if (kept == null && !unsent && !restoring) null else {
            {
                Column {
                    if (kept != null) {
                        kept.email?.let { Say(UiText.Plain(it)) }
                        InstanceName(kept.instance, MaterialTheme.typography.bodyMedium)
                        Say(Placeholder.KEPT_ACCOUNT_SIGN_OUT_DELETES)
                    }
                    UnsentLines(ask)
                    UnfinishedRestoreLine(model)
                }
            }
        },
        // The way out first, then "try sending them first" where it is offered, then Sign out.
        confirmButton = { ConfirmationButtons(UiText.ph(Placeholder.STAY_SIGNED_IN), close, ask, s, UiText.ph(Placeholder.SIGN_OUT)) { ask.proceed() } },
    )
}
