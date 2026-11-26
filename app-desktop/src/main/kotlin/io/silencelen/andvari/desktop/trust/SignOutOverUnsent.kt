package io.silencelen.andvari.desktop.trust

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import io.silencelen.andvari.core.app.AppSnapshot
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.IntentResult
import io.silencelen.andvari.core.app.OpenedInvite
import io.silencelen.andvari.core.app.PlainResult
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.SignOutCheck

// No copy on this computer is deleted over changes that were not sent without the person being told how many (the rule
// of 2026-11-17, design §4.4: a sign-out deletes this computer's copy). Every place that signs an account out here
// (Settings, the lock screen, an account its server signed out and this computer kept, the invitation for another
// server, whose switch signs out) asks through one [SignOutAsk]: it reads the shared code's check when its confirmation
// opens; with changes waiting it shows how many are lost, offers to send them first, and only a second confirmation
// signs out; while locked it says that this computer cannot tell, and still asks twice; with nothing waiting the
// confirmation signs out as before.

/** What a confirmation ends with: a sign-out, or the switch to the server of an invitation, which signs out here. */
internal sealed class SignOutAct {
    object SignOut : SignOutAct()

    class Switch(val opened: OpenedInvite.OtherInstance) : SignOutAct()
}

/**
 * The state of one sign-out confirmation, from its opening to its end: the shared code's check ([check]), whether the
 * second confirmation is on show ([second]), and what the last try said inside the confirmation ([said]). [closed]
 * runs once the act is done, or for a sign-out that failed otherwise (its sentence is then said on the page).
 */
internal class SignOutAsk(private val model: TrustModel, val act: SignOutAct, private val closed: () -> Unit) {
    /** The shared code's check, read when the confirmation opens and again after every try. */
    var check: SignOutCheck? by mutableStateOf(model.api.signOutCheck())
        private set

    /** The second confirmation is on show: it alone signs out over what waits (or what this computer cannot count). */
    var second: Boolean by mutableStateOf(false)
        private set

    /** What the last try said in this confirmation ("not all could be sent", "not signed out: confirm"). */
    var said: UiText? by mutableStateOf(null)
        private set

    /** The check's line: how many changes are lost, or that this computer cannot tell. Null when nothing waits. */
    val line: UiText? get() = check?.line?.let { UiText.of(it) }

    /** "Try sending them first", where the shared code offers it. */
    val sendFirstLabel: UiText? get() = check?.sendFirstLabel?.let { UiText.of(it) }

    /** Read the check again (the page changed under the confirmation: a lock, a sync). */
    fun reread() {
        check = model.api.signOutCheck()
        if (check?.needsConfirmation != true) second = false
    }

    /** The first confirmation's main button: over what waits, it opens the second confirmation; otherwise it signs out. */
    fun proceed() {
        said = null
        if (check?.needsConfirmation == true) {
            second = true
            return
        }
        go(null)
    }

    /** Back from the second confirmation to the first (the switch's way out there: its window stays). */
    fun back() {
        second = false
    }

    /** The second confirmation's button: signs out (or switches) over the check on show. */
    fun confirmLoss() {
        val c = check ?: return go(null)
        go(c)
    }

    /** "Try sending them first": a sync of what waits, then the check is read again and shown. Nothing is deleted. */
    fun sendFirst() {
        val c = check ?: return
        said = null
        model.runSaying({ sendBeforeSignOut(c) }, { null }) { r ->
            reread()
            second = false
            said = UiText.forResult(r, model.api.retryAfterSeconds())
        }
    }

    private fun go(confirmed: SignOutCheck?) {
        when (act) {
            SignOutAct.SignOut -> model.signOut(confirmed) { answered(it, it === PlainResult.UNSENT_NOT_CONFIRMED) }
            is SignOutAct.Switch -> model.switchInstance(act.opened, confirmed) { answered(it, it === ServerResult.UNSENT_NOT_CONFIRMED) }
        }
    }

    /**
     * The shared code refused because the check no longer holds (more changes, a lock): the new check is shown in the
     * first confirmation with the refusal's sentence, and the person decides again. Done, or a sign-out that failed
     * otherwise, puts the confirmation away; a switch the other server did not answer stays in its window, where it is said.
     */
    private fun answered(r: IntentResult, unconfirmed: Boolean) {
        if (unconfirmed) {
            reread()
            second = false
            said = unconfirmedLine(act)
            return
        }
        second = false
        if (r.done || act == SignOutAct.SignOut) closed()
    }
}

/**
 * The shared code refused because the check no longer holds: for a sign-out its own sentence; for a switch to another
 * server a line of its own (the shared sentence says "signed in" and "signing out", and the person asked to switch).
 */
internal fun unconfirmedLine(act: SignOutAct): UiText = when (act) {
    SignOutAct.SignOut -> UiText.of(CopyKey.UNSENT_NOT_CONFIRMED)
    is SignOutAct.Switch -> UiText.ph(Placeholder.SWITCH_UNSENT_NOT_CONFIRMED)
}

/** The check's line and what the last try said, in the error tone, inside a confirmation. */
@Composable
internal fun UnsentLines(ask: SignOutAsk) {
    ask.line?.let { Say(it, color = MaterialTheme.colorScheme.error) }
    ask.said?.let { Say(it, color = MaterialTheme.colorScheme.error) }
}

/**
 * A confirmation's buttons in one row, in this order: the way out, "try sending them first" where it is offered, then
 * the main action. They stand in one row of their own, not in the dialog's two button slots: the dialog stacks those
 * with the main action on top once a label is too long for one line (seen on the display), and the way out must come
 * first however long the words are. Each button shares the row's width and wraps its own words.
 */
@Composable
internal fun ConfirmationButtons(wayOut: UiText, onWayOut: () -> Unit, ask: SignOutAsk?, s: AppSnapshot, main: UiText, onMain: () -> Unit) {
    Row(horizontalArrangement = Arrangement.End, verticalAlignment = Alignment.CenterVertically) {
        Box(Modifier.weight(1f, fill = false)) { DialogButton(wayOut, onClick = onWayOut) }
        ask?.sendFirstLabel?.let { Box(Modifier.weight(1f, fill = false)) { DialogButton(it, enabled = !s.busy) { ask.sendFirst() } } }
        Box(Modifier.weight(1f, fill = false)) { DialogButton(main, enabled = !s.busy, onClick = onMain) }
    }
}

/**
 * The second confirmation, in the same window style: its title, the check's line again, then the way out first and
 * the one button that signs out (or switches) over what is lost.
 */
@Composable
internal fun SecondConfirmation(ask: SignOutAsk, s: AppSnapshot, close: () -> Unit) {
    val switch = ask.act is SignOutAct.Switch
    AlertDialog(
        onDismissRequest = close,
        title = { Say(UiText.ph(if (switch) Placeholder.SWITCH_SECOND_CONFIRM else Placeholder.SIGN_OUT_SECOND_CONFIRM), style = MaterialTheme.typography.titleMedium) },
        text = { Column { UnsentLines(ask) } },
        confirmButton = {
            ConfirmationButtons(
                // Sending first is offered in the first confirmation; this one only goes on or goes back.
                if (switch) UiText.of(CopyKey.CANCEL) else UiText.ph(Placeholder.STAY_SIGNED_IN), close, null, s,
                UiText.ph(if (switch) Placeholder.SWITCH_ALL_THE_SAME else Placeholder.SIGN_OUT_ALL_THE_SAME),
            ) { ask.confirmLoss() }
        },
    )
}
