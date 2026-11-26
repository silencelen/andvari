package io.silencelen.andvari.app.trust

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.ui.Modifier
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import io.silencelen.andvari.core.app.AppApi
import io.silencelen.andvari.core.app.AppSnapshot
import io.silencelen.andvari.core.app.IntentResult
import io.silencelen.andvari.core.app.PlainResult
import io.silencelen.andvari.core.app.SendFirstResult
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.SignOutCheck

// A sign-out deletes this phone's copy of the account, and with it every change made here that the server does not
// have (design §4.4). Rule of 2026-11-17: no copy on a device is deleted over changes that were not sent without the
// person being told how many. Every place the phone signs out (Settings, the lock screen, the account its server signed
// out and the phone kept, and the switch to another server's invitation) asks through one [SignOutAsk]:
//
// - When the confirmation opens it reads the shared code's check ([AppApi.signOutCheck]).
// - Nothing waits: the confirmation signs out as it always did ([AppApi.signOut], or the plain switch).
// - Changes wait: it shows the line that says how many are lost ([SignOutCheck.line]) and, where the shared code
//   offers it, "try sending them first" ([AppApi.sendBeforeSignOut], then the check is read again). Its sign-out
//   button opens a second confirmation, and only that one signs out ([AppApi.signOutConfirmed] with the check it
//   showed, or [io.silencelen.andvari.core.app.LinksApi.switchInstanceConfirmed]).
// - Locked: the line says this phone cannot tell, and the second confirmation is still asked.
// - A check that no longer holds when the person confirms (another change, a lock): the shared code answers
//   UNSENT_NOT_CONFIRMED, nothing is deleted, and the first confirmation opens again with the new check.

/** One sign-out confirmation and its steps. Made by [TrustModel.signOutAsk] and [TrustModel.switchAsk]. */
class SignOutAsk internal constructor(
    private val model: TrustModel,
    /** The act when nothing waits: [AppApi.signOut], or the switch. */
    private val plain: suspend AppApi.() -> IntentResult,
    /** The act after the person's second confirmation of the check on show. */
    private val confirmed: suspend AppApi.(SignOutCheck) -> IntentResult,
    /** The switch to another server's invitation (its second confirmation names that act), not a plain sign-out. */
    internal val switching: Boolean = false,
    private val after: (IntentResult) -> Unit,
) {
    enum class Step {
        /** Not asking (a dialog place before its button is tapped, or after it signed out). */
        CLOSED,

        /** The confirmation: the line, "try sending them first", and the sign-out button. */
        FIRST,

        /** The second confirmation, over changes that would be lost or that this phone cannot count. */
        SECOND,
    }

    var step: Step by mutableStateOf(Step.CLOSED)
        private set

    /** The shared code's check as the confirmation shows it; null where a sign-out would answer STALE. */
    var check: SignOutCheck? by mutableStateOf(null)
        private set

    /** What the last "try sending them first" answered; null before it, and once nothing is left to say. */
    var sendAnswer: SendFirstResult? by mutableStateOf(null)
        private set

    /** "Try sending them first" is running. */
    var sending: Boolean by mutableStateOf(false)
        private set

    /** The confirmation opens: the check is read now. */
    fun open() {
        check = model.api.signOutCheck()
        sendAnswer = null
        step = Step.FIRST
    }

    /**
     * Read the check again (the snapshot changed): the first confirmation, and the switch's screen, show what holds
     * now. The second confirmation keeps the check it shows; the shared code refuses it if it no longer holds.
     */
    fun refresh() {
        if (step != Step.SECOND && !sending) check = model.api.signOutCheck()
    }

    /** The person backs out: nothing is deleted. */
    fun close() {
        step = Step.CLOSED
        sendAnswer = null
    }

    /** Back from the second confirmation to the first (the switch's screen stays). */
    fun back() {
        step = Step.FIRST
        refresh()
    }

    /** The second confirmation is needed for the check on show. */
    val asksTwice: Boolean get() = check?.needsConfirmation == true

    /**
     * The sign-out button. On the first confirmation: signs out when nothing waits, otherwise opens the second one. On
     * the second: signs out with the check it showed.
     */
    fun confirm() {
        val c = check
        when (step) {
            Step.SECOND -> if (c != null) go { confirmed(this, c) } else go(plain)
            else -> if (c?.needsConfirmation == true) step = Step.SECOND else go(plain)
        }
    }

    private fun go(act: suspend AppApi.() -> IntentResult) {
        step = Step.CLOSED
        sendAnswer = null
        // The person's own end of the session: work it overtakes is said as not done by it, never as the server's.
        model.personEnds()
        model.runSaying(act, { r -> if (notConfirmed(r)) null else model.wordsFor(r) }) { r ->
            model.personEndAnswered(r.done)
            // The check no longer held: nothing was deleted; the first confirmation opens again with the new check.
            if (notConfirmed(r)) open()
            after(r)
        }
    }

    /** "Try sending them first": a sync of what waits, then the check is read again. Nothing is deleted. */
    fun sendFirst() {
        val c = check ?: return
        if (c.sendFirstLabel == null || sending) return
        sending = true
        sendAnswer = null
        model.runSaying({ sendBeforeSignOut(c) }, { null }) { r ->
            sending = false
            check = model.api.signOutCheck()
            sendAnswer = r.takeUnless { it == SendFirstResult.DONE }
            step = Step.FIRST
        }
    }

    internal companion object {
        fun notConfirmed(r: IntentResult): Boolean = r == PlainResult.UNSENT_NOT_CONFIRMED || r == ServerResult.UNSENT_NOT_CONFIRMED
    }
}

/**
 * A sign-out or switch confirmation already open at a given step, for the screen images (ScreenImagesTest) only: the
 * drawing makes it with [TrustModel.signOutAsk] or [TrustModel.switchAsk] and walks it to the step it draws. Nothing
 * in the app provides it, so on a phone it is null and each place makes its own.
 */
internal val LocalDrawnAsk = androidx.compose.runtime.staticCompositionLocalOf<SignOutAsk?> { null }

/** What "try sending them first" answered, said inside the confirmation; null when it sent everything. */
internal fun sendAnswerWords(r: SendFirstResult?): UiText? = r?.let { UiText.forResult(it, 0) }

/**
 * The part of a first confirmation about changes not sent: the shared code's line, what sending first answered, and
 * the "try sending them first" button where it is offered. Nothing when nothing waits.
 */
@Composable
internal fun UnsentLines(ask: SignOutAsk, s: AppSnapshot) {
    val check = ask.check ?: return
    check.line?.let { Say(UiText.of(it), color = MaterialTheme.colorScheme.error) }
    sendAnswerWords(ask.sendAnswer)?.let { Say(it) }
    check.sendFirstLabel?.let { label ->
        Second(UiText.of(label), enabled = !s.busy && !ask.sending) { ask.sendFirst() }
    }
    if (ask.sending) Quiet(UiText.ph(Placeholder.WORKING))
}

/**
 * The first confirmation of a sign-out, as the current app's "Sign out of this device?" dialog: [title], then
 * [warning] where the place has one (the kept account's), then the lines about changes not sent; the sign-out button
 * and the way out. The second confirmation follows it ([SecondSignOutConfirm]).
 */
@Composable
internal fun SignOutConfirm(ask: SignOutAsk, s: AppSnapshot, title: UiText, warning: UiText?, dismiss: UiText, body: UiText? = null) {
    when (ask.step) {
        SignOutAsk.Step.CLOSED -> Unit
        SignOutAsk.Step.FIRST -> AlertDialog(
            onDismissRequest = { ask.close() },
            title = { Say(title) },
            text = {
                // It scrolls: at the largest font the lines and "try sending them first" do not fit a phone's height.
                Column(Modifier.verticalScroll(rememberScrollState())) {
                    body?.let { Say(it) }
                    warning?.let { Say(it, color = MaterialTheme.colorScheme.error) }
                    UnsentLines(ask, s)
                }
            },
            confirmButton = { TextButton(onClick = { ask.confirm() }, enabled = !ask.sending) { Say(Placeholder.SIGN_OUT) } },
            dismissButton = { TextButton(onClick = { ask.close() }) { Say(dismiss) } },
        )
        SignOutAsk.Step.SECOND -> SecondSignOutConfirm(ask, dismiss) { ask.close() }
    }
}

/**
 * The second confirmation: its own short title (the same entry in both apps), the shared code's line again (how many
 * changes are lost, or that this phone cannot tell), and the one button that signs out over them. [onBack] is the way
 * out; nothing is deleted. The line is the dialog's text, which scrolls: as the title it filled the dialog at the
 * largest font and pushed the buttons out.
 */
@Composable
internal fun SecondSignOutConfirm(ask: SignOutAsk, dismiss: UiText, onBack: () -> Unit) {
    if (ask.step != SignOutAsk.Step.SECOND) return
    val line = ask.check?.line ?: return
    val large = largeFont()
    AlertDialog(
        onDismissRequest = onBack,
        title = { Say(UiText.ph(if (ask.switching) Placeholder.SWITCH_SECOND_CONFIRM else Placeholder.SIGN_OUT_SECOND_CONFIRM)) },
        text = { Column(Modifier.verticalScroll(rememberScrollState())) { Say(UiText.of(line), color = MaterialTheme.colorScheme.error) } },
        confirmButton = {
            val confirm = @Composable {
                TextButton(onClick = { ask.confirm() }) { Say(UiText.ph(if (ask.switching) Placeholder.SWITCH_ALL_THE_SAME else Placeholder.SIGN_OUT_ALL_THE_SAME), color = MaterialTheme.colorScheme.error) }
            }
            // At the largest font a long label beside the way out ran over it: there the two stand one above the other.
            if (large) {
                Column(horizontalAlignment = androidx.compose.ui.Alignment.End) {
                    confirm()
                    TextButton(onClick = onBack) { Say(dismiss) }
                }
            } else {
                confirm()
            }
        },
        dismissButton = if (large) null else ({ TextButton(onClick = onBack) { Say(dismiss) } }),
    )
}
