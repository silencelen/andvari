package io.silencelen.andvari.desktop.trust

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.widthIn
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import io.silencelen.andvari.core.app.AccountPrompt
import io.silencelen.andvari.core.app.AppSnapshot
import io.silencelen.andvari.core.app.ConnectResult
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.IntentResult
import io.silencelen.andvari.core.app.LinkCreateResult
import io.silencelen.andvari.core.app.OpenedInvite
import io.silencelen.andvari.core.app.OwnNameResult
import io.silencelen.andvari.core.app.ShareChoice

// A link's offer and its answer carry the name this account goes by, and the server serves no account its own name: a
// computer keeps only the name chosen on it, at the registration or here. An account made on another device has none
// here, and until it has one every link road stops with nothing sent. So before Connect on an opened link, before
// making a connect link or an invitation, and before trying again a connection a sign-in still owes, the desktop reads
// the shared code's name; with none (or when the call answers that a name is needed) a window asks for the name the
// other person will see, keeps it, and then goes on with what the person was doing.

/** What the person was doing when the name was asked for: done once the name is kept. */
internal sealed class NamedLinkAct {
    /** "Connect" on an opened "Connect with …?". */
    class Connect(val opened: OpenedInvite.Connect) : NamedLinkAct()

    /** Making a connect link with these shares and this lifetime; [after] sees the answer (the screen clears its ticks). */
    class CreateLink(val shares: List<ShareChoice>, val minutes: Int, val after: (LinkCreateResult) -> Unit = {}) : NamedLinkAct()

    /** Making an invitation with this lifetime. */
    class Invitation(val minutes: Int) : NamedLinkAct()

    /** Trying again the connection a sign-in still owes. */
    class Retry(val prompt: AccountPrompt.ConnectionNotMade) : NamedLinkAct()
}

/**
 * The name window's state: the act it waits to do ([waiting]; the window is on show while it is set), and what the last
 * try to keep a name said ([said]). One per window of the app ([TrustModel.linkName]); a lock puts it away.
 */
internal class LinkNameAsk(private val model: TrustModel) {
    /** The act the window waits to do; null while no name is asked for. */
    var waiting: NamedLinkAct? by mutableStateOf(null)
        private set

    /** A name refused, in the window. */
    var said: UiText? by mutableStateOf(null)
        private set

    /** Do [act]; with no name kept on this computer the window asks for it first, and nothing is sent. */
    fun go(act: NamedLinkAct) {
        said = null
        if (model.readOr(null) { model.api.links.ownName() } == null) {
            waiting = act
            return
        }
        send(act)
    }

    /**
     * The window's Continue: keep [name] ([io.silencelen.andvari.core.app.LinksApi.setOwnName]). Kept, the window goes
     * and the act is done; a name a link cannot carry is said in the window, which stays with what was typed.
     */
    fun keep(name: String) {
        val act = waiting ?: return
        said = null
        val r = model.readOr(OwnNameResult.STALE) { model.api.links.setOwnName(name) }
        when (r) {
            OwnNameResult.DONE -> {
                waiting = null
                send(act)
            }
            OwnNameResult.NOT_A_NAME -> said = UiText.forResult(r, 0)
            // The vault is not open any more (a lock): the window goes, and the lock screen says nothing of it.
            OwnNameResult.STALE -> waiting = null
        }
    }

    /** The window's way out: nothing is kept and nothing is sent; the opened link (or the owed connection) stays. */
    fun cancel() {
        waiting = null
        said = null
    }

    /**
     * The act itself. A call that answers that a name is needed (the name went meanwhile) opens the window again rather
     * than saying the sentence on the page; every other answer is said in place, as before.
     */
    private fun send(act: NamedLinkAct) {
        fun <R : IntentResult> words(needed: R): (R) -> UiText? = { r -> if (r == needed) null else UiText.forResult(r, model.api.retryAfterSeconds()) }
        when (act) {
            is NamedLinkAct.Connect -> model.runSaying({ links.connect(act.opened) }, words(ConnectResult.NAME_NEEDED)) { if (it == ConnectResult.NAME_NEEDED) waiting = act }
            is NamedLinkAct.CreateLink -> model.runSaying({ links.createConnectLink(act.shares, act.minutes) }, words(LinkCreateResult.NAME_NEEDED)) {
                if (it == LinkCreateResult.NAME_NEEDED) waiting = act
                act.after(it)
            }
            is NamedLinkAct.Invitation -> model.runSaying({ links.createInvitation(act.minutes) }, words(LinkCreateResult.NAME_NEEDED)) { if (it == LinkCreateResult.NAME_NEEDED) waiting = act }
            is NamedLinkAct.Retry -> model.runSaying({ links.retryConnection(act.prompt) }, words(ConnectResult.NAME_NEEDED)) { if (it == ConnectResult.NAME_NEEDED) waiting = act }
        }
    }
}

/**
 * The window that asks for the name this account goes by in its links, in the current app's window style: its title,
 * the shared code's sentence ([CopyKey.LINK_NAME_NEEDED]), the field, a refused name's sentence under it, then Cancel
 * first and Continue. Nothing is focused by itself; Enter in the field is Continue.
 */
@Composable
internal fun LinkNameWindow(model: TrustModel, s: AppSnapshot) {
    val ask = model.linkName
    val act = ask.waiting ?: return
    var name by remember(act) { mutableStateOf("") }
    val cancel = { ask.cancel() }
    AlertDialog(
        onDismissRequest = cancel,
        title = { Say(UiText.ph(Placeholder.LINK_NAME_TITLE), style = MaterialTheme.typography.titleMedium) },
        text = {
            Column(Modifier.widthIn(min = 320.dp, max = 560.dp)) {
                Say(CopyKey.LINK_NAME_NEEDED)
                Gap(10)
                Field(UiText.ph(Placeholder.LINK_NAME_FIELD), name, onEnter = { if (!s.busy) ask.keep(name) }) { name = it }
                ask.said?.let { Say(it, color = MaterialTheme.colorScheme.error) }
            }
        },
        confirmButton = { ConfirmationButtons(UiText.of(CopyKey.CANCEL), cancel, null, s, UiText.ph(Placeholder.CONTINUE)) { ask.keep(name) } },
    )
}
