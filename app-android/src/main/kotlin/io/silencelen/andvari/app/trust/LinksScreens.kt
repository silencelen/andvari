package io.silencelen.andvari.app.trust

import android.content.Context
import android.content.Intent
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.TextButton
import androidx.compose.runtime.collectAsState
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.selection.selectable
import androidx.compose.material3.RadioButton
import androidx.compose.ui.semantics.Role
import androidx.compose.material3.Checkbox
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.FilterQuality
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import io.silencelen.andvari.app.AuthColumn
import io.silencelen.andvari.app.ExternalExcursion
import io.silencelen.andvari.app.copyToClipboard
import io.silencelen.andvari.core.app.AccountSnapshot
import io.silencelen.andvari.core.app.AppSnapshot
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.LinkLifetimes
import io.silencelen.andvari.core.app.OpenedInvite
import io.silencelen.andvari.core.app.OwnLinkKind
import io.silencelen.andvari.core.app.OwnLinkRow
import io.silencelen.andvari.core.app.PayloadSource
import io.silencelen.andvari.core.app.ShareChoice
import io.silencelen.andvari.core.app.UncomparedShareWarning
import io.silencelen.andvari.core.trust.MemberRole
import kotlinx.coroutines.delay

/** The lifetimes offered for a connect link: in person, a day, the longest the design allows. */
internal val connectLifetimes: List<Int> = listOf(LinkLifetimes.IN_PERSON_MINUTES, 24 * 60, LinkLifetimes.CONNECT_LONGEST_MINUTES)

/** A link's lifetime in words: minutes under an hour, hours under a day, days from there; never a bare count of minutes. */
internal fun lifetimeWords(minutes: Int): UiText = when {
    minutes == LinkLifetimes.IN_PERSON_MINUTES -> UiText.ph(Placeholder.LINK_LIFETIME_IN_PERSON, minutes.toString())
    minutes < 60 -> UiText.ph(Placeholder.LINK_LIFETIME_MINUTES, minutes.toString())
    minutes % (24 * 60) == 0 && minutes / (24 * 60) == 1 -> UiText.ph(Placeholder.LINK_LIFETIME_A_DAY)
    minutes % (24 * 60) == 0 -> UiText.ph(Placeholder.LINK_LIFETIME_DAYS, (minutes / (24 * 60)).toString())
    else -> UiText.ph(Placeholder.LINK_LIFETIME_HOURS, (minutes / 60).toString())
}

/**
 * Links (map §3.11, slice 14): make a connect link with a lifetime and the vaults to share with a role, or an
 * invitation where the server allows them ("Send an invitation instead"); each open link as a QR with share, Copy, the
 * time left and revoke; answered links; shares waiting for a comparison, whose release raises the uncompared warning.
 * A link someone sent is scanned or pasted here; once opened it is a screen of its own ([OpenedLinkPage]).
 */
@Composable
internal fun LinksSection(model: TrustModel, s: AppSnapshot, account: AccountSnapshot) {
    SectionDivider()
    account.shareWarning?.let { UncomparedWarningView(model, s, it) }
    val screen = account.links
    if (screen == null) {
        Quieter(UiText.ph(Placeholder.LINKS), enabled = !s.busy) { model.run({ links.openLinks() }) }
        return
    }
    Say(UiText.ph(Placeholder.LINKS), style = sectionTitleStyle())
    // Open a link someone sent: scanned or pasted, both go to openInvite, and the opened link is shown before anything.
    var pasted by remember { mutableStateOf("") }
    ScanQrControl(enabled = !s.busy) { model.run({ links.openInvite(it, PayloadSource.SCANNED) }) }
    Field(UiText.ph(Placeholder.LINK_FIELD), pasted) { pasted = it }
    Second(UiText.ph(Placeholder.CONTINUE), enabled = pasted.isNotBlank() && !s.busy) {
        val p = pasted.trim()
        model.run({ links.openInvite(p, PayloadSource.PASTED) }) { if (it.done) pasted = "" }
    }
    HorizontalDivider()
    var minutes by remember { mutableStateOf(LinkLifetimes.IN_PERSON_MINUTES) }
    var shares by remember { mutableStateOf(mapOf<String, MemberRole>()) }
    Say(Placeholder.LINK_LIFETIME)
    // One of three, in words, as choices (they were tick boxes reading "minutes: 1440").
    for (m in connectLifetimes) {
        Row(
            Modifier.fillMaxWidth().selectable(selected = minutes == m, enabled = !s.busy, role = Role.RadioButton) { minutes = m },
            verticalAlignment = Alignment.CenterVertically,
        ) {
            RadioButton(selected = minutes == m, onClick = null, enabled = !s.busy)
            Say(lifetimeWords(m), Modifier.padding(start = 8.dp))
        }
    }
    for (v in account.vaults) {
        val role = shares[v.vaultId]
        Row(verticalAlignment = Alignment.CenterVertically) {
            Checkbox(checked = role != null, onCheckedChange = { on -> shares = if (on) shares + (v.vaultId to MemberRole.READER) else shares - v.vaultId })
            Text((v.name ?: "—") + (role?.let { "  ·  " + roleWord(it) } ?: ""))
        }
        if (role != null) {
            Quieter(UiText.ph(Placeholder.LINK_ROLE_SWITCH)) {
                shares = shares + (v.vaultId to if (role == MemberRole.READER) MemberRole.WRITER else MemberRole.READER)
            }
        }
    }
    Second(UiText.ph(Placeholder.LINK_CREATE), enabled = !s.busy) {
        val choices = shares.map { (id, r) -> ShareChoice(id, r) }
        val mins = minutes
        // A link carries the account's name: asked first when this phone keeps none (§6.7, [LinkNameDialog]).
        model.linkAct(TrustModel.LinkAct.MakeConnectLink(choices, mins)) { if (it.done) shares = emptyMap() }
    }
    if (screen.invitationsAllowed) {
        Quieter(UiText.of(CopyKey.SEND_INVITATION_INSTEAD), enabled = !s.busy) { model.linkAct(TrustModel.LinkAct.MakeInvitation(LinkLifetimes.IN_PERSON_MINUTES)) }
    }
    for (link in screen.links) OwnLinkView(model, s, link)
    for (a in screen.answered) {
        Say(UiText.ph(if (a.keyChanged) Placeholder.LINK_ANSWERED_KEY_CHANGED else Placeholder.LINK_ANSWERED, a.contact.label))
    }
    for (w in screen.waitingShares) {
        Say(w.line)
        Quieter(UiText.ph(Placeholder.LINK_RELEASE_SHARE), enabled = !s.busy) { model.run({ links.releaseShare(w) }) }
    }
    Quieter(UiText.ph(Placeholder.CLOSE), enabled = !s.busy) { model.act { links.closeLinks() } }
}

/**
 * The question for the name this account goes by in its links ([TrustModel.nameAsk]), over whatever screen the
 * person was on: the shared code's sentence ([CopyKey.LINK_NAME_NEEDED]), an empty field (the app never fills one in),
 * the refusal of a name that cannot go in a link under it with what was typed kept, then Continue, which keeps the
 * name and goes on with what the person was doing, and the way out, which does nothing.
 */
@Composable
internal fun LinkNameDialog(model: TrustModel, s: AppSnapshot) {
    val ask by model.nameAsk.collectAsState()
    val open = ask ?: return
    // Empty at first; after a refusal, what the person typed (the app never fills a name in).
    var name by remember { mutableStateOf(open.typed) }
    AlertDialog(
        onDismissRequest = { model.dropNameAsk() },
        text = {
            // It scrolls: at the largest font the sentence and the field do not fit a phone's height.
            Column(Modifier.verticalScroll(rememberScrollState())) {
                Say(CopyKey.LINK_NAME_NEEDED)
                Field(UiText.ph(Placeholder.LINK_NAME_FIELD), name) { name = it }
                open.refused?.let { Say(it, color = MaterialTheme.colorScheme.error) }
            }
        },
        confirmButton = { TextButton(onClick = { model.giveOwnName(name) }, enabled = name.isNotEmpty() && !s.busy) { Say(Placeholder.CONTINUE) } },
        dismissButton = { TextButton(onClick = { model.dropNameAsk() }) { Say(CopyKey.CANCEL) } },
    )
}

/** A link's kind and how many vaults it shares, with a line of its own for one. */
internal fun linkKindLine(link: OwnLinkRow): UiText =
    if (link.kind == OwnLinkKind.CONNECT) counted(link.shares.size.toLong(), Placeholder.LINK_KIND_CONNECT, Placeholder.LINK_KIND_CONNECT_ONE)
    else counted(link.shares.size.toLong(), Placeholder.LINK_KIND_INVITATION, Placeholder.LINK_KIND_INVITATION_ONE)

/** One open link: its QR (byte mode, level M), the system share sheet, Copy (cleared after the policy's window), time left, revoke. */
@Composable
private fun OwnLinkView(model: TrustModel, s: AppSnapshot, link: OwnLinkRow) {
    val context = LocalContext.current
    val url = remember(link.linkId) { model.api.links.linkToShare(link) }
    Say(linkKindLine(link))
    if (url != null) {
        val qr = remember(url) { qrBitmap(url, 600) }
        Image(qr.asImageBitmap(), contentDescription = null, filterQuality = FilterQuality.None, modifier = Modifier.size(200.dp))
        ButtonRow {
            Quieter(UiText.ph(Placeholder.LINK_SHARE)) { shareLink(context, url) }
            Quieter(UiText.ph(Placeholder.LINK_COPY)) { copyToClipboard(context, "andvari link", url, (model.clipboardClearMs() / 1000).toInt()) }
        }
    }
    var left by remember(link.linkId) { mutableLongStateOf(model.api.links.linkTimeLeftMs(link)) }
    LaunchedEffect(link.linkId) {
        while (true) {
            left = model.api.links.linkTimeLeftMs(link)
            delay(1_000)
        }
    }
    // In minutes and seconds, as the line says (it read "3600").
    // A link's own line: the device link's approved "{0} seconds left" would read "60:00 seconds left" here.
    Quiet(UiText.ph(Placeholder.LINK_TIME_LEFT, countdownText(left)))
    Quieter(UiText.ph(Placeholder.LINK_REVOKE), enabled = !s.busy) { model.run({ links.revokeLink(link) }) }
}

/** The system share sheet is another app's screen: the excursion is armed so leaving for it does not lock. */
private fun shareLink(context: Context, url: String) {
    val send = Intent(Intent.ACTION_SEND).apply {
        type = "text/plain"
        putExtra(Intent.EXTRA_TEXT, url)
    }
    ExternalExcursion.begin()
    context.startActivity(Intent.createChooser(send, null))
}

/** §6.7 step 8: one confirmation releases one vault to one person who has not compared codes. */
@Composable
private fun UncomparedWarningView(model: TrustModel, s: AppSnapshot, w: UncomparedShareWarning) {
    Say(CopyKey.UNCOMPARED_WARNING, color = MaterialTheme.colorScheme.error)
    Text(w.vaultName + "  ·  " + w.label + "  ·  " + roleWord(w.role))
    Quieter(UiText.of(CopyKey.CANCEL), enabled = !s.busy) { model.act { vaults.cancelUncomparedShare(w) } }
    Second(UiText.ph(Placeholder.LINK_RELEASE_SHARE), enabled = !s.busy) { model.run({ vaults.confirmUncomparedShare(w) }) }
    HorizontalDivider()
}

/**
 * A link opened while signed in is answered first (§12.1: a tapped link "opens the app on its join screen"): it is a
 * screen of its own ([AccountShell]), the question at the top, its actions after it, and the way out last. Back is the
 * way out too. A person who tapped a link did so on purpose and is waiting for exactly this.
 */
@Composable
internal fun OpenedLinkPage(model: TrustModel, s: AppSnapshot, opened: OpenedInvite) {
    ActiveBackHandler(model, enabled = !s.busy) { model.act { links.dismissOpened() } }
    AuthColumn {
        OpenedInviteView(model, s, opened)
    }
}

/** A link opened while signed in: connect, a key change, another instance, its Trust Gate, a server change, connected. */
@Composable
internal fun OpenedInviteView(model: TrustModel, s: AppSnapshot, opened: OpenedInvite) {
    OpenedInviteBody(model, s, opened)
    // The way out comes last; nothing is focused. After "connected" there is nothing to cancel, only to close.
    val out = if (opened is OpenedInvite.Connected) UiText.ph(Placeholder.DONE) else UiText.of(CopyKey.CANCEL)
    Quieter(out, enabled = !s.busy) { model.act { links.dismissOpened() } }
}

@Composable
private fun OpenedInviteBody(model: TrustModel, s: AppSnapshot, opened: OpenedInvite) {
    when (opened) {
        is OpenedInvite.Connect -> {
            Say(opened.question)
            InstanceName(opened.instance, MaterialTheme.typography.bodyMedium)
            Main(UiText.of(CopyKey.CONNECT), enabled = !s.busy, busy = s.busy) { model.linkAct(TrustModel.LinkAct.Connect(opened)) }
        }
        is OpenedInvite.KeyChanged -> {
            Say(opened.line)
            Second(UiText.ph(Placeholder.CONTINUE), enabled = !s.busy) { model.act { links.acknowledgeKeyChange(opened) } }
        }
        is OpenedInvite.OtherInstance -> {
            // Both servers as the shared code names them: the invite's (name and address, as pinned) in the question,
            // the one this phone is signed in to in the line about signing out, which is read before the switch.
            Say(opened.line)
            InstanceName(opened.inviteInstance, MaterialTheme.typography.bodyMedium)
            Gap(8)
            // The line names what the shared code knows of "New devices must be linked" for this account (on, off or
            // not known). The switch signs out of this server, so the lines about changes not sent stand under it, and
            // over such changes the switch asks a second time ([SignOutAsk]).
            Quiet(UiText.of(opened.signOutLine))
            val drawn = LocalDrawnAsk.current
            val ask = drawn ?: remember(model, opened) { model.switchAsk(opened).also { it.open() } }
            LaunchedEffect(s) { ask.refresh() }
            UnsentLines(ask, s)
            Second(UiText.of(opened.switchLabel), enabled = !s.busy && !ask.sending) { ask.confirm() }
            SecondSignOutConfirm(ask, UiText.of(CopyKey.CANCEL)) { ask.back() }
        }
        is OpenedInvite.TrustGate -> {
            TrustGateBody(opened.gate)
            Main(trustGateConfirmLabel(opened.gate), enabled = !s.busy, busy = s.busy) { model.run({ links.confirmOpenedGate(opened) }) }
        }
        is OpenedInvite.ServerChanged -> InstanceCard(model, s, opened.instance)
        is OpenedInvite.Connected -> Say(UiText.ph(Placeholder.LINK_CONNECTED, opened.contact.label))
    }
}
