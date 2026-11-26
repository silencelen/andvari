package io.silencelen.andvari.desktop.trust

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
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
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import io.silencelen.andvari.core.app.AccountSnapshot
import io.silencelen.andvari.core.app.AppSnapshot
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.InviteResult
import io.silencelen.andvari.core.app.LinkLifetimes
import io.silencelen.andvari.core.app.OpenedInvite
import io.silencelen.andvari.core.app.OwnLinkKind
import io.silencelen.andvari.core.app.OwnLinkRow
import io.silencelen.andvari.core.app.PayloadSource
import io.silencelen.andvari.core.app.RoleInVault
import io.silencelen.andvari.core.app.ShareChoice
import io.silencelen.andvari.core.app.UncomparedShareWarning
import io.silencelen.andvari.core.trust.MemberRole
import io.silencelen.andvari.desktop.CLIPBOARD_COPY_FAILED
import io.silencelen.andvari.desktop.copyWithAutoClear
import kotlinx.coroutines.delay

// Links (§6.7 to §6.11), ported from the Android app. The desktop has no share sheet and no camera: a link is shown
// as a QR code (for a phone to scan) and as its text with Copy, and a link someone sent is pasted.

/** The lifetimes offered for a connect link: in person, a day, the longest the design allows. */
internal val connectLifetimes: List<Int> = listOf(LinkLifetimes.IN_PERSON_MINUTES, 24 * 60, LinkLifetimes.CONNECT_LONGEST_MINUTES)

/**
 * Links: open a link someone sent (pasted; its own field, which takes invites only: a device link or a kit pasted here
 * is refused by the API and forwarded nowhere, §17); make a connect link with a lifetime and the vaults to share with a
 * role, or an invitation where the server allows them; each open link with its QR, its text, Copy, the time left and
 * revoke; answered links; shares waiting for a comparison, whose release raises the uncompared warning.
 */
/**
 * What opening a pasted link answered, said in place. The already-signed-in refusal says nothing here: its sentence is
 * core's [AccountSnapshot.inviteNotUsed], shown in place of the invite.
 */
internal fun openInviteLine(r: InviteResult, retryAfterSeconds: Int = 0): UiText? =
    if (r == InviteResult.NOT_USABLE_SIGNED_IN) null else UiText.forResult(r, retryAfterSeconds)

@Composable
internal fun LinksSection(model: TrustModel, s: AppSnapshot, account: AccountSnapshot) {
    val answers = @Composable {
        account.opened?.let { OpenedInviteView(model, s, it) }
        // A link to create an account on the server this computer is signed in to: the owner's approved sentence (entry
        // 7), filled by core with that server's pinned name and address, in place of the invite; put away by dismissOpened.
        account.inviteNotUsed?.let { line ->
            Say(line)
            Quieter(UiText.ph(Placeholder.INVITE_NOT_USED_DISMISS), enabled = !s.busy) { model.act { links.dismissOpened() } }
        }
        account.shareWarning?.let { UncomparedWarningView(model, s, it) }
    }
    val screen = account.links
    if (screen == null) {
        answers()
        return ClosedSection(Placeholder.LINKS, enabled = !s.busy) { model.run({ links.openLinks() }) }
    }
    // The card's title first, then what a pasted link opened, under it (it stood above the title, found in the run).
    SectionTitle(Placeholder.LINKS)
    answers()
    var pasted by remember { mutableStateOf("") }
    val open = { if (pasted.isNotBlank() && !s.busy) pasted.trim().let { p -> model.runSaying({ links.openInvite(p, PayloadSource.PASTED) }, { openInviteLine(it, model.api.retryAfterSeconds()) }) { if (it.done) pasted = "" } } }
    Field(UiText.ph(Placeholder.LINK_FIELD), pasted, mono = true, onEnter = { open() }) { pasted = it }
    Second(UiText.of(CopyKey.FIRST_PASTE_LINK), enabled = pasted.isNotBlank() && !s.busy) { open() }
    HorizontalDivider()
    var minutes by remember { mutableStateOf(LinkLifetimes.IN_PERSON_MINUTES) }
    var shares by remember { mutableStateOf(mapOf<String, MemberRole>()) }
    Say(Placeholder.LINK_LIFETIME)
    for (m in connectLifetimes) {
        Choice(UiText.ph(Placeholder.LINK_MINUTES, m.toString()), UiText.Plain(""), selected = minutes == m, enabled = !s.busy) { minutes = m }
    }
    // Only a vault this account owns can be shared; one it reads or writes in is not offered (found in the run).
    for (v in shareableVaults(account)) {
        val role = shares[v.vaultId]
        Tick(UiText.Plain(vaultSlot(v.name).text +(role?.let { "  ·  " + it.literal } ?: "")), role != null, enabled = !s.busy) { on ->
            shares = if (on) shares + (v.vaultId to MemberRole.READER) else shares - v.vaultId
        }
        if (role != null) {
            Quieter(UiText.ph(Placeholder.LINK_ROLE_SWITCH)) {
                shares = shares + (v.vaultId to if (role == MemberRole.READER) MemberRole.WRITER else MemberRole.READER)
            }
        }
    }
    // Each link road goes through the name this account's links carry: with none kept here, its window asks first.
    Second(UiText.ph(Placeholder.LINK_CREATE), enabled = !s.busy) {
        val choices = shares.map { (id, r) -> ShareChoice(id, r) }
        val mins = minutes
        model.linkName.go(NamedLinkAct.CreateLink(choices, mins) { if (it.done) shares = emptyMap() })
    }
    if (screen.invitationsAllowed) {
        Quieter(UiText.of(CopyKey.SEND_INVITATION_INSTEAD), enabled = !s.busy) { model.linkName.go(NamedLinkAct.Invitation(LinkLifetimes.IN_PERSON_MINUTES)) }
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

/** The vaults a connect link may offer to share: the ones this account owns. */
internal fun shareableVaults(account: AccountSnapshot) = account.vaults.filter { it.role == RoleInVault.OWNER }

/** One open link: its QR (byte mode, level M), its text, Copy (cleared after the policy's window), time left, revoke. */
@Composable
private fun OwnLinkView(model: TrustModel, s: AppSnapshot, link: OwnLinkRow) {
    val url = remember(link.linkId) { model.api.links.linkToShare(link) }
    var copyFailed by remember(link.linkId) { mutableStateOf(false) }
    Say(UiText.ph(if (link.kind == OwnLinkKind.CONNECT) Placeholder.LINK_KIND_CONNECT else Placeholder.LINK_KIND_INVITATION, link.shares.size.toString()))
    if (url != null) {
        QrImage(url)
        Text(url, style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace))
        // A copied link is treated like a secret: it is cleared after the policy's window (as on Android).
        Quieter(UiText.ph(Placeholder.LINK_COPY)) { copyFailed = !copyWithAutoClear(url, clipboardSeconds(model)) }
        if (copyFailed) Say(UiText.Plain(CLIPBOARD_COPY_FAILED), color = MaterialTheme.colorScheme.error)
    }
    var left by remember(link.linkId) { mutableLongStateOf(model.readOr(0L) { model.api.links.linkTimeLeftMs(link) }) }
    LaunchedEffect(link.linkId) {
        while (true) {
            left = model.readOr(0L) { model.api.links.linkTimeLeftMs(link) }
            delay(1_000)
        }
    }
    // The countdown as m:ss, as the device links show it (bare seconds read "Time left: 272").
    Quiet(UiText.ph(Placeholder.DEVICE_LINK_TIME_LEFT, countdown(left)))
    Quieter(UiText.ph(Placeholder.LINK_REVOKE), enabled = !s.busy) { model.run({ links.revokeLink(link) }) }
}

/** §6.7 step 8: one confirmation releases one vault to one person who has not compared codes. Cancel comes first. */
@Composable
private fun UncomparedWarningView(model: TrustModel, s: AppSnapshot, w: UncomparedShareWarning) {
    Say(CopyKey.UNCOMPARED_WARNING, color = MaterialTheme.colorScheme.error)
    Text(w.vaultName + "  ·  " + w.label + "  ·  " + w.role.literal)
    Row {
        Quieter(UiText.of(CopyKey.CANCEL), enabled = !s.busy) { model.act { vaults.cancelUncomparedShare(w) } }
        Quieter(UiText.ph(Placeholder.LINK_RELEASE_SHARE), enabled = !s.busy) { model.run({ vaults.confirmUncomparedShare(w) }) }
    }
    HorizontalDivider()
}

/** The way out of an opened link: Cancel while something is still asked, Close once it is connected. */
internal fun openedWayOut(opened: OpenedInvite): UiText =
    if (opened is OpenedInvite.Connected) UiText.ph(Placeholder.CLOSE) else UiText.of(CopyKey.CANCEL)

/**
 * A link opened while signed in: connect, a key change, a server change, connected; an invite for another server and
 * its Trust Gate are windows of their own ([OtherInstanceWindow], [OpenedGateWindow]).
 */
@Composable
internal fun OpenedInviteView(model: TrustModel, s: AppSnapshot, opened: OpenedInvite) {
    when (opened) {
        is OpenedInvite.OtherInstance -> return OtherInstanceWindow(model, s, opened)
        is OpenedInvite.TrustGate -> return OpenedGateWindow(model, s, opened)
        else -> {}
    }
    // Cancel first, as on every gate; nothing is focused. Once connected there is nothing left to cancel: it closes.
    Quieter(openedWayOut(opened), enabled = !s.busy) { model.act { links.dismissOpened() } }
    when (opened) {
        is OpenedInvite.Connect -> {
            Say(opened.question)
            InstanceName(opened.instance, MaterialTheme.typography.bodyMedium)
            Main(UiText.of(CopyKey.CONNECT), enabled = !s.busy, busy = s.busy) { model.linkName.go(NamedLinkAct.Connect(opened)) }
        }
        is OpenedInvite.KeyChanged -> {
            Say(opened.line)
            Second(UiText.ph(Placeholder.CONTINUE), enabled = !s.busy) { model.act { links.acknowledgeKeyChange(opened) } }
        }
        is OpenedInvite.ServerChanged -> InstanceCard(model, s, opened.instance)
        is OpenedInvite.Connected -> Say(UiText.ph(Placeholder.LINK_CONNECTED, opened.contact.label))
        is OpenedInvite.OtherInstance, is OpenedInvite.TrustGate -> {}
    }
    HorizontalDivider()
}

/**
 * An invite for another server, opened while signed in (§6.7), as the current app's window for connecting to a different
 * server: the shared code's line naming both servers, the server the invite is for with its address, the line that the
 * switch signs this account out on this computer, then Cancel (the way out, first, and Escape's) and the switch. After
 * the switch the entry windows follow, on the other server (the join screen, the sign-up form or "not taking accounts").
 */
@Composable
internal fun OtherInstanceWindow(model: TrustModel, s: AppSnapshot, opened: OpenedInvite.OtherInstance) {
    val cancel = { if (!s.busy) model.act { links.dismissOpened() } }
    // The switch signs out here: the window reads the shared code's check as it opens, as Sign out does ([SignOutAsk]).
    val ask = remember(opened) { SignOutAsk(model, SignOutAct.Switch(opened)) {} }
    LaunchedEffect(s) { ask.reread() }
    // The second confirmation's way out goes back to this window; the invitation stays.
    if (ask.second) return SecondConfirmation(ask, s) { ask.back() }
    AlertDialog(
        onDismissRequest = cancel,
        title = { Say(UiText.ph(Placeholder.OTHER_INSTANCE_TITLE), style = MaterialTheme.typography.titleMedium) },
        text = {
            Column(Modifier.widthIn(min = 320.dp, max = 560.dp).verticalScroll(rememberScrollState())) {
                Say(opened.line)
                Gap(10)
                // The server the switch goes to, as the current app's gate shows the address it will dial.
                InstanceName(opened.inviteInstance)
                Gap(10)
                Say(opened.signOutLine, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                // How many changes made here the switch would lose, or what the last try to send them said.
                UnsentLines(ask)
                // A restore of a backup not finished on this computer: its record goes with the sign-out.
                UnfinishedRestoreLine(model)
                // A switch the other server did not answer signs nothing out; its sentence is said here, over the page.
                SaidHere(model, s)
            }
        },
        // Cancel first, then "try sending them first" where it is offered, then the switch.
        confirmButton = { ConfirmationButtons(UiText.of(CopyKey.CANCEL), cancel, ask, s, UiText.of(opened.switchLabel)) { ask.proceed() } },
    )
}

/**
 * The Trust Gate for an invite's server this computer never used (an enrol link, opened while signed in elsewhere), as
 * the current app's gate window: the gate's title, the address it will dial, its sentences and the operator key, then
 * Cancel first and Connect. Connecting pins that server and goes on to [OtherInstanceWindow].
 */
@Composable
internal fun OpenedGateWindow(model: TrustModel, s: AppSnapshot, opened: OpenedInvite.TrustGate) {
    val cancel = { if (!s.busy) model.act { links.dismissOpened() } }
    AlertDialog(
        onDismissRequest = cancel,
        title = { Say(trustGateTitle(opened.gate), style = MaterialTheme.typography.titleMedium) },
        text = {
            Column(Modifier.widthIn(min = 320.dp, max = 560.dp).verticalScroll(rememberScrollState())) {
                TrustGateBody(opened.gate, titled = false)
                SaidHere(model, s)
            }
        },
        dismissButton = { DialogButton(UiText.of(CopyKey.CANCEL), enabled = !s.busy, onClick = cancel) },
        confirmButton = { DialogButton(trustGateConfirmLabel(opened.gate), enabled = !s.busy) { model.run({ links.confirmOpenedGate(opened) }) } },
    )
}
