package io.silencelen.andvari.desktop.trust

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.TextButton
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import io.silencelen.andvari.core.app.AppSnapshot
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.FirstRunNotice
import io.silencelen.andvari.core.app.InstanceCardState
import io.silencelen.andvari.core.app.InstanceSnapshot
import io.silencelen.andvari.core.app.UnfinishedMove
import io.silencelen.andvari.core.app.JoinMode
import io.silencelen.andvari.core.app.PayloadSource
import io.silencelen.andvari.core.app.TrustGatePrompt
import io.silencelen.andvari.core.client.pin.TrustGateWording

/** One composable per signed-out screen ([EntryScreen]); a `when` with no `else`, so a new screen fails to compile. */
@Composable
internal fun EntryScreens(model: TrustModel, s: AppSnapshot, screen: EntryScreen) {
    when (screen) {
        is EntryScreen.FirstRun -> FirstRunScreen(model, s, screen)
        is EntryScreen.InviteEntry -> InviteEntryScreen(model, s, screen)
        is EntryScreen.OwnServer -> OwnServerScreen(model, s, screen)
        is EntryScreen.TrustGate -> TrustGateScreen(model, s, screen)
        is EntryScreen.ServerChanged -> ServerChangedScreen(model, s, screen)
        is EntryScreen.AddressMismatch -> AddressMismatchScreen(model, s, screen)
        is EntryScreen.Server -> ServerScreen(model, s, screen)
        is EntryScreen.SignInChoice -> SignInChoiceScreen(model, s, screen)
        is EntryScreen.Forgot -> ForgotScreen(model, s, screen)
        is EntryScreen.JoinInvite -> JoinInviteScreen(model, s, screen)
        is EntryScreen.NotTakingAccounts -> NotTakingAccountsScreen(model, s, screen)
        is EntryScreen.SignUpEmail -> SignUpEmailScreen(model, s, screen)
        is EntryScreen.SignUpCode -> SignUpCodeScreen(model, s, screen)
        is EntryScreen.CreateAccount -> CreateAccountScreen(model, s, screen)
        is EntryScreen.RecoveryWarning -> RecoveryWarningScreen(model, s, screen)
        is EntryScreen.Kit -> KitScreenView(model, s, screen.kit)
        is EntryScreen.SignInServer -> SignInServerScreen(model, s, screen)
        is EntryScreen.SignIn -> SignInScreen(model, s, screen)
        is EntryScreen.LinkRequired -> LinkRequiredScreen(model, s, screen)
        is EntryScreen.LinkDeviceEntry -> LinkDeviceEntryScreen(model, s, screen)
        is EntryScreen.LinkDeviceWaiting -> LinkDeviceWaitingScreen(model, s, screen)
        is EntryScreen.LinkDeviceCode -> LinkDeviceCodeScreen(model, s, screen)
        is EntryScreen.LinkDevicePassword -> LinkDevicePasswordScreen(model, s, screen)
        is EntryScreen.LinkDeviceEnded -> LinkDeviceEndedScreen(model, s, screen)
        is EntryScreen.KitEntry -> KitEntryScreen(model, s, screen)
        is EntryScreen.KitRecover -> KitRecoverScreen(model, s, screen)
        is EntryScreen.ReplacePassword -> ReplacePasswordScreen(model, s, screen)
        is EntryScreen.AskOperator -> AskOperatorScreen(model, s, screen)
        is EntryScreen.OperatorHelp -> OperatorHelpScreen(model, s, screen)
        is EntryScreen.CheckAccount -> CheckAccountScreen(model, s, screen)
        // A server set up from this computer through its setup link (§6.7).
        is EntryScreen.ServerSetup -> ServerSetupScreen(model, s, screen)
    }
}

/** A screen whose slice has not landed yet: says so visibly, and offers the way back. */
@Composable
internal fun NotBuilt(model: TrustModel, s: AppSnapshot, what: UiText) {
    AuthColumn {
        Sigil()
        Gap()
        Say(Placeholder.NOT_BUILT_YET, what.shown())
        SaidHere(model, s)
        Gap()
        Quieter(UiText.ph(Placeholder.BACK), enabled = !s.busy) { model.act { entry.back() } }
        Quieter(UiText.ph(Placeholder.START_OVER), enabled = !s.busy) { model.act { entry.startOver() } }
    }
}

// ---- §12.1: the first screen ----

/**
 * §12.1: three buttons of equal size and style, none preselected or focused, then "Already have an account? Sign in"
 * as text. On desktop the first is "Paste an invite link". The public-instance button is shown only when this build
 * bakes one ([EntryScreen.FirstRun.offersPublicInstance]).
 */
@Composable
internal fun FirstRunScreen(model: TrustModel, s: AppSnapshot, screen: EntryScreen.FirstRun) {
    AuthColumn(verticalArrangement = Arrangement.Center, horizontalAlignment = Alignment.CenterHorizontally) {
        Sigil()
        Gap(24)
        // The account was deleted from this computer: core's own notice, said once, here, until dismissed.
        screen.accountDeleted?.let { deleted ->
            Say(UiText.of(deleted.line))
            Quieter(UiText.ph(Placeholder.DISMISS)) { model.act { entry.dismissNotice(screen) } }
            Gap()
        }
        // A deletion whose outcome is unknown, after the server signed this computer out: core's notice,
        // which took the place of the desktop's own flag.
        screen.deletionOutcomeUnknown?.let { unknown ->
            Say(UiText.of(unknown.line))
            Quieter(UiText.ph(Placeholder.DISMISS)) { model.act { entry.dismissNotice(screen) } }
            Gap()
        }
        // The shared code's offer to forget that account on this computer, in two steps (wherever it offers it).
        ForgetUnknownDeletionOffer(model, s)
        // This computer could not confirm its session with its server in time: that end, said once, never the server's.
        if (screen.sessionNotConfirmed) {
            Say(UiText.of(CopyKey.SESSION_NOT_CONFIRMED))
            Quieter(UiText.ph(Placeholder.DISMISS)) { model.act { entry.dismissNotice(screen) } }
            Gap()
        }
        // A recovery the person left whose outcome arrived later: what it came to, here, until dismissed.
        screen.lateRecovery?.let { late ->
            Say(UiText.of(late.line))
            Quieter(UiText.ph(Placeholder.DISMISS)) { model.act { entry.dismissNotice(screen) } }
            Gap()
        }
        // This computer holds its server's operator account (stopped and locked here): said as long as it stands, and its
        // only way out is its removal from this computer, behind a confirmation that says what is lost. Never a sign-out.
        screen.heldAsOperator?.let { held ->
            Say(UiText.of(held.line))
            HeldOperatorRemoval(model, s, held)
            Gap()
        }
        screen.notice?.let { notice ->
            Say(firstRunNotice(notice))
            Quieter(UiText.ph(Placeholder.DISMISS)) { model.act { entry.dismissNotice(screen) } }
            Gap()
        }
        for (choice in firstRunChoices(screen)) {
            EqualChoice(choice.label, enabled = choice.enabled && !s.busy) { choice.go(model, screen) }
            choice.line?.let { Quiet(it) }
        }
        Gap()
        Quieter(UiText.of(CopyKey.FIRST_SIGN_IN), enabled = !s.busy) { model.act { entry.openSignIn(screen) } }
        if (screen.operatorHelpWaiting) {
            Quieter(UiText.ph(Placeholder.RESUME_OPERATOR_HELP), enabled = !s.busy) { model.run({ entry.resumeOperatorHelp(screen) }) }
        }
        SaidHere(model, s)
    }
}

internal fun firstRunNotice(notice: FirstRunNotice): UiText = when (notice) {
    FirstRunNotice.RECOVERY_STOPPED -> UiText.approved("RECOVERY_CHECK_STOPPED.body")
    FirstRunNotice.SIGNED_OUT_BY_SERVER -> UiText.ph(Placeholder.NOTICE_SIGNED_OUT_BY_SERVER)
    FirstRunNotice.OPERATOR_NEEDS_COMPUTER -> UiText.ph(Placeholder.NOTICE_OPERATOR_NEEDS_COMPUTER)
}

/** One of the first screen's three buttons, as data: so a test can check them without a Compose runtime. */
internal class FirstRunChoice(
    val label: UiText,
    val enabled: Boolean,
    /** The line under the button, if any. */
    val line: UiText?,
    val go: (TrustModel, EntryScreen.FirstRun) -> Unit,
)

/** The first screen's buttons, in order (§12.1). Every one is the same composable ([EqualChoice]): same size, same style. */
internal fun firstRunChoices(screen: EntryScreen.FirstRun): List<FirstRunChoice> {
    val out = ArrayList<FirstRunChoice>(3)
    out += FirstRunChoice(UiText.of(CopyKey.FIRST_PASTE_INVITE_LINK), true, null) { m, sc -> m.act { entry.openInviteEntry(sc) } }
    if (screen.offersPublicInstance) {
        val signup = screen.signup
        // JoinMode.NOT_KNOWN is never shown as closed (IF-3 author note 9): the button stays and the intent asks.
        // Approved entries 1 and 2: when more than one state applies, closed, then full, then invitation-only. The line
        // under the button replaces FIRST_CREATE_ACCOUNT_LINE for those two.
        val line = UiText.of(CopyKey.FIRST_CREATE_ACCOUNT_LINE)
        val (label, enabled, under) = when {
            signup.mode == JoinMode.CLOSED ->
                Triple(UiText.approved("FIRST_SIGNUP_CLOSED.button0"), false, UiText.approved("FIRST_SIGNUP_CLOSED.body"))
            signup.full -> Triple(UiText.of(CopyKey.FIRST_SIGNUP_FULL), false, line)
            signup.mode == JoinMode.INVITATION_ONLY -> Triple(
                UiText.approved("FIRST_SIGNUP_INVITATION_ONLY.button0"), false,
                UiText.approved("FIRST_SIGNUP_INVITATION_ONLY.body", UiText.of(CopyKey.FIRST_PASTE_INVITE_LINK).shown()),
            )
            else -> Triple(UiText.of(CopyKey.FIRST_CREATE_ACCOUNT), true, line)
        }
        out += FirstRunChoice(label, enabled, under) { m, sc -> m.run({ entry.createAccountOnAndvari(sc) }) }
    }
    out += FirstRunChoice(UiText.of(CopyKey.FIRST_OWN_SERVER), true, null) { m, sc -> m.act { entry.openOwnServer(sc) } }
    return out
}

/** The one button style of the first screen: none is filled, so none reads as the default. */
@Composable
private fun EqualChoice(label: UiText, enabled: Boolean, onClick: () -> Unit) {
    val (source, mark) = focusMark(label.shown())
    OutlinedButton(onClick = onClick, enabled = enabled, modifier = Modifier.fillMaxWidth().heightIn(min = 52.dp).padding(vertical = 4.dp).then(mark), interactionSource = source) { Say(label) }
}

// ---- "Paste an invite link" ----

/**
 * "Paste an invite link" (§12.1; the desktop has no camera and no link handler). It takes invites, and on desktop a
 * server's setup link ([EntryScreen.InviteEntry.takesSetupLinks]); a device link or a kit pasted here is refused with
 * the API's sentence, and nothing is forwarded to another entry (§17 flow conformance).
 */
@Composable
internal fun InviteEntryScreen(model: TrustModel, s: AppSnapshot, screen: EntryScreen.InviteEntry) {
    var link by remember { mutableStateOf("") }
    val submit = { if (link.isNotBlank() && !s.busy) model.run({ entry.submitInvite(screen, link.trim(), PayloadSource.PASTED) }) }
    AuthColumn {
        WindowHead(UiText.of(CopyKey.FIRST_PASTE_INVITE_LINK))
        Field(UiText.ph(Placeholder.LINK_FIELD), link, mono = true, onEnter = { submit() }) { link = it }
        Main(UiText.of(CopyKey.FIRST_PASTE_LINK), enabled = link.isNotBlank() && !s.busy, busy = s.busy) { submit() }
        SaidHere(model, s)
        BackRow(model, s)
    }
}

// ---- "Use your own server" and the Trust Gate ----

@Composable
internal fun OwnServerScreen(model: TrustModel, s: AppSnapshot, screen: EntryScreen.OwnServer) {
    var address by remember { mutableStateOf("") }
    val submit = { if (address.isNotBlank() && !s.busy) model.run({ entry.submitServerAddress(screen, address.trim()) }) }
    AuthColumn {
        // The desktop also takes the server's setup link here (§12.1, §9.5), said under the title; a phone never does.
        WindowHead(UiText.of(CopyKey.FIRST_OWN_SERVER), line = if (screen.takesSetupLinks) UiText.ph(Placeholder.OWN_SERVER_TAKES_SETUP_LINK) else null)
        Field(UiText.ph(Placeholder.SERVER_ADDRESS_FIELD), address, mono = true, onEnter = { submit() }) { address = it }
        Main(UiText.ph(Placeholder.SUBMIT_ADDRESS), enabled = address.isNotBlank() && !s.busy, busy = s.busy) { submit() }
        SaidHere(model, s)
        BackRow(model, s)
    }
}

/**
 * The Trust Gate (§4.4, §12.3) as a screen: the title, the exact origin (dominant, monospaced: never a display name),
 * the body's sentences, the cautions and the operator key's short form. Cancel is the safe default and comes first;
 * nothing is focused and Enter confirms nothing, so Connect is always a deliberate click.
 */
@Composable
internal fun TrustGateScreen(model: TrustModel, s: AppSnapshot, screen: EntryScreen.TrustGate) {
    AuthColumn {
        // A window that stands alone: the brand head carries the gate's title; the origin stays the dominant line.
        WindowHead(trustGateTitle(screen.prompt))
        TrustGateBody(screen.prompt, titled = false)
        SaidHere(model, s)
        Gap()
        // The current app's gate: Cancel as a text button first, then Connect, filled.
        WayOutThenMain(
            UiText.of(CopyKey.CANCEL), !s.busy, { model.act { entry.declineTrustGate(screen) } },
            trustGateConfirmLabel(screen.prompt), enabled = !s.busy, busy = s.busy,
        ) { model.run({ entry.confirmTrustGate(screen) }) }
    }
}

/** The confirm button: the design's "It's the same" in the device-link wording; no wording is given otherwise. */
internal fun trustGateConfirmLabel(prompt: TrustGatePrompt): UiText =
    prompt.confirmLabel?.let { UiText.of(it) } ?: UiText.ph(Placeholder.TRUST_GATE_CONNECT)

/** The gate's title; where the design gives none (the `kind` change), the approved one (entry 10). */
internal fun trustGateTitle(prompt: TrustGatePrompt): UiText =
    prompt.title?.let { UiText.of(it) } ?: UiText.approved("GATE_TITLE_KIND_CHANGE.title")

@Composable
internal fun TrustGateBody(prompt: TrustGatePrompt, titled: Boolean = true) {
    if (titled) Title(trustGateTitle(prompt))
    // As the current app's gate: the address it will dial, dominant, monospaced, in the brand colour.
    Text(prompt.origin, style = MaterialTheme.typography.titleMedium.copy(fontFamily = FontFamily.Monospace), color = MaterialTheme.colorScheme.primary)
    Gap(10)
    if (prompt.punycodeCaution) {
        Text(PUNYCODE_CAUTION, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
        Gap(8)
    }
    if (prompt.httpCaution) {
        val loopback = httpCautionIsLoopback(prompt.origin)
        Text(
            if (loopback) HTTP_LOOPBACK_CAUTION else HTTP_LAN_CAUTION,
            style = MaterialTheme.typography.bodySmall,
            color = if (loopback) MaterialTheme.colorScheme.onSurfaceVariant else MaterialTheme.colorScheme.error,
        )
        Gap(8)
    }
    for (line in prompt.lines) Say(line, Modifier.padding(bottom = 8.dp), MaterialTheme.typography.bodyMedium)
    if (prompt.wording != TrustGateWording.DEVICE_LINK) {
        Say(Placeholder.OPERATOR_KEY, style = MaterialTheme.typography.labelSmall)
        Text(prompt.operatorKeyShort.chunked(4).joinToString(" "), style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace))
    }
}

/**
 * The cautions are "the existing cautions" (§12.3): the old desktop gate's sentences, carried over word for word
 * (`DesktopState.kt`'s `internationalCaution`, `TRUST_GATE_HTTP_LOOPBACK`, `TRUST_GATE_HTTP_LAN`, audit H68's split).
 */
internal const val PUNYCODE_CAUTION =
    "This address uses international characters, shown above in their ASCII (punycode) form. " +
        "Lookalike letters are a common phishing trick — confirm it matches exactly what you were given."
internal const val HTTP_LOOPBACK_CAUTION =
    "This is an unencrypted http:// address on this computer. Traffic to it never leaves the machine, so it isn't exposed to the network."
internal const val HTTP_LAN_CAUTION =
    "This is an unencrypted http:// connection — traffic to this server can be read on the network. Only continue on a network you trust."

/** Whether plain-http traffic to [origin] never leaves this computer: `127.0.0.0/8`, `localhost`, `::1` (audit H68). */
internal fun httpCautionIsLoopback(origin: String): Boolean {
    val rest = origin.removePrefix("http://")
    val host = if (rest.startsWith("[")) rest.substringAfter('[').substringBefore(']') else rest.substringBefore('/').substringBefore(':')
    return host == "localhost" || host == "::1" || Regex("^127(\\.\\d{1,3}){3}$").matches(host)
}

// ---- a server this device knows, and what its card says ----

/**
 * Connected to a typed server, signed out (§12.1): create an account when its mode allows, or sign in. The design
 * gives this screen no wording; its keys are reserved, so they show as placeholders.
 */
@Composable
internal fun ServerScreen(model: TrustModel, s: AppSnapshot, screen: EntryScreen.Server) {
    AuthColumn {
        // The first window's brand head, then the server it is about, centred under it.
        BrandHead()
        InstanceName(screen.instance, centered = true)
        Gap()
        val notTaking = screen.notTaking
        if (notTaking == null) {
            Main(UiText.of(screen.createAccountLabel), enabled = !s.busy, busy = s.busy) { model.run({ entry.createAccountHere(screen) }) }
        } else {
            Say(notTaking)
            screen.notTakingWhy?.let { Say(it) }
        }
        Second(UiText.of(screen.signInLabel), enabled = !s.busy) { model.run({ entry.signInHere(screen) }) }
        SaidHere(model, s)
        BackRow(model, s)
    }
}

/**
 * A pinned server a flow cannot open as its pin stands (§2.4, §4.4): a move, a `kind` change, an older chain, a fork
 * or a damaged record. Shows the card's own state ([InstanceCard]).
 */
@Composable
internal fun ServerChangedScreen(model: TrustModel, s: AppSnapshot, screen: EntryScreen.ServerChanged) {
    AuthColumn {
        WindowHead(null, screen.instance.label)
        InstanceCard(model, s, screen.instance)
        SaidHere(model, s)
        BackRow(model, s)
    }
}

/**
 * What a server's card asks for, wherever an instance is on show (§4.4, §12.3). A fork stops traffic, not reading
 * (§4.4): the copy on this computer stays readable, and "Forget this server" is the way out, said to delete this copy.
 */
@Composable
internal fun InstanceCard(model: TrustModel, s: AppSnapshot, instance: InstanceSnapshot) {
    // Checked before the card, which reads "not verified" while a followed move is unfinished.
    instance.unfinishedMove?.let { return UnfinishedMoveCard(model, s, instance, it) }
    when (val card = instance.card) {
        is InstanceCardState.Ok -> {}
        is InstanceCardState.Stopped -> {
            Say(CopyKey.CARD_FORK, color = MaterialTheme.colorScheme.error)
            ForgetServerButton(model, s, instance)
        }
        is InstanceCardState.Damaged -> {
            CardDamagedWords(instance.label.origin)
            ForgetServerButton(model, s, instance)
        }
        is InstanceCardState.Withheld -> Say(CopyKey.CARD_WITHHELD)
        is InstanceCardState.NotVerified -> Say(UiText.approved("CARD_NOT_VERIFIED.body"))
        is InstanceCardState.Moved -> {
            Say(card.line)
            if (card.alreadyPinnedThere) {
                Say(UiText.approved("CARD_MOVE_NOT_FOLLOWED.title"), style = MaterialTheme.typography.titleSmall)
                Say(UiText.approved("CARD_MOVE_NOT_FOLLOWED.body", card.toOrigin))
                ForgetOtherServerButton(model, s, card)
                ForgetServerButton(model, s, instance)
            } else {
                Main(UiText.ph(Placeholder.FOLLOW_MOVE), enabled = !s.busy, busy = s.busy) { model.run({ this.instance.followMove(card) }) }
            }
        }
        is InstanceCardState.KindChanged -> {
            TrustGateBody(card.gate)
            // Approved entry 10: Continue accepts the change; Not now closes the gate until the next unlock. The gate's
            // buttons as the current app's: the way out first, as a text button.
            WayOutThenMain(
                UiText.approved("GATE_TITLE_KIND_CHANGE.button1"), !s.busy, { model.act { this.instance.kindChangeNotNow(card) } },
                UiText.approved("GATE_TITLE_KIND_CHANGE.button0"), enabled = !s.busy, busy = s.busy,
            ) { model.run({ this.instance.acceptKindChange(card) }) }
        }
        is InstanceCardState.UpdateAndvari -> Say(card.sentence)
    }
}

/** Approved entry 12: this device's record of the server does not decode. Its title, then its two paragraphs. */
@Composable
internal fun CardDamagedWords(origin: String) {
    Say(UiText.approved("CARD_RECORD_DAMAGED.title"), style = MaterialTheme.typography.titleSmall)
    Say(UiText.approvedLine("CARD_RECORD_DAMAGED.body", 0, origin))
    Say(UiText.approvedLine("CARD_RECORD_DAMAGED.body", 1, origin))
}

/** The line of a followed move whose data has not reached the new address: the old address, then the new one. */
internal fun unfinishedMoveLine(instance: InstanceSnapshot, move: UnfinishedMove): UiText =
    UiText.ph(Placeholder.MOVE_UNFINISHED, move.fromOrigin, instance.label.origin)

/**
 * A followed move whose data on this computer has not reached the new address yet ([UnfinishedMove]): nothing is sent
 * there and no vault opens until it is finished (the vault is locked meanwhile). The ways on are "Try again"
 * ([io.silencelen.andvari.core.app.InstanceApi.finishMove]) and "Forget this server". Its line names the address the
 * server moved from and the one it moved to.
 */
@Composable
internal fun UnfinishedMoveCard(model: TrustModel, s: AppSnapshot, instance: InstanceSnapshot, move: UnfinishedMove) {
    Say(unfinishedMoveLine(instance, move), color = MaterialTheme.colorScheme.error)
    Main(UiText.ph(Placeholder.TRY_AGAIN), enabled = !s.busy, busy = s.busy) { model.run({ this.instance.finishMove(move) }) }
    ForgetServerButton(model, s, instance)
}

/**
 * "Forget this server" (§12.3): removes the pin and this computer's data for it. The only way out of a fork. It
 * always asks first, with the same question as Settings ([ForgetServerQuestion]), on every
 * card that offers it: a click aimed at a row that a card pushed down must never delete the copy.
 */
@Composable
internal fun ForgetServerButton(model: TrustModel, s: AppSnapshot, instance: InstanceSnapshot) {
    var asking by remember { mutableStateOf(false) }
    Quiet(forgetDeletesLine(instance))
    Second(UiText.of(CopyKey.FORGET_THIS_SERVER), enabled = !s.busy) { asking = true }
    if (asking) ForgetServerQuestion(model, instance) { asking = false }
}

/**
 * What forgetting this server deletes. Under an unfinished move nothing of this computer's copy is read and no vault
 * opens, so the line that says the copy "stays readable" until then is not said there (a line of its own).
 */
internal fun forgetDeletesLine(instance: InstanceSnapshot): UiText =
    UiText.ph(if (instance.unfinishedMove != null) Placeholder.FORGET_DELETES_COPY_MOVE_UNFINISHED else Placeholder.FORGET_DELETES_COPY)

/**
 * The one question before "Forget this server": the server named whole, what forgetting deletes, Cancel first (it is
 * the dialog's dismiss; Escape and a click outside also cancel). Only its own confirm forgets.
 */
@Composable
internal fun ForgetServerQuestion(model: TrustModel, instance: InstanceSnapshot, close: () -> Unit) =
    ForgetQuestion(
        named = { InstanceName(instance.label) },
        line = forgetDeletesLine(instance),
        close = close,
        // The account signed in at this server: a restore of a backup not finished here goes with what is forgotten.
        more = { if (model.api.snapshot.instance?.label?.origin == instance.label.origin) UnfinishedRestoreLine(model) },
    ) { model.forgetServer(instance) }

/** "Remove" of an operator's account held here, behind the shared code's confirmation line ([HeldOperatorAccount.removeLine]). */
@Composable
private fun HeldOperatorRemoval(model: TrustModel, s: AppSnapshot, held: io.silencelen.andvari.core.app.HeldOperatorAccount) {
    var asking by remember { mutableStateOf(false) }
    Second(UiText.ph(Placeholder.HELD_OPERATOR_REMOVE), enabled = !s.busy) { asking = true }
    if (asking) {
        AlertDialog(
            onDismissRequest = { asking = false },
            title = { Say(Placeholder.HELD_OPERATOR_REMOVE) },
            text = { Say(UiText.of(held.removeLine)) },
            dismissButton = { DialogButton(UiText.of(CopyKey.CANCEL)) { asking = false } },
            confirmButton = { DialogButton(UiText.ph(Placeholder.HELD_OPERATOR_REMOVE)) { asking = false; model.run({ entry.removeHeldOperatorAccount(held) }) } },
        )
    }
}

/** The question's shape, for this server and for the one this computer knows at a move's new address. */
@Composable
private fun ForgetQuestion(named: @Composable () -> Unit, line: UiText = UiText.ph(Placeholder.FORGET_DELETES_COPY), close: () -> Unit, more: @Composable () -> Unit = {}, forget: () -> Unit) {
    AlertDialog(
        onDismissRequest = close,
        title = { Say(CopyKey.FORGET_THIS_SERVER) },
        text = {
            Column {
                named()
                Say(line)
                more()
            }
        },
        dismissButton = { DialogButton(UiText.of(CopyKey.CANCEL), onClick = close) },
        confirmButton = { DialogButton(UiText.of(CopyKey.FORGET_THIS_SERVER)) { close(); forget() } },
    )
}

/** "Forget the other server" under a move whose new address this computer already knows: it deletes that server's data here too, so it asks. */
@Composable
private fun ForgetOtherServerButton(model: TrustModel, s: AppSnapshot, card: InstanceCardState.Moved) {
    var asking by remember { mutableStateOf(false) }
    Second(UiText.ph(Placeholder.FORGET_OTHER_SERVER), enabled = !s.busy) { asking = true }
    if (asking) ForgetQuestion(named = { Origin(card.toOrigin) }, close = { asking = false }) { model.forgetServerAtNewAddress(card) }
}

/** §2.4 `origin_mismatch`: the address dialed served a card made for another address. Both addresses shown whole. */
@Composable
internal fun AddressMismatchScreen(model: TrustModel, s: AppSnapshot, screen: EntryScreen.AddressMismatch) {
    AuthColumn {
        if (screen.publicInstance) {
            // Approved entry 8: for the baked public instance, the existing CARD_MOVED_UPDATE (core's sentence) instead.
            WindowHead(null)
            Origin(screen.dialed)
            Origin(screen.cardNames)
        } else {
            WindowHead(UiText.approved("CARD_OTHER_ADDRESS.title"))
            Say(UiText.approved("CARD_OTHER_ADDRESS.body", screen.dialed, screen.cardNames))
        }
        screen.sentence?.let { Say(it) }
        if (screen.canRecoverThere) {
            Main(UiText.ph(Placeholder.RECOVER_THERE), enabled = !s.busy, busy = s.busy) { model.run({ entry.recoverAtNamedAddress(screen) }) }
        }
        SaidHere(model, s)
        BackRow(model, s)
    }
}

// ---- "Already have an account? Sign in" ----

@Composable
internal fun SignInChoiceScreen(model: TrustModel, s: AppSnapshot, screen: EntryScreen.SignInChoice) {
    AuthColumn {
        WindowHead(UiText.of(CopyKey.FIRST_SIGN_IN))
        Second(UiText.of(CopyKey.SIGN_IN_LINK_DEVICE), enabled = !s.busy) { model.act { entry.openLinkDevice(screen) } }
        Second(UiText.of(CopyKey.SIGN_IN_PASSWORD), enabled = !s.busy) { model.act { entry.openPasswordSignIn(screen) } }
        Second(UiText.of(CopyKey.SIGN_IN_FORGOT), enabled = !s.busy) { model.act { entry.openForgot(screen) } }
        BackRow(model, s)
    }
}

/** "Forgot your master password?": the kit, or the operator's help where a server offers it (§12.1, §9.3). */
@Composable
internal fun ForgotScreen(model: TrustModel, s: AppSnapshot, screen: EntryScreen.Forgot) {
    AuthColumn {
        WindowHead(UiText.of(CopyKey.SIGN_IN_FORGOT))
        Second(UiText.of(CopyKey.SIGN_IN_SCAN_KIT), enabled = !s.busy) { model.act { entry.openKitEntry(screen) } }
        Second(UiText.of(CopyKey.LOST_PASSWORD_AND_KIT), enabled = !s.busy) { model.act { entry.openAskOperator(screen) } }
        BackRow(model, s)
    }
}

/** Back: the way out of a signed-out screen that can be left (Escape does the same, from the root). */
@Composable
internal fun BackRow(model: TrustModel, s: AppSnapshot) {
    Gap()
    Quieter(UiText.ph(Placeholder.BACK), enabled = !s.busy) { model.act { entry.back() } }
}
