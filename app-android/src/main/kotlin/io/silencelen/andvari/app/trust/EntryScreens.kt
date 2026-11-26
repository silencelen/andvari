package io.silencelen.andvari.app.trust

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
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
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import io.silencelen.andvari.app.AuthColumn
import io.silencelen.andvari.app.Sigil
import io.silencelen.andvari.core.app.AddressMismatchFor
import io.silencelen.andvari.core.app.AppSnapshot
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.FirstRunNotice
import io.silencelen.andvari.core.app.InstanceCardState
import io.silencelen.andvari.core.app.JoinMode
import io.silencelen.andvari.core.app.PayloadSource
import io.silencelen.andvari.core.app.TrustGatePrompt
import io.silencelen.andvari.core.client.pin.TrustGateWording

/** One composable per signed-out screen ([EntryScreen]); a screen whose slice has not landed says so. */
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
        // Desktop and CLI only (§9.5): a phone never reaches a server's setup.
        is EntryScreen.ServerSetup -> NotBuilt(model, s, "ServerSetup")
    }
}

// ---- §12.1: the first screen ----

/**
 * The first screen's notice after a deletion done on this device: the shared code's line
 * ([io.silencelen.andvari.core.app.AccountDeletedNotice.line]); while its key awaits the owner it shows as a placeholder.
 */
internal fun accountDeletedLine(screen: EntryScreen.FirstRun): UiText? = screen.accountDeleted?.let { UiText.of(it.line) }

/**
 * The first screen's line after a session this phone could not confirm with its server ([EntryScreen.FirstRun.sessionNotConfirmed]).
 * [besideSignOut] ([signOutWayOutStands]): a way out that signs that kept account OUT stands on the screen, so the shared
 * code's line without "sign in again" ([EntryScreen.FirstRun.sessionNotConfirmedBesideSignOut]) in its place.
 */
internal fun sessionNotConfirmedLine(screen: EntryScreen.FirstRun, besideSignOut: Boolean = false): UiText? =
    (if (besideSignOut) screen.sessionNotConfirmedBesideSignOut else null)?.let { UiText.of(it) }
        ?: if (screen.sessionNotConfirmed) UiText.of(CopyKey.SESSION_NOT_CONFIRMED) else null

/**
 * The first screen's "can't tell yet whether the account was deleted": the shared code's notice
 * ([EntryScreen.FirstRun.deletionOutcomeUnknown]) where it gives one, dismissed with `dismissNotice`; the app's own line
 * ([TrustModel.deletionCannotTell]) only where it gives none, never both. [dismissable]: the shared code's.
 */
internal class DeletionUnknownLine(val text: UiText, val dismissable: Boolean)

internal fun deletionUnknownLine(screen: EntryScreen.FirstRun, appCannotTell: Boolean, copyKept: Boolean = true): DeletionUnknownLine? =
    screen.deletionOutcomeUnknown?.let { DeletionUnknownLine(UiText.of(it.line), dismissable = true) }
        ?: if (appCannotTell) DeletionUnknownLine(UiText.ph(appDeletionLine(copyKept)), dismissable = false) else null

/** The app's own line for a deletion nobody can tell yet: "the copy on this device is kept" only where one is ([TrustModel.deletionCopyKept]). */
internal fun appDeletionLine(copyKept: Boolean): Placeholder =
    if (copyKept) Placeholder.DELETION_CANNOT_TELL else Placeholder.DELETION_CANNOT_TELL_NO_COPY

/**
 * §12.1: three buttons of equal size and style, none preselected or focused, then "Already have an account? Sign in"
 * as text. The public-instance button is shown only when this build bakes one ([EntryScreen.FirstRun.offersPublicInstance]).
 */
@Composable
internal fun FirstRunScreen(model: TrustModel, s: AppSnapshot, screen: EntryScreen.FirstRun) {
    AuthColumn(verticalArrangement = Arrangement.Center, horizontalAlignment = Alignment.CenterHorizontally) {
        Sigil()
        Gap(24)
        screen.notice?.let { notice ->
            Say(
                when (notice) {
                    FirstRunNotice.RECOVERY_STOPPED -> UiText.Plain(Approved.RECOVERY_CHECK_STOPPED)
                    FirstRunNotice.SIGNED_OUT_BY_SERVER -> UiText.ph(Placeholder.NOTICE_SIGNED_OUT_BY_SERVER)
                    FirstRunNotice.OPERATOR_NEEDS_COMPUTER -> UiText.ph(Placeholder.NOTICE_OPERATOR_NEEDS_COMPUTER)
                },
            )
            Quieter(UiText.ph(Placeholder.DISMISS)) { model.act { entry.dismissNotice(screen) } }
            Gap()
        }
        // After "Sign in again" from a session this phone could not confirm with its server: that end, as the shared code
        // says it (the notice above is empty then), never "signed out by its server".
        sessionNotConfirmedLine(screen, signOutWayOutStands(s))?.let { line ->
            Say(line)
            Quieter(UiText.ph(Placeholder.DISMISS)) { model.act { entry.dismissNotice(screen) } }
            Gap()
        }
        // An account a hand-over made its server's operator: stopped and locked on this phone until the person removes it.
        screen.heldAsOperator?.let { held ->
            HeldOperatorCard(model, s, held)
            Gap()
        }
        // A recovery kit was wiped and the notice above names what stands in the way here: its way out, on this screen.
        s.kitWiped?.let { KitWipedWayOut(model, s, it) }
        // The saved sign-in could not be read (the Keystore key that sealed it is gone): never silent. GAP: the API has
        // no FirstRunNotice for it, so the app shows its own placeholder; the file is kept until a new session replaces it.
        val unreadable by model.savedSignInUnreadable.collectAsState()
        if (unreadable) {
            Say(UiText.ph(Placeholder.SAVED_SIGN_IN_UNREADABLE))
            Quieter(UiText.ph(Placeholder.DISMISS)) { model.dismissSavedSignInNotice() }
            Gap()
        }
        // A recovery the person left whose outcome arrived later: the shared code's line, with a dismiss (dismissNotice).
        screen.lateRecovery?.let { late ->
            Say(late.line, color = if (late.result == io.silencelen.andvari.core.app.LateRecoveryResult.RESET) androidx.compose.ui.graphics.Color.Unspecified else MaterialTheme.colorScheme.error)
            Quieter(UiText.ph(Placeholder.DISMISS), enabled = !s.busy) { model.act { entry.dismissNotice(screen) } }
            Gap()
        }
        // A deletion done here: the shared code's notice, once, with a dismiss (dismissNotice clears it with `notice`).
        accountDeletedLine(screen)?.let { line ->
            Say(line)
            Quieter(UiText.ph(Placeholder.DISMISS), enabled = !s.busy) { model.act { entry.dismissNotice(screen) } }
            Gap()
        }
        // An outcome nobody can tell yet: the shared code's notice, or the app's own line where it gives none.
        deletionUnknownLine(screen, model.deletionCannotTell(s), model.deletionCopyKept(s))?.let { line ->
            Say(line.text)
            if (line.dismissable) Quieter(UiText.ph(Placeholder.DISMISS), enabled = !s.busy) { model.act { entry.dismissNotice(screen) } }
            if (screen.deletionOutcomeUnknown != null) ForgetUnknownDeletionOffer(model, s)
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

/**
 * The account a hand-over made its server's operator, on a phone (decided on 2026-11-16, §9.1): the phone stopped using
 * it and keeps its copy locked; the shared code's line says so for as long as it stands (it has no dismiss), in a card
 * of the current app's notice style, as information rather than a warning. "Remove from this phone" asks first, with
 * the shared code's sentence of what is lost ([io.silencelen.andvari.core.app.HeldOperatorAccount.removeLine]); only the
 * confirmation removes it, and nothing is sent.
 */
@Composable
internal fun HeldOperatorCard(model: TrustModel, s: AppSnapshot, held: io.silencelen.andvari.core.app.HeldOperatorAccount) {
    var asking by remember(held) { mutableStateOf(false) }
    // "Remove this account from this phone" under a stop on another screen brought the person here: its confirmation opens.
    val asked by model.removeHeldAsked.collectAsState()
    androidx.compose.runtime.LaunchedEffect(asked) {
        if (asked) {
            asking = true
            model.removeHeldAskTaken()
        }
    }
    androidx.compose.material3.Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp)) {
            Say(held.line)
            Gap(8)
            androidx.compose.material3.TextButton(onClick = { asking = true }, enabled = !s.busy) {
                Say(UiText.ph(Placeholder.OPERATOR_HELD_REMOVE))
            }
        }
    }
    if (asking) {
        androidx.compose.material3.AlertDialog(
            onDismissRequest = { asking = false },
            text = { Say(held.removeLine) },
            confirmButton = {
                androidx.compose.material3.TextButton(onClick = { asking = false; removeHeldOperator(model, held) }) {
                    Say(UiText.ph(Placeholder.OPERATOR_HELD_REMOVE_CONFIRM))
                }
            },
            dismissButton = { androidx.compose.material3.TextButton(onClick = { asking = false }) { Say(CopyKey.CANCEL) } },
        )
    }
}

/** The confirmation's one call: this phone's copy of [held] is deleted, and nothing is sent. */
internal fun removeHeldOperator(model: TrustModel, held: io.silencelen.andvari.core.app.HeldOperatorAccount) =
    model.run({ entry.removeHeldOperatorAccount(held) })

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
    out += FirstRunChoice(UiText.of(CopyKey.FIRST_SCAN_INVITE), true, null) { m, sc -> m.act { entry.openInviteEntry(sc) } }
    if (screen.offersPublicInstance) {
        val signup = screen.signup
        // JoinMode.NOT_KNOWN is never shown as closed (IF-3 author note 9): the button stays and the intent asks.
        // When more than one state applies: closed, then full, then invitation-only (copy page, entries 1 and 2).
        val line = UiText.of(CopyKey.FIRST_CREATE_ACCOUNT_LINE)
        val (label, enabled, under) = when {
            signup.mode == JoinMode.CLOSED -> Triple(UiText.Plain(Approved.FIRST_SIGNUP_CLOSED), false, UiText.Plain(Approved.FIRST_SIGNUP_CLOSED_LINE))
            signup.full -> Triple(UiText.of(CopyKey.FIRST_SIGNUP_FULL), false, line)
            signup.mode == JoinMode.INVITATION_ONLY -> Triple(
                UiText.Plain(Approved.FIRST_SIGNUP_INVITATION_ONLY),
                false,
                UiText.approved(Approved.FIRST_SIGNUP_INVITATION_ONLY_LINE, UiText.of(CopyKey.FIRST_SCAN_INVITE).shown()),
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
    OutlinedButton(onClick = onClick, enabled = enabled, modifier = Modifier.fillMaxWidth().heightIn(min = 56.dp).padding(vertical = 4.dp)) { Say(label) }
}

// ---- "Scan an invite" ----

/**
 * "Scan an invite", with "Paste a link" (§12.1). It takes invites only: a device link or a kit handed in here is
 * refused with the API's sentence, and nothing is forwarded to another entry (§17 flow conformance). The scanner and
 * the paste field hand their text to the same intent; only the source differs.
 */
@Composable
internal fun InviteEntryScreen(model: TrustModel, s: AppSnapshot, screen: EntryScreen.InviteEntry) {
    var link by remember { mutableStateOf("") }
    val send = { text: String, source: PayloadSource -> model.run({ entry.submitInvite(screen, text, source) }) }
    AuthColumn {
        Title(UiText.of(CopyKey.FIRST_SCAN_INVITE))
        ScanQrControl(enabled = !s.busy) { send(it, PayloadSource.SCANNED) }
        Gap()
        Field(UiText.ph(Placeholder.LINK_FIELD), link, KeyboardType.Uri, mono = true) { link = it }
        Main(UiText.of(CopyKey.FIRST_PASTE_LINK), enabled = link.isNotBlank() && !s.busy, busy = s.busy) {
            send(link, PayloadSource.PASTED)
        }
        SaidHere(model, s)
        BackRow(model, s)
    }
}

// ---- "Use your own server" and the Trust Gate ----

@Composable
internal fun OwnServerScreen(model: TrustModel, s: AppSnapshot, screen: EntryScreen.OwnServer) {
    var address by remember { mutableStateOf("") }
    AuthColumn {
        Title(UiText.of(CopyKey.FIRST_OWN_SERVER))
        Field(UiText.ph(Placeholder.SERVER_ADDRESS_FIELD), address, KeyboardType.Uri, mono = true) { address = it }
        Main(UiText.ph(Placeholder.SUBMIT_ADDRESS), enabled = address.isNotBlank() && !s.busy, busy = s.busy) {
            model.run({ entry.submitServerAddress(screen, address.trim()) })
        }
        SaidHere(model, s)
        BackRow(model, s)
    }
}

/**
 * The Trust Gate (§4.4, §12.3) as a screen: the title, the exact origin (dominant, monospaced: never a display name),
 * the body's sentences, the cautions and the operator key's short form. Cancel is the safe default and comes first;
 * nothing is pre-focused, so Connect is always a deliberate tap.
 */
@Composable
internal fun TrustGateScreen(model: TrustModel, s: AppSnapshot, screen: EntryScreen.TrustGate) {
    AuthColumn {
        TrustGateBody(screen.prompt)
        SaidHere(model, s)
        Gap()
        Second(UiText.of(CopyKey.CANCEL), enabled = !s.busy) { model.act { entry.declineTrustGate(screen) } }
        Main(trustGateConfirmLabel(screen.prompt), enabled = !s.busy, busy = s.busy) {
            model.run({ entry.confirmTrustGate(screen) })
        }
    }
}

/**
 * The confirm button: the design's "It's the same" in the device-link wording, the approved "Continue" in the `kind`
 * change wording; no wording is given otherwise.
 */
internal fun trustGateConfirmLabel(prompt: TrustGatePrompt): UiText =
    prompt.confirmLabel?.let { UiText.of(it) }
        ?: if (prompt.wording == TrustGateWording.KIND_CHANGE) UiText.Plain(Approved.GATE_KIND_CHANGE_CONTINUE) else UiText.ph(Placeholder.TRUST_GATE_CONNECT)

/** The gate's title: the design's, or the approved one where the design gives none (the `kind` change). */
internal fun trustGateTitle(prompt: TrustGatePrompt): UiText =
    prompt.title?.let { UiText.of(it) } ?: UiText.Plain(Approved.GATE_TITLE_KIND_CHANGE)

@Composable
internal fun TrustGateBody(prompt: TrustGatePrompt) {
    Title(trustGateTitle(prompt))
    Text(prompt.origin, style = MaterialTheme.typography.titleMedium.copy(fontFamily = FontFamily.Monospace), modifier = Modifier.padding(vertical = 8.dp))
    if (prompt.punycodeCaution) {
        Text(PUNYCODE_CAUTION, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
        Gap(8)
    }
    if (prompt.httpCaution) {
        val loopback = httpCautionIsLoopback(prompt.origin)
        Text(
            if (loopback) HTTP_LOOPBACK_CAUTION else HTTP_BLOCKED_CAUTION,
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
 * The cautions are "the existing cautions" (§12.3): the old app's sentences, carried over word for word. The shipped
 * network config permits cleartext to 127.0.0.1 only; a debug build also to `localhost`.
 */
internal const val PUNYCODE_CAUTION =
    "This address uses international characters, shown above in their punycode (xn--) form. Check it is exactly the server you expect — lookalike letters are a known phishing trick."
internal const val HTTP_LOOPBACK_CAUTION =
    "This is an unencrypted http:// address on this device. Traffic to it never leaves the phone, so it isn't exposed to the network."
internal const val HTTP_BLOCKED_CAUTION =
    "Android will refuse this connection — it does not allow unencrypted http:// to other devices. Put the server behind https (a reverse proxy, or Tailscale Serve) first; connecting will fail until you do."

/** Whether Android will let this app speak plain http to [origin]: 127.0.0.1 always, `localhost` in a debug build. */
internal fun httpCautionIsLoopback(origin: String): Boolean {
    val host = origin.removePrefix("http://").substringBefore(':').substringBefore('/')
    return host == "127.0.0.1" || (host == "localhost" && DEBUG_ALLOWS_LOCALHOST)
}

/** The debug overlay of the network config lists `localhost`; the shipped one does not. */
internal val DEBUG_ALLOWS_LOCALHOST: Boolean get() = isDebugBuild

/** Whether this is a debuggable build, read once from the application info at start (no BuildConfig by decision). */
@Volatile internal var isDebugBuild: Boolean = false

// ---- a server this device knows, and what its card says ----

/**
 * Connected to a typed server, signed out (§12.1): create an account when its mode allows, or sign in. The design
 * gives this screen no wording; its keys carry the owner's approved words (entries 3, 4, 5) in the shared code itself.
 */
@Composable
internal fun ServerScreen(model: TrustModel, s: AppSnapshot, screen: EntryScreen.Server) {
    AuthColumn {
        Sigil()
        Gap()
        InstanceName(screen.instance)
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
        InstanceName(screen.instance.label)
        Gap()
        InstanceCard(model, s, screen.instance)
        SaidHere(model, s)
        BackRow(model, s)
    }
}

/** What a server's card asks for, wherever an instance is on show (§4.4, §12.3). */
@Composable
internal fun InstanceCard(model: TrustModel, s: AppSnapshot, instance: io.silencelen.andvari.core.app.InstanceSnapshot) {
    when (val card = instance.card) {
        is InstanceCardState.Ok -> {}
        is InstanceCardState.Stopped -> {
            Say(CopyKey.CARD_FORK, color = MaterialTheme.colorScheme.error)
            ForgetServerButton(model, s, instance)
        }
        is InstanceCardState.Damaged -> {
            CardRecordDamaged(instance.label.origin)
            ForgetServerButton(model, s, instance)
        }
        is InstanceCardState.Withheld -> Say(CopyKey.CARD_WITHHELD)
        is InstanceCardState.NotVerified -> Say(UiText.Plain(Approved.CARD_NOT_VERIFIED))
        is InstanceCardState.Moved -> {
            Say(card.line)
            if (card.alreadyPinnedThere) {
                Say(UiText.Plain(Approved.CARD_MOVE_NOT_FOLLOWED_TITLE), style = MaterialTheme.typography.titleSmall)
                Say(UiText.approved(Approved.CARD_MOVE_NOT_FOLLOWED_BODY, card.toOrigin))
                AskFirst(s, UiText.ph(Placeholder.FORGET_OTHER_SERVER), UiText.Plain(card.toOrigin), quiet = false) {
                    model.run({ this.instance.forgetServerAtNewAddress(card) })
                }
                ForgetServerButton(model, s, instance)
            } else {
                Main(UiText.ph(Placeholder.FOLLOW_MOVE), enabled = !s.busy, busy = s.busy) { model.run({ this.instance.followMove(card) }) }
            }
        }
        is InstanceCardState.KindChanged -> KindChangeGate(model, s, card)
        is InstanceCardState.UpdateAndvari -> Say(card.sentence)
    }
}

/**
 * The Trust Gate of a server's change of kind. "Not now" does what it says: the question goes away, and a line says
 * that it was put off and when it is asked again (the shared code's rule: at the next unlock, and the old kind stays
 * in force meanwhile). The question can still be opened from that line before then.
 */
@Composable
internal fun KindChangeGate(model: TrustModel, s: AppSnapshot, card: InstanceCardState.KindChanged) {
    var reopened by remember(card) { mutableStateOf(false) }
    if (card.putOff && !reopened) {
        Say(UiText.ph(Placeholder.KIND_CHANGE_PUT_OFF))
        Quieter(UiText.ph(Placeholder.KIND_CHANGE_ANSWER_NOW), enabled = !s.busy) { reopened = true }
        return
    }
    TrustGateBody(card.gate)
    Second(UiText.Plain(Approved.GATE_KIND_CHANGE_NOT_NOW), enabled = !s.busy) {
        reopened = false
        model.act { this.instance.kindChangeNotNow(card) }
    }
    Main(trustGateConfirmLabel(card.gate), enabled = !s.busy, busy = s.busy) { model.run({ this.instance.acceptKindChange(card) }) }
}

/** This device's record of the server at [origin] does not decode (approved copy, entry 12): the title and two paragraphs. */
@Composable
internal fun CardRecordDamaged(origin: String) {
    Say(UiText.Plain(Approved.CARD_RECORD_DAMAGED_TITLE), style = MaterialTheme.typography.titleSmall)
    Say(UiText.approved(Approved.CARD_RECORD_DAMAGED_BODY, origin))
}

/**
 * "Forget this server" (§12.3): removes the pin and this device's data for it; the only way out of a fork. On every
 * card that offers it, and in Settings, it asks the same question first: the button opens it, and only its confirm
 * forgets, as on the desktop.
 */
@Composable
internal fun ForgetServerButton(model: TrustModel, s: AppSnapshot, instance: io.silencelen.andvari.core.app.InstanceSnapshot, quiet: Boolean = false) {
    AskFirst(s, UiText.of(CopyKey.FORGET_THIS_SERVER), UiText.Plain(instance.label.name.ifEmpty { instance.label.origin } + "\n" + instance.label.origin), quiet) {
        // The person's own end of a session at that server, where one is open (Settings): what it overtakes is said as that.
        model.personEnds()
        model.run({ this.instance.forgetServer(instance) }, model::personEnded)
    }
}

/** A button whose act runs only from the question it opens: [what] as the title and the confirm, [detail] as its text. */
@Composable
internal fun AskFirst(s: AppSnapshot, what: UiText, detail: UiText, quiet: Boolean, act: () -> Unit) {
    var asking by remember { mutableStateOf(false) }
    if (quiet) Quieter(what, enabled = !s.busy) { asking = true } else Second(what, enabled = !s.busy) { asking = true }
    if (asking) {
        androidx.compose.material3.AlertDialog(
            onDismissRequest = { asking = false },
            title = { Say(what) },
            text = { Say(detail) },
            confirmButton = { androidx.compose.material3.TextButton(onClick = { asking = false; act() }) { Say(what) } },
            dismissButton = { androidx.compose.material3.TextButton(onClick = { asking = false }) { Say(CopyKey.CANCEL) } },
        )
    }
}

/**
 * What the address-mismatch screen says to do next, by what was opened: null where the API's own sentence covers it
 * (the baked instance) or nothing more is said (a typed address; a kit, which offers `recoverAtNamedAddress`).
 */
internal fun addressMismatchNext(screen: EntryScreen.AddressMismatch): Placeholder? = when {
    screen.sentence != null -> null
    screen.opening == AddressMismatchFor.INVITE -> Placeholder.ADDRESS_MISMATCH_INVITE
    screen.opening == AddressMismatchFor.DEVICE_LINK -> Placeholder.ADDRESS_MISMATCH_DEVICE_LINK
    else -> null
}

/** What the address-mismatch screen says: the API's sentence where it gives one, else the approved one with both addresses. */
internal fun addressMismatchLine(screen: EntryScreen.AddressMismatch): UiText =
    screen.sentence?.let { UiText.of(it) } ?: UiText.approved(Approved.CARD_OTHER_ADDRESS_BODY, screen.dialed, screen.cardNames)

/**
 * §2.4 `origin_mismatch`: the address dialed served a card made for another address. Both addresses are shown whole.
 * The approved title and sentence (copy page, entry 8) say it; for the baked public instance the API's own sentence
 * ([CopyKey.CARD_MOVED_UPDATE]) stands instead of them.
 */
@Composable
internal fun AddressMismatchScreen(model: TrustModel, s: AppSnapshot, screen: EntryScreen.AddressMismatch) {
    AuthColumn {
        if (screen.sentence == null) {
            Say(UiText.Plain(Approved.CARD_OTHER_ADDRESS_TITLE), style = MaterialTheme.typography.titleMedium)
            Gap(8)
        }
        // Each address is said to be what it is: the one typed (or that the link or kit names), and the one the server
        // gave (the two stood unlabelled, one under the other).
        Quiet(UiText.ph(dialedAddressLabel(screen.opening)))
        Text(addressBreaks(screen.dialed), style = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace))
        Quiet(UiText.ph(Placeholder.ADDRESS_CARD_NAMES))
        Text(addressBreaks(screen.cardNames), style = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace))
        Gap(8)
        Say(addressMismatchLine(screen))
        // Never redirected: an invite names its address (ask its sender for a new one); a device link's QR names its
        // address (start again from the other device). Only a kit can be taken to the address the card names.
        addressMismatchNext(screen)?.let { Say(it) }
        if (screen.canRecoverThere) {
            Main(UiText.ph(Placeholder.RECOVER_THERE), enabled = !s.busy, busy = s.busy) { model.run({ entry.recoverAtNamedAddress(screen) }) }
        }
        SaidHere(model, s)
        BackRow(model, s)
    }
}

/** What the dialed address was: the one typed, or the one the link or kit names. */
internal fun dialedAddressLabel(opening: AddressMismatchFor): Placeholder = when (opening) {
    AddressMismatchFor.TYPED_ADDRESS, AddressMismatchFor.TYPED_KIT -> Placeholder.ADDRESS_YOU_TYPED
    AddressMismatchFor.INVITE -> Placeholder.ADDRESS_THE_LINK_NAMES
    AddressMismatchFor.DEVICE_LINK -> Placeholder.ADDRESS_DEVICE_LINK_NAMES
    AddressMismatchFor.KIT -> Placeholder.ADDRESS_THE_KIT_NAMES
}

// ---- "Already have an account? Sign in" ----

@Composable
internal fun SignInChoiceScreen(model: TrustModel, s: AppSnapshot, screen: EntryScreen.SignInChoice) {
    AuthColumn {
        Title(UiText.of(CopyKey.FIRST_SIGN_IN))
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
        Title(UiText.of(CopyKey.SIGN_IN_FORGOT))
        Second(UiText.of(CopyKey.SIGN_IN_SCAN_KIT), enabled = !s.busy) { model.act { entry.openKitEntry(screen) } }
        Second(UiText.of(CopyKey.LOST_PASSWORD_AND_KIT), enabled = !s.busy) { model.act { entry.openAskOperator(screen) } }
        BackRow(model, s)
    }
}

/** Back, and start over: the two ways out of a signed-out screen that can be left. */
@Composable
internal fun BackRow(model: TrustModel, s: AppSnapshot) {
    Gap()
    Quieter(UiText.ph(Placeholder.BACK), enabled = !s.busy) { model.act { entry.back() } }
}
