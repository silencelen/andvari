package io.silencelen.andvari.app.trust

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import io.silencelen.andvari.app.AuthColumn
import io.silencelen.andvari.app.MasterPasswordStrengthHints
import io.silencelen.andvari.app.SecretField
import io.silencelen.andvari.core.app.AppSnapshot
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.OperatorHelpStage
import io.silencelen.andvari.core.app.PayloadSource
import java.text.DateFormat
import java.util.Date

// "Link from your other device" on the new device (§8.2) and "Forgot your master password?" (§10, §9.3). Each entry
// takes its own kind of payload only, and no screen hands a refused payload to another entry (§12.1 "three scanners,
// three jobs", §17 flow conformance). Each entry has its scanner and its paste field, and both hand their text to the
// entry's one intent; only the source differs.

// ---- §8.2: linking this device ----

/** The only place a device link is taken. An invite or a kit here answers NOT_A_DEVICE_LINK and starts nothing. */
@Composable
internal fun LinkDeviceEntryScreen(model: TrustModel, s: AppSnapshot, screen: EntryScreen.LinkDeviceEntry) {
    var link by remember { mutableStateOf("") }
    val send = { text: String, source: PayloadSource -> model.run({ entry.submitDeviceLink(screen, text, source) }) }
    AuthColumn {
        Title(UiText.of(CopyKey.SIGN_IN_LINK_DEVICE))
        ScanQrControl(enabled = !s.busy) { send(it, PayloadSource.SCANNED) }
        Field(UiText.ph(Placeholder.LINK_FIELD), link, KeyboardType.Uri, mono = true) { link = it }
        Main(UiText.ph(Placeholder.CONTINUE), enabled = link.isNotBlank() && !s.busy, busy = s.busy) {
            send(link, PayloadSource.PASTED)
        }
        SaidHere(model, s)
        BackRow(model, s)
    }
}

/** Claimed; the other device has yet to answer. No code exists yet. A claimed link has no Back: Start over gives it up. */
@Composable
internal fun LinkDeviceWaitingScreen(model: TrustModel, s: AppSnapshot, screen: EntryScreen.LinkDeviceWaiting) {
    AuthColumn {
        InstanceName(screen.instance)
        Say(Placeholder.LINK_DEVICE_WAITING)
        SaidHere(model, s)
        Quieter(UiText.ph(Placeholder.START_OVER), enabled = !s.busy) { model.act { entry.startOver() } }
    }
}

/**
 * The six digits to type into the other device (§8.2 step 5). **There is no "they match" control**: the digits are
 * typed on the other device, never confirmed here (§17).
 */
@Composable
internal fun LinkDeviceCodeScreen(model: TrustModel, s: AppSnapshot, screen: EntryScreen.LinkDeviceCode) {
    AuthColumn {
        InstanceName(screen.instance)
        Gap()
        // The digits alone said nothing of what to do with them.
        Say(Placeholder.LINK_CODE_TYPE_THERE)
        Text(screen.code.chunked(3).joinToString(" "), style = MaterialTheme.typography.displaySmall.copy(fontFamily = FontFamily.Monospace))
        Gap()
        SaidHere(model, s)
        Quieter(UiText.ph(Placeholder.START_OVER), enabled = !s.busy) { model.act { entry.startOver() } }
    }
}

/** §8.2 step 7: the master password of the account being linked, named with its instance (§4.4). */
@Composable
internal fun LinkDevicePasswordScreen(model: TrustModel, s: AppSnapshot, screen: EntryScreen.LinkDevicePassword) {
    var password by remember { mutableStateOf("") }
    var code by remember { mutableStateOf("") }
    AuthColumn {
        // The title names the account, the server and its address once (they were said twice,
        // and at the largest font the password field fell below the first screen).
        PasswordStepTitle(screen.prompt.title?.let { UiText.of(it) }, screen.prompt.instance)
        if (!screen.codeNeeded) {
            SecretField(UiText.ph(Placeholder.PASSWORD_FIELD).shown(), password) { password = it }
            Main(UiText.ph(Placeholder.SIGN_IN_BUTTON), enabled = password.isNotEmpty() && !s.busy, busy = s.busy) {
                val typed = password
                model.run({ entry.submitLinkPassword(screen, typed) }) { password = "" }
            }
        } else {
            Field(UiText.ph(Placeholder.TWO_STEP_CODE_FIELD), code, KeyboardType.Number, mono = true) { code = it }
            Main(UiText.ph(Placeholder.SIGN_IN_BUTTON), enabled = code.isNotBlank() && !s.busy, busy = s.busy) {
                model.run({ entry.submitLinkCode(screen, code.trim()) }) { code = "" }
            }
        }
        SaidHere(model, s)
        Quieter(UiText.ph(Placeholder.START_OVER), enabled = !s.busy) { model.act { entry.startOver() } }
    }
}

@Composable
internal fun LinkDeviceEndedScreen(model: TrustModel, s: AppSnapshot, screen: EntryScreen.LinkDeviceEnded) {
    AuthColumn {
        Say(OutcomeWords.linkDeviceEnd(screen.outcome, model.api.retryAfterSeconds()))
        // This phone's own reason (a damaged copy, a held operator account): its way out, under the sentence.
        WayOutOffer(model, s, wayOutFor(screen.outcome))
        // A link refused for an address this phone knows under an earlier account: the shared code's offer to forget it,
        // exactly where the snapshot hands it, as at a sign-in.
        s.earlierAccount?.let { EarlierAccountOffer(model, s, it) }
        Gap()
        Main(UiText.of(CopyKey.SIGN_IN_LINK_DEVICE), enabled = !s.busy, busy = false) { model.act { entry.dismissLinkDevice(screen) } }
        // An end whose line points to the sign-in with the master password: that sign-in, beside another link.
        if (linkEndOffersPasswordSignIn(screen.outcome)) {
            Second(UiText.of(CopyKey.SIGN_IN_PASSWORD), enabled = !s.busy) { model.openPasswordSignInAfterLink(screen) }
        }
        Quieter(UiText.ph(Placeholder.START_OVER), enabled = !s.busy) { model.act { entry.startOver() } }
    }
}

/**
 * A device link that ended where this phone cannot tell an account made again from a substitution
 * ([LinkDeviceEnd.IDENTITY_FAULT_CANNOT_TELL]): its line points to the sign-in with the master password, which can tell,
 * so the ended screen offers that sign-in beside another link.
 */
internal fun linkEndOffersPasswordSignIn(end: io.silencelen.andvari.core.app.LinkDeviceEnd): Boolean =
    end == io.silencelen.andvari.core.app.LinkDeviceEnd.IDENTITY_FAULT_CANNOT_TELL

// ---- §10: recovery with the kit ----

/**
 * "Scan your recovery kit": **the only place a kit is taken** (FS-B1). The kit's text pasted counts as a scan; a kit
 * typed by hand is the account's address, the server's address and the eleven groups.
 */
@Composable
internal fun KitEntryScreen(model: TrustModel, s: AppSnapshot, screen: EntryScreen.KitEntry) {
    var pasted by remember { mutableStateOf("") }
    var email by remember { mutableStateOf("") }
    var server by remember { mutableStateOf("") }
    var groups by remember { mutableStateOf("") }
    AuthColumn {
        Title(UiText.of(CopyKey.SIGN_IN_SCAN_KIT))
        ScanQrControl(enabled = !s.busy) { model.run({ entry.submitKit(screen, it, PayloadSource.SCANNED) }) }
        SecretField(UiText.ph(Placeholder.KIT_TEXT_FIELD).shown(), pasted) { pasted = it }
        Main(UiText.ph(Placeholder.CONTINUE), enabled = pasted.isNotBlank() && !s.busy, busy = s.busy) {
            val text = pasted
            model.run({ entry.submitKit(screen, text, PayloadSource.PASTED) }) { pasted = "" }
        }
        Gap(24)
        Field(UiText.ph(Placeholder.EMAIL_FIELD), email, KeyboardType.Email) { email = it }
        Field(UiText.ph(Placeholder.SERVER_ADDRESS_FIELD), server, KeyboardType.Uri, mono = true) { server = it }
        SecretField(UiText.ph(Placeholder.KIT_GROUPS_FIELD).shown(), groups) { groups = it }
        Second(UiText.ph(Placeholder.CONTINUE), enabled = email.isNotBlank() && server.isNotBlank() && groups.isNotBlank() && !s.busy) {
            val typed = groups
            model.run({ entry.submitTypedKit(screen, email.trim(), server.trim(), typed) }) { groups = "" }
        }
        SaidHere(model, s)
        BackRow(model, s)
    }
}

/** §10: before anything is sent, "Recover {email} on {name} ({origin})". A kit is proved once. */
@Composable
internal fun KitRecoverScreen(model: TrustModel, s: AppSnapshot, screen: EntryScreen.KitRecover) {
    AuthColumn {
        Title(UiText.of(screen.title))
        // Under the title: this sets a new master password for that existing account (awaiting the owner's words).
        Quiet(UiText.of(screen.setsPasswordLine))
        InstanceName(screen.instance)
        Main(UiText.ph(Placeholder.CONTINUE), enabled = !s.busy, busy = s.busy) { model.run({ entry.confirmKitRecovery(screen) }) }
        SaidHere(model, s)
        BackRow(model, s)
    }
}

/**
 * A new master password after a recovery. Core runs no idle timer for it: the old wizard dropped a verified recovery
 * after five idle minutes, and that rule is the app's (IF-3 [EntryScreen.ReplacePassword]); see [TrustModel].
 */
@Composable
internal fun ReplacePasswordScreen(model: TrustModel, s: AppSnapshot, screen: EntryScreen.ReplacePassword) {
    var password by remember { mutableStateOf("") }
    var again by remember { mutableStateOf("") }
    AuthColumn {
        Title(UiText.Plain(screen.email))
        InstanceName(screen.instance)
        SecretField(UiText.ph(Placeholder.NEW_PASSWORD_FIELD).shown(), password) { password = it }
        MasterPasswordStrengthHints(password)
        SecretField(UiText.ph(Placeholder.NEW_PASSWORD_AGAIN_FIELD).shown(), again) { again = it }
        Main(UiText.ph(Placeholder.CONTINUE), enabled = password.isNotEmpty() && !s.busy, busy = s.busy) {
            if (password != again) {
                model.say(UiText.ph(Placeholder.PASSWORDS_DIFFER))
            } else {
                val typed = password
                model.run({ entry.chooseReplacementPassword(screen, typed) }) { password = ""; again = "" }
            }
        }
        SaidHere(model, s)
        Quieter(UiText.ph(Placeholder.START_OVER), enabled = !s.busy) { model.act { entry.startOver() } }
    }
}

// ---- §9.3: the operator's help ----

@Composable
internal fun AskOperatorScreen(model: TrustModel, s: AppSnapshot, screen: EntryScreen.AskOperator) {
    var email by remember { mutableStateOf("") }
    AuthColumn {
        Title(UiText.of(CopyKey.ASK_THE_OPERATOR))
        InstanceName(screen.instance)
        Quiet(UiText.of(CopyKey.ASK_OPERATOR_WHO_CAN))
        Field(UiText.ph(Placeholder.EMAIL_FIELD), email, KeyboardType.Email) { email = it }
        Main(UiText.of(CopyKey.ASK_THE_OPERATOR), enabled = email.isNotBlank() && !s.busy, busy = s.busy) {
            model.run({ entry.requestOperatorHelp(screen, email.trim()) })
        }
        SaidHere(model, s)
        BackRow(model, s)
    }
}

/**
 * Each stage of an operator-help request has its own line, for the person who asked, on their own screen only (the
 * request code stands above it). Settings › Recovery's list names a stage with [requestRowStage].
 */
internal fun operatorHelpStageLine(stage: OperatorHelpStage): UiText = when (stage) {
    OperatorHelpStage.CODE_NEEDED -> UiText.ph(Placeholder.OPERATOR_HELP_CODE_NEEDED)
    OperatorHelpStage.HOLDING -> UiText.ph(Placeholder.OPERATOR_HELP_HOLDING)
    OperatorHelpStage.AWAITING_OPERATOR -> UiText.ph(Placeholder.OPERATOR_HELP_AWAITING_OPERATOR)
    // The server answers "vetoed" for a request a signed-in device refused, for one it ended itself (a password change,
    // recovery turned off) and for one ended by whoever runs the server: the device cannot tell which, so the shared
    // code's line ([EntryScreen.OperatorHelp.endedLine]) is true of every cause.
    OperatorHelpStage.VETOED -> UiText.of(CopyKey.ASSIST_REQUEST_ENDED)
    OperatorHelpStage.EXPIRED -> UiText.ph(Placeholder.OPERATOR_HELP_EXPIRED)
    OperatorHelpStage.DID_NOT_CHECK_OUT -> UiText.ph(Placeholder.OPERATOR_HELP_DID_NOT_CHECK_OUT)
}

/** The request's own line: the shared code's line for a request that is over where it gives one, the stage's otherwise. */
internal fun operatorHelpLine(screen: EntryScreen.OperatorHelp): UiText =
    screen.endedLine?.let { UiText.of(it) } ?: operatorHelpStageLine(screen.stage)

/** A request that ended (cancelled by a device, expired, an answer that did not check out): nothing to wait for. */
internal fun operatorHelpEnded(stage: OperatorHelpStage): Boolean =
    stage == OperatorHelpStage.VETOED || stage == OperatorHelpStage.EXPIRED || stage == OperatorHelpStage.DID_NOT_CHECK_OUT

@Composable
internal fun OperatorHelpScreen(model: TrustModel, s: AppSnapshot, screen: EntryScreen.OperatorHelp) {
    var code by remember { mutableStateOf("") }
    AuthColumn {
        InstanceName(screen.instance)
        Quiet(UiText.Plain(screen.email))
        Text(screen.requestCode.joinToString(" "), style = MaterialTheme.typography.titleMedium.copy(fontFamily = FontFamily.Monospace))
        Quiet(UiText.of(CopyKey.REQUEST_CODE_READ_OUT))
        Gap()
        val keyChange = screen.keyChange
        val warning = keyChange?.warningTitle
        if (keyChange != null && warning != null) {
            // The server's recovery key changed and the old key did not sign it: the request is stopped and nothing is
            // opened. The warning, with "stop" first (the default) and "keep waiting" (sends nothing).
            KeyChangedWarning(model, s, screen, keyChange)
            return@AuthColumn
        }
        // A server that no longer knows this request: said in place of the stage, with wait and start again.
        val unknown = screen.requestUnknown
        if (unknown != null) {
            Say(UiText.of(unknown), color = MaterialTheme.colorScheme.error)
            Second(UiText.of(CopyKey.ASSIST_REQUEST_UNKNOWN_WAIT), enabled = !s.busy) { model.run({ entry.refreshOperatorHelp(screen) }) }
            Quieter(UiText.of(CopyKey.ASSIST_REQUEST_UNKNOWN_START_AGAIN), enabled = !s.busy) { model.act { entry.abandonOperatorHelp(screen) } }
            SaidHere(model, s)
            return@AuthColumn
        }
        // The operator's answer cannot be used on this phone now (another account kept, this phone's copy, a held
        // operator account, an answer naming another account, the identity fault): said in place of the stage, with its
        // way out where it has one; the request is kept, and Try again looks once the way is clear.
        val stop = operatorHelpStop(screen)
        if (stop != null) {
            Say(UiText.of(stop.line), color = MaterialTheme.colorScheme.error)
            if (stop.line == CopyKey.SIGN_IN_SERVER_KEYS_NOT_KNOWN_HERE) Say(Placeholder.SIGN_IN_KEYS_WAY_OUT)
            WayOutOffer(model, s, stop.way)
            Second(UiText.ph(Placeholder.TRY_AGAIN), enabled = !s.busy) { model.run({ entry.refreshOperatorHelp(screen) }) }
            SaidHere(model, s)
            Quieter(UiText.ph(Placeholder.START_OVER), enabled = !s.busy) { model.act { entry.abandonOperatorHelp(screen) } }
            return@AuthColumn
        }
        Say(operatorHelpLine(screen))
        // A key change the old key signed: one line beside the stage.
        keyChangeLine(keyChange)?.let { Say(it) }
        // The operator's answer did not match what this device opened: the request is kept, the operator uploads again.
        screen.answerReplaced?.let { Say(UiText.of(it), color = MaterialTheme.colorScheme.error) }
        if (screen.stage == OperatorHelpStage.HOLDING && screen.holdEndsAtMs > 0) {
            Quiet(UiText.Plain(Dates.dateTime(screen.holdEndsAtMs)))
        }
        if (screen.stage == OperatorHelpStage.CODE_NEEDED) {
            Quiet(UiText.of(CopyKey.EMAIL_CHECK_SPAM))
            Field(UiText.ph(Placeholder.CODE_FIELD), code, KeyboardType.Number, mono = true) { code = it }
            Main(UiText.ph(Placeholder.VERIFY_CODE), enabled = code.isNotBlank() && !s.busy, busy = s.busy) {
                model.run({ entry.verifyOperatorHelp(screen, code.trim()) }) { code = "" }
            }
        } else if (!operatorHelpEnded(screen.stage)) {
            // Waiting: ask the server again (the hold, the operator); an ended request has only Start over.
            Second(UiText.ph(Placeholder.TRY_AGAIN), enabled = !s.busy) { model.run({ entry.refreshOperatorHelp(screen) }) }
        }
        SaidHere(model, s)
        Quieter(UiText.ph(Placeholder.START_OVER), enabled = !s.busy) { model.act { entry.abandonOperatorHelp(screen) } }
    }
}

/** A change of the server's recovery key that the old key signed: its one line, with the date of the signature. Null otherwise. */
internal fun keyChangeLine(change: io.silencelen.andvari.core.app.AssistKeyChange?): UiText? {
    val key = change?.line ?: return null
    return UiText.of(key, Dates.date(change.rotatedAtMs))
}

/**
 * The server's recovery key changed and the old key did not sign the change: the approved title, the shared code's body,
 * then "stop this request" first, as the default, and "keep waiting", which sends nothing and leaves the request kept
 * and stopped until a signed change is served.
 */
@Composable
private fun KeyChangedWarning(model: TrustModel, s: AppSnapshot, screen: EntryScreen.OperatorHelp, change: io.silencelen.andvari.core.app.AssistKeyChange) {
    var waiting by remember(screen) { mutableStateOf(false) }
    change.warningTitle?.let { Say(it, style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.error) }
    change.warningBody?.let { Say(UiText.of(it)) }
    Gap()
    Main(UiText.of(change.stop), enabled = !s.busy, busy = s.busy) { model.act { entry.abandonOperatorHelp(screen) } }
    if (waiting) {
        Second(UiText.ph(Placeholder.TRY_AGAIN), enabled = !s.busy) { model.run({ entry.refreshOperatorHelp(screen) }) }
    } else {
        Quieter(UiText.of(change.keepWaiting), enabled = !s.busy) { waiting = true }
    }
    SaidHere(model, s)
}

/**
 * §9.3 step 4: the delivered account's ID, checked by the person against an earlier email before any new password.
 * Three explicit choices, in the approved words (copy page, entry 16): the title above the ID, and below it the shared
 * code's line that names the kit first (the approved body, which names only an email, is no longer shown, §9.3 step 4).
 */
/**
 * Under the approved body: what to compare the ID with (the kit first; an email is the weaker source), and, after the
 * first "It's the same", the second step's sentence: the next tap goes on to a new password.
 */
internal fun checkAccountLines(screen: EntryScreen.CheckAccount): List<UiText> =
    listOfNotNull(UiText.of(screen.compareLine), screen.confirmLine?.let { UiText.of(it) })

@Composable
internal fun CheckAccountScreen(model: TrustModel, s: AppSnapshot, screen: EntryScreen.CheckAccount) {
    AuthColumn {
        InstanceName(screen.instance)
        Title(UiText.Plain(Approved.RECOVERY_CHECK_ACCOUNT_TITLE))
        Text(screen.accountId.chunked(4).joinToString(" "), style = MaterialTheme.typography.titleMedium.copy(fontFamily = FontFamily.Monospace))
        // Under the ID, first, the line that names the kit and why an email is the weaker source (design §9.3 step 4):
        // it stands in place of the older sentence that named only an email, as on the desktop.
        for (line in checkAccountLines(screen)) Say(line)
        // A key change the old key signed, while the request was open: its one line on the check too.
        keyChangeLine(screen.keyChange)?.let { Say(it) }
        Gap()
        Second(UiText.of(CopyKey.GATE_ITS_THE_SAME), enabled = !s.busy) { model.act { entry.acceptRecoveredAccount(screen) } }
        Second(UiText.Plain(Approved.RECOVERY_CHECK_ACCOUNT_DIFFERENT), enabled = !s.busy) { model.act { entry.rejectRecoveredAccount(screen) } }
        Quieter(UiText.Plain(Approved.RECOVERY_CHECK_ACCOUNT_NOT_NOW), enabled = !s.busy) { model.act { entry.recoveredAccountNotNow(screen) } }
    }
}
