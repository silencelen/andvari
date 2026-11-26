package io.silencelen.andvari.desktop.trust

import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.text.font.FontFamily
import io.silencelen.andvari.core.app.AppSnapshot
import io.silencelen.andvari.core.app.AssistKeyChange
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.KeptWayOut
import io.silencelen.andvari.core.app.LinkDeviceEnd
import io.silencelen.andvari.core.app.OperatorHelpStage
import io.silencelen.andvari.core.app.PayloadSource
import java.text.DateFormat
import java.util.Date

// "Link from your other device" on the new device (§8.2) and "Forgot your master password?" (§10, §9.3), ported from
// the Android app. Each entry takes its own kind of payload only, and no screen hands a refused payload to another
// entry (§12.1 "three scanners, three jobs", §17 flow conformance). The desktop has no camera: each entry is a paste
// field, and a kit typed or pasted is plain text.

// ---- §8.2: linking this device ----

/**
 * The only place a device link is taken ("scan the QR it shows, or paste the link on desktop", D:2035). An invite or
 * a kit here answers NOT_A_DEVICE_LINK and starts nothing. The desktop shows the master-password path only (decision 18).
 */
@Composable
internal fun LinkDeviceEntryScreen(model: TrustModel, s: AppSnapshot, screen: EntryScreen.LinkDeviceEntry) {
    var link by remember { mutableStateOf("") }
    val submit = { if (link.isNotBlank() && !s.busy) model.run({ entry.submitDeviceLink(screen, link.trim(), PayloadSource.PASTED) }) }
    AuthColumn {
        WindowHead(UiText.of(CopyKey.SIGN_IN_LINK_DEVICE))
        Field(UiText.ph(Placeholder.LINK_FIELD), link, mono = true, onEnter = { submit() }) { link = it }
        Main(UiText.ph(Placeholder.CONTINUE), enabled = link.isNotBlank() && !s.busy, busy = s.busy) { submit() }
        SaidHere(model, s)
        BackRow(model, s)
    }
}

/** Claimed; the other device has yet to answer. No code exists yet. A claimed link has no Back: Start over gives it up. */
@Composable
internal fun LinkDeviceWaitingScreen(model: TrustModel, s: AppSnapshot, screen: EntryScreen.LinkDeviceWaiting) {
    AuthColumn {
        WindowHead(UiText.of(CopyKey.SIGN_IN_LINK_DEVICE), screen.instance)
        // The current app's wait: a small spinner beside the line that names it.
        Row(verticalAlignment = Alignment.CenterVertically) {
            OpeningSpinner()
            Say(UiText.ph(Placeholder.LINK_DEVICE_WAITING), Modifier.padding(start = 8.dp))
        }
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
        WindowHead(UiText.of(CopyKey.SIGN_IN_LINK_DEVICE), screen.instance)
        // The digits in the current app's card for something to copy by hand (its recovery phrase's).
        CodeCard {
            Text(
                screen.code.chunked(3).joinToString(" "), Modifier.fillMaxWidth(),
                style = MaterialTheme.typography.displaySmall.copy(fontFamily = FontFamily.Monospace, textAlign = TextAlign.Center),
            )
        }
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
    val submitPassword = {
        if (password.isNotEmpty() && !s.busy) {
            val typed = password
            model.run({ entry.submitLinkPassword(screen, typed) }) { password = "" }
        }
    }
    val submitCode = { if (code.isNotBlank() && !s.busy) model.run({ entry.submitLinkCode(screen, code.trim()) }) { code = "" } }
    AuthColumn {
        WindowHead(screen.prompt.title?.let { UiText.of(it) }, screen.prompt.instance)
        if (!screen.codeNeeded) {
            SecretField(UiText.ph(Placeholder.PASSWORD_FIELD), password, onEnter = { submitPassword() }) { password = it }
            Main(UiText.ph(Placeholder.SIGN_IN_BUTTON), enabled = password.isNotEmpty() && !s.busy, busy = s.busy) { submitPassword() }
        } else {
            Field(UiText.ph(Placeholder.TWO_STEP_CODE_FIELD), code, mono = true, onEnter = { submitCode() }) { code = it }
            Main(UiText.ph(Placeholder.SIGN_IN_BUTTON), enabled = code.isNotBlank() && !s.busy, busy = s.busy) { submitCode() }
        }
        SaidHere(model, s)
        Quieter(UiText.ph(Placeholder.START_OVER), enabled = !s.busy) { model.act { entry.startOver() } }
    }
}

/**
 * How a device link ended: the design's sentence where it gives one; for a pickup the server did not answer, a
 * placeholder that says the link is spent and nothing was linked; otherwise a placeholder naming the outcome.
 */
internal fun linkDeviceEndLine(end: LinkDeviceEnd, retryAfterSeconds: Int = 0): UiText = when {
    // Too many requests: its own line, with the wait the server named in its slot.
    end == LinkDeviceEnd.TOO_MANY && end.sentence != null -> UiText.filled(end.sentence!!, waitText(retryAfterSeconds).shown())
    end.sentence != null -> UiText.of(end.sentence!!)
    end == LinkDeviceEnd.NO_ANSWER -> UiText.ph(Placeholder.LINK_DEVICE_NO_ANSWER)
    else -> UiText.ph(Placeholder.REFUSAL, "LinkDeviceEnd." + end.name)
}

@Composable
internal fun LinkDeviceEndedScreen(model: TrustModel, s: AppSnapshot, screen: EntryScreen.LinkDeviceEnded) {
    AuthColumn {
        WindowHead(UiText.of(CopyKey.SIGN_IN_LINK_DEVICE))
        Say(linkDeviceEndLine(screen.outcome, model.readOr(0) { model.api.retryAfterSeconds() }))
        // Ended over something kept here: the shared code's way out (the removal of this computer's copy, which counts
        // what was not sent first; the kept account's sign-out).
        linkEndWayOut(screen, s)?.let { KeptAccountRefusal(model, s, it) }
        // Ended over an earlier account known here under the address: the same offer and two steps as at a sign-in.
        EarlierAccountOffer(model, s)
        Gap()
        Main(UiText.of(CopyKey.SIGN_IN_LINK_DEVICE), enabled = !s.busy, busy = false) { model.act { entry.dismissLinkDevice(screen) } }
        // Ended where this computer cannot tell from the link alone a remade account from a substitution: the line points
        // to the sign-in with the master password, which can tell; offered beside another link.
        if (offersPasswordSignIn(screen)) {
            Second(UiText.of(CopyKey.SIGN_IN_PASSWORD), enabled = !s.busy) { model.act { toPasswordSignIn(screen) } }
        }
        Quieter(UiText.ph(Placeholder.START_OVER), enabled = !s.busy) { model.act { entry.startOver() } }
    }
}

/** The ended link's line points to the sign-in with the master password ([LinkDeviceEnd.IDENTITY_FAULT_CANNOT_TELL]). */
internal fun offersPasswordSignIn(screen: EntryScreen.LinkDeviceEnded): Boolean = screen.outcome == LinkDeviceEnd.IDENTITY_FAULT_CANNOT_TELL

/**
 * From the ended link [screen] to the sign-in with the master password, the way a person would go by hand: the first
 * screen, "Sign in", then the password's way. Nothing is sent; the link has ended already. Each step only while the
 * screen it was meant for is on show.
 */
internal fun io.silencelen.andvari.core.app.DesktopAppApi.toPasswordSignIn(screen: EntryScreen.LinkDeviceEnded) {
    if (snapshot.entry !== screen) return
    entry.startOver()
    val first = snapshot.entry as? EntryScreen.FirstRun ?: return
    entry.openSignIn(first)
    val choice = snapshot.entry as? EntryScreen.SignInChoice ?: return
    entry.openPasswordSignIn(choice)
}

// ---- §10: recovery with the kit ----

/**
 * The kit entry: **the only place a kit is taken** (FS-B1). The kit's text pasted counts as a scan; a kit typed by
 * hand is the account's address, the server's address and the eleven groups. The title is the design's "Scan your
 * recovery kit" (the API has no desktop wording for it).
 */
@Composable
internal fun KitEntryScreen(model: TrustModel, s: AppSnapshot, screen: EntryScreen.KitEntry) {
    var pasted by remember { mutableStateOf("") }
    var email by remember { mutableStateOf("") }
    var server by remember { mutableStateOf("") }
    var groups by remember { mutableStateOf("") }
    val submitPasted = {
        if (pasted.isNotBlank() && !s.busy) {
            val text = pasted
            model.run({ entry.submitKit(screen, text, PayloadSource.PASTED) }) { pasted = "" }
        }
    }
    val submitTyped = {
        if (email.isNotBlank() && server.isNotBlank() && groups.isNotBlank() && !s.busy) {
            val typed = groups
            model.run({ entry.submitTypedKit(screen, email.trim(), server.trim(), typed) }) { groups = "" }
        }
    }
    AuthColumn {
        WindowHead(UiText.of(CopyKey.SIGN_IN_SCAN_KIT))
        Field(UiText.ph(Placeholder.KIT_TEXT_FIELD), pasted, mono = true, onEnter = { submitPasted() }) { pasted = it }
        Main(UiText.ph(Placeholder.CONTINUE), enabled = pasted.isNotBlank() && !s.busy, busy = s.busy) { submitPasted() }
        Gap(24)
        Field(UiText.ph(Placeholder.EMAIL_FIELD), email) { email = it }
        Field(UiText.ph(Placeholder.SERVER_ADDRESS_FIELD), server, mono = true) { server = it }
        Field(UiText.ph(Placeholder.KIT_GROUPS_FIELD), groups, mono = true, onEnter = { submitTyped() }) { groups = it }
        Second(UiText.ph(Placeholder.CONTINUE), enabled = email.isNotBlank() && server.isNotBlank() && groups.isNotBlank() && !s.busy) { submitTyped() }
        SaidHere(model, s)
        BackRow(model, s)
    }
}

/** §10: before anything is sent, "Recover {email} on {name} ({origin})". A kit is proved once. */
@Composable
internal fun KitRecoverScreen(model: TrustModel, s: AppSnapshot, screen: EntryScreen.KitRecover) {
    AuthColumn {
        WindowHead(UiText.of(screen.title), screen.instance)
        // Under the title: this sets a new master password for that existing account (core's line, awaiting wording).
        Say(screen.setsPasswordLine)
        Gap()
        Main(UiText.ph(Placeholder.CONTINUE), enabled = !s.busy, busy = s.busy) { model.run({ entry.confirmKitRecovery(screen) }) }
        SaidHere(model, s)
        BackRow(model, s)
    }
}

/**
 * A new master password after a recovery. Core runs no idle timer for it: the old wizard dropped a verified recovery
 * after five idle minutes, and that rule is the app's ([TrustModel.tick]).
 */
@Composable
internal fun ReplacePasswordScreen(model: TrustModel, s: AppSnapshot, screen: EntryScreen.ReplacePassword) {
    var password by remember { mutableStateOf("") }
    var again by remember { mutableStateOf("") }
    AuthColumn {
        WindowHead(UiText.Plain(screen.email), screen.instance)
        SecretField(UiText.ph(Placeholder.NEW_PASSWORD_FIELD), password) { password = it }
        MasterPasswordStrengthHints(password)
        SecretField(UiText.ph(Placeholder.NEW_PASSWORD_AGAIN_FIELD), again) { again = it }
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
    val submit = { if (email.isNotBlank() && !s.busy) model.run({ entry.requestOperatorHelp(screen, email.trim()) }) }
    AuthColumn {
        WindowHead(UiText.of(CopyKey.ASK_THE_OPERATOR), screen.instance)
        Quiet(UiText.of(CopyKey.ASK_OPERATOR_WHO_CAN))
        Field(UiText.ph(Placeholder.EMAIL_FIELD), email, onEnter = { submit() }) { email = it }
        Main(UiText.of(CopyKey.ASK_THE_OPERATOR), enabled = email.isNotBlank() && !s.busy, busy = s.busy) { submit() }
        SaidHere(model, s)
        BackRow(model, s)
    }
}

@Composable
internal fun OperatorHelpScreen(model: TrustModel, s: AppSnapshot, screen: EntryScreen.OperatorHelp) {
    var code by remember { mutableStateOf("") }
    val submit = { if (code.isNotBlank() && !s.busy) model.run({ entry.verifyOperatorHelp(screen, code.trim()) }) { code = "" } }
    AuthColumn {
        WindowHead(UiText.of(CopyKey.ASK_THE_OPERATOR), screen.instance, UiText.Plain(screen.email))
        // The request code in the current app's card for something read out or written down.
        CodeCard {
            Text(screen.requestCode.joinToString(" "), style = MaterialTheme.typography.titleMedium.copy(fontFamily = FontFamily.Monospace))
            Quiet(UiText.of(CopyKey.REQUEST_CODE_READ_OUT))
        }
        Gap()
        // A stop before anything was opened or committed (the request is kept) is said in place of the stage's line,
        // with its own way out: the kept account's sign-out, the removal of a damaged copy, or nothing at all.
        val stop = operatorHelpStop(screen)
        if (stop == null) {
            Say(operatorHelpStageLine(screen))
        } else {
            Say(UiText.of(stop), color = MaterialTheme.colorScheme.error)
            operatorHelpWayOut(screen, s)?.let { KeptAccountRefusal(model, s, it) }
        }
        // The server's recovery key changed while the request was open. Signed by the old key: one line beside the stage.
        keyChangeLine(screen.keyChange)?.let { Quiet(it) }
        // The answer on the server was not the one this device opened: the request is kept, the operator uploads again.
        screen.answerReplaced?.let { Say(UiText.of(it), color = MaterialTheme.colorScheme.error) }
        // Not signed by the old key: the request is stopped and nothing is opened. The warning, "stop" first (the
        // default); "keep waiting" sends nothing and leaves the request kept, and "try again" asks later.
        val unsigned = screen.keyChange?.takeIf { !it.byOldKey }
        var keptWaiting by remember(screen.keyChange) { mutableStateOf(false) }
        if (unsigned != null) {
            unsigned.warningTitle?.let { Say(UiText.of(it), style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.error) }
            unsigned.warningBody?.let { Say(UiText.of(it)) }
            if (!keptWaiting) {
                // Stop is the default here (it opens nothing): filled, and first.
                Main(UiText.of(unsigned.stop), enabled = !s.busy, busy = false) { model.act { entry.abandonOperatorHelp(screen) } }
                Quieter(UiText.of(unsigned.keepWaiting), enabled = !s.busy) { keptWaiting = true }
                SaidHere(model, s)
                return@AuthColumn
            }
        }
        // The server no longer knows the request: this device keeps it until its time runs out. Wait, or start again.
        screen.requestUnknown?.let { unknown ->
            Say(UiText.of(unknown), color = MaterialTheme.colorScheme.error)
            Second(UiText.of(CopyKey.ASSIST_REQUEST_UNKNOWN_WAIT), enabled = !s.busy) { model.run({ entry.refreshOperatorHelp(screen) }) }
            Quieter(UiText.of(CopyKey.ASSIST_REQUEST_UNKNOWN_START_AGAIN), enabled = !s.busy) { model.act { entry.abandonOperatorHelp(screen) } }
            SaidHere(model, s)
            return@AuthColumn
        }
        // No key store here: the request is held in memory only, so it does not outlive this run.
        if (model.assistRequestThisRunOnly()) Say(UiText.ph(Placeholder.ASSIST_REQUEST_THIS_RUN_ONLY))
        if (screen.stage == OperatorHelpStage.HOLDING && screen.holdEndsAtMs > 0) {
            Quiet(UiText.Plain(DateFormat.getDateTimeInstance().format(Date(screen.holdEndsAtMs))))
        }
        if (screen.stage == OperatorHelpStage.CODE_NEEDED) {
            Quiet(UiText.of(CopyKey.EMAIL_CHECK_SPAM))
            Field(UiText.ph(Placeholder.CODE_FIELD), code, mono = true, onEnter = { submit() }) { code = it }
            Main(UiText.ph(Placeholder.VERIFY_CODE), enabled = code.isNotBlank() && !s.busy, busy = s.busy) { submit() }
        } else {
            Second(UiText.ph(Placeholder.TRY_AGAIN), enabled = !s.busy) { model.run({ entry.refreshOperatorHelp(screen) }) }
        }
        SaidHere(model, s)
        Quieter(UiText.ph(Placeholder.START_OVER), enabled = !s.busy) { model.act { entry.abandonOperatorHelp(screen) } }
    }
}

/**
 * The request's stage line where no stop stands: for a request that is over (the server says `vetoed`, whether a
 * signed-in device of the account refused it, its master password or recovery setting changed, or whoever runs the
 * server ended it), the shared code's [EntryScreen.OperatorHelp.endedLine], which is true of every one of those causes;
 * at every other stage, where the request stands.
 */
internal fun operatorHelpStageLine(screen: EntryScreen.OperatorHelp): UiText =
    screen.endedLine?.let { UiText.of(it) } ?: UiText.ph(Placeholder.OPERATOR_HELP_STAGE, screen.stage.name)

/**
 * The stop the request's screen says in place of its stage (each field is the shared code's line for it): the keys the
 * answer delivered are not this account's as this computer knows it; another account is kept; the address is known here
 * under another account or key; this computer holds its server's operator account; the kept copy is damaged; the answer
 * names another account than the one kept. Null while none stands.
 */
internal fun operatorHelpStop(screen: EntryScreen.OperatorHelp): CopyKey? =
    screen.keysNotKnownHere ?: screen.anotherAccountKept ?: screen.identityFault ?: screen.operatorAccountHeld ?: screen.keptCopyDamaged
        ?: screen.notTheKeptAccount

/**
 * The way out under that stop: the shared code's act for it ([EntryScreen.OperatorHelp.wayOut]): another account kept →
 * its sign-out (named whole); this computer's own copy in the way → its removal; every other stop → none here. Null too
 * when no account is kept to act on.
 */
internal fun operatorHelpWayOut(screen: EntryScreen.OperatorHelp, s: AppSnapshot): WayOut? {
    val act = screen.wayOut
    val lines = if (act == KeptWayOut.SIGN_OUT_KEPT_ACCOUNT) keptAccountNamed(s) else emptyList()
    return wayOutFor(act, lines, s)
}

/** The line of a recovery-key change the old key signed, with the date the operator signed it; null otherwise. */
internal fun keyChangeLine(change: AssistKeyChange?): UiText? {
    val key = change?.line ?: return null
    return UiText.filled(key, DateFormat.getDateInstance(DateFormat.MEDIUM).format(Date(change.rotatedAtMs)))
}

/**
 * §9.3 step 4: the delivered account's ID, checked by the person against an earlier email before any new password.
 * Three explicit choices, in the approved words (entry 16).
 */
@Composable
internal fun CheckAccountScreen(model: TrustModel, s: AppSnapshot, screen: EntryScreen.CheckAccount) {
    AuthColumn {
        WindowHead(UiText.approved("RECOVERY_CHECK_ACCOUNT.title"), screen.instance)
        CodeCard {
            Text(screen.accountId.chunked(4).joinToString(" "), style = MaterialTheme.typography.titleMedium.copy(fontFamily = FontFamily.Monospace))
        }
        // The kit first; an email is the weaker source, as this server sent it (the shared code's line, which takes the
        // place of the email-only sentence on this screen), in both steps.
        Say(UiText.of(screen.compareLine))
        // The second step: "It's the same" once more goes on to a new password, so one tap never passes the comparison.
        screen.confirmLine?.let { Say(UiText.of(it), style = MaterialTheme.typography.titleSmall) }
        // A recovery-key change the old key signed, said here too (an unsigned one never reaches this screen).
        keyChangeLine(screen.keyChange)?.let { Quiet(it) }
        Gap()
        Second(UiText.approved("RECOVERY_CHECK_ACCOUNT.button0"), enabled = !s.busy) { model.act { entry.acceptRecoveredAccount(screen) } }
        Second(UiText.approved("RECOVERY_CHECK_ACCOUNT.button1"), enabled = !s.busy) { model.act { entry.rejectRecoveredAccount(screen) } }
        Quieter(UiText.approved("RECOVERY_CHECK_ACCOUNT.button2"), enabled = !s.busy) { model.act { entry.recoveredAccountNotNow(screen) } }
    }
}
