package io.silencelen.andvari.app.trust

import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.selection.selectable
import androidx.compose.ui.semantics.Role
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.FilterQuality
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import io.silencelen.andvari.app.SecretField
import io.silencelen.andvari.core.app.AccountSnapshot
import io.silencelen.andvari.core.app.AppSnapshot
import io.silencelen.andvari.core.app.DeletionBlockerKind
import io.silencelen.andvari.core.app.DeletionBlockerRow
import io.silencelen.andvari.core.app.DeletionResult
import io.silencelen.andvari.core.app.PlainResult
import io.silencelen.andvari.core.app.DeletionScreen
import io.silencelen.andvari.core.app.KitAfterMovePrompt
import io.silencelen.andvari.core.app.PasswordChangeResult
import io.silencelen.andvari.core.app.QuickEnrolResult
import io.silencelen.andvari.core.app.QuickUnlockResult
import io.silencelen.andvari.core.app.QuickUnlockSetting
import io.silencelen.andvari.core.app.QuickUnlockState
import io.silencelen.andvari.core.app.ServerPolicy
import io.silencelen.andvari.core.app.TwoStepScreen
import io.silencelen.andvari.core.app.VaultUnlockResult
import kotlinx.coroutines.delay

// ---- quick unlock (IF-3 author notes 1 to 3) ----

/**
 * What a quick unlock on the lock screen says (author note 1): CANCELLED nothing; USE_PASSWORD points at the password
 * field; TURNED_OFF says it is off now; SERVER_BLOCKED and IDENTITY_FAULT say what the password unlock says for them.
 */
internal fun quickUnlockWords(r: QuickUnlockResult, retryAfterSeconds: Int): UiText? = when (r) {
    QuickUnlockResult.DONE, QuickUnlockResult.CANCELLED -> null
    QuickUnlockResult.USE_PASSWORD -> UiText.ph(Placeholder.QUICK_UNLOCK_USE_PASSWORD)
    QuickUnlockResult.TURNED_OFF -> UiText.ph(Placeholder.QUICK_UNLOCK_TURNED_OFF)
    QuickUnlockResult.SERVER_BLOCKED -> UiText.forResult(VaultUnlockResult.SERVER_BLOCKED, retryAfterSeconds)
    QuickUnlockResult.IDENTITY_FAULT -> UiText.forResult(VaultUnlockResult.IDENTITY_FAULT, retryAfterSeconds)
    else -> UiText.forResult(r, retryAfterSeconds)
}

/** What turning quick unlock on says: a cancelled prompt says nothing; NOT_AVAILABLE is shown by the setting's state. */
internal fun quickEnrolWords(r: QuickEnrolResult, retryAfterSeconds: Int): UiText? = when (r) {
    QuickEnrolResult.DONE, QuickEnrolResult.CANCELLED, QuickEnrolResult.NOT_AVAILABLE -> null
    else -> UiText.forResult(r, retryAfterSeconds)
}

/** The line Settings shows for quick unlock's state. */
internal fun quickUnlockStateLine(setting: QuickUnlockSetting): UiText = when (setting.state) {
    QuickUnlockState.UNAVAILABLE -> UiText.ph(Placeholder.QUICK_UNLOCK_UNAVAILABLE)
    QuickUnlockState.NOT_ALLOWED -> UiText.ph(Placeholder.QUICK_UNLOCK_NOT_ALLOWED)
    QuickUnlockState.OFF -> UiText.ph(Placeholder.QUICK_UNLOCK_OFF)
    QuickUnlockState.ON -> UiText.ph(Placeholder.QUICK_UNLOCK_ON)
}

/**
 * Settings › Quick unlock (author note 2): the state; "Turn on" shows the platform prompt through the app's
 * [AndroidKeyWrap]; "Turn off" destroys the key. While [QuickUnlockSetting.offerNow] the section is the offer card, whose
 * "Not now" is [io.silencelen.andvari.core.app.AccountSettingsApi.quickUnlockNotNow].
 */
@Composable
internal fun QuickUnlockSection(model: TrustModel, s: AppSnapshot, setting: QuickUnlockSetting) {
    SectionDivider()
    Say(Placeholder.QUICK_UNLOCK_TITLE, style = sectionTitleStyle())
    if (setting.offerNow) Say(Placeholder.QUICK_UNLOCK_OFFER) else Say(quickUnlockStateLine(setting))
    when (setting.state) {
        QuickUnlockState.OFF -> {
            Second(UiText.ph(Placeholder.TURN_ON), enabled = !s.busy) {
                model.runSaying({ settings.turnOnQuickUnlock(setting) }, { quickEnrolWords(it, model.api.retryAfterSeconds()) })
            }
            if (setting.offerNow) Quieter(UiText.ph(Placeholder.NOT_NOW), enabled = !s.busy) { model.act { settings.quickUnlockNotNow(setting) } }
        }
        QuickUnlockState.ON -> Quieter(UiText.ph(Placeholder.TURN_OFF), enabled = !s.busy) { model.act { settings.turnOffQuickUnlock(setting) } }
        QuickUnlockState.UNAVAILABLE, QuickUnlockState.NOT_ALLOWED -> {}
    }
}

// ---- the client policy (author note 5) ----

/**
 * Read-only: the windows this device applies, from the server's policy (or the client's own ceilings until it is read),
 * then, under a policy that forbids keeping data on the phone, the shared code's line that caught logins are kept here
 * sealed until they are answered ([ServerPolicy.capturesKeptLine]), as handed.
 */
internal fun policyLines(p: ServerPolicy): List<UiText> = listOfNotNull(
    counted(p.autoLockSeconds.toLong(), Placeholder.POLICY_AUTO_LOCK, Placeholder.POLICY_AUTO_LOCK_ONE),
    counted(p.clipboardClearSeconds.toLong(), Placeholder.POLICY_CLIPBOARD, Placeholder.POLICY_CLIPBOARD_ONE),
    if (!p.known) UiText.ph(Placeholder.POLICY_NOT_READ) else null,
    p.capturesKeptLine?.let { UiText.of(it) },
)

@Composable
internal fun PolicySection(policy: ServerPolicy) {
    for (line in policyLines(policy)) Quiet(line)
}

// ---- two-step sign-in (author note 4) ----

/** How often a two-step key on show is read again, so it is never shown after the engine dropped it. */
internal const val TWO_STEP_KEY_REREAD_MS = 1_000L

/**
 * The signed-in page to show: Settings while a two-step set-up is open on its confirm step (the person left the app to
 * add the key to an authenticator, and the next unlock brings it back), the vault otherwise.
 */
internal fun landingPage(account: AccountSnapshot): SignedInPage =
    if (account.twoStep?.enrolment != null) SignedInPage.SETTINGS else SignedInPage.VAULT

/**
 * Settings › Two-step sign-in. Closed: one button that asks the server ([openTwoStep]). Open and off: the master
 * password starts an enrolment, whose key is read through [twoStepKey] (never from a snapshot) and shown as a QR code
 * and as typed text; the first code confirms it. Open and on: a current code turns it off.
 */
@Composable
internal fun TwoStepSection(model: TrustModel, s: AppSnapshot, twoStep: TwoStepScreen?) {
    SectionDivider()
    Say(Placeholder.TWO_STEP_TITLE, style = sectionTitleStyle())
    if (twoStep == null) {
        Quieter(UiText.ph(Placeholder.TWO_STEP_OPEN), enabled = !s.busy) { model.runIn(TWO_STEP_SECTION, { settings.openTwoStep() }) }
        SaidIn(model, s, TWO_STEP_SECTION)
        return
    }
    var password by remember(twoStep) { mutableStateOf("") }
    var code by remember(twoStep) { mutableStateOf("") }
    Say(if (twoStep.enabled) Placeholder.TWO_STEP_ON else Placeholder.TWO_STEP_OFF)
    val enrolment = twoStep.enrolment
    when {
        enrolment != null -> {
            // The key lives only as long as this screen shows it; it is never in a snapshot. It is read again every
            // second ([TWO_STEP_KEY_REREAD_MS]), so it leaves the screen as soon as the engine drops it (ten minutes
            // from its setup, a lock or a sign-out excepted) even when no new snapshot says so.
            var key by remember(enrolment) { mutableStateOf(model.api.settings.twoStepKey(enrolment)) }
            LaunchedEffect(enrolment) {
                while (key != null) {
                    delay(TWO_STEP_KEY_REREAD_MS)
                    key = model.api.settings.twoStepKey(enrolment)
                }
            }
            val shown = key
            if (shown != null) {
                Say(Placeholder.TWO_STEP_SCAN)
                val qr = remember(shown.uri) { qrBitmap(shown.uri, 600) }
                Image(qr.asImageBitmap(), contentDescription = null, filterQuality = FilterQuality.None, modifier = Modifier.size(200.dp))
                Say(Placeholder.TWO_STEP_TYPE_KEY)
                Text(shown.secret.chunked(4).joinToString(" "), style = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace))
                Field(UiText.ph(Placeholder.TWO_STEP_CODE_FIELD), code, KeyboardType.NumberPassword, mono = true) { code = it }
                Main(UiText.ph(Placeholder.VERIFY_CODE), enabled = code.isNotBlank() && !s.busy, busy = s.busy) {
                    val c = code
                    model.runIn(TWO_STEP_SECTION, { settings.confirmTwoStep(enrolment, c) }) { code = "" }
                }
            } else {
                // Its time ran out: the set-up cannot be confirmed any more (the engine answers NOT_PENDING); Close,
                // then turn it on again for a new key.
                Say(Placeholder.TWO_STEP_KEY_GONE)
            }
        }
        twoStep.enabled -> {
            // Since 2026-11-16 turning it off, and a new key for the authenticator, take the master password as well
            // as a current code. Both fields are emptied at the tap, before anything is sent, so on every path.
            MasterPasswordField(s, password) { password = it }
            Field(UiText.ph(Placeholder.TWO_STEP_CODE_FIELD), code, KeyboardType.NumberPassword, mono = true) { code = it }
            val ready = code.isNotBlank() && password.isNotEmpty() && !s.busy
            Second(UiText.ph(Placeholder.TURN_OFF), enabled = ready) {
                val c = code
                val p = password
                password = ""
                code = ""
                model.runIn(TWO_STEP_SECTION, { settings.turnOffTwoStepWithPassword(twoStep, c, p) }, { twoStepWords(it, model.api.retryAfterSeconds()) })
            }
            Quieter(UiText.ph(Placeholder.TWO_STEP_NEW_KEY), enabled = ready) {
                val c = code
                val p = password
                password = ""
                code = ""
                model.runIn(TWO_STEP_SECTION, { settings.replaceTwoStepKey(twoStep, c, p) }, { twoStepWords(it, model.api.retryAfterSeconds()) })
            }
        }
        else -> {
            MasterPasswordField(s, password) { password = it }
            Second(UiText.ph(Placeholder.TURN_ON), enabled = password.isNotEmpty() && !s.busy) {
                val p = password
                model.runIn(TWO_STEP_SECTION, { settings.startTwoStep(twoStep, p) }) { password = "" }
            }
        }
    }
    // Every answer of this card is said here, at the card, never at the top of Settings (far above, at the largest font
    // off the screen the person tapped on).
    SaidIn(model, s, TWO_STEP_SECTION)
    Quieter(UiText.ph(Placeholder.CLOSE), enabled = !s.busy) { model.act { settings.closeTwoStep() } }
}

/** The section name of the two-step card's answers ([TrustModel.runIn]). */
internal const val TWO_STEP_SECTION = "two-step"

/**
 * What turning two-step sign-in off, or a new key for it, answered: the shared code's words, or the result's own words
 * where it has none (a wrong password and a wrong code each say what they are). Too many tries with a known wait is one
 * sentence that names the wait ([Placeholder.TWO_STEP_WAIT]), in place of the shared code's, which says the same
 * without it; with no wait known, the shared code's sentence alone.
 */
internal fun twoStepWords(r: io.silencelen.andvari.core.app.TwoStepResult, retryAfterSeconds: Int): UiText? {
    val said = UiText.forResult(r, retryAfterSeconds) ?: return null
    if (r != io.silencelen.andvari.core.app.TwoStepResult.TOO_MANY_TRIES || retryAfterSeconds <= 0) return said
    return counted(retryAfterSeconds.toLong(), Placeholder.TWO_STEP_WAIT, Placeholder.TWO_STEP_WAIT_ONE)
}

// ---- a new kit after a followed move (author note 6) ----

/**
 * After a followed move the kit names the old address: "Make a new kit" is `recovery.makeKit(password)` (the new kit
 * then shows as any other), "Later" is [io.silencelen.andvari.core.app.RecoveryApi.kitAfterMoveLater], back at the next unlock.
 */
@Composable
internal fun KitAfterMoveCard(model: TrustModel, s: AppSnapshot, prompt: KitAfterMovePrompt) {
    var password by remember(prompt) { mutableStateOf("") }
    Say(Placeholder.KIT_AFTER_MOVE, style = MaterialTheme.typography.titleSmall)
    InstanceName(prompt.instance, MaterialTheme.typography.bodyMedium)
    MasterPasswordField(s, password) { password = it }
    Second(UiText.ph(Placeholder.KIT_AFTER_MOVE_MAKE), enabled = password.isNotEmpty() && !s.busy) {
        val p = password
        model.run({ recovery.makeKit(p) }) { password = "" }
    }
    Quieter(UiText.ph(Placeholder.LATER), enabled = !s.busy) { model.act { recovery.kitAfterMoveLater(prompt) } }
    HorizontalDivider()
}

// ---- change master password (map §3.18) ----

/** The change can be asked for: all three fields typed and the new password typed the same twice. The floor is core's. */
internal fun passwordChangeReady(current: String, replacement: String, again: String): Boolean =
    current.isNotEmpty() && replacement.isNotEmpty() && replacement == again

/** The section name of the password change's answers ([TrustModel.runIn]). */
internal const val PASSWORD_CHANGE_SECTION = "password-change"

/**
 * What a password change answered, a line of its own for each outcome the person can act on: a wrong current password
 * (never an expired session, S3-K1), a new one too weak (nothing was sent), a change made elsewhere meanwhile, and a
 * server that did not answer. DONE says nothing here: [passwordChangedLines] follow it.
 */
internal fun passwordChangeWords(r: PasswordChangeResult, retryAfterSeconds: Int): UiText? = when (r) {
    PasswordChangeResult.DONE -> null
    PasswordChangeResult.WRONG_PASSWORD -> UiText.ph(Placeholder.PASSWORD_CHANGE_WRONG)
    PasswordChangeResult.WEAK_PASSWORD -> UiText.ph(Placeholder.PASSWORD_CHANGE_WEAK)
    PasswordChangeResult.CHANGED_ELSEWHERE -> UiText.ph(Placeholder.PASSWORD_CHANGE_CHANGED_ELSEWHERE)
    PasswordChangeResult.UNREACHABLE -> UiText.ph(Placeholder.PASSWORD_CHANGE_NO_ANSWER)
    // The new password is in force at the server, but this phone's copy still opens with the previous one: never "try again".
    PasswordChangeResult.CHANGED_PREVIOUS_OPENS_HERE -> UiText.ph(Placeholder.PASSWORD_CHANGED_PREVIOUS_OPENS_HERE)
    else -> UiText.forResult(r, retryAfterSeconds)
}

/**
 * What the person is told after the change (l2b-14 item 4, IF-3 `changeMasterPassword`): no new kit follows, because
 * the account's key did not change; this phone opens with the new password from now on; and quick unlock's state
 * after the change, as the app interface reports it ([AccountSnapshot.quickUnlock]).
 */
internal fun passwordChangedLines(account: AccountSnapshot): List<UiText> = listOf(
    // In the order of the approved lines: done and the other devices, this phone, the kit.
    UiText.ph(Placeholder.PASSWORD_CHANGED),
    UiText.ph(Placeholder.PASSWORD_CHANGED_THIS_PHONE),
    UiText.ph(Placeholder.PASSWORD_CHANGED_NO_KIT),
    UiText.ph(Placeholder.PASSWORD_CHANGED_QUICK_UNLOCK),
    quickUnlockStateLine(account.quickUnlock),
)

/**
 * Settings › Change master password (IF-3 "Change master password", §7.8): names the account and the instance (§4.4),
 * takes the current password and the new one twice with the strength answer, and says that every other session ends
 * while the kit and any operator recovery stay valid. Each outcome is said in place ([passwordChangeWords]); after the
 * change, [passwordChangedLines]. It needs a live session: a copy the server signed out, or a stopped server, offers it not.
 *
 * The passwords are held in `remember`, never `rememberSaveable`, so they never enter saved instance state; each is set
 * to "" once the intent has it, and all three when the section leaves the screen.
 */
@Composable
internal fun ChangePasswordSection(model: TrustModel, s: AppSnapshot, account: AccountSnapshot) {
    var open by remember { mutableStateOf(false) }
    var changed by remember { mutableStateOf(false) }
    SectionDivider()
    if (account.serverStopped) return
    if (!open) {
        Quieter(UiText.ph(Placeholder.CHANGE_PASSWORD), enabled = !s.busy) { open = true; changed = false }
        return
    }
    Say(Placeholder.CHANGE_PASSWORD, style = sectionTitleStyle())
    if (changed) {
        for (line in passwordChangedLines(account)) Say(line)
        Quieter(UiText.ph(Placeholder.CLOSE)) { open = false; changed = false }
        return
    }
    var current by remember { mutableStateOf("") }
    var replacement by remember { mutableStateOf("") }
    var again by remember { mutableStateOf("") }
    DisposableEffect(Unit) {
        onDispose {
            current = ""
            replacement = ""
            again = ""
        }
    }
    Quiet(UiText.ph(Placeholder.CHANGE_PASSWORD_EFFECT))
    MasterPasswordField(s, current) { current = it }
    SecretField(UiText.ph(Placeholder.NEW_PASSWORD_FIELD).shown(), replacement) { replacement = it }
    io.silencelen.andvari.app.MasterPasswordStrengthHints(replacement)
    SecretField(UiText.ph(Placeholder.NEW_PASSWORD_AGAIN_FIELD).shown(), again) { again = it }
    if (again.isNotEmpty() && again != replacement) Quiet(UiText.ph(Placeholder.PASSWORDS_DIFFER))
    SaidIn(model, s, PASSWORD_CHANGE_SECTION)
    Main(UiText.ph(Placeholder.CHANGE_PASSWORD), enabled = passwordChangeReady(current, replacement, again) && !s.busy, busy = s.busy) {
        val c = current
        val r = replacement
        current = ""
        model.runIn(PASSWORD_CHANGE_SECTION, { settings.changeMasterPassword(c, r) }, { passwordChangeWords(it, model.api.retryAfterSeconds()) }) { result ->
            if (result.done || result == PasswordChangeResult.WEAK_PASSWORD || result == PasswordChangeResult.CHANGED_PREVIOUS_OPENS_HERE) {
                replacement = ""
                again = ""
            }
            if (result.done) changed = true
        }
    }
    Quieter(UiText.ph(Placeholder.CLOSE), enabled = !s.busy) { open = false }
}

// ---- delete account (map §3.19, slice 17) ----

/** The section name of the deletion's answers ([TrustModel.runIn]). */
internal const val DELETION_SECTION = "deletion"

/** A vault's name in the plan: as it is, or said to be unreadable, never an empty line (l2b-14: `""` is unreadable). */
private fun readable(name: String?): String? = name?.takeIf { it.isNotBlank() }

/** A vault that goes with the account (its personal vault and every vault only it holds). */
internal fun deletionGoesLine(name: String): UiText =
    readable(name)?.let { UiText.ph(Placeholder.DELETION_VAULT_GOES, it) } ?: UiText.ph(Placeholder.DELETION_VAULT_GOES_UNREADABLE)

/** A shared vault the account leaves, with one signed leave: what it saved there stays for the others. */
internal fun deletionLeftLine(name: String): UiText =
    readable(name)?.let { UiText.ph(Placeholder.DELETION_VAULT_LEFT, it) } ?: UiText.ph(Placeholder.DELETION_VAULT_LEFT_UNREADABLE)

/** One line per blocker; an unknown kind is shown as a blocker it cannot explain, and nothing goes past any of them. */
internal fun deletionBlockerLine(row: DeletionBlockerRow): UiText = when (row.kind) {
    DeletionBlockerKind.SHARED_VAULT_WITH_OTHERS -> readable(row.vaultName)
        ?.let { counted(row.others.toLong(), Placeholder.DELETION_BLOCKER_SHARED, Placeholder.DELETION_BLOCKER_SHARED_ONE, it) }
        ?: counted(row.others.toLong(), Placeholder.DELETION_BLOCKER_SHARED_UNREADABLE, Placeholder.DELETION_BLOCKER_SHARED_UNREADABLE_ONE)
    DeletionBlockerKind.OPERATOR_ACCOUNT -> UiText.ph(Placeholder.DELETION_BLOCKER_OPERATOR)
    DeletionBlockerKind.NOT_KNOWN -> UiText.ph(Placeholder.DELETION_BLOCKER_UNKNOWN)
}

/** What the person must do first, under each blocker (the account-deletion design §11 step 3). */
internal fun deletionBlockerDo(row: DeletionBlockerRow): UiText = when (row.kind) {
    DeletionBlockerKind.SHARED_VAULT_WITH_OTHERS -> UiText.ph(Placeholder.DELETION_BLOCKER_SHARED_DO)
    DeletionBlockerKind.OPERATOR_ACCOUNT -> UiText.ph(Placeholder.DELETION_BLOCKER_OPERATOR_DO)
    DeletionBlockerKind.NOT_KNOWN -> UiText.ph(Placeholder.DELETION_BLOCKER_UNKNOWN_DO)
}

/** The typed confirmation: the account's address, trimmed and case-folded (the server checks it again, EMAIL_MISMATCH). */
internal fun typedEmailMatches(email: String, typed: String): Boolean = typed.trim().lowercase() == email.trim().lowercase()

/**
 * The deletion may be asked for: the server's plan is in and has no blocker, nothing is running or unknown, the address
 * typed matches the account's, the password is typed, and the code is typed when it is asked for.
 */
internal fun deletionReady(screen: DeletionScreen, typedEmail: String, password: String, code: String, codeAsked: Boolean = false): Boolean {
    val plan = screen.plan ?: return false
    return plan.canProceed && !screen.retrying && !screen.outcomeUnknown &&
        typedEmailMatches(screen.email, typedEmail) && password.isNotEmpty() && (!(plan.codeNeeded || codeAsked) || code.isNotBlank())
}

/**
 * What a deletion answered, in place. DONE says nothing here (the first screen says it: the shared code's
 * [io.silencelen.andvari.core.app.EntryScreen.FirstRun.accountDeleted]);
 * OUTCOME_UNKNOWN says nothing here either, because the screen's own state says it cannot tell
 * ([DeletionScreen.outcomeUnknown]). Never "deleted" for anything but DONE.
 */
internal fun deletionWords(r: DeletionResult, retryAfterSeconds: Int): UiText? = when (r) {
    DeletionResult.DONE, DeletionResult.OUTCOME_UNKNOWN -> null
    DeletionResult.EMAIL_MISMATCH -> UiText.ph(Placeholder.DELETION_EMAIL_MISMATCH)
    DeletionResult.WRONG_PASSWORD -> UiText.ph(Placeholder.DELETION_WRONG_PASSWORD)
    DeletionResult.CODE_NEEDED -> UiText.ph(Placeholder.DELETION_CODE_NEEDED)
    DeletionResult.WRONG_CODE -> UiText.ph(Placeholder.DELETION_WRONG_CODE)
    DeletionResult.BLOCKED -> UiText.ph(Placeholder.DELETION_BLOCKED)
    DeletionResult.STILL_CHANGING -> UiText.ph(Placeholder.DELETION_STILL_CHANGING)
    DeletionResult.CHANGED_ELSEWHERE -> UiText.ph(Placeholder.DELETION_CHANGED_ELSEWHERE)
    // FAR_FUTURE and CLOCK_AHEAD carry the design's sentences; the troubles are said as every intent says them.
    else -> UiText.forResult(r, retryAfterSeconds)
}

/** What a check after an unknown outcome answered: DONE means the account is there (nothing was deleted). */
internal fun deletionCheckWords(r: PlainResult, retryAfterSeconds: Int): UiText? = when (r) {
    PlainResult.DONE -> UiText.ph(Placeholder.DELETION_CHECKED_STILL_THERE)
    // The session ended at the check: that cannot be told from another end (the design's step 7). The lock screen
    // says andvari cannot tell yet ([TrustModel.deletionCannotTell]).
    PlainResult.STALE -> null
    else -> UiText.forResult(r, retryAfterSeconds)
}

/**
 * Settings › Delete account (§3.11, the account-deletion design §11): what goes with the account and each vault by name,
 * what is left (one signed leave per shared vault), each blocker with what to do first and no way past it, then the
 * typed address, the master password and the two-step code when asked. While it runs it says so, and that it is
 * retrying by itself when a vault's history moved on. Every end has its line ([deletionWords]); DONE lands on the first
 * screen; an unknown outcome is never shown as done or failed: the screen says it cannot tell yet and offers the check.
 */
@Composable
internal fun DeleteAccountSection(model: TrustModel, s: AppSnapshot, account: AccountSnapshot) {
    SectionDivider()
    val screen = account.deletion
    if (screen == null) {
        Quieter(UiText.ph(Placeholder.DELETE_ACCOUNT), enabled = !s.busy) { model.runIn(DELETION_SECTION, { settings.openDeletion() }) }
        SaidIn(model, s, DELETION_SECTION)
        return
    }
    var typedEmail by remember(screen.email) { mutableStateOf("") }
    var password by remember(screen.email) { mutableStateOf("") }
    var code by remember(screen.email) { mutableStateOf("") }
    var codeAsked by remember(screen.email) { mutableStateOf(false) }
    DisposableEffect(screen.email) { onDispose { password = ""; code = "" } }
    Say(Placeholder.DELETE_ACCOUNT, style = sectionTitleStyle())
    val plan = screen.plan
    when {
        screen.outcomeUnknown -> {
            Say(Placeholder.DELETION_OUTCOME_UNKNOWN, style = MaterialTheme.typography.bodyMedium)
            SaidIn(model, s, DELETION_SECTION)
            Second(UiText.ph(Placeholder.DELETION_CHECK), enabled = !s.busy) {
                model.runIn(DELETION_SECTION, { settings.checkDeletion(screen) }, { deletionCheckWords(it, model.api.retryAfterSeconds()) })
            }
            // Beside the check: the shared code's offer to forget the account on this phone, behind its second step.
            ForgetUnknownDeletionOffer(model, s, DELETION_SECTION)
        }
        plan == null -> Quiet(UiText.ph(Placeholder.WORKING))
        else -> {
            Say(UiText.ph(Placeholder.DELETION_WHAT_GOES))
            for (name in plan.deletedVaults) Say(deletionGoesLine(name))
            for (name in plan.leftVaults) Say(deletionLeftLine(name))
            Say(UiText.ph(Placeholder.DELETION_CANNOT_UNDO), color = MaterialTheme.colorScheme.error)
            for (b in plan.blockers) {
                Say(deletionBlockerLine(b), color = MaterialTheme.colorScheme.error)
                Quiet(deletionBlockerDo(b))
            }
            if (plan.canProceed) {
                Say(UiText.ph(Placeholder.DELETION_TYPE_EMAIL, screen.email))
                Field(UiText.ph(Placeholder.EMAIL_FIELD), typedEmail, KeyboardType.Email) { typedEmail = it }
                MasterPasswordField(s, password) { password = it }
                if (plan.codeNeeded || codeAsked) Field(UiText.ph(Placeholder.TWO_STEP_CODE_FIELD), code, KeyboardType.NumberPassword, mono = true) { code = it }
                if (s.busy) Quiet(UiText.ph(if (screen.retrying) Placeholder.DELETION_RETRYING else Placeholder.DELETION_RUNNING))
                SaidIn(model, s, DELETION_SECTION)
                Main(UiText.ph(Placeholder.DELETE_ACCOUNT), enabled = deletionReady(screen, typedEmail, password, code, codeAsked) && !s.busy, busy = s.busy) {
                    val e = typedEmail
                    val p = password
                    val c = code.takeIf { plan.codeNeeded || codeAsked }
                    password = ""
                    // The person's own end of the session (deletionAnswered says how it ended).
                    model.personEnds()
                    model.runIn(DELETION_SECTION, { settings.deleteAccount(screen, e, p, c) }, { deletionWords(it, model.api.retryAfterSeconds()) }) {
                        code = ""
                        // The code field appears once the server asks for it, and stays.
                        if (it == DeletionResult.CODE_NEEDED || it == DeletionResult.WRONG_CODE) codeAsked = true
                        model.deletionAnswered(it)
                    }
                }
            } else {
                SaidIn(model, s, DELETION_SECTION)
            }
        }
    }
    Quieter(UiText.ph(Placeholder.CLOSE), enabled = !s.busy) { model.act { settings.closeDeletion() } }
}

/** The signed-in Settings sections, in order. */
@Composable
internal fun SettingsSections(model: TrustModel, s: AppSnapshot, account: AccountSnapshot) {
    // No title of its own: the page's top bar names it (a second "settings" under the bar said it twice).
    // Each section is a card, as in the current app's Settings, in its order: the backups, then autofill, quick unlock
    // and two-step sign-in; what the current app has no card for (storage, devices, recovery, the password, the
    // server's policy, deleting the account) is drawn the same way after them.
    VaultBackupSection(model)
    StorageSection(model)
    SettingsCard { AutofillTrustSection() }
    SettingsCard { QuickUnlockSection(model, s, account.quickUnlock) }
    SettingsCard { TwoStepSection(model, s, account.twoStep) }
    SettingsCard { DevicesSection(model, s, account) }
    SettingsCard { RecoverySection(model, s, account) }
    if (!account.serverStopped) SettingsCard { ChangePasswordSection(model, s, account) }
    SettingsCard { PolicySection(account.policy) }
    SettingsCard { DeleteAccountSection(model, s, account) }
    PhoneCheckSection()
}

/**
 * The test build only: a way to the check of this phone's crypto against the specification's test vectors
 * ([io.silencelen.andvari.app.PhoneCheckEntry]). A release build has no entry, so nothing is drawn there.
 */
@Composable
private fun PhoneCheckSection() {
    val entry = io.silencelen.andvari.app.phoneCheck ?: return
    var open by remember { mutableStateOf(false) }
    HorizontalDivider()
    if (open) entry.screen { open = false } else Quieter(UiText.Plain(PHONE_CHECK_ENTRY)) { open = true }
}

/** The test build's own button, not product wording: it never ships (a release build has no entry). */
internal const val PHONE_CHECK_ENTRY = "Test build: check this phone's crypto"

/** One entry of Settings' autofill list: a browser trusted on this device, or an app remembered for its own logins. */
internal data class AutofillTrustRow(val kind: Kind, val pkg: String, val name: String) {
    enum class Kind { BROWSER, APP }
}

/** What the list shows, in order (browsers first, each kind by package). */
internal fun autofillTrustRows(browsers: Map<String, String>, apps: Map<String, String>): List<AutofillTrustRow> =
    browsers.keys.sorted().map { AutofillTrustRow(AutofillTrustRow.Kind.BROWSER, it, io.silencelen.andvari.app.browserLabel(it)) } +
        apps.keys.sorted().map { AutofillTrustRow(AutofillTrustRow.Kind.APP, it, it) }

/**
 * The browsers trusted on this device ("Trust this browser") and the apps remembered for
 * their own logins (the app-fill confirm), each with a revoke. Both are device-local records, read here directly.
 */
@Composable
internal fun AutofillTrustSection() {
    val context = androidx.compose.ui.platform.LocalContext.current.applicationContext
    var version by remember { mutableStateOf(0) }
    val rows = remember(version) {
        runCatching {
            autofillTrustRows(
                io.silencelen.andvari.app.autofill.ApprovedBrowsers.all(context),
                io.silencelen.andvari.app.autofill.AppSignerBindings.all(context),
            )
        }.getOrDefault(emptyList())
    }
    SectionDivider()
    Say(Placeholder.AUTOFILL_TRUST_TITLE, style = sectionTitleStyle())
    if (rows.isEmpty()) Quiet(UiText.ph(Placeholder.AUTOFILL_TRUST_NONE))
    for (row in rows) {
        Say(if (row.kind == AutofillTrustRow.Kind.BROWSER) Placeholder.AUTOFILL_TRUSTED_BROWSER else Placeholder.AUTOFILL_REMEMBERED_APP, row.name)
        Text(row.pkg, style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace)
        Quieter(UiText.ph(Placeholder.AUTOFILL_REVOKE)) {
            when (row.kind) {
                AutofillTrustRow.Kind.BROWSER -> io.silencelen.andvari.app.autofill.ApprovedBrowsers.revoke(context, row.pkg)
                AutofillTrustRow.Kind.APP -> io.silencelen.andvari.app.autofill.AppSignerBindings.forget(context, row.pkg)
            }
            version++
        }
    }
}

/**
 * The account ID, where the current app's Settings has "My identity code": a card of its own, its title, one line on
 * what it is for, and the ID large, in monospace, as eight groups of four on two lines, selectable. What it is for
 * differs: the new design compares six-digit codes with each person (§6.11) instead of reading this out, and the ID is
 * what the recovery kit and every email about the account carry (§10, §11.2), so the line says that.
 */
@Composable
internal fun AccountIdCard(account: AccountSnapshot) {
    SectionDivider()
    Say(Placeholder.ACCOUNT_ID_TITLE, style = sectionTitleStyle())
    Say(UiText.ph(Placeholder.ACCOUNT_ID_LINE), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    Gap(8)
    androidx.compose.foundation.text.selection.SelectionContainer {
        Text(accountIdGroups(account.accountId), style = MaterialTheme.typography.titleMedium, fontFamily = FontFamily.Monospace)
    }
}

/** The account ID in groups of four, four groups a line (32 hex: two lines, as the current app's identity code). */
internal fun accountIdGroups(id: String): String = id.chunked(4).chunked(4).joinToString("\n") { it.joinToString(" ") }

/**
 * Appearance, as the current app's card: a line, then Auto, Light and Dark as radio rows. The choice is this device's
 * own ([io.silencelen.andvari.app.ThemePref], kept outside the account) and every screen of the app follows it at once,
 * the autofill windows too.
 */
@Composable
internal fun AppearanceSection() {
    val context = androidx.compose.ui.platform.LocalContext.current
    val mode = io.silencelen.andvari.app.ThemePref.mode(context)
    SectionDivider()
    Say(Placeholder.APPEARANCE, style = sectionTitleStyle())
    Say(UiText.ph(Placeholder.APPEARANCE_LINE), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    Gap(4)
    for (m in io.silencelen.andvari.app.ThemeMode.entries) {
        androidx.compose.foundation.layout.Row(
            Modifier.fillMaxWidth()
                .selectable(selected = mode == m, role = Role.RadioButton, onClick = { io.silencelen.andvari.app.ThemePref.set(context, m) })
                .padding(vertical = 6.dp),
            verticalAlignment = androidx.compose.ui.Alignment.CenterVertically,
        ) {
            androidx.compose.material3.RadioButton(selected = mode == m, onClick = null)
            androidx.compose.foundation.layout.Spacer(Modifier.width(10.dp))
            Say(UiText.ph(appearanceLabel(m)))
        }
    }
}

internal fun appearanceLabel(m: io.silencelen.andvari.app.ThemeMode): Placeholder = when (m) {
    io.silencelen.andvari.app.ThemeMode.Auto -> Placeholder.APPEARANCE_AUTO
    io.silencelen.andvari.app.ThemeMode.Light -> Placeholder.APPEARANCE_LIGHT
    io.silencelen.andvari.app.ThemeMode.Dark -> Placeholder.APPEARANCE_DARK
}
