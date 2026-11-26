package io.silencelen.andvari.desktop.trust

import androidx.compose.foundation.layout.Column
import androidx.compose.material3.HorizontalDivider
import androidx.compose.runtime.collectAsState
import io.silencelen.andvari.desktop.CaptureState
import io.silencelen.andvari.desktop.LocalCaptureGuard
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import io.silencelen.andvari.core.app.AccountSnapshot
import io.silencelen.andvari.core.app.AppSnapshot
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.DeletionBlockerKind
import io.silencelen.andvari.core.app.DeletionBlockerRow
import io.silencelen.andvari.core.app.DeletionResult
import io.silencelen.andvari.core.app.DeletionScreen
import io.silencelen.andvari.core.app.PlainResult
import io.silencelen.andvari.core.app.DeviceLinkHost
import io.silencelen.andvari.core.app.DeviceLinkHostEnd
import io.silencelen.andvari.core.app.ProofResult
import io.silencelen.andvari.core.app.DeviceRow
import io.silencelen.andvari.core.app.DevicesScreen
import io.silencelen.andvari.core.app.HowDeviceJoined
import io.silencelen.andvari.core.app.KitAfterMovePrompt
import io.silencelen.andvari.core.app.OperatorRecoveryWarning
import io.silencelen.andvari.core.app.PasswordChangeResult
import io.silencelen.andvari.core.app.RecoveryRequestRow
import io.silencelen.andvari.core.app.RecoveryScreen
import io.silencelen.andvari.core.app.ServerPolicy
import io.silencelen.andvari.core.app.TwoStepScreen
import io.silencelen.andvari.core.app.WhoCanRecover
import kotlinx.coroutines.delay
import java.text.DateFormat
import java.util.Date

// The signed-in Settings of the new path on desktop, ported from the Android app's SettingsScreens, DevicesScreens
// and RecoverySettingsScreens: two-step sign-in, the client policy, a new kit after a followed move, your devices and
// adding a device from this computer, recovery, change master password, delete account. No quick unlock (decision 18).

/** The Settings sections, in order. */
@Composable
internal fun SettingsSections(model: TrustModel, s: AppSnapshot, account: AccountSnapshot) {
    // One card per section, as the current app's Settings; storage and screen capture draw their own (or nothing).
    SectionCard { TwoStepSection(model, s, account.twoStep) }
    SectionCard { DevicesSection(model, s, account) }
    SectionCard { RecoverySection(model, s, account) }
    SectionCard { ChangePasswordSection(model, s, account) }
    SectionCard { PolicySection(account.policy) }
    StorageSection(model)
    ScreenCaptureSection()
    SectionCard { DeleteAccountSection(model, s, account) }
}

// ---- screen capture on this computer (the owner's decision of 2026-11-16) ----

/**
 * What the Settings page says of screen capture, from what is true now ([CaptureState]): whether the switch is
 * offered, and each line. Linux has nothing of the kind, so it gets one sentence and no switch that would do nothing.
 */
internal class CaptureView(val offersSwitch: Boolean, val lines: List<UiText>, val error: Boolean)

internal fun captureView(state: CaptureState, offersSwitch: Boolean): CaptureView {
    if (!offersSwitch || state == CaptureState.NOT_POSSIBLE_HERE) return CaptureView(false, listOf(UiText.ph(Placeholder.CAPTURE_NOT_POSSIBLE_HERE)), false)
    val now = when (state) {
        CaptureState.HIDDEN -> UiText.ph(Placeholder.CAPTURE_HIDDEN)
        CaptureState.BLACKED_OUT -> UiText.ph(Placeholder.CAPTURE_BLACKED_OUT)
        CaptureState.NOT_ACTIVE -> UiText.ph(Placeholder.CAPTURE_NOT_ACTIVE)
        else -> UiText.ph(Placeholder.CAPTURE_ALLOWED)
    }
    return CaptureView(true, listOf(now, UiText.ph(Placeholder.CAPTURE_SWITCH_MEANS)), state == CaptureState.NOT_ACTIVE || state == CaptureState.ALLOWED)
}

@Composable
internal fun ScreenCaptureSection() {
    val guard = LocalCaptureGuard.current ?: return
    val state by guard.state.collectAsState()
    val allowed by guard.allowed.collectAsState()
    val view = captureView(state, guard.offersSwitch)
    SectionCard {
        SectionTitle(Placeholder.CAPTURE_TITLE)
        if (view.offersSwitch) {
            Tick(UiText.ph(Placeholder.CAPTURE_SWITCH), allowed) { guard.setAllowed(it) }
        }
        view.lines.forEachIndexed { i, line ->
            if (i == 0) Say(line, color = if (view.error) MaterialTheme.colorScheme.error else androidx.compose.ui.graphics.Color.Unspecified) else Quiet(line)
        }
    }
}

// ---- the client policy ----

/** Read-only: the windows this computer applies, from the server's policy (or the client's own ceilings until read). */
internal fun policyLines(p: ServerPolicy): List<UiText> = listOfNotNull(
    UiText.ph(Placeholder.POLICY_AUTO_LOCK, p.autoLockSeconds.toString()),
    UiText.ph(Placeholder.POLICY_CLIPBOARD, p.clipboardClearSeconds.toString()),
    if (!p.known) UiText.ph(Placeholder.POLICY_NOT_READ) else null,
)

@Composable
internal fun PolicySection(policy: ServerPolicy) {
    for (line in policyLines(policy)) Quiet(line)
}

/**
 * The account's own use and limits (spec 03 §14.4): one line for each of the four meters, used and limit, as the
 * freshest sync of the open vault served them ([ContentState.storage]). Nothing at all when the server gave none.
 */
@Composable
internal fun StorageSection(model: TrustModel) {
    val content by model.content.collectAsState()
    val c = content ?: return
    val state by c.states.collectAsState()
    val lines = storageLines(state.storage)
    if (lines.isEmpty()) return
    SectionCard {
        SectionTitle(Placeholder.STORAGE_TITLE)
        for (line in lines) Quiet(line)
    }
}

/** The four lines of [storage], used then limit; none for null. */
internal fun storageLines(storage: io.silencelen.andvari.core.app.content.AccountStorage?): List<UiText> {
    val s = storage ?: return emptyList()
    return listOf(
        UiText.ph(Placeholder.STORAGE_BYTES, sizeText(s.accountBytes.used), sizeText(s.accountBytes.limit)),
        UiText.ph(Placeholder.STORAGE_ITEMS, s.items.used.toString(), s.items.limit.toString()),
        UiText.ph(Placeholder.STORAGE_VAULTS, s.ownedSharedVaults.used.toString(), s.ownedSharedVaults.limit.toString()),
        UiText.ph(Placeholder.STORAGE_LINKS, s.openLinks.used.toString(), s.openLinks.limit.toString()),
    )
}

// ---- two-step sign-in ----

/** How often a set-up key on show is read again, so a key whose ten minutes ran out leaves the screen. */
internal const val TWO_STEP_KEY_REREAD_MS = 1_000L

/**
 * The lines beside a two-step set-up: with its key, the QR code's line and the typed key's line; once the key ran out
 * (the shared code gives none), the line that says so.
 */
internal fun twoStepKeyLines(key: io.silencelen.andvari.core.app.TwoStepKey?): List<Placeholder> =
    if (key != null) listOf(Placeholder.TWO_STEP_SCAN, Placeholder.TWO_STEP_TYPE_KEY) else listOf(Placeholder.TWO_STEP_KEY_GONE)

/**
 * Two-step sign-in. Closed: one button that asks the server ([io.silencelen.andvari.core.app.AccountSettingsApi.openTwoStep]).
 * Open and off: the master password starts an enrolment, whose key is read through `twoStepKey` (never from a
 * snapshot) and shown as a QR code and as typed text; the first code confirms it. Open and on: a current code turns it off.
 */
@Composable
internal fun TwoStepSection(model: TrustModel, s: AppSnapshot, twoStep: TwoStepScreen?) {
    SectionTitle(Placeholder.TWO_STEP_TITLE)
    if (twoStep == null) {
        Gap(4)
        Second(UiText.ph(Placeholder.TWO_STEP_OPEN), enabled = !s.busy) { model.run({ settings.openTwoStep() }) }
        return
    }
    var password by remember(twoStep) { mutableStateOf("") }
    var code by remember(twoStep) { mutableStateOf("") }
    Say(if (twoStep.enabled) Placeholder.TWO_STEP_ON else Placeholder.TWO_STEP_OFF)
    val enrolment = twoStep.enrolment
    when {
        enrolment != null -> {
            // The key lives only as long as this screen shows it; it is never in a snapshot. It is read again every
            // second: its ten minutes run out, and then the shared code no longer gives it.
            var key by remember(enrolment) { mutableStateOf(model.readOr(null) { model.api.settings.twoStepKey(enrolment) }) }
            LaunchedEffect(enrolment) {
                while (true) {
                    delay(TWO_STEP_KEY_REREAD_MS)
                    key = model.readOr(null) { model.api.settings.twoStepKey(enrolment) }
                }
            }
            val shown = key
            for (line in twoStepKeyLines(shown)) {
                Say(line)
                if (line == Placeholder.TWO_STEP_SCAN && shown != null) QrImage(shown.uri)
                if (line == Placeholder.TWO_STEP_TYPE_KEY && shown != null) {
                    Text(shown.secret.chunked(4).joinToString(" "), style = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace))
                }
            }
            // A key that ran out cannot be confirmed any more (the shared code answers NOT_PENDING): no code is asked,
            // and Close below is the way on.
            if (shown != null) {
                val submit = { if (code.isNotBlank() && !s.busy) code.let { c -> model.run({ settings.confirmTwoStep(enrolment, c) }) { code = "" } } }
                Field(UiText.ph(Placeholder.TWO_STEP_CODE_FIELD), code, mono = true, onEnter = { submit() }) { code = it }
                Main(UiText.ph(Placeholder.VERIFY_CODE), enabled = code.isNotBlank() && !s.busy, busy = s.busy) { submit() }
            }
        }
        twoStep.enabled -> {
            // Turning it off and getting a new key each ask for the master password with a current code (decided on
            // 2026-11-16). Both fields are emptied as the step is sent, whatever it answers: a wrong password, a wrong
            // code and "too many tries, wait" are each said in place in the shared code's words.
            MasterPasswordField(s, password) { password = it }
            Field(UiText.ph(Placeholder.TWO_STEP_CODE_FIELD), code, mono = true) { code = it }
            val ready = twoStepStepReady(password, code) && !s.busy
            Actions {
                Quieter(UiText.ph(Placeholder.TWO_STEP_NEW_KEY), enabled = ready) {
                    val c = code.trim()
                    val p = password
                    code = ""
                    password = ""
                    model.run({ settings.replaceTwoStepKey(twoStep, c, p) })
                }
                Quieter(UiText.ph(Placeholder.TURN_OFF), enabled = ready) {
                    val c = code.trim()
                    val p = password
                    code = ""
                    password = ""
                    model.run({ settings.turnOffTwoStepWithPassword(twoStep, c, p) })
                }
            }
        }
        else -> {
            MasterPasswordField(s, password) { password = it }
            Second(UiText.ph(Placeholder.TURN_ON), enabled = password.isNotEmpty() && !s.busy) {
                val p = password
                model.run({ settings.startTwoStep(twoStep, p) }) { password = "" }
            }
        }
    }
    Quieter(UiText.ph(Placeholder.CLOSE), enabled = !s.busy) { model.act { settings.closeTwoStep() } }
}

// ---- a new kit after a followed move ----

/**
 * After a followed move the kit names the old address: "Make a new kit" is `recovery.makeKit(password)` (the new kit
 * then shows as any other), "Later" is [io.silencelen.andvari.core.app.RecoveryApi.kitAfterMoveLater].
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

// ---- change master password ----

/** The slot under the repeated new password for "they differ". */
private val MISMATCH_SLOT = 28.dp

/** The box the device list scrolls in (about three devices). */
private val DEVICES_BOX = 240.dp

/** The lines under the recovery requests' list: the rows this device could not read, then a list not read at all. */
internal fun requestListLines(screen: io.silencelen.andvari.core.app.RecoveryScreen): List<UiText> =
    listOfNotNull(screen.unreadableLine?.let { UiText.of(it) }, screen.notReadLine?.let { UiText.of(it) })

/** Turning two-step sign-in off, or a new key, may be sent: the master password and a code are both typed. */
internal fun twoStepStepReady(password: String, code: String): Boolean = password.isNotEmpty() && code.isNotBlank()

/** The change can be asked for: all three fields typed and the new password typed the same twice. The floor is core's. */
internal fun passwordChangeReady(current: String, replacement: String, again: String): Boolean =
    current.isNotEmpty() && replacement.isNotEmpty() && replacement == again

/**
 * What a password change came to, one line per outcome: the current password is wrong; the new one is too weak (and
 * nothing was sent); it was changed elsewhere meanwhile; the server did not answer (so whether it changed is not
 * known: never "not changed"). Done says nothing here: [PASSWORD_CHANGED_LINES] are shown under the closed section.
 * Every other trouble is said as any intent's ([UiText.forResult]).
 */
internal fun passwordChangeLine(r: PasswordChangeResult, retryAfterSeconds: Int = 0): UiText? = when (r) {
    PasswordChangeResult.DONE -> null
    PasswordChangeResult.WRONG_PASSWORD -> UiText.ph(Placeholder.PASSWORD_CHANGE_WRONG)
    PasswordChangeResult.WEAK_PASSWORD -> UiText.ph(Placeholder.PASSWORD_CHANGE_WEAK)
    PasswordChangeResult.CHANGED_ELSEWHERE -> UiText.ph(Placeholder.PASSWORD_CHANGE_ELSEWHERE)
    PasswordChangeResult.UNREACHABLE -> UiText.ph(Placeholder.PASSWORD_CHANGE_NO_ANSWER)
    // In force at the server; this computer's copy could not follow: said under the closed section, never "try again".
    PasswordChangeResult.CHANGED_PREVIOUS_OPENS_HERE -> null
    else -> UiText.forResult(r, retryAfterSeconds)
}

/**
 * What the person is told once the password is changed but this computer's copy could not be wrapped under it
 * (`CHANGED_PREVIOUS_OPENS_HERE`): the new password is in force at the server, the previous one still opens the copy
 * here, and the other two lines hold as for a change that is done.
 */
internal val PASSWORD_CHANGED_PREVIOUS_OPENS_LINES: List<Placeholder> = listOf(
    Placeholder.PASSWORD_CHANGED_PREVIOUS_OPENS_HERE,
    Placeholder.PASSWORD_CHANGED_OTHERS_SIGNED_OUT,
    Placeholder.PASSWORD_CHANGED_KIT_STAYS,
)

/**
 * What the person is told once the password is changed (the app interface's contract for the change, design §7.8 and
 * R33): every other device was signed out; the recovery kit and any operator recovery still work (the account's key
 * did not change, so no new kit is due); this computer's copy now opens with the new password, the old one no longer.
 */
internal val PASSWORD_CHANGED_LINES: List<Placeholder> = listOf(
    Placeholder.PASSWORD_CHANGED,
    Placeholder.PASSWORD_CHANGED_OTHERS_SIGNED_OUT,
    Placeholder.PASSWORD_CHANGED_KIT_STAYS,
)

/**
 * Change master password (§7.8): names the account and the instance (§4.4), takes the current password and the new
 * one twice with the strength hints, and says that every other session ends while the kit and any operator recovery
 * stay valid. Each outcome is said in its own words ([passwordChangeLine]); once done, the section closes and says
 * what follows ([PASSWORD_CHANGED_LINES]) until the person dismisses it.
 */
@Composable
internal fun ChangePasswordSection(model: TrustModel, s: AppSnapshot, account: AccountSnapshot) {
    var open by remember { mutableStateOf(false) }
    var changed by remember(account.accountId) { mutableStateOf(false) }
    var previousOpensHere by remember(account.accountId) { mutableStateOf(false) }
    if (!open) {
        if (changed) {
            for (p in if (previousOpensHere) PASSWORD_CHANGED_PREVIOUS_OPENS_LINES else PASSWORD_CHANGED_LINES) Say(p)
            Quieter(UiText.ph(Placeholder.DISMISS)) { changed = false }
        }
        Quieter(UiText.ph(Placeholder.CHANGE_PASSWORD), enabled = !s.busy) { open = true; changed = false }
        return
    }
    var current by remember { mutableStateOf("") }
    var replacement by remember { mutableStateOf("") }
    var again by remember { mutableStateOf("") }
    SectionTitle(Placeholder.CHANGE_PASSWORD)
    s.instance?.let { Say(UiText.Plain(fillCopy(CopyKey.MASTER_PASSWORD_FOR, account.email, it.label.name, it.label.origin)), style = MaterialTheme.typography.bodySmall) }
    Quiet(UiText.ph(Placeholder.CHANGE_PASSWORD_EFFECT))
    SecretField(UiText.ph(Placeholder.PASSWORD_FIELD), current) { current = it }
    SecretField(UiText.ph(Placeholder.NEW_PASSWORD_FIELD), replacement) { replacement = it }
    MasterPasswordStrengthHints(replacement)
    SecretField(UiText.ph(Placeholder.NEW_PASSWORD_AGAIN_FIELD), again) { again = it }
    // In a slot of a fixed height: the button under it does not move while the field is typed in.
    FixedSlot(MISMATCH_SLOT) { if (again.isNotEmpty() && again != replacement) Quiet(UiText.ph(Placeholder.PASSWORDS_DIFFER)) }
    Main(UiText.ph(Placeholder.CHANGE_PASSWORD), enabled = passwordChangeReady(current, replacement, again) && !s.busy, busy = s.busy) {
        val c = current
        val r = replacement
        model.runSaying({ settings.changeMasterPassword(c, r) }, { passwordChangeLine(it, model.api.retryAfterSeconds()) }) { result ->
            current = ""
            val previous = result == PasswordChangeResult.CHANGED_PREVIOUS_OPENS_HERE
            if (result.done || previous) {
                replacement = ""
                again = ""
                open = false
                changed = true
                previousOpensHere = previous
            }
        }
    }
    Quieter(UiText.ph(Placeholder.CLOSE), enabled = !s.busy) { open = false }
}

// ---- delete account ----

/** One line per blocker; an unknown kind is shown as a blocker it cannot explain, and nothing goes past any of them. */
internal fun deletionBlockerLine(row: DeletionBlockerRow): UiText = when (row.kind) {
    DeletionBlockerKind.SHARED_VAULT_WITH_OTHERS -> UiText.phWith(Placeholder.DELETION_BLOCKER_SHARED, vaultSlot(row.vaultName), said(row.others.toString()))
    DeletionBlockerKind.OPERATOR_ACCOUNT -> UiText.ph(Placeholder.DELETION_BLOCKER_OPERATOR)
    DeletionBlockerKind.NOT_KNOWN -> UiText.ph(Placeholder.DELETION_BLOCKER_UNKNOWN)
}

/**
 * The typed address is the account's: trimmed and case-folded, as the server compares it (the account-deletion design,
 * §11 step 4: the button is enabled only once it matches; the server checks again, EMAIL_MISMATCH).
 */
internal fun deletionEmailMatches(screen: DeletionScreen, typedEmail: String): Boolean =
    typedEmail.trim().lowercase() == screen.email.trim().lowercase()

/**
 * The deletion may be asked for: the server's plan is in and has no blocker, nothing is retrying, the outcome of an
 * earlier request is known, the typed address matches the account's, the password is typed, and the code is typed when
 * the plan, or the server's last answer ([codeAsked]), asks for one.
 */
internal fun deletionReady(screen: DeletionScreen, typedEmail: String, password: String, code: String, codeAsked: Boolean = false): Boolean {
    val plan = screen.plan ?: return false
    return plan.canProceed && !screen.retrying && !screen.outcomeUnknown &&
        deletionEmailMatches(screen, typedEmail) && password.isNotEmpty() && (!(plan.codeNeeded || codeAsked) || code.isNotBlank())
}

/**
 * What a deletion request came to, one line per end. DONE says nothing here: the app is at the first screen, which
 * says the account was deleted (core's notice, [TrustModel.accountDeletedNotice]). OUTCOME_UNKNOWN says andvari cannot tell yet, never
 * "deleted" nor "not deleted". The two clock ends carry the design's own sentences.
 */
internal fun deletionLine(r: DeletionResult, retryAfterSeconds: Int = 0): UiText? = when (r) {
    DeletionResult.DONE -> null
    DeletionResult.EMAIL_MISMATCH -> UiText.ph(Placeholder.DELETION_EMAIL_MISMATCH)
    DeletionResult.WRONG_PASSWORD -> UiText.ph(Placeholder.DELETION_WRONG_PASSWORD)
    DeletionResult.CODE_NEEDED -> UiText.ph(Placeholder.DELETION_CODE_NEEDED)
    DeletionResult.WRONG_CODE -> UiText.ph(Placeholder.DELETION_WRONG_CODE)
    DeletionResult.BLOCKED -> UiText.ph(Placeholder.DELETION_BLOCKED)
    DeletionResult.STILL_CHANGING -> UiText.ph(Placeholder.DELETION_STILL_CHANGING)
    DeletionResult.CHANGED_ELSEWHERE -> UiText.ph(Placeholder.DELETION_CHANGED_ELSEWHERE)
    DeletionResult.OUTCOME_UNKNOWN -> UiText.ph(Placeholder.DELETION_OUTCOME_UNKNOWN)
    else -> UiText.forResult(r, retryAfterSeconds)
}

/**
 * What "Check whether it went through" came to. DONE: the server answered that the account is there, so nothing was
 * deleted. STALE with the app on the lock screen is the session's end, which cannot be told from a deletion: the lock
 * screen says so ([TrustModel.deletionCantTell]) and nothing is said here.
 */
internal fun deletionCheckLine(r: PlainResult, retryAfterSeconds: Int = 0): UiText? = when (r) {
    PlainResult.DONE -> UiText.ph(Placeholder.DELETION_STILL_THERE)
    PlainResult.STALE -> null
    else -> UiText.forResult(r, retryAfterSeconds)
}

/**
 * Delete account (the account-deletion design §11 on desktop): what deleting means and that it cannot be undone; the
 * server's plan (what goes for good, by name, and the shared vaults left with a signed leave each); the blockers, each
 * on its own line with no way past them; then the typed address, the master password and the two-step code when
 * needed. While the server's histories move on it says it is retrying by itself. An unknown outcome is never shown as
 * done or failed: the section says it cannot tell yet and offers the check, and keeps nothing else on offer.
 */
@Composable
internal fun DeleteAccountSection(model: TrustModel, s: AppSnapshot, account: AccountSnapshot) {
    val screen = account.deletion
    if (screen == null) {
        Quiet(UiText.ph(Placeholder.DELETION_WHAT))
        Quieter(UiText.ph(Placeholder.DELETE_ACCOUNT), enabled = !s.busy) { model.run({ settings.openDeletion() }) }
        return
    }
    var typedEmail by remember(screen.email) { mutableStateOf("") }
    var password by remember(screen.email) { mutableStateOf("") }
    var code by remember(screen.email) { mutableStateOf("") }
    // The server asked for the code although the plan did not (two-step turned on elsewhere since): it stays asked.
    var codeAsked by remember(screen.email) { mutableStateOf(false) }
    SectionTitle(Placeholder.DELETE_ACCOUNT)
    val plan = screen.plan
    when {
        screen.outcomeUnknown -> {
            Say(Placeholder.DELETION_OUTCOME_UNKNOWN, style = MaterialTheme.typography.bodyMedium)
            Second(UiText.ph(Placeholder.DELETION_CHECK), enabled = !s.busy) { model.checkDeletion(screen) }
            ForgetUnknownDeletionOffer(model, s)
        }
        plan == null -> Quiet(UiText.ph(Placeholder.WORKING))
        else -> {
            Say(Placeholder.DELETION_CANNOT_UNDO)
            if (screen.retrying) Quiet(UiText.ph(Placeholder.DELETION_RETRYING))
            if (plan.deletedVaults.isNotEmpty()) Say(UiText.ph(Placeholder.DELETION_GOES, plan.deletedVaults.joinToString { vaultNameOrUnreadable(it) }))
            if (plan.leftVaults.isNotEmpty()) Say(UiText.ph(Placeholder.DELETION_LEAVES, plan.leftVaults.joinToString { vaultNameOrUnreadable(it) }))
            for (b in plan.blockers) Say(deletionBlockerLine(b), color = MaterialTheme.colorScheme.error)
            if (plan.canProceed) {
                Quiet(UiText.ph(Placeholder.DELETION_BACK_UP_FIRST))
                Field(UiText.ph(Placeholder.DELETION_TYPE_EMAIL, screen.email), typedEmail) { typedEmail = it }
                MasterPasswordField(s, password) { password = it }
                val codeWanted = plan.codeNeeded || codeAsked
                // A code the plan asked for stands with the other fields; one the server asks for only after a try comes
                // under the button, so the button the person just used does not move under the pointer.
                val codeLate = codeWanted && !plan.codeNeeded
                if (codeWanted && !codeLate) Field(UiText.ph(Placeholder.TWO_STEP_CODE_FIELD), code, mono = true) { code = it }
                Main(UiText.ph(Placeholder.DELETION_CONFIRM), enabled = deletionReady(screen, typedEmail, password, code, codeAsked) && !s.busy, busy = s.busy) {
                    val e = typedEmail
                    val p = password
                    val c = code.takeIf { codeWanted }
                    model.deleteAccount(screen, e, p, c) { r ->
                        password = ""
                        if (r == DeletionResult.CODE_NEEDED) codeAsked = true
                        if (r == DeletionResult.WRONG_CODE) code = ""
                    }
                }
                if (codeLate) Field(UiText.ph(Placeholder.TWO_STEP_CODE_FIELD), code, mono = true) { code = it }
            }
        }
    }
    Quieter(UiText.ph(Placeholder.CLOSE), enabled = !s.busy) { model.act { settings.closeDeletion() } }
}

/** A vault whose name this device cannot read comes as `""` (the app interface's note): it is said so, not left blank. */
internal fun vaultNameOrUnreadable(name: String): String = name.ifEmpty { UiText.ph(Placeholder.VAULT_NAME_UNREADABLE).shown() }

// ---- your devices, and adding a device from this computer ----

/** This device first, then the rest as the server lists them. */
internal fun devicesInOrder(screen: DevicesScreen): List<DeviceRow> = screen.devices.sortedByDescending { it.current }

/** How a device joined: registered, password, linked from which device, recovered. */
internal fun howJoinedLine(row: DeviceRow): UiText = when (row.how) {
    HowDeviceJoined.REGISTERED -> UiText.ph(Placeholder.DEVICE_JOINED_REGISTERED)
    HowDeviceJoined.PASSWORD -> UiText.ph(Placeholder.DEVICE_JOINED_PASSWORD)
    HowDeviceJoined.LINKED -> UiText.ph(Placeholder.DEVICE_JOINED_LINKED, row.linkedFrom)
    HowDeviceJoined.RECOVERED -> UiText.ph(Placeholder.DEVICE_JOINED_RECOVERED)
    HowDeviceJoined.NOT_KNOWN -> UiText.ph(Placeholder.DEVICE_JOINED_NOT_KNOWN)
}

/**
 * Revoke is offered for every device but this one, live or not (a device that is not live may still hold a session the
 * server would honour), and only with the master password.
 */
internal fun canRevoke(row: DeviceRow): Boolean = !row.current

/**
 * What "New devices must be linked from one of mine" offers: while its state is known, the one answer that changes
 * it; while it is not (`requireLinkKnown` false: the server serves no read of it, so only what this device set during
 * this session is known), the switch has no state and both answers are offered.
 */
/** How "New devices must be linked" stands: on, off, or not known on this computer. */
internal fun requireLinkState(screen: DevicesScreen): Placeholder = when {
    !screen.requireLinkKnown -> Placeholder.DEVICE_REQUIRE_LINK_NOT_KNOWN
    screen.requireLink -> Placeholder.DEVICE_REQUIRE_LINK_IS_ON
    else -> Placeholder.DEVICE_REQUIRE_LINK_IS_OFF
}

internal fun requireLinkChoices(screen: DevicesScreen): List<Boolean> = if (screen.requireLinkKnown) listOf(!screen.requireLink) else listOf(true, false)

/**
 * The six digits typed from the new device may be submitted: exactly six digits (§8.2, after the pin: a code that is
 * not six digits is a mismatch, so the control waits for six). There is no other way to confirm.
 */
internal fun deviceDigitsReady(digits: String): Boolean = digits.replace(" ", "").let { d -> d.length == 6 && d.all { it in '0'..'9' } }

/**
 * How this computer's device link ended without an approval: the design's "Linking was cancelled" where core gives it
 * (cancelled here or by a newer link; a mismatch of the typed digits), a line of its own for the two it gives no words.
 */
internal fun deviceLinkEndLine(outcome: DeviceLinkHostEnd): UiText = outcome.sentence?.let { UiText.of(it) } ?: when (outcome) {
    DeviceLinkHostEnd.EXPIRED -> UiText.ph(Placeholder.DEVICE_LINK_EXPIRED)
    DeviceLinkHostEnd.DID_NOT_CHECK_OUT -> UiText.ph(Placeholder.DEVICE_LINK_DID_NOT_CHECK_OUT)
    else -> UiText.ph(Placeholder.REFUSAL, "DeviceLinkHostEnd." + outcome.name)
}

/**
 * [host]'s end as drawn: its own line where the shared code hands one ([DeviceLinkHost.Ended.line]: too many requests,
 * with the wait), in place of the outcome's, which would say "a check failed"; otherwise [deviceLinkEndLine].
 */
internal fun deviceLinkHostEndText(host: DeviceLinkHost.Ended, retryAfterSeconds: Int): UiText =
    host.line?.let { UiText.filled(it, waitText(retryAfterSeconds).shown()) } ?: deviceLinkEndLine(host.outcome)

/**
 * The digits or the approval refused as one of too many requests, which ended the link this computer shows: the ended
 * link's own line says it, with the wait ([deviceLinkHostEndText]), so nothing is said in place beside it.
 */
internal fun endedLinkSaysIt(r: io.silencelen.andvari.core.app.IntentResult, s: AppSnapshot): Boolean =
    (r === io.silencelen.andvari.core.app.DigitsResult.RATE_LIMITED || r === ProofResult.RATE_LIMITED) &&
        (s.account?.deviceLink as? DeviceLinkHost.Ended)?.line != null

/** The approval's answers: a wrong master password is said as such (nothing was approved, the link waits). */
internal fun deviceLinkApproveLine(r: ProofResult, retryAfterSeconds: Int = 0): UiText? = when (r) {
    ProofResult.WRONG_PASSWORD -> UiText.ph(Placeholder.DEVICE_LINK_WRONG_PASSWORD)
    else -> UiText.forResult(r, retryAfterSeconds)
}

/** The countdown as minutes and seconds, from the milliseconds core counts on a clock the person cannot set. */
internal fun countdown(ms: Long): String {
    val s = (maxOf(0L, ms) + 999) / 1000
    return "%d:%02d".format(s / 60, s % 60)
}

/**
 * Your devices: this device first; how each joined; live or not; revoke with the master password, never for this
 * device; "New devices must be linked from one of mine" (with the password). Below it, "Add a device", the approving
 * side of a device link ([DeviceLinkHostView]).
 */
@Composable
internal fun DevicesSection(model: TrustModel, s: AppSnapshot, account: AccountSnapshot) {
    // Leaving the screen the link is shown on (another page, the kit, a lock) cancels a link still running; a lock and
    // a session's end cancel it in core as well ([TrustModel.leftDeviceLink]).
    DisposableEffect(Unit) { onDispose { model.leftDeviceLink() } }
    account.deviceLink?.let { DeviceLinkHostView(model, s, it) }
    val screen = account.devices
    if (screen == null) return ClosedSection(Placeholder.DEVICES, enabled = !s.busy) { model.run({ devices.openDevices() }) }
    var password by remember { mutableStateOf("") }
    SectionTitle(Placeholder.DEVICES)
    // §4.4, always on this screen: revoking stops a device syncing and does not wipe it (core's key, awaiting wording).
    Quiet(UiText.of(screen.revokeLine))
    val date = DateFormat.getDateInstance(DateFormat.MEDIUM)
    // The list in a box of a fixed height: a read that adds or drops a device does not move the password field under it.
    ListBox(DEVICES_BOX) {
        for (row in devicesInOrder(screen)) {
            Text(row.name + "  ·  " + row.platform.wireName + (if (row.current) "  ·  " + UiText.ph(Placeholder.DEVICE_THIS_ONE).shown() else ""), style = MaterialTheme.typography.bodyMedium)
            Quiet(howJoinedLine(row))
            Quiet(UiText.ph(if (row.live) Placeholder.DEVICE_LIVE else Placeholder.DEVICE_NOT_LIVE, date.format(Date(row.addedAtMs)), date.format(Date(row.lastSeenAtMs)), row.clientVersion))
            if (canRevoke(row)) {
                Quieter(UiText.ph(Placeholder.DEVICE_REVOKE), enabled = password.isNotEmpty() && !s.busy) {
                    val p = password
                    model.run({ devices.revokeDevice(row, p) }) { if (it.done) password = "" }
                }
            }
        }
    }
    // One password field for the actions that need it: revoking a device, and the switch.
    MasterPasswordField(s, password) { password = it }
    // The setting: its name, what it does, how it stands, then the button that changes it.
    Say(Placeholder.DEVICE_REQUIRE_LINK_TITLE, style = MaterialTheme.typography.titleSmall)
    Quiet(UiText.ph(Placeholder.DEVICE_REQUIRE_LINK_BODY))
    Say(requireLinkState(screen))
    for (next in requireLinkChoices(screen)) {
        Second(UiText.ph(if (next) Placeholder.DEVICE_REQUIRE_LINK_ON else Placeholder.DEVICE_REQUIRE_LINK_OFF), enabled = password.isNotEmpty() && !s.busy) {
            val p = password
            model.run({ devices.setRequireLink(next, p) }) { if (it.done) password = "" }
        }
    }
    if (account.deviceLink == null) {
        Second(UiText.ph(Placeholder.DEVICE_ADD), enabled = !s.busy) { model.run({ devices.startDeviceLink() }) }
    }
    Quieter(UiText.ph(Placeholder.CLOSE), enabled = !s.busy) { model.act { devices.closeDevices() } }
}

/**
 * This computer as the approving device (§8.2). It shows the link as a QR code and as text to paste on a computer
 * without a camera ("the existing device offers Share link", D:1712; a desktop shares it by showing it). This side
 * never shows a code and has no confirm-without-typing control: the six digits are typed here from the new device, a
 * mismatch cancels the link, and approval is by master password only (no quick unlock on desktop). The countdown reads
 * [io.silencelen.andvari.core.app.DevicesApi.deviceLinkTimeLeftMs], never the computer's clock.
 */
@Composable
internal fun DeviceLinkHostView(model: TrustModel, s: AppSnapshot, host: DeviceLinkHost) {
    when (host) {
        is DeviceLinkHost.Shown -> {
            Say(host.line)
            val link = remember(host) { model.api.devices.deviceLinkToShow(host) }
            if (link != null) {
                QrImage(link)
                Text(link, style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace))
            }
            var left by remember(host) { mutableLongStateOf(model.readOr(0L) { model.api.devices.deviceLinkTimeLeftMs() }) }
            LaunchedEffect(host) {
                while (true) {
                    left = model.readOr(0L) { model.api.devices.deviceLinkTimeLeftMs() }
                    delay(1_000)
                }
            }
            Quiet(UiText.ph(Placeholder.DEVICE_LINK_TIME_LEFT, countdown(left)))
            Quieter(UiText.of(CopyKey.CANCEL), enabled = !s.busy) { model.run({ devices.cancelDeviceLink() }) }
        }
        is DeviceLinkHost.Claimed -> {
            Say(UiText.ph(Placeholder.DEVICE_LINK_CLAIMED, host.deviceName, host.platform.wireName))
            LinkCountdown(model, host)
            Quieter(UiText.of(CopyKey.CANCEL), enabled = !s.busy) { model.run({ devices.cancelDeviceLink() }) }
        }
        is DeviceLinkHost.TypeDigits -> {
            var digits by remember(host) { mutableStateOf("") }
            val submit = { if (deviceDigitsReady(digits) && !s.busy) digits.let { d -> model.run({ devices.submitDeviceDigits(host, d) }) { digits = "" } } }
            Say(host.line)
            Field(UiText.ph(Placeholder.CODE_FIELD), digits, mono = true, onEnter = { submit() }) { digits = it }
            Main(UiText.ph(Placeholder.VERIFY_CODE), enabled = deviceDigitsReady(digits) && !s.busy, busy = s.busy) { submit() }
            LinkCountdown(model, host)
            Quieter(UiText.of(CopyKey.CANCEL), enabled = !s.busy) { model.run({ devices.cancelDeviceLink() }) }
        }
        is DeviceLinkHost.Approvable -> {
            var password by remember(host) { mutableStateOf("") }
            Say(UiText.ph(Placeholder.DEVICE_LINK_APPROVE, host.deviceName, host.platform.wireName))
            // The master password only: the desktop has no quick unlock, so the biometric approval is never offered.
            MasterPasswordField(s, password) { password = it }
            Main(UiText.ph(Placeholder.DEVICE_LINK_APPROVE_BUTTON), enabled = password.isNotEmpty() && !s.busy, busy = s.busy) {
                val p = password
                model.runSaying({ devices.approveWithPassword(host, p) }, { deviceLinkApproveLine(it, model.api.retryAfterSeconds()) }) { password = "" }
            }
            LinkCountdown(model, host)
            Quieter(UiText.of(CopyKey.CANCEL), enabled = !s.busy) { model.run({ devices.cancelDeviceLink() }) }
        }
        is DeviceLinkHost.Approved -> {
            Say(UiText.ph(Placeholder.DEVICE_LINK_APPROVED, host.deviceName))
            Quieter(UiText.ph(Placeholder.DISMISS)) { model.act { devices.dismissDeviceLink() } }
        }
        is DeviceLinkHost.Ended -> {
            Say(deviceLinkHostEndText(host, model.readOr(0) { model.api.retryAfterSeconds() }))
            Quieter(UiText.ph(Placeholder.DISMISS)) { model.act { devices.dismissDeviceLink() } }
        }
    }
    HorizontalDivider()
}

/** How long the link's current step still has (each step has its own five minutes, §8.2's table). */
@Composable
private fun LinkCountdown(model: TrustModel, host: DeviceLinkHost) {
    var left by remember(host) { mutableLongStateOf(model.readOr(0L) { model.api.devices.deviceLinkTimeLeftMs() }) }
    LaunchedEffect(host) {
        while (true) {
            left = model.readOr(0L) { model.api.devices.deviceLinkTimeLeftMs() }
            delay(1_000)
        }
    }
    Quiet(UiText.ph(Placeholder.DEVICE_LINK_TIME_LEFT, countdown(left)))
}

// ---- recovery ----

/** Who can recover the account, in the design's own words. */
internal fun whoCanRecoverLine(screen: RecoveryScreen): UiText = when (screen.whoCanRecover) {
    WhoCanRecover.ONLY_ME -> UiText.of(CopyKey.RECOVERY_ONLY_ME)
    WhoCanRecover.ME_OR_OPERATOR -> screen.question?.let { UiText.of(it.meOrOperator) } ?: UiText.ph(Placeholder.RECOVERY_ME_OR_OPERATOR)
}

/**
 * A live request, in the shared code's row line ([io.silencelen.andvari.core.app.AccountPrompt.RecoveryRequest.rowLine]):
 * {0} when it was asked, {1} the kind of device as the server says it, {2} when the wait ends.
 */
internal fun requestDetailLine(rowLine: CopyKey, r: RecoveryRequestRow): UiText {
    val d = DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT)
    return keyLine(rowLine, d.format(Date(r.askedAtMs)), r.reportedPlatform.wireName, d.format(Date(r.holdEndsAtMs)))
}

/** What a request's flags say, each in the shared code's words: answered by the operator, a wait cut short, a cancel the server did not take. */
internal fun requestFlagKeys(answered: Boolean, holdCutShort: Boolean, cancelNotTaken: Boolean): List<CopyKey> = buildList {
    if (answered) add(CopyKey.RECOVERY_REQUEST_ANSWERED)
    if (holdCutShort) add(CopyKey.RECOVERY_REQUEST_HOLD_CUT_SHORT)
    if (cancelNotTaken) add(CopyKey.RECOVERY_REQUEST_CANCEL_NOT_TAKEN)
}

internal fun requestFlags(r: RecoveryRequestRow): List<CopyKey> = requestFlagKeys(r.answered, r.holdCutShort, r.cancelNotTaken)

/**
 * Recovery: who can recover; the choice where offered (`question` null on the public instance, without a recovery
 * key, or for the operator account); the warning before turning operator recovery on, with its tick; turning it off
 * with the design's note; "Make a new recovery kit" (then the kit, as any other); live requests with "cancel".
 */
@Composable
internal fun RecoverySection(model: TrustModel, s: AppSnapshot, account: AccountSnapshot) {
    val screen = account.recovery
    if (screen == null) return ClosedSection(Placeholder.RECOVERY_SETTINGS, enabled = !s.busy) { model.run({ recovery.openRecovery() }) }
    var password by remember { mutableStateOf("") }
    SectionTitle(Placeholder.RECOVERY_SETTINGS)
    Say(whoCanRecoverLine(screen))
    if (screen.requests.isNotEmpty()) {
        Say(CopyKey.RECOVERY_REQUEST_ALERT, color = MaterialTheme.colorScheme.error)
        for (r in screen.requests) {
            Quiet(requestDetailLine(CopyKey.RECOVERY_REQUEST_DETAILS, r))
            for (flag in requestFlags(r)) Say(UiText.of(flag), color = MaterialTheme.colorScheme.error)
            Second(UiText.of(CopyKey.CANCEL), enabled = !s.busy) { model.run({ recovery.cancelRecoveryRequest(r) }) }
        }
    }
    // The requests this device could not read, and a list that could not be read at all, as the two lines under the
    // list: a short or empty list is never read as "nobody asked".
    for (line in requestListLines(screen)) Say(line, color = MaterialTheme.colorScheme.error)
    val warning = screen.warning
    val question = screen.question
    when {
        warning != null -> OperatorRecoveryWarningView(model, s, warning)
        screen.whoCanRecover == WhoCanRecover.ME_OR_OPERATOR -> Quiet(UiText.of(CopyKey.RECOVERY_TURN_OFF_NOTE))
        question != null -> Second(UiText.of(question.meOrOperator), enabled = !s.busy) { model.act { recovery.reviewOperatorRecovery(screen) } }
    }
    if (warning == null) {
        // One password field for the two actions that need it here.
        MasterPasswordField(s, password) { password = it }
        if (screen.whoCanRecover == WhoCanRecover.ME_OR_OPERATOR) {
            Second(UiText.ph(Placeholder.TURN_OFF), enabled = password.isNotEmpty() && !s.busy) {
                val p = password
                model.run({ recovery.turnOffOperatorRecovery(screen, p) }) { password = "" }
            }
        }
        Second(UiText.ph(Placeholder.KIT_AFTER_MOVE_MAKE), enabled = password.isNotEmpty() && !s.busy) {
            val p = password
            model.run({ recovery.makeKit(p) }) { password = "" }
        }
    }
    Quieter(UiText.ph(Placeholder.CLOSE), enabled = !s.busy) { model.act { recovery.closeRecovery() } }
}

/** The warning before operator recovery is turned on: its title and paragraphs, the tick, the password, "keep it private". */
@Composable
private fun OperatorRecoveryWarningView(model: TrustModel, s: AppSnapshot, warning: OperatorRecoveryWarning) {
    var understood by remember(warning) { mutableStateOf(false) }
    var password by remember(warning) { mutableStateOf("") }
    Column {
        warning.takeoverTitle?.let { Say(it, color = MaterialTheme.colorScheme.error) }
        Say(warning.title, style = MaterialTheme.typography.titleSmall)
        for (p in warning.paragraphs) Say(p)
        Tick(UiText.of(warning.understand), understood) { understood = it }
        MasterPasswordField(s, password) { password = it }
        Main(UiText.of(warning.turnOn), enabled = understood && password.isNotEmpty() && !s.busy, busy = s.busy) {
            val p = password
            model.run({ recovery.turnOnOperatorRecovery(warning, understood, p) }) { password = "" }
        }
        Quieter(UiText.of(warning.keepPrivate), enabled = !s.busy) { model.act { recovery.keepRecoveryPrivate(warning) } }
    }
}
