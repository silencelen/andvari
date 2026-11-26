package io.silencelen.andvari.app.trust

import androidx.compose.foundation.layout.Row
import androidx.compose.material3.Checkbox
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import io.silencelen.andvari.app.SecretField
import io.silencelen.andvari.core.app.AccountPrompt
import io.silencelen.andvari.core.app.AccountSnapshot
import io.silencelen.andvari.core.app.AppSnapshot
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.OperatorHelpStage
import io.silencelen.andvari.core.app.OperatorRecoveryWarning
import io.silencelen.andvari.core.app.RecoveryRequestRow
import io.silencelen.andvari.core.app.RecoveryScreen
import io.silencelen.andvari.core.app.WhoCanRecover
import java.text.DateFormat
import java.util.Date

/** Who can recover the account, in the design's own words. */
/** The two lines under the list of requests, in the shared code's words: some could not be shown; none could be read. */
internal fun requestListLines(screen: RecoveryScreen): List<UiText> =
    listOfNotNull(screen.unreadableLine?.let { UiText.of(it) }, screen.notReadLine?.let { UiText.of(it) })

internal fun whoCanRecoverLine(screen: RecoveryScreen): UiText = when (screen.whoCanRecover) {
    WhoCanRecover.ONLY_ME -> UiText.of(CopyKey.RECOVERY_ONLY_ME)
    WhoCanRecover.ME_OR_OPERATOR -> screen.question?.let { UiText.of(it.meOrOperator) } ?: UiText.ph(Placeholder.RECOVERY_ME_OR_OPERATOR)
}

/** A live request: its stage, its times, and the platform it reported, marked as reported. */
internal fun requestLine(r: RecoveryRequestRow): UiText {
    return UiText.ph(Placeholder.RECOVERY_REQUEST_ROW, requestRowStage(r.stage).shown(), Dates.dateTime(r.askedAtMs), Dates.dateTime(r.holdEndsAtMs), r.reportedPlatform.wireName)
}

/**
 * A live request's stage in the list on the account's own devices, as a stage's name only: the request may be a
 * stranger's, no code is shown here, and the server may have cut the wait short. The shared code lists a request in
 * its wait or past it (anything not in its wait is past it, as the shared code reads the server's state).
 */
internal fun requestRowStage(stage: OperatorHelpStage): UiText =
    UiText.ph(if (stage == OperatorHelpStage.HOLDING) Placeholder.RECOVERY_ROW_STAGE_HOLDING else Placeholder.RECOVERY_ROW_STAGE_AWAITING_OPERATOR)

/**
 * §9.3, the alert on the account's own signed-in devices: under each request, when it was made ({0}), the kind of
 * device the server says it came from ({1}), and when the wait ends ({2}), in the shared code's sentence.
 */
internal fun alertRowLine(p: AccountPrompt.RecoveryRequest, r: RecoveryRequestRow): UiText =
    UiText.of(p.rowLine, Dates.dateTime(r.askedAtMs), r.reportedPlatform.wireName, Dates.dateTime(r.holdEndsAtMs))

/**
 * What a request's flags say, each in the shared code's sentence and in this order: the operator already answered it,
 * the server lets its wait end early, a cancel the server said it took and still lists. Empty when none holds.
 */
internal fun requestFlagLines(answered: Boolean, holdCutShort: Boolean, cancelNotTaken: Boolean): List<UiText> = listOfNotNull(
    if (answered) UiText.of(CopyKey.RECOVERY_REQUEST_ANSWERED) else null,
    if (holdCutShort) UiText.of(CopyKey.RECOVERY_REQUEST_HOLD_CUT_SHORT) else null,
    if (cancelNotTaken) UiText.of(CopyKey.RECOVERY_REQUEST_CANCEL_NOT_TAKEN) else null,
)

internal fun requestFlagLines(r: RecoveryRequestRow): List<UiText> = requestFlagLines(r.answered, r.holdCutShort, r.cancelNotTaken)

/**
 * The alert's lines above its rows: the alert itself, then, when the server says there is a request this device could
 * not read, [CopyKey.RECOVERY_REQUEST_UNREADABLE] (Settings' recovery screen is offered under it).
 */
internal fun alertLines(p: AccountPrompt.RecoveryRequest): List<UiText> = alertLines(p.line, p.unreadable)

internal fun alertLines(line: CopyKey, unreadable: Boolean): List<UiText> =
    listOfNotNull(UiText.of(line), if (unreadable) UiText.of(CopyKey.RECOVERY_REQUEST_UNREADABLE) else null)

/**
 * The alert for a request for the operator's help on this signed-in device (§9.3): the alert and, when the request
 * could not be read, that line and the way to Settings' recovery screen; each request with its details, its flags (in
 * the error colour) and Cancel; then "This was me", which takes the alert away for these requests on this device.
 */
@Composable
internal fun RecoveryRequestAlert(model: TrustModel, s: AppSnapshot, p: AccountPrompt.RecoveryRequest) {
    val lines = alertLines(p)
    Say(lines.first(), color = MaterialTheme.colorScheme.error)
    if (p.unreadable) {
        Say(lines[1], color = MaterialTheme.colorScheme.error)
        Second(UiText.ph(Placeholder.RECOVERY_SETTINGS), enabled = !s.busy) { model.run({ recovery.openRecovery() }) }
    }
    for (r in p.requests) {
        Quiet(alertRowLine(p, r))
        for (line in requestFlagLines(r)) Say(line, color = MaterialTheme.colorScheme.error)
        Second(UiText.of(CopyKey.CANCEL), enabled = !s.busy) { model.run({ recovery.cancelRecoveryRequest(r) }) }
    }
    if (p.requests.isNotEmpty()) Quieter(UiText.of(p.wasMe), enabled = !s.busy) { model.act { recovery.recoveryRequestWasMe(p) } }
}

/**
 * §4.5 (FS-R2, FC-2): the takeover warning, when a change of the recovery key is not covered by a statement the old
 * key signed: its title and [CopyKey.RECOVERY_KEY_CHANGED_BODY], with the choice and on the warning alike. Empty
 * otherwise.
 */
internal fun takeoverLines(title: io.silencelen.andvari.core.app.CopyLine?): List<UiText> =
    if (title == null) emptyList() else listOf(UiText.of(title), UiText.of(CopyKey.RECOVERY_KEY_CHANGED_BODY))

/**
 * What Settings › Recovery shows for a screen the API gave, in order (pure, so every state is walked in a test):
 * the takeover warning, then who can recover, then what is offered.
 */
internal enum class RecoveryOffer { WARNING, TURN_OFF, CHOICE, NOTHING }

internal fun recoveryOffer(screen: RecoveryScreen): RecoveryOffer = when {
    screen.warning != null -> RecoveryOffer.WARNING
    screen.whoCanRecover == WhoCanRecover.ME_OR_OPERATOR -> RecoveryOffer.TURN_OFF
    screen.question != null -> RecoveryOffer.CHOICE
    else -> RecoveryOffer.NOTHING
}

/**
 * Settings › Recovery (map §3.16): who can recover; the choice where offered (none on the public instance, without a
 * recovery key, or for the operator account: `question` is null); the warning before turning operator recovery on,
 * with its tick; turning it off with the design's note; "Make a new recovery kit" (then the kit, as any other); live
 * requests with "cancel". Opening it reads the posture from the server first, so it can answer UNREACHABLE: that is
 * said above the page (SaidHere) and the button stays. The two recovery prompts (`KeepOperatorRecovery`,
 * `RecoveryKeyChanged`) are answered from the prompts list (PeopleScreens' `PromptView`).
 */
@Composable
internal fun RecoverySection(model: TrustModel, s: AppSnapshot, account: AccountSnapshot) {
    SectionDivider()
    val screen = account.recovery
    if (screen == null) {
        Quieter(UiText.ph(Placeholder.RECOVERY_SETTINGS), enabled = !s.busy) { model.run({ recovery.openRecovery() }) }
        return
    }
    var password by remember { mutableStateOf("") }
    Say(Placeholder.RECOVERY_SETTINGS, style = sectionTitleStyle())
    if (screen.warning == null) {
        for (line in takeoverLines(screen.question?.takeoverTitle)) Say(line, color = MaterialTheme.colorScheme.error)
    }
    Say(whoCanRecoverLine(screen))
    if (screen.requests.isNotEmpty()) {
        Say(CopyKey.RECOVERY_REQUEST_ALERT, color = MaterialTheme.colorScheme.error)
        for (r in screen.requests) {
            Quiet(requestLine(r))
            for (line in requestFlagLines(r)) Say(line, color = MaterialTheme.colorScheme.error)
            Quieter(UiText.of(CopyKey.CANCEL), enabled = !s.busy) { model.run({ recovery.cancelRecoveryRequest(r) }) }
        }
    }
    // Under the list: the requests this device could not show, and a list that could not be read at all.
    for (line in requestListLines(screen)) Say(line, color = MaterialTheme.colorScheme.error)
    val warning = screen.warning
    when (recoveryOffer(screen)) {
        RecoveryOffer.WARNING -> OperatorRecoveryWarningView(model, s, warning!!)
        RecoveryOffer.TURN_OFF -> Quiet(UiText.of(CopyKey.RECOVERY_TURN_OFF_NOTE))
        RecoveryOffer.CHOICE -> Second(UiText.of(screen.question!!.meOrOperator), enabled = !s.busy) { model.act { recovery.reviewOperatorRecovery(screen) } }
        RecoveryOffer.NOTHING -> Unit
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

/** The warning before operator recovery is turned on: its title and paragraphs, the tick, the password, and "keep it private". */
@Composable
private fun OperatorRecoveryWarningView(model: TrustModel, s: AppSnapshot, warning: OperatorRecoveryWarning) {
    var understood by remember(warning) { mutableStateOf(false) }
    var password by remember(warning) { mutableStateOf("") }
    for (line in takeoverLines(warning.takeoverTitle)) Say(line, color = MaterialTheme.colorScheme.error)
    Say(warning.title, style = MaterialTheme.typography.titleSmall)
    for (p in warning.paragraphs) Say(p)
    Row(verticalAlignment = Alignment.CenterVertically) {
        Checkbox(checked = understood, onCheckedChange = { understood = it })
        Say(warning.understand)
    }
    MasterPasswordField(s, password) { password = it }
    Main(UiText.of(warning.turnOn), enabled = understood && password.isNotEmpty() && !s.busy, busy = s.busy) {
        val p = password
        model.run({ recovery.turnOnOperatorRecovery(warning, understood, p) }) { password = "" }
    }
    Quieter(UiText.of(warning.keepPrivate), enabled = !s.busy) { model.act { recovery.keepRecoveryPrivate(warning) } }
}
