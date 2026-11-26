package io.silencelen.andvari.app.trust

import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.size
import androidx.compose.material3.HorizontalDivider
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
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.FilterQuality
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import io.silencelen.andvari.app.AuthColumn
import io.silencelen.andvari.app.SecretField
import io.silencelen.andvari.core.app.AccountSnapshot
import io.silencelen.andvari.core.app.AppSnapshot
import io.silencelen.andvari.core.app.DeviceLinkHost
import io.silencelen.andvari.core.app.DeviceLinkHostEnd
import io.silencelen.andvari.core.app.DigitsResult
import io.silencelen.andvari.core.app.ProofResult
import io.silencelen.andvari.core.app.DeviceRow
import io.silencelen.andvari.core.app.DevicesScreen
import io.silencelen.andvari.core.app.HowDeviceJoined
import kotlinx.coroutines.delay
import java.text.DateFormat
import java.util.Date

/** This device first, then the rest as the server lists them (map §3.17). */
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
 * Revoke is offered for every device but this one, live or not (l2b-13: a device the server lists as not live is
 * still one the account knows), and only with the master password.
 */
internal fun canRevoke(row: DeviceRow): Boolean = !row.current

/**
 * The switch "New devices must be linked from one of mine" as it can be offered: the state when this device set it
 * in this session ([DevicesScreen.requireLinkKnown]), else no state and both "on" and "off" (the server serves no
 * read of the setting).
 */
internal fun requireLinkChoices(screen: DevicesScreen): List<Boolean> = when {
    !screen.requireLinkKnown -> listOf(true, false)
    screen.requireLink -> listOf(false)
    else -> listOf(true)
}

/**
 * How the switch stands, as this device knows it: not known (the server serves no read of the setting), on, or off.
 * Each state has its own line; the setting's explanation is a line of its own above it ([Placeholder.DEVICE_REQUIRE_LINK_BODY]).
 */
internal fun requireLinkState(screen: DevicesScreen): Placeholder = when {
    !screen.requireLinkKnown -> Placeholder.DEVICE_REQUIRE_LINK_UNKNOWN
    screen.requireLink -> Placeholder.DEVICE_REQUIRE_LINK_IS_ON
    else -> Placeholder.DEVICE_REQUIRE_LINK_IS_OFF
}

/**
 * Settings › Your devices (map §3.17): this device first; how each joined; live or not; revoke with the master password,
 * never for this device; the switch "New devices must be linked from one of mine" (with the password). Below it,
 * "Add a device", the approving side of a device link ([DeviceLinkHostView]).
 */
@Composable
internal fun DevicesSection(model: TrustModel, s: AppSnapshot, account: AccountSnapshot) {
    SectionDivider()
    val screen = account.devices
    if (screen == null) {
        Quieter(UiText.ph(Placeholder.DEVICES), enabled = !s.busy) { model.run({ devices.openDevices() }) }
        return
    }
    var password by remember { mutableStateOf("") }
    Say(Placeholder.DEVICES, style = sectionTitleStyle())
    // Always on Devices (§4.4): revoking a lost device stops it syncing, it does not wipe it (awaiting the owner's words).
    Quiet(UiText.of(screen.revokeLine))
    for (row in devicesInOrder(screen)) {
        Text(row.name + "  ·  " + row.platform.wireName + (if (row.current) "  ·  " + UiText.ph(Placeholder.DEVICE_THIS_ONE).shown() else ""), style = MaterialTheme.typography.bodyMedium)
        Quiet(howJoinedLine(row))
        Quiet(UiText.ph(if (row.live) Placeholder.DEVICE_LIVE else Placeholder.DEVICE_NOT_LIVE, Dates.date(row.addedAtMs), Dates.date(row.lastSeenAtMs), row.clientVersion))
        if (canRevoke(row)) {
            Quieter(UiText.ph(Placeholder.DEVICE_REVOKE), enabled = password.isNotEmpty() && !s.busy) {
                val p = password
                model.run({ devices.revokeDevice(row, p) }) { if (it.done) password = "" }
            }
        }
    }
    // One password field for the actions that need it: revoking a device, and the switch.
    MasterPasswordField(s, password) { password = it }
    // The setting's name, what it does, then how it stands: "It's off." has its subject above it.
    Say(Placeholder.DEVICE_REQUIRE_LINK_TITLE, style = MaterialTheme.typography.titleSmall)
    Quiet(UiText.ph(Placeholder.DEVICE_REQUIRE_LINK_BODY))
    Quiet(UiText.ph(requireLinkState(screen)))
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

/** The section name of a device link's answers ([TrustModel.runIn]). */
internal const val DEVICE_LINK_SECTION = "device-link"

/** The link is still running: leaving the screen cancels it ([TrustModel.leaveDeviceLink]). Approved and Ended are over here. */
internal fun deviceLinkRunning(host: DeviceLinkHost): Boolean =
    host is DeviceLinkHost.Shown || host is DeviceLinkHost.Claimed || host is DeviceLinkHost.TypeDigits || host is DeviceLinkHost.Approvable

/**
 * The confirm control is enabled once six digits are present under §6.11's rule: every ASCII space removed, then exactly
 * six ASCII digits (§8.2 step 5). The field's text itself goes to core untouched.
 */
internal fun deviceDigitsReady(typed: String): Boolean {
    val d = typed.filter { it != ' ' }
    return d.length == 6 && d.all { it in '0'..'9' }
}

/**
 * A device link's time left in whole seconds, rounded up, from the API's milliseconds: the approved line counts
 * seconds ("{0} seconds left"), so it never carries minutes and seconds.
 */
internal fun secondsLeft(ms: Long): String = ((maxOf(0L, ms) + 999) / 1000).toString()

/** "{0} seconds left" for an approval's time, with a line of its own for one second. */
internal fun deviceLinkTimeLeftLine(ms: Long): UiText =
    counted(secondsLeft(ms).toLong(), Placeholder.DEVICE_LINK_TIME_LEFT, Placeholder.DEVICE_LINK_TIME_LEFT_ONE)

/** The countdown as minutes and seconds, from the API's milliseconds (never the device clock). */
internal fun countdownText(ms: Long): String {
    val s = (maxOf(0L, ms) + 999) / 1000
    return "${s / 60}:${(s % 60).toString().padStart(2, '0')}"
}

/** What an approval answered, in place. */
internal fun deviceLinkProofWords(r: ProofResult, retryAfterSeconds: Int): UiText? = when (r) {
    ProofResult.WRONG_PASSWORD -> UiText.ph(Placeholder.DEVICE_LINK_WRONG_PASSWORD)
    ProofResult.CHANGED_ELSEWHERE -> UiText.ph(Placeholder.DEVICE_LINK_CHANGED_ELSEWHERE)
    else -> UiText.forResult(r, retryAfterSeconds)
}

/**
 * The title of the system prompt that approves a new device with fingerprint or face: design §8.2 step 5's words,
 * "Add *name* (*platform*)?". A system prompt cannot show the placeholder style.
 */
internal fun deviceApprovalReason(host: DeviceLinkHost.Approvable): String =
    fillTemplate(DEVICE_APPROVAL_PROMPT, listOf(host.deviceName, host.platform.wireName))

internal const val DEVICE_APPROVAL_PROMPT = "Add {0} ({1})?"

/** What typed digits answered, in place. A mismatch says nothing here: the link ended, and its end says it. */
internal fun deviceDigitsWords(r: DigitsResult, retryAfterSeconds: Int): UiText? =
    if (r == DigitsResult.MISMATCH) null else UiText.forResult(r, retryAfterSeconds)

/** How the link ended, each end its own line: the design's "Linking was cancelled" where it applies. */
/**
 * What the showing phone says when its link ended: the shared code's own line where it gives one
 * ([DeviceLinkHost.Ended.line], a link refused as one of too many requests, with the wait), in place of the outcome's
 * lines, which would say "a check failed" for it; the outcome's lines otherwise.
 */
internal fun hostEndedLines(host: DeviceLinkHost.Ended, retryAfterSeconds: Int): List<UiText> =
    host.line?.let { listOfNotNull(OutcomeWords.tooManyLine(it, tooMany = true, retryAfterSeconds)) } ?: deviceLinkEndLines(host.outcome)

internal fun deviceLinkEndLines(end: DeviceLinkHostEnd): List<UiText> = when (end) {
    DeviceLinkHostEnd.CANCELLED -> listOf(UiText.of(io.silencelen.andvari.core.app.CopyKey.DEVICE_LINK_CANCELLED))
    DeviceLinkHostEnd.CODE_MISMATCH -> listOf(UiText.of(io.silencelen.andvari.core.app.CopyKey.DEVICE_LINK_CANCELLED), UiText.ph(Placeholder.DEVICE_LINK_DIGITS_DIFFERED))
    DeviceLinkHostEnd.EXPIRED -> listOf(UiText.ph(Placeholder.DEVICE_LINK_EXPIRED))
    DeviceLinkHostEnd.DID_NOT_CHECK_OUT -> listOf(UiText.ph(Placeholder.DEVICE_LINK_DID_NOT_CHECK_OUT))
}

/**
 * Settings › Your devices › Add a device, while the link runs: a screen of its own, over the signed-in pages
 * ([AccountShell]). Back, or the screen leaving for any reason, cancels a running link ([TrustModel.leaveDeviceLink]);
 * a lock and the end of the session cancel it in core. The window is FLAG_SECURE throughout (MainActivity), so no
 * screenshot or recording shows the link or the digits; nothing of it is logged.
 */
@Composable
internal fun DeviceLinkHostPage(model: TrustModel, s: AppSnapshot, account: AccountSnapshot, host: DeviceLinkHost) {
    ActiveBackHandler(model) { model.leaveDeviceLink() }
    DisposableEffect(Unit) { onDispose { model.leaveDeviceLink() } }
    AuthColumn {
        Title(UiText.ph(Placeholder.DEVICE_ADD))
        DeviceLinkHostView(model, s, account, host)
    }
}

/**
 * The approving device (§8.1, §8.2, map §3.10). This side never shows a code and has no confirm-without-typing control:
 * the six digits are typed from the new device, a mismatch cancels the link, and approval is by the master password only
 * (the biometric approval is not offered: quick unlock gives no proof of the person that leaves the open account
 * untouched, l2b-14 item 6). The link shows as a QR code and as text, and reaches the clipboard only from the person's
 * own tap. The countdown reads [io.silencelen.andvari.core.app.DevicesApi.deviceLinkTimeLeftMs], never the device clock.
 */
@Composable
internal fun DeviceLinkHostView(model: TrustModel, s: AppSnapshot, account: AccountSnapshot, host: DeviceLinkHost) {
    val cancel = UiText.of(io.silencelen.andvari.core.app.CopyKey.CANCEL)
    if (deviceLinkRunning(host)) {
        var left by remember(host) { mutableLongStateOf(model.api.devices.deviceLinkTimeLeftMs()) }
        LaunchedEffect(host) {
            while (true) {
                left = model.api.devices.deviceLinkTimeLeftMs()
                delay(1_000)
            }
        }
        Quiet(deviceLinkTimeLeftLine(left))
    }
    when (host) {
        is DeviceLinkHost.Shown -> {
            // §8.1: the address beside the QR, to compare with the one the new device shows.
            Say(host.line)
            val link = remember(host) { model.api.devices.deviceLinkToShow(host) }
            if (link != null) {
                val qr = remember(link) { qrBitmap(link, 600) }
                Image(qr.asImageBitmap(), contentDescription = UiText.ph(Placeholder.DEVICE_LINK_QR).shown(), filterQuality = FilterQuality.None, modifier = Modifier.size(220.dp))
                Quiet(UiText.ph(Placeholder.DEVICE_LINK_AS_TEXT))
                Text(link, style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace))
                val context = LocalContext.current
                Quieter(UiText.ph(Placeholder.DEVICE_LINK_COPY)) {
                    io.silencelen.andvari.app.copyToClipboard(context, "andvari device link", link, maxOf(1, (model.clipboardClearMs() / 1000).toInt()))
                }
            }
        }
        is DeviceLinkHost.Claimed -> Say(UiText.ph(Placeholder.DEVICE_LINK_CLAIMED, host.deviceName, host.platform.wireName))
        is DeviceLinkHost.TypeDigits -> {
            var digits by remember(host) { mutableStateOf("") }
            Say(host.line)
            Field(UiText.ph(Placeholder.CODE_FIELD), digits, KeyboardType.NumberPassword, mono = true) { digits = it }
            SaidIn(model, s, DEVICE_LINK_SECTION)
            Main(UiText.ph(Placeholder.VERIFY_CODE), enabled = deviceDigitsReady(digits) && !s.busy, busy = s.busy) {
                val d = digits
                digits = ""
                model.runIn(DEVICE_LINK_SECTION, { devices.submitDeviceDigits(host, d) }, { deviceDigitsWords(it, model.api.retryAfterSeconds()) })
            }
        }
        is DeviceLinkHost.Approvable -> {
            var password by remember(host) { mutableStateOf("") }
            DisposableEffect(host) { onDispose { password = "" } }
            Say(UiText.ph(Placeholder.DEVICE_LINK_APPROVE, host.deviceName, host.platform.wireName))
            // §4.4: a screen that asks for the master password names the account and the instance.
            MasterPasswordField(s, password) { password = it }
            SaidIn(model, s, DEVICE_LINK_SECTION)
            Main(UiText.ph(Placeholder.DEVICE_LINK_APPROVE_BUTTON), enabled = password.isNotEmpty() && !s.busy, busy = s.busy) {
                val p = password
                password = ""
                model.runIn(DEVICE_LINK_SECTION, { devices.approveWithPassword(host, p) }, { deviceLinkProofWords(it, model.api.retryAfterSeconds()) })
            }
            // §8.2 step 6: fingerprint or face where the shared code offers it; the system prompt names the device
            // being added ([deviceApprovalReason]), never "Unlock".
            if (host.biometricsOffered) {
                Second(UiText.ph(Placeholder.DEVICE_LINK_APPROVE_BIOMETRIC), enabled = !s.busy) {
                    model.runIn(DEVICE_LINK_SECTION, { devices.approveWithBiometrics(host, deviceApprovalReason(host)) }, { deviceLinkProofWords(it, model.api.retryAfterSeconds()) })
                }
            }
        }
        is DeviceLinkHost.Approved -> {
            Say(UiText.ph(Placeholder.DEVICE_LINK_APPROVED, host.deviceName))
            Quiet(UiText.ph(Placeholder.DEVICE_LINK_APPROVED_NEXT))
            Main(UiText.ph(Placeholder.DONE), enabled = true, busy = false) { model.act { devices.dismissDeviceLink() } }
        }
        is DeviceLinkHost.Ended -> {
            for (line in hostEndedLines(host, model.api.retryAfterSeconds())) Say(line)
            Main(UiText.ph(Placeholder.DISMISS), enabled = true, busy = false) { model.act { devices.dismissDeviceLink() } }
        }
    }
    if (deviceLinkRunning(host)) {
        if (host is DeviceLinkHost.Shown || host is DeviceLinkHost.Claimed) SaidIn(model, s, DEVICE_LINK_SECTION)
        Quieter(cancel, enabled = !s.busy) { model.runIn(DEVICE_LINK_SECTION, { devices.cancelDeviceLink() }) }
    }
}
