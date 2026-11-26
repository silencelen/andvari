package io.silencelen.andvari.desktop.trust

import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.FilterQuality
import androidx.compose.ui.graphics.toComposeImageBitmap
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.common.BitMatrix
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import androidx.compose.runtime.collectAsState
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppSnapshot
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.IntentResult
import io.silencelen.andvari.core.app.KitDocument
import io.silencelen.andvari.core.app.KitReason
import io.silencelen.andvari.core.app.KitScreen
import io.silencelen.andvari.core.app.KitStep
import java.awt.Color
import java.awt.Font
import java.awt.Graphics
import java.awt.Graphics2D
import java.awt.image.BufferedImage
import java.awt.print.PageFormat
import java.awt.print.Printable
import java.awt.print.PrinterJob
import java.text.DateFormat
import java.util.Date

/**
 * The recovery kit (§10): made, revealed once, then confirmed by typing three groups. **No Copy
 * button, no "Save PDF" of our own, and the groups are not selectable text** (no selection container anywhere on the
 * path). The document is printed through the system's print dialog only ([printKit]); a PDF, where wanted, is the
 * operating system's PDF printer. The same view serves the kit before the vault opens
 * ([io.silencelen.andvari.core.app.EntryScreen.Kit]) and a kit made in Settings.
 */
@Composable
internal fun KitScreenView(model: TrustModel, s: AppSnapshot, kit: KitScreen) {
    // Read here, so the answer that brought a kit this computer did not keep is drawn the moment it is noted.
    model.kitResult.collectAsState().value
    val idleWarning = model.kitIdleWarning.collectAsState().value
    AuthColumn {
        // On the kit's first step, before anything else: this kit replaces one shown here and never confirmed, so what the
        // person wrote down of that one no longer works (the shared code's line, set on the reveal only).
        kit.earlierKitVoidLine?.let { Say(UiText.of(it), color = MaterialTheme.colorScheme.error) }
        // The kit screen's idle limit is near, and the lock takes this kit off the screen: the shared code's line (a
        // click or a key keeps the kit). It cannot be drawn over a system dialog such as the print dialog, and this
        // toolkit announces no line that appears: so the app asks the operating system for attention on its window and
        // sounds the system's alert once ([KitWarningSignal]), and where the window has the focus the line takes it,
        // which a screen reader reads ([KitIdleWarningLine]). Whether a screen reader speaks it is for a Windows computer
        // to show.
        idleWarning?.let { KitIdleWarningLine(kitIdleWarningText(kit, it)) }
        // A kit the server holds for an account this computer did not keep: on every step, what happened, how long the
        // kit holds, and the answer's own words; never the kept account's sign-out, which would take the kit with it.
        for (line in notKeptKitLines(kit, model.kitResultOn(s), s)) Say(line, color = MaterialTheme.colorScheme.error)
        when (kit.step) {
            // The current app's "preparing" line: its small spinner beside the words.
            KitStep.MAKING -> Row(verticalAlignment = Alignment.CenterVertically) {
                OpeningSpinner()
                Say(UiText.ph(Placeholder.KIT_MAKING), Modifier.padding(start = 8.dp))
            }
            KitStep.NOT_MADE -> KitNotMade(model, s, kit)
            KitStep.REVEAL -> KitReveal(model, s, kit)
            KitStep.CONFIRM -> KitConfirm(model, s, kit)
        }
        SaidHere(model, s)
    }
}

/** The kit on show in [s] when it is one this computer did not keep ([KitScreen.notKeptLine]); null otherwise. */
internal fun notKeptKitOf(s: AppSnapshot): KitScreen? =
    (s.entry as? EntryScreen.Kit)?.kit?.takeIf { s.phase == AppPhase.ENTRY && it.notKeptLine != null }

/**
 * The kit on show in [s] (in the journey, or made in Settings over the open vault) that carries the shared code's idle
 * limit ([KitScreen.idleLockAfterMs]; every kit the shared code makes does); null otherwise.
 */
internal fun kitIdleLimitOf(s: AppSnapshot): KitScreen? {
    val kit = when (s.phase) {
        AppPhase.ENTRY -> (s.entry as? EntryScreen.Kit)?.kit
        AppPhase.UNLOCKED -> s.account?.kit
        else -> null
    }
    return kit?.takeIf { it.idleLockAfterMs != null }
}

/**
 * The warning [on] of [kit] as drawn: the kit's own filled line ([KitScreen.idleWarning]: the short warning names the
 * limit in its slot), never the bare key.
 */
internal fun kitIdleWarningText(kit: KitScreen, on: io.silencelen.andvari.core.app.CopyKey): UiText =
    kit.idleWarning?.takeIf { it.key == on }?.let { UiText.of(it) } ?: UiText.of(on)

/** [kit]'s warning is on show from the start of its screen: its limit is not longer than the warning's time. */
internal fun warnsFromStart(kit: KitScreen): Boolean {
    val limit = kit.idleLockAfterMs ?: return false
    return kit.idleWarningLine != null && (kit.idleWarnBeforeMs ?: 0L) >= limit
}

/** [notKeptKitOf] is on show: a sign-out there would take the kit with it unsaid. */
internal fun showsNotKeptKit(s: AppSnapshot): Boolean = notKeptKitOf(s) != null

/** A screen that says the keeper's stop itself, so the answer that brought the person there is not said twice. */
internal fun saysTheStopItself(s: AppSnapshot): Boolean =
    s.phase == AppPhase.ENTRY && (s.entry is EntryScreen.OperatorHelp || s.entry is EntryScreen.LinkDeviceEnded)

/**
 * What a kit this computer did not keep says above its step (the check of 2026-11-17, property 5): the shared code's
 * line ([KitScreen.notKeptLine]); beside it, how long the kit holds ([KitScreen.notKeptHoldsLine]: the next sign-in to
 * the account shows a new kit that replaces it, as the device cannot tell the server it was typed back); then the
 * answer that brought it ([result]) where it says more: the kept account named, the new password in force. Empty for
 * every other kit.
 */
internal fun notKeptKitLines(kit: KitScreen, result: TrustModel.KitResult?, s: AppSnapshot): List<UiText> {
    val line = kit.notKeptLine ?: return emptyList()
    val head = UiText.of(line)
    val lines = mutableListOf(head)
    kit.notKeptHoldsLine?.let { lines += UiText.of(it) }
    if (result != null) {
        val said = wayOutOf(result.result, result.text, s)?.lines ?: listOfNotNull(result.text)
        lines += said.filter { it.shown() != head.shown() }
    }
    return lines
}

@Composable
private fun KitNotMade(model: TrustModel, s: AppSnapshot, kit: KitScreen) {
    var password by remember { mutableStateOf("") }
    val submit = {
        if (password.isNotEmpty() && !s.busy) {
            val typed = password
            model.run({ this.kit.retryKit(kit, typed) }) { password = "" }
        }
    }
    WindowHead(null, kit.instance)
    Say(if (kit.reason == KitReason.REPLACED_ELSEWHERE) UiText.ph(Placeholder.KIT_REPLACED_ELSEWHERE) else UiText.ph(Placeholder.KIT_NOT_MADE))
    Gap()
    // A screen that asks for an existing account's master password names the account and the instance (§4.4).
    Say(UiText.Plain(fillCopy(CopyKey.MASTER_PASSWORD_FOR, kit.email, kit.instance.name, kit.instance.origin)), style = MaterialTheme.typography.titleSmall)
    SecretField(UiText.ph(Placeholder.PASSWORD_FIELD), password, onEnter = { submit() }) { password = it }
    Main(UiText.ph(Placeholder.KIT_RETRY), enabled = password.isNotEmpty() && !s.busy, busy = s.busy) { submit() }
}

@Composable
private fun KitReveal(model: TrustModel, s: AppSnapshot, kit: KitScreen) {
    val doc: KitDocument = remember(kit) { model.api.kit.kitDocument(kit) } ?: return
    // The current app's reveal: the head, what it is for, then what to write down in its surface card.
    WindowHead(UiText.of(doc.title), doc.instance, UiText.Plain(DateFormat.getDateInstance(DateFormat.LONG).format(Date(doc.madeAtMs))))
    Say(doc.keepPrivate, color = MaterialTheme.colorScheme.error)
    Gap(8)
    Text(doc.email, style = MaterialTheme.typography.bodyLarge)
    Gap()
    CodeCard {
        KitGroups(doc.groups)
        Gap()
        QrImage(doc.qrPayload)
    }
    Gap()
    Say(doc.accountIdLine)
    Say(doc.howToRecover, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    Gap()
    // Print stays (the owner's decision), with what printing leaves said beside it.
    Quiet(UiText.ph(Placeholder.KIT_PRINT_LEAVES))
    // The print holds the kit only through a hold that a lock, or the end of this kit's screen, drops (KitPrintHold).
    Second(UiText.ph(Placeholder.KIT_PRINT), enabled = !s.busy) {
        printKit(model.holdForPrint(doc), { model.say(UiText.ph(Placeholder.KIT_PRINT_FAILED, it)) }) { model.say(UiText.ph(Placeholder.KIT_PRINT_STOPPED_BY_LOCK)) }
    }
    Main(UiText.ph(Placeholder.KIT_SAVED_NEXT), enabled = !s.busy, busy = false) { model.act { this.kit.proceedToConfirm(kit) } }
}

/** The eleven groups, large and monospaced, numbered so "Type groups 2, 7 and 10" can be followed. Not selectable. */
@Composable
private fun KitGroups(groups: List<String>) {
    for (row in groups.withIndex().chunked(3)) {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            for ((i, g) in row) {
                Row(Modifier.padding(vertical = 4.dp), verticalAlignment = Alignment.Bottom) {
                    Text("${i + 1}", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Text(" $g", style = MaterialTheme.typography.headlineSmall.copy(fontFamily = FontFamily.Monospace))
                }
            }
        }
    }
}

@Composable
private fun KitConfirm(model: TrustModel, s: AppSnapshot, kit: KitScreen) {
    val typed = remember(kit) { mutableStateOf(List(kit.groupsToType.size) { "" }) }
    WindowHead(kit.confirmLine?.let { UiText.of(it) })
    if (kit.failedTries > 0) Quiet(UiText.ph(Placeholder.KIT_FAILED_TRIES, kit.failedTries.toString()))
    val ready = typed.value.all { it.isNotBlank() } && !s.busy
    val submit = { if (ready) typed.value.let { groups -> model.run({ this.kit.confirmKit(kit, groups) }) } }
    kit.groupsToType.forEachIndexed { i, n ->
        // What is typed back cannot be copied out of the field (no Copy, no Cut, by key or menu).
        KitGroupField(UiText.ph(Placeholder.KIT_GROUP_FIELD, n.toString()), typed.value[i], onEnter = { submit() }) { v ->
            typed.value = typed.value.toMutableList().also { it[i] = v }
        }
    }
    Main(UiText.ph(Placeholder.KIT_CONFIRM), enabled = ready, busy = s.busy) { submit() }
    Quieter(UiText.ph(Placeholder.KIT_SHOW_AGAIN), enabled = !s.busy) { model.act { this.kit.showKitAgain(kit) } }
}

/**
 * A QR code (§0.3: the full string, byte mode, error correction M), as large as the column allows: one pixel per
 * module, scaled up with no smoothing so the modules stay sharp at any size.
 */
@Composable
internal fun QrImage(payload: String) {
    // A server can make a link too long to draw (a two-step key past ~2,300 bytes). That
    // never throws out of the screen: it says so and shows the text instead, not selectable, as the rest of the kit.
    val bitmap = remember(payload) { qrImageOrNull(payload)?.toComposeImageBitmap() }
    if (bitmap == null) {
        Say(Placeholder.QR_TOO_LONG)
        Text(payload, style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace))
        return
    }
    Image(
        bitmap, contentDescription = null, filterQuality = FilterQuality.None,
        modifier = Modifier.widthIn(max = TRUST_AUTH_MAX_WIDTH).fillMaxWidth().aspectRatio(1f),
    )
}

/** A design sentence with its values, filled the way core fills one (one pass; a value reading "{0}" is copied). */
internal fun fillCopy(key: CopyKey, vararg values: String): String = fillTemplate(key.english, values.toList())

/**
 * The QR matrix: byte mode (ISO-8859-1 keeps zxing out of the alphanumeric mode), error correction M, a quiet zone of
 * four modules. [size] 0 gives one cell per module. Pure Java, so the JVM tests decode it back.
 */
internal fun qrMatrix(payload: String, size: Int = 0): BitMatrix =
    QRCodeWriter().encode(
        payload, BarcodeFormat.QR_CODE, size, size,
        mapOf(EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.M, EncodeHintType.MARGIN to 4, EncodeHintType.CHARACTER_SET to "ISO-8859-1"),
    )

/**
 * [qrMatrix], or null when the payload cannot be drawn as a QR code (too long for the largest version, or a character
 * the byte mode cannot carry): zxing throws [com.google.zxing.WriterException] or [IllegalArgumentException] then.
 */
internal fun qrMatrixOrNull(payload: String): BitMatrix? =
    try {
        qrMatrix(payload)
    } catch (e: com.google.zxing.WriterException) {
        null
    } catch (e: IllegalArgumentException) {
        null
    }

/** [qrImage], or null when the payload cannot be drawn ([qrMatrixOrNull]). */
internal fun qrImageOrNull(payload: String): BufferedImage? = qrMatrixOrNull(payload)?.let(::imageOf)

/** The matrix as an image, one pixel per module, black on white whatever the theme (scanners want that). */
internal fun qrImage(payload: String): BufferedImage = imageOf(qrMatrix(payload))

private fun imageOf(m: BitMatrix): BufferedImage {
    val img = BufferedImage(m.width, m.height, BufferedImage.TYPE_INT_RGB)
    for (y in 0 until m.height) for (x in 0 until m.width) img.setRGB(x, y, if (m[x, y]) 0x000000 else 0xFFFFFF)
    return img
}

/**
 * Print the kit through the system's print dialog. The page is drawn straight to the printer
 * ([KitPrintable]); nothing is written to this computer's disk by the app itself, but the print system can keep copies
 * (on Linux a `/tmp/javaprint*.ps` spool file and CUPS's job files; "print to file"), which
 * the screen says ([Placeholder.KIT_PRINT_LEAVES]). The dialog and the print run off the UI
 * thread; a failure is said in place through [failed], never swallowed.
 *
 * The thread holds the kit only through [hold], which a lock and the end of the kit's screen drop
 * ([TrustModel.dropKitPrints]; the check of 2026-11-18: a print dialog left open printed the kit after the lock had
 * taken it and said so). Once dropped, the page source has no page, a dialog confirmed afterwards prints nothing, and a
 * job already under way is cancelled where the platform allows. When the print is over, the hold is dropped as well.
 */
internal fun printKit(hold: KitPrintHold, failed: (String) -> Unit, stopped: () -> Unit) {
    Thread({ printKitHere(hold, failed, stopped) { PrinterJob.getPrinterJob() } }, "andvari-kit-print").apply { isDaemon = true }.start()
}

/**
 * [printKit]'s steps, on the calling thread, over the job [newJob] makes. A print that a lock stopped ([KitPrintHold.stoppedByLock]:
 * Print pressed in the dialog after the lock, or the job aborted by it) is said when it returns ([stopped]), in one
 * line; a dialog the person cancelled says nothing, and a print stopped because the kit's screen ended says nothing.
 */
internal fun printKitHere(hold: KitPrintHold, failed: (String) -> Unit, stopped: () -> Unit, newJob: () -> PrinterJob) {
    try {
        val job = newJob()
        job.setJobName("andvari recovery kit")
        job.setPrintable(KitPrintable(hold))
        hold.attach(job)
        val pressed = job.printDialog()
        if (pressed && hold.held) job.print() else if (pressed && hold.stoppedByLock) stopped()
    } catch (e: java.awt.print.PrinterAbortException) {
        // Cancelled because the lock dropped the hold: said as the lock's. Any other abort is said as a failure.
        if (hold.held) failed(e.javaClass.simpleName) else if (hold.stoppedByLock) stopped()
    } catch (e: Exception) {
        failed(e.javaClass.simpleName)
    } finally {
        hold.drop()
    }
}

/**
 * What one print of a kit holds of it: the document, until [drop]. A lock and the end of the kit's screen drop every
 * hold ([TrustModel.dropKitPrints]); after that [doc] is null, so the page source ([KitPrintable]) answers that there
 * is no page and nothing of the kit is left here, and the printer job [attach]ed to it is cancelled.
 */
internal class KitPrintHold(doc: KitDocument) {
    @Volatile private var kept: KitDocument? = doc

    @Volatile private var job: PrinterJob? = null

    /** The kit's document while the hold lasts; null once dropped. */
    val doc: KitDocument? get() = kept

    val held: Boolean get() = kept != null

    /** The printer job this print runs as: cancelled at [drop], or at once if the hold was dropped already. */
    fun attach(j: PrinterJob) {
        job = j
        if (kept == null) cancel(j)
    }

    /** A lock let go of the kit before the print was done (set before the document goes). */
    @Volatile var stoppedByLock: Boolean = false
        private set

    fun drop(byLock: Boolean = false) {
        if (byLock && kept != null) stoppedByLock = true
        kept = null
        job?.let(::cancel)
        job = null
    }

    private fun cancel(j: PrinterJob) {
        // A job that is not printing yet has nothing to cancel; the page source then has no page all the same.
        runCatching { j.cancel() }
    }
}

/** One page: the kit's text, its eleven groups and its QR, in black on white, while [hold] lasts. Pure AWT, so a test can draw it. */
internal class KitPrintable(private val hold: KitPrintHold) : Printable {
    override fun print(g: Graphics, pf: PageFormat, page: Int): Int {
        if (page > 0) return Printable.NO_SUCH_PAGE
        // Read once per page: a hold dropped by a lock gives no page at all.
        val doc = hold.doc ?: return Printable.NO_SUCH_PAGE
        val g2 = g as Graphics2D
        g2.translate(pf.imageableX, pf.imageableY)
        g2.color = Color.BLACK
        val width = pf.imageableWidth
        var y = 0.0
        fun line(s: String, font: Font, gap: Double = 6.0) {
            g2.font = font
            val fm = g2.fontMetrics
            for (part in wrap(s, width) { fm.stringWidth(it).toDouble() }) {
                y += fm.ascent
                g2.drawString(part, 0f, y.toFloat())
                y += fm.descent + gap
            }
        }
        val text = Font(Font.SANS_SERIF, Font.PLAIN, 10)
        line(doc.title.english, Font(Font.SANS_SERIF, Font.BOLD, 18), 10.0)
        line(doc.keepPrivate.english, text)
        line(doc.email, text)
        line("${doc.instance.name} (${doc.instance.origin})", text)
        line(DateFormat.getDateInstance(DateFormat.LONG).format(Date(doc.madeAtMs)), text, 14.0)
        for (row in doc.groups.withIndex().chunked(4)) line(row.joinToString("   ") { (i, gr) -> "${i + 1}: $gr" }, Font(Font.MONOSPACED, Font.PLAIN, 14), 8.0)
        y += 10
        val m = qrMatrixOrNull(doc.qrPayload)
        if (m == null) {
            // Too long to draw (note N4): the page carries the text instead.
            line(doc.qrPayload, Font(Font.MONOSPACED, Font.PLAIN, 8))
        } else {
            val cell = (minOf(width, 220.0) / m.width)
            for (qy in 0 until m.height) for (qx in 0 until m.width) {
                if (m[qx, qy]) g2.fill(java.awt.geom.Rectangle2D.Double(qx * cell, y + qy * cell, cell, cell))
            }
            y += m.height * cell + 12
        }
        line(doc.accountIdLine.english, text)
        line(doc.howToRecover.english, text)
        return Printable.PAGE_EXISTS
    }
}

/** Greedy word wrap to [width], by the measure given. */
internal fun wrap(s: String, width: Double, measure: (String) -> Double): List<String> {
    val out = ArrayList<String>()
    var cur = ""
    for (word in s.split(' ')) {
        val next = if (cur.isEmpty()) word else "$cur $word"
        if (measure(next) > width && cur.isNotEmpty()) {
            out += cur
            cur = word
        } else {
            cur = next
        }
    }
    if (cur.isNotEmpty()) out += cur
    return out
}
