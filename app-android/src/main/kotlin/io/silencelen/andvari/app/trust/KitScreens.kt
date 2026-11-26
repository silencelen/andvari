package io.silencelen.andvari.app.trust

import android.content.Context
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Paint
import android.graphics.Typeface
import android.os.Bundle
import android.os.CancellationSignal
import android.os.ParcelFileDescriptor
import android.print.PageRange
import android.print.PrintAttributes
import android.print.PrintDocumentAdapter
import android.print.PrintDocumentInfo
import android.print.PrintManager
import android.print.pdf.PrintedPdfDocument
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Rect
import androidx.compose.ui.graphics.FilterQuality
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.input.key.Key
import androidx.compose.ui.input.key.KeyEventType
import androidx.compose.ui.input.key.isCtrlPressed
import androidx.compose.ui.input.key.isMetaPressed
import androidx.compose.ui.input.key.isShiftPressed
import androidx.compose.ui.input.key.key
import androidx.compose.ui.input.key.onPreviewKeyEvent
import androidx.compose.ui.input.key.type
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalTextToolbar
import androidx.compose.ui.platform.TextToolbar
import androidx.compose.ui.platform.TextToolbarStatus
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.copyText
import androidx.compose.ui.semantics.cutText
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.common.BitMatrix
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import io.silencelen.andvari.app.AuthColumn
import io.silencelen.andvari.app.ExternalExcursion
import io.silencelen.andvari.app.SecretField
import io.silencelen.andvari.core.app.AppSnapshot
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.KitDocument
import io.silencelen.andvari.core.app.KitReason
import io.silencelen.andvari.core.app.KitScreen
import io.silencelen.andvari.core.app.KitStep
import java.io.FileOutputStream
import java.text.DateFormat
import java.util.Date

/**
 * The recovery kit (§10): made, revealed once, then confirmed by typing three groups. **There is no Copy button on the
 * reveal or the confirm step**, and the groups are not selectable text. The document is printed or saved as PDF
 * through the system print service, written straight to the destination the person picks: this app keeps no copy.
 * The same view serves the kit before the vault opens ([io.silencelen.andvari.core.app.EntryScreen.Kit]) and a kit
 * made in Settings.
 */
@Composable
internal fun KitScreenView(model: TrustModel, s: AppSnapshot, kit: KitScreen) {
    val covered by model.kitCovered.collectAsState()
    AuthColumn {
        if (covered && (kit.step == KitStep.REVEAL || kit.step == KitStep.CONFIRM)) {
            // Left in the background: the kit's document and QR are out of the composition until asked for again.
            Say(Placeholder.KIT_COVERED)
            Gap()
            Main(UiText.ph(Placeholder.KIT_SHOW_AGAIN), enabled = true, busy = false) { model.uncoverKit() }
            return@AuthColumn
        }
        // Before anything else: this kit replaces one shown here before and never confirmed, which no longer works.
        kitVoidLine(kit)?.let {
            Say(it, color = MaterialTheme.colorScheme.error)
            Gap(8)
        }
        // A kit the server took while this phone refused the session: why, and how long the kit holds, above the kit on
        // every step, until it is typed back (then the first screen says the refusal again, with its way out).
        val refusal by model.kitRefusal.collectAsState()
        for (line in kitRefusalLines(kit, refusal)) Say(line, color = MaterialTheme.colorScheme.error)
        if (kit.notKeptLine != null) Gap(8)
        // The kit's idle limit is near (the shared code's figures and line): the lock then takes the kit off the screen
        // and out of memory. A touch or a key ends the warning. A polite live region: a screen reader says it.
        model.kitIdleWarning.collectAsState().value?.let { Say(UiText.of(it), Modifier.semantics { liveRegion = LiveRegionMode.Polite }, color = MaterialTheme.colorScheme.error) }
        when (kit.step) {
            KitStep.MAKING -> {
                Say(Placeholder.KIT_MAKING)
                Gap()
                CircularProgressIndicator()
            }
            KitStep.NOT_MADE -> KitNotMade(model, s, kit)
            KitStep.REVEAL -> KitReveal(model, s, kit)
            KitStep.CONFIRM -> KitConfirm(model, s, kit)
        }
        SaidHere(model, s)
    }
}

/**
 * The shared code's line on a kit that replaces one shown on this phone before and never confirmed
 * ([KitScreen.earlierKitVoidLine], on the kit's first step only): whatever the person kept of that earlier kit no longer
 * works. Null for every other kit and step.
 */
internal fun kitVoidLine(kit: KitScreen): UiText? = kit.earlierKitVoidLine?.let { UiText.of(it) }

/**
 * What stands above a kit that came with a refusal ([KitScreen.notKeptLine]): the result's own words where they are not
 * the kit's line already, the kit's line, and how long the kit holds ([KitScreen.notKeptHoldsLine]: the next sign-in
 * shows a new one that replaces it). Nothing for every other kit.
 */
internal fun kitRefusalLines(kit: KitScreen, refusal: TrustModel.KitRefusal?): List<UiText> {
    val line = kit.notKeptLine ?: return emptyList()
    return listOfNotNull(UiText.of(line), refusal?.text, kit.notKeptHoldsLine?.let { UiText.of(it) })
}

@Composable
private fun KitNotMade(model: TrustModel, s: AppSnapshot, kit: KitScreen) {
    var password by remember { mutableStateOf("") }
    Say(if (kit.reason == KitReason.REPLACED_ELSEWHERE) UiText.ph(Placeholder.KIT_REPLACED_ELSEWHERE) else UiText.ph(Placeholder.KIT_NOT_MADE))
    Gap()
    // A screen that asks for an existing account's master password names the account and the instance (§4.4).
    Say(UiText.Plain(fillCopy(CopyKey.MASTER_PASSWORD_FOR, kit.email, kit.instance.name, kit.instance.origin)), style = MaterialTheme.typography.titleSmall)
    SecretField(UiText.ph(Placeholder.PASSWORD_FIELD).shown(), password) {
        model.touched()
        password = it
    }
    Main(UiText.ph(Placeholder.KIT_RETRY), enabled = password.isNotEmpty() && !s.busy, busy = s.busy) {
        val typed = password
        model.run({ this.kit.retryKit(kit, typed) }) { password = "" }
    }
}

@Composable
private fun KitReveal(model: TrustModel, s: AppSnapshot, kit: KitScreen) {
    // Drawn from the model's holder, which a lock empties: the composition never keeps the document or its picture.
    val hold = model.kitScreen
    val doc: KitDocument = hold.documentFor(kit) { model.api.kit.kitDocument(kit) } ?: return
    val context = LocalContext.current
    Title(UiText.of(doc.title))
    Say(doc.keepPrivate, color = MaterialTheme.colorScheme.error)
    Gap(8)
    Text(doc.email, style = MaterialTheme.typography.bodyLarge)
    InstanceName(doc.instance)
    Quiet(UiText.Plain(Dates.date(doc.madeAtMs, DateFormat.LONG)))
    Gap()
    KitGroups(doc.groups)
    Gap()
    hold.pictureFor(doc) { qrBitmap(it.qrPayload, 720) }
    // The picture is read from the holder as it is drawn; once a lock emptied it, nothing is.
    androidx.compose.foundation.Canvas(Modifier.size(240.dp)) {
        (hold.picture as? Bitmap)?.let { qr ->
            drawImage(qr.asImageBitmap(), dstSize = androidx.compose.ui.unit.IntSize(size.width.toInt(), size.height.toInt()), filterQuality = FilterQuality.None)
        }
    }
    Gap()
    // On the screen the account ID is in groups of four, so that it can be read aloud; the kit's printed and stored
    // form is the specification's and stays whole.
    Say(UiText.of(CopyKey.KIT_ACCOUNT_ID, groupedForReading(doc.accountId)))
    Say(doc.howToRecover, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    Gap()
    // What printing hands over, said before the button (whether Print stays is the owner's).
    Quiet(UiText.ph(Placeholder.KIT_PRINT_HANDS_OVER))
    Second(UiText.ph(Placeholder.KIT_PRINT), enabled = !s.busy) { hold.document?.let { printKit(context, it) } }
    Main(UiText.ph(Placeholder.KIT_SAVED_NEXT), enabled = !s.busy, busy = false) { model.act { this.kit.proceedToConfirm(kit) } }
}

/** The eleven groups, large and monospaced, numbered so "Type groups 2, 7 and 10" can be followed. Not selectable. */
@Composable
private fun KitGroups(groups: List<String>) = androidx.compose.foundation.layout.BoxWithConstraints(Modifier.fillMaxWidth()) {
    // Three to a row, or fewer when three do not fit (the largest font on a small phone cut the third group in two).
    // The widest group with its number is measured in the styles it is drawn in.
    val measurer = androidx.compose.ui.text.rememberTextMeasurer()
    val number = MaterialTheme.typography.labelSmall
    val group = MaterialTheme.typography.headlineSmall.copy(fontFamily = FontFamily.Monospace)
    val widest = groups.maxOfOrNull { it.length } ?: 4
    val cellPx = measurer.measure("88", number).size.width + measurer.measure(" " + "W".repeat(widest), group).size.width
    val perRow = kitGroupsPerRow(constraints.maxWidth, cellPx, with(androidx.compose.ui.platform.LocalDensity.current) { 12.dp.roundToPx() })
    androidx.compose.foundation.layout.Column {
        KitGroupRows(groups, perRow)
    }
}

/** How many kit groups fit side by side: three at most, at least one, each [cellPx] wide with [gapPx] between them. */
internal fun kitGroupsPerRow(availablePx: Int, cellPx: Int, gapPx: Int): Int =
    (3 downTo 1).first { n -> n == 1 || n * cellPx + (n - 1) * gapPx <= availablePx }

@Composable
private fun KitGroupRows(groups: List<String>, perRow: Int) {
    for (row in groups.withIndex().chunked(perRow)) {
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
    // The groups typed back live in the model's holder, which a lock empties ([KitScreenHold]).
    val hold = model.kitScreen
    val typed = hold.typed(kit, kit.groupsToType.size)
    kit.confirmLine?.let { Title(UiText.of(it)) }
    if (kit.failedTries > 0) Quiet(UiText.ph(Placeholder.KIT_FAILED_TRIES, kit.failedTries.toString()))
    // What is typed back cannot be copied out: no Copy and no Cut, from the text menu or from a keyboard.
    NoCopyOut {
        kit.groupsToType.forEachIndexed { i, n ->
            // Visible text, but no suggestions and no learning: the groups are the account's recovery secret.
            Field(UiText.ph(Placeholder.KIT_GROUP_FIELD, n.toString()), typed.getOrElse(i) { "" }, KeyboardType.Password, mono = true, modifier = Modifier.semantics(properties = noCopyOutActions)) { v ->
                // Typing on the on-screen keyboard reaches no key event of this window: it counts for the idle limit here.
                model.touched()
                hold.type(kit, i, v)
            }
        }
    }
    Main(UiText.ph(Placeholder.KIT_CONFIRM), enabled = typed.size == kit.groupsToType.size && typed.all { it.isNotBlank() } && !s.busy, busy = s.busy) {
        val groups = hold.typed(kit, kit.groupsToType.size)
        model.run({ this.kit.confirmKit(kit, groups) })
    }
    Quieter(UiText.ph(Placeholder.KIT_SHOW_AGAIN), enabled = !s.busy) { model.act { this.kit.showKitAgain(kit) } }
}

/**
 * Fields whose text must not leave the app: their text menu offers no Copy and no Cut ([PasteOnlyToolbar]), and the
 * keyboard's copy and cut keys never reach them ([copiesOut]). Paste and Select all stay.
 */
@Composable
internal fun NoCopyOut(content: @Composable () -> Unit) {
    val system = LocalTextToolbar.current
    val toolbar = remember(system) { PasteOnlyToolbar(system) }
    CompositionLocalProvider(LocalTextToolbar provides toolbar) {
        androidx.compose.foundation.layout.Column(Modifier.onPreviewKeyEvent { e -> e.type == KeyEventType.KeyDown && copiesOut(e.key, e.isCtrlPressed || e.isMetaPressed, e.isShiftPressed) }) {
            content()
        }
    }
}

/**
 * An accessibility service's Copy and Cut (TalkBack's "Copy", `ACTION_COPY`, `ACTION_CUT`) on a field the kit is typed
 * into: answered with nothing done. Set on the field's own modifier, outside the text field's semantics, whose actions
 * of the same name these replace (an outer semantics modifier of one node is applied last).
 */
internal val noCopyOutActions: androidx.compose.ui.semantics.SemanticsPropertyReceiver.() -> Unit = {
    copyText { false }
    cutText { false }
}

/** A key that copies or cuts a text field's selection: Ctrl (or Cmd) with C, X or Insert; Shift with Delete; Copy; Cut. */
internal fun copiesOut(key: Key, ctrl: Boolean, shift: Boolean): Boolean =
    key == Key.Copy || key == Key.Cut ||
        (ctrl && (key == Key.C || key == Key.X || key == Key.Insert)) ||
        (shift && key == Key.Delete)

/** The system's text menu with Copy and Cut taken out; everything else is the system's. */
internal class PasteOnlyToolbar(private val inner: TextToolbar) : TextToolbar {
    override val status: TextToolbarStatus get() = inner.status

    override fun hide() = inner.hide()

    override fun showMenu(
        rect: Rect,
        onCopyRequested: (() -> Unit)?,
        onPasteRequested: (() -> Unit)?,
        onCutRequested: (() -> Unit)?,
        onSelectAllRequested: (() -> Unit)?,
    ) = inner.showMenu(rect, null, onPasteRequested, null, onSelectAllRequested)
}

/** A design sentence with its values, filled the way core fills one (one pass; a value reading "{0}" is copied). */
internal fun fillCopy(key: CopyKey, vararg values: String): String = fillTemplate(key.english, values.toList())

/**
 * The kit QR (§10): `andvari-kit:2:…` in byte mode (its lower-case letters keep zxing out of the alphanumeric mode),
 * error correction M, a quiet zone of four modules. Pure Java, so the JVM tests decode it back.
 */
internal fun qrMatrix(payload: String, size: Int): BitMatrix =
    QRCodeWriter().encode(
        payload, BarcodeFormat.QR_CODE, size, size,
        mapOf(EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.M, EncodeHintType.MARGIN to 4, EncodeHintType.CHARACTER_SET to "ISO-8859-1"),
    )

internal fun qrBitmap(payload: String, size: Int): Bitmap {
    val m = qrMatrix(payload, size)
    val px = IntArray(m.width * m.height) { if (m[it % m.width, it / m.width]) 0xFF000000.toInt() else 0xFFFFFFFF.toInt() }
    return Bitmap.createBitmap(px, m.width, m.height, Bitmap.Config.ARGB_8888)
}

/**
 * Print or save as PDF through the system print service (§10). The page is drawn straight into the file descriptor the
 * print framework hands over, so nothing is written to this app's storage. The print UI is an activity of its own,
 * so the excursion is armed: leaving for it does not count as going to the background.
 */
private fun printKit(context: Context, doc: KitDocument) {
    val pm = context.getSystemService(Context.PRINT_SERVICE) as? PrintManager ?: return
    ExternalExcursion.begin()
    pm.print("andvari recovery kit", KitPrintAdapter(context, doc), PrintAttributes.Builder().setMediaSize(PrintAttributes.MediaSize.ISO_A4).build())
}

/**
 * The page for the system's print screen. It holds the kit's document (its groups and its code) and the page drawn from
 * it only until the print framework is done ([onFinish]), and no longer than a kit is on show: a lock reaches it through
 * [KitHolds] and it lets go of both, so a later write fails instead of drawing a kit the lock took.
 */
private class KitPrintAdapter(private val context: Context, doc: KitDocument) : PrintDocumentAdapter(), KitHolds.Held {
    private var doc: KitDocument? = doc
    private var pdf: PrintedPdfDocument? = null

    init {
        KitHolds.hold(this)
    }

    override fun drop() {
        doc = null
        pdf?.close()
        pdf = null
    }

    override fun onLayout(old: PrintAttributes?, attrs: PrintAttributes, cancel: CancellationSignal, cb: LayoutResultCallback, extras: Bundle?) {
        if (cancel.isCanceled) return cb.onLayoutCancelled()
        if (doc == null) return cb.onLayoutFailed(null)
        pdf = PrintedPdfDocument(context, attrs)
        cb.onLayoutFinished(PrintDocumentInfo.Builder("andvari-recovery-kit.pdf").setContentType(PrintDocumentInfo.CONTENT_TYPE_DOCUMENT).setPageCount(1).build(), true)
    }

    override fun onWrite(pages: Array<out PageRange>, dest: ParcelFileDescriptor, cancel: CancellationSignal, cb: WriteResultCallback) {
        val d = doc
        val p = pdf
        if (d == null || p == null) return cb.onWriteFailed(null)
        val page = p.startPage(0)
        drawKit(page.canvas, d)
        p.finishPage(page)
        try {
            FileOutputStream(dest.fileDescriptor).use { p.writeTo(it) }
            cb.onWriteFinished(arrayOf(PageRange.ALL_PAGES))
        } catch (e: Exception) {
            cb.onWriteFailed(e.javaClass.simpleName)
        } finally {
            p.close()
            pdf = null
        }
    }

    override fun onFinish() {
        KitHolds.release(this)
        drop()
    }

    private fun drawKit(c: Canvas, d: KitDocument) {
        val w = c.width.toFloat()
        val margin = 48f
        var y = 64f
        val text = Paint().apply { isAntiAlias = true; textSize = 11f }
        val title = Paint(text).apply { textSize = 20f; typeface = Typeface.DEFAULT_BOLD }
        val mono = Paint(text).apply { textSize = 18f; typeface = Typeface.MONOSPACE }
        fun line(s: String, paint: Paint = text, gap: Float = 6f) {
            for (part in wrap(s, paint, w - 2 * margin)) {
                y += paint.textSize
                c.drawText(part, margin, y, paint)
                y += gap
            }
        }
        line(d.title.english, title, 12f)
        line(d.keepPrivate.english)
        line(d.email)
        line("${d.instance.name} (${d.instance.origin})")
        line(DateFormat.getDateInstance(DateFormat.LONG).format(Date(d.madeAtMs)), gap = 16f)
        for (row in d.groups.withIndex().chunked(4)) line(row.joinToString("   ") { (i, g) -> "${i + 1}: $g" }, mono, 10f)
        y += 12f
        val qr = qrBitmap(d.qrPayload, 220)
        c.drawBitmap(qr, margin, y, null)
        y += qr.height + 12f
        line(d.accountIdLine.english)
        line(d.howToRecover.english)
    }

    private fun wrap(s: String, p: Paint, width: Float): List<String> {
        val out = ArrayList<String>()
        var cur = StringBuilder()
        for (word in s.split(' ')) {
            val next = if (cur.isEmpty()) word else "$cur $word"
            if (p.measureText(next) > width && cur.isNotEmpty()) {
                out += cur.toString()
                cur = StringBuilder(word)
            } else {
                cur = StringBuilder(next)
            }
        }
        if (cur.isNotEmpty()) out += cur.toString()
        return out
    }
}
