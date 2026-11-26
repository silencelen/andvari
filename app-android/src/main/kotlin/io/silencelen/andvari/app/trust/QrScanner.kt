package io.silencelen.andvari.app.trust

import android.Manifest
import android.content.pm.PackageManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.ReaderException
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader
import java.util.concurrent.Executors

// The in-app QR scanner (onboarding and trust design §12.1 "three scanners, three jobs"): ONE camera component with a
// call site on each entry that takes a payload ("Scan an invite", "Link from your other device", "Scan your recovery
// kit") and on the signed-in Links page. The scanner only reads text and hands it to its call site, which passes it to
// exactly the intent its paste field calls, with PayloadSource.SCANNED: every check a pasted payload gets, a scanned one
// gets, and nothing scanned is acted on without the screen that follows a paste. The scanner calls no intent itself.
//
// Camera frames go to the preview surface and to the analyser. The analyser copies a frame's brightness plane into ONE
// reused buffer, decodes it, and zeroes the buffer before it returns; it keeps no frame, takes no picture, and writes
// nothing to disk. The camera permission is asked only when the person opens a scanner; a refusal leaves the field
// below the scanner as the way in, and says so.

/** What the scanner accepts from a decoded QR code before it is handed on; the entry's own checks follow. */
internal object ScannedText {
    /** Far above any link or kit the app makes (a few hundred characters); a QR code can carry about 4,000. */
    const val MAX_CHARS: Int = 2048

    /**
     * The decoded text, trimmed, or null when it is refused: nothing, blank, longer than [MAX_CHARS], or holding a
     * control or invisible formatting character (a line break, a NUL, a right-to-left override). A payload the app
     * makes is one line of plain characters, so a refusal here loses nothing a paste field would have taken.
     */
    fun accept(raw: String?): String? {
        val t = raw?.trim() ?: return null
        if (t.isEmpty() || t.length > MAX_CHARS) return null
        if (t.any { Character.isISOControl(it) || Character.getType(it) == Character.FORMAT.toInt() || it.code in REFUSED_EXTRA }) return null
        return t
    }

    /**
     * The line and paragraph separators (U+2028, U+2029) are not
     * controls or formatting characters to Java, and the Hangul filler (U+3164) is a letter that draws as nothing.
     */
    private val REFUSED_EXTRA = setOf(0x2028, 0x2029, 0x3164)
}

/** Decodes QR codes from a camera frame's brightness plane with zxing-core. QR codes only; no other symbology. */
internal class QrFrameDecoder {
    private val reader = QRCodeReader()
    private val hints: Map<DecodeHintType, Any> = mapOf(
        DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE),
        DecodeHintType.CHARACTER_SET to "UTF-8",
    )

    /**
     * The accepted text of the QR code in [luma] (a brightness plane of [width] x [height] whose rows are [rowStride]
     * bytes apart), or null. [luma] is zeroed before this returns, whatever happens, so no frame outlives its decode.
     */
    fun decodeAndWipe(luma: ByteArray, rowStride: Int, width: Int, height: Int): String? {
        try {
            if (width <= 0 || height <= 0 || rowStride < width || luma.size < rowStride * height) return null
            val source = PlanarYUVLuminanceSource(luma, rowStride, height, 0, 0, width, height, false)
            val text = try {
                reader.decode(BinaryBitmap(HybridBinarizer(source)), hints).text
            } catch (_: ReaderException) {
                null
            } finally {
                reader.reset()
            }
            return ScannedText.accept(text)
        } finally {
            luma.fill(0)
        }
    }
}

/**
 * The analyser: one reused buffer, wiped after every frame by [QrFrameDecoder.decodeAndWipe]. It reports the first
 * accepted text once and then lets every later frame go unread.
 */
internal class QrAnalyzer(private val onText: (String) -> Unit) : ImageAnalysis.Analyzer {
    private val decoder = QrFrameDecoder()
    private var luma = ByteArray(0)

    @Volatile
    private var done = false

    override fun analyze(image: ImageProxy) {
        image.use {
            if (done) return
            val plane = image.planes[0]
            val stride = plane.rowStride
            val need = stride * image.height
            if (luma.size != need) luma = ByteArray(need)
            val buffer = plane.buffer
            buffer.rewind()
            buffer.get(luma, 0, minOf(buffer.remaining(), need))
            val text = decoder.decodeAndWipe(luma, stride, image.width, image.height) ?: return
            done = true
            onText(text)
        }
    }
}

/**
 * The scanner's control on a screen: a button that opens the camera (asking for the permission first, only now), the
 * camera while it is open, and what stopped it. [onScanned] gets accepted text once per opening, on the main thread.
 */
@Composable
internal fun ScanQrControl(enabled: Boolean, onScanned: (String) -> Unit) {
    val context = LocalContext.current
    val hasCamera = remember { context.packageManager.hasSystemFeature(PackageManager.FEATURE_CAMERA_ANY) }
    var open by remember { mutableStateOf(false) }
    var stopped by remember { mutableStateOf<Placeholder?>(null) }
    val askCamera = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        if (granted) {
            stopped = null
            open = true
        } else {
            stopped = Placeholder.SCAN_NOT_ALLOWED
        }
    }
    if (!hasCamera) {
        Quiet(UiText.ph(Placeholder.SCAN_NO_CAMERA))
        return
    }
    if (open && enabled) {
        QrCameraView(
            onText = { text ->
                open = false
                onScanned(text)
            },
            onFailed = {
                open = false
                stopped = Placeholder.SCAN_CAMERA_FAILED
            },
        )
        Quieter(UiText.ph(Placeholder.SCAN_STOP)) { open = false }
    } else {
        Second(UiText.ph(Placeholder.SCAN_OPEN), enabled = enabled) {
            stopped = null
            if (ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) {
                open = true
            } else {
                askCamera.launch(Manifest.permission.CAMERA)
            }
        }
    }
    stopped?.let { Quiet(UiText.ph(it)) }
}

/** The camera: a preview and the analyser, bound while this is shown and released when it leaves. */
@Composable
private fun QrCameraView(onText: (String) -> Unit, onFailed: () -> Unit) {
    val context = LocalContext.current
    val owner = LocalLifecycleOwner.current
    val latestOnText by rememberUpdatedState(onText)
    val latestOnFailed by rememberUpdatedState(onFailed)
    val previewView = remember { PreviewView(context).apply { implementationMode = PreviewView.ImplementationMode.COMPATIBLE } }
    DisposableEffect(owner) {
        val main = ContextCompat.getMainExecutor(context)
        val worker = Executors.newSingleThreadExecutor()
        val future = ProcessCameraProvider.getInstance(context)
        var provider: ProcessCameraProvider? = null
        var analysis: ImageAnalysis? = null
        var disposed = false
        future.addListener({
            if (disposed) return@addListener
            val p = runCatching { future.get() }.getOrNull()
            if (p == null) {
                latestOnFailed()
                return@addListener
            }
            val selector = listOf(CameraSelector.DEFAULT_BACK_CAMERA, CameraSelector.DEFAULT_FRONT_CAMERA)
                .firstOrNull { runCatching { p.hasCamera(it) }.getOrDefault(false) }
            if (selector == null) {
                latestOnFailed()
                return@addListener
            }
            val preview = Preview.Builder().build().also { it.setSurfaceProvider(previewView.surfaceProvider) }
            val a = ImageAnalysis.Builder().setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST).build()
            a.setAnalyzer(worker, QrAnalyzer { text -> main.execute { if (!disposed) latestOnText(text) } })
            val bound = runCatching {
                p.unbindAll()
                p.bindToLifecycle(owner, selector, preview, a)
            }
            if (bound.isFailure) {
                a.clearAnalyzer()
                latestOnFailed()
                return@addListener
            }
            provider = p
            analysis = a
        }, main)
        onDispose {
            disposed = true
            analysis?.clearAnalyzer()
            provider?.unbindAll()
            worker.shutdown()
        }
    }
    AndroidView({ previewView }, Modifier.fillMaxWidth().aspectRatio(1f).padding(vertical = 4.dp))
    Quiet(UiText.ph(Placeholder.SCAN_POINT))
}
