package io.silencelen.andvari.app

import io.silencelen.andvari.app.ClipboardClear.Act
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * A copied secret is cleared after the policy's window whether or not andvari is in front,
 * without reading the clipboard when it is not, from a timer that survives a lock and a background stay. The old rule
 * kept the secret whenever the clipboard could not be read (always, in the background).
 */
class ClipboardClearTest {
    @Test
    fun notInFrontTheClearRunsWithoutReading() {
        // The old shouldClearClipboard answered false for a null read: the secret stayed after a background stay.
        assertEquals(Act.CLEAR_WITHOUT_READING, ClipboardClear.decide(5, 5, inFront = false, recordedTimestamp = 7, clipTimestamp = null, valueStillThere = null))
        // In front with nothing readable (an empty clipboard, no focus): nothing to tell apart, so it clears.
        assertEquals(Act.CLEAR_WITHOUT_READING, ClipboardClear.decide(5, 5, inFront = true, recordedTimestamp = 7, clipTimestamp = null, valueStillThere = null))
    }

    @Test
    fun inFrontOnlyThisCopyIsCleared() {
        // The clip's timestamp is the one recorded at the copy: ours, even after the process was ended (no value then).
        assertEquals(Act.CLEAR, ClipboardClear.decide(5, 5, inFront = true, recordedTimestamp = 7, clipTimestamp = 7, valueStillThere = null))
        // In the same process the text tells it too.
        assertEquals(Act.CLEAR, ClipboardClear.decide(5, 5, inFront = true, recordedTimestamp = 0, clipTimestamp = 9, valueStillThere = true))
        // Something copied since is left alone.
        assertEquals(Act.KEEP, ClipboardClear.decide(5, 5, inFront = true, recordedTimestamp = 7, clipTimestamp = 9, valueStillThere = false))
        assertEquals(Act.KEEP, ClipboardClear.decide(5, 5, inFront = true, recordedTimestamp = 7, clipTimestamp = 9, valueStillThere = null))
    }

    @Test
    fun aLaterCopyOrADoneClearOwnsNothing() {
        assertEquals(Act.KEEP, ClipboardClear.decide(5, 6, inFront = false, recordedTimestamp = 7, clipTimestamp = null, valueStillThere = null))
        assertEquals(Act.KEEP, ClipboardClear.decide(5, null, inFront = false, recordedTimestamp = 7, clipTimestamp = null, valueStillThere = null))
    }

    @Test
    fun theRecordHoldsANonceAndATimestampOnly() {
        assertEquals("-12:34", ClipboardClear.encode(-12, 34))
        assertEquals(-12L to 34L, ClipboardClear.decode("-12:34"))
        assertNull(ClipboardClear.decode(null))
        assertNull(ClipboardClear.decode("x:1"))
        assertNull(ClipboardClear.decode("1:2:3"))
    }

    @Test
    fun theTimerSurvivesALockAndTheProcessEnd() {
        val src = File("src/main/kotlin/io/silencelen/andvari/app/ClipboardClear.kt").readText()
        // A main-thread timer that nothing at a lock cancels, and an alarm for a process the system ended.
        assertTrue(src.contains("handler.postDelayed({ fire(app, nonce, value) }, clearMs)"))
        assertTrue(src.contains("am.setAndAllowWhileIdle(AlarmManager.ELAPSED_REALTIME_WAKEUP"))
        assertTrue(src.contains("PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT"))
        // The clipboard is read only in front.
        assertTrue(src.contains("val clipTs = if (inFront) runCatching { cm.primaryClipDescription?.timestamp }.getOrNull() else null"))
        assertTrue(src.contains("val stillThere = if (inFront && value != null)"))
        // No secret in the record.
        assertTrue(src.contains("file(app).writeText(encode(nonce, timestamp))"))
        val manifest = File("src/main/AndroidManifest.xml").readText()
        assertTrue(Regex("""ClipboardClearReceiver"\s+android:exported="false"""").containsMatchIn(manifest))
        assertFalse(manifest.contains("SCHEDULE_EXACT_ALARM") || manifest.contains("USE_EXACT_ALARM"), "no new permission")
        assertTrue(File("src/main/kotlin/io/silencelen/andvari/app/MainActivity.kt").readText().contains("ClipboardClear.scheduled(ctx, cm, value, clearSeconds * 1000L)"))
    }
}
