package io.silencelen.andvari.app.trust

import java.text.DateFormat
import java.util.Date

/** A long identifier in groups of four, as a screen shows it to be read aloud (Settings and the kit's screen). */
internal fun groupedForReading(id: String): String = id.chunked(4).joinToString(" ")

/**
 * Every date and time a screen shows. No seconds, anywhere: a time is to the minute. A time the app does not know (the
 * shared code gives 0, or nothing that can be a time) says so in words, never a date in 1969.
 */
internal object Dates {

    /** A day and a time to the minute, as the phone's language writes them. */
    fun dateTime(ms: Long): String =
        if (!known(ms)) notKnown() else DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT).format(Date(ms))

    /** A day, as the phone's language writes it. */
    fun date(ms: Long, style: Int = DateFormat.MEDIUM): String =
        if (!known(ms)) notKnown() else DateFormat.getDateInstance(style).format(Date(ms))

    /** A time is known when it is after the start of 1970; 0 and below are what the shared code gives for "unknown". */
    fun known(ms: Long): Boolean = ms > 0

    private fun notKnown(): String = UiText.ph(Placeholder.TIME_NOT_KNOWN).shown()
}
