package io.silencelen.andvari.app.autofill

import android.service.autofill.FillEventHistory

/**
 * Item 6: the platform's own record of which offered row the person picked ([FillEventHistory], which the service reads
 * at the next request). A row that carries values names its item as its dataset id ([DatasetBuilder]); a pick of it is
 * `TYPE_DATASET_SELECTED` with that id. A row without values (a confirm, the chooser) is released when the person
 * confirms in andvari's window, so its pick is not read here.
 */
internal object FillPicks {
    /** `FillEventHistory.Event.TYPE_DATASET_SELECTED`. */
    const val DATASET_SELECTED = 0

    /** The items picked, from (event type, dataset id) pairs, once each, in order. */
    fun picked(events: List<Pair<Int, String?>>): List<String> =
        events.filter { it.first == DATASET_SELECTED }.mapNotNull { it.second?.takeIf { id -> id.isNotEmpty() } }.distinct()

    /**
     * When this service last replied to a fill request (Unix milliseconds), 0 when it has not replied since its process
     * started. The platform's record of picks is about the last reply only, and the platform gives no time with it, so a
     * pick read from that record happened after this time and before the request that reads it.
     */
    @Volatile
    var lastReplyAtMs: Long = 0L
        private set

    /** The service replied now ([lastReplyAtMs]). */
    fun replied(atMs: Long) {
        lastReplyAtMs = atMs
    }

    /** The platform's history as plain pairs; empty when it has none or cannot be read. */
    fun eventsOf(history: FillEventHistory?): List<Pair<Int, String?>> =
        runCatching { history?.events.orEmpty().map { it.type to it.datasetId } }.getOrDefault(emptyList())
}
