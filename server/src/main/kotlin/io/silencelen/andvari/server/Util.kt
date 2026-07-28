package io.silencelen.andvari.server

import java.util.UUID

/** Lowercase canonical UUIDv4 — the ID form used everywhere (spec 00). */
fun uuid(): String = UUID.randomUUID().toString()

/** The reader for the [uuid] form — ONE pattern for every id gate on the server: the path/query
 *  gate ([requireUuid], App.kt) and the body-field gates in Service. Kept here beside the writer
 *  so the two can never drift; it was maintained as two identical copies until 2026-07-27. */
internal val UUID_RE = Regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
