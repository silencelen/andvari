package io.silencelen.andvari.server

import java.util.UUID

/** Lowercase canonical UUIDv4 — the ID form used everywhere (spec 00). */
fun uuid(): String = UUID.randomUUID().toString()

/** The reader for the [uuid] form — ONE pattern for every id gate on the server: the path/query
 *  gate ([requireUuid], App.kt) and the body-field gates in Service. Kept here beside the writer
 *  so the two can never drift; it was maintained as two identical copies until 2026-07-27. */
internal val UUID_RE = Regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

/** A v2 removal/leave nonce (security review 2026-10, root cause A §6.1, branch A7): 16 bytes as canonical
 *  base64url, unpadded — 22 characters, the last carrying only two data bits. */
internal val V2_NONCE_RE = Regex("^[A-Za-z0-9_-]{21}[AQgw]$")
