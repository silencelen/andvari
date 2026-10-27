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

/**
 * Bounds on client-chosen strings the server PERSISTS outside every per-user quota (server scan
 * 2026-10-26, F1/F2/F3). Each is well above anything a fielded client sends and well below the
 * route's body cap, which was the only ceiling before.
 *
 * - [MUTATION_ID_MAX_CHARS]: every client mints a 36-char UUID (`Mutation.mutationId`), the server
 *   stores the id twice per applied mutation (`mutations` primary key + `resultJson`) for 180 days.
 * - [ITEM_ATTACHMENTS_MAX]: refs per item, each a UUID; the per-item BYTE quota already bounds the
 *   attachments themselves, this bounds the list that names them (`items.attachmentIds`).
 * - [EMAIL_MAX_CHARS]: RFC 5321's 254, the bound `EmailAddress.isValid` already applies to invites;
 *   login/prelogin only ever used the email as a lookup + backoff key, so nothing bounded it.
 */
internal const val MUTATION_ID_MAX_CHARS = 64
internal const val ITEM_ATTACHMENTS_MAX = 256
internal const val EMAIL_MAX_CHARS = 254
