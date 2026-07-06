package io.silencelen.andvari.server

import java.util.UUID

/** Lowercase canonical UUIDv4 — the ID form used everywhere (spec 00). */
fun uuid(): String = UUID.randomUUID().toString()
