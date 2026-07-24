package io.silencelen.andvari.core.client.autofill

import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonPrimitive

/** Shared parsing for the card vector suites — enum strings use the TS-facing spellings the
 *  web + extension classifiers will consume from the same files. */
internal fun vectorFieldKind(s: String): FieldKind = when (s) {
    "username" -> FieldKind.USERNAME
    "password" -> FieldKind.PASSWORD
    "none" -> FieldKind.NONE
    "cc-number" -> FieldKind.CC_NUMBER
    "cc-exp-month" -> FieldKind.CC_EXP_MONTH
    "cc-exp-year" -> FieldKind.CC_EXP_YEAR
    "cc-exp" -> FieldKind.CC_EXP
    "cc-name" -> FieldKind.CC_NAME
    "cc-csc" -> FieldKind.CC_CSC
    "cc-type" -> FieldKind.CC_TYPE
    else -> error("unknown FieldKind vector value: $s")
}

internal fun vectorFormKind(s: String): FormKind = when (s) {
    "login" -> FormKind.LOGIN
    "card" -> FormKind.CARD
    "mixed" -> FormKind.MIXED
    else -> error("unknown FormKind vector value: $s")
}

/** maxLength/inputMode/frameDomain are optional — classify cases omit them, cardform cases spell them out. */
internal fun vectorFieldSignal(o: JsonObject): FieldSignal {
    fun str(k: String): String? = o[k]?.takeIf { it !is JsonNull }?.jsonPrimitive?.content
    fun int(k: String): Int? = o[k]?.takeIf { it !is JsonNull }?.jsonPrimitive?.int
    return FieldSignal(
        hints = o["hints"]?.jsonArray?.map { it.jsonPrimitive.content } ?: emptyList(),
        inputTypeClass = int("inputTypeClass") ?: 0,
        inputTypeVariation = int("inputTypeVariation") ?: 0,
        htmlType = str("htmlType"),
        htmlNameOrId = str("htmlNameOrId"),
        maxLength = int("maxLength"),
        inputMode = str("inputMode"),
        frameDomain = str("frameDomain"),
        htmlId = str("htmlId"),
        labelText = str("labelText"),
    )
}
