package io.silencelen.andvari.core.client.pin

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject

/**
 * `spec/public-instance.json` read at run time (design §0.3): the one in-repo source of the store-build constants, for a
 * platform whose build cannot generate Kotlin from it. The Android and desktop builds read the same file at build time
 * (their `generateAndvariBuildConstants` tasks) and apply the same rule: the instance is baked only when none of
 * `origin`, `instanceId`, `card0Hash` and `kind` is missing or starts with [PLACEHOLDER]. The iPhone app ships the file
 * in its bundle; its Release build must refuse to be made while [placeholders] is not empty (the file's own rule), which
 * is the Xcode build's check, not this reader's.
 *
 * Shared code because the rule is the same everywhere and can be tested on the JVM; nothing in it is the iPhone's.
 */
class PublicInstanceSpec private constructor(
    /** The baked public instance, or null while any of its four values is missing or a placeholder: nothing is baked. */
    val baked: BakedInstance?,
    /** `joinBase`, where the invite and device links point (null when absent or a placeholder). */
    val joinBase: String?,
    /** The names of every value that is still a placeholder (the four instance values and `joinBase`), in file order. */
    val placeholders: List<String>,
) {
    companion object {
        const val PLACEHOLDER = "PLACEHOLDER:"

        private val json = Json { ignoreUnknownKeys = true }

        /** The spec in [text]; null when it is not the file's shape (`v` 1 with a `PUBLIC_INSTANCE` object). */
        fun parse(text: String): PublicInstanceSpec? {
            val root = runCatching { json.parseToJsonElement(text).jsonObject }.getOrNull() ?: return null
            if ((root["v"] as? JsonPrimitive)?.content != "1") return null
            val pi = root["PUBLIC_INSTANCE"] as? JsonObject ?: return null
            fun str(o: JsonObject, key: String): String? = (o[key] as? JsonPrimitive)?.takeIf { it.isString }?.content
            val values = INSTANCE_KEYS.associateWith { str(pi, it) }
            val join = str(root, "joinBase")
            val placeholders = INSTANCE_KEYS.filter { values[it]?.startsWith(PLACEHOLDER) == true } +
                listOfNotNull("joinBase".takeIf { join?.startsWith(PLACEHOLDER) == true })
            val complete = INSTANCE_KEYS.all { k -> values[k].let { it != null && !it.startsWith(PLACEHOLDER) } }
            val baked = if (complete) {
                BakedInstance(values.getValue("origin")!!, values.getValue("instanceId")!!, values.getValue("card0Hash")!!, values.getValue("kind")!!)
            } else {
                null
            }
            return PublicInstanceSpec(baked, join?.takeIf { !it.startsWith(PLACEHOLDER) }, placeholders)
        }

        private val INSTANCE_KEYS = listOf("origin", "instanceId", "card0Hash", "kind")
    }
}
