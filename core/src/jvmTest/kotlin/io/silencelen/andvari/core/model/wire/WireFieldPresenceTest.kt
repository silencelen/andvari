package io.silencelen.andvari.core.model.wire

import io.silencelen.andvari.core.crypto.KdfParams
import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PolymorphicKind
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.SerialKind
import kotlinx.serialization.descriptors.StructureKind
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.serializer
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * Spec 03 §0.1 "Field presence": a message carries every field it lists, default-valued or not; an
 * optional field (`field?`) is absent when it has no value; `null` is sent only where a row gives it a
 * meaning of its own.
 *
 * The Kotlin types encode the spec's listing this way (WireCommon.kt): a field the spec lists is a
 * property without a default, or with a non-null default; an optional field is nullable with a `null`
 * default; a field whose `null` has a meaning is nullable WITHOUT a default. So the rule the encoding
 * must keep, per property, is:
 *  - not (optional and nullable) → always a key in the JSON, whatever its value;
 *  - optional and nullable, at its `null` default → no key at all;
 *  - a JSON `null` appears only for a property that is nullable without a default.
 *
 * [everyWireDtoCarriesEveryListedField] builds, from each serializer's descriptor, the smallest JSON the
 * type accepts (only the keys it requires), decodes it — so every defaulted property takes its default,
 * which is the case a library would leave out — re-encodes it with [WireJson.json] and checks the rule
 * on the result, recursing into nested objects (`kdfParams` inside `AccountKeys`, `Quota` inside
 * `AdminPolicy`, …). The set of types is every request and response class of [WireRoute] plus every
 * serializable class in the `core.model.wire` package, found on the class path, so a type added later
 * is covered without editing this test.
 */
@OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
class WireFieldPresenceTest {

    /** Types (by serial name, at any depth) whose decoder demands more than the descriptor shows. */
    private val samples: Map<String, String> = mapOf(
        // `auth`: exactly one key (spec 03 §2)
        "RegisterAuth" to """{"signupTicket":"x"}""",
    )

    @Test
    fun everyWireDtoCarriesEveryListedField() {
        val types = wireTypes()
        assertTrue(types.size > 80, "found only ${types.size} wire types; the class-path scan is broken")
        val problems = mutableListOf<String>()
        var checked = 0
        for ((name, ser) in types) {
            val d = ser.descriptor
            if (d.kind != StructureKind.CLASS) continue
            val input = minimal(d, 0) ?: continue
            val value = try {
                WireJson.json.decodeFromJsonElement(ser, input)
            } catch (e: Exception) {
                problems += "$name: the minimal body $input does not decode (${e.message?.take(160)}); add a sample"
                continue
            }
            val out = WireJson.json.encodeToJsonElement(ser, value)
            check(name, d, out, problems)
            checked++
        }
        assertTrue(checked > 80, "checked only $checked types")
        if (problems.isNotEmpty()) fail(problems.joinToString("\n"))
    }

    /** `kdfParams` is the field that was sent as `{}`: every one of its four keys is present at its defaults. */
    @Test
    fun kdfParamsAtItsDefaultsCarriesAllFourKeys() {
        val o = WireJson.json.encodeToJsonElement(KdfParams.serializer(), KdfParams()).jsonObject
        assertEquals(setOf("v", "alg", "ops", "memBytes"), o.keys)
        val p = WireJson.json.encodeToJsonElement(PreloginResponse.serializer(), PreloginResponse("salt", KdfParams())).jsonObject
        assertEquals(setOf("v", "alg", "ops", "memBytes"), p.getValue("kdfParams").jsonObject.keys)
    }

    /** A `false` is written as `false`: the calling device's flag is present when it is false. */
    @Test
    fun aFalseIsWrittenAsFalse() {
        val o = WireJson.json.encodeToJsonElement(Device.serializer(),
            Device("d", WirePlatform.CLI, "n", "1.0.0", 1, 2, true, DeviceHow.REGISTERED)).jsonObject
        assertEquals(JsonPrimitive(false), o["current"])
        assertFalse("linkedFrom" in o, "an optional field with no value is absent")
    }

    /** The rows where `null` has a meaning of its own still send it (spec 03 §0.1). */
    @Test
    fun theRowsWhereNullHasAMeaningStillSendIt() {
        fun keysWithNull(e: JsonElement) = e.jsonObject.filterValues { it is JsonNull }.keys
        val j = WireJson.json
        // §5: an account that never stored a state; §5.x: never wrote a ledger
        assertEquals(setOf("sealedState"), keysWithNull(j.encodeToJsonElement(AccountStateResponse.serializer(), AccountStateResponse(null, 0))))
        assertEquals(setOf("sealedUsage"), keysWithNull(j.encodeToJsonElement(UsageResponse.serializer(), UsageResponse(null, 0))))
        // §16.7: a device not yet seen
        assertEquals(setOf("clientVersion", "lastSeenAt"), keysWithNull(j.encodeToJsonElement(Device.serializer(),
            Device("d", WirePlatform.CLI, "n", null, 1, null, false, DeviceHow.LINKED))))
        // §7.1: a quota PUT returns each null limit to the instance default; the keys are required
        assertEquals(setOf("accountBytes", "items", "ownedSharedVaults", "openLinks"),
            keysWithNull(j.encodeToJsonElement(QuotaPut.serializer(), QuotaPut(null, null, null, null, "k"))))
        // §7.2: a policy PUT's signup null leaves the stored value unchanged; GET shows null when nothing is stored
        assertEquals(setOf("mode", "cap"), keysWithNull(j.encodeToJsonElement(AdminSignupPolicy.serializer(), AdminSignupPolicy(null, null))))
        // §15.3: an open link has `reveal: null`, and host-minted links name no creator with explicit nulls
        val open = j.encodeToJsonElement(LinkFetchResponse.serializer(),
            LinkFetchResponse.open(LinkKind.CONNECT, "offer", 5, null, null))
        assertEquals(setOf("reveal", "creatorUserId", "creatorIdentityPub"), keysWithNull(open))
        assertEquals(setOf("kind", "offer", "expiresAt", "state", "creatorUserId", "creatorIdentityPub", "reveal"), open.jsonObject.keys)
        // ... while the answered form serves neither the offer nor its creator, and reveal (null until posted)
        val answered = j.encodeToJsonElement(LinkFetchResponse.serializer(), LinkFetchResponse.answered(LinkKind.CONNECT, null))
        assertEquals(setOf("kind", "state", "reveal"), answered.jsonObject.keys)
        // both forms still decode to what was encoded
        assertEquals(LinkFetchResponse.open(LinkKind.CONNECT, "offer", 5, null, null),
            j.decodeFromJsonElement(LinkFetchResponse.serializer(), open))
        assertEquals(LinkFetchResponse.answered(LinkKind.CONNECT, null),
            j.decodeFromJsonElement(LinkFetchResponse.serializer(), answered))
    }

    // ---- the descriptor walk ----

    private fun check(path: String, d: SerialDescriptor, e: JsonElement, problems: MutableList<String>) {
        if (d.kind != StructureKind.CLASS) return
        val o = e as? JsonObject ?: return problems.add("$path: not an object: $e").let { }
        for (i in 0 until d.elementsCount) {
            val n = d.getElementName(i)
            val ed = d.getElementDescriptor(i)
            val optionalNullable = d.isElementOptional(i) && ed.isNullable
            val v = o[n]
            when {
                v == null && !optionalNullable -> problems += "$path.$n: listed, but absent from ${o.keys}"
                v is JsonNull && d.isElementOptional(i) -> problems += "$path.$n: an optional field sent as null"
                v != null && v !is JsonNull -> check("$path.$n", ed, v, problems)
            }
        }
    }

    /** The smallest JSON a descriptor accepts: its required keys only, each at a neutral value. */
    private fun minimal(d: SerialDescriptor, depth: Int): JsonElement? {
        if (depth > 8) return null
        samples[d.serialName]?.let { return WireJson.json.parseToJsonElement(it) }
        return when (d.kind) {
            PrimitiveKind.STRING -> JsonPrimitive("x")
            PrimitiveKind.BOOLEAN -> JsonPrimitive(false)
            PrimitiveKind.INT, PrimitiveKind.LONG, PrimitiveKind.SHORT, PrimitiveKind.BYTE -> JsonPrimitive(0)
            PrimitiveKind.FLOAT, PrimitiveKind.DOUBLE -> JsonPrimitive(0.0)
            PrimitiveKind.CHAR -> JsonPrimitive("x")
            SerialKind.ENUM -> JsonPrimitive(d.getElementName(0))
            StructureKind.LIST -> JsonArray(emptyList())
            StructureKind.MAP -> JsonObject(emptyMap())
            StructureKind.CLASS -> {
                val m = LinkedHashMap<String, JsonElement>()
                for (i in 0 until d.elementsCount) {
                    if (d.isElementOptional(i)) continue
                    val ed = d.getElementDescriptor(i)
                    m[d.getElementName(i)] = if (ed.isNullable) JsonNull else (minimal(ed, depth + 1) ?: return null)
                }
                JsonObject(m)
            }
            PolymorphicKind.SEALED -> if (d.serialName.startsWith("kotlinx.serialization.json.")) JsonObject(emptyMap()) else null
            else -> null
        }
    }

    /** Every request/response class of the route index, plus every serializable class of this package. */
    private fun wireTypes(): Map<String, KSerializer<Any?>> {
        val classes = LinkedHashSet<Class<*>>()
        for (r in WireRoute.entries) {
            r.request?.let { classes += it.java }
            r.response?.let { classes += it.java }
        }
        val pkg = WireJson::class.java.`package`.name
        val loader = WireJson::class.java.classLoader
        for (url in loader.getResources(pkg.replace('.', '/')).toList()) {
            if (url.protocol != "file") continue
            File(url.toURI()).listFiles().orEmpty()
                .filter { it.name.endsWith(".class") && '$' !in it.name }
                .forEach { classes += loader.loadClass(pkg + "." + it.name.removeSuffix(".class")) }
        }
        val out = LinkedHashMap<String, KSerializer<Any?>>()
        for (c in classes) {
            if (c.isEnum || c.isInterface || java.lang.reflect.Modifier.isAbstract(c.modifiers)) continue
            @Suppress("UNCHECKED_CAST")
            val s = try { serializer(c) as KSerializer<Any?> } catch (_: Exception) { continue }
            out[c.name] = s
        }
        return out
    }
}
