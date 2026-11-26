package io.silencelen.andvari.desktop.trust

import java.lang.reflect.Modifier

/**
 * A shared-code object the fake cannot reach by its own walk, for a test: a copy of [obj] (an object the shared code
 * made) through the constructor whose parameters are the class's own instance fields, in their order, with only the
 * fields named in [changes] replaced; every other field, one the shared code adds later among them, is carried from
 * [obj] as it is. A constructor that no longer matches the fields, or a name that is not a field, fails loudly.
 */
internal fun <T : Any> rebuilt(obj: T, vararg changes: Pair<String, Any?>): T {
    val c = obj.javaClass
    val fields = c.declaredFields.filter { !Modifier.isStatic(it.modifiers) && !it.isSynthetic }
    val asked = changes.toMap()
    check(asked.keys.all { name -> fields.any { it.name == name } }) { "${asked.keys} are not all among ${c.simpleName}'s fields ${fields.map { it.name }}" }
    val ctor = c.declaredConstructors.singleOrNull { k -> k.parameterTypes.toList() == fields.map { it.type } }
        ?: error("${c.simpleName} has no constructor whose parameters are its fields ${fields.map { it.name }}")
    ctor.isAccessible = true
    val args = fields.map { f -> if (f.name in asked) asked[f.name] else f.also { it.isAccessible = true }.get(obj) }
    @Suppress("UNCHECKED_CAST")
    return ctor.newInstance(*args.toTypedArray()) as T
}
