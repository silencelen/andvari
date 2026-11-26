package io.silencelen.andvari.core.app.content

import java.io.File
import java.lang.reflect.Modifier
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The app API's surface rules (`AppApiSurfaceTest`), held for the vault's content too: Swift reaches [VaultContent]
 * through the same Objective-C export, so no name may be changed by it, and no type may share its simple name with
 * another type of the module.
 */
class ContentSurfaceTest {
    private val repo = File(System.getProperty("andvari.vectors.dir") ?: error("andvari.vectors.dir not set")).resolve("../..").canonicalFile
    private val main = repo.resolve("core/src/commonMain/kotlin")
    private val dir = main.resolve("io/silencelen/andvari/core/app/content")
    private val files = dir.listFiles { f -> f.isFile && f.extension == "kt" }.orEmpty().sortedBy { it.name }

    private val topLevel = Regex("""(?m)^((?:(?:public|internal|private|open|sealed|abstract|enum|data|fun|value|annotation)\s+)*)(class|interface|object)\s+(\w+)""")

    private class Declared(val name: String, val exported: Boolean, val file: File)

    private fun declarations(file: File): List<Declared> = topLevel.findAll(file.readText()).map { m ->
        val mods = m.groupValues[1]
        Declared(m.groupValues[3], "internal" !in mods && "private" !in mods, file)
    }.toList()

    private fun surface(): List<Class<*>> {
        val out = LinkedHashSet<Class<*>>()
        fun add(c: Class<*>) {
            if (c.isAnonymousClass || c.isSynthetic || c.isLocalClass || Modifier.isPrivate(c.modifiers)) return
            if (!out.add(c)) return
            c.declaredClasses.forEach(::add)
        }
        for (f in files) for (d in declarations(f).filter { it.exported }) add(Class.forName("io.silencelen.andvari.core.app.content.${d.name}"))
        return out.toList()
    }

    private val families = listOf("alloc", "copy", "mutableCopy", "new", "init")
    private fun inFamily(name: String): Boolean {
        val n = name.trimStart('_')
        return families.any { n.startsWith(it) && (n.length == it.length || !n[it.length].isLowerCase()) }
    }
    private val reserved = (
        "auto break case char const continue default do double else enum extern float for goto if inline int long register restrict return " +
            "short signed sizeof static struct switch typedef union unsigned void volatile while bool class delete explicit export friend mutable " +
            "namespace operator private protected public template this throw try typename using virtual id in out inout bycopy byref oneway self " +
            "super nil associatedtype deinit extension fileprivate func import internal let open protocol rethrows subscript typealias var as " +
            "catch defer fallthrough guard is repeat throws where true false description debugDescription hash superclass zone retain release " +
            "autorelease retainCount dealloc finalize load initialize"
        ).split(' ').toSet()

    @Test
    fun noMemberOrEnumCaseHasANameTheSwiftExportChanges() {
        val classes = surface()
        assertTrue(classes.any { it == VaultContent::class.java } && classes.size >= 8, "found ${classes.map { it.simpleName }}")
        val bad = ArrayList<String>()
        for (c in classes) {
            val names = LinkedHashSet<String>()
            for (m in c.declaredMethods) {
                if (m.isSynthetic || m.isBridge || '$' in m.name || !Modifier.isPublic(m.modifiers)) continue
                if (c.isEnum && m.name in setOf("values", "valueOf", "getEntries")) continue
                val n = m.name
                names += if (n.length > 3 && n.startsWith("get") && n[3].isUpperCase() && m.parameterCount == 0) n.substring(3).replaceFirstChar(Char::lowercaseChar) else n
                for (p in m.parameters) if (p.isNamePresent) names += p.name
            }
            if (c.isEnum) for (k in c.enumConstants) names += (k as Enum<*>).name.lowercase().split('_').mapIndexed { i, w -> if (i == 0) w else w.replaceFirstChar(Char::uppercaseChar) }.joinToString("")
            for (n in names) {
                if (inFamily(n)) bad += "${c.simpleName}.$n is in an Objective-C method family"
                if (n in reserved) bad += "${c.simpleName}.$n is a reserved word"
            }
        }
        assertEquals(emptyList(), bad)
    }

    @Test
    fun noTypeSharesItsNameWithAnotherTypeOfTheModule() {
        val mine = files.flatMap(::declarations).filter { it.exported }
        val all = listOf(main, repo.resolve("core/src/iosMain/kotlin")).flatMap { root -> root.walk().filter { it.isFile && it.extension == "kt" }.toList() }
            .flatMap(::declarations).filter { it.exported }
        val clashes = mine.mapNotNull { d -> all.filter { it.name == d.name && it.file != d.file }.takeIf { it.isNotEmpty() }?.let { "${d.name} is also in ${it.map { o -> o.file.name }}" } }
        assertEquals(emptyList(), clashes)
    }

    @Test
    fun theInterfaceHasNoDefaultArgumentOverloadOrTypeParameter_andNoStateIsADataClass() {
        val c = VaultContent::class.java
        val methods = c.declaredMethods.filter { !it.isSynthetic && '$' !in it.name }
        assertEquals(emptyList(), methods.groupBy { it.name }.filter { it.value.size > 1 }.keys.toList(), "overloads")
        assertEquals(emptyList(), methods.filter { it.typeParameters.isNotEmpty() }.map { it.name }, "type parameters")
        assertTrue(c.declaredClasses.none { it.simpleName == "DefaultImpls" }, "a default argument or implementation")
        val data = files.filter { Regex("""(?m)^\s*(?:\w+\s+)*data\s+class\s+\w+""").containsMatchIn(it.readText()) }.map { it.name }
        assertEquals(emptyList(), data)
    }
}
