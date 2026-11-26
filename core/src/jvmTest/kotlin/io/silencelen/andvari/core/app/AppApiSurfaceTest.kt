package io.silencelen.andvari.core.app

import java.io.File
import java.lang.reflect.Modifier
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * What can be checked on this side of the Swift boundary. The IF-3 surface is called from Swift through the
 * Kotlin/Native Objective-C export, which only a Mac builds; these tests keep the surface inside the part of Kotlin
 * that the export carries over unchanged, so a Swift call site written from the Kotlin source is the one that
 * compiles. They also pin, from the source, the two shape rules the API's safety rests on.
 *
 * JVM only: it reads the sources and uses Java reflection.
 */
class AppApiSurfaceTest {
    private val repo = File(System.getProperty("andvari.vectors.dir") ?: error("andvari.vectors.dir not set")).resolve("../..").canonicalFile
    private val main = repo.resolve("core/src/commonMain/kotlin")
    private val appDir = main.resolve("io/silencelen/andvari/core/app")

    /** The files of the app API: every `*Api.kt` and the copy keys. */
    private val apiFiles: List<File> =
        appDir.listFiles { f -> f.isFile && (f.name.endsWith("Api.kt") || f.name == "AppCopy.kt") }.orEmpty().sortedBy { it.name }

    /** The fake, which Swift previews and UI tests construct. */
    private val fakeFiles: List<File> = appDir.resolve("fake").listFiles { f -> f.isFile && f.extension == "kt" }.orEmpty().sortedBy { it.name }

    private class Declared(val name: String, val modifiers: Set<String>, val kind: String, val file: File) {
        val exported: Boolean get() = "internal" !in modifiers && "private" !in modifiers
    }

    private val topLevel = Regex("""(?m)^((?:(?:public|internal|private|open|sealed|abstract|enum|data|fun|value|annotation)\s+)*)(class|interface|object)\s+(\w+)""")

    private fun declarations(file: File): List<Declared> = topLevel.findAll(file.readText()).map { m ->
        Declared(m.groupValues[3], m.groupValues[1].split(Regex("\\s+")).filter { it.isNotEmpty() }.toSet(), m.groupValues[2], file)
    }.toList()

    private fun packageOf(file: File): String = Regex("""(?m)^package\s+([\w.]+)""").find(file.readText())!!.groupValues[1]

    /** Every exported class of the surface, with its nested classes. */
    private fun surfaceClasses(): List<Class<*>> {
        val out = LinkedHashSet<Class<*>>()
        fun add(c: Class<*>) {
            if (c.isAnonymousClass || c.isSynthetic || c.isLocalClass || Modifier.isPrivate(c.modifiers)) return
            if (!out.add(c)) return
            c.declaredClasses.forEach(::add)
        }
        for (file in apiFiles + fakeFiles) {
            for (d in declarations(file).filter { it.exported }) add(Class.forName("${packageOf(file)}.${d.name}"))
        }
        return out.toList()
    }

    // Objective-C gives a method whose selector starts with one of these words (and then anything but a lowercase
    // letter) the ownership rules of that family; Kotlin/Native renames such a member, so Swift sees another name.
    private val families = listOf("alloc", "copy", "mutableCopy", "new", "init")

    private fun inFamily(name: String): Boolean {
        val n = name.trimStart('_')
        return families.any { n.startsWith(it) && (n.length == it.length || !n[it.length].isLowerCase()) }
    }

    // Names Swift or Objective-C cannot use plainly as a member, an enum case or a parameter label: keywords of C,
    // C++, Objective-C and Swift, and the members every NSObject already has. The export appends `_` to them or
    // needs backticks at every call site.
    private val reserved: Set<String> = (
        "auto break case char const continue default do double else enum extern float for goto if inline int long " +
            "register restrict return short signed sizeof static struct switch typedef union unsigned void volatile while " +
            "bool class delete explicit export friend mutable namespace operator private protected public template this " +
            "throw try typename using virtual " +
            "id in out inout bycopy byref oneway self super nil " +
            "associatedtype deinit extension fileprivate func import internal let open protocol rethrows subscript " +
            "typealias var as catch defer fallthrough guard is repeat throws where true false " +
            "description debugDescription hash superclass zone retain release autorelease retainCount dealloc finalize load initialize"
        ).split(' ').toSet()

    private fun camel(enumName: String): String =
        enumName.lowercase().split('_').filter { it.isNotEmpty() }.mapIndexed { i, w -> if (i == 0) w else w.replaceFirstChar(Char::uppercaseChar) }.joinToString("")

    private fun problem(name: String): String? = when {
        inFamily(name) -> "is in an Objective-C method family"
        name in reserved -> "is a reserved word in Swift or Objective-C"
        else -> null
    }

    @Test
    fun theSurfaceIsFound() {
        // The checks below pass vacuously over nothing, so say what they looked at.
        assertTrue(apiFiles.size >= 13, "the app API's files: ${apiFiles.map { it.name }}")
        assertTrue(fakeFiles.size >= 9, "the fake's files: ${fakeFiles.map { it.name }}")
        val classes = surfaceClasses()
        assertTrue(classes.size > 150, "only ${classes.size} classes found")
        for (expected in listOf(AppApi::class.java, EntryScreen.SignIn::class.java, InviteResult::class.java, CopyKey::class.java)) {
            assertTrue(expected in classes, expected.name)
        }
    }

    @Test
    fun noMemberOrEnumCaseHasANameTheSwiftExportChanges() {
        val bad = ArrayList<String>()
        for (c in surfaceClasses()) {
            val names = LinkedHashSet<String>()
            for (m in c.declaredMethods) {
                if (m.isSynthetic || m.isBridge || '$' in m.name) continue
                if (!Modifier.isPublic(m.modifiers) && !Modifier.isProtected(m.modifiers)) continue
                // What an enum has by itself, which the export handles.
                if (c.isEnum && m.name in setOf("values", "valueOf", "getEntries")) continue
                val n = m.name
                val property = when {
                    n.length > 3 && n.startsWith("get") && n[3].isUpperCase() && m.parameterCount == 0 -> n.substring(3).replaceFirstChar(Char::lowercaseChar)
                    // The setter of a Kotlin property `isX` is `setX`.
                    n.length > 3 && n.startsWith("set") && n[3].isUpperCase() && m.parameterCount == 1 ->
                        if (c.declaredMethods.any { it.name == "is" + n.substring(3) }) "is" + n.substring(3) else n.substring(3).replaceFirstChar(Char::lowercaseChar)
                    else -> n
                }
                names += property
            }
            if (c.isEnum) for (constant in c.enumConstants) names += camel((constant as Enum<*>).name)
            for (n in names) problem(n)?.let { bad += "${c.name.substringAfter("core.app.")}.$n $it" }
        }
        assertEquals(emptyList(), bad)
    }

    @Test
    fun noParameterHasANameTheSwiftExportChanges() {
        val bad = ArrayList<String>()
        var seen = 0
        val start = Regex("""\bfun\s+(?:<[^>]*>\s*)?(?:[\w.<>?]+\.)?(\w+)\(""")
        for (file in apiFiles + fakeFiles) {
            val text = file.readText()
            for (m in start.findAll(text)) {
                // The parameter list, to its matching parenthesis.
                var depth = 1
                var i = m.range.last + 1
                val begin = i
                while (i < text.length && depth > 0) {
                    when (text[i]) {
                        '(' -> depth++
                        ')' -> depth--
                    }
                    i++
                }
                val list = text.substring(begin, i - 1)
                // Split at the commas of the list itself, not those inside a type.
                var level = 0
                var from = 0
                val parameters = ArrayList<String>()
                for ((at, ch) in list.withIndex()) {
                    when (ch) {
                        '(', '<', '[' -> level++
                        ')', ']' -> level--
                        '>' -> if (at == 0 || list[at - 1] != '-') level--
                        ',' -> if (level == 0) {
                            parameters += list.substring(from, at)
                            from = at + 1
                        }
                    }
                }
                parameters += list.substring(from)
                for (p in parameters) {
                    val name = Regex("""^\s*(?:(?:vararg|noinline|crossinline)\s+)*(\w+)\s*:""").find(p)?.groupValues?.get(1) ?: continue
                    seen++
                    problem(name)?.let { bad += "${file.name}: ${m.groupValues[1]}($name) $it" }
                }
            }
        }
        assertTrue(seen > 400, "only $seen parameters found")
        assertEquals(emptyList(), bad)
    }

    @Test
    fun noTypeOfTheSurfaceSharesItsNameWithAnotherTypeOfTheModule() {
        // The export puts every class of the module in one namespace: of two with the same simple name, one gets a `_`.
        val mine = (apiFiles + fakeFiles).flatMap(::declarations).filter { it.exported }
        val sources = listOf(main, repo.resolve("core/src/iosMain/kotlin")).flatMap { root -> root.walk().filter { it.isFile && it.extension == "kt" }.toList() }
        val all = sources.flatMap(::declarations).filter { it.exported }
        assertTrue(mine.size > 100 && all.size > mine.size + 300, "found ${mine.size} types of the surface among ${all.size}")
        val clashes = mine.mapNotNull { d ->
            val others = all.filter { it.name == d.name && it.file != d.file }
            if (others.isEmpty()) null else "${d.name} (${d.file.name}) is also in ${others.map { it.file.relativeTo(repo).path }}"
        }
        assertEquals(emptyList(), clashes)
        // And within the surface itself.
        val twice = mine.groupBy { it.name }.filter { it.value.size > 1 }.keys
        assertEquals(emptySet(), twice)
    }

    @Test
    fun onlyCoreMakesAState() {
        // Rule of the API: a state is the token of the step that produced it, so a UI must not be able to make one.
        // Every plain class of the API's files therefore has a constructor only core can call. The three exceptions
        // are what a UI hands in, and they carry no authority.
        val inputs = setOf("NewAccountInput", "ShareChoice", "QuotaLimits")
        val plainClass = Regex("""(?m)^\s*((?:(?:public|open|data|value|inner)\s+)*)class\s+(\w+)([^\n]*)""")
        val open = ArrayList<String>()
        var seen = 0
        for (file in apiFiles) {
            for (m in plainClass.findAll(file.readText())) {
                val name = m.groupValues[2]
                seen++
                if (name in inputs) continue
                val rest = m.groupValues[3].trimStart()
                if (!rest.startsWith("internal constructor(") && !rest.startsWith("private constructor(")) open += "${file.name}: $name"
            }
        }
        assertTrue(seen > 80, "only $seen classes found")
        assertEquals(emptyList(), open)
    }

    @Test
    fun noStateIsADataClass() {
        // A data class has a public `copy`, which would let a UI make a changed state from a real one (and it is a
        // name in the `copy` family besides). Identity is what the intents compare, so none is needed.
        val found = (apiFiles + fakeFiles).filter { Regex("""(?m)^\s*(?:\w+\s+)*data\s+class\s+\w+""").containsMatchIn(it.readText()) }.map { it.name }
        assertEquals(emptyList(), found)
    }

    @Test
    fun noIntentHasADefaultArgumentOrAnOverloadOrATypeParameter() {
        // Swift sees no default arguments, tells overloads apart only by labels, and loses a function's type
        // parameters. The API's interfaces use none of the three.
        val bad = ArrayList<String>()
        for (c in surfaceClasses().filter { it.isInterface && it.name.startsWith("io.silencelen.andvari.core.app.") && ".fake." !in it.name }) {
            val methods = c.declaredMethods.filter { !it.isSynthetic && '$' !in it.name }
            for ((name, same) in methods.groupBy { it.name }) if (same.size > 1) bad += "${c.simpleName}.$name is overloaded"
            for (m in methods) if (m.typeParameters.isNotEmpty()) bad += "${c.simpleName}.${m.name} has a type parameter"
            // A default argument compiles to a `DefaultImpls` holder or a `$default` bridge.
            if (c.declaredClasses.any { it.simpleName == "DefaultImpls" }) bad += "${c.simpleName} has a default implementation or argument"
            if (c.declaredMethods.any { it.name.endsWith("\$default") }) bad += "${c.simpleName} has a default argument"
        }
        assertEquals(emptyList(), bad)
    }

    /**
     * The fake must be unreachable in a release build. On iOS the bridge answers nil outside a debug
     * binary. On Android and desktop the rule is the source set: a release build compiles only `src/main`, so no file
     * there may name the fake's package; previews and UI tests that use it live in `app-android/src/debug`,
     * `src/test` or `src/androidTest`, and in `app-desktop/src/test`. With nothing in a release build referring to it,
     * no code path of that build can construct one.
     */
    @Test
    fun noReleaseSourceSetOfAnAppNamesTheFake() {
        val releaseRoots = listOf("app-android/src/main", "app-desktop/src/main").map(repo::resolve)
        assertTrue(releaseRoots.all { it.isDirectory }, "the apps' release source sets moved: ${releaseRoots.filter { !it.isDirectory }}")
        val fakePackage = Regex("""io\.silencelen\.andvari\.core\.app\.fake\b""")
        val found = releaseRoots.flatMap { root ->
            root.walkTopDown().filter { it.isFile && (it.extension == "kt" || it.extension == "java") && fakePackage.containsMatchIn(it.readText()) }
                .map { it.relativeTo(repo).path }.toList()
        }
        assertEquals(emptyList(), found, "a release source set names the fake")
    }
}
