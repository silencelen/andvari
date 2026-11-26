package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import java.io.File
import java.lang.reflect.Modifier
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * No test of this app builds a shared-code object by the number of its constructor's parameters: a field the shared
 * code adds that has nothing to do with the test broke such helpers three times in one night. A test takes the object
 * from the fake's own walk, or rebuilds one the shared code made ([rebuilt]), every field it is not about carried along.
 */
class SharedCodeRebuiltTest {
    @Test
    fun noTestBuildsASharedCodeObjectByTheCountOfItsParameters() {
        val needles = listOf("parameter" + "Count", "getDeclared" + "Constructor(")
        val found = File("src/test/kotlin").walkTopDown().filter { it.isFile && it.extension == "kt" }
            .flatMap { f -> f.readLines().mapIndexedNotNull { i, l -> "${f.name}:${i + 1}".takeIf { needles.any { n -> l.contains(n) } } } }
            .toList()
        assertEquals(emptyList(), found)
    }

    @Test
    fun aRebuiltObjectCarriesEveryFieldItWasNotAskedToChangeAndAnUnknownFieldFailsLoudly() {
        val made = FakeScenes.desktopAt(FakeScene.VAULTS).snapshot
        val changed = rebuilt(made, "busy" to !made.busy)
        assertEquals(!made.busy, changed.busy)
        for (f in made.javaClass.declaredFields.filter { !Modifier.isStatic(it.modifiers) && !it.isSynthetic && it.name != "busy" }) {
            f.isAccessible = true
            val was = f.get(made)
            assertTrue(if (f.type.isPrimitive) f.get(changed) == was else f.get(changed) === was, "${f.name} carried as it was")
        }
        assertFailsWith<IllegalStateException> { rebuilt(made, "noSuchField" to null) }
    }
}
