package io.silencelen.andvari.desktop.trust

import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import java.awt.EventQueue
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** What the first run of the new path under a virtual display found, pinned so it cannot come back. */
class AppRunTest {
    private val mainSources: List<File> =
        listOf(File("src/main/kotlin"), File("app-desktop/src/main/kotlin")).first { it.isDirectory }
            .walkTopDown().filter { it.isFile && it.extension == "kt" }.toList()

    private fun codeLines(f: File): List<String> =
        f.readLines().map { it.trim() }.filterNot { it.startsWith("//") || it.startsWith("*") || it.startsWith("/*") }

    /** No module here provides Dispatchers.Main (kotlinx-coroutines-swing is not a dependency): the first intent threw. */
    @Test
    fun nothingRunsOnDispatchersMain() {
        val users = mainSources.filter { f -> codeLines(f).any { "Dispatchers.Main" in it } }.map { it.name }
        assertEquals(emptyList(), users)
        val seam = codeLines(mainSources.single { it.name == "TrustSeam.kt" })
        assertTrue(seam.any { it.startsWith("main = SwingMain") })
        // With the desktop's handler for what escapes.
        assertTrue(seam.any { "CoroutineScope(SupervisorJob() + SwingMain + faults.handler)" in it })
    }

    @Test
    fun swingMainRunsOnTheEventThread() = runBlocking {
        assertTrue(!EventQueue.isDispatchThread())
        assertTrue(withContext(SwingMain) { EventQueue.isDispatchThread() })
    }
}
