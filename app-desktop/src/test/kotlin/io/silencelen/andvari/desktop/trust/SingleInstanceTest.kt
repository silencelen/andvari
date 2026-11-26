package io.silencelen.andvari.desktop.trust

import java.io.File
import java.nio.file.Files
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/** One instance, and atomic replaces that do not share a temporary name. */
class SingleInstanceTest {
    private fun tempRoot(): File = Files.createTempDirectory("andvari-one").toFile().also { it.deleteOnExit() }

    @Test
    fun aSecondStartInThisProcessIsRefusedAndTheFirstLockStays() {
        val file = SingleInstance.fileIn(tempRoot())
        val first = assertIs<SingleInstance.Gate.Acquired>(SingleInstance.acquire(file))
        try {
            assertIs<SingleInstance.Gate.AlreadyOpen>(SingleInstance.acquire(file))
        } finally {
            first.instance.release()
        }
        val again = assertIs<SingleInstance.Gate.Acquired>(SingleInstance.acquire(file), "free again once the first ends")
        again.instance.release()
    }

    /** The real case: another process (a double-click on the launcher) starts while this one holds the lock. */
    @Test
    fun aSecondProcessIsRefusedWhileTheFirstHoldsTheLock() {
        val file = SingleInstance.fileIn(tempRoot())
        val first = assertIs<SingleInstance.Gate.Acquired>(SingleInstance.acquire(file))
        try {
            assertEquals("AlreadyOpen", secondProcess(file))
        } finally {
            first.instance.release()
        }
        assertEquals("Acquired", secondProcess(file))
    }

    private fun secondProcess(file: File): String {
        val java = File(System.getProperty("java.home"), "bin/java").path
        val p = ProcessBuilder(java, "-cp", System.getProperty("java.class.path"), SecondStartProbe::class.java.name, file.path)
            .redirectErrorStream(true).start()
        assertTrue(p.waitFor(60, TimeUnit.SECONDS), "the probe ends")
        return p.inputStream.bufferedReader().readText().trim().lines().last()
    }

    @Test
    fun mainTakesTheLockBeforeAnythingElseRuns() {
        val main = File("src/main/kotlin/io/silencelen/andvari/desktop/Main.kt").readText()
        val body = main.substringAfter("fun main() {")
        val lock = body.indexOf("SingleInstance.acquire(")
        assertTrue(lock >= 0, "main takes the lock")
        for (later in listOf("NativeSodium.prepare()", "DesktopDiagnostics.runStartupSelfCheck()", "DesktopSessionStore()", "TrustSeam.model(")) {
            val at = body.indexOf(later)
            assertTrue(at > lock, "$later runs after the lock")
        }
    }

    /** Two writers of one file: with one fixed `.tmp` name they deleted and moved each other's file. */
    @Test
    fun twoWritersOfOneFileNeverTearIt() {
        val dir = tempRoot()
        val target = File(dir, "device-state.json")
        val a = OwnerOnlyFile(target)
        val b = OwnerOnlyFile(target)
        val failures = java.util.concurrent.ConcurrentLinkedQueue<Throwable>()
        val torn = java.util.concurrent.atomic.AtomicInteger()
        val go = CountDownLatch(1)
        val texts = (0 until 2).map { w -> (0 until 200).map { i -> """{"writer":$w,"n":$i,"pad":"${"x".repeat(2000)}"}""" } }
        val writers = listOf(a, b).mapIndexed { w, f ->
            thread {
                go.await()
                for (t in texts[w]) runCatching { f.replace(t) }.onFailure { failures += it }
            }
        }
        val reader = thread {
            go.await()
            repeat(400) {
                val read = runCatching { a.read() }.getOrNull()
                if (read != null && !(read.startsWith("{") && read.endsWith("}"))) torn.incrementAndGet()
            }
        }
        go.countDown()
        (writers + reader).forEach { it.join() }
        assertEquals(emptyList(), failures.map { it.javaClass.simpleName }, "no replace failed")
        assertEquals(0, torn.get(), "every read saw a whole file")
        assertEquals(listOf("device-state.json"), dir.listFiles()!!.map { it.name }.sorted(), "no temporary file is left")
    }

    @Test
    fun deletingAFileAlsoDeletesTheTemporaryFilesACrashLeft() {
        val dir = tempRoot()
        val target = File(dir, "secure-state.json")
        OwnerOnlyFile(target).replace("{}")
        File(dir, "secure-state.json.tmp").writeText("old fixed name")
        File(dir, "secure-state.json.12345.tmp").writeText("a crash between the write and the move")
        File(dir, "device-state.json").writeText("{}")
        assertTrue(OwnerOnlyFile(target).delete())
        assertEquals(listOf("device-state.json"), dir.listFiles()!!.map { it.name })
    }
}

/** Run in a second JVM by [SingleInstanceTest]: tries the lock once and prints what it got. */
object SecondStartProbe {
    @JvmStatic
    fun main(args: Array<String>) {
        when (val g = SingleInstance.acquire(File(args[0]))) {
            is SingleInstance.Gate.Acquired -> { println("Acquired"); g.instance.release() }
            SingleInstance.Gate.AlreadyOpen -> println("AlreadyOpen")
            is SingleInstance.Gate.Failed -> println("Failed ${g.why}")
        }
    }
}
