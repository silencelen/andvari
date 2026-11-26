package io.silencelen.andvari.cli

/**
 * What a test prints when a run it waits for takes far longer than it does alone: at each of [marksMs] after [start],
 * unless [done] by then, [what] (the runs' output so far, the requests a proxy saw with their times) and a summary of
 * every thread of this process: how many of each kind, and the stack of each thread that serves coroutines or HTTP
 * clients. It only prints (to standard output, which the test report keeps); it changes nothing.
 */
class SlowRunReport(private val label: String, private val what: () -> String, private val marksMs: List<Long> = listOf(20_000, 70_000)) : AutoCloseable {
    @Volatile private var done = false
    private val started = System.nanoTime()

    private val watcher = Thread({
        for (mark in marksMs) {
            val left = mark - (System.nanoTime() - started) / 1_000_000
            if (left > 0) try { Thread.sleep(left) } catch (e: InterruptedException) { return@Thread }
            if (done) return@Thread
            println(report(mark))
        }
    }, "slow-run-report").apply { isDaemon = true; start() }

    fun report(atMs: Long): String = buildString {
        appendLine("==== SLOW RUN: $label, still running after ${atMs / 1000} s ====")
        appendLine(runCatching(what).getOrElse { "(could not read: $it)" })
        val all = Thread.getAllStackTraces()
        appendLine("---- ${all.size} threads, by kind and state ----")
        all.keys.groupBy { it.name.replace(Regex("[0-9]+"), "#") + " " + it.state }.entries.sortedByDescending { it.value.size }
            .forEach { (k, v) -> appendLine("  ${v.size}  $k") }
        appendLine("---- stacks of coroutine, HTTP client and test threads ----")
        for ((t, st) in all) {
            val n = t.name
            if (!(n.startsWith("DefaultDispatcher") || n.contains("HttpClient") || n.contains("ktor") || n.startsWith("pool-") || n.contains("Test worker")))
                continue
            appendLine("  \"$n\" ${t.state}")
            st.take(14).forEach { appendLine("      at $it") }
        }
    }

    override fun close() {
        done = true
        watcher.interrupt()
    }
}
