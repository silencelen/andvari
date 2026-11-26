package io.silencelen.andvari.server

import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** No request can mint a new meter, whatever path or method it names. */
class MetricsCardinalityTest {
    @Test
    fun unknownPathsAndMethods_addNoMeter() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val c = client
        // Warm up: the meters an unknown path and an unknown method use exist once.
        c.call(HttpMethod.Post, "/warm-up", "{}")
        c.call(HttpMethod.Delete, "/warm-up", "{}")
        c.call(HttpMethod("WARMUP"), "/warm-up")
        c.call(HttpMethod("WARMUP"), "/api/v1/sync")
        // A timer is recorded as the call completes, which can be just after the client has its answer: wait
        // until the warm-up's meters have all landed before counting.
        // Request meters only: the JVM's own (a GC pause with a new cause) may appear at any time.
        fun requestMeters() = s.metrics.meters.filter { it.id.name.startsWith("ktor.") }
        var before = requestMeters().size
        repeat(20) {
            kotlinx.coroutines.delay(100)
            val now = requestMeters().size
            if (now == before && it >= 2) return@repeat
            before = now
        }
        before = requestMeters().size
        assertTrue(before > 0, "the request meters are named ktor.*")
        repeat(1000) { i -> c.call(if (i % 2 == 0) HttpMethod.Post else HttpMethod.Delete, "/probe-$i/${uuid()}", "{}") }
        repeat(50) { i -> c.call(HttpMethod("M$i"), "/api/v1/sync") }
        kotlinx.coroutines.delay(500)
        val after = requestMeters().size
        assertEquals(before, after, "request meters grew from $before to $after: " + requestMeters().map { it.id.toString() }.sorted().joinToString("\n"))
        val scrape = s.metrics.scrape()
        assertTrue(!scrape.contains("probe-"), "the scrape names no raw path")
        assertTrue(!scrape.contains("method=\"M1\""), "the scrape names no unknown method")
    }
}
