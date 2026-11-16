package io.silencelen.andvari.server

import io.ktor.client.request.request
import io.ktor.client.request.setBody
import io.ktor.http.ContentType
import io.ktor.http.HttpMethod
import io.ktor.http.contentType
import io.ktor.server.testing.testApplication
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * No request can mint a new meter, whatever path or method it names. Ktor 3.0.3's MicrometerMetrics
 * tags a request that matches no route with its raw path by default, and the method tag is the token
 * as sent, so every unknown path or method used to become a permanent timer with percentile histograms:
 * an unauthenticated way to fill the heap, one 404 at a time.
 */
class MetricsCardinalityTest : P4TestSupport() {
    @Test
    fun unknownPathsAndMethods_addNoRequestMeter() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val c = client
        suspend fun call(method: HttpMethod, path: String) {
            c.request(path) {
                this.method = method
                contentType(ContentType.Application.Json)
                setBody("{}")
            }
        }
        // Warm up: the meters an unknown path and an unknown method use exist once.
        call(HttpMethod.Post, "/warm-up")
        call(HttpMethod.Delete, "/warm-up")
        call(HttpMethod("WARMUP"), "/warm-up")
        call(HttpMethod("WARMUP"), "/api/v1/sync")
        // Request meters only (the JVM's own may appear at any time), counted once the warm-up's
        // timers have landed: a timer is recorded as the call completes, possibly after the answer.
        fun requestMeters() = services.metrics.meters.filter { it.id.name.startsWith("ktor.") }
        var before = requestMeters().size
        for (i in 0 until 20) {
            kotlinx.coroutines.delay(100)
            val now = requestMeters().size
            if (now == before && i >= 2) break
            before = now
        }
        before = requestMeters().size
        assertTrue(before > 0, "the request meters are named ktor.*")

        repeat(300) { i -> call(if (i % 2 == 0) HttpMethod.Post else HttpMethod.Delete, "/probe-$i/${uuid()}") }
        repeat(30) { i -> call(HttpMethod("M$i"), "/api/v1/sync") }
        kotlinx.coroutines.delay(500)

        val after = requestMeters().size
        assertEquals(before, after, "request meters grew from $before to $after:\n" + requestMeters().map { it.id.toString() }.sorted().joinToString("\n"))
        val scrape = services.metrics.scrape()
        assertFalse(scrape.contains("probe-"), "the scrape names no raw path")
        assertFalse(scrape.contains("method=\"M1\""), "the scrape names no unknown method")
    }
}
